# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bidirectional signed OCSF ingestor with automatic gateway SVID quarantine escalation."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.actuation import ReceiptVerification
from src.gateway.governance.seams.quarantine import QuarantineTriggerReason
from src.integrations.actuator_04.adapter import verify_substrate_receipt_signature
from src.integrations.actuator_04.constants import OCSF_EVENT_DOMAIN_TAG
from src.integrations.actuator_04.models import OcsfEventModel
from src.integrations.trust.key_manifest import Ed25519KeyResolver

logger = logging.getLogger("cage.integrations.actuator_04.ocsf")

_SENSITIVE_KEY_RE = re.compile(
    r"(?:secret|token|password|credential|authorization|api_key|private_key)",
    re.IGNORECASE,
)


def _sanitize_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask sensitive credential patterns before recording."""
    cleaned: dict[str, Any] = {}
    for k, v in data.items():
        if _SENSITIVE_KEY_RE.search(str(k)):
            cleaned[k] = "[REDACTED]"
        elif isinstance(v, dict):
            cleaned[k] = _sanitize_mapping(v)
        elif isinstance(v, list):
            cleaned[k] = [
                _sanitize_mapping(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            cleaned[k] = v
    return cleaned


class Actuator04OcsfIngestor:
    """Ingests Ed25519-signed OCSF telemetry and executes immediate gateway quarantine on breakouts."""

    def __init__(
        self,
        *,
        sink: Any | None = None,
        key_resolver: Ed25519KeyResolver | None = None,
    ) -> None:
        self._sink = sink
        self._key_resolver = key_resolver

    async def ingest_ocsf_event(self, raw_event: dict[str, Any]) -> str | None:
        """Validate, verify signature, sanitize, and record host kernel OCSF event."""
        # 1. Signature verification over OCSF_EVENT_DOMAIN_TAG + JCS(event_without_signature)
        v_status, finding = await verify_substrate_receipt_signature(
            raw_event,
            domain_tag=OCSF_EVENT_DOMAIN_TAG,
            expected_envelope_digest=raw_event.get("governance_decision_digest", ""),
            key_resolver=self._key_resolver,
        )

        if v_status != ReceiptVerification.VERIFIED or finding:
            detail = finding["detail"] if finding else "Receipt signature not verified"
            logger.error(
                "OCSF telemetry signature verification failed: %s (status=%s)",
                finding,
                v_status,
            )
            raise ValueError(f"Invalid OCSF signature: {detail}")

        # 2. Pydantic validation
        validated = OcsfEventModel.model_validate(raw_event)
        sanitized_meta = _sanitize_mapping(validated.metadata)

        is_blocked = validated.disposition.strip().lower() in (
            "blocked",
            "denied",
            "dropped",
            "rejected",
            "quarantined",
        )
        control_id = "AC-3" if is_blocked else "SI-4"

        record: dict[str, Any] = {
            "type": "SANDBOX_OCSF_TELEMETRY",
            "controlId": control_id,
            "ocsf_class_uid": validated.class_uid,
            "ocsf_category_uid": validated.category_uid,
            "ocsf_severity_id": validated.severity_id,
            "ocsf_activity_id": validated.activity_id,
            "ocsf_action": validated.action,
            "ocsf_disposition": validated.disposition,
            "sandbox_id": validated.sandbox_id,
            "thread_id": validated.thread_id,
            "governance_decision_digest": validated.governance_decision_digest,
            "agent_svid": validated.agent_svid,
            "trace_id": validated.trace_id or validated.thread_id,
            "metadata": sanitized_meta,
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        }

        # 3. Emergency Escalation Boundary: Critical breakout -> Revoke SVID immediately
        if (
            validated.severity_id >= 4
            or "escape" in validated.action.lower()
            or "taint" in validated.action.lower()
        ):
            logger.critical(
                "Host Kernel Breakout Detected (severity=%d, action=%s). Revoking SVID %s across CAGE Gateway!",
                validated.severity_id,
                validated.action,
                validated.agent_svid,
            )
            # Issue gateway quarantine
            import hashlib

            from src.gateway.governance.quarantine_actuator import (
                QuarantineDirective,
                dispatch_quarantine,
            )

            directive = QuarantineDirective(
                thread_id=validated.thread_id,
                agent_svid=validated.agent_svid or validated.sandbox_id,
                sandbox_id=validated.sandbox_id,
                reason=QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT,
                violation_codes=(
                    "HOST_KERNEL_BREAKOUT_TAINT",
                    f"OCSF_SEVERITY_{validated.severity_id}",
                ),
                issued_at=int(datetime.now(tz=timezone.utc).timestamp()),
                correlation_id=validated.trace_id or validated.thread_id,
                nonce=hashlib.sha256(jcs_canonicalize_plan(raw_event)).hexdigest()[:32],
                governance_decision_digest=validated.governance_decision_digest,
            )
            await dispatch_quarantine(directive)

        # 4. Commit to Evidence Stream
        sink = self._sink
        if sink is None:
            from src.gateway.governance.evidence.stream import get_evidence_sink

            sink = get_evidence_sink()

        return await sink.ingest(record)
