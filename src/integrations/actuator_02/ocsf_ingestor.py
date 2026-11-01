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

"""OCSF (Open Cybersecurity Schema Framework) telemetry ingestor for actuator_02.

Validates OpenShell sandbox file (1001), process (1007), and network (4001)
events, strips any potential secret/credential keys, and writes hash-chained
records into CAGE's ``EvidenceStreamSink`` bound to ``governance_decision_digest``:
the SHA-256 of the routing seal that authorised the sandboxed action
(``seal_digest(seal)``), lowercase hex (POAM-2026-149).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.gateway.governance.seams.digests import (
    DECISION_DIGEST_FIELDS,
    GOVERNANCE_DECISION_DIGEST,
    require_sha256_hex,
)
from src.integrations.actuator_02.constants import ALLOWED_OCSF_CLASS_UIDS

MAX_OCSF_METADATA_BYTES = 64 * 1024
"""Maximum serialized UTF-8 byte length of ``OcsfEventModel.metadata`` (#405)."""

_SENSITIVE_KEY_RE = re.compile(
    r"(?:secret|token|password|credential|authorization|api_key|private_key)",
    re.IGNORECASE,
)


def _require_nested_digests(value: Any) -> None:
    """Refuse a decision-digest key, at any depth of ``value``, that holds no digest.

    ``metadata`` reaches the evidence record verbatim, so a nested
    ``governance_decision_digest`` or ``refusal_proof_hash`` is checked like the
    top-level field. The error names the field, never the value or the path.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if key in DECISION_DIGEST_FIELDS:
                require_sha256_hex(item, field=f"{key} inside metadata")
            _require_nested_digests(item)
    elif isinstance(value, list):
        for item in value:
            _require_nested_digests(item)


def _sanitize_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask any dictionary keys that resemble credentials or tokens."""
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


class OcsfEventModel(BaseModel):
    """Validated OCSF event emitted by the sandbox supervisor.

    ``governance_decision_digest`` must be ``seal_digest(seal)``: 64 lowercase
    hex characters, checked by the shared validator
    (``src.gateway.governance.seams.digests``), as is any decision-digest key
    nested in ``metadata``. ``hide_input_in_errors`` keeps a refused value out
    of the ``ValidationError``'s string and repr. Its ``errors()`` and
    ``json()`` still carry the input unless called with
    ``include_input=False``, so a caller that serializes the errors must pass
    that.
    """

    model_config = ConfigDict(hide_input_in_errors=True)

    class_uid: int
    category_uid: int = Field(default=1, ge=0)
    severity_id: int = Field(default=1, ge=0, le=6)
    activity_id: int = Field(default=1, ge=0)
    action: str = Field(default="observed", min_length=1, max_length=64)
    disposition: str = Field(default="Allowed", min_length=1, max_length=64)
    sandbox_id: str = Field(min_length=1, max_length=128)
    thread_id: str = Field(min_length=1, max_length=128)
    governance_decision_digest: str
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("class_uid")
    @classmethod
    def _v_class_uid(cls, v: int) -> int:
        if v not in ALLOWED_OCSF_CLASS_UIDS:
            raise ValueError(
                f"Unsupported OCSF class_uid={v}; expected one of {sorted(ALLOWED_OCSF_CLASS_UIDS)}"
            )
        return v

    @field_validator("governance_decision_digest")
    @classmethod
    def _v_governance_decision_digest(cls, v: str) -> str:
        return require_sha256_hex(v, field=GOVERNANCE_DECISION_DIGEST)

    @field_validator("metadata")
    @classmethod
    def _v_metadata_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        serialized = json.dumps(v, default=str).encode("utf-8")
        if len(serialized) > MAX_OCSF_METADATA_BYTES:
            raise ValueError(
                f"OCSF metadata is {len(serialized)} bytes; limit {MAX_OCSF_METADATA_BYTES}"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _v_metadata_digests(cls, v: dict[str, Any]) -> dict[str, Any]:
        _require_nested_digests(v)
        return v


class OcsfEvidenceIngestor:
    """Ingests validated OCSF sandbox events into CAGE's EvidenceStreamSink."""

    def __init__(self, sink: Any | None = None) -> None:
        self._sink = sink

    async def ingest_ocsf_event(self, raw_event: dict[str, Any]) -> str | None:
        """Validate, sanitize, and commit an OCSF event to the hash-chained stream."""
        validated = OcsfEventModel.model_validate(raw_event)
        sanitized_meta = _sanitize_mapping(validated.metadata)

        is_blocked = validated.disposition.strip().lower() in (
            "blocked",
            "denied",
            "dropped",
            "rejected",
        )
        control_id = "AC-3" if is_blocked else "AU-2"

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
            "trace_id": validated.trace_id or validated.thread_id,
            "metadata": sanitized_meta,
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        }

        sink = self._sink
        if sink is None:
            from src.gateway.governance.evidence.stream import get_evidence_sink

            sink = get_evidence_sink()

        return await sink.ingest(record)
