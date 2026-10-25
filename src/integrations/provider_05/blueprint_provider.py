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

"""
Provider 05 Blueprint Attestation Provider (Axiom 1: Policy Legitimacy).

Cryptographically binds Authorizing Official (AO) risk-acceptance records
to machine-enforced governance thresholds (e.g. THR-FIN-006) and detects
threshold drift between authorized risk acceptance and active runtime policy.
Supports both v0.1 seeded records and VEIP v0.3 signed RiskAcceptanceRecord
artifacts (``veip-riskacceptancerecord/0.3``).
"""

from __future__ import annotations

import logging
from typing import Any

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.integrations.provider_05.client import (
    BLUEPRINT_SCHEMA_VERSION_V03,
    Provider05Client,
    verify_v03_artifact,
)

logger = logging.getLogger("cage.integrations.provider_05.blueprint")

# Default consensus threshold value for THR-FIN-006 ($10,000)
_DEFAULT_THR_FIN_006_VALUE: float = 10000.0


class Provider05BlueprintProvider(AttestationProvider):
    """Blueprint (Policy Legitimacy) attestation provider.

    Validates that active runtime thresholds have a signed risk-acceptance
    record on file from an Authorizing Official and detects parameter drift.
    """

    def __init__(
        self,
        client: Provider05Client | None = None,
        active_thresholds: dict[str, float] | None = None,
    ) -> None:
        self._client = client or Provider05Client()
        self._active_thresholds = dict(
            active_thresholds or {"THR-FIN-006": _DEFAULT_THR_FIN_006_VALUE}
        )

    @classmethod
    def from_env(cls) -> Provider05BlueprintProvider:
        """Instantiate provider from environment variables."""
        return cls()

    @property
    def provider_name(self) -> str:
        return "provider_05-blueprint"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch risk-acceptance attestations and verify alignment with active thresholds.

        Args:
            context: Context containing optional 'threshold_id' or 'artifact_id'
                (defaults to 'THR-FIN-006') and optional VEIP v0.3 evaluation
                fields ('now', 'action', 'jurisdiction', 'actor', 'system').

        Returns:
            List containing the BLUEPRINT ExternalAttestation entry.
        """
        threshold_id = (
            context.get("artifact_id") or context.get("threshold_id") or "THR-FIN-006"
        )
        record = await self._client.get_risk_acceptance(threshold_id)

        if record is None:
            logger.warning(
                "⚠️ [BLUEPRINT] No risk acceptance record found for threshold %s",
                threshold_id,
            )
            return [
                ExternalAttestation(
                    attestation_type="BLUEPRINT",
                    status=AttestationStatus.STALE.value,
                    receipt_id="",
                    attested_at="",
                    provider_name=self.provider_name,
                    metadata={
                        "threshold_id": threshold_id,
                        "veip_v03_status": "REJECT",
                        "reason_code": "MISSING",
                        "error": "Record not found",
                    },
                )
            ]

        v03_meta: dict[str, Any] = {}
        if record.is_v03 or self._client.key_manifest is not None:
            key_manifest = await self._client.get_verified_key_manifest(
                now=context.get("now")
            )
            verification = verify_v03_artifact(
                record,
                expected_purpose="BLUEPRINT",
                expected_schema_version=BLUEPRINT_SCHEMA_VERSION_V03,
                key_manifest=key_manifest,
                context=context,
            )
            if not verification.accepted:
                return [
                    ExternalAttestation(
                        attestation_type="BLUEPRINT",
                        status=verification.attestation_status,
                        receipt_id=record.receipt_id,
                        attested_at=record.attested_at,
                        provider_name=self.provider_name,
                        metadata={
                            "threshold_id": record.threshold_id,
                            "kid": record.kid,
                            "digest": record.digest,
                            "veip_v03_status": verification.expected_status,
                            "reason_code": verification.reason_code,
                            "error": verification.reason,
                        },
                    )
                ]
            v03_meta = {
                "kid": record.kid,
                "digest": record.digest,
                "veip_v03_status": verification.expected_status,
                "reason_code": verification.reason_code,
            }

        # Check for threshold drift between signed risk acceptance and active runtime value
        active_val = self._active_thresholds.get(record.threshold_id)
        if active_val is not None and abs(active_val - record.threshold_value) > 1e-6:
            logger.error(
                "⛔ [BLUEPRINT_DRIFT] Threshold %s drifted! Active=%s, Authorized=%s",
                record.threshold_id,
                active_val,
                record.threshold_value,
            )
            status = AttestationStatus.DRIFT_DETECTED.value
            if v03_meta:
                v03_meta["veip_v03_status"] = "REJECT"
                v03_meta["reason_code"] = "DRIFT_DETECTED"
        else:
            status = AttestationStatus.VERIFIED.value

        metadata: dict[str, Any] = {
            "threshold_id": record.threshold_id,
            "ao_signature_hash": record.ao_signature_hash,
            "ao_name": record.ao_name,
            "threshold_value": record.threshold_value,
            **v03_meta,
        }
        return [
            ExternalAttestation(
                attestation_type="BLUEPRINT",
                status=status,
                receipt_id=record.receipt_id,
                attested_at=record.attested_at,
                provider_name=self.provider_name,
                metadata=metadata,
            )
        ]
