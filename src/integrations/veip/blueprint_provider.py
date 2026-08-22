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
VEIP Blueprint Attestation Provider (Axiom 1: Policy Legitimacy).

Cryptographically binds Authorizing Official (AO) risk-acceptance records
to machine-enforced governance thresholds (e.g. THR-FIN-006) and detects
threshold drift between authorized risk acceptance and active runtime policy.
"""

from __future__ import annotations

import logging
from typing import Any

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.integrations.veip.client import VEIPClient

logger = logging.getLogger("cage.integrations.veip.blueprint")

# Default consensus threshold value for THR-FIN-006 ($10,000)
_DEFAULT_THR_FIN_006_VALUE: float = 10000.0


class VEIPBlueprintProvider(AttestationProvider):
    """Blueprint (Policy Legitimacy) attestation provider.

    Validates that active runtime thresholds have a signed risk-acceptance
    record on file from an Authorizing Official and detects parameter drift.
    """

    def __init__(
        self,
        client: VEIPClient | None = None,
        active_thresholds: dict[str, float] | None = None,
    ) -> None:
        self._client = client or VEIPClient()
        self._active_thresholds = dict(
            active_thresholds or {"THR-FIN-006": _DEFAULT_THR_FIN_006_VALUE}
        )

    @property
    def provider_name(self) -> str:
        return "veip-blueprint"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch risk-acceptance attestations and verify alignment with active thresholds.

        Args:
            context: Context containing optional 'threshold_id' (defaults to 'THR-FIN-006').

        Returns:
            List containing the BLUEPRINT ExternalAttestation entry.
        """
        threshold_id = context.get("threshold_id", "THR-FIN-006")
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
                    metadata={
                        "threshold_id": threshold_id,
                        "error": "Record not found",
                    },
                )
            ]

        # Check for threshold drift between signed risk acceptance and active runtime value
        active_val = self._active_thresholds.get(threshold_id)
        if active_val is not None and abs(active_val - record.threshold_value) > 1e-6:
            logger.error(
                "⛔ [BLUEPRINT_DRIFT] Threshold %s drifted! Active=%s, Authorized=%s",
                threshold_id,
                active_val,
                record.threshold_value,
            )
            status = AttestationStatus.DRIFT_DETECTED.value
        else:
            status = AttestationStatus.VERIFIED.value

        return [
            ExternalAttestation(
                attestation_type="BLUEPRINT",
                status=status,
                receipt_id=record.receipt_id,
                attested_at=record.attested_at,
                metadata={
                    "threshold_id": record.threshold_id,
                    "ao_signature_hash": record.ao_signature_hash,
                    "ao_name": record.ao_name,
                    "threshold_value": record.threshold_value,
                },
            )
        ]

