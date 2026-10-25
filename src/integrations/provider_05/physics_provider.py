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
Provider 05 Physics Attestation Provider (Axiom 3: Substrate Integrity).

Validates that the underlying execution substrate (GKE node vTPM and AgentSight
eBPF hypervisor monitors) has not been compromised by kernel exploits or physical
memory corruption (Rowhammer, fault injection). Supports both v0.1 seeded records
and VEIP v0.3 signed SubstrateAttestation artifacts
(``veip-substrateattestation/0.3``).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.integrations.provider_05.client import (
    PHYSICS_SCHEMA_VERSION_V03,
    Provider05Client,
    verify_v03_artifact,
)

logger = logging.getLogger("cage.integrations.provider_05.physics")

_DEFAULT_NODE_ID = os.environ.get("CAGE_NODE_ID", "gke-node-us-central1-01")


class Provider05PhysicsProvider(AttestationProvider):
    """Physics (Substrate Integrity) attestation provider.

    Polls vTPM measurements and AgentSight eBPF counters to detect hardware
    or kernel-level anomalies.
    """

    def __init__(
        self,
        client: Provider05Client | None = None,
        node_id: str = _DEFAULT_NODE_ID,
    ) -> None:
        self._client = client or Provider05Client()
        self._node_id = node_id

    @property
    def provider_name(self) -> str:
        return "provider_05-physics"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch substrate integrity measurements for the node hosting the gateway.

        Args:
            context: Context containing optional 'node_id' or 'artifact_id' and
                VEIP v0.3 evaluation fields.

        Returns:
            List containing the PHYSICS ExternalAttestation entry.
        """
        node_id = context.get("artifact_id") or context.get("node_id") or self._node_id
        attestation = await self._client.get_substrate_attestation(node_id)

        if attestation is None:
            logger.warning(
                "⚠️ [PHYSICS] No substrate attestation found for node %s",
                node_id,
            )
            return [
                ExternalAttestation(
                    attestation_type="PHYSICS",
                    status=AttestationStatus.STALE.value,
                    receipt_id="",
                    attested_at="",
                    provider_name=self.provider_name,
                    metadata={
                        "node_id": node_id,
                        "veip_v03_status": "REJECT",
                        "reason_code": "MISSING",
                        "error": "Substrate attestation not found",
                    },
                )
            ]

        v03_meta: dict[str, Any] = {}
        if attestation.is_v03 or self._client.key_manifest is not None:
            key_manifest = await self._client.get_verified_key_manifest(
                now=context.get("now")
            )
            verification = verify_v03_artifact(
                attestation,
                expected_purpose="PHYSICS",
                expected_schema_version=PHYSICS_SCHEMA_VERSION_V03,
                key_manifest=key_manifest,
                context=context,
            )
            if not verification.accepted:
                return [
                    ExternalAttestation(
                        attestation_type="PHYSICS",
                        status=verification.attestation_status,
                        receipt_id=attestation.receipt_id,
                        attested_at=attestation.attested_at,
                        provider_name=self.provider_name,
                        metadata={
                            "node_id": attestation.node_id,
                            "vtpm_status": attestation.vtpm_status,
                            "ebpf_anomaly_count": attestation.ebpf_anomaly_count,
                            "freshness_seconds": attestation.freshness_seconds,
                            "kid": attestation.kid,
                            "digest": attestation.digest,
                            "veip_v03_status": verification.expected_status,
                            "reason_code": verification.reason_code,
                            "error": verification.reason,
                        },
                    )
                ]
            v03_meta = {
                "kid": attestation.kid,
                "digest": attestation.digest,
                "veip_v03_status": verification.expected_status,
                "reason_code": verification.reason_code,
            }

        # Validated if vTPM is verified and eBPF kernel monitors report zero anomalies
        if (
            attestation.vtpm_status == "VERIFIED"
            and attestation.ebpf_anomaly_count == 0
        ):
            status = AttestationStatus.VERIFIED.value
        else:
            logger.error(
                "⛔ [SUBSTRATE_CORRUPT] Node %s anomaly detected! vTPM=%s eBPF_anomalies=%d",
                node_id,
                attestation.vtpm_status,
                attestation.ebpf_anomaly_count,
            )
            status = AttestationStatus.DENIED.value
            if v03_meta:
                v03_meta["veip_v03_status"] = "REJECT"
                v03_meta["reason_code"] = "ATTESTATION_FAIL"

        return [
            ExternalAttestation(
                attestation_type="PHYSICS",
                status=status,
                receipt_id=attestation.receipt_id,
                attested_at=attestation.attested_at,
                provider_name=self.provider_name,
                metadata={
                    "node_id": attestation.node_id,
                    "vtpm_status": attestation.vtpm_status,
                    "ebpf_anomaly_count": attestation.ebpf_anomaly_count,
                    "freshness_seconds": attestation.freshness_seconds,
                    **v03_meta,
                },
            )
        ]
