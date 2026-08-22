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
VEIP Physics Attestation Provider (Axiom 3: Substrate Integrity).

Validates that the underlying execution substrate (GKE node vTPM and AgentSight
eBPF hypervisor monitors) has not been compromised by kernel exploits or physical
memory corruption (Rowhammer, fault injection).
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
from src.integrations.veip.client import VEIPClient

logger = logging.getLogger("cage.integrations.veip.physics")

_DEFAULT_NODE_ID = os.environ.get("CAGE_NODE_ID", "gke-node-us-central1-01")


class VEIPPhysicsProvider(AttestationProvider):
    """Physics (Substrate Integrity) attestation provider.

    Polls vTPM measurements and AgentSight eBPF counters to detect hardware
    or kernel-level anomalies.
    """

    def __init__(
        self,
        client: VEIPClient | None = None,
        node_id: str = _DEFAULT_NODE_ID,
    ) -> None:
        self._client = client or VEIPClient()
        self._node_id = node_id

    @property
    def provider_name(self) -> str:
        return "veip-physics"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch substrate integrity measurements for the node hosting the gateway.

        Args:
            context: Context containing optional 'node_id'.

        Returns:
            List containing the PHYSICS ExternalAttestation entry.
        """
        node_id = context.get("node_id", self._node_id)
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
                    metadata={
                        "node_id": node_id,
                        "error": "Substrate attestation not found",
                    },
                )
            ]

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

        return [
            ExternalAttestation(
                attestation_type="PHYSICS",
                status=status,
                receipt_id=attestation.receipt_id,
                attested_at=attestation.attested_at,
                metadata={
                    "node_id": attestation.node_id,
                    "vtpm_status": attestation.vtpm_status,
                    "ebpf_anomaly_count": attestation.ebpf_anomaly_count,
                    "freshness_seconds": attestation.freshness_seconds,
                },
            )
        ]
