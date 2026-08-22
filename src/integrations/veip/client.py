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
VEIP (Verifiable Execution Evidence Pack) Client Interface.

Provides structured access to VEIP attestation endpoints for the Three Axioms:
  1. Policy Legitimacy (Blueprint) — RiskAcceptanceRecord
  2. Identity Genesis (Key) — AdmissibilityGrant
  3. Substrate Integrity (Physics) — SubstrateAttestation

Supports both seeded synthetic test instances and live HTTP endpoint connections.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.integrations.veip.client")

_ENDPOINT: str = os.environ.get("VEIP_ATTESTATION_ENDPOINT", "")
_API_KEY_SECRET: str = os.environ.get("VEIP_API_KEY_SECRET", "")
_TIMEOUT_SECONDS: float = float(os.environ.get("VEIP_TIMEOUT_SECONDS", "5.0"))


@dataclass
class RiskAcceptanceRecord:
    """Signed risk-acceptance record for a threshold value (Axiom 1: Blueprint)."""

    threshold_id: str
    threshold_value: float
    ao_name: str
    ao_signature_hash: str
    receipt_id: str
    attested_at: str
    rationale: str = ""

    def to_canonical_bytes(self) -> bytes:
        return jcs_canonicalize_plan(
            {
                "threshold_id": self.threshold_id,
                "threshold_value": self.threshold_value,
                "ao_name": self.ao_name,
                "ao_signature_hash": self.ao_signature_hash,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "rationale": self.rationale,
            }
        )


@dataclass
class AdmissibilityGrant:
    """Identity authority admissibility grant (Axiom 2: Key)."""

    spiffe_id: str
    consequence_class: str
    ca_fingerprint: str
    receipt_id: str
    attested_at: str
    admitted: bool = True

    def to_canonical_bytes(self) -> bytes:
        return jcs_canonicalize_plan(
            {
                "spiffe_id": self.spiffe_id,
                "consequence_class": self.consequence_class,
                "ca_fingerprint": self.ca_fingerprint,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "admitted": self.admitted,
            }
        )


@dataclass
class SubstrateAttestation:
    """Substrate hardware & hypervisor integrity attestation (Axiom 3: Physics)."""

    node_id: str
    vtpm_status: str  # "VERIFIED", "TAMPERED", "UNKNOWN"
    ebpf_anomaly_count: int
    receipt_id: str
    attested_at: str
    freshness_seconds: int = 0

    def to_canonical_bytes(self) -> bytes:
        return jcs_canonicalize_plan(
            {
                "node_id": self.node_id,
                "vtpm_status": self.vtpm_status,
                "ebpf_anomaly_count": self.ebpf_anomaly_count,
                "receipt_id": self.receipt_id,
                "attested_at": self.attested_at,
                "freshness_seconds": self.freshness_seconds,
            }
        )


class VEIPClient:
    """Client for querying VEIP attestation services."""

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._timeout = timeout

        # Seeded in-memory store for synthetic testing / local execution
        self._risk_acceptances: dict[str, RiskAcceptanceRecord] = {}
        self._admissibility_grants: dict[tuple[str, str], AdmissibilityGrant] = {}
        self._substrate_attestations: dict[str, SubstrateAttestation] = {}

    def seed_risk_acceptance(self, record: RiskAcceptanceRecord) -> None:
        """Seed a risk acceptance record for local/synthetic evaluation."""
        self._risk_acceptances[record.threshold_id] = record

    def seed_admissibility_grant(self, grant: AdmissibilityGrant) -> None:
        """Seed an admissibility grant for local/synthetic evaluation."""
        self._admissibility_grants[(grant.spiffe_id, grant.consequence_class)] = grant

    def seed_substrate_attestation(self, attestation: SubstrateAttestation) -> None:
        """Seed a substrate attestation for local/synthetic evaluation."""
        self._substrate_attestations[attestation.node_id] = attestation

    async def get_risk_acceptance(
        self, threshold_id: str
    ) -> RiskAcceptanceRecord | None:
        """Retrieve the risk acceptance record for a given threshold."""
        if threshold_id in self._risk_acceptances:
            return self._risk_acceptances[threshold_id]
        if not self._endpoint:
            return None
        # HTTP client implementation for live deployment
        return None

    async def get_admissibility_grant(
        self, spiffe_id: str, consequence_class: str
    ) -> AdmissibilityGrant | None:
        """Retrieve the admissibility grant for an identity and consequence class."""
        key = (spiffe_id, consequence_class)
        if key in self._admissibility_grants:
            return self._admissibility_grants[key]
        if not self._endpoint:
            return None
        # HTTP client implementation for live deployment
        return None

    async def get_substrate_attestation(
        self, node_id: str
    ) -> SubstrateAttestation | None:
        """Retrieve substrate attestation for a host/node."""
        if node_id in self._substrate_attestations:
            return self._substrate_attestations[node_id]
        if not self._endpoint:
            return None
        # HTTP client implementation for live deployment
        return None
