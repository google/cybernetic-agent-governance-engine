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
VEIP Key Attestation Provider (Axiom 2: Identity Genesis).

Validates that an agent's SPIFFE mTLS identity chains to a Certificate
Authority that is explicitly admitted to authorize the requested consequence
class (e.g. treasury transfers vs market data reads).
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

logger = logging.getLogger("cage.integrations.veip.key")

_DEFAULT_SPIFFE_ID = "spiffe://cage.local/treasury-agent"
_DEFAULT_CONSEQUENCE_CLASS = "treasury_transfer"


class VEIPKeyProvider(AttestationProvider):
    """Key (Identity Genesis) attestation provider.

    Validates SPIFFE ID authority scope against institutional consequence classes.
    """

    def __init__(self, client: VEIPClient | None = None) -> None:
        self._client = client or VEIPClient()

    @property
    def provider_name(self) -> str:
        return "veip-key"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch admissibility grant for the given identity and consequence class.

        Args:
            context: Context containing 'spiffe_id' and 'consequence_class'.

        Returns:
            List containing the KEY ExternalAttestation entry.
        """
        spiffe_id = context.get("spiffe_id", _DEFAULT_SPIFFE_ID)
        consequence_class = context.get("consequence_class", _DEFAULT_CONSEQUENCE_CLASS)

        grant = await self._client.get_admissibility_grant(
            spiffe_id=spiffe_id, consequence_class=consequence_class
        )

        if grant is None:
            logger.warning(
                "⚠️ [KEY] No admissibility grant found for %s on %s",
                spiffe_id,
                consequence_class,
            )
            return [
                ExternalAttestation(
                    attestation_type="KEY",
                    status=AttestationStatus.STALE.value,
                    receipt_id="",
                    attested_at="",
                    metadata={
                        "spiffe_id": spiffe_id,
                        "consequence_class": consequence_class,
                        "error": "Grant not found",
                    },
                )
            ]

        status = (
            AttestationStatus.VERIFIED.value
            if grant.admitted
            else AttestationStatus.DENIED.value
        )

        return [
            ExternalAttestation(
                attestation_type="KEY",
                status=status,
                receipt_id=grant.receipt_id,
                attested_at=grant.attested_at,
                metadata={
                    "spiffe_id": grant.spiffe_id,
                    "consequence_class": grant.consequence_class,
                    "ca_fingerprint": grant.ca_fingerprint,
                },
            )
        ]
