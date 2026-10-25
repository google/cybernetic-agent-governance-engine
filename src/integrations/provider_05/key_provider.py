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
Provider 05 Key Attestation Provider (Axiom 2: Identity Genesis).

Validates that an agent's SPIFFE mTLS identity chains to a Certificate
Authority that is explicitly admitted to authorize the requested consequence
class (e.g. treasury transfers vs market data reads). Supports both v0.1 seeded
records and VEIP v0.3 signed AdmissibilityGrant artifacts
(``veip-admissibilitygrant/0.3``).
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
    KEY_SCHEMA_VERSION_V03,
    Provider05Client,
    verify_v03_artifact,
)

logger = logging.getLogger("cage.integrations.provider_05.key")

_DEFAULT_SPIFFE_ID = "spiffe://cage.local/treasury-agent"
_DEFAULT_CONSEQUENCE_CLASS = "treasury_transfer"


class Provider05KeyProvider(AttestationProvider):
    """Key (Identity Genesis) attestation provider.

    Validates SPIFFE ID authority scope against institutional consequence classes.
    """

    def __init__(self, client: Provider05Client | None = None) -> None:
        self._client = client or Provider05Client()

    @property
    def provider_name(self) -> str:
        return "provider_05-key"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch admissibility grant for the given identity and consequence class.

        Args:
            context: Context containing 'spiffe_id', 'consequence_class', or
                optional 'artifact_id' and VEIP v0.3 evaluation fields.

        Returns:
            List containing the KEY ExternalAttestation entry.
        """
        spiffe_id = context.get("spiffe_id", _DEFAULT_SPIFFE_ID)
        consequence_class = context.get("consequence_class", _DEFAULT_CONSEQUENCE_CLASS)
        artifact_id = str(context.get("artifact_id", ""))

        grant = await self._client.get_admissibility_grant(
            spiffe_id=spiffe_id,
            consequence_class=consequence_class,
            artifact_id=artifact_id,
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
                    provider_name=self.provider_name,
                    metadata={
                        "spiffe_id": spiffe_id,
                        "consequence_class": consequence_class,
                        "veip_v03_status": "REJECT",
                        "reason_code": "MISSING",
                        "error": "Grant not found",
                    },
                )
            ]

        v03_meta: dict[str, Any] = {}
        if grant.is_v03 or self._client.key_manifest is not None:
            key_manifest = await self._client.get_verified_key_manifest(
                now=context.get("now")
            )
            verification = verify_v03_artifact(
                grant,
                expected_purpose="KEY",
                expected_schema_version=KEY_SCHEMA_VERSION_V03,
                key_manifest=key_manifest,
                context=context,
            )
            if not verification.accepted:
                return [
                    ExternalAttestation(
                        attestation_type="KEY",
                        status=verification.attestation_status,
                        receipt_id=grant.receipt_id,
                        attested_at=grant.attested_at,
                        provider_name=self.provider_name,
                        metadata={
                            "spiffe_id": grant.spiffe_id,
                            "consequence_class": grant.consequence_class,
                            "ca_fingerprint": grant.ca_fingerprint,
                            "kid": grant.kid,
                            "digest": grant.digest,
                            "veip_v03_status": verification.expected_status,
                            "reason_code": verification.reason_code,
                            "error": verification.reason,
                        },
                    )
                ]
            v03_meta = {
                "kid": grant.kid,
                "digest": grant.digest,
                "veip_v03_status": verification.expected_status,
                "reason_code": verification.reason_code,
            }

        status = (
            AttestationStatus.VERIFIED.value
            if grant.admitted
            else AttestationStatus.DENIED.value
        )
        if not grant.admitted and v03_meta:
            v03_meta["veip_v03_status"] = "REJECT"
            v03_meta["reason_code"] = "NOT_ADMITTED"

        return [
            ExternalAttestation(
                attestation_type="KEY",
                status=status,
                receipt_id=grant.receipt_id,
                attested_at=grant.attested_at,
                provider_name=self.provider_name,
                metadata={
                    "spiffe_id": grant.spiffe_id,
                    "consequence_class": grant.consequence_class,
                    "ca_fingerprint": grant.ca_fingerprint,
                    **v03_meta,
                },
            )
        ]
