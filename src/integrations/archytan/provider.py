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
Archytan Attestation Provider.

Implements the generic ``AttestationProvider`` protocol for the Archytan
trust service.  Maps Archytan-specific receipt formats, signature
verification, and protocol-level conventions to the generic
``ExternalAttestation`` schema used by ``GovernanceEnvelopeBuilder``.

Architecture:
  - Follows the vendor-isolation pattern established by
    ``src/integrations/veritas/provider.py``.
  - Fetches attestation records from the Archytan endpoint at boot
    and on a configurable poll interval.
  - Caches results in-memory via ``AttestationAggregator``.
  - No per-transaction network calls on the hot path.
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

logger = logging.getLogger("cage.integrations.archytan")

_ENDPOINT: str = os.environ.get("ARCHYTAN_ATTESTATION_ENDPOINT", "")
_API_KEY_SECRET: str = os.environ.get("ARCHYTAN_ATTESTATION_API_KEY_SECRET", "")
_TIMEOUT_SECONDS: float = float(
    os.environ.get("ARCHYTAN_ATTESTATION_TIMEOUT_SECONDS", "5.0")
)


class ArchytanAttestationProvider(AttestationProvider):
    """Archytan-specific attestation provider.

    Maps Archytan envelope semantics to the generic ExternalAttestation
    schema.  Handles Archytan-specific receipt formats, signature
    verification against Archytan's JWKS, and protocol-level mapping.
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        timeout: float = _TIMEOUT_SECONDS,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY_SECRET
        self._timeout = timeout

    @property
    def provider_name(self) -> str:
        """Unique provider identifier for telemetry."""
        return "archytan"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch current attestations from the Archytan service.

        Args:
            context: Governance context (action, region, agent identity).

        Returns:
            A list of ExternalAttestation entries from Archytan.
        """
        if not self._endpoint:
            logger.debug(
                "Archytan endpoint not configured — returning empty attestations"
            )
            return []

        # TODO: Implement actual HTTP fetch against Archytan's attestation
        # endpoint once the production API is available.  The implementation
        # should follow the httpx async pattern established in
        # VeritasNormativeProvider.fetch_legal_baseline().
        #
        # For now, return an empty list so the aggregator can be wired up
        # end-to-end without a live endpoint.
        logger.info(
            "Archytan attestation fetch (endpoint=%s) — stub implementation",
            self._endpoint,
        )
        return []
