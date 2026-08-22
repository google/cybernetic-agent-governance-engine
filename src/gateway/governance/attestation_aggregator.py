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
Attestation Aggregator.

Collects ``ExternalAttestation`` entries from multiple registered
``AttestationProvider`` instances, caches results in-memory, and
supplies them to ``GovernanceEnvelopeBuilder`` at build time with
zero per-transaction network calls.

Boot-fetch pattern mirrors ``NormativeProviderDaemon`` (fetch at startup,
periodic poll, fail-open with alert on error).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)

logger = logging.getLogger("Gateway.Governance.AttestationAggregator")

# Default poll interval: 6 hours (matches THR-AUD-002 Lula cadence)
_DEFAULT_POLL_INTERVAL_S = 21600.0


class AttestationAggregator:
    """Aggregates external attestations from multiple providers.

    Boot-fetches and periodically polls all registered providers,
    caching results in-memory.  The cached attestations are embedded
    into GovernanceEnvelopes at build time with zero per-transaction
    network calls.

    Usage::

        aggregator = AttestationAggregator()
        aggregator.register(VEIPBlueprintProvider(...))
        aggregator.register(ArchytanAttestationProvider(...))
        await aggregator.boot_fetch()

        # Later, at envelope-build time:
        attestations = aggregator.get_cached_attestations()
        envelope = builder.build_unsigned(
            ...,
            external_attestations=attestations,
        )
    """

    def __init__(
        self,
        providers: list[AttestationProvider] | None = None,
        poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
    ) -> None:
        self._providers: list[AttestationProvider] = list(providers or [])
        self._poll_interval_s = poll_interval_s
        self._cache: list[ExternalAttestation] = []
        self._last_fetch_at: float = 0.0
        self._poll_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Provider management
    # ------------------------------------------------------------------

    def register(self, provider: AttestationProvider) -> None:
        """Register an attestation provider.

        Args:
            provider: The attestation provider to register.
        """
        self._providers.append(provider)
        logger.info("Registered attestation provider: %s", provider.provider_name)

    @property
    def provider_count(self) -> int:
        """Number of registered providers."""
        return len(self._providers)

    # ------------------------------------------------------------------
    # Fetch & cache
    # ------------------------------------------------------------------

    async def boot_fetch(self) -> None:
        """Fetch attestations from all providers at startup.

        Errors from individual providers are logged but do not prevent
        other providers from being fetched (fail-open per §7.3).
        """
        await self._do_fetch()
        logger.info(
            "Boot-fetched %d attestation(s) from %d provider(s)",
            len(self._cache),
            len(self._providers),
        )

    async def poll(self) -> None:
        """Re-fetch attestations from all providers.

        Typically called on a periodic schedule by the poll loop.
        """
        await self._do_fetch()

    async def _do_fetch(self) -> None:
        """Internal fetch implementation."""
        all_attestations: list[ExternalAttestation] = []

        for provider in self._providers:
            try:
                attestations = await provider.fetch_attestations({})
                all_attestations.extend(attestations)
                logger.debug(
                    "Fetched %d attestation(s) from %s",
                    len(attestations),
                    provider.provider_name,
                )
            except Exception as exc:
                logger.warning(
                    "⚠️ Attestation provider %s failed (fail-open): %s",
                    provider.provider_name,
                    exc,
                )
                # Emit a STALE attestation entry so the envelope records
                # that a provider was registered but could not be reached.
                all_attestations.append(
                    ExternalAttestation(
                        attestation_type=f"PROVIDER_ERROR:{provider.provider_name}",
                        status=AttestationStatus.ERROR.value,
                        receipt_id="",
                        attested_at="",
                        metadata={"error": str(exc)},
                    )
                )

        self._cache = all_attestations
        self._last_fetch_at = time.monotonic()

    def get_cached_attestations(
        self, context: dict[str, Any] | None = None
    ) -> list[ExternalAttestation]:
        """Return cached attestations for envelope embedding.

        Args:
            context: Optional governance context for future filtering.
                Currently unused; reserved for per-action attestation
                scoping in a follow-on phase.

        Returns:
            A list of ExternalAttestation entries from the last fetch.
        """
        return list(self._cache)

    @property
    def last_fetch_at(self) -> float:
        """Monotonic timestamp of the last successful fetch."""
        return self._last_fetch_at

    # ------------------------------------------------------------------
    # Periodic poll loop
    # ------------------------------------------------------------------

    async def start_poll_loop(self) -> None:
        """Start the background poll loop.

        The loop runs indefinitely, re-fetching attestations every
        ``poll_interval_s`` seconds.
        """
        self._poll_task = asyncio.current_task()
        while True:
            await asyncio.sleep(self._poll_interval_s)
            try:
                await self.poll()
            except Exception as exc:
                logger.error("Attestation poll loop error (continuing): %s", exc)

    def stop_poll_loop(self) -> None:
        """Cancel the background poll loop if running."""
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
