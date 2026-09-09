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
from src.gateway.governance.seams.attestation import (
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
        aggregator.register(Provider05BlueprintProvider(...))
        aggregator.register(Provider02AttestationProvider(...))
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
        self._last_fetch_succeeded: bool = False  # Staleness signal
        self._poll_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Provider management
    # ------------------------------------------------------------------

    def register(self, provider: AttestationProvider) -> None:
        """Register an attestation provider.

        Args:
            provider: The attestation provider to register.

        Raises:
            TypeError: If provider does not implement AttestationProvider protocol.
        """
        if not isinstance(provider, AttestationProvider):
            raise TypeError(
                f"Provider must implement AttestationProvider protocol, got {type(provider)}"
            )

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

        Individual provider failures are recorded as ERROR-status attestation
        entries in the cache, preserving attributability. The aggregator
        continues fetching from remaining providers to maximize coverage.

        A total failure (all providers fail) retains the prior cache and does
        not advance ``_last_fetch_at``, preventing stale attestations from
        masquerading as fresh. Partial failures update the cache normally.
        """
        await self._do_fetch()
        logger.info(
            "Boot-fetched %d attestation(s) from %d provider(s) (success=%s)",
            len(self._cache),
            len(self._providers),
            self._last_fetch_succeeded,
        )

    async def poll(self) -> None:
        """Re-fetch attestations from all providers.

        Typically called on a periodic schedule by the poll loop.
        """
        await self._do_fetch()

    async def _do_fetch(self) -> None:
        """Internal fetch implementation.

        Phase 5b Changes (C3):
            - Capture provider_name before the try block to prevent a raising
              property from aborting the loop (defect b).
            - Use first-class provider_name field instead of encoding identity
              into attestation_type (defect a).
            - Distinguish total from partial failure: on total failure, retain
              the prior cache and leave _last_fetch_at unchanged (defects c, d).
        """
        all_attestations: list[ExternalAttestation] = []
        success_count = 0

        for provider in self._providers:
            # Capture provider_name BEFORE the try block so a raising property
            # cannot abort the loop (defect b). If provider_name itself raises,
            # we handle it and continue with a placeholder identity rather than
            # losing the remaining providers.
            try:
                provider_name = provider.provider_name
            except Exception as exc:
                provider_name = f"<unknown-provider-{id(provider)}>"
                logger.error(
                    "Provider.provider_name property raised: %s. "
                    "Continuing with placeholder identity.",
                    exc,
                )

            try:
                attestations = await provider.fetch_attestations({})
                all_attestations.extend(attestations)
                success_count += 1
                logger.debug(
                    "Fetched %d attestation(s) from %s",
                    len(attestations),
                    provider_name,
                )
            except Exception as exc:
                logger.warning(
                    "⚠️ Attestation provider %s failed: %s",
                    provider_name,
                    exc,
                )
                # Emit an ERROR-status attestation entry with first-class
                # provider_name field (defect a fix).
                all_attestations.append(
                    ExternalAttestation(
                        attestation_type="ERROR",
                        status=AttestationStatus.ERROR.value,
                        receipt_id="",
                        attested_at="",
                        provider_name=provider_name,
                        metadata={"error": str(exc)},
                    )
                )

        # Distinguish total from partial failure (defects c, d):
        # On total failure with existing good cache: retain prior cache and
        # leave _last_fetch_at unchanged to prevent stale data from masquerading as fresh.
        # On total failure with empty cache: record ERROR entries for attributability.
        # On partial or full success: update cache and timestamp normally.
        if success_count > 0:
            self._cache = all_attestations
            self._last_fetch_at = time.monotonic()
            self._last_fetch_succeeded = True
        else:
            # Total failure
            self._last_fetch_succeeded = False
            if self._cache:
                # Prior good cache exists: retain it, do not advance timestamp
                logger.error(
                    "⚠️ Total attestation fetch failure: all %d provider(s) failed. "
                    "Retaining prior cache (%d attestation(s)).",
                    len(self._providers),
                    len(self._cache),
                )
                # Do NOT update self._cache or self._last_fetch_at
            else:
                # No prior cache: record ERROR entries for attributability
                logger.error(
                    "⚠️ Total attestation fetch failure: all %d provider(s) failed. "
                    "Recording %d ERROR attestation(s) for audit trail.",
                    len(self._providers),
                    len(all_attestations),
                )
                self._cache = all_attestations
                # Do NOT update self._last_fetch_at (remains 0.0)

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
        """Monotonic timestamp of the last successful fetch.

        Use in conjunction with ``last_fetch_succeeded`` to distinguish
        between "no fetch has ever run" (timestamp=0.0) and "last fetch
        failed" (timestamp>0.0 but last_fetch_succeeded=False).
        """
        return self._last_fetch_at

    @property
    def last_fetch_succeeded(self) -> bool:
        """Staleness signal: True if the last fetch had at least one success.

        A False value indicates total failure — all providers failed on the
        most recent poll. Staleness monitors should alert when this is False,
        even if ``last_fetch_at`` is recent, as it indicates the cache may
        be stale despite a healthy-looking timestamp.

        Usage::

            if not aggregator.last_fetch_succeeded:
                logger.error("Attestation cache is stale (total fetch failure)")
            elif time.monotonic() - aggregator.last_fetch_at > threshold:
                logger.warning("Attestation cache is stale (poll interval exceeded)")
        """
        return self._last_fetch_succeeded

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
