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
provider.py — Provider 02 Attestation Provider (Feature 5)
==========================================================

Integrates Provider 02 as an attestation provider following the ``AttestationProvider``
protocol from ``src.gateway.governance.seams.attestation``.

Provider 02 adds a capability: **public JWK-verifiable receipts**
(Ed25519 signed CERs).  This module provides:

  1. CER creation via ``certifyDecision`` — wraps the raw HTTP API
  2. CER verification via locally-cached Ed25519 JWKs — no hot-path network call
  3. Project Bundle registration via ``registerProjectBundle``
  4. Attestation fetch via ``fetch_attestations`` — returns UNVERIFIED status
     until Wave 3 (Ed25519 signature verification) lands

JWK Caching Strategy
--------------------
The JWK endpoint is configured via ``PROVIDER_02_JWK_ENDPOINT`` and cached locally
with a 24-hour sync interval.  This avoids relying on a live out-of-band
network request during hot-path validation, which would break zero-trust
network boundaries and paralyse the worker pool on DNS degradation.

The cache syncs out-of-band via a background asyncio task, keeping the public
PEM string instantly accessible inside the execution environment.

Environment variables
---------------------
  PROVIDER_02_API_ENDPOINT       — API base URL (required)
  PROVIDER_02_API_KEY_SECRET     — API key (direct or Secret Manager path)
  PROVIDER_02_JWK_ENDPOINT       — Public JWK endpoint for receipt verification
  PROVIDER_02_JWK_CACHE_TTL_HOURS — JWK cache TTL (default: 24)
  PROVIDER_02_TIMEOUT_SECONDS    — Per-request timeout (default: 5.0)

Architecture precedent: follows the Provider 01 pattern in
``normative_provider.py`` — httpx.AsyncClient, timeout config, fail-closed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.seams.attestation import (
    AttestationProvider,
    AttestationStatus,
    ExternalAttestation,
)

logger = logging.getLogger("cage.provider_02")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("PROVIDER_02_API_ENDPOINT", "")
_API_KEY: str = os.environ.get("PROVIDER_02_API_KEY_SECRET", "")
_JWK_ENDPOINT: str = os.environ.get("PROVIDER_02_JWK_ENDPOINT", "")
_JWK_CACHE_TTL_HOURS: float = float(
    os.environ.get("PROVIDER_02_JWK_CACHE_TTL_HOURS", "24")
)
_TIMEOUT: float = float(os.environ.get("PROVIDER_02_TIMEOUT_SECONDS", "5.0"))


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class CERReceipt:
    """Provider 02 Certified Evidence Receipt.

    Returned by ``certifyDecision``.  The ``certificate_hash`` is the
    primary identifier for verification against the public JWK set.
    """

    certificate_hash: str = ""
    receipt_url: str = ""
    signer_key_id: str = ""
    signed_at: str = ""
    error: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.error is None and bool(self.certificate_hash)


@dataclass
class CERVerification:
    """Result of verifying a CER against Provider 02's public JWKs.

    Invariant: `valid` must never be `True` while `signature_checked` is `False`.
    This is enforced structurally in __post_init__ to prevent accidentally
    returning verified=True without performing signature verification.
    """

    valid: bool = False
    signer: str = ""
    timestamp: str = ""
    key_id: str = ""
    error: str | None = None
    signature_checked: bool = False

    def __post_init__(self) -> None:
        """Enforce the invariant: valid=True requires signature_checked=True."""
        if self.valid and not self.signature_checked:
            raise ValueError(
                "CERVerification invariant violated: "
                "valid=True requires signature_checked=True. "
                "This indicates a fail-open code path that must be corrected."
            )


@dataclass
class JWKCache:
    """In-memory cache of Provider 02's public JWK set.

    Synced out-of-band every ``_JWK_CACHE_TTL_HOURS`` hours.
    The cache holds the raw JWK set dict and the last sync timestamp.
    """

    jwk_set: dict[str, Any] = field(default_factory=dict)
    last_synced: float = 0.0
    etag: str = ""

    @property
    def is_stale(self) -> bool:
        ttl_seconds = _JWK_CACHE_TTL_HOURS * 3600
        return (time.time() - self.last_synced) > ttl_seconds

    @property
    def has_keys(self) -> bool:
        return bool(self.jwk_set.get("keys"))


# ---------------------------------------------------------------------------
# Provider 02 Attestation Provider
# ---------------------------------------------------------------------------


class Provider02AttestationProvider(AttestationProvider):
    """Provider 02 attestation provider for CER creation and verification.

    Implements the ``AttestationProvider`` protocol from
    ``src.gateway.governance.seams.attestation``.

    Provider 02 fetches CER attestations and returns them with
    ``AttestationStatus.UNVERIFIED`` until Wave 3 (Ed25519 signature verification)
    lands. At that point, the status will transition to ``AttestationStatus.VERIFIED``
    when signature checks pass.

    Usage::

        provider = Provider02AttestationProvider()
        await provider.start()  # starts JWK sync daemon

        # Fetch attestations (AttestationProvider protocol)
        attestations = await provider.fetch_attestations({"action": "execute_trade"})

        # Create a CER (provider-specific)
        cer = await provider.certify_decision(evidence_payload)

        # Verify a CER (local — uses cached JWKs)
        result = await provider.verify_cer(cer.certificate_hash)

        # Register a bundle (provider-specific)
        await provider.register_project_bundle(bundle_dict)
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        jwk_endpoint: str = "",
        timeout: float = _TIMEOUT,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY
        self._jwk_endpoint = jwk_endpoint or _JWK_ENDPOINT
        self._timeout = timeout
        self._jwk_cache = JWKCache()
        self._sync_task: asyncio.Task | None = None
        self._running = False

        if not self._endpoint:
            logger.warning(
                "[Provider02] PROVIDER_02_API_ENDPOINT not set. "
                "Attestation calls will fail."
            )

        logger.info(
            "[Provider02] Initialised: endpoint=%s jwk=%s timeout=%.1fs",
            self._endpoint or "(not set)",
            self._jwk_endpoint or "(not set)",
            self._timeout,
        )

    def _headers(self) -> dict[str, str]:
        """Authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ------------------------------------------------------------------
    # AttestationProvider Protocol
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        """Unique provider identifier for telemetry and logging."""
        return "provider_02"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        """Fetch current attestations for the given governance context.

        Wraps ``verify_cer`` and returns attestations with
        ``AttestationStatus.UNVERIFIED`` until Wave 3 (B3) implements
        real Ed25519 signature verification.

        Args:
            context: Governance context dict. Expected keys:
                - certificate_hash: str (required for CER verification)

        Returns:
            List of ExternalAttestation entries with UNVERIFIED status.
        """
        certificate_hash = context.get("certificate_hash", "")
        if not certificate_hash:
            logger.warning(
                "[Provider02] fetch_attestations called without certificate_hash — "
                "returning empty attestation list."
            )
            return []

        # Verify the CER (currently returns valid=False, signature_checked=False)
        result = await self.verify_cer(certificate_hash)

        # Map CERVerification to ExternalAttestation
        # Phase 0 fail-closed: status is UNVERIFIED until signature verification
        # is implemented in Wave 3 (B3).
        #
        # Status mapping:
        #   - valid=True, signature_checked=True  → VERIFIED (Wave 3 / B3)
        #   - valid=False, signature_checked=False, error contains "Phase 2b" → UNVERIFIED
        #   - valid=False, signature_checked=False, error is real failure → ERROR
        status = AttestationStatus.UNVERIFIED
        
        if result.valid and result.signature_checked:
            # Wave 3 (B3) path: real Ed25519 verification passed
            status = AttestationStatus.VERIFIED
        elif result.error and "Phase 2b" not in result.error and "not yet implemented" not in result.error:
            # Real errors (network failures, parse errors, etc.) → ERROR
            # But "Phase 2b pending" messages → UNVERIFIED
            status = AttestationStatus.ERROR

        attestation = ExternalAttestation(
            attestation_type="CER",
            status=status.value,
            receipt_id=certificate_hash[:16],  # First 16 chars as receipt ID
            attested_at=result.timestamp or "",
            metadata={
                "signer": result.signer,
                "key_id": result.key_id,
                "signature_checked": result.signature_checked,
                "error": result.error,
            },
        )

        return [attestation]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the JWK sync daemon."""
        if self._running:
            return

        self._running = True

        # Initial JWK fetch
        if self._jwk_endpoint:
            await self._sync_jwks()
            self._sync_task = asyncio.create_task(
                self._jwk_sync_loop(),
                name="provider-02-jwk-sync",
            )

    async def stop(self) -> None:
        """Stop the JWK sync daemon."""
        self._running = False
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # CER creation
    # ------------------------------------------------------------------

    async def certify_decision(self, evidence_record: dict[str, Any]) -> CERReceipt:
        """Submit a governance decision for Provider 02 CER certification.

        Args:
            evidence_record: Governance decision payload with signals and state hash.

        Returns:
            CERReceipt with certificate_hash and receipt_url.
        """
        import httpx

        url = f"{self._endpoint}/certifyDecision"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url, json=evidence_record, headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()
                return CERReceipt(
                    certificate_hash=data.get("certificateHash", ""),
                    receipt_url=data.get("receiptUrl", ""),
                    signer_key_id=data.get("signerKeyId", ""),
                    signed_at=data.get("signedAt", ""),
                )
        except Exception as exc:
            logger.error("[Provider02] certifyDecision failed: %s %s", url, exc)
            return CERReceipt(error=str(exc))

    # ------------------------------------------------------------------
    # CER verification (local — uses cached JWKs)
    # ------------------------------------------------------------------

    async def verify_cer(self, certificate_hash: str) -> CERVerification:
        """Verify a CER against locally-cached Provider 02 JWKs.

        This method does NOT make a network call during verification.
        JWKs are synced out-of-band by the background daemon.

        Falls back to a remote verification call if JWK cache is empty.
        """
        if self._jwk_cache.has_keys:
            return self._inspect_local(certificate_hash)

        # Fallback: remote verification
        return await self._verify_remote(certificate_hash)

    def _inspect_local(self, certificate_hash: str) -> CERVerification:
        """Inspect a CER for well-formedness against the locally-cached JWK set.

        IMPORTANT: This method does NOT perform signature verification.
        It only validates well-formedness (hash length, JWK cache presence).
        Real Ed25519 signature verification is deferred to Phase 2b.

        Returns valid=False with signature_checked=False to indicate that
        the CER is structurally valid but cryptographically unverified.
        """
        if not self._jwk_cache.has_keys:
            return CERVerification(
                valid=False,
                signature_checked=False,
                error="JWK cache is empty — cannot inspect locally.",
            )

        if len(certificate_hash) != 64:  # SHA-256 hex length
            return CERVerification(
                valid=False,
                signature_checked=False,
                error=f"Invalid certificate hash length: {len(certificate_hash)}",
            )

        # Well-formedness checks passed, but signature verification is not
        # yet implemented. Fail closed: return valid=False until Phase 2b
        # implements real Ed25519 verification.
        logger.debug(
            "[Provider02] Local inspection (no signature check): hash=%s… keys=%d",
            certificate_hash[:16],
            len(self._jwk_cache.jwk_set.get("keys", [])),
        )

        return CERVerification(
            valid=False,
            signature_checked=False,
            signer="",
            key_id="",
            error="Signature verification not yet implemented (Phase 2b pending)",
        )

    async def _verify_remote(self, certificate_hash: str) -> CERVerification:
        """Fallback: query Provider 02's remote verification endpoint.

        Phase 0 fail-closed: Even if the remote endpoint returns valid=True,
        CAGE itself did not check the signature, so we return valid=False
        until Phase 2b implements real Ed25519 verification.

        The remote response is captured for diagnostics but does not override
        the fail-closed contract.
        """
        import httpx

        url = f"{self._endpoint}/verify/{certificate_hash}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                # Phase 0 fail-closed: CAGE did not verify the signature itself,
                # so valid=False regardless of what the remote endpoint reports.
                return CERVerification(
                    valid=False,  # Fail closed until Phase 2b
                    signature_checked=False,  # CAGE did not check the signature
                    signer=data.get("signer", ""),
                    timestamp=data.get("timestamp", ""),
                    key_id=data.get("keyId", ""),
                    error=(
                        "Remote endpoint queried but signature verification "
                        "not yet implemented (Phase 2b pending)"
                    ),
                )
        except Exception as exc:
            logger.error("[Provider02] Remote verification failed: %s %s", url, exc)
            return CERVerification(
                valid=False,
                signature_checked=False,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Project Bundle registration
    # ------------------------------------------------------------------

    async def register_project_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Register a completed Project Bundle with Provider 02.

        Args:
            bundle: Serialized AttestationBundle dict (from provider_02_adapter.py).

        Returns:
            Registration response with bundleHash and receiptUrl.
        """
        import httpx

        url = f"{self._endpoint}/registerProjectBundle"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=bundle, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("[Provider02] registerProjectBundle failed: %s %s", url, exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # JWK sync daemon
    # ------------------------------------------------------------------

    async def _sync_jwks(self) -> None:
        """Fetch the Provider 02 public JWK set and update the local cache."""
        if not self._jwk_endpoint:
            return

        import httpx

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                headers = {}
                if self._jwk_cache.etag:
                    headers["If-None-Match"] = self._jwk_cache.etag

                resp = await client.get(self._jwk_endpoint, headers=headers)

                if resp.status_code == 304:
                    # Not modified — cache is still valid
                    self._jwk_cache.last_synced = time.time()
                    logger.debug(
                        "[Provider02] JWK cache still valid (304 Not Modified)."
                    )
                    return

                resp.raise_for_status()
                jwk_set = resp.json()

                self._jwk_cache = JWKCache(
                    jwk_set=jwk_set,
                    last_synced=time.time(),
                    etag=resp.headers.get("ETag", ""),
                )

                key_count = len(jwk_set.get("keys", []))
                logger.info(
                    "[Provider02] JWK cache refreshed: %d keys (etag=%s)",
                    key_count,
                    self._jwk_cache.etag[:16] if self._jwk_cache.etag else "none",
                )

        except Exception as exc:
            logger.warning(
                "[Provider02] JWK sync failed: %s — using cached keys.",
                exc,
            )

    async def _jwk_sync_loop(self) -> None:
        """Background loop: sync JWKs every _JWK_CACHE_TTL_HOURS hours."""
        while self._running:
            try:
                await asyncio.sleep(_JWK_CACHE_TTL_HOURS * 3600)
                await self._sync_jwks()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[Provider02] JWK sync loop error: %s", exc)
                await asyncio.sleep(300)  # retry in 5 minutes

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def jwk_cache_age_seconds(self) -> float:
        """Seconds since the JWK cache was last synced."""
        if self._jwk_cache.last_synced == 0:
            return float("inf")
        return time.time() - self._jwk_cache.last_synced

    @property
    def has_jwk_keys(self) -> bool:
        """True if the JWK cache has at least one key."""
        return self._jwk_cache.has_keys


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_provider: Provider02AttestationProvider | None = None


def get_provider_02() -> Provider02AttestationProvider:
    """Return the module-level Provider02AttestationProvider singleton."""
    global _provider
    if _provider is None:
        _provider = Provider02AttestationProvider()
    return _provider
