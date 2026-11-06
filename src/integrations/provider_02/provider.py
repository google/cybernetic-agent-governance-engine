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

  1. Bundle attestation via ``attest_bundle`` — seals the ``AttestationBundle``
     into a ``cer.governed.execution.v1`` CER, submits it to ``POST /api/attest``
     and verifies both Ed25519 signatures on the node's response against the
     ``kid``-resolved manifest key (see ``governed_cer.py``)
  2. CER creation via ``certifyDecision`` — wraps the raw HTTP API
  3. CER verification via locally-cached Ed25519 JWKs — inline TTL refresh and
     hard ``max_staleness_seconds`` fail-closed ceiling
  4. Attestation fetch via ``fetch_attestations`` — maps ``verify_cer`` verdicts
     to ``ExternalAttestation`` records

JWK Caching & Staleness Strategy
--------------------------------
The JWK endpoint is configured via ``PROVIDER_02_JWK_ENDPOINT`` and cached
in-memory with two monotonic bounds:

  * ``ttl_seconds`` (``PROVIDER_02_JWKS_TTL_S`` or
    ``PROVIDER_02_JWK_CACHE_TTL_HOURS * 3600``, default 24h): refresh threshold.
    Once ``age > ttl_seconds`` (``JWKCache.is_stale``) or an unknown ``kid`` is
    encountered, ``verify_cer`` and ``attest_bundle`` refresh the manifest
    inline via ``ETag`` / ``If-None-Match`` conditional GET and atomically
    replace the cached key set so revoked or removed keys are evicted.
  * ``max_staleness_seconds`` (``PROVIDER_02_JWKS_MAX_STALENESS_S``, default
    ``2 * ttl_seconds``): hard fail-closed ceiling. If a refresh fails and the
    cache age exceeds ``max_staleness_seconds``
    (``JWKCache.exceeds_max_staleness``), cached keys are evicted and
    verification/attestation fails closed with ``CER_JWKS_STALE``.

Environment variables
---------------------
  PROVIDER_02_API_ENDPOINT          — API base URL (required)
  PROVIDER_02_API_KEY_SECRET        — API key (direct or Secret Manager path)
  PROVIDER_02_ATTEST_PATH           — Attestation path (default: /api/attest)
  PROVIDER_02_JWK_ENDPOINT          — Public JWK endpoint for receipt verification
  PROVIDER_02_JWK_CACHE_TTL_HOURS   — JWK cache refresh TTL in hours (default: 24)
  PROVIDER_02_JWKS_TTL_S            — Optional JWK refresh TTL override in seconds
  PROVIDER_02_JWKS_MAX_STALENESS_S  — Hard fail-closed JWK max staleness in seconds
  PROVIDER_02_TIMEOUT_SECONDS       — Per-request timeout (default: 5.0)

Architecture precedent: follows the Provider 01 pattern in
``normative_provider.py`` — httpx.AsyncClient, timeout config, fail-closed.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.content_address import ContentAddress, ContentAddressKind
from src.gateway.governance.seams.attestation import (
    AttestationProvider,
    AttestationStatus,
    ExternalAttestation,
)
from src.integrations.provider_02.governed_cer import (
    AttestationVerdict,
    GovernedCerError,
    seal_governed_execution,
    verify_attestation,
    verify_governed_cer,
)
from src.integrations.provider_02.resolver import Provider02CERResolver

logger = logging.getLogger("cage.provider_02")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENDPOINT: str = os.environ.get("PROVIDER_02_API_ENDPOINT", "")
_API_KEY: str = os.environ.get("PROVIDER_02_API_KEY_SECRET", "")
# Default to well-known path; env var overrides for non-standard deployments
_JWK_ENDPOINT: str = os.environ.get(
    "PROVIDER_02_JWK_ENDPOINT", "/.well-known/nexart-node.json"
)
_JWK_CACHE_TTL_HOURS: float = float(
    os.environ.get("PROVIDER_02_JWK_CACHE_TTL_HOURS", "24")
)
_TIMEOUT: float = float(os.environ.get("PROVIDER_02_TIMEOUT_SECONDS", "5.0"))
_ATTEST_PATH: str = os.environ.get("PROVIDER_02_ATTEST_PATH", "/api/attest")
_VERIFY_PATH: str = os.environ.get("PROVIDER_02_VERIFY_PATH", "/v1/cer/verify")


def _default_jwk_ttl_seconds() -> float:
    """Resolve default JWK refresh TTL in seconds from environment."""
    raw_seconds = os.environ.get("PROVIDER_02_JWKS_TTL_S")
    if raw_seconds is not None and raw_seconds.strip():
        return float(raw_seconds)
    return _JWK_CACHE_TTL_HOURS * 3600.0


def _default_jwk_max_staleness_seconds(ttl_seconds: float) -> float:
    """Resolve default hard fail-closed JWK max staleness ceiling in seconds."""
    raw_max = os.environ.get("PROVIDER_02_JWKS_MAX_STALENESS_S")
    if raw_max is not None and raw_max.strip():
        return float(raw_max)
    return ttl_seconds * 2.0


def _node_rejection(status: int, body: Any) -> tuple[str, str]:
    """Map a non-200 ``/api/attest`` response to a ``(code, error)`` pair.

    The node returns ``{"error": ..., "reasonCode": ..., "details": [...]}``;
    ``reasonCode`` is the most specific and wins over ``error``.
    """
    if not isinstance(body, dict):
        return f"HTTP_{status}", f"node returned HTTP {status} without a JSON body"
    code = str(body.get("reasonCode") or body.get("error") or f"HTTP_{status}")
    details = body.get("details")
    if isinstance(details, list) and details:
        error = "; ".join(str(d) for d in details)
    else:
        error = str(body.get("message") or body.get("error") or f"HTTP {status}")
    return code, error


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
    """Bounded in-memory cache of Provider 02's public JWK set.

    Tracks both a soft refresh threshold (``ttl_seconds``) and a hard fail-closed
    staleness ceiling (``max_staleness_seconds``). Freshness is measured via
    ``time.monotonic()`` when ``fetched_at_monotonic`` is recorded (falling back
    to ``last_synced`` wall-clock timestamps when constructed directly in tests).
    """

    jwk_set: dict[str, Any] = field(default_factory=dict)
    last_synced: float = 0.0
    etag: str = ""
    ttl_seconds: float = field(default_factory=_default_jwk_ttl_seconds)
    max_staleness_seconds: float | None = None
    fetched_at_monotonic: float | None = None

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError(
                f"JWKCache ttl_seconds must be positive, got {self.ttl_seconds}"
            )
        resolved_max = (
            _default_jwk_max_staleness_seconds(self.ttl_seconds)
            if self.max_staleness_seconds is None
            else self.max_staleness_seconds
        )
        if resolved_max < self.ttl_seconds:
            raise ValueError(
                f"JWKCache max_staleness_seconds ({resolved_max}) "
                f"must be >= ttl_seconds ({self.ttl_seconds})"
            )
        self.max_staleness_seconds = resolved_max

    @property
    def effective_max_staleness_seconds(self) -> float:
        """Hard fail-closed staleness ceiling in seconds."""
        if self.max_staleness_seconds is None:
            return _default_jwk_max_staleness_seconds(self.ttl_seconds)
        return self.max_staleness_seconds

    @property
    def was_synced(self) -> bool:
        """True if this cache has ever completed a JWK sync."""
        return self.fetched_at_monotonic is not None or self.last_synced > 0.0

    @property
    def age_seconds(self) -> float:
        """Elapsed seconds since the JWK set was last synced."""
        if self.fetched_at_monotonic is not None:
            return time.monotonic() - self.fetched_at_monotonic
        if self.last_synced > 0.0:
            return time.time() - self.last_synced
        return float("inf")

    @property
    def is_stale(self) -> bool:
        """True when the cache has never synced or exceeded ``ttl_seconds``."""
        return self.age_seconds > self.ttl_seconds

    @property
    def exceeds_max_staleness(self) -> bool:
        """True when the cache has never synced or exceeded ``max_staleness_seconds``."""
        return self.age_seconds > self.effective_max_staleness_seconds

    @property
    def is_expired(self) -> bool:
        """Alias for ``exceeds_max_staleness``."""
        return self.exceeds_max_staleness

    @property
    def has_keys(self) -> bool:
        return bool(self.jwk_set.get("keys"))

    def contains_kid(self, kid: str) -> bool:
        """True if ``kid`` appears in the cached key manifest entries."""
        if not kid:
            return False
        keys = self.jwk_set.get("keys")
        if not isinstance(keys, list):
            return False
        return any(
            isinstance(entry, dict) and entry.get("kid") == kid for entry in keys
        )


# ---------------------------------------------------------------------------
# Provider 02 Attestation Provider
# ---------------------------------------------------------------------------


class Provider02AttestationProvider(AttestationProvider):
    """Provider 02 attestation provider for CER creation and verification.

    Implements the ``AttestationProvider`` protocol from
    ``src.gateway.governance.seams.attestation``.

    JWK manifests are refreshed inline on ``verify_cer`` and ``attest_bundle``
    whenever the cache is empty, ``is_stale`` (``age > ttl_seconds``), or missing
    the requested ``kid``, and fail closed with ``CER_JWKS_STALE`` if refresh
    fails once ``age > max_staleness_seconds``.

    Usage::

        provider = Provider02AttestationProvider()

        # Fetch attestations (AttestationProvider protocol)
        attestations = await provider.fetch_attestations({"certificate_hash": cer_hash})

        # Create a CER (provider-specific)
        cer = await provider.certify_decision(evidence_payload)

        # Verify a CER (uses TTL-bounded cached JWKs)
        result = await provider.verify_cer(cer.certificate_hash)

        # Attest a completed bundle (provider-specific)
        verdict = await provider.attest_bundle(bundle_dict)
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        jwk_endpoint: str = "",
        timeout: float = _TIMEOUT,
        jwk_ttl_seconds: float | None = None,
        jwk_max_staleness_seconds: float | None = None,
    ) -> None:
        self._endpoint = (endpoint or _ENDPOINT).rstrip("/")
        self._api_key = api_key or _API_KEY
        self._jwk_endpoint = jwk_endpoint or _JWK_ENDPOINT
        self._timeout = timeout
        resolved_ttl = (
            _default_jwk_ttl_seconds() if jwk_ttl_seconds is None else jwk_ttl_seconds
        )
        self._jwk_cache = JWKCache(
            ttl_seconds=resolved_ttl,
            max_staleness_seconds=jwk_max_staleness_seconds,
        )

        # mTLS configuration
        self._client_cert = os.getenv("PROVIDER_02_CLIENT_CERT", "")
        self._client_key = os.getenv("PROVIDER_02_CLIENT_KEY", "")
        self._ca_bundle = os.getenv("PROVIDER_02_CA_BUNDLE", "")

        self._attest_path = _ATTEST_PATH
        self._verify_path = _VERIFY_PATH

        # CER resolver for fetching receipts during verification
        # Extract base URL without the /v1 suffix if present
        resolver_base_url = (
            self._endpoint.rsplit("/v1", 1)[0]
            if self._endpoint.endswith("/v1")
            else self._endpoint
        )
        self._resolver = Provider02CERResolver(
            base_url=resolver_base_url,
            timeout=self._timeout,
        )

        if not self._endpoint:
            logger.warning(
                "[Provider02] PROVIDER_02_API_ENDPOINT not set. "
                "Attestation calls will fail."
            )

        logger.info(
            "[Provider02] Initialised: endpoint=%s jwk=%s timeout=%.1fs "
            "ttl=%.1fs max_staleness=%.1fs",
            self._endpoint or "(not set)",
            self._jwk_endpoint or "(not set)",
            self._timeout,
            self._jwk_cache.ttl_seconds,
            self._jwk_cache.effective_max_staleness_seconds,
        )

    @classmethod
    def from_env(cls) -> Provider02AttestationProvider:
        """Instantiate provider from environment variables."""
        return cls()

    def _build_httpx_kwargs(self) -> dict[str, Any]:
        """Build httpx.AsyncClient configuration with optional mTLS."""
        kwargs: dict[str, Any] = {"timeout": self._timeout}

        # mTLS client certificate
        if self._client_cert and self._client_key:
            kwargs["cert"] = (self._client_cert, self._client_key)
            logger.debug(
                "[Provider02] mTLS enabled: cert=%s key=%s",
                self._client_cert,
                self._client_key,
            )

        # Server verification (CA bundle or system trust)
        if self._ca_bundle:
            kwargs["verify"] = self._ca_bundle
            logger.debug("[Provider02] Custom CA bundle: %s", self._ca_bundle)
        else:
            kwargs["verify"] = True  # Use system trust store

        return kwargs

    def _headers(self) -> dict[str, str]:
        """Authorization headers."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _b64url_decode_unpadded(s: str) -> bytes:
        """Decode base64url without padding.

        Ed25519 signatures are 64 bytes, encoded as 86-character base64url
        strings with no padding. Python's base64.urlsafe_b64decode requires
        padding, so we add it back before decoding.
        """
        # Add padding if needed (base64 requires length to be multiple of 4)
        padding = (4 - len(s) % 4) % 4
        return base64.urlsafe_b64decode(s + "=" * padding)

    def _resolve_public_key(self, kid: str) -> Ed25519PublicKey | None:
        """Resolve an Ed25519 public key from the JWK cache by kid.

        This is the ONLY function that can produce an Ed25519PublicKey for
        verification. Accepting the key as a parameter would allow the embedded
        key from the response to reach the verifier, which would be security
        theatre.

        Refuses any cached key once ``exceeds_max_staleness`` is True so an
        expired warm cache cannot be converted into key validity during a JWKS
        outage.

        Args:
            kid: Key ID to resolve

        Returns:
            Ed25519PublicKey if found and within ``max_staleness_seconds``, None otherwise
        """
        if not self._jwk_cache.has_keys:
            return None
        if self._jwk_cache.exceeds_max_staleness:
            logger.error(
                "[Provider02] Refusing cached key %s: JWK cache age %.1fs "
                "exceeds max_staleness_seconds %.1fs",
                kid,
                self._jwk_cache.age_seconds,
                self._jwk_cache.effective_max_staleness_seconds,
            )
            return None

        for entry in self._jwk_cache.jwk_set.get("keys", []):
            if not isinstance(entry, dict) or entry.get("kid") != kid:
                continue
            # The node manifest wraps each key as
            # ``{kid, alg, status, revoked, publicKeyJwk: {kty, crv, x}}``;
            # a bare JWK (``{kid, kty, crv, x}``) is also accepted.
            if (
                entry.get("revoked") is True
                or entry.get("status", "active") != "active"
            ):
                logger.warning("[Provider02] Key %s is revoked or inactive", kid)
                return None
            jwk = entry.get("publicKeyJwk", entry)
            if not isinstance(jwk, dict):
                return None
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                logger.warning(
                    "[Provider02] Key %s is not OKP/Ed25519 (kty=%s, crv=%s)",
                    kid,
                    jwk.get("kty"),
                    jwk.get("crv"),
                )
                continue

            # Decode the public key bytes from base64url
            x_b64url = jwk.get("x", "")
            if not x_b64url:
                logger.warning("[Provider02] Key %s missing 'x' parameter", kid)
                continue

            try:
                key_bytes = self._b64url_decode_unpadded(x_b64url)
                return Ed25519PublicKey.from_public_bytes(key_bytes)
            except Exception as exc:
                logger.warning("[Provider02] Failed to load key %s: %s", kid, exc)
                return None

        return None

    async def _ensure_fresh_jwks(
        self,
        kid: str | None = None,
        *,
        already_synced: bool = False,
    ) -> bool:
        """Refresh JWKs inline when stale or missing ``kid``; check max staleness.

        Args:
            kid: Optional key ID expected in the manifest.
            already_synced: True if ``_sync_jwks()`` already ran in this call.

        Returns:
            True if ``self._jwk_cache`` is within ``max_staleness_seconds`` after
            any sync attempt; False if stale past ``max_staleness_seconds``.
        """
        needs_sync = not already_synced and (
            not self._jwk_cache.has_keys
            or self._jwk_cache.is_stale
            or (kid is not None and not self._jwk_cache.contains_kid(kid))
        )
        if needs_sync:
            await self._sync_jwks()
        return not self._jwk_cache.exceeds_max_staleness

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

        Wraps ``verify_cer`` and maps the verification outcome to
        ``ExternalAttestation``.

        Args:
            context: Governance context dict. Expected keys:
                - certificate_hash: str (required for CER verification)

        Returns:
            List of ExternalAttestation entries.
        """
        certificate_hash = context.get("certificate_hash", "")
        if not certificate_hash:
            logger.warning(
                "[Provider02] fetch_attestations called without certificate_hash — "
                "returning empty attestation list."
            )
            return []

        result = await self.verify_cer(certificate_hash)

        # Status mapping:
        #   - valid=True, signature_checked=True  → VERIFIED (Wave 3 / B3)
        #   - valid=False, signature_checked=False, error contains "Phase 2b" → UNVERIFIED
        #   - valid=False, signature_checked=False, error is real failure → ERROR
        status = AttestationStatus.UNVERIFIED

        if result.valid and result.signature_checked:
            status = AttestationStatus.VERIFIED
        elif (
            result.error
            and "Phase 2b" not in result.error
            and "not yet implemented" not in result.error
        ):
            status = AttestationStatus.ERROR

        attestation = ExternalAttestation(
            attestation_type="CER",
            status=status.value,
            receipt_id=certificate_hash[:16],  # First 16 chars as receipt ID
            attested_at=result.timestamp or "",
            provider_name="provider_02",
            metadata={
                "signer": result.signer,
                "key_id": result.key_id,
                "signature_checked": result.signature_checked,
                "error": result.error,
            },
        )

        return [attestation]

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
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
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
    # CER verification (TTL-bounded cached JWKs, fail-closed on staleness)
    # ------------------------------------------------------------------

    async def verify_cer(
        self, certificate_hash: str, cer_body: dict[str, Any] | None = None
    ) -> CERVerification:
        """Verify a CER with two-stage Ed25519 signature verification.

        Stage 1: Certificate-hash binding (SHA-256 recomputation)
        Stage 2: Envelope signature (Ed25519 verification against fresh JWK set)

        Both stages must pass before valid=True and signature_checked=True are set.

        Args:
            certificate_hash: SHA-256 hex digest of the certificate payload
            cer_body: Optional CER body (for testing). If None, resolves via content address.

        Returns:
            CERVerification with valid=True only if both stages pass
        """
        # Early validation: SHA-256 hex length
        if len(certificate_hash) != 64:
            return CERVerification(
                valid=False,
                signature_checked=False,
                error=f"Invalid certificate hash length: {len(certificate_hash)} (expected 64)",
            )

        # Inline JWK sync when cold or past refresh TTL (F-110 Defect A)
        synced_on_entry = False
        if not self._jwk_cache.has_keys or self._jwk_cache.is_stale:
            await self._sync_jwks()
            synced_on_entry = True

        # Fail closed when a warm cache exceeded max_staleness_seconds and refresh failed (F-110 Defect B)
        if self._jwk_cache.was_synced and self._jwk_cache.exceeds_max_staleness:
            return CERVerification(
                valid=False,
                signature_checked=False,
                error=(
                    "CER_JWKS_STALE: cached JWK set exceeded max_staleness_seconds "
                    "and refresh from JWK endpoint failed"
                ),
            )

        # Cold cache that has never loaded keys: fail-closed remote diagnostic fallback
        if not self._jwk_cache.was_synced and not self._jwk_cache.has_keys:
            if cer_body is None:
                return await self._verify_remote(certificate_hash)
            return CERVerification(
                valid=False,
                signature_checked=False,
                error="CER_JWKS_STALE: JWK cache unavailable and initial sync failed",
            )

        # If CER body not provided, resolve it
        if cer_body is None:
            try:
                address = ContentAddress(
                    algorithm="sha256",
                    hex_digest=certificate_hash,
                    kind=ContentAddressKind.DIGEST,  # type: ignore
                )
            except Exception as exc:
                return CERVerification(
                    valid=False,
                    signature_checked=False,
                    error=f"Invalid content address: {exc}",
                )

            resolution = await self._resolver.resolve(address)
            if not resolution.resolved:
                return CERVerification(
                    valid=False,
                    signature_checked=False,
                    error=f"CER resolution failed: {resolution.findings}",
                )

            cer_body = resolution.evidence

        return await self._verify_two_stage(
            certificate_hash, cer_body, already_synced=synced_on_entry
        )

    async def _verify_two_stage(
        self,
        certificate_hash: str,
        cer_body: dict[str, Any],
        *,
        already_synced: bool = False,
    ) -> CERVerification:
        """Perform two-stage verification: hash binding + signature.

        Stage 1: Verify SHA-256(canonical.certificate.payload) == certificate_hash
        Stage 2: Verify Ed25519 signature over canonical.envelope.payload

        Args:
            certificate_hash: Expected SHA-256 hex digest
            cer_body: Full CER JSON structure
            already_synced: True if ``verify_cer`` already refreshed JWKs on entry

        Returns:
            CERVerification with valid=True only if BOTH stages pass
        """
        canonical = cer_body.get("canonical", {})
        certificate = canonical.get("certificate", {})
        envelope = canonical.get("envelope", {})
        verification_envelope = cer_body.get("verification", {})

        # --- Stage 1: Certificate-hash binding ---

        # Check matchesCertificateHash self-attestation
        if not certificate.get("matchesCertificateHash"):
            return CERVerification(
                valid=False,
                signature_checked=False,
                error="CER self-attestation failed: matchesCertificateHash is false",
            )

        # Recompute the certificate hash
        cert_payload = certificate.get("payload", "")
        if not cert_payload:
            return CERVerification(
                valid=False,
                signature_checked=False,
                error="CER_DIGEST_MISMATCH: canonical.certificate.payload is missing",
            )

        computed_hash = hashlib.sha256(cert_payload.encode("utf-8")).hexdigest()
        if computed_hash != certificate_hash:
            logger.error(
                "[Provider02] Certificate hash mismatch: expected %s, got %s",
                certificate_hash,
                computed_hash,
            )
            return CERVerification(
                valid=False,
                signature_checked=False,
                error=f"CER_DIGEST_MISMATCH: expected {certificate_hash}, got {computed_hash}",
            )

        # --- Stage 2: Envelope signature verification ---

        kid = envelope.get("kid", "")
        if not kid:
            return CERVerification(
                valid=False,
                signature_checked=False,
                error="CER_SIGNATURE_INVALID: envelope.kid is missing",
            )

        # Ensure JWKs are fresh or re-synced for unknown kid; fail closed on max staleness
        if not await self._ensure_fresh_jwks(kid, already_synced=already_synced):
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error=(
                    "CER_JWKS_STALE: cached JWK set exceeded max_staleness_seconds "
                    "and refresh from JWK endpoint failed"
                ),
            )

        # Resolve the public key from the JWK cache (ONLY source of keys)
        public_key = self._resolve_public_key(kid)
        if public_key is None:
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error=f"CER_UNKNOWN_KEY: kid '{kid}' not found in key manifest",
            )

        # Extract signature and payload
        signature_b64url = verification_envelope.get(
            "verificationEnvelopeSignature", ""
        )
        if not signature_b64url:
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error="CER_SIGNATURE_INVALID: verificationEnvelopeSignature is missing",
            )

        envelope_payload = envelope.get("payload", "")
        if not envelope_payload:
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error="CER_SIGNATURE_INVALID: canonical.envelope.payload is missing",
            )

        # Decode the signature (base64url, unpadded)
        try:
            signature_bytes = self._b64url_decode_unpadded(signature_b64url)
        except Exception as exc:
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error=f"CER_SIGNATURE_INVALID: failed to decode signature: {exc}",
            )

        # Verify the Ed25519 signature
        try:
            public_key.verify(signature_bytes, envelope_payload.encode("utf-8"))
        except InvalidSignature:
            logger.error(
                "[Provider02] Ed25519 signature verification failed for kid=%s", kid
            )
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error="CER_SIGNATURE_INVALID: Ed25519 verification failed",
            )
        except Exception as exc:
            logger.error(
                "[Provider02] Signature verification error for kid=%s: %s", kid, exc
            )
            return CERVerification(
                valid=False,
                signature_checked=False,
                key_id=kid,
                error=f"CER_SIGNATURE_INVALID: {exc}",
            )

        # Both stages passed — return verified
        logger.info(
            "[Provider02] CER verified: hash=%s… kid=%s",
            certificate_hash[:16],
            kid,
        )
        return CERVerification(
            valid=True,
            signature_checked=True,
            key_id=kid,
            signer=envelope.get("signer", ""),
            timestamp=cer_body.get("timestamp", {}).get("attestedAt", ""),
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
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                return CERVerification(
                    valid=False,  # Fail closed
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
    # Bundle attestation (POST /api/attest)
    # ------------------------------------------------------------------

    def _base_url(self) -> str:
        """API base URL without a trailing ``/v1`` segment."""
        if self._endpoint.endswith("/v1"):
            return self._endpoint.rsplit("/v1", 1)[0]
        return self._endpoint

    async def attest_bundle(
        self,
        bundle: Mapping[str, Any],
        topology: Mapping[str, Any] | None = None,
    ) -> AttestationVerdict:
        """Seal ``bundle`` into a governed CER, attest it and verify the receipt.

        Args:
            bundle: Serialized ``AttestationBundle`` (``bundle.to_dict()``).
            topology: Optional wire topology (``topology_to_wire()``). When
                supplied, the node must report ``topologyValidation: valid``.

        Returns:
            An ``AttestationVerdict``. ``verified`` is True only when the node
            accepted the CER *and* CAGE verified both Ed25519 signatures against
            a fresh ``kid``-resolved manifest key. Transport errors, stale JWK
            caches exceeding ``max_staleness_seconds``, and node rejections
            return a non-verified verdict; this method never raises.
        """
        import httpx

        try:
            cer = seal_governed_execution(bundle, topology)
        except GovernedCerError as exc:
            return AttestationVerdict.reject("CER_SEAL_FAILED", str(exc))
        certificate_hash = str(cer["certificateHash"])

        url = f"{self._base_url()}{self._attest_path}"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.post(url, json=cer, headers=self._headers())
        except httpx.HTTPError as exc:
            logger.error("[Provider02] attest failed: %s %s", url, exc)
            return AttestationVerdict.reject(
                "TRANSPORT_ERROR", str(exc), certificate_hash
            )

        try:
            body: Any = resp.json()
        except ValueError:
            body = None
        if resp.status_code != 200 or not isinstance(body, dict):
            code, error = _node_rejection(resp.status_code, body)
            logger.warning(
                "[Provider02] attest rejected: status=%d code=%s",
                resp.status_code,
                code,
            )
            return AttestationVerdict.reject(code, error, certificate_hash)

        synced_on_entry = False
        if not self._jwk_cache.has_keys or self._jwk_cache.is_stale:
            await self._sync_jwks()
            synced_on_entry = True

        if self._jwk_cache.exceeds_max_staleness:
            return AttestationVerdict.reject(
                "CER_JWKS_STALE",
                "cached JWK set exceeded max_staleness_seconds and refresh failed",
                certificate_hash,
            )

        supplied = topology is not None
        verdict = verify_attestation(
            cer, body, self._resolve_public_key, topology_supplied=supplied
        )
        if verdict.code == "UNKNOWN_KEY" and not synced_on_entry:
            await self._sync_jwks()
            if self._jwk_cache.exceeds_max_staleness:
                return AttestationVerdict.reject(
                    "CER_JWKS_STALE",
                    "cached JWK set exceeded max_staleness_seconds and refresh failed",
                    certificate_hash,
                )
            verdict = verify_attestation(
                cer, body, self._resolve_public_key, topology_supplied=supplied
            )
        return verdict

    async def verify_bundle(
        self,
        bundle: Mapping[str, Any],
        topology: Mapping[str, Any] | None = None,
    ) -> AttestationVerdict:
        """Seal ``bundle`` into a governed CER and verify it via ``POST /v1/cer/verify``.

        This is the node's stateless, non-persisting verification route. It
        validates CER integrity, CAGE schema, causal graph, wire topology (when
        supplied) and resource safety, and confirms RFC 8785 JCS hash parity
        without persisting a certificate on the node.
        """
        import httpx

        try:
            cer = seal_governed_execution(bundle, topology)
        except GovernedCerError as exc:
            return AttestationVerdict.reject("CER_SEAL_FAILED", str(exc))
        certificate_hash = str(cer["certificateHash"])

        url = f"{self._base_url()}{self._verify_path}"
        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                resp = await client.post(
                    url, json={"bundle": cer}, headers=self._headers()
                )
        except httpx.HTTPError as exc:
            logger.error("[Provider02] verify_bundle failed: %s %s", url, exc)
            return AttestationVerdict.reject(
                "TRANSPORT_ERROR", str(exc), certificate_hash
            )

        try:
            body: Any = resp.json()
        except ValueError:
            body = None
        if resp.status_code != 200 or not isinstance(body, dict):
            code, error = _node_rejection(resp.status_code, body)
            logger.warning(
                "[Provider02] verify_bundle HTTP error: status=%d code=%s",
                resp.status_code,
                code,
            )
            return AttestationVerdict.reject(code, error, certificate_hash)

        return verify_governed_cer(cer, body, topology_supplied=topology is not None)

    # ------------------------------------------------------------------
    # Inline JWK synchronization
    # ------------------------------------------------------------------

    def _evict_expired_jwks(self) -> None:
        """Atomically clear cached keys and ETag once ``max_staleness_seconds`` elapses."""
        self._jwk_cache = JWKCache(
            jwk_set={},
            last_synced=self._jwk_cache.last_synced,
            etag="",
            ttl_seconds=self._jwk_cache.ttl_seconds,
            max_staleness_seconds=self._jwk_cache.effective_max_staleness_seconds,
            fetched_at_monotonic=self._jwk_cache.fetched_at_monotonic,
        )

    async def _sync_jwks(self) -> None:
        """Fetch the Provider 02 public JWK set and atomically replace the local cache."""
        ttl_seconds = self._jwk_cache.ttl_seconds
        max_staleness_seconds = self._jwk_cache.effective_max_staleness_seconds

        if not self._jwk_endpoint:
            if self._jwk_cache.was_synced and self._jwk_cache.exceeds_max_staleness:
                self._evict_expired_jwks()
            return

        import httpx

        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                headers: dict[str, str] = {}
                if self._jwk_cache.etag and self._jwk_cache.has_keys:
                    headers["If-None-Match"] = self._jwk_cache.etag

                # Construct full URL: if jwk_endpoint is relative, prepend base endpoint
                jwk_url = self._jwk_endpoint
                if self._jwk_endpoint.startswith("/"):
                    base = (
                        self._endpoint.rsplit("/v1", 1)[0]
                        if self._endpoint.endswith("/v1")
                        else self._endpoint
                    )
                    jwk_url = f"{base}{self._jwk_endpoint}"

                resp = await client.get(jwk_url, headers=headers)

                if resp.status_code == 304:
                    if "If-None-Match" not in headers or not self._jwk_cache.has_keys:
                        raise ValueError(
                            "unexpected HTTP 304 without cached ETag and keys"
                        )
                    self._jwk_cache = JWKCache(
                        jwk_set={"keys": list(self._jwk_cache.jwk_set.get("keys", []))},
                        last_synced=time.time(),
                        etag=self._jwk_cache.etag,
                        ttl_seconds=ttl_seconds,
                        max_staleness_seconds=max_staleness_seconds,
                        fetched_at_monotonic=time.monotonic(),
                    )
                    logger.debug(
                        "[Provider02] JWK cache still valid (304 Not Modified)."
                    )
                    return

                resp.raise_for_status()
                jwk_set = resp.json()
                if not isinstance(jwk_set, dict) or not isinstance(
                    jwk_set.get("keys"), list
                ):
                    raise ValueError("key manifest has no 'keys' list")

                # Atomic full-set replacement (never mutates/merges old keys)
                fresh_keys = list(jwk_set["keys"])
                self._jwk_cache = JWKCache(
                    jwk_set={"keys": fresh_keys},
                    last_synced=time.time(),
                    etag=resp.headers.get("ETag", ""),
                    ttl_seconds=ttl_seconds,
                    max_staleness_seconds=max_staleness_seconds,
                    fetched_at_monotonic=time.monotonic(),
                )

                logger.info(
                    "[Provider02] JWK cache refreshed: %d keys (etag=%s)",
                    len(fresh_keys),
                    self._jwk_cache.etag[:16] if self._jwk_cache.etag else "none",
                )

        except Exception as exc:
            if self._jwk_cache.was_synced and self._jwk_cache.exceeds_max_staleness:
                self._evict_expired_jwks()
                logger.error(
                    "[Provider02] JWK sync failed (%s) and cache exceeded "
                    "max_staleness_seconds (%.1fs) — evicted stale keys (fail-closed).",
                    exc,
                    max_staleness_seconds,
                )
            elif self._jwk_cache.has_keys:
                logger.warning(
                    "[Provider02] JWK sync failed (%s) — retaining cached keys "
                    "within max staleness window (age=%.1fs, max=%.1fs).",
                    exc,
                    self._jwk_cache.age_seconds,
                    max_staleness_seconds,
                )
            else:
                logger.warning(
                    "[Provider02] Initial JWK sync failed (%s) — cache remains empty.",
                    exc,
                )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def jwk_cache_age_seconds(self) -> float:
        """Seconds since the JWK cache was last synced."""
        return self._jwk_cache.age_seconds

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
