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
  3. CER verification via locally-cached Ed25519 JWKs — no hot-path network call
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
  PROVIDER_02_ATTEST_PATH        — Attestation path (default: /api/attest)
  PROVIDER_02_JWK_ENDPOINT       — Public JWK endpoint for receipt verification
  PROVIDER_02_JWK_CACHE_TTL_HOURS — JWK cache TTL (default: 24)
  PROVIDER_02_TIMEOUT_SECONDS    — Per-request timeout (default: 5.0)

Architecture precedent: follows the Provider 01 pattern in
``normative_provider.py`` — httpx.AsyncClient, timeout config, fail-closed.
"""

from __future__ import annotations

import asyncio
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

        # Attest a completed bundle (provider-specific)
        verdict = await provider.attest_bundle(bundle_dict)
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
            "[Provider02] Initialised: endpoint=%s jwk=%s timeout=%.1fs",
            self._endpoint or "(not set)",
            self._jwk_endpoint or "(not set)",
            self._timeout,
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

        Args:
            kid: Key ID to resolve

        Returns:
            Ed25519PublicKey if found in cache, None otherwise
        """
        if not self._jwk_cache.has_keys:
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
        elif (
            result.error
            and "Phase 2b" not in result.error
            and "not yet implemented" not in result.error
        ):
            # Real errors (network failures, parse errors, etc.) → ERROR
            # But "Phase 2b pending" messages → UNVERIFIED
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
    # CER verification (local — uses cached JWKs)
    # ------------------------------------------------------------------

    async def verify_cer(
        self, certificate_hash: str, cer_body: dict[str, Any] | None = None
    ) -> CERVerification:
        """Verify a CER with two-stage Ed25519 signature verification.

        Stage 1: Certificate-hash binding (SHA-256 recomputation)
        Stage 2: Envelope signature (Ed25519 verification)

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

        # Fallback to remote verification if JWK cache is empty
        if not self._jwk_cache.has_keys:
            return await self._verify_remote(certificate_hash)

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

        return await self._verify_two_stage(certificate_hash, cer_body)

    async def _verify_two_stage(
        self, certificate_hash: str, cer_body: dict[str, Any]
    ) -> CERVerification:
        """Perform two-stage verification: hash binding + signature.

        Stage 1: Verify SHA-256(canonical.certificate.payload) == certificate_hash
        Stage 2: Verify Ed25519 signature over canonical.envelope.payload

        Args:
            certificate_hash: Expected SHA-256 hex digest
            cer_body: Full CER JSON structure

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

        # Resolve the public key from the JWK cache (ONLY source of keys)
        public_key = self._resolve_public_key(kid)
        if public_key is None:
            # Unknown kid: try one refresh, then fail closed
            logger.info("[Provider02] Unknown kid %s — refreshing JWK cache", kid)
            await self._sync_jwks()
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
            the ``kid``-resolved manifest key. Transport errors and node
            rejections return a non-verified verdict; this method never raises.
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

        if not self._jwk_cache.has_keys or self._jwk_cache.is_stale:
            await self._sync_jwks()
        supplied = topology is not None
        verdict = verify_attestation(
            cer, body, self._resolve_public_key, topology_supplied=supplied
        )
        if verdict.code == "UNKNOWN_KEY":
            # The node may have rotated keys since the last sync. Refresh the
            # independently fetched manifest once; never trust a key from the
            # response itself.
            await self._sync_jwks()
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
    # JWK sync daemon
    # ------------------------------------------------------------------

    async def _sync_jwks(self) -> None:
        """Fetch the Provider 02 public JWK set and update the local cache."""
        if not self._jwk_endpoint:
            return

        import httpx

        try:
            async with httpx.AsyncClient(**self._build_httpx_kwargs()) as client:
                headers = {}
                if self._jwk_cache.etag:
                    headers["If-None-Match"] = self._jwk_cache.etag

                # Construct full URL: if jwk_endpoint is relative, prepend base endpoint
                jwk_url = self._jwk_endpoint
                if self._jwk_endpoint.startswith("/"):
                    # Relative path - construct full URL from base endpoint
                    # Extract base from _endpoint (without /v1 suffix if present)
                    base = (
                        self._endpoint.rsplit("/v1", 1)[0]
                        if self._endpoint.endswith("/v1")
                        else self._endpoint
                    )
                    jwk_url = f"{base}{self._jwk_endpoint}"

                resp = await client.get(jwk_url, headers=headers)

                if resp.status_code == 304:
                    # Not modified — cache is still valid
                    self._jwk_cache.last_synced = time.time()
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
