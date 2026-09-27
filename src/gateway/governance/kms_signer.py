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
kms_signer.py — Multi-Cloud KMS Asymmetric Governance Signer (Layer 1 Kernel)
=============================================================================

Provides asymmetric signing and verification for governance plans and batches.
Cloud KMS provider adapters reside in Layer 3 (`src/integrations/*/kms_provider.py`)
and are loaded lazily through `src.gateway.governance.signer_factory`.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from opentelemetry import trace as otel_trace

from src.gateway.governance.env_posture import is_enforcing, resolve_posture
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("Gateway.Governance.KMSSigner")
_tracer = otel_trace.get_tracer(__name__)

# ---------------------------------------------------------------------------
# Global Configuration (Module-level for mock support in unit tests)
# ---------------------------------------------------------------------------

_KMS_KEY_VERSION: str = os.environ.get("KMS_GOVERNANCE_KEY", "")
_PUBLIC_PEM_PATH: str = os.environ.get("KMS_GOVERNANCE_PUBLIC_PEM", "")

# Maximum age of a KMS-signed payload before it is rejected as stale (seconds).
# Payloads older than this threshold are rejected to prevent replay attacks.
MAX_KMS_PAYLOAD_AGE_SECONDS: int = 300

_FORBIDDEN_ENFORCING_ALGORITHMS: frozenset[str] = frozenset(
    {
        "HMAC_SHA256_FALLBACK",
        "HS256",
        "SOFTWARE_ED25519",
    }
)


def _is_forbidden_enforcing_alg(alg: str | None) -> bool:
    if not alg:
        return False
    cleaned = alg.strip()
    return cleaned in _FORBIDDEN_ENFORCING_ALGORITHMS or cleaned.startswith("HMAC_")


def _canonicalise_plan(plan: dict[str, Any]) -> bytes:
    """Produce a deterministic byte representation of a governance plan.
    Uses RFC 8785 JCS (JSON Canonicalization Scheme) to prevent cross-language
    float drift during signature verification."""
    return jcs_canonicalize_plan(plan)


# ---------------------------------------------------------------------------
# Abstract KMS Provider Strategy & Hermetic Software Providers
# ---------------------------------------------------------------------------


class BaseKMSProvider(abc.ABC):
    """Abstract base provider for HSM and hermetic asymmetric signing."""

    @abc.abstractmethod
    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a pre-hashed digest (width per ``digest_algorithm``) returning
        signature bytes."""

    @abc.abstractmethod
    def sign_raw(self, message: bytes) -> bytes:
        """Sign a raw message directly (used for PureEdDSA / Ed25519) returning
        signature bytes."""

    @abc.abstractmethod
    def get_public_key_pem(self) -> bytes:
        """Fetch the public key PEM from the provider."""

    def get_public_keys_pem(self) -> dict[str, bytes]:
        """Fetch all active public key PEMs keyed by ``kid``."""
        return {self.key_id: self.get_public_key_pem()}

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Returns provider name identifier for telemetry."""

    @property
    def digest_algorithm(self) -> str:
        """hashlib algorithm name for the digest this provider expects.

        Defaults to "sha256"; providers whose key requires a different
        digest width or raw message override this.
        """
        return "sha256"

    @property
    def expects_raw_message(self) -> bool:
        """True if the provider signs raw unhashed messages (e.g. Ed25519)."""
        return self.digest_algorithm == "raw"

    @property
    def jose_alg(self) -> str:
        """Return the RFC 7518 JOSE algorithm identifier for this provider."""
        if self.digest_algorithm == "raw":
            return "EdDSA"
        if self.digest_algorithm == "sha256":
            return "ES256"
        if self.digest_algorithm == "sha384":
            return "ES384"
        if self.digest_algorithm == "sha512":
            return "PS512"
        logger.warning(
            "[KMSSigner] Unknown digest algorithm %s, defaulting to ES256",
            self.digest_algorithm,
        )
        return "ES256"

    @property
    def uses_rsa_pss(self) -> bool:
        """True if the provider's RSA signature uses PSS padding."""
        try:
            return self.jose_alg.startswith("PS")
        except Exception:
            return False

    @property
    def is_software_fallback(self) -> bool:
        """True for local software providers forbidden in enforcing postures."""
        return False

    @property
    def key_id(self) -> str:
        """Active key identifier (`kid`) for this provider."""
        return (
            getattr(self, "_key_version_name", "")
            or getattr(self, "_key_id", "")
            or "default"
        )

    def warm_channel(self) -> None:
        """Optional transport pre-warm hook invoked during initialization."""
        return None

    def validate_ready(self, key_version_name: str = "") -> None:
        """Probe provider readiness; raises RuntimeError on failure."""
        self.get_public_key_pem()


class SoftwareHMACProvider(BaseKMSProvider):
    """Hermetic symmetric HMAC-SHA256 provider for non-enforcing development/test only."""

    def __init__(
        self,
        secret: bytes | str | None = None,
        key_id: str = "dev-hmac-01",
    ) -> None:
        raw_secret = secret or os.environ.get(
            "GOVERNANCE_HMAC_SECRET", "cage-hermetic-dev-hmac-key"
        )
        self._secret: bytes = (
            raw_secret.encode("utf-8") if isinstance(raw_secret, str) else raw_secret
        )
        self._key_id = key_id

    @property
    def provider_name(self) -> str:
        return "HMAC_SHA256_FALLBACK"

    @property
    def digest_algorithm(self) -> str:
        return "raw"

    @property
    def expects_raw_message(self) -> bool:
        return True

    @property
    def jose_alg(self) -> str:
        return "HS256"

    @property
    def is_software_fallback(self) -> bool:
        return True

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest: bytes) -> bytes:
        return hmac.new(self._secret, digest, hashlib.sha256).digest()

    def sign_raw(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()

    def get_public_key_pem(self) -> bytes:
        return b""

    def get_public_keys_pem(self) -> dict[str, bytes]:
        return {}


class SoftwareEd25519Provider(BaseKMSProvider):
    """Hermetic asymmetric Ed25519 signing provider for non-enforcing posture tests.

    Exercises the full asymmetric sign/verify and ``kid``-resolved trust anchor
    verification code path without network calls or cloud credentials.
    """

    def __init__(
        self,
        key_id: str = "dev-ed25519-01",
        private_key: object | None = None,
        private_key_pem: bytes | None = None,
    ) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if private_key is not None:
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise TypeError("private_key must be an Ed25519PrivateKey instance")
            self._private_key = private_key
        elif private_key_pem is not None:
            loaded = serialization.load_pem_private_key(private_key_pem, password=None)
            if not isinstance(loaded, ed25519.Ed25519PrivateKey):
                raise TypeError("private_key_pem did not contain an Ed25519 key")
            self._private_key = loaded
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()

        self._key_id = key_id
        self._public_key_pem: bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def provider_name(self) -> str:
        return "SOFTWARE_ED25519"

    @property
    def digest_algorithm(self) -> str:
        return "raw"

    @property
    def expects_raw_message(self) -> bool:
        return True

    @property
    def jose_alg(self) -> str:
        return "EdDSA"

    @property
    def is_software_fallback(self) -> bool:
        return True

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(digest)

    def sign_raw(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def get_public_key_pem(self) -> bytes:
        return self._public_key_pem

    def get_public_keys_pem(self) -> dict[str, bytes]:
        return {self._key_id: self._public_key_pem}


@dataclass
class SignedRecord:
    """Envelope representing a signed governance decision or batch item."""

    payload: dict[str, Any]
    signature: str
    algorithm: str
    kid: str
    signed_at: float = field(default_factory=time.time)

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.payload[key]

    def __setitem__(self, key: str, value: Any) -> None:
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            self.payload[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.payload.get(key, default)

    def keys(self) -> list[str]:
        return ["payload", "signature", "algorithm", "kid", "signed_at"]

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and (
            key in ("payload", "signature", "algorithm", "kid", "signed_at")
            or key in self.payload
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "kid": self.kid,
            "signed_at": self.signed_at,
        }


# ---------------------------------------------------------------------------
# Multi-Cloud KMS Governance Signer
# ---------------------------------------------------------------------------


class KMSGovernanceSigner:
    """Asymmetric governance signature generator supporting multi-cloud targets."""

    def __init__(
        self,
        kms_client: object | None = None,
        key_version_name: str = "",
        public_key_pem: bytes = b"",
        provider: BaseKMSProvider | None = None,
        trust_anchors: dict[str, bytes] | None = None,
    ) -> None:
        posture = resolve_posture()
        if (
            provider is not None
            and provider.is_software_fallback
            and is_enforcing(posture)
        ):
            raise RuntimeError(
                f"[KMSSigner] Software provider {provider.provider_name!r} is "
                f"forbidden in enforcing posture ({posture.value}). "
                "Configure a hardware-backed Cloud KMS provider."
            )

        self._kms_client = kms_client
        self._key_version_name = key_version_name
        self._public_key_pem = public_key_pem
        self._provider = provider

        if not self._provider and (kms_client is not None or key_version_name):
            from src.gateway.governance.signer_factory import get_kms_provider_class

            gcp_cls = get_kms_provider_class("GCPKMSProvider")
            self._provider = gcp_cls(
                key_version_name=key_version_name, kms_client=kms_client
            )

        if self._provider is not None and not self._key_version_name:
            provider_kid = self._provider.key_id
            if provider_kid and provider_kid != "default":
                self._key_version_name = provider_kid

        if (
            self._provider is not None
            and not self._public_key_pem
            and self._provider.is_software_fallback
        ):
            self._public_key_pem = self._provider.get_public_key_pem()

        self._kms_active = (
            kms_client is not None and bool(key_version_name)
            if provider is None
            else provider is not None
        )

        # Out-of-band trust anchor registry mapping kid -> public key PEM.
        # Verification resolves public keys by kid from this manifest, never
        # from keys embedded inside signed documents.
        self._trust_anchors: dict[str, bytes] = dict(trust_anchors or {})
        if self._public_key_pem:
            active_kid = self._key_version_name or "default"
            self._trust_anchors[active_kid] = self._public_key_pem
            self._trust_anchors.setdefault("default", self._public_key_pem)
        if self._provider is not None and self._provider.is_software_fallback:
            for anchor_kid, pem in self._provider.get_public_keys_pem().items():
                if pem:
                    self._trust_anchors[anchor_kid] = pem

        self._channel_warmed: threading.Event = threading.Event()
        if self._kms_active:
            self._channel_warmed.set()

    def register_trust_anchor(self, kid: str, public_key_pem: bytes) -> None:
        """Register an out-of-band trust anchor public key PEM for ``kid``."""
        if not kid or not public_key_pem:
            raise ValueError("Both kid and public_key_pem must be non-empty.")
        self._trust_anchors[kid] = public_key_pem

    def resolve_trust_anchor(self, kid: str) -> bytes | None:
        """Resolve a trusted public key PEM by ``kid`` from the out-of-band manifest."""
        if not kid:
            return None
        return self._trust_anchors.get(kid)

    @property
    def is_kms_active(self) -> bool:
        """True if signing provider is configured and active."""
        return self._kms_active

    @property
    def signing_algorithm(self) -> str:
        """Returns active signing algorithm and provider identifier."""
        if not self._kms_active:
            return "HMAC_SHA256_FALLBACK"
        return self._provider.provider_name if self._provider else "KMS_ASYMMETRIC"

    @property
    def key_id(self) -> str:
        """Returns the active signing key identifier.

        Raises:
            RuntimeError: If KMS is not active (no key configured).
        """
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] key_id requested but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        if self._key_version_name:
            return self._key_version_name
        if self._provider is not None:
            return self._provider.key_id
        return ""

    @property
    def jose_alg(self) -> str:
        """Returns the JOSE-compliant algorithm string for the active key."""
        if not self._kms_active or not self._provider:
            raise RuntimeError(
                "[KMSSigner] jose_alg requested but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        return self._provider.jose_alg

    def get_public_key_pem(self) -> bytes:
        """Return the public key PEM for this signer.

        If KMS is active and no cached PEM exists, fetches from the provider.
        """
        if self._public_key_pem:
            return self._public_key_pem
        if self._provider:
            self._public_key_pem = self._provider.get_public_key_pem()
            if self._public_key_pem:
                active_kid = (
                    self._key_version_name or self._provider.key_id or "default"
                )
                self._trust_anchors[active_kid] = self._public_key_pem
                self._trust_anchors.setdefault("default", self._public_key_pem)
            return self._public_key_pem
        raise RuntimeError(
            "[KMSSigner] get_public_key_pem() called but no public key is available. "
            "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
        )

    @classmethod
    def from_env(cls) -> KMSGovernanceSigner:
        """Construct from environment variables via ``signer_factory``."""
        explicit_provider = os.environ.get("KMS_PROVIDER", "").strip().lower()
        provider_name = (
            explicit_provider or os.environ.get("CAGE_KMS_PROVIDER", "gcp")
        ).lower()
        key_version = _KMS_KEY_VERSION

        posture = resolve_posture()
        is_non_production = not is_enforcing(posture)

        if provider_name == "gcp" and not key_version and not explicit_provider:
            if is_non_production:
                logger.info(
                    "[KMSSigner] KMS_GOVERNANCE_KEY not set in %s posture. "
                    "Using HMAC fallback mode.",
                    posture.value,
                )
                return cls(
                    kms_client=None,
                    key_version_name="",
                    public_key_pem=b"",
                    provider=None,
                )
            raise RuntimeError(
                "[KMSSigner] KMS_GOVERNANCE_KEY is not set. "
                "Set it to the full Cloud KMS key version resource name. "
                "The legacy HMAC GOVERNANCE_SALT fallback has been removed. "
                "See CTRL_KMS_001 in control_mappings.json."
            )

        from src.gateway.governance.signer_factory import build_kms_provider

        kwargs: dict[str, Any] = {}
        if provider_name == "gcp":
            kwargs["key_version_name"] = key_version
        provider = build_kms_provider(provider_name, **kwargs)
        kms_client = getattr(provider, "_kms_client", None)

        public_key_pem = b""
        public_pem_path = _PUBLIC_PEM_PATH or os.environ.get(
            "KMS_GOVERNANCE_PUBLIC_PEM", ""
        )
        if public_pem_path and os.path.isfile(public_pem_path):
            with open(public_pem_path, "rb") as f:
                public_key_pem = f.read()
            logger.info("[KMSSigner] Public key loaded from: %s", public_pem_path)
            if provider and not provider.is_software_fallback:
                try:
                    remote_pem = provider.get_public_key_pem()
                    if public_key_pem.strip().replace(
                        b"\n", b""
                    ) != remote_pem.strip().replace(b"\n", b""):
                        logger.error(
                            "[%s] CRITICAL: Local PEM validation failed. Does not match Remote HSM Key!",
                            provider.provider_name,
                        )
                    else:
                        logger.info(
                            "[%s] Local PEM successfully validated against HSM.",
                            provider.provider_name,
                        )
                except Exception as exc:
                    logger.warning(
                        "[KMSSigner] Could not validate local PEM against remote HSM: %s",
                        exc,
                    )
        elif provider:
            try:
                public_key_pem = provider.get_public_key_pem()
                logger.info(
                    "[KMSSigner] Public key fetched from KMS provider (%s).",
                    provider_name,
                )
            except Exception as pk_exc:
                raise RuntimeError(
                    f"[KMSSigner] Failed to fetch public key from KMS: {pk_exc}. "
                    "Set KMS_GOVERNANCE_PUBLIC_PEM to a local PEM file path."
                ) from pk_exc

        return cls(
            kms_client=kms_client,
            key_version_name=key_version or provider.key_id,
            public_key_pem=public_key_pem,
            provider=provider,
        )

    def sign(self, plan: dict[str, Any]) -> str:
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] sign() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        plan_bytes = _canonicalise_plan(plan)
        with _tracer.start_as_current_span("cage.kms_signer.sign") as span:
            span.set_attribute("cage.signing.algorithm", self.signing_algorithm)
            span.set_attribute("cage.signing.kms_active", self._kms_active)
            span.set_attribute("kms.channel.pre_warmed", self._channel_warmed.is_set())
            if "signed_at" in plan:
                span.set_attribute("cage.signing.signed_at", plan["signed_at"])
            return self._kms_sign(plan_bytes)

    def sign_decision(
        self,
        plan: dict[str, Any],
        *,
        kid: str | None = None,
    ) -> SignedRecord:
        """Sign a governance decision dictionary and return a ``SignedRecord``."""
        sig_hex = self.sign(plan)
        resolved_kid = (
            kid
            or self._key_version_name
            or (self._provider.key_id if self._provider else "")
            or "default"
        )
        signed_at = float(plan.get("signed_at", time.time()))
        return SignedRecord(
            payload=dict(plan),
            signature=sig_hex,
            algorithm=self.signing_algorithm,
            kid=resolved_kid,
            signed_at=signed_at,
        )

    def sign_raw(self, message: bytes) -> bytes:
        """Sign raw bytes directly (for JWT signing)."""
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] sign_raw() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        if not self._provider:
            raise RuntimeError(
                "[KMSSigner] sign_raw() called but no provider is configured."
            )
        with _tracer.start_as_current_span("cage.kms_signer.sign_raw") as span:
            span.set_attribute("cage.signing.algorithm", self.signing_algorithm)
            span.set_attribute("cage.signing.kms_active", self._kms_active)
            span.set_attribute("kms.channel.pre_warmed", self._channel_warmed.is_set())
            span.set_attribute("cage.signing.message_len", len(message))

            if self._provider.expects_raw_message:
                return self._provider.sign_raw(message)
            hash_fn = getattr(hashlib, self._provider.digest_algorithm)
            digest = hash_fn(message).digest()
            return self._provider.sign_digest(digest)

    def sign_precomputed_digest(self, digest: bytes) -> str:
        """Sign a pre-computed envelope digest directly."""
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] sign_precomputed_digest() called but KMS is not active."
            )
        if not self._provider:
            raise RuntimeError(
                "[KMSSigner] sign_precomputed_digest() called but no provider is configured."
            )

        with _tracer.start_as_current_span(
            "cage.kms_signer.sign_precomputed_digest"
        ) as span:
            span.set_attribute("cage.signing.algorithm", self.signing_algorithm)
            span.set_attribute("cage.signing.digest_len", len(digest))

            sig_bytes = self._provider.sign_digest(digest)
            return sig_bytes.hex()

    def _kms_sign(self, plan_bytes: bytes) -> str:
        try:
            if not self._provider:
                raise RuntimeError("No active provider available.")

            if self._provider.expects_raw_message:
                sig_bytes = self._provider.sign_raw(plan_bytes)
            else:
                hash_fn = getattr(hashlib, self._provider.digest_algorithm)
                digest = hash_fn(plan_bytes).digest()
                sig_bytes = self._provider.sign_digest(digest)

            signature_hex = sig_bytes.hex()
            logger.info(
                "[KMSSigner] KMS signature generated: %s... (key=%s)",
                signature_hex[:16],
                self._key_version_name.split("/")[-1]
                if self._key_version_name
                else "default",
            )
            return signature_hex
        except Exception as exc:
            logger.critical(
                json.dumps(
                    {
                        "event": "KMS_SIGNING_FAILED",
                        "severity": "CRITICAL",
                        "kms_key": self._key_version_name,
                        "error": str(exc),
                        "audit_note": "signing failed — no fallback; trade blocked",
                    }
                )
            )
            raise RuntimeError(
                f"[KMSSigner] KMS asymmetricSign failed: {exc}. "
                "The HMAC fallback has been removed. Fix KMS connectivity."
            ) from exc

    def validate_ready(self) -> None:
        """Verify the KMS key version is reachable and ENABLED."""
        if not self._kms_active or self._provider is None:
            raise RuntimeError(
                "[KMSSigner] validate_ready() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        try:
            self._provider.validate_ready(self._key_version_name)
        except RuntimeError:
            raise
        except Exception as exc:
            if self._public_key_pem:
                logger.warning(
                    "[KMSSigner] Remote KMS probe failed (%s), but valid local public key is loaded — proceeding in verification-only mode.",
                    exc,
                )
                return
            raise RuntimeError(
                f"KMS key version {self._key_version_name!r} is not reachable: {exc}"
            ) from exc

    def _reject_if_enforcing_software_alg(self, algorithm: str | None) -> bool:
        """Return True (and log CRITICAL) if posture is enforcing and algorithm/provider is software/HMAC."""
        posture = resolve_posture()
        if not is_enforcing(posture):
            return False

        alg_to_check = (algorithm or "").strip()
        provider_is_software = bool(
            self._provider is not None and self._provider.is_software_fallback
        )
        if _is_forbidden_enforcing_alg(alg_to_check) or provider_is_software:
            logger.critical(
                json.dumps(
                    {
                        "event": "KMS_SOFTWARE_SIGNATURE_REJECTED",
                        "severity": "CRITICAL",
                        "posture": posture.value,
                        "algorithm": alg_to_check or self.signing_algorithm,
                        "audit_note": "Software/HMAC signature rejected in enforcing posture (K3)",
                    }
                )
            )
            return True
        return False

    def verify(
        self,
        plan: dict[str, Any],
        signature_hex: str,
        *,
        algorithm: str | None = None,
    ) -> bool:
        if not signature_hex:
            return False
        if _is_forbidden_enforcing_alg(signature_hex):
            self._reject_if_enforcing_software_alg(signature_hex)
            return False
        if self._reject_if_enforcing_software_alg(algorithm):
            return False
        if not self._public_key_pem:
            raise RuntimeError(
                "[KMSSigner] verify() called but no public key is loaded. "
                "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
            )
        plan_bytes = _canonicalise_plan(plan)
        result = self._kms_verify(plan_bytes, signature_hex)
        if result:
            signed_at = plan.get("signed_at")
            if signed_at is not None:
                age = int(time.time()) - int(signed_at)
                if age > MAX_KMS_PAYLOAD_AGE_SECONDS:
                    raise ValueError("KMS payload has expired (signed_at too old)")
        return result

    def verify_decision(
        self,
        decision_or_record: SignedRecord | dict[str, Any],
        signature_hex: str | None = None,
        *,
        kid: str | None = None,
        algorithm: str | None = None,
    ) -> bool:
        """Verify a signed decision using ``kid``-resolved trust anchors (fail-closed).

        Never verifies against a key embedded in the signed payload. Rejects
        ``HMAC_SHA256_FALLBACK`` / ``HS256`` / software providers when posture
        is enforcing (Defect K3).
        """
        if isinstance(decision_or_record, SignedRecord):
            payload = decision_or_record.payload
            sig_hex = (
                signature_hex
                if signature_hex is not None
                else decision_or_record.signature
            )
            record_kid = kid if kid is not None else decision_or_record.kid
            record_alg = (
                algorithm if algorithm is not None else decision_or_record.algorithm
            )
        elif isinstance(decision_or_record, dict):
            if (
                "payload" in decision_or_record
                and isinstance(decision_or_record["payload"], dict)
                and ("signature" in decision_or_record or signature_hex is not None)
            ):
                payload = decision_or_record["payload"]
                sig_hex = (
                    signature_hex
                    if signature_hex is not None
                    else str(decision_or_record.get("signature", ""))
                )
                record_kid = kid if kid is not None else decision_or_record.get("kid")
                record_alg = (
                    algorithm
                    if algorithm is not None
                    else decision_or_record.get("algorithm")
                )
            else:
                payload = {
                    k: v
                    for k, v in decision_or_record.items()
                    if k
                    not in (
                        "signature",
                        "kms_signature",
                        "signing_algorithm",
                        "algorithm",
                        "kid",
                        "public_key",
                        "public_key_pem",
                    )
                }
                sig_hex = (
                    signature_hex
                    if signature_hex is not None
                    else str(
                        decision_or_record.get("signature")
                        or decision_or_record.get("kms_signature")
                        or ""
                    )
                )
                record_kid = kid if kid is not None else decision_or_record.get("kid")
                record_alg = (
                    algorithm
                    if algorithm is not None
                    else (
                        decision_or_record.get("algorithm")
                        or decision_or_record.get("signing_algorithm")
                    )
                )
        else:
            return False

        effective_alg = str(record_alg or self.signing_algorithm)
        if _is_forbidden_enforcing_alg(sig_hex):
            effective_alg = sig_hex

        if self._reject_if_enforcing_software_alg(effective_alg):
            return False

        if not sig_hex or _is_forbidden_enforcing_alg(sig_hex):
            return False

        # Resolve public key strictly by kid from the out-of-band trust anchor
        # manifest. Never trust a public key supplied inside the payload.
        lookup_kid = (
            record_kid
            if record_kid is not None
            else (
                self._key_version_name
                or (self._provider.key_id if self._provider else "default")
            )
        )
        public_key_pem = self.resolve_trust_anchor(str(lookup_kid))
        if not public_key_pem:
            logger.warning(
                "[KMSSigner] Unknown or untrusted kid %r in verify_decision — failing closed.",
                lookup_kid,
            )
            return False

        plan_bytes = _canonicalise_plan(payload)
        return self._kms_verify(plan_bytes, sig_hex, public_key_pem=public_key_pem)

    def verify_batch(
        self,
        records: Sequence[SignedRecord | dict[str, Any]],
        *,
        algorithm: str | None = None,
    ) -> bool:
        """Verify a batch of signed governance records (fail-closed)."""
        if self._reject_if_enforcing_software_alg(algorithm):
            return False
        if not records:
            return False
        for record in records:
            if not self.verify_decision(record, algorithm=algorithm):
                return False
        return True

    def verify_raw(self, message: bytes, signature: bytes) -> bool:
        """Verify a raw signature produced by sign_raw()."""
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] verify_raw() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        if not self._public_key_pem:
            raise RuntimeError(
                "[KMSSigner] verify_raw() called but no public key is loaded. "
                "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
            )

        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import (
                ec,
                ed25519,
                padding,
                rsa,
            )
            from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

            public_key = serialization.load_pem_public_key(self._public_key_pem)

            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, message)
                return True

            hash_alg_name = (
                self._provider.digest_algorithm.upper() if self._provider else "SHA256"
            )
            hash_alg = getattr(hashes, hash_alg_name)()
            digest = hashlib.new(hash_alg_name.lower(), message).digest()

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    digest,
                    ec.ECDSA(asym_utils.Prehashed(hash_alg)),
                )
                return True
            if isinstance(public_key, rsa.RSAPublicKey):
                padding_scheme: padding.PKCS1v15 | padding.PSS = padding.PKCS1v15()
                if self._provider and self._provider.uses_rsa_pss:
                    padding_scheme = padding.PSS(
                        mgf=padding.MGF1(hash_alg),
                        salt_length=padding.PSS.MAX_LENGTH,
                    )

                public_key.verify(
                    signature,
                    digest,
                    padding_scheme,
                    asym_utils.Prehashed(hash_alg),
                )
                return True

            logger.warning(
                "[KMSSigner] verify_raw: Unsupported public key type: %s",
                type(public_key).__name__,
            )
            return False
        except Exception as exc:
            logger.debug("[KMSSigner] verify_raw failed: %s", exc)
            return False

    def _kms_verify(
        self,
        plan_bytes: bytes,
        signature_hex: str,
        *,
        public_key_pem: bytes | None = None,
    ) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import (
                ec,
                ed25519,
                padding,
                rsa,
            )
            from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

            pem_to_use = public_key_pem or self._public_key_pem
            public_key = serialization.load_pem_public_key(pem_to_use)
            signature_bytes = bytes.fromhex(signature_hex)

            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature_bytes, plan_bytes)
                return True

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                # The digest is bound to the curve of the kid-resolved key,
                # not to this instance's provider: a verify-only instance has
                # no provider, and a foreign kid may use a different curve.
                hash_alg_name = {384: "SHA384", 521: "SHA512"}.get(
                    public_key.curve.key_size, "SHA256"
                )
            else:
                hash_alg_name = (
                    self._provider.digest_algorithm.upper()
                    if self._provider
                    else "SHA256"
                )
            hash_alg = getattr(hashes, hash_alg_name)()
            digest = hashlib.new(hash_alg_name.lower(), plan_bytes).digest()

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(asym_utils.Prehashed(hash_alg)),
                )
                return True
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_bytes,
                    digest,
                    padding.PKCS1v15(),
                    asym_utils.Prehashed(hash_alg),
                )
                return True

            logger.warning(
                "[KMSSigner] Unsupported public key type: %s",
                type(public_key).__name__,
            )
            return False
        except Exception as exc:
            logger.warning("[KMSSigner] KMS public key verification failed: %s", exc)
            return False


class BatchGovernanceSigner:
    """Batch governance signer and verifier backed by ``KMSGovernanceSigner``."""

    def __init__(self, signer: KMSGovernanceSigner | None = None) -> None:
        self._signer = signer or get_governance_signer()

    @property
    def signer(self) -> KMSGovernanceSigner:
        return self._signer

    def sign_batch(
        self,
        decisions: Sequence[dict[str, Any]],
        *,
        kid: str | None = None,
    ) -> list[SignedRecord]:
        return [self._signer.sign_decision(d, kid=kid) for d in decisions]

    def verify_batch(
        self,
        records: Sequence[SignedRecord | dict[str, Any]],
        *,
        algorithm: str | None = None,
    ) -> bool:
        return self._signer.verify_batch(records, algorithm=algorithm)


_signer: KMSGovernanceSigner | None = None


def get_governance_signer() -> KMSGovernanceSigner:
    global _signer
    if _signer is None:
        _signer = KMSGovernanceSigner.from_env()
    return _signer


def reset_governance_signer() -> None:
    """Reset the cached signer singleton (for test isolation)."""
    global _signer
    _signer = None


def __getattr__(name: str) -> Any:
    """Lazily resolve Layer 3 cloud KMS provider classes for backwards compatibility."""
    if name in ("GCPKMSProvider", "AWSKMSProvider", "AzureKMSProvider"):
        from src.gateway.governance.signer_factory import get_kms_provider_class

        return get_kms_provider_class(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
