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
kms_signer.py — Multi-Cloud KMS Asymmetric Governance Signer (Priority 1)
========================================================================

Provides Cloud KMS asymmetric signing for governance plans across multi-target
cloud infrastructure: Google Cloud KMS (GCP), AWS KMS (AWS), and Azure Key Vault
Managed HSM (Azure).
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import os
import threading
import time

from opentelemetry import trace as otel_trace

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


from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan


def _canonicalise_plan(plan: dict) -> bytes:
    """Produce a deterministic byte representation of a governance plan.
    Now uses RFC 8785 JCS (JSON Canonicalization Scheme) to prevent cross-language
    float drift during signature verification."""
    return jcs_canonicalize_plan(plan)


# ---------------------------------------------------------------------------
# Abstract KMS Provider Strategy
# ---------------------------------------------------------------------------


class BaseKMSProvider(abc.ABC):
    """Abstract base provider for cloud-native HSM asymmetric signing."""

    @abc.abstractmethod
    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a pre-hashed digest (width per ``digest_algorithm``) returning
        signature bytes."""
        pass

    @abc.abstractmethod
    def sign_raw(self, message: bytes) -> bytes:
        """Sign a raw message directly (used for PureEdDSA / Ed25519) returning
        signature bytes."""
        pass

    @abc.abstractmethod
    def get_public_key_pem(self) -> bytes:
        """Fetch the public key PEM from the cloud provider."""
        pass

    def get_public_keys_pem(self) -> dict[str, bytes]:
        """Fetch all active public key PEMs. Defaults to returning the single primary key."""
        return {"default": self.get_public_key_pem()}

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Returns provider name identifier for telemetry."""
        pass

    @property
    def digest_algorithm(self) -> str:
        """hashlib algorithm name for the digest this provider expects.

        Defaults to "sha256"; providers whose key requires a different
        digest width (e.g. GCP RSA_SIGN_*_SHA512 keys) override this.
        """
        return "sha256"


# CryptoKeyVersionAlgorithm names (as returned by CryptoKeyVersion.algorithm)
# that use each hash width. Anything not listed here defaults to SHA-256,
# preserving prior behaviour for EC_SIGN_P256_SHA256 and similar keys.
_GCP_KMS_SHA384_ALGORITHMS = frozenset(
    {
        "RSA_SIGN_PKCS1_3072_SHA384",
        "RSA_SIGN_PSS_3072_SHA384",
        "EC_SIGN_P384_SHA384",
    }
)
_GCP_KMS_SHA512_ALGORITHMS = frozenset(
    {
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_SIGN_PSS_4096_SHA512",
    }
)
_GCP_KMS_ED25519_ALGORITHMS = frozenset(
    {
        "EC_SIGN_ED25519",
    }
)


class GCPKMSProvider(BaseKMSProvider):
    """Google Cloud KMS HSM provider."""

    def __init__(self, key_version_name: str, kms_client: object | None = None) -> None:
        self._key_version_name = key_version_name
        self._kms_client = kms_client
        self._hash_width = "sha256"
        if not kms_client and key_version_name:
            try:
                from google.cloud import kms  # type: ignore[import]

                self._kms_client = kms.KeyManagementServiceClient()
                logger.info(
                    "[GCPKMSProvider] Client initialised for key: %s",
                    self._key_version_name,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"[GCPKMSProvider] KMS client init failed: {exc}"
                ) from exc
        self._detect_hash_width()

    def _detect_hash_width(self) -> None:
        """Determine the digest width required by this key's signing algorithm.

        CryptoKeyVersionAlgorithm dictates the required digest length —
        e.g. RSA_SIGN_PKCS1_4096_SHA512 requires a SHA-512 digest, not
        SHA-256. Calling asymmetricSign with the wrong digest field
        (previously hardcoded to sha256) fails with a 400 INVALID_ARGUMENT
        ("The digest SHA256 is not valid for CryptoKeys with algorithm
        RSA_SIGN_PKCS1_4096_SHA512"). Querying the version metadata once at
        construction time and caching the required width avoids this class
        of misconfiguration entirely, regardless of which key is provisioned.
        """
        if not self._kms_client or not self._key_version_name:
            return
        try:
            version = self._kms_client.get_crypto_key_version(  # type: ignore[union-attr, attr-defined]
                name=self._key_version_name
            )
            algorithm_name = version.algorithm.name
            if algorithm_name in _GCP_KMS_SHA512_ALGORITHMS:
                self._hash_width = "sha512"
            elif algorithm_name in _GCP_KMS_SHA384_ALGORITHMS:
                self._hash_width = "sha384"
            elif algorithm_name in _GCP_KMS_ED25519_ALGORITHMS:
                self._hash_width = "raw"
            else:
                self._hash_width = "sha256"
            logger.info(
                "[GCPKMSProvider] Key algorithm=%s → digest width=%s",
                algorithm_name,
                self._hash_width,
            )
        except Exception as exc:
            logger.warning(
                "[GCPKMSProvider] Could not determine key algorithm (defaulting "
                "to sha256 digest width): %s",
                exc,
            )

    @property
    def provider_name(self) -> str:
        return "KMS_ASYMMETRIC"

    @property
    def digest_algorithm(self) -> str:
        return self._hash_width

    def sign_digest(self, digest: bytes) -> bytes:
        from google.cloud.kms_v1.types import (
            service as kms_service,  # type: ignore[import]
        )

        digest_kwargs = {self._hash_width: digest}
        response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
            request=kms_service.AsymmetricSignRequest(
                name=self._key_version_name,
                digest=kms_service.Digest(**digest_kwargs),
            )
        )
        return response.signature

    def sign_raw(self, message: bytes) -> bytes:
        from google.cloud.kms_v1.types import (
            service as kms_service,  # type: ignore[import]
        )

        response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
            request=kms_service.AsymmetricSignRequest(
                name=self._key_version_name,
                data=message,
            )
        )
        return response.signature

    def get_public_key_pem(self) -> bytes:
        response = self._kms_client.get_public_key(name=self._key_version_name)  # type: ignore[union-attr]
        return response.pem.encode("utf-8")

    def get_public_keys_pem(self) -> dict[str, bytes]:
        """Fetch all ENABLED public keys for the CryptoKey to support rotation."""
        parts = self._key_version_name.split("/cryptoKeyVersions/")
        if len(parts) != 2:
            return {self._key_version_name: self.get_public_key_pem()}

        crypto_key_name = parts[0]
        keys = {}
        try:
            versions = self._kms_client.list_crypto_key_versions(parent=crypto_key_name)  # type: ignore[union-attr]
            for v in versions:
                if v.state.name == "ENABLED":
                    pub = self._kms_client.get_public_key(name=v.name)  # type: ignore[union-attr]
                    keys[v.name] = pub.pem.encode("utf-8")
        except Exception as exc:
            import logging

            logging.getLogger(__name__).warning(
                "Failed to list crypto key versions: %s", exc
            )

        if not keys:
            keys[self._key_version_name] = self.get_public_key_pem()
        return keys


class AWSKMSProvider(BaseKMSProvider):
    """AWS KMS HSM provider."""

    def __init__(self, key_id: str) -> None:
        if not key_id:
            raise RuntimeError(
                "[AWSKMSProvider] AWS_KMS_KEY_ID is not set. "
                "Set it to the AWS KMS Key ID or ARN."
            )
        try:
            import boto3  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "[AWSKMSProvider] boto3 is not installed. "
                "Install with: pip install boto3"
            ) from exc

        self._key_id = key_id
        try:
            self._client = boto3.client("kms")
            logger.info("[AWSKMSProvider] Client initialised for key: %s", self._key_id)
        except Exception as exc:
            raise RuntimeError(
                f"[AWSKMSProvider] AWS KMS client init failed: {exc}"
            ) from exc

    @property
    def provider_name(self) -> str:
        return "AWS_KMS"

    def sign_digest(self, digest: bytes) -> bytes:
        response = self._client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response["Signature"]

    def sign_raw(self, message: bytes) -> bytes:
        raise NotImplementedError(
            "AWS KMS does not support Ed25519 raw-message signing."
        )

    def get_public_key_pem(self) -> bytes:
        response = self._client.get_public_key(KeyId=self._key_id)
        pub_der = response["PublicKey"]
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_der_public_key(pub_der)
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class AzureKMSProvider(BaseKMSProvider):
    """Azure Key Vault Managed HSM provider."""

    def __init__(self, vault_url: str, key_name: str) -> None:
        if not vault_url or not key_name:
            raise RuntimeError(
                "[AzureKMSProvider] AZURE_KEYVAULT_URL and AZURE_KMS_KEY_NAME must be set."
            )
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import]
            from azure.keyvault.keys import KeyClient  # type: ignore[import]
            from azure.keyvault.keys.crypto import (
                CryptographyClient,  # type: ignore[import]
            )
        except ImportError as exc:
            raise RuntimeError(
                "[AzureKMSProvider] azure-keyvault-keys is not installed. "
                "Install with: pip install azure-keyvault-keys azure-identity"
            ) from exc

        self._vault_url = vault_url
        self._key_name = key_name
        try:
            credential = DefaultAzureCredential()
            key_client = KeyClient(vault_url=vault_url, credential=credential)
            self._key = key_client.get_key(key_name)
            self._crypto_client = CryptographyClient(self._key, credential=credential)
            logger.info(
                "[AzureKMSProvider] Client initialised for key: %s", self._key_name
            )
        except Exception as exc:
            raise RuntimeError(
                f"[AzureKMSProvider] Azure client init failed: {exc}"
            ) from exc

    @property
    def provider_name(self) -> str:
        return "AZURE_KEYVAULT_HSM"

    def sign_digest(self, digest: bytes) -> bytes:
        from azure.keyvault.keys.crypto import (
            SignatureAlgorithm,  # type: ignore[import]
        )

        result = self._crypto_client.sign(SignatureAlgorithm.es256, digest)
        return result.signature

    def sign_raw(self, message: bytes) -> bytes:
        raise NotImplementedError(
            "Azure Key Vault does not support Ed25519 raw-message signing."
        )

    def get_public_key_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        jwk = self._key.key
        if jwk.kty == "EC":
            from cryptography.hazmat.primitives.asymmetric import ec

            curve_cls = getattr(ec, jwk.crv.replace("-", "_").upper(), ec.SECP256R1)
            public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(jwk.x, "big"),
                int.from_bytes(jwk.y, "big"),
                curve_cls(),
            )
            key = public_numbers.public_key()
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        raise NotImplementedError(
            f"Azure Key Vault JWK key type {jwk.kty} not implemented"
        )


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
    ) -> None:
        self._kms_client = kms_client
        self._key_version_name = key_version_name
        self._public_key_pem = public_key_pem
        self._provider = provider

        if not self._provider and (kms_client is not None or key_version_name):
            self._provider = GCPKMSProvider(
                key_version_name=key_version_name, kms_client=kms_client
            )

        self._kms_active = (
            kms_client is not None and bool(key_version_name)
            if provider is None
            else provider is not None
        )

        # Channel warm-state tracking.  GCPKMSProvider._detect_hash_width()
        # issues a get_crypto_key_version call synchronously during __init__,
        # which pre-establishes the gRPC channel before the first sign() call.
        # AWS/Azure providers also initialise their transport at construction.
        # The Event is therefore set immediately when a provider is active so
        # that sign() can emit kms.channel.pre_warmed=True in its OTel span,
        # giving operators trace-level visibility into channel warm state.
        self._channel_warmed: threading.Event = threading.Event()
        if self._kms_active:
            self._channel_warmed.set()

    @property
    def is_kms_active(self) -> bool:
        """True if Cloud KMS signing is available (production mode)."""
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

        Returns:
            The configured key resource identifier when KMS is active.

        Raises:
            RuntimeError: If KMS is not active (no key configured).
        """
        if not self._kms_active:
            raise RuntimeError(
                "[KMSSigner] key_id requested but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        return self._key_version_name

    @property
    def jose_alg(self) -> str:
        """Returns the JOSE-compliant algorithm string for the active key.

        Maps the underlying KMS key algorithm to JOSE registered algorithm names
        per RFC 7518 (JSON Web Algorithms).

        Supported mappings:
        - ECDSA P-256 + SHA-256 → ES256
        - ECDSA P-384 + SHA-384 → ES384
        - Ed25519 → EdDSA
        - RSA PSS SHA-256 → PS256
        - RSA PKCS1 SHA-256 → RS256
        - RSA PSS SHA-384 → PS384
        - RSA PKCS1 SHA-384 → RS384
        - RSA PSS SHA-512 → PS512
        - RSA PKCS1 SHA-512 → RS512

        Returns:
            JOSE algorithm string (e.g., "ES256", "EdDSA").

        Raises:
            RuntimeError: If KMS is not active or algorithm cannot be determined.
        """
        if not self._kms_active or not self._provider:
            raise RuntimeError(
                "[KMSSigner] jose_alg requested but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )

        # For GCP KMS, query the key version algorithm to map to JOSE
        if isinstance(self._provider, GCPKMSProvider):
            if not self._provider._kms_client or not self._key_version_name:
                raise RuntimeError(
                    "[KMSSigner] GCP KMS provider has no client or key version name."
                )
            try:
                # Type narrowing: _kms_client is object but we know it's KMS client at runtime
                version = self._provider._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                    name=self._key_version_name
                )
                algorithm_name = version.algorithm.name

                # Map GCP CryptoKeyVersionAlgorithm to JOSE alg
                if algorithm_name == "EC_SIGN_P256_SHA256":
                    return "ES256"
                elif algorithm_name == "EC_SIGN_P384_SHA384":
                    return "ES384"
                elif algorithm_name == "EC_SIGN_ED25519":
                    return "EdDSA"
                elif algorithm_name in (
                    "RSA_SIGN_PSS_2048_SHA256",
                    "RSA_SIGN_PSS_3072_SHA256",
                ):
                    return "PS256"
                elif algorithm_name in (
                    "RSA_SIGN_PKCS1_2048_SHA256",
                    "RSA_SIGN_PKCS1_3072_SHA256",
                ):
                    return "RS256"
                elif algorithm_name == "RSA_SIGN_PSS_3072_SHA384":
                    return "PS384"
                elif algorithm_name == "RSA_SIGN_PKCS1_3072_SHA384":
                    return "RS384"
                elif algorithm_name in (
                    "RSA_SIGN_PSS_4096_SHA512",
                    "RSA_SIGN_PSS_4096_SHA256",
                ):
                    return "PS512" if "SHA512" in algorithm_name else "PS256"
                elif algorithm_name in (
                    "RSA_SIGN_PKCS1_4096_SHA512",
                    "RSA_SIGN_PKCS1_4096_SHA256",
                ):
                    return "RS512" if "SHA512" in algorithm_name else "RS256"
                else:
                    logger.warning(
                        "[KMSSigner] Unknown GCP algorithm %s, defaulting to ES256",
                        algorithm_name,
                    )
                    return "ES256"
            except Exception as exc:
                raise RuntimeError(
                    f"[KMSSigner] Failed to determine JOSE algorithm: {exc}"
                ) from exc

        # AWS/Azure: infer from digest_algorithm (best-effort)
        if self._provider.digest_algorithm == "raw":
            return "EdDSA"
        elif self._provider.digest_algorithm == "sha256":
            return "ES256"  # Assume ECDSA P-256 by default
        elif self._provider.digest_algorithm == "sha384":
            return "ES384"
        elif self._provider.digest_algorithm == "sha512":
            return "PS512"  # Assume RSA PSS by default
        else:
            logger.warning(
                "[KMSSigner] Unknown digest algorithm %s, defaulting to ES256",
                self._provider.digest_algorithm,
            )
            return "ES256"

    def get_public_key_pem(self) -> bytes:
        """Return the public key PEM for this signer.

        If KMS is active and no cached PEM exists, fetches from the provider.
        """
        if self._public_key_pem:
            return self._public_key_pem
        if self._provider:
            self._public_key_pem = self._provider.get_public_key_pem()
            return self._public_key_pem
        raise RuntimeError(
            "[KMSSigner] get_public_key_pem() called but no public key is available. "
            "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
        )

    @classmethod
    def from_env(cls) -> KMSGovernanceSigner:
        """Construct from environment variables based on CAGE_KMS_PROVIDER.

        In test/dev environments without KMS configured, returns a fallback
        signer that uses HMAC-SHA256 with GOVERNANCE_SALT.
        """
        provider_name = os.environ.get("CAGE_KMS_PROVIDER", "gcp").lower()
        provider: BaseKMSProvider | None = None
        kms_client = None
        key_version = _KMS_KEY_VERSION

        # Check if we're in a non-production environment
        env = (
            os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
        ).lower()
        is_non_production = env in ("development", "test", "dev", "ci")

        if provider_name == "gcp":
            if not key_version:
                if is_non_production:
                    # Return a fallback signer for test/dev without KMS
                    logger.info(
                        "[KMSSigner] KMS_GOVERNANCE_KEY not set in %s environment. "
                        "Using HMAC fallback mode.",
                        env,
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
            try:
                from google.cloud import kms  # type: ignore[import]
            except ImportError as exc:
                raise RuntimeError(
                    "[KMSSigner] google-cloud-kms is not installed. "
                    "Install with: pip install google-cloud-kms"
                ) from exc
            try:
                kms_client = kms.KeyManagementServiceClient()
                logger.info(
                    "[KMSSigner] Cloud KMS client initialised for key: %s", key_version
                )
            except Exception as exc:
                raise RuntimeError(
                    f"[KMSSigner] KMS client init failed: {exc}. Check workload identity / ADC credentials."
                ) from exc
            provider = GCPKMSProvider(
                key_version_name=key_version, kms_client=kms_client
            )
        elif provider_name == "aws":
            key_id = os.environ.get("AWS_KMS_KEY_ID", "")
            provider = AWSKMSProvider(key_id)
        elif provider_name == "azure":
            vault_url = os.environ.get("AZURE_KEYVAULT_URL", "")
            key_name = os.environ.get("AZURE_KMS_KEY_NAME", "")
            provider = AzureKMSProvider(vault_url, key_name)
        else:
            raise RuntimeError(
                f"Unknown CAGE_KMS_PROVIDER '{provider_name}'. Use 'gcp', 'aws', or 'azure'."
            )

        public_key_pem = b""
        public_pem_path = _PUBLIC_PEM_PATH or os.environ.get(
            "KMS_GOVERNANCE_PUBLIC_PEM", ""
        )
        if public_pem_path and os.path.isfile(public_pem_path):
            with open(public_pem_path, "rb") as f:
                public_key_pem = f.read()
            logger.info("[KMSSigner] Public key loaded from: %s", public_pem_path)
            if provider:
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
            key_version_name=key_version,
            public_key_pem=public_key_pem,
            provider=provider,
        )

    def sign(self, plan: dict) -> str:
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

    def sign_raw(self, message: bytes) -> bytes:
        """Sign raw bytes directly (for JWT signing).

        This is a thin wrapper around the provider's sign_raw/sign_digest methods.
        Uses the provider's digest algorithm to determine the correct signing path.

        Args:
            message: Raw bytes to sign (e.g., JWT signing input).

        Returns:
            Raw signature bytes.
        """
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

            if self._provider.digest_algorithm == "raw":
                # Ed25519 / PureEdDSA: sign the message directly
                return self._provider.sign_raw(message)
            else:
                # ECDSA / RSA: hash first, then sign digest
                hash_fn = getattr(hashlib, self._provider.digest_algorithm)
                digest = hash_fn(message).digest()
                return self._provider.sign_digest(digest)

    def sign_precomputed_digest(self, digest: bytes) -> str:
        """Sign a pre-computed envelope digest directly.

        Bypasses local canonicalization and hashing to minimize memory and KMS bandwidth
        for large plan envelopes.

        Args:
            digest: Pre-computed digest bytes matching the provider's expected digest width.

        Returns:
            Hex-encoded signature string.
        """
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
            if self._provider:
                # Use the digest width the provider's key actually requires
                # (e.g. sha512 for RSA_SIGN_PKCS1_4096_SHA512) rather than
                # hardcoding sha256, which fails with a 400 INVALID_ARGUMENT
                # against keys provisioned with a different algorithm.
                if self._provider.digest_algorithm == "raw":
                    sig_bytes = self._provider.sign_raw(plan_bytes)
                else:
                    hash_fn = getattr(hashlib, self._provider.digest_algorithm)
                    digest = hash_fn(plan_bytes).digest()
                    sig_bytes = self._provider.sign_digest(digest)
            elif self._kms_client:
                from google.cloud.kms_v1.types import (
                    service as kms_service,  # type: ignore[import]
                )

                digest = hashlib.sha256(plan_bytes).digest()
                response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr, attr-defined]
                    request=kms_service.AsymmetricSignRequest(
                        name=self._key_version_name,
                        digest=kms_service.Digest(sha256=digest),
                    ),
                )
                sig_bytes = response.signature
            else:
                raise RuntimeError("No active provider or client available.")

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
        """Verify the KMS key version is reachable and ENABLED.

        Call this at startup before marking the pod ready. Raises RuntimeError
        if the key is unreachable, missing, or not in ENABLED state — preventing
        silent HTTP 500s on every signing call (see PERFORMANCE_REVIEW.md §3,
        CTRL_KMS_001).

        For GCP: performs a read-only ``get_crypto_key_version`` metadata call
        and asserts ``state == ENABLED``.
        For AWS / Azure: calls ``get_public_key_pem()`` as a reachability probe
        (these providers do not expose a per-version state enum equivalent to
        GCP's ``CryptoKeyVersion.state``).

        Returns:
            None on success (key is reachable and ready).

        Raises:
            RuntimeError: If KMS is not active, the key version does not exist
                (404 / NotFound), is DISABLED or DESTROYED, or any other
                exception is raised during the probe.
        """
        if not self._kms_active or self._provider is None:
            raise RuntimeError(
                "[KMSSigner] validate_ready() called but KMS is not active. "
                "Ensure KMS_GOVERNANCE_KEY is set and from_env() succeeded."
            )
        try:
            if (
                isinstance(self._provider, GCPKMSProvider)
                and self._provider._kms_client is not None
            ):
                # GCP: read-only metadata call — no signing performed.
                # Verifies the key version exists AND is in ENABLED state.
                version = self._provider._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                    name=self._key_version_name
                )
                if version.state.name not in ("ENABLED",):
                    raise RuntimeError(
                        f"KMS key version {self._key_version_name!r} is in state "
                        f"{version.state.name!r} — expected ENABLED"
                    )
            else:
                # AWS / Azure: get_public_key_pem() proves the key is reachable
                # and accessible with the configured credentials.
                self._provider.get_public_key_pem()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"KMS key version {self._key_version_name!r} is not reachable: {exc}"
            ) from exc

    def verify(self, plan: dict, signature_hex: str) -> bool:
        if not signature_hex:
            return False
        if not self._public_key_pem:
            raise RuntimeError(
                "[KMSSigner] verify() called but no public key is loaded. "
                "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
            )
        plan_bytes = _canonicalise_plan(plan)
        result = self._kms_verify(plan_bytes, signature_hex)
        if result:
            # H52: staleness check — reject payloads older than MAX_KMS_PAYLOAD_AGE_SECONDS
            # to prevent replay of previously-valid signed reconciliation payloads.
            signed_at = plan.get("signed_at")
            if signed_at is not None:
                age = int(time.time()) - int(signed_at)
                if age > MAX_KMS_PAYLOAD_AGE_SECONDS:
                    raise ValueError("KMS payload has expired (signed_at too old)")
        return result

    def verify_raw(self, message: bytes, signature: bytes) -> bool:
        """Verify a raw signature produced by sign_raw().

        Verifies that the signature was produced by signing the message with
        the private key corresponding to this signer's public key.

        Args:
            message: Raw bytes that were signed.
            signature: Raw signature bytes produced by sign_raw().

        Returns:
            True if the signature is valid, False otherwise.

        Raises:
            RuntimeError: If KMS is not active (fail-closed, never fail-open).
        """
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

            # Ed25519: verify raw message directly (PureEdDSA)
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, message)
                return True

            # ECDSA / RSA: hash first, then verify digest
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
            elif isinstance(public_key, rsa.RSAPublicKey):
                # Infer padding from algorithm name if available
                padding_scheme: padding.PKCS1v15 | padding.PSS = (
                    padding.PKCS1v15()
                )  # Default to PKCS1v15
                if self._provider and isinstance(self._provider, GCPKMSProvider):
                    try:
                        # Type narrowing: _kms_client is object but we know it's KMS client at runtime
                        version = self._provider._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                            name=self._key_version_name
                        )
                        if "PSS" in version.algorithm.name:
                            padding_scheme = padding.PSS(
                                mgf=padding.MGF1(hash_alg),
                                salt_length=padding.PSS.MAX_LENGTH,
                            )
                    except Exception:
                        pass  # Fall back to PKCS1v15

                public_key.verify(
                    signature,
                    digest,
                    padding_scheme,
                    asym_utils.Prehashed(hash_alg),
                )
                return True
            else:
                logger.warning(
                    "[KMSSigner] verify_raw: Unsupported public key type: %s",
                    type(public_key).__name__,
                )
                return False
        except Exception as exc:
            # Invalid signature or verification failure
            logger.debug("[KMSSigner] verify_raw failed: %s", exc)
            return False

    def _kms_verify(self, plan_bytes: bytes, signature_hex: str) -> bool:
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
            signature_bytes = bytes.fromhex(signature_hex)

            # Ed25519: verify raw message directly (PureEdDSA)
            # Ed25519 signs the raw message without a separate pre-hash step.
            # Previously, this code path would fail because it tried to use
            # hashlib.new("raw", ...) which doesn't exist, and Ed25519PublicKey
            # isn't an EllipticCurvePublicKey instance.
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature_bytes, plan_bytes)
                return True

            # ECDSA / RSA: use pre-hashed digest
            # Use the same digest width the provider's key requires (e.g.
            # sha512 for RSA_SIGN_PKCS1_4096_SHA512) — hardcoding SHA-256
            # here previously caused verification to fail (silently, since
            # this method returns False rather than raising) against any
            # non-default key algorithm.
            hash_alg_name = (
                self._provider.digest_algorithm.upper() if self._provider else "SHA256"
            )
            hash_alg = getattr(hashes, hash_alg_name)()
            digest = hashlib.new(hash_alg_name.lower(), plan_bytes).digest()

            # Pyrefly fix: narrow the type explicitly so each branch calls the
            # correct overload of verify() with the right number of arguments.
            # EC keys (ECDSA): 3-arg verify(signature, data, algorithm)
            # RSA keys: 4-arg verify(signature, data, padding, algorithm).
            # GCP's RSA_SIGN_PKCS1_* algorithms use PKCS1v15 padding, not PSS
            # — using PSS here (the prior hardcoded behaviour) would make
            # every signature fail verification against a PKCS1 key.
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(asym_utils.Prehashed(hash_alg)),
                )
                return True
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_bytes,
                    digest,
                    padding.PKCS1v15(),
                    asym_utils.Prehashed(hash_alg),
                )
                return True
            else:
                logger.warning(
                    "[KMSSigner] Unsupported public key type: %s",
                    type(public_key).__name__,
                )
                return False
        except Exception as exc:
            logger.warning("[KMSSigner] KMS public key verification failed: %s", exc)
            return False


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


def assert_kms_active_in_production() -> None:
    env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    if env in ("development", "test", "dev", "ci"):
        return
    signer = get_governance_signer()
    if not signer.is_kms_active:
        raise RuntimeError(
            "CAGE STARTUP FAILURE: KMSGovernanceSigner is in HMAC fallback mode "
            "in a non-development environment. Set KMS_GOVERNANCE_KEY to the full "
            "Cloud KMS key version resource name. "
            "Evidentiary independence control violation (see CTRL_KMS_001 in control_mappings.json)."
        )
