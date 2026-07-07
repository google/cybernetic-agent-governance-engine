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

from opentelemetry import trace as otel_trace

logger = logging.getLogger("Gateway.Governance.KMSSigner")
_tracer = otel_trace.get_tracer(__name__)

# ---------------------------------------------------------------------------
# Global Configuration (Module-level for mock support in unit tests)
# ---------------------------------------------------------------------------

_KMS_KEY_VERSION: str = os.environ.get("KMS_GOVERNANCE_KEY", "")
_PUBLIC_PEM_PATH: str = os.environ.get("KMS_GOVERNANCE_PUBLIC_PEM", "")


def _canonicalise_plan(plan: dict) -> bytes:
    """Produce a deterministic byte representation of a governance plan."""
    return json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Abstract KMS Provider Strategy
# ---------------------------------------------------------------------------


class BaseKMSProvider(abc.ABC):
    """Abstract base provider for cloud-native HSM asymmetric signing."""

    @abc.abstractmethod
    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a 32-byte SHA-256 digest returning signature bytes."""
        pass

    @abc.abstractmethod
    def get_public_key_pem(self) -> bytes:
        """Fetch the public key PEM from the cloud provider."""
        pass

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Returns provider name identifier for telemetry."""
        pass


class GCPKMSProvider(BaseKMSProvider):
    """Google Cloud KMS HSM provider."""

    def __init__(self, key_version_name: str, kms_client: object | None = None) -> None:
        self._key_version_name = key_version_name
        self._kms_client = kms_client
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

    @property
    def provider_name(self) -> str:
        return "KMS_ASYMMETRIC"

    def sign_digest(self, digest: bytes) -> bytes:
        from google.cloud.kms_v1.types import (
            service as kms_service,  # type: ignore[import]
        )

        response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
            request=kms_service.AsymmetricSignRequest(
                name=self._key_version_name,
                digest=kms_service.Digest(sha256=digest),
            )
        )
        return response.signature

    def get_public_key_pem(self) -> bytes:
        response = self._kms_client.get_public_key(name=self._key_version_name)  # type: ignore[union-attr]
        return response.pem.encode("utf-8")


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

    @classmethod
    def from_env(cls) -> KMSGovernanceSigner:
        """Construct from environment variables based on CAGE_KMS_PROVIDER."""
        provider_name = os.environ.get("CAGE_KMS_PROVIDER", "gcp").lower()
        provider: BaseKMSProvider | None = None
        kms_client = None
        key_version = _KMS_KEY_VERSION

        if provider_name == "gcp":
            if not key_version:
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
            return self._kms_sign(plan_bytes)

    def _kms_sign(self, plan_bytes: bytes) -> str:
        try:
            digest = hashlib.sha256(plan_bytes).digest()
            if self._provider:
                sig_bytes = self._provider.sign_digest(digest)
            elif self._kms_client:
                from google.cloud.kms_v1.types import (
                    service as kms_service,  # type: ignore[import]
                )

                response = self._kms_client.asymmetric_sign(  # type: ignore[union-attr]
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

    def verify(self, plan: dict, signature_hex: str) -> bool:
        if not signature_hex:
            return False
        if not self._public_key_pem:
            raise RuntimeError(
                "[KMSSigner] verify() called but no public key is loaded. "
                "Ensure KMS_GOVERNANCE_PUBLIC_PEM is set or KMS bootstrap succeeded."
            )
        plan_bytes = _canonicalise_plan(plan)
        return self._kms_verify(plan_bytes, signature_hex)

    def _kms_verify(self, plan_bytes: bytes, signature_hex: str) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding
            from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

            public_key = serialization.load_pem_public_key(self._public_key_pem)
            signature_bytes = bytes.fromhex(signature_hex)
            digest = hashlib.sha256(plan_bytes).digest()

            if hasattr(public_key, "verify"):
                try:
                    public_key.verify(
                        signature_bytes,
                        digest,
                        ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
                    )
                    return True
                except (TypeError, AttributeError):
                    public_key.verify(
                        signature_bytes,
                        digest,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        asym_utils.Prehashed(hashes.SHA256()),
                    )
                    return True
        except Exception as exc:
            logger.warning("[KMSSigner] KMS public key verification failed: %s", exc)
            return False
        return False


_signer: KMSGovernanceSigner | None = None


def get_governance_signer() -> KMSGovernanceSigner:
    global _signer
    if _signer is None:
        _signer = KMSGovernanceSigner.from_env()
    return _signer


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
