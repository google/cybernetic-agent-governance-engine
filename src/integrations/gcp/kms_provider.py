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

"""Google Cloud KMS HSM provider (Layer 3 integration)."""

from __future__ import annotations

import logging

from src.gateway.governance.kms_signer import BaseKMSProvider

logger = logging.getLogger("Gateway.Governance.KMSSigner")

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

    def __init__(
        self, key_version_name: str = "", kms_client: object | None = None
    ) -> None:
        self._key_version_name = key_version_name
        self._kms_client = kms_client
        self._hash_width = "sha256"
        if not kms_client and key_version_name:
            try:
                from google.cloud import kms  # type: ignore[import]
            except ImportError as exc:
                raise RuntimeError(
                    "[KMSSigner] google-cloud-kms is not installed. "
                    "Install with: pip install google-cloud-kms"
                ) from exc
            try:
                self._kms_client = kms.KeyManagementServiceClient()
                logger.info(
                    "[GCPKMSProvider] Client initialised for key: %s",
                    self._key_version_name,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"[KMSSigner] KMS client init failed: {exc}. Check workload identity / ADC credentials."
                ) from exc
        self._detect_hash_width()

    def _detect_hash_width(self) -> None:
        """Determine the digest width required by this key's signing algorithm."""
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

    def warm_channel(self) -> None:
        """Pre-warm the KMS gRPC channel by querying key version metadata."""
        self._detect_hash_width()

    @property
    def provider_name(self) -> str:
        return "KMS_ASYMMETRIC"

    @property
    def digest_algorithm(self) -> str:
        return self._hash_width

    @property
    def expects_raw_message(self) -> bool:
        return self._hash_width == "raw"

    @property
    def jose_alg(self) -> str:
        """Map the GCP CryptoKeyVersionAlgorithm to its RFC 7518 JOSE name."""
        if not self._kms_client or not self._key_version_name:
            raise RuntimeError(
                "[KMSSigner] GCP KMS provider has no client or key version name."
            )
        try:
            version = self._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                name=self._key_version_name
            )
            algorithm_name = version.algorithm.name

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

    @property
    def uses_rsa_pss(self) -> bool:
        """True if the active GCP KMS key version uses RSA-PSS padding."""
        if not self._kms_client or not self._key_version_name:
            return False
        try:
            version = self._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                name=self._key_version_name
            )
            return "PSS" in str(version.algorithm.name)
        except Exception:
            return False

    def validate_ready(self, key_version_name: str = "") -> None:
        """Verify the GCP KMS key version exists and is in ENABLED state."""
        target_key = key_version_name or self._key_version_name
        if self._kms_client is not None:
            version = self._kms_client.get_crypto_key_version(  # type: ignore[attr-defined]
                name=target_key
            )
            if version.state.name not in ("ENABLED",):
                raise RuntimeError(
                    f"KMS key version {target_key!r} is in state "
                    f"{version.state.name!r} — expected ENABLED"
                )
        else:
            self.get_public_key_pem()

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
            logging.getLogger(__name__).warning(
                "Failed to list crypto key versions: %s", exc
            )

        if not keys:
            keys[self._key_version_name] = self.get_public_key_pem()
        return keys
