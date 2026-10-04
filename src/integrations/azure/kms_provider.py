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

"""Azure Key Vault Managed HSM provider (Layer 3 integration)."""

from __future__ import annotations

import logging

from src.gateway.governance.kms_signer import BaseKMSProvider

logger = logging.getLogger("Gateway.Governance.KMSSigner")


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

    @property
    def ecdsa_signature_encoding(self) -> str:
        # Key Vault's sign() already returns the JWS raw R||S concatenation.
        return "raw"

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
