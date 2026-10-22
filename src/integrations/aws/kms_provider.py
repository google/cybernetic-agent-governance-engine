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

"""AWS KMS HSM provider (Layer 3 integration)."""

from __future__ import annotations

import logging
import os

from src.gateway.governance.kms_signer import BaseKMSProvider

logger = logging.getLogger("Gateway.Governance.KMSSigner")

_DEFAULT_AWS_KMS_READ_TIMEOUT_S = 5.0
_DEFAULT_AWS_KMS_CONNECT_TIMEOUT_S = 2.0


def _resolve_aws_kms_timeout_seconds() -> float:
    raw = os.environ.get("CAGE_KMS_RPC_TIMEOUT_SECONDS", "") or os.environ.get(
        "CAGE_KMS_SIGN_TIMEOUT_SECONDS", ""
    )
    if raw:
        try:
            val = float(raw)
            if val > 0.0:
                return val
        except ValueError:
            pass
    return _DEFAULT_AWS_KMS_READ_TIMEOUT_S


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
        read_timeout = _resolve_aws_kms_timeout_seconds()
        try:
            try:
                from botocore.config import Config  # type: ignore[import]

                cfg = Config(
                    connect_timeout=_DEFAULT_AWS_KMS_CONNECT_TIMEOUT_S,
                    read_timeout=read_timeout,
                    retries={"max_attempts": 2, "mode": "standard"},
                )
                self._client = boto3.client("kms", config=cfg)
            except (ImportError, TypeError):
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
