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

"""Factory for loading Cloud KMS and hermetic signing providers."""

from __future__ import annotations

import os
from typing import Any

from src.gateway.governance.env_posture import is_enforcing, resolve_posture
from src.gateway.governance.kms_signer import (
    BaseKMSProvider,
    SoftwareEd25519Provider,
    SoftwareHMACProvider,
)


def get_kms_provider_class(name: str) -> type[BaseKMSProvider]:
    """Lazily resolve a KMS provider class by name or provider identifier."""
    normalized = name.strip()
    lower = normalized.lower()
    if normalized == "GCPKMSProvider" or lower == "gcp":
        from src.integrations.gcp.kms_provider import GCPKMSProvider

        return GCPKMSProvider
    if normalized == "AWSKMSProvider" or lower == "aws":
        from src.integrations.aws.kms_provider import AWSKMSProvider

        return AWSKMSProvider
    if normalized == "AzureKMSProvider" or lower == "azure":
        from src.integrations.azure.kms_provider import AzureKMSProvider

        return AzureKMSProvider
    if normalized == "SoftwareEd25519Provider" or lower in (
        "ed25519",
        "software_ed25519",
    ):
        return SoftwareEd25519Provider
    if normalized == "SoftwareHMACProvider" or lower in ("hmac", "software_hmac"):
        return SoftwareHMACProvider
    raise ValueError(f"Unknown KMS provider class or identifier: {name!r}")


def build_kms_provider(
    provider_name: str | None = None,
    **kwargs: Any,
) -> BaseKMSProvider:
    """Construct a KMS signing provider based on configuration and posture.

    Cloud KMS providers (``gcp``, ``aws``, ``azure``) are lazy-imported from
    ``src.integrations.{gcp,aws,azure}.kms_provider`` so Layer 1 remains free
    of vendor SDK imports. Software providers (``ed25519``, ``hmac``) are
    permitted only when ``is_enforcing(resolve_posture())`` is ``False``.
    """
    resolved_name = (
        provider_name
        or os.environ.get("KMS_PROVIDER")
        or os.environ.get("CAGE_KMS_PROVIDER")
        or "gcp"
    ).lower()

    posture = resolve_posture()
    enforcing = is_enforcing(posture)

    if resolved_name in ("ed25519", "software_ed25519"):
        if enforcing:
            raise RuntimeError(
                f"[SignerFactory] SoftwareEd25519Provider is forbidden in enforcing "
                f"posture ({posture.value}). Configure a Cloud KMS provider."
            )
        return SoftwareEd25519Provider(**kwargs)

    if resolved_name in ("hmac", "software_hmac"):
        if enforcing:
            raise RuntimeError(
                f"[SignerFactory] SoftwareHMACProvider is forbidden in enforcing "
                f"posture ({posture.value}). Configure a Cloud KMS provider."
            )
        return SoftwareHMACProvider(**kwargs)

    if resolved_name == "gcp":
        from src.integrations.gcp.kms_provider import GCPKMSProvider

        key_version_name = kwargs.pop(
            "key_version_name",
            os.environ.get("KMS_GOVERNANCE_KEY", ""),
        )
        kms_client = kwargs.pop("kms_client", None)
        if not key_version_name and kms_client is None:
            if enforcing:
                raise RuntimeError(
                    "[KMSSigner] KMS_GOVERNANCE_KEY is not set. "
                    "Set it to the full Cloud KMS key version resource name. "
                    "The legacy HMAC GOVERNANCE_SALT fallback has been removed. "
                    "See CTRL_KMS_001 in control_mappings.json."
                )
            return SoftwareEd25519Provider(**kwargs)
        return GCPKMSProvider(
            key_version_name=key_version_name,
            kms_client=kms_client,
            **kwargs,
        )

    if resolved_name == "aws":
        from src.integrations.aws.kms_provider import AWSKMSProvider

        key_id = kwargs.pop("key_id", os.environ.get("AWS_KMS_KEY_ID", ""))
        return AWSKMSProvider(key_id=key_id, **kwargs)

    if resolved_name == "azure":
        from src.integrations.azure.kms_provider import AzureKMSProvider

        vault_url = kwargs.pop("vault_url", os.environ.get("AZURE_KEYVAULT_URL", ""))
        key_name = kwargs.pop("key_name", os.environ.get("AZURE_KMS_KEY_NAME", ""))
        return AzureKMSProvider(vault_url=vault_url, key_name=key_name, **kwargs)

    raise RuntimeError(
        f"Unknown CAGE_KMS_PROVIDER '{resolved_name}'. Use 'gcp', 'aws', or 'azure'."
    )
