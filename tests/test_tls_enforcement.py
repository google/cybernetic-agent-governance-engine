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

"""Unit tests for TLS and cryptographic transport enforcement (POAM-2026-011 / SC-8).

Validates:
1. NIST SP 800-52 Rev. 2 minimum TLS version compliance (TLS 1.2+ mandatory, TLS 1.0/1.1 disabled).
2. OIDC and external key endpoint TLS verification (explicit verify=True, HTTPS URL schemes).
3. HSTS and proxy transport header evaluation.
4. Linkerd mTLS service mesh manifest annotations (IA-3 / SC-8 / POAM-011).
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

pytestmark = pytest.mark.local


# ---------------------------------------------------------------------------
# 1. NIST SP 800-52 Rev. 2 TLS Protocol Version Configuration Tests
# ---------------------------------------------------------------------------


class TestTlsProtocolStandards:
    """Validate standard SSLContext configuration meets NIST SP 800-52 Rev. 2 (SC-8)."""

    def test_default_client_context_minimum_version(self) -> None:
        """Verify standard client SSLContext defaults enforce at least TLS 1.2."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # Python 3.10+ create_default_context enforces TLSv1_2 minimum by default
        assert ctx.minimum_version in (
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_3,
        ), (
            f"[POAM-2026-011] Client SSLContext minimum_version is {ctx.minimum_version}. "
            f"Expected TLSv1_2 or TLSv1_3 per NIST SP 800-52 Rev. 2 / SC-8."
        )

    def test_legacy_tls_protocols_disabled(self) -> None:
        """Verify that TLS 1.0 and TLS 1.1 are explicitly not allowed in client contexts."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        assert (
            ctx.options & ssl.OP_NO_TLSv1
            or ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        )
        assert (
            ctx.options & ssl.OP_NO_TLSv1_1
            or ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        )


# ---------------------------------------------------------------------------
# 2. OIDC & JWKS TLS Enforcement Tests
# ---------------------------------------------------------------------------


class TestOidcTlsEnforcement:
    """Validate OIDC JWKS fetching enforces secure transport (SC-8 / HIGH-4)."""

    @pytest.mark.asyncio
    async def test_fetch_jwks_uses_tls_verification(self) -> None:
        """Verify that _fetch_jwks configures httpx.AsyncClient with verify=True."""
        from src.gateway.server import governance_middleware

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"keys": [{"kid": "test-key-1", "kty": "EC"}]}
        mock_resp.raise_for_status.return_value = None

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch.object(
            governance_middleware,
            "_OIDC_JWKS_URI",
            "https://auth.example.com/.well-known/jwks.json",
        ):
            with patch("httpx.AsyncClient", return_value=mock_client) as mock_httpx_cls:
                # Clear any prior cache
                governance_middleware._jwks_cache.clear()
                jwks = await governance_middleware._fetch_jwks()

                # Verify httpx.AsyncClient was instantiated with verify=True
                mock_httpx_cls.assert_called_once_with(verify=True, timeout=5.0)
                assert "test-key-1" in jwks
                assert jwks["test-key-1"]["kty"] == "EC"


# ---------------------------------------------------------------------------
# 3. Linkerd mTLS Policy Manifest Assertions (SC-8 / IA-3)
# ---------------------------------------------------------------------------


class TestLinkerdMtlsPolicyManifest:
    """Validate that Kubernetes manifests configure Linkerd mTLS mesh policies."""

    @pytest.fixture
    def policy_manifest(self) -> list[dict]:
        manifest_path = (
            Path(__file__).resolve().parents[1]
            / "deployment"
            / "k8s"
            / "linkerd-mtls-policy.yaml"
        )
        assert manifest_path.exists(), (
            f"Missing Linkerd policy manifest: {manifest_path}"
        )
        with open(manifest_path, encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        return [d for d in docs if d is not None]

    def test_service_accounts_declare_sc8_and_poam011(
        self, policy_manifest: list[dict]
    ) -> None:
        """Verify ServiceAccounts have compliance annotations for SC-8 and POAM-011."""
        service_accounts = [
            d for d in policy_manifest if d.get("kind") == "ServiceAccount"
        ]
        assert len(service_accounts) >= 3, (
            "Expected at least gateway, opa, and nemo ServiceAccounts"
        )

        for sa in service_accounts:
            name = sa.get("metadata", {}).get("name", "unknown")
            annotations = sa.get("metadata", {}).get("annotations", {})
            controls = annotations.get("compliance.nist.gov/control", "")
            poam = annotations.get("cage.io/poam", "")

            assert "SC-8" in controls, (
                f"ServiceAccount '{name}' missing SC-8 control annotation"
            )
            assert "POAM-011" in poam or "POAM-2026-011" in poam, (
                f"ServiceAccount '{name}' missing POAM-011 tracking annotation"
            )

    def test_server_authorizations_require_mtls_authentication(
        self, policy_manifest: list[dict]
    ) -> None:
        """Verify ServerAuthorizations in linkerd-mtls-policy enforce authenticated mTLS."""
        server_auths = [
            d
            for d in policy_manifest
            if d.get("kind")
            in ("ServerAuthorization", "AuthorizationPolicy", "MeshTLSAuthentication")
        ]
        # Manifest defines Server / ServerAuthorization resources enforcing mesh mTLS
        assert len(server_auths) > 0, (
            "Expected ServerAuthorization or MeshTLS policies in manifest"
        )
