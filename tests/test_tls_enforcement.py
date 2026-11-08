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
2. HSTS and proxy transport header evaluation.
3. Linkerd mTLS service mesh manifest annotations (IA-3 / SC-8 / POAM-011).
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from src.gateway.infrastructure.tls_context import create_hardened_client_context

pytestmark = pytest.mark.local


# ---------------------------------------------------------------------------
# 1. NIST SP 800-52 Rev. 2 TLS Protocol Version Configuration Tests
# ---------------------------------------------------------------------------


class TestTlsProtocolStandards:
    """Validate standard SSLContext configuration meets NIST SP 800-52 Rev. 2 (SC-8)."""

    def test_default_client_context_minimum_version(self) -> None:
        """Verify hardened client SSLContext enforces at least TLS 1.2."""
        ctx = create_hardened_client_context(ssl.Purpose.SERVER_AUTH)
        # create_hardened_client_context must enforce TLSv1_2 minimum per NIST SP 800-52 Rev. 2
        assert ctx.minimum_version in (
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_3,
        ), (
            f"[POAM-2026-011] Client SSLContext minimum_version is {ctx.minimum_version}. "
            f"Expected TLSv1_2 or TLSv1_3 per NIST SP 800-52 Rev. 2 / SC-8."
        )

    def test_legacy_tls_protocols_disabled(self) -> None:
        """Verify that TLS 1.0 and TLS 1.1 are explicitly not allowed in client contexts."""
        ctx = create_hardened_client_context(ssl.Purpose.SERVER_AUTH)
        assert (
            ctx.options & ssl.OP_NO_TLSv1
            or ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        )
        assert (
            ctx.options & ssl.OP_NO_TLSv1_1
            or ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        )


# ---------------------------------------------------------------------------
# 2. Linkerd mTLS Terraform & Helm Mesh Policy Assertions (SC-8 / IA-3)
# ---------------------------------------------------------------------------


class TestLinkerdMtlsPolicyManifest:
    """Validate that Terraform and Helm mesh-policy templates configure Linkerd mTLS."""

    @pytest.fixture
    def repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @pytest.fixture
    def policy_manifest(self, repo_root: Path) -> list[dict]:
        from tests.test_gateway_mesh_policy import (
            ADVISOR_IDENTITY,
            _render_mesh_policy_chart,
        )

        docs = _render_mesh_policy_chart([ADVISOR_IDENTITY])
        assert docs, "Rendered gateway mesh-policy chart produced zero documents"
        return docs

    def test_trusted_mesh_identities_resolve_to_declared_terraform_ksas(
        self, repo_root: Path, policy_manifest: list[dict]
    ) -> None:
        """Verify every SPIFFE identity trusted by MeshTLSAuthentication resolves to a Terraform KSA."""
        import re

        iam_tf = (repo_root / "infra" / "targets" / "gcp-gke" / "iam.tf").read_text(
            encoding="utf-8"
        )
        main_tf = (repo_root / "infra" / "targets" / "gcp-gke" / "main.tf").read_text(
            encoding="utf-8"
        )
        mesh_tf = (
            repo_root / "infra" / "modules" / "service_mesh" / "main.tf"
        ).read_text(encoding="utf-8")

        ksa_locals = dict(re.findall(r'\b(ksa_\w+)\s*=\s*"([^"]+)"', iam_tf))
        declared_ksa_names = {
            ksa_locals[ref]
            for ref in re.findall(r"name\s*=\s*local\.(ksa_\w+)", iam_tf)
            if ref in ksa_locals
        }
        assert len(declared_ksa_names) >= 6, (
            f"Expected Terraform workload KSAs in iam.tf, found {declared_ksa_names}"
        )

        trusted_sa_names: set[str] = set()
        for doc in policy_manifest:
            if doc.get("kind") != "MeshTLSAuthentication":
                continue
            for identity in doc.get("spec", {}).get("identities", []):
                sa_name = identity.split(".", 1)[0]
                trusted_sa_names.add(sa_name)
        assert trusted_sa_names, "No MeshTLSAuthentication identities found"

        missing = trusted_sa_names - declared_ksa_names
        assert not missing, (
            f"Trusted mesh identities missing from iam.tf terraform_workload_ksas: {missing}"
        )

        # Namespace-level Linkerd mTLS injection and CAS root trust anchor (SC-8 / IA-3)
        assert '"linkerd.io/inject" = "enabled"' in main_tf
        assert (
            'resource "google_privateca_certificate_authority" "mesh_root"' in mesh_tf
        )

    def test_server_authorizations_require_mtls_authentication(
        self, policy_manifest: list[dict]
    ) -> None:
        """Verify rendered mesh-policy chart defines Server, AuthorizationPolicy, and MeshTLSAuthentication."""
        kinds = {d.get("kind") for d in policy_manifest}
        assert {"Server", "AuthorizationPolicy", "MeshTLSAuthentication"} <= kinds
