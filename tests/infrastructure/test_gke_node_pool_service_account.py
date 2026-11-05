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

"""Regression tests for GKE node-pool service account hardening (POAM-2026-187, CP-5).

Verifies that `infra/modules/gcp_gke_cluster/main.tf`:
1. Provisions a dedicated least-privilege Google Service Account
   (`google_service_account.gke_nodes`) rather than falling back to the Compute
   Engine default service account (`<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`).
2. Grants only `roles/container.defaultNodeServiceAccount` and
   `roles/artifactregistry.reader` to that node service account (Decision A3).
3. Sets `service_account = local.node_service_account_email` and intentionally
   retains `oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]`
   (Decision A4: legacy GCE OAuth access scopes are coarse pre-IAM VM ceilings
   where effective permissions equal `scope ∩ IAM roles`, so per Google's GKE
   hardening guidance `cloud-platform` is paired with the dedicated least-privilege
   GSA rather than brittle legacy per-API scope lists) inside all six
   `node_config` blocks (`google_container_cluster.primary`, `primary_nodes`,
   `general_spot_nodes`, `gpu_nodes`, `clickhouse_nodes`, `extra_pools`).
4. Records the Decision A3 / Decision A4 architectural rationale and the
   `<PROJECT_NUMBER>-compute@developer.gserviceaccount.com` de-privileging boundary
   directly in the HCL comments of `infra/modules/gcp_gke_cluster/main.tf`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "gcp_gke_cluster"
GKE_MAIN_TF = GKE_MODULE_DIR / "main.tf"
GKE_OUTPUTS_TF = GKE_MODULE_DIR / "outputs.tf"


def _strip_hcl_comments(text: str) -> str:
    """Remove `#` and `//` line comments from HCL source."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        lines.append(line.split("#", 1)[0])
    return "\n".join(lines)


def _extract_named_blocks(text: str, header_pattern: str) -> list[tuple[str, str]]:
    """Return `(header, body)` for every brace-balanced block matching `header_pattern`."""
    results: list[tuple[str, str]] = []
    for match in re.finditer(header_pattern, text, re.MULTILINE):
        brace_open = text.find("{", match.end() - 1)
        if brace_open == -1:
            continue
        depth = 0
        pos = brace_open
        while pos < len(text):
            ch = text[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    results.append((match.group(0), text[brace_open + 1 : pos]))
                    break
            pos += 1
    return results


class TestGkeNodePoolServiceAccount:
    """Verify POAM-2026-187 / CP-5 dedicated node GSA and `node_config` bindings."""

    def test_dedicated_node_service_account_resource_is_defined(self) -> None:
        source = _strip_hcl_comments(GKE_MAIN_TF.read_text(encoding="utf-8"))
        sa_blocks = _extract_named_blocks(
            source, r'resource\s+"google_service_account"\s+"gke_nodes"\s*\{'
        )
        assert len(sa_blocks) == 1, (
            "Expected exactly one google_service_account.gke_nodes resource in gcp_gke_cluster/main.tf"
        )
        _, body = sa_blocks[0]
        assert "account_id" in body and "local.node_service_account_id" in body
        assert (
            'node_service_account_id    = "cage-gke-nodes-${var.environment}"' in source
        )
        assert (
            'node_service_account_email = "${google_service_account.gke_nodes.account_id}@${var.project_id}.iam.gserviceaccount.com"'
            in source
        )

    def test_node_service_account_grants_only_minimal_hardening_roles(self) -> None:
        source = _strip_hcl_comments(GKE_MAIN_TF.read_text(encoding="utf-8"))
        iam_blocks = _extract_named_blocks(
            source, r'resource\s+"google_project_iam_member"\s+"[^"]+"\s*\{'
        )
        assert len(iam_blocks) == 2, (
            f"Expected exactly 2 google_project_iam_member resources in gcp_gke_cluster/main.tf, found {len(iam_blocks)}"
        )
        roles: set[str] = set()
        for header, body in iam_blocks:
            role_match = re.search(r'role\s*=\s*"([^"]+)"', body)
            assert role_match is not None, f"Missing role in {header}"
            roles.add(role_match.group(1))
            assert (
                'member  = "serviceAccount:${local.node_service_account_email}"' in body
            ), (
                f"{header} must bind serviceAccount:${{local.node_service_account_email}}"
            )

        assert roles == {
            "roles/container.defaultNodeServiceAccount",
            "roles/artifactregistry.reader",
        }

    @pytest.mark.parametrize(
        ("resource_type", "resource_name"),
        [
            ("google_container_cluster", "primary"),
            ("google_container_node_pool", "primary_nodes"),
            ("google_container_node_pool", "general_spot_nodes"),
            ("google_container_node_pool", "gpu_nodes"),
            ("google_container_node_pool", "clickhouse_nodes"),
            ("google_container_node_pool", "extra_pools"),
        ],
    )
    def test_every_cluster_and_node_pool_sets_dedicated_service_account_and_cloud_platform_scope(
        self, resource_type: str, resource_name: str
    ) -> None:
        source = _strip_hcl_comments(GKE_MAIN_TF.read_text(encoding="utf-8"))
        resource_blocks = _extract_named_blocks(
            source,
            rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{',
        )
        assert len(resource_blocks) == 1, (
            f"Expected resource {resource_type}.{resource_name} in gcp_gke_cluster/main.tf"
        )
        _, resource_body = resource_blocks[0]
        node_configs = _extract_named_blocks(resource_body, r"\bnode_config\s*\{")
        assert len(node_configs) == 1, (
            f"Expected exactly one node_config block in {resource_type}.{resource_name}"
        )
        _, node_config_body = node_configs[0]
        assert re.search(
            r"service_account\s*=\s*local\.node_service_account_email\b",
            node_config_body,
        ), (
            f"{resource_type}.{resource_name}.node_config must set service_account = local.node_service_account_email"
        )
        assert "https://www.googleapis.com/auth/cloud-platform" in node_config_body, (
            f"{resource_type}.{resource_name}.node_config must retain cloud-platform oauth_scopes bounded by IAM"
        )

    def test_total_node_config_block_count_is_six(self) -> None:
        source = _strip_hcl_comments(GKE_MAIN_TF.read_text(encoding="utf-8"))
        all_node_configs = _extract_named_blocks(source, r"\bnode_config\s*\{")
        assert len(all_node_configs) == 6, (
            f"Expected 6 node_config blocks in gcp_gke_cluster/main.tf, found {len(all_node_configs)}"
        )
        for _, body in all_node_configs:
            assert "service_account = local.node_service_account_email" in body

    def test_cluster_and_primary_pool_depend_on_node_sa_iam_bindings(self) -> None:
        source = _strip_hcl_comments(GKE_MAIN_TF.read_text(encoding="utf-8"))
        for resource_type, resource_name in (
            ("google_container_cluster", "primary"),
            ("google_container_node_pool", "primary_nodes"),
        ):
            blocks = _extract_named_blocks(
                source, rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{'
            )
            assert len(blocks) == 1
            _, body = blocks[0]
            assert "google_project_iam_member.gke_nodes_default_node_sa" in body
            assert (
                "google_project_iam_member.gke_nodes_artifact_registry_reader" in body
            )

    def test_outputs_tf_exposes_node_service_account_email(self) -> None:
        outputs_tf = _strip_hcl_comments(GKE_OUTPUTS_TF.read_text(encoding="utf-8"))
        output_blocks = _extract_named_blocks(
            outputs_tf, r'output\s+"node_service_account_email"\s*\{'
        )
        assert len(output_blocks) == 1
        _, body = output_blocks[0]
        assert "local.node_service_account_email" in body

    def test_decision_a3_and_a4_rationale_comment_is_recorded_in_main_tf(self) -> None:
        raw_main_tf = GKE_MAIN_TF.read_text(encoding="utf-8")
        assert (
            "Decision A3 (Minimal IAM roles on the dedicated node GSA):" in raw_main_tf
        )
        assert (
            'Decision A4 (Why oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"] stays):'
            in raw_main_tf
        )
        assert "effective = scope ∩ IAM" in raw_main_tf
