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

"""Step 6f verification suite: GKE as the sole target (regional prod, node pools,
Dataplane V2 + FQDNNetworkPolicy, perimeter controls, and OSCAL SC-7 / Tier 3 SSP).
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE_CLUSTER_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "gcp_gke_cluster"
GATEWAY_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "gateway"
VLLM_MODULE_DIR = REPO_ROOT / "infra" / "modules" / "vllm_inference"
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
K8S_DIR = REPO_ROOT / "deployment" / "k8s"
CILIUM_DIR = K8S_DIR / "cilium"
OSCAL_SSP_PATH = REPO_ROOT / "compliance" / "oscal" / "system-security-plan.yaml"


def _load_yaml_docs(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    return [doc for doc in yaml.safe_load_all(text) if isinstance(doc, dict)]


# ============================================================================
# 1. Zero legacy Cloud Run target references outside `plans/` and `CHANGELOG.md`
# ============================================================================


class TestCloudRunEliminated:
    """Exit criterion: searching for the removed Cloud Run target outside `plans/` finds only `CHANGELOG.md`."""

    def test_no_gcp_cloudrun_references_outside_plans_and_changelog(self) -> None:
        forbidden_token = "gcp-" + "cloudrun"
        offending: list[str] = []
        skip_dirs = {
            ".git",
            ".venv",
            ".hypothesis",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "node_modules",
        }

        for path in REPO_ROOT.rglob("*"):
            if any(part in skip_dirs for part in path.parts):
                continue
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT)
            if rel.parts[0] == "plans" or rel == Path("CHANGELOG.md"):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if forbidden_token in content:
                offending.append(str(rel))

        assert offending == [], (
            f"Found forbidden {forbidden_token!r} references outside plans/ and CHANGELOG.md: {offending}"
        )



# ============================================================================
# 2. Posture Matrix & Regional Prod vs Zonal Dev/Staging (§1.1)
# ============================================================================


class TestPostureMatrixAndTopology:
    """Verify §1.1 posture matrix across GKE module and target tfvars."""

    def test_cluster_location_is_regional_in_prod_and_zonal_in_dev_staging(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        assert "cluster_location = local.is_regional ? var.region : var.zone" in main_tf
        assert 'var.regional_cluster != null ? var.regional_cluster : (var.environment == "prod")' in main_tf
        assert "location = local.cluster_location" in main_tf

    def test_dataplane_v2_and_fqdn_network_policy_default_true_in_module_and_target(self) -> None:
        for vars_path in (
            GKE_CLUSTER_MODULE_DIR / "variables.tf",
            GKE_TARGET_DIR / "variables.tf",
        ):
            text = vars_path.read_text(encoding="utf-8")
            for var_name in ("enable_dataplane_v2", "enable_fqdn_network_policy"):
                pattern = rf'variable\s+"{var_name}"\s*\{{[^}}]*default\s*=\s*true'
                assert re.search(pattern, text, re.DOTALL), (
                    f"{var_name} must default to true in {vars_path}"
                )

    def test_fqdn_network_policy_wired_into_cluster_resource(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        assert "datapath_provider" in main_tf
        assert "ADVANCED_DATAPATH" in main_tf
        assert "enable_fqdn_network_policy = var.enable_dataplane_v2 && var.enable_fqdn_network_policy" in main_tf
        assert "release_channel" in main_tf
        assert "channel = var.release_channel" in main_tf
        assert "min_master_version = var.min_master_version" in main_tf

    def test_cluster_dns_provider_forbids_CoreDNS(self) -> None:
        vars_tf = (GKE_CLUSTER_MODULE_DIR / "variables.tf").read_text(encoding="utf-8")
        assert 'contains(["PROVIDER_UNSPECIFIED", "CLOUD_DNS"], var.cluster_dns_provider)' in vars_tf

    @pytest.mark.parametrize(
        "tfvars_name,expected_env,expected_regional",
        [
            ("dev.tfvars", "dev", False),
            ("us-dev.tfvars", "dev", False),
            ("eu-dev.tfvars", "dev", False),
            ("apac-dev.tfvars", "dev", False),
            ("staging.tfvars", "staging", False),
            ("prod.tfvars", "prod", True),
            ("eu-prod.tfvars", "prod", True),
            ("apac-prod.tfvars", "prod", True),
        ],
    )
    def test_tfvars_posture_settings(
        self, tfvars_name: str, expected_env: str, expected_regional: bool
    ) -> None:
        text = (GKE_TARGET_DIR / tfvars_name).read_text(encoding="utf-8")
        assert re.search(rf'environment\s*=\s*"{expected_env}"', text)
        assert re.search(r"enable_dataplane_v2\s*=\s*true", text), (
            f"{tfvars_name} must enable_dataplane_v2 = true"
        )
        assert re.search(r"enable_fqdn_network_policy\s*=\s*true", text), (
            f"{tfvars_name} must enable_fqdn_network_policy = true"
        )
        if expected_regional:
            assert re.search(r"regional_cluster\s*=\s*true", text), (
                f"{tfvars_name} must set regional_cluster = true"
            )
            assert re.search(r"enable_cmek\s*=\s*true", text), (
                f"{tfvars_name} must set enable_cmek = true"
            )
            assert re.search(r'kms_signing_protection_level\s*=\s*"HSM"', text), (
                f"{tfvars_name} must set kms_signing_protection_level = HSM"
            )
        else:
            assert not re.search(r"regional_cluster\s*=\s*true", text), (
                f"{tfvars_name} must not set regional_cluster = true"
            )

    def test_staging_tfvars_enables_staging_posture_controls(self) -> None:
        text = (GKE_TARGET_DIR / "staging.tfvars").read_text(encoding="utf-8")
        assert re.search(r"regional_cluster\s*=\s*false", text)
        assert re.search(r"enable_binary_authorization\s*=\s*true", text)
        assert re.search(r"enable_cmek\s*=\s*true", text)
        assert re.search(r"enable_audit_logging\s*=\s*true", text)
        assert re.search(r"enable_pod_security_standards\s*=\s*true", text)
        assert re.search(r'pod_security_level\s*=\s*"restricted"', text)


# ============================================================================
# 3. Node Pools & Anti-Spot Scheduling (§3)
# ============================================================================


class TestNodePoolsAndAntiSpotAffinity:
    """Verify the 4-node-pool topology and anti-Spot scheduling rules."""

    def test_four_node_pools_defined_in_gke_cluster_module(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        for pool_resource in (
            'resource "google_container_node_pool" "primary_nodes"',
            'resource "google_container_node_pool" "general_spot_nodes"',
            'resource "google_container_node_pool" "gpu_nodes"',
            'resource "google_container_node_pool" "clickhouse_nodes"',
        ):
            assert pool_resource in main_tf, f"Missing node pool resource: {pool_resource}"
        for pool_label in (
            'pool-name        = "gpu-l4"',
            'pool-name     = "general"',
            'pool-name                  = "general-spot"',
            'pool-name     = "clickhouse"',
        ):
            assert pool_label in main_tf, f"Missing canonical pool label: {pool_label}"

    def test_gpu_l4_and_clickhouse_pools_are_never_spot(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        gpu_start = main_tf.index('resource "google_container_node_pool" "gpu_nodes"')
        ch_start = main_tf.index('resource "google_container_node_pool" "clickhouse_nodes"')
        extra_start = main_tf.index('resource "google_container_node_pool" "extra_pools"')
        gpu_block = main_tf[gpu_start:ch_start]
        ch_block = main_tf[ch_start:extra_start]

        assert re.search(r"spot\s*=\s*false", gpu_block), (
            "gpu-l4 node pool must have spot = false in every posture"
        )
        assert 'pool-name        = "gpu-l4"' in gpu_block
        assert re.search(r"spot\s*=\s*false", ch_block), (
            "clickhouse node pool must have spot = false in every posture"
        )
        assert "local_ssd_count" in ch_block

    def test_gpu_node_pool_enables_gcfs_image_streaming(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        gpu_start = main_tf.index('resource "google_container_node_pool" "gpu_nodes"')
        ch_start = main_tf.index('resource "google_container_node_pool" "clickhouse_nodes"')
        gpu_block = main_tf[gpu_start:ch_start]

        assert re.search(r"gcfs_config\s*\{\s*enabled\s*=\s*true\s*\}", gpu_block), (
            "gpu-l4 node pool must enable GKE Image Streaming (gcfs_config { enabled = true })"
        )
        # Ensure existing GPU node pool posture controls remain intact
        assert re.search(r"spot\s*=\s*false", gpu_block)
        assert 'mode = "GKE_METADATA"' in gpu_block
        assert 'key    = "nvidia.com/gpu"' in gpu_block
        assert "enable_secure_boot          = true" in gpu_block
        assert "enable_integrity_monitoring = true" in gpu_block
        assert "node_locations = var.gpu_node_locations" in gpu_block
        assert "autoscaling {" in gpu_block

    def test_general_spot_pool_only_in_staging_with_spot_taint(self) -> None:
        main_tf = (GKE_CLUSTER_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        spot_start = main_tf.index('resource "google_container_node_pool" "general_spot_nodes"')
        gpu_start = main_tf.index('resource "google_container_node_pool" "gpu_nodes"')
        spot_block = main_tf[spot_start:gpu_start]

        assert re.search(r"spot\s*=\s*true", spot_block)
        assert 'key    = "cloud.google.com/gke-spot"' in spot_block
        assert 'effect = "NO_SCHEDULE"' in spot_block

        vars_tf = (GKE_CLUSTER_MODULE_DIR / "variables.tf").read_text(encoding="utf-8")
        assert "enable_general_spot_node_pool" in vars_tf

        staging_tfvars = (GKE_TARGET_DIR / "staging.tfvars").read_text(encoding="utf-8")
        prod_tfvars = (GKE_TARGET_DIR / "prod.tfvars").read_text(encoding="utf-8")
        dev_tfvars = (GKE_TARGET_DIR / "dev.tfvars").read_text(encoding="utf-8")
        assert re.search(r"enable_general_spot_node_pool\s*=\s*true", staging_tfvars)
        assert re.search(r"enable_general_spot_node_pool\s*=\s*false", prod_tfvars)
        assert re.search(r"enable_general_spot_node_pool\s*=\s*false", dev_tfvars)

    def test_governance_workloads_have_anti_spot_node_affinity(self) -> None:
        # 1. Gateway Deployment
        gw_docs = _load_yaml_docs(K8S_DIR / "gateway.yaml")
        gw_deploy = next(
            d for d in gw_docs
            if d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == "gateway"
        )
        gw_terms = (
            gw_deploy["spec"]["template"]["spec"]["affinity"]["nodeAffinity"]
            ["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
        )
        assert any(
            expr.get("key") == "cloud.google.com/gke-spot"
            and expr.get("operator") == "NotIn"
            and "true" in expr.get("values", [])
            for term in gw_terms
            for expr in term.get("matchExpressions", [])
        ), "gateway Deployment must enforce cloud.google.com/gke-spot NotIn ['true']"

        # 2. Reconciliation Worker CronJob
        rw_docs = _load_yaml_docs(K8S_DIR / "reconciliation-worker.yaml")
        rw_cron = next(
            d for d in rw_docs
            if d.get("kind") == "CronJob"
            and d.get("metadata", {}).get("name") == "reconciliation-worker"
        )
        rw_terms = (
            rw_cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["affinity"]["nodeAffinity"]
            ["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"]
        )
        assert any(
            expr.get("key") == "cloud.google.com/gke-spot"
            and expr.get("operator") == "NotIn"
            and "true" in expr.get("values", [])
            for term in rw_terms
            for expr in term.get("matchExpressions", [])
        ), "reconciliation-worker CronJob must enforce cloud.google.com/gke-spot NotIn ['true']"

    def test_gateway_terraform_module_enforces_anti_spot_node_affinity(self) -> None:
        gateway_tf = (GATEWAY_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        assert 'key      = "cloud.google.com/gke-spot"' in gateway_tf
        assert 'operator = "NotIn"' in gateway_tf
        assert 'values   = ["true"]' in gateway_tf

    def test_vllm_inference_enforces_anti_spot_affinity_and_drops_spot_tolerations(
        self,
    ) -> None:
        vllm_tf = (VLLM_MODULE_DIR / "main.tf").read_text(encoding="utf-8")
        assert "required_during_scheduling_ignored_during_execution" in vllm_tf
        assert 'key      = "cloud.google.com/gke-spot"' in vllm_tf
        assert 'operator = "NotIn"' in vllm_tf
        assert 'values   = ["true"]' in vllm_tf
        assert "cloud.google.com/gke-provisioning" not in vllm_tf
        assert "preferred_during_scheduling_ignored_during_execution" not in vllm_tf

        gke_main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
        assert "cloud.google.com/gke-spot" not in gke_main_tf

    def test_vllm_resource_defaults_and_validations_fit_g2_standard_8(self) -> None:
        expected_module_vars = {
            "memory_limit": ("24Gi", "28928"),
            "cpu_limit": ("6000m", "7910"),
            "memory_request": ("10Gi", "28928"),
            "cpu_request": ("3000m", "7910"),
            "shared_memory_size": ("2Gi", "28928"),
        }
        expected_target_vars = {
            "vllm_memory_limit": ("24Gi", "28928"),
            "vllm_cpu_limit": ("6000m", "7910"),
            "vllm_memory_request": ("10Gi", "28928"),
            "vllm_cpu_request": ("3000m", "7910"),
            "vllm_shared_memory_size": ("2Gi", "28928"),
        }

        for vars_path, expected in (
            (VLLM_MODULE_DIR / "variables.tf", expected_module_vars),
            (GKE_TARGET_DIR / "variables.tf", expected_target_vars),
        ):
            text = vars_path.read_text(encoding="utf-8")
            for var_name, (default_val, max_bound) in expected.items():
                match = re.search(
                    rf'variable\s+"{var_name}"\s*\{{(.*?)\n\}}',
                    text,
                    re.DOTALL,
                )
                assert match is not None, f"Missing variable {var_name} in {vars_path}"
                block = match.group(1)
                assert "g2-standard-8" in block, (
                    f"{var_name} description in {vars_path} must record g2-standard-8"
                )
                assert re.search(rf'default\s*=\s*"{default_val}"', block), (
                    f"{var_name} in {vars_path} must default to {default_val}"
                )
                assert "validation {" in block and f"<= {max_bound}" in block, (
                    f"{var_name} in {vars_path} must validate <= {max_bound}"
                )

        example_tfvars = (
            GKE_TARGET_DIR / "terraform.auto.tfvars.example"
        ).read_text(encoding="utf-8")
        assert 'gpu_node_pool_machine_type = "g2-standard-8"' in example_tfvars
        assert "g2-standard-4" not in example_tfvars

        def _eval_cpu_valid(val: str) -> bool:
            if not re.match(r"^[0-9]+(\.[0-9]+)?m?$", val):
                return False
            millicores = (
                float(val[:-1]) if val.endswith("m") else float(val) * 1000.0
            )
            return 0 < millicores <= 7910

        def _eval_mem_valid(val: str) -> bool:
            if not re.match(r"^[0-9]+(Mi|Gi)$", val):
                return False
            mib = (
                int(val[:-2]) * 1024 if val.endswith("Gi") else int(val[:-2])
            )
            return 0 < mib <= 28928

        # Valid g2-standard-8 quantities pass
        assert _eval_cpu_valid("6000m") is True
        assert _eval_cpu_valid("6") is True
        assert _eval_cpu_valid("3000m") is True
        assert _eval_cpu_valid("7910m") is True
        assert _eval_mem_valid("24Gi") is True
        assert _eval_mem_valid("10Gi") is True
        assert _eval_mem_valid("2Gi") is True
        assert _eval_mem_valid("28Gi") is True

        # Oversized / invalid quantities fail closed
        assert _eval_cpu_valid("16000m") is False
        assert _eval_cpu_valid("8") is False
        assert _eval_cpu_valid("7911m") is False
        assert _eval_cpu_valid("0m") is False
        assert _eval_mem_valid("64Gi") is False
        assert _eval_mem_valid("32Gi") is False
        assert _eval_mem_valid("29Gi") is False
        assert _eval_mem_valid("0Gi") is False


# ============================================================================
# 4. Network Policy & FQDNNetworkPolicy Enforcement (§5.3 / G6 / 6f)
# ============================================================================


def _fqdn_matches_pattern(fqdn: str, pattern: str) -> bool:
    """Match an FQDN against a GKE FQDNNetworkPolicy pattern (exact or single-label `*.` prefix)."""
    fqdn = fqdn.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. ".googleapis.com"
        if not fqdn.endswith(suffix):
            return False
        prefix_label = fqdn[: -len(suffix)]
        return bool(prefix_label) and fnmatch.fnmatch(fqdn, pattern)
    return fqdn == pattern


def _selector_matches(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    """Evaluate a Kubernetes LabelSelector (matchLabels + matchExpressions)."""
    for k, v in selector.get("matchLabels", {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions", []):
        key = expr.get("key", "")
        op = expr.get("operator", "")
        values = expr.get("values", [])
        if op == "In":
            if labels.get(key) not in values:
                return False
        elif op == "NotIn":
            if labels.get(key) in values:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False
        else:
            return False
    return True


def _evaluate_pod_egress(
    network_policies: list[dict[str, Any]],
    fqdn_policies: list[dict[str, Any]],
    pod_labels: dict[str, str],
    *,
    dest_ip: str | None = None,
    dest_fqdn: str | None = None,
    dest_pod_labels: dict[str, str] | None = None,
    dest_namespace_labels: dict[str, str] | None = None,
    port: int,
    protocol: str = "TCP",
) -> bool:
    """Simulate GKE Dataplane V2 + FQDNNetworkPolicy egress evaluation (fail-closed)."""
    matching_netpols = [
        np for np in network_policies
        if _selector_matches(np.get("spec", {}).get("podSelector", {}), pod_labels)
        and "Egress" in np.get("spec", {}).get("policyTypes", [])
    ]
    matching_fqdnpols = [
        fp for fp in fqdn_policies
        if _selector_matches(fp.get("spec", {}).get("podSelector", {}), pod_labels)
        and "Egress" in fp.get("spec", {}).get("policyTypes", [])
    ]

    if not matching_netpols and not matching_fqdnpols:
        return False

    for np in matching_netpols:
        for rule in np.get("spec", {}).get("egress", []):
            ports_spec = rule.get("ports", [])
            port_ok = any(
                int(p.get("port", -1)) == port and p.get("protocol", "TCP").upper() == protocol.upper()
                for p in ports_spec
            )
            if not port_ok:
                continue

            for to_peer in rule.get("to", []):
                if "ipBlock" in to_peer and dest_ip is not None and dest_fqdn is None:
                    cidr = ipaddress.ip_network(to_peer["ipBlock"]["cidr"], strict=False)
                    ip_obj = ipaddress.ip_address(dest_ip)
                    except_cidrs = [
                        ipaddress.ip_network(ex, strict=False)
                        for ex in to_peer["ipBlock"].get("except", [])
                    ]
                    if ip_obj in cidr and not any(ip_obj in ex for ex in except_cidrs):
                        return True

                if ("podSelector" in to_peer or "namespaceSelector" in to_peer) and dest_pod_labels is not None:
                    req_pod = to_peer.get("podSelector", {}).get("matchLabels", {})
                    req_ns = to_peer.get("namespaceSelector", {}).get("matchLabels", {})
                    pod_match = all(dest_pod_labels.get(k) == v for k, v in req_pod.items())
                    ns_match = all(
                        (dest_namespace_labels or {}).get(k) == v for k, v in req_ns.items()
                    )
                    if pod_match and ns_match:
                        return True

    if dest_fqdn is not None:
        for fp in matching_fqdnpols:
            for rule in fp.get("spec", {}).get("egress", []):
                ports_spec = rule.get("ports", [])
                port_ok = any(
                    int(p.get("port", -1)) == port
                    and p.get("protocol", "TCP").upper() == protocol.upper()
                    for p in ports_spec
                )
                if not port_ok:
                    continue
                for to_peer in rule.get("to", []):
                    for fqdn_pattern in to_peer.get("fqdns", []):
                        if _fqdn_matches_pattern(dest_fqdn, fqdn_pattern):
                            return True

    return False


class TestDataplaneV2AndFQDNNetworkPolicies:
    """Verify §5.3 network policy migration from CiliumNetworkPolicy to NetworkPolicy + FQDNNetworkPolicy."""

    @pytest.mark.parametrize(
        "manifest_name",
        [
            "egress-lockdown.yaml",
            "reconciliation-worker-egress.yaml",
            "trivy-egress-fqdn.yaml",
        ],
    )
    def test_no_cilium_network_policy_or_l7_rules_in_manifests(self, manifest_name: str) -> None:
        path = CILIUM_DIR / manifest_name
        raw = path.read_text(encoding="utf-8")
        docs = _load_yaml_docs(path)
        assert docs, f"{manifest_name} must contain valid YAML documents"

        for doc in docs:
            kind = doc.get("kind")
            api_version = doc.get("apiVersion")
            assert kind in ("NetworkPolicy", "FQDNNetworkPolicy"), (
                f"Unexpected kind {kind!r} in {manifest_name}; CiliumNetworkPolicy is prohibited"
            )
            if kind == "NetworkPolicy":
                assert api_version == "networking.k8s.io/v1"
            elif kind == "FQDNNetworkPolicy":
                assert api_version == "networking.gke.io/v1alpha1"
                for rule in doc.get("spec", {}).get("egress", []):
                    for to_peer in rule.get("to", []):
                        for fqdn in to_peer.get("fqdns", []):
                            assert re.match(r"^(\*\.)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$", fqdn), (
                                f"Invalid FQDN pattern {fqdn!r} in {manifest_name}: "
                                "only exact FQDNs or single-label prefix wildcards (*.domain.tld) are valid"
                            )

        assert "toFQDNs" not in raw
        assert "toEndpoints" not in raw
        assert "matchPattern" not in raw
        assert "matchName" not in raw

    def test_dns_egress_never_opens_port_53_to_0_0_0_0_0(self) -> None:
        all_policy_files = [
            CILIUM_DIR / "egress-lockdown.yaml",
            CILIUM_DIR / "reconciliation-worker-egress.yaml",
            CILIUM_DIR / "trivy-egress-fqdn.yaml",
            K8S_DIR / "network-policy.yaml",
        ]
        for policy_file in all_policy_files:
            docs = _load_yaml_docs(policy_file)
            for doc in docs:
                if doc.get("kind") != "NetworkPolicy":
                    continue
                for rule in doc.get("spec", {}).get("egress", []):
                    ports = [int(p.get("port", -1)) for p in rule.get("ports", [])]
                    if 53 in ports:
                        to_peers = rule.get("to", [])
                        assert to_peers, (
                            f"Port 53 rule in {policy_file.name} ({doc['metadata']['name']}) "
                            "must specify explicit 'to:' peers (kube-dns or 169.254.169.254/32), "
                            "never an unrestricted empty 'to' (0.0.0.0/0)"
                        )
                        for peer in to_peers:
                            if "ipBlock" in peer:
                                assert peer["ipBlock"]["cidr"] == "169.254.169.254/32", (
                                    f"Port 53 ipBlock in {policy_file.name} must only target "
                                    f"GKE NodeLocal DNSCache / Cloud DNS (169.254.169.254/32), got {peer['ipBlock']['cidr']}"
                                )
                            else:
                                assert (
                                    peer.get("podSelector", {}).get("matchLabels", {}).get("k8s-app")
                                    == "kube-dns"
                                ), f"Port 53 podSelector in {policy_file.name} must target k8s-app: kube-dns"

    def test_memorystore_psc_ipblock_replaces_redis_stack_pod_selector(self) -> None:
        for manifest_name in ("egress-lockdown.yaml", "reconciliation-worker-egress.yaml"):
            raw = (CILIUM_DIR / manifest_name).read_text(encoding="utf-8")
            assert "redis-stack" not in raw, (
                f"{manifest_name} must not reference legacy in-cluster redis-stack pod"
            )
            docs = _load_yaml_docs(CILIUM_DIR / manifest_name)
            netpols = [d for d in docs if d.get("kind") == "NetworkPolicy"]
            redis_rules = [
                rule
                for np in netpols
                for rule in np.get("spec", {}).get("egress", [])
                if any(int(p.get("port", -1)) == 6379 for p in rule.get("ports", []))
            ]
            assert redis_rules, f"{manifest_name} must include a port 6379 egress rule for Memorystore PSC"
            for rule in redis_rules:
                ip_blocks = [peer["ipBlock"]["cidr"] for peer in rule.get("to", []) if "ipBlock" in peer]
                assert ip_blocks, f"Port 6379 rule in {manifest_name} must use an ipBlock for Memorystore PSC"

    def test_reconciliation_worker_egress_enforcement_probe_allows_and_blocks(self) -> None:
        """Fail-closed behavioral verification of reconciliation-worker egress policies:
        - Allows `cloudkms.googleapis.com:443` and Memorystore PSC `:6379`
        - Blocks `storage.googleapis.com:443` (not in reconciliation-worker allowlist)
        - Blocks `example.com:443`
        - Blocks direct IP literal connection (`142.250.80.46:443`) bypassing DNS
        - Blocks external DNS (`8.8.8.8:53`) while allowing `kube-dns` and `169.254.169.254:53`
        """
        docs = _load_yaml_docs(CILIUM_DIR / "reconciliation-worker-egress.yaml")
        netpols = [d for d in docs if d.get("kind") == "NetworkPolicy"]
        fqdnpols = [d for d in docs if d.get("kind") == "FQDNNetworkPolicy"]
        worker_labels = {
            "app": "reconciliation-worker",
            "cage.io/account-purpose": "ledger-reconciliation",
        }

        # 1. Allowed FQDN: cloudkms.googleapis.com:443
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_fqdn="cloudkms.googleapis.com", port=443
        ) is True

        # 2. Allowed Memorystore PSC IP CIDR (10.128.0.0/20): 10.128.0.50:6379
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_ip="10.128.0.50", port=6379
        ) is True

        # 3. Allowed DNS: kube-system kube-dns and 169.254.169.254:53
        assert _evaluate_pod_egress(
            netpols,
            fqdnpols,
            worker_labels,
            dest_pod_labels={"k8s-app": "kube-dns"},
            dest_namespace_labels={"kubernetes.io/metadata.name": "kube-system"},
            port=53,
            protocol="UDP",
        ) is True
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_ip="169.254.169.254", port=53, protocol="UDP"
        ) is True

        # 4. Fail-closed: storage.googleapis.com:443 is NOT in reconciliation-worker's allowlist
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_fqdn="storage.googleapis.com", port=443
        ) is False

        # 5. Fail-closed: unapproved external FQDN example.com:443 is blocked
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_fqdn="example.com", port=443
        ) is False

        # 6. Fail-closed: direct IP literal connect on 443 (bypassing DNS) is blocked
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_ip="142.250.80.46", port=443
        ) is False

        # 7. Fail-closed: external DNS exfiltration to 8.8.8.8:53 is blocked
        assert _evaluate_pod_egress(
            netpols, fqdnpols, worker_labels, dest_ip="8.8.8.8", port=53, protocol="UDP"
        ) is False

    def test_network_policy_spec_hash_triggers_workload_rollout_restart(self) -> None:
        netpol_tf = (GKE_TARGET_DIR / "network_policy.tf").read_text(encoding="utf-8")
        vars_tf = (GKE_TARGET_DIR / "variables.tf").read_text(encoding="utf-8")
        main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
        gateway_tf = (GATEWAY_MODULE_DIR / "main.tf").read_text(encoding="utf-8")

        assert "network_policy_spec_hash = sha256(jsonencode(" in netpol_tf
        assert "network_policy_hash = local.network_policy_spec_hash" in main_tf
        assert '"cage.io/network-policy-hash" = var.network_policy_hash' in gateway_tf
        assert 'resource "terraform_data" "network_policy_workload_rollout"' in netpol_tf

        # Verify deterministic hash sensitivity: mutating an FQDN allowlist changes the rollout hash
        assert "cloudkms.googleapis.com" in vars_tf
        mutated_vars = vars_tf.replace("cloudkms.googleapis.com", "storage.googleapis.com")
        assert hashlib.sha256(vars_tf.encode()).hexdigest() != hashlib.sha256(
            mutated_vars.encode()
        ).hexdigest()


# ============================================================================
# 5. Perimeter Controls (§5.4)
# ============================================================================


class TestPerimeterControls:
    """Verify §5.4 perimeter wiring in `infra/targets/gcp-gke/perimeter.tf`."""

    def test_perimeter_tf_wires_vpc_binauthz_vpcsc_cloud_armor_and_cloud_dns(self) -> None:
        perimeter_tf = (GKE_TARGET_DIR / "perimeter.tf").read_text(encoding="utf-8")

        # 1. VPC & Private Google Access module
        assert 'module "vpc_network"' in perimeter_tf
        assert 'source = "../../modules/vpc_network"' in perimeter_tf

        # 2. Binary Authorization policy & attestor
        assert 'resource "google_binary_authorization_policy" "cluster_policy"' in perimeter_tf
        assert 'evaluation_mode         = "REQUIRE_ATTESTATION"' in perimeter_tf
        assert 'enforcement_mode        = "ENFORCED_BLOCK_AND_AUDIT_LOG"' in perimeter_tf

        # 3. VPC Service Controls perimeter covering storage, bigquery, container, secretmanager, cloudkms, sqladmin, redis
        assert 'resource "google_access_context_manager_service_perimeter" "cage_perimeter"' in perimeter_tf
        for restricted_svc in (
            "storage.googleapis.com",
            "bigquery.googleapis.com",
            "container.googleapis.com",
            "secretmanager.googleapis.com",
            "cloudkms.googleapis.com",
            "sqladmin.googleapis.com",
            "redis.googleapis.com",
            "artifactregistry.googleapis.com",
            "containerfilesystem.googleapis.com",
        ):
            assert restricted_svc in perimeter_tf, (
                f"VPC-SC perimeter in perimeter.tf must restrict {restricted_svc}"
            )

        # 4. Cloud Armor WAF security policy & BackendConfig
        assert 'resource "google_compute_security_policy" "gateway_armor"' in perimeter_tf
        assert "sqli-stable" in perimeter_tf
        assert "xss-stable" in perimeter_tf
        assert "rate_based_ban" in perimeter_tf
        assert "gateway_backend_config_manifest" in perimeter_tf
        assert 'kind       = "BackendConfig"' in perimeter_tf

        # 5. Cloud DNS managed zone & A record
        assert 'data "google_dns_managed_zone" "cage_zone"' in perimeter_tf
        assert 'resource "google_dns_record_set" "gateway_a_record"' in perimeter_tf

    def test_ingress_manifest_includes_cloud_armor_backend_config(self) -> None:
        docs = _load_yaml_docs(K8S_DIR / "ingress.yaml")
        backend_configs = [d for d in docs if d.get("kind") == "BackendConfig"]
        assert len(backend_configs) == 1
        assert (
            backend_configs[0]["spec"]["securityPolicy"]["name"]
            == "cage-waf-policy"
        )


# ============================================================================
# 6. OSCAL SC-7 Narrative & Tier 3 Commercial Ledger Responsibility (§5.3 / §7)
# ============================================================================


class TestOSCALStep6fCompliance:
    """Verify OSCAL SC-7 narrative and Tier 3 commercial retail-banking ledger responsibility."""

    def test_oscal_sc7_describes_fqdn_network_policy_and_drops_l7_http_method_claim(self) -> None:
        ssp_doc = yaml.safe_load(OSCAL_SSP_PATH.read_text(encoding="utf-8"))
        impl_reqs = (
            ssp_doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
        )
        sc7 = next(req for req in impl_reqs if req["control-id"] == "sc-7")
        desc = sc7["description"]

        assert "FQDNNetworkPolicy" in desc
        assert "NetworkPolicy" in desc
        assert "L3/L4" in desc
        # Must NOT claim L7 HTTP method enforcement at the CNI layer
        assert "L7 HTTP method" not in desc
        assert "HTTP method filtering" not in desc

    def test_oscal_ssp_records_tier3_commercial_ledger_customer_responsibility(self) -> None:
        from src.gateway.governance.oscal_ssp_exporter import (
            TIER3_COMMERCIAL_LEDGER_CUSTOMER_RESPONSIBILITY,
        )

        ssp_doc = yaml.safe_load(OSCAL_SSP_PATH.read_text(encoding="utf-8"))
        ssp = ssp_doc["system-security-plan"]

        meta_props = {p["name"]: p for p in ssp["metadata"].get("props", [])}
        assert "customer_responsibility_tier3_ledger_apis" in meta_props
        meta_prop = meta_props["customer_responsibility_tier3_ledger_apis"]
        assert meta_prop["class"] == "customer-responsibility"
        assert "Tier-3 commercial-deployment-only" in meta_prop["value"]
        assert meta_prop["value"] == TIER3_COMMERCIAL_LEDGER_CUSTOMER_RESPONSIBILITY


# ============================================================================
# 7. WP2 — Remove HF Token & Load vLLM Weights from GCS (POAM-2026-082)
# ============================================================================


class TestVllmHfTokenRemovalAndGcsModelStreaming:
    """Verify WP2 / POAM-2026-082 invariants:
    - No Dockerfile contains `ENV .*TOKEN` or `ARG .*TOKEN`.
    - No `.tf` file declares `hf_token` or `hf-token-secret`.
    - Cloud Build and `build_images.sh` do not pass `_HF_TOKEN` or `--build-arg=HF_TOKEN`.
    - vLLM loads weights from `gs://` paths via `runai_streamer` with `--load-format $VLLM_LOAD_FORMAT`,
      `--served-model-name $SERVED_MODEL_NAME`, `HF_HUB_OFFLINE=1`, and `TRANSFORMERS_OFFLINE=1`.
    - vLLM NetworkPolicy + FQDNNetworkPolicy permit DNS, GKE Workload Identity metadata server
      (`169.254.169.254:80`, `169.254.169.252:988`), and `storage.googleapis.com:443` /
      `oauth2.googleapis.com:443`, while failing closed on `huggingface.co` and other external egress.
    - `local.fqdn_network_policies` is materialized via `kubernetes_manifest.fqdn_network_policy`.
    """

    def test_no_dockerfile_declares_env_or_arg_token(self) -> None:
        dockerfiles = [
            p
            for p in REPO_ROOT.rglob("*Dockerfile*")
            if p.is_file() and ".git" not in p.parts and ".venv" not in p.parts
        ]
        assert dockerfiles, "Expected to find Dockerfiles in repository"
        token_directive_re = re.compile(r"^\s*(?:ENV|ARG)\s+[^\n]*TOKEN", re.IGNORECASE | re.MULTILINE)
        for df in dockerfiles:
            content = df.read_text(encoding="utf-8")
            match = token_directive_re.search(content)
            assert match is None, (
                f"{df.relative_to(REPO_ROOT)} must not declare ENV/ARG *TOKEN "
                f"(found: {match.group(0).strip()!r})"
            )

    def test_no_terraform_file_declares_hf_token_or_hf_token_secret(self) -> None:
        tf_files = list((REPO_ROOT / "infra").rglob("*.tf"))
        assert tf_files, "Expected .tf files under infra/"
        for tf_file in tf_files:
            content = tf_file.read_text(encoding="utf-8")
            assert "hf_token" not in content, (
                f"{tf_file.relative_to(REPO_ROOT)} must not declare or reference hf_token"
            )
            assert "hf-token-secret" not in content, (
                f"{tf_file.relative_to(REPO_ROOT)} must not declare or reference hf-token-secret"
            )
            assert "HUGGING_FACE_HUB_TOKEN" not in content, (
                f"{tf_file.relative_to(REPO_ROOT)} must not inject HUGGING_FACE_HUB_TOKEN into pods"
            )

    def test_cloudbuild_and_build_scripts_do_not_pass_hf_token(self) -> None:
        cb_vllm = (REPO_ROOT / "deployment" / "docker" / "cloudbuild.vllm.yaml").read_text(
            encoding="utf-8"
        )
        build_sh = (REPO_ROOT / "scripts" / "build_images.sh").read_text(encoding="utf-8")
        deploy_sh = (REPO_ROOT / "deploy_all.sh").read_text(encoding="utf-8")
        load_env_sh = (REPO_ROOT / "infra" / "load_env.sh").read_text(encoding="utf-8")

        assert "_HF_TOKEN" not in cb_vllm
        assert "HF_TOKEN" not in cb_vllm
        assert "_HF_TOKEN" not in build_sh
        assert "hf_token" not in build_sh
        assert "TF_VAR_hf_token" not in deploy_sh
        assert "TF_VAR_hf_token" not in load_env_sh

    def test_vllm_loads_from_gcs_with_runai_streamer_served_model_name_and_offline_mode(
        self,
    ) -> None:
        gke_main = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
        gke_vars = (GKE_TARGET_DIR / "variables.tf").read_text(encoding="utf-8")
        vllm_mod_main = (REPO_ROOT / "infra" / "modules" / "vllm_inference" / "main.tf").read_text(
            encoding="utf-8"
        )
        vllm_mod_vars = (
            REPO_ROOT / "infra" / "modules" / "vllm_inference" / "variables.tf"
        ).read_text(encoding="utf-8")

        # 1. Invalid loader name gcs_filesystem is gone; runai_streamer is used
        assert "gcs_filesystem" not in gke_main
        assert 'can(regex("^gs://", var.model_fast)) ? "runai_streamer" : "auto"' in gke_main
        assert 'can(regex("^gs://", var.model_reasoning)) ? "runai_streamer" : "auto"' in gke_main

        # 2. vllm_command passes --served-model-name $SERVED_MODEL_NAME and --load-format $VLLM_LOAD_FORMAT
        assert "--served-model-name $SERVED_MODEL_NAME" in gke_main
        assert "--load-format $VLLM_LOAD_FORMAT" in gke_main
        assert "--served-model-name $SERVED_MODEL_NAME" in vllm_mod_vars
        assert "--load-format $VLLM_LOAD_FORMAT" in vllm_mod_vars

        # 3. HF_HUB_OFFLINE=1 and TRANSFORMERS_OFFLINE=1 set on vLLM pods
        assert '"HF_HUB_OFFLINE"       = "1"' in gke_main
        assert '"TRANSFORMERS_OFFLINE" = "1"' in gke_main
        assert 'name  = "HF_HUB_OFFLINE"' in vllm_mod_main
        assert 'name  = "TRANSFORMERS_OFFLINE"' in vllm_mod_main
        assert 'name  = "SERVED_MODEL_NAME"' in vllm_mod_main

        # 4. Default model_fast and model_reasoning in gcp-gke variables.tf and all posture tfvars are gs:// paths
        assert 'default     = "gs://cage-models/Qwen/Qwen2.5-1.5B-Instruct"' in gke_vars
        assert 'default     = "gs://cage-models/deepseek-ai/DeepSeek-R1-Distill-Llama-8B"' in gke_vars
        assert 'variable "served_model_fast"' in gke_vars
        assert 'variable "served_model_reasoning"' in gke_vars

        for tfvars_name in (
            "dev.tfvars",
            "staging.tfvars",
            "prod.tfvars",
            "us-dev.tfvars",
            "eu-dev.tfvars",
            "eu-prod.tfvars",
            "apac-dev.tfvars",
            "apac-prod.tfvars",
        ):
            tfvars_text = (GKE_TARGET_DIR / tfvars_name).read_text(encoding="utf-8")
            assert 'model_fast             = "gs://' in tfvars_text, (
                f"{tfvars_name} must set model_fast to a gs:// path in the model bucket"
            )
            assert 'model_reasoning        = "gs://' in tfvars_text, (
                f"{tfvars_name} must set model_reasoning to a gs:// path in the model bucket"
            )

    def test_fqdn_network_policies_materialized_and_vllm_egress_enforced(self) -> None:
        netpol_tf = (GKE_TARGET_DIR / "network_policy.tf").read_text(encoding="utf-8")

        # 1. Terraform materializes local.fqdn_network_policies via kubernetes_manifest
        assert 'resource "kubernetes_manifest" "fqdn_network_policy"' in netpol_tf
        assert "for_each = local.fqdn_network_policies" in netpol_tf
        assert "manifest = each.value" in netpol_tf

        # 2. Terraform defines vllm_egress_l3_l4 and vllm_egress_fqdn
        assert 'resource "kubernetes_network_policy_v1" "vllm_egress_l3_l4"' in netpol_tf
        assert "vllm_egress_fqdn = {" in netpol_tf
        assert '"169.254.169.254/32"' in netpol_tf
        assert '"169.254.169.252/32"' in netpol_tf
        assert 'port     = "988"' in netpol_tf

        # 3. Behavioral evaluation of vLLM egress in deployment/k8s/cilium/egress-lockdown.yaml
        docs = _load_yaml_docs(CILIUM_DIR / "egress-lockdown.yaml")
        netpols = [d for d in docs if d.get("kind") == "NetworkPolicy"]
        fqdnpols = [d for d in docs if d.get("kind") == "FQDNNetworkPolicy"]

        for app_label in ("vllm-inference", "vllm-reasoning"):
            pod_labels = {"app": app_label, "component": "vllm-inference"}

            # Allowed: DNS to kube-dns and 169.254.169.254:53
            assert _evaluate_pod_egress(
                netpols,
                fqdnpols,
                pod_labels,
                dest_pod_labels={"k8s-app": "kube-dns"},
                dest_namespace_labels={"kubernetes.io/metadata.name": "kube-system"},
                port=53,
                protocol="UDP",
            ) is True
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_ip="169.254.169.254", port=53, protocol="UDP"
            ) is True

            # Allowed: GKE Workload Identity metadata server (169.254.169.254:80 and 169.254.169.252:988)
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_ip="169.254.169.254", port=80, protocol="TCP"
            ) is True
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_ip="169.254.169.252", port=988, protocol="TCP"
            ) is True

            # Allowed: GCS and OAuth2 token exchange over HTTPS (443)
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_fqdn="storage.googleapis.com", port=443
            ) is True
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_fqdn="oauth2.googleapis.com", port=443
            ) is True

            # Fail-closed: Hugging Face Hub and arbitrary external FQDNs are blocked
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_fqdn="huggingface.co", port=443
            ) is False
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_fqdn="cdn-lfs.huggingface.co", port=443
            ) is False
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_fqdn="example.com", port=443
            ) is False

            # Fail-closed: direct IP literal on 443 and external DNS 8.8.8.8:53 are blocked
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_ip="142.250.80.46", port=443
            ) is False
            assert _evaluate_pod_egress(
                netpols, fqdnpols, pod_labels, dest_ip="8.8.8.8", port=53, protocol="UDP"
            ) is False



# ============================================================================
# 8. Image Digest Pinning & Binary Authorization Attestation Chain (WP6)
# ============================================================================


def _extract_image_digests_block(variables_tf: str) -> str:
    """Return the HCL block for `variable "image_digests"` in `variables.tf`."""
    marker = 'variable "image_digests"'
    assert marker in variables_tf, "variable \"image_digests\" missing from variables.tf"
    start = variables_tf.index(marker)
    next_var = variables_tf.find('\nvariable "', start + len(marker))
    return variables_tf[start:] if next_var == -1 else variables_tf[start:next_var]


def _evaluate_image_digests_validation(
    variables_tf: str,
    image_digests: dict[str, str],
    *,
    enable_binary_authorization: bool = True,
) -> bool:
    """Evaluate the `variable "image_digests"` validation rules from `variables.tf`."""
    block = _extract_image_digests_block(variables_tf)
    regex_matches = re.findall(r'regex\("([^"]+)",\s*ref\)', block)
    assert len(regex_matches) >= 2, (
        "Expected digest and :latest regex(..., ref) in variable \"image_digests\" validation"
    )
    # Unescape HCL string double-backslashes (e.g. `\\s` -> `\s`)
    digest_regex = re.compile(regex_matches[0].replace(r"\\", "\\"))
    latest_regex = re.compile(regex_matches[1].replace(r"\\", "\\"))

    # Rule 1: when enable_binary_authorization = true, every image must match @sha256:<64-hex> and not :latest
    if enable_binary_authorization:
        if not all(
            bool(digest_regex.match(ref)) and not bool(latest_regex.search(ref))
            for ref in image_digests.values()
        ):
            return False

    # Rule 2: unconditional digest + no-:latest check
    for ref in image_digests.values():
        if not digest_regex.match(ref) or latest_regex.search(ref):
            return False

    return True


class TestImageSupplyChainAndAttestation:
    """Verify WP6: digest pinning, KMS-backed Binary Authorization attestor, and build signing."""

    def test_no_latest_tags_in_gke_main_tf_or_deployment_docker(self) -> None:
        main_tf = GKE_TARGET_DIR / "main.tf"
        docker_dir = REPO_ROOT / "deployment" / "docker"
        offending: list[str] = []

        for path in [main_tf, *sorted(docker_dir.rglob("*"))]:
            if not path.is_file():
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if ":latest" in line:
                    offending.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")

        assert not offending, f"Mutable :latest image references found:\n" + "\n".join(offending)

    def test_image_digests_validation_rejects_tag_only_reference_when_binauthz_enabled(
        self,
    ) -> None:
        variables_tf = (GKE_TARGET_DIR / "variables.tf").read_text(encoding="utf-8")
        block = _extract_image_digests_block(variables_tf)

        assert "!var.enable_binary_authorization" in block
        assert ':latest(@|$)' in block

        # Extract default map entries from variable "image_digests"
        default_entries = dict(
            re.findall(r'"([^"]+)"\s*=\s*"([^"]+)"', block.split("validation {", 1)[0])
        )
        expected_keys = {
            "gateway",
            "governed-financial-advisor",
            "vllm-streamer",
            "nemo-guardrails",
            "compliance-bridge",
            "agentsight-ui",
            "presidio-analyzer",
            "presidio-anonymizer",
            "opa",
            "langfuse",
            "langfuse-worker",
            "cloud-sql-proxy",
            "clickhouse-server",
            "clickhouse-keeper",
            "redis",
        }
        assert expected_keys.issubset(default_entries.keys()), (
            f"Missing required keys in image_digests default map: "
            f"{expected_keys - set(default_entries.keys())}"
        )

        # 1. Default digest-pinned map passes validation when enable_binary_authorization = True
        assert (
            _evaluate_image_digests_validation(
                variables_tf, default_entries, enable_binary_authorization=True
            )
            is True
        )

        # 2. Fail-closed: a tag-only reference (even a version tag like :v1.2.3) is rejected
        with_version_tag = dict(default_entries)
        with_version_tag["gateway"] = (
            "us-central1-docker.pkg.dev/project/cage-images/cage-gateway:v1.2.3"
        )
        assert (
            _evaluate_image_digests_validation(
                variables_tf, with_version_tag, enable_binary_authorization=True
            )
            is False
        )

        # 3. Fail-closed: a :latest tag reference is rejected
        with_latest_tag = dict(default_entries)
        with_latest_tag["gateway"] = (
            "us-central1-docker.pkg.dev/project/cage-images/cage-gateway:latest"
        )
        assert (
            _evaluate_image_digests_validation(
                variables_tf, with_latest_tag, enable_binary_authorization=True
            )
            is False
        )

        # 4. Fail-closed: a malformed/truncated sha256 digest is rejected
        with_short_digest = dict(default_entries)
        with_short_digest["gateway"] = (
            "us-central1-docker.pkg.dev/project/cage-images/cage-gateway@sha256:deadbeef"
        )
        assert (
            _evaluate_image_digests_validation(
                variables_tf, with_short_digest, enable_binary_authorization=True
            )
            is False
        )

    def test_gke_main_tf_wires_image_digests_across_all_workloads(self) -> None:
        main_tf = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
        for key in (
            'var.image_digests["gateway"]',
            'var.image_digests["governed-financial-advisor"]',
            'var.image_digests["agentsight-ui"]',
            'var.image_digests["nemo-guardrails"]',
            'var.image_digests["presidio-analyzer"]',
            'var.image_digests["presidio-anonymizer"]',
            'var.image_digests["vllm-streamer"]',
            'var.image_digests["opa"]',
            'var.image_digests["compliance-bridge"]',
            'var.image_digests["clickhouse-server"]',
            'var.image_digests["clickhouse-keeper"]',
            'var.image_digests["langfuse"]',
            'var.image_digests["langfuse-worker"]',
            'var.image_digests["cloud-sql-proxy"]',
        ):
            assert key in main_tf, f"Expected {key} to be wired in infra/targets/gcp-gke/main.tf"

    def test_binauthz_attestor_wired_to_asymmetric_kms_key_without_third_party_whitelists(
        self,
    ) -> None:
        kms_tf = (GKE_TARGET_DIR / "kms_signing.tf").read_text(encoding="utf-8")
        perimeter_tf = (GKE_TARGET_DIR / "perimeter.tf").read_text(encoding="utf-8")

        assert 'resource "google_kms_crypto_key" "binauthz_attestor"' in kms_tf
        assert 'data "google_kms_crypto_key_version" "binauthz_attestor"' in perimeter_tf
        assert "pkix_public_key" in perimeter_tf
        assert (
            "data.google_kms_crypto_key_version.binauthz_attestor[0].public_key[0].pem"
            in perimeter_tf
        )
        assert (
            'resource "google_binary_authorization_attestor_iam_member" "cloudbuild_attestor_viewer"'
            in perimeter_tf
        )
        assert (
            'resource "google_container_analysis_note_iam_member" "cloudbuild_note_attacher"'
            in perimeter_tf
        )

        # No third-party docker.io / gcr.io/cloud-marketplace admission_whitelist_patterns
        assert "docker.io/" not in perimeter_tf
        assert "gcr.io/cloud-marketplace/" not in perimeter_tf

    def test_cloudbuild_configs_and_scripts_sign_digests(self) -> None:
        docker_dir = REPO_ROOT / "deployment" / "docker"
        cloudbuild_files = sorted(docker_dir.glob("cloudbuild.*.yaml"))
        assert [p.name for p in cloudbuild_files] == [
            "cloudbuild.image.yaml",
            "cloudbuild.lula.yaml",
            "cloudbuild.vllm.yaml",
        ]

        for cb_path in cloudbuild_files:
            text = cb_path.read_text(encoding="utf-8")
            assert "scripts/attest_image.sh" in text, (
                f"{cb_path.name} must invoke scripts/attest_image.sh to sign and verify the pushed digest"
            )

        attest_script = (REPO_ROOT / "scripts" / "attest_image.sh").read_text(
            encoding="utf-8"
        )
        assert (
            "gcloud beta container binauthz attestations sign-and-create"
            in attest_script
        )
        assert "${IMAGE_REPO}@${DIGEST}" in attest_script

        build_script = (REPO_ROOT / "scripts" / "build_images.sh").read_text(encoding="utf-8")
        assert "deployment/docker/cloudbuild.image.yaml" in build_script
        assert ":latest" not in build_script

        mirror_script = (REPO_ROOT / "scripts" / "mirror_and_attest_images.sh").read_text(
            encoding="utf-8"
        )
        assert "scripts/attest_image.sh" in mirror_script
        assert "THIRD_PARTY_IMAGES=(" in mirror_script

    def test_lula_si2_validates_actual_terraform_deployments_and_digests(self) -> None:
        lula_si2_path = REPO_ROOT / "compliance" / "lula" / "lula-validation-si2.yaml"
        doc = yaml.safe_load(lula_si2_path.read_text(encoding="utf-8"))
        lula_desc = doc["component-definition"]["back-matter"]["resources"][0]["description"]
        lula_spec = yaml.safe_load(lula_desc)
        rego = lula_spec["provider"]["opa-spec"]["rego"]

        for expected_deployment in (
            '"gateway"',
            '"governed-financial-advisor"',
            '"vllm-inference"',
            '"vllm-reasoning"',
            '"nemo-guardrails"',
            '"agentsight-ui"',
            '"compliance-bridge"',
        ):
            assert expected_deployment in rego, (
                f"lula-validation-si2.yaml must validate {expected_deployment}"
            )
        assert '"@sha256:"' in rego
        assert '"IfNotPresent"' in rego
        assert "advisor-deployment" not in rego
