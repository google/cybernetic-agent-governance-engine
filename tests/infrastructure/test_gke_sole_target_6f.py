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
        if all(
            pod_labels.get(k) == v
            for k, v in np.get("spec", {}).get("podSelector", {}).get("matchLabels", {}).items()
        )
        and "Egress" in np.get("spec", {}).get("policyTypes", [])
    ]
    matching_fqdnpols = [
        fp for fp in fqdn_policies
        if all(
            pod_labels.get(k) == v
            for k, v in fp.get("spec", {}).get("podSelector", {}).get("matchLabels", {}).items()
        )
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


