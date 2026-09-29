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

"""Static gate: evidence custody lives in the compliance bridge (Option A).

The gateway appends unsigned hash-chained records to a Redis Stream on the
GOVERNANCE Memorystore instance. The compliance bridge's EvidenceCustodian reads
that stream, re-verifies the chain, signs per-batch attestations with
EVIDENCE_KMS_KEY and writes batches to the WORM bucket.

Enforces, for both Terraform (infra/) and raw manifests (deployment/k8s/):

1. Gateway and bridge share one evidence-stream contract (URL, db, key) that
   points at the governance instance, with the same TLS / IAM auth mode.
2. The gateway is producer-only: no EVIDENCE_COLD_STORE*, EVIDENCE_KMS_KEY,
   EVIDENCE_STREAM_KMS_SIGN or WORM bucket IAM.
3. The bridge can reach the governance instance (IAM + NetworkPolicy) and
   GCS / Cloud KMS (FQDNNetworkPolicy).
4. The bridge's ClickHouse env matches what clickhouse_sink.py reads and the
   cage_evidence schema.
5. Deleted knobs (EVIDENCE_STREAM_KMS_SIGN, EVIDENCE_COLD_STORE_FLUSH_SECONDS)
   are set nowhere.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE = _REPO / "infra/targets/gcp-gke"
_GKE_MAIN = _GKE / "main.tf"
_GKE_IAM = _GKE / "iam.tf"
_GKE_NETPOL = _GKE / "network_policy.tf"
_GATEWAY_MOD = _REPO / "infra/modules/gateway/main.tf"
_BRIDGE_MOD = _REPO / "infra/modules/compliance_bridge/main.tf"
_BRIDGE_VARS = _REPO / "infra/modules/compliance_bridge/variables.tf"
_CH_SINK = _REPO / "src/compliance_bridge/clickhouse_sink.py"
_CH_SCHEMA = _REPO / "deployment/clickhouse/evidence_stream_schema.sql"
_K8S = _REPO / "deployment/k8s"

_GATEWAY_FORBIDDEN_ENV = (
    "EVIDENCE_COLD_STORE",
    "EVIDENCE_COLD_STORE_BUCKET",
    "EVIDENCE_KMS_KEY",
    "EVIDENCE_STREAM_KMS_SIGN",
)
_DELETED_ENV = ("EVIDENCE_STREAM_KMS_SIGN", "EVIDENCE_COLD_STORE_FLUSH_SECONDS")

_PLACEHOLDER_LINE = re.compile(r"^\s*\$\{[A-Z0-9_]+\}\s*$", re.M)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(text: str, header: str) -> str:
    """Return the brace-balanced block that starts at ``header``."""
    start = text.find(header)
    assert start != -1, f"{header!r} not found"
    pos = text.index("{", start) + 1
    depth = 1
    while depth:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


def _tf_env(text: str) -> dict[str, str]:
    """Map env var name -> raw value expression for every env block in ``text``."""
    out: dict[str, str] = {}
    for m in re.finditer(r'name\s*=\s*"([A-Z][A-Z0-9_]+)"\s*\n\s*(value(?:_from)?)\s*=?\s*([^\n]*)', text):
        out[m.group(1)] = m.group(3).strip() if m.group(2) == "value" else "value_from"
    # dynamic "env" blocks: name  = "X" / value = var.x inside content {}
    return out


def _tf_attr(block: str, attr: str) -> str:
    m = re.search(rf"^\s*{attr}\s*=\s*(.+)$", block, re.M)
    assert m, f"{attr} not set in block"
    return m.group(1).strip()


def _load_manifest(path: Path) -> list[dict]:
    text = path.read_text()
    if path.name.endswith(".tpl"):
        text = re.sub(r"\$\{[A-Z0-9_]+(:-[^}]*)?\}", "placeholder", _PLACEHOLDER_LINE.sub("", text))
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]


def _container_env(path: Path, deployment: str) -> dict[str, dict]:
    for doc in _load_manifest(path):
        if doc.get("kind") == "Deployment" and doc["metadata"]["name"] == deployment:
            container = doc["spec"]["template"]["spec"]["containers"][0]
            return {e["name"]: e for e in container.get("env", [])}
    raise AssertionError(f"Deployment {deployment} not found in {path}")


_GATEWAY_MANIFESTS = ["gateway.yaml", "gateway.yaml.tpl", "gateway-deployment.yaml.tpl"]
_BRIDGE_MANIFESTS = ["compliance-bridge.yaml", "compliance-bridge-deployment.yaml.tpl"]


# ---------------------------------------------------------------------------
# 1. Shared evidence-stream contract (Terraform)
# ---------------------------------------------------------------------------


def test_evidence_stream_locals_point_at_governance_instance() -> None:
    main_tf = _GKE_MAIN.read_text()
    url = re.search(r"^\s*evidence_stream_redis_url\s*=\s*(.+)$", main_tf, re.M)
    assert url, "local.evidence_stream_redis_url not defined"
    assert "module.memorystore_governance.primary_endpoint_ip" in url.group(1)
    assert "memorystore_app" not in url.group(1)
    assert re.search(r'^\s*evidence_stream_redis_db\s*=\s*1\s*$', main_tf, re.M)
    assert re.search(r'^\s*evidence_stream_key\s*=\s*"cage:evidence:stream"\s*$', main_tf, re.M)
    # Governance instance runs cluster mode disabled, so db 1 is addressable.
    gov = _block(main_tf, 'module "memorystore_governance"')
    assert 'mode          = "CLUSTER_DISABLED"' in gov


@pytest.mark.parametrize("module_name", ["gateway", "compliance_bridge"])
def test_gateway_and_bridge_receive_identical_stream_contract(module_name: str) -> None:
    block = _block(_GKE_MAIN.read_text(), f'module "{module_name}"')
    assert _tf_attr(block, "evidence_stream_redis_url") == "local.evidence_stream_redis_url"
    assert _tf_attr(block, "evidence_stream_redis_db") == "local.evidence_stream_redis_db"
    assert _tf_attr(block, "evidence_stream_key") == "local.evidence_stream_key"
    assert _tf_attr(block, "enable_redis_tls") == "var.enable_memorystore_tls"
    assert _tf_attr(block, "redis_auth_mode") == "local.governance_redis_auth"


@pytest.mark.parametrize("module_file", [_GATEWAY_MOD, _BRIDGE_MOD])
def test_modules_export_stream_contract_env(module_file: Path) -> None:
    env = _tf_env(module_file.read_text())
    assert env.get("EVIDENCE_STREAM_ENABLED") == '"true"'
    assert env.get("EVIDENCE_STREAM_REDIS_URL") == "var.evidence_stream_redis_url"
    assert env.get("EVIDENCE_STREAM_REDIS_DB") == "tostring(var.evidence_stream_redis_db)"
    assert env.get("EVIDENCE_STREAM_KEY") == "var.evidence_stream_key"
    assert env.get("REDIS_TLS") == "tostring(var.enable_redis_tls)"
    assert env.get("REDIS_AUTH_MODE") == "var.redis_auth_mode"


# ---------------------------------------------------------------------------
# 2. Gateway is producer-only
# ---------------------------------------------------------------------------


def test_gateway_module_has_no_custody_env() -> None:
    env = _tf_env(_GATEWAY_MOD.read_text())
    leaked = [name for name in _GATEWAY_FORBIDDEN_ENV if name in env]
    assert leaked == [], f"gateway module sets custody env: {leaked}"
    assert env.get("EVIDENCE_CHAIN_BLOCKING") == '"true"'


def test_gateway_target_block_has_no_custody_inputs() -> None:
    block = _block(_GKE_MAIN.read_text(), 'module "gateway"')
    for token in ("evidence_cold_store", "evidence_kms_key", "worm_bucket"):
        assert token not in block, f"gateway module receives {token}"


def test_gateway_gsa_holds_no_worm_bucket_iam() -> None:
    iam = _GKE_IAM.read_text()
    for m in re.finditer(r'resource "google_storage_bucket_iam_member" "(\w+)" \{[^}]*\}', iam, re.S):
        if "module.worm_bucket" in m.group(0):
            assert "google_service_account.gateway" not in m.group(0), m.group(1)


@pytest.mark.parametrize("manifest", _GATEWAY_MANIFESTS)
def test_gateway_manifests_are_producer_only(manifest: str) -> None:
    env = _container_env(_K8S / manifest, "gateway")
    leaked = [name for name in _GATEWAY_FORBIDDEN_ENV if name in env]
    assert leaked == [], f"{manifest}: gateway receives custody env {leaked}"
    assert env["EVIDENCE_STREAM_ENABLED"]["value"] == "true"
    assert env["EVIDENCE_CHAIN_BLOCKING"]["value"] == "true"


# ---------------------------------------------------------------------------
# 3. Bridge reaches the governance instance, GCS and KMS
# ---------------------------------------------------------------------------


def test_bridge_gsa_can_connect_to_governance_memorystore() -> None:
    block = _block(_GKE_IAM.read_text(), 'resource "google_project_iam_member" "compliance_bridge_memorystore_user"')
    assert 'role    = "roles/memorystore.dbConnectionUser"' in block
    assert "google_service_account.compliance_bridge.email" in block
    assert "var.enable_memorystore_iam_auth" in block


def test_bridge_storage_iam_is_bucket_scoped_only() -> None:
    """A project-wide storage grant would also reach the ClickHouse tiering bucket."""
    iam = _GKE_IAM.read_text()
    for m in re.finditer(r'resource "google_project_iam_member" "(\w+)" \{.*?\n\}', iam, re.S):
        if "google_service_account.compliance_bridge" in m.group(0):
            assert "roles/storage." not in m.group(0), f"{m.group(1)} grants project-wide storage"


def test_bridge_network_policy_allows_governance_psc() -> None:
    block = _block(_GKE_NETPOL.read_text(), 'resource "kubernetes_network_policy_v1" "compliance_bridge_egress_l3_l4"')
    assert 'app = "compliance-bridge"' in block
    assert "cidr = var.memorystore_governance_psc_cidr" in block
    assert 'port     = "6379"' in block
    assert "memorystore_app_psc_cidr" not in block


def test_bridge_fqdn_policy_allows_gcs_and_kms() -> None:
    netpol = _GKE_NETPOL.read_text()
    block = _block(netpol, "compliance_bridge_egress_fqdn = ")
    assert 'app = "compliance-bridge"' in block
    assert "var.compliance_bridge_egress_allowed_fqdns" in block
    variables = _block((_GKE / "variables.tf").read_text(), 'variable "compliance_bridge_egress_allowed_fqdns"')
    for fqdn in ("storage.googleapis.com", "cloudkms.googleapis.com"):
        assert f'"{fqdn}"' in variables


def test_manifest_bridge_egress_allowlist_covers_redis() -> None:
    docs = _load_manifest(_K8S / "network-policy-hardening.yaml")
    policy = next(d for d in docs if d["metadata"]["name"] == "compliance-bridge-egress-allowlist")
    ports = {p["port"] for rule in policy["spec"]["egress"] for p in rule.get("ports", [])}
    assert 6379 in ports


# ---------------------------------------------------------------------------
# 4. Bridge env: custody + ClickHouse sink (Terraform and manifests)
# ---------------------------------------------------------------------------


def _sink_env_names() -> set[str]:
    return set(re.findall(r'os\.environ\.get\("(CLICKHOUSE_[A-Z_]+)"', _CH_SINK.read_text()))


def test_bridge_module_clickhouse_env_matches_sink_and_schema() -> None:
    env = _tf_env(_BRIDGE_MOD.read_text())
    sink_names = _sink_env_names()
    for name in ("CLICKHOUSE_ENABLED", "CLICKHOUSE_USERNAME", "CLICKHOUSE_DATABASE", "CLICKHOUSE_PASSWORD"):
        assert name in sink_names, f"clickhouse_sink.py no longer reads {name}"
        assert name in env, f"compliance_bridge module does not set {name}"
    assert env["CLICKHOUSE_PASSWORD"] == "value_from"  # secretKeyRef, never a literal

    schema_db = re.search(r"CREATE DATABASE IF NOT EXISTS (\w+);", _CH_SCHEMA.read_text()).group(1)
    assert schema_db == "cage_evidence"
    assert f'default     = "{schema_db}"' in _block(_BRIDGE_VARS.read_text(), 'variable "clickhouse_database"')
    bridge = _block(_GKE_MAIN.read_text(), 'module "compliance_bridge"')
    assert _tf_attr(bridge, "clickhouse_database") == f'"{schema_db}"'


def test_bridge_module_keeps_cold_store_and_custody_interval() -> None:
    env = _tf_env(_BRIDGE_MOD.read_text())
    for name in (
        "EVIDENCE_COLD_STORE",
        "EVIDENCE_COLD_STORE_BUCKET",
        "EVIDENCE_KMS_KEY",
        "EVIDENCE_VERIFY_INTERVAL_S",
        "EVIDENCE_VERIFY_PREFIX",
        "OSCAL_REQUIRE_VERIFIED_CUSTODY",
    ):
        assert name in env
    assert env["EVIDENCE_CUSTODY_INTERVAL_S"] == "tostring(var.evidence_custody_interval_s)"
    assert env["EVIDENCE_VERIFY_INTERVAL_S"] == "tostring(var.evidence_verify_interval_s)"
    assert env["EVIDENCE_VERIFY_PREFIX"] == "var.evidence_verify_prefix"
    bridge = _block(_GKE_MAIN.read_text(), 'module "compliance_bridge"')
    assert _tf_attr(bridge, "evidence_cold_store_bucket") == "module.worm_bucket.bucket_name"
    assert _tf_attr(bridge, "evidence_verify_interval_s") == "300"


def test_evidence_kms_key_description_has_no_hmac_fallback() -> None:
    block = _block(_BRIDGE_VARS.read_text(), 'variable "evidence_kms_key"')
    assert "falls back" not in block
    assert "no HMAC fallback" in block
    assert "unsigned" in block


@pytest.mark.parametrize("gateway_manifest,bridge_manifest", [
    ("gateway.yaml", "compliance-bridge.yaml"),
    ("gateway-deployment.yaml.tpl", "compliance-bridge-deployment.yaml.tpl"),
])
def test_manifest_bridge_reads_the_gateway_stream(gateway_manifest: str, bridge_manifest: str) -> None:
    gw = _container_env(_K8S / gateway_manifest, "gateway")
    br = _container_env(_K8S / bridge_manifest, "compliance-bridge")
    for name in ("EVIDENCE_STREAM_REDIS_URL", "EVIDENCE_STREAM_REDIS_DB", "EVIDENCE_STREAM_KEY"):
        assert gw[name] == br[name], f"{name} drifts between {gateway_manifest} and {bridge_manifest}"
    assert br["EVIDENCE_STREAM_ENABLED"]["value"] == "true"
    assert br["EVIDENCE_CUSTODY_INTERVAL_S"]["value"] == "60"
    assert br["EVIDENCE_VERIFY_INTERVAL_S"]["value"] == "300"
    assert br["EVIDENCE_VERIFY_PREFIX"]["value"] == "evidence"


@pytest.mark.parametrize("manifest", _BRIDGE_MANIFESTS)
def test_manifest_bridge_clickhouse_env(manifest: str) -> None:
    env = _container_env(_K8S / manifest, "compliance-bridge")
    assert env["CLICKHOUSE_DATABASE"]["value"] == "cage_evidence"
    assert env["CLICKHOUSE_ENABLED"]["value"] == "true"
    assert "CLICKHOUSE_USERNAME" in env
    assert "secretKeyRef" in env["CLICKHOUSE_PASSWORD"]["valueFrom"]


# ---------------------------------------------------------------------------
# 5. Deleted knobs are set nowhere
# ---------------------------------------------------------------------------


def test_deleted_evidence_env_vars_are_not_set_anywhere() -> None:
    offenders = []
    for root in (_REPO / "infra", _K8S):
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".tf", ".tfvars", ".yaml", ".tpl", ".yml"}:
                text = path.read_text(errors="ignore")
                offenders += [f"{path.relative_to(_REPO)}: {n}" for n in _DELETED_ENV if n in text]
    assert offenders == [], f"Deleted evidence env vars still set: {offenders}"


# ---------------------------------------------------------------------------
# Negative control: the gates above actually fail on a leaking config.
# ---------------------------------------------------------------------------


def test_forbidden_env_detector_fails_on_leak() -> None:
    leaking = '''
          env {
            name  = "EVIDENCE_KMS_KEY"
            value = var.evidence_kms_key
          }
'''
    env = _tf_env(leaking)
    assert [n for n in _GATEWAY_FORBIDDEN_ENV if n in env] == ["EVIDENCE_KMS_KEY"]
