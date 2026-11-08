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

Enforces across Terraform (infra/) and Lula validations:

1. Gateway and bridge share one evidence-stream contract (URL, db, key) that
   points at the governance instance, with the same TLS / IAM auth mode.
2. The gateway is producer-only: no EVIDENCE_COLD_STORE*, EVIDENCE_KMS_KEY,
   EVIDENCE_STREAM_KMS_SIGN or WORM bucket IAM.
3. The bridge can reach the governance instance (IAM + NetworkPolicy) and
   GCS / Cloud KMS (FQDNNetworkPolicy).
4. The bridge's Terraform module and GKE target carry zero retired ClickHouse
   evidence-sink wiring, and the retired ClickHouse evidence files stay absent.
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
_GATEWAY_VARS = _REPO / "infra/modules/gateway/variables.tf"
_BRIDGE_MOD = _REPO / "infra/modules/compliance_bridge/main.tf"
_BRIDGE_VARS = _REPO / "infra/modules/compliance_bridge/variables.tf"
_LULA_SC8 = _REPO / "compliance/lula/lula-validation-sc8.yaml"
_CH_SINK = _REPO / "src/compliance_bridge/clickhouse_sink.py"
_CH_SCHEMA = _REPO / "deployment/clickhouse/evidence_stream_schema.sql"

_GATEWAY_FORBIDDEN_ENV = (
    "EVIDENCE_COLD_STORE",
    "EVIDENCE_COLD_STORE_BUCKET",
    "EVIDENCE_KMS_KEY",
    "EVIDENCE_STREAM_KMS_SIGN",
)
_DELETED_ENV = ("EVIDENCE_STREAM_KMS_SIGN", "EVIDENCE_COLD_STORE_FLUSH_SECONDS")


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
    for m in re.finditer(
        r'name\s*=\s*"([A-Z][A-Z0-9_]+)"\s*\n\s*(value(?:_from)?)\s*=?\s*([^\n]*)', text
    ):
        out[m.group(1)] = m.group(3).strip() if m.group(2) == "value" else "value_from"
    # dynamic "env" blocks: name  = "X" / value = var.x inside content {}
    return out


def _tf_attr(block: str, attr: str) -> str:
    m = re.search(rf"^\s*{attr}\s*=\s*(.+)$", block, re.M)
    assert m, f"{attr} not set in block"
    return m.group(1).strip()


# ---------------------------------------------------------------------------
# 1. Shared evidence-stream contract (Terraform)
# ---------------------------------------------------------------------------


def test_evidence_stream_locals_point_at_governance_instance() -> None:
    main_tf = _GKE_MAIN.read_text()
    url = re.search(r"^\s*evidence_stream_redis_url\s*=\s*(.+)$", main_tf, re.M)
    assert url, "local.evidence_stream_redis_url not defined"
    assert "module.memorystore_governance.primary_endpoint_ip" in url.group(1)
    assert "memorystore_app" not in url.group(1)
    assert re.search(r"^\s*evidence_stream_redis_db\s*=\s*1\s*$", main_tf, re.M)
    assert re.search(
        r'^\s*evidence_stream_key\s*=\s*"cage:evidence:stream"\s*$', main_tf, re.M
    )
    # Governance instance runs cluster mode disabled, so db 1 is addressable.
    gov = _block(main_tf, 'module "memorystore_governance"')
    assert 'mode          = "CLUSTER_DISABLED"' in gov


@pytest.mark.parametrize("module_name", ["gateway", "compliance_bridge"])
def test_gateway_and_bridge_receive_identical_stream_contract(module_name: str) -> None:
    block = _block(_GKE_MAIN.read_text(), f'module "{module_name}"')
    assert (
        _tf_attr(block, "evidence_stream_redis_url")
        == "local.evidence_stream_redis_url"
    )
    assert (
        _tf_attr(block, "evidence_stream_redis_db") == "local.evidence_stream_redis_db"
    )
    assert _tf_attr(block, "evidence_stream_key") == "local.evidence_stream_key"
    assert _tf_attr(block, "enable_redis_tls") == "var.enable_memorystore_tls"
    assert (
        _tf_attr(block, "redis_ca_pem")
        == 'var.enable_memorystore_tls ? join("\\n", module.memorystore_governance.managed_server_ca) : ""'
    )
    assert _tf_attr(block, "redis_auth_mode") == "local.governance_redis_auth"


@pytest.mark.parametrize("module_file", [_GATEWAY_MOD, _BRIDGE_MOD])
def test_modules_export_stream_contract_env(module_file: Path) -> None:
    env = _tf_env(module_file.read_text())
    assert env.get("EVIDENCE_STREAM_ENABLED") == '"true"'
    assert env.get("EVIDENCE_STREAM_REDIS_URL") == "var.evidence_stream_redis_url"
    assert (
        env.get("EVIDENCE_STREAM_REDIS_DB") == "tostring(var.evidence_stream_redis_db)"
    )
    assert env.get("EVIDENCE_STREAM_KEY") == "var.evidence_stream_key"
    assert env.get("REDIS_TLS") == "tostring(var.enable_redis_tls)"
    assert env.get("REDIS_CA_CERT_PATH") == '"/etc/cage/tls/redis/ca.pem"'
    assert env.get("REDIS_AUTH_MODE") == "var.redis_auth_mode"


@pytest.mark.parametrize("vars_file", [_GATEWAY_VARS, _BRIDGE_VARS])
def test_modules_declare_redis_ca_pem_and_retire_redis_ca_cert_path(
    vars_file: Path,
) -> None:
    text = vars_file.read_text()
    block = _block(text, 'variable "redis_ca_pem"')
    assert "type        = string" in block
    assert 'default     = ""' in block
    assert "redis_ca_cert_path" not in text


def test_no_terraform_file_references_dangling_redis_ca_cert_path() -> None:
    offenders = [
        str(p.relative_to(_REPO))
        for p in (_REPO / "infra").rglob("*.tf")
        if "redis_ca_cert_path" in p.read_text()
    ]
    assert offenders == [], (
        f"Dangling redis_ca_cert_path still referenced in: {offenders}"
    )


@pytest.mark.parametrize(
    "module_file,app_name",
    [
        (_GATEWAY_MOD, "gateway"),
        (_BRIDGE_MOD, "compliance-bridge"),
    ],
)
def test_modules_own_redis_ca_configmap_mount_annotation_and_revision_limit(
    module_file: Path, app_name: str
) -> None:
    text = module_file.read_text()
    cm_block = _block(text, 'resource "kubernetes_config_map_v1" "redis_ca"')
    assert 'count = var.redis_ca_pem != "" ? 1 : 0' in cm_block
    assert f'name      = "{app_name}-redis-ca"' in cm_block
    assert '"ca.pem" = var.redis_ca_pem' in cm_block

    assert "revision_history_limit = 3" in text
    assert '"cage.io/redis-ca-sha256" = sha256(var.redis_ca_pem)' in text
    assert '!var.enable_redis_tls || trimspace(var.redis_ca_pem) != ""' in text

    vm_match = re.search(
        r'dynamic "volume_mount" \{\s*for_each = var\.redis_ca_pem != "" \? \[1\] : \[\]\s*content \{(.*?)\}\s*\}',
        text,
        re.S,
    )
    assert vm_match, f"{module_file}: missing redis-ca dynamic volume_mount"
    assert 'name       = "redis-ca"' in vm_match.group(1)
    assert 'mount_path = "/etc/cage/tls/redis"' in vm_match.group(1)
    assert "read_only  = true" in vm_match.group(1)

    vol_match = re.search(
        r'dynamic "volume" \{\s*for_each = var\.redis_ca_pem != "" \? \[1\] : \[\]\s*content \{(.*?)\}\s*\}',
        text,
        re.S,
    )
    assert vol_match, f"{module_file}: missing redis-ca dynamic volume"
    assert 'name = "redis-ca"' in vol_match.group(1)
    assert (
        "name = kubernetes_config_map_v1.redis_ca[0].metadata[0].name"
        in vol_match.group(1)
    )


def test_gke_target_guards_non_empty_managed_server_ca_when_tls_enabled() -> None:
    main_tf = _GKE_MAIN.read_text()
    assert (
        "!var.enable_memorystore_tls || length(module.memorystore_governance.managed_server_ca) > 0"
        in main_tf
    )


def test_lula_sc8_asserts_redis_ca_pinning() -> None:
    doc = yaml.safe_load(_LULA_SC8.read_text(encoding="utf-8"))
    lula_desc = doc["component-definition"]["back-matter"]["resources"][0][
        "description"
    ]
    lula_spec = yaml.safe_load(lula_desc)
    rego = lula_spec["provider"]["opa-spec"]["rego"]

    for expected in (
        "redis_tls_deployments := {",
        '"gateway",',
        '"compliance-bridge"',
        "deployment_pins_redis_ca(deploy) if {",
        'endswith(vol.configMap.name, "-redis-ca")',
        'vm.mountPath == "/etc/cage/tls/redis"',
        "vm.readOnly == true",
        'env.name == "REDIS_CA_CERT_PATH"',
        'env.value == "/etc/cage/tls/redis/ca.pem"',
        'deploy.spec.template.metadata.annotations["cage.io/redis-ca-sha256"] != ""',
    ):
        assert expected in rego, f"lula-validation-sc8.yaml missing {expected}"

    validate_block = _block(rego, "validate if")
    assert "redis_ca_pinned" in validate_block


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
    for m in re.finditer(
        r'resource "google_storage_bucket_iam_member" "(\w+)" \{[^}]*\}', iam, re.S
    ):
        if "module.worm_bucket" in m.group(0):
            assert "google_service_account.gateway" not in m.group(0), m.group(1)


# ---------------------------------------------------------------------------
# 3. Bridge reaches the governance instance, GCS and KMS
# ---------------------------------------------------------------------------


def test_bridge_gsa_can_connect_to_governance_memorystore() -> None:
    block = _block(
        _GKE_IAM.read_text(),
        'resource "google_project_iam_member" "compliance_bridge_memorystore_user"',
    )
    assert 'role    = "roles/memorystore.dbConnectionUser"' in block
    assert "google_service_account.compliance_bridge.email" in block
    assert "var.enable_memorystore_iam_auth" in block


def test_bridge_storage_iam_is_bucket_scoped_only() -> None:
    """A project-wide storage grant would also reach the ClickHouse tiering bucket."""
    iam = _GKE_IAM.read_text()
    for m in re.finditer(
        r'resource "google_project_iam_member" "(\w+)" \{.*?\n\}', iam, re.S
    ):
        if "google_service_account.compliance_bridge" in m.group(0):
            assert "roles/storage." not in m.group(0), (
                f"{m.group(1)} grants project-wide storage"
            )


def test_bridge_network_policy_allows_governance_psc() -> None:
    block = _block(
        _GKE_NETPOL.read_text(),
        'resource "kubernetes_network_policy_v1" "compliance_bridge_egress_l3_l4"',
    )
    assert 'app = "compliance-bridge"' in block
    assert "cidr = local.governance_valkey_cidr" in block
    assert 'port     = "6379"' in block
    assert "local.app_valkey_cidr" not in block
    assert "app_valkey_cidr" not in block
    assert "memorystore_app" not in block


def test_bridge_fqdn_policy_allows_gcs_and_kms() -> None:
    netpol = _GKE_NETPOL.read_text()
    block = _block(netpol, "compliance_bridge_egress_fqdn = ")
    assert 'app = "compliance-bridge"' in block
    assert "var.compliance_bridge_egress_allowed_fqdns" in block
    variables = _block(
        (_GKE / "variables.tf").read_text(),
        'variable "compliance_bridge_egress_allowed_fqdns"',
    )
    for fqdn in ("storage.googleapis.com", "cloudkms.googleapis.com"):
        assert f'"{fqdn}"' in variables


# ---------------------------------------------------------------------------
# 4. Bridge env: WORM custody only (ClickHouse evidence sink retired)
# ---------------------------------------------------------------------------


def test_bridge_module_has_no_clickhouse_evidence_wiring() -> None:
    assert not _CH_SINK.exists(), "Retired clickhouse_sink.py must not exist"
    assert not _CH_SCHEMA.exists(), "Retired evidence_stream_schema.sql must not exist"

    env = _tf_env(_BRIDGE_MOD.read_text())
    leaked_env = [name for name in env if name.startswith("CLICKHOUSE_")]
    assert leaked_env == [], (
        f"compliance_bridge module sets retired ClickHouse env: {leaked_env}"
    )
    assert "clickhouse_" not in _BRIDGE_VARS.read_text().lower()

    bridge = _block(_GKE_MAIN.read_text(), 'module "compliance_bridge"')
    assert "clickhouse" not in bridge.lower()


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
    assert (
        env["EVIDENCE_CUSTODY_INTERVAL_S"]
        == "tostring(var.evidence_custody_interval_s)"
    )
    assert (
        env["EVIDENCE_VERIFY_INTERVAL_S"] == "tostring(var.evidence_verify_interval_s)"
    )
    assert env["EVIDENCE_VERIFY_PREFIX"] == "var.evidence_verify_prefix"
    bridge = _block(_GKE_MAIN.read_text(), 'module "compliance_bridge"')
    assert (
        _tf_attr(bridge, "evidence_cold_store_bucket")
        == "module.worm_bucket.bucket_name"
    )
    assert _tf_attr(bridge, "evidence_verify_interval_s") == "300"


def test_evidence_kms_key_description_has_no_hmac_fallback() -> None:
    block = _block(_BRIDGE_VARS.read_text(), 'variable "evidence_kms_key"')
    assert "falls back" not in block
    assert "no HMAC fallback" in block
    assert "unsigned" in block


# ---------------------------------------------------------------------------
# 5. Deleted knobs are set nowhere
# ---------------------------------------------------------------------------


def test_deleted_evidence_env_vars_are_not_set_anywhere() -> None:
    assert not (_REPO / "deployment" / "k8s").exists()
    offenders = []
    for root in (
        _REPO / "infra",
        _REPO / "tests" / "e2e" / "fixtures",
        _REPO / "scripts" / "fixtures" / "benchmark",
    ):
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {
                ".tf",
                ".tfvars",
                ".yaml",
                ".tpl",
                ".yml",
            }:
                text = path.read_text(errors="ignore")
                offenders += [
                    f"{path.relative_to(_REPO)}: {n}" for n in _DELETED_ENV if n in text
                ]
    assert offenders == [], f"Deleted evidence env vars still set: {offenders}"


# ---------------------------------------------------------------------------
# Negative control: the gates above actually fail on a leaking config.
# ---------------------------------------------------------------------------


def test_forbidden_env_detector_fails_on_leak() -> None:
    leaking = """
          env {
            name  = "EVIDENCE_KMS_KEY"
            value = var.evidence_kms_key
          }
"""
    env = _tf_env(leaking)
    assert [n for n in _GATEWAY_FORBIDDEN_ENV if n in env] == ["EVIDENCE_KMS_KEY"]
