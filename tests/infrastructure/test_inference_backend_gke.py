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
"""W6: on GKE, ``inference_backend`` decides what is deployed (AG-7).

``"none"`` deploys nothing that needs a model: no vLLM, no advisor and no NeMo
server, so no workload is left pointing at a model service that does not exist
(absent, not degraded). ``"vllm"`` deploys vLLM on the GPU pool and the advisor.
``"external"`` is compose-only: the cluster denies external egress and the
advisor's egress is internal-only. Every profile configures a multi-zone GPU
pool using ``total_min_node_count = 0`` and ``initial_node_count = 0`` across
the region's verified L4 + ``g2-standard-8`` zones, so moving to ``"vllm"`` is
a variable change, not an infrastructure rebuild, and zonal stockouts fall back
without multiplying counts. ``enable_vllm`` is replaced and fails the plan if set.

These tests read the Terraform source, as the other infrastructure tests do.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GKE = REPO_ROOT / "infra" / "targets" / "gcp-gke"
CLUSTER_MODULE = REPO_ROOT / "infra" / "modules" / "gcp_gke_cluster"
PROFILES = sorted(p.name for p in GKE.glob("*.tfvars"))
VERIFIED_L4_G2_ZONES: dict[str, list[str]] = {
    "us-central1": ["us-central1-a", "us-central1-b", "us-central1-c"],
    "europe-west1": ["europe-west1-b", "europe-west1-c"],
    "asia-southeast1": [
        "asia-southeast1-a",
        "asia-southeast1-b",
        "asia-southeast1-c",
    ],
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _block(text: str, header: str) -> str:
    """The top-level block that starts with ``header``, up to its closing brace."""
    start = text.find(header)
    assert start != -1, f"missing block: {header}"
    end = text.find("\n}\n", start)
    return text[start : end + 2]


def _setting(text: str, name: str) -> str | None:
    match = re.search(rf'^\s*{name}\s*=\s*"?([^"\s#]+)"?', text, re.MULTILINE)
    return match.group(1) if match else None


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text)


MAIN = _read(GKE / "main.tf")
VARIABLES = _read(GKE / "variables.tf")
CLUSTER_MAIN = _read(CLUSTER_MODULE / "main.tf")
CLUSTER_VARIABLES = _read(CLUSTER_MODULE / "variables.tf")


# ── The selector ──────────────────────────────────────────────────────────────


def test_inference_backend_defaults_to_none_and_refuses_external() -> None:
    block = _squash(_block(VARIABLES, 'variable "inference_backend"'))
    assert 'default = "none"' in block
    assert 'condition = contains(["none", "vllm"], var.inference_backend)' in block
    assert "compose-only" in block, "the refusal must say where external is allowed"


def test_enable_vllm_is_kept_only_to_fail_with_a_migration_message() -> None:
    block = _block(VARIABLES, 'variable "enable_vllm"')
    squashed = _squash(block)
    assert "default = null" in squashed
    assert "condition = var.enable_vllm == null" in squashed
    assert 'set inference_backend = \\"vllm\\"' in squashed
    for tf in sorted(GKE.glob("*.tf")):
        text = _read(tf).replace(block, "")
        assert "var.enable_vllm" not in text, f"{tf.name} still reads enable_vllm"


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_names_its_backend_and_drops_enable_vllm(profile: str) -> None:
    text = _read(GKE / profile)
    assert _setting(text, "enable_vllm") is None, f"{profile} still sets enable_vllm"
    assert _setting(text, "inference_backend") in {"none", "vllm"}, profile


def test_staging_is_the_profile_without_a_model() -> None:
    backends = {p: _setting(_read(GKE / p), "inference_backend") for p in PROFILES}
    assert {p for p, b in backends.items() if b == "none"} == {"staging.tfvars"}


def test_staging_keeps_a_three_zone_gpu_pool_that_scales_from_zero() -> None:
    text = _read(GKE / "staging.tfvars")
    assert _setting(text, "enable_gpu_node_pool") == "true"
    assert _setting(text, "gpu_node_pool_min_count") == "0"
    assert _setting(text, "gpu_node_pool_max_count") == "2"
    assert _setting(text, "gpu_node_pool_initial_count") == "0"
    zones = re.search(r"^gpu_node_locations\s*=\s*\[(.*?)\]", text, re.MULTILINE)
    assert zones is not None
    assert re.findall(r'"([^"]+)"', zones.group(1)) == [
        "us-central1-a",
        "us-central1-b",
        "us-central1-c",
    ]
    assert _setting(text, "enable_nemo_guardrails") == "false"


def test_gpu_node_pool_uses_total_autoscaling_and_zero_initial_default() -> None:
    gpu_block = _block(
        CLUSTER_MAIN, 'resource "google_container_node_pool" "gpu_nodes"'
    )
    autoscaling_match = re.search(r"autoscaling\s*\{(.*?)\}", gpu_block, re.DOTALL)
    assert autoscaling_match is not None
    autoscaling = _squash(autoscaling_match.group(1))
    assert "total_min_node_count = var.gpu_node_pool_min_count" in autoscaling
    assert "total_max_node_count = var.gpu_node_pool_max_count" in autoscaling
    assert 'location_policy = "ANY"' in autoscaling
    assert re.search(r"(?<!total_)min_node_count\s*=", autoscaling) is None
    assert re.search(r"(?<!total_)max_node_count\s*=", autoscaling) is None

    zones_map = _block(CLUSTER_MAIN, "verified_l4_g2_zones = {")
    for region, expected in VERIFIED_L4_G2_ZONES.items():
        row = re.search(rf'"{re.escape(region)}"\s*=\s*\[(.*?)\]', zones_map)
        assert row is not None, region
        assert re.findall(r'"([^"]+)"', row.group(1)) == expected, region

    for source_name, vars_text in (
        ("gcp_gke_cluster/variables.tf", CLUSTER_VARIABLES),
        ("gcp-gke/variables.tf", VARIABLES),
    ):
        init_block = _squash(
            _block(vars_text, 'variable "gpu_node_pool_initial_count"')
        )
        min_block = _squash(_block(vars_text, 'variable "gpu_node_pool_min_count"'))
        assert "default = 0" in init_block, source_name
        assert "default = 0" in min_block, source_name


@pytest.mark.parametrize("profile", [*PROFILES, "terraform.auto.tfvars.example"])
def test_every_profile_starts_with_zero_gpus_and_lists_only_verified_l4_zones(
    profile: str,
) -> None:
    text = _read(GKE / profile)
    region = _setting(text, "region") or "us-central1"
    expected_zones = VERIFIED_L4_G2_ZONES[region]

    assert _setting(text, "enable_gpu_node_pool") == "true", profile
    assert _setting(text, "gpu_type") == "nvidia-l4", profile
    assert _setting(text, "gpu_node_pool_machine_type") == "g2-standard-8", profile
    assert _setting(text, "gpu_node_pool_initial_count") == "0", profile
    assert _setting(text, "gpu_node_pool_min_count") == "0", profile

    expected_max = "5" if profile.endswith("prod.tfvars") else "2"
    assert _setting(text, "gpu_node_pool_max_count") == expected_max, profile

    zones_match = re.search(r"^gpu_node_locations\s*=\s*\[(.*?)\]", text, re.MULTILINE)
    assert zones_match is not None, f"{profile} must explicitly list gpu_node_locations"
    zones = re.findall(r'"([^"]+)"', zones_match.group(1))
    assert zones == expected_zones, (profile, zones, expected_zones)
    assert "europe-west1-d" not in zones, profile


# ── What each backend deploys ─────────────────────────────────────────────────


def test_model_workloads_are_counted_on_the_backend() -> None:
    assert re.search(r'vllm_enabled\s*=\s*var\.inference_backend == "vllm"', MAIN)
    assert re.search(r"advisor_enabled\s*=\s*local\.vllm_enabled", MAIN)
    for name in ("vllm", "vllm_reasoning"):
        block = _block(MAIN, f'module "{name}" {{')
        assert "count = local.vllm_enabled ? 1 : 0" in block, name
    geap = _block(MAIN, 'module "gcp_geap_advisor" {')
    gke = _block(MAIN, 'module "governed_advisor" {')
    assert (
        'count  = local.advisor_enabled && var.advisor_runtime == "geap" ? 1 : 0'
        in geap
    )
    assert (
        'count  = local.advisor_enabled && var.advisor_runtime == "gke" ? 1 : 0' in gke
    )


def test_no_workload_is_pointed_at_vllm_outside_the_backend_locals() -> None:
    # Every vLLM URL comes from a local that is empty under "none".
    locals_block = _block(MAIN, "locals {\n  vllm_enabled")
    rest = MAIN.replace(locals_block, "")
    assert "vllm-service." not in rest and "vllm-reasoning." not in rest
    assert 'vllm_api_key = local.vllm_enabled ? "EMPTY" : ""' in locals_block


def test_gateway_and_bridge_are_told_the_backend() -> None:
    gateway = _squash(_block(MAIN, 'module "gateway" {'))
    bridge = _squash(_block(MAIN, 'module "compliance_bridge" {'))
    for block in (gateway, bridge):
        assert "cage_inference_backend = var.inference_backend" in block
        assert "vllm_api_key = local.vllm_api_key" in block
    module_main = _read(REPO_ROOT / "infra" / "modules" / "gateway" / "main.tf")
    for env in ("CAGE_INFERENCE_BACKEND", "VLLM_API_KEY"):
        assert f'name  = "{env}"' in module_main, env


def test_geap_principal_is_trusted_only_while_a_geap_advisor_exists() -> None:
    gateway = _squash(_block(MAIN, 'module "gateway" {'))
    assert (
        'trusted_geap_principals = local.advisor_enabled && var.advisor_runtime == "geap"'
        in gateway
    )


def test_switching_backend_changes_no_cluster_or_node_pool_input() -> None:
    # "vllm" must come up by a variable flip, not an infrastructure rebuild.
    gke = _block(MAIN, 'module "gke" {')
    assert "inference_backend" not in gke and "vllm_enabled" not in gke


def test_plan_refuses_backends_that_cannot_run() -> None:
    guard = _squash(_block(MAIN, 'resource "terraform_data" "inference_backend_guard"'))
    assert "condition = !local.vllm_enabled || var.enable_gpu_node_pool" in guard
    assert "condition = !var.enable_nemo_guardrails || local.vllm_enabled" in guard


def test_nemo_server_is_off_by_default() -> None:
    block = _squash(_block(VARIABLES, 'variable "enable_nemo_guardrails"'))
    assert "default = false" in block


# ── POAM-2026-136: the unread URL variables are gone ─────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "infra/targets/gcp-gke/variables.tf",
        "infra/targets/agnostic/variables.tf",
        "deploy_all.sh",
        "infra/load_env.sh",
    ],
)
def test_unread_vllm_url_variables_are_removed(path: str) -> None:
    text = _read(REPO_ROOT / path)
    for name in ("vllm_fast_url", "vllm_reasoning_url", "vllm_gateway_url"):
        assert f'variable "{name}"' not in text and f"TF_VAR_{name}" not in text, (
            path,
            name,
        )


# ── Lula: absent, not degraded ────────────────────────────────────────────────


def _rego(manifest: str) -> tuple[list[str], str]:
    doc = yaml.safe_load(_read(REPO_ROOT / "compliance" / "lula" / manifest))
    spec = yaml.safe_load(
        doc["component-definition"]["back-matter"]["resources"][0]["description"]
    )
    names = [r["name"] for r in spec["domain"]["kubernetes-spec"]["resources"]]
    return names, spec["provider"]["opa-spec"]["rego"]


def _set(rego: str, name: str) -> set[str]:
    match = re.search(rf"{name} := \{{(.*?)\}}", rego, re.DOTALL)
    assert match is not None, name
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def test_si2_requires_only_what_every_backend_deploys() -> None:
    _, rego = _rego("lula-validation-si2.yaml")
    assert _set(rego, "required_deployments") == {"gateway", "agentsight-ui"}
    assert _set(rego, "optional_deployments") == {
        "governed-financial-advisor",
        "vllm-inference",
        "vllm-reasoning",
        "nemo-guardrails",
        "compliance-bridge",
    }
    assert "optional_images_pinned" in rego.split("validate if {", 1)[1]


def test_cm6_no_longer_requires_the_nemo_configmap() -> None:
    names, rego = _rego("lula-validation-cm6.yaml")
    assert names == ["governance-thresholds-config"]
    assert "nemo-guardrails-config" not in rego
