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

"""Regression gates for INF-02: enforcing-dev runtime CAGE_ENV & non-prod WORM cap.

Locks both halves of INF-02 across ``infra/targets/gcp-gke/``:

1. **Half A — Workload Runtime Posture (``local.effective_cage_env``):**
   When ``var.environment == "dev"`` and ``var.enforce_in_dev == true`` (committed
   ``eu-dev.tfvars`` and ``apac-dev.tfvars``), ``local.effective_cage_env`` must
   resolve to ``"staging"`` (while ``prod`` stays ``"prod"``, ``staging`` stays
   ``"staging"``, and permissive ``dev`` stays ``"dev"``), and every workload
   module/container setting ``cage_env`` or ``CAGE_ENV`` must consume
   ``local.effective_cage_env`` rather than raw ``var.environment``. Cloud
   resource naming (``cage-postgres-${var.environment}``,
   ``cage-signing-${var.environment}``, VPC/KMS/Valkey/bucket names) must stay
   on ``var.environment``.

2. **Half B — Non-``prod`` Irreversible 7-Year GCS WORM Lock Guard:**
   ``local.retention_period_seconds`` must resolve to ``86400`` (1 day) whenever
   a non-``prod`` posture locks buckets (``staging`` and ``dev`` with
   ``enforce_in_dev = true``), keeping ``220752000`` (2555 days / 7 years)
   locked strictly in ``prod`` (and ``220752000`` unlocked in permissive ``dev``
   where ``force_destroy = true`` can delete objects immediately).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE_DIR = _REPO / "infra" / "targets" / "gcp-gke"
_MODULES_DIR = _REPO / "infra" / "modules"
_MAIN_TF = _GKE_DIR / "main.tf"
_CANARY_TF = _GKE_DIR / "gateway_canary.tf"
_KMS_SIGNING_TF = _GKE_DIR / "kms_signing.tf"
_PERIMETER_TF = _GKE_DIR / "perimeter.tf"
_RETENTION_TFTEST = _GKE_DIR / "tests" / "retention_posture.tftest.hcl"


def _strip_hcl_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        line = re.sub(r"\s+#.*$", "", line)
        lines.append(line)
    return "\n".join(lines)


def _extract_blocks(kind: str, text: str) -> list[tuple[str, str]]:
    """Return ``(name, full_block_text)`` for every top-level ``<kind> "<name>" { ... }``."""
    pattern = re.compile(rf'(?m)^\s*{re.escape(kind)}\s+"([^"]+)"\s*\{{')
    results: list[tuple[str, str]] = []
    for match in pattern.finditer(text):
        name = match.group(1)
        open_brace = text.index("{", match.start())
        pos = open_brace + 1
        depth = 1
        while pos < len(text) and depth > 0:
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
            pos += 1
        results.append((name, text[match.start() : pos]))
    return results


def _parse_tfvars_scalars(tfvars_path: Path) -> dict[str, str]:
    text = tfvars_path.read_text(encoding="utf-8")
    matches = re.findall(r'(?m)^([a-z_][a-z0-9_]*)\s*=\s*("[^"]*"|true|false)', text)
    return {key: val.strip('"') for key, val in matches}


def _evaluate_posture(
    environment: str, enforce_in_dev: bool
) -> tuple[bool, str, int, bool, int]:
    """Mirror root locals and governance Valkey replica resolution in ``main.tf``."""
    enforcing_posture = (
        environment == "prod" or environment == "staging" or enforce_in_dev
    )
    effective_cage_env = (
        "staging" if (enforcing_posture and environment == "dev") else environment
    )
    retention_period_seconds = (
        220752000
        if environment == "prod"
        else (86400 if enforcing_posture else 220752000)
    )
    retention_locked = enforcing_posture
    governance_replicas = (
        2 if environment == "prod" else (1 if enforcing_posture else 0)
    )
    return (
        enforcing_posture,
        effective_cage_env,
        retention_period_seconds,
        retention_locked,
        governance_replicas,
    )


# ---------------------------------------------------------------------------
# Half A: Workload Runtime Posture (effective_cage_env)
# ---------------------------------------------------------------------------


def test_effective_cage_env_local_is_defined_and_preserves_prod() -> None:
    """main.tf must define effective_cage_env promoting only enforcing dev to staging."""
    main_nc = _strip_hcl_comments(_MAIN_TF.read_text(encoding="utf-8"))
    assert (
        'effective_cage_env = local.enforcing_posture && var.environment == "dev" ? "staging" : var.environment'
        in main_nc
    ), (
        "main.tf must define local.effective_cage_env promoting enforcing dev to staging while preserving prod"
    )
    assert 'local.enforcing_posture ? "staging" : var.environment' not in main_nc, (
        "Legacy ternary that downgraded prod to staging in app_secrets must not remain"
    )


def test_every_cage_env_module_wires_local_effective_cage_env() -> None:
    """Every module declaring cage_env (plus inference_stub CAGE_ENV) must receive local.effective_cage_env."""
    all_target_tf = "\n".join(
        _strip_hcl_comments(p.read_text(encoding="utf-8"))
        for p in sorted(_GKE_DIR.glob("*.tf"))
    )
    modules = dict(_extract_blocks("module", all_target_tf))

    expected_cage_env_modules = {
        "compliance_bridge",
        "gateway",
        "reconciliation_worker",
        "governed_advisor",
        "app_secrets",
    }
    for mod_name in expected_cage_env_modules:
        assert mod_name in modules, f"Missing module.{mod_name} in gcp-gke"
        block = modules[mod_name]
        assert re.search(
            r"(?m)^\s*cage_env\s*=\s*local\.effective_cage_env\s*$", block
        ), f"module.{mod_name} must wire cage_env = local.effective_cage_env"
        assert not re.search(r"(?m)^\s*cage_env\s*=\s*var\.environment\s*$", block), (
            f"module.{mod_name} must never wire raw var.environment to cage_env"
        )

    # Dynamic check: scan all child modules referenced from gcp-gke; if a module
    # declares variable "cage_env", gcp-gke MUST pass local.effective_cage_env.
    discovered_cage_env_modules: set[str] = set()
    for mod_name, block in modules.items():
        src_match = re.search(r'source\s*=\s*"\.\./\.\./modules/([^"]+)"', block)
        if not src_match:
            continue
        mod_vars = _MODULES_DIR / src_match.group(1) / "variables.tf"
        if mod_vars.exists() and 'variable "cage_env"' in mod_vars.read_text(
            encoding="utf-8"
        ):
            discovered_cage_env_modules.add(mod_name)
            assert re.search(
                r"(?m)^\s*cage_env\s*=\s*local\.effective_cage_env\s*$", block
            ), (
                f"Discovered cage_env consumer module.{mod_name} must wire local.effective_cage_env"
            )

    assert discovered_cage_env_modules == expected_cage_env_modules

    # inference_stub maps var.environment directly to container CAGE_ENV.
    stub_block = modules["inference_stub"]
    assert re.search(
        r"(?m)^\s*environment\s*=\s*local\.effective_cage_env\s*$", stub_block
    ), "module.inference_stub must wire environment = local.effective_cage_env"


def test_gateway_canary_and_inline_workloads_wire_effective_cage_env() -> None:
    """gateway_canary.tf and any inline gcp-gke K8s workloads must never pass var.environment to CAGE_ENV."""
    canary_nc = _strip_hcl_comments(_CANARY_TF.read_text(encoding="utf-8"))
    assert re.search(
        r'name\s*=\s*"CAGE_ENV"\s+value\s*=\s*local\.effective_cage_env\b',
        canary_nc,
    ), "gateway_canary.tf must set CAGE_ENV = local.effective_cage_env"

    for tf_path in sorted(_GKE_DIR.glob("*.tf")):
        nc = _strip_hcl_comments(tf_path.read_text(encoding="utf-8"))
        assert not re.search(
            r'name\s*=\s*"(?:CAGE_ENV|ENVIRONMENT)"\s+value\s*=\s*var\.environment\b',
            nc,
        ), f"{tf_path.name} sets CAGE_ENV/ENVIRONMENT directly from var.environment"


def test_enforcing_dev_satisfies_downstream_gateway_and_bridge_preconditions() -> None:
    """Promoting CAGE_ENV to staging requires 1 governance Valkey replica and human OIDC trust anchors."""
    main_nc = _strip_hcl_comments(_MAIN_TF.read_text(encoding="utf-8"))
    gov_valkey = dict(_extract_blocks("module", main_nc))["memorystore_governance"]
    assert (
        'replica_count = var.environment == "prod" ? 2 : (local.enforcing_posture ? 1 : 0)'
        in gov_valkey
    ), (
        "memorystore_governance must provision 1 replica under local.enforcing_posture so gateway WAIT 1 precondition holds"
    )

    for profile_name in ("eu-dev.tfvars", "apac-dev.tfvars"):
        text = (_GKE_DIR / profile_name).read_text(encoding="utf-8")
        scalars = _parse_tfvars_scalars(_GKE_DIR / profile_name)
        assert scalars.get("environment") == "dev"
        assert scalars.get("enforce_in_dev") == "true"
        assert scalars.get("operator_oidc_issuer", "").startswith("https://"), (
            f"{profile_name} must set https:// operator_oidc_issuer for compliance_bridge POAM-2026-196"
        )
        assert scalars.get("operator_jwks_uri", "").startswith("https://"), (
            f"{profile_name} must set https:// operator_jwks_uri for compliance_bridge POAM-2026-196"
        )
        assert scalars.get("operator_oidc_audience", "") != "", (
            f"{profile_name} must set non-empty operator_oidc_audience"
        )
        ids_match = re.search(
            r"(?ms)^trusted_operator_identities\s*=\s*\[(.*?)\]", text
        )
        assert ids_match is not None, (
            f"{profile_name} must set trusted_operator_identities for compliance_bridge POAM-2026-196"
        )
        principals = re.findall(r'"([^"]+)"', ids_match.group(1))
        assert len(principals) >= 2, (
            f"{profile_name} must configure human operator identities for HITL quorum"
        )


def test_cloud_resource_naming_remains_on_var_environment() -> None:
    """Cloud infrastructure resource names must stay keyed on var.environment, not local.effective_cage_env."""
    main_nc = _strip_hcl_comments(_MAIN_TF.read_text(encoding="utf-8"))
    kms_nc = _strip_hcl_comments(_KMS_SIGNING_TF.read_text(encoding="utf-8"))
    perim_nc = _strip_hcl_comments(_PERIMETER_TF.read_text(encoding="utf-8"))

    assert (
        'instance_name      = "cage-postgres-${var.environment}-${random_id.cloudsql_suffix.hex}"'
        in main_nc
    )
    assert '"cage-valkey-gov-${var.environment}"' in main_nc
    assert '"cage-valkey-app-${var.environment}"' in main_nc
    assert '"${local.evidence_project_id}-evidence-worm-${var.environment}"' in main_nc
    assert (
        'ca_pool_id             = "cage-mesh-${var.environment}-${random_id.mesh_ca_pool_suffix.hex}"'
        in main_nc
    )
    assert 'name     = "cage-signing-${var.environment}"' in kms_nc
    assert '"cage-vpc-${var.environment}"' in perim_nc
    assert '"cage-subnet-${var.environment}"' in perim_nc


# ---------------------------------------------------------------------------
# Half B: Non-prod Irreversible 7-Year GCS WORM Lock Cap
# ---------------------------------------------------------------------------


def test_worm_retention_expression_caps_non_prod_locked_buckets_at_one_day() -> None:
    """main.tf must cap locked non-prod retention at 86400s while keeping 220752000s in prod and unlocked dev."""
    main_nc = _strip_hcl_comments(_MAIN_TF.read_text(encoding="utf-8"))
    assert (
        'retention_period_seconds = var.environment == "prod" ? 220752000 : (local.enforcing_posture ? 86400 : 220752000)'
        in main_nc
    )
    assert "retention_locked         = local.enforcing_posture" in main_nc
    assert (
        'retention_period_seconds = var.environment == "staging" ? 86400 : 220752000'
        not in main_nc
    ), "Legacy retention_period_seconds expression locked eu-dev/apac-dev for 7 years"


@pytest.mark.parametrize(
    (
        "profile_name",
        "expected_tier",
        "expected_enforcing",
        "expected_effective_cage_env",
        "expected_retention_s",
        "expected_locked",
        "expected_gov_replicas",
    ),
    [
        ("dev.tfvars", "dev", False, "dev", 220752000, False, 0),
        ("us-dev.tfvars", "dev", False, "dev", 220752000, False, 0),
        ("eu-dev.tfvars", "dev", True, "staging", 86400, True, 1),
        ("apac-dev.tfvars", "dev", True, "staging", 86400, True, 1),
        ("staging.tfvars", "staging", True, "staging", 86400, True, 1),
        ("prod.tfvars", "prod", True, "prod", 220752000, True, 2),
        ("eu-prod.tfvars", "prod", True, "prod", 220752000, True, 2),
        ("apac-prod.tfvars", "prod", True, "prod", 220752000, True, 2),
    ],
)
def test_committed_tfvars_posture_and_worm_matrix(
    profile_name: str,
    expected_tier: str,
    expected_enforcing: bool,
    expected_effective_cage_env: str,
    expected_retention_s: int,
    expected_locked: bool,
    expected_gov_replicas: int,
) -> None:
    """Evaluate every committed .tfvars profile against INF-02 runtime and WORM invariants."""
    scalars = _parse_tfvars_scalars(_GKE_DIR / profile_name)
    tier = scalars.get("environment", "dev")
    enforce_in_dev = scalars.get("enforce_in_dev", "false") == "true"

    (
        enforcing,
        effective_env,
        retention_s,
        locked,
        gov_replicas,
    ) = _evaluate_posture(tier, enforce_in_dev)

    assert tier == expected_tier
    assert enforcing is expected_enforcing
    assert effective_env == expected_effective_cage_env
    assert retention_s == expected_retention_s
    assert locked is expected_locked
    assert gov_replicas == expected_gov_replicas

    # Core safety invariant: no non-prod profile may EVER lock a bucket for > 1 day.
    if tier != "prod" and locked:
        assert retention_s == 86400, (
            f"Non-prod profile {profile_name} locks WORM buckets for {retention_s}s (> 86400s)!"
        )


def test_retention_posture_tftest_covers_enforcing_dev_one_day_cap_and_effective_env() -> (
    None
):
    """retention_posture.tftest.hcl must assert 86400s locked + effective_cage_env on eu-dev and apac-dev."""
    tftest = _RETENTION_TFTEST.read_text(encoding="utf-8")
    assert 'run "eu_dev_profile_locks_both_buckets_for_one_day"' in tftest
    assert 'run "apac_dev_profile_locks_both_buckets_for_one_day"' in tftest
    assert "eu_dev_profile_keeps_2555_days_locked" not in tftest
    assert "apac_dev_profile_keeps_2555_days_locked" not in tftest
    assert 'local.effective_cage_env == "staging"' in tftest
    assert 'local.effective_cage_env == "prod"' in tftest
    assert 'local.effective_cage_env == "dev"' in tftest
