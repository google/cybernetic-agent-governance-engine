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

"""Regression gates for INF-02 & data-class WORM retention / certification custody.

Locks:
1. **Half A — Workload Runtime Posture (``local.effective_cage_env``):**
   When ``var.environment == "dev"`` and ``var.enforce_in_dev == true`` (committed
   ``eu-dev.tfvars`` and ``apac-dev.tfvars``), ``local.effective_cage_env`` must
   resolve to ``"staging"`` (while ``prod`` stays ``"prod"``, ``staging`` stays
   ``"staging"``, and permissive ``dev`` stays ``"dev"``), and every workload
   module/container setting ``cage_env`` or ``CAGE_ENV`` must consume
   ``local.effective_cage_env`` while cloud resource names remain keyed on
   ``var.environment``.

2. **Half B — Data-Class WORM Retention Split & ``certification_mode`` CMEK Guard:**
   - Operational telemetry (``google_storage_bucket.langfuse_event_upload``) reads
     ``local.telemetry_retention_period_seconds``: ``220752000`` s in ``prod``,
     ``86400`` s in non-``prod`` enforcing postures, ``220752000`` s unlocked in
     permissive ``dev``.
   - Evidentiary WORM custody (``module.worm_bucket`` and ``module.evidence_domain``)
     reads ``local.evidence_retention_period_seconds``: ``220752000`` s whenever
     ``environment == "prod"``, ``local.cross_project_evidence_custody`` is true,
     or ``var.certification_mode`` is true; ``86400`` s in ordinary single-project
     ``staging`` / enforcing ``dev``; ``220752000`` s unlocked in permissive ``dev``.
   - ``local.require_separate_evidence_project`` defaults to ``true`` under both
     ``environment == "prod"`` and ``certification_mode == true`` so 7-year locked
     WORM objects are never encrypted under an ephemeral workload project's CMEK
     key unless explicitly overridden (``F-97``), and ``scripts/staging_lifecycle.sh``
     enforces the same fail-closed pre-Phase-0 check on ``--certification``.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE_DIR = _REPO / "infra" / "targets" / "gcp-gke"
_MODULES_DIR = _REPO / "infra" / "modules"
_MAIN_TF = _GKE_DIR / "main.tf"
_VARS_TF = _GKE_DIR / "variables.tf"
_OUTPUTS_TF = _GKE_DIR / "outputs.tf"
_CANARY_TF = _GKE_DIR / "gateway_canary.tf"
_KMS_SIGNING_TF = _GKE_DIR / "kms_signing.tf"
_PERIMETER_TF = _GKE_DIR / "perimeter.tf"
_RETENTION_TFTEST = _GKE_DIR / "tests" / "retention_posture.tftest.hcl"
_EVIDENCE_TFTEST = _GKE_DIR / "tests" / "evidence_domain.tftest.hcl"
_STAGING_LIFECYCLE_SH = _REPO / "scripts" / "staging_lifecycle.sh"


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
    environment: str,
    enforce_in_dev: bool,
    *,
    project_id: str = "workload-proj",
    evidence_project_id: str | None = None,
    external_evidence_domain_enabled: bool = False,
    certification_mode: bool = False,
    require_separate_evidence_project: bool | None = None,
) -> tuple[bool, str, int, int, bool, int, bool, bool]:
    """Mirror root locals, retention split, and isolation guard in ``main.tf``."""
    enforcing_posture = (
        environment == "prod" or environment == "staging" or enforce_in_dev
    )
    effective_cage_env = (
        "staging" if (enforcing_posture and environment == "dev") else environment
    )
    resolved_ev_proj = (
        evidence_project_id if evidence_project_id is not None else project_id
    )
    cross_project_evidence_custody = (
        external_evidence_domain_enabled or resolved_ev_proj != project_id
    )
    telemetry_retention_s = (
        220752000
        if environment == "prod"
        else (86400 if enforcing_posture else 220752000)
    )
    evidence_retention_s = (
        220752000
        if (
            environment == "prod"
            or cross_project_evidence_custody
            or certification_mode
        )
        else (86400 if enforcing_posture else 220752000)
    )
    retention_locked = enforcing_posture
    governance_replicas = (
        2 if environment == "prod" else (1 if enforcing_posture else 0)
    )
    effective_require_separate = (
        require_separate_evidence_project
        if require_separate_evidence_project is not None
        else (environment == "prod" or certification_mode)
    )
    isolation_guard_passes = (
        not effective_require_separate or cross_project_evidence_custody
    )
    return (
        enforcing_posture,
        effective_cage_env,
        telemetry_retention_s,
        evidence_retention_s,
        retention_locked,
        governance_replicas,
        effective_require_separate,
        isolation_guard_passes,
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
            r"(?ms)^trusted_operator_identities\s*=\s*\[(.*?)\]",
            text,
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
# Half B: Data-Class WORM Split & certification_mode CMEK Coupling Guard
# ---------------------------------------------------------------------------


def test_data_class_worm_retention_and_certification_mode_wiring() -> None:
    """variables.tf, main.tf, and outputs.tf must split telemetry vs evidence WORM retention and guard certification_mode."""
    vars_text = _VARS_TF.read_text(encoding="utf-8")
    vars_blocks = dict(_extract_blocks("variable", vars_text))
    assert "certification_mode" in vars_blocks
    assert re.search(
        r"(?m)^\s*default\s*=\s*false\s*$", vars_blocks["certification_mode"]
    )
    assert (
        "certification_mode == true" in vars_blocks["require_separate_evidence_project"]
    )

    main_nc = _strip_hcl_comments(_MAIN_TF.read_text(encoding="utf-8"))
    assert (
        "cross_project_evidence_custody = var.external_evidence_domain_enabled || local.evidence_project_id != var.project_id"
        in main_nc
    )
    assert (
        'telemetry_retention_period_seconds = var.environment == "prod" ? 220752000 : (local.enforcing_posture ? 86400 : 220752000)'
        in main_nc
    )
    assert (
        'evidence_retention_period_seconds  = (var.environment == "prod" || local.cross_project_evidence_custody || var.certification_mode) ? 220752000 : (local.enforcing_posture ? 86400 : 220752000)'
        in main_nc
    )
    assert ':(var.environment == "prod" || var.certification_mode)' in main_nc.replace(
        ": (", ":("
    )

    modules = dict(_extract_blocks("module", main_nc))
    assert (
        "retention_period_seconds = local.evidence_retention_period_seconds"
        in modules["worm_bucket"]
    )
    assert (
        "retention_period_seconds          = local.evidence_retention_period_seconds"
        in modules["evidence_domain"]
    )
    assert "retention_period = local.telemetry_retention_period_seconds" in main_nc

    outputs_nc = _strip_hcl_comments(_OUTPUTS_TF.read_text(encoding="utf-8"))
    for key in (
        "certification_mode",
        "telemetry_retention_period_seconds",
        "evidence_retention_period_seconds",
    ):
        assert re.search(rf"(?m)^\s*{key}\s*=", outputs_nc), (
            f"outputs.tf deployment_summary missing {key}"
        )


@pytest.mark.parametrize(
    (
        "profile_name",
        "expected_tier",
        "expected_enforcing",
        "expected_effective_cage_env",
        "expected_telemetry_s",
        "expected_evidence_s",
        "expected_locked",
        "expected_gov_replicas",
    ),
    [
        ("dev.tfvars", "dev", False, "dev", 220752000, 220752000, False, 0),
        ("us-dev.tfvars", "dev", False, "dev", 220752000, 220752000, False, 0),
        ("eu-dev.tfvars", "dev", True, "staging", 86400, 86400, True, 1),
        ("apac-dev.tfvars", "dev", True, "staging", 86400, 86400, True, 1),
        ("staging.tfvars", "staging", True, "staging", 86400, 86400, True, 1),
        ("prod.tfvars", "prod", True, "prod", 220752000, 220752000, True, 2),
        ("eu-prod.tfvars", "prod", True, "prod", 220752000, 220752000, True, 2),
        ("apac-prod.tfvars", "prod", True, "prod", 220752000, 220752000, True, 2),
    ],
)
def test_committed_tfvars_posture_and_worm_matrix(
    profile_name: str,
    expected_tier: str,
    expected_enforcing: bool,
    expected_effective_cage_env: str,
    expected_telemetry_s: int,
    expected_evidence_s: int,
    expected_locked: bool,
    expected_gov_replicas: int,
) -> None:
    """Evaluate every committed .tfvars profile (default single-project for non-prod, separate project for prod)."""
    scalars = _parse_tfvars_scalars(_GKE_DIR / profile_name)
    tier = scalars.get("environment", "dev")
    enforce_in_dev = scalars.get("enforce_in_dev", "false") == "true"
    ev_proj = "prod-evidence-proj" if tier == "prod" else None

    (
        enforcing,
        effective_env,
        telemetry_s,
        evidence_s,
        locked,
        gov_replicas,
        _,
        guard_ok,
    ) = _evaluate_posture(tier, enforce_in_dev, evidence_project_id=ev_proj)

    assert guard_ok is True
    assert tier == expected_tier
    assert enforcing is expected_enforcing
    assert effective_env == expected_effective_cage_env
    assert telemetry_s == expected_telemetry_s
    assert evidence_s == expected_evidence_s
    assert locked is expected_locked
    assert gov_replicas == expected_gov_replicas


@pytest.mark.parametrize(
    (
        "tier",
        "enforce_in_dev",
        "evidence_project_id",
        "certification_mode",
        "require_separate_override",
        "expected_telemetry_s",
        "expected_evidence_s",
        "expected_guard_ok",
    ),
    [
        # (a) staging + certification_mode without separate project -> refused
        ("staging", False, None, True, None, 86400, 220752000, False),
        # (b) staging + certification_mode + separate evidence_project_id -> 1d telemetry, 2555d evidence
        ("staging", False, "ev-proj", True, None, 86400, 220752000, True),
        # (c) staging / eu-dev + cross-project custody without certification_mode -> 1d telemetry, 2555d evidence
        ("staging", False, "ev-proj", False, None, 86400, 220752000, True),
        ("dev", True, "ev-proj", False, None, 86400, 220752000, True),
        # (d) staging + certification_mode + explicit require_separate_evidence_project=false -> allowed override
        ("staging", False, None, True, False, 86400, 220752000, True),
    ],
)
def test_certification_and_cross_project_custody_matrix(
    tier: str,
    enforce_in_dev: bool,
    evidence_project_id: str | None,
    certification_mode: bool,
    require_separate_override: bool | None,
    expected_telemetry_s: int,
    expected_evidence_s: int,
    expected_guard_ok: bool,
) -> None:
    """Verify data-class retention split and CMEK isolation guard across certification and cross-project modes."""
    (
        _,
        _,
        telemetry_s,
        evidence_s,
        locked,
        _,
        _,
        guard_ok,
    ) = _evaluate_posture(
        tier,
        enforce_in_dev,
        evidence_project_id=evidence_project_id,
        certification_mode=certification_mode,
        require_separate_evidence_project=require_separate_override,
    )
    assert locked is True
    assert telemetry_s == expected_telemetry_s
    assert evidence_s == expected_evidence_s
    assert guard_ok is expected_guard_ok


def test_tftest_suites_cover_data_class_split_and_certification_guard() -> None:
    """retention_posture.tftest.hcl and evidence_domain.tftest.hcl must test all 4 certification/custody cases."""
    retention_hcl = _RETENTION_TFTEST.read_text(encoding="utf-8")
    for run_name in (
        "eu_dev_profile_locks_both_buckets_for_one_day",
        "apac_dev_profile_locks_both_buckets_for_one_day",
        "staging_certification_mode_refuses_single_project_evidence_custody",
        "staging_certification_mode_with_separate_project_splits_retention",
        "staging_cross_project_custody_without_certification_mode_splits_retention",
        "eu_dev_cross_project_custody_without_certification_mode_splits_retention",
        "staging_certification_mode_explicit_single_project_override_splits_retention",
    ):
        assert f'run "{run_name}"' in retention_hcl, (
            f"Missing {run_name} in retention_posture.tftest.hcl"
        )

    evidence_hcl = _EVIDENCE_TFTEST.read_text(encoding="utf-8")
    assert (
        'run "staging_certification_mode_refuses_single_project_evidence_domain"'
        in evidence_hcl
    )
    assert (
        'run "staging_certification_mode_with_separate_evidence_project_locks_custody_2555d"'
        in evidence_hcl
    )


def test_staging_lifecycle_certification_flag_fails_fast_without_separate_evidence_project(
    tmp_path: Path,
) -> None:
    """staging_lifecycle.sh --certification must fail fast before Phase 0 unless a distinct --evidence-project is supplied."""
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
    }

    # 1. Missing --evidence-project -> fails fast before Phase 0
    proc_missing = subprocess.run(
        [
            "bash",
            str(_STAGING_LIFECYCLE_SH),
            "--project=ephemeral-workload-proj",
            "--certification",
        ],
        cwd=str(tmp_path),
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_missing.returncode != 0
    assert "--evidence-project" in proc_missing.stderr
    assert "2,555 days" in proc_missing.stderr
    assert "Phase 0" not in proc_missing.stdout

    # 2. --evidence-project equal to workload --project -> also fails fast
    proc_same = subprocess.run(
        [
            "bash",
            str(_STAGING_LIFECYCLE_SH),
            "--project=ephemeral-workload-proj",
            "--certification",
            "--evidence-project=ephemeral-workload-proj",
        ],
        cwd=str(tmp_path),
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_same.returncode != 0
    assert "--evidence-project" in proc_same.stderr
    assert "Phase 0" not in proc_same.stdout

    # 3. Distinct --evidence-project <id> (space-separated) passes the pre-Phase-0 certification guard
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gcloud = fake_bin / "gcloud"
    fake_gcloud.write_text(
        "#!/usr/bin/env bash\necho GCLOUD_CALLED >&2\nexit 99\n", encoding="utf-8"
    )
    fake_gcloud.chmod(0o755)
    env_with_fake_gcloud = {
        **base_env,
        "PATH": f"{fake_bin}:{base_env['PATH']}",
        "TF_VAR_authorized_networks": '[{"cidr":"203.0.113.7/32","display_name":"test"}]',
    }
    proc_distinct = subprocess.run(
        [
            "bash",
            str(_STAGING_LIFECYCLE_SH),
            "--fresh-project=ephemeral-workload-proj",
            "--certification",
            "--evidence-project",
            "persistent-evidence-proj",
            f"--archive-dir={tmp_path / 'arch1'}",
        ],
        cwd=str(tmp_path),
        env=env_with_fake_gcloud,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Phase 0: Fresh-project bootstrap" in proc_distinct.stdout
    assert "--certification locks WORM evidence custody" not in proc_distinct.stderr

    # 4. Explicit TF_VAR_require_separate_evidence_project=false override also passes the pre-Phase-0 guard
    proc_override = subprocess.run(
        [
            "bash",
            str(_STAGING_LIFECYCLE_SH),
            "--fresh-project=ephemeral-workload-proj",
            "--certification",
            f"--archive-dir={tmp_path / 'arch2'}",
        ],
        cwd=str(tmp_path),
        env={
            **env_with_fake_gcloud,
            "TF_VAR_require_separate_evidence_project": "false",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Phase 0: Fresh-project bootstrap" in proc_override.stdout
    assert "--certification locks WORM evidence custody" not in proc_override.stderr

    # 5. Script wires ${TF_VAR_evidence_project_id:-$PROJECT_ID}-evidence-worm-staging and --project across bucket reads
    script_text = _STAGING_LIFECYCLE_SH.read_text(encoding="utf-8")
    assert 'export TF_VAR_certification_mode="true"' in script_text
    assert 'export TF_VAR_evidence_project_id="$EVIDENCE_PROJECT_ID"' in script_text
    assert (
        '--gcs-bucket="${TF_VAR_evidence_project_id:-$PROJECT_ID}-evidence-worm-staging" '
        '--gcs-project="${TF_VAR_evidence_project_id:-$PROJECT_ID}"'
    ) in script_text
    assert (
        'gcloud storage rsync -r "gs://${TF_VAR_evidence_project_id:-$PROJECT_ID}-evidence-worm-staging" '
        '"$ARCHIVE_DIR/worm-objects" --project="${TF_VAR_evidence_project_id:-$PROJECT_ID}"'
    ) in script_text
