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

"""Unit tests for the fail-closed staging lifecycle Gate W harness (`scripts/staging_lifecycle.sh`)."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_SCRIPT = REPO_ROOT / "scripts" / "staging_lifecycle.sh"
CORROBORATION_SCRIPT = REPO_ROOT / "scripts" / "verify_audit_corroboration.py"
ANCHOR_SCRIPT = REPO_ROOT / "scripts" / "read_worm_chain_anchor.py"

DEFAULT_PRE_HASH = "1" * 64
DEFAULT_PRE_ATTEST = "2" * 64
DEFAULT_POST_HASH = "3" * 64
DEFAULT_POST_ATTEST = "4" * 64

DEFAULT_JOB_LOGS = (
    "assessment-results:\n"
    "  observations:\n"
    "    - uuid: 00000000-0000-4000-8000-000000000001\n"
    "  state: satisfied\n"
    'POST /v1/infra/events -> {"status": "INGESTED", "record_hash": "'
    + ("a" * 64)
    + '"}\n'
)

DEFAULT_EVIDENCE_VERIFY_JSON = json.dumps(
    {
        "ok": True,
        "citable": True,
        "verified": [
            {
                "attestation_key": "evidence-stream/2026/11/09/chain01/000000000000-000000000005.ndjson.attestation.json",
                "data_key": "evidence-stream/2026/11/09/chain01/000000000000-000000000005.ndjson",
                "chain_id": "chain01",
                "first_sequence": 0,
                "last_sequence": 5,
                "entries": 6,
                "first_prev_hash": "",
                "last_record_hash": DEFAULT_PRE_HASH,
                "attestation_sha256": DEFAULT_PRE_ATTEST,
                "bound_chain_rotation": False,
            }
        ],
        "failures": [],
        "declared_gaps": [],
        "bound_rotations": [],
        "non_evidentiary": [],
    }
)

DEFAULT_POST_REBUILD_EVIDENCE_VERIFY_JSON = json.dumps(
    {
        "ok": True,
        "citable": True,
        "verified": [
            {
                "attestation_key": "evidence-stream/2026/11/09/chain01/000000000000-000000000005.ndjson.attestation.json",
                "data_key": "evidence-stream/2026/11/09/chain01/000000000000-000000000005.ndjson",
                "chain_id": "chain01",
                "first_sequence": 0,
                "last_sequence": 5,
                "entries": 6,
                "first_prev_hash": "",
                "last_record_hash": DEFAULT_PRE_HASH,
                "attestation_sha256": DEFAULT_PRE_ATTEST,
                "bound_chain_rotation": False,
            },
            {
                "attestation_key": "evidence-stream/2026/11/09/chain02/000000000000-000000000001.ndjson.attestation.json",
                "data_key": "evidence-stream/2026/11/09/chain02/000000000000-000000000001.ndjson",
                "chain_id": "chain02",
                "first_sequence": 0,
                "last_sequence": 1,
                "entries": 2,
                "first_prev_hash": "",
                "last_record_hash": DEFAULT_POST_HASH,
                "attestation_sha256": DEFAULT_POST_ATTEST,
                "rotated_from_chain_id": "chain01",
                "bound_chain_rotation": True,
            },
        ],
        "failures": [],
        "declared_gaps": [],
        "bound_rotations": [
            {
                "previous_chain_id": "chain01",
                "new_chain_id": "chain02",
                "previous_last_sequence": 5,
                "previous_chain_head_hash": DEFAULT_PRE_HASH,
                "previous_batch_attestation_digest": DEFAULT_PRE_ATTEST,
                "attestation_key": "evidence-stream/2026/11/09/chain02/000000000000-000000000001.ndjson.attestation.json",
                "kind": "BOUND_CHAIN_ROTATION",
            }
        ],
        "non_evidentiary": [],
    }
)

DEFAULT_MONITORING_JSON = json.dumps(
    {
        "timeSeries": [
            {
                "metric": {
                    "type": "prometheus.googleapis.com/cage_governance_decisions_total"
                }
            }
        ]
    }
)


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _base_env(bin_dir: Path, **overrides: str) -> dict[str, str]:
    clean = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "TF_VAR_authorized_networks",
            "TF_VAR_startup_grace_hours",
            "TF_VAR_enable_e2e_advisor",
            "TF_VAR_e2e_operator_jwks_json",
            "TF_VAR_evidence_previous_chain_head_hash",
            "TF_VAR_evidence_previous_batch_attestation_digest",
            "EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH",
            "EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST",
            "CAGE_GATE_W_ARCHIVE_DIR",
            "CAGE_HERMETIC_PYTEST_WRAPPER",
            "CAGE_E2E_SUITE_SCRIPT",
            "DEPLOYER_EGRESS_IP",
            "COMPLIANCE_BRIDGE_URL",
            "CAGE_AUDIT_CORROBORATION_SCRIPT",
            "CAGE_WORM_ANCHOR_SCRIPT",
            "CAGE_DEPLOYMENT_REGION",
            "GOOGLE_CLOUD_PROJECT",
            "BILLING_ACCOUNT_ID",
        }
    }
    clean["PATH"] = f"{bin_dir}:{os.environ.get('PATH', '')}"
    clean["CAGE_PRE_TEARDOWN_FLUSH_WAIT_SECONDS"] = "0"
    clean["CAGE_POST_REBUILD_CUSTODY_WAIT_SECONDS"] = "0"
    clean.update(overrides)
    return clean


def _setup_fake_repo(
    tmp_path: Path,
    *,
    kubectl_wait_rc: int = 0,
    ready_replicas: str = "1",
    desired_replicas: int = 1,
    missing_core_workload: str = "",
    cronjob_present: bool = True,
    cronjob_suspend: bool = False,
    pod_restart_count: int = 0,
    init_restart_count: int = 0,
    lula_rc: int = 0,
    lula_state: str = "satisfied",
    startup_grace_active: bool = False,
    job_exit_code: int = 0,
    job_logs: str = DEFAULT_JOB_LOGS,
    pytest_rc: int = 0,
    partner_pytest_rc: int | None = None,
    pytest_summary: str = "5 passed in 0.12s",
    langfuse_rc: int = 0,
    audit_corroboration_rc: int = 0,
    post_rebuild_audit_corroboration_rc: int | None = None,
    include_audit_corroboration_script: bool = True,
    plan_rc: int = 0,
    rebuild_plan_rc: int = 0,
    monitoring_json: str = DEFAULT_MONITORING_JSON,
    monitoring_rc: int = 0,
    evidence_verify_json: str = DEFAULT_EVIDENCE_VERIFY_JSON,
    post_rebuild_evidence_verify_json: str = DEFAULT_POST_REBUILD_EVIDENCE_VERIFY_JSON,
    evidence_verify_rc: int = 0,
    surviving_bucket: str = "",
    surviving_lien: str = "",
) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True, exist_ok=True)
    (repo / "compliance" / "lula").mkdir(parents=True, exist_ok=True)
    tf_dir = repo / "infra" / "targets" / "gcp-gke"
    tf_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(LIFECYCLE_SCRIPT, repo / "scripts" / "staging_lifecycle.sh")
    shutil.copy2(ANCHOR_SCRIPT, repo / "scripts" / "read_worm_chain_anchor.py")
    (repo / "compliance" / "lula" / "lula-validation-sample.yaml").write_text(
        "kind: LulaValidation\n", encoding="utf-8"
    )
    (tf_dir / "staging.tfvars").write_text(
        'environment = "staging"\n', encoding="utf-8"
    )
    (tf_dir / "image_digests.abc1234.tfvars.json").write_text(
        '{"image_digests": {}}\n', encoding="utf-8"
    )

    if include_audit_corroboration_script:
        shutil.copy2(
            CORROBORATION_SCRIPT, repo / "scripts" / "verify_audit_corroboration.py"
        )

    log_file = tmp_path / "calls.log"
    log_file.write_text("", encoding="utf-8")

    # Fixtures written to files so bash stubs avoid quoting issues
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    ready_int = int(ready_replicas)
    workload_items = []
    for kind, name in (
        ("Deployment", "gateway"),
        ("Deployment", "compliance-bridge"),
        ("StatefulSet", "clickhouse"),
    ):
        if name == missing_core_workload:
            continue
        spec_rep = desired_replicas if name == "gateway" else 1
        workload_items.append(
            {
                "kind": kind,
                "metadata": {"name": name},
                "spec": {"replicas": spec_rep},
                "status": {"readyReplicas": ready_int},
            }
        )
    (fixtures_dir / "workloads.json").write_text(
        json.dumps({"items": workload_items}), encoding="utf-8"
    )
    (fixtures_dir / "cronjob.json").write_text(
        json.dumps(
            {
                "kind": "CronJob",
                "metadata": {"name": "lula-audit"},
                "spec": {"suspend": cronjob_suspend},
            }
        ),
        encoding="utf-8",
    )
    (fixtures_dir / "pods.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "gateway-7f9d8"},
                        "status": {
                            "phase": "Running",
                            "initContainerStatuses": [
                                {
                                    "name": "linkerd-init",
                                    "restartCount": init_restart_count,
                                }
                            ],
                            "containerStatuses": [
                                {"name": "gateway", "restartCount": pod_restart_count},
                                {"name": "linkerd-proxy", "restartCount": 0},
                            ],
                        },
                    },
                    {
                        "metadata": {"name": "compliance-bridge-6c4b2"},
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [
                                {"name": "compliance-bridge", "restartCount": 0}
                            ],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (fixtures_dir / "job_pods.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "lula-gate-w-abcde"},
                        "status": {
                            "phase": "Succeeded" if job_exit_code == 0 else "Failed",
                            "containerStatuses": [
                                {
                                    "name": "lula-auditor",
                                    "restartCount": 0,
                                    "state": {
                                        "terminated": {"exitCode": job_exit_code}
                                    },
                                }
                            ],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (fixtures_dir / "job_logs.txt").write_text(job_logs, encoding="utf-8")
    (fixtures_dir / "metrics_a53.json").write_text(
        json.dumps(
            {
                "control_id": "A.5.3",
                "startup_grace_active": startup_grace_active,
                "startup_grace_remaining_hours": 6.0 if startup_grace_active else 0.0,
            }
        ),
        encoding="utf-8",
    )
    (fixtures_dir / "evidence_verify.json").write_text(
        evidence_verify_json, encoding="utf-8"
    )
    (fixtures_dir / "evidence_verify_post.json").write_text(
        post_rebuild_evidence_verify_json, encoding="utf-8"
    )
    rebuilt_flag = fixtures_dir / "rebuilt_flag"
    (fixtures_dir / "monitoring.json").write_text(monitoring_json, encoding="utf-8")
    plan_counter_file = fixtures_dir / "tf_plan_count"
    plan_counter_file.write_text("0", encoding="utf-8")

    _write_executable(
        repo / "deploy_all.sh",
        f"""#!/usr/bin/env bash
echo "deploy_all.sh $* | SKIP_BUILD=${{SKIP_BUILD:-}} | BOOTSTRAP_IMPORT_STATE=${{BOOTSTRAP_IMPORT_STATE:-}} | TF_VAR_authorized_networks=${{TF_VAR_authorized_networks:-}} | TF_VAR_evidence_previous_chain_head_hash=${{TF_VAR_evidence_previous_chain_head_hash:-}} | TF_VAR_evidence_previous_batch_attestation_digest=${{TF_VAR_evidence_previous_batch_attestation_digest:-}}" >> "{log_file}"
exit 0
""",
    )

    _write_executable(
        repo / "scripts" / "bootstrap_gcp_project.sh",
        f"""#!/usr/bin/env bash
echo "bootstrap_gcp_project.sh $*" >> "{log_file}"
if [[ "$*" == *"--import-state"* ]]; then
  touch "{rebuilt_flag}"
fi
exit 0
""",
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    _write_executable(
        bin_dir / "git",
        """#!/usr/bin/env bash
if [[ "$*" == *"rev-parse --short HEAD"* ]]; then
  echo "abc1234"
  exit 0
fi
if [[ "$*" == *"rev-parse HEAD"* ]]; then
  echo "abc1234567890abcdef1234567890abcdef12345"
  exit 0
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "gcloud",
        f"""#!/usr/bin/env bash
echo "gcloud $*" >> "{log_file}"
if [[ "$*" == *"auth print-access-token"* ]]; then
  echo "fake-access-token"
  exit 0
fi
if [[ "$*" == *"projects describe"* ]]; then
  exit 1
fi
if [[ "$*" == *"storage buckets list"* ]]; then
  echo "ephemeral-proj-99-tfstate"
  echo "ephemeral-proj-99_cloudbuild"
  if [[ -n "{surviving_bucket}" ]]; then
    printf '%b\\n' "{surviving_bucket}"
  fi
  exit 0
fi
if [[ "$*" == *"resource-manager liens list"* ]]; then
  if [[ -n "{surviving_lien}" ]]; then
    printf '%b\\n' "{surviving_lien}"
  fi
  exit 0
fi
exit 0
""",
    )

    cronjob_rc = 0 if cronjob_present else 1
    _write_executable(
        bin_dir / "kubectl",
        f"""#!/usr/bin/env bash
echo "kubectl $*" >> "{log_file}"
if [[ "$*" == *"wait --for=condition=Ready"* ]]; then
  exit {kubectl_wait_rc}
fi
if [[ "$*" == *"get deploy,sts"* ]]; then
  cat "{fixtures_dir / "workloads.json"}"
  exit 0
fi
if [[ "$*" == *"rollout status"* ]]; then
  exit 0
fi
if [[ "$*" == *"get cronjob lula-audit"* ]]; then
  if [[ {cronjob_rc} -ne 0 ]]; then
    exit {cronjob_rc}
  fi
  cat "{fixtures_dir / "cronjob.json"}"
  exit 0
fi
if [[ "$*" == *"get pods"* && "$*" == *"job-name=lula-gate-w"* ]]; then
  cat "{fixtures_dir / "job_pods.json"}"
  exit 0
fi
if [[ "$*" == *"get pods"* && "$*" == *"-o json"* ]]; then
  cat "{fixtures_dir / "pods.json"}"
  exit 0
fi
if [[ "$*" == *"logs job/lula-gate-w"* ]]; then
  cat "{fixtures_dir / "job_logs.txt"}"
  exit 0
fi
if [[ "$*" == *"exec"* && "$*" == *"deploy/compliance-bridge"* && "$*" == *"/v1/metrics/A.5.3"* ]]; then
  cat "{fixtures_dir / "metrics_a53.json"}"
  exit 0
fi
if [[ "$*" == *"exec"* && "$*" == *"deploy/compliance-bridge"* ]]; then
  if [[ -f "{rebuilt_flag}" ]]; then
    cat "{fixtures_dir / "evidence_verify_post.json"}"
  else
    cat "{fixtures_dir / "evidence_verify.json"}"
  fi
  exit {evidence_verify_rc}
fi
echo '{{}}'
exit 0
""",
    )

    _write_executable(
        bin_dir / "lula",
        f"""#!/usr/bin/env bash
echo "lula $*" >> "{log_file}"
out_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output-file)
      out_file="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$out_file" ]]; then
  cat <<EOF > "$out_file"
assessment-results:
  results:
    - findings:
        - target:
            status:
              state: {lula_state}
      observations:
        - uuid: 00000000-0000-4000-8000-000000000001
          relevant-evidence:
            - description: "Result: {lula_state}"
EOF
fi
exit {lula_rc}
""",
    )

    corroboration_exit = audit_corroboration_rc
    post_corroboration_exit = (
        audit_corroboration_rc
        if post_rebuild_audit_corroboration_rc is None
        else post_rebuild_audit_corroboration_rc
    )
    effective_partner_rc = pytest_rc if partner_pytest_rc is None else partner_pytest_rc
    _write_executable(
        bin_dir / "uv",
        f"""#!/usr/bin/env bash
echo "uv $*" >> "{log_file}"
if [[ "$*" == *"verify_langfuse_posture.py"* ]]; then
  exit {langfuse_rc}
fi
if [[ "$*" == *"verify_audit_corroboration.py"* ]]; then
  if [[ -f "{rebuilt_flag}" ]]; then
    exit {post_corroboration_exit}
  fi
  exit {corroboration_exit}
fi
if [[ "$*" == *"pytest"* && "$*" == *"--run-partner-integration"* ]]; then
  echo "============================= test session starts ============================="
  echo "{pytest_summary}"
  exit {effective_partner_rc}
fi
if [[ "$*" == *"pytest"* ]]; then
  echo "============================= test session starts ============================="
  echo "{pytest_summary}"
  exit {pytest_rc}
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "terraform",
        f"""#!/usr/bin/env bash
echo "terraform $*" >> "{log_file}"
if [[ "$*" == *"plan -detailed-exitcode"* ]]; then
  count="$(cat "{plan_counter_file}")"
  count=$((count + 1))
  echo "$count" > "{plan_counter_file}"
  if [[ "$count" -eq 1 ]]; then
    exit {plan_rc}
  fi
  exit {rebuild_plan_rc}
fi
exit 0
""",
    )

    _write_executable(
        bin_dir / "jq",
        """#!/usr/bin/env bash
exit 0
""",
    )

    _write_executable(
        bin_dir / "curl",
        f"""#!/usr/bin/env bash
if [[ "$*" == *"monitoring.googleapis.com"* ]]; then
  echo "curl $*" >> "{log_file}"
  cat "{fixtures_dir / "monitoring.json"}"
  exit {monitoring_rc}
fi
echo "203.0.113.42"
exit 0
""",
    )

    return repo, bin_dir, log_file


def test_staging_lifecycle_happy_path_passes_and_destroys_with_rendered_digests(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    calls = log_file.read_text(encoding="utf-8")
    # PF5: Auto-populated deployer /32 authorized_networks
    assert (
        'TF_VAR_authorized_networks=[{"cidr":"203.0.113.42/32","display_name":"deployer-egress"}]'
        in calls
    )
    # Phase 1 + Stage 5 zero-drift read-back plans
    assert calls.count("plan -detailed-exitcode") == 2
    # Phase 2 dynamic workload checks without opa-service or agentsight-ui
    assert "rollout status deployment/gateway" in calls
    assert "rollout status deployment/compliance-bridge" in calls
    assert "rollout status statefulset/clickhouse" in calls
    assert "opa-service" not in calls
    assert "agentsight-ui" not in calls
    # Phase 3 in-cluster Job/lula-gate-w
    assert "create job lula-gate-w --from=cronjob/lula-audit" in calls
    assert "wait --for=condition=complete job/lula-gate-w" in calls
    # Phase 4 regional posture + live residency + live Langfuse (--posture staging, no --dry-run)
    assert "-m us_fed" in calls
    assert "-m eu_ecb" in calls
    assert "-m apac_mas" in calls
    assert "test_data_residency.py --run-integration" in calls
    assert "verify_langfuse_posture.py --posture staging" in calls
    assert "--dry-run" not in calls
    # Phase 5 live sweeps + Cloud Monitoring GMP timeSeries.list + WORM /v1/evidence/verify
    assert "-m live_external and not partner --run-live-external" in calls
    assert "-m integration --run-integration" in calls
    assert "-m partner_integration --run-partner-integration" in calls
    assert "monitoring.googleapis.com/v3/projects/demo-staging-proj/timeSeries" in calls
    assert "/v1/evidence/verify?require_citable=true" in calls
    assert calls.count("verify_audit_corroboration.py --project demo-staging-proj") == 2
    # Phase 6: Stage 4 (--import-state), Stage 5 (SKIP_BUILD=true clean rebuild + bound genesis), Stage 6 (final destroy)
    assert "--import-state" in calls
    assert "SKIP_BUILD=true | BOOTSTRAP_IMPORT_STATE=true" in calls
    assert f"TF_VAR_evidence_previous_chain_head_hash={DEFAULT_PRE_HASH}" in calls
    assert (
        f"TF_VAR_evidence_previous_batch_attestation_digest={DEFAULT_PRE_ATTEST}"
        in calls
    )
    assert calls.count("destroy -var-file=staging.tfvars") == 2
    # PF8: Persistent KMS + BinAuthz resources detached before destroy
    assert "state rm google_kms_key_ring.signing" in calls
    assert "state rm google_kms_crypto_key.binauthz_attestor" in calls
    assert "state rm google_binary_authorization_attestor.build_attestor" in calls
    assert "state rm google_container_analysis_note.build_attestor_note" in calls
    assert "state rm google_service_account.cloudbuild" in calls
    assert "state rm module.kms" in calls
    assert "enable_nist_compliance" not in calls
    assert "image_digests.abc1234.tfvars.json" in calls


def test_staging_lifecycle_fails_closed_on_phase1_post_apply_drift_and_still_tears_down(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, plan_rc=2)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "post-apply configuration drift detected" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "destroy -var-file=staging.tfvars" in calls
    assert "--import-state" not in calls


def test_staging_lifecycle_fails_closed_on_phase1_plan_error_and_still_tears_down(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, plan_rc=1)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Zero-drift read-back FAILED" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "destroy -var-file=staging.tfvars" in calls


def test_staging_lifecycle_fails_closed_when_workload_unready_after_teardown(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, ready_replicas="0")
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Workload readiness check failed" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    # Still runs Phase 6 teardown for cost containment before exiting non-zero
    assert "destroy -var-file=staging.tfvars" in calls


@pytest.mark.parametrize("missing_core", ["gateway", "compliance-bridge"])
def test_staging_lifecycle_fails_closed_when_core_workload_missing(
    tmp_path: Path, missing_core: str
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(
        tmp_path, missing_core_workload=missing_core
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert f"core workload deployment/{missing_core} missing" in proc.stderr
    assert "destroy -var-file=staging.tfvars" in log_file.read_text(encoding="utf-8")


def test_staging_lifecycle_fails_closed_when_cronjob_lula_audit_suspended_or_missing(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(tmp_path, cronjob_suspend=True)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "CronJob/lula-audit has .spec.suspend=true" in proc.stderr


@pytest.mark.parametrize(
    ("pod_restarts", "init_restarts"),
    [(2, 0), (0, 1)],
)
def test_staging_lifecycle_fails_closed_when_any_container_restarted(
    tmp_path: Path, pod_restarts: int, init_restarts: int
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        pod_restart_count=pod_restarts,
        init_restart_count=init_restarts,
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Pod restart check failed" in proc.stderr


def test_staging_lifecycle_fails_closed_when_lula_or_posture_fails(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, lula_rc=1, pytest_rc=1)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Staging lifecycle gate FAILED" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "destroy -var-file=staging.tfvars" in calls


def test_staging_lifecycle_fresh_project_bootstraps_and_verifies_zero_survivors(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    env = _base_env(bin_dir)
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--billing-account=012345-6789AB-CDEF01",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "gcloud projects create ephemeral-proj-99" in calls
    assert (
        "gcloud billing projects link ephemeral-proj-99 --billing-account=012345-6789AB-CDEF01"
        in calls
    )
    assert "bootstrap_gcp_project.sh --project=ephemeral-proj-99" in calls
    assert "gcloud storage buckets list --project=ephemeral-proj-99" in calls


def test_staging_lifecycle_fresh_project_fails_on_surviving_workload_bucket(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        surviving_bucket="ephemeral-proj-99-models",
    )
    env = _base_env(bin_dir)
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Surviving workload GCS bucket(s) after destroy" in proc.stderr


def test_staging_lifecycle_fresh_project_retains_locked_langfuse_event_upload_bucket(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        surviving_bucket="langfuse-event-upload-ephemeral-proj-99-deadbeef",
    )
    env = _base_env(bin_dir)
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "POAM-2026-159" in proc.stdout


def test_staging_lifecycle_fails_closed_when_lula_exits_zero_with_not_satisfied(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(
        tmp_path, lula_rc=0, lula_state="not-satisfied"
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "not-satisfied" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "destroy -var-file=staging.tfvars" in calls


def test_staging_lifecycle_skips_api_and_planned_lula_specs_on_host_and_prints_planned_list(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    (repo / "compliance" / "lula" / "lula-validation-api.yaml").write_text(
        "  type: api\n  url: http://compliance-bridge.governance-stack.svc.cluster.local/v1/metrics/A.5.2\n",
        encoding="utf-8",
    )
    (repo / "compliance" / "lula" / "lula-validation-ra5.yaml").write_text(
        "# cage-status: planned\n  type: kubernetes\n",
        encoding="utf-8",
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        ["bash", str(repo / "scripts" / "staging_lifecycle.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Planned Lula specs skipped (1): lula-validation-ra5.yaml" in proc.stdout
    assert "[planned] lula-validation-ra5.yaml" in proc.stdout
    calls = log_file.read_text(encoding="utf-8")
    assert "lula-validation-sample.yaml" in calls
    assert "lula-validation-api.yaml" not in calls
    assert "lula-validation-ra5.yaml" not in calls


@pytest.mark.parametrize(
    ("job_exit_code", "job_logs", "expected_err"),
    [
        (1, DEFAULT_JOB_LOGS, "container exit status check FAILED"),
        (
            0,
            'assessment-results:\n  state: not-satisfied\n{"status": "INGESTED"}\n',
            "reported not-satisfied",
        ),
        (
            0,
            'GET /v1/oscal/assessment-results -> satisfied\n{"status": "INGESTED"}\n',
            "metrics-derived /v1/oscal/assessment-results",
        ),
        (
            0,
            "assessment-results:\n  observations:\n    - uuid: 1\n  state: satisfied\n",
            "lack /v1/infra/events custody receipt acknowledgment",
        ),
    ],
)
def test_staging_lifecycle_fails_closed_on_incluster_lula_job_defects(
    tmp_path: Path, job_exit_code: int, job_logs: str, expected_err: str
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        job_exit_code=job_exit_code,
        job_logs=job_logs,
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert expected_err in proc.stderr


@pytest.mark.parametrize(
    "vacuous_summary",
    [
        "3 skipped, 2 deselected in 0.05s",
        "0 passed, 4 skipped in 0.05s",
        "no tests ran in 0.01s",
    ],
)
def test_staging_lifecycle_fails_closed_on_vacuous_zero_passed_pytest_run(
    tmp_path: Path, vacuous_summary: str
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        pytest_rc=0,
        pytest_summary=vacuous_summary,
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "vacuous pytest run (0 passed tests detected" in proc.stderr


def test_staging_lifecycle_fails_closed_when_live_langfuse_posture_fails(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(tmp_path, langfuse_rc=1)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert (
        "Live Langfuse posture isolation check (--posture staging) FAILED"
        in proc.stderr
    )


def test_staging_lifecycle_fails_closed_when_gmp_timeseries_empty(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        monitoring_json=json.dumps({"timeSeries": []}),
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "0 timeSeries returned for prometheus.googleapis.com/cage_*" in proc.stderr


@pytest.mark.parametrize(
    ("bad_payload", "expected_fragment"),
    [
        (
            {
                "ok": True,
                "citable": True,
                "verified": [],
                "failures": [],
                "declared_gaps": [],
                "non_evidentiary": [],
            },
            "verified=0 (expected > 0)",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [{"batch_id": "b1"}],
                "failures": [{"batch_id": "b2", "reason": "tampered"}],
                "declared_gaps": [],
                "non_evidentiary": [],
            },
            "failures=1 (expected 0)",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [{"batch_id": "b1"}],
                "failures": [],
                "declared_gaps": [{"seq": 2}],
                "non_evidentiary": [],
            },
            "gaps=1 (expected 0)",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [{"batch_id": "b1"}],
                "failures": [],
                "declared_gaps": [],
                "non_evidentiary": [{"batch_id": "b3"}],
            },
            "unsigned=1 (expected 0)",
        ),
        (
            {
                "ok": True,
                "citable": False,
                "verified": [{"batch_id": "b1"}],
                "failures": [],
                "declared_gaps": [],
                "non_evidentiary": [],
            },
            "archive not ok/citable",
        ),
    ],
)
def test_staging_lifecycle_fails_closed_on_worm_evidence_verify_violations(
    tmp_path: Path, bad_payload: dict[str, object], expected_fragment: str
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        evidence_verify_json=json.dumps(bad_payload),
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert expected_fragment in proc.stderr


def test_staging_lifecycle_executes_pluggable_as6_corroboration_hook_and_fails_closed(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, audit_corroboration_rc=1)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Cloud Audit Log corroboration hook FAILED" in proc.stderr
    assert (
        "verify_audit_corroboration.py --project demo-staging-proj"
        in log_file.read_text(encoding="utf-8")
    )


def test_staging_lifecycle_fails_closed_when_audit_corroboration_script_missing(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path, include_audit_corroboration_script=False
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Required AS-6 Cloud Audit Log corroboration script missing" in proc.stderr


def test_staging_lifecycle_stage5_rebuild_drift_fails_closed_after_final_destroy(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, plan_rc=0, rebuild_plan_rc=2)
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Stage 5 post-rebuild zero-drift verification FAILED" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    # Both initial teardown and post-rebuild final teardown must run
    assert calls.count("destroy -var-file=staging.tfvars") == 2


def test_staging_lifecycle_fresh_project_retains_evidence_domain_worm_buckets_and_lien(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(
        tmp_path,
        surviving_bucket="ephemeral-proj-99-evidence-worm-staging\nephemeral-proj-99-audit-logs-worm-staging",
        surviving_lien="liens/p123-l1\tstorage.googleapis.com\tresourcemanager.projects.delete",
    )
    env = _base_env(bin_dir)
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "PF9 persistent evidence-domain WORM bucket(s) retained by design"
        in proc.stdout
    )
    calls = log_file.read_text(encoding="utf-8")
    assert "state rm module.evidence_domain" in calls
    assert "state rm module.worm_bucket" in calls


def test_staging_lifecycle_allow_legacy_lien_survivor_accepts_known_langfuse_events_bucket(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        surviving_bucket="langfuse-events-ephemeral-proj-99-deadbeef",
        surviving_lien="liens/p123-l2\tstorage.googleapis.com\tresourcemanager.projects.delete",
    )
    env = _base_env(bin_dir)
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--allow-legacy-lien-survivor",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "PF9 explicit known survivor" in proc.stdout


@pytest.mark.parametrize(
    ("post_rebuild_payload", "expected_fragment"),
    [
        (
            {
                "ok": True,
                "citable": True,
                "verified": json.loads(DEFAULT_POST_REBUILD_EVIDENCE_VERIFY_JSON)[
                    "verified"
                ],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "bound_rotations=0 (expected >= 1 across teardown boundary)",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": json.loads(DEFAULT_POST_REBUILD_EVIDENCE_VERIFY_JSON)[
                    "verified"
                ],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [
                    {
                        "previous_chain_id": "legacy-chain",
                        "new_chain_id": "chain01",
                        "previous_last_sequence": 1,
                        "previous_chain_head_hash": "9" * 64,
                        "previous_batch_attestation_digest": "8" * 64,
                        "kind": "BOUND_CHAIN_ROTATION",
                    }
                ],
                "non_evidentiary": [],
            },
            "bound_rotations did not bind expected pre-teardown chain head",
        ),
        (
            json.loads(DEFAULT_EVIDENCE_VERIFY_JSON),
            "verified=1 (expected >= 2)",
        ),
    ],
)
def test_staging_lifecycle_stage5b_fails_closed_when_post_rebuild_worm_lacks_bound_rotation(
    tmp_path: Path, post_rebuild_payload: dict[str, object], expected_fragment: str
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(
        tmp_path,
        post_rebuild_evidence_verify_json=json.dumps(post_rebuild_payload),
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert expected_fragment in proc.stderr
    assert (
        "Stage 5b post-rebuild cross-teardown WORM chain continuity FAILED"
        in proc.stderr
    )
    calls = log_file.read_text(encoding="utf-8")
    assert calls.count("destroy -var-file=staging.tfvars") == 2


def test_staging_lifecycle_stage5b_fails_closed_when_post_rebuild_audit_corroboration_fails(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(
        tmp_path,
        audit_corroboration_rc=0,
        post_rebuild_audit_corroboration_rc=1,
    )
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Stage 5b post-rebuild Cloud Audit Log corroboration FAILED" in proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert calls.count("verify_audit_corroboration.py --project demo-staging-proj") == 2
    assert calls.count("destroy -var-file=staging.tfvars") == 2


def test_staging_lifecycle_archive_manifest_stamps_existing_vs_fresh_target_mode_and_suite_counts(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(
        tmp_path,
        pytest_summary="collected 9 items\n5 passed, 2 skipped, 2 deselected in 0.12s",
    )
    (repo / "compliance" / "lula" / "lula-validation-ra5.yaml").write_text(
        "# cage-status: planned\n  type: kubernetes\n",
        encoding="utf-8",
    )
    archive_existing = tmp_path / "archive-existing"
    env = _base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj")
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            f"--archive-dir={archive_existing}",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    manifest = json.loads(
        (archive_existing / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["deployment_target_mode"] == "existing_operated_project"
    assert manifest["overall_status"] == "PASS"
    assert manifest["full_unskipped_gate_w"] is True
    assert manifest["startup_grace_hours"] == 0
    assert manifest["partner_conformance_status"] == "passed"
    assert manifest["worm_continuity"]["post_rebuild_bound_rotation_verified"] is True
    assert manifest["worm_continuity"]["pre_teardown_head_hash"] == DEFAULT_PRE_HASH
    assert (archive_existing / "lula" / "assessment-results-sample.yaml").is_file()
    assert (archive_existing / "lula" / "planned-lula-specs.txt").read_text(
        encoding="utf-8"
    ).strip() == "lula-validation-ra5.yaml"
    assert (archive_existing / "lula" / "job-lula-gate-w.log").is_file()
    assert any((archive_existing / "worm").glob("*.json"))
    assert len(manifest["pytest_suites"]) >= 7
    first_suite = manifest["pytest_suites"][0]
    assert first_suite["collected"] == 9
    assert first_suite["passed"] == 5
    assert first_suite["skipped"] == 2
    assert first_suite["deselected"] == 2

    archive_fresh = tmp_path / "archive-fresh"
    proc_fresh = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            f"--archive-dir={archive_fresh}",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_fresh.returncode == 0, proc_fresh.stderr
    manifest_fresh = json.loads(
        (archive_fresh / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_fresh["deployment_target_mode"] == "fresh_project_clean_room"
    assert manifest_fresh["overall_status"] == "PARTIAL_PASS"
    assert manifest_fresh["full_unskipped_gate_w"] is False


def test_staging_lifecycle_fails_closed_when_startup_grace_active_true(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(tmp_path, startup_grace_active=True)
    archive_dir = tmp_path / "archive-grace-fail"
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            f"--archive-dir={archive_dir}",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "startup_grace_active != false" in proc.stderr
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["overall_status"] == "FAIL"
    assert manifest["phase_failures"]["lula"] >= 1


def test_staging_lifecycle_enable_e2e_advisor_and_allow_partner_outage_manifest_recording(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path, partner_pytest_rc=1)
    archive_waived = tmp_path / "archive-partner-waived"
    proc_waived = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--enable-e2e-advisor",
            "--allow-partner-outage",
            f"--archive-dir={archive_waived}",
            "--skip-lula",
            "--skip-posture",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_waived.returncode == 0, proc_waived.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "--var enable_e2e_advisor=true" in calls
    assert "-m e2e --run-e2e" in calls
    manifest_waived = json.loads(
        (archive_waived / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_waived["enable_e2e_advisor"] is True
    assert manifest_waived["partner_conformance_status"] == "unreachable_waived"

    archive_unwaived = tmp_path / "archive-partner-unwaived"
    proc_unwaived = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            f"--archive-dir={archive_unwaived}",
            "--skip-lula",
            "--skip-posture",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_unwaived.returncode != 0
    manifest_unwaived = json.loads(
        (archive_unwaived / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_unwaived["partner_conformance_status"] == "failed"
    assert manifest_unwaived["overall_status"] == "FAIL"


def test_staging_lifecycle_clean_room_dotenv_isolation_wrapper_and_e2e_suite_wiring(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    # Seed a conflicting .env pointing at an operated project/registry to prove
    # --fresh-project isolates project_id, registry_url, and LIVE_ENV_FILE.
    (repo / ".env").write_text(
        "GOOGLE_CLOUD_PROJECT=operated-legacy-proj\n"
        "REGISTRY_URL=gcr.io/operated-legacy-proj\n"
        "LANGFUSE_HOST=http://langfuse-web.legacy.svc.cluster.local:3000\n",
        encoding="utf-8",
    )
    e2e_stub = repo / "tests" / "e2e" / "run_gke_e2e_suite.py"
    e2e_stub.parent.mkdir(parents=True, exist_ok=True)
    e2e_stub.write_text("# stub\n", encoding="utf-8")

    # Extend uv stub to emit fake JWKS on --generate-ephemeral-jwks
    uv_path = bin_dir / "uv"
    uv_body = uv_path.read_text(encoding="utf-8")
    uv_body = uv_body.replace(
        f'echo "uv $*" >> "{log_file}"\n',
        f'echo "uv $*" >> "{log_file}"\n'
        'if [[ "$*" == *"--generate-ephemeral-jwks"* ]]; then\n'
        '  echo \'{"keys":[{"crv":"P-256","kid":"cage-e2e-op-1","kty":"EC","x":"AA","y":"BB"}]}\'\n'
        "  exit 0\n"
        "fi\n"
        'if [[ "$*" == *"run_gke_e2e_suite.py"* ]]; then\n'
        "  echo '{\"passed\": true}'\n"
        "  exit 0\n"
        "fi\n",
    )
    _write_executable(uv_path, uv_body)

    wrapper = tmp_path / "hermetic_wrapper.sh"
    _write_executable(
        wrapper,
        f"""#!/usr/bin/env bash
echo "wrapper $*" >> "{log_file}"
echo "collected 3 items"
echo "3 passed in 0.05s"
exit 0
""",
    )

    archive_dir = tmp_path / "archive-clean-room"
    env = _base_env(
        bin_dir,
        CAGE_HERMETIC_PYTEST_WRAPPER=str(wrapper),
    )
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--enable-e2e-advisor",
            f"--archive-dir={archive_dir}",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert "--var project_id=ephemeral-proj-99" in calls
    assert "--var registry_url=" in calls
    assert "operated-legacy-proj" not in calls
    assert (
        "wrapper env CAGE_DEPLOYMENT_REGION=US_FED ./.venv/bin/pytest tests/ -m us_fed"
        in calls
    )
    assert (
        "wrapper env CAGE_DEPLOYMENT_REGION=EU_ECB ./.venv/bin/pytest tests/ -m eu_ecb"
        in calls
    )
    assert (
        "wrapper env CAGE_DEPLOYMENT_REGION=APAC_MAS ./.venv/bin/pytest tests/ -m apac_mas"
        in calls
    )
    assert "--generate-ephemeral-jwks" in calls
    assert "--seed-only" in calls
    assert "--full-e2e" in calls
    assert "e2e_operator_jwks_json=" in calls
    # .env restored intact on disk
    assert (repo / ".env").is_file()
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["deployment_target_mode"] == "fresh_project_clean_room"
    assert manifest["pre_existing_project_state"]["project_pre_existed"] is False
    assert (
        "operator_orchestrated_rebuild_of_cage_evidence_stream"
        in manifest["worm_continuity"]["rotation_binding_scope"]["covered"]
    )
    assert (
        "unorchestrated_empty_redis_stream_cold_start_on_operated_clusters"
        in manifest["worm_continuity"]["rotation_binding_scope"]["not_covered"]
    )


def test_staging_lifecycle_records_phase0_kms_residue_when_project_pre_exists(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(tmp_path)
    gcloud_path = bin_dir / "gcloud"
    gcloud_body = gcloud_path.read_text(encoding="utf-8")
    gcloud_body = gcloud_body.replace(
        'if [[ "$*" == *"projects describe"* ]]; then\n  exit 1\nfi',
        'if [[ "$*" == *"projects describe"* ]]; then\n  exit 0\nfi\n'
        'if [[ "$*" == *"kms keyrings list"* ]]; then\n'
        '  echo "projects/ephemeral-proj-99/locations/us-central1/keyRings/cage-signing-staging"\n'
        "  exit 0\n"
        "fi\n"
        'if [[ "$*" == *"kms keys list"* ]]; then\n'
        '  echo "projects/ephemeral-proj-99/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/binauthz-attestor"\n'
        "  exit 0\n"
        "fi",
    )
    _write_executable(gcloud_path, gcloud_body)

    archive_dir = tmp_path / "archive-kms-residue"
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            f"--archive-dir={archive_dir}",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["deployment_target_mode"] == "fresh_project_with_phase0_kms_residue"
    pre_state = manifest["pre_existing_project_state"]
    assert pre_state["project_pre_existed"] is True
    assert pre_state["has_prior_cage_residue"] is True
    assert pre_state["pre_run_evidence_stream_object_count"] == 0
    assert pre_state["kms_keyrings"] == [
        "projects/ephemeral-proj-99/locations/us-central1/keyRings/cage-signing-staging"
    ]
    assert pre_state["kms_crypto_keys"] == [
        "projects/ephemeral-proj-99/locations/us-central1/keyRings/cage-signing-staging/cryptoKeys/binauthz-attestor"
    ]


def test_destroy_sigpipe_safe_and_gke_neg_ignore_annotations() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    lifecycle_sh = (repo_root / "scripts" / "staging_lifecycle.sh").read_text(
        encoding="utf-8"
    )
    assert "state list 2>/dev/null | grep -q" not in lifecycle_sh, (
        "piping terraform state list into grep -q triggers SIGPIPE (exit 141) under set -o pipefail"
    )
    assert (
        'grep -q \'^module\\.gke\\.\' <<<"$(terraform -chdir="$TF_DIR" state list 2>/dev/null || true)"'
        in lifecycle_sh
    )

    providers_tf = (
        repo_root / "infra" / "targets" / "gcp-gke" / "providers.tf"
    ).read_text(encoding="utf-8")
    assert "ignore_annotations" in providers_tf
    assert "^cloud\\\\.google\\\\.com/neg(-status)?$" in providers_tf


def test_pf9_manifest_distinguishes_preexisting_vs_retained_by_design_buckets_and_skip_provision(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    gcloud_path = bin_dir / "gcloud"
    gcloud_body = gcloud_path.read_text(encoding="utf-8")
    # Pre-existing project starts with evidence-worm-staging + tfstate; post-destroy also
    # holds a newly created 1-day-locked langfuse-event-upload-<proj>-a1b2c3d4 bucket.
    marker_file = tmp_path / "provisioned.marker"
    gcloud_body = gcloud_body.replace(
        'if [[ "$*" == *"projects describe"* ]]; then\n  exit 1\nfi',
        'if [[ "$*" == *"projects describe"* ]]; then\n  exit 0\nfi\n'
        'if [[ "$*" == *"storage buckets list"* ]]; then\n'
        '  echo "ephemeral-proj-99-tfstate"\n'
        '  echo "ephemeral-proj-99-evidence-worm-staging"\n'
        f'  if [[ -f "{marker_file}" ]]; then\n'
        '    echo "langfuse-event-upload-ephemeral-proj-99-a1b2c3d4"\n'
        "  fi\n"
        "  exit 0\n"
        "fi",
    )
    _write_executable(gcloud_path, gcloud_body)

    deploy_path = repo / "deploy_all.sh"
    deploy_body = deploy_path.read_text(encoding="utf-8")
    deploy_body = deploy_body.replace(
        "exit 0",
        f'touch "{marker_file}"\nexit 0',
    )
    _write_executable(deploy_path, deploy_body)

    archive_dir = tmp_path / "archive-pf9-diff"
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            f"--archive-dir={archive_dir}",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
        ],
        env=_base_env(bin_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    pre_state = manifest["pre_existing_project_state"]
    post_state = manifest["post_destroy_project_state"]
    assert pre_state is not None and post_state is not None
    assert post_state["buckets_pre_existed"] == [
        "ephemeral-proj-99-evidence-worm-staging",
        "ephemeral-proj-99-tfstate",
    ]
    assert post_state["buckets_created_and_retained_this_run"] == [
        "langfuse-event-upload-ephemeral-proj-99-a1b2c3d4"
    ]
    assert post_state["buckets_retained_by_design"]["langfuse_retention_locked"] == [
        "langfuse-event-upload-ephemeral-proj-99-a1b2c3d4"
    ]
    assert post_state["buckets_unexpected_survivors"] == []

    # Verify --skip-provision skips deploy_all.sh and marks full_unskipped_gate_w = False.
    log_file.write_text("", encoding="utf-8")
    archive_skip_prov = tmp_path / "archive-skip-prov"
    proc_skip = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--project=ephemeral-proj-99",
            f"--archive-dir={archive_skip_prov}",
            "--skip-provision",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
            "--no-destroy",
        ],
        env=_base_env(bin_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_skip.returncode == 0, proc_skip.stderr
    assert "deploy_all.sh" not in log_file.read_text(encoding="utf-8")
    manifest_skip = json.loads(
        (archive_skip_prov / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest_skip["overall_status"] == "PARTIAL_PASS"
    assert manifest_skip["full_unskipped_gate_w"] is False


def test_staging_lifecycle_stage5b_seeds_post_rebuild_custody_before_worm_verification(
    tmp_path: Path,
) -> None:
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    e2e_stub = repo / "tests" / "e2e" / "run_gke_e2e_suite.py"
    e2e_stub.parent.mkdir(parents=True, exist_ok=True)
    e2e_stub.write_text("# stub\n", encoding="utf-8")
    archive_dir = tmp_path / "archive-stage5b-seed"
    env = _base_env(
        bin_dir,
        GOOGLE_CLOUD_PROJECT="demo-staging-proj",
        TF_VAR_e2e_operator_jwks_json='{"keys":[]}',
    )
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--enable-e2e-advisor",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            f"--archive-dir={archive_dir}",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (archive_dir / "post-rebuild-custody-seed.json").is_file()
    calls = log_file.read_text(encoding="utf-8")
    assert "rollout status deployment/governed-financial-advisor" in calls
    assert "rollout status deployment/inference-stub" in calls
    assert "run_gke_e2e_suite.py --seed-only" in calls
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["worm_continuity"]["post_rebuild_bound_rotation_verified"] is True


def test_binauthz_note_and_attestor_declare_prevent_destroy() -> None:
    """POAM-2026-202: Deleting `build_attestor_note` cascade-deletes Grafeas image attestations."""
    import re

    perimeter_tf = (
        REPO_ROOT / "infra" / "targets" / "gcp-gke" / "perimeter.tf"
    ).read_text(encoding="utf-8")
    for resource_type, resource_name in (
        ("google_container_analysis_note", "build_attestor_note"),
        ("google_binary_authorization_attestor", "build_attestor"),
    ):
        pattern = re.compile(
            rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{(?P<body>.*?)\n\}}',
            re.DOTALL,
        )
        match = pattern.search(perimeter_tf)
        assert match is not None, (
            f"missing {resource_type}.{resource_name} in perimeter.tf"
        )
        assert "prevent_destroy = true" in match.group("body"), (
            f"{resource_type}.{resource_name} must set lifecycle.prevent_destroy = true"
        )


def test_no_piped_grep_quiet_under_pipefail_across_repo_scripts_and_workflows() -> None:
    """Prevent `| grep -q` SIGPIPE (141) inversions under `set -o pipefail`."""
    import re

    piped_grep_q = re.compile(
        r"(?<!\|)\|(?!\|)\s*grep(?:\s+-[A-Za-z]+)*\s+(?:-[A-Za-z]*q\b|--quiet\b)"
    )
    candidates = [
        REPO_ROOT / "deploy_all.sh",
        *sorted((REPO_ROOT / "scripts").rglob("*.sh")),
        *sorted((REPO_ROOT / "deployment" / "scripts").rglob("*.sh")),
        *sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")),
    ]
    offenders: list[str] = []
    for path in candidates:
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if stripped.startswith("#"):
                continue
            prev_line = lines[lineno - 2] if lineno >= 2 else ""
            joined = (
                f"{prev_line.rstrip()[:-1]} {stripped}"
                if prev_line.rstrip().endswith("\\")
                else raw_line
            )
            if piped_grep_q.search(joined):
                rel = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel}:{lineno}: {stripped}")
    assert offenders == [], f"Found SIGPIPE-prone `| grep -q` pipeline(s): {offenders}"


def test_pf9_accepts_live_gcloud_wire_names_for_cloudbuild_sa_and_attestors_and_rejects_workload_sa(
    tmp_path: Path,
) -> None:
    repo, bin_dir, _ = _setup_fake_repo(tmp_path)
    gcloud_path = bin_dir / "gcloud"
    orig_gcloud = gcloud_path.read_text(encoding="utf-8")
    _write_executable(
        gcloud_path,
        orig_gcloud.removesuffix("exit 0\n")
        + """if [[ "$*" == *"iam service-accounts list"* ]]; then
  echo "cage-cloudbuild-staging@ephemeral-proj-99.iam.gserviceaccount.com"
  if [[ -n "${EXTRA_SA:-}" ]]; then
    echo "${EXTRA_SA}"
  fi
  exit 0
fi
if [[ "$*" == *"container binauthz attestors list"* ]]; then
  echo "built-by-cloud-build"
  echo "cage-build-attestor-staging"
  if [[ -n "${EXTRA_ATTESTOR:-}" ]]; then
    echo "${EXTRA_ATTESTOR}"
  fi
  exit 0
fi
exit 0
""",
    )
    archive_ok = tmp_path / "archive-pf9-ok"
    proc_ok = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
            f"--archive-dir={archive_ok}",
        ],
        env=_base_env(bin_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_ok.returncode == 0, proc_ok.stderr
    post_ok = json.loads((archive_ok / "manifest.json").read_text(encoding="utf-8"))[
        "post_destroy_project_state"
    ]
    assert post_ok["service_accounts_retained_by_design"] == [
        "cage-cloudbuild-staging@ephemeral-proj-99.iam.gserviceaccount.com"
    ]
    assert post_ok["service_accounts_unexpected_survivors"] == []
    assert post_ok["binauthz_attestors_retained_by_design"] == [
        "built-by-cloud-build",
        "cage-build-attestor-staging",
    ]
    assert post_ok["binauthz_attestors_unexpected_survivors"] == []
    assert post_ok["grafeas_notes_retained_by_design"] == [
        "projects/ephemeral-proj-99/notes/cage-build-attestor-note-staging"
    ]

    archive_bad = tmp_path / "archive-pf9-bad"
    proc_bad = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--fresh-project=ephemeral-proj-99",
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            "--skip-rebuild",
            f"--archive-dir={archive_bad}",
        ],
        env=_base_env(
            bin_dir,
            EXTRA_SA="cage-gateway-staging@ephemeral-proj-99.iam.gserviceaccount.com",
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc_bad.returncode != 0
    assert "Surviving workload service account(s) after destroy" in proc_bad.stderr


def test_staging_lifecycle_cold_node_sidecar_timeouts_and_drift_read_back_scope(
    tmp_path: Path,
) -> None:
    """POAM-2026-203: Phase 2/Stage 5b timeouts tolerate cold-node native-sidecar sequencing and manifest records drift_read_back_scope."""
    repo, bin_dir, log_file = _setup_fake_repo(tmp_path)
    archive_dir = tmp_path / "archive-drift-scope"
    proc = subprocess.run(
        [
            "bash",
            str(repo / "scripts" / "staging_lifecycle.sh"),
            "--skip-lula",
            "--skip-posture",
            "--skip-live-sweep",
            "--skip-telemetry",
            f"--archive-dir={archive_dir}",
        ],
        env=_base_env(bin_dir, GOOGLE_CLOUD_PROJECT="demo-staging-proj"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    calls = log_file.read_text(encoding="utf-8")
    assert (
        "kubectl wait --for=condition=Ready pods -l !job-name -n governance-stack --timeout=600s"
        in calls
    )
    assert (
        "kubectl rollout status deployment/gateway -n governance-stack --timeout=300s"
        in calls
    )
    lifecycle_sh = (REPO_ROOT / "scripts" / "staging_lifecycle.sh").read_text(
        encoding="utf-8"
    )
    assert (
        'kubectl rollout status deployment/gateway -n "$NAMESPACE" --timeout=420s'
        in lifecycle_sh
    )
    manifest = json.loads((archive_dir / "manifest.json").read_text(encoding="utf-8"))
    scope = manifest["drift_read_back_scope"]
    assert "google_*" in scope["field_granularity"]
    assert any(
        "module.gateway.helm_release.gateway" in entry
        for entry in scope["release_granularity"]
    )


# Regression coverage binding: POAM-024, POAM-2026-159, POAM-2026-192, POAM-2026-197, POAM-2026-202, POAM-2026-203, POAM-2026-204, POAM-2026-205, POAM-2026-206, POAM-2026-207
