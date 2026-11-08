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

"""Reconciler cadence vs snapshot TTL.

The reconciler previously ran as a ``*/5`` CronJob in single-shot mode with a
300 s snapshot TTL, so the signed snapshot expired before the next run could
publish and strict-mode CBF refused every CBF-gated action for part of every
cycle. These tests pin the invariant on both the Terraform module and the daemon.
"""

from __future__ import annotations

import re
from pathlib import Path

import fakeredis
import pytest

from src.gateway.governance.reconciliation.daemon import GroundTruthReconciler

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parent.parent
_MOD_DIR = _REPO / "infra" / "modules" / "reconciliation_worker"
_MOD_MAIN = _MOD_DIR / "main.tf"
_MOD_VARS = _MOD_DIR / "variables.tf"


def _var_default_int(vars_text: str, name: str) -> int:
    block = vars_text.split(f'variable "{name}"', 1)[1].split("\n}", 1)[0]
    m = re.search(r"default\s*=\s*(\d+)", block)
    assert m is not None, f"variable {name} has no integer default"
    return int(m.group(1))


def test_reconciler_runs_as_single_writer_deployment() -> None:
    mod_main = _MOD_MAIN.read_text(encoding="utf-8")
    assert 'resource "kubernetes_deployment" "reconciliation_worker"' in mod_main
    assert "kubernetes_cron_job" not in mod_main
    assert re.search(r"\breplicas\s*=\s*1\b", mod_main)
    # Never two reconcilers publishing snapshots during a rollout.
    assert re.search(r'strategy\s*\{\s*type\s*=\s*"Recreate"\s*\}', mod_main)


def test_reconciler_runs_loop_mode_with_ttl_margin() -> None:
    mod_main = _MOD_MAIN.read_text(encoding="utf-8")
    vars_text = _MOD_VARS.read_text(encoding="utf-8")
    assert "RECONCILIATION_SINGLE_SHOT" not in mod_main
    ttl = _var_default_int(vars_text, "ttl_seconds")
    poll = _var_default_int(vars_text, "poll_interval_seconds")
    assert ttl >= 2 * poll, f"TTL {ttl}s must be >= 2 x poll interval {poll}s"


def test_run_loop_refuses_ttl_shorter_than_two_ticks() -> None:
    reconciler = GroundTruthReconciler(
        redis_client=fakeredis.FakeRedis(), poll_interval=300, ttl=300
    )
    with pytest.raises(ValueError, match="2 x poll interval"):
        reconciler.run_loop()


def test_reconciler_managed_in_gke_terraform_state() -> None:
    """POAM-2026-096 / F-86: reconciliation-worker Deployment, Secret, and KSA live in Terraform state."""
    mod_main = _MOD_MAIN.read_text(encoding="utf-8")
    gke_main = (_REPO / "infra" / "targets" / "gcp-gke" / "main.tf").read_text(
        encoding="utf-8"
    )
    gke_iam = (_REPO / "infra" / "targets" / "gcp-gke" / "iam.tf").read_text(
        encoding="utf-8"
    )

    assert 'name      = "reconciliation-worker"' in mod_main
    assert 'name      = "reconciliation-worker-secrets"' in mod_main
    assert '"reconciler-kms-key" = var.reconciler_kms_key' in mod_main
    assert 'type = "Recreate"' in mod_main
    assert "replicas               = 1" in mod_main
    assert "var.ttl_seconds >= 2 * var.poll_interval_seconds" in mod_main
    assert re.search(r"\bread_only_root_filesystem\s*=\s*true\b", mod_main)
    assert 'module "reconciliation_worker"' in gke_main
    assert 'kubernetes_service_account.workload["reconciler"]' in gke_main
    assert re.search(r'\bksa_reconciler\s*=\s*"cage-reconciler-sa"', gke_iam)
    assert re.search(
        r"\breconciler\s*=\s*\{\s*name\s*=\s*local\.ksa_reconciler\b", gke_iam
    )
