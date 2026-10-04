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
cycle. These tests pin the invariant on both the manifest and the daemon.
"""

from __future__ import annotations

from pathlib import Path

import fakeredis
import pytest
import yaml

from src.gateway.governance.reconciliation.daemon import GroundTruthReconciler

pytestmark = [pytest.mark.unit, pytest.mark.local]

_MANIFEST = (
    Path(__file__).resolve().parent.parent
    / "deployment"
    / "k8s"
    / "reconciliation-worker.yaml"
)


def _worker() -> dict:
    docs = [d for d in yaml.safe_load_all(_MANIFEST.read_text()) if d]
    (worker,) = [
        d for d in docs if d["metadata"]["name"] == "reconciliation-worker"
    ]
    return worker


def _env(worker: dict) -> dict[str, str]:
    (container,) = worker["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e.get("value") for e in container["env"]}


def test_reconciler_runs_as_single_writer_deployment() -> None:
    worker = _worker()
    assert worker["kind"] == "Deployment"
    assert worker["spec"]["replicas"] == 1
    # Never two reconcilers publishing snapshots during a rollout.
    assert worker["spec"]["strategy"]["type"] == "Recreate"


def test_reconciler_runs_loop_mode_with_ttl_margin() -> None:
    env = _env(_worker())
    assert env.get("RECONCILIATION_SINGLE_SHOT") in (None, "", "false")
    ttl = int(env["RECONCILIATION_TTL_SECONDS"])
    poll = int(env["RECONCILIATION_POLL_INTERVAL_SECONDS"])
    assert ttl >= 2 * poll, f"TTL {ttl}s must be >= 2 x poll interval {poll}s"


def test_run_loop_refuses_ttl_shorter_than_two_ticks() -> None:
    reconciler = GroundTruthReconciler(
        redis_client=fakeredis.FakeRedis(), poll_interval=300, ttl=300
    )
    with pytest.raises(ValueError, match="2 x poll interval"):
        reconciler.run_loop()
