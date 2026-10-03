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

"""Hermetic smoke tests for the §6 benchmark scripts.

``scripts/measure_reconciliation_metrics.py`` is exercised end to end over
fakeredis with the development-only software signer, so the script cannot
silently drift away from the reconciler/CBF modules it measures again. The
numbers it produces here are meaningless; only the wiring is asserted.
``scripts/measure_paper_metrics.py --unmocked`` is checked for its fail-closed
preflight and its table labelling.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import measure_paper_metrics as paper  # noqa: E402
import measure_reconciliation_metrics as recon  # noqa: E402

from src.cage_finance.invariants import CashBarrier  # noqa: E402
from src.gateway.governance.reconciliation import trust  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def redis_pair(monkeypatch: pytest.MonkeyPatch) -> Any:
    """One fakeredis server seen by the script (sync) and the CBF (sync + async)."""
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.delenv(trust.RECONCILER_KMS_KEY_ENV, raising=False)
    monkeypatch.delenv(trust.GATEWAY_KMS_KEY_ENV, raising=False)
    server = fakeredis.FakeServer()
    sync_redis = fakeredis.FakeRedis(server=server, decode_responses=True)
    async_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    redis_mod = MagicMock()
    redis_mod.get_raw_client = MagicMock(return_value=async_redis)
    redis_mod.get = async_redis.get
    with (
        patch("src.gateway.governance.safety.cbf_engine.redis_client", redis_mod),
        patch("src.gateway.governance.safety.cbf_engine.sync_redis_client", sync_redis),
    ):
        yield sync_redis


def test_no_signer_skips_instead_of_fabricating() -> None:
    identity, why = recon.resolve_signing_identity(allow_software=False)
    assert identity is None
    assert trust.RECONCILER_KMS_KEY_ENV in why


def test_software_signer_is_refused_in_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(trust.RECONCILER_KMS_KEY_ENV, raising=False)
    monkeypatch.setenv("CAGE_ENV", "production")
    with pytest.raises(RuntimeError, match="development-only"):
        recon.resolve_signing_identity(allow_software=True)


def test_preflight_refuses_a_redis_holding_cbf_state(redis_pair: Any) -> None:
    assert recon.preflight_redis(redis_pair, force=False) is None
    redis_pair.set(CashBarrier.state_key, "1.0")
    assert "ephemeral" in (recon.preflight_redis(redis_pair, force=False) or "")
    assert recon.preflight_redis(redis_pair, force=True) is None


@pytest.mark.asyncio
async def test_full_run_with_software_signer(redis_pair: Any) -> None:
    identity, _ = recon.resolve_signing_identity(allow_software=True)
    assert identity is not None and not identity.evidence_grade

    results = await recon.collect(redis_pair, identity, write_runs=3, read_runs=3)

    write = results["write_path"]
    assert write["iterations_succeeded"] == 3, write["failures"]
    assert write["signer"] == recon.SIGNER_SOFTWARE
    assert results["read_overhead"]["reconciled_ms"] is not None

    safety = results["safety_violation"]
    assert safety["a_self_reported"]["admitted"]
    assert safety["b_reconciler_vs_inflated_state"]["discrepancy_detected"]
    assert not safety["b_reconciler_vs_inflated_state"]["published"]
    assert safety["c_reconciled_after_inflation"]["balance_source"] == "reconciled"
    assert safety["c_reconciled_after_inflation"]["refused"]
    assert safety["poam_023_validated"]
    assert "Table 3" in recon.render_text(results)


@pytest.mark.asyncio
async def test_run_without_signer_reports_skips(redis_pair: Any) -> None:
    results = await recon.collect(redis_pair, None, write_runs=2, read_runs=2)
    assert "skipped" in results["write_path"]
    assert results["read_overhead"]["reconciled_ms"] is None
    assert "skipped" in results["safety_violation"]["c_reconciled_after_inflation"]
    assert not results["safety_violation"]["poam_023_validated"]
    assert "SKIPPED" in recon.render_text(results)


def test_unmocked_mode_fails_closed_without_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("REDIS_URL", "OPA_URL", "VLLM_REASONING_API_BASE", "VLLM_FAST_API_BASE"):
        monkeypatch.delenv(name, raising=False)
    for name in [k for k in os.environ if k.startswith("CONSENSUS_")]:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="REDIS_URL, OPA_URL, CONSENSUS_"):
        paper._require_unmocked_env()


def test_unmocked_flag_and_table_labels() -> None:
    assert paper._parse_args(["--unmocked"]).unmocked
    assert not paper._parse_args([]).unmocked
    assert "Table 2b" in paper._latency_table_title(True)
    assert "over-the-wire" in paper._latency_table_title(True)
    assert "compute-only" in paper._latency_table_title(False)
