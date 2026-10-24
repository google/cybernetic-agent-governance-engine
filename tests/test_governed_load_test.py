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

"""Unit tests for the A2 fixed-replica committing load test and baseline tools."""

from __future__ import annotations

import datetime
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.check_locust_baseline import (
    _load_aggregated_p95,
    _load_row_p95,
    _parse_endpoint_thresholds,
)
from scripts.check_locust_baseline import (
    main as check_locust_baseline_main,
)
from tests.load.locustfile import (
    FAILURE_CATEGORY_CBF_EPOCH_CONTENDED,
    FAILURE_CATEGORY_MCP_404,
    FAILURE_CATEGORY_RATE_LIMIT_429,
    FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN,
    GovernedTradeUser,
    classify_load_failure,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: dict[str, Any] | str,
        *,
        elapsed_ms: float = 12.0,
    ) -> None:
        self.status_code = status_code
        self._json: dict[str, Any] | None
        if isinstance(payload, dict):
            self._json = payload
            self.text = json.dumps(payload)
        else:
            self._json = None
            self.text = payload
        self.content = self.text.encode("utf-8")
        self.elapsed = datetime.timedelta(milliseconds=elapsed_ms)
        self.marked_success = False
        self.failure_message: str | None = None

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def json(self) -> dict[str, Any]:
        if self._json is None:
            raise json.JSONDecodeError("Invalid JSON", self.text, 0)
        return self._json

    def success(self) -> None:
        self.marked_success = True

    def failure(self, message: str) -> None:
        self.failure_message = message


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.headers: dict[str, str] = {}
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return self._responses.pop(0)


def test_classify_load_failure_categories() -> None:
    assert (
        classify_load_failure(429, '{"error":"rate_limit_exceeded"}', "/tools/execute")
        == FAILURE_CATEGORY_RATE_LIMIT_429
    )
    assert (
        classify_load_failure(
            403,
            '{"verdict":"DENIED","reason":"CBF_EPOCH_CONTENDED: Fence epoch advanced"}',
            "/governance/validate-action",
        )
        == FAILURE_CATEGORY_CBF_EPOCH_CONTENDED
    )
    assert (
        classify_load_failure(
            200,
            "BLOCKED: Fence epoch mismatch: expected 4, got 5",
            "/tools/execute",
        )
        == FAILURE_CATEGORY_CBF_EPOCH_CONTENDED
    )
    assert (
        classify_load_failure(
            200,
            "ERROR: EvidenceChainUnavailableError: evidence chain unavailable",
            "/tools/execute",
        )
        == FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN
    )
    assert (
        classify_load_failure(
            200,
            "Evidence commit failed: evidence_id=123 Cannot guarantee durable commit — seal issuance blocked.",
            "/tools/execute",
        )
        == FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN
    )
    assert (
        classify_load_failure(
            200,
            "Evidence commit timeout after 5.0s for evidence_id=123. Cannot guarantee durable commit — seal issuance blocked.",
            "/tools/execute",
        )
        == FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN
    )
    assert (
        classify_load_failure(404, "Session not found", "/mcp/messages")
        == FAILURE_CATEGORY_MCP_404
    )
    assert (
        classify_load_failure(200, '{"status":"SUCCESS","output":"DRY_RUN: APPROVED"}')
        is None
    )


def test_governed_trade_user_assigns_distinct_principals_and_executes_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOAD_TEST_ENABLE_MCP", "true")

    r1 = _FakeResponse(200, {"verdict": "ALLOW"})
    r2 = _FakeResponse(
        200,
        {
            "status": "SUCCESS",
            "output": "DRY_RUN: APPROVED by OPA, Safety, and Consensus.",
        },
    )
    r3 = _FakeResponse(200, {"jsonrpc": "2.0", "id": 1, "result": {"status": "OPEN"}})

    user_a = GovernedTradeUser.__new__(GovernedTradeUser)
    user_a.client = _FakeClient([r1, r2, r3])  # type: ignore[assignment]
    user_a.on_start()

    user_b = GovernedTradeUser.__new__(GovernedTradeUser)
    user_b.client = _FakeClient([])  # type: ignore[assignment]
    user_b.on_start()

    assert user_a.principal_id != user_b.principal_id
    assert user_a.client.headers["x-cage-principal"] == user_a.principal_id
    assert "l5d-client-id" in user_a.client.headers

    user_a.governed_trade_flow()

    assert len(user_a.client.calls) == 3
    assert user_a.client.calls[0]["url"] == "/governance/validate-action"
    assert user_a.client.calls[0]["json"]["action"] == "execute_trade"
    # Who trades is bound by the gateway from the workload identity
    # (GHSA-w39v-5v7h-fxg9): neither request names a role or a trader.
    for call in user_a.client.calls[:2]:
        assert not {"trader_role", "trader_id"} & set(call["json"]["params"])
    assert user_a.client.calls[1]["url"] == "/tools/execute"
    assert user_a.client.calls[1]["json"]["tool_name"] == "execute_trade_action"
    assert user_a.client.calls[2]["url"] == "/mcp/"
    assert r1.marked_success is True
    assert r2.marked_success is True
    assert r3.marked_success is True


def test_governed_trade_user_categorizes_committing_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOAD_TEST_ENABLE_MCP", "true")

    r_validate = _FakeResponse(429, '{"error":"rate_limit_exceeded"}')
    r_execute = _FakeResponse(
        200,
        {
            "status": "SUCCESS",
            "output": "BLOCKED: CBF_EPOCH_CONTENDED (Fence epoch mismatch)",
        },
    )
    r_mcp = _FakeResponse(404, "Session not found")

    user = GovernedTradeUser.__new__(GovernedTradeUser)
    user.client = _FakeClient([r_validate, r_execute, r_mcp])  # type: ignore[assignment]
    user.on_start()
    user.governed_trade_flow()

    assert r_validate.failure_message is not None
    assert f"[{FAILURE_CATEGORY_RATE_LIMIT_429}]" in r_validate.failure_message
    assert r_execute.failure_message is not None
    assert f"[{FAILURE_CATEGORY_CBF_EPOCH_CONTENDED}]" in r_execute.failure_message
    assert r_mcp.failure_message is not None
    assert f"[{FAILURE_CATEGORY_MCP_404}]" in r_mcp.failure_message


def test_governed_trade_user_rejects_blocked_and_evidence_timeout_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOAD_TEST_ENABLE_MCP", "false")

    r_validate_1 = _FakeResponse(200, {"verdict": "ALLOW"})
    r_execute_blocked = _FakeResponse(
        200,
        {
            "status": "SUCCESS",
            "output": "BLOCKED: routing seal invalid, expired, or already consumed",
        },
    )
    r_validate_2 = _FakeResponse(200, {"verdict": "ALLOW"})
    r_execute_seal_err = _FakeResponse(
        200,
        {
            "status": "ERROR",
            "error": (
                "Evidence commit failed: evidence_id=abc Cannot guarantee durable "
                "commit — seal issuance blocked."
            ),
        },
    )

    user = GovernedTradeUser.__new__(GovernedTradeUser)
    user.client = _FakeClient(
        [r_validate_1, r_execute_blocked, r_validate_2, r_execute_seal_err]
    )  # type: ignore[assignment]
    user.on_start()

    user.governed_trade_flow()
    assert r_execute_blocked.marked_success is False
    assert r_execute_blocked.failure_message is not None
    assert "Tool execution error: BLOCKED:" in r_execute_blocked.failure_message

    user.governed_trade_flow()
    assert r_execute_seal_err.marked_success is False
    assert r_execute_seal_err.failure_message is not None
    assert (
        f"[{FAILURE_CATEGORY_SEAL_EVIDENCE_CHAIN}]"
        in r_execute_seal_err.failure_message
    )


def test_check_locust_baseline_per_endpoint_thresholds(tmp_path: Path) -> None:
    stats_csv = tmp_path / "locust_stats.csv"
    stats_csv.write_text(
        "Type,Name,Request Count,Failure Count,50%,95%,99%,Requests/s\n"
        "POST,POST /governance/validate-action,100,0,120,350,490,5.0\n"
        "POST,POST /tools/execute,100,0,280,920,1400,5.0\n"
        ",Aggregated,200,0,200,750,1200,10.0\n",
        encoding="utf-8",
    )

    assert _load_aggregated_p95(str(stats_csv)) == 750.0
    assert _load_row_p95(str(stats_csv), "POST /tools/execute") == 920.0

    thresholds = _parse_endpoint_thresholds(
        ["POST /governance/validate-action=500,POST /tools/execute=1000"]
    )
    assert thresholds == {
        "POST /governance/validate-action": 500.0,
        "POST /tools/execute": 1000.0,
    }

    rc_pass = check_locust_baseline_main(
        [
            "--stats-csv",
            str(stats_csv),
            "--p95-baseline-ms",
            "1000",
            "--endpoint-p95",
            "POST /governance/validate-action=400",
            "--endpoint-p95",
            "POST /tools/execute=1000",
        ]
    )
    assert rc_pass == 0

    rc_fail = check_locust_baseline_main(
        [
            "--stats-csv",
            str(stats_csv),
            "--p95-baseline-ms",
            "1000",
            "--endpoint-p95",
            "POST /tools/execute=800",
        ]
    )
    assert rc_fail == 1


def test_run_scaling_benchmark_script_syntax_and_summary(tmp_path: Path) -> None:
    script_path = REPO_ROOT / "scripts" / "run_scaling_benchmark.sh"
    syntax_res = subprocess.run(
        ["bash", "-n", str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax_res.returncode == 0, syntax_res.stderr

    stats_csv = tmp_path / "stats.csv"
    stats_csv.write_text(
        "Type,Name,Request Count,Failure Count,50%,95%,99%,Requests/s\n"
        "POST,POST /governance/validate-action,50,0,140,360,510,4.2\n"
        "POST,POST /tools/execute,50,2,300,880,1300,4.0\n"
        ",Aggregated,100,2,220,700,1150,8.2\n",
        encoding="utf-8",
    )
    failures_csv = tmp_path / "failures.csv"
    failures_csv.write_text(
        "Method,Name,Error,Occurrences\n"
        "POST,POST /tools/execute,[cbf_epoch_contended] Fence epoch mismatch,2\n"
        "POST,POST /mcp/,[mcp_session_404] Session not found,3\n",
        encoding="utf-8",
    )
    pre_prom = tmp_path / "pre.prom"
    pre_prom.write_text(
        'cage_kms_rpc_total{op="asymmetric_sign"} 10\n'
        'cage_kms_rpc_total{op="get_crypto_key_version"} 20\n'
        "cage_evidence_append_conflicts_total 1\n"
        "cage_evidence_commit_duration_seconds_count 10\n"
        'mcp_rate_limit_hits_total{client_ip="10.0.0.1"} 2\n'
        'cage_event_loop_lag_seconds_bucket{le="0.01"} 10\n'
        'cage_event_loop_lag_seconds_bucket{le="0.1"} 10\n'
        'cage_event_loop_lag_seconds_bucket{le="+Inf"} 10\n',
        encoding="utf-8",
    )
    post_prom = tmp_path / "post.prom"
    post_prom.write_text(
        'cage_kms_rpc_total{op="asymmetric_sign"} 60\n'
        'cage_kms_rpc_total{op="get_crypto_key_version"} 120\n'
        "cage_evidence_append_conflicts_total 11\n"
        "cage_evidence_commit_duration_seconds_count 60\n"
        'mcp_rate_limit_hits_total{client_ip="10.0.0.1"} 7\n'
        'cage_event_loop_lag_seconds_bucket{le="0.01"} 20\n'
        'cage_event_loop_lag_seconds_bucket{le="0.1"} 110\n'
        'cage_event_loop_lag_seconds_bucket{le="+Inf"} 110\n',
        encoding="utf-8",
    )

    cmd = (
        f"source {script_path} && "
        f"summarize_replica_run 2 {stats_csv} {failures_csv} {pre_prom} {post_prom}"
    )
    res = subprocess.run(
        ["bash", "-c", cmd],
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, res.stderr
    row = res.stdout.strip()
    # Expected:
    # Replicas=2, RPS=8.20, validate=140/360/510, execute=300/880/1300,
    # KMS delta=150 over 50 seals -> 3.00, conflicts delta=10 over 50 seals -> 0.200,
    # 429s=5, CBF=2, Seal=0, MCP=3
    assert "| 2 | 8.20 | 140/360/510 | 300/880/1300 |" in row
    assert "| 3.00 | 0.200 | 5 | 2 | 0 | 3 |" in row
