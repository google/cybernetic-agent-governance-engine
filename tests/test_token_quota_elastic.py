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

"""
Unit tests for Elastic Task-Aware Quota Bursting & Agent Handover Relay Protocol.

Tests cover:
1. AgentHandoverManifest contract & serialization (RFC #652)
2. TokenQuotaProxy soft cap thresholds & status transitions
3. Elastic burst overdraft allowance and hard cap enforcement
4. request_completion_overdraft and session quota calculations
5. InferenceProxy header propagation & allow_burst trigger parsing
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.gateway.governance.contracts import AgentHandoverManifest
from src.gateway.governance.token_quota_proxy import (
    QuotaCheckResult,
    TokenQuotaProxy,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------


def _make_elastic_proxy(
    step_quota: int = 10,
    token_quota: int = 10_000,
    soft_cap_ratio: float = 0.85,
    burst_allowance_ratio: float = 0.15,
    safe_landing_reserve: int = 1500,
) -> tuple[TokenQuotaProxy, AsyncMock]:
    """Return a TokenQuotaProxy wired to an AsyncMock Redis client."""
    redis = AsyncMock()
    redis.script_load = AsyncMock(
        side_effect=["sha_check_xx", "sha_rollback_xx", "sha_reconcile_xx"]
    )
    proxy = TokenQuotaProxy(
        redis_client=redis,
        step_quota_max=step_quota,
        token_quota_max=token_quota,
        soft_cap_ratio=soft_cap_ratio,
        burst_allowance_ratio=burst_allowance_ratio,
        safe_landing_reserve=safe_landing_reserve,
        session_ttl=60,
    )
    return proxy, redis


# ---------------------------------------------------------------------------
# 1. AgentHandoverManifest Contract Tests
# ---------------------------------------------------------------------------


def test_agent_handover_manifest_serialization() -> None:
    """AgentHandoverManifest serializes correctly to JSON with clean state integrity."""
    manifest = AgentHandoverManifest(
        task_id="task-12345",
        agent_id="agent-claude-prime",
        status="HANDOVER_PENDING",
        repository_clean=True,
        syntax_valid=True,
        tests_passing=True,
        completed_milestones=("milestone-1-ast", "milestone-2-lua"),
        pending_actions=({"action": "deploy_canary", "stage": 3},),
        successor_instructions="Execute remaining integration tests and open PR.",
        total_tokens_spent=9500,
        burst_tokens_used=1200,
        efficiency_rating=0.94,
        created_at_utc="2026-11-04T00:00:00Z",
    )

    data = manifest.to_dict()
    serialized = json.dumps(data)
    loaded = json.loads(serialized)

    assert loaded["task_id"] == "task-12345"
    assert loaded["agent_id"] == "agent-claude-prime"
    assert loaded["status"] == "HANDOVER_PENDING"
    assert loaded["state_integrity"]["repository_clean"] is True
    assert loaded["state_integrity"]["syntax_valid"] is True
    assert loaded["state_integrity"]["tests_passing"] is True
    assert loaded["completed_milestones"] == ["milestone-1-ast", "milestone-2-lua"]
    assert loaded["pending_actions"] == [{"action": "deploy_canary", "stage": 3}]
    assert (
        loaded["successor_instructions"]
        == "Execute remaining integration tests and open PR."
    )
    assert loaded["tokenomics"]["total_tokens_spent"] == 9500
    assert loaded["tokenomics"]["burst_tokens_used"] == 1200
    assert loaded["tokenomics"]["efficiency_rating"] == 0.94


# ---------------------------------------------------------------------------
# 2. TokenQuotaProxy Elastic Ratios & Configuration
# ---------------------------------------------------------------------------


def test_token_quota_proxy_elastic_defaults() -> None:
    """TokenQuotaProxy defaults to 85% soft cap, 15% burst allowance, 1500 safe reserve."""
    proxy, _ = _make_elastic_proxy(token_quota=10_000)
    assert proxy.soft_cap_ratio == 0.85
    assert proxy.burst_allowance_ratio == 0.15
    assert proxy.safe_landing_reserve == 1500
    assert proxy.soft_cap_tokens == 8500
    assert proxy.burst_max_tokens == 11500


def test_token_quota_proxy_from_env_custom_ratios(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """from_env parses elastic quota environment variables."""
    monkeypatch.setenv("CAGE_TOKEN_QUOTA_MAX", "20000")
    monkeypatch.setenv("CAGE_QUOTA_SOFT_CAP_RATIO", "0.80")
    monkeypatch.setenv("CAGE_QUOTA_BURST_ALLOWANCE_RATIO", "0.20")
    monkeypatch.setenv("CAGE_QUOTA_SAFE_LANDING_RESERVE", "2000")

    redis = AsyncMock()
    proxy = TokenQuotaProxy.from_env(redis_client=redis)

    assert proxy.token_quota_max == 20000
    assert proxy.soft_cap_ratio == 0.80
    assert proxy.burst_allowance_ratio == 0.20
    assert proxy.safe_landing_reserve == 2000
    assert proxy.soft_cap_tokens == 16000
    assert proxy.burst_max_tokens == 24000


# ---------------------------------------------------------------------------
# 3. Quota Status Transitions & Elastic Overdraft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_and_increment_status_normal() -> None:
    """Within soft cap, quota_status is NORMAL and burst is available."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(return_value=["1", "2", "3000", "", "NORMAL"])

    result = await proxy.check_and_increment("agent-test", token_delta=1000)

    assert result.allowed is True
    assert result.quota_status == "NORMAL"
    assert result.accumulated_tokens == 3000
    assert result.tokens_remaining == 7000
    assert result.burst_available is True


@pytest.mark.asyncio
async def test_check_and_increment_status_soft_cap_reached() -> None:
    """Between soft cap and hard cap, status is SOFT_CAP_REACHED."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(return_value=["1", "5", "8800", "", "SOFT_CAP_REACHED"])

    result = await proxy.check_and_increment("agent-test", token_delta=500)

    assert result.allowed is True
    assert result.quota_status == "SOFT_CAP_REACHED"
    assert result.accumulated_tokens == 8800
    assert result.tokens_remaining == 1200
    assert result.burst_available is True


@pytest.mark.asyncio
async def test_check_and_increment_burst_active_when_allowed() -> None:
    """When allow_burst=True and tokens exceed limit up to burst_max, BURST_ACTIVE is granted."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(return_value=["1", "6", "10600", "", "BURST_ACTIVE"])

    result = await proxy.check_and_increment(
        "agent-test", token_delta=800, allow_burst=True
    )

    assert result.allowed is True
    assert result.quota_status == "BURST_ACTIVE"
    assert result.accumulated_tokens == 10600
    assert result.tokens_remaining == 900  # 11,500 burst_max - 10,600
    assert result.burst_available is True

    # Verify Lua script received allow_burst="1"
    call_args = redis.evalsha.call_args[0]
    # ARGV: [delta_steps, delta_tokens, ttl, step_max, soft_cap, burst_max, allow_burst]
    assert call_args[-1] == "1"


@pytest.mark.asyncio
async def test_check_and_increment_burst_rejected_when_not_allowed() -> None:
    """When allow_burst=False and tokens exceed token_quota_max, request is blocked as EXHAUSTED."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(
        return_value=["0", "5", "10000", "token_quota", "EXHAUSTED"]
    )

    result = await proxy.check_and_increment(
        "agent-test", token_delta=500, allow_burst=False
    )

    assert result.allowed is False
    assert result.quota_status == "EXHAUSTED"
    assert result.block_reason == "token_quota"
    assert result.tokens_remaining == 0
    # Burst buffer is still available to be requested with allow_burst=True
    assert result.burst_available is True


@pytest.mark.asyncio
async def test_check_and_increment_burst_rejected_exceeding_max_burst() -> None:
    """Even with allow_burst=True, requests exceeding burst_max_tokens fail-closed."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(
        return_value=["0", "7", "11600", "burst_quota_exceeded", "EXHAUSTED"]
    )

    result = await proxy.check_and_increment(
        "agent-test", token_delta=2000, allow_burst=True
    )

    assert result.allowed is False
    assert result.quota_status == "EXHAUSTED"
    assert result.block_reason == "burst_quota_exceeded"
    assert result.tokens_remaining == 0
    assert result.burst_available is False


# ---------------------------------------------------------------------------
# 4. request_completion_overdraft & get_session_quota
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_quota() -> None:
    """get_session_quota calculates remaining budget, soft cap and burst allowance."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.get = AsyncMock(side_effect=[b"4", b"6000"])

    session = await proxy.get_session_quota("agent-abc")

    assert session["agent_id"] == "agent-abc"
    assert session["step_count"] == 4
    assert session["accumulated_tokens"] == 6000
    assert session["quota_max_tokens"] == 10_000
    assert session["soft_cap_tokens"] == 8500
    assert session["burst_max_tokens"] == 11500
    assert session["tokens_remaining"] == 4000
    assert session["burst_tokens_remaining"] == 5500
    assert session["quota_status"] == "NORMAL"
    assert session["burst_available"] is True


@pytest.mark.asyncio
async def test_request_completion_overdraft_success() -> None:
    """request_completion_overdraft succeeds when estimated_delta fits within burst allowance."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(return_value=["1", "9", "10700", "", "BURST_ACTIVE"])

    overdraft = await proxy.request_completion_overdraft(
        "agent-abc", estimated_delta=1200
    )

    assert isinstance(overdraft, QuotaCheckResult)
    assert overdraft.allowed is True
    assert overdraft.quota_status == "BURST_ACTIVE"
    assert overdraft.accumulated_tokens == 10700


@pytest.mark.asyncio
async def test_request_completion_overdraft_rejected_excessive_delta() -> None:
    """request_completion_overdraft fails closed when requested delta exceeds burst allowance."""
    proxy, redis = _make_elastic_proxy(token_quota=10_000)
    redis.evalsha = AsyncMock(
        return_value=["0", "8", "12500", "burst_quota_exceeded", "EXHAUSTED"]
    )

    overdraft = await proxy.request_completion_overdraft(
        "agent-abc", estimated_delta=3000
    )

    assert isinstance(overdraft, QuotaCheckResult)
    assert overdraft.allowed is False
    assert overdraft.quota_status == "EXHAUSTED"
    assert overdraft.block_reason == "burst_quota_exceeded"


# ---------------------------------------------------------------------------
# 5. InferenceProxy Header Propagation & Parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inference_proxy_allow_burst_header_and_response_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """InferenceProxy parses X-Cage-Allow-Burst header and returns quota telemetry headers."""
    import src.gateway.server.inference_proxy as ip_mod

    mock_quota_result = QuotaCheckResult(
        allowed=True,
        agent_id="test-agent",
        step_count=8,
        accumulated_tokens=10500,
        step_quota_max=20,
        token_quota_max=10000,
        block_reason=None,
        session_ttl=60,
        quota_status="BURST_ACTIVE",
        burst_available=True,
        tokens_remaining=0,
    )

    mock_quota_proxy = MagicMock()
    mock_quota_proxy.check_and_increment = AsyncMock(return_value=mock_quota_result)

    monkeypatch.setattr(ip_mod, "_get_token_quota_proxy", lambda: mock_quota_proxy)
    monkeypatch.setattr(
        "src.gateway.server.workload_identity.extract_client_identity",
        lambda _scope: "test-agent.linkerd.cluster.local",
    )
    monkeypatch.setattr(ip_mod, "ac_keyword_scan", MagicMock(return_value=False))
    monkeypatch.setattr(ip_mod, "stamp_iso_control", MagicMock())
    monkeypatch.setattr(ip_mod, "scrub_pii", lambda x: x)
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "false")

    fake_vllm_resp = MagicMock(spec=httpx.Response)
    fake_vllm_resp.status_code = 200
    fake_vllm_resp.text = json.dumps(
        {"choices": [{"message": {"content": "Task completed."}}]}
    )
    fake_vllm_resp.json = MagicMock(
        return_value={"choices": [{"message": {"content": "Task completed."}}]}
    )

    fake_client = MagicMock(spec=httpx.AsyncClient)
    fake_client.is_closed = False
    fake_client.post = AsyncMock(return_value=fake_vllm_resp)
    monkeypatch.setattr(ip_mod, "_get_http_client", lambda: fake_client)
    monkeypatch.setattr(
        ip_mod.config_manager, "get", lambda k, d=None: "http://fake-vllm:8000/v1"
    )

    transport = httpx.ASGITransport(app=ip_mod.inference_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "test-model",
                "messages": [{"role": "user", "content": "Finish task"}],
            },
            headers={"X-Cage-Allow-Burst": "true"},
        )

        assert resp.status_code == 200
        # Verify check_and_increment was called with allow_burst=True
        mock_quota_proxy.check_and_increment.assert_awaited_once()
        _, kwargs = mock_quota_proxy.check_and_increment.call_args
        assert kwargs.get("allow_burst") is True

        # Verify response headers carry telemetry
        assert resp.headers.get("X-Cage-Quota-Status") == "BURST_ACTIVE"
        assert resp.headers.get("X-Cage-Tokens-Remaining") == "0"
