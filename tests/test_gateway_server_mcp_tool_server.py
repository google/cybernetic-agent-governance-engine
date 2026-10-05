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
Unit tests for src.cage_finance.tools.tool_provider.py.

Tests the rate-limiting logic (_check_rate_limit) and module-level constants
without spinning up FastAPI, MCP, NeMo, OPA, or Redis.

Heavy dependencies (FastMCP, NeMo, tracing, etc.) are bypassed by patching at
the sys.modules level before import. The governor is read from
``app.state.governor``, so tests install a mock governor there.
"""

from __future__ import annotations

import asyncio
import collections
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Stub patches — minimum surface to allow import
# ---------------------------------------------------------------------------


def _mcp_import_stubs():
    """Return sys.modules patches that make the mcp_tool_server importable."""
    mock_fastmcp = MagicMock()
    mock_fastmcp.FastMCP.return_value = MagicMock(
        _tool_manager=MagicMock(
            call_tool=AsyncMock(),
            list_tools=MagicMock(return_value=[]),
        ),
        tool=MagicMock(return_value=lambda f: f),
        sse_app=MagicMock(return_value=MagicMock()),
    )

    return {
        "mcp.server.fastmcp": mock_fastmcp,
        "mcp.server.transport_security": MagicMock(),
        "src.gateway.core.tools": MagicMock(),
        "src.integrations.nemo.manager": MagicMock(
            initialize_rails=MagicMock(return_value=MagicMock()),
            validate_with_nemo=AsyncMock(return_value=(True, "SAFE", True)),
        ),
        "src.gateway.governance.schemas.thresholds": MagicMock(
            load_and_validate_thresholds=MagicMock()
        ),
        "src.gateway.observability.mcp_tracing": MagicMock(patch_mcp_tools=MagicMock()),
        "src.gateway.server.governance_middleware": MagicMock(
            enforce_governance=AsyncMock(return_value=MagicMock()),
        ),
        "src.gateway.tracing_setup": MagicMock(setup_tracing=MagicMock()),
        "src.governed_financial_advisor.infrastructure.config_manager": MagicMock(
            config_manager=MagicMock(get=MagicMock(return_value="http://vllm:8000/v1"))
        ),
        "src.governed_financial_advisor.tools.market_data_tool": MagicMock(
            get_market_data=MagicMock(return_value="OPEN: AAPL at $150")
        ),
        "opentelemetry.instrumentation.fastapi": MagicMock(),
        "src.gateway.governance.routing_seal": MagicMock(
            verify_seal=MagicMock(),
            SymbolicGovernorViolation=Exception,
        ),
        "src.gateway.infrastructure.redis_client": MagicMock(
            redis_client=MagicMock(set=AsyncMock())
        ),
        "src.cage_finance.consensus.consensus": MagicMock(
            _background_audit_worker=AsyncMock()
        ),
        "src.governed_financial_advisor.utils.telemetry": MagicMock(
            configure_telemetry=MagicMock()
        ),
    }


def _mock_governor(
    *, verify_result: dict | None = None, opa_decision: str = "ALLOW"
) -> MagicMock:
    """A ``SymbolicGovernor``-shaped mock for ``app.state.governor``."""
    from src.gateway.governance.governor.governor import SymbolicGovernor

    governor = MagicMock(spec=SymbolicGovernor)
    governor.verify = AsyncMock(return_value=verify_result or {"violations": []})
    governor.components = MagicMock()
    governor.components.opa.evaluate_policy = AsyncMock(return_value=opa_decision)
    return governor


# ---------------------------------------------------------------------------
# Tests: _check_rate_limit (pure async logic — no app server required)
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestCheckRateLimit:
    """Tests for the sliding-window rate limiter."""

    @pytest.mark.asyncio
    async def test_first_call_always_allowed(self):
        """First call from a new IP address is always allowed."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod._rate_limit_buckets = {}

            result = await mod._check_rate_limit("192.168.1.1")

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_within_limit_are_allowed(self):
        """Calls within the configured window+max are all allowed."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod._rate_limit_buckets = {}
            # Set low limit for test
            original_max = mod._RATE_LIMIT_MAX_CALLS
            mod._RATE_LIMIT_MAX_CALLS = 5

            results = []
            for _ in range(5):
                r = await mod._check_rate_limit("10.0.0.1")
                results.append(r)

            mod._RATE_LIMIT_MAX_CALLS = original_max

        assert all(results), f"Expected all True, got: {results}"

    @pytest.mark.asyncio
    async def test_call_exceeding_limit_is_rejected(self):
        """The (max+1)-th call within the window is rejected."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod._rate_limit_buckets = {}
            original_max = mod._RATE_LIMIT_MAX_CALLS
            mod._RATE_LIMIT_MAX_CALLS = 3

            for _ in range(3):
                await mod._check_rate_limit("10.0.0.2")

            over_limit = await mod._check_rate_limit("10.0.0.2")
            mod._RATE_LIMIT_MAX_CALLS = original_max

        assert over_limit is False

    @pytest.mark.asyncio
    async def test_different_ips_are_isolated(self):
        """Rate limit buckets are per-IP — different clients don't share quotas."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod._rate_limit_buckets = {}
            original_max = mod._RATE_LIMIT_MAX_CALLS
            mod._RATE_LIMIT_MAX_CALLS = 1

            r1 = await mod._check_rate_limit("1.1.1.1")  # first for this IP → allowed
            r2 = await mod._check_rate_limit(
                "2.2.2.2"
            )  # first for different IP → allowed
            r3 = await mod._check_rate_limit("1.1.1.1")  # second for 1.1.1.1 → rejected

            mod._RATE_LIMIT_MAX_CALLS = original_max

        assert r1 is True
        assert r2 is True
        assert r3 is False

    @pytest.mark.asyncio
    async def test_expired_timestamps_evicted(self):
        """Old timestamps outside the window are evicted, freeing quota."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod._rate_limit_buckets = {}
            original_max = mod._RATE_LIMIT_MAX_CALLS
            original_window = mod._RATE_LIMIT_WINDOW_SECONDS

            mod._RATE_LIMIT_MAX_CALLS = 1
            mod._RATE_LIMIT_WINDOW_SECONDS = 1

            ip = "3.3.3.3"
            # Manually plant an old timestamp that is already expired
            old_ts = time.monotonic() - 10  # 10s ago, well outside a 1s window
            mod._rate_limit_buckets[ip] = collections.deque([old_ts])

            result = await mod._check_rate_limit(ip)

            mod._RATE_LIMIT_MAX_CALLS = original_max
            mod._RATE_LIMIT_WINDOW_SECONDS = original_window

        assert result is True  # old entry evicted, slot is free


# ---------------------------------------------------------------------------
# Tests: module-level constants
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestModuleConstants:
    """Tests that rate-limit env-var overrides are respected."""

    def test_default_rate_limit_max_calls(self):
        """Default MCP_RATE_LIMIT_MAX_CALLS is 60."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            # Test the default (no env override)
            assert mod._RATE_LIMIT_MAX_CALLS == 60

    def test_env_override_rate_limit_max_calls(self):
        """MCP_RATE_LIMIT_MAX_CALLS env var overrides the default."""
        import os
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            with patch.dict(os.environ, {"MCP_RATE_LIMIT_MAX_CALLS": "120"}):
                sys.modules.pop("src.gateway.server.mcp_tool_server", None)
                import src.gateway.server.mcp_tool_server as mod

                assert mod._RATE_LIMIT_MAX_CALLS == 120

    def test_default_rate_limit_window(self):
        """Default MCP_RATE_LIMIT_WINDOW_SECONDS is 60."""
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            assert mod._RATE_LIMIT_WINDOW_SECONDS == 60


@pytest.mark.local
class TestMCPToolServerFunctions:
    """Tests for MCP tools defined in mcp_tool_server.py."""

    @pytest.mark.asyncio
    async def test_simulate_governance_check(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor()
            res = await mod.simulate_governance_check("buy", {"amount": 100})
            assert res["verdict"] == "ALLOW"
            assert "status" not in res
            assert res["message"] == "No violations detected."

    @pytest.mark.asyncio
    async def test_simulate_governance_check_reports_rejection(self):
        """verify() returns Violation objects; the tool must serialize, not crash."""
        import json
        import sys

        from src.gateway.governance.contracts import Violation, ViolationKind

        stubs = _mcp_import_stubs()
        refusal = Violation(
            tier="cbf",
            code="CBF_BARRIER_VIOLATED",
            message="UNSAFE: bankruptcy",
            kind=ViolationKind.HARD,
        )
        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor(
                verify_result={"violations": [refusal]}
            )

            res = await mod.simulate_governance_check("execute_trade", {"amount": 100})
            # verify() reported no classified decision: fail closed to DENY.
            assert res["verdict"] == "DENY"
            assert res["message"] == "[CBF_BARRIER_VIOLATED] UNSAFE: bankruptcy"
            assert res["violations"][0]["kind"] == "hard"
            json.dumps(res)  # MCP responses must be JSON-serializable

    @pytest.mark.asyncio
    async def test_simulate_governance_check_reports_classified_verdict(self):
        """With violations, the verdict is verify()'s classified decision."""
        import sys

        from src.gateway.governance.contracts import Violation, ViolationKind

        hitl = Violation(
            tier="opa",
            code="OPA_MANUAL_REVIEW",
            message="needs review",
            kind=ViolationKind.HITL,
        )
        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor(
                verify_result={"violations": [hitl], "decision": "REQUIRE_APPROVAL"}
            )
            res = await mod.simulate_governance_check("execute_trade", {"amount": 100})
            assert res["verdict"] == "REQUIRE_APPROVAL"

    @pytest.mark.asyncio
    async def test_evaluate_policy_internal_allow(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor(opa_decision="ALLOW")

            res = await mod._evaluate_policy_internal("execute_trade", 500)
            assert "APPROVED" in res

    @pytest.mark.asyncio
    async def test_evaluate_policy_internal_manual_review(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor(opa_decision="MANUAL_REVIEW")

            res = await mod._evaluate_policy_internal("execute_trade", 500)
            assert "MANUAL_REVIEW" in res

    @pytest.mark.asyncio
    async def test_evaluate_policy_internal_denied(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.governor = _mock_governor(opa_decision="DENY")

            res = await mod._evaluate_policy_internal("execute_trade", 500)
            assert "DENIED" in res

    @pytest.mark.asyncio
    async def test_trigger_safety_intervention(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            res = await mod.trigger_safety_intervention("Test intervention")
            assert "INTERVENTION_ACK" in res

    @pytest.mark.asyncio
    async def test_check_market_status(self):
        import sys

        # check_market_status was moved to cage_finance plugin as a tool registration
        # This test now validates the market data stub directly
        from src.governed_financial_advisor.tools.market_data_tool import (
            get_market_data,
        )

        res = get_market_data("AAPL")
        assert "AAPL" in res

    @pytest.mark.asyncio
    async def test_verify_content_safety(self):
        import sys

        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            mod.app.state.nemo_rails = MagicMock()
            res = await mod.verify_content_safety("Hello safe world")
            assert res == "SAFE"


# ---------------------------------------------------------------------------
# Tests: _activate_domain — OPA package/rule handshake (fail-closed)
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestActivateDomainOpaHandshake:
    """Startup refuses to install a domain whose OPA policy is not loaded."""

    def _run(self, verify):
        """Run _activate_domain; return (governor, tool_provider, app, result-or-exception)."""
        import sys

        from src.gateway.governance.contracts import DomainConfig, PluginContribution

        config = DomainConfig(
            ftra_registry_path=MagicMock(),
            opa_package="trade.governance",
            opa_required_rules=("allow",),
        )
        tool_provider = MagicMock()
        governor = _mock_governor()
        governor.components.opa.verify_domain_policy = verify
        governor.components.contributions = (
            PluginContribution(domain="finance", tool_provider=tool_provider),
        )
        governor.registered_tier_names = MagicMock(return_value=["finance"])
        with patch.dict("sys.modules", _mcp_import_stubs()):
            sys.modules.pop("src.gateway.server.mcp_tool_server", None)
            import src.gateway.server.mcp_tool_server as mod

            with (
                patch(
                    "src.gateway.governance.governor.bootstrap.bootstrap_governor",
                    return_value=governor,
                ),
                patch(
                    "src.gateway.governance.plugin_loader.active_domain_config",
                    return_value=config,
                ),
            ):
                try:
                    outcome = asyncio.run(mod._activate_domain())
                except Exception as exc:  # noqa: BLE001 — returned for assertion
                    outcome = exc
            return governor, tool_provider, mod, outcome

    def test_opa_mismatch_aborts_startup_before_install(self):
        from src.gateway.core.policy import OPAPolicyMismatchError

        verify = AsyncMock(
            side_effect=OPAPolicyMismatchError("OPA has no module declaring package")
        )
        _governor, tool_provider, mod, outcome = self._run(verify)
        assert isinstance(outcome, OPAPolicyMismatchError)
        tool_provider.register_tools.assert_not_called()
        assert getattr(mod.app.state, "governor", None) is None

    def test_verified_domain_is_installed_with_declared_package(self):
        verify = AsyncMock(return_value=None)
        governor, tool_provider, mod, outcome = self._run(verify)
        verify.assert_awaited_once_with("trade.governance", ("allow",))
        tool_provider.register_tools.assert_called_once_with(mod.mcp, governor)
        assert outcome is governor
        assert mod.app.state.governor is governor
