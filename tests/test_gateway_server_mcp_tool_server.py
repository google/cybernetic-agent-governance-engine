"""
Unit tests for src/gateway/server/mcp_tool_server.py.

Tests the rate-limiting logic (_check_rate_limit) and module-level constants
without spinning up FastAPI, MCP, NeMo, OPA, or Redis.

Heavy dependencies (FastMCP, governance singletons, etc.) are bypassed by
patching at the sys.modules level before import.
"""

from __future__ import annotations

import asyncio
import collections
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


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
        "src.gateway.governance.nemo.manager": MagicMock(
            initialize_rails=MagicMock(return_value=MagicMock()),
            validate_with_nemo=AsyncMock(return_value=(True, "SAFE", True)),
        ),
        "src.gateway.governance.schemas.thresholds": MagicMock(
            load_and_validate_thresholds=MagicMock()
        ),
        "src.gateway.governance.singletons": MagicMock(
            opa_client=MagicMock(close=AsyncMock()),
            symbolic_governor=MagicMock(
                verify=AsyncMock(return_value={"violations": []}),
                safety_filter=MagicMock(update_state=AsyncMock(), rollback_state=AsyncMock()),
            ),
        ),
        "src.gateway.observability.mcp_tracing": MagicMock(patch_mcp_tools=MagicMock()),
        "src.gateway.server.governance_middleware": MagicMock(
            enforce_governance=AsyncMock(return_value=MagicMock()),
            enforce_routing_seal=MagicMock(),
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
        "src.gateway.governance.consensus": MagicMock(
            _background_audit_worker=AsyncMock()
        ),
        "src.governed_financial_advisor.utils.telemetry": MagicMock(
            configure_telemetry=MagicMock()
        ),
    }


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
            r2 = await mod._check_rate_limit("2.2.2.2")  # first for different IP → allowed
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
        import sys
        import os
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
