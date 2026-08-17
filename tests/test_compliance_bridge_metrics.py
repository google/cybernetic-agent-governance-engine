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
tests/test_compliance_bridge_metrics.py
========================================
Dedicated unit tests for src/compliance_bridge/metrics.py.

Gap 10: metrics.py has no dedicated test file. This file tests metric
calculation correctness, cache behavior, grace period logic, and the
public get_compliance_metrics() API without hitting live Langfuse.

All external dependencies (Langfuse SDK, httpx) are mocked.

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal stub for langfuse / cachetools so the module imports cleanly
# ---------------------------------------------------------------------------


def _ensure_stubs() -> None:
    """Pre-install minimal stubs for optional heavy imports."""
    if "cachetools" not in sys.modules:
        cachetools_stub = MagicMock()

        class _TTLCache(dict):
            def __init__(self, maxsize=128, ttl=300):
                super().__init__()
                self._maxsize = maxsize
                self._ttl = ttl

        cachetools_stub.TTLCache = _TTLCache
        sys.modules["cachetools"] = cachetools_stub

    if "langfuse" not in sys.modules:
        langfuse_stub = MagicMock()
        sys.modules["langfuse"] = langfuse_stub
        sys.modules["langfuse.api"] = MagicMock()

    if "httpx" not in sys.modules:
        httpx_stub = MagicMock()
        sys.modules["httpx"] = httpx_stub


_ensure_stubs()


# ---------------------------------------------------------------------------
# Helper: build a fake trace object
# ---------------------------------------------------------------------------


def _make_trace(
    timestamp: datetime,
    outcome: str = "PASSED",
) -> MagicMock:
    """Return a minimal fake Langfuse trace with the given metadata."""
    trace = MagicMock()
    trace.timestamp = timestamp
    trace.metadata = {"iso_42001_outcome": outcome}
    return trace


def _make_traces_response(traces: list) -> MagicMock:
    """Wrap a list of traces in a mock Langfuse list-response object."""
    resp = MagicMock()
    resp.data = traces
    return resp


# ---------------------------------------------------------------------------
# Tests: _get_grace_status() and _parse_deployment_start()
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGraceStatus:
    """Tests for deployment cold-start grace period logic."""

    def test_grace_active_within_window(self) -> None:
        """Grace must be active when deployment is recent (within STARTUP_GRACE_HOURS)."""
        # Patch DEPLOYMENT_START to now so grace is definitely active
        now = datetime.now(tz=timezone.utc)

        with patch.dict("os.environ", {"STARTUP_GRACE_HOURS": "6"}):
            # Re-import after patching to exercise the function
            import importlib

            if "src.compliance_bridge.metrics" in sys.modules:
                del sys.modules["src.compliance_bridge.metrics"]

            # Patch the module-level _DEPLOYMENT_START to now
            import src.compliance_bridge.metrics as metrics_mod
            from src.compliance_bridge.metrics import _get_grace_status

            original_start = metrics_mod._DEPLOYMENT_START
            metrics_mod._DEPLOYMENT_START = now
            try:
                status = _get_grace_status()
                assert status["active"] is True, (
                    "Grace must be active when deployment just started"
                )
                assert status["remaining_hours"] > 0, (
                    "remaining_hours must be > 0 within grace window"
                )
            finally:
                metrics_mod._DEPLOYMENT_START = original_start

    def test_grace_inactive_after_window(self) -> None:
        """Grace must be inactive when deployment is old (past STARTUP_GRACE_HOURS)."""
        from datetime import timedelta

        old_start = datetime.now(tz=timezone.utc) - timedelta(hours=48)

        import src.compliance_bridge.metrics as metrics_mod

        original_start = metrics_mod._DEPLOYMENT_START
        original_grace = metrics_mod._STARTUP_GRACE_HOURS
        metrics_mod._DEPLOYMENT_START = old_start
        metrics_mod._STARTUP_GRACE_HOURS = 6
        try:
            status = metrics_mod._get_grace_status()
            assert status["active"] is False, (
                "Grace must be inactive after 48h when grace window is 6h"
            )
            assert status["remaining_hours"] == 0.0, (
                "remaining_hours must be 0 when grace expired"
            )
        finally:
            metrics_mod._DEPLOYMENT_START = original_start
            metrics_mod._STARTUP_GRACE_HOURS = original_grace

    def test_parse_deployment_start_returns_now_when_unset(self) -> None:
        """_parse_deployment_start() must return a recent datetime when env var is unset."""
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("DEPLOYMENT_START_UTC", None)

            from src.compliance_bridge.metrics import _parse_deployment_start

            result = _parse_deployment_start()
            assert isinstance(result, datetime), (
                "_parse_deployment_start must return a datetime"
            )
            age_seconds = abs((datetime.now(tz=timezone.utc) - result).total_seconds())
            assert age_seconds < 5, (
                "Fallback deployment start must be close to now (within 5s)"
            )

    def test_parse_deployment_start_parses_z_suffix(self) -> None:
        """_parse_deployment_start() must handle ISO 8601 with Z suffix."""
        with patch.dict("os.environ", {"DEPLOYMENT_START_UTC": "2026-01-15T08:00:00Z"}):
            from src.compliance_bridge.metrics import _parse_deployment_start

            result = _parse_deployment_start()
            assert isinstance(result, datetime), "Must return a datetime"
            assert result.tzinfo is not None, "Must return timezone-aware datetime"
            assert result.year == 2026, f"Expected year 2026, got {result.year}"


# ---------------------------------------------------------------------------
# Tests: _fetch_from_langfuse_sync() — metric calculation correctness
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestFetchFromLangfuseSync:
    """Tests for _fetch_from_langfuse_sync() metric calculation correctness."""

    def _run_fetch(
        self,
        traces: list,
        control_id: str = "A.5.2",
        window_hours: int = 24,
    ):
        """Run _fetch_from_langfuse_sync with mocked Langfuse client."""
        from src.compliance_bridge.metrics import _fetch_from_langfuse_sync

        mock_langfuse_api = MagicMock()
        mock_langfuse_api.trace.list.return_value = _make_traces_response(traces)

        with patch(
            "src.compliance_bridge.metrics._make_app_langfuse",
            return_value=mock_langfuse_api,
        ):
            return _fetch_from_langfuse_sync(control_id, window_hours)

    def test_safety_rate_is_none_when_no_traces(self) -> None:
        """safety_rate must be None when no traces exist (avoids false 1.0 score)."""
        result = self._run_fetch(traces=[])
        assert result.safety_rate is None, (
            "safety_rate must be None when total_traces=0 (M-10 requirement)"
        )

    def test_total_traces_count_is_correct(self) -> None:
        """total_traces must equal the number of traces returned by Langfuse."""
        now = datetime.now(tz=timezone.utc)
        traces = [
            _make_trace(now, "PASSED"),
            _make_trace(now, "PASSED"),
            _make_trace(now, "BLOCKED"),
        ]
        result = self._run_fetch(traces=traces)
        assert result.total_traces == 3, (
            f"Expected total_traces=3, got {result.total_traces}"
        )

    def test_passed_traces_count_is_correct(self) -> None:
        """passed_traces must count only traces with outcome=PASSED."""
        now = datetime.now(tz=timezone.utc)
        traces = [
            _make_trace(now, "PASSED"),
            _make_trace(now, "PASSED"),
            _make_trace(now, "BLOCKED"),
        ]
        result = self._run_fetch(traces=traces)
        assert result.passed_traces == 2, (
            f"Expected passed_traces=2, got {result.passed_traces}"
        )

    def test_blocked_traces_count_is_correct(self) -> None:
        """blocked_traces must be total_traces - passed_traces."""
        now = datetime.now(tz=timezone.utc)
        traces = [
            _make_trace(now, "PASSED"),
            _make_trace(now, "BLOCKED"),
            _make_trace(now, "BLOCKED"),
        ]
        result = self._run_fetch(traces=traces)
        assert result.blocked_traces == 2, (
            f"Expected blocked_traces=2, got {result.blocked_traces}"
        )
        assert result.blocked_traces == result.total_traces - result.passed_traces

    def test_safety_rate_calculation_correct(self) -> None:
        """safety_rate must equal passed_traces / total_traces."""
        now = datetime.now(tz=timezone.utc)
        traces = [
            _make_trace(now, "PASSED"),
            _make_trace(now, "PASSED"),
            _make_trace(now, "PASSED"),
            _make_trace(now, "BLOCKED"),
        ]
        result = self._run_fetch(traces=traces)
        expected_rate = 3 / 4  # 0.75
        assert result.safety_rate is not None, (
            "safety_rate must not be None with traces"
        )
        assert abs(result.safety_rate - expected_rate) < 0.001, (
            f"Expected safety_rate≈0.75, got {result.safety_rate}"
        )

    def test_safety_rate_is_rounded_to_4_decimal_places(self) -> None:
        """safety_rate must be rounded to 4 decimal places."""
        now = datetime.now(tz=timezone.utc)
        # 2/3 = 0.66666... → rounds to 0.6667
        traces = [
            _make_trace(now, "PASSED"),
            _make_trace(now, "PASSED"),
            _make_trace(now, "BLOCKED"),
        ]
        result = self._run_fetch(traces=traces)
        assert result.safety_rate is not None
        # Check it's rounded: at most 4 decimal places
        decimal_str = str(result.safety_rate).rstrip("0").split(".")
        if len(decimal_str) > 1:
            assert len(decimal_str[1]) <= 4, (
                f"safety_rate must be at most 4 decimal places, got {result.safety_rate}"
            )

    def test_control_id_is_preserved_in_result(self) -> None:
        """ComplianceMetrics.control_id must match the input control_id."""
        result = self._run_fetch(traces=[], control_id="SC-4")
        assert result.control_id == "SC-4", (
            f"Expected control_id='SC-4', got {result.control_id!r}"
        )

    def test_window_hours_is_preserved_in_result(self) -> None:
        """ComplianceMetrics.window_hours must match the input window_hours."""
        result = self._run_fetch(traces=[], window_hours=48)
        assert result.window_hours == 48.0, (
            f"Expected window_hours=48.0, got {result.window_hours}"
        )

    def test_evidence_age_seconds_is_zero_with_no_traces(self) -> None:
        """evidence_age_seconds must be 0.0 when no traces exist."""
        result = self._run_fetch(traces=[])
        assert result.evidence_age_seconds == 0.0, (
            f"Expected evidence_age_seconds=0.0 with no traces, got {result.evidence_age_seconds}"
        )

    def test_result_is_compliance_metrics_instance(self) -> None:
        """_fetch_from_langfuse_sync must return a ComplianceMetrics instance."""
        from src.compliance_bridge.types import ComplianceMetrics

        result = self._run_fetch(traces=[])
        assert isinstance(result, ComplianceMetrics), (
            f"Expected ComplianceMetrics, got {type(result)}"
        )


# ---------------------------------------------------------------------------
# Tests: get_compliance_metrics() — cache behavior and async API
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGetComplianceMetrics:
    """Tests for the public async get_compliance_metrics() API."""

    @pytest.mark.asyncio
    async def test_returns_compliance_metrics_on_cache_miss(self) -> None:
        """get_compliance_metrics() must return ComplianceMetrics on first call."""
        from src.compliance_bridge.types import ComplianceMetrics

        now = datetime.now(tz=timezone.utc)
        mock_langfuse_api = MagicMock()
        mock_langfuse_api.trace.list.return_value = _make_traces_response(
            [_make_trace(now, "PASSED")]
        )

        with patch(
            "src.compliance_bridge.metrics._make_app_langfuse",
            return_value=mock_langfuse_api,
        ):
            import src.compliance_bridge.metrics as metrics_mod

            # Clear cache to force cache miss
            metrics_mod._metrics_cache.clear()

            result = await metrics_mod.get_compliance_metrics("A.5.2", window_hours=24)

        assert isinstance(result, ComplianceMetrics), (
            f"get_compliance_metrics must return ComplianceMetrics, got {type(result)}"
        )
        assert result.control_id == "A.5.2"
        assert result.total_traces == 1

    @pytest.mark.asyncio
    async def test_cache_hit_skips_langfuse_call(self) -> None:
        """get_compliance_metrics() must serve cache hits without calling Langfuse."""
        from src.compliance_bridge.types import ComplianceMetrics

        now = datetime.now(tz=timezone.utc)
        cached_result = ComplianceMetrics(
            control_id="A.5.3",
            safety_rate=0.95,
            total_traces=20,
            blocked_traces=1,
            passed_traces=19,
            window_hours=24.0,
            last_event_utc=now.isoformat(),
            evidence_age_seconds=10.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )

        import src.compliance_bridge.metrics as metrics_mod

        # Pre-populate cache
        cache_key = "A.5.3:24"
        metrics_mod._metrics_cache[cache_key] = cached_result

        mock_langfuse_api = MagicMock()

        with patch(
            "src.compliance_bridge.metrics._make_app_langfuse",
            return_value=mock_langfuse_api,
        ):
            result = await metrics_mod.get_compliance_metrics("A.5.3", window_hours=24)

        # Langfuse must NOT have been called (cache hit)
        mock_langfuse_api.trace.list.assert_not_called()
        assert result.control_id == "A.5.3"
        assert result.passed_traces == 19

    @pytest.mark.asyncio
    async def test_cache_hit_updates_evidence_age(self) -> None:
        """get_compliance_metrics() cache hit must update evidence_age_seconds."""
        from datetime import timedelta

        from src.compliance_bridge.types import ComplianceMetrics

        # Set last_event to 60 seconds ago
        last_event = datetime.now(tz=timezone.utc) - timedelta(seconds=60)
        cached_result = ComplianceMetrics(
            control_id="A.6.2",
            safety_rate=1.0,
            total_traces=5,
            blocked_traces=0,
            passed_traces=5,
            window_hours=24.0,
            last_event_utc=last_event.isoformat(),
            evidence_age_seconds=0.0,  # stale placeholder
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )

        import src.compliance_bridge.metrics as metrics_mod

        cache_key = "A.6.2:24"
        metrics_mod._metrics_cache[cache_key] = cached_result

        result = await metrics_mod.get_compliance_metrics("A.6.2", window_hours=24)

        # evidence_age_seconds must be updated to reflect real time elapsed
        assert result.evidence_age_seconds >= 55, (
            f"evidence_age_seconds must be updated on cache hit, got {result.evidence_age_seconds}"
        )
