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
Unit tests for src/compliance_bridge/sla_monitor.py.

All tests are hermetic — no Langfuse, no Redis, no external I/O.
Heavy dependencies are patched via unittest.mock.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. _is_disabled() reads the EVIDENCE_SLA_DISABLED env var
# ---------------------------------------------------------------------------

@pytest.mark.local
def test_is_disabled_when_env_set_to_1() -> None:
    """_is_disabled() returns True when EVIDENCE_SLA_DISABLED=1."""
    from src.compliance_bridge.sla_monitor import _is_disabled

    with patch.dict(os.environ, {"EVIDENCE_SLA_DISABLED": "1"}):
        assert _is_disabled() is True


@pytest.mark.local
def test_is_disabled_returns_false_by_default() -> None:
    """_is_disabled() returns False when EVIDENCE_SLA_DISABLED is not set."""
    from src.compliance_bridge.sla_monitor import _is_disabled

    env = {k: v for k, v in os.environ.items() if k != "EVIDENCE_SLA_DISABLED"}
    with patch.dict(os.environ, env, clear=True):
        assert _is_disabled() is False


# ---------------------------------------------------------------------------
# 2. _poll_interval() reads EVIDENCE_SLA_POLL_INTERVAL_SECONDS
# ---------------------------------------------------------------------------

@pytest.mark.local
def test_poll_interval_reads_env_var() -> None:
    """_poll_interval() returns the integer value of EVIDENCE_SLA_POLL_INTERVAL_SECONDS."""
    from src.compliance_bridge.sla_monitor import _poll_interval

    with patch.dict(os.environ, {"EVIDENCE_SLA_POLL_INTERVAL_SECONDS": "120"}):
        assert _poll_interval() == 120


@pytest.mark.local
def test_poll_interval_default() -> None:
    """_poll_interval() returns 300 when env var is absent."""
    from src.compliance_bridge.sla_monitor import _poll_interval

    env = {k: v for k, v in os.environ.items() if k != "EVIDENCE_SLA_POLL_INTERVAL_SECONDS"}
    with patch.dict(os.environ, env, clear=True):
        assert _poll_interval() == 300


# ---------------------------------------------------------------------------
# 3. _check_sla_once() skips controls while startup grace is active
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_check_sla_once_skips_during_grace() -> None:
    """_check_sla_once returns no breaches when startup_grace_active is True."""
    from src.compliance_bridge.sla_monitor import _check_sla_once

    mock_metrics = MagicMock()
    mock_metrics.startup_grace_active = True
    mock_metrics.startup_grace_remaining_hours = 2.5

    with (
        patch(
            "src.compliance_bridge.sla_monitor._active_sla_seconds",
            return_value={"ISO-42001-4.1": 3600},
        ),
        patch(
            "src.compliance_bridge.sla_monitor.get_compliance_metrics",
            AsyncMock(return_value=mock_metrics),
        ),
    ):
        breached = await _check_sla_once()

    assert breached == []


# ---------------------------------------------------------------------------
# 4. _check_sla_once() detects a breach when evidence age exceeds the SLA
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_check_sla_once_detects_breach() -> None:
    """_check_sla_once returns the control ID when evidence_age_seconds > sla_seconds."""
    from src.compliance_bridge.sla_monitor import _check_sla_once

    mock_metrics = MagicMock()
    mock_metrics.startup_grace_active = False
    mock_metrics.evidence_age_seconds = 7200  # 2 hours — exceeds 1-hour SLA

    with (
        patch(
            "src.compliance_bridge.sla_monitor._active_sla_seconds",
            return_value={"ISO-42001-4.1": 3600},
        ),
        patch(
            "src.compliance_bridge.sla_monitor.get_compliance_metrics",
            AsyncMock(return_value=mock_metrics),
        ),
    ):
        breached = await _check_sla_once()

    assert "ISO-42001-4.1" in breached


# ---------------------------------------------------------------------------
# 5. _fire_sla_alerts() does nothing when breached list is empty
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_fire_sla_alerts_noop_when_empty() -> None:
    """_fire_sla_alerts returns immediately without creating a notifier when breached=[]."""
    from src.compliance_bridge.sla_monitor import _fire_sla_alerts

    with patch("src.compliance_bridge.sla_monitor.create_notifier") as mock_notifier:
        await _fire_sla_alerts([])
        mock_notifier.assert_not_called()


# ---------------------------------------------------------------------------
# 6. _fire_sla_alerts() sends a critical alert for each breached control
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_fire_sla_alerts_sends_critical_alert() -> None:
    """_fire_sla_alerts calls notifier.send_critical_alert with at least one finding."""
    from src.compliance_bridge.sla_monitor import _fire_sla_alerts

    mock_metrics = MagicMock()
    mock_metrics.evidence_age_seconds = 7200
    mock_metrics.last_event_utc = "2026-01-01T00:00:00Z"
    mock_metrics.safety_rate = 0.95

    mock_notifier = MagicMock()
    mock_notifier.send_critical_alert = AsyncMock()

    with (
        patch(
            "src.compliance_bridge.sla_monitor.create_notifier",
            return_value=mock_notifier,
        ),
        patch(
            "src.compliance_bridge.sla_monitor.get_compliance_metrics",
            AsyncMock(return_value=mock_metrics),
        ),
        patch(
            "src.compliance_bridge.sla_monitor._active_sla_seconds",
            return_value={"ISO-42001-4.1": 3600},
        ),
    ):
        await _fire_sla_alerts(["ISO-42001-4.1"])

    mock_notifier.send_critical_alert.assert_awaited_once()
    findings, _audit_id = mock_notifier.send_critical_alert.call_args.args
    assert len(findings) == 1
    assert findings[0].control_id == "ISO-42001-4.1"
    assert findings[0].result == "FAIL"


# ---------------------------------------------------------------------------
# 7. run_sla_monitor() exits immediately when disabled
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_run_sla_monitor_exits_when_disabled() -> None:
    """run_sla_monitor returns immediately when EVIDENCE_SLA_DISABLED=1."""
    from src.compliance_bridge.sla_monitor import run_sla_monitor

    with patch.dict(os.environ, {"EVIDENCE_SLA_DISABLED": "1"}):
        # Should return without looping or sleeping
        await run_sla_monitor()
