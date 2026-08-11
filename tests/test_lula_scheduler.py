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
Unit tests for src/compliance_bridge/lula_scheduler.py.

All tests are hermetic — no live lula binary, no network, no filesystem I/O
beyond tmp_path fixtures.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# 1. run_lula_scheduler() exits immediately when disabled
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_run_lula_scheduler_exits_when_disabled() -> None:
    """run_lula_scheduler() returns without looping when LULA_SCHEDULER_DISABLED=1."""
    from src.compliance_bridge.lula_scheduler import run_lula_scheduler

    with patch.dict(os.environ, {"LULA_SCHEDULER_DISABLED": "1"}):
        # Must return promptly — no sleep, no looping
        await run_lula_scheduler()


# ---------------------------------------------------------------------------
# 2. _run_lula_cycle() returns "skipped" when component file does not exist
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_run_lula_cycle_skips_when_component_missing(tmp_path: Path) -> None:
    """_run_lula_cycle returns status='skipped' when the component YAML is absent."""
    from src.compliance_bridge.lula_scheduler import _run_lula_cycle

    nonexistent = str(tmp_path / "nonexistent-component.yaml")
    with patch("src.compliance_bridge.lula_scheduler._component_path", return_value=nonexistent):
        result = await _run_lula_cycle()

    assert result["status"] == "skipped"
    assert result["reason"] == "component_not_found"
    assert "audit_id" in result


# ---------------------------------------------------------------------------
# 3. _run_lula_validate() returns False when lula binary is not found
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_run_lula_validate_returns_false_when_binary_missing() -> None:
    """_run_lula_validate() returns False (does not raise) when lula is not on PATH."""
    from src.compliance_bridge.lula_scheduler import _run_lula_validate

    with patch(
        "asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError("lula not found"),
    ):
        result = await _run_lula_validate("/fake/component.yaml", "/tmp/results.yaml", 30)

    assert result is False


# ---------------------------------------------------------------------------
# 4. _post_results_to_bridge() returns False when results file is missing
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_post_results_to_bridge_returns_false_when_file_missing(tmp_path: Path) -> None:
    """_post_results_to_bridge() returns False when the results YAML does not exist."""
    from src.compliance_bridge.lula_scheduler import _post_results_to_bridge

    missing_path = str(tmp_path / "no-results.yaml")
    result = await _post_results_to_bridge(missing_path, "audit-test-001")
    assert result is False


# ---------------------------------------------------------------------------
# 5. _run_lula_cycle() returns "failed" when lula validate fails
# ---------------------------------------------------------------------------

@pytest.mark.local
@pytest.mark.asyncio
async def test_run_lula_cycle_returns_failed_when_validate_fails(tmp_path: Path) -> None:
    """_run_lula_cycle returns status='failed' when _run_lula_validate returns False."""
    from src.compliance_bridge.lula_scheduler import _run_lula_cycle

    # Create a real component file so the existence check passes
    component = tmp_path / "component.yaml"
    component.write_text("component: definition", encoding="utf-8")

    with (
        patch(
            "src.compliance_bridge.lula_scheduler._component_path",
            return_value=str(component),
        ),
        patch(
            "src.compliance_bridge.lula_scheduler._results_path",
            return_value=str(tmp_path / "results.yaml"),
        ),
        patch(
            "src.compliance_bridge.lula_scheduler._run_lula_validate",
            AsyncMock(return_value=False),
        ),
    ):
        result = await _run_lula_cycle()

    assert result["status"] == "failed"
    assert result["reason"] == "lula_validate_failed"
    assert "audit_id" in result
