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

"""Plugin Seam Architecture Tests

Verifies that the plugin seam contracts allow domain plugins to contribute
components to the kernel without hardcoding dependencies:

1. Overlay registry (register_overlay_dir): Plugins contribute compliance
   mappings without hardcoding paths in the kernel
2. Background task registry: Plugins contribute long-running coroutines
   without direct imports in hybrid_server.py
3. Governor assembly: plugins contribute safety filters and consensus
   providers as data; assemble_governor() fills the engine slots

Markers: pytest.mark.local, pytest.mark.unit
"""

import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.local
@pytest.mark.unit
class TestOverlayRegistry:
    """Test suite for the compliance overlay registry (T-B4)."""

    def test_register_overlay_dir_accepts_valid_path(self):
        """Verify that register_overlay_dir accepts a valid directory path."""
        from src.gateway.governance.constants import register_overlay_dir

        # Create a temporary path (doesn't need to exist for registration)
        test_path = Path(__file__).parent / "fixtures" / "test_overlay"

        # Should not raise
        register_overlay_dir(test_path)

    def test_overlay_registry_deduplicates_paths(self):
        """Verify that the same overlay path registered twice appears only once."""
        from src.gateway.governance.constants import _OVERLAY_DIRS, register_overlay_dir

        test_path = Path(__file__).parent / "fixtures" / "unique_overlay"
        register_overlay_dir(test_path)
        count_after_first = len(_OVERLAY_DIRS)

        # Register the same path again
        register_overlay_dir(test_path)
        count_after_second = len(_OVERLAY_DIRS)

        # The count should increase by 1 after the first registration,
        # but not increase after the second
        assert count_after_second == count_after_first

    def test_cage_finance_contributes_overlay_dir(self):
        """cage_finance contributes its overlay directory as data (the server lifespan registers it)."""
        from src.cage_finance.plugin import FinanceCagePlugin

        overlay_dirs = FinanceCagePlugin().contribute().compliance_overlay_dirs
        finance_overlays = [
            path
            for path in overlay_dirs
            if "cage_finance" in str(path) and "compliance" in str(path)
        ]
        assert finance_overlays, "Finance plugin contributes no compliance overlay directory"
        assert all(path.is_dir() for path in finance_overlays)


@pytest.mark.local
@pytest.mark.unit
class TestBackgroundTaskRegistry:
    """Test suite for the background task registry (T-B6)."""

    @pytest.mark.asyncio
    async def test_register_background_task_accepts_coroutine_factory(self):
        """Verify that register_background_task accepts a coroutine factory."""
        from src.gateway.governance.background_tasks import register_background_task

        async def mock_worker() -> None:
            """Mock background worker."""
            await asyncio.sleep(0.01)

        # Should not raise
        register_background_task("test_worker", mock_worker)

    @pytest.mark.asyncio
    async def test_start_all_launches_registered_tasks(self):
        """Verify that start_all launches all registered background tasks."""
        from src.gateway.governance.background_tasks import (
            _STARTUP_TASKS,
            register_background_task,
            start_all,
        )

        # Track how many times the worker runs
        run_count = 0

        async def counting_worker() -> None:
            nonlocal run_count
            run_count += 1
            await asyncio.sleep(0.01)

        # Register a test worker
        register_background_task("counting_worker", counting_worker)

        # Start all tasks
        tasks = start_all()

        # Wait for tasks to start
        await asyncio.sleep(0.05)

        # Verify that at least one task was started
        assert len(tasks) > 0, "start_all should return at least one task"

        # Verify the counting worker ran
        assert run_count >= 1, "Registered worker should have run at least once"

        # Cleanup: cancel all tasks
        for task in tasks:
            task.cancel()

        # Wait for cancellation
        await asyncio.gather(*tasks, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_task_death_callback_logs_critical(self, caplog):
        """Verify that _log_task_death callback logs CRITICAL when a task dies."""
        from src.gateway.governance.background_tasks import _log_task_death

        # Create a mock task that raises an exception
        async def failing_worker() -> None:
            raise RuntimeError("Worker crashed")

        task = asyncio.create_task(failing_worker(), name="cage.bg.test_failing")
        task.add_done_callback(_log_task_death)

        # Wait for the task to complete and fail
        with caplog.at_level(logging.CRITICAL):
            await asyncio.gather(task, return_exceptions=True)

        # Verify that a CRITICAL log was emitted
        critical_logs = [
            rec for rec in caplog.records if rec.levelno == logging.CRITICAL
        ]
        assert len(critical_logs) > 0, "Task death should log CRITICAL"

        # Verify the log mentions the task name
        assert any("cage.bg.test_failing" in rec.message for rec in critical_logs)

    def test_cage_finance_contributes_audit_worker(self):
        """cage_finance contributes the consensus audit worker as a named background task."""
        from src.cage_finance.plugin import FinanceCagePlugin

        background_tasks = FinanceCagePlugin().contribute().background_tasks
        assert "consensus_audit_worker" in background_tasks, (
            "Consensus audit worker not contributed"
        )
        assert callable(background_tasks["consensus_audit_worker"])


class _SlotPlugin:
    """Minimal plugin contributing only engine slots (no tiers, no actions)."""

    api_version = "1.0"
    domain_config = None

    def __init__(self, name: str, *, safety_filter=None, consensus=None) -> None:
        self.name = name
        self._safety_filter = safety_filter
        self._consensus = consensus

    def contribute(self):
        from src.gateway.governance.contracts import PluginContribution

        return PluginContribution(
            domain=self.name,
            safety_filter=self._safety_filter,
            consensus=self._consensus,
        )


def _assemble(plugins):
    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.assembly import (
        DecisionFlags,
        assemble_governor,
    )
    from tests.fixtures.governor import allow_opa, clean_stpa

    return assemble_governor(
        plugins,
        posture=DeploymentPosture.DEV,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=True, narrow=False),
    )


@pytest.mark.local
@pytest.mark.unit
class TestStartupReadinessAssertions:
    """Test suite for engine-slot readiness at governor assembly (T-B3)."""

    def test_bare_kernel_reports_null_slots(self):
        """With no plugin contributions, both engine slots stay deny-by-default nulls."""
        from src.gateway.governance.null_components import NullSafetyFilter

        governor = _assemble([])
        assert governor.components.unfilled_slots == ("safety_filter", "consensus")
        assert isinstance(governor.components.safety_filter, NullSafetyFilter)

    def test_contribution_replaces_null_objects(self):
        """A plugin's safety filter and consensus provider fill the engine slots."""
        safety_filter = MagicMock(name="safety_filter")
        consensus = MagicMock(name="consensus")

        governor = _assemble(
            [_SlotPlugin("slots", safety_filter=safety_filter, consensus=consensus)]
        )

        assert governor.components.safety_filter is safety_filter
        assert governor.components.consensus is consensus
        assert governor.components.unfilled_slots == ()

    def test_two_plugins_filling_same_slot_fail_closed(self):
        """A slot may be filled once; a second contribution is rejected at assembly."""
        from src.gateway.governance.governor.assembly import GovernorAssemblyError

        with pytest.raises(GovernorAssemblyError, match="slot collision"):
            _assemble(
                [
                    _SlotPlugin("first", safety_filter=MagicMock()),
                    _SlotPlugin("second", safety_filter=MagicMock()),
                ]
            )
