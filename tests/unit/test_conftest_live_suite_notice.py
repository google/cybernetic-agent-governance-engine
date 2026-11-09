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

"""Unit tests for the live / opt-in suite omission notice in tests/conftest.py."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.conftest import (
    _AUTOSKIPPED_LIVE_COUNTS,
    _DESELECTED_LIVE_COUNTS,
    format_unexecuted_live_suites_notice,
    pytest_deselected,
    pytest_terminal_summary,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_format_unexecuted_live_suites_notice_lists_omitted_suites_and_flags() -> None:
    lines = format_unexecuted_live_suites_notice(
        autoskipped={"integration": 12, "e2e": 3},
        deselected={"partner_integration": 7, "integration": 4},
    )
    assert len(lines) == 3
    assert (
        "[NOT EXECUTED] @integration: 12 auto-skipped, 4 deselected — pass --run-integration"
        in lines[0]
    )
    assert (
        "[NOT EXECUTED] @partner_integration: 7 deselected — pass --run-partner-integration"
        in lines[1]
    )
    assert "[NOT EXECUTED] @e2e: 3 auto-skipped — pass --run-e2e" in lines[2]


def test_format_unexecuted_live_suites_notice_empty_when_none_omitted() -> None:
    assert format_unexecuted_live_suites_notice({}, {}) == []


def test_pytest_deselected_and_terminal_summary_emit_section_on_controller() -> None:
    stash = pytest.Stash()
    fake_config = SimpleNamespace(stash=stash)

    item_int = MagicMock()
    item_int.config = fake_config
    item_int.iter_markers.return_value = [SimpleNamespace(name="integration")]
    item_int.parent = None

    item_partner = MagicMock()
    item_partner.config = fake_config
    item_partner.iter_markers.return_value = [
        SimpleNamespace(name="partner_integration")
    ]
    item_partner.parent = None

    pytest_deselected([item_int, item_partner])
    assert stash[_DESELECTED_LIVE_COUNTS] == {
        "integration": 1,
        "partner_integration": 1,
    }

    stash[_AUTOSKIPPED_LIVE_COUNTS] = {"live_external": 2}
    reporter = MagicMock()
    pytest_terminal_summary(reporter, 0, fake_config)  # type: ignore[arg-type]

    reporter.section.assert_called_once_with(
        "live / opt-in suites not executed", sep="-"
    )
    written = [call.args[0] for call in reporter.write_line.call_args_list]
    assert any("@integration: 1 deselected" in line for line in written)
    assert any("@live_external: 2 auto-skipped" in line for line in written)
    assert any("@partner_integration: 1 deselected" in line for line in written)


def test_pytest_terminal_summary_skips_xdist_worker_nodes() -> None:
    stash = pytest.Stash()
    stash[_AUTOSKIPPED_LIVE_COUNTS] = {"integration": 5}
    worker_config = SimpleNamespace(stash=stash, workerinput={"workerid": "gw0"})
    reporter = MagicMock()
    pytest_terminal_summary(reporter, 0, worker_config)  # type: ignore[arg-type]
    reporter.section.assert_not_called()
