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

"""Regression guard for the QUICKSTART §8a chaos-agent playground.

#293 moved the generated STPA validator and saga nodes into the finance plugin
(``src/cage_finance/stpa``), and #113 moved ``SagaCallbackHandler`` into the
kernel. The playground kept importing the old paths inside ``try/except``, so
Tier 0 printed "Validator unavailable ... failing closed" and scenarios D and E
printed "Saga nodes unavailable", while the run still reported a working
governance pipeline. These tests run the playground the way the guide does.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PLAYGROUND = _REPO_ROOT / "examples" / "chaos_agent_playground.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "OTEL_TRACES_EXPORTER": "none"}
    return subprocess.run(
        [sys.executable, str(_PLAYGROUND), "--no-pause", *args],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_quickstart_scenario_uses_the_real_stpa_validator() -> None:
    result = _run("--scenario", "A")
    assert result.returncode == 0, result.stderr[-2000:]
    assert "real GeneratedSTPAValidator ✓" in result.stdout
    assert "Validator unavailable" not in result.stdout
    # A finding produced by the generated UCA-2 check, not by the fallback.
    assert "stale market data" in result.stdout


@pytest.mark.parametrize("scenario", ["D", "E"])
def test_saga_scenarios_load_their_nodes(scenario: str) -> None:
    result = _run("--scenario", scenario)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Saga nodes unavailable" not in result.stdout
