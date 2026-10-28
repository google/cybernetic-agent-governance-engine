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


def _tier_lines(stdout: str) -> dict[int, str]:
    """The header line each tier printed, keyed by tier number."""
    lines: dict[int, str] = {}
    for line in stdout.splitlines():
        for tier in range(5):
            if f"Tier {tier}  ·  " in line:
                lines[tier] = line
    return lines


def test_the_real_tier_allows_and_denies_on_one_code_path() -> None:
    """Tier 0, the real validator, denies Scenario A and allows Scenario F.

    Until every trade carried ``order_size`` and ``daily_vol``, UCA-6 refused
    every playground trade: the reasons varied with the input, the verdict
    never did, and the playground had no ALLOW path.
    """
    denied, allowed = _run("--scenario", "A"), _run("--scenario", "F")
    assert denied.returncode == 0, denied.stderr[-2000:]
    assert allowed.returncode == 0, allowed.stderr[-2000:]
    for result in (denied, allowed):
        assert "Missing required composite param" not in result.stdout
    assert "BLOCKED" in _tier_lines(denied.stdout)[0]
    assert "PASS" in _tier_lines(allowed.stdout)[0]
    assert "ACTION BLOCKED" in denied.stdout
    assert "ACTION APPROVED" in allowed.stdout


def test_no_tier_names_a_component_it_did_not_call() -> None:
    """Tiers 1-4 are emulations and must say so; Tier 0 is the only real tier."""
    result = _run("--scenario", "A")  # A prints all five tiers
    assert result.returncode == 0, result.stderr[-2000:]
    tiers = _tier_lines(result.stdout)
    assert sorted(tiers) == [0, 1, 2, 3, 4]
    assert "REAL" in tiers[0]
    for tier in (1, 2, 3, 4):
        assert "EMULATED" in tiers[tier] or "SIMULATED" in tiers[tier], tiers[tier]
    assert "OPA Rego Policy" not in result.stdout
    assert "[OPA]" not in result.stdout
