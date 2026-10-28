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

import importlib.util
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


def _scenario_f_params() -> dict:
    """Scenario F's payload, read from the playground itself rather than copied."""
    spec = importlib.util.spec_from_file_location("chaos_agent_playground", _PLAYGROUND)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve the playground's annotations through sys.modules.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    (baseline,) = [s for s in module._SCENARIOS if s.id == "F"]
    return dict(baseline.params)


def _tier0_codes(params: dict) -> set[str]:
    from src.cage_finance.stpa import GeneratedSTPAValidator

    return {
        v.code
        for v in GeneratedSTPAValidator().validate_generated("execute_trade", params)
    }


def _threshold(name: str) -> float:
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    return float(THRESHOLDS.resolve(f"domains.finance.stpa.{name}"))


def _at_and_past(field: str) -> tuple[dict, dict, str]:
    """F moved onto one Tier 0 boundary, then just past it, with the rule that trips."""
    f = _scenario_f_params()
    if field == "latency_ms":
        limit = _threshold("max_latency_ms")
        return (
            {**f, "latency_ms": limit},
            {**f, "latency_ms": limit + 0.01},
            "STPA_UCA_UCA_2",
        )
    if field == "drawdown":
        limit = _threshold("uca5_drawdown_threshold_pct")
        return (
            {**f, "drawdown": limit},
            {**f, "drawdown": limit + 0.01},
            "STPA_UCA_UCA_5",
        )
    if field == "order_size":
        limit = _threshold("uca6_max_order_volume_fraction") * f["daily_vol"]
        return (
            {**f, "order_size": limit},
            {**f, "order_size": limit * 1.001},
            "STPA_UCA_UCA_6",
        )
    if field == "risk_assessed":
        return f, {**f, "risk_assessed": False}, "STPA_UCA_UCA_8"
    if field == "compliance_checked":
        return f, {**f, "compliance_checked": False}, "STPA_UCA_UCA_9"
    raise AssertionError(field)


def test_scenario_f_passes_every_tier0_rule_it_is_subject_to() -> None:
    assert _tier0_codes(_scenario_f_params()) == set()


@pytest.mark.parametrize(
    "field",
    ["latency_ms", "drawdown", "order_size", "risk_assessed", "compliance_checked"],
)
def test_scenario_f_allow_is_load_bearing(field: str) -> None:
    """Each Tier 0 rule F is subject to allows F at its boundary and denies just past it.

    An ALLOW that passed because the payload avoided a check would look the
    same from outside as one the tier evaluated. Moving F across each
    boundary shows every rule that applies to a BUY ``execute_trade`` was
    evaluated: UCA-2 (latency), UCA-5 (drawdown), UCA-6 (order size against
    daily volume), UCA-8 (risk assessed) and UCA-9 (compliance checked).
    """
    at_boundary, past_boundary, code = _at_and_past(field)
    assert _tier0_codes(at_boundary) == set()
    assert _tier0_codes(past_boundary) == {code}
