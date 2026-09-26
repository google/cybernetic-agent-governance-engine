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
Golden test suite for SymbolicGovernor verdicts.

Executes 40 deterministic governance scenarios against all applicable entry points
(`validate_action`, `govern`, `revalidate_post_hitl`, `verify`) and asserts:
1. Verdict outcomes match `expected.json` (or regenerates with `--regen-golden`).
2. HARD GUARD: Test fails immediately if ANY recorded outcome is TypeError,
   AttributeError, or NameError (indicating broken governor code or mocks).
3. First violation control ID / code matches expected.
4. Seal presence matches expected.
5. Collaborator call sequence matches expected.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from tests.governor.golden.fixtures import SCENARIOS, Scenario, build_governor_for_scenario

pytestmark = [pytest.mark.unit, pytest.mark.local]

EXPECTED_JSON_PATH = Path(__file__).parent / "expected.json"
BANNED_OUTCOMES = frozenset({"TypeError", "AttributeError", "NameError"})


def _check_hard_guard(outcome: str, scenario_id: str, entry_point: str) -> None:
    """Enforce the Hard Guard: reject TypeError, AttributeError, NameError."""
    if outcome in BANNED_OUTCOMES:
        raise AssertionError(
            f"HARD GUARD FAILURE: Scenario '{scenario_id}' entry point '{entry_point}' "
            f"produced banned outcome '{outcome}'. Golden tests MUST NOT record internal errors."
        )


async def _execute_scenario_entry_point(
    scenario: Scenario,
    entry_point: str,
) -> dict[str, Any]:
    """Execute a single entry point for a scenario with deterministic mocks."""
    with patch(
        "src.gateway.governance.evidence.stream.is_evidence_chain_blocking",
        return_value=False,
    ), patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new_callable=AsyncMock,
        return_value="mock-seal-" + "a" * 32,
    ), patch(
        "src.gateway.governance.symbolic_governor._park_defer_context",
        new_callable=AsyncMock,
        return_value="mock-defer-token",
    ), patch(
        "src.gateway.governance.pause_primitive.PauseManager"
    ):
        governor, collaborators = build_governor_for_scenario(scenario)
        fn = getattr(governor, entry_point)

        outcome: str
        first_violation_code: str | None = None
        seal_issued: bool = False

        try:
            res = await fn(scenario.action, scenario.params)
            if isinstance(res, dict):
                if "verdict" in res:
                    v = res["verdict"]
                    outcome = v.value if hasattr(v, "value") else str(v)
                    viols = res.get("violations", [])
                    first_violation_code = viols[0] if viols else None
                    seal_issued = bool(res.get("seal"))
                else:
                    # verify entry point returns dict with 'violations'
                    viols = res.get("violations", [])
                    outcome = "ALLOW" if not viols else "DENY"
                    first_violation_code = viols[0] if viols else None
                    seal_issued = False
            elif isinstance(res, str):
                outcome = "ALLOW"
                first_violation_code = None
                seal_issued = bool(res)
            else:
                outcome = str(res)
                first_violation_code = None
                seal_issued = False
        except Exception as e:
            outcome = type(e).__name__
            if hasattr(e, "receipt") and getattr(e.receipt, "violations", None):
                first_violation_code = str(e.receipt.violations[0])
            elif hasattr(e, "violations") and getattr(e, "violations", None):
                first_violation_code = str(e.violations[0])
            elif hasattr(e, "violation") and getattr(e, "violation", None):
                first_violation_code = str(e.violation)
            else:
                first_violation_code = str(e)
            seal_issued = False

        _check_hard_guard(outcome, scenario.id, entry_point)

        called = [
            k
            for k, v in collaborators.items()
            if (getattr(v, "called", False) or getattr(v, "call_count", 0) > 0)
        ]

        return {
            "outcome": outcome,
            "first_violation_code": first_violation_code,
            "seal_issued": seal_issued,
            "collaborators_called": sorted(called),
        }


async def _run_all_scenarios() -> dict[str, Any]:
    """Run all scenarios across all their applicable entry points."""
    results: dict[str, Any] = {}
    for scenario in SCENARIOS:
        results[scenario.id] = {
            "description": scenario.description,
            "action": scenario.action,
            "entry_points": {},
        }
        for ep in scenario.applicable_entry_points:
            res = await _execute_scenario_entry_point(scenario, ep)
            results[scenario.id]["entry_points"][ep] = res
    return results


def test_golden_verdicts(pytestconfig: pytest.Config) -> None:
    """Run golden verdict corpus against expected.json or regenerate if requested."""
    regen = pytestconfig.getoption("--regen-golden", default=False)
    actual_results = asyncio.run(_run_all_scenarios())

    if regen:
        # Check hard guard on every outcome before writing
        for sid, sc_data in actual_results.items():
            for ep, ep_data in sc_data["entry_points"].items():
                _check_hard_guard(ep_data["outcome"], sid, ep)

        with open(EXPECTED_JSON_PATH, "w") as f:
            json.dump(actual_results, f, indent=2)
            f.write("\n")
        return

    assert EXPECTED_JSON_PATH.exists(), (
        f"Missing expected golden results at {EXPECTED_JSON_PATH}. "
        "Run `uv run pytest tests/governor/golden/test_golden_verdicts.py --regen-golden` to generate."
    )

    with open(EXPECTED_JSON_PATH) as f:
        expected_results = json.load(f)

    # Compare scenario count and ids
    assert set(actual_results.keys()) == set(expected_results.keys()), (
        f"Scenario IDs mismatch: added={set(actual_results.keys()) - set(expected_results.keys())}, "
        f"removed={set(expected_results.keys()) - set(actual_results.keys())}"
    )

    mismatches: list[str] = []
    for sid, expected_sc in expected_results.items():
        actual_sc = actual_results[sid]
        for ep, expected_ep in expected_sc["entry_points"].items():
            actual_ep = actual_sc["entry_points"].get(ep)
            if not actual_ep:
                mismatches.append(f"[{sid}][{ep}] missing in actual results")
                continue

            if actual_ep["outcome"] != expected_ep["outcome"]:
                mismatches.append(
                    f"[{sid}][{ep}] outcome mismatch: expected={expected_ep['outcome']}, actual={actual_ep['outcome']}"
                )
            if actual_ep["first_violation_code"] != expected_ep["first_violation_code"]:
                mismatches.append(
                    f"[{sid}][{ep}] violation mismatch: expected={expected_ep['first_violation_code']}, actual={actual_ep['first_violation_code']}"
                )
            if actual_ep["seal_issued"] != expected_ep["seal_issued"]:
                mismatches.append(
                    f"[{sid}][{ep}] seal_issued mismatch: expected={expected_ep['seal_issued']}, actual={actual_ep['seal_issued']}"
                )
            if actual_ep["collaborators_called"] != expected_ep["collaborators_called"]:
                mismatches.append(
                    f"[{sid}][{ep}] collaborators mismatch: expected={expected_ep['collaborators_called']}, actual={actual_ep['collaborators_called']}"
                )

    assert not mismatches, (
        f"Golden corpus verdict mismatches ({len(mismatches)}):\n"
        + "\n".join(mismatches[:30])
    )


# ── Hard Guard Negative Tests ───────────────────────────────────────────────


def test_hard_guard_catches_type_error() -> None:
    """Verify that the hard guard fails closed when TypeError is encountered."""
    with pytest.raises(AssertionError, match="HARD GUARD FAILURE.*TypeError"):
        _check_hard_guard("TypeError", "test_scenario", "validate_action")


def test_hard_guard_catches_attribute_error() -> None:
    """Verify that the hard guard fails closed when AttributeError is encountered."""
    with pytest.raises(AssertionError, match="HARD GUARD FAILURE.*AttributeError"):
        _check_hard_guard("AttributeError", "test_scenario", "govern")


def test_hard_guard_catches_name_error() -> None:
    """Verify that the hard guard fails closed when NameError is encountered."""
    with pytest.raises(AssertionError, match="HARD GUARD FAILURE.*NameError"):
        _check_hard_guard("NameError", "test_scenario", "verify")


def test_hard_guard_allows_legitimate_outcomes() -> None:
    """Verify that legitimate outcomes (ALLOW, DENY, GovernanceError, etc.) pass the guard."""
    for outcome in ("ALLOW", "DENY", "DEFER", "NARROW", "REQUIRE_APPROVAL", "GovernanceError", "ValueError"):
        _check_hard_guard(outcome, "test_scenario", "validate_action")
