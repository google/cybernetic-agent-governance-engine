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

"""Regression tests for the NoDirectBind exhaustive state-space proof.

``proof/model.py`` is cited in CAGE_ARXIV.MD §4.4 and Appendix A, and its
reachable-state counts are quoted verbatim in the paper and in
``docs/technical-report/``.  These tests pin those numbers so that a change to
the tier list or the transition functions cannot silently invalidate the
published figures.

If a test here fails because the model legitimately changed, update BOTH the
expected constant below AND every location listed in
``docs/paper/REVISION_TRACKER.md`` under "Consistency blast radius".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# This module is pure-stdlib (no Redis/OPA/network dependencies) and is safe
# to run in every CI matrix leg. Without this marker, `pytest tests/ -m local`
# (the invocation used by the `pytest-logic` CI job) silently excludes this
# file, leaving the 21/24/19/20 state-count regression tests unexercised by
# CI — only the bare `python proof/model.py` script assertions run via the
# separate `no-direct-bind-proof` job. See REVISION_TRACKER.md.
pytestmark = pytest.mark.local

# ---------------------------------------------------------------------------
# proof/ is not a package (no __init__.py) — load the module by path so the
# test runs regardless of how pytest is invoked.
# ---------------------------------------------------------------------------

_MODEL_PATH = Path(__file__).resolve().parents[1] / "proof" / "model.py"
_spec = importlib.util.spec_from_file_location("cage_proof_model", _MODEL_PATH)
assert _spec is not None and _spec.loader is not None
model = importlib.util.module_from_spec(_spec)
sys.modules["cage_proof_model"] = model
_spec.loader.exec_module(model)


# ---------------------------------------------------------------------------
# Published figures — these appear in the paper and must not drift silently.
# ---------------------------------------------------------------------------

EXPECTED_GATED_STATES = 21
EXPECTED_UNGATED_STATES = 19
EXPECTED_CONCURRENT_STATES = 24
EXPECTED_SKIPPED_TIER_STATES = 20  # Gap 3 and Gap 4 variants


# ---------------------------------------------------------------------------
# Tier tuple — C1: the model must cover every tier inside _run_checks()
# ---------------------------------------------------------------------------


def test_tier_tuple_matches_run_checks_pipeline() -> None:
    """The modelled tiers mirror SymbolicGovernor._run_checks() in order.

    Tier 0.5 (FTRA) is intentionally excluded: it is a LangGraph-level
    pre-execution gate over a whole ExecutionPlan, not a step inside
    ``_run_checks()``.  See the module docstring of ``proof/model.py``.
    """
    assert model.TIERS == (
        "stpa",
        "confidence",
        "cbf",
        "opa",
        "fiscal",
        "consensus",
        "causal",
        "fria",
    )
    assert "ftra" not in model.TIERS


def test_concurrent_tiers_are_the_gathered_pair() -> None:
    """Only CBF and OPA are dispatched concurrently by the runtime."""
    assert model.CONCURRENT_TIERS == frozenset({"cbf", "opa"})
    assert model.CONCURRENT_TIERS <= set(model.TIERS)


def test_initial_state_has_all_tiers_pending() -> None:
    initial = model.initial_state()
    assert initial.phase == "PENDING"
    assert not initial.seal_present
    assert not initial.resolved_allow
    assert all(result == "PENDING" for _, result in initial.tier_results)
    assert len(initial.tier_results) == len(model.TIERS)


# ---------------------------------------------------------------------------
# The invariant itself
# ---------------------------------------------------------------------------


def test_gated_architecture_satisfies_no_direct_bind() -> None:
    states = model.enumerate_reachable(model.gated_transitions)
    holds, counterexample = model.check_no_direct_bind(states)
    assert holds, f"NoDirectBind violated at {counterexample}"


def test_gated_reachable_state_count_is_stable() -> None:
    """Pins the figure quoted in CAGE_ARXIV.MD §4.4 and Appendix A."""
    states = model.enumerate_reachable(model.gated_transitions)
    assert len(states) == EXPECTED_GATED_STATES


def test_exactly_one_executed_state_and_it_is_authorised() -> None:
    states = model.enumerate_reachable(model.gated_transitions)
    executed = [s for s in states if s.phase == "EXECUTED"]
    assert len(executed) == 1
    assert executed[0].resolved_allow is True
    assert executed[0].seal_present is True
    assert executed[0].all_tiers_passed()


def test_seal_issued_requires_every_tier_to_pass() -> None:
    """No SEAL_ISSUED state exists with an unresolved or failed tier."""
    states = model.enumerate_reachable(model.gated_transitions)
    sealed = [s for s in states if s.phase == "SEAL_ISSUED"]
    assert sealed, "expected at least one SEAL_ISSUED state"
    for state in sealed:
        assert state.all_tiers_passed()
        assert state.seal_present is True
        assert state.resolved_allow is True


def test_denied_states_never_carry_a_seal() -> None:
    states = model.enumerate_reachable(model.gated_transitions)
    for state in (s for s in states if s.phase == "DENIED"):
        assert state.seal_present is False
        assert state.resolved_allow is False


# ---------------------------------------------------------------------------
# Gap 1 — the seal gate is load-bearing (negative control)
# ---------------------------------------------------------------------------


def test_gap1_ungated_variant_violates_the_invariant() -> None:
    states = model.enumerate_reachable(model.ungated_transitions)
    holds, counterexample = model.check_no_direct_bind(states)
    assert not holds, "the ungated variant must produce a counterexample"
    assert counterexample is not None
    assert counterexample.phase == "EXECUTED"
    assert counterexample.resolved_allow is False
    assert counterexample.seal_present is False


def test_gap1_ungated_reachable_state_count_is_stable() -> None:
    states = model.enumerate_reachable(model.ungated_transitions)
    assert len(states) == EXPECTED_UNGATED_STATES


# ---------------------------------------------------------------------------
# C2 — concurrency: the invariant is order-independent
# ---------------------------------------------------------------------------


def test_concurrent_model_over_approximates_the_sequential_one() -> None:
    """Every sequentially reachable state is also concurrently reachable."""
    gated = model.enumerate_reachable(model.gated_transitions)
    concurrent = model.enumerate_reachable(model.concurrent_tier_transitions)
    assert gated <= concurrent
    assert len(concurrent) > len(gated), (
        "the concurrent model must add interleaving states, otherwise it is "
        "not exercising the parallel gate"
    )


def test_concurrent_reachable_state_count_is_stable() -> None:
    states = model.enumerate_reachable(model.concurrent_tier_transitions)
    assert len(states) == EXPECTED_CONCURRENT_STATES


def test_invariant_holds_under_every_cbf_opa_interleaving() -> None:
    states = model.enumerate_reachable(model.concurrent_tier_transitions)
    holds, counterexample = model.check_no_direct_bind(states)
    assert holds, f"NoDirectBind violated under interleaving at {counterexample}"


def test_concurrent_model_reaches_the_opa_first_interleaving() -> None:
    """The OPA-before-CBF ordering is genuinely explored, not just declared."""
    states = model.enumerate_reachable(model.concurrent_tier_transitions)
    opa_first = [
        s
        for s in states
        if s.tier_result("opa") == "PASS" and s.tier_result("cbf") == "PENDING"
    ]
    assert opa_first, (
        "expected at least one state where OPA resolved before CBF — the "
        "sequential model cannot reach this"
    )


def test_concurrent_model_still_yields_a_single_executed_state() -> None:
    states = model.enumerate_reachable(model.concurrent_tier_transitions)
    executed = [s for s in states if s.phase == "EXECUTED"]
    assert len(executed) == 1
    assert executed[0].resolved_allow is True


# ---------------------------------------------------------------------------
# Gaps 3 and 4 — skipped tiers preserve structure but drop a check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skipped_tier", ["cbf", "causal"])
def test_skipping_a_tier_preserves_structure_but_shrinks_the_gate(
    skipped_tier: str,
) -> None:
    """Gap 3 (CBF_FAIL_OPEN) and Gap 4 (DoWhy absent).

    Marking a tier PASS without evaluating it does not break the structural
    invariant — the seal is still issued only after the remaining tiers pass —
    but it removes one check from the gate, which is why CAGE backs both with
    a production startup ``RuntimeError`` rather than relying on the model.
    """

    def skipping_transitions(state):  # type: ignore[no-untyped-def]
        if state.phase == "CHECKING":
            results = dict(state.tier_results)
            pending = [t for t in model.TIERS if results[t] == "PENDING"]
            if pending and pending[0] == skipped_tier:
                results[skipped_tier] = "PASS"
                yield model.State(
                    phase="CHECKING",
                    tier_results=tuple((t, results[t]) for t in model.TIERS),
                    seal_present=False,
                    resolved_allow=False,
                )
                return
        yield from model.gated_transitions(state)

    states = model.enumerate_reachable(skipping_transitions)
    holds, _ = model.check_no_direct_bind(states)

    assert holds, "skipping a tier must not break the structural invariant"
    assert len(states) == EXPECTED_SKIPPED_TIER_STATES
    # The skipped tier can never be observed as FAIL — it is never evaluated.
    assert not any(s.tier_result(skipped_tier) == "FAIL" for s in states)


# ---------------------------------------------------------------------------
# End-to-end: the script itself must run clean (it asserts internally)
# ---------------------------------------------------------------------------


def test_proof_script_main_runs_and_asserts_clean(capsys) -> None:  # type: ignore[no-untyped-def]
    model.main()
    out = capsys.readouterr().out
    assert "All assertions passed" in out
    assert f"({EXPECTED_GATED_STATES} states)" in out
