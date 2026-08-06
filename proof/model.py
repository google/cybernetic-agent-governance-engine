# Adapted from the open-source implementation by LalaSkye (Apache 2.0)
# Original repository: https://github.com/LalaSkye/no-direct-bind
# Modifications: Adapted for the CAGE 8-tier governance architecture,
# extended with Gap 1/2/3/4 sub-proofs and a concurrency-interleaving
# sub-proof, and integrated with CAGE state machine phases
# (PENDING → CHECKING → SEAL_ISSUED → EXECUTED/DENIED).
#
# Original copyright notice preserved per Apache 2.0 Section 4(b):
# Copyright (c) LalaSkye contributors
# Licensed under the Apache License, Version 2.0

"""
CAGE No-Direct-Bind Proof — Exhaustive State-Space Enumerator
==============================================================

Theorem (No-Direct-Bind):
    In any run of the CAGE gated architecture, the system reaches an EXECUTED
    state only via a transition guarded by resolvedAllow = TRUE.
    Equivalently: there is no reachable state in which an effect has occurred
    while authority was unresolved.

    Formally (TLA+ safety invariant):
        NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

This file:
  1. Defines the CAGE 8-tier governance state machine.
  2. Enumerates every reachable state via BFS.
  3. Asserts the invariant holds in ALL reachable states.
  4. Defines an ungated (direct-bind) variant and proves it VIOLATES the
     invariant, producing an explicit counterexample — confirming the gate is
     load-bearing, not decorative.
  5. Proves the invariant is insensitive to the CBF/OPA evaluation order,
     which the runtime executes concurrently via ``asyncio.gather()``.

Usage (no dependencies beyond the Python standard library):
    python proof/model.py

Expected output:
    [gated]   No-Direct-Bind holds over all N reachable states: True
    [ungated] direct-bind shortcut produces a violation: True

The model is intentionally small and enumerable.  It captures the essential
structure of the CAGE pipeline:
  - 8 governance tiers, each of which can PASS or FAIL
  - A routing seal that is issued only after all tiers pass
  - A downstream actuator that verifies the seal before executing

Scope of the model
------------------
The tuple models ``SymbolicGovernor._run_checks()`` — Tiers 1 through 7,
with Tier 3 split into its concurrent ``cbf`` and ``opa`` components.
Tier 0.5 (FTRA) is deliberately NOT in the tuple: it is a *pre-execution*
gate that runs at the LangGraph graph level, before ``_run_checks()`` is
invoked, and operates on a whole ``ExecutionPlan`` rather than a single tool
call.  Its verdict (CLEAR | HITL_REQUIRED | BLOCKED) is recorded separately
in the LangGraph state.  See ``src/gateway/governance/ftra/node_factory.py``
and ``src/governed_financial_advisor/graph/graph.py``.

Tier 7 (FRIA) caveat
--------------------
The ``fria`` tier is included in the tuple because ``enforce_fria_boundary()``
runs as a distinct step inside ``_run_checks()`` after the causal gatekeeper.
However, the *adaptive* FRIA enforcement path (lines 603-660 of
``symbolic_governor.py``) is gated on
``CAGE_NORMATIVE_PROVIDER != "static"``.  That environment variable is not
set in any committed deployment manifest, so the adaptive path is unreachable
in the reference deployment.  The unconditional portion (OTel attribute
stamping, lines 662-693) always runs.  The proof models the tier as present
and capable of blocking (FAIL) — which is the conservative, safe-side
assumption: if the tier can block, the invariant must hold even when it does.
What the proof does NOT claim is that the adaptive FRIA logic is exercised in
the reference deployment; that depends on ``CAGE_NORMATIVE_PROVIDER`` being
set to a non-static value.

Gaps closed by this proof:
  Gap 1: Proves the ungated (no-seal) architecture violates the invariant,
         establishing that the seal-issuance gate is load-bearing
  Gap 2: Proves govern() path satisfies the invariant when seal is issued
  Gap 3: Proves CBF_FAIL_OPEN shortcut removes the CBF tier from the gate
  Gap 4: Proves DoWhy-absent shortcut removes the causal tier from the gate
  Concurrency: Proves the invariant is order-independent across the
         concurrently-evaluated CBF and OPA tiers
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# State definition
# ---------------------------------------------------------------------------

# Governance tiers in execution order, mirroring the sequence of checks in
# ``SymbolicGovernor._run_checks()``.  Each tier can be PENDING, PASS or FAIL.
#
# Tier numbering follows the paper (§4.2).  Tier 3 is split into its two
# concurrently-evaluated components (``cbf`` and ``opa``) because each can
# independently block the action; see ``concurrent_tier_transitions()`` for
# the proof that their evaluation order does not affect the invariant.
TIERS = (
    "stpa",  # Tier 1:  STAMP/STPA unsafe control action check
    "confidence",  # Tier 2:  agent confidence threshold
    "cbf",  # Tier 3a: Control Barrier Function (Redis cash barrier)
    "opa",  # Tier 3b: OPA Rego policy evaluation
    "fiscal",  # Tier 4:  fiscal limit pre-reservation
    "consensus",  # Tier 5:  multi-agent consensus gate
    "causal",  # Tier 6:  DoWhy causal gatekeeper
    "fria",  # Tier 7:  FRIA normative boundary enforcement
)

# The subset of tiers that the runtime evaluates concurrently
# (``asyncio.gather()`` in symbolic_governor.py).  Used by
# ``concurrent_tier_transitions()`` to explore both interleavings.
CONCURRENT_TIERS = frozenset({"cbf", "opa"})

# Execution phases — mirrors the TLA+ state machine.
PHASES = ("PENDING", "CHECKING", "SEAL_ISSUED", "EXECUTED", "DENIED")


@dataclass(frozen=True)
class State:
    """A single point in the CAGE governance state space.

    Attributes:
        phase:          Current execution phase.
        tier_results:   Tuple of (tier_name, result) pairs where result is
                        "PASS", "FAIL", or "PENDING".
        seal_present:   True if a valid routing seal has been issued.
        resolved_allow: True if all tiers have passed AND a seal is present.
                        This is the ``resolvedAllow`` variable in the TLA+ spec.
    """

    phase: str
    tier_results: tuple[tuple[str, str], ...]
    seal_present: bool
    resolved_allow: bool

    def tier_result(self, tier: str) -> str:
        return dict(self.tier_results).get(tier, "PENDING")

    def all_tiers_passed(self) -> bool:
        return all(r == "PASS" for _, r in self.tier_results)

    def any_tier_failed(self) -> bool:
        return any(r == "FAIL" for _, r in self.tier_results)


def initial_state() -> State:
    """The single initial state: all tiers pending, no seal, phase=PENDING."""
    return State(
        phase="PENDING",
        tier_results=tuple((t, "PENDING") for t in TIERS),
        seal_present=False,
        resolved_allow=False,
    )


# ---------------------------------------------------------------------------
# Gated transition function (the correct CAGE architecture)
# ---------------------------------------------------------------------------


def gated_transitions(state: State) -> Iterator[State]:
    """Generate all successor states from *state* under the gated architecture.

    Rules (mirror the CAGE symbolic_governor._run_checks() pipeline):
      - From PENDING: begin checking (move to CHECKING).
      - From CHECKING: each tier can PASS or FAIL in sequence.
        - If any tier FAILs → move to DENIED immediately (fail-closed).
        - If all tiers PASS → issue seal → move to SEAL_ISSUED.
      - From SEAL_ISSUED: actuator verifies seal.
        - Seal valid → move to EXECUTED (resolvedAllow=TRUE).
        - Seal invalid/expired → move to DENIED.
      - EXECUTED and DENIED are terminal.

    The key invariant: EXECUTED is only reachable from SEAL_ISSUED, and
    SEAL_ISSUED is only reachable when all tiers have passed.
    """
    if state.phase == "PENDING":
        # Begin the governance pipeline
        yield State(
            phase="CHECKING",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
        )

    elif state.phase == "CHECKING":
        # Find the first PENDING tier
        results = dict(state.tier_results)
        pending_tiers = [t for t in TIERS if results[t] == "PENDING"]

        if not pending_tiers:
            # All tiers resolved
            if state.any_tier_failed():
                yield State(
                    phase="DENIED",
                    tier_results=state.tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )
            else:
                # All passed — issue routing seal
                yield State(
                    phase="SEAL_ISSUED",
                    tier_results=state.tier_results,
                    seal_present=True,
                    resolved_allow=True,  # resolvedAllow = TRUE only here
                )
        else:
            # Advance the next pending tier: it can PASS or FAIL
            next_tier = pending_tiers[0]
            for outcome in ("PASS", "FAIL"):
                new_results = dict(state.tier_results)
                new_results[next_tier] = outcome
                new_tier_results = tuple((t, new_results[t]) for t in TIERS)

                if outcome == "FAIL":
                    # Fail-closed: any failure → DENIED immediately
                    yield State(
                        phase="DENIED",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                    )
                else:
                    yield State(
                        phase="CHECKING",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                    )

    elif state.phase == "SEAL_ISSUED":
        # Actuator verifies seal before executing
        # Seal valid → EXECUTED
        yield State(
            phase="EXECUTED",
            tier_results=state.tier_results,
            seal_present=True,
            resolved_allow=True,
        )
        # Seal invalid/expired → DENIED (e.g. TTL elapsed, HMAC mismatch)
        yield State(
            phase="DENIED",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
        )

    # EXECUTED and DENIED are terminal — no successors


# ---------------------------------------------------------------------------
# Ungated (direct-bind) transition function — the violation variant
# ---------------------------------------------------------------------------


def ungated_transitions(state: State) -> Iterator[State]:
    """Generate successor states under the UNGATED (direct-bind) architecture.

    The direct-bind shortcut: execution proceeds without waiting for a resolved
    seal.  This models three concrete CAGE gaps:
      - Gap 2: govern() path that raises GovernanceError but issues no seal,
               and a caller that catches the exception and executes anyway.
      - Gap 3: CBF_FAIL_OPEN=true — CBF tier is skipped entirely.
      - Gap 4: DoWhy ImportError silently removes the causal tier.

    In this variant, EXECUTED is reachable from CHECKING directly (bypassing
    SEAL_ISSUED), which violates the No-Direct-Bind invariant.
    """
    if state.phase == "PENDING":
        yield State(
            phase="CHECKING",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
        )

    elif state.phase == "CHECKING":
        results = dict(state.tier_results)
        pending_tiers = [t for t in TIERS if results[t] == "PENDING"]

        if not pending_tiers:
            if state.any_tier_failed():
                yield State(
                    phase="DENIED",
                    tier_results=state.tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )
            else:
                # Direct-bind shortcut: skip SEAL_ISSUED, go straight to EXECUTED
                # without issuing or verifying a seal.
                # resolvedAllow remains FALSE — this is the violation.
                yield State(
                    phase="EXECUTED",
                    tier_results=state.tier_results,
                    seal_present=False,
                    resolved_allow=False,  # ← authority never resolved
                )
        else:
            next_tier = pending_tiers[0]
            for outcome in ("PASS", "FAIL"):
                new_results = dict(state.tier_results)
                new_results[next_tier] = outcome
                new_tier_results = tuple((t, new_results[t]) for t in TIERS)

                if outcome == "FAIL":
                    yield State(
                        phase="DENIED",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                    )
                else:
                    yield State(
                        phase="CHECKING",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                    )

    elif state.phase == "SEAL_ISSUED":
        # Ungated variant never reaches SEAL_ISSUED, but handle for completeness
        yield State(
            phase="EXECUTED",
            tier_results=state.tier_results,
            seal_present=True,
            resolved_allow=True,
        )


# ---------------------------------------------------------------------------
# Concurrent transition function — models the CBF/OPA parallel gate
# ---------------------------------------------------------------------------


def concurrent_tier_transitions(state: State) -> Iterator[State]:
    """Gated transitions in which the concurrent tiers may resolve in any order.

    ``gated_transitions()`` advances tiers strictly in ``TIERS`` order, which
    is an *under-approximation* of the runtime: ``SymbolicGovernor._run_checks()``
    dispatches the CBF and OPA checks together via ``asyncio.gather()``, so
    either may resolve first.

    This variant relaxes the ordering constraint for every tier in
    ``CONCURRENT_TIERS``: whenever the next pending tier belongs to that set,
    *any* pending concurrent tier may advance.  Every interleaving of the
    concurrent tiers — including the partial-failure states in which one has
    resolved and the other has not — therefore appears in the reachable set.

    Because this strictly adds transitions (and thus states) relative to
    ``gated_transitions()``, proving the invariant here is a strictly stronger
    result: the seal gate holds under every interleaving, not merely under the
    canonical order.
    """
    if state.phase != "CHECKING":
        yield from gated_transitions(state)
        return

    results = dict(state.tier_results)
    pending_tiers = [t for t in TIERS if results[t] == "PENDING"]

    if not pending_tiers:
        # Terminal resolution is order-independent — delegate.
        yield from gated_transitions(state)
        return

    next_tier = pending_tiers[0]
    if next_tier not in CONCURRENT_TIERS:
        yield from gated_transitions(state)
        return

    # The pipeline has reached the concurrent gate: any pending concurrent
    # tier may resolve next, in either order.
    advanceable = [t for t in pending_tiers if t in CONCURRENT_TIERS]
    for tier in advanceable:
        for outcome in ("PASS", "FAIL"):
            new_results = dict(state.tier_results)
            new_results[tier] = outcome
            new_tier_results = tuple((t, new_results[t]) for t in TIERS)

            if outcome == "FAIL":
                # Fail-closed: either concurrent check failing denies the action.
                yield State(
                    phase="DENIED",
                    tier_results=new_tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )
            else:
                yield State(
                    phase="CHECKING",
                    tier_results=new_tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )


# ---------------------------------------------------------------------------
# BFS reachable-state enumerator
# ---------------------------------------------------------------------------


def enumerate_reachable(
    transition_fn,
    start: State | None = None,
) -> set[State]:
    """BFS over the state space.  Returns the set of all reachable states."""
    if start is None:
        start = initial_state()

    visited: set[State] = set()
    frontier: list[State] = [start]

    while frontier:
        state = frontier.pop()
        if state in visited:
            continue
        visited.add(state)
        for successor in transition_fn(state):
            if successor not in visited:
                frontier.append(successor)

    return visited


# ---------------------------------------------------------------------------
# Invariant checker
# ---------------------------------------------------------------------------


def check_no_direct_bind(states: set[State]) -> tuple[bool, State | None]:
    """Check the No-Direct-Bind invariant over all states.

    Invariant: (phase = "EXECUTED") => (resolvedAllow = TRUE)

    Returns:
        (holds, counterexample) — holds=True if the invariant holds everywhere,
        counterexample is the first violating state (or None if holds=True).
    """
    for state in states:
        if state.phase == "EXECUTED" and not state.resolved_allow:
            return False, state
    return True, None


# ---------------------------------------------------------------------------
# Main — run both proofs
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 70)
    print("CAGE No-Direct-Bind Exhaustive State-Space Proof")
    print("=" * 70)
    print()

    # ── Gated architecture (correct CAGE) ────────────────────────────────────
    gated_states = enumerate_reachable(gated_transitions)
    gated_holds, gated_cex = check_no_direct_bind(gated_states)

    print(f"[gated]   Reachable states: {len(gated_states)}")
    print(
        f"[gated]   No-Direct-Bind holds over all {len(gated_states)} reachable states: {gated_holds}"
    )

    if not gated_holds:
        print(f"[gated]   ❌ COUNTEREXAMPLE FOUND: {gated_cex}")
    else:
        # Show the single EXECUTED state to confirm it has resolvedAllow=TRUE
        executed = [s for s in gated_states if s.phase == "EXECUTED"]
        print(f"[gated]   EXECUTED states: {len(executed)}")
        for s in executed:
            print(
                f"[gated]     → resolvedAllow={s.resolved_allow}  seal_present={s.seal_present}"
            )

    print()

    # ── Ungated architecture (direct-bind shortcut) ───────────────────────────
    ungated_states = enumerate_reachable(ungated_transitions)
    ungated_holds, ungated_cex = check_no_direct_bind(ungated_states)

    print(f"[ungated] Reachable states: {len(ungated_states)}")
    print(f"[ungated] No-Direct-Bind holds: {ungated_holds}")

    if ungated_cex is not None:
        print("[ungated] direct-bind shortcut produces a violation: True")
        print("[ungated] Counterexample state:")
        print(f"[ungated]   phase         = {ungated_cex.phase}")
        print(f"[ungated]   resolvedAllow = {ungated_cex.resolved_allow}")
        print(f"[ungated]   seal_present  = {ungated_cex.seal_present}")
        tier_summary = dict(ungated_cex.tier_results)
        print(f"[ungated]   tier_results  = {tier_summary}")
    else:
        print("[ungated] direct-bind shortcut produces a violation: False")
        print(
            "[ungated] ⚠️  WARNING: ungated variant did not produce a violation — "
            "check transition function."
        )

    print()

    # ── Concurrency sub-proof: CBF/OPA interleaving ───────────────────────────
    # gated_transitions() resolves tiers in a fixed order, which under-
    # approximates the runtime (asyncio.gather dispatches CBF and OPA
    # together).  concurrent_tier_transitions() explores both interleavings,
    # producing a strict superset of the gated reachable states.
    concurrent_states = enumerate_reachable(concurrent_tier_transitions)
    concurrent_holds, concurrent_cex = check_no_direct_bind(concurrent_states)
    concurrent_executed = [s for s in concurrent_states if s.phase == "EXECUTED"]

    print("Concurrency sub-proof (CBF ∥ OPA interleaving):")
    print(
        f"  Reachable states: {len(concurrent_states)} "
        f"(gated: {len(gated_states)}) — superset={gated_states <= concurrent_states}"
    )
    print(f"  No-Direct-Bind holds under every interleaving: {concurrent_holds}")
    print(
        f"  EXECUTED states: {len(concurrent_executed)} "
        f"(all with resolvedAllow=TRUE: "
        f"{all(s.resolved_allow for s in concurrent_executed)})"
    )
    if not concurrent_holds:
        print(f"  ❌ COUNTEREXAMPLE FOUND: {concurrent_cex}")
    print()

    # ── Gap-specific sub-proofs ───────────────────────────────────────────────
    print("Gap-specific sub-proofs:")
    print()

    # Gap 1: ungated architecture — the seal gate removed structurally.
    # Re-uses the ungated enumeration above; reported here so the four
    # gap-specific sub-proofs are enumerated contiguously (Gaps 1-4).
    print(
        f"  Gap 1 (no routing seal on approval): reachable states="
        f"{len(ungated_states)}, invariant holds={ungated_holds}"
    )
    print(
        "  → Violation confirmed: EXECUTED with resolvedAllow=False, seal_present=False"
    )
    print("  → Removing the seal-issuance step structurally (not merely skipping one")
    print("    tier's evaluation) yields a genuine, minimal counterexample — the")
    print("    seal gate in gated_transitions() is load-bearing.")
    print()

    # Gap 3: CBF_FAIL_OPEN — model as CBF tier always PASS regardless of check
    def cbf_fail_open_transitions(state: State) -> Iterator[State]:
        """CBF tier is skipped (always PASS) — models CBF_FAIL_OPEN=true."""
        if state.phase == "CHECKING":
            results = dict(state.tier_results)
            pending_tiers = [t for t in TIERS if results[t] == "PENDING"]
            if pending_tiers and pending_tiers[0] == "cbf":
                # Skip CBF: mark as PASS without any check
                new_results = dict(state.tier_results)
                new_results["cbf"] = "PASS"
                new_tier_results = tuple((t, new_results[t]) for t in TIERS)
                yield State(
                    phase="CHECKING",
                    tier_results=new_tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )
                return
        yield from gated_transitions(state)

    cbf_states = enumerate_reachable(cbf_fail_open_transitions)
    # CBF_FAIL_OPEN alone doesn't violate the invariant structurally (seal is
    # still issued after all remaining tiers pass), but it removes a mandatory
    # tier from the gate.  The proof here confirms the seal path is preserved
    # even with CBF skipped — the Gap 3 fix (RuntimeError at startup) prevents
    # this configuration from being reachable in production at all.
    cbf_holds, _cbf_cex = check_no_direct_bind(cbf_states)
    print(
        f"  Gap 3 (CBF_FAIL_OPEN): reachable states={len(cbf_states)}, "
        f"invariant holds={cbf_holds}"
    )
    print("  → Structural invariant preserved, but CBF tier is absent from gate.")
    print("  → Production startup RuntimeError prevents this configuration.")
    print()

    # Gap 4: DoWhy absent — causal tier always PASS (silently skipped)
    def dowhy_absent_transitions(state: State) -> Iterator[State]:
        """Causal tier is silently skipped — models DoWhy ImportError."""
        if state.phase == "CHECKING":
            results = dict(state.tier_results)
            pending_tiers = [t for t in TIERS if results[t] == "PENDING"]
            if pending_tiers and pending_tiers[0] == "causal":
                # Skip causal: mark as PASS without any check
                new_results = dict(state.tier_results)
                new_results["causal"] = "PASS"
                new_tier_results = tuple((t, new_results[t]) for t in TIERS)
                yield State(
                    phase="CHECKING",
                    tier_results=new_tier_results,
                    seal_present=False,
                    resolved_allow=False,
                )
                return
        yield from gated_transitions(state)

    dowhy_states = enumerate_reachable(dowhy_absent_transitions)
    dowhy_holds, _dowhy_cex = check_no_direct_bind(dowhy_states)
    print(
        f"  Gap 4 (DoWhy absent): reachable states={len(dowhy_states)}, "
        f"invariant holds={dowhy_holds}"
    )
    print("  → Structural invariant preserved, but causal tier is absent from gate.")
    print("  → Production startup RuntimeError prevents this configuration.")
    print()

    # Gap 2: govern() without seal — models the old path where govern() returned
    # None and callers could proceed without seal verification.
    def no_seal_govern_transitions(state: State) -> Iterator[State]:
        """govern() issues no seal — models the pre-fix direct-bind path."""
        if state.phase == "CHECKING":
            results = dict(state.tier_results)
            pending_tiers = [t for t in TIERS if results[t] == "PENDING"]
            if not pending_tiers and not state.any_tier_failed():
                # All tiers passed but no seal issued — direct bind to EXECUTED
                yield State(
                    phase="EXECUTED",
                    tier_results=state.tier_results,
                    seal_present=False,
                    resolved_allow=False,  # ← violation
                )
                return
        yield from ungated_transitions(state)

    no_seal_states = enumerate_reachable(no_seal_govern_transitions)
    no_seal_holds, no_seal_cex = check_no_direct_bind(no_seal_states)
    print(
        f"  Gap 2 (govern() no seal): reachable states={len(no_seal_states)}, "
        f"invariant holds={no_seal_holds}"
    )
    if no_seal_cex:
        print("  → Violation confirmed: EXECUTED with resolvedAllow=False")
        print("  → Fix: govern() now issues seal; callers verify before executing.")
    print()

    # ── Final assertions ──────────────────────────────────────────────────────
    print("=" * 70)
    assert gated_holds, "PROOF FAILED: gated architecture violates No-Direct-Bind!"
    assert not ungated_holds, (
        "PROOF FAILED: ungated variant should violate No-Direct-Bind!"
    )
    assert not no_seal_holds, (
        "PROOF FAILED: no-seal govern() should violate No-Direct-Bind!"
    )
    assert concurrent_holds, (
        "PROOF FAILED: No-Direct-Bind does not hold under CBF/OPA interleaving!"
    )
    assert gated_states <= concurrent_states, (
        "PROOF FAILED: the concurrent model must over-approximate the sequential one!"
    )

    print("✅ All assertions passed.")
    print()
    print("PROVED:")
    print("  1. The gated CAGE architecture satisfies No-Direct-Bind over the")
    print(f"     entire reachable state space ({len(gated_states)} states).")
    print("  2. The ungated (direct-bind) variant provably violates the invariant.")
    print("  3. The pre-fix govern() path (no seal) provably violates the invariant.")
    print("  4. The invariant is order-independent across the concurrently-")
    print(f"     evaluated CBF and OPA tiers ({len(concurrent_states)} states,")
    print("     a strict superset of the sequential model).")
    print()
    print("PLAUSIBLE (not proved here):")
    print("  That this model generalises to the full production CAGE stack.")
    print()
    print("NOT CLAIMED:")
    print("  That this is a security product or hardens any specific deployment.")


if __name__ == "__main__":
    main()
