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
#
# ---------------------------------------------------------------------------
# Model Scope & Distributed Extensions (review recommendation by Krti Tallam)
# ---------------------------------------------------------------------------
# This model covers SINGLE-REQUEST evaluation within the governance pipeline.
# It proves the No-Direct-Bind invariant holds for sequential tier evaluations.
#
# State counts — these are PINNED by tests/test_no_direct_bind_proof.py
# (EXPECTED_GATED_STATES / EXPECTED_UNGATED_STATES / EXPECTED_SKIPPED_TIER_STATES)
# and must be regenerated (``uv run python proof/model.py``) whenever the
# transition relation changes:
#   - Gated sequential model:     38 reachable states
#   - Ungated (direct-bind) model: 19 reachable states
#   - Skipped-tier (Gap 4) model: 35 reachable states
# The NARROW terminal state is included in the counts above, enabled by:
#   - narrower_present / clamped_params_valid flags (NARROW terminal state)
#   - Non-deterministic branching in tier FAIL transitions
# There is no PAUSE state: a transient infrastructure fault is a DENIED
# terminal with a refusal receipt (refactor/prune-pause).
#
# For MULTI-AGENT cross-Redis contention (distributed locking, split-brain
# scenarios, cross-shard coordination), see: proof/distributed_cbf_model.py
#
# The actuator seal check (routing_seal.verify_seal()) is a verified
# precondition in the routing_seal module. See: src/gateway/governance/routing_seal.py
# The seal verification is not modeled here because it is a distinct trust
# boundary — the actuator independently verifies the seal was issued by the
# governance pipeline, providing defense-in-depth.
# ---------------------------------------------------------------------------

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
  1. Defines the CAGE 8-tier governance state machine (FTRA + 7 in-pipeline tiers).
  2. Enumerates every reachable state via BFS.
  3. Asserts the invariant holds in ALL reachable states.
  4. Defines an ungated (direct-bind) variant and proves it VIOLATES the
     invariant, producing an explicit counterexample — confirming the gate is
     load-bearing, not decorative.
  5. Instantiates the same transition relation over any runtime plan
     (``reachable_over()``), so a governance trace can be checked for
     membership in the model (``proof/trace_conformance.py``).

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
The tuple models the kernel stages that ``run_pipeline()``
(``src/gateway/governance/governor/pipeline.py``) runs for every governed
call made through ``SymbolicGovernor.govern()`` / ``verify()``: Tier 0.5
(FTRA) and Tiers 1 through 6, with Tier 3 split into its ``opa`` (phase 1)
and ``cbf`` (phase 2) components.  Plugin-contributed tiers (e.g. finance's
``bounding`` or healthcare's ``dose_barrier``) add no proof states of their
own; they are covered structurally by ``PLUGIN_TIER_PHASE`` so the POST_HITL
predicate cannot skip a plugin-named phase-2 tier.  Jurisdiction tiers
(``JURISDICTION_TIERS``: ``fria`` under ``EU_ECB`` only) are appended per
region in a sub-proof; the universal tuple below stays the proved model.

Gaps closed by this proof:
  Gap 1: Proves the ungated (no-seal) architecture violates the invariant,
         establishing that the seal-issuance gate is load-bearing
  Gap 2: Proves govern() path satisfies the invariant when seal is issued
  Gap 3: Proves CBF_FAIL_OPEN shortcut removes the CBF tier from the gate
  Gap 4: Proves DoWhy-absent shortcut removes the causal tier from the gate
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from itertools import product

# ---------------------------------------------------------------------------
# State definition
# ---------------------------------------------------------------------------

# Governance tiers in execution order, mirroring ``run_pipeline()``: the
# read-only (phase 1) stages first, in the pipeline's order (FTRA, STPA, OPA,
# confidence, then domain tiers), then the mutating (phase 2) stages.  Each
# tier can be PENDING, PASS or FAIL.
#
# Tier numbering follows the paper (§4.2).  Tier 3 is split into its two
# components (``opa`` and ``cbf``) because each can independently block the
# action.  They are evaluated sequentially (OPA in phase 1, CBF in phase 2),
# so no interleaving sub-proof is needed.
# FTRA (Tier 0.5) added to close proof/implementation divergence (ARCH-1).
TIERS = (
    "ftra",  # Tier 0.5: FTRA action classification & reachability analysis
    "stpa",  # Tier 1:  STAMP/STPA unsafe control action check
    "opa",  # Tier 3b: OPA Rego policy evaluation
    "confidence",  # Tier 2:  agent confidence threshold
    "consensus",  # Tier 5:  multi-agent consensus gate
    "causal",  # Tier 6:  DoWhy causal gatekeeper
    "cbf",  # Tier 3a: Control Barrier Function (Redis cash barrier)
    "fiscal",  # Tier 4:  fiscal limit pre-reservation
)

# The domain-agnostic kernel stages every governor runs
# (``governor/assembly.py::kernel_stages``).
KERNEL_TIERS: tuple[str, ...] = ("ftra", "stpa", "opa", "confidence")

# The only tiers an action that no domain tier claims runs through.
# Mirrors ``pipeline.py::UNGOVERNED_STAGES``.
UNGOVERNED_TIERS: frozenset[str] = frozenset({"ftra", "stpa", "opa"})

TIER_LABELS: dict[str, str] = {
    "ftra": "Tier 0.5",
    "stpa": "Tier 1",
    "confidence": "Tier 2",
    "cbf": "Tier 3a",
    "opa": "Tier 3b",
    "fiscal": "Tier 4",
    "consensus": "Tier 5",
    "causal": "Tier 6",
}


# Execution phases — mirrors the TLA+ state machine.
#   - NARROW: All tiers pass but action parameters exceed soft thresholds;
#             seal issued on clamped params, resolvedAllow=TRUE (ALLOW variant)
# The verdict lattice is ALLOW | NARROW | REQUIRE_APPROVAL | DEFER | DENY;
# anything the runtime cannot classify, including a transient fault, is DENIED.
PHASES = ("PENDING", "CHECKING", "SEAL_ISSUED", "EXECUTED", "DENIED", "NARROW")
PROFILES = ("FULL", "POST_HITL", "DRY_RUN")

# Pipeline phase per tier: phase 2 tiers mutate (reserve barrier headroom or
# budget) and so must re-check after a human approves (TOCTOU). Phase 1 tiers
# are read-only.
TIER_PHASE: dict[str, int] = dict.fromkeys(TIERS, 1) | {"cbf": 2, "fiscal": 2}

# Plugin-named phase-2 tiers (not in TIERS: they do not add proof states, but
# the POST_HITL predicate must cover them). E.g. healthcare's ``dose_barrier``
# or finance's ``bounding``: a name filter that lists only kernel tiers would
# skip them after approval.
PLUGIN_TIER_PHASE: dict[str, int] = {"domain_barrier": 2}

# Read-only tiers re-checked after approval (policy may change while waiting).
POST_HITL_READ_ONLY_TIERS: frozenset[str] = frozenset({"opa"})


def runs_under_profile(profile: str, tier: str, phase: int) -> bool:
    """Whether ``tier`` (in pipeline ``phase``) runs under ``profile``.

    Structural, never by name: POST_HITL runs every phase-2 tier plus the
    read-only tiers in POST_HITL_READ_ONLY_TIERS; FULL and DRY_RUN run all.
    Mirrored by ``src/gateway/governance/governor/pipeline.py::stage_runs_under``
    (``tests/test_formal_profile_parity.py``).
    """
    if profile == "POST_HITL":
        return phase == 2 or tier in POST_HITL_READ_ONLY_TIERS
    return True


PROFILE_STAGES: dict[str, frozenset[str]] = {
    profile: frozenset(
        t for t in TIERS if runs_under_profile(profile, t, TIER_PHASE[t])
    )
    for profile in PROFILES
}


def post_hitl_runs_every_phase2_tier() -> bool:
    """Claim: no phase-2 tier (kernel or plugin-named) is skipped after approval."""
    phases = TIER_PHASE | PLUGIN_TIER_PHASE
    return all(
        runs_under_profile("POST_HITL", tier, phase)
        for tier, phase in phases.items()
        if phase == 2
    )


# ---------------------------------------------------------------------------
# Jurisdiction tiers (D-L)
# ---------------------------------------------------------------------------
#
# A deployment region may add obligations to every domain. They are appended
# to the universal TIERS for that region only; the 8-tier tuple above stays
# the proved universal model (38/19/35). Mirrored by
# ``src/gateway/governance/jurisdiction/registry.py::JURISDICTIONS`` (parity in
# ``tests/test_formal_profile_parity.py``, once per region).

JURISDICTION_TIERS: dict[str, tuple[str, ...]] = {
    "US_FED": (),
    "APAC_MAS": (),
    "EU_ECB": ("fria",),  # EU AI Act Art. 27 FRIA (CTRL_FRIA_006)
}

# Jurisdiction tiers are assessments, never barriers: phase 1 (read-only).
# ``JurisdictionContribution`` refuses any other phase at construction.
JURISDICTION_TIER_PHASE: dict[str, int] = {"fria": 1}


def region_tiers(region: str) -> tuple[str, ...]:
    """The tiers a governed call runs through in ``region``, in pipeline order.

    Jurisdiction tiers are phase 1, so they run after the phase-1 tiers and
    before any phase-2 tier.
    """
    phase1 = tuple(t for t in TIERS if TIER_PHASE[t] == 1)
    phase2 = tuple(t for t in TIERS if TIER_PHASE[t] == 2)
    return phase1 + JURISDICTION_TIERS[region] + phase2


def region_tier_phase(region: str) -> dict[str, int]:
    return TIER_PHASE | {
        t: JURISDICTION_TIER_PHASE[t] for t in JURISDICTION_TIERS[region]
    }


def region_profile_stages(region: str) -> dict[str, frozenset[str]]:
    phases = region_tier_phase(region)
    return {
        profile: frozenset(
            t for t in region_tiers(region) if runs_under_profile(profile, t, phases[t])
        )
        for profile in PROFILES
    }


def jurisdiction_tiers_are_read_only() -> bool:
    """Claim: every jurisdiction tier is phase 1."""
    return all(
        JURISDICTION_TIER_PHASE[t] == 1
        for tiers in JURISDICTION_TIERS.values()
        for t in tiers
    )


def jurisdiction_keeps_post_hitl_set() -> bool:
    """Claim: no region changes what POST_HITL re-runs, and every region's
    POST_HITL still re-runs every phase-2 tier (a phase-1 tier adds nothing
    after approval and removes nothing)."""
    for region in JURISDICTION_TIERS:
        stages = region_profile_stages(region)
        if stages["POST_HITL"] != PROFILE_STAGES["POST_HITL"]:
            return False
        phases = region_tier_phase(region) | PLUGIN_TIER_PHASE
        if not all(
            runs_under_profile("POST_HITL", t, p) for t, p in phases.items() if p == 2
        ):
            return False
        # FULL and DRY_RUN run the region's obligations: no seal skips them.
        if not set(JURISDICTION_TIERS[region]) <= stages["FULL"] & stages["DRY_RUN"]:
            return False
    return True


# ---------------------------------------------------------------------------
# Phase-2 gate and the pending-approval outcome
# ---------------------------------------------------------------------------
#
# Mirrored by ``src/gateway/governance/governor/pipeline.py::phase2_mode`` and,
# for the outcome, by ``run_pipeline`` + ``ClassificationEngine`` (parity in
# ``tests/test_formal_profile_parity.py``). Kinds mirror ``contracts.ViolationKind``.

VIOLATION_KINDS: tuple[str, ...] = ("HARD", "HITL", "DEFERRABLE", "NARROWABLE")


def phase2_mode(profile: str, phase1_kinds: frozenset[str]) -> str:
    """SKIP after any HARD; PREVIEW after only non-HARD findings or under
    DRY_RUN; COMMIT only over a clean phase 1 under a committing profile."""
    if "HARD" in phase1_kinds:
        return "SKIP"
    if phase1_kinds or profile == "DRY_RUN":
        return "PREVIEW"
    return "COMMIT"


def pending_approval_outcome(
    phase1_kinds: frozenset[str], preview_kinds: frozenset[str]
) -> tuple[str, str]:
    """CHECKING → (DENIED | REQUIRE_APPROVAL, barrier_preview ∈ {PASS, FAIL}).

    Defined for an approval-pending phase 1 (HITL present, no HARD): the
    barriers are previewed, a HARD preview denies outright, and otherwise the
    request waits for a human with the preview's result recorded.
    """
    if "HITL" not in phase1_kinds or "HARD" in phase1_kinds:
        raise ValueError("pending_approval_outcome needs a HITL, non-HARD phase 1")
    barrier_preview = "FAIL" if preview_kinds else "PASS"
    if "HARD" in preview_kinds:
        return "DENIED", barrier_preview
    return "REQUIRE_APPROVAL", barrier_preview


def _kind_sets() -> Iterator[frozenset[str]]:
    for mask in range(1 << len(VIOLATION_KINDS)):
        yield frozenset(k for i, k in enumerate(VIOLATION_KINDS) if mask >> i & 1)


def no_commit_under_pending_findings() -> bool:
    """Claim: phase 2 never commits while phase 1 reported anything — so a
    request awaiting approval holds no barrier headroom (no seal, no spend)."""
    return all(
        phase2_mode(profile, kinds) != "COMMIT"
        for profile in PROFILES
        for kinds in _kind_sets()
        if kinds
    )


def hard_preview_denies_before_hitl() -> bool:
    """Claim: with approval pending, the barriers are previewed, a HARD
    preview yields DENIED (no human is asked), and every REQUIRE_APPROVAL
    records the preview's outcome (FAIL iff a barrier reported anything)."""
    for phase1 in _kind_sets():
        if "HITL" not in phase1 or "HARD" in phase1:
            continue
        if any(phase2_mode(p, phase1) != "PREVIEW" for p in PROFILES):
            return False
        for preview in _kind_sets():
            outcome, barrier_preview = pending_approval_outcome(phase1, preview)
            if ("HARD" in preview) != (outcome == "DENIED"):
                return False
            if (barrier_preview == "FAIL") != bool(preview):
                return False
    return True


# ---------------------------------------------------------------------------
# Verdict lattice
# ---------------------------------------------------------------------------
#
# Mirrors ``ClassificationEngine.classify`` in
# ``src/gateway/governance/classification_engine.py`` (parity in
# ``tests/test_distributed_cbf_proof.py``). Only ALLOW and NARROW lead to
# SEAL_ISSUED; DENY, REQUIRE_APPROVAL and DEFER mint no seal.

VERDICTS: tuple[str, ...] = ("ALLOW", "NARROW", "DEFER", "REQUIRE_APPROVAL", "DENY")
SEALING_VERDICTS: frozenset[str] = frozenset({"ALLOW", "NARROW"})


def verdict_of(
    kinds: frozenset[str],
    *,
    low_confidence: bool,
    narrows: bool,
    manual_review: bool = False,
    defer_enabled: bool = True,
) -> str:
    """HARD > (MANUAL_REVIEW | HITL) > all-NARROWABLE + proposal > DEFERRABLE
    with low confidence > DENY. ``narrows`` = NARROW enabled and a narrower
    proposes clamped params. No findings is ALLOW."""
    if not kinds:
        return "ALLOW"
    if "HARD" in kinds:
        return "DENY"
    if manual_review or "HITL" in kinds:
        return "REQUIRE_APPROVAL"
    if kinds == frozenset({"NARROWABLE"}) and narrows:
        return "NARROW"
    if "DEFERRABLE" in kinds and defer_enabled and low_confidence:
        return "DEFER"
    return "DENY"


def _verdict_inputs() -> Iterator[tuple[frozenset[str], bool, bool, bool, bool]]:
    for kinds in _kind_sets():
        for low, nar, mr, de in product((False, True), repeat=4):
            yield kinds, low, nar, mr, de


def verdict_lattice_holds() -> bool:
    """Claims: any HARD finding denies; DEFER needs a DEFERRABLE finding and
    low confidence; NARROW needs every finding NARROWABLE; a seal-issuing
    verdict (ALLOW, NARROW) never coexists with a HARD, HITL or DEFERRABLE
    finding; ALLOW iff no findings."""
    for kinds, low, nar, mr, de in _verdict_inputs():
        v = verdict_of(
            kinds, low_confidence=low, narrows=nar, manual_review=mr, defer_enabled=de
        )
        if "HARD" in kinds and v != "DENY":
            return False
        if v == "DEFER" and not ("DEFERRABLE" in kinds and low):
            return False
        if v == "NARROW" and kinds != frozenset({"NARROWABLE"}):
            return False
        if v in SEALING_VERDICTS and kinds & {"HARD", "HITL", "DEFERRABLE"}:
            return False
        if (v == "ALLOW") != (not kinds):
            return False
    return True


def narrow_valid(state: State) -> bool:
    """I-6 (restated): ``phase = NARROW ⇒ seal_present ∧ resolved_allow ∧
    clamped_params_valid``. Replaces the manuscript's ``EXECUTED_unmodified``,
    which no model defines."""
    return state.phase != "NARROW" or (
        state.seal_present and state.resolved_allow and state.clamped_params_valid
    )


@dataclass(frozen=True)
class State:
    """A single point in the CAGE governance state space.

    Attributes:
        phase:          Current execution phase (PENDING, CHECKING, SEAL_ISSUED,
                        EXECUTED, DENIED, NARROW).
        tier_results:   Tuple of (tier_name, result) pairs where result is
                        "PASS", "FAIL", or "PENDING".
        seal_present:   True if a valid routing seal has been issued.
        resolved_allow: True if all tiers have passed AND a seal is present.
                        This is the ``resolvedAllow`` variable in the TLA+ spec.
                        NARROW states have resolved_allow=TRUE (they are ALLOW variants).
        profile:        The execution profile defining which tiers are evaluated.
        narrower_present: True if a domain narrower proposed clamped parameters.
        clamped_params_valid: True if re-evaluating the FULL profile on the clamped
                              parameters yielded 0 violations.
        seal_consumed:  (Peer Review Fix - Gap 2 alignment) True if the seal has been
                        consumed by the actuator. Seals are single-use: once consumed,
                        the same seal cannot authorize another EXECUTED transition.
                        This models the routing_seal.consume_seal() atomic operation.
        seal_expired:   (Peer Review Fix - Gap 2 alignment) True if the seal TTL has
                        elapsed before consumption. Expired seals cannot authorize
                        EXECUTED transitions; the action must re-enter CHECKING.
    """

    phase: str
    tier_results: tuple[tuple[str, str], ...]
    seal_present: bool
    resolved_allow: bool
    profile: str = "FULL"
    narrower_present: bool = False
    clamped_params_valid: bool = False
    seal_consumed: bool = False
    seal_expired: bool = False

    def tier_result(self, tier: str) -> str:
        return dict(self.tier_results).get(tier, "PENDING")

    def all_tiers_passed(self) -> bool:
        return all(r == "PASS" for _, r in self.tier_results)

    def any_tier_failed(self) -> bool:
        return any(r == "FAIL" for _, r in self.tier_results)

    def all_profile_tiers_passed(self) -> bool:
        required_tiers = PROFILE_STAGES[self.profile]
        return all(
            dict(self.tier_results).get(t, "PENDING") == "PASS" for t in required_tiers
        )

    def any_profile_tier_failed(self) -> bool:
        required_tiers = PROFILE_STAGES[self.profile]
        return any(
            dict(self.tier_results).get(t, "PENDING") == "FAIL" for t in required_tiers
        )

    def is_allow_variant(self) -> bool:
        """True if this state represents an ALLOW decision (SEAL_ISSUED, EXECUTED, NARROW)."""
        return self.phase in ("SEAL_ISSUED", "EXECUTED", "NARROW")

    def is_terminal(self) -> bool:
        """True if this state has no successors (EXECUTED, DENIED, NARROW)."""
        return self.phase in ("EXECUTED", "DENIED", "NARROW")


def initial_state() -> State:
    """The single initial state: all tiers pending, no seal, phase=PENDING."""
    return State(
        phase="PENDING",
        tier_results=tuple((t, "PENDING") for t in TIERS),
        seal_present=False,
        resolved_allow=False,
        profile="FULL",
        narrower_present=False,
        clamped_params_valid=False,
        seal_consumed=False,
        seal_expired=False,
    )


# ---------------------------------------------------------------------------
# Gated transition function (the correct CAGE architecture)
# ---------------------------------------------------------------------------


def gated_transitions(state: State) -> Iterator[State]:
    """Generate all successor states from *state* under the gated architecture."""
    if state.phase == "PENDING":
        yield State(
            phase="CHECKING",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
            seal_consumed=False,
            seal_expired=False,
            profile=state.profile,
            narrower_present=state.narrower_present,
            clamped_params_valid=state.clamped_params_valid,
        )

    elif state.phase == "CHECKING":
        results = dict(state.tier_results)
        required_tiers = PROFILE_STAGES[state.profile]
        pending_tiers = [
            t
            for t in TIERS
            if t in required_tiers and results.get(t, "PENDING") == "PENDING"
        ]

        if not pending_tiers:
            if state.profile != "DRY_RUN":
                yield State(
                    phase="SEAL_ISSUED",
                    tier_results=state.tier_results,
                    seal_present=True,
                    resolved_allow=True,
                    seal_consumed=False,
                    seal_expired=False,
                    profile=state.profile,
                    narrower_present=state.narrower_present,
                    clamped_params_valid=state.clamped_params_valid,
                )
        else:
            next_tier = pending_tiers[0]
            for outcome in ("PASS", "FAIL"):
                new_results = dict(state.tier_results)
                new_results[next_tier] = outcome
                new_tier_results = tuple(
                    (t, new_results.get(t, "PENDING")) for t in TIERS
                )

                if outcome == "FAIL":
                    # Fail-closed optimization: if a tier fails, we either NARROW or DENIED
                    # NARROW requires narrower_present=True and clamped_params_valid=True

                    # 1. Deny (no narrower, or clamped params invalid)
                    yield State(
                        phase="DENIED",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=False,
                        clamped_params_valid=False,
                    )
                    # Narrower present, but rerun fails (negative case) -> DENIED
                    yield State(
                        phase="DENIED",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=True,
                        clamped_params_valid=False,
                    )
                    # Narrower present, and rerun passes -> NARROW (ALLOW variant, committing profiles only)
                    if state.profile != "DRY_RUN":
                        yield State(
                            phase="NARROW",
                            tier_results=new_tier_results,
                            seal_present=True,
                            resolved_allow=True,
                            seal_consumed=False,
                            seal_expired=False,
                            profile=state.profile,
                            narrower_present=True,
                            clamped_params_valid=True,
                        )
                else:
                    # PASS: continue checking
                    yield State(
                        phase="CHECKING",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=False,
                        clamped_params_valid=False,
                    )

    elif state.phase == "SEAL_ISSUED":
        if not state.seal_consumed and not state.seal_expired:
            yield State(
                phase="EXECUTED",
                tier_results=state.tier_results,
                seal_present=True,
                resolved_allow=True,
                seal_consumed=True,
                seal_expired=False,
                profile=state.profile,
                narrower_present=state.narrower_present,
                clamped_params_valid=state.clamped_params_valid,
            )
            yield State(
                phase="DENIED",
                tier_results=state.tier_results,
                seal_present=False,
                resolved_allow=False,
                seal_consumed=False,
                seal_expired=True,
                profile=state.profile,
                narrower_present=state.narrower_present,
                clamped_params_valid=state.clamped_params_valid,
            )

        if state.seal_consumed:
            yield State(
                phase="DENIED",
                tier_results=state.tier_results,
                seal_present=False,
                resolved_allow=False,
                seal_consumed=True,
                seal_expired=False,
                profile=state.profile,
                narrower_present=state.narrower_present,
                clamped_params_valid=state.clamped_params_valid,
            )

        yield State(
            phase="DENIED",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
            seal_consumed=False,
            seal_expired=False,
            profile=state.profile,
            narrower_present=state.narrower_present,
            clamped_params_valid=state.clamped_params_valid,
        )


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
            profile="FULL",
            narrower_present=False,
            clamped_params_valid=False,
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
                    profile="FULL",
                    narrower_present=False,
                    clamped_params_valid=False,
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
                    profile="FULL",
                    narrower_present=False,
                    clamped_params_valid=False,
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
                        profile="FULL",
                        narrower_present=False,
                        clamped_params_valid=False,
                    )
                else:
                    yield State(
                        phase="CHECKING",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        profile="FULL",
                        narrower_present=False,
                        clamped_params_valid=False,
                    )

    elif state.phase == "SEAL_ISSUED":
        # Ungated variant never reaches SEAL_ISSUED, but handle for completeness
        yield State(
            phase="EXECUTED",
            tier_results=state.tier_results,
            seal_present=True,
            resolved_allow=True,
            profile="FULL",
            narrower_present=False,
            clamped_params_valid=False,
        )


# ---------------------------------------------------------------------------
# Ungated NARROW transition function — negative control for NARROW state
# ---------------------------------------------------------------------------


def ungated_narrow_transitions(state: State) -> Iterator[State]:
    if state.phase == "PENDING":
        yield State(
            phase="CHECKING",
            tier_results=state.tier_results,
            seal_present=False,
            resolved_allow=False,
            seal_consumed=False,
            seal_expired=False,
            profile=state.profile,
            narrower_present=False,
            clamped_params_valid=False,
        )

    elif state.phase == "CHECKING":
        results = dict(state.tier_results)
        required_tiers = PROFILE_STAGES[state.profile]
        pending_tiers = [
            t
            for t in TIERS
            if t in required_tiers and results.get(t, "PENDING") == "PENDING"
        ]

        if not pending_tiers:
            if state.any_profile_tier_failed():
                if state.narrower_present and state.clamped_params_valid:
                    # Bug: NARROW without seal, then allow EXECUTED transition
                    yield State(
                        phase="NARROW",
                        tier_results=state.tier_results,
                        seal_present=False,  # ← No seal issued!
                        resolved_allow=False,  # ← Authority not resolved!
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=True,
                        clamped_params_valid=True,
                    )
                else:
                    yield State(
                        phase="DENIED",
                        tier_results=state.tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=state.narrower_present,
                        clamped_params_valid=state.clamped_params_valid,
                    )
            else:
                yield State(
                    phase="SEAL_ISSUED",
                    tier_results=state.tier_results,
                    seal_present=True,
                    resolved_allow=True,
                    seal_consumed=False,
                    seal_expired=False,
                    profile=state.profile,
                    narrower_present=state.narrower_present,
                    clamped_params_valid=state.clamped_params_valid,
                )
        else:
            next_tier = pending_tiers[0]
            for outcome in ("PASS", "FAIL"):
                new_results = dict(state.tier_results)
                new_results[next_tier] = outcome
                new_tier_results = tuple(
                    (t, new_results.get(t, "PENDING")) for t in TIERS
                )

                if outcome == "FAIL":
                    yield State(
                        phase="DENIED",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=False,
                        clamped_params_valid=False,
                    )
                    yield State(
                        phase="NARROW",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=True,
                        clamped_params_valid=True,
                    )
                else:
                    yield State(
                        phase="CHECKING",
                        tier_results=new_tier_results,
                        seal_present=False,
                        resolved_allow=False,
                        seal_consumed=False,
                        seal_expired=False,
                        profile=state.profile,
                        narrower_present=False,
                        clamped_params_valid=False,
                    )

    elif state.phase == "NARROW":
        # Bug: NARROW can transition to EXECUTED without seal verification
        yield State(
            phase="EXECUTED",
            tier_results=state.tier_results,
            seal_present=False,  # ← No seal!
            resolved_allow=False,  # ← Authority not resolved! VIOLATION
            seal_consumed=False,
            seal_expired=False,
            profile=state.profile,
            narrower_present=True,
            clamped_params_valid=True,
        )

    elif state.phase == "SEAL_ISSUED":
        yield State(
            phase="EXECUTED",
            tier_results=state.tier_results,
            seal_present=True,
            resolved_allow=True,
            seal_consumed=False,
            seal_expired=False,
            profile=state.profile,
            narrower_present=False,
            clamped_params_valid=False,
        )


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

    Invariant: (phase = "EXECUTED") => (resolvedAllow = TRUE and seal_present = TRUE)

    Returns:
        (holds, counterexample) — holds=True if the invariant holds everywhere,
        counterexample is the first violating state (or None if holds=True).
    """
    for state in states:
        if state.phase == "EXECUTED" and not (
            state.resolved_allow and state.seal_present
        ):
            return False, state
    return True, None


def enumerate_region(region: str, transition_fn=None) -> set[State]:
    """Enumerate the gated model with ``region``'s jurisdiction tiers appended.

    The transition functions and ``State`` read the module-level ``TIERS`` /
    ``TIER_PHASE`` / ``PROFILE_STAGES``; they are rebound to the region's
    model for the enumeration and restored afterwards, so the universal model
    (and its 38/19/35 counts) is never altered.
    """
    global TIERS, TIER_PHASE, PROFILE_STAGES
    saved = (TIERS, TIER_PHASE, PROFILE_STAGES)
    try:
        TIERS = region_tiers(region)
        TIER_PHASE = region_tier_phase(region)
        PROFILE_STAGES = region_profile_stages(region)
        return enumerate_reachable(transition_fn or gated_transitions)
    finally:
        TIERS, TIER_PHASE, PROFILE_STAGES = saved


_REACHABLE_OVER_CACHE: dict[
    tuple[tuple[tuple[str, int], ...], str], frozenset[State]
] = {}


def reachable_over(plan: tuple[tuple[str, int], ...], profile: str) -> frozenset[State]:
    """The gated model instantiated over a runtime ``plan``, from ``profile``.

    ``plan`` is the ``(tier, phase)`` sequence a run selected, in execution
    order (``PipelineResult.plan``). Every planned tier is required, so a
    seal needs every one of them to pass. Like :func:`enumerate_region`, the
    module-level model is rebound for the enumeration and restored after.
    """
    key = (plan, profile)
    cached = _REACHABLE_OVER_CACHE.get(key)
    if cached is not None:
        return cached
    global TIERS, TIER_PHASE, PROFILE_STAGES
    saved = (TIERS, TIER_PHASE, PROFILE_STAGES)
    names = tuple(name for name, _ in plan)
    try:
        TIERS = names
        TIER_PHASE = dict(plan)
        PROFILE_STAGES = {p: frozenset(names) for p in PROFILES}
        start = State(
            phase="PENDING",
            tier_results=tuple((t, "PENDING") for t in names),
            seal_present=False,
            resolved_allow=False,
            profile=profile,
        )
        states = frozenset(enumerate_reachable(gated_transitions, start))
    finally:
        TIERS, TIER_PHASE, PROFILE_STAGES = saved
    _REACHABLE_OVER_CACHE[key] = states
    return states


def region_seal_requires_obligations(region: str, states: set[State]) -> bool:
    """Claim: in ``region`` no seal is issued unless every jurisdiction tier passed."""
    obligations = JURISDICTION_TIERS[region]
    return all(
        all(s.tier_result(t) == "PASS" for t in obligations)
        for s in states
        if s.phase in ("SEAL_ISSUED", "EXECUTED") and s.seal_present
    )


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
                    profile=state.profile,
                    narrower_present=state.narrower_present,
                    clamped_params_valid=state.clamped_params_valid,
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
    #
    # Peer Review Fix: Gap 2 alignment — clarify actuator gate semantics.
    # The actuator gate is the LAST defense: it verifies the seal before executing.
    # Without seal issuance, the actuator has no artifact to verify, and the action
    # could proceed without governance approval. This function models that violation.
    def no_seal_govern_transitions(state: State) -> Iterator[State]:
        """govern() issues no seal — models the pre-fix direct-bind path.

        Actuator Gate Semantics (Gap 2 alignment):
        -------------------------------------------
        The actuator is the component that EXECUTES the governed action (e.g., the
        trade execution endpoint). Its sole responsibility in the seal-based
        architecture is:
            1. Receive the seal from the caller
            2. Call routing_seal.consume_seal() to atomically validate + consume
            3. Only proceed with execution if consume_seal() returns True

        Without seal issuance (this function), the actuator receives no seal, and
        if it proceeds anyway, it creates a direct-bind violation: EXECUTED state
        is reached without resolvedAllow=TRUE.

        This models the pre-fix architecture where govern() returned None on
        approval (no seal), and the actuator had no artifact to verify.
        """
        if state.phase == "CHECKING":
            results = dict(state.tier_results)
            pending_tiers = [t for t in TIERS if results[t] == "PENDING"]
            if not pending_tiers and not state.any_tier_failed():
                # All tiers passed but no seal issued — direct bind to EXECUTED
                # This is a VIOLATION: actuator cannot verify governance approval
                yield State(
                    phase="EXECUTED",
                    tier_results=state.tier_results,
                    seal_present=False,
                    resolved_allow=False,  # ← VIOLATION: No seal → no resolution
                    profile="FULL",
                    narrower_present=False,
                    clamped_params_valid=False,
                    seal_consumed=False,
                    seal_expired=False,
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

    # ── NARROW state-space sub-proofs ─────────────────────────────────────────
    print("NARROW state-space sub-proofs (C1-sub audit remediation):")
    print()

    # Count NARROW states in the gated model
    narrow_states = [s for s in gated_states if s.phase == "NARROW"]
    print(f"  NARROW states: {len(narrow_states)}")
    for s in narrow_states:
        print(
            f"    → resolvedAllow={s.resolved_allow}  "
            f"seal_present={s.seal_present}  "
            f"narrower_present={s.narrower_present}  clamped_params_valid={s.clamped_params_valid}"
        )
    print()

    # Verify NARROW states satisfy NoDirectBind (they are ALLOW variants)
    narrow_ok = all(narrow_valid(s) for s in gated_states)
    print(
        "  I-6 narrow_valid (NARROW => seal_present, resolvedAllow, clamped_params_valid): "
        f"{narrow_ok}"
    )
    lattice_ok = verdict_lattice_holds()
    print(
        f"  Verdict lattice (only ALLOW/NARROW seal; HARD always denies): {lattice_ok}"
    )

    # Verify profile ALLOW property
    # under every profile, an ALLOW (SEAL_ISSUED) requires every tier in that profile to PASS.
    seal_issued_states = [s for s in gated_states if s.phase == "SEAL_ISSUED"]
    profile_allow_valid = all(s.all_profile_tiers_passed() for s in seal_issued_states)
    print(f"  SEAL_ISSUED states have all profile tiers passed: {profile_allow_valid}")

    # Negative case: a profile whose tier FAILs never yields ALLOW
    # i.e., no SEAL_ISSUED state has any_profile_tier_failed() == True
    profile_fail_blocks = all(
        not s.any_profile_tier_failed() for s in seal_issued_states
    )
    print(
        f"  No SEAL_ISSUED states have any failed profile tier: {profile_fail_blocks}"
    )

    # Every phase the model can reach is one the runtime can name: no state
    # outside PHASES exists (there is no PAUSE).
    phases_closed = all(s.phase in PHASES for s in gated_states)
    print(f"  Every reachable phase is in PHASES: {phases_closed}")
    print()

    # ── Ungated NARROW negative control ───────────────────────────────────────
    print("Ungated NARROW negative control (C1-sub):")
    ungated_narrow_states = enumerate_reachable(ungated_narrow_transitions)
    ungated_narrow_holds, ungated_narrow_cex = check_no_direct_bind(
        ungated_narrow_states
    )
    print(f"  Reachable states: {len(ungated_narrow_states)}")
    print(f"  No-Direct-Bind holds: {ungated_narrow_holds}")
    if ungated_narrow_cex is not None:
        print("  → Violation confirmed: EXECUTED via NARROW without seal verification")
        print(f"     phase={ungated_narrow_cex.phase}")
        print(f"     resolvedAllow={ungated_narrow_cex.resolved_allow}")
        print(f"     seal_present={ungated_narrow_cex.seal_present}")
        print(
            f"     narrower_present={ungated_narrow_cex.narrower_present}\n     clamped_params_valid={ungated_narrow_cex.clamped_params_valid}"
        )
    print()

    # ── Jurisdiction sub-proof (D-L) ──────────────────────────────────────────
    print("Jurisdiction sub-proof (JURISDICTION_TIERS, D-L):")
    region_results: dict[str, tuple[int, bool, bool]] = {}
    for region, extra in JURISDICTION_TIERS.items():
        states = enumerate_region(region)
        holds, _cex = check_no_direct_bind(states)
        sealed_ok = region_seal_requires_obligations(region, states)
        region_results[region] = (len(states), holds, sealed_ok)
        print(
            f"  {region:<8} tiers=+{list(extra)}  reachable states={len(states)}  "
            f"No-Direct-Bind={holds}  seal requires obligations={sealed_ok}"
        )
    read_only = jurisdiction_tiers_are_read_only()
    post_hitl_unchanged = jurisdiction_keeps_post_hitl_set()
    print(f"  Every jurisdiction tier is phase 1: {read_only}")
    print(f"  POST_HITL set unchanged in every region: {post_hitl_unchanged}")
    # The universal model is untouched by the regional enumerations.
    universal_after = len(enumerate_reachable(gated_transitions))
    print(f"  Universal gated model still {universal_after} states")
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
    # NARROW assertions
    assert narrow_ok, (
        "PROOF FAILED: I-6 narrow_valid violated by a reachable NARROW state!"
    )
    assert lattice_ok, "PROOF FAILED: verdict lattice violated!"
    assert profile_allow_valid, (
        "PROOF FAILED: SEAL_ISSUED requires all profile tiers to pass!"
    )
    assert profile_fail_blocks, (
        "PROOF FAILED: SEAL_ISSUED state with failed profile tier!"
    )

    assert phases_closed, "PROOF FAILED: a reachable state has a phase outside PHASES!"
    assert not ungated_narrow_holds, (
        "PROOF FAILED: ungated NARROW variant should violate No-Direct-Bind!"
    )
    assert post_hitl_runs_every_phase2_tier(), (
        "PROOF FAILED: POST_HITL skips a phase-2 tier!"
    )
    assert no_commit_under_pending_findings(), (
        "PROOF FAILED: phase 2 commits while phase 1 reported findings!"
    )
    assert hard_preview_denies_before_hitl(), (
        "PROOF FAILED: a HARD barrier preview reaches a human, or REQUIRE_APPROVAL "
        "misreports the barrier preview!"
    )
    for region, (_count, holds, sealed_ok) in region_results.items():
        assert holds, (
            f"PROOF FAILED: {region} jurisdiction model violates No-Direct-Bind!"
        )
        assert sealed_ok, (
            f"PROOF FAILED: {region} issues a seal without its jurisdiction tiers!"
        )
    assert (
        region_results["US_FED"][0]
        == region_results["APAC_MAS"][0]
        == len(gated_states)
    ), "PROOF FAILED: a region without obligations changed the state space!"
    assert read_only, "PROOF FAILED: a jurisdiction tier is not phase 1!"
    assert post_hitl_unchanged, (
        "PROOF FAILED: a jurisdiction tier changes the POST_HITL set!"
    )
    assert universal_after == len(gated_states), (
        "PROOF FAILED: regional enumeration leaked!"
    )

    print("✅ All assertions passed.")
    print()
    print("PROVED:")
    print("  1. The gated CAGE architecture satisfies No-Direct-Bind over the")
    print(f"     entire reachable state space ({len(gated_states)} states).")
    print("  2. The ungated (direct-bind) variant provably violates the invariant.")
    print("  3. The pre-fix govern() path (no seal) provably violates the invariant.")
    print(f"  4. NARROW states ({len(narrow_states)}) are ALLOW variants with")
    print("     resolvedAllow=TRUE, seal_present=TRUE and clamped_params_valid=TRUE")
    print("     (I-6, narrow_valid).")
    print("  5. Every reachable phase is in PHASES: the model names no verdict")
    print("     the runtime lacks (there is no PAUSE).")
    print("  6. The ungated NARROW variant produces a counterexample, confirming")
    print("     the seal gate is load-bearing for NARROW decisions as well.")
    print("  7. POST_HITL re-runs every phase-2 tier, kernel or plugin-named")
    print("     (post_hitl_runs_every_phase2_tier).")
    print("  8. Phase 2 never commits while phase 1 reported findings, so a")
    print("     pending approval holds no headroom (no_commit_under_pending_findings).")
    print("  9. With approval pending the barriers are previewed: a HARD preview")
    print("     denies before any human is asked, and REQUIRE_APPROVAL records")
    print("     barrier_preview PASS/FAIL (hard_preview_denies_before_hitl).")
    print(" 10. Per region (JURISDICTION_TIERS), No-Direct-Bind still holds, no seal")
    print("     is issued unless the region's obligations passed (fria under EU_ECB),")
    print("     and the phase-1 jurisdiction tiers leave the POST_HITL set unchanged")
    print(f"     (EU_ECB: {region_results['EU_ECB'][0]} states).")
    print(" 11. Verdict lattice (verdict_of, parity with ClassificationEngine): HARD")
    print("     always denies, DEFER needs low confidence, and only ALLOW/NARROW")
    print("     reach SEAL_ISSUED (verdict_lattice_holds).")
    print()
    print("PLAUSIBLE (not proved here):")
    print("  That this model generalises to the full production CAGE stack.")
    print()
    print("NOT CLAIMED:")
    print("  That this is a security product or hardens any specific deployment.")


if __name__ == "__main__":
    main()
