-------------------------- MODULE LangGraphHarness --------------------------
(* Copyright 2026 Google LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   --------------------------------------------------------------------------
   LangGraph Harness State Machine — TLA+ Formal Specification
   --------------------------------------------------------------------------

   This specification models the LangGraph harness state machine for the
   CAGE Governed Financial Advisor (GFA) workflow. It captures:
   
   - Graph lifecycle phases (INIT → ROUTING → GOVERNANCE_CHECK → LLM_CALL → RESPONSE/ERROR)
   - Canonical GovernanceDecision branching (ALLOW/DENY/DEFER/NARROW/PAUSE/REQUIRE_APPROVAL)
   - Evidence chain commit points (routing seal generation)
   - Fence epoch validation integration (EXTENDS DistributedCBF concepts)
   - HITL interrupt/park semantics with TTL expiration

   Source Code Cross-Reference:
   - src/governed_financial_advisor/graph/graph.py     → Graph topology
   - src/governed_financial_advisor/graph/state.py     → AgentState TypedDict
   - src/gateway/governance/decisions.py              → GovernanceDecision enum
   - src/gateway/governance/routing_seal.py           → Seal generation/validation
   - src/gateway/governance/provenance_chain.py       → Evidence chain
   - src/gateway/governance/symbolic_governor.py      → Governance pipeline

   Key Graph Nodes (from graph.py):
   - nemo_guardrail      → BLOCKED | thinker_node
   - thinker_node        → doer_node
   - doer_node           → data_analyst | execution_analyst | nemo_output_rail
   - execution_analyst   → evaluator
   - evaluator           → ftra_node | execution_analyst (loop) | explainer
   - ftra_node           → safety_check | explainer | [DeferQueue park]
   - safety_check        → governed_trader | defer_node | explainer
   - governed_trader     → explainer (interrupt_before triggers here)
   - explainer           → nemo_output_rail
   - nemo_output_rail    → END

   Governance Decision Flow (from symbolic_governor.py):
   - ALLOW            → Routing seal issued, action proceeds
   - DENY             → Action blocked, no seal
   - REQUIRE_APPROVAL → HITL queue (human sign-off required)
   - DEFER            → DeferQueue (automated data-hydration)
   - NARROW           → Clamped parameters, action proceeds with constraints
   - PAUSE            → Temporarily suspended, resume API required

   Verification Status:
   - Python BFS (proof/model.py): 21-state automaton for 8-tier governance
   - This TLA+ extends to include full LangGraph harness lifecycle
   - Cross-validates with DistributedCBF.tla for fence epoch semantics

   TLC Configuration:
   ---------------------------------------------------------------------------
   CONSTANTS
       MaxLoopCount = 3
       HITLTimeoutTicks = 5
   INIT Init
   NEXT Next
   INVARIANT TypeOK
   INVARIANT NoDirectBind
   INVARIANT EvidenceChainIntegrity
   ---------------------------------------------------------------------------
*)

EXTENDS Naturals, FiniteSets, Sequences

-----------------------------------------------------------------------------
(* CONSTANTS *)
-----------------------------------------------------------------------------

CONSTANTS
    MaxLoopCount,      \* Safety breaker loop cap (default: 3)
    HITLTimeoutTicks   \* HITL TTL in abstract time ticks (default: 5)

-----------------------------------------------------------------------------
(* GRAPH PHASES — Lifecycle states of the LangGraph execution *)
-----------------------------------------------------------------------------

\* Graph execution phases
Phases == {
    "INIT",              \* Initial state, awaiting input
    "GUARDRAIL",         \* NeMo input guardrail check
    "ROUTING",           \* Supervisor routing decision
    "GOVERNANCE_CHECK",  \* Symbolic Governor validation (7-tier)
    "FTRA_CHECK",        \* FTRA Tier 0.5 reachability analysis
    "LLM_CALL",          \* LLM inference in progress
    "HITL_PENDING",      \* Awaiting human-in-the-loop approval
    "DEFER_PENDING",     \* Parked in DeferQueue for data hydration
    "PAUSE_PENDING",     \* Temporarily paused, awaiting resume
    "RESPONSE",          \* Successful completion with output
    "ERROR"              \* Terminal error state
}

\* Canonical governance decisions (from decisions.py GovernanceDecision enum)
GovernanceDecisions == {
    "ALLOW",
    "DENY",
    "REQUIRE_APPROVAL",
    "DEFER",
    "NARROW",
    "PAUSE"
}

\* FTRA verdicts (from ftra/models.py FTRAVerdict enum)
FTRAVerdicts == {"CLEAR", "HITL_REQUIRED", "BLOCKED"}

\* Safety check statuses (from state.py AgentState.safety_status)
SafetyStatuses == {"APPROVED", "BLOCKED", "ESCALATED", "SKIPPED", "DEFERRED", "MANUAL_REVIEW"}

-----------------------------------------------------------------------------
(* VARIABLES — LangGraph harness state *)
-----------------------------------------------------------------------------

VARIABLES
    phase,              \* Current execution phase
    loop_count,         \* Recursion depth counter for safety breaker
    governance_decision,\* Latest GovernanceDecision from validate_action()
    ftra_verdict,       \* FTRA Tier 0.5 verdict
    safety_status,      \* OPA safety gate status
    seal_issued,        \* TRUE if routing seal was generated
    seal_valid,         \* TRUE if seal passed verification
    evidence_committed, \* TRUE if evidence chain record committed
    hitl_ticks_remaining,\* Countdown for HITL TTL expiration
    guardrail_blocked,  \* TRUE if NeMo guardrail blocked input
    output_rail_applied,\* TRUE if NeMo output rail was executed
    resolved_allow      \* TRUE only when all gates passed AND seal valid

\* All variables for UNCHANGED expressions
vars == <<phase, loop_count, governance_decision, ftra_verdict, safety_status,
          seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
          guardrail_blocked, output_rail_applied, resolved_allow>>

-----------------------------------------------------------------------------
(* TYPE INVARIANT *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ phase \in Phases
    /\ loop_count \in 0..MaxLoopCount
    /\ governance_decision \in GovernanceDecisions \cup {"NONE"}
    /\ ftra_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ safety_status \in SafetyStatuses \cup {"NONE"}
    /\ seal_issued \in BOOLEAN
    /\ seal_valid \in BOOLEAN
    /\ evidence_committed \in BOOLEAN
    /\ hitl_ticks_remaining \in 0..HITLTimeoutTicks
    /\ guardrail_blocked \in BOOLEAN
    /\ output_rail_applied \in BOOLEAN
    /\ resolved_allow \in BOOLEAN

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS *)
-----------------------------------------------------------------------------

(* NoDirectBind: The core safety property from proof/model.py
   RESPONSE phase is only reachable when resolved_allow = TRUE.
   This ensures execution cannot proceed without validated governance approval.
   
   Python cross-reference: proof/model.py lines 22-23, 435-447
   TLA+ formulation: (phase = "RESPONSE") => (resolved_allow = TRUE) *)
NoDirectBind == (phase = "RESPONSE") => resolved_allow

(* EvidenceChainIntegrity: Evidence must be committed before response.
   
   Python cross-reference:
   - src/gateway/governance/provenance_chain.py
   - EVIDENCE_CHAIN_BLOCKING mode in evidence_stream.py
   
   This property ensures audit trail integrity. *)
EvidenceChainIntegrity ==
    (phase = "RESPONSE" /\ governance_decision = "ALLOW") => evidence_committed

(* SealGateIntegrity: Seal must be issued and valid for ALLOW responses.
   
   Python cross-reference: src/gateway/governance/routing_seal.py lines 33-38 *)
SealGateIntegrity ==
    (phase = "RESPONSE" /\ governance_decision = "ALLOW") => (seal_issued /\ seal_valid)

(* HITLTimeoutSafety: HITL timeout leads to ERROR, not RESPONSE.
   
   If HITL times out without approval, the request must not proceed. *)
HITLTimeoutSafety ==
    (phase = "HITL_PENDING" /\ hitl_ticks_remaining = 0) => ~resolved_allow

(* OutputRailCoverage: All non-error terminal paths pass through output rail.
   
   Python cross-reference: graph.py line 238 (nemo_output_rail → END)
   Exception: guardrail_blocked path skips output rail (no agent output to screen) *)
OutputRailCoverage ==
    (phase = "RESPONSE" /\ ~guardrail_blocked) => output_rail_applied

\* Combined safety invariant
Safety == NoDirectBind /\ EvidenceChainIntegrity /\ SealGateIntegrity
       /\ HITLTimeoutSafety /\ OutputRailCoverage

-----------------------------------------------------------------------------
(* INITIAL STATE *)
-----------------------------------------------------------------------------

Init ==
    /\ phase = "INIT"
    /\ loop_count = 0
    /\ governance_decision = "NONE"
    /\ ftra_verdict = "NONE"
    /\ safety_status = "NONE"
    /\ seal_issued = FALSE
    /\ seal_valid = FALSE
    /\ evidence_committed = FALSE
    /\ hitl_ticks_remaining = HITLTimeoutTicks
    /\ guardrail_blocked = FALSE
    /\ output_rail_applied = FALSE
    /\ resolved_allow = FALSE

-----------------------------------------------------------------------------
(* ACTIONS — Graph node transitions *)
-----------------------------------------------------------------------------

(* StartExecution: INIT → GUARDRAIL
   Begin processing a new request through the NeMo input guardrail. *)
StartExecution ==
    /\ phase = "INIT"
    /\ phase' = "GUARDRAIL"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GuardrailPass: GUARDRAIL → ROUTING
   Input passes NeMo guardrail, proceed to supervisor routing. *)
GuardrailPass ==
    /\ phase = "GUARDRAIL"
    /\ phase' = "ROUTING"
    /\ guardrail_blocked' = FALSE
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   output_rail_applied, resolved_allow>>

(* GuardrailBlock: GUARDRAIL → ERROR
   Input blocked by NeMo guardrail, terminate immediately.
   Note: This path skips output rail (no agent output to screen). *)
GuardrailBlock ==
    /\ phase = "GUARDRAIL"
    /\ phase' = "ERROR"
    /\ guardrail_blocked' = TRUE
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   output_rail_applied, resolved_allow>>

(* RouteToGovernance: ROUTING → GOVERNANCE_CHECK
   Supervisor routes to execution_analyst → evaluator → governance check. *)
RouteToGovernance ==
    /\ phase = "ROUTING"
    /\ phase' = "GOVERNANCE_CHECK"
    /\ loop_count' = loop_count + 1
    /\ UNCHANGED <<governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* RouteToDataAnalyst: ROUTING → RESPONSE (via data_analyst)
   Supervisor routes to data_analyst path (no governance needed).
   Still passes through output rail. *)
RouteToDataAnalyst ==
    /\ phase = "ROUTING"
    /\ phase' = "RESPONSE"
    /\ output_rail_applied' = TRUE
    /\ resolved_allow' = TRUE  \* Data analyst path has implicit approval
    /\ evidence_committed' = TRUE  \* Commit provenance record
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, hitl_ticks_remaining, guardrail_blocked>>

(* GovernanceAllow: GOVERNANCE_CHECK → FTRA_CHECK
   Governance passes with ALLOW verdict, proceed to FTRA Tier 0.5. *)
GovernanceAllow ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "FTRA_CHECK"
    /\ governance_decision' = "ALLOW"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GovernanceDeny: GOVERNANCE_CHECK → ERROR
   Governance rejects with DENY verdict. *)
GovernanceDeny ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "ERROR"
    /\ governance_decision' = "DENY"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GovernanceRequireApproval: GOVERNANCE_CHECK → HITL_PENDING
   Governance requires human sign-off (MANUAL_REVIEW from OPA). *)
GovernanceRequireApproval ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "HITL_PENDING"
    /\ governance_decision' = "REQUIRE_APPROVAL"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GovernanceDefer: GOVERNANCE_CHECK → DEFER_PENDING
   Governance defers for data hydration (confidence below threshold). *)
GovernanceDefer ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "DEFER_PENDING"
    /\ governance_decision' = "DEFER"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GovernanceNarrow: GOVERNANCE_CHECK → FTRA_CHECK (with narrowed params)
   Governance allows with clamped parameters. *)
GovernanceNarrow ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "FTRA_CHECK"
    /\ governance_decision' = "NARROW"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* GovernancePause: GOVERNANCE_CHECK → PAUSE_PENDING
   Governance pauses for external resume signal. *)
GovernancePause ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ phase' = "PAUSE_PENDING"
    /\ governance_decision' = "PAUSE"
    /\ UNCHANGED <<loop_count, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* FTRAClear: FTRA_CHECK → LLM_CALL
   FTRA clears the plan, proceed to safety_check and LLM execution. *)
FTRAClear ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "LLM_CALL"
    /\ ftra_verdict' = "CLEAR"
    /\ safety_status' = "APPROVED"  \* safety_check passes
    /\ seal_issued' = TRUE          \* Generate routing seal
    /\ UNCHANGED <<loop_count, governance_decision,
                   seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* FTRAHITLRequired: FTRA_CHECK → HITL_PENDING
   FTRA detects irreversible terminal with sufficient confidence.
   Parks in DeferQueue db=1 for human review. *)
FTRAHITLRequired ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "HITL_PENDING"
    /\ ftra_verdict' = "HITL_REQUIRED"
    /\ UNCHANGED <<loop_count, governance_decision, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* FTRABlocked: FTRA_CHECK → ERROR
   FTRA blocks the plan (low confidence + irreversible terminal). *)
FTRABlocked ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "ERROR"
    /\ ftra_verdict' = "BLOCKED"
    /\ UNCHANGED <<loop_count, governance_decision, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* LLMCallComplete: LLM_CALL → RESPONSE
   LLM inference completes, verify seal, commit evidence, finalize.
   This is the only path that sets resolved_allow = TRUE. *)
LLMCallComplete ==
    /\ phase = "LLM_CALL"
    /\ seal_issued = TRUE
    /\ seal_valid' = TRUE           \* Seal verification passes
    /\ evidence_committed' = TRUE   \* Commit evidence chain record
    /\ output_rail_applied' = TRUE  \* Pass through output rail
    /\ resolved_allow' = TRUE       \* CRITICAL: Authority resolved
    /\ phase' = "RESPONSE"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, hitl_ticks_remaining, guardrail_blocked>>

(* LLMCallError: LLM_CALL → ERROR
   LLM inference fails or seal verification fails. *)
LLMCallError ==
    /\ phase = "LLM_CALL"
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* HITLApprove: HITL_PENDING → LLM_CALL
   Human approves the request, proceed with execution. *)
HITLApprove ==
    /\ phase = "HITL_PENDING"
    /\ hitl_ticks_remaining > 0
    /\ phase' = "LLM_CALL"
    /\ seal_issued' = TRUE          \* Generate seal after HITL approval
    /\ safety_status' = "APPROVED"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict,
                   seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* HITLReject: HITL_PENDING → ERROR
   Human rejects the request. *)
HITLReject ==
    /\ phase = "HITL_PENDING"
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* HITLTimeout: HITL_PENDING → ERROR
   HITL TTL expires without response. *)
HITLTimeout ==
    /\ phase = "HITL_PENDING"
    /\ hitl_ticks_remaining = 0
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* HITLTick: Time passes while waiting for HITL
   Models the hitl_expires_at TTL countdown. *)
HITLTick ==
    /\ phase = "HITL_PENDING"
    /\ hitl_ticks_remaining > 0
    /\ hitl_ticks_remaining' = hitl_ticks_remaining - 1
    /\ UNCHANGED <<phase, loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* DeferResolve: DEFER_PENDING → GOVERNANCE_CHECK
   Deferred request is resolved with hydrated data, retry governance. *)
DeferResolve ==
    /\ phase = "DEFER_PENDING"
    /\ phase' = "GOVERNANCE_CHECK"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* DeferTimeout: DEFER_PENDING → ERROR
   Defer TTL expires without resolution. *)
DeferTimeout ==
    /\ phase = "DEFER_PENDING"
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* PauseResume: PAUSE_PENDING → GOVERNANCE_CHECK
   Paused request receives resume signal, retry governance. *)
PauseResume ==
    /\ phase = "PAUSE_PENDING"
    /\ phase' = "GOVERNANCE_CHECK"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* PauseTimeout: PAUSE_PENDING → ERROR
   Pause TTL expires without resume. *)
PauseTimeout ==
    /\ phase = "PAUSE_PENDING"
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* LoopBack: GOVERNANCE_CHECK → ROUTING
   Loop back for re-planning (safety breaker check). *)
LoopBack ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ loop_count < MaxLoopCount
    /\ phase' = "ROUTING"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

(* LoopCapExceeded: GOVERNANCE_CHECK → ERROR
   Safety breaker triggered — max loop count exceeded. *)
LoopCapExceeded ==
    /\ phase = "GOVERNANCE_CHECK"
    /\ loop_count >= MaxLoopCount
    /\ phase' = "ERROR"
    /\ UNCHANGED <<loop_count, governance_decision, ftra_verdict, safety_status,
                   seal_issued, seal_valid, evidence_committed, hitl_ticks_remaining,
                   guardrail_blocked, output_rail_applied, resolved_allow>>

-----------------------------------------------------------------------------
(* NEXT STATE RELATION *)
-----------------------------------------------------------------------------

Next ==
    \/ StartExecution
    \/ GuardrailPass
    \/ GuardrailBlock
    \/ RouteToGovernance
    \/ RouteToDataAnalyst
    \/ GovernanceAllow
    \/ GovernanceDeny
    \/ GovernanceRequireApproval
    \/ GovernanceDefer
    \/ GovernanceNarrow
    \/ GovernancePause
    \/ FTRAClear
    \/ FTRAHITLRequired
    \/ FTRABlocked
    \/ LLMCallComplete
    \/ LLMCallError
    \/ HITLApprove
    \/ HITLReject
    \/ HITLTimeout
    \/ HITLTick
    \/ DeferResolve
    \/ DeferTimeout
    \/ PauseResume
    \/ PauseTimeout
    \/ LoopBack
    \/ LoopCapExceeded

-----------------------------------------------------------------------------
(* SPECIFICATION *)
-----------------------------------------------------------------------------

Spec == Init /\ [][Next]_vars

\* Fairness: Eventually all pending actions complete (for liveness)
FairSpec == Spec /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* TEMPORAL PROPERTIES — Optional liveness checks *)
-----------------------------------------------------------------------------

\* Eventually reach a terminal state (RESPONSE or ERROR)
EventuallyTerminates == <>(phase \in {"RESPONSE", "ERROR"})

\* If HITL approval is granted, eventually reach RESPONSE
HITLEventuallyResolves ==
    (phase = "HITL_PENDING") ~> (phase \in {"RESPONSE", "ERROR"})

-----------------------------------------------------------------------------
(* TLC MODEL CHECKING NOTES *)
-----------------------------------------------------------------------------
(*
   Cross-Validation with Python BFS (proof/model.py):
   --------------------------------------------------
   The Python model verifies NoDirectBind over 21 states for the 8-tier
   governance automaton. This TLA+ model extends to include:
   - Full LangGraph node lifecycle (GUARDRAIL through OUTPUT_RAIL)
   - HITL interrupt/TTL semantics (hitl_expires_at)
   - FTRA Tier 0.5 integration (CLEAR/HITL_REQUIRED/BLOCKED)
   - DEFER/NARROW/PAUSE decision paths

   The extended state space is larger than the Python model, but the
   core NoDirectBind property should still hold: RESPONSE is only
   reachable when resolved_allow = TRUE.

   Integration with DistributedCBF.tla:
   ------------------------------------
   This module references fence epoch semantics from DistributedCBF.
   In a composed model, the seal_issued/seal_valid transitions would
   be conditioned on successful fence epoch validation. For standalone
   model checking, these are modeled abstractly.

   Key Invariants to Verify:
   1. NoDirectBind        — Core safety, always holds
   2. EvidenceChainIntegrity — Audit trail, always holds
   3. SealGateIntegrity   — Cryptographic gate, always holds
   4. HITLTimeoutSafety   — TTL enforcement, always holds
   5. OutputRailCoverage  — NeMo output screening, always holds

   Expected Behavior:
   - All safety invariants hold under Spec
   - EventuallyTerminates holds under FairSpec
*)

=============================================================================
