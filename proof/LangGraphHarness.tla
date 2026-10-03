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

   One Governed Financial Advisor (GFA) thread over MaxTurns user turns, and
   the gateway DeferQueue tickets those turns park.

   Graph (src/governed_financial_advisor/graph/graph.py, _build_workflow):
     nemo_guardrail    -> END (blocked, no output rail) | thinker -> doer
     doer (supervisor) -> data_analyst -> nemo_output_rail
                        | nemo_output_rail (FINISH)
                        | execution_analyst
     execution_analyst -> evaluator
     evaluator         -> ftra_node (APPROVED)
                        | execution_analyst (rejected, loop_count < 3)
                        | explainer (rejected, loop_count >= 3)
     ftra_node         -> safety_check (CLEAR) | explainer (BLOCKED)
                        | interrupt (HITL_REQUIRED), then explainer on resume
                          (route_after_ftra sends HITL_REQUIRED to explainer)
     safety_check      -> approval_node | governed_trader (APPROVED / SKIPPED)
                        | defer_node (DEFERRED) | explainer (BLOCKED / HARD_PAUSE)
     approval_node     -> governed_trader | explainer
     governed_trader   -> explainer;  defer_node -> explainer
     explainer         -> nemo_output_rail -> END

   safety_check (graph/nodes/safety_node.py) asks the gateway
   (POST /governance/validate-action) only for an execute_trade plan; any
   other plan is SKIPPED. ALLOW / NARROW / REQUIRE_APPROVAL reset
   consecutive_denials to 0; DEFER leaves it; a refusal or gateway error
   increments it and reports HARD_PAUSE_BUDGET_EXCEEDED once the new count
   reaches MAX_CONSECUTIVE_DENIALS (2), else BLOCKED. The counter lives in
   the thread checkpoint across turns. The pause ends that turn; it does not
   lock the thread.

   Actuation happens only in the governed-trader subgraph
   (graph/subgraphs/governed_trader_graph.py): gateway_tool_guard submits each
   tool call to the gateway (FULL profile). ALLOW / NARROW: the gateway seals,
   commits evidence and actuates inside execute_trade_action. REQUIRE_APPROVAL:
   the gateway parks a HITL_REQUIRED ticket, the subgraph interrupts, and on
   resume (after post-HITL re-hydration and the drift check) the gateway runs
   enforce_approved_governance (server/governance_middleware.py):
   consume_approval exactly once, then POST_HITL re-validation, then the
   seal. Every refusal emits a refusal receipt (evidence).

   DeferQueue (src/gateway/governance/defer_queue.py), one ticket slot per
   turn. Kinds: DEFER (governor DEFER at safety_check, injectable), FTRA
   (ftra_node park, FTRA_IRREVERSIBLE_TERMINAL; the bridge's reason gate
   forbids injection) and APPROVAL (HITL_REQUIRED, consumed by the trader).
   Status PARKED -> PARTIALLY_APPROVED -> RESOLVED/ESCALATED (approve, quorum
   abstracted to two approvals) -> CONSUMED (consume_approval); PARKED ->
   RESOLVED/INJECTED (POST /v1/defer/{id}/inject -> replay_evaluate);
   PARKED | PARTIALLY_APPROVED -> RESOLVED/EXPIRED (expire_stale). Tickets
   change asynchronously, in any later turn.

   ResolveGuarded = TRUE is HEAD after POAM-2026-093: _resolve only leaves
   the statuses in _RESOLVABLE_FROM. ResolveGuarded = FALSE is the code
   before it: replay_evaluate re-resolved any token the bridge's gates let
   through, and expire_stale could overwrite a quorum approval in the window
   between approve()'s CAS and its zrem.

   Bounding: loop_count saturates at MaxLoopCount (the router only compares
   it with 3; the runtime counter keeps growing and is never reset in a
   thread). resolve_count is capped at 2, enough to witness a second
   resolution.

   Configurations (POAM-2026-091):
     LangGraphHarness.cfg            HEAD: every invariant holds
     LangGraphHarness_unguarded.cfg  NEGATIVE CONTROL (pre-POAM-2026-093
                                     DeferQueue): SingleUseDeferralTicket fails
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxLoopCount,           \* evaluator re-plan cap (route_after_evaluator: 3)
    HITLTimeoutTicks,       \* interrupt TTL in abstract ticks
    MaxConsecutiveDenials,  \* safety_node.MAX_CONSECUTIVE_DENIALS (2)
    MaxTurns,               \* user turns explored on one thread
    ResolveGuarded          \* _resolve status guard (TRUE at HEAD)

ASSUME MaxConsecutiveDenials >= 1 /\ MaxTurns >= 1 /\ ResolveGuarded \in BOOLEAN

-----------------------------------------------------------------------------
(* VOCABULARY *)
-----------------------------------------------------------------------------

Phases == {
    "IDLE",           \* awaiting the first user message
    "GUARDRAIL",      \* nemo_guardrail
    "SUPERVISOR",     \* thinker_node -> doer_node
    "PLANNING",       \* execution_analyst -> evaluator
    "FTRA_CHECK",     \* ftra_node
    "FTRA_HITL",      \* ftra_node interrupt()
    "SAFETY_CHECK",   \* safety_check (gateway validate-action)
    "APPROVAL",       \* approval_node interrupt()
    "TRADER",         \* governed_trader: tool call through gateway_tool_guard
    "TRADER_HITL",    \* governed_trader approval interrupt (deferred_id)
    "DEFER_NODE",     \* defer_node
    "EXPLAINER",      \* explainer
    "OUTPUT_RAIL",    \* nemo_output_rail
    "DONE"            \* END of the turn
}
HITLPhases == {"FTRA_HITL", "APPROVAL", "TRADER_HITL"}
TradingPhases == {"APPROVAL", "TRADER", "TRADER_HITL"}

GatewayDecisions == {"ALLOW", "NARROW", "REQUIRE_APPROVAL", "DENY"}
FTRAVerdicts == {"CLEAR", "HITL_REQUIRED", "BLOCKED"}
SafetyStatuses == {"APPROVED", "SKIPPED", "DEFERRED", "BLOCKED",
                   "HARD_PAUSE_BUDGET_EXCEEDED"}

TicketIds == 1..MaxTurns          \* ticket t is parked in turn t
TicketKinds == {"DEFER", "FTRA", "APPROVAL"}
TicketStatuses == {"PARKED", "PARTIALLY_APPROVED", "RESOLVED", "CONSUMED"}
Resolutions == {"ESCALATED", "INJECTED", "EXPIRED"}
MaxResolveCount == 2

-----------------------------------------------------------------------------
(* VARIABLES *)
-----------------------------------------------------------------------------

VARIABLES
    phase,                \* current graph node (per turn)
    turn,                 \* turns started on this thread
    loop_count,           \* AgentState.loop_count (thread-lifetime)
    consecutive_denials,  \* AgentState.consecutive_denials (thread-lifetime)
    ftra_verdict,         \* this turn's ftra_status
    safety_status,        \* this turn's safety_status
    governance_decision,  \* this turn's gateway decision on the trader's tool call
    guardrail_blocked,    \* this turn's input was blocked
    output_rail_applied,  \* this turn passed nemo_output_rail
    seal_issued,          \* the gateway sealed this turn's action
    resolved_allow,       \* the gateway's authority resolved to allow
    executed,             \* the trade was actuated this turn
    evidence_committed,   \* a decision or refusal receipt was committed this turn
    hitl_ticks_remaining, \* TTL of this turn's interrupt
    ticket_kind,          \* [TicketIds -> TicketKinds \cup {"NONE"}]
    ticket_status,        \* [TicketIds -> TicketStatuses \cup {"NONE"}]
    ticket_resolution,    \* [TicketIds -> Resolutions \cup {"NONE"}]
    resolve_count,        \* [TicketIds -> 0..MaxResolveCount]: times resolved
    consume_count         \* [TicketIds -> 0..2]: times consumed

turn_vars == <<ftra_verdict, safety_status, governance_decision, guardrail_blocked,
               output_rail_applied, seal_issued, resolved_allow, executed,
               evidence_committed, hitl_ticks_remaining>>
ticket_vars == <<ticket_kind, ticket_status, ticket_resolution, resolve_count,
                 consume_count>>
vars == <<phase, turn, loop_count, consecutive_denials, turn_vars, ticket_vars>>

TypeOK ==
    /\ phase \in Phases
    /\ turn \in 0..MaxTurns
    /\ loop_count \in 0..MaxLoopCount
    /\ consecutive_denials \in 0..MaxTurns
    /\ ftra_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ safety_status \in SafetyStatuses \cup {"NONE"}
    /\ governance_decision \in GatewayDecisions \cup {"NONE"}
    /\ guardrail_blocked \in BOOLEAN
    /\ output_rail_applied \in BOOLEAN
    /\ seal_issued \in BOOLEAN
    /\ resolved_allow \in BOOLEAN
    /\ executed \in BOOLEAN
    /\ evidence_committed \in BOOLEAN
    /\ hitl_ticks_remaining \in 0..HITLTimeoutTicks
    /\ ticket_kind \in [TicketIds -> TicketKinds \cup {"NONE"}]
    /\ ticket_status \in [TicketIds -> TicketStatuses \cup {"NONE"}]
    /\ ticket_resolution \in [TicketIds -> Resolutions \cup {"NONE"}]
    /\ resolve_count \in [TicketIds -> 0..MaxResolveCount]
    /\ consume_count \in [TicketIds -> 0..2]

\* Tickets resolved at least once (formerly the deferral_resolved variable).
DeferralResolved == {t \in TicketIds : resolve_count[t] > 0}

-----------------------------------------------------------------------------
(* INITIAL STATE *)
-----------------------------------------------------------------------------

Init ==
    /\ phase = "IDLE"
    /\ turn = 0
    /\ loop_count = 0
    /\ consecutive_denials = 0
    /\ ftra_verdict = "NONE"
    /\ safety_status = "NONE"
    /\ governance_decision = "NONE"
    /\ guardrail_blocked = FALSE
    /\ output_rail_applied = FALSE
    /\ seal_issued = FALSE
    /\ resolved_allow = FALSE
    /\ executed = FALSE
    /\ evidence_committed = FALSE
    /\ hitl_ticks_remaining = HITLTimeoutTicks
    /\ ticket_kind = [t \in TicketIds |-> "NONE"]
    /\ ticket_status = [t \in TicketIds |-> "NONE"]
    /\ ticket_resolution = [t \in TicketIds |-> "NONE"]
    /\ resolve_count = [t \in TicketIds |-> 0]
    /\ consume_count = [t \in TicketIds |-> 0]

-----------------------------------------------------------------------------
(* HELPERS *)
-----------------------------------------------------------------------------

\* Move to the next node; nothing else in the turn changes.
Goto(p) ==
    /\ phase' = p
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, turn_vars, ticket_vars>>

\* DeferQueue.park for this turn's slot.
Park(kind) ==
    /\ ticket_kind' = [ticket_kind EXCEPT ![turn] = kind]
    /\ ticket_status' = [ticket_status EXCEPT ![turn] = "PARKED"]
    /\ UNCHANGED <<ticket_resolution, resolve_count, consume_count>>

\* _resolve(t, resolution): one resolution of ticket t.
Resolve(t, res) ==
    /\ ticket_status' = [ticket_status EXCEPT ![t] = "RESOLVED"]
    /\ ticket_resolution' = [ticket_resolution EXCEPT ![t] = res]
    /\ resolve_count' = [resolve_count EXCEPT ![t] = @ + 1]
    /\ UNCHANGED <<ticket_kind, consume_count>>

-----------------------------------------------------------------------------
(* GRAPH ACTIONS *)
-----------------------------------------------------------------------------

(* A new user message on the thread. Per-turn fields start clean; the
   checkpointed counters (loop_count, consecutive_denials) carry over. *)
StartTurn ==
    /\ phase \in {"IDLE", "DONE"}
    /\ turn < MaxTurns
    /\ phase' = "GUARDRAIL"
    /\ turn' = turn + 1
    /\ ftra_verdict' = "NONE"
    /\ safety_status' = "NONE"
    /\ governance_decision' = "NONE"
    /\ guardrail_blocked' = FALSE
    /\ output_rail_applied' = FALSE
    /\ seal_issued' = FALSE
    /\ resolved_allow' = FALSE
    /\ executed' = FALSE
    /\ evidence_committed' = FALSE
    /\ hitl_ticks_remaining' = HITLTimeoutTicks
    /\ UNCHANGED <<loop_count, consecutive_denials, ticket_vars>>

(* route_after_guardrail: blocked input ends the turn without the output
   rail (there is no agent output to screen). *)
GuardrailBlock ==
    /\ phase = "GUARDRAIL"
    /\ phase' = "DONE"
    /\ guardrail_blocked' = TRUE
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   governance_decision, output_rail_applied, seal_issued,
                   resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

GuardrailPass   == phase = "GUARDRAIL"  /\ Goto("SUPERVISOR")

(* route_supervisor: data_analyst (then the output rail) or FINISH. *)
RouteToOutput   == phase = "SUPERVISOR" /\ Goto("OUTPUT_RAIL")
RouteToPlanner  == phase = "SUPERVISOR" /\ Goto("PLANNING")

(* execution_analyst increments loop_count; route_after_evaluator. *)
Plan ==
    /\ phase = "PLANNING"
    /\ LET lc == IF loop_count < MaxLoopCount THEN loop_count + 1 ELSE MaxLoopCount
       IN  /\ loop_count' = lc
           /\ \E approved \in BOOLEAN :
                phase' = IF approved THEN "FTRA_CHECK"
                         ELSE IF lc >= MaxLoopCount THEN "EXPLAINER"
                         ELSE "PLANNING"
    /\ UNCHANGED <<turn, consecutive_denials, turn_vars, ticket_vars>>

FTRAClear ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "SAFETY_CHECK"
    /\ ftra_verdict' = "CLEAR"
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, safety_status,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   seal_issued, resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

FTRABlocked ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "EXPLAINER"
    /\ ftra_verdict' = "BLOCKED"
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, safety_status,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   seal_issued, resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

(* HITL_REQUIRED from the reachability analysis parks a ticket
   (_park_in_defer_queue); HITL_REQUIRED from a parse failure does not
   (ftra_defer_id None). Either way the node interrupts. *)
FTRAHITLRequired ==
    /\ phase = "FTRA_CHECK"
    /\ phase' = "FTRA_HITL"
    /\ ftra_verdict' = "HITL_REQUIRED"
    /\ \/ Park("FTRA")
       \/ UNCHANGED ticket_vars
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, safety_status,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   seal_issued, resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining>>

(* On resume the node returns ftra_status HITL_REQUIRED, which
   route_after_ftra sends to the explainer: an FTRA park never trades in
   this turn. *)
FTRAResume  == phase = "FTRA_HITL" /\ hitl_ticks_remaining > 0  /\ Goto("EXPLAINER")
FTRATimeout == phase = "FTRA_HITL" /\ hitl_ticks_remaining = 0  /\ Goto("EXPLAINER")

(* safety_check: a non-trade plan skips the gateway. *)
SafetySkip ==
    /\ phase = "SAFETY_CHECK"
    /\ safety_status' = "SKIPPED"
    /\ phase' \in {"APPROVAL", "TRADER"}
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   seal_issued, resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

(* Gateway ALLOW / NARROW / REQUIRE_APPROVAL: APPROVED, counter reset.
   route_after_safety picks approval_node on risk or amount. *)
SafetyApprove ==
    /\ phase = "SAFETY_CHECK"
    /\ safety_status' = "APPROVED"
    /\ consecutive_denials' = 0
    /\ phase' \in {"APPROVAL", "TRADER"}
    /\ UNCHANGED <<turn, loop_count, ftra_verdict, governance_decision,
                   guardrail_blocked, output_rail_applied, seal_issued,
                   resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

(* Gateway DEFER with a defer_id: the governor parked a ticket; the counter
   is left alone (deferral is not approval). *)
SafetyDefer ==
    /\ phase = "SAFETY_CHECK"
    /\ safety_status' = "DEFERRED"
    /\ phase' = "DEFER_NODE"
    /\ Park("DEFER")
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   seal_issued, resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining>>

(* Gateway refusal (HTTP 403 / PermissionError), gateway error or an
   unroutable verdict: safety_node._blocked. The gateway commits a refusal
   receipt for a refusal; a transport error is modelled the same way. *)
SafetyDeny ==
    /\ phase = "SAFETY_CHECK"
    /\ LET new == consecutive_denials + 1
       IN  /\ consecutive_denials' = new
           /\ safety_status' = IF new >= MaxConsecutiveDenials
                               THEN "HARD_PAUSE_BUDGET_EXCEEDED" ELSE "BLOCKED"
    /\ evidence_committed' = TRUE
    /\ phase' = "EXPLAINER"
    /\ UNCHANGED <<turn, loop_count, ftra_verdict, governance_decision,
                   guardrail_blocked, output_rail_applied, seal_issued,
                   resolved_allow, executed, hitl_ticks_remaining, ticket_vars>>

(* approval_node: interrupt(); Command(goto=...) on the reviewer's decision. *)
ApprovalGranted  == phase = "APPROVAL" /\ hitl_ticks_remaining > 0 /\ Goto("TRADER")
ApprovalRejected == phase = "APPROVAL" /\ Goto("EXPLAINER")

(* The trader's tool call, gateway FULL run: ALLOW / NARROW seal, commit
   evidence and actuate in execute_trade_action. *)
TraderAllow ==
    /\ phase = "TRADER"
    /\ \E d \in {"ALLOW", "NARROW"} : governance_decision' = d
    /\ seal_issued' = TRUE
    /\ resolved_allow' = TRUE
    /\ evidence_committed' = TRUE
    /\ executed' = TRUE
    /\ phase' = "EXPLAINER"
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   guardrail_blocked, output_rail_applied, hitl_ticks_remaining,
                   ticket_vars>>

TraderDeny ==
    /\ phase = "TRADER"
    /\ governance_decision' = "DENY"
    /\ evidence_committed' = TRUE
    /\ phase' = "EXPLAINER"
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   guardrail_blocked, output_rail_applied, seal_issued,
                   resolved_allow, executed, hitl_ticks_remaining, ticket_vars>>

(* REQUIRE_APPROVAL: the governor parks a HITL_REQUIRED ticket; the
   subgraph interrupts with its deferred_id. *)
TraderRequireApproval ==
    /\ phase = "TRADER"
    /\ governance_decision' = "REQUIRE_APPROVAL"
    /\ phase' = "TRADER_HITL"
    /\ Park("APPROVAL")
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   guardrail_blocked, output_rail_applied, seal_issued,
                   resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining>>

(* The executor emitted no tool call. *)
TraderNoToolCall == phase = "TRADER" /\ Goto("EXPLAINER")

(* Resume after the interrupt: post_hitl_rehydrate / revalidate (the drift
   check may block), then the executor's tool call carries deferred_id and
   the gateway runs enforce_approved_governance: consume_approval (status
   RESOLVED, resolution ESCALATED, kind HITL_REQUIRED; atomic
   RESOLVED -> CONSUMED), then POST_HITL re-validation. The approval is
   spent before re-validation, so a re-validation refusal burns it. *)
TraderResume ==
    /\ phase = "TRADER_HITL"
    /\ hitl_ticks_remaining > 0
    /\ phase' = "EXPLAINER"
    /\ \E drift_blocked \in BOOLEAN, revalidates \in BOOLEAN :
        LET t == turn
            consumable == /\ ticket_kind[t] = "APPROVAL"
                          /\ ticket_status[t] = "RESOLVED"
                          /\ ticket_resolution[t] = "ESCALATED"
        IN  IF drift_blocked
            THEN UNCHANGED <<seal_issued, resolved_allow, executed,
                             evidence_committed, ticket_vars>>
            ELSE IF ~consumable
            THEN /\ evidence_committed' = TRUE      \* refusal receipt
                 /\ UNCHANGED <<seal_issued, resolved_allow, executed, ticket_vars>>
            ELSE /\ ticket_status' = [ticket_status EXCEPT ![t] = "CONSUMED"]
                 /\ consume_count' = [consume_count EXCEPT ![t] = @ + 1]
                 /\ UNCHANGED <<ticket_kind, ticket_resolution, resolve_count>>
                 /\ evidence_committed' = TRUE
                 /\ seal_issued' = revalidates
                 /\ resolved_allow' = revalidates
                 /\ executed' = revalidates
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   governance_decision, guardrail_blocked, output_rail_applied,
                   hitl_ticks_remaining>>

TraderHITLTimeout == phase = "TRADER_HITL" /\ hitl_ticks_remaining = 0 /\ Goto("EXPLAINER")

(* Interrupt TTL countdown. *)
HITLTick ==
    /\ phase \in HITLPhases
    /\ hitl_ticks_remaining > 0
    /\ hitl_ticks_remaining' = hitl_ticks_remaining - 1
    /\ UNCHANGED <<phase, turn, loop_count, consecutive_denials, ftra_verdict,
                   safety_status, governance_decision, guardrail_blocked,
                   output_rail_applied, seal_issued, resolved_allow, executed,
                   evidence_committed, ticket_vars>>

DeferNodeDone == phase = "DEFER_NODE" /\ Goto("EXPLAINER")
ExplainerDone == phase = "EXPLAINER"  /\ Goto("OUTPUT_RAIL")

OutputRail ==
    /\ phase = "OUTPUT_RAIL"
    /\ phase' = "DONE"
    /\ output_rail_applied' = TRUE
    /\ UNCHANGED <<turn, loop_count, consecutive_denials, ftra_verdict, safety_status,
                   governance_decision, guardrail_blocked, seal_issued,
                   resolved_allow, executed, evidence_committed,
                   hitl_ticks_remaining, ticket_vars>>

-----------------------------------------------------------------------------
(* DEFERQUEUE ACTIONS — asynchronous, on any parked ticket *)
-----------------------------------------------------------------------------

DQ(stmt) == stmt /\ UNCHANGED <<phase, turn, loop_count, consecutive_denials, turn_vars>>

(* approve(): first approval. *)
ApproveFirst(t) == DQ(
    /\ ticket_status[t] = "PARKED"
    /\ ticket_status' = [ticket_status EXCEPT ![t] = "PARTIALLY_APPROVED"]
    /\ UNCHANGED <<ticket_kind, ticket_resolution, resolve_count, consume_count>>)

(* approve(): quorum reached -> RESOLVED / ESCALATED. *)
ApproveQuorum(t) == DQ(
    /\ ticket_status[t] = "PARTIALLY_APPROVED"
    /\ resolve_count[t] < MaxResolveCount
    /\ Resolve(t, "ESCALATED"))

(* POST /v1/defer/{id}/inject -> replay_evaluate -> _resolve(INJECTED).
   Bridge gates: no quorum-3 reason (FTRA), no partial approvals. *)
Inject(t) == DQ(
    /\ ticket_kind[t] \in {"DEFER", "APPROVAL"}
    /\ ticket_status[t] \in {"PARKED", "RESOLVED", "CONSUMED"}
    /\ ResolveGuarded => ticket_status[t] = "PARKED"
    /\ resolve_count[t] < MaxResolveCount
    /\ Resolve(t, "INJECTED"))

(* expire_stale -> _resolve(EXPIRED) on an index member past its TTL.
   Unguarded, a quorum approval still in the index (approve()'s CAS landed,
   its zrem not yet) is overwritten. *)
Expire(t) == DQ(
    /\ \/ ticket_status[t] \in {"PARKED", "PARTIALLY_APPROVED"}
       \/ /\ ~ResolveGuarded
          /\ ticket_status[t] = "RESOLVED" /\ ticket_resolution[t] = "ESCALATED"
    /\ resolve_count[t] < MaxResolveCount
    /\ Resolve(t, "EXPIRED"))

-----------------------------------------------------------------------------
(* NEXT STATE RELATION *)
-----------------------------------------------------------------------------

Next ==
    \/ StartTurn \/ GuardrailBlock \/ GuardrailPass
    \/ RouteToOutput \/ RouteToPlanner \/ Plan
    \/ FTRAClear \/ FTRABlocked \/ FTRAHITLRequired \/ FTRAResume \/ FTRATimeout
    \/ SafetySkip \/ SafetyApprove \/ SafetyDefer \/ SafetyDeny
    \/ ApprovalGranted \/ ApprovalRejected
    \/ TraderAllow \/ TraderDeny \/ TraderRequireApproval \/ TraderNoToolCall
    \/ TraderResume \/ TraderHITLTimeout \/ HITLTick
    \/ DeferNodeDone \/ ExplainerDone \/ OutputRail
    \/ \E t \in TicketIds : ApproveFirst(t) \/ ApproveQuorum(t) \/ Inject(t) \/ Expire(t)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS *)
-----------------------------------------------------------------------------

(* proof/model.py's core property: nothing is actuated without the
   gateway's authority. *)
NoDirectBind == executed => resolved_allow

(* A trade executes only under a gateway seal, issued for ALLOW / NARROW or
   for a quorum approval this turn spent exactly once. *)
SealGateIntegrity ==
    executed =>
        /\ seal_issued
        /\ \/ governance_decision \in {"ALLOW", "NARROW"}
           \/ /\ governance_decision = "REQUIRE_APPROVAL"
              /\ ticket_kind[turn] = "APPROVAL"
              /\ ticket_status[turn] = "CONSUMED"
              /\ ticket_resolution[turn] = "ESCALATED"
              /\ consume_count[turn] = 1

(* Every actuation and every refusal leaves a committed receipt. *)
EvidenceChainIntegrity ==
    (\/ executed
     \/ governance_decision = "DENY"
     \/ safety_status \in {"BLOCKED", "HARD_PAUSE_BUDGET_EXCEEDED"})
        => evidence_committed

(* An expired interrupt never resumes into execution. *)
HITLTimeoutSafety ==
    (phase \in HITLPhases /\ hitl_ticks_remaining = 0) => ~executed

(* Every turn that was not blocked at the input guardrail ends through
   nemo_output_rail. *)
OutputRailCoverage ==
    (phase = "DONE" /\ ~guardrail_blocked) => output_rail_applied

(* A deferral ticket is resolved at most once and an approval is spent at
   most once. *)
SingleUseDeferralTicket ==
    \A t \in TicketIds : resolve_count[t] <= 1 /\ consume_count[t] <= 1

(* The denial budget at its real threshold: a refusal that brings the
   counter to MaxConsecutiveDenials or more pauses the turn; one below it
   does not. *)
BudgetNeverExceededWithoutPause ==
    safety_status \in {"BLOCKED", "HARD_PAUSE_BUDGET_EXCEEDED"} =>
        ((safety_status = "HARD_PAUSE_BUDGET_EXCEEDED")
            <=> (consecutive_denials >= MaxConsecutiveDenials))

(* A refused, paused or deferred turn never reaches the trader. *)
RefusedTurnNeverTrades ==
    safety_status \in {"BLOCKED", "HARD_PAUSE_BUDGET_EXCEEDED", "DEFERRED"} =>
        (~executed /\ phase \notin TradingPhases)

(* An FTRA HITL or BLOCKED verdict never trades in that turn. *)
FtraHoldNeverTradesThisTurn ==
    ftra_verdict \in {"HITL_REQUIRED", "BLOCKED"} =>
        (~executed /\ phase \notin TradingPhases \cup {"SAFETY_CHECK"})

=============================================================================
