---------------------------- MODULE FtraBoundary ----------------------------
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
   FTRA Boundary Verification — TLA+ Formal Specification
   --------------------------------------------------------------------------

   One request's path through the two FTRA enforcement points:

   - IN-GRAPH: the advisor graph's ftra_node (create_ftra_node in
     src/gateway/governance/ftra/node_factory.py, analysis in
     ftra/graph_analyzer.py). Only the governed-financial-advisor (GFA) pod
     runs it. It has no magnitude extractor, so nothing auto-clears in-graph.
   - CONTROLLER: FtraStage (src/gateway/governance/governor/stages/ftra.py),
     the first read-only stage of every FULL / DRY_RUN governor run
     (kernel_stages() in governor/assembly.py; read_only_sort_key in
     governor/pipeline.py). It is unconditional: there is no feature flag.

   R-03 (trust-boundary bypass): ftra_node only fires if the caller wires it
   into its graph. Any other admitted caller reaches the governor directly;
   the controller check covers that path. R-02 (post-classification plan
   mutation) is outside this model.

   Every request starts PENDING and ends in one terminal phase:
     DROPPED   network policy refused the connection
     REFUSED   the in-graph node blocked it, or a human rejected the
               in-graph HITL park
     DENIED    the governor refused it (FTRA HARD, another tier, a human, or
               post-approval re-validation)
     EXECUTED  sealed by the governor and actuated
   Only the governor issues a routing seal and only a sealed action is
   actuated (verify_and_consume_seal + ActuatorRegistry, ADR-008), so
   Execute requires SEALED.

   Registry: the finance registry config/ftra/terminal_registry.json —
   execute_trade IRREVERSIBLE_TERMINAL and execute_trade_bounded
   EXTERNALLY_REVERSIBLE, both with an autonomous envelope; check_balance
   READ_ONLY; anything else unregistered (fail-closed IRREVERSIBLE_TERMINAL).
   Each process loads the registry independently (ig_registry_ok,
   ctl_registry_ok); an unloadable registry classifies everything
   IRREVERSIBLE_TERMINAL (classifier.classify_with_provenance, UNAVAILABLE).

   Confidence is an integer percentage. CONFIDENCE_DEFER_FLOOR is
   confidence.defer_floor (0.70) and CONFIDENCE_ALLOW_FLOOR is
   confidence.agent_threshold (0.95), the conditional-clear floor
   (autonomy.conditional_clear_reason). Confidences is the finite set of
   values explored; it must straddle both floors.

   Configurations (POAM-2026-091):
     FtraBoundary.cfg             shipped posture, network policy applied
     FtraBoundary_nonetpol.cfg    no NetworkPolicy (e.g. the agnostic target):
                                  the controller check alone must suffice
     FtraBoundary_noboundary.cfg  NEGATIVE CONTROL: governor without FtraStage;
                                  the R-03 invariants must fail
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    CONFIDENCE_DEFER_FLOOR,     \* confidence.defer_floor x 100 (70)
    CONFIDENCE_ALLOW_FLOOR,     \* confidence.agent_threshold x 100 (95)
    Confidences,                \* explored confidence values (subset of 0..100)
    NetworkPolicyApplied,       \* deployment/k8s/ftra-network-policy.yaml in force
    ControllerBoundaryEnabled   \* FtraStage in the governor (TRUE at HEAD)

ASSUME Confidences \subseteq 0..100
ASSUME NetworkPolicyApplied \in BOOLEAN /\ ControllerBoundaryEnabled \in BOOLEAN

-----------------------------------------------------------------------------
(* VOCABULARY — ftra/models.py *)
-----------------------------------------------------------------------------

IRREV   == "IRREVERSIBLE_TERMINAL"
EXTREV  == "EXTERNALLY_REVERSIBLE"
TerminalClassifications == {IRREV, EXTREV, "REVERSIBLE", "READ_ONLY"}
Terminal(c) == c \in {IRREV, EXTREV}   \* autonomy.ENVELOPE_CLASSIFICATIONS

FTRAVerdicts == {"CLEAR", "HITL_REQUIRED", "BLOCKED"}

\* ParseFailureClass plus PLAN_MISSING (plan extractor returned None, which
\* node_factory._run_ftra reports as BLOCKED / SCHEMA_VALIDATION_ERROR).
ParseOutcomes == {"SUCCESS", "TOKENIZER_ARTIFACT", "JSON_DECODE_ERROR",
                  "SCHEMA_VALIDATION_ERROR", "EMPTY_STEPS", "TRUNCATED_PLAN",
                  "PLAN_MISSING"}
\* Outcomes after which the node never returns CLEAR.
NonClearingParse == {"JSON_DECODE_ERROR", "SCHEMA_VALIDATION_ERROR",
                     "TRUNCATED_PLAN", "PLAN_MISSING"}

RequestSources == {
    "GFA_POD",              \* runs the in-graph ftra_node
    "COMPLIANCE_BRIDGE",    \* governance infrastructure
    "INGRESS_CONTROLLER",   \* external traffic via ingress
    "GOVERNANCE_VALIDATED", \* pod with the governance-validated label
    "DIRECT_HTTP"           \* any other pod
}

\* ftra-network-policy.yaml: ingress to cage-gateway only from these.
NetworkPolicyPermits(src) ==
    src \in {"GFA_POD", "COMPLIANCE_BRIDGE", "INGRESS_CONTROLLER", "GOVERNANCE_VALIDATED"}

Actions == {"execute_trade", "execute_trade_bounded", "check_balance", "unknown_action"}
InRegistry(a)  == a # "unknown_action"
HasEnvelope(a) == a \in {"execute_trade", "execute_trade_bounded"}
RegClass(a) ==
    CASE a = "execute_trade"         -> IRREV
      [] a = "execute_trade_bounded" -> EXTREV
      [] a = "check_balance"         -> "READ_ONLY"
      [] OTHER                       -> IRREV
\* IrreversibilityClassifier.classify_with_provenance: every non-REGISTERED
\* state is IRREVERSIBLE_TERMINAL.
Classify(a, registry_ok) == IF registry_ok /\ InRegistry(a) THEN RegClass(a) ELSE IRREV
\* What the action really is: a terminal, or unknown to the domain.
TrulyTerminal(a) == ~InRegistry(a) \/ Terminal(RegClass(a))

Phases == {"PENDING", "IN_GRAPH_HITL", "AT_GATEWAY", "TIERS", "AWAITING_HUMAN",
           "SEALED", "DROPPED", "REFUSED", "DENIED", "EXECUTED"}
TerminalPhases == {"DROPPED", "REFUSED", "DENIED", "EXECUTED"}
\* Phases a request reaches only through a governor run.
GovernorPhases == {"TIERS", "AWAITING_HUMAN", "SEALED", "EXECUTED"}

-----------------------------------------------------------------------------
(* VARIABLES *)
-----------------------------------------------------------------------------

VARIABLES
    \* request (fixed at Init)
    request_source, action_name, confidence, magnitude_in_envelope,
    network_policy_allows, ig_registry_ok, ctl_registry_ok,
    \* lifecycle
    request_phase,
    \* in-graph ftra_node
    parse_failure_class, in_graph_classification, in_graph_verdict,
    in_graph_executed, ig_human_approved,
    \* controller FtraStage (FtraBoundaryResult)
    controller_classification, controller_verdict, controller_executed,
    auto_cleared, bypassed_ftra_node,
    \* governor human approval (DeferQueue quorum + consume_approval)
    human_approved

request_vars == <<request_source, action_name, confidence, magnitude_in_envelope,
                  network_policy_allows, ig_registry_ok, ctl_registry_ok>>
ig_vars   == <<parse_failure_class, in_graph_classification, in_graph_verdict,
               in_graph_executed, ig_human_approved>>
ctl_vars  == <<controller_classification, controller_verdict, controller_executed,
               auto_cleared, bypassed_ftra_node>>
vars == <<request_vars, request_phase, ig_vars, ctl_vars, human_approved>>

TypeOK ==
    /\ request_source \in RequestSources
    /\ action_name \in Actions
    /\ confidence \in Confidences
    /\ magnitude_in_envelope \in BOOLEAN
    /\ network_policy_allows \in BOOLEAN
    /\ ig_registry_ok \in BOOLEAN
    /\ ctl_registry_ok \in BOOLEAN
    /\ request_phase \in Phases
    /\ parse_failure_class \in ParseOutcomes \cup {"NONE"}
    /\ in_graph_classification \in TerminalClassifications \cup {"NONE"}
    /\ in_graph_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ in_graph_executed \in BOOLEAN
    /\ ig_human_approved \in BOOLEAN
    /\ controller_classification \in TerminalClassifications \cup {"NONE"}
    /\ controller_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ controller_executed \in BOOLEAN
    /\ auto_cleared \in BOOLEAN
    /\ bypassed_ftra_node \in BOOLEAN
    /\ human_approved \in BOOLEAN

-----------------------------------------------------------------------------
(* VERDICT FUNCTIONS *)
-----------------------------------------------------------------------------

\* PlanGraphAnalyzer.analyze verdict without a magnitude extractor
\* (graph_analyzer.py: IRREVERSIBLE gates on the defer floor;
\* EXTERNALLY_REVERSIBLE always needs a human).
AnalyzerVerdict(c, conf) ==
    CASE c = IRREV  -> IF conf >= CONFIDENCE_DEFER_FLOOR THEN "HITL_REQUIRED" ELSE "BLOCKED"
      [] c = EXTREV -> "HITL_REQUIRED"
      [] OTHER      -> "CLEAR"

\* node_factory._run_ftra. EMPTY_STEPS compares against a literal 0.70,
\* equal to the shipped confidence.defer_floor.
InGraphVerdict(pf, c, conf) ==
    CASE pf = "PLAN_MISSING" -> "BLOCKED"
      [] pf \in {"JSON_DECODE_ERROR", "SCHEMA_VALIDATION_ERROR", "TRUNCATED_PLAN"}
                             -> "HITL_REQUIRED"
      [] pf = "EMPTY_STEPS"  -> IF conf >= CONFIDENCE_DEFER_FLOOR THEN "CLEAR" ELSE "HITL_REQUIRED"
      [] OTHER               -> AnalyzerVerdict(c, conf)

\* autonomy.conditional_clear_reason # None
ConditionalClear(a, registry_ok, conf, in_env) ==
    /\ registry_ok /\ InRegistry(a)
    /\ Terminal(RegClass(a))
    /\ HasEnvelope(a)
    /\ in_env
    /\ conf >= CONFIDENCE_ALLOW_FLOOR

\* FtraBoundaryResult.from_classification: HARD (BLOCKED here) when the
\* registry is UNAVAILABLE; HITL for an uncleared terminal (registered,
\* unregistered or invalid); otherwise no violation.
ControllerVerdict(registry_ok, c, cleared) ==
    IF ~registry_ok THEN "BLOCKED"
    ELSE IF Terminal(c) /\ ~cleared THEN "HITL_REQUIRED"
    ELSE "CLEAR"

-----------------------------------------------------------------------------
(* INITIAL STATE *)
-----------------------------------------------------------------------------

Init ==
    /\ request_source \in RequestSources
    /\ action_name \in Actions
    /\ confidence \in Confidences
    /\ magnitude_in_envelope \in BOOLEAN
    /\ network_policy_allows = (IF NetworkPolicyApplied
                                THEN NetworkPolicyPermits(request_source)
                                ELSE TRUE)
    /\ ig_registry_ok \in BOOLEAN
    /\ ctl_registry_ok \in BOOLEAN
    /\ request_phase = "PENDING"
    /\ parse_failure_class = "NONE"
    /\ in_graph_classification = "NONE"
    /\ in_graph_verdict = "NONE"
    /\ in_graph_executed = FALSE
    /\ ig_human_approved = FALSE
    /\ controller_classification = "NONE"
    /\ controller_verdict = "NONE"
    /\ controller_executed = FALSE
    /\ auto_cleared = FALSE
    /\ bypassed_ftra_node = FALSE
    /\ human_approved = FALSE

-----------------------------------------------------------------------------
(* ACTIONS *)
-----------------------------------------------------------------------------

(* The connection never reaches cage-gateway. *)
NetworkPolicyBlock ==
    /\ request_phase = "PENDING"
    /\ ~network_policy_allows
    /\ request_phase' = "DROPPED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

(* Any admitted caller other than the GFA pod calls the gateway directly:
   no in-graph check runs (the R-03 bypass path). *)
ReachGatewayDirect ==
    /\ request_phase = "PENDING"
    /\ network_policy_allows
    /\ request_source # "GFA_POD"
    /\ request_phase' = "AT_GATEWAY"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

(* The GFA graph's ftra_node: parse, classify, verdict, route
   (route_after_ftra). CLEAR goes on to safety_check, whose gateway call (or
   the governed trader's gateway_tool_guard) reaches the governor. BLOCKED
   goes to the explainer. HITL_REQUIRED parks in the DeferQueue. *)
InGraphFtraNode ==
    /\ request_phase = "PENDING"
    /\ network_policy_allows
    /\ request_source = "GFA_POD"
    /\ ~in_graph_executed
    /\ \E pf \in ParseOutcomes :
        LET analyzed == pf \in {"SUCCESS", "TOKENIZER_ARTIFACT"}
            cls      == IF analyzed THEN Classify(action_name, ig_registry_ok) ELSE "NONE"
            v        == InGraphVerdict(pf, cls, confidence)
        IN  /\ parse_failure_class' = pf
            /\ in_graph_classification' = cls
            /\ in_graph_verdict' = v
            /\ in_graph_executed' = TRUE
            /\ request_phase' = CASE v = "CLEAR"         -> "AT_GATEWAY"
                                  [] v = "HITL_REQUIRED" -> "IN_GRAPH_HITL"
                                  [] OTHER               -> "REFUSED"
    /\ UNCHANGED <<request_vars, ig_human_approved, ctl_vars, human_approved>>

(* A human clears the in-graph park; the request still goes through the
   governor (the advisor holds no governance state). *)
InGraphHumanApprove ==
    /\ request_phase = "IN_GRAPH_HITL"
    /\ ig_human_approved' = TRUE
    /\ request_phase' = "AT_GATEWAY"
    /\ UNCHANGED <<request_vars, parse_failure_class, in_graph_classification,
                   in_graph_verdict, in_graph_executed, ctl_vars, human_approved>>

InGraphHumanReject ==
    /\ request_phase = "IN_GRAPH_HITL"
    /\ request_phase' = "REFUSED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

(* FtraStage._ftra_boundary_check: the first read-only stage. A HARD
   violation (registry UNAVAILABLE) stops the pipeline and the governor
   denies; HITL goes to the remaining tiers, which cannot clear it (the
   classifier routes any violation to approval at best); CLEAR goes to the
   remaining tiers. bypassed_ftra_node is set for every uncleared
   IRREVERSIBLE_TERMINAL: the stage cannot see whether ftra_node ran, so the
   flag is a telemetry label, not a detection.
   With ControllerBoundaryEnabled = FALSE (negative control) the governor
   runs without FtraStage. *)
ControllerBoundaryCheck ==
    /\ request_phase = "AT_GATEWAY"
    /\ IF ControllerBoundaryEnabled
       THEN LET cls     == Classify(action_name, ctl_registry_ok)
                cleared == ConditionalClear(action_name, ctl_registry_ok,
                                            confidence, magnitude_in_envelope)
                v       == ControllerVerdict(ctl_registry_ok, cls, cleared)
            IN  /\ controller_classification' = cls
                /\ controller_verdict' = v
                /\ controller_executed' = TRUE
                /\ auto_cleared' = cleared
                /\ bypassed_ftra_node' = (cls = IRREV /\ ~cleared)
                /\ request_phase' = CASE v = "BLOCKED"       -> "DENIED"
                                      [] v = "HITL_REQUIRED" -> "AWAITING_HUMAN"
                                      [] OTHER               -> "TIERS"
       ELSE /\ request_phase' = "TIERS"
            /\ UNCHANGED ctl_vars
    /\ UNCHANGED <<request_vars, ig_vars, human_approved>>

(* STPA, OPA, confidence and the domain tiers, abstracted: they may seal,
   ask for approval or deny. None of them owns irreversibility. *)
OtherTiersSeal ==
    /\ request_phase = "TIERS"
    /\ request_phase' = "SEALED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

OtherTiersRequireApproval ==
    /\ request_phase = "TIERS"
    /\ request_phase' = "AWAITING_HUMAN"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

OtherTiersDeny ==
    /\ request_phase = "TIERS"
    /\ request_phase' = "DENIED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

(* Quorum approval consumed once, then POST_HITL re-validation seals
   (enforce_approved_governance). FTRA is not re-run post-HITL. *)
HumanApprove ==
    /\ request_phase = "AWAITING_HUMAN"
    /\ human_approved' = TRUE
    /\ request_phase' = "SEALED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars>>

(* Rejection, expiry, or a refused post-approval re-validation. *)
HumanReject ==
    /\ request_phase = "AWAITING_HUMAN"
    /\ request_phase' = "DENIED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

(* verify_and_consume_seal + ActuatorRegistry dispatch. *)
Execute ==
    /\ request_phase = "SEALED"
    /\ request_phase' = "EXECUTED"
    /\ UNCHANGED <<request_vars, ig_vars, ctl_vars, human_approved>>

Next ==
    \/ NetworkPolicyBlock
    \/ ReachGatewayDirect
    \/ InGraphFtraNode
    \/ InGraphHumanApprove
    \/ InGraphHumanReject
    \/ ControllerBoundaryCheck
    \/ OtherTiersSeal
    \/ OtherTiersRequireApproval
    \/ OtherTiersDeny
    \/ HumanApprove
    \/ HumanReject
    \/ Execute

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS *)
-----------------------------------------------------------------------------

(* R-03: a request that skipped the in-graph node and reached a governor
   decision was checked at the controller boundary. Stated over reachable
   states: Init has every request PENDING, before any check could run. *)
ControllerBoundaryCoversInGraphBypass ==
    (request_phase \in GovernorPhases /\ ~in_graph_executed) => controller_executed

(* Stronger: the controller check runs on every governed request, in-graph
   node or not. *)
ControllerBoundaryUnconditional ==
    request_phase \in GovernorPhases => controller_executed

(* No terminal (or unknown) action executes unless a human approved it (at
   the governor or at the in-graph park) or it cleared inside its registered
   autonomous envelope. *)
NoUnreviewedIrreversibleExecution ==
    (request_phase = "EXECUTED" /\ TrulyTerminal(action_name))
        => (human_approved \/ ig_human_approved \/ auto_cleared)

(* Unregistered actions fail closed at both enforcement points. *)
FailClosedOnUnknownAction ==
    ~InRegistry(action_name) =>
        /\ in_graph_classification \in {"NONE", IRREV}
        /\ in_graph_verdict # "CLEAR" \/ parse_failure_class = "EMPTY_STEPS"
        /\ controller_executed =>
               /\ controller_classification = IRREV
               /\ controller_verdict # "CLEAR"
               /\ ~auto_cleared

(* An unreadable registry at the controller is a HARD refusal. *)
RegistryUnavailableFailsClosed ==
    (controller_executed /\ ~ctl_registry_ok) =>
        (controller_verdict = "BLOCKED" /\ request_phase = "DENIED")

(* Only a registered terminal inside its envelope, at or above the ALLOW
   floor, auto-clears (UNREGISTERED_NEVER_AUTO_CLEARS). *)
AutoClearOnlyInsideEnvelope ==
    auto_cleared =>
        /\ ctl_registry_ok /\ InRegistry(action_name) /\ HasEnvelope(action_name)
        /\ magnitude_in_envelope /\ confidence >= CONFIDENCE_ALLOW_FLOOR

(* With the NetworkPolicy applied, a source it does not permit never gets
   past the network. *)
NetworkPolicyEnforced ==
    (NetworkPolicyApplied /\ ~NetworkPolicyPermits(request_source)
        /\ request_phase # "PENDING") => request_phase = "DROPPED"

(* Both checks use the same classifier and registry: when both processes
   loaded it (or both failed to), they agree. If only one loaded it they may
   differ, and both differences are fail-closed (IRREVERSIBLE_TERMINAL). *)
ConsistentClassification ==
    (in_graph_classification # "NONE" /\ controller_executed
        /\ ig_registry_ok = ctl_registry_ok)
        => in_graph_classification = controller_classification

(* A HITL verdict at either point is never passed without a human. *)
HITLRequiredPropagates ==
    /\ (in_graph_verdict = "HITL_REQUIRED" /\ request_phase \notin {"IN_GRAPH_HITL", "REFUSED"})
           => ig_human_approved
    /\ (controller_verdict = "HITL_REQUIRED" /\ request_phase \in {"SEALED", "EXECUTED"})
           => human_approved

(* BUG-FTRA-SCHEMA-001: parse failures never CLEAR (they DEFER to a human,
   or BLOCK when there is no plan at all). *)
ParseErrorsPreventClear ==
    parse_failure_class \in NonClearingParse => in_graph_verdict # "CLEAR"

-----------------------------------------------------------------------------
(* LIVENESS — checked under FairSpec in FtraBoundary.cfg *)
-----------------------------------------------------------------------------

EveryRequestTerminates == <>(request_phase \in TerminalPhases)

=============================================================================
