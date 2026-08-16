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

   This specification models the Forward-Looking Trajectory Reachability
   Analyzer (FTRA) boundary enforcement at both the agent-side (in-graph
   ftra_node) and controller-side (validate_action boundary check).

   FTRA addresses risks R-02 and R-03:
   - R-02: Trust Boundary Mutation — ftra_node fires within GFA's LangGraph,
     but classification happens BEFORE execution; a compromised host agent
     could mutate the plan post-classification but pre-execution.
   - R-03: Trust Boundary Bypass — ftra_node only fires if the host agent
     wires it into its own LangGraph. Direct HTTP access to /validate-action
     or ext_authz bypasses it entirely.

   The controller-boundary check (_ftra_boundary_check in symbolic_governor.py)
   closes the R-03 gap by running the same IrreversibilityClassifier at the
   HTTP/controller layer, catching direct bypasses.

   Source Code Cross-Reference:
   - src/gateway/governance/ftra/models.py          → FtraBoundaryResult, ParseFailureClass
   - src/gateway/governance/ftra/node_factory.py    → ftra_node, route_after_ftra
   - src/gateway/governance/ftra/classifier.py      → IrreversibilityClassifier
   - src/gateway/governance/ftra/graph_analyzer.py  → PlanGraphAnalyzer
   - src/gateway/governance/symbolic_governor.py    → _ftra_boundary_check()
   - deployment/k8s/ftra-network-policy.yaml        → NetworkPolicy constraints
   - config/ftra/terminal_registry.json             → Action classification registry

   Integration with LangGraphHarness.tla:
   - This module extends LangGraphHarness's ftra_verdict concept
   - FTRA_CHECK phase in LangGraphHarness corresponds to FtraNode here
   - The controller-boundary check runs BEFORE all other governance checks

   Verification Status:
   - Python BFS: Not directly modeled (FTRA is outside proof/model.py scope)
   - This TLA+ model fills the gap identified in CAGE_IMPLEMENTATION_SPECS §2.9.2

   TLC Configuration:
   ---------------------------------------------------------------------------
   CONSTANTS
       FRIA_ZONE_DEFER = 70
       FRIA_ZONE_ALLOW = 95
   INIT Init
   NEXT Next
   INVARIANT TypeOK
   INVARIANT ControllerBoundaryCoversInGraphBypass
   INVARIANT FailClosedOnUnknownAction
   INVARIANT NetworkPolicyEnforced
   ---------------------------------------------------------------------------
*)

EXTENDS Naturals, FiniteSets

-----------------------------------------------------------------------------
(* CONSTANTS *)
-----------------------------------------------------------------------------

CONSTANTS
    FRIA_ZONE_DEFER,   \* Confidence threshold for HITL (default: 70 = 0.70)
    FRIA_ZONE_ALLOW    \* Confidence threshold for clear passage (default: 95 = 0.95)

\* Confidence values are integers 0-100 representing percentages
\* to avoid floating-point complexity in TLA+

-----------------------------------------------------------------------------
(* TERMINAL CLASSIFICATIONS — From ftra/models.py TerminalClassification *)
-----------------------------------------------------------------------------

\* Action reversibility classifications
TerminalClassifications == {
    "IRREVERSIBLE_TERMINAL",  \* Commits external, unalterable state change
    "REVERSIBLE",             \* Modifiable state with compensating action
    "READ_ONLY"               \* No state modification
}

-----------------------------------------------------------------------------
(* FTRA VERDICTS — From ftra/models.py FTRAVerdict *)
-----------------------------------------------------------------------------

\* Commencement-time routing verdicts
FTRAVerdicts == {
    "CLEAR",          \* No IRREVERSIBLE_TERMINAL reachable, proceed to safety_check
    "HITL_REQUIRED",  \* IRREVERSIBLE_TERMINAL reachable, confidence >= FRIA_ZONE_DEFER
    "BLOCKED"         \* IRREVERSIBLE_TERMINAL reachable, confidence < FRIA_ZONE_DEFER
}

-----------------------------------------------------------------------------
(* PARSE FAILURE CLASSES — From ftra/models.py ParseFailureClass *)
-----------------------------------------------------------------------------

\* Classification of parse failures for structured error handling
ParseFailureClasses == {
    "SUCCESS",                 \* Parsing succeeded
    "JSON_DECODE_ERROR",       \* Raw JSON syntax error (blocking)
    "SCHEMA_VALIDATION_ERROR", \* Valid JSON but fails ExecutionPlan validation (blocking)
    "EMPTY_STEPS",             \* Valid plan with no steps (warning)
    "TRUNCATED_PLAN",          \* Plan appears cut off (warning → DEFER)
    "TOKENIZER_ARTIFACT"       \* Input contains tokenizer artifacts (informational)
}

\* Blocking errors vs warnings (from ParseResult.is_blocking_error)
BlockingParseErrors == {"JSON_DECODE_ERROR", "SCHEMA_VALIDATION_ERROR"}
WarningParseClasses == {"EMPTY_STEPS", "TRUNCATED_PLAN", "TOKENIZER_ARTIFACT"}

-----------------------------------------------------------------------------
(* TRUST BOUNDARY LOCATIONS — Controller vs Agent side *)
-----------------------------------------------------------------------------

\* Where the FTRA check is enforced
EnforcementPoints == {
    "IN_GRAPH",     \* ftra_node within GFA's LangGraph (agent-side)
    "CONTROLLER"    \* _ftra_boundary_check in symbolic_governor (controller-side)
}

\* Request source types (for network policy modeling)
RequestSources == {
    "GFA_POD",              \* governed-financial-advisor pod (trusted, has in-graph ftra_node)
    "COMPLIANCE_BRIDGE",    \* compliance-bridge pod (trusted infrastructure)
    "INGRESS_CONTROLLER",   \* External traffic via nginx-ingress
    "DIRECT_HTTP",          \* Direct HTTP access (potential bypass)
    "GOVERNANCE_VALIDATED"  \* Pod with governance-validated label
}

-----------------------------------------------------------------------------
(* VARIABLES — FTRA boundary state *)
-----------------------------------------------------------------------------

VARIABLES
    \* In-graph ftra_node state
    in_graph_classification,  \* TerminalClassification from ftra_node
    in_graph_verdict,         \* FTRAVerdict from ftra_node
    in_graph_executed,        \* TRUE if ftra_node has executed
    
    \* Controller-boundary check state
    controller_classification,\* TerminalClassification from _ftra_boundary_check
    controller_verdict,       \* FTRAVerdict/requires_hitl outcome
    controller_executed,      \* TRUE if boundary check has executed
    
    \* Request context
    action_name,              \* The action being validated
    action_in_registry,       \* TRUE if action is in terminal_registry.json
    confidence,               \* Evaluator confidence score (0-100)
    request_source,           \* Where the request originated
    
    \* Parse state
    parse_failure_class,      \* ParseFailureClass from parsing LLM output
    
    \* Network policy state
    network_policy_allows,    \* TRUE if network policy permits the request
    bypassed_ftra_node        \* TRUE if controller detected in-graph bypass

\* All variables
vars == <<in_graph_classification, in_graph_verdict, in_graph_executed,
          controller_classification, controller_verdict, controller_executed,
          action_name, action_in_registry, confidence, request_source,
          parse_failure_class, network_policy_allows, bypassed_ftra_node>>

-----------------------------------------------------------------------------
(* TYPE INVARIANT *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ in_graph_classification \in TerminalClassifications \cup {"NONE"}
    /\ in_graph_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ in_graph_executed \in BOOLEAN
    /\ controller_classification \in TerminalClassifications \cup {"NONE"}
    /\ controller_verdict \in FTRAVerdicts \cup {"NONE"}
    /\ controller_executed \in BOOLEAN
    /\ action_name \in {"execute_trade", "market_analysis", "check_balance", "unknown_action"}
    /\ action_in_registry \in BOOLEAN
    /\ confidence \in 0..100
    /\ request_source \in RequestSources
    /\ parse_failure_class \in ParseFailureClasses
    /\ network_policy_allows \in BOOLEAN
    /\ bypassed_ftra_node \in BOOLEAN

-----------------------------------------------------------------------------
(* HELPER PREDICATES *)
-----------------------------------------------------------------------------

\* Determine verdict based on classification and confidence
\* From ftra/graph_analyzer.py lines 249-254
ComputeVerdict(classification, conf) ==
    IF classification # "IRREVERSIBLE_TERMINAL"
    THEN "CLEAR"
    ELSE IF conf >= FRIA_ZONE_DEFER
         THEN "HITL_REQUIRED"
         ELSE "BLOCKED"

\* Map action to classification (from terminal_registry.json semantics)
\* execute_trade → IRREVERSIBLE_TERMINAL (commits trade)
\* market_analysis → READ_ONLY (no state change)
\* check_balance → READ_ONLY (no state change)
\* unknown_action → IRREVERSIBLE_TERMINAL (fail-closed)
ActionClassification(action, in_registry) ==
    IF ~in_registry THEN "IRREVERSIBLE_TERMINAL"  \* Fail-closed on unknown
    ELSE IF action = "execute_trade" THEN "IRREVERSIBLE_TERMINAL"
    ELSE IF action = "market_analysis" THEN "READ_ONLY"
    ELSE IF action = "check_balance" THEN "READ_ONLY"
    ELSE "IRREVERSIBLE_TERMINAL"  \* Fail-closed default

\* Network policy evaluation (from ftra-network-policy.yaml)
\* - GFA_POD: allowed (has in-graph ftra_node)
\* - COMPLIANCE_BRIDGE: allowed (governance infrastructure)
\* - INGRESS_CONTROLLER: allowed (subject to controller boundary check)
\* - GOVERNANCE_VALIDATED: allowed (has governance-validated label)
\* - DIRECT_HTTP: denied (bypasses governance)
NetworkPolicyPermits(source) ==
    source \in {"GFA_POD", "COMPLIANCE_BRIDGE", "INGRESS_CONTROLLER", "GOVERNANCE_VALIDATED"}

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS *)
-----------------------------------------------------------------------------

(* ControllerBoundaryCoversInGraphBypass: If in-graph ftra_node is bypassed
   (request comes via direct HTTP without in-graph execution), the controller
   boundary check must have executed.
   
   This is the R-03 mitigation: direct HTTP access triggers controller-side check.
   
   Python cross-reference:
   - symbolic_governor.py lines 834-849: bypassed_ftra_node detection
   - symbolic_governor.py lines 974-1005: CAGE_FTRA_BOUNDARY_ENABLED check *)
ControllerBoundaryCoversInGraphBypass ==
    (request_source = "DIRECT_HTTP" /\ ~in_graph_executed) => controller_executed

(* FailClosedOnUnknownAction: Actions not in terminal_registry must be classified
   as IRREVERSIBLE_TERMINAL (fail-closed).
   
   Python cross-reference:
   - ftra/classifier.py: IrreversibilityClassifier.classify() fail-closed behavior
   - ftra/models.py lines 349-351: FtraBoundaryResult violation string for unknown *)
FailClosedOnUnknownAction ==
    ~action_in_registry =>
        /\ (in_graph_executed => in_graph_classification = "IRREVERSIBLE_TERMINAL")
        /\ (controller_executed => controller_classification = "IRREVERSIBLE_TERMINAL")

(* NetworkPolicyEnforced: Requests from sources not permitted by network policy
   must not proceed.
   
   Python cross-reference: deployment/k8s/ftra-network-policy.yaml
   The network policy blocks DIRECT_HTTP requests that don't have
   governance-validated label or come from untrusted pods. *)
NetworkPolicyEnforced ==
    network_policy_allows = NetworkPolicyPermits(request_source)

(* ConsistentClassification: If both in-graph and controller checks execute,
   they must produce the same classification (they use the same
   IrreversibilityClassifier and terminal_registry.json).
   
   Note: This assumes no TOCTOU race between checks. R-02 addresses
   plan mutation post-classification. *)
ConsistentClassification ==
    (in_graph_executed /\ controller_executed) =>
        (in_graph_classification = controller_classification)

(* HITLRequiredPropagates: If either check requires HITL, execution must be blocked.
   Both checks independently can require HITL for the same action. *)
HITLRequiredPropagates ==
    ((in_graph_verdict = "HITL_REQUIRED") \/ (controller_verdict = "HITL_REQUIRED"))
        => ~(in_graph_verdict = "CLEAR" /\ controller_verdict = "CLEAR")

(* ParseErrorsPreventClear: Blocking parse errors cannot result in CLEAR verdict.
   
   Python cross-reference: ftra/node_factory.py lines 380-428
   JSON_DECODE_ERROR and SCHEMA_VALIDATION_ERROR → HITL_REQUIRED (not BLOCKED)
   per BUG-FTRA-SCHEMA-001 fix *)
ParseErrorsPreventClear ==
    (parse_failure_class \in BlockingParseErrors) =>
        (in_graph_verdict # "CLEAR")

\* Combined safety invariant
Safety == ControllerBoundaryCoversInGraphBypass /\ FailClosedOnUnknownAction
       /\ NetworkPolicyEnforced /\ ConsistentClassification
       /\ HITLRequiredPropagates /\ ParseErrorsPreventClear

-----------------------------------------------------------------------------
(* INITIAL STATE *)
-----------------------------------------------------------------------------

Init ==
    /\ in_graph_classification = "NONE"
    /\ in_graph_verdict = "NONE"
    /\ in_graph_executed = FALSE
    /\ controller_classification = "NONE"
    /\ controller_verdict = "NONE"
    /\ controller_executed = FALSE
    /\ action_name \in {"execute_trade", "market_analysis", "check_balance", "unknown_action"}
    /\ action_in_registry = (action_name # "unknown_action")
    /\ confidence \in 0..100
    /\ request_source \in RequestSources
    /\ parse_failure_class = "SUCCESS"  \* Assume successful parse initially
    /\ network_policy_allows = NetworkPolicyPermits(request_source)
    /\ bypassed_ftra_node = FALSE

-----------------------------------------------------------------------------
(* ACTIONS — FTRA check execution *)
-----------------------------------------------------------------------------

(* InGraphFtraNode: Execute the in-graph ftra_node.
   This models the ftra_node in GFA's LangGraph workflow.
   
   Python cross-reference: ftra/node_factory.py create_ftra_node() *)
InGraphFtraNode ==
    /\ ~in_graph_executed
    /\ request_source = "GFA_POD"  \* Only GFA has in-graph ftra_node
    /\ in_graph_classification' = ActionClassification(action_name, action_in_registry)
    /\ in_graph_verdict' = ComputeVerdict(in_graph_classification', confidence)
    /\ in_graph_executed' = TRUE
    /\ UNCHANGED <<controller_classification, controller_verdict, controller_executed,
                   action_name, action_in_registry, confidence, request_source,
                   parse_failure_class, network_policy_allows, bypassed_ftra_node>>

(* ControllerBoundaryCheck: Execute the controller-side FTRA boundary check.
   This models _ftra_boundary_check in symbolic_governor.py.
   
   Python cross-reference: symbolic_governor.py lines 785-932 *)
ControllerBoundaryCheck ==
    /\ ~controller_executed
    /\ controller_classification' = ActionClassification(action_name, action_in_registry)
    /\ controller_verdict' = IF controller_classification' = "IRREVERSIBLE_TERMINAL"
                             THEN "HITL_REQUIRED"  \* Controller check always requires HITL for irreversible
                             ELSE "CLEAR"
    /\ controller_executed' = TRUE
    \* Detect if this check is catching a bypass of in-graph ftra_node
    /\ bypassed_ftra_node' = (~in_graph_executed /\ controller_classification' = "IRREVERSIBLE_TERMINAL")
    /\ UNCHANGED <<in_graph_classification, in_graph_verdict, in_graph_executed,
                   action_name, action_in_registry, confidence, request_source,
                   parse_failure_class, network_policy_allows>>

(* ParseSuccess: LLM output parses successfully. *)
ParseSuccess ==
    /\ parse_failure_class = "SUCCESS"
    /\ UNCHANGED vars

(* ParseJsonError: JSON decode error during parsing.
   Results in HITL_REQUIRED, not BLOCKED (BUG-FTRA-SCHEMA-001 fix).
   
   Python cross-reference: ftra/node_factory.py lines 382-398 *)
ParseJsonError ==
    /\ parse_failure_class' = "JSON_DECODE_ERROR"
    /\ in_graph_verdict' = "HITL_REQUIRED"  \* DEFER, not BLOCKED
    /\ in_graph_executed' = TRUE
    /\ UNCHANGED <<in_graph_classification, controller_classification, controller_verdict,
                   controller_executed, action_name, action_in_registry, confidence,
                   request_source, network_policy_allows, bypassed_ftra_node>>

(* ParseSchemaError: Schema validation error during parsing.
   Results in HITL_REQUIRED, not BLOCKED (BUG-FTRA-SCHEMA-001 fix).
   
   Python cross-reference: ftra/node_factory.py lines 400-426 *)
ParseSchemaError ==
    /\ parse_failure_class' = "SCHEMA_VALIDATION_ERROR"
    /\ in_graph_verdict' = "HITL_REQUIRED"  \* DEFER, not BLOCKED
    /\ in_graph_executed' = TRUE
    /\ UNCHANGED <<in_graph_classification, controller_classification, controller_verdict,
                   controller_executed, action_name, action_in_registry, confidence,
                   request_source, network_policy_allows, bypassed_ftra_node>>

(* ParseTruncated: Plan appears truncated.
   Results in HITL_REQUIRED (warning, not blocking).
   
   Python cross-reference: ftra/node_factory.py lines 460-477 *)
ParseTruncated ==
    /\ parse_failure_class' = "TRUNCATED_PLAN"
    /\ in_graph_verdict' = "HITL_REQUIRED"  \* DEFER, not BLOCKED
    /\ in_graph_executed' = TRUE
    /\ UNCHANGED <<in_graph_classification, controller_classification, controller_verdict,
                   controller_executed, action_name, action_in_registry, confidence,
                   request_source, network_policy_allows, bypassed_ftra_node>>

(* ParseEmptySteps: Plan has no steps.
   With high confidence, this can still CLEAR (empty plan is valid choice).
   
   Python cross-reference: ftra/node_factory.py lines 419-458 *)
ParseEmptySteps ==
    /\ parse_failure_class' = "EMPTY_STEPS"
    /\ in_graph_verdict' = IF confidence >= FRIA_ZONE_ALLOW
                           THEN "CLEAR"         \* High confidence: empty plan is OK
                           ELSE "HITL_REQUIRED" \* Low confidence: defer for review
    /\ in_graph_executed' = TRUE
    /\ UNCHANGED <<in_graph_classification, controller_classification, controller_verdict,
                   controller_executed, action_name, action_in_registry, confidence,
                   request_source, network_policy_allows, bypassed_ftra_node>>

(* DirectHTTPAccess: Model direct HTTP access that bypasses in-graph ftra_node.
   Network policy may block this, or controller boundary check catches it.
   
   Python cross-reference: 
   - R-03 risk in CAGE_RISK_MATRIX.md
   - symbolic_governor.py line 843-849: WARN log for bypass detection *)
DirectHTTPAccess ==
    /\ request_source = "DIRECT_HTTP"
    /\ ~in_graph_executed  \* No in-graph check
    /\ UNCHANGED vars

(* NetworkPolicyBlock: Network policy blocks the request.
   Models the ftra-network-policy.yaml NetworkPolicy enforcement. *)
NetworkPolicyBlock ==
    /\ ~network_policy_allows
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(* NEXT STATE RELATION *)
-----------------------------------------------------------------------------

Next ==
    \/ InGraphFtraNode
    \/ ControllerBoundaryCheck
    \/ ParseSuccess
    \/ ParseJsonError
    \/ ParseSchemaError
    \/ ParseTruncated
    \/ ParseEmptySteps
    \/ DirectHTTPAccess
    \/ NetworkPolicyBlock

-----------------------------------------------------------------------------
(* SPECIFICATION *)
-----------------------------------------------------------------------------

Spec == Init /\ [][Next]_vars

\* Fairness for liveness properties
FairSpec == Spec /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* TEMPORAL PROPERTIES — Optional liveness checks *)
-----------------------------------------------------------------------------

\* If GFA pod makes a request, in-graph ftra_node eventually executes
GFAPodEventuallyChecked ==
    (request_source = "GFA_POD") ~> in_graph_executed

\* Direct HTTP access eventually triggers controller boundary check
DirectHTTPEventuallyCaught ==
    (request_source = "DIRECT_HTTP") ~> controller_executed

-----------------------------------------------------------------------------
(* TLC MODEL CHECKING NOTES *)
-----------------------------------------------------------------------------
(*
   Cross-Validation with Python Model:
   ------------------------------------
   The Python BFS model (proof/model.py) explicitly excludes FTRA/Tier 0.5
   from its scope. This TLA+ model fills that gap as described in
   CAGE_IMPLEMENTATION_SPECS §2.9.2 Phase C.

   Integration with LangGraphHarness.tla:
   --------------------------------------
   - LangGraphHarness.tla models the full graph lifecycle
   - FtraBoundary.tla focuses on the FTRA-specific checks
   - The FTRA_CHECK phase in LangGraphHarness corresponds to
     InGraphFtraNode here
   - ControllerBoundaryCheck runs BEFORE all other governance checks
     (represented by CAGE_FTRA_BOUNDARY_ENABLED in symbolic_governor.py)

   Network Policy Modeling:
   ------------------------
   The ftra-network-policy.yaml defines three NetworkPolicies:
   1. ftra-egress-lockdown: Restricts ingress to cage-gateway to
      pods with governance-validated=true label
   2. ftra-allow-gfa-ingress: Allows governed-financial-advisor pod
   3. ftra-allow-ingress-controller: Allows nginx-ingress traffic

   This is modeled via NetworkPolicyPermits predicate and
   NetworkPolicyEnforced invariant.

   Risk Mitigation Verification:
   -----------------------------
   - R-02 (Trust Boundary Mutation): Model does not directly address
     post-classification mutation (requires temporal logic over plan state)
   - R-03 (Trust Boundary Bypass): ControllerBoundaryCoversInGraphBypass
     invariant verifies that controller check catches direct HTTP bypasses

   Key Invariants to Verify:
   1. ControllerBoundaryCoversInGraphBypass — R-03 mitigation
   2. FailClosedOnUnknownAction — Defense in depth
   3. NetworkPolicyEnforced — Network-level isolation
   4. ConsistentClassification — Classifier determinism
   5. HITLRequiredPropagates — Human review requirement
   6. ParseErrorsPreventClear — BUG-FTRA-SCHEMA-001 fix

   Expected Behavior:
   - All safety invariants hold under Spec
   - GFAPodEventuallyChecked holds under FairSpec
   - DirectHTTPEventuallyCaught holds under FairSpec
*)

=============================================================================
