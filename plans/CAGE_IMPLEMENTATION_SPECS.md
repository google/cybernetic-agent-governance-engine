# CAGE Implementation Specifications & Architecture Decisions

| Field | Value |
|---|---|
| Status | DRAFT — design only, no code changes |
| Scope | P0/P1/P2 remediation items from CAGE analysis (DEFER wiring, reconciliation worker activation, evidence chain blocking gate, FTRA hardening, Redis failover, formal model extensions) |
| Audience | Engineers implementing the remediation backlog |

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Technical Specifications by Component](#2-technical-specifications-by-component)
3. [API Contract Changes](#3-api-contract-changes)
4. [Data Model Changes](#4-data-model-changes)
5. [Integration Points](#5-integration-points)
6. [Migration Considerations](#6-migration-considerations)

## 1. Architecture Overview

### 1.1 Current State — DEFER Collapse & Reconciliation Gap

```
                         ┌─────────────────────────────┐
                         │   agent_gateway_adapter.py   │
                         │   handle_check_request()     │
                         └──────────────┬────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │  symbolic_governor.validate_  │
                         │  action() — 7-tier pipeline   │
                         └──────────────┬────────────────┘
                                        │
                     ┌──────────────────┼───────────────────┐
                     ▼                  ▼                    ▼
                 violations=[]     "Manual Review          any other
                                    Required" in            violation
                                    violations[0]           string
                     │                  │                    │
                     ▼                  ▼                    ▼
                  ALLOW          REQUIRE_APPROVAL      raise GovernanceError
                  (seal)         (HTTP 202)            (HTTP 403 DENY-shaped)
                                                              │
                                                              ▼
                                              *** GovernanceDecision.DEFER is
                                                  NEVER constructed here ***
                                                  low-confidence / ambiguous-
                                                  context cases that SHOULD
                                                  route to DeferQueue instead
                                                  collapse into a hard DENY.
```

Evidence: [`symbolic_governor.py:1410-1463`](../src/gateway/governance/symbolic_governor.py:1410) only special-cases the
`REQUIRE_APPROVAL` (OPA `MANUAL_REVIEW`) branch before falling through to
`raise GovernanceError(violations[0], ...)` for every other violation,
including ones that are semantically `DEFER` conditions (confidence below the
Confidence-Starvation Boundary, missing FRIA context, etc. — see
[`decisions.py:113-127`](../src/gateway/governance/decisions.py:113) and
[`defer_queue.py:80-105`](../src/gateway/governance/defer_queue.py:80) for the
already-defined `DeferReason` vocabulary). `GovernanceDecision.DEFER` exists in
the enum ([`decisions.py:113`](../src/gateway/governance/decisions.py:113)) and
is fully wired on the **adapter** side
([`agent_gateway_adapter.py:386-407`](../src/gateway/server/agent_gateway_adapter.py:386)
already renders `verdict=DEFER` as an HTTP 202 with `defer_id` /
`missing_input_reason`) — but nothing in `validate_action()` ever *returns*
that verdict. The FTRA node factory is the **only** current producer of a
`DeferToken` ([`node_factory.py:334-406`](../src/gateway/governance/ftra/node_factory.py:334)),
and it operates one layer up in the LangGraph plan-level gate, not inside
`SymbolicGovernor`.

```
Reconciliation Worker — code/manifest exist, secret never populated
──────────────────────────────────────────────────────────────────
┌────────────────────┐   schedule: */5 * * * *   ┌───────────────────────┐
│ CronJob             │──────────────────────────▶│ reconciliation-worker  │
│ (k8s manifest EXISTS│                            │ pod (compliance-bridge│
│  and is correct)    │                            │  image)                │
└────────────────────┘                            └───────────┬────────────┘
                                                                │ reads env
                                                                ▼
                                                   ┌─────────────────────────┐
                                                   │ reconciliation-worker-   │
                                                   │ secrets Secret            │
                                                   │  gcs-reconciliation-      │
                                                   │  bucket: ⚠ NEVER SET     │
                                                   └───────────┬──────────────┘
                                                                │
                                                                ▼
                                              CreateContainerConfigError
                                              (POAM-2026-038, reopened 2026-08-09)
                                                                │
                                                                ▼
                                        FiscalLimitGuard falls back to
                                        un-reconciled Redis counters —
                                        fiscal:daily_limit:{day} over-counts
```

Evidence: [`deployment/k8s/reconciliation-worker.yaml:130-148`](../deployment/k8s/reconciliation-worker.yaml:130)
correctly sets `RECONCILIATION_PROVIDER=gcs` and wires `GCS_RECONCILIATION_BUCKET`
from `secretKeyRef: reconciliation-worker-secrets/gcs-reconciliation-bucket`, and
[`reconciliation_worker.py:1147-1157`](../src/compliance_bridge/reconciliation_worker.py:1147)
already registers `"gcs": GcsLedgerProvider` in the provider dict. Both
artifacts are code/manifest-complete; [`docs/POAM.md:76`](../docs/POAM.md:76)
(POAM-2026-038) confirms the only outstanding item is out-of-band secret
population.

### 1.2 Target State Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │            symbolic_governor.validate_action()  │
                    │                                                  │
                    │   ┌──────────────────────────────────────────┐  │
                    │   │ _classify_violation(violations) →         │  │
                    │   │   ALLOW | DENY | REQUIRE_APPROVAL | DEFER  │  │
                    │   └──────────────────────────────────────────┘  │
                    └───────┬───────────┬────────────┬────────────┬───┘
                            ▼           ▼            ▼            ▼
                          ALLOW       DENY     REQUIRE_APPROVAL  DEFER
                        (200, seal) (403)      (202 + thread_id) (202 + defer_id)
                            │                                       │
                            │                                       ▼
                            │                          DeferQueue.park() — Redis db=1
                            │                          NARROW/PAUSE primitives available
                            │                          for partial-authority execution
                            ▼
              ┌─────────────────────────────────────────┐
              │  Controller/HTTP boundary FTRA check      │
              │  (NEW — closes untrusted-Plant bypass)     │
              │  Equivalent IrreversibilityClassifier gate │
              │  runs INSIDE SymbolicGovernor, not just    │
              │  inside the host agent's LangGraph process │
              └─────────────────────────────────────────┘

     Evidence Chain (blocking gate)                 Reconciliation Worker (active)
     ───────────────────────────────                ──────────────────────────────
     validate_action() ALLOW path                    CronJob */5m — secret populated
        │                                               │
        ▼                                               ▼
     if EVIDENCE_CHAIN_BLOCKING=true:                GcsLedgerProvider.fetch_balance()
        await sink.ingest_sync(event)  ← BLOCKS          │
        seal issuance until durable                      ▼
        chain commit succeeds                        KMS-signed write → Redis
        else: fail-closed DENY                        reconciliation:verified_balance
```

### 1.3 Component Interaction — FTRA Dual-Gate (Plant + Controller)

```
Host Agent Process (untrusted "Plant")          Gateway Process (trusted "Controller")
───────────────────────────────────────         ────────────────────────────────────────
execution_analyst → evaluator                    POST /validate-action (HTTP boundary)
        │                                                  │
        ▼                                                  ▼
   ftra_node (create_ftra_node())              symbolic_governor.validate_action()
        │  CLEAR/HITL_REQUIRED/BLOCKED                     │
        ▼                                        NEW: ftra_boundary_check(action, params)
   safety_check (OPA)                              — re-derives ExecutionPlan from params
        │                                            (or receives ftra_result attestation)
        ▼                                          — re-classifies against terminal_registry
   governed_trader ─────── HTTP call ──────────▶  — BLOCKS/DEFERs even if the host's
                                                     ftra_node was bypassed, patched out,
                                                     or never wired into the caller's graph
```

This closes the bypass documented in the analysis: *"FTRA runs inside the
untrusted host agent process... an adversary with direct HTTP access to the
Controller can bypass it entirely."* Both gates share the same
`IrreversibilityClassifier` and `config/ftra/terminal_registry.json`
([`classifier.py`](../src/gateway/governance/ftra/classifier.py)) so
classification never drifts between the two enforcement points.

## 2. Technical Specifications by Component

### 2.1 Governance Layer — DEFER/NARROW/PAUSE Primitives

**Problem statement.** [`symbolic_governor.py:1435-1463`](../src/gateway/governance/symbolic_governor.py:1435)
treats every non-`REQUIRE_APPROVAL` violation identically: it builds a
`RefusalReceipt` and raises `GovernanceError`. There is no code path that
returns `GovernanceDecision.DEFER`. Two new runtime primitives — `NARROW` and
`PAUSE` — do not exist at all today; they are referenced only in the analysis
findings, not in `decisions.py`.

**Design.**

1. **Violation classification function.** Introduce a pure function that
   inspects the violation list (and the tier that produced it) and returns a
   `GovernanceDecision` plus structured metadata, replacing the current
   single `if _is_manual_review` branch:

   ```python
   # src/gateway/governance/symbolic_governor.py (new helper)
   def _classify_violation(
       violations: list[str],
       stpa_violation_count: int,
       confidence: float | None,
   ) -> tuple[GovernanceDecision, dict[str, Any]]:
       """Map raw violation strings to a canonical GovernanceDecision.

       Returns (decision, meta) where meta carries decision-specific fields
       (defer_reason, thread_id hints, narrow_scope, pause_resume_token).
       """
   ```

   Classification rules (extends the existing `REQUIRE_APPROVAL` special
   case, does not replace it):

   | Condition | Decision | DeferReason / detail |
   |---|---|---|
   | `"Manual Review Required"` in violations[0] | `REQUIRE_APPROVAL` | unchanged |
   | `confidence is not None and confidence < FRIA_ZONE_DEFER` | `DEFER` | `DeferReason.CONFIDENCE_BELOW_THRESHOLD` |
   | STPA/OPA input snapshot missing required fields | `DEFER` | `DeferReason.INSUFFICIENT_CONTEXT` |
   | Any other violation | `DENY` (current behavior, unchanged) | — |

2. **DEFER wiring in `validate_action()`.** After `_run_checks()` returns,
   before the existing `if violations:` DENY branch
   ([`symbolic_governor.py:1435`](../src/gateway/governance/symbolic_governor.py:1435)),
   insert:

   ```python
   decision, meta = _classify_violation(
       violations, _stpa_violation_count, params.get("confidence")
   )
   if decision == GovernanceDecision.DEFER:
       from src.gateway.governance.defer_queue import DeferQueue, DeferToken, DeferReason
       token = DeferToken(
           thread_id=str(params.get("thread_id") or params.get("transaction_id") or ""),
           defer_reason=meta["defer_reason"],
           opa_input_snapshot=_sanitize_for_defer(params),
           confidence_score=params.get("confidence"),
       )
       defer_id = await DeferQueue().park(token)
       span.set_attribute("cage.verdict", GovernanceDecision.DEFER)
       return {
           "verdict": GovernanceDecision.DEFER,
           "violations": violations,
           "seal": "",
           "defer_id": defer_id,
           "missing_input_reason": meta["defer_reason"].value,
           "latency_ms": latency_ms,
       }
   ```

   This reuses the already-implemented `DeferQueue`/`DeferToken` machinery in
   [`defer_queue.py`](../src/gateway/governance/defer_queue.py) — no new
   Redis schema is required for the DEFER path itself (see §4.2).

3. **HTTP 202 routing.** No change required in
   [`agent_gateway_adapter.py:386-407`](../src/gateway/server/agent_gateway_adapter.py:386)
   — the `verdict == GovernanceDecision.DEFER` branch already builds the
   correct 202 response. The gap is entirely upstream in `validate_action()`.
   `governance_middleware.py`'s `/validate-action` endpoint
   ([`governance_middleware.py:611-717`](../src/gateway/server/governance_middleware.py:611))
   propagates `result["verdict"]` transparently and requires no change either,
   confirming this is a single-point fix in `symbolic_governor.py`.

4. **NARROW primitive (new).** `NARROW` represents *partial-authority*
   execution: the agent may proceed with a reduced action scope (e.g. a
   smaller trade amount, or a read-only variant of the requested action)
   rather than being fully blocked or fully deferred. Add to
   `decisions.py`:

   ```python
   class GovernanceDecision(str, Enum):
       ...
       NARROW = "NARROW"
       """Action is partially approved with a reduced/clamped scope.

       Emitted when a tier (typically FiscalLimitGuard or the CBF) can
       satisfy a *smaller* version of the request but not the one requested
       verbatim. HTTP response: 200 with `verdict: NARROW`, `narrowed_params`
       (the clamped payload the caller must re-submit or accept), and
       `narrow_reason`.
       """
   ```

   Enforcement point: `SymbolicGovernor._run_checks()` CBF branch
   ([`symbolic_governor.py:359-403`](../src/gateway/governance/symbolic_governor.py:359))
   — when `atomic_verify_and_commit()` reports an envelope violation that is
   solely attributable to amount (not to a hard policy DENY), compute the
   maximum admissible amount via the existing barrier certificate
   (`h(S) = cash_balance - min_cash_balance`, [`cbf.py:31-42`](../src/gateway/governance/cbf.py:31))
   and return `NARROW` with the clamped amount instead of `DENY`. This is
   opt-in via `CAGE_NARROW_ENABLED` (default `"false"`) so existing DENY
   semantics are preserved until callers adopt the new contract (see §6.3
   feature-flag rollout).

5. **PAUSE primitive (new).** `PAUSE` represents a *resumable* suspension —
   distinct from `DEFER` (automated data-hydration) and `REQUIRE_APPROVAL`
   (human sign-off): the graph is parked with a resume token that any
   authorized caller (human or system) can present to continue execution
   from the exact suspension point, without re-running the full pipeline.

   ```python
   PAUSE = "PAUSE"
   """Action execution is suspended pending an explicit resume signal.

   Unlike DEFER (automated hydration) or REQUIRE_APPROVAL (human review of
   a complete context), PAUSE is used when the LangGraph host raises a
   NodeInterrupt/GraphInterrupt for a reason CAGE does not natively resolve
   (e.g. host-specific rate limiting, external system maintenance window).
   HTTP response: 202 with `verdict: PAUSE`, `resume_token`, `resume_after`
   (ISO-8601 timestamp or null for manual-only resume).
   Client action: POST /v1/pause/{resume_token}/resume.
   """
   ```

   Implementation reuses the `NodeInterrupt`/`GraphInterrupt` mechanism
   already proven out in FTRA's `_raise_node_interrupt()`
   ([`node_factory.py:408-431`](../src/gateway/governance/ftra/node_factory.py:408)),
   generalized into a shared helper
   `src/gateway/governance/pause_primitive.py` so any node factory
   (`nemo_node_factory.py`, `opa_node_factory.py`, future harness nodes) can
   raise a `PAUSE` verdict without duplicating the graceful-degradation
   logic for older LangGraph versions.

**Files touched (design-time inventory, no code written in this document):**

| File | Change |
|---|---|
| [`src/gateway/governance/decisions.py`](../src/gateway/governance/decisions.py) | Add `NARROW`, `PAUSE` enum members |
| [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) | Add `_classify_violation()`; wire DEFER/NARROW returns in `validate_action()` |
| [`src/gateway/governance/pause_primitive.py`](../src/gateway/governance/pause_primitive.py) (new) | Shared `NodeInterrupt`/`GraphInterrupt` PAUSE helper |
| [`src/gateway/governance/provenance_chain.py`](../src/gateway/governance/provenance_chain.py) | Extend `VALID_DECISIONS` frozenset (currently `{ALLOW, BLOCK, ESCALATE, REQUIRE_APPROVAL, DEFER}`, [line 66](../src/gateway/governance/provenance_chain.py:66)) with `NARROW`, `PAUSE` |
| [`src/gateway/server/agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py) | Add `NARROW`/`PAUSE` branches to `handle_check_request()` (mirrors existing `DEFER` branch at [line 386](../src/gateway/server/agent_gateway_adapter.py:386)) |
| `proof/model.py` | Extend the tier tuple's outcome domain if DEFER/NARROW/PAUSE are to be included in the formal model (see §2.6 / §6) |

### 2.2 Controller-Boundary FTRA Enforcement (Bypass Closure)

**Problem statement.** `create_ftra_node()` is a LangGraph node that only
executes if the host agent's graph wires it in
([`graph.py:127`](../src/governed_financial_advisor/graph/graph.py:127)). A
caller with direct HTTP access to `/validate-action` or the ext_authz
`/check` endpoint bypasses the LangGraph process entirely and never
triggers FTRA.

**Design.** Add a Tier 0.5-equivalent check *inside*
`SymbolicGovernor._run_checks()`, gated on the presence of a plan-shaped
payload:

```python
# src/gateway/governance/symbolic_governor.py
async def _ftra_boundary_check(
    self, tool_name: str, params: dict[str, Any]
) -> list[str]:
    """Controller-boundary equivalent of ftra_node — closes the untrusted-
    Plant bypass. Runs INSIDE SymbolicGovernor, independent of whether the
    calling process wired ftra_node into its own LangGraph graph.

    Returns a list of violation strings (empty if CLEAR or not applicable).
    """
    if "execution_plan" not in params and "execution_plan_output" not in params:
        return []  # Not a plan-shaped action; FTRA does not apply.
    from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
    from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
    ...
```

This is registered as a new step in `_run_checks()` immediately after the
STPA tier (before Tier 2/CBF), sharing the same
`IrreversibilityClassifier`/`config/ftra/terminal_registry.json` used by the
in-graph `ftra_node`
([`classifier.py:56-113`](../src/gateway/governance/ftra/classifier.py:56)),
so classification is identical regardless of enforcement point. When the
boundary check yields `HITL_REQUIRED`, it routes through the same
`_classify_violation()` → `DEFER`/`REQUIRE_APPROVAL` path described in
§2.1 rather than introducing a third parking mechanism.

**Compatibility contract.** Document as a first-class harness requirement
(per the analysis's recommendation #2): *"FTRA requires the host agent to
materialize a complete multi-step `ExecutionPlan` before any tool
execution; reactive/ReAct-style agents without an upfront plan are not
currently supported and will fail closed."* This applies to both the
in-graph node and the new Controller-boundary check.

### 2.3 Evidence Chain — Blocking Gate

**Problem statement.** [`evidence_stream.py:106`](../src/compliance_bridge/evidence_stream.py:106)
defaults `EVIDENCE_STREAM_ENABLED` to `"false"`, and even when enabled,
`ingest()` ([`evidence_stream.py:261-331`](../src/compliance_bridge/evidence_stream.py:261))
is fire-and-forget: failures are logged and `None` is returned, never
raised. Seal issuance in `validate_action()`
([`symbolic_governor.py:1469-1471`](../src/gateway/governance/symbolic_governor.py:1469))
has no dependency on evidence chain commit status at all.

**Design.**

1. **New env var** `EVIDENCE_CHAIN_BLOCKING` (default `"false"`). When
   `"true"`, seal issuance in `validate_action()` MUST NOT proceed until a
   synchronous `ingest_sync()` call confirms durable commit.

2. **New synchronous method** on `EvidenceStreamSink`:

   ```python
   # src/compliance_bridge/evidence_stream.py
   async def ingest_sync(
       self, event: dict, timeout_s: float = 2.0
   ) -> str:
       """Synchronous-contract variant of ingest().

       Unlike ingest(), this method:
         - Raises EvidenceChainUnavailableError if Redis is unreachable,
           the XADD fails, or the call exceeds `timeout_s`, instead of
           returning None.
         - Is intended to be awaited on the request-serving path when
           EVIDENCE_CHAIN_BLOCKING=true, gating seal issuance.

       Returns:
           The Redis Stream message ID (never None — raises instead).
       """
   ```

3. **Call-site integration** in `validate_action()`, immediately before the
   existing `cage.routing_seal` span
   ([`symbolic_governor.py:1469`](../src/gateway/governance/symbolic_governor.py:1469)):

   ```python
   if os.getenv("EVIDENCE_CHAIN_BLOCKING", "false").lower() == "true":
       from src.compliance_bridge.evidence_stream import get_evidence_sink
       try:
           await get_evidence_sink().ingest_sync(governance_event)
       except EvidenceChainUnavailableError as exc:
           raise GovernanceError(
               f"Evidence chain commit failed — seal issuance blocked (fail-closed): {exc}"
           )
   ```

4. **Fail-closed semantics.** When `EVIDENCE_CHAIN_BLOCKING=true` and the
   evidence sink is unavailable, `validate_action()` must DENY rather than
   silently proceed — this inverts the current fail-open default described
   in the analysis ("on backend unavailability, ingestion is silently
   skipped rather than raising or halting the request").

5. **Backward compatibility.** When `EVIDENCE_CHAIN_BLOCKING=false`
   (default), behavior is byte-for-byte identical to today: the existing
   fire-and-forget SSE/evidence-stream publish path
   (`GovernanceEventBus.publish()` → `EvidenceStreamSink.ingest()`) is
   untouched.

### 2.4 FTRA Harness — Pluggable Extractor Abstraction

**Problem statement.** `create_ftra_node()` hard-codes the state keys
`execution_plan_output` and reads `evaluation_result` for confidence
implicitly via the caller
([`node_factory.py:180-230`](../src/gateway/governance/ftra/node_factory.py:180)),
coupling FTRA to GFA's specific `AgentState` schema
([`state.py:86-96`](../src/governed_financial_advisor/graph/state.py:86)).
This mirrors the already-solved pattern in `OpaNodeConfig.payload_extractor`
([`types.py:53-85`](../src/gateway/governance/langgraph_harness/types.py:53))
and `NemoNodeConfig.message_extractor`
([`types.py:93-123`](../src/gateway/governance/langgraph_harness/types.py:93)).

**Design.** Add an `FtraNodeConfig` dataclass to
[`langgraph_harness/types.py`](../src/gateway/governance/langgraph_harness/types.py),
following the existing `OpaNodeConfig`/`NemoNodeConfig` convention:

```python
# src/gateway/governance/langgraph_harness/types.py

#: Callable that extracts an ExecutionPlan (or None) from agent state.
PlanExtractor: TypeAlias = Callable[[StateDict], "ExecutionPlan | None"]

#: Callable that extracts the Evaluator confidence score from agent state.
ConfidenceExtractor: TypeAlias = Callable[[StateDict], float]


@dataclasses.dataclass(frozen=True)
class FtraNodeConfig:
    """Configuration for :func:`create_ftra_node`.

    Args:
        plan_extractor: Callable that receives the full agent state dict
            and returns a parsed ExecutionPlan, or None if absent/unparseable.
            Defaults to the current hard-coded
            ``state.get("execution_plan_output")`` + ``_parse_plan()`` behavior
            for backward compatibility.
        confidence_extractor: Callable that returns the Evaluator confidence
            score in [0, 1]. Defaults to
            ``state.get("evaluation_result", {}).get("confidence", 0.0)``.
        status_state_key: State key the node writes its verdict into
            (default: "ftra_status").
        result_state_key: State key for the serialized ReachabilityResult
            (default: "ftra_result").
        defer_id_state_key: State key for the DeferQueue token id
            (default: "ftra_defer_id").
        registry_path: Override path to the compiled terminal registry.
    """

    plan_extractor: PlanExtractor | None = None
    confidence_extractor: ConfidenceExtractor | None = None
    status_state_key: str = "ftra_status"
    result_state_key: str = "ftra_result"
    defer_id_state_key: str = "ftra_defer_id"
    registry_path: Any | None = None
```

`create_ftra_node(config: FtraNodeConfig | None = None)` signature change:
when `config is None`, construct a default `FtraNodeConfig()` whose
`plan_extractor` falls back to today's behavior
(`state.get("execution_plan_output")` → `_parse_plan()`), preserving 100%
backward compatibility for `graph.py`'s existing
`create_ftra_node()` call (no-arg invocation,
[`graph.py:127`](../src/governed_financial_advisor/graph/graph.py:127)).

### 2.5 FTRA Schema Drift Hardening

**Problem statement.** `_parse_plan()`
([`node_factory.py:296-331`](../src/gateway/governance/ftra/node_factory.py:296))
attempts dict validation, then raw JSON parse, then markdown-fence-stripped
JSON parse — but two confirmed production defects remain:

- **BUG-FTRA-SCHEMA-001**: `ExecutionPlan`/`PlanStep` previously required
  fields with no defaults, so a schema-valid-but-incomplete LLM plan output
  (5 "Field required" errors) surfaced as a FTRA `BLOCKED` verdict — a
  schema/prompt mismatch misrepresented as a governance denial. Partially
  addressed in
  [`execution_analyst/agent.py:25-35`](../src/governed_financial_advisor/agents/execution_analyst/agent.py:25)
  by adding defaults, but `_parse_plan()` itself has no defense-in-depth for
  future schema drift.
- **BUG-FTRA-JSON-001**: tokenizer artifacts (`Ġ`/`Ċ` markers) are not valid
  JSON whitespace and cause `json.loads` to fail with a "not valid JSON"
  error before `_parse_plan()` even sees clean text
  ([`execution_analyst/agent.py:252-257`](../src/governed_financial_advisor/agents/execution_analyst/agent.py:252)).

**Design.**

1. **Structured parse-failure telemetry.** `_parse_plan()` should return a
   tagged result (`ParseResult(plan: ExecutionPlan | None, failure_class: str
   | None)`) rather than a bare `None`, distinguishing:
   - `SCHEMA_VALIDATION_ERROR` (Pydantic `ValidationError`, missing/extra
     fields)
   - `JSON_DECODE_ERROR` (malformed JSON, tokenizer artifacts)
   - `EMPTY_STEPS` (schema-valid, `steps=[]` — already flagged as
     governance-fatal but silent in
     [`execution_analyst/agent.py:103-107`](../src/governed_financial_advisor/agents/execution_analyst/agent.py:103))

   This lets `ftra_node`'s OTel span (`cage.ftra_analysis`,
   [`node_factory.py:230`](../src/gateway/governance/ftra/node_factory.py:230))
   carry a `cage.ftra.parse_failure_class` attribute so a BLOCKED verdict
   caused by a plan-generation defect is distinguishable in Langfuse from one
   caused by a genuine irreversible-terminal reachability finding — closing
   the "plausible-looking but incorrect governance denial" ambiguity called
   out in both bug reports.

2. **Pre-parse sanitization.** Before attempting `model_validate_json()`,
   strip known tokenizer whitespace artifacts (`\u0120` "Ġ", `\u010a` "Ċ",
   and related BPE marker codepoints) in addition to the existing markdown
   fence stripping
   ([`node_factory.py:322-326`](../src/gateway/governance/ftra/node_factory.py:322)).
   This generalizes the fix already applied ad hoc in
   `execution_analyst/agent.py` into the shared `_parse_plan()` path so any
   future plan producer benefits.

3. **Fail-closed invariant preserved.** All hardening is defense-in-depth
   around classification, not a relaxation of the BLOCKED default — an
   unparseable plan must still fail closed per the existing design
   philosophy documented at
   [`node_factory.py:15-24`](../src/gateway/governance/ftra/node_factory.py:15).

### 2.6 Redis Infrastructure — Failover Hardening

**Problem statement.** The reference deployment uses single-node Redis, so
the double-spend-on-failover risk is currently only theoretical, but no
fencing mechanism exists in
[`redis_client.py`](../src/gateway/infrastructure/redis_client.py) or
[`cbf.py`](../src/gateway/governance/cbf.py) to make replicated deployments
safe. `WATCH`/`MULTI`/`EXEC` optimistic locking
(`TransactionAbortedError`, [`redis_client.py:42-51`](../src/gateway/infrastructure/redis_client.py:42))
protects against concurrent-client races on a single node but does not
protect against a primary-to-replica failover silently rewinding
acknowledged writes.

**Design.**

1. **New env var** `CAGE_REDIS_SYNCHRONOUS_REPLICATION` (default `"false"`).
   When `"true"`, every CBF-mutating write
   (`atomic_verify_and_commit()`, `update_state()`, `rollback_state()` in
   [`cbf.py`](../src/gateway/governance/cbf.py)) must additionally:
   - Increment and persist a monotonic `safety:fence_epoch` counter via a
     Lua script co-located with the existing debit script, and
   - Either (a) issue a Redis `WAIT <replica_count> <timeout_ms>` call
     after the write to confirm replica acknowledgment, or (b) when Redis
     Sentinel is detected (reusing the existing Sentinel-probe pattern in
     [`checkpointer.py:110-151`](../src/governed_financial_advisor/graph/checkpointer.py:110)
     and
     [`governed_financial_advisor/infrastructure/redis_client.py:116-159`](../src/governed_financial_advisor/infrastructure/redis_client.py:116)),
     verify the fence epoch against the newly-promoted master before trusting
     any read.

2. **Fencing read-path check.** `read_verified_balance()`/`verify_action()`
   must reject any balance record whose `safety:fence_epoch` is *lower* than
   the highest epoch this process has previously observed — this is the
   concrete mechanism the analysis names ("monotonic `safety:fence_epoch` or
   `WAIT` acknowledgment/Sentinel-aware fencing") to close the failover
   double-spend window.

3. **Scope guard.** This hardening is a no-op (feature-flag off) for the
   current single-node reference deployment; it becomes load-bearing only
   when an operator sets `architecture=replication` for Redis, per the
   existing caveat in the analysis ("current reference deployment uses
   single-node Redis and is therefore not subject to this").

### 2.7 Reconciliation Worker — Activation Requirements

**Problem statement.** Both the provider registry fix and the Kubernetes
manifest are **already complete** in the codebase — this is an operational
secret-population gap, not a code or infrastructure gap, per
[`docs/POAM.md:76`](../docs/POAM.md:76) (POAM-2026-038, reopened 2026-08-09).

**Activation checklist (operational, not code):**

1. Populate the `reconciliation-worker-secrets` Secret's
   `gcs-reconciliation-bucket` (and `gcs-reconciliation-object` if
   non-default) keys — see the `kubectl create secret` template at
   [`reconciliation-worker.yaml:268-273`](../deployment/k8s/reconciliation-worker.yaml:268),
   or automate via
   `deployment/scripts/setup_reconciliation_secret.sh` (referenced in
   [`POAM.md:76`](../docs/POAM.md:76)).
2. Confirm `kms-governance-key` is populated (required for all providers).
3. Verify `RECONCILIATION_PROVIDER=gcs`
   ([`reconciliation-worker.yaml:132-133`](../deployment/k8s/reconciliation-worker.yaml:132))
   matches the intended provider — the POAM notes a prior misconfiguration
   as `"s3"` that has since been corrected in the manifest.
4. Re-apply: `kubectl apply -f deployment/k8s/reconciliation-worker.yaml`.
5. Verify the next scheduled run (`*/5 * * * *`) completes without
   `CreateContainerConfigError` and that
   `reconciliation:verified_balance` is populated in Redis
   (`redis-cli GET reconciliation:verified_balance`).
6. Close POAM-2026-038 with the run's KMS-signature verification timestamp
   as evidence.

**No source code changes are required for this item** — it is included here
because the CAGE_ARXIV.md correction (§2.8) depends on accurately describing
this as an operational, not architectural, gap.

### 2.8 CAGE_ARXIV.md Stale Claims Correction (Documentation Spec)

Although `tmp/CAGE_ARXIV.md` is a reference document under `tmp/` (not the
canonical published paper location per `docs/paper/REVISION_TRACKER.md`),
the analysis identifies specific §5.4 claims that no longer match the
codebase and must be corrected wherever the paper text is authoritative:

| Stale claim | Location | Correction |
|---|---|---|
| *"there is no Kubernetes manifest for it"* | [`tmp/CAGE_ARXIV.md:520`](../tmp/CAGE_ARXIV.md:520) | `deployment/k8s/reconciliation-worker.yaml` exists and is fully specified (CronJob + Secret template + CiliumNetworkPolicy) |
| *"`RECONCILIATION_PROVIDER=gcs` setting does not match any key in the daemon's own provider registry"* | [`tmp/CAGE_ARXIV.md:520`](../tmp/CAGE_ARXIV.md:520) | `GcsLedgerProvider` is registered under `"gcs"` in [`reconciliation_worker.py:1147-1157`](../src/compliance_bridge/reconciliation_worker.py:1147) — this was fixed as POAM-2026-042 |
| *"Deploy the reconciliation daemon: Author a Kubernetes Deployment or CronJob manifest"* (future-work framing) | [`tmp/CAGE_ARXIV.md:547`](../tmp/CAGE_ARXIV.md:547) | Reframe as: manifest exists; remaining work is secret population only (POAM-2026-038) |
| *"Fix the RECONCILIATION_PROVIDER mismatch"* (future-work framing) | [`tmp/CAGE_ARXIV.md:548`](../tmp/CAGE_ARXIV.md:548) | Remove — already fixed |

**Correction procedure.** Follow the existing paper-update discipline in
[`docs/paper/MEASUREMENT_RUNBOOK.md`](../docs/paper/MEASUREMENT_RUNBOOK.md):
never hand-edit the paper text directly; route corrections through the
`scripts/_patch_paper.py`-style replacement-block pattern, record the change
in `docs/paper/REVISION_TRACKER.md`, and cite the commit SHAs that
introduced `GcsLedgerProvider` (POAM-2026-042) and the CronJob manifest
(`2026-08-06-fafef04` measurement provenance,
[`docs/paper/measurements/2026-08-06-fafef04/PROVENANCE.md:24-25`](../docs/paper/measurements/2026-08-06-fafef04/PROVENANCE.md:24))
as the evidence trail. This is a documentation-only change; it is listed
here because it was explicitly named as a P0 item in the analysis.

### 2.9 Formal Verification — Distributed Model & NoDirectBind Extension

**2.9.1 Distributed Formal Model (`proof/distributed_cbf_model.py`, new)**

**Problem statement.** `proof/model.py` models a single agent's tier
pipeline in isolation ([`model.py:42-57`](../proof/model.py:42)) — it has
zero imports from `src/` (a pure hand-abstraction, confirmed via grep) and
does not model concurrent agents contending for the same bounded resource
(`cash_balance`). The CBF Invariance Theorem is explicitly scoped to a
"single-trade-per-window execution model"
([`tmp/CAGE_ARXIV.md:188`](../tmp/CAGE_ARXIV.md:188)); multi-agent
concurrent contention against a shared balance is unmodeled.

**Design.** New module `proof/distributed_cbf_model.py`, following the same
dependency-free, exhaustively-enumerable BFS style as `proof/model.py`:

```python
"""
Distributed CBF Model — N Concurrent Agents, Bounded Shared Balance
=====================================================================

Models N agents each attempting atomic_verify_and_commit()-style debits
against a single shared `cash_balance` resource, to check whether the CBF
Invariance Theorem's safe set h(S) >= 0 remains closed under interleaved
concurrent access — i.e. whether Redis's WATCH/MULTI/EXEC (or Lua-atomic)
serialization is sufficient, or whether a reachable interleaving exists
that drives the balance negative.

State tuple: (balance: int, agent_phases: tuple[Phase, ...], fence_epoch: int)
  where Phase in {IDLE, CHECKING, COMMITTING, DONE}

Transitions: each agent independently advances its own phase; the shared
balance is only mutated on a COMMITTING -> DONE transition, gated by the
same atomicity assumption verified operationally by
tests/test_symbolic_governor_cbf_atomicity.py.

Usage: python proof/distributed_cbf_model.py --agents 3
"""
```

Key properties to assert via exhaustive BFS (mirroring
`proof/model.py`'s `assert` style):

1. **Safety**: `balance >= min_cash_balance` holds in every reachable state
   for N ∈ {2, 3, 4} concurrent agents under atomic (Lua-serialized) commit.
2. **Negative control**: an "ungated" variant that allows two agents to both
   read `balance` before either writes (modeling a naive
   read-then-write race, i.e. the TOCTOU pattern already fixed by
   `atomic_verify_and_commit()`) MUST produce a reachable violation — this
   is the distributed analogue of `proof/model.py`'s `ungated_transitions()`
   negative control and demonstrates the model is load-bearing, not
   decorative.
3. **Fencing interaction**: when `CAGE_REDIS_SYNCHRONOUS_REPLICATION`-style
   fencing is modeled (a `fence_epoch` component in the state tuple), a
   commit using a stale epoch must be rejected in all reachable states —
   this analytically validates the §2.6 design before/alongside its runtime
   rollout (Stage 3, §6.3).

**Scope boundary.** Like `proof/model.py`, this model deliberately excludes
FTRA/Tier 0.5 and OPA policy internals — it isolates the CBF
read-check-commit concurrency question, matching the analysis's framing:
"proof/model.py's lack of any src/ import... the model acknowledges scope
limits abstractly but doesn't name this specific verification gap."

**CI integration.** Add a `distributed-cbf-proof` job to
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) alongside the
existing `no-direct-bind-proof` job (referenced at
[`ci.yml:295-297`](../.github/workflows/ci.yml:295)), and a corresponding
`tests/test_distributed_cbf_proof.py` with `pytestmark = pytest.mark.local`
(following the precedent fix documented in
[`docs/paper/REVISION_TRACKER.md:154`](../docs/paper/REVISION_TRACKER.md:154)
— V2 — where the original `test_no_direct_bind_proof.py` was silently
excluded from `pytest -m local` for lack of this marker).

**2.9.2 NoDirectBind Proof Extension (TLA+/Alloy)**

**Problem statement.** The current proof covers a 21-state hand-abstracted
automaton over `SymbolicGovernor._run_checks()`'s tier list only — not the
full LangGraph harness, Redis state, or the FTRA boundary. This is
explicitly named as Priority 2 future work in the analysis.

**Design (phased, not a single deliverable):**

1. **Phase A — TLA+ transliteration of the existing Python model.** Encode
   the current `proof/model.py` state machine (8 tiers, PENDING → CHECKING →
   SEAL_ISSUED → EXECUTED/DENIED phases) as a TLA+ module
   (`proof/tla/NoDirectBind.tla`) with the `NoDirectBind` safety invariant
   stated formally: `NoDirectBind == (phase = "EXECUTED") => (resolvedAllow
   = TRUE)` (already given in prose at
   [`model.py:22-23`](../proof/model.py:22)). Validate with TLC that the
   21/24/19/20 reachable-state counts match the Python BFS enumeration
   exactly — this is a cross-validation step, not a new proof.
2. **Phase B — Extend the TLA+ model to include the LangGraph harness
   state machine**: NodeInterrupt/GraphInterrupt suspension, the
   `hitl_expires_at` TTL ([`state.py`](../src/governed_financial_advisor/graph/state.py))
   and Redis checkpoint persistence, formalizing the "outside the verified
   envelope" caveat currently only stated in prose
   (HITL-resumption paths after ESCALATE/ERROR).
3. **Phase C — Extend to include the FTRA boundary** (both the in-graph
   node and the new Controller-boundary check from §2.2), closing the gap
   where "Tier 0.5/FTRA is outside the 21-state BFS automaton scope."
4. **Phase D (stretch)** — Alloy model for bounded model-checking of the
   distributed multi-agent case (§2.9.1) as a complementary technique to
   the exhaustive Python BFS, useful for exploring larger N without
   state-space explosion in the enumerator.

**Consistency requirement.** Any phase that changes the modeled state count
requires updating `tests/test_no_direct_bind_proof.py`'s `EXPECTED_*`
constants and every location in
[`docs/paper/REVISION_TRACKER.md`](../docs/paper/REVISION_TRACKER.md)'s
"Consistency blast radius" section (see §6.4 for the specific trigger
condition from this spec's own DEFER/NARROW/PAUSE and FTRA-boundary
changes).

### 2.10 Reconciliation Payload Replay Defense — Monotonic Sequence Number

**Problem statement.** `reconciliation:verified_balance`
([`reconciliation_worker.py:120`](../src/compliance_bridge/reconciliation_worker.py:120))
is trusted by the CBF's `_read_cbf_state_atomic()`
([`cbf.py:167-204`](../src/gateway/governance/cbf.py:167)) whenever its KMS
signature verifies and its Redis TTL (`RECONCILIATION_TTL_SECONDS`, default
300s) has not expired. Staleness is enforced *purely* by Redis key TTL —
`ReconciliationResult.is_stale`
([`reconciliation_worker.py:160-163`](../src/compliance_bridge/reconciliation_worker.py:160))
compares `verified_at` against wall-clock time, and `read_verified_balance()`
([`reconciliation_worker.py:1180-1217`](../src/compliance_bridge/reconciliation_worker.py:1180))
returns `None` (fail-closed) only once that TTL window has elapsed.
Critically, the signed payload itself (`source`, `balance_usd`,
`verified_at` — the exact dict passed to `signer.sign()` at
[`reconciliation_worker.py:1014-1019`](../src/compliance_bridge/reconciliation_worker.py:1014))
carries no monotonic counter. A compromised agent with direct Redis write
access (bypassing the isolated `reconciliation-worker` namespace entirely)
can therefore re-issue `SETEX reconciliation:verified_balance <ttl>
<previously-captured-payload>` indefinitely: the signature still verifies
(it is a byte-for-byte replay of a payload the worker legitimately signed
at some earlier `verified_at`), and each replay resets the TTL clock, so
`read_verified_balance()` never returns `None` and the CBF never fails
closed on staleness — this is the concrete gap the analysis names (zero
`sequence_id`/monotonic references found via search in `cbf.py`/
`reconciliation_worker.py`).

**Design.** This is a narrower, additive complement to the
`safety:fence_epoch` replication-fencing design in §2.6: fencing there
protects against a *primary-to-replica failover* rewinding writes; the
sequence-number check here protects against a *replayed-but-validly-signed*
payload being reintroduced on a single node — the two mechanisms are
independent and both apply even on the reference single-node Redis
deployment (unlike §2.6, which is a no-op there).

**2.10.1 Signed balance payload schema change.** Add a monotonic
`sequence` field to the exact dict that
`ExternalLedgerReconciler.reconcile()` passes into `signer.sign()`
([`reconciliation_worker.py:1014-1019`](../src/compliance_bridge/reconciliation_worker.py:1014)),
so the sequence number is covered by the KMS signature itself (a replayed
payload cannot have its `sequence` field silently bumped without
invalidating the signature):

```python
# src/compliance_bridge/reconciliation_worker.py — ReconciliationResult (extended)
@dataclass
class ReconciliationResult:
    source: str
    balance_usd: float
    verified_at: float = field(default_factory=time.time)
    signature: str = ""
    ttl_seconds: int = TTL_SECONDS
    raw_response: dict | None = None
    error: str | None = None
    sequence: int = 0  # NEW — monotonic, strictly increasing per account_id

    def to_redis_payload(self) -> str:
        return json.dumps(
            {
                "source": self.source,
                "balance_usd": self.balance_usd,
                "verified_at": self.verified_at,
                "signature": self.signature,
                "sequence": self.sequence,  # NEW
            },
            sort_keys=True,
            separators=(",", ":"),
        )
```

The signed payload dict in `reconcile()` gains the same field:

```python
payload_dict = {
    "source": result.source,
    "balance_usd": result.balance_usd,
    "verified_at": result.verified_at,
    "sequence": result.sequence,  # NEW — signed, not just stored
}
result.signature = signer.sign(payload_dict)
```

The mirrored `payload_dict` used by `cbf.py`'s signature-verification call
([`cbf.py:215-219`](../src/gateway/governance/cbf.py:215)) must be updated
identically — signature verification fails (safely, fail-closed) if the two
call sites' dict shapes ever drift, which is itself a useful regression
guard.

**2.10.2 Sequence-number source of truth.** The reconciliation worker reads
the last-issued sequence number from a new Redis key,
`reconciliation:sequence:latest`, immediately before each cycle's write,
increments it by exactly 1, and writes both the incremented counter and the
now-sequenced payload in the same Redis pipeline
([`reconciliation_worker.py:1041-1066`](../src/compliance_bridge/reconciliation_worker.py:1041)):

```python
# ExternalLedgerReconciler.reconcile() — Redis write step (extended)
pipe = self._redis.pipeline()
next_sequence = pipe_incr_result  # INCR reconciliation:sequence:latest, read back
result.sequence = next_sequence
pipe.setex(_REDIS_KEY_VERIFIED_BALANCE, self._ttl, result.to_redis_payload())
pipe.set(_REDIS_KEY_SEQUENCE_LATEST, str(next_sequence))  # NEW, no TTL — must
                                                            # survive independently
                                                            # of the balance TTL
...
pipe.execute()
```

`reconciliation:sequence:latest` is **never TTL'd** — unlike
`reconciliation:verified_balance`, the sequence counter must persist
indefinitely (a TTL expiry on the counter itself would let a replayed
payload's stale sequence look "new" again after the counter key expired
and reset). Using Redis `INCR` (atomic single-key increment, no Lua script
required) is sufficient here because there is exactly one legitimate writer
(the isolated `reconciliation-worker` CronJob pod) — this is a materially
different threat model than the multi-writer CBF debit path in §2.6, which
is why a bare `INCR` suffices instead of the Lua-script pattern used there.

**2.10.3 Validation on the CBF read path.** `_read_cbf_state_atomic()`
([`cbf.py:167-204`](../src/gateway/governance/cbf.py:167)) gains a second
Redis read (`reconciliation:sequence:last_accepted` — the highest sequence
number *this CBF process* has ever accepted) and rejects any payload whose
`sequence` does not strictly exceed it:

```python
# src/gateway/governance/cbf.py — _read_cbf_state_atomic() (extended)
if verified is not None and verified.is_valid and sig_valid:
    last_accepted = await redis_client.get_int(
        "reconciliation:sequence:last_accepted", default=0
    )
    if verified.sequence <= last_accepted:
        logger.critical(json.dumps({
            "event": "CBF_RECONCILED_BALANCE_SEQUENCE_REPLAY_DETECTED",
            "severity": "CRITICAL",
            "replayed_sequence": verified.sequence,
            "last_accepted_sequence": last_accepted,
            "audit_note": (
                "Reconciled balance sequence number did not advance — "
                "possible replay attack. Falling back to self-reported "
                "balance (fail-closed per R-04 contingency plan)."
            ),
        }))
        # Falls through to the existing self-reported fallback path,
        # exactly as an invalid KMS signature does today.
    else:
        await redis_client.set("reconciliation:sequence:last_accepted", str(verified.sequence))
        return {"current_cash": verified.balance_usd, "source": "reconciled"}
```

This reuses the exact fail-closed fallback semantics already implemented
for KMS-signature failure ([`cbf.py:233-263`](../src/gateway/governance/cbf.py:233))
— a replay is treated identically to an invalid signature: fall through to
`safety:current_cash` with a `CRITICAL` audit log, never a silent accept.

**2.10.4 Implementation locations (files touched).**

| File | Change |
|---|---|
| [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py) | Add `sequence: int = 0` to `ReconciliationResult`; include `sequence` in `to_redis_payload()`/`from_redis_payload()` and in the KMS-signed `payload_dict`; `reconcile()` reads+increments `reconciliation:sequence:latest` via Redis `INCR` in the same pipeline as the balance write |
| [`src/gateway/governance/cbf.py`](../src/gateway/governance/cbf.py) | `_read_cbf_state_atomic()` reads `reconciliation:sequence:last_accepted`, rejects non-advancing `sequence` values, updates the accepted-sequence high-water mark on success; the mirrored signature-verification `payload_dict` includes `sequence` |

**2.10.5 Rollout strategy — backward compatibility.** New env var
`CAGE_RECONCILIATION_REPLAY_DEFENSE` (default `"false"`). When `"false"`
(default), behavior is byte-for-byte identical to today: `sequence`
defaults to `0` on any pre-migration payload still present in Redis (via
`from_redis_payload()`'s `.get("sequence", 0)` deserialization), and the
CBF read path skips the sequence check entirely, falling back to today's
TTL+signature-only trust model. When `"true"`:

- The reconciliation worker begins stamping and signing `sequence` on every
  new write (this side is unconditional and cheap — it is always safe to
  *write* a sequence number even before the *read* side enforces it, which
  is the recommended first sub-stage of rollout: enable writing one
  deployment cycle before enabling read-side enforcement, so the CBF never
  has to reject a payload from a not-yet-upgraded worker).
- The CBF begins enforcing strict advancement and will fail closed
  (fall back to self-reported balance with a `CRITICAL` log) on any
  payload with `sequence <= last_accepted` — including a legitimate
  payload from a worker that has not yet been upgraded to stamp sequence
  numbers (`sequence` defaults to `0`, which never exceeds a
  previously-accepted non-zero value). Operators MUST upgrade the
  reconciliation worker before enabling read-side enforcement in the
  gateway, per the two-phase sequencing above.
- A worker restart (e.g. pod rescheduling) does not reset
  `reconciliation:sequence:latest` — it is a plain Redis key, not
  worker-local state, so `INCR` continues from wherever the counter left
  off.

**2.10.6 Testing requirements.** See
[`plans/CAGE_TESTING_FRAMEWORK.md`](CAGE_TESTING_FRAMEWORK.md) §4.2 (Redis
Replay Attack Simulation Tests) for the full test matrix, including the
integration test named in the task context,
`test_monotonic_sequence_number_rejects_non_advancing_replay`, and the
Redis-replay chaos scenario `test_failover_without_fencing_reproduces_known_vulnerability`-style
negative control adapted for the single-node replay case (§4.2 of the
Testing Framework already stubs both).

## 3. API Contract Changes

### 3.1 New Environment Variables

| Variable | Default | Component | Purpose |
|---|---|---|---|
| `EVIDENCE_CHAIN_BLOCKING` | `"false"` | [`evidence_stream.py`](../src/compliance_bridge/evidence_stream.py) | When `"true"`, gates seal issuance on synchronous `ingest_sync()` commit (§2.3) |
| `CAGE_REDIS_SYNCHRONOUS_REPLICATION` | `"false"` | [`cbf.py`](../src/gateway/governance/cbf.py), [`redis_client.py`](../src/gateway/infrastructure/redis_client.py) | When `"true"`, enables `WAIT`/Sentinel-aware fencing on CBF writes (§2.6) |
| `CAGE_NARROW_ENABLED` | `"false"` | [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) | When `"true"`, CBF amount violations may return `NARROW` instead of `DENY` (§2.1) |
| `CAGE_FTRA_BOUNDARY_ENABLED` | `"false"` | [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py) | When `"true"`, enables the Controller-boundary FTRA check inside `_run_checks()` (§2.2) |
| `FTRA_SANITIZE_TOKENIZER_ARTIFACTS` | `"true"` | [`ftra/node_factory.py`](../src/gateway/governance/ftra/node_factory.py) | Controls whether `_parse_plan()` strips known BPE whitespace markers before JSON parse (§2.5) |
| `CAGE_RECONCILIATION_REPLAY_DEFENSE` | `"false"` | [`reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py), [`cbf.py`](../src/gateway/governance/cbf.py) | When `"true"`, enables monotonic-sequence-number replay defense on the read path; the write path (stamping `sequence`) is unconditional regardless of this flag (§2.10) |

Existing env vars whose *documented default behavior* changes semantics
(not the variable itself) as a result of this work:

| Variable | Existing default | Note |
|---|---|---|
| `EVIDENCE_STREAM_ENABLED` | `"false"` ([`evidence_stream.py:106`](../src/compliance_bridge/evidence_stream.py:106)) | Unchanged. `EVIDENCE_CHAIN_BLOCKING=true` requires `EVIDENCE_STREAM_ENABLED=true` as a precondition — validated at startup (fail fast if blocking is requested but the stream itself is disabled) |
| `FRIA_ZONE_DEFER` | `0.70` ([`symbolic_governor.py:192`](../src/gateway/governance/symbolic_governor.py:192)) | Unchanged value; now actually reachable as a `DEFER` verdict end-to-end (previously reachable only in intent, not in `validate_action()` return value) |
| `RECONCILIATION_PROVIDER` | `"gcs"` (manifest, [`reconciliation-worker.yaml:133`](../deployment/k8s/reconciliation-worker.yaml:133)) | No code change; operational secret population only (§2.7) |

### 3.2 Modified/New HTTP Response Codes

| Endpoint | Verdict | Status | Body (new/changed fields in bold) |
|---|---|---|---|
| `POST /v1/governance/validate-action` | `DEFER` | **202** (was previously unreachable — collapsed to 403) | `{"verdict": "DEFER", "defer_id": "...", "missing_input_reason": "...", "latency_ms": ...}` |
| `POST /v1/governance/validate-action` | **`NARROW`** (new) | **200** | `{"verdict": "NARROW", "narrowed_params": {...}, "narrow_reason": "...", "seal": "..."}` — seal is issued for the *narrowed* action only |
| `POST /v1/governance/validate-action` | **`PAUSE`** (new) | **202** | `{"verdict": "PAUSE", "resume_token": "...", "resume_after": "2026-08-15T12:00:00Z" \| null}` |
| ext_authz `CheckRequest`/`CheckResponse` ([`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py)) | `DEFER` | **202** (already implemented at [line 396](../src/gateway/server/agent_gateway_adapter.py:396); now actually reachable) | unchanged body shape |
| ext_authz `CheckRequest`/`CheckResponse` | **`NARROW`**/**`PAUSE`** (new) | **200**/**202** | New branches mirroring the existing `REQUIRE_APPROVAL`/`DEFER` branches ([lines 363-407](../src/gateway/server/agent_gateway_adapter.py:363)) |
| **New**: `POST /v1/pause/{resume_token}/resume` | — | 200 / 404 / 410 (expired) | Resumes a `PAUSE`-suspended LangGraph thread via `Command(resume=...)` |

### 3.3 State Field Additions

| Field | Type | Owner | Purpose |
|---|---|---|---|
| `narrow_reason` | `str \| None` | `symbolic_governor.validate_action()` return dict | Human-readable reason a request was narrowed rather than denied |
| `narrowed_params` | `dict[str, Any] \| None` | `symbolic_governor.validate_action()` return dict | The clamped payload the caller may re-submit |
| `resume_token` | `str \| None` | `symbolic_governor.validate_action()` return dict / new `pause_primitive.py` | Opaque token presented to `/v1/pause/{token}/resume` |
| `ftra_status` / `ftra_result` / `ftra_defer_id` | existing | [`AgentState`](../src/governed_financial_advisor/graph/state.py:147) | **No new fields** — already typed members per the task's stated contract; confirmed present at [`state.py:147-149`](../src/governed_financial_advisor/graph/state.py:147) |
| `cage.ftra.parse_failure_class` | `str \| None` | OTel span attribute, `cage.ftra_analysis` | New span attribute distinguishing schema/JSON parse failures from genuine BLOCKED verdicts (§2.5) |
| `safety:fence_epoch` | Redis key (int, monotonic) | [`cbf.py`](../src/gateway/governance/cbf.py) | New fencing counter for Redis failover hardening (§2.6, §4.2) |

## 4. Data Model Changes

### 4.1 Evidence Chain Schema 1.1 Specification

**Current schema (1.0)** — [`evidence_stream.py:52-61`](../src/compliance_bridge/evidence_stream.py:52):

```json
{
  "schema":        "cage-evidence-stream/1.0",
  "sequence":      "42",
  "event_type":    "AUDIT_FINDING",
  "control_id":    "A.5.3",
  "prev_hash":     "<sha256 hex>",
  "record_hash":   "<sha256 hex>",
  "payload_json":  "<JSON-serialized event payload>",
  "timestamp_utc": "2026-05-29T14:00:00Z",
  "kms_signature": ""
}
```

**Root cause of the spec/implementation mismatch.** `_link_hash()`
([`evidence_stream.py:131-154`](../src/compliance_bridge/evidence_stream.py:131))
already uses `separators=(",", ":")` for the *header* JSON
(`json.dumps({...}, sort_keys=True, separators=(",", ":"))`,
[line 151](../src/compliance_bridge/evidence_stream.py:151)) — but the
**payload** JSON passed into `ingest()`
([`evidence_stream.py:277`](../src/compliance_bridge/evidence_stream.py:277))
is serialized as `json.dumps(event, sort_keys=True, default=str)` **without**
the canonical separator, meaning `payload_json` embeds default
`", "`/`": "` whitespace. This is the analysis's cited "canonical hash
separator fix" — the header is already canonical; the payload is not,
making the overall `record_hash` non-reproducible across any two encoders
that differ only in default `json.dumps` whitespace behavior (e.g. a
downstream verifier using `json.dumps(event)` naively rather than the exact
producer call).

**Schema 1.1 changes:**

```json
{
  "schema":        "cage-evidence-stream/1.1",
  "sequence":      "42",
  "event_type":    "AUDIT_FINDING",
  "control_id":    "A.5.3",
  "prev_hash":     "<sha256 hex>",
  "record_hash":   "<sha256 hex — now computed over canonical payload_json>",
  "payload_json":  "<JSON-serialized event payload, separators=(',',':')>",
  "timestamp_utc": "2026-05-29T14:00:00Z",
  "kms_signature": "",
  "kms_signature_algorithm": "KMS_ASYMMETRIC | HMAC_SHA256_FALLBACK | UNKNOWN"
}
```

Concretely, [`evidence_stream.py:277`](../src/compliance_bridge/evidence_stream.py:277)
changes from:

```python
payload_json = json.dumps(event, sort_keys=True, default=str)
```

to:

```python
payload_json = json.dumps(event, sort_keys=True, default=str, separators=(",", ":"))
```

`_SCHEMA` constant ([`evidence_stream.py:118`](../src/compliance_bridge/evidence_stream.py:118))
bumps from `"cage-evidence-stream/1.0"` to `"cage-evidence-stream/1.1"`.
`kms_signature_algorithm` (already written per-entry at
[`evidence_stream.py:301`](../src/compliance_bridge/evidence_stream.py:301))
is promoted from an informal addition to a documented part of the 1.1 wire
format.

This mirrors the sibling fix already applied to
`context_accumulator.py`'s `_content_hash()` under POAM-2026-041
([`docs/POAM.md:117`](../docs/POAM.md:117)) — that POAM is the precedent and
template for this migration.

### 4.2 Redis Key Schema Updates

| Key pattern | DB | Status | Purpose |
|---|---|---|---|
| `DEFER:{defer_id}` | 1 | Existing, unchanged | Full `DeferToken` JSON ([`defer_queue.py:40`](../src/gateway/governance/defer_queue.py:40)) |
| `DEFER:expiry_index` | 1 | Existing, unchanged | ZSet of `defer_id` → expiry unix ts |
| `cage:evidence:stream` | 1 | Existing; entries move to schema 1.1 | Redis Stream of hash-chained evidence records |
| `reconciliation:verified_balance` | 0 | Existing, unchanged | KMS-signed external balance written by reconciliation worker |
| `safety:current_cash` | 0 | Existing, unchanged | Execution-system-reported balance (pre-reconciliation) |
| `safety:fence_epoch` | 0 | **New** | Monotonic integer, incremented on every CBF-mutating write when `CAGE_REDIS_SYNCHRONOUS_REPLICATION=true`; read-side rejects any snapshot whose epoch regresses (§2.6) |
| `PAUSE:{resume_token}` | 1 | **New** | Serialized suspension context for the `PAUSE` primitive (mirrors `DEFER:{defer_id}` shape: `thread_id`, `pause_reason`, `created_at_utc`, `expires_at_utc`) |
| `PAUSE:expiry_index` | 1 | **New** | ZSet mirroring `DEFER:expiry_index` for `PAUSE` token TTL sweeps |
| `reconciliation:sequence:latest` | 0 | **New** | Monotonic counter (plain Redis `INCR`, never TTL'd) incremented once per reconciliation cycle; embedded in and covered by the KMS-signed balance payload (§2.10) |
| `reconciliation:sequence:last_accepted` | 0 | **New** | Highest `sequence` value the CBF has ever accepted from a valid, non-replayed payload; read-modify-write on every successful `_read_cbf_state_atomic()` reconciled-balance acceptance (§2.10) |

### 4.3 AgentState Field Additions

Per the task's stated contract, `ftra_status`, `ftra_result`, and
`ftra_defer_id` are **already** typed members of `AgentState`
([`state.py:147-149`](../src/governed_financial_advisor/graph/state.py:147))
— no field addition is required there. New fields required to support the
NARROW/PAUSE primitives at the LangGraph state level:

```python
# src/governed_financial_advisor/graph/state.py — additions

class AgentState(TypedDict):
    ...
    # NARROW primitive (Tier governance partial-authority result)
    # narrow_status:    "NARROWED" | None (default None)
    # narrowed_params:  the clamped payload the graph should re-attempt with
    narrow_status: str | None
    narrowed_params: dict[str, Any] | None

    # PAUSE primitive (resumable suspension, distinct from HITL approval/DEFER)
    # pause_resume_token: opaque token for POST /v1/pause/{token}/resume
    # pause_reason:       human-readable suspension reason
    pause_resume_token: str | None
    pause_reason: str | None
```

### 4.4 FTRA Terminal Registry — No Schema Change

`config/ftra/terminal_registry.json`, compiled from
`config/stpa_control_structure.yaml` via
`generate_terminal_registry()`
([`stpa_compiler.py:1213-1224`](../src/gateway/governance/stpa_compiler.py:1213)),
requires **no schema change** for this work. The Controller-boundary FTRA
check (§2.2) and the pluggable extractor abstraction (§2.4) both consume the
registry through the existing `IrreversibilityClassifier` interface
unchanged — this is intentional: classification must be identical
regardless of enforcement point or host agent.

## 5. Integration Points

### 5.1 LangGraph Harness Compatibility Requirements

**Version floor.** `pyproject.toml` already pins
[`langgraph>=1.1.0`](../pyproject.toml:116) under the `advisor` extra. This
spec does not change the floor but adds a **CI validation requirement**: any
future dependency bump must re-run the `NodeInterrupt`/`GraphInterrupt`
graceful-degradation path exercised today in
`_raise_node_interrupt()` ([`node_factory.py:408-431`](../src/gateway/governance/ftra/node_factory.py:408)),
which already handles the case where `NodeInterrupt` is unavailable in the
installed LangGraph version by falling back to state-only routing
([`node_factory.py:427-431`](../src/gateway/governance/ftra/node_factory.py:427)).
The new shared `pause_primitive.py` helper (§2.1.5) generalizes this same
try/except pattern — a dependency bump must verify both call sites still
degrade gracefully rather than raising an unhandled `ImportError`.

**Recommended CI addition:** a matrix test job that pins the previous minor
LangGraph version (e.g. `langgraph==1.0.x`) alongside the floor
(`langgraph==1.1.0`) and asserts both `create_ftra_node()` and the new
`pause_primitive.raise_pause()` helper degrade to state-only routing without
raising, exercising the same code path validated manually today.

**Node factory pattern conformance.** All new/modified node factories in
this spec (`create_ftra_node()` with `FtraNodeConfig`, the new
`pause_primitive.py` helper) MUST follow the existing
`create_X_node(config) -> node_fn` contract established by
`create_opa_safety_node(config: OpaNodeConfig)`
([`opa_node_factory.py:79`](../src/gateway/governance/langgraph_harness/opa_node_factory.py:79))
and `create_nemo_guardrail_node(config: NemoNodeConfig | None = None)`
([`nemo_node_factory.py:320`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py:320)):
accept an optional frozen dataclass config, return a callable
`(StateDict) -> StateDict` (sync or async), and default to today's
hard-coded behavior when `config is None`.

### 5.2 Controller Boundary Enforcement

The Controller-boundary FTRA check (§2.2) and the DEFER/NARROW/PAUSE
classification (§2.1) both live inside `SymbolicGovernor`, which is the
single choke point already documented at
[`validate_action():1325`](../src/gateway/governance/symbolic_governor.py:1325)
("This is the **Single Choke Point** for all tool execution"). This
integration point is critical: it is what makes the Controller-boundary FTRA
check effective against the bypass described in §1.3 — any caller that
reaches `validate_action()` (whether via `agent_gateway_adapter.py`'s
ext_authz path, `governance_middleware.py`'s REST path, or a future direct
Python import) is subject to the same enforcement, independent of whether
the caller's own process graph wired in `ftra_node`.

**Both enforcement layers must remain interoperable:**

| Layer | Enforced by | Applies to |
|---|---|---|
| In-graph FTRA node | `create_ftra_node()` | Only callers that wire `ftra_node` into their own LangGraph (e.g. GFA's `graph.py`) |
| Controller-boundary FTRA check | `SymbolicGovernor._ftra_boundary_check()` (new) | **Every** caller of `validate_action()`, including direct HTTP/ext_authz callers that bypass LangGraph entirely |

Both share `IrreversibilityClassifier` and the compiled
`config/ftra/terminal_registry.json` so a given action always classifies
identically at either boundary — this is a hard design invariant, not an
optimization.

### 5.3 Compliance Bridge Interfaces

**Evidence Chain Blocking Gate ↔ Compliance Bridge.** The synchronous
`ingest_sync()` call (§2.3) is invoked from `src/gateway/*` (the governance
process) but writes into the same Redis Stream
(`cage:evidence:stream`, db=1) that the Compliance Bridge's
`EvidenceStreamSink` / GCS Flush Daemon already consumes
([`evidence_stream.py:22-46`](../src/compliance_bridge/evidence_stream.py:22)).
No new cross-service RPC is introduced — the gateway and compliance-bridge
processes continue to communicate only through shared Redis state, matching
the existing architecture.

**Reconciliation Worker ↔ Compliance Bridge.** Both `reconciliation_worker.py`
and `evidence_stream.py` live in `src/compliance_bridge/`; no interface
change is required between them for this work. The reconciliation worker's
activation (§2.7) is purely operational (secret population), so its
existing write path into `reconciliation:verified_balance`
(consumed by `cbf.py`'s `read_verified_balance()`) is unaffected by this
spec.

**OSCAL / Lula evidence obligations.** Per repository-wide compliance
policy, any change to `src/gateway/governance/` or `src/compliance_bridge/`
(both are shared modules deployed to all three regional postures) requires:

1. An OSCAL component update in `compliance/oscal/` within 2 business days
   of merge for any control implementation touched by DEFER/NARROW/PAUSE
   wiring, the evidence-chain blocking gate, or the Controller-boundary
   FTRA check.
2. A Lula validation update in `compliance/lula/` in the same PR (or a
   flagged follow-on) for any Kubernetes resource change — this spec
   introduces no new K8s resources (the reconciliation worker manifest
   already exists), so no Lula update is anticipated for §2.7, but the new
   `PAUSE:{resume_token}` Redis key pattern and `safety:fence_epoch` key
   should be reflected in any Lula assertion that enumerates governance
   Redis key namespaces.
3. Region-impact disclosure (US_FED / EU_ECB / APAC_MAS) for every change to
   `src/gateway/governance/` or `src/compliance_bridge/` per the
   Shared-Module Cross-Region Impact rule — see §6.1 below for the
   region-guard analysis specific to this work.

## 6. Migration Considerations

### 6.1 Backward Compatibility Constraints

| Change | Backward compatibility strategy |
|---|---|
| `DEFER` wiring in `validate_action()` | **Additive.** Callers that never trigger a DEFER-eligible condition see no change. Callers that previously received a DENY-shaped `GovernanceError` for what should have been a DEFER now receive a 202 instead of a 403/exception — this is a **behavior change for a subset of previously-mislabeled DENY responses**. Must be called out in the PR description and CHANGELOG as a breaking change for any client that pattern-matches on HTTP 403 for these cases. |
| `NARROW`, `PAUSE` new decisions | **Purely additive** — gated behind `CAGE_NARROW_ENABLED`/new PAUSE code paths that only activate when a node factory explicitly opts in. No existing caller can receive these verdicts until the corresponding feature flag is enabled. |
| `FtraNodeConfig` on `create_ftra_node()` | **Fully backward compatible** — `config: FtraNodeConfig | None = None` with default extractors reproducing today's `execution_plan_output`/`evaluation_result` behavior exactly. `graph.py`'s existing no-arg call ([`graph.py:127`](../src/governed_financial_advisor/graph/graph.py:127)) requires zero changes. |
| `EVIDENCE_CHAIN_BLOCKING` | **Opt-in, default `"false"`** — zero behavior change unless explicitly enabled, and requires `EVIDENCE_STREAM_ENABLED=true` as a validated precondition. |
| `CAGE_REDIS_SYNCHRONOUS_REPLICATION` | **Opt-in, default `"false"`** — no-op for the current single-node reference deployment. |
| `CAGE_RECONCILIATION_REPLAY_DEFENSE` | **Opt-in, default `"false"`** — sequence-number *writing* is unconditional (harmless no-op for old readers), but *enforcement* on the CBF read path only activates when `"true"`; requires the reconciliation worker to be upgraded before enabling read-side enforcement (two-phase rollout, §2.10.5). |
| Evidence chain schema 1.0 → 1.1 | **Not wire-compatible for verification** — see §6.2. |
| Region-guard impact | Per repository policy, `src/gateway/governance/`, `src/compliance_bridge/`, `config/thresholds/`, and `config/oscal/` are shared across US_FED/EU_ECB/APAC_MAS. All new env vars in this spec default to today's behavior in all three postures; no region-specific gating is introduced by default. The `EVIDENCE_CHAIN_BLOCKING` flag, once enabled, should be evaluated per-region: EU_ECB (GDPR/DORA Art. 10 logging obligations) and APAC_MAS (MAS Notice 655) both benefit from stronger evidence durability guarantees, so blocking mode is expected to become the eventual default in those postures ahead of US_FED. |

### 6.2 Evidence Chain Hash Migration Strategy

Because `record_hash` is computed over `payload_json`, and schema 1.1
changes how `payload_json` is serialized (adding `separators=(",", ":")`),
**existing schema-1.0 records cannot be re-verified using the schema-1.1
hashing routine**, and the reverse is also true. This is the same
backward-incompatibility class already disclosed for the paper's `1.0→1.1`
migration item in the analysis ("Backward-incompatibility warning: old
artifacts won't re-verify under new hash").

**Migration steps:**

1. **Dual-schema verification window.** Ship a `verify_record(entry: dict)`
   utility that inspects `entry["schema"]` and dispatches to the correct
   historical hashing routine (`1.0`: `json.dumps(event, sort_keys=True,
   default=str)`; `1.1`: same + `separators=(",", ":")`). This utility must
   live alongside `_link_hash()` in `evidence_stream.py` (or a new
   `evidence_chain_verify.py` module) so any auditor or the GCS Flush Daemon
   can verify both eras of records without ambiguity.
2. **No retroactive rehashing.** Do NOT attempt to recompute schema-1.0
   records' `record_hash` under the 1.1 rule — this would break the
   existing hash chain's `prev_hash` linkage for every record after the
   changepoint. Instead, the chain transitions at a single, recorded
   `sequence` boundary: the first schema-1.1 record's `prev_hash` is the
   last schema-1.0 record's `record_hash`, preserving an unbroken
   (heterogeneous-schema) chain.
3. **Cutover procedure.**
   - Deploy the schema-1.1 code change during a low-traffic window.
   - On process restart, `EvidenceStreamSink.__init__()`'s `_prev_hash`
     seed ([`evidence_stream.py:195`](../src/compliance_bridge/evidence_stream.py:195))
     must be initialized from the **last persisted record's** `record_hash`
     (read via `XREVRANGE ... COUNT 1`), not from the `EVIDENCE_STREAM_GENESIS`
     sentinel — this is already implied by the existing design but must be
     explicitly verified during migration since a fresh sentinel-seeded chain
     would silently break continuity with the pre-migration chain.
   - Record the cutover `sequence` number and both chain-boundary hashes in
     `docs/POAM.md` and `compliance/oscal/` evidence for audit continuity.
4. **GCS-archived records.** NDJSON batches already flushed to GCS
   ([`_gcs_flush_loop()`](../src/compliance_bridge/evidence_stream.py:350))
   under schema 1.0 remain valid archives under the 1.0 verification
   routine; no re-archival is required.

### 6.3 Feature Flag Rollout Sequence

Recommended staged rollout, ordered to minimize risk and to respect
dependency ordering between items (e.g. NARROW/PAUSE HTTP branches depend on
the DEFER classification refactor landing first):

```
Stage 0 (P0 — no flags, direct fix)
  └─ Reconciliation payload replay defense, write-side only (§2.10.5 phase 1)
       — stamp+sign `sequence` unconditionally; safe no-op for any
         not-yet-upgraded CBF reader since enforcement is gated separately.
  └─ DEFER wiring in validate_action() (§2.1.1-2.1.3)
       — no feature flag; this is a correctness fix for an already-
         documented, already-enum'd decision. Ship directly once tested
         against the No-Direct-Bind proof extensions (§6.4 note below).
  └─ Reconciliation worker secret population (§2.7) — operational, no flag.
  └─ CAGE_ARXIV.md stale-claims correction (§2.8) — documentation only.

Stage 1 (P1 — opt-in flags, default off)
  └─ CAGE_RECONCILIATION_REPLAY_DEFENSE=false → true, read-side enforcement
       (§2.10.5 phase 2) — enable only after confirming every reconciliation
       worker instance is stamping `sequence` (Stage 0 write-side phase 1
       has soaked); ship ahead of or alongside Stage 0 given R-04's active-
       exploit nature (Risk Matrix §1.3), but the two-phase sequencing
       within this flag's own rollout is itself load-bearing.
  └─ EVIDENCE_CHAIN_BLOCKING=false → true (per-environment, staged:
       dev → staging → US_FED prod → EU_ECB/APAC_MAS prod)
  └─ FtraNodeConfig plan_extractor abstraction (§2.4) — no flag needed,
       backward-compatible by construction; land alongside schema hardening.
  └─ FTRA schema drift hardening (§2.5) — no flag; defense-in-depth only.
  └─ CAGE_FTRA_BOUNDARY_ENABLED=false → true (Controller-boundary check,
       §2.2) — stage per-region since this changes DENY/DEFER rates.

Stage 2 (P2 — opt-in flags, longer soak)
  └─ CAGE_REDIS_SYNCHRONOUS_REPLICATION=false → true — only relevant once
       an operator adopts Redis replication; ship the flag disabled and
       document it as a prerequisite for any future replicated-Redis
       deployment, rather than actively rolling it out in the reference
       environment.
  └─ CAGE_NARROW_ENABLED=false → true — soak in staging with synthetic
       fiscal-limit-boundary traffic before enabling in any production
       region.
  └─ PAUSE primitive — ship the shared pause_primitive.py helper and the
       /v1/pause/{token}/resume endpoint, but do not wire any node factory
       to emit PAUSE until a concrete consumer (e.g. a future harness node)
       requires it.

Stage 3 (Formal verification — independent of runtime rollout)
  └─ proof/distributed_cbf_model.py (new) — N-concurrent-agent model against
       bounded shared balance; validates the CAGE_REDIS_SYNCHRONOUS_REPLICATION
       fencing design (§2.6) analytically before/alongside the Stage 2 rollout.
  └─ NoDirectBind proof extension (TLA+/Alloy) — full model-checking of the
       21-state hand-abstracted automaton in proof/model.py; if DEFER/NARROW/
       PAUSE are added to the tuple's outcome domain (§2.1 files-touched
       table), the state count WILL change from the published 21/24/19/20
       figures — any such change requires updating tests/test_no_direct_bind_
       proof.py's EXPECTED_* constants AND every location in docs/paper/
       REVISION_TRACKER.md's "Consistency blast radius" list before merging.
```

**Rollback strategy.** Every flag in this spec defaults to today's behavior
when unset or `"false"`. Rolling back any Stage 1/2 item is a single env var
flip with no data migration required, **except** the evidence chain schema
1.1 change (§6.2), which is append-only and forward-moving: rollback there
means reverting the code change (new records resume schema-1.0 serialization)
without needing to touch already-written schema-1.1 records, since the
dual-schema `verify_record()` utility (§6.2 step 1) handles both eras
permanently.

### 6.4 Formal Model Consistency Note

Any change that alters the outcome domain of `SymbolicGovernor._run_checks()`
(specifically, adding `NARROW`/`PAUSE` as reachable terminal-ish outcomes, or
adding the Controller-boundary FTRA check as a new tier in the tuple) is a
**blast-radius change** for `proof/model.py`, which explicitly models
`_run_checks()`'s tier list ([`model.py:50-51`](../proof/model.py:50)) and
currently excludes FTRA/Tier 0.5 by design
([`model.py:52-57`](../proof/model.py:52)). If the Controller-boundary FTRA
check (§2.2) is implemented as a new step *inside* `_run_checks()` (as
proposed), it must either be added to the proof's tier tuple (changing the
published 21/24/19/20 reachable-state counts and requiring the full
consistency-blast-radius update documented in
[`docs/paper/REVISION_TRACKER.md`](../docs/paper/REVISION_TRACKER.md:152-157)),
or the model's scope note must be updated to explicitly justify continuing
to exclude it. This decision should be made explicitly during implementation
planning, not discovered post-hoc when `tests/test_no_direct_bind_proof.py`
fails.
