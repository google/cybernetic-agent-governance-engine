# GAP-3: AgentState Schema Enforcement Architecture

**Status:** Approved for Implementation  
**Date:** 2026-07-05  
**Author:** Architecture Review  
**Implements:** GAP-3 (Schema Enforcement at API and Node Boundaries)  
**Affected files:**
- `src/governed_financial_advisor/server.py`
- `src/gateway/governance/langgraph_harness/types.py`
- `src/gateway/governance/langgraph_harness/nemo_node_factory.py`
- `src/governed_financial_advisor/graph/state.py` (read-only reference)
- `compliance/oscal/component-definition.yaml` (OSCAL update required within 2 business days of merge)

---

## 1. Problem Statement

Two schema enforcement gaps were identified in code review:

1. **`POST /agent/query` has no `response_model`** — FastAPI returns an unvalidated `dict` from the route handler. Any field added or removed from the return dict silently changes the API contract with no validation error. Callers cannot rely on a stable schema.

2. **LangGraph harness nodes accept and return `StateDict = dict[str, Any]`** — The `nemo_guardrail_node` and `nemo_output_rail_node` factories in `nemo_node_factory.py` operate on untyped dicts. A field rename or type change in `AgentState` propagates silently through all nodes, making runtime failures the only detection mechanism.

This document specifies the exact models, schemas, enforcement strategy, drift detection, and migration path a Code mode agent needs to implement GAP-3 without further design decisions.

---

## 2. Source of Truth — Fields Observed in `server.py`

The `/agent/query` handler at line 423 of `server.py` returns:

```python
return {"response": final_response_text, "trace_id": trace_id}
```

The cache-hit path at line 317 returns the same two fields:

```python
return JSONResponse(content={"response": final_response_text, "trace_id": trace_id})
```

`trace_id` is set to `None` when `ENABLE_TRACING=false` or when the current span is not sampled (line 287: `trace_id = f"{ctx.trace_id:032x}"` only executes inside `if ctx.trace_flags.sampled`). Therefore `trace_id` is `str | None`.

No other fields are present in the `/agent/query` return dict. The governance metadata (guardrail status, safety status, etc.) lives in the graph state and is **not** surfaced in the HTTP response — this is intentional (PII/audit hygiene).

---

## 3. `QueryResponse` Pydantic Model Specification

### 3.1 Model Definition

Add the following class to `src/governed_financial_advisor/server.py`, immediately after the existing `QueryRequest` class (after line 140):

```python
class QueryResponse(BaseModel):
    """Response model for POST /agent/query.

    Fields:
        response:  The final agent-generated text after NeMo output rail
                   screening and PII masking.  Always a non-empty string
                   on HTTP 200; blocked responses return HTTP 403 before
                   this model is serialised.
        trace_id:  OpenTelemetry trace ID as a 32-character lowercase hex
                   string (e.g. "4bf92f3577b34da6a3ce929d0e0e4736").
                   None when ENABLE_TRACING=false or the span is not sampled.
    """

    response: str
    trace_id: Optional[str] = None

    @field_validator("response")
    @classmethod
    def response_must_be_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("response must be a non-empty string")
        return v

    @field_validator("trace_id")
    @classmethod
    def trace_id_must_be_hex_or_none(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if len(v) != 32 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError(
                "trace_id must be a 32-character lowercase hex string or None"
            )
        return v
```

**Required import addition** (Pydantic v2 — already a dependency):

```python
from pydantic import BaseModel, field_validator
```

### 3.2 Route Decorator Change

Change the `@app.post("/agent/query")` decorator to:

```python
@app.post("/agent/query", response_model=QueryResponse, response_model_exclude_none=False)
```

`response_model_exclude_none=False` is explicit: `trace_id: null` must be serialised so callers can distinguish "tracing disabled" from a missing field. If callers need to suppress the null, they can opt in via `response_model_exclude_none=True` — but the default must be inclusive for audit completeness.

### 3.3 Return Statement Changes

Both return sites must return a `QueryResponse`-compatible dict (FastAPI serialises it automatically when `response_model` is set):

**Line 317 (cache-hit path)** — change `JSONResponse` to a plain dict return so FastAPI applies the `response_model`:

```python
# BEFORE
return JSONResponse(content={"response": final_response_text, "trace_id": trace_id})

# AFTER
return {"response": final_response_text, "trace_id": trace_id}
```

**Line 423 (normal path)** — already returns a plain dict; no change needed:

```python
return {"response": final_response_text, "trace_id": trace_id}
```

### 3.4 Migration Safety

All existing callers receive `{"response": str, "trace_id": str | null}`. The `QueryResponse` model exactly matches this shape. No existing caller will break because:
- No fields are removed.
- `trace_id` was already nullable in practice (callers must handle `null`).
- FastAPI's `response_model` validation runs server-side only; it raises `500` if the handler returns a non-conforming dict, which is the desired fail-closed behaviour.

---

## 4. `AgentStateSchema` JSON Schema (Draft-07)

### 4.1 Rationale for JSON Schema over TypedDict

`AgentState` is a LangGraph `TypedDict`. LangGraph nodes in the harness receive `StateDict = dict[str, Any]` — a plain dict at runtime. `TypedDict` annotations are erased at runtime and cannot be used for runtime validation. JSON Schema draft-07 is used because:
- `jsonschema` is already a transitive dependency (via `openapi-schema-validator`).
- Draft-07 is the version supported by `jsonschema.validate` without additional configuration.
- The schema can be stored as a static JSON file and compared in CI.

### 4.2 Schema File Location

Store the schema at:

```
compliance/schemas/agent_state_schema.json
```

This location is under `compliance/` (not `src/`) so it is treated as a compliance artifact alongside OSCAL and Lula files, and is subject to the same change-management controls.

### 4.3 Complete JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://cage.internal/schemas/agent_state_schema.json",
  "title": "AgentState",
  "description": "Runtime schema for the CAGE governed financial advisor LangGraph AgentState TypedDict. Source of truth: src/governed_financial_advisor/graph/state.py. Any change to AgentState MUST be reflected here within the same PR.",
  "type": "object",
  "required": [
    "messages",
    "next_step",
    "risk_status",
    "safety_status",
    "user_id",
    "approval_required",
    "guardrail_blocked",
    "guardrail_reason",
    "output_rail_applied",
    "completed_transactions"
  ],
  "additionalProperties": true,
  "properties": {
    "messages": {
      "type": "array",
      "description": "Shared conversation history. Annotated with add_messages reducer. Items are LangChain BaseMessage objects serialised as dicts at the boundary.",
      "items": {
        "type": "object"
      }
    },
    "next_step": {
      "type": "string",
      "description": "Routing control — the next node the supervisor selects.",
      "enum": [
        "data_analyst",
        "execution_analyst",
        "evaluator",
        "governed_trader",
        "explainer",
        "human_review",
        "FINISH"
      ]
    },
    "risk_status": {
      "type": "string",
      "description": "Risk loop control — outcome of the evaluator's risk assessment.",
      "enum": ["UNKNOWN", "APPROVED", "REJECTED_REVISE"]
    },
    "risk_feedback": {
      "type": ["string", "null"],
      "description": "Free-text feedback from the evaluator when risk_status is REJECTED_REVISE."
    },
    "loop_count": {
      "type": ["integer", "null"],
      "description": "Recursion depth counter for the evaluator safety breaker. Incremented unconditionally in execution_analyst_node. Graph breaks to explainer at loop_count >= 3.",
      "minimum": 0
    },
    "safety_status": {
      "type": "string",
      "description": "OPA pre-trade gate outcome set by safety_check_node.",
      "enum": ["APPROVED", "BLOCKED", "ESCALATED", "SKIPPED"]
    },
    "governance_signature": {
      "type": ["string", "null"],
      "description": "Cryptographic-style approval string generated by evaluator_node after a successful governance check."
    },
    "risk_attitude": {
      "type": ["string", "null"],
      "description": "User profile: risk tolerance (e.g. 'conservative', 'moderate', 'aggressive')."
    },
    "investment_period": {
      "type": ["string", "null"],
      "description": "User profile: investment horizon (e.g. 'short-term', 'long-term')."
    },
    "reasoning_output": {
      "type": ["string", "null"],
      "description": "Thinker node output — the reasoning chain passed to the Doer."
    },
    "execution_plan_output": {
      "oneOf": [
        {"type": "string"},
        {"type": "object"},
        {"type": "null"}
      ],
      "description": "Structured execution plan from execution_analyst_node. May be a JSON string or a parsed dict."
    },
    "data_analyst_ticker": {
      "type": ["string", "null"],
      "description": "Ticker symbol identified by the data analyst planner. Forwarded to governed_trader_graph for TOCTOU re-hydration."
    },
    "evaluation_result": {
      "type": ["object", "null"],
      "description": "Evaluator verdict and simulation results (CAGE System 3 control signal)."
    },
    "opa_results": {
      "type": ["object", "null"],
      "description": "Detailed OPA policy engine outputs for the auditor."
    },
    "execution_result": {
      "type": ["object", "null"],
      "description": "Executor technical output (CAGE System 1 output)."
    },
    "governance_summary": {
      "type": ["string", "null"],
      "description": "Final auditor report string surfaced to the UI."
    },
    "user_id": {
      "type": "string",
      "description": "User identity — ISO 42001 A.7.2 accountability attribution. Must be non-empty.",
      "minLength": 1
    },
    "latency_stats": {
      "type": ["object", "null"],
      "description": "Cumulative per-node latency in seconds. Used by the Bankruptcy Protocol.",
      "additionalProperties": {
        "type": "number"
      }
    },
    "completed_transactions": {
      "type": "array",
      "description": "Saga transaction ledger (Write-Ahead Log). Append-only via operator.add reducer. Sorted by sequence_id DESC for LIFO rollback. MUST be filtered before passing state to LLM-backed nodes.",
      "items": {
        "type": "object",
        "required": ["sequence_id", "timestamp", "uca_ref", "action", "idempotency_key", "status", "context_data"],
        "properties": {
          "sequence_id": {"type": "integer", "minimum": 0},
          "timestamp": {"type": "string", "description": "ISO-8601 UTC string."},
          "uca_ref": {"type": "string", "description": "STPA UCA ID (e.g. 'UCA-4')."},
          "action": {"type": "string"},
          "idempotency_key": {"type": "string"},
          "status": {
            "type": "string",
            "enum": ["PENDING", "COMPLETED", "ROLLED_BACK", "PARTIAL_FAILURE"]
          },
          "context_data": {"type": "object"}
        },
        "additionalProperties": false
      }
    },
    "approval_required": {
      "type": "boolean",
      "description": "HITL gate flag. True when trade value > $10k OR risk_score > 0.7. Default false."
    },
    "approval_decision": {
      "type": ["object", "null"],
      "description": "Human approval decision dict. Schema: {approved: bool, reviewer: str, rationale: str, comment: str, timestamp: str}.",
      "properties": {
        "approved": {"type": "boolean"},
        "reviewer": {"type": "string", "minLength": 1},
        "rationale": {"type": "string", "minLength": 1},
        "comment": {"type": "string"},
        "timestamp": {"type": "string"}
      },
      "required": ["approved", "reviewer", "rationale"]
    },
    "hitl_expires_at": {
      "type": ["string", "null"],
      "description": "ISO-8601 UTC TTL expiration timestamp for the pending HITL approval state."
    },
    "guardrail_blocked": {
      "type": "boolean",
      "description": "Set True by nemo_guardrail_node when the input rail blocks. Graph routes to END immediately. Default false."
    },
    "guardrail_reason": {
      "type": "string",
      "description": "Block reason string from nemo_guardrail_node. Empty string when not blocked."
    },
    "output_rail_applied": {
      "type": "boolean",
      "description": "Set True by nemo_output_rail_node after output screening/masking. Auditors assert this is True on every non-blocked trace. Default false."
    }
  }
}
```

### 4.4 `additionalProperties: true` Rationale

The schema uses `additionalProperties: true` at the top level because:
1. LangGraph may inject internal bookkeeping keys (e.g. `__pregel_*`) into the state dict at runtime.
2. Subgraph state dicts (e.g. `governed_trader_graph`) carry additional fields not in the parent `AgentState`.
3. Strict `additionalProperties: false` would cause false-positive validation failures in these cases.

The `LedgerEntry` sub-schema uses `additionalProperties: false` because it is a closed, well-defined record type.

---

## 5. Enforcement Strategy

### 5.1 API Boundary — `response_model` on `/agent/query`

**Location:** `src/governed_financial_advisor/server.py`

**Change:** Add `response_model=QueryResponse` to the `@app.post("/agent/query")` decorator.

**Effect:** FastAPI validates the handler's return dict against `QueryResponse` before serialising the HTTP response. A non-conforming return raises `ResponseValidationError` → HTTP 500. This is the correct fail-closed behaviour: a malformed response is a server error, not a client error.

**No performance impact:** FastAPI's Pydantic v2 serialisation is negligible compared to LLM inference latency.

### 5.2 LangGraph Node Boundary — `validate_state` Helper

**Location:** `src/gateway/governance/langgraph_harness/types.py`

Add the following after the existing type alias definitions:

```python
import json as _json
import logging as _logging
import os as _os
from pathlib import Path as _Path
from typing import Any

_schema_logger = _logging.getLogger("gateway.governance.langgraph_harness.types")

# Lazy-loaded schema and validator — imported only when CAGE_SCHEMA_STRICT=true
_AGENT_STATE_SCHEMA: dict | None = None
_JSONSCHEMA_AVAILABLE: bool | None = None


def _load_agent_state_schema() -> dict:
    """Load AgentStateSchema from compliance/schemas/agent_state_schema.json.

    Raises FileNotFoundError if the schema file is missing.
    Raises json.JSONDecodeError if the file is malformed.
    """
    global _AGENT_STATE_SCHEMA
    if _AGENT_STATE_SCHEMA is None:
        schema_path = _Path(__file__).parents[5] / "compliance" / "schemas" / "agent_state_schema.json"
        with schema_path.open() as f:
            _AGENT_STATE_SCHEMA = _json.load(f)
    return _AGENT_STATE_SCHEMA


def validate_state(state: StateDict, location: str = "unknown") -> None:
    """Validate *state* against AgentStateSchema when CAGE_SCHEMA_STRICT=true.

    This function is a no-op when the env var is absent or set to any value
    other than "true" (case-insensitive).  This allows hot paths (e.g.
    production inference under load) to disable validation without a code
    change.

    Args:
        state:    The LangGraph state dict to validate.
        location: Human-readable label for the call site (e.g.
                  "nemo_guardrail_node:entry").  Included in the error log.

    Raises:
        jsonschema.ValidationError: When CAGE_SCHEMA_STRICT=true and the
            state dict does not conform to AgentStateSchema.
        RuntimeError: When CAGE_SCHEMA_STRICT=true but jsonschema is not
            installed.
    """
    global _JSONSCHEMA_AVAILABLE

    if _os.environ.get("CAGE_SCHEMA_STRICT", "").lower() != "true":
        return

    if _JSONSCHEMA_AVAILABLE is None:
        try:
            import jsonschema as _jsonschema  # noqa: F401
            _JSONSCHEMA_AVAILABLE = True
        except ImportError:
            _JSONSCHEMA_AVAILABLE = False

    if not _JSONSCHEMA_AVAILABLE:
        raise RuntimeError(
            "CAGE_SCHEMA_STRICT=true but jsonschema is not installed. "
            "Run: pip install jsonschema"
        )

    import jsonschema

    schema = _load_agent_state_schema()
    try:
        jsonschema.validate(instance=state, schema=schema)
    except jsonschema.ValidationError as exc:
        _schema_logger.error(
            "[SchemaEnforcement] AgentState validation FAILED at %s: %s",
            location,
            exc.message,
        )
        raise
```

### 5.3 Which Nodes Call `validate_state` and When

The following table specifies the exact call sites. "Entry" means the first line of the node function body (before any business logic). "Exit" means immediately before the `return` statement.

| Node | Entry | Exit | Rationale |
|---|---|---|---|
| `nemo_guardrail_node` | ✅ | ✅ | Mandatory first node. Entry validates the initial state from `graph.ainvoke`. Exit validates the guardrail decision fields (`guardrail_blocked`, `guardrail_reason`) are correctly typed. |
| `nemo_output_rail_node` | ✅ | ❌ | Entry validates the full state before output screening. Exit is skipped: the node only returns `{"messages": [...], "output_rail_applied": True}` — a partial update dict, not a full state. |
| `evaluator_node` | ✅ | ❌ | Entry validates state before OPA policy evaluation. Exit skipped: partial update. |
| `safety_check_node` | ✅ | ❌ | Entry validates state before OPA pre-trade gate. Exit skipped: partial update. |
| `governed_trader_node` | ✅ | ❌ | Entry validates state before trade execution. This is the highest-risk node — schema validation here catches any upstream corruption before actuation. |
| `data_analyst_node` | ❌ | ❌ | Skipped: data analyst is a read-only subgraph with no governance actuation. Adding validation here would add latency to the hot path without safety benefit. |
| `execution_analyst_node` | ❌ | ❌ | Skipped: planning node, no actuation. |
| `explainer_node` | ❌ | ❌ | Skipped: terminal display node, no actuation. |
| `thinker_node` / `doer_node` | ❌ | ❌ | Skipped: supervisor routing nodes, no actuation. |

**Implementation pattern for each node that validates on entry:**

```python
from src.gateway.governance.langgraph_harness.types import validate_state

async def nemo_guardrail_node(state: StateDict) -> dict[str, Any]:
    validate_state(state, location="nemo_guardrail_node:entry")
    # ... existing logic ...
    result = {**base, cfg.blocked_state_key: False, cfg.reason_state_key: ""}
    validate_state(result, location="nemo_guardrail_node:exit")  # only for nodes with exit validation
    return result
```

### 5.4 Environment Variable Specification

| Variable | Default | Values | Effect |
|---|---|---|---|
| `CAGE_SCHEMA_STRICT` | `""` (absent) | `"true"` / anything else | `"true"` enables `jsonschema.validate` calls in `validate_state`. Any other value (including absent) is a no-op. |

**Deployment guidance:**
- `dev`: Set `CAGE_SCHEMA_STRICT=true` in `.env` to catch schema drift during development.
- `staging`: Set `CAGE_SCHEMA_STRICT=true` to validate before production promotion.
- `production`: Leave unset (default no-op) to avoid jsonschema overhead on the inference hot path. Re-enable temporarily during incident investigation.

---

## 6. Drift Detection Strategy

### 6.1 Problem

`AgentState` in [`src/governed_financial_advisor/graph/state.py`](src/governed_financial_advisor/graph/state.py) and the JSON Schema in `compliance/schemas/agent_state_schema.json` are maintained separately. A developer who adds a field to `AgentState` without updating the schema creates silent drift.

### 6.2 CI Check — pytest Schema Consistency Test

Add the following test to `tests/test_agent_state_schema.py`:

```python
"""
CI drift detection: verify AgentState TypedDict fields are all present
in the stored AgentStateSchema JSON Schema.

This test does NOT generate the schema from the TypedDict (that would
require a full type-introspection library). Instead it performs a
structural consistency check: every key declared in AgentState.__annotations__
must appear in the schema's "properties" dict.

This catches the most common drift pattern: a developer adds a field to
AgentState but forgets to update the JSON Schema.

Run with: pytest tests/test_agent_state_schema.py -v
"""

import json
from pathlib import Path

import pytest

SCHEMA_PATH = Path(__file__).parents[1] / "compliance" / "schemas" / "agent_state_schema.json"


def get_agent_state_annotations() -> set[str]:
    """Return the set of field names declared in AgentState.__annotations__."""
    from src.governed_financial_advisor.graph.state import AgentState
    # TypedDict stores annotations in __annotations__ (includes inherited)
    annotations: dict = {}
    for cls in reversed(AgentState.__mro__):
        annotations.update(getattr(cls, "__annotations__", {}))
    return set(annotations.keys())


def get_schema_properties() -> set[str]:
    """Return the set of property names declared in the JSON Schema."""
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    return set(schema.get("properties", {}).keys())


def test_schema_file_exists():
    """The schema file must exist at the expected path."""
    assert SCHEMA_PATH.exists(), (
        f"AgentStateSchema not found at {SCHEMA_PATH}. "
        "Run the schema generation step or restore the file from git."
    )


def test_all_agent_state_fields_in_schema():
    """Every AgentState field must appear in the JSON Schema properties.

    Failure means a field was added to AgentState without updating the schema.
    Update compliance/schemas/agent_state_schema.json to fix this.
    """
    state_fields = get_agent_state_annotations()
    schema_props = get_schema_properties()

    missing_from_schema = state_fields - schema_props
    assert not missing_from_schema, (
        f"The following AgentState fields are missing from the JSON Schema: "
        f"{sorted(missing_from_schema)}. "
        f"Add them to compliance/schemas/agent_state_schema.json."
    )


def test_no_phantom_schema_properties():
    """Every JSON Schema property must correspond to an AgentState field.

    Failure means a field was removed from AgentState but left in the schema
    (stale schema entry). Remove the stale property from the JSON Schema.
    """
    state_fields = get_agent_state_annotations()
    schema_props = get_schema_properties()

    phantom_in_schema = schema_props - state_fields
    assert not phantom_in_schema, (
        f"The following JSON Schema properties have no corresponding AgentState field: "
        f"{sorted(phantom_in_schema)}. "
        f"Remove them from compliance/schemas/agent_state_schema.json."
    )


def test_required_fields_are_non_optional_in_state():
    """Fields listed as 'required' in the schema must not be Optional in AgentState.

    This is a best-effort check using string inspection of annotations.
    It catches the most common case: a required field made Optional without
    updating the schema's required array.
    """
    import typing
    from src.governed_financial_advisor.graph.state import AgentState

    with SCHEMA_PATH.open() as f:
        schema = json.load(f)

    required_in_schema: list[str] = schema.get("required", [])

    hints = typing.get_type_hints(AgentState, include_extras=True)
    for field in required_in_schema:
        if field not in hints:
            continue
        hint = hints[field]
        hint_str = str(hint)
        # Optional[X] is Union[X, None] — both forms indicate nullable
        is_optional = (
            "Optional" in hint_str
            or "NoneType" in hint_str
            or "None" in hint_str
        )
        assert not is_optional, (
            f"Field '{field}' is listed as required in the JSON Schema but is "
            f"Optional in AgentState (hint: {hint}). Either remove it from the "
            f"schema's required array or make it non-optional in AgentState."
        )
```

### 6.3 CI Integration

Add the test to the existing pytest run in `.github/workflows/ci.yml`. The test must run in the same job that runs the existing unit tests. No additional dependencies are needed beyond `jsonschema` (already a transitive dep) and `pytest`.

```yaml
# In the existing test job, the test is picked up automatically by pytest
# discovery since it follows the tests/test_*.py naming convention.
# No explicit step addition is required if pytest runs tests/ recursively.
```

### 6.4 Pre-commit Hook (Optional Enhancement)

For faster feedback, add a pre-commit hook that runs `pytest tests/test_agent_state_schema.py -x -q` before any commit that touches `src/governed_financial_advisor/graph/state.py` or `compliance/schemas/agent_state_schema.json`. This is optional and does not block the CI-based enforcement.

---

## 7. Migration Path

### 7.1 Step-by-Step Implementation Order

A Code mode agent must implement changes in this exact order to avoid breaking the running service:

**Step 1 — Create the schema file**

Create `compliance/schemas/agent_state_schema.json` with the JSON Schema from Section 4.3. This is a new file with no runtime dependencies; it can be merged independently.

**Step 2 — Add `validate_state` to `types.py`**

Add the `validate_state` function and supporting globals to `src/gateway/governance/langgraph_harness/types.py` as specified in Section 5.2. The function is a no-op unless `CAGE_SCHEMA_STRICT=true`, so this change is safe to deploy without enabling the env var.

**Step 3 — Add `validate_state` call sites to nodes**

Add `validate_state(state, location="<node>:entry")` calls to the five nodes listed in Section 5.3. Because `validate_state` is a no-op in production (env var not set), this change is safe to deploy before enabling enforcement.

**Step 4 — Add `QueryResponse` model to `server.py`**

Add the `QueryResponse` class and the `field_validator` import to `server.py`. Do not yet add `response_model=QueryResponse` to the decorator. Verify the class definition is syntactically correct by running `python -c "from src.governed_financial_advisor.server import QueryResponse"`.

**Step 5 — Verify all return sites conform**

Before adding `response_model`, manually verify that both return sites in `/agent/query` return dicts that satisfy `QueryResponse`:
- `{"response": str, "trace_id": str | None}` — ✅ conforms.
- The `JSONResponse(content=...)` cache-hit path must be changed to a plain dict return (see Section 3.3).

**Step 6 — Add `response_model` to the route decorator**

Add `response_model=QueryResponse` to `@app.post("/agent/query")`. Deploy to `dev` and run the existing integration tests. Promote to `staging` after passing.

**Step 7 — Add the drift detection test**

Add `tests/test_agent_state_schema.py` as specified in Section 6.2. Run `pytest tests/test_agent_state_schema.py -v` locally to confirm all three tests pass before committing.

**Step 8 — Enable `CAGE_SCHEMA_STRICT=true` in dev and staging**

Set `CAGE_SCHEMA_STRICT=true` in the dev and staging environment configs. Monitor logs for `[SchemaEnforcement] AgentState validation FAILED` messages. Resolve any failures before promoting to production.

### 7.2 Rollback Plan

- **`response_model` rollback:** Remove `response_model=QueryResponse` from the decorator. The handler continues to return the same dict; FastAPI stops validating it. Zero downtime.
- **`validate_state` rollback:** Unset `CAGE_SCHEMA_STRICT` env var. All `validate_state` calls become no-ops immediately (no restart required if the env var is read per-call, which the implementation above does via `os.environ.get`).

### 7.3 Backward Compatibility Guarantee

The `QueryResponse` model is a strict subset of what the handler already returns. No existing caller receives fewer fields. The only observable change for callers is:
1. FastAPI now generates an OpenAPI schema for the `/agent/query` response (previously `{}` / untyped).
2. `trace_id: null` is now explicitly documented as a valid response value.