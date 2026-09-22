# GAP-3: AgentState Schema Enforcement Architecture

> [!NOTE]
> **Document Status**: Design Specification (GAP-3) — **partially implemented**.
> **Implementation Target**: Layer 4 Reference Application ([`src/governed_financial_advisor/`](../../src/governed_financial_advisor/)) and the Layer 1 kernel state contract.

**Status:** Partially Implemented — see the component matrix below
**Date:** 2026-07-05
**Last Updated:** 2026-09-22
**Author:** Architecture Review
**Implements:** GAP-3 (Schema Enforcement at API and Node Boundaries)

### Implementation Status at HEAD

| Component | Specified in | Status at HEAD | Evidence |
| --------- | ------------ | -------------- | -------- |
| `QueryResponse` Pydantic model | §3 | **Implemented** | [`src/governed_financial_advisor/models/query.py`](../../src/governed_financial_advisor/models/query.py) — `response`, `trace_id` (32-hex pattern), `frozen=True` |
| `response_model` on `/agent/query` | §5.1 | **Implemented** | [`server.py:323`](../../src/governed_financial_advisor/server.py#L323) — `@app.post("/agent/query", response_model=QueryResponse)` |
| `agent_state_schema.json` artifact | §4 | **Implemented, auto-generated** | [`compliance/schemas/agent_state_schema.json`](../../compliance/schemas/agent_state_schema.json) — 40 properties, Draft 2020-12 |
| Schema drift detection in CI | §6 | **Implemented** | `make check-agent-state-schema` → `uv run python scripts/generate_agent_state_schema.py --check` |
| Kernel state-contract validator | §5.2 | **Implemented but not wired** | [`src/gateway/governance/state_contract.py`](../../src/gateway/governance/state_contract.py) — `CompiledStateValidator` / `StateContractViolation`. Unit-tested in [`tests/test_runtime_schema_enforcement.py`](../../tests/test_runtime_schema_enforcement.py); **no importer exists in `src/`** |
| `validate_state` helper + `CAGE_SCHEMA_STRICT` | §5.2–§5.4 | **Not implemented** | Neither symbol appears anywhere in `src/`. The kernel took the `CompiledStateValidator` route instead |

> [!WARNING]
> Sections 5.2, 5.3 and 5.4 below describe a `validate_state` helper gated by a `CAGE_SCHEMA_STRICT` environment variable. **That design was not the one adopted.** The kernel instead ships `CompiledStateValidator`, which takes an explicit `enforcing: bool = True` constructor argument rather than reading an env var. Read those sections as historical design intent, not as a description of runtime behaviour.

**Affected files:**
- `src/governed_financial_advisor/server.py`
- `src/gateway/governance/state_contract.py`
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

## 4. `AgentStateSchema` JSON Schema (Draft 2020-12)

### 4.1 Rationale for JSON Schema over TypedDict

`AgentState` is a LangGraph `TypedDict`. LangGraph nodes in the harness receive `StateDict = dict[str, Any]` — a plain dict at runtime. `TypedDict` annotations are erased at runtime and cannot be used for runtime validation. JSON Schema is used because:
- `jsonschema` is already available in the resolved environment and is imported directly by [`state_contract.py`](../../src/gateway/governance/state_contract.py).
- The schema can be stored as a static JSON file and compared in CI.

> [!IMPORTANT]
> This section originally specified **draft-07**. The artifact that actually shipped declares
> `"$schema": "https://json-schema.org/draft/2020-12/schema"` and is compiled with
> `jsonschema.Draft202012Validator`. Draft 2020-12 is the binding version.

### 4.2 Schema File Location

The schema lives at:

```
compliance/schemas/agent_state_schema.json
```

This location is under `compliance/` (not `src/`) so it is treated as a compliance artifact alongside OSCAL and Lula files, and is subject to the same change-management controls.

> [!IMPORTANT]
> The file is **machine-generated, not hand-edited**. [`scripts/generate_agent_state_schema.py`](../../scripts/generate_agent_state_schema.py) derives it from the `AgentState` runtime model and writes it to `SCHEMA_OUTPUT_PATH`. Regenerate with `uv run python scripts/generate_agent_state_schema.py`; verify freshness with `make check-agent-state-schema`. The inline copy in §4.3 below is illustrative and may lag the generated artifact — the generated file is authoritative.

### 4.3 Illustrative JSON Schema

**NOTE:** The schema is auto-generated by [`scripts/generate_agent_state_schema.py`](../../scripts/generate_agent_state_schema.py). The canonical source is [`compliance/schemas/agent_state_schema.json`](../../compliance/schemas/agent_state_schema.json). The inline structure below is a trimmed illustration; the generated artifact carries all 40 AgentState properties:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://cage.internal/schemas/agent_state_schema.json",
  "$comment": "Auto-generated by scripts/generate_agent_state_schema.py — do not edit directly",
  "title": "AgentState",
  "description": "Financial Advisor Agent State Schema — synchronized from src/governed_financial_advisor/graph/state.py",
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
  "additionalProperties": false,
  "properties": {
    "messages": {
      "type": "array",
      "description": "Shared conversation history (LangChain BaseMessage serialized at boundary)",
      "items": {"$ref": "#/$defs/OpaqueMessage"}
    },
    "next_step": {
      "type": "string",
      "enum": ["data_analyst", "execution_analyst", "evaluator", "governed_trader", "explainer", "human_review", "FINISH"]
    },
    "risk_status": {
      "type": "string",
      "enum": ["UNKNOWN", "APPROVED", "REJECTED_REVISE"]
    },
    "risk_feedback": {"type": ["string", "null"]},
    "loop_count": {"type": ["integer", "null"], "minimum": 0},
    "safety_status": {
      "type": "string",
      "enum": ["APPROVED", "BLOCKED", "ESCALATED", "SKIPPED"]
    },
    "governance_signature": {"type": ["string", "null"]},
    "risk_attitude": {"type": ["string", "null"]},
    "investment_period": {"type": ["string", "null"]},
    "reasoning_output": {"type": ["string", "null"]},
    "execution_plan_output": {
      "oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}]
    },
    "data_analyst_ticker": {"type": ["string", "null"]},
    "evaluation_result": {"type": ["object", "null"]},
    "opa_results": {"type": ["object", "null"]},
    "execution_result": {"type": ["object", "null"]},
    "governance_summary": {"type": ["string", "null"]},
    "user_id": {
      "type": "string",
      "description": "User identity — ISO 42001 A.7.2 accountability attribution",
      "minLength": 1
    },
    "latency_stats": {
      "type": ["object", "null"],
      "additionalProperties": {"type": "number"}
    },
    "completed_transactions": {
      "type": "array",
      "description": "Saga transaction ledger (Write-Ahead Log) — append-only via operator.add reducer",
      "items": {"$ref": "#/$defs/LedgerEntry"}
    },
    "approval_required": {"type": "boolean"},
    "approval_decision": {"type": ["object", "null"]},
    "hitl_expires_at": {"type": ["string", "null"]},
    "guardrail_blocked": {"type": "boolean"},
    "guardrail_reason": {
      "type": "string",
      "description": "NeMo guardrail block reason — empty string when not blocked"
    },
    "output_rail_applied": {"type": "boolean"},
    "ftra_status": {"type": ["string", "null"]},
    "ftra_result": {"type": ["object", "null"]},
    "ftra_defer_id": {"type": ["string", "null"]},
    "narrow_status": {"type": ["string", "null"]},
    "narrowed_params": {"type": ["object", "null"]},
    "pause_resume_token": {"type": ["string", "null"]},
    "pause_reason": {"type": ["string", "null"]}
  },
  "$defs": {
    "OpaqueMessage": {
      "type": "object",
      "description": "LangChain BaseMessage serialised at boundary"
    },
    "LedgerEntry": {
      "type": "object",
      "required": ["sequence_id", "timestamp", "uca_ref", "action", "idempotency_key", "status", "context_data"],
      "properties": {
        "sequence_id": {"type": "integer", "minimum": 0},
        "timestamp": {"type": "string"},
        "uca_ref": {"type": "string"},
        "action": {"type": "string"},
        "idempotency_key": {"type": "string"},
        "status": {"type": "string", "enum": ["PENDING", "COMPLETED", "ROLLED_BACK", "PARTIAL_FAILURE"]},
        "context_data": {"type": "object"}
      },
      "additionalProperties": false
    }
  }
}
```

### 4.4 State Contract Enforcement Boundary

**Validation applies strictly to entry and terminal state boundaries, not intermediate LangGraph node deltas.**

- **Full-state validation (where `additionalProperties: false` is enforced):**
  - Graph entry: `graph.ainvoke(initial_state)` — the initial state dict must satisfy the full schema.
  - Terminal state: The final state dict returned by `graph.ainvoke()` after all nodes complete.
  - Entry validation sites: `nemo_guardrail_node:entry`, `evaluator_node:entry`, `governed_trader_node:entry` (see Section 5.3).

- **Partial delta updates (exempt from `additionalProperties` enforcement):**
  - LangGraph nodes return partial update dicts (e.g., `{"guardrail_blocked": True, "guardrail_reason": "..."}`) that merge into the state via reducers.
  - These partial updates are not validated against the full schema — only their merge result is validated at the next node entry boundary.
  - Example: `nemo_guardrail_node` returns `{"messages": [...], "guardrail_blocked": False, "guardrail_reason": ""}` — this is a 3-key dict, not a 40-key AgentState, and is not validated until the next node receives the merged state.

**Rationale:** `additionalProperties: false` enforces that the full state at boundaries contains only the declared 40 properties, preventing schema drift from undeclared fields leaking into the state contract. Intermediate node return values are partial deltas by design and are merged into state via LangGraph reducers before the next validation checkpoint.

**Implementation detail:** The `LedgerEntry` sub-schema uses `additionalProperties: false` because it is a closed, well-defined record type with no partial-update semantics.

---

## 5. Enforcement Strategy

### 5.1 API Boundary — `response_model` on `/agent/query`

**Location:** [`src/governed_financial_advisor/server.py:323`](../../src/governed_financial_advisor/server.py#L323)

**Status: Implemented.** The decorator reads `@app.post("/agent/query", response_model=QueryResponse)` at HEAD.

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
        schema_path = (
            _Path(__file__).parents[5]
            / "compliance"
            / "schemas"
            / "agent_state_schema.json"
        )
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
    validate_state(
        result, location="nemo_guardrail_node:exit"
    )  # only for nodes with exit validation
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

`AgentState` in [`src/governed_financial_advisor/graph/state.py`](../../src/governed_financial_advisor/graph/state.py) and the JSON Schema in [`compliance/schemas/agent_state_schema.json`](../../compliance/schemas/agent_state_schema.json) could drift if maintained separately: a developer who adds a field to `AgentState` without updating the schema creates a silent gap.

> [!NOTE]
> **Resolved at HEAD by generation, not by parallel maintenance.** The schema is derived from the `AgentState` runtime model by [`scripts/generate_agent_state_schema.py`](../../scripts/generate_agent_state_schema.py), and `--check` mode compares the freshly generated schema against the committed artifact. The `make check-agent-state-schema` target runs exactly this and is the enforcing gate. The pytest approach described in §6.2 below was the original proposal; the generator-diff approach is what shipped.

### 6.2 CI Check — pytest Schema Consistency Test (original proposal)

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

SCHEMA_PATH = (
    Path(__file__).parents[1] / "compliance" / "schemas" / "agent_state_schema.json"
)


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
            "Optional" in hint_str or "NoneType" in hint_str or "None" in hint_str
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