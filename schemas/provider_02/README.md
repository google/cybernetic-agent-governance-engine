# CAGE Governance Schema Definitions (v1)

**Schema URN Namespace:** `urn:cage:governance:v1`  
**JSON Schema Version:** Draft 2020-12  
**Status:** Candidate for NexArt native support

---

## Schema Files

| File | Schema URN | Description |
|---|---|---|
| [`project_bundle_step.schema.json`](project_bundle_step.schema.json) | `urn:cage:governance:v1:step-entry` | Single DAG node execution snapshot |
| [`attestation_bundle.schema.json`](attestation_bundle.schema.json) | `urn:cage:governance:v1:attestation-bundle` | Complete governance bundle (full DAG traversal) |
| [`graph_topology.schema.json`](graph_topology.schema.json) | `urn:cage:governance:v1:graph-topology` | Domain-agnostic graph structure definition |
| [`types.ts`](types.ts) | N/A | TypeScript type definitions |

---

## Schema Overview

### ProjectBundleStepEntry

**Purpose:** Represents a single node execution in the governance DAG.

**Key Fields:**
- `stepId` (UUID): Unique identifier
- `nodeName` (string): LangGraph node name
- `parentStepIds` (UUID[]): Parent nodes (captures DAG edges)
- `timestampUtc` (ISO 8601): Execution timestamp
- `durationMs` (number): Execution duration
- `signals` (object): Governance signals (CBF verdicts, OPA decisions) — **open extension point**
- `metadata` (object): Arbitrary node metadata — **open extension point**
- `stateHash` (SHA-256 hex): State snapshot digest

**Extension Points:**
- `signals`: Domain-specific governance signals
- `metadata`: Arbitrary execution metadata

---

### AttestationBundle

**Purpose:** Complete governance bundle for one graph execution.

**Key Fields:**
- `bundleId` (UUID): Unique bundle identifier
- `threadId` (string): Session/thread ID
- `steps` (ProjectBundleStepEntry[]): Ordered DAG steps
- `startedAt` (ISO 8601): Execution start time
- `completedAt` (ISO 8601): Execution end time
- `terminalPath` (enum): Terminal path classification

**Terminal Path Classification:**
- `happy_path`: Successful execution, all gates passed
- `nemo_block`: NeMo Guardrails policy violation
- `cbf_block`: Control Barrier Function safety constraint
- `loop_breaker`: Iteration limit reached
- `unknown`: Unclassifiable/fallback (fail-closed — used when path cannot be determined)

---

### GraphTopology

**Purpose:** Domain-agnostic DAG structure definition.

**Key Fields:**
- `nodes` (string[]): All node names
- `parentEdges` (object): Node → parent nodes mapping
- `terminalNode` (string): Success terminal node
- `interruptNode` (string | null): HITL interrupt node (optional)
- `attestationNodes` (string[]): CER emission trigger nodes (optional)

**Usage:** Attestation adapters use this for parent-edge resolution and terminal path classification without hardcoding domain vocabulary.

---

## Invariants

### DAG Structural Invariants
1. **Acyclicity:** Steps form a directed acyclic graph (enforced by execution order, not schema)
2. **Parent References:** All `parentStepIds` must reference earlier steps in the same bundle
3. **Node Validity:** `nodeName` must exist in `GraphTopology.nodes` (if topology provided)
4. **Timestamp Ordering:** Child steps must have `timestampUtc` ≥ any parent's `timestampUtc`

### Terminal Path Invariants
1. **Happy Path:** `terminalNode` step executed successfully
2. **Block Paths:** Execution terminated before `terminalNode`
3. **Loop Breaker:** Execution halted due to iteration limit (not error)

### Extension Point Guarantees
1. **Unknown Fields:** `signals` and `metadata` may contain arbitrary domain-specific fields
2. **Forward Compatibility:** Consumers must ignore unknown fields in `signals`/`metadata`
3. **Additive Changes:** New terminal path types may be added in future versions

### RFC 8785 (JCS) Canonicalization Requirements
**Critical for CER Hash Integrity:**

All data in `signals` and `metadata` extension points **must** comply with RFC 8785 (JSON Canonicalization Scheme) to ensure deterministic digest computation:

1. **Object Key Ordering:** Keys must be lexicographically sorted before serialization
2. **No Trailing Zeros:** Floating-point values must not have trailing zeros (e.g., `1.0` → `1`)
3. **No Scientific Notation:** Use decimal representation (e.g., `1000000` not `1e6`)
4. **Unicode Normalization:** String values must be NFC-normalized
5. **No Whitespace:** No spaces, tabs, or newlines outside string values

**Example:**
```json
// ❌ INVALID (keys unsorted, trailing zero)
{"signals": {"z_score": 2.0, "verdict": "ALLOW"}}

// ✅ VALID (keys sorted, no trailing zero)
{"signals": {"verdict": "ALLOW", "z_score": 2}}
```

**Implementation:**
- Python: Use `import jcs; jcs.canonicalize(data)`
- TypeScript: Use `@stablelib/canonical-json`
- Other: See RFC 8785 reference implementations

**Verification:**
NexArt's CER hashing pipeline expects JCS-canonicalized payloads. Non-compliant data will cause hash mismatches during verification.

---

## Examples

### Example 1: Single-Path Happy Path

```json
{
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "threadId": "session-12345",
  "steps": [
    {
      "stepId": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
      "nodeName": "nemo_guardrail",
      "parentStepIds": [],
      "timestampUtc": "2026-09-14T12:00:00.000Z",
      "durationMs": 150.5,
      "signals": {},
      "metadata": {"model": "meta-llama/Llama-Guard-3-8B"},
      "stateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "stepId": "7d793037-5e6a-4f7a-9c8d-2e5f8b3a4c1d",
      "nodeName": "safety_check",
      "parentStepIds": ["c9bf9e57-1685-4c89-bafb-ff5af830be8a"],
      "timestampUtc": "2026-09-14T12:00:00.500Z",
      "durationMs": 80.2,
      "signals": {"opa_verdict": "ALLOW"},
      "metadata": {"policy": "OPA_PRE_TRADE_001"},
      "stateHash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  ],
  "startedAt": "2026-09-14T12:00:00.000Z",
  "completedAt": "2026-09-14T12:00:05.000Z",
  "terminalPath": "happy_path"
}
```

### Example 2: CBF Block

```json
{
  "bundleId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "threadId": "session-67890",
  "steps": [
    {
      "stepId": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
      "nodeName": "ftra_node",
      "parentStepIds": [],
      "timestampUtc": "2026-09-14T14:30:00.000Z",
      "durationMs": 200.0,
      "signals": {
        "cbf_verdict": "BLOCKED",
        "cbf_reason": "reachable_set_violation"
      },
      "metadata": {"cbf_engine": "casadi_v3.6"},
      "stateHash": "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90"
    }
  ],
  "startedAt": "2026-09-14T14:30:00.000Z",
  "completedAt": "2026-09-14T14:30:00.500Z",
  "terminalPath": "cbf_block"
}
```

### Example 3: GraphTopology

```json
{
  "nodes": [
    "nemo_guardrail",
    "thinker_node",
    "ftra_node",
    "safety_check",
    "governed_trader",
    "explainer"
  ],
  "parentEdges": {
    "nemo_guardrail": [],
    "thinker_node": ["nemo_guardrail"],
    "ftra_node": ["thinker_node"],
    "safety_check": ["ftra_node"],
    "governed_trader": ["safety_check"],
    "explainer": ["governed_trader"]
  },
  "terminalNode": "governed_trader",
  "interruptNode": "ftra_node",
  "attestationNodes": ["safety_check", "governed_trader"]
}
```

---

## Validation

### JSON Schema Validation

```bash
# Using ajv-cli
npm install -g ajv-cli
ajv validate -s attestation_bundle.schema.json -d example_bundle.json
```

### TypeScript Type Checking

```typescript
import { AttestationBundle, ProjectBundleStepEntry } from './types';

const bundle: AttestationBundle = {
  bundleId: "550e8400-e29b-41d4-a716-446655440000",
  threadId: "session-12345",
  steps: [/* ... */],
  startedAt: "2026-09-14T12:00:00.000Z",
  completedAt: "2026-09-14T12:00:05.000Z",
  terminalPath: "happy_path"
};
```

---

## Versioning Strategy

**Current Version:** `v1`  
**Schema URN Pattern:** `urn:cage:governance:v{major}:{schema-name}`

### Version Compatibility Rules

**Breaking Changes (require major version bump):**
- Removing required fields
- Changing field types
- Renaming fields
- Removing terminal path enum values

**Additive Changes (no version bump required):**
- Adding optional fields
- Adding new terminal path enum values
- Adding new fields to `signals` or `metadata`

**Consumers must:**
- Ignore unknown fields in `signals` and `metadata`
- Treat unknown `terminalPath` values as errors (fail-closed)

---

## Usage in CAGE

**Source Python Definitions:**
- [`src/integrations/provider_02/adapter.py:104`](../../src/integrations/provider_02/adapter.py) — `ProjectBundleStepEntry`
- [`src/integrations/provider_02/adapter.py:135`](../../src/integrations/provider_02/adapter.py) — `AttestationBundle`
- [`src/gateway/governance/seams/graph_topology.py:34`](../../src/gateway/governance/seams/graph_topology.py) — `GraphTopology`

**Serialization:**
```python
from src.integrations.provider_02.adapter import AttestationBundle

bundle = AttestationBundle(...)
json_data = bundle.to_dict()  # Produces schema-compliant JSON
```

---

## Integration with NexArt

**Proposal:** NexArt native schema support (Option 2A)

**Benefits:**
- Eliminates need for intermediate `cer.ai.execution.v1` wrappers
- CAGE's governance DAGs recorded natively
- No migration cost (schemas already match CAGE's internal models)

**Open Questions:**
1. Should NexArt issue per-node CERs + bundle-level composite CER, or per-node only?
2. Are unknown `terminalPath` values accepted (with warning) or rejected?
3. Are unknown fields in `signals`/`metadata` preserved through round-trip?

---

## References

- Implementation plan: [`plans/provider_02_native_schema_handoff.md`](../../plans/provider_02_native_schema_handoff.md)
- Existing adapter: [`src/integrations/provider_02/adapter.py`](../../src/integrations/provider_02/adapter.py)
- Graph topology seam: [`src/gateway/governance/seams/graph_topology.py`](../../src/gateway/governance/seams/graph_topology.py)
- JSON Schema specification: https://json-schema.org/draft/2020-12/json-schema-core
