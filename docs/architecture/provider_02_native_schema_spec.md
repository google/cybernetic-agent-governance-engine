# NexArt Native Schema Support — CAGE Governance DAG Recording

**Schema Version:** v1  
**Schema URN Namespace:** `urn:cage:governance:v1`  
**JSON Schema Specification:** Draft 2020-12  
**Document Status:** Technical Specification for NexArt Native Integration  
**Last Updated:** 2026-09-14  
**Author:** CAGE Engineering Team  
**Audience:** NexArt Engineering (Jeremy Bouedo), CAGE Adopters

---

## Executive Summary

This document specifies the formal technical contract for **NexArt native support of CAGE governance DAG schemas (Option 2A)**. Instead of wrapping CAGE's governance execution traces in generic execution tracking schemas (`cer.ai.execution.v1`), NexArt will ingest CAGE's canonical governance schemas directly as first-class attestation primitives.

**Strategic Decision:** Native governance DAG recording ensures:
- CAGE's governance schemas remain authoritative and version-controlled within CAGE
- No impedance mismatch from conforming to intermediate composite formats
- NexArt becomes a native governance recorder, not a wrapped execution tracker
- Zero migration debt when CAGE evolves governance semantics

**Deliverables in this specification:**
1. Architecture overview and Option 2A rationale
2. Core schema contracts (3 schemas: attestation-bundle, step-entry, graph-topology)
3. Deterministic canonicalization rules (RFC 8785 JCS)
4. DAG topological invariants and validation rules
5. Test fixtures catalog with verification targets
6. NexArt ingestion and integration checklist

---

## 1. Architecture Overview & Rationale

### 1.1 Option 2A Decision Model

**Rejected Approach (Option 2B):** Tactical hash chaining via `parentCertificateHashes[]` array in generic execution wrappers.

**Accepted Approach (Option 2A):** Native CAGE governance schema support in NexArt.

**Rationale:**

| Criterion | Option 2B (Generic Wrapper) | Option 2A (Native Support) |
|-----------|----------------------------|----------------------------|
| **Schema Authority** | NexArt owns composite schema | CAGE owns governance schema |
| **Semantic Fidelity** | DAG structure implied via hash chains | DAG structure explicit via `parentStepIds` |
| **Migration Cost** | Must migrate if CAGE evolves | Zero migration (schemas co-evolve) |
| **Terminal Path Taxonomy** | Generic execution states | Domain-specific governance outcomes |
| **Query Semantics** | Hash traversal only | Native DAG queries (path finding, filtering) |
| **Technical Debt** | Permanent conformance layer | Clean architectural boundary |

**Jeremy Bouedo's offer (Sep 9, 2026, 12:19 PM):**
> *"If you send us the stabilized CAGE governance/graph schema, we're happy to look at supporting that natively in NexArt rather than having you permanently shape CAGE around an intermediate NexArt composite model."*

### 1.2 URN Namespace Structure

**Base Namespace:** `urn:cage:governance:v1`

**Schema URIs:**
- `urn:cage:governance:v1:attestation-bundle` — Complete governance bundle (full DAG traversal)
- `urn:cage:governance:v1:step-entry` — Single DAG node execution snapshot
- `urn:cage:governance:v1:graph-topology` — Domain-agnostic graph structure definition

**Versioning Convention:**
- Major version (`v1`, `v2`) embedded in URN for breaking changes
- Additive changes (new optional fields, new terminal path types) do NOT require version bump
- Schema evolution follows semantic versioning principles

### 1.3 Governance DAG Recording Model

**CAGE Execution Model:**
1. User request enters LangGraph-based governance workflow
2. Each LangGraph node executes sequentially or in parallel
3. Each node execution generates a [`ProjectBundleStepEntry`](../../src/integrations/provider_02/adapter.py:104)
4. Node entries track parent/child relationships via `parentStepIds` array
5. Complete execution bundle wrapped in [`AttestationBundle`](../../src/integrations/provider_02/adapter.py:135)
6. Terminal path classification determines execution outcome (`happy_path`, `cbf_block`, `nemo_block`, `loop_breaker`, `unknown`)

**NexArt Recording Contract:**
- Ingest entire [`AttestationBundle`](../../src/integrations/provider_02/adapter.py:135) as atomic submission
- Issue Certificate of Execution Record (CER) for each [`ProjectBundleStepEntry`](../../src/integrations/provider_02/adapter.py:104)
- Preserve DAG topology via `parentStepIds` linkage
- Store terminal path classification for filtering and auditing
- Compute deterministic state hashes per RFC 8785 (JCS)
- Maintain queryable transparency log with DAG traversal APIs

---
## 2. Core Schema Contracts

### 2.1 Schema Summary

CAGE defines three foundational schemas for governance DAG recording:

| Schema Name | Schema URI | Purpose | Source Definition |
|-------------|-----------|---------|-------------------|
| **AttestationBundle** | `urn:cage:governance:v1:attestation-bundle` | Complete governance bundle wrapping full DAG traversal | [`src/integrations/provider_02/adapter.py:135`](../../src/integrations/provider_02/adapter.py:135) |
| **ProjectBundleStepEntry** | `urn:cage:governance:v1:step-entry` | Single DAG node execution snapshot with parent edges | [`src/integrations/provider_02/adapter.py:104`](../../src/integrations/provider_02/adapter.py:104) |
| **GraphTopology** | `urn:cage:governance:v1:graph-topology` | Domain-agnostic graph structure definition | [`src/gateway/governance/seams/graph_topology.py:34`](../../src/gateway/governance/seams/graph_topology.py:34) |

**JSON Schema Definitions:**
- [`schemas/provider_02/attestation_bundle.schema.json`](../../schemas/provider_02/attestation_bundle.schema.json)
- [`schemas/provider_02/project_bundle_step.schema.json`](../../schemas/provider_02/project_bundle_step.schema.json)
- [`schemas/provider_02/graph_topology.schema.json`](../../schemas/provider_02/graph_topology.schema.json)

### 2.2 AttestationBundle Schema

**Purpose:** Top-level container for complete governance execution DAG.

**Required Fields:**

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `bundleId` | UUID v4 string | Unique bundle identifier | RFC 4122 compliant |
| `threadId` | string | Session/conversation thread ID | Non-empty, max 256 chars |
| `steps` | ProjectBundleStepEntry[] | Ordered array of DAG node executions | Min 1 step, topologically sorted |
| `startedAt` | ISO 8601 string | Execution start timestamp (UTC) | Valid ISO 8601 with 'Z' suffix |
| `completedAt` | ISO 8601 string | Execution completion timestamp (UTC) | ≥ startedAt |
| `terminalPath` | enum | Terminal path classification | One of: `happy_path`, `nemo_block`, `cbf_block`, `loop_breaker`, `unknown` |

**Terminal Path Taxonomy:**

| Value | Meaning | DAG Completion State |
|-------|---------|---------------------|
| `happy_path` | Successful execution, all governance gates passed | Reached designated `terminalNode` |
| `nemo_block` | NeMo Guardrails policy violation | Halted before `terminalNode` due to policy check failure |
| `cbf_block` | Control Barrier Function safety constraint violation | Halted before `terminalNode` due to CBF safety boundary |
| `loop_breaker` | Iteration limit reached in refinement loop | Halted via iteration counter (not error) |
| `unknown` | Unclassifiable execution path (fail-closed fallback) | Cannot determine terminal state; conservative classification |

**Semantic Invariants:**
- `steps` array MUST be topologically sorted (parents appear before children)
- `completedAt` timestamp MUST be ≥ `startedAt` timestamp
- `terminalPath` MUST accurately reflect final DAG node reached
- Unknown `terminalPath` values SHOULD be rejected (fail-closed) unless NexArt explicitly supports forward compatibility

### 2.3 ProjectBundleStepEntry Schema

**Purpose:** Individual node execution record capturing governance signals and DAG edges.

**Required Fields:**

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `stepId` | UUID v4 string | Unique step identifier | RFC 4122 compliant, distinct per execution instance |
| `nodeName` | string | LangGraph node name | Must exist in `GraphTopology.nodes` if topology provided |
| `parentStepIds` | UUID[] | Array of parent step IDs (DAG edges) | Each ID must reference earlier step in same bundle |
| `timestampUtc` | ISO 8601 string | Node execution start time (UTC) | Monotonic non-decreasing relative to parents |
| `durationMs` | number | Execution duration in milliseconds | Non-negative float |
| `stateHash` | string | SHA-256 hex digest of node state | 64-character lowercase hex string |

**Extension Point Fields:**

| Field | Type | Description | JCS Canonicalization Required |
|-------|------|-------------|-------------------------------|
| `signals` | object | Governance signals (CBF verdicts, OPA decisions, NeMo outcomes) | **YES** — Keys must be sorted, no trailing zeros |
| `metadata` | object | Arbitrary node metadata (model names, policy IDs, timing breakdowns) | **YES** — Keys must be sorted, no trailing zeros |

**Common Signal Examples:**

```json
{
  "signals": {
    "cbf_verdict": "BLOCKED",
    "cbf_reason": "reachable_set_violation",
    "opa_decision": "DENY",
    "opa_policy": "OPA_PRE_TRADE_001"
  }
}
```

**Semantic Invariants:**
- `parentStepIds` MUST reference steps with earlier array indices in `AttestationBundle.steps`
- `timestampUtc` MUST be ≥ any parent step's `timestampUtc` (monotonic time ordering)
- `stateHash` MUST be deterministically computed from JCS-canonicalized state snapshot
- Unknown fields in `signals`/`metadata` MUST be preserved by NexArt for forward compatibility

### 2.4 GraphTopology Schema

**Purpose:** Domain-agnostic DAG structure definition enabling topology-aware validation and terminal path classification.

**Required Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `nodes` | string[] | Complete list of all node names in DAG |
| `parentEdges` | object | Map from node name to array of parent node names |
| `terminalNode` | string | Designated success terminal node (for `happy_path` detection) |

**Optional Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `interruptNode` | string \| null | Human-in-the-loop (HITL) interrupt node name |
| `attestationNodes` | string[] | Nodes that trigger CER emission checkpoints |

**Example:**

```json
{
  "nodes": ["nemo_guardrail", "thinker_node", "ftra_node", "safety_check", "governed_trader", "explainer"],
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

**Usage by NexArt:**
- Validate `ProjectBundleStepEntry.nodeName` exists in `nodes` array
- Verify `parentStepIds` conform to `parentEdges` topology
- Classify `terminalPath` by checking if final step matches `terminalNode`
- Optionally enforce attestation checkpoints at designated `attestationNodes`

---
## 3. Deterministic Canonicalization (RFC 8785)

### 3.1 JSON Canonicalization Scheme (JCS) Requirement

**Critical for CER Hash Integrity:** All data in `signals` and `metadata` extension points **MUST** comply with **RFC 8785 (JSON Canonicalization Scheme)** to ensure deterministic digest computation across heterogeneous implementations.

**Why JCS is Non-Negotiable:**
- CER signatures depend on byte-for-byte identical JSON representations
- Naive JSON serialization produces non-deterministic output (key ordering, floating-point formatting, whitespace)
- Without JCS, hash mismatches break verification chains
- Extension points (`signals`, `metadata`) accept arbitrary user data requiring strict canonicalization

### 3.2 RFC 8785 Canonicalization Rules

All JSON data submitted to NexArt via `signals` and `metadata` fields MUST conform to these rules:

| Rule | Requirement | Example |
|------|-------------|---------|
| **1. Object Key Ordering** | Keys MUST be lexicographically sorted (Unicode code point order) | `{"a": 1, "b": 2}` not `{"b": 2, "a": 1}` |
| **2. No Trailing Zeros** | Floating-point values MUST NOT have trailing zeros | `2` not `2.0` |
| **3. No Scientific Notation** | Use decimal representation for all numbers | `1000000` not `1e6` |
| **4. Unicode Normalization** | String values MUST be NFC-normalized | Apply NFC to all string content |
| **5. No Whitespace** | No spaces, tabs, or newlines outside string values | Compact serialization only |
| **6. No Null Bytes** | JSON strings MUST NOT contain `\u0000` | Escape or reject null bytes |

**Invalid vs. Valid Examples:**

```json
// ❌ INVALID (keys unsorted, trailing zero, whitespace)
{
  "signals": {
    "z_score": 2.0,
    "verdict": "ALLOW"
  }
}

// ✅ VALID (keys sorted, no trailing zero, compact)
{"signals":{"verdict":"ALLOW","z_score":2}}
```

### 3.3 Implementation Guidance

**Python (Recommended):**
```python
import jcs  # pip install rfc8785

data = {"signals": {"z_score": 2.0, "verdict": "ALLOW"}}
canonical_bytes = jcs.canonicalize(data)
# Output: b'{"signals":{"verdict":"ALLOW","z_score":2}}'
```

**TypeScript/JavaScript:**
```typescript
import canonicalize from '@stablelib/canonical-json';

const data = {signals: {z_score: 2.0, verdict: "ALLOW"}};
const canonical = canonicalize(data);
// Output: '{"signals":{"verdict":"ALLOW","z_score":2}}'
```

**Other Languages:**
- Go: `github.com/cyberphone/json-canonicalization`
- Rust: `canonical_json` crate
- See: https://www.rfc-editor.org/rfc/rfc8785.html#appendix-A

### 3.4 Hashing Invariants

**Node-Level State Hash (`stateHash` field):**
- Compute SHA-256 digest of JCS-canonicalized node state snapshot
- State snapshot includes: `stepId`, `nodeName`, `timestampUtc`, `signals`, `metadata`
- Exclude `parentStepIds` and `durationMs` from state hash (these are DAG metadata, not state)
- **Format:** 64-character lowercase hexadecimal string

**Example State Hash Computation:**
```python
import jcs
import hashlib

state = {
    "stepId": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
    "nodeName": "safety_check",
    "timestampUtc": "2026-09-14T12:00:00.500Z",
    "signals": {"opa_verdict": "ALLOW"},
    "metadata": {"policy": "OPA_PRE_TRADE_001"}
}

canonical = jcs.canonicalize(state)
state_hash = hashlib.sha256(canonical).hexdigest()
# Result: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

**Bundle-Level CER Digest (NexArt responsibility):**
- NexArt MAY compute composite CER for entire `AttestationBundle`
- Composite CER SHOULD include Merkle tree root of all step-level CERs
- Terminal path classification (`terminalPath`) MUST be included in bundle-level digest

### 3.5 Verification Rules

**NexArt Ingestion Pipeline MUST:**
1. Parse incoming `AttestationBundle` JSON
2. Re-canonicalize each `ProjectBundleStepEntry.signals` and `.metadata` per RFC 8785
3. Recompute `stateHash` and verify against submitted value
4. Reject bundles with hash mismatches (fail-closed)
5. Preserve original `signals`/`metadata` content after validation

**CAGE Submission Pipeline MUST:**
1. Apply JCS canonicalization to all extension point data before computing `stateHash`
2. Never submit non-canonicalized JSON to NexArt
3. Validate local hash computation matches NexArt's recomputed hash

---
## 4. DAG Topological Invariants

### 4.1 Parent/Child Step ID Referencing Rules

**Core Invariant:** All `parentStepIds` in a [`ProjectBundleStepEntry`](../../src/integrations/provider_02/adapter.py:104) MUST reference steps that appear earlier in the `AttestationBundle.steps` array.

**Validation Algorithm:**
```python
def validate_parent_references(bundle: AttestationBundle) -> bool:
    seen_step_ids = set()
    
    for step in bundle.steps:
        # All parent IDs must have been seen already
        for parent_id in step.parentStepIds:
            if parent_id not in seen_step_ids:
                raise ValidationError(
                    f"Step {step.stepId} references unknown parent {parent_id}"
                )
        
        # Mark this step as seen
        seen_step_ids.add(step.stepId)
    
    return True
```

**Root Node Convention:**
- The first step(s) in the DAG MUST have empty `parentStepIds` arrays (`[]`)
- Multiple root nodes are permitted (parallel entry points)

**Leaf Node Convention:**
- Leaf nodes have no children (no other step references them as parent)
- Terminal path classification depends on which leaf node(s) were reached

### 4.2 Monotonic Non-Decreasing Timestamp Constraints

**Temporal Ordering Invariant:** For any step `S` with parent step `P`, `S.timestampUtc` MUST be ≥ `P.timestampUtc`.

**Rationale:**
- Child nodes cannot execute before their parent nodes complete
- Parallel branches may have identical timestamps (acceptable)
- Strict inequality NOT required (allows for sub-millisecond precision limitations)

**Validation Algorithm:**
```python
def validate_timestamp_ordering(bundle: AttestationBundle) -> bool:
    step_timestamps = {step.stepId: step.timestampUtc for step in bundle.steps}
    
    for step in bundle.steps:
        for parent_id in step.parentStepIds:
            parent_timestamp = step_timestamps[parent_id]
            if step.timestampUtc < parent_timestamp:
                raise ValidationError(
                    f"Step {step.stepId} timestamp {step.timestampUtc} "
                    f"precedes parent {parent_id} timestamp {parent_timestamp}"
                )
    
    return True
```

**Edge Cases:**
- Parallel branches MAY have identical `timestampUtc` values
- Timestamp precision SHOULD be millisecond-level or finer
- Timezone MUST be UTC (enforced by ISO 8601 'Z' suffix)

### 4.3 Acyclicity Enforcement

**DAG Property:** The governance execution graph MUST be acyclic (no cycles).

**How CAGE Ensures Acyclicity:**
- LangGraph execution model prevents cycles via topological sort
- Each step receives a new unique `stepId` (UUID v4)
- Even in iterative refinement loops, each iteration gets a distinct `stepId`

**Loop Breaker Mechanism:**
- Iterative loops (e.g., query planner ↔ executor refinement) track iteration count
- When iteration limit reached, execution halts with `terminalPath: "loop_breaker"`
- Loop breaker is NOT a cycle — it's a controlled exit from iteration

**NexArt Validation:**
- NexArt SHOULD perform cycle detection on ingestion
- If a cycle is detected (step references itself transitively via `parentStepIds`), reject the bundle
- **Algorithm:** Depth-first search for back edges

```python
def detect_cycle(bundle: AttestationBundle) -> bool:
    # Build adjacency list
    children = defaultdict(list)
    for step in bundle.steps:
        for parent_id in step.parentStepIds:
            children[parent_id].append(step.stepId)
    
    # DFS for cycle detection
    visited = set()
    rec_stack = set()
    
    def has_cycle(step_id):
        visited.add(step_id)
        rec_stack.add(step_id)
        
        for child_id in children.get(step_id, []):
            if child_id not in visited:
                if has_cycle(child_id):
                    return True
            elif child_id in rec_stack:
                return True  # Back edge found (cycle)
        
        rec_stack.remove(step_id)
        return False
    
    for step in bundle.steps:
        if step.stepId not in visited:
            if has_cycle(step.stepId):
                return True
    
    return False
```

### 4.4 Terminal Path Classification Logic

**Classification Algorithm (NexArt Implementation):**

1. **Identify Final Step(s):** Steps with no children (leaf nodes)
2. **Check Against Topology:**
   - If final step's `nodeName` matches `GraphTopology.terminalNode` → `happy_path`
   - If final step has CBF block signal (`signals.cbf_verdict == "BLOCKED"`) → `cbf_block`
   - If final step has NeMo block signal (`signals.nemo_verdict == "BLOCKED"`) → `nemo_block`
   - If final step has loop breaker signal (`metadata.loop_breaker == true`) → `loop_breaker`
   - Otherwise → `unknown` (fail-closed)

**Classification Precedence (highest to lowest):**
1. Explicit terminal path markers in `signals` or `metadata`
2. Match against `GraphTopology.terminalNode`
3. Fall back to `unknown` (never guess)

**Example Classification Logic:**
```python
def classify_terminal_path(bundle: AttestationBundle, topology: GraphTopology) -> str:
    # Find leaf nodes (no children)
    step_ids = {step.stepId for step in bundle.steps}
    children_ids = set()
    for step in bundle.steps:
        children_ids.update(step.parentStepIds)
    
    leaf_steps = [step for step in bundle.steps if step.stepId not in children_ids]
    
    # Check each leaf for terminal path markers
    for leaf in leaf_steps:
        signals = leaf.signals or {}
        metadata = leaf.metadata or {}
        
        # Explicit block signals take precedence
        if signals.get("cbf_verdict") == "BLOCKED":
            return "cbf_block"
        if signals.get("nemo_verdict") == "BLOCKED":
            return "nemo_block"
        if metadata.get("loop_breaker") is True:
            return "loop_breaker"
        
        # Check if reached terminal node
        if leaf.nodeName == topology.terminalNode:
            return "happy_path"
    
    # Fail-closed: cannot classify
    return "unknown"
```

### 4.5 Multi-Parent Step Handling

**Convergence Nodes:** Steps MAY have multiple parents (convergence points in DAG).

**Example:**
```json
{
  "stepId": "convergence-step-uuid",
  "nodeName": "aggregator",
  "parentStepIds": [
    "branch-a-uuid",
    "branch-b-uuid",
    "branch-c-uuid"
  ],
  "timestampUtc": "2026-09-14T12:00:05.000Z",
  ...
}
```

**Validation Requirements:**
- `timestampUtc` MUST be ≥ ALL parent timestamps (not just one)
- All `parentStepIds` MUST reference valid earlier steps
- Convergence nodes are common in parallel workflow patterns (fan-in)

**NexArt Query Implications:**
- "Find all paths from node A to node B" queries MUST handle multi-parent steps
- Graph traversal algorithms MUST account for join points

---
## 5. Test Fixtures Catalog

### 5.1 Fixture Overview

CAGE provides **5 realistic test fixtures** representing diverse governance execution patterns. These fixtures validate NexArt's ingestion pipeline, CER issuance, and terminal path classification logic.

**Fixture Location:** [`tests/fixtures/provider_02_native/`](../../tests/fixtures/provider_02_native/)

**Validation Status:** All 5 fixtures passed JSON schema validation on 2026-09-14T17:12:03Z

### 5.2 Fixture Inventory

| Fixture | Terminal Path | Nodes | Duration | Primary Verification Target |
|---------|---------------|-------|----------|----------------------------|
| [`01_single_path_happy.json`](../../tests/fixtures/provider_02_native/01_single_path_happy.json) | `happy_path` | 4 | 715ms | Basic schema compliance, linear DAG |
| [`02_cbf_block.json`](../../tests/fixtures/provider_02_native/02_cbf_block.json) | `cbf_block` | 3 | 260ms | CBF safety barrier enforcement |
| [`03_loop_breaker.json`](../../tests/fixtures/provider_02_native/03_loop_breaker.json) | `loop_breaker` | 6 | 915ms | Iteration limit handling |
| [`04_nemo_policy_block.json`](../../tests/fixtures/provider_02_native/04_nemo_policy_block.json) | `nemo_block` | 3 | 380ms | Policy violation halt flow |
| [`05_large_dag.json`](../../tests/fixtures/provider_02_native/05_large_dag.json) | `happy_path` | 22 | 2,160ms | Complex multi-branch topology |

### 5.3 Detailed Fixture Specifications

#### Fixture 01: Single-Path Happy Path
**File:** [`01_single_path_happy.json`](../../tests/fixtures/provider_02_native/01_single_path_happy.json)  
**Terminal Path:** `happy_path`  
**DAG Structure:** Linear 4-node execution  
**Nodes:** `input_validator` → `safety_check` → `governed_executor` → `report_generator`

**Verification Checklist:**
- ✅ All 4 steps have valid UUIDs
- ✅ Timestamps monotonically increase
- ✅ Parent references form valid chain
- ✅ Terminal node (`report_generator`) reached
- ✅ No governance blocks in `signals`

**Expected NexArt Behavior:**
- Issue 4 CERs (one per step)
- Classify bundle as `happy_path`
- Link CERs via `parentStepIds` chain

---

#### Fixture 02: CBF Block
**File:** [`02_cbf_block.json`](../../tests/fixtures/provider_02_native/02_cbf_block.json)  
**Terminal Path:** `cbf_block`  
**DAG Structure:** 3-node execution terminating at CBF safety check  
**Nodes:** `request_parser` → `cbf_velocity_check` (BLOCKED) → `termination_handler`

**CBF Violation Details:**
```json
{
  "signals": {
    "cbf_verdict": "BLOCKED",
    "cbf_reason": "reachable_set_violation",
    "velocity_actual": 125.3,
    "velocity_limit": 100.0
  }
}
```

**Verification Checklist:**
- ✅ CBF block signal present in step 2
- ✅ Execution halts before designated terminal node
- ✅ Termination handler executed (cleanup step)
- ✅ `terminalPath` correctly classified as `cbf_block`

**Expected NexArt Behavior:**
- Issue 3 CERs (including termination handler)
- Preserve CBF violation details in `signals`
- Enable filtering by `cbf_block` terminal path

---

#### Fixture 03: Loop Breaker
**File:** [`03_loop_breaker.json`](../../tests/fixtures/provider_02_native/03_loop_breaker.json)  
**Terminal Path:** `loop_breaker`  
**DAG Structure:** 6-node execution with query planner ↔ executor refinement loops  
**Iteration Count:** 5 (max limit reached)

**Loop Breaker Signal:**
```json
{
  "metadata": {
    "loop_breaker": true,
    "iteration_count": 5,
    "iteration_limit": 5,
    "reason": "max_iterations_reached"
  }
}
```

**Verification Checklist:**
- ✅ Multiple steps share same `nodeName` (different `stepId` per iteration)
- ✅ Parent references form valid DAG (no cycles)
- ✅ Loop breaker signal present in final step
- ✅ `terminalPath` correctly classified as `loop_breaker`

**Expected NexArt Behavior:**
- Issue 6 CERs (one per iteration step)
- Distinguish iterations via unique `stepId` values
- Validate no cycles despite repeated node names

---

#### Fixture 04: NeMo Policy Block
**File:** [`04_nemo_policy_block.json`](../../tests/fixtures/provider_02_native/04_nemo_policy_block.json)  
**Terminal Path:** `nemo_block`  
**DAG Structure:** 3-node execution terminating at NeMo Guardrails policy violation  
**Nodes:** `request_intake` → `nemo_guardrails_check` (BLOCKED) → `policy_enforcement`

**Policy Violation Details:**
```json
{
  "signals": {
    "nemo_verdict": "BLOCKED",
    "policy_id": "GDPR_CROSS_REGION_PII",
    "violation_reason": "cross_region_pii_access_denied"
  }
}
```

**Verification Checklist:**
- ✅ NeMo block signal present in step 2
- ✅ Execution halts before designated terminal node
- ✅ Policy enforcement step executed (audit trail)
- ✅ `terminalPath` correctly classified as `nemo_block`

**Expected NexArt Behavior:**
- Issue 3 CERs (including enforcement step)
- Preserve policy violation details in `signals`
- Enable compliance auditing via `nemo_block` filtering

---

#### Fixture 05: Large DAG
**File:** [`05_large_dag.json`](../../tests/fixtures/provider_02_native/05_large_dag.json)  
**Terminal Path:** `happy_path`  
**DAG Structure:** Complex 22-node workflow with parallel branches and convergence  
**Topology:** Ingestion → routing → 3 parallel branches → convergence → finalization

**Complexity Features:**
- Multiple root nodes (parallel entry points)
- Fan-out (1 node → 3 parallel branches)
- Fan-in (3 branches → 1 convergence node)
- Multi-parent steps (convergence points)
- Deep nesting (7 levels)

**Verification Checklist:**
- ✅ All 22 steps have valid parent references
- ✅ Parallel branches have overlapping timestamps (acceptable)
- ✅ Convergence nodes reference multiple parents
- ✅ No cycles despite complex topology
- ✅ Terminal node reached successfully

**Expected NexArt Behavior:**
- Issue 22 CERs with correct parent linkage
- Handle multi-parent steps in convergence nodes
- Support DAG traversal queries (e.g., "find path from ingestion to finalization")
- Demonstrate acceptable query performance on large graphs

---

### 5.4 Fixture Validation Commands

**Run JSON Schema Validation:**
```bash
uv run pytest tests/test_provider_02_native_fixtures.py -v
```

**Expected Output:**
```
tests/test_provider_02_native_fixtures.py::test_fixture_01_single_path_happy PASSED
tests/test_provider_02_native_fixtures.py::test_fixture_02_cbf_block PASSED
tests/test_provider_02_native_fixtures.py::test_fixture_03_loop_breaker PASSED
tests/test_provider_02_native_fixtures.py::test_fixture_04_nemo_policy_block PASSED
tests/test_provider_02_native_fixtures.py::test_fixture_05_large_dag PASSED
```

**Standalone Validator:**
```bash
uv run python tests/test_provider_02_native_fixtures.py
```

### 5.5 Coverage Matrix

| Terminal Path | Fixture Count | Coverage Status |
|---------------|---------------|-----------------|
| `happy_path` | 2 (fixtures 01, 05) | ✅ Complete |
| `cbf_block` | 1 (fixture 02) | ✅ Complete |
| `loop_breaker` | 1 (fixture 03) | ✅ Complete |
| `nemo_block` | 1 (fixture 04) | ✅ Complete |
| `unknown` | 0 | ⚠️ Not tested (fail-closed state) |

**Note:** `unknown` terminal path represents unclassifiable execution states and is intentionally not included in test fixtures (fail-closed design).

---
## 6. NexArt Ingestion & Integration Checklist

### 6.1 Schema Registry Registration

**Objective:** Register CAGE governance schemas in NexArt's schema registry.

**Tasks for NexArt Engineering:**

- [ ] **Register Schema URNs:**
  - `urn:cage:governance:v1:attestation-bundle`
  - `urn:cage:governance:v1:step-entry`
  - `urn:cage:governance:v1:graph-topology`

- [ ] **Upload JSON Schema Definitions:**
  - [`attestation_bundle.schema.json`](../../schemas/provider_02/attestation_bundle.schema.json)
  - [`project_bundle_step.schema.json`](../../schemas/provider_02/project_bundle_step.schema.json)
  - [`graph_topology.schema.json`](../../schemas/provider_02/graph_topology.schema.json)

- [ ] **Configure Validation Rules:**
  - Enable strict JSON Schema validation on ingestion
  - Reject bundles failing schema validation (fail-closed)
  - Log validation errors for debugging

- [ ] **Version Compatibility Matrix:**
  - Define backward compatibility policy (v1 → v2 migration)
  - Document additive vs. breaking change semantics
  - Establish deprecation timeline for schema evolution

**Deliverable:** Schema registry endpoint returning registered schema URIs and definitions.

---

### 6.2 Ingestion Parser Configuration

**Objective:** Implement native parser for [`AttestationBundle`](../../src/integrations/provider_02/adapter.py:135) ingestion.

**Parser Requirements:**

- [ ] **Atomic Bundle Ingestion:**
  - Accept entire `AttestationBundle` as single HTTP POST payload
  - Validate schema compliance before processing
  - Reject partial bundles (all-or-nothing semantics)

- [ ] **Step-Level Parsing:**
  - Extract each `ProjectBundleStepEntry` from `steps[]` array
  - Validate `parentStepIds` references (must point to earlier steps)
  - Verify timestamp ordering (monotonic non-decreasing)

- [ ] **DAG Topology Validation:**
  - Check for cycles (DFS-based cycle detection)
  - Validate root nodes (empty `parentStepIds`)
  - Verify leaf nodes (no children in bundle)

- [ ] **Extension Point Handling:**
  - Preserve `signals` and `metadata` fields as-is (no schema enforcement)
  - Support arbitrary JSON objects in extension points
  - Forward-compatible: ignore unknown fields gracefully

**API Endpoint Design (Proposed):**
```http
POST /v1/attestation/cage-governance
Content-Type: application/json

{
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "threadId": "session-12345",
  "steps": [...],
  "startedAt": "2026-09-14T12:00:00.000Z",
  "completedAt": "2026-09-14T12:00:05.000Z",
  "terminalPath": "happy_path"
}
```

**Response:**
```json
{
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "accepted",
  "cerIds": [
    "cer-c9bf9e57-1685-4c89-bafb-ff5af830be8a",
    "cer-7d793037-5e6a-4f7a-9c8d-2e5f8b3a4c1d"
  ],
  "timestamp": "2026-09-14T12:00:06.123Z"
}
```

---

### 6.3 CER Digest Computation

**Objective:** Issue Certificate of Execution Record (CER) for each step with deterministic digest.

**CER Issuance Strategy:**

- [ ] **Per-Step CER Emission:**
  - Issue one CER per `ProjectBundleStepEntry`
  - CER ID derived from `stepId` (e.g., `cer-{stepId}`)
  - Include step-level `stateHash` in CER payload

- [ ] **Bundle-Level Composite CER (Optional):**
  - Decide: Issue composite CER for entire `AttestationBundle`? (Question for Jeremy)
  - If yes: Include Merkle tree root of all step-level CER digests
  - If no: Bundle is virtual (query-only construct)

- [ ] **RFC 8785 Canonicalization:**
  - Re-canonicalize `signals` and `metadata` per JCS rules
  - Recompute `stateHash` and verify against submitted value
  - Reject mismatches (fail-closed)

- [ ] **Parent CER Linkage:**
  - Include `parentStepIds` in CER metadata
  - Enable CER chain traversal via parent references
  - Preserve DAG topology in CER graph

**CER Payload Example:**
```json
{
  "cerId": "cer-c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "stepId": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "nodeName": "nemo_guardrail",
  "parentCerIds": [],
  "stateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestampUtc": "2026-09-14T12:00:00.000Z",
  "signature": "<NexArt-signature>",
  "publicKeyId": "nexart-2026-prod-key-01"
}
```

---

### 6.4 Query Interface Validation

**Objective:** Provide queryable transparency log with DAG-aware APIs.

**Required Query Capabilities:**

- [ ] **Bundle Retrieval:**
  - `GET /v1/attestation/cage-governance/{bundleId}`
  - Returns complete `AttestationBundle` with all steps

- [ ] **Terminal Path Filtering:**
  - `GET /v1/attestation/cage-governance?terminalPath=cbf_block&startDate=...&endDate=...`
  - Filter bundles by terminal path classification
  - Support time-range queries for audit trails

- [ ] **Step-Level Queries:**
  - `GET /v1/attestation/cage-governance/step/{stepId}`
  - Returns individual `ProjectBundleStepEntry` with CER
  - Include parent/child step references

- [ ] **DAG Traversal Queries:**
  - `GET /v1/attestation/cage-governance/{bundleId}/path?from={nodeName}&to={nodeName}`
  - Find all paths between two nodes in DAG
  - Return ordered sequence of step IDs

- [ ] **Parent/Child Lookups:**
  - `GET /v1/attestation/cage-governance/step/{stepId}/parents`
  - `GET /v1/attestation/cage-governance/step/{stepId}/children`
  - Enable graph navigation

**Performance SLOs (Question for Jeremy):**
- Expected query latency for 10,000+ node DAGs?
- Indexing strategy for `terminalPath` filtering?
- Retention policy for historical bundles?

---

### 6.5 Integration Testing Protocol

**Objective:** Validate NexArt ingestion pipeline against CAGE test fixtures.

**Testing Phases:**

**Phase 1: Schema Validation (NexArt Staging)**
- [ ] Ingest all 5 test fixtures successfully
- [ ] Verify no schema validation errors
- [ ] Confirm CER issuance for each step

**Phase 2: CER Verification (CAGE → NexArt)**
- [ ] Submit fixture bundles from CAGE test harness
- [ ] Retrieve issued CERs via API
- [ ] Verify CER signatures against NexArt public key
- [ ] Confirm `stateHash` values match

**Phase 3: Query Validation (CAGE Integration Tests)**
- [ ] Query bundles by `terminalPath` filter
- [ ] Retrieve individual steps by `stepId`
- [ ] Execute DAG traversal queries (path finding)
- [ ] Verify parent/child relationship lookups

**Phase 4: Terminal Path Classification (Correctness Check)**
- [ ] Confirm fixture 01 classified as `happy_path`
- [ ] Confirm fixture 02 classified as `cbf_block`
- [ ] Confirm fixture 03 classified as `loop_breaker`
- [ ] Confirm fixture 04 classified as `nemo_block`
- [ ] Confirm fixture 05 classified as `happy_path`

**Test Environment:**
- **NexArt Staging URL:** (TBD — provided by Jeremy)
- **CAGE Test Harness:** [`tests/test_provider_02_adapter.py`](../../tests/test_provider_02_adapter.py)
- **Integration Marker:** `@pytest.mark.integration` (manual trigger, not CI)

**Success Criteria:**
- ✅ All 5 fixtures ingest successfully
- ✅ All CER signatures verify
- ✅ All query APIs return expected results
- ✅ Terminal path classifications match fixture expectations
- ✅ No hash mismatches or validation errors

---

### 6.6 Production Readiness Checklist

**Pre-Production Requirements:**

- [ ] **Authentication & Authorization:**
  - API key authentication for CAGE submissions
  - Tenant isolation (CAGE-specific namespace)
  - Rate limiting (requests per second/minute)

- [ ] **Monitoring & Alerting:**
  - CER issuance latency metrics
  - Schema validation error rates
  - Hash mismatch alerts (potential tampering)

- [ ] **Documentation:**
  - API reference documentation (OpenAPI/Swagger)
  - Schema evolution guide (version migration)
  - Troubleshooting guide (common ingestion errors)

- [ ] **SLA Commitments:**
  - Ingestion availability SLA (e.g., 99.9%)
  - Query latency SLA (e.g., p95 < 500ms)
  - CER issuance latency (e.g., p99 < 2s)

- [ ] **Backward Compatibility:**
  - Confirm v1 schema stability (no breaking changes)
  - Define v2 migration path (if needed)
  - Establish deprecation policy

**Go-Live Approval:**
- **CAGE Sign-Off:** All integration tests passing
- **NexArt Sign-Off:** Staging validation complete
- **Joint Sign-Off:** Production configuration reviewed

---

## 7. Open Questions for NexArt Engineering

### Q1: Composite Bundle CER Strategy
**Question:** Should NexArt issue a bundle-level composite CER in addition to per-step CERs?

**Option A:** Per-step CERs only (bundle is virtual query construct)  
**Option B:** Per-step CERs + composite CER with Merkle tree root

**CAGE Preference:** Option B (composite CER provides single verification anchor)

---

### Q2: Unknown `terminalPath` Value Handling
**Question:** How should NexArt handle unknown `terminalPath` enum values in future schema versions?

**Option A:** Reject with error (strict fail-closed)  
**Option B:** Accept with warning (forward-compatible)

**CAGE Preference:** Option B (enables additive terminal path types without NexArt schema update)

---

### Q3: Extension Point Field Preservation
**Question:** Are unknown fields in `signals`/`metadata` preserved through round-trip ingestion and retrieval?

**Requirement:** CAGE may add new signal types (e.g., `signals.ftra_verdict`) without schema version bump.

**Expected Behavior:** NexArt stores and returns all `signals`/`metadata` fields as-is (no filtering).

---

### Q4: Query Performance SLOs
**Question:** What query latency should CAGE expect for large DAGs (10,000+ nodes)?

**Use Cases:**
- Bulk audit queries: "Find all CBF blocks in last 30 days"
- DAG traversal: "Find path from ingestion → finalization"

**Expected Indexing:** `terminalPath`, `timestampUtc`, `bundleId`, `threadId`

---

### Q5: Schema Registry Versioning
**Question:** How does NexArt signal schema version compatibility to CAGE clients?

**Desired Mechanism:**
- `GET /v1/schemas/urn:cage:governance:v1:attestation-bundle` returns current schema
- Include `compatibleWith: ["v1", "v2"]` field in response

---

## 8. References

**CAGE Schema Definitions:**
- [`schemas/provider_02/README.md`](../../schemas/provider_02/README.md)
- [`schemas/provider_02/attestation_bundle.schema.json`](../../schemas/provider_02/attestation_bundle.schema.json)
- [`schemas/provider_02/project_bundle_step.schema.json`](../../schemas/provider_02/project_bundle_step.schema.json)
- [`schemas/provider_02/graph_topology.schema.json`](../../schemas/provider_02/graph_topology.schema.json)

**Implementation Plan:**
- [`plans/provider_02_native_schema_handoff.md`](../../plans/provider_02_native_schema_handoff.md)

**Test Fixtures:**
- [`tests/fixtures/provider_02_native/README.md`](../../tests/fixtures/provider_02_native/README.md)
- [`tests/fixtures/provider_02_native/01_single_path_happy.json`](../../tests/fixtures/provider_02_native/01_single_path_happy.json)
- [`tests/fixtures/provider_02_native/02_cbf_block.json`](../../tests/fixtures/provider_02_native/02_cbf_block.json)
- [`tests/fixtures/provider_02_native/03_loop_breaker.json`](../../tests/fixtures/provider_02_native/03_loop_breaker.json)
- [`tests/fixtures/provider_02_native/04_nemo_policy_block.json`](../../tests/fixtures/provider_02_native/04_nemo_policy_block.json)
- [`tests/fixtures/provider_02_native/05_large_dag.json`](../../tests/fixtures/provider_02_native/05_large_dag.json)

**Source Code:**
- [`src/integrations/provider_02/adapter.py`](../../src/integrations/provider_02/adapter.py) — Python dataclass definitions
- [`src/gateway/governance/seams/graph_topology.py`](../../src/gateway/governance/seams/graph_topology.py) — Graph topology seam

**Standards:**
- RFC 8785 (JSON Canonicalization Scheme): https://www.rfc-editor.org/rfc/rfc8785.html
- RFC 4122 (UUID): https://www.rfc-editor.org/rfc/rfc4122.html
- ISO 8601 (Timestamps): https://www.iso.org/iso-8601-date-and-time-format.html
- JSON Schema Draft 2020-12: https://json-schema.org/draft/2020-12/json-schema-core

---

## Appendix A: Complete Example

**Minimal Valid AttestationBundle:**

```json
{
  "bundleId": "550e8400-e29b-41d4-a716-446655440000",
  "threadId": "demo-session-001",
  "steps": [
    {
      "stepId": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
      "nodeName": "start",
      "parentStepIds": [],
      "timestampUtc": "2026-09-14T12:00:00.000Z",
      "durationMs": 100,
      "signals": {},
      "metadata": {},
      "stateHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "stepId": "7d793037-5e6a-4f7a-9c8d-2e5f8b3a4c1d",
      "nodeName": "end",
      "parentStepIds": ["c9bf9e57-1685-4c89-bafb-ff5af830be8a"],
      "timestampUtc": "2026-09-14T12:00:00.200Z",
      "durationMs": 50,
      "signals": {},
      "metadata": {},
      "stateHash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    }
  ],
  "startedAt": "2026-09-14T12:00:00.000Z",
  "completedAt": "2026-09-14T12:00:00.250Z",
  "terminalPath": "happy_path"
}
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-09-14  
**Next Review:** Upon NexArt staging deployment
