# Provider 02 Native Schema Support — Implementation Plan

**Date:** 2026-09-14  
**Decision:** Accept Jeremy Bouedo's offer for NexArt native CAGE governance schema support (Option 2A)  
**Status:** Schema extraction and documentation phase  
**Timeline:** 2–3 weeks (NexArt engineering) + 1 week (CAGE integration testing)

---

## Strategic Decision Summary

**Chosen:** Option 2A — Native Schema Support  
**Rejected:** Option 2B — Tactical hash chaining via `parentCertificateHashes[]`

**Rationale:**
- Eliminates need for CAGE to build intermediate `cer.ai.execution.v1` composite schemas
- Prevents technical debt from conforming to generic execution tracker formats
- CAGE's canonical governance schemas remain authoritative
- NexArt becomes a native governance DAG recorder, not a wrapped execution tracker
- No migration cost later (schemas already correct)

**Jeremy's offer (Sep 9, 12:19 PM):**
> *"If you send us the stabilized CAGE governance/graph schema, we're happy to look at supporting that natively in NexArt rather than having you permanently shape CAGE around an intermediate NexArt composite model."*

---

## Phase 1: Schema Extraction & Documentation (CAGE — 3 days)

### 1.1 Core Governance Schemas to Extract

| Schema | Location | Purpose |
|---|---|---|
| [`AttestationBundle`](../src/integrations/provider_02/adapter.py:135) | `src/integrations/provider_02/adapter.py:135` | Top-level governance bundle wrapping entire DAG traversal |
| [`ProjectBundleStepEntry`](../src/integrations/provider_02/adapter.py:104) | `src/integrations/provider_02/adapter.py:104` | Individual node execution snapshot with DAG edges |
| [`GraphTopology`](../src/governed_financial_advisor/graph/graph.py) | `src/governed_financial_advisor/graph/graph.py` | DAG structure definition (nodes, edges, entry/exit points) |

### 1.2 Schema Documentation Requirements

For each schema, produce:

#### JSON Schema Definition
- TypeScript interfaces or JSON Schema format
- All required vs. optional fields
- Field-level descriptions
- Example instances

#### Semantic Contracts
- Invariants (e.g., `parent_step_ids` must reference earlier steps)
- DAG properties (acyclicity, reachability)
- Terminal path classification semantics
- Timing/ordering constraints

#### Extension Points
- Which fields accept arbitrary metadata
- Future additive fields (versioning strategy)
- Domain-specific signal schemas

### 1.3 Deliverables

Create in `docs/partners/nexart/`:

1. **`NATIVE_SCHEMA_SPEC.md`**
   - Comprehensive schema documentation
   - Usage examples
   - Invariant catalog
   - Extension point registry

2. **`schemas/cage_governance_v1.json`** (or TypeScript)
   - Machine-readable schema definitions
   - JSON Schema or TypeScript type definitions
   - Validation rules

3. **`provider_02_schema_handoff_package.md`**
   - Executive summary for Jeremy
   - Schema overview
   - Integration requirements
   - Test fixtures

---

## Phase 2: Schema Handoff to NexArt (CAGE → NexArt — 1 day)

### 2.1 Package Contents

Send to Jeremy:
- Schema specification document
- JSON Schema / TypeScript definitions
- 3–5 realistic test fixtures (real governance DAG snapshots)
- Expected CER structure for each fixture

### 2.2 Coordination Topics

#### Versioning Strategy
**Question for Jeremy:**
- Propose: `urn:cage:governance:v1` as schema URI
- Breaking vs. additive change signaling
- Deprecation policy for schema evolution

#### Extension Guarantees
**Question for Jeremy:**
- Can CAGE add fields to `metadata` / `signals` without schema version bump?
- Are unknown fields preserved by NexArt ingestion?
- Forward compatibility strategy

#### Ingestion Endpoint
**Question for Jeremy:**
- New endpoint (`/v1/ingest/cage-governance`) or existing Project Bundle API?
- Authentication / tenant isolation
- Rate limits / batch size constraints

---

## Phase 3: NexArt Implementation (NexArt — 2–3 weeks)

**NexArt responsibilities:**

### 3.1 Schema Registry
- Register `urn:cage:governance:v1` schema
- Schema validation on ingestion
- Version compatibility matrix

### 3.2 Ingestion Pipeline
- Native DAG parser for [`AttestationBundle`](../src/integrations/provider_02/adapter.py:135)
- Node-level CER issuance for [`ProjectBundleStepEntry`](../src/integrations/provider_02/adapter.py:104)
- Edge preservation via `parent_step_ids`
- Terminal path classification storage

### 3.3 Query Interface
- DAG traversal queries (find path from node A to node B)
- Terminal path filtering (happy_path, cbf_block, etc.)
- Parent/child relationship lookups
- Timestamp-based slicing

### 3.4 Transparency Log
- Per-node CERs linkable via `parent_step_ids`
- Bundle-level composite CER (optional)
- Merkle tree construction over DAG

---

## Phase 4: CAGE Integration Testing (CAGE — 1 week)

### 4.1 Test Scenarios

#### Scenario 1: Single-Path Happy Path
**DAG:** `start → node_a → node_b → end` (4 nodes, linear)  
**Expected:** 4 CERs, `terminalPath: "happy_path"`, all nodes linked sequentially

#### Scenario 2: Multi-Path with CBF Block
**DAG:** Finance demo with CBF rejection at `risk_assessment`  
**Expected:** CERs up to block point, `terminalPath: "cbf_block"`, traversal stops

#### Scenario 3: Loop Breaker
**DAG:** Iterative refinement loop exited via counter  
**Expected:** Multiple CERs for same node (different step IDs), `terminalPath: "loop_breaker"`

#### Scenario 4: NeMo Block
**DAG:** Policy violation at `compliance_check`  
**Expected:** `terminalPath: "nemo_block"`, downstream nodes not executed

#### Scenario 5: Large DAG (20+ nodes)
**DAG:** Full healthcare clinical agent workflow  
**Expected:** All nodes ingested, parent edges preserved, query performance acceptable

### 4.2 Verification Checklist

For each scenario:
- ✅ All expected CERs issued
- ✅ Parent/child relationships correct
- ✅ Terminal path classification accurate
- ✅ Timestamp ordering preserved
- ✅ Metadata / signals intact
- ✅ CER signatures verify against NexArt public keys

### 4.3 Integration Environment

**NexArt staging endpoint:**
- Provided by Jeremy after schema implementation
- CAGE configures `PROVIDER_02_ENDPOINT` to staging URL
- Tenant ID for test isolation

**CAGE test harness:**
- Extend existing [`tests/test_provider_02_adapter.py`](../tests/test_provider_02_adapter.py)
- Add integration marker: `@pytest.mark.integration`
- Run against live NexArt staging (not in CI, manual trigger)

---

## Phase 5: Production Readiness (CAGE — 2 days)

### 5.1 Configuration Updates

Update [`src/integrations/provider_02/README.md`](../src/integrations/provider_02/README.md):
- Document native schema support
- Provide schema URI reference
- Update example usage

### 5.2 Backward Compatibility

**Question to resolve:**
- Does NexArt maintain backward compatibility with existing Project Bundle API?
- If yes, CAGE can support both schemas simultaneously
- If no, document migration path for adopters

### 5.3 Documentation

Create:
- **Migration guide** (if applicable)
- **Schema reference card** (quick lookup for developers)
- **Troubleshooting guide** (common ingestion errors)

---

## Open Questions for Jeremy

### Q1: `terminalPath: "unknown"` Handling
**Context:** CAGE currently fails closed (raises `ValueError`) if traversal cannot be classified.  
**Question:** Should CAGE emit `terminalPath: "unknown"` for unclassifiable cases, or is fail-closed correct?

### Q2: Composite Bundle CER
**Context:** [`AttestationBundle`](../src/integrations/provider_02/adapter.py:135) wraps entire DAG traversal.  
**Question:** Should NexArt issue:
- (A) One CER per node + one composite CER for the bundle, or
- (B) Only per-node CERs (bundle is virtual)?

### Q3: Schema Evolution
**Context:** CAGE may add new terminal path types or node signal fields.  
**Question:**
- Are unknown `terminalPath` values accepted (with warning)?
- Are unknown fields in `signals` / `metadata` preserved?

### Q4: Query Latency SLOs
**Context:** CAGE may query "find all CBF blocks in last 24h" for metrics.  
**Question:** What query latency should CAGE expect for 10k+ node DAGs?

---

## Success Criteria

### Phase 1 Complete When:
✅ Schema spec document written and reviewed  
✅ JSON Schema / TypeScript definitions generated  
✅ Test fixtures prepared (3–5 realistic DAGs)  
✅ Handoff package sent to Jeremy

### Phase 3 Complete When:
✅ NexArt staging endpoint available  
✅ Test fixture ingestion succeeds  
✅ CERs issued for all nodes  
✅ Parent/child queries return correct results

### Phase 4 Complete When:
✅ All 5 test scenarios pass  
✅ CER signature verification succeeds  
✅ Query performance acceptable  
✅ Jeremy confirms production-ready

### Production Readiness When:
✅ Documentation updated  
✅ Configuration examples provided  
✅ Migration guide written (if needed)  
✅ Integration tests passing consistently

---

## Timeline

| Phase | Owner | Duration | Dependencies |
|---|---|---|---|
| **1. Schema Extraction** | CAGE | 3 days | None |
| **2. Schema Handoff** | CAGE → NexArt | 1 day | Phase 1 complete |
| **3. NexArt Implementation** | NexArt | 2–3 weeks | Phase 2 complete |
| **4. Integration Testing** | CAGE | 1 week | Phase 3 complete |
| **5. Production Readiness** | CAGE | 2 days | Phase 4 complete |

**Total estimated time:** 4–5 weeks from start to production-ready

**Critical path:** NexArt schema implementation (2–3 weeks)

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Schema changes during NexArt implementation | Medium | Freeze CAGE schema after Phase 1; defer additive changes to v2 |
| NexArt timeline extends beyond 3 weeks | Low | CAGE unblocked — reference architecture has no production deadline |
| Unknown field handling differs from expectation | Medium | Clarify in Phase 2 coordination; test in Phase 4 |
| Query performance unacceptable for large DAGs | Medium | Identify early in Phase 4; NexArt can add indexes |

---

## Next Actions (Immediate)

1. **CAGE (Lars):** Begin Phase 1 schema extraction (estimated 3 days)
2. **CAGE (Lars):** Send coordination email to Jeremy with:
   - Confirmation of Option 2A decision
   - Timeline proposal
   - Request for open question responses (Q1–Q4 above)
   - Proposed coordination call after Phase 1 complete
3. **NexArt (Jeremy):** Review timeline and flag any constraints
4. **NexArt (Jeremy):** Answer open questions Q1–Q4

---

## References

- Jeremy's native schema offer: [`docs/meetings/nexart_sep9_prep.md`](../docs/meetings/nexart_sep9_prep.md)
- Existing schemas: [`src/integrations/provider_02/adapter.py`](../src/integrations/provider_02/adapter.py)
- Tactical hash chaining (rejected): [`plans/provider_02_cer_unblocked_work.md`](provider_02_cer_unblocked_work.md)
- Current test suite: [`tests/test_provider_02_adapter.py`](../tests/test_provider_02_adapter.py)
