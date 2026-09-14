# Provider 02 Native Schema Test Fixtures

This directory contains realistic test fixtures for validating Provider 02's native attestation bundle schema ingestion.

## Fixture Inventory

### 1. [`01_single_path_happy.json`](01_single_path_happy.json)
**Terminal Path:** `happy_path`  
**Description:** Linear 4-node execution representing successful end-to-end governance flow.
- **Nodes:** input_validator → safety_check → governed_executor → report_generator
- **Duration:** 715ms
- **Use Case:** Validates basic schema compliance and happy path completion.

### 2. [`02_cbf_block.json`](02_cbf_block.json)
**Terminal Path:** `cbf_block`  
**Description:** Execution terminating at a Control Barrier Function (CBF) safety violation.
- **Nodes:** request_parser → cbf_velocity_check (BLOCKED) → termination_handler
- **Duration:** 260ms
- **Violation:** Velocity limit exceeded (125.3 vs. max 100.0)
- **Use Case:** Validates CBF safety barrier enforcement and premature termination handling.

### 3. [`03_loop_breaker.json`](03_loop_breaker.json)
**Terminal Path:** `loop_breaker`  
**Description:** Iterative refinement cycle hitting iteration limit with graceful resolution.
- **Nodes:** 6-node execution with query_planner ↔ executor refinement loops
- **Duration:** 915ms
- **Iterations:** 5 (max limit reached)
- **Use Case:** Validates loop detection, iteration counting, and breaker enforcement.

### 4. [`04_nemo_policy_block.json`](04_nemo_policy_block.json)
**Terminal Path:** `nemo_block`  
**Description:** Policy violation detected by NeMo Guardrails triggering execution halt.
- **Nodes:** request_intake → nemo_guardrails_check (BLOCKED) → policy_enforcement
- **Duration:** 380ms
- **Violation:** Cross-region PII access denied (GDPR/CCPA compliance)
- **Use Case:** Validates policy engine integration and compliance halt flows.

### 5. [`05_large_dag.json`](05_large_dag.json)
**Terminal Path:** `happy_path`  
**Description:** Complex multi-branch DAG workflow with parallel execution and convergence.
- **Nodes:** 22 nodes including parallel branches and convergence points
- **Duration:** 2,160ms
- **Topology:** Ingestion → routing → 3 parallel branches → convergence → finalization
- **Use Case:** Validates complex graph topology, parallel execution tracking, and multi-parent step resolution.

## Schema Validation

All fixtures are validated against:
- **Primary Schema:** [`schemas/provider_02/attestation_bundle.schema.json`](../../schemas/provider_02/attestation_bundle.schema.json)
- **Referenced Schema:** [`schemas/provider_02/project_bundle_step.schema.json`](../../schemas/provider_02/project_bundle_step.schema.json)

## Running Validation

### Automated Test Suite (pytest)
```bash
uv run pytest tests/test_provider_02_native_fixtures.py -v
```

### Standalone Validator
```bash
uv run python tests/test_provider_02_native_fixtures.py
```

## Test Coverage

| Terminal Path | Fixture | Coverage |
|---------------|---------|----------|
| `happy_path` | 01, 05 | ✓ |
| `cbf_block` | 02 | ✓ |
| `loop_breaker` | 03 | ✓ |
| `nemo_block` | 04 | ✓ |
| `unknown` | — | Not tested |

## Schema Compliance

All fixtures adhere to:
- **UUID v4 Format:** `bundleId`, `stepId` fields
- **ISO 8601 UTC Timestamps:** `startedAt`, `completedAt`, `timestampUtc`
- **SHA-256 State Hashing:** 64-character hex digests in `stateHash`
- **DAG Parent Tracking:** `parentStepIds` arrays maintaining execution topology
- **Signal/Metadata Extension Points:** Domain-specific governance data

## Last Validated
2026-09-14T17:12:03Z — All 5 fixtures passed JSON schema validation.
