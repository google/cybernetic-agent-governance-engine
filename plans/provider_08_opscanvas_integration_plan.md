# Architecture & Implementation Plan: OpsCanvas (`provider_08`) CloudOps Partner Adapter

**Document ID:** PLAN-2026-PROV08-01  
**Status:** DRAFT / PROPOSAL  
**Author:** Lars Ahlfors  
**Target Package:** `src/integrations/provider_08/`  
**Target Seams:** [`src/gateway/governance/seams/normative.py`](../src/gateway/governance/seams/normative.py) · [`src/gateway/governance/defer_queue.py`](../src/gateway/governance/defer_queue.py) · [`src/gateway/governance/ftra/`](../src/gateway/governance/ftra/)  
**Classification:** Reference Architecture Partner Integration  

---

## 1. Executive Summary & Architectural Posture

### 1.1 The Integration Handshake: "Perimeter Meets Estate"
Autonomous AI agents are increasingly authorized to manage infrastructure, modify cloud configurations, trigger deployments, and remediate incidents (CloudOps). In a cybernetic architecture:
* **CAGE (Layer 1 Kernel)** enforces the **admission control perimeter and deterministic physical invariants**: discrete-time Control Barrier Functions (CBFs), compiled OPA Rego ASTs, Forward Trajectory Reachability Analysis (FTRA), asymmetric deferral queues (`PARK` → `HYDRATE` → `REPLAY`), and cryptographic state-mutation seals. CAGE **deliberately avoids building cloud discovery scanners, graph databases, or asset scrapers**.
* **OpsCanvas (`provider_08`)** provides the **dated ground truth of the cloud estate**: confirmed dependency graphs (services, deployments, network topology, ownership, blast radius, cost) assembled from git repos, IaC (Terraform), CI/CD, and cloud APIs, exposed over the **Model Context Protocol (MCP)**.

### 1.2 Architectural Invariants (ADR-008 & Three-Layer Architecture)
1. **Zero Kernel Pollutants (Gate G3):** The CAGE kernel ([`src/gateway/`](../src/gateway/)) is domain-agnostic and vendor-neutral. Code in `src/gateway/` must never import `src/integrations/` directly (enforced via dynamic factory loading).
2. **Fail-Closed by Design:** If the OpsCanvas MCP server is unreachable, times out, or emits malformed data, CAGE policies fail closed (`DENY` or `PARK`), never failing open into unverified mutations.
3. **Over-the-Wire Conformance Mandate:** Conformance tests (`tests/integrations/provider_08/`) must run over physical wire/stdio transports against an authentic OpsCanvas daemon/sandbox. In-memory stubs or synthetic HTTP mocks are prohibited.
4. **Anonymized Code, Specific Prose:** Code paths and package names use `provider_08`. Brand names (OpsCanvas) appear only in prose documentation, READMEs, and meeting memos.

---

## 2. Optimal CloudOps Predicates for CAGE Alignment

Policy engines (OPA Rego) and barrier functions (CBF) evaluate in microseconds and cannot parse unbounded, multi-megabyte raw graph ASTs. To integrate with CAGE, OpsCanvas must expose **deterministic, strongly typed, scalar and boolean predicates** over MCP.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Canonical CloudOps Estate Predicate Schema (MCP Tool: get_cloudops_predicate)          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [1. Blast Radius & Topology]                                                          │
│   • is_load_bearing: bool                     ──► Active production traffic / ingress? │
│   • direct_dependents_count: int              ──► Immediate downstream services        │
│   • transitive_dependency_depth: int          ──► Cascading dependency layers          │
│   • has_failover_redundancy: bool             ──► HA replica / multi-zone standby?     │
│   • active_network_flows_last_1h: int         ──► Real-time packet/request presence    │
│                                                                                        │
│  [2. Governance & Classification]                                                      │
│   • environment_tier: str                     ──► "PRODUCTION" | "STAGING" | "DEV"     │
│   • data_classification_tier: str             ──► "RESTRICTED" | "CONFIDENTIAL" | ...  │
│   • service_criticality_tier: str             ──► "TIER_0" | "TIER_1" | "TIER_2"       │
│   • owner_team_urn: str                       ──► "urn:team:cloud-infrastructure"      │
│                                                                                        │
│  [3. Configuration & Drift]                                                            │
│   • iac_drift_status: str                     ──► "SYNCHRONIZED" | "DRIFT_DETECTED"    │
│   • managed_by_terraform: bool                ──► Declared in IaC codebase?            │
│   • last_iac_commit_hash: str                 ──► Git commit sha of IaC definition     │
│                                                                                        │
│  [4. Reachability & Reversibility]                                                     │
│   • reversibility_tier: str                   ──► Maps to FTRA TerminalClassification  │
│   • estimated_blast_radius_score: float       ──► Normalized [0.0 - 1.0]               │
│   • compensating_rollback_action: str | None  ──► Automated rollback action verb       │
│                                                                                        │
│  [5. Cryptographic Provenance]                                                         │
│   • snapshot_id: str                          ──► Dated estate state identifier        │
│   • snapshot_hash: str                        ──► sha256:... content-addressed root   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Pydantic Wire Contract (`src/integrations/provider_08/schema.py`)

```python
from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class EnvironmentTier(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    SANDBOX = "SANDBOX"


class CriticalityTier(str, Enum):
    TIER_0 = "TIER_0"  # Core routing, auth, primary DB
    TIER_1 = "TIER_1"  # User-facing business microservices
    TIER_2 = "TIER_2"  # Internal async tooling, reporting
    TIER_3 = "TIER_3"  # Non-critical batch jobs


class IaCDriftStatus(str, Enum):
    SYNCHRONIZED = "SYNCHRONIZED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    UNMANAGED = "UNMANAGED"


class CloudOpsReversibility(str, Enum):
    """Direct mapping to FTRA TerminalClassification."""
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    EXTERNALLY_REVERSIBLE = "EXTERNALLY_REVERSIBLE"
    IRREVERSIBLE_TERMINAL = "IRREVERSIBLE_TERMINAL"


class CloudOpsResourcePredicate(BaseModel):
    """Deterministic, typed CloudOps predicate returned by OpsCanvas over MCP."""
    
    resource_urn: str = Field(..., description="Canonical URN (e.g. gcp:cloudrun:us-central1:gateway)")
    resource_type: str = Field(..., description="e.g. compute.instance, run.service, sql.database")
    
    # 1. Topology & Blast Radius
    is_load_bearing: bool = Field(..., description="True if actively serving live production ingress/traffic")
    direct_dependents_count: int = Field(ge=0, description="Number of direct upstream callers")
    transitive_dependency_depth: int = Field(ge=0, description="Max depth of transitive dependency chain")
    has_failover_redundancy: bool = Field(..., description="True if HA/failover replica is active")
    active_network_flows_last_1h: int = Field(ge=0, description="Observed network flows in the last hour")
    
    # 2. Classification & Governance
    environment_tier: EnvironmentTier = Field(...)
    criticality_tier: CriticalityTier = Field(...)
    owner_team_urn: str = Field(..., description="URN of the responsible engineering squad")
    
    # 3. State & Drift
    managed_by_terraform: bool = Field(...)
    iac_drift_status: IaCDriftStatus = Field(...)
    last_iac_commit_hash: str | None = Field(default=None)
    
    # 4. FTRA Reversibility
    reversibility_tier: CloudOpsReversibility = Field(...)
    estimated_blast_radius_score: float = Field(ge=0.0, le=1.0, description="Composite risk metric [0, 1]")
    compensating_rollback_action: str | None = Field(default=None, description="Automated recovery action")
    
    # 5. Provenance Anchor
    snapshot_id: str = Field(..., description="OpsCanvas immutable snapshot ID")
    snapshot_hash: str = Field(..., regex=r"^sha256:[a-f0-9]{64}$", description="Content-addressed root hash")
    evaluated_at_utc: str = Field(..., description="ISO 8601 evaluation timestamp")
```

---

## 3. Four Core Touchpoints with CAGE Architecture

```
                      ┌─────────────────────────────────────────────────────────┐
                      │              Autonomous Agent Proposal                  │
                      │         (e.g., delete_database_replica)                 │
                      └───────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│ CAGE Layer 1: Consequence Gateway & Admission Controller                                      │
│                                                                                               │
│  [Touchpoint 1: FTRA Gate] ──(Fast MCP: <30ms)──► In-Cluster OpsCanvas Sidecar                 │
│         │                                         │ (reversibility_tier, blast_radius_score)   │
│         ▼                                         ▼                                           │
│     Irreversible? ──► [Touchpoint 2: Defer Queue] ──► Redis db=1 (noeviction)                  │
│                               │                                                               │
│                               ▼                                                               │
│                      [Async Context HYDRATE] ──(Deep MCP Query)──► OpsCanvas Estate Graph     │
│                               │                                    (IaC drift, owner, flows)  │
│                               ▼                                                               │
│                      [REPLAY Evaluate Gate] ──► OPA Rego Engine (cloudops_admission.rego)     │
│                               │                                                               │
│                               ▼                                                               │
│  [Touchpoint 3: Normative] ──(validate_fria) ──► Normative Baseline Evaluation                │
│                               │                                                               │
│                               ▼                                                               │
│  [Touchpoint 4: Evidence]  ──(KMS/Ed25519 Seal) ◄──► OpsCanvas Snapshot Hash (sha256:...)     │
│         │                                                                                     │
│         ▼                                                                                     │
│   Immutable OSCAL / ISO 42001 Dual-Proof Package                                              │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Touchpoint 1: FTRA Reachability Grounding (Pre-Flight)
* **Anchor:** [`src/gateway/governance/ftra/graph_analyzer.py`](../src/gateway/governance/ftra/graph_analyzer.py) and [`src/gateway/governance/ftra/models.py`](../src/gateway/governance/ftra/models.py).
* **Mechanism:** When an agent proposes an action graph, FTRA evaluates reversibility:
  * If `is_load_bearing == true` AND `has_failover_redundancy == false`, the action is classified as `IRREVERSIBLE_TERMINAL`.
  * If `reversibility_tier == IRREVERSIBLE_TERMINAL`, FTRA yields `FTRAVerdict.HITL_REQUIRED` or `FTRAVerdict.BLOCKED` based on agent confidence score.
* **Latency Budget:** <30ms P99 via in-cluster sidecar (Unix Domain Socket / stdio) or local cache.

### 3.2 Touchpoint 2: Asymmetric Deferral Hydration (`PARK` → `HYDRATE` → `REPLAY`)
* **Anchor:** [`src/gateway/governance/defer_queue.py`](../src/gateway/governance/defer_queue.py) (`DeferReason.INSUFFICIENT_CONTEXT`, `replay_evaluate()`).
* **Mechanism:**
  1. **PARK:** A high-impact mutation with incomplete context parks in Redis `db=1` (`noeviction`).
  2. **HYDRATE:** Background worker calls OpsCanvas MCP: `get_cloudops_predicate(resource_urn)`.
  3. **REPLAY:** Injects `CloudOpsResourcePredicate` into `opa_input_snapshot` and executes `replay_evaluate()`. If confidence clears threshold (`≥ 0.70`), the action is admitted (`resolution="INJECTED"`).

### 3.3 Touchpoint 3: Normative Provider Protocol Adaptation
* **Anchor:** [`src/gateway/governance/seams/normative.py`](../src/gateway/governance/seams/normative.py) (`NormativeProvider`).
* **Implementation in `provider_08`:**
  * `fetch_baseline(region)`: Fetches expected cloud topology baseline and allowed infrastructure tags for `US_FED`, `EU_ECB`, or `APAC_MAS`.
  * `validate_fria(payload)`: Submits the proposed cloud mutation to OpsCanvas to assert no circular dependencies or network boundary violations are introduced.
  * `submit_evidence(thread_id, evidence_hash)`: Links the local decision hash to OpsCanvas for mutual sealing.

### 3.4 Touchpoint 4: Cryptographic Dual-Evidence Sealing
* **Anchor:** [`src/gateway/governance/evidence/stream.py`](../src/gateway/governance/evidence/stream.py) and [`src/gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py).
* **Mechanism:** CAGE signs the decision via KMS/Ed25519 using RFC 8785 JCS canonicalization. The seal includes:
  ```json
  {
    "cage_decision": "ALLOW",
    "rule_id": "RULE_CLOUDOPS_MUTATION_001",
    "opscanvas_snapshot_id": "snap-2026-09-25T10:30:00Z",
    "opscanvas_snapshot_hash": "sha256:54647b22bfbf7166613c12dabda026a6a21647d85f3e12de3206d8ebfbc066e6"
  }
  ```
  This proves to regulators (NIST SP 800-53 CM-8, ISO 42001 A.8.4) exactly what the cloud estate looked like at the millisecond the decision was rendered.

---

## 4. OPA Rego Policy Specification (`config/policies/cloudops_admission.rego`)

```rego
package cage.cloudops.admission

default allow = false
default defer = false

# Allow automated mutation if resource is non-production OR has failover redundancy and low blast radius
allow {
    input.predicate.environment_tier != "PRODUCTION"
    input.predicate.iac_drift_status == "SYNCHRONIZED"
}

allow {
    input.predicate.environment_tier == "PRODUCTION"
    input.predicate.criticality_tier != "TIER_0"
    input.predicate.has_failover_redundancy == true
    input.predicate.estimated_blast_radius_score < 0.25
    input.predicate.iac_drift_status == "SYNCHRONIZED"
}

# Defer to human review (HITL) if production resource is load-bearing or drift detected
defer {
    input.predicate.environment_tier == "PRODUCTION"
    input.predicate.is_load_bearing == true
    input.predicate.has_failover_redundancy == false
}

defer {
    input.predicate.iac_drift_status == "DRIFT_DETECTED"
}
```

---

## 5. Implementation Roadmap & Milestones

| Milestone | Deliverables | Target Timeline | Verification Gate |
|---|---|---|---|
| **M1: Wire Schema & MCP Client** | `src/integrations/provider_08/schema.py`, `mcp_client.py` (stdio / SSE JSON-RPC) | Week 1 | Unit tests with mock stdio subprocess |
| **M2: Normative Seam Adapter** | `src/integrations/provider_08/adapter.py` implementing `NormativeProvider` | Week 2 | Interface verification against `NormativeProvider` protocol |
| **M3: Deferral Queue Hydration** | Extension to `defer_queue.py` hydration loop for CloudOps predicates | Week 3 | `PARK` → `HYDRATE` → `REPLAY` integration test |
| **M4: FTRA Reachability Extension** | Dynamic predicate ingestion in `graph_analyzer.py` | Week 4 | Action DAG reachability evaluation with live blast radius |
| **M5: Over-the-Wire Conformance** | `tests/integrations/provider_08/` running against live OpsCanvas sandbox | Week 5 | End-to-end multi-agent CloudOps test with zero synthetic stubs |
