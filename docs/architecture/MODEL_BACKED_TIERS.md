# Model-Backed & Dormant Governance Tiers — Architecture, Placement, and Activation Preconditions

| Field                | Value                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Document Version** | 3.2.0                                                                                                                               |
| **Date**             | 2026-11-05                                                                                                                          |
| **Classification**   | INTERNAL                                                                                                                            |
| **Document Series**  | CAGE Architecture Specification                                                                                                     |
| **Status**           | DORMANT BY DEFAULT — Activation preconditions enforced at plan and assembly (`POAM-2026-168`, `POAM-2026-180`, `POAM-2026-196`)     |
| **Canonical Path**   | `docs/architecture/MODEL_BACKED_TIERS.md`                                                                                           |
| **References**       | [`AGENT_SYSTEM_ARCHITECTURE.md`](AGENT_SYSTEM_ARCHITECTURE.md), [`INFERENCE_GATEWAY_ARCHITECTURE.md`](INFERENCE_GATEWAY_ARCHITECTURE.md), [`GATEWAY_ARCHITECTURE.md`](GATEWAY_ARCHITECTURE.md), [`docs/POAM.md`](../POAM.md) |

**Last Updated:** 2026-11-05

---

## 1. Purpose & Architectural Position

The CAGE runtime kernel (`src/gateway/`) is model-free by default (`POAM-2026-168`): base installation and the shipped gateway container image (`src/gateway/Dockerfile`) exclude every LLM client and model runtime (`scripts/check_model_free_install.py`). Two optional domain/runtime tiers — **Consensus Critics** (`CAGE_CONSENSUS_CRITICS_ENABLED`) and the **Causal Tier** (`CAGE_CAUSAL_TIER_ENABLED`) — together with optional LLM-backed **NeMo Guardrails** (`CAGE_NEMO_ENABLED`) remain dormant in the default and staging postures.

The OSCAL System Security Plan (`compliance/oscal/system-security-plan.yaml`) mentions neither consensus nor the causal tier (`0` matches), and credits only deterministic screening rather than NeMo (`POAM-2026-145`). This document records the exact runtime behaviour, placement constraints, GPU footprint, and mandatory activation preconditions for these tiers so that enabling any of them via a single variable flip cannot weaken the deterministic governance boundary.

---

## 2. Multi-Agent Consensus Tier (`CAGE_CONSENSUS_CRITICS_ENABLED`)

### 2.1 Threshold Gating & Critic Assignment

- **Threshold-gated, not per-decision:** `ConsensusEngine` ([`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py)) triggers only for actions above the jurisdiction threshold (`$10,000 USD` in `US_FED`). Approval must be synchronous and unanimous.
- **Two critics mapped to the existing vLLM pair:** The finance plugin defines two critics in [`src/cage_finance/config/critics.yaml`](../../src/cage_finance/config/critics.yaml), which the split-brain fallback in [`src/integrations/inference_client/critic_backend.py`](../../src/integrations/inference_client/critic_backend.py) assigns to the existing vLLM fast and reasoning services. Turning consensus on adds inference load to the existing model pair rather than introducing independent model families.

### 2.2 Timeout, Escalation, and Admission Semantics

- **A critic timeout escalates rather than refusing:** The per-critic timeout in [`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py) is `10 s`. All-error, error-plus-approve, and error-plus-some-rejects outcomes all escalate (`REQUIRE_APPROVAL`). Only unanimous approval admits (`ALLOW`), and only unanimous rejection with zero errors denies (`DENY`). Consequently, scaling GPU nodes to zero is safe for governance refusal invariants — unavailability costs critic votes and escalates rather than admitting.
- **Turning critics on replaces human review with a model vote for above-threshold actions:** When `CAGE_CONSENSUS_CRITICS_ENABLED=true`, unanimous critic approval admits an above-threshold trade without human review ([`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py)). That behaviour conflicts with the model-free kernel invariant (`POAM-2026-168`) and with deterministic replay of verdicts through the symbolic path.
- **Advisory-only target design ("escalates rather than decides"):** In the current implementation, unanimous critic approval decides admission directly. For consensus to act purely as decision support, every above-threshold action must still escalate to human review (`POAM-2026-196`), with critic votes attached as advisory notes for the reviewer; verdicts then remain replayable and independent of model availability.

### 2.3 Container Image & Import Boundary Posture

- **Shipped gateway image cannot run critics:** [`scripts/check_model_free_install.py`](../../scripts/check_model_free_install.py) keeps `openai` and all other LLM SDKs out of the base install and `src/gateway/Dockerfile`, so enabling `CAGE_CONSENSUS_CRITICS_ENABLED=true` against the shipped gateway image fails closed at startup with `CriticBackendUnavailable` in [`src/gateway/governance/critic_backend_factory.py`](../../src/gateway/governance/critic_backend_factory.py).
- **Import-boundary allowlist note:** [`scripts/check_import_boundaries.py`](../../scripts/check_import_boundaries.py) allowlists [`src/gateway/governance/critic_backend_factory.py`](../../src/gateway/governance/critic_backend_factory.py) in `INTEGRATIONS_FACTORY_ALLOWLIST`, and [`tests/test_kernel_assembly_model_free.py`](../../tests/test_kernel_assembly_model_free.py) verifies that critic code loads when the `inference` extra is installed. Only `POAM-2026-168`'s image check prevents in-gateway model client execution in production images.

---

## 3. Causal Tier (`CAGE_CAUSAL_TIER_ENABLED`)

- **In-process CPU refutation worker:** `WorldModelRefresher` ([`src/gateway/governance/causal/world_model_refresher.py`](../../src/gateway/governance/causal/world_model_refresher.py)) runs a `20 s` loop executing DoWhy's 50-simulation placebo test in a single worker process inside the gateway pod (`src/gateway/Dockerfile` includes DoWhy, and [`src/cage_finance/tiers/causal_tier.py`](../../src/cage_finance/tiers/causal_tier.py) instantiates the tier). Verdicts expire after `60 s` and telemetry after `300 s`. There is no separate batch job for world-model refresh.
- **Telemetry feed requirement:** Turning the causal tier on requires a live telemetry feed carrying the causal graph's variables ([`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf)). Without live telemetry, `CausalTier` refuses every evaluated action (`no_live_telemetry`). The gateway pod's `2 CPU` limit covers the single refutation worker.
- **Input integrity hazard:** While `CausalTier` can only add a hard violation ([`src/cage_finance/tiers/causal_tier.py`](../../src/cage_finance/tiers/causal_tier.py)), the governed advisor and the gateway share the same application Langfuse project credentials in [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) (`POAM-2026-169` Instance 10). The governed agent can therefore write all three causal columns (`market_volatility`, `trade_amount`, `risk_score`) read by the refresher, and when `CAUSAL_GATEKEEPER_STRICT_MODE` is `false` (its default in [`src/gateway/governance/causal/gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)), spans lacking trace IDs are ordered by producer-supplied timestamp alone.

---

## 4. GPU Footprint & Workload Placement (`GKE` vs. `Cloud Run`)

- **GKE vLLM GPU footprint:** [`infra/modules/vllm_inference/main.tf`](../../infra/modules/vllm_inference/main.tf) deploys fixed replicas (`vllm_replicas = 1`) with no HorizontalPodAutoscaler, so setting `inference_backend = "vllm"` keeps two NVIDIA L4 nodes (`g2-standard-8`) running continuously (one for the 1.5B fast model and one for the 8B reasoning model). The `gpu-l4` node pool's `min_count = 0` ([`infra/targets/gcp-gke/variables.tf`](../../infra/targets/gcp-gke/variables.tf)) scales to zero only when `inference_backend = "none"`.
- **Cloud Run L4 availability:** Cloud Run L4 GPUs are available in `us-central1`, `europe-west1`, and `asia-southeast1` (plus `europe-west4`, `us-east4`, and `asia-south1`), starting an instance in approximately `5 s` with a minimum of `4 CPU` / `16 GiB`.
- **Mesh identity barrier:** Cloud Run workloads cannot obtain a CAGE Linkerd mesh identity (`l5d-client-id`), because Linkerd issues workload certificates only in exchange for a Kubernetes `ServiceAccount` token. Any agent running outside the GKE cluster would require an internal load balancer plus a network-based exception on the gated route.
- **Placement rule:** Any component whose output a gated decision waits on stays inside the GKE Linkerd mesh. The governed agent process itself needs no GPU (only its model server does); all governed workloads and synchronous decision dependencies remain on GKE.

---

## 5. Dormant-Feature Integrity Preconditions

Because telemetry and configuration wiring ship in the Terraform modules while consumer flags default to `false`, enabling a dormant feature is a single variable change unless guarded mechanically. In accordance with `POAM-2026-180` ([`tests/infrastructure/test_guard_placement.py`](../../tests/infrastructure/test_guard_placement.py)), Terraform guards must be placed as `lifecycle` `precondition` blocks directly on the `kubernetes_deployment_v1` resource in [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) (never as standalone `terraform_data` resources that targeted plans skip), paired with startup guards in kernel assembly ([`src/gateway/governance/governor/assembly.py`](../../src/gateway/governance/governor/assembly.py)).

| Feature (Switch) | Effect When Enabled | Who Writes Its Inputs | Integrity Precondition | Mechanical Enforcement |
| --- | --- | --- | --- | --- |
| **Causal tier** (`CAGE_CAUSAL_TIER_ENABLED`) | Can only add a hard violation ([`src/cage_finance/tiers/causal_tier.py`](../../src/cage_finance/tiers/causal_tier.py)) | Governed agent can write all three columns (`market_volatility`, `trade_amount`, `risk_score`) via shared Langfuse credentials | Telemetry credentials (`TELEMETRY_*`) must belong to a plane-only source the governed agent cannot write (distinct from `advisor-secrets` / advisor Langfuse keys), and `CAUSAL_GATEKEEPER_STRICT_MODE=true` | Gateway `kubernetes_deployment_v1` `lifecycle` `precondition` in [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) + kernel assembly guard in [`src/gateway/governance/governor/assembly.py`](../../src/gateway/governance/governor/assembly.py) |
| ↳ `CAUSAL_GATEKEEPER_STRICT_MODE` (nested; default `false`) | When `false`, spans without trace IDs are ordered by producer-supplied timestamp alone ([`src/gateway/governance/causal/gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)) | Producer-supplied span timestamps | Must be `true` whenever `CAGE_CAUSAL_TIER_ENABLED=true` under an enforcing posture | Kernel assembly guard in [`src/gateway/governance/governor/assembly.py`](../../src/gateway/governance/governor/assembly.py) |
| **Consensus critics** (`CAGE_CONSENSUS_CRITICS_ENABLED`) | **Can admit:** unanimous critic approval admits an above-threshold action without a human ([`src/gateway/governance/consensus/engine.py`](../../src/gateway/governance/consensus/engine.py)) | Critic prompt renders `action`, `amount`, and `symbol` ([`src/cage_finance/config/critics.yaml`](../../src/cage_finance/config/critics.yaml)); `TradeOrder` declares `symbol` as an unconstrained `str` ([`src/cage_finance/models/trade_order.py`](../../src/cage_finance/models/trade_order.py)) | Every action parameter rendered into the critic prompt must be pattern-bound and length-bounded by the action schema (or consensus must run in advisory-only escalation mode), and human-bound HITL (`POAM-2026-196`) must be closed | Gateway `kubernetes_deployment_v1` `lifecycle` `precondition` in [`infra/modules/gateway/main.tf`](../../infra/modules/gateway/main.tf) + kernel assembly guard in [`src/gateway/governance/governor/assembly.py`](../../src/gateway/governance/governor/assembly.py) |
| **NeMo rails** (`CAGE_NEMO_ENABLED`) | Adds LLM-backed Colang rails on top of deterministic keyword and Presidio PII controls ([`src/gateway/governance/feature_flags.py`](../../src/gateway/governance/feature_flags.py)) | Agent's own messages (the input being judged) | Availability only (deterministic PII and keyword screening run unconditionally regardless of `CAGE_NEMO_ENABLED`, `POAM-2026-142` / `POAM-2026-144` / `POAM-2026-145`) | Unbundled deterministic path enforced at startup |
| `CAGE_ALLOW_NONBLOCKING_PROD` (override; `false` is the enforcing setting) | Lets an enforcing posture run without blocking evidence writes ([`src/gateway/governance/evidence/stream.py`](../../src/gateway/governance/evidence/stream.py)) | Operator | Must never be set in `infra/`; any override must emit a hash-chained evidence record rather than a log line alone | Not set anywhere in `infra/` |
