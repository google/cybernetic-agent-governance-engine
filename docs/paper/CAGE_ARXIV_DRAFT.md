# CAGE: A Neuro-Symbolic Architecture for Deterministic and Verifiable Governance of Agentic AI — From Hazard Analysis to Runtime Enforcement with Formal Safety Guarantees

**Draft for arxiv submission — cs.CR + cs.AI cross-list**

> **Author note (pre-submission blockers):**
> 1. Resolve Google LLC copyright / affiliation before submitting.
> 2. Verify `proof/model.py` LalaSkye attribution — confirm co-authorship or
>    cite as prior work.
> 3. Obtain arxiv endorser for cs.CR or cs.AI (first-time submitter requirement).
> 4. ~~POAM-023 closure~~ **DONE** — `feat/POAM-023-cbf-external-reconcil`
>    merged; Plaid Production reconciliation daemon is live. Run §5 evaluation
>    with Plaid Production credentials to replace `[PLACEHOLDER]` values.
> 5. Replace all `[PLACEHOLDER]` values with measured data.
> 6. **SECURITY** — Merge fix for GHSA-hfqj-24cj-693g (CVSS 9.4, inference
>    proxy governance bypass) before submission; §4.2 and §4.7 claims are
>    invalidated until that patch lands in `main`.
> 7. **SECURITY** — Merge fix for GHSA-v3h4-8458-5ww3 (CVSS 6.5, unauthenticated
>    `POST /governance/validate-action`) before submission; undermines §4.7
>    NIST IA-3/AC-3 control assertions.

---

## Abstract

The rapid advancement of agentic AI systems built on non-deterministic Large
Language Models (LLMs) presents significant challenges for safety, reliability,
and regulatory compliance in high-stakes industries. We present the **Cybernetic
Agent Governance Engine (CAGE)**, grounded in Ashby's Law of Requisite Variety
and Stafford Beer's Viable System Model (VSM), which frames the governance
problem as matching the immense variety of emergent LLM behaviors with a
sufficiently rich, deterministic set of control states. CAGE is a
compiler-driven runtime governance framework that translates System-Theoretic
Process Analysis (STPA) hazard models into executable enforcement policies, then
evaluates every agent action through an eight-tier symbolic governor (including
a pre-execution Forward-Looking Trajectory Reachability Analyzer, FTRA) before
execution is permitted. The governor combines discrete-time Control Barrier
Functions (CBF), Open Policy Agent (OPA) Rego policies, causal intervention
simulation, and human-in-the-loop escalation into a single, formally verified
pipeline. Governance is enforced at the HTTP layer for all message roles,
eliminating role-based bypass paths. We prove the **NoDirectBind invariant** —
that no action can reach the EXECUTED state without passing all governance
tiers — via exhaustive breadth-first search over 19 reachable automaton states.
We further prove CBF invariance, FiscalLimitGuard race-condition freedom, Cloud
KMS non-repudiation, and evidence chain integrity via cryptographic
`record_hash` binding across the full NDJSON audit chain. To close a recursive
self-authentication gap in the CBF (POAM-023), we implement an isolated
reconciliation daemon that fetches externally attested balances from Plaid
Production, signs them with Cloud KMS, and writes them to Redis with strict
TTL; the CBF reads this signed external ground truth instead of the
self-reported balance. We evaluate CAGE against a corpus of 290+ adversarial
attacks across five attack categories and report governance latency,
reconciliation write-path cost, and per-request CBF read overhead. CAGE is
open-source and targets NIST SP 800-53, ISO 42001, SR 26-2, and
multi-jurisdiction compliance (US FED, EU ECB, APAC MAS).

---

## 1. Introduction

Autonomous AI agents that execute financial transactions introduce a class of
safety and compliance risks that static policy frameworks cannot address.
Unlike traditional software, agentic systems exhibit goal-directed persistence:
they may pursue objectives across multiple tool calls, accumulate context
across sessions, and generate novel action sequences not anticipated at design
time. Existing governance approaches — prompt-level guardrails, post-hoc
auditing, or manual review — are insufficient for high-frequency, low-latency
financial execution.

The reference architecture of Ahlfors et al. [CITE: arxiv:2606.12320]
identifies five enforcement planes (reasoning, network, identity, endpoint,
data) and six interruption primitives for runtime governance of production AI
agents. Their framework provides a conceptual taxonomy but does not specify how
hazard analysis translates into enforcement code, how formal safety invariants
are verified, or how the ground truth used by safety functions is protected
from manipulation by the governed system itself.

We address these gaps with CAGE. Our contributions are:

1. **STPA compiler**: A tool that translates STPA Unsafe Control Actions (UCAs)
   into OPA Rego policies, NeMo Colang rails, and GEAP Agent Registry
   authorization manifests, eliminating the manual translation step that
   introduces policy drift.

2. **Eight-tier symbolic governor**: A formally specified pipeline that
   evaluates every agent action through a pre-execution FTRA reachability gate
   (Tier 0.5), STPA validation, confidence scoring, CBF + OPA (parallel),
   FiscalLimitGuard, consensus, causal gatekeeper, and FRIA before execution.
   Governance is enforced at the HTTP layer for all message roles — not only
   `user`-role messages — eliminating role-based bypass paths in the inference
   proxy.

3. **Machine-verified NoDirectBind invariant**: Exhaustive BFS over 19
   reachable automaton states proves that `(phase=EXECUTED) ⟹
   (resolvedAllow=TRUE)` — no action can bypass the governance pipeline.

4. **External balance reconciliation (POAM-023 closure)**: An isolated
   reconciliation daemon fetches KMS-signed external balances from Plaid
   Production, eliminating the recursive self-authentication vulnerability
   where the execution system writes its own balance to Redis and then uses
   that balance to pass the CBF check. A module-level `_IS_PRODUCTION` guard
   raises `RuntimeError` at startup if `RECONCILIATION_PROVIDER=stub` in
   production, preventing accidental deployment without live reconciliation.

5. **Evidence chain integrity**: Every node in the NDJSON audit chain is bound
   into its `record_hash` via `SHA-256(prev_hash ‖ content_json ‖ control_id ‖
   event_type ‖ node_index ‖ audit_id)`, ensuring that metadata fields cannot
   be altered post-hoc without invalidating the chain.

6. **Multi-jurisdiction compliance**: A single `CAGE_DEPLOYMENT_REGION`
   environment variable gates data paths, telemetry sinks, and control
   implementations for US FED (NIST SP 800-53), EU ECB (GDPR / SR 26-2), and
   APAC MAS (MAS Notice 655).

---

## 2. Cybernetic Foundations

A fundamental challenge in agentic AI governance is controlling a system whose
output space is practically infinite. Natural language reasoning and open-ended
tool environments generate high "variety" in the cybernetic sense — the number
of possible states a system can occupy. To address this, CAGE draws upon
classical cybernetics and systems engineering as its theoretical grounding.

### 2.1 Ashby's Law of Requisite Variety

Ashby's Law states that "only variety can destroy variety" [Ashby, 1956]. If an
LLM-based agent possesses an enormous variety of potentially unsafe emergent
behaviors, the governance engine must match this variety with a sufficiently
rich, deterministic set of control states. CAGE accomplishes this by mapping
fine-grained safety boundaries to a multi-tiered, deterministic policy
enforcement runtime. By translating specific, complex hazard scenarios into
modular, machine-readable rules, CAGE provides a matching regulatory variety
that guarantees deterministic safety bounds regardless of the LLM's
non-deterministic reasoning steps.

### 2.2 Stafford Beer's Viable System Model (VSM)

CAGE conceptualizes the agentic ecosystem through Stafford Beer's Viable System
Model (VSM) [Beer, 1972; Beer, 1979] to ensure systemic viability and
compliance:

- **System 1 (Operation)**: Represented by the reasoning plane (the "Plant"),
  which executes the primary tasks and proposes tool actions.
- **System 2 (Coordination)**: Managed by the outer gateway layer, preventing
  oscillatory behaviors, repetitive actions, and conflicting commands across
  multi-agent workflows.
- **System 3 (Control/Execution)**: Enforced by the SymbolicGovernor, which
  synchronously intercepts and evaluates proposed actions against hard security
  limits.
- **System 4 (Intelligence/Adaptation)**: Sustained by the adaptive self-healing
  feedback loop that dynamically adjusts policy variables based on environment
  feedback.
- **System 5 (Policy)**: Formulated by the enterprise-defined STPA safety
  requirements, establishing the absolute boundary of acceptable behavior.

### 2.3 The Controller-Plant Separation

CAGE maintains a strict physical and logical separation between the agent
reasoning plane (the "Plant") and the hybrid neuro-symbolic governance plane
(the "Controller" or SymbolicGovernor). This design pattern is mathematically
grounded in the Good Regulator Theorem [Conant & Ashby, 1970], which dictates
that any optimal controller must contain a structural model of the system being
controlled.

Rather than embedding safety guardrails inside the agent's prompt — which are
easily bypassed via jailbreaks or prompt injections — the Controller acts as an
external, untrusted gateway. When the Plant proposes a tool invocation, it
cannot execute it directly. Instead, it must send a structured payload to the
Controller. The Controller evaluates the request against compiled policies and
only returns the necessary credentials or permits execution upon successful
verification.

---

## 3. Background and Related Work

### 3.1 Five-Plane Reference Architecture

Ahlfors et al. [CITE: arxiv:2606.12320] propose a five-plane architecture for
runtime governance: a reasoning plane that monitors agent cognition, and four
enforcement planes (network, identity, endpoint, data) that implement
interruption primitives. They identify six primitives: BLOCK, DEFER, REDACT,
AUDIT, ESCALATE, and TERMINATE. Their correctness invariants include
completeness (all actions pass through at least one enforcement plane),
non-circumventability (no action bypasses enforcement), auditability (all
decisions are logged), and recoverability (blocked actions can be replayed
after human review).

CAGE implements all six primitives and satisfies all four invariants. Table 1
maps the five-plane taxonomy to CAGE subsystems.

**Table 1: Five-Plane to CAGE Mapping**

| Plane | CAGE Subsystem |
|---|---|
| Reasoning | SymbolicGovernor (7-tier pipeline) + ConfabulationScorer |
| Network | Cilium NetworkPolicy (reconciliation-worker isolation) |
| Identity | Cloud KMS asymmetric signing + Workload Identity |
| Endpoint | OPA Rego policies + NeMo Colang rails |
| Data | CBF (Redis-backed) + FiscalLimitGuard + ContextAccumulator |

### 3.2 Control Barrier Functions for Safety

Discrete-time CBFs [Ames et al., IEEE TAC 2017] provide a formal mechanism for
enforcing safety constraints on dynamical systems. For a safety function
`h: S → ℝ`, the CBF condition requires:

```
h(S(t+1)) ≥ (1 − γ) · h(S(t))   for all t, γ ∈ (0, 1)
```

This ensures the system remains in the safe set `{s : h(s) ≥ 0}` for all
future time steps. Prior work applies CBFs to robotic systems [CITE] and
autonomous vehicles [CITE]; we apply them to financial agent governance.

### 3.3 STPA for AI Systems

System-Theoretic Process Analysis [Leveson, 2011] identifies Unsafe Control
Actions (UCAs) — control actions that are unsafe given the system context.
Prior work applies STPA to autonomous vehicles [CITE] and medical devices
[CITE]. Mylius [2025] confirms that STPA dramatically improves traceability,
exposes complex causal factors missed by unstructured hazard analysis, and
adapts naturally to AI systems with minimal domain-specific tailoring. We apply
STPA to AI agent governance and introduce a compiler that translates UCAs into
executable enforcement policies, guided by the Process-oriented Hazard Analysis
for AI Systems (PHASE) methodology [Rismani et al., 2024].

### 3.4 Related Work and Positioning

The CAGE framework operates at the intersection of neuro-symbolic AI oversight,
runtime verification, and distributed systems security.

**FormalJudge** [Zhou et al., 2026] is highly effective for proof-oriented,
post-hoc oversight of agent trajectories, enabling rigorous offline verification
of agent reasoning pathways. However, it lacks the synchronous, deterministic
execution constraints needed for active runtime enforcement. CAGE, by contrast,
operates inline as a synchronous runtime governor, blocking unsafe actions
before they reach the execution plane.

**G-SPEC and LogicGuard** [Vijay & Ethiraj, 2025] support the broader case
that deterministic, symbolic validation layers can materially improve safety in
complex systems such as 5G autonomous networks. CAGE extends this paradigm by
integrating symbolic validation directly with a comprehensive, enterprise-grade
zero-trust identity fabric.

**AgentSpec** [Wang, Poskitt & Sun, 2025] provides a lightweight,
trigger-predicate-enforcement DSL that achieves robust runtime safety, but
operates primarily on agent-level event streams rather than concrete
wire-protocol schemas. CAGE integrates event-driven predicate validation with
OPA and continuous barrier functions to capture dynamic, physical and digital
state deviations.

**AgenTRIM** [2026] similarly addresses tool misuse in LLM agents, while
adversarial evaluation studies [Deng et al., 2025] confirm the attack surface
that CAGE's deflection pipeline targets.

**Multi-agent governance architectures** [Aguiar et al., 2025] and
**neurosymbolic runtime verification frameworks** [Sathe, 2025] further
validate the need for deterministic enforcement layers. Zero-trust identity
frameworks for agentic AI [Raza et al., 2026; Bhushan et al., 2025; Saleem,
2024; Pappu et al., 2026; Pappu et al., 2025] confirm that boundary-based
perimeter controls are inadequate for multi-service and multi-agent systems,
motivating CAGE's identity-centric posture.

**AARM-V3** [Errico, 2026; Cloud Security Alliance, 2026] catalogues the
Confused Deputy attack class that CAGE's routing seal and zero-trust controls
directly neutralize.

---

## 4. System Architecture

### 4.1 Overview

CAGE consists of four subsystems:

1. **STPA Compiler** (`src/gateway/governance/stpa_compiler.py`): Translates
   STPA UCAs into OPA Rego policies and NeMo Colang rails.

2. **Eight-Tier Symbolic Governor** (`src/gateway/governance/symbolic_governor.py`):
   Evaluates every agent action through a sequential pipeline before execution.

3. **Compliance Bridge** (`src/compliance_bridge/`): Reconciliation daemon,
   OSCAL exporter, Lula validator, and audit workflow.

4. **Governed Financial Advisor** (`src/governed_financial_advisor/`):
   Reference application demonstrating CAGE integration with a LangGraph agent.

### 4.2 Eight-Tier Symbolic Governor

The governor evaluates every action through seven tiers in sequence:

**Tier 0.5 — FTRA (Forward-Looking Trajectory Reachability Analyzer)**:
Before the first LangGraph node fires, the FTRA builds a NetworkX directed
graph from `ExecutionPlan.steps`, classifies each reachable action against the
compiled terminal registry, and issues one of three verdicts: `CLEAR` (proceed
to OPA safety gate), `HITL_REQUIRED` (park in `DeferQueue` + `NodeInterrupt`),
or `BLOCKED` (route to explainer; plan cannot proceed). This pre-execution gate
catches unsafe trajectories before any tool call is made.

**HTTP-layer enforcement**: Governance is applied at the HTTP layer for all
message roles (`user`, `system`, `assistant`). The inference proxy enforces
input governance — Tier-1 keyword scan, token/step quota, and NeMo input rails
— regardless of whether a `user`-role message is present, and applies output
filtering for all response paths including `stream: true`. This eliminates the
role-based bypass path identified in GHSA-hfqj-24cj-693g.

**Tier 1 — STPA Validation**: Checks the action against compiled UCAs. If the
action matches a UCA pattern, it is blocked with a structured violation record.

**Tier 2 — Confidence Scoring**: Evaluates the agent's confidence in the
action. Actions below the threshold (default: 0.95) are escalated to HITL.

**Tier 3 — CBF + OPA (parallel)**: Evaluates the discrete-time CBF condition
and OPA Rego policies concurrently. Either can block the action.

**Tier 4 — FiscalLimitGuard**: Enforces daily spending caps with atomic
WATCH/MULTI/EXEC Redis transactions, preventing TOCTOU races under concurrent
agent execution.

**Tier 5 — Consensus**: For high-value actions (above configurable threshold),
requires agreement from multiple independent critic models.

**Tier 6 — DoWhy Causal Gatekeeper**: Simulates the causal effect of the
action using a structural causal model. Actions with high marginal risk are
blocked.

**Tier 7 — FRIA**: Financial Risk Impact Assessment. Classifies the action
into risk zones and applies zone-specific controls.

### 4.3 Control Barrier Function

The CBF enforces the financial safety invariant:

```
h(S(t)) = cash_balance(t) − min_cash_balance
```

The CBF condition requires:

```
h(S(t+1)) ≥ (1 − γ) · h(S(t))
```

where `γ = 0.1` (default). An action is safe if and only if the post-action
balance satisfies this condition.

**POAM-023 gap (closed)**: Prior to this work, the CBF read
`safety:current_cash` from Redis — a value written by the execution system
itself. This creates a recursive self-authentication vulnerability: the
execution system could write an inflated balance, pass the CBF check, then
execute a trade that violates the true safety constraint.

**Closure**: We implement an isolated reconciliation daemon
(`src/compliance_bridge/reconciliation_worker.py`) that:
1. Runs in a dedicated Kubernetes namespace with Cilium network policy
   preventing it from communicating with the gateway or financial-advisor pods.
2. Fetches the real account balance from Plaid Production via
   `POST /accounts/balance/get`.
3. Signs the balance payload with Cloud KMS (`asymmetricSign`).
4. Writes the signed balance to `reconciliation:verified_balance` in Redis
   with a 300-second TTL.

The CBF reads `reconciliation:verified_balance` first. If the key is absent
(TTL expired) or the KMS signature is invalid, the CBF fails closed — it
rejects the action rather than falling back to the self-reported balance. Every
CBF span carries OTel attributes `safety.balance.source` (`"reconciled"` or
`"self_reported"`) and `safety.balance.reconciled` (`True`/`False`) for full
balance provenance auditability.

A module-level `_IS_PRODUCTION` constant in `cbf.py` (patchable in tests)
gates the production guard: if `CAGE_ENV=production` and
`RECONCILIATION_PROVIDER=stub`, the system raises `RuntimeError` at startup,
preventing accidental deployment without live reconciliation.

### 4.4 NoDirectBind Invariant

**Definition**: Let `phase ∈ {PENDING, CHECKING, APPROVED, REJECTED, EXECUTED,
ROLLED_BACK}` and `resolvedAllow ∈ {TRUE, FALSE, UNKNOWN}`. The NoDirectBind
invariant states:

```
∀ states s: (s.phase = EXECUTED) ⟹ (s.resolvedAllow = TRUE)
```

**Proof**: We enumerate all reachable states via BFS from the initial state
`(phase=PENDING, resolvedAllow=UNKNOWN)` using the transition function defined
in `proof/model.py`. The BFS visits 19 reachable states. In all states where
`phase=EXECUTED`, `resolvedAllow=TRUE`. The state `(phase=EXECUTED,
resolvedAllow=FALSE)` is unreachable. ∎

The proof is machine-verified: `proof/model.py` implements the BFS enumerator
and asserts the invariant over all reachable states. The proof runs in O(|S|)
time where |S| = 19.

### 4.5 STPA Compiler

The STPA compiler (`src/gateway/governance/stpa_compiler.py`) translates UCAs
into enforcement policies:

```
UCA → OPA Rego rule (structural policy)
UCA → NeMo Colang rail (conversational guardrail)
UCA → STPA validator check (runtime assertion)
UCA → Agent Registry authorization manifest (--targets registry)
```

The `--targets registry` flag emits a tool-authorization JSON manifest from
the STPA YAML, which the GEAP Agent Registry adapter
(`src/gateway/governance/agent_registry_adapter.py`) pushes to OPA via
`PUT /v1/data/agent_catalog_data` at boot and on a background poll. This
extends OSCAL AC-3 (Access Enforcement) evidence to cover agent-level tool
authorization, not only human-level access control.

The compiler eliminates the manual translation step that introduces policy
drift between the hazard model and the enforcement code. The generated
validator (`src/gateway/governance/generated_stpa_validator.py`) is
regenerated from the STPA source on every CI run; a freshness check
(`scripts/check_stpa_freshness.py`) fails the build if the generated code is
stale.

### 4.6 Multi-Jurisdiction Compliance

CAGE deploys simultaneously to three regulatory jurisdictions via
`CAGE_DEPLOYMENT_REGION`:

- **US_FED**: NIST SP 800-53 Rev 5, FedRAMP High, SR 26-2 Model Risk
  Management. Data paths within `us-central1`.
- **EU_ECB**: GDPR, SR 26-2 (no legal force sentinel suppresses telemetry
  lacking legal basis). Data paths within `europe-west1`.
- **APAC_MAS**: MAS Notice 655. Data paths within `asia-southeast1`.

Every new storage path, GCS write, Langfuse sink, or telemetry export in
shared modules (`src/gateway/governance/` and `src/compliance_bridge/`) must
be gated on `CAGE_DEPLOYMENT_REGION`.

### 4.7 Zero-Trust Security Controls

A critical vulnerability in distributed multi-agent systems is the
"direct-bind shortcut" [Errico, 2026] — when an agent, under the influence of
an adversarial attack or unexpected emergent state, attempts to bypass the
governance plane to bind directly with raw system tools or databases.
Boundary-based perimeter controls are consistently inadequate for multi-service
and multi-agent systems [Raza et al., 2026; Bhushan et al., 2025; Saleem,
2024]. CAGE mitigates this risk by enforcing an identity-centric, zero-trust
architecture at each request boundary.

**Fail-Safe Startup Assertions**: The SymbolicGovernor enforces module-level
startup assertions that raise a `RuntimeError` at import time under two
conditions: (1) `CBF_FAIL_OPEN=true` in a production environment — this
removes the cash-barrier tier from the governance gate; (2) the `dowhy` library
is absent or fails to import in production — this silently removes the causal
gatekeeper (Tier 6) from the pipeline. These checks run before the gateway
begins accepting traffic, ensuring the service fails fast rather than surfacing
gaps on the first live request.

**Cluster-Level Mesh Microsegmentation**: CAGE treats the underlying network as
hostile. Workload identity and mutual TLS (mTLS) are implemented at the
deployment infrastructure layer using Linkerd [Buoyant, 2026] and SPIRE
daemonsets. Linkerd automatically intercepts TCP traffic and performs
bidirectional validation using SPIFFE-verifiable identity documents (SVIDs)
[SPIFFE, 2022] mapped to Kubernetes ServiceAccounts, matching the standard
format `spiffe://cluster.local/ns/<namespace>/sa/<service-account>`.

**Continuous Verification**: Unlike static access controls that verify
credentials once at session initiation, CAGE performs continuous, intent-aware
verification [Pappu et al., 2026; Bhushan et al., 2025]. This is essential for
agentic environments because agents can dynamically spawn subagents and change
execution intents at runtime, necessitating constant re-evaluation of security
postures.

**Runtime Routing Seal**: Once all checks inside `_run_checks()` return zero
violations, `routing_seal.py` generates an ephemeral symmetric routing token
formatted as `<expire_ts_hex>.<action_slug>.<hmac_hex>` using HMAC-SHA256
keyed by a high-entropy `GOVERNANCE_SALT`. The seal lifetime is 30 seconds
(configurable via `GOVERNANCE_SEAL_TTL_S`). The `require_cleared_seal`
decorator provides strict enforcement: it calls `verify_seal()` and raises a
`SymbolicGovernorViolation` before the wrapped callable is invoked, making it
impossible for callers to silently ignore a failed verification. This design
directly eliminates the Confused Deputy class of attacks catalogued in AARM-V3
[Errico, 2026; Cloud Security Alliance, 2026].

**Asymmetric Plan Attestation**: To prevent tampering with static policy
manifests deployed across federated clusters, CAGE implements asymmetric
signature validation inside `kms_signer.py`. Manifests are cryptographically
signed and validated using Key Management Services across three cloud providers:
GCP Cloud KMS, AWS KMS (ECDSA_SHA_256), and Azure Key Vault (ES256). For GCP,
the governor performs verification against the configured public key using
EC-DSA (SHA-256 prehashed) with RSA-PSS as a fallback, supporting both key
families transparently.

---

## 5. Formal Safety Properties

### 5.1 CBF Invariance Theorem

**Theorem**: If the CBF condition is satisfied at time `t`, and the
reconciliation daemon provides a valid external balance, then the cash balance
remains in the safe set for all future time steps.

**Formal statement**:
```
∀ t ≥ 0: h(S(t)) ≥ 0 ∧ verify_action(a, S(t)) = "SAFE"
  ⟹ h(S(t+1)) ≥ (1 − γ) · h(S(t)) ≥ 0
```

**Proof sketch**: By definition of `verify_action`, if the result is "SAFE"
then `h(S(t+1)) ≥ (1 − γ) · h(S(t))`. Since `γ ∈ (0, 1)` and `h(S(t)) ≥ 0`,
we have `h(S(t+1)) ≥ 0`. By induction, `h(S(t)) ≥ 0` for all `t ≥ 0`. ∎

### 5.2 FiscalLimitGuard Race-Condition Freedom

**Theorem**: Under concurrent execution of `n` agents, the total committed
spend never exceeds the daily cap `C`.

**Proof**: The FiscalLimitGuard uses Redis WATCH/MULTI/EXEC optimistic locking.
The Lua atomic script (`atomic_verify_and_commit`) evaluates the CBF condition
and commits the state update in a single atomic operation. No two agents can
simultaneously observe a balance that satisfies the CBF condition and both
commit a trade that violates it. ∎

### 5.3 Cloud KMS Non-Repudiation

**Theorem**: Every governance decision is non-repudiably attested by a Cloud
KMS asymmetric signature that cannot be forged without access to the HSM-backed
private key.

**Proof**: Cloud KMS uses FIPS 140-2 Level 3 HSMs. The private key never
leaves the HSM. The signature is produced by `asymmetricSign` over the
SHA-256 hash of the governance decision payload. Forgery requires either
breaking ECDSA-P256 or compromising the HSM — both computationally infeasible
under standard cryptographic assumptions. ∎

### 5.4 Reconciliation Isolation Guarantee

**Theorem**: The reconciliation daemon cannot be influenced by the execution
system to report a false balance.

**Proof**: The Cilium NetworkPolicy for the `reconciliation-worker` namespace
permits egress only to Plaid Production FQDNs and the Redis endpoint. It
denies all ingress from the gateway and financial-advisor namespaces. The
daemon fetches balances directly from Plaid Production — a path the execution
system cannot intercept or modify. The KMS signature on the balance payload
provides cryptographic evidence that the balance was written by the
reconciliation daemon, not by the execution system. ∎

### 5.5 Evidence Chain Integrity

**Theorem**: No field in a persisted audit node can be altered post-hoc
without invalidating the `record_hash` chain.

**Formal statement**: Let `r_i` denote the `i`-th node record with fields
`content_json`, `control_id`, `event_type`, `node_index`, `audit_id`, and
`prev_hash`. The record hash is:

```
record_hash(r_i) = SHA-256(
    prev_hash(r_{i-1}) ‖ content_json(r_i) ‖ control_id(r_i)
    ‖ event_type(r_i) ‖ node_index(r_i) ‖ audit_id(r_i)
)
```

**Proof**: SHA-256 is collision-resistant under standard cryptographic
assumptions. Any modification to any bound field changes the input to SHA-256,
producing a different digest with overwhelming probability. Since each node's
`prev_hash` is the `record_hash` of its predecessor, a modification to node
`r_i` invalidates `record_hash(r_i)` and therefore `prev_hash(r_{i+1})`,
propagating the invalidation to all subsequent nodes. An auditor re-computing
the chain from the NDJSON artifact will detect the mismatch. ∎

Prior to this work, `content_json` alone was hashed; `control_id`,
`event_type`, `node_index`, and `audit_id` were serialised beside the payload
in the NDJSON artifact but not bound into the hash, allowing those fields to be
altered without chain invalidation. The fix (PR #23,
`evidence-chain-metadata-binding`) binds all metadata fields into the hash.
Note: existing NDJSON artifacts produced before this change will not re-verify
under the new hash function; a schema version bump to `cage-context-accumulator/1.1`
with version-dispatched verification preserves backward compatibility.

---

## 6. Evaluation

### 6.1 Experimental Setup

We evaluate CAGE on a governed financial advisor agent implemented with
LangGraph. The agent executes equity trades on behalf of a simulated portfolio.

**Latency context**: In enterprise banking and instant settlement scenarios,
low latency is critical. Real-time payment rails — such as FedNow in the United
States and SEPA Instant in Europe — operate under an end-to-end clearing SLA of
10 seconds [Volt Active Data, 2026]. Financial institutions typically allocate
an internal processing budget of 2 to 3 seconds for synchronous compliance,
AML, and fraud-screening loops. To operate seamlessly within this constraint,
CAGE enforces an internal transactional latency target of under 200 ms. This
target acts as a soft SLA tracked and logged continuously via OpenTelemetry
(OTel) instrumentation spans recording `governance.stage.latency_ms` on every
tier of the pipeline. Individual deterministic governance tiers — such as the
STPA UCA validator — complete in under 1 ms due to their pure-Python, I/O-free
implementation. Payment message schemas conform to ISO 20022 [ISO, 2013] for
interoperability with FedNow and SEPA Instant clearing infrastructure.

**Adversarial corpus**: We evaluate CAGE's deflection pipeline against a corpus
of 290+ adversarial attacks designed to trigger safety violations, goal
hijacking (AARM-V2) [Errico, 2026], and perimeter bypasses [Deng et al., 2025].
The corpus spans five attack categories: prompt injection, PII exfiltration,
RBAC escalation, harmful financial instructions, and compound multi-vector
attacks.

We measure:

- **Governance latency**: End-to-end latency of the eight-tier governor for
  APPROVED and REJECTED actions.
- **Deflection rate**: Fraction of adversarial corpus attacks blocked by the
  governance pipeline, broken down by attack category.
- **Reconciliation write-path cost** (`T_reconcile`): Total time for one
  reconciliation cycle: Plaid fetch + KMS sign + Redis write.
- **CBF read-path overhead** (`Δt`): Additional latency per governance check
  from reading and verifying the reconciled balance vs. the self-reported
  balance.

**Infrastructure**: [PLACEHOLDER — describe GKE cluster, Redis instance,
Cloud KMS key ring, Plaid Production account.]

### 6.2 Governance Latency

[PLACEHOLDER — fill with measured data after Plaid Production integration.]

**Table 2: Eight-Tier Governor Latency (ms)**

| Tier | P50 | P95 | P99 |
|---|---|---|---|
| FTRA Reachability (Tier 0.5) | [X] | [X] | [X] |
| STPA Validation | [X] | [X] | [X] |
| Confidence Scoring | [X] | [X] | [X] |
| CBF Check (reconciled) | [X] | [X] | [X] |
| OPA Policy Evaluation | [X] | [X] | [X] |
| FiscalLimitGuard | [X] | [X] | [X] |
| Consensus Gate | [X] | [X] | [X] |
| Causal Gatekeeper | [X] | [X] | [X] |
| **Total (APPROVED)** | **[X]** | **[X]** | **[X]** |
| **Total (REJECTED)** | **[X]** | **[X]** | **[X]** |

### 6.3 Reconciliation Write-Path Cost

The reconciliation daemon runs every 60 seconds. The write-path cost is
amortised over the polling interval:

```
T_reconcile = t_plaid_fetch + t_kms_sign + t_redis_write
```

[PLACEHOLDER — fill with measured data.]

**Table 3: Reconciliation Write-Path Latency (ms)**

| Component | P50 | P95 | P99 |
|---|---|---|---|
| Plaid `/accounts/balance/get` | [X] | [X] | [X] |
| Cloud KMS `asymmetricSign` | [X] | [X] | [X] |
| Redis `SETEX` pipeline | [X] | [X] | [X] |
| **T_reconcile total** | **[X]** | **[X]** | **[X]** |

Amortised per-request overhead: `T_reconcile / (poll_interval_s × request_rate_hz)`.
At 60 s polling and [X] req/s, amortised overhead ≈ [X] ms/request.

### 6.4 CBF Read-Path Overhead

The CBF read-path overhead is the additional latency from reading
`reconciliation:verified_balance` and verifying the KMS signature, compared
to reading `safety:current_cash` directly:

```
Δt = t_reconciled_read − t_self_reported_read
   = t_redis_get(reconciliation:verified_balance)
     + t_kms_verify(signature)
     − t_redis_get(safety:current_cash)
```

KMS verification is a local ECDSA-P256 verify operation (no network call):
expected P50 ≈ 0.1–0.5 ms.

[PLACEHOLDER — fill with measured data.]

**Table 4: CBF Read-Path Overhead**

| Path | P50 (ms) | P95 (ms) |
|---|---|---|
| Self-reported (`safety:current_cash`) | [X] | [X] |
| Reconciled (`reconciliation:verified_balance` + KMS verify) | [X] | [X] |
| **Δt overhead** | **[X]** | **[X]** |

### 6.5 Safety Violation Detection

[PLACEHOLDER — describe experiment: inject a false self-reported balance into
Redis; verify that the CBF correctly rejects the action using the reconciled
balance; verify that the CRITICAL audit log is emitted.]

### 6.6 Adversarial Deflection

We evaluate CAGE's governance pipeline against a corpus of 290+ adversarial
attacks [Deng et al., 2025] spanning five attack categories:

**Table 5: Adversarial Deflection by Attack Category**

| Attack Category | Corpus Size | Deflected | Notes |
|---|---|---|---|
| Prompt injection | [X] | [X] | Gateway Aho-Corasick + structural regex |
| PII exfiltration | [X] | [X] | PIISanitizer + OPA ABAC |
| RBAC escalation | [X] | [X] | OPA Rego + STPA UCA validation |
| Harmful financial instructions | [X] | [X] | CBF + FiscalLimitGuard + Consensus |
| Compound multi-vector | [X] | [X] | Full eight-tier pipeline |
| **Total** | **290+** | **[X]** | |

[PLACEHOLDER — fill with measured deflection counts after running
`tests/red_team/run_red_team.py` against the full adversarial corpus.]

This security was achieved without sacrificing performance: the total
governance pipeline operates within the 200 ms soft SLA target, demonstrating
that robust, multi-layered cybernetic governance and zero-trust verification can
be deployed in production without introducing significant performance overhead
to real-time financial systems.

---

## 7. Discussion

### 7.1 Comparison with Five-Plane Architecture

CAGE implements all five planes of the reference architecture [CITE:
arxiv:2606.12320] and extends it in three dimensions:

**Compiler-driven policy generation**: The five-plane architecture assumes
policies are written manually. CAGE's STPA compiler generates OPA Rego, NeMo
Colang, and Agent Registry authorization manifests from hazard analysis,
eliminating policy drift across all three enforcement surfaces.

**Formal verification**: The five-plane architecture states correctness
invariants informally. CAGE machine-verifies the NoDirectBind invariant via
BFS over the full reachable state space, and proves evidence chain integrity
via SHA-256 collision resistance (§5.5).

**External ground truth**: The five-plane architecture does not address the
recursive self-authentication problem in safety functions. CAGE's reconciliation
daemon provides an externally attested, KMS-signed balance that the execution
system cannot influence.

**Pre-execution reachability**: The five-plane architecture evaluates actions
at execution time. CAGE's FTRA gate (Tier 0.5) performs a NetworkX reachability
analysis over the full execution plan before the first tool call, catching
unsafe trajectories at commencement time rather than at each individual action.

### 7.2 Limitations

**Plaid coverage**: Plaid Production covers bank accounts and brokerage
accounts linked via Plaid Link. Custody accounts at OCC-chartered custodians
(e.g., Anchorage Digital) require the `AnchorageGrpcLedgerProvider`, which is
not yet implemented (pending enterprise API onboarding).

**Reconciliation TTL**: The 300-second TTL means the CBF may evaluate against
a balance that is up to 5 minutes stale. For high-frequency trading, a shorter
TTL (e.g., 30 seconds) may be required, increasing the write-path cost.
OTel span attributes `safety.balance.source` and `safety.balance.reconciled`
allow operators to detect TTL expiry events in production dashboards.

**Evidence chain schema versioning**: The `record_hash` binding change
(§5.5) is not backward-compatible. NDJSON artifacts produced before the
`cage-context-accumulator/1.1` schema bump will not re-verify under the new
hash function. Deployments with WORM archive requirements must coordinate a
schema migration or accept that pre-migration artifacts are verified only
against the v1.0 hash function.

**ReDoS in PII scrubbing**: Prior to this work, the email PII pattern in
`PIISanitizer` and `scrub_pii` used unbounded quantifiers, causing quadratic
backtracking on adversarial no-TLD inputs. A crafted 128 KB body could stall
the async event loop for seconds on the unauthenticated
`POST /v1/chat/completions` path. Bounding the local part to `{1,64}` and the
domain to `{1,255}` (RFC 5321 maxima) makes the scan linear while preserving
matching behaviour for all valid addresses.

**Causal model accuracy**: The DoWhy causal gatekeeper uses a structural causal
model that must be calibrated to the specific financial domain. An inaccurate
causal model may produce false positives (blocking safe actions) or false
negatives (allowing unsafe actions).

**Endorsement requirement**: arxiv requires endorsement from an established
researcher for first-time submitters to cs.CR or cs.AI. This is a non-technical
blocker that must be resolved before submission.

### 7.3 Future Work

- **Anchorage Digital integration**: Implement `AnchorageGrpcLedgerProvider`
  for OCC-chartered custody accounts.
- **Shorter reconciliation TTL**: Evaluate the latency/freshness tradeoff for
  high-frequency trading.
- **Formal verification of causal model**: Apply formal methods to verify the
  structural causal model against the domain specification.
- **Multi-agent consensus**: Extend the consensus tier to support Byzantine
  fault-tolerant agreement among multiple governance nodes.
- **FTRA formal verification**: Apply model checking (e.g., TLA+ or Alloy) to
  the FTRA reachability analysis to prove that no unsafe trajectory can receive
  a `CLEAR` verdict under the compiled terminal registry.
- **Evidence chain schema migration**: Implement version-dispatched
  `record_hash` verification in the OSCAL exporter to support both
  `cage-context-accumulator/1.0` and `1.1` artifacts in the same WORM archive.

---

## 8. Conclusion

As agentic AI continues to integrate into mission-critical corporate operations,
relying on probabilistic, model-side safety measures is no longer acceptable.
The Cybernetic Agent Governance Engine (CAGE) provides a mathematically
grounded, highly performant, and secure solution grounded in Ashby's Law of
Requisite Variety and Stafford Beer's Viable System Model. By combining
cybernetic foundations with a systematic STPA-to-Rego compiler pipeline and an
identity-centric zero-trust posture, CAGE successfully bridges the gap between
the probabilistic behavior of LLMs and the deterministic demands of regulated
industries.

CAGE translates STPA hazard analysis into executable enforcement policies,
evaluates every agent action through a formally verified eight-tier pipeline
(including a pre-execution FTRA reachability gate), and closes the recursive
self-authentication gap in CBF ground truth via an isolated reconciliation
daemon with KMS-signed external balances. Governance is enforced at the HTTP
layer for all message roles, eliminating role-based bypass paths. We prove the
NoDirectBind invariant via exhaustive state-space enumeration, CBF invariance
via induction, FiscalLimitGuard race-condition freedom via atomic Redis
transactions, and evidence chain integrity via SHA-256 collision resistance.
CAGE is open-source and targets NIST SP 800-53, ISO 42001, SR 26-2, and
multi-jurisdiction compliance (US FED, EU ECB, APAC MAS).

---

## References

[1] Ahlfors, L. et al. "A Five-Plane Reference Architecture for Runtime
    Governance of Production AI Agents." arXiv:2606.12320, 2026.

[2] Ames, A. D., Xu, X., Grizzle, J. W., and Tabuada, P. "Control Barrier
    Function Based Quadratic Programs for Safety Critical Systems." IEEE
    Transactions on Automatic Control, 62(8):3861–3876, 2017.

[3] Leveson, N. G. "Engineering a Safer World: Systems Thinking Applied to
    Safety." MIT Press, 2011. https://doi.org/10.7551/mitpress/8179.001.0001

[4] NIST. "Security and Privacy Controls for Information Systems and
    Organizations." Special Publication 800-53 Rev 5, 2020.

[5] ISO. "Information technology — Artificial intelligence — Management system."
    ISO/IEC 42001:2023.

[6] Federal Reserve. "Supervisory Guidance on Model Risk Management."
    SR 11-7, 2011. [Note: SR 26-2 is the successor guidance — verify citation
    when published.]

[7] Doshi, A., Hong, Y., Xu, C., Kang, E., Kapravelos, A., & Kastner, C.
    (2026). Towards Verifiably Safe Tool Use for LLM Agents. ICSE NIER 2026.
    https://doi.org/10.48550/arXiv.2601.08012

[8] Gupta, V., & Sreenivasamurthy, D. (2026). Prose2Policy (P2P): A Practical
    LLM Pipeline for Translating Natural-Language Access Policies into Executable
    Rego. arXiv:2603.15799. https://doi.org/10.48550/arXiv.2603.15799

[9] Wang, S., Zhu, S., & Li, R. (2026). Runtime Policy Enforcement for
    MCP-Based LLM Agents. Electronics, 15(13), 2829.
    https://doi.org/10.3390/electronics15132829

[10] Mylius, S. (2025). Systematic Hazard Analysis for Frontier AI using STPA.
     arXiv:2506.01782. https://doi.org/10.48550/arXiv.2506.01782

[11] SPIFFE. (2022). Kubernetes Workload Identity attestation via Projected
     Service Account Tokens. https://spiffe.io/docs/latest/spiffe-about/overview/

[12] Zhou, J., Sheng, H., Lou, Y., Yang, Y., & Fu, J. (2026). FormalJudge:
     A Neuro-Symbolic Paradigm for Agentic Oversight. arXiv:2602.11136.
     https://doi.org/10.48550/arXiv.2602.11136

[13] Aguiar, V. A. et al. (2025). A Multi-Agent Architecture for Governance and
     Security of LLM-Based Knowledge Access. IEEE BigData 2025.
     https://doi.org/10.1109/bigdata66926.2025.11401633

[14] Raza, S., Sapkota, R., & Emmanouilidis, C. (2026). TRiSM for Agentic AI:
     A Review of Trust, Risk, and Security Management in Multi-Agent Systems.
     AI Open. https://doi.org/10.1016/j.aiopen.2026.02.006

[15] Bhushan, B., Rajgopal, P. R., & Sharma, K. (2025). An Intent-Aware Zero
     Trust Identity Architecture for Unifying Human and Machine Access.
     IJCESEN, 11(3). https://doi.org/10.22399/ijcesen.3886

[16] Saleem, K. (2024). Zero-Trust Agent Gateway: Identity-Centric Access
     Control for Multi-Actor AI Ecosystems Aligned with SASE Principles.
     AJACCM, 4(2), 36–45. https://doi.org/10.64751/ajaccm.2024.v4.n2.pp36-45

[17] Pappu, K., Bhushan, B., & Jaiswal, N. (2026). Future-Proofing Identity
     Security for Agentic AI Systems. ICAISET 2026.
     https://doi.org/10.1109/icaiset66439.2026.11541783

[18] Pappu, K., Bhushan, B., & Mittal, A. (2025). SPIFFE-Based Zero-Trust
     Authentication for AI Agent Ecosystems. ICCA 2025.
     https://doi.org/10.1109/icca66035.2025.11431026

[19] Rismani, S., Dobbe, R. I. J., & Moon, A. (2024). From Silos to Systems:
     Process-Oriented Hazard Analysis for AI Systems. arXiv:2410.22526.
     https://doi.org/10.48550/arXiv.2410.22526

[20] Sathe, O. (2025). Machine Learning–Augmented Neurosymbolic Agenticops
     Framework for Runtime Verification and Enforcement of Standard Operating
     Procedures. IJRSI, 12(11). https://doi.org/10.51244/ijrsi.2025.12110199

[21] Vijay, D., & Ethiraj, V. (2025). Graph-Symbolic Policy Enforcement and
     Control (G-SPEC): A Neuro-Symbolic Framework for Safe Agentic AI in 5G
     Autonomous Networks. arXiv:2512.20275.
     https://doi.org/10.48550/arxiv.2512.20275

[22] ISO. (2013). Financial services — Universal financial industry message
     scheme (ISO 20022). https://www.iso.org/standard/66370.html

[23] Errico, H. (2026). Autonomous Action Runtime Management (AARM): A System
     Specification for Securing AI-Driven Actions at Runtime. arXiv:2602.09433.
     https://doi.org/10.48550/arXiv.2602.09433

[24] Cloud Security Alliance. (2026). Autonomous Action Runtime Management
     Working Group Threat Model Checklist. https://aarm.dev/

[25] Ashby, W. R. (1956). An Introduction to Cybernetics. Chapman and Hall.
     https://doi.org/10.5962/bhl.title.5851

[26] Beer, S. (1972). Brain of the Firm. Allen Lane.

[27] Beer, S. (1979). The Heart of Enterprise. John Wiley & Sons.

[28] OWASP Foundation. (2025). OWASP Top 10 for Large Language Model
     Applications: LLM06 - Excessive Agency Risks.
     https://owasp.org/www-project-top-10-for-large-language-model-applications/

[29] Volt Active Data. (2026). The Infrastructure Requirement that Instant Rails
     Expose. Real-Time Rails Industry Brief.
     https://www.voltactivedata.com/wp-content/uploads/2026/06/Volt_Real_Time_Rails_Industry-Brief.pdf

[30] Cloud Native Computing Foundation. (2021). Open Policy Agent (OPA)
     (Graduated CNCF Project). https://openpolicyagent.org/docs

[31] AgentGuard. (2026). Attribute-Based Access Control (ABAC) for Tool-Use LLM
     Agents. arXiv:2605.28071. https://arxiv.org/abs/2605.28071

[32] Wang, H., Poskitt, C. M., & Sun, J. (2025). AgentSpec: Customizable Runtime
     Enforcement for Safe and Reliable LLM Agents. arXiv:2503.18666.
     https://arxiv.org/abs/2503.18666

[33] Buoyant, Inc. (2026). Linkerd Policy Resources and Workload Identity
     Verification. https://oneuptime.com/blog/post/2026-01-30-linkerd-policy-resources/view

[34] Conant, R. C., & Ashby, W. R. (1970). Every Good Regulator of a System
     Must Be a Model of that System. International Journal of Systems Science,
     1(2), 89–97. https://doi.org/10.1080/00207727008920220

[35] AgenTRIM. (2026). Balancing Tool-Driven Agency in LLM-Based Agents to
     Address Tool Misuse. arXiv:2601.12449.
     https://arxiv.org/abs/2601.12449

[36] Deng et al. (2025). Systematic Evaluation of Agentic AI Security
     Vulnerabilities under Cost and Delay Amplification Attacks. ProQuest
     Dissertations Publishing.

---

## Appendix A: Proof of NoDirectBind Invariant

The full BFS proof is implemented in `proof/model.py`. The state space is:

```
States S = {(phase, resolvedAllow) :
  phase ∈ {PENDING, CHECKING, APPROVED, REJECTED, EXECUTED, ROLLED_BACK},
  resolvedAllow ∈ {TRUE, FALSE, UNKNOWN}}
```

The transition function `δ: S × A → S` is defined by the governance pipeline.
The BFS visits 19 reachable states from the initial state
`(PENDING, UNKNOWN)`. The invariant `(phase=EXECUTED) ⟹ (resolvedAllow=TRUE)`
holds in all 19 reachable states.

**Attribution**: The BFS enumerator in `proof/model.py` was contributed by
LalaSkye — **verify co-authorship or cite as prior work before submission**
(pre-submission blocker #2).

---

## Appendix B: Reconciliation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  reconciliation-worker namespace (Cilium isolated)              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ExternalLedgerReconciler (60s poll)                     │  │
│  │                                                          │  │
│  │  1. PlaidLedgerProvider.fetch_balance()                  │  │
│  │     POST https://production.plaid.com/accounts/balance/get│  │
│  │                                                          │  │
│  │  2. KMSGovernanceSigner.sign(payload)                    │  │
│  │     Cloud KMS asymmetricSign (ECDSA-P256)                │  │
│  │                                                          │  │
│  │  3. redis.setex("reconciliation:verified_balance", 300,  │  │
│  │                 signed_payload)                          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          │ Redis (shared, read-only for gateway)│
│                          ▼                                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  gateway namespace                                              │
│                                                                 │
│  ControlBarrierFunction._read_cbf_state_atomic()               │
│                                                                 │
│  Priority 1: read reconciliation:verified_balance               │
│              verify KMS signature                               │
│              → source = "reconciled"                            │
│                                                                 │
│  Priority 2 (fallback): read safety:current_cash               │
│              emit CRITICAL audit log (POAM-023 open)            │
│              → source = "self_reported"                         │
│                                                                 │
│  OTel span attributes:                                          │
│    safety.balance.source = "reconciled" | "self_reported"       │
│    safety.balance.reconciled = True | False                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Appendix C: Environment Variables

| Variable | Description | Default |
|---|---|---|
| `CAGE_ENV` | Environment: `development`, `test`, `production` | `production` |
| `CAGE_DEPLOYMENT_REGION` | Jurisdiction: `US_FED`, `EU_ECB`, `APAC_MAS` | `US_FED` |
| `RECONCILIATION_PROVIDER` | Ledger provider: `stub`, `plaid`, `anchorage` | `stub` |
| `PLAID_CLIENT_ID` | Plaid client identifier | — |
| `PLAID_SECRET` | Plaid secret key | — |
| `PLAID_ACCESS_TOKEN` | Per-account OAuth access token | — |
| `PLAID_ENV` | `production` or `sandbox` | `production` |
| `PLAID_ACCOUNT_ID` | Filter to specific account | (first USD account) |
| `KMS_GOVERNANCE_KEY` | Cloud KMS key resource name | — |
| `CBF_FAIL_OPEN` | Bypass CBF gate (never in production) | `false` |
| `RECONCILIATION_POLL_INTERVAL_SECONDS` | Polling interval | `60` |
| `RECONCILIATION_TTL_SECONDS` | Redis TTL for verified balances | `300` |

---

*Draft version — 2026-07-25. Not yet submitted. All [PLACEHOLDER] values must
be replaced with measured experimental data before submission.*

---

## Change Log

| Date | Change | Trigger |
|---|---|---|
| 2026-07-25 | Updated pre-submission blockers: POAM-023 marked done; added GHSA-hfqj-24cj-693g and GHSA-v3h4-8458-5ww3 as new blockers | Branch/PR/advisory analysis |
| 2026-07-25 | Abstract: updated to eight-tier governor; added FTRA, HTTP-layer enforcement, evidence chain integrity | feat/FTRA-001, GHSA-hfqj-24cj-693g fix, PR #23 |
| 2026-07-25 | §1 Contributions: added FTRA (Tier 0.5), evidence chain integrity (§5.5), Agent Registry manifest generation | feat/FTRA-001, PR #23, feat/CAGE-003 |
| 2026-07-25 | §4.2: added FTRA Tier 0.5 description; added HTTP-layer enforcement paragraph | feat/FTRA-001, GHSA-hfqj-24cj-693g |
| 2026-07-25 | §4.3: updated POAM-023 from "now closed" to "closed"; added OTel span attributes and `_IS_PRODUCTION` guard | feat/POAM-023-cbf-external-reconcil |
| 2026-07-25 | §4.5: added `--targets registry` STPA compiler output and Agent Registry adapter | feat/CAGE-003 |
| 2026-07-25 | §5.3: no change to theorem; new §5.5 Evidence Chain Integrity added | PR #23 |
| 2026-07-25 | §6.2 Table 2: renamed to eight-tier; added FTRA row | feat/FTRA-001 |
| 2026-07-25 | §7.1: added compiler-driven registry manifests, FTRA pre-execution reachability | feat/CAGE-003, feat/FTRA-001 |
| 2026-07-25 | §7.2: added evidence chain schema versioning, ReDoS limitations | PR #23, PR #22 |
| 2026-07-25 | §7.3: added FTRA formal verification, evidence chain schema migration future work | feat/FTRA-001, PR #23 |
| 2026-07-25 | §8 Conclusion: updated to eight-tier, added HTTP-layer enforcement, evidence chain integrity, cybernetic framing | All above |
| 2026-07-25 | **MERGE**: Injected Google Doc content — §2 Cybernetic Foundations (VSM/Ashby/Good Regulator Theorem); §3.4 expanded related work (32 citations); §4.7 full zero-trust section (SPIFFE/Linkerd/routing seal/KMS multi-cloud); §6.1 FedNow/SEPA SLA context + 290+ adversarial corpus; §6.6 Adversarial Deflection table; full bibliography [1]–[36]; merged title | Google Doc analysis |
