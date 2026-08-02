# CAGE: A Neuro-Symbolic Architecture for Deterministic and Verifiable Governance of Agentic AI — From Hazard Analysis to Runtime Enforcement with Formal Safety Guarantees

**Draft for arxiv submission — cs.CR \+ cs.AI cross-list**

## Abstract

The rapid advancement of agentic AI systems built on non-deterministic Large Language Models (LLMs) presents significant challenges for safety, reliability, and regulatory compliance in high-stakes industries. We present the **Cybernetic Agent Governance Engine (CAGE)**, grounded in Ashby's Law of Requisite Variety and Stafford Beer's Viable System Model (VSM), which frames the governance problem as matching the immense variety of emergent LLM behaviors with a sufficiently rich, deterministic set of control states. CAGE is a compiler-driven runtime governance framework that translates System-Theoretic Process Analysis (STPA) hazard models into executable enforcement policies, then evaluates every agent action through an eight-tier symbolic governor (including a pre-execution Forward-Looking Trajectory Reachability Analyzer, FTRA) before execution is permitted. The governor combines discrete-time Control Barrier Functions (CBF), Open Policy Agent (OPA) Rego policies, causal intervention simulation, and human-in-the-loop escalation into a single, formally verified pipeline. Governance is enforced at the HTTP layer for all message roles, eliminating role-based bypass paths. We prove the **NoDirectBind invariant** — that no action can reach the EXECUTED state without passing all governance tiers — via exhaustive breadth-first search over 21 reachable automaton states. We further prove CBF invariance, FiscalLimitGuard race-condition freedom, Cloud KMS non-repudiation, and evidence chain integrity via cryptographic `record_hash` binding across the full NDJSON audit chain. To close a recursive self-authentication gap in the CBF (POAM-023), we design and implement an isolated reconciliation daemon that fetches externally attested balances from Plaid Production, signs them with Cloud KMS, and writes them to Redis with strict TTL; the CBF is built to prefer this signed external ground truth over the self-reported balance whenever it is present. We benchmark this mechanism against live Redis and Cloud KMS infrastructure and report its performance characteristics; as discussed in §5.4, deploying the daemon into the live serving path of the reference system is ongoing integration work, distinct from the design and implementation reported here. We evaluate CAGE against a corpus of 21 adversarial attacks across five attack categories and report governance latency, reconciliation write-path cost, and per-request CBF read overhead. CAGE is open-source at [https://github.com/google/cybernetic-agent-governance-engine](https://github.com/google/cybernetic-agent-governance-engine) and targets NIST SP 800-53, ISO 42001, SR 26-2, and multi-jurisdiction compliance (US FED, EU ECB, APAC MAS).

---

## 1\. Introduction

Autonomous AI agents that execute financial transactions introduce a class of safety and compliance risks that static policy frameworks cannot address. Unlike traditional software, agentic systems exhibit goal-directed persistence: they may pursue objectives across multiple tool calls, accumulate context across sessions, and generate novel action sequences not anticipated at design time. Existing governance approaches — prompt-level guardrails, post-hoc auditing, or manual review — are insufficient for high-frequency, low-latency financial execution.

The reference architecture of Tallam \[1\] identifies five enforcement planes (reasoning, network, identity, endpoint, data) and six interruption primitives for runtime governance of production AI agents. Their framework provides a conceptual taxonomy but does not specify how hazard analysis translates into enforcement code, how formal safety invariants are verified, or how the ground truth used by safety functions is protected from manipulation by the governed system itself.

We address these gaps with CAGE. Our contributions are:

1. **STPA compiler**: A tool that translates STPA Unsafe Control Actions (UCAs) into OPA Rego policies, NeMo Colang rails, and GEAP Agent Registry authorization manifests, eliminating the manual translation step that introduces policy drift.  
     
2. **Eight-tier symbolic governor**: A formally specified pipeline that evaluates every agent action through a pre-execution FTRA reachability gate (Tier 0.5), STPA validation, confidence scoring, CBF \+ OPA (parallel), FiscalLimitGuard, consensus, causal gatekeeper, and FRIA before execution. Governance is enforced at the HTTP layer for all message roles — not only `user`\-role messages — eliminating role-based bypass paths in the inference proxy.  
     
3. **Machine-verified NoDirectBind invariant**: Exhaustive BFS over 21 reachable automaton states proves that `(phase=EXECUTED) ⟹ (resolvedAllow=TRUE)` — no action can bypass the governance pipeline.  
     
4. **External balance reconciliation design (POAM-023)**: An isolated reconciliation daemon is designed and implemented to fetch KMS-signed external balances from Plaid Production, eliminating the recursive self-authentication vulnerability where the execution system writes its own balance to Redis and then uses that balance to pass the CBF check. A module-level `_IS_PRODUCTION` guard raises `RuntimeError` at startup if `RECONCILIATION_PROVIDER=stub` in production. As detailed in §5.4, the daemon is not yet wired into the live serving path of the reference deployment; this contribution should be read as a validated, benchmarked design pending deployment, not as an active production control.  
     
5. **Evidence chain integrity**: Every node in the NDJSON audit chain is bound into its `record_hash` via `SHA-256(prev_hash ‖ content_json ‖ control_id ‖ event_type ‖ node_index ‖ audit_id)`, ensuring that metadata fields cannot be altered post-hoc without invalidating the chain.  
     
6. **Multi-jurisdiction compliance**: A single `CAGE_DEPLOYMENT_REGION` environment variable gates data paths, telemetry sinks, and control implementations for US FED (NIST SP 800-53), EU ECB (GDPR / SR 26-2), and APAC MAS (MAS Notice 655).

---

## 2\. Cybernetic Foundations

A fundamental challenge in agentic AI governance is controlling a system whose output space is practically infinite. Natural language reasoning and open-ended tool environments generate high "variety" in the cybernetic sense — the number of possible states a system can occupy. To address this, CAGE draws upon classical cybernetics and systems engineering as its theoretical grounding.

### 2.1 Ashby's Law of Requisite Variety

Ashby's Law states that "only variety can destroy variety" \[25\]. If an LLM-based agent possesses an enormous variety of potentially unsafe emergent behaviors, the governance engine must match this variety with a sufficiently rich, deterministic set of control states. CAGE accomplishes this by mapping fine-grained safety boundaries to a multi-tiered, deterministic policy enforcement runtime. By translating specific, complex hazard scenarios into modular, machine-readable rules, CAGE provides a matching regulatory variety that guarantees deterministic safety bounds regardless of the LLM's non-deterministic reasoning steps.

### 2.2 Stafford Beer's Viable System Model (VSM)

CAGE conceptualizes the agentic ecosystem through Stafford Beer's Viable System Model (VSM) \[26, 27\] to ensure systemic viability and compliance:

- **System 1 (Operation)**: Represented by the reasoning plane (the "Plant"), which executes the primary tasks and proposes tool actions.  
- **System 2 (Coordination)**: Managed by the outer gateway layer, preventing oscillatory behaviors, repetitive actions, and conflicting commands across multi-agent workflows.  
- **System 3 (Control/Execution)**: Enforced by the SymbolicGovernor, which synchronously intercepts and evaluates proposed actions against hard security limits.  
- **System 4 (Intelligence/Adaptation)**: Represented by the STPA compiler and OSCAL exporter, which translate environmental hazard analysis into updated policy artifacts. A fully adaptive, self-healing policy-adjustment loop is tracked as future work (§7.3); the current implementation uses statically compiled policies regenerated on each CI run.  
- **System 5 (Policy)**: Formulated by the enterprise-defined STPA safety requirements, establishing the absolute boundary of acceptable behavior.

### 2.3 The Controller-Plant Separation

CAGE maintains a strict physical and logical separation between the agent reasoning plane (the "Plant") and the hybrid neuro-symbolic governance plane (the "Controller" or SymbolicGovernor). This design pattern is mathematically grounded in the Good Regulator Theorem \[34\], which dictates that any optimal controller must contain a structural model of the system being controlled.

Rather than embedding safety guardrails inside the agent's prompt — which are easily bypassed via jailbreaks or prompt injections — the Controller acts as an external, untrusted gateway. When the Plant proposes a tool invocation, it cannot execute it directly. Instead, it must send a structured payload to the Controller. The Controller evaluates the request against compiled policies and only returns the necessary credentials or permits execution upon successful verification.

---

## 3\. Background and Related Work

### 3.1 Five-Plane Reference Architecture

Tallam \[1\] propose a five-plane architecture for runtime governance: a reasoning plane that monitors agent cognition, and four enforcement planes (network, identity, endpoint, data) that implement interruption primitives. They identify six primitives: BLOCK, DEFER, REDACT, AUDIT, ESCALATE, and TERMINATE. Their correctness invariants include completeness (all actions pass through at least one enforcement plane), non-circumventability (no action bypasses enforcement), auditability (all decisions are logged), and recoverability (blocked actions can be replayed after human review).

CAGE implements all six primitives and satisfies all four invariants. BLOCK and DEFER map to the governor's DENY and HITL escalation paths. REDACT maps to `inference_proxy.py`'s `scrub_pii()` function, which masks PII before the payload reaches the agent. TERMINATE maps to the `dge_action: TERMINATED_WITH_ROLLBACK` verdict emitted by the governor when a saga compensating action is triggered. AUDIT and ESCALATE map to the NDJSON audit chain and the `DeferQueue` HITL path respectively. Table 1 maps the five-plane taxonomy to CAGE subsystems.

**Table 1: Five-Plane to CAGE Mapping**

| Plane | CAGE Subsystem |
| :---- | :---- |
| Reasoning | SymbolicGovernor (8-tier pipeline) + ConfabulationScorer (a non-blocking AI 600-1 §2.1 scorer that evaluates response faithfulness via Langfuse and emits a `confabulation_score` OTel attribute; it does not gate execution) |
| Network | Kubernetes `NetworkPolicy` L3/L4 default-deny (`deployment/k8s/network-policy.yaml`, live in the reference GKE deployment); a Cilium CNI L7 FQDN-egress design exists (`deployment/k8s/cilium-egress-lockdown.yaml`) but is not installed by the automated deployment pipeline — see §4.7 and §7.2 |
| Identity | Cloud KMS asymmetric signing \+ Workload Identity |
| Endpoint | OPA Rego policies \+ NeMo Colang rails |
| Data | CBF (Redis-backed) \+ FiscalLimitGuard \+ ContextAccumulator |

### 3.2 Control Barrier Functions for Safety

Discrete-time CBFs \[2\] provide a formal mechanism for enforcing safety constraints on dynamical systems. For a safety function `h: S → ℝ`, the CBF condition requires:

h(S(t+1)) ≥ (1 − γ) · h(S(t))   for all t, γ ∈ (0, 1\)

This ensures the system remains in the safe set `{s : h(s) ≥ 0}` for all future time steps. Prior work applies CBFs to robotic systems \[37\] and autonomous vehicles \[38\]; we apply them to financial agent governance.

### 3.3 STPA for AI Systems

System-Theoretic Process Analysis \[3\] identifies Unsafe Control Actions (UCAs) — control actions that are unsafe given the system context. Prior work applies STPA to autonomous vehicles \[39\] and medical devices \[40\]. Mylius \[10\] confirms that STPA dramatically improves traceability, exposes complex causal factors missed by unstructured hazard analysis, and adapts naturally to AI systems with minimal domain-specific tailoring. We apply STPA to AI agent governance and introduce a compiler that translates UCAs into executable enforcement policies, guided by the Process-oriented Hazard Analysis for AI Systems (PHASE) methodology \[19\].

### 3.4 Related Work and Positioning

The CAGE framework operates at the intersection of neuro-symbolic AI oversight, runtime verification, and distributed systems security.

**FormalJudge** \[12\] is highly effective for proof-oriented, post-hoc oversight of agent trajectories, enabling rigorous offline verification of agent reasoning pathways. However, it lacks the synchronous, deterministic execution constraints needed for active runtime enforcement. CAGE, by contrast, operates inline as a synchronous runtime governor, blocking unsafe actions before they reach the execution plane.

**G-SPEC and LogicGuard** \[21\] support the broader case that deterministic, symbolic validation layers can materially improve safety in complex systems such as 5G autonomous networks. CAGE extends this paradigm by integrating symbolic validation directly with a comprehensive, enterprise-grade zero-trust identity fabric.

**AgentSpec** \[32\] provides a lightweight, trigger-predicate-enforcement DSL that achieves robust runtime safety, but operates primarily on agent-level event streams rather than concrete wire-protocol schemas. CAGE integrates event-driven predicate validation with OPA and continuous barrier functions to capture dynamic, physical and digital state deviations.

**AgenTRIM** \[35\] similarly addresses tool misuse in LLM agents, while adversarial evaluation studies \[36\] confirm the attack surface that CAGE's deflection pipeline targets.

**Multi-agent governance architectures** \[13\] and **neurosymbolic runtime verification frameworks** \[20\] further validate the need for deterministic enforcement layers. Zero-trust identity frameworks for agentic AI \[14, 15, 16, 17, 18\] confirm that boundary-based perimeter controls are inadequate for multi-service and multi-agent systems, motivating CAGE's identity-centric posture.

**AARM-V3** \[23, 24\] catalogues the Confused Deputy attack class that CAGE's routing seal and zero-trust controls directly neutralize.

**STPA for frontier AI systems** \[41\] extends STPA-based hazard analysis to general-purpose frontier models, corroborating our application of the same methodology to agentic financial governance in §3.3 and §4.5, though that work stops at hazard identification rather than compiling UCAs directly into executable enforcement artifacts. **Verifiably safe tool use** \[7\] similarly targets pre-execution safety verification for LLM agent tool calls; CAGE's FTRA reachability gate (Tier 0.5) addresses an analogous class of problem — verifying an entire proposed trajectory before execution — but does so via graph reachability over a compiled `ExecutionPlan` rather than per-call formal verification of tool arguments. **Proactive probabilistic enforcement** \[42\] shares FTRA's pre-execution orientation, using probabilistic model checking to estimate the likelihood of unsafe trajectories before they are taken; FTRA instead makes a deterministic CLEAR/HITL_REQUIRED/BLOCKED classification based on reachability of an irreversible terminal step, trading probabilistic nuance for the fail-closed determinism required by CAGE's regulatory posture. **Cryptographic route-origin authorization for agent actions** \[43\] independently motivates the same class of mechanism as CAGE's HMAC routing seal (§4.7) — binding a governance decision cryptographically to the specific action it authorizes to prevent a Confused Deputy substitution — though CAGE's seal is a short-TTL symmetric token scoped to a single synchronous request rather than a persistent route-authorization credential. **Control barrier functions under sensor attacks** \[44\] formalizes exactly the state-spoofing threat that motivates CAGE's external reconciliation daemon (§4.3, §5.4): an adversary that can manipulate the CBF's input state can render the barrier certificate vacuous regardless of the correctness of the barrier function itself, which is the precise vulnerability (POAM-023) the reconciliation mechanism is designed to close. **Access-control policy generation from natural language** \[8\] and **runtime policy enforcement for MCP-based agents** \[9\] both target machine-generated enforcement policy, paralleling CAGE's STPA compiler (§4.5) — Prose2Policy \[8\] generates Rego from natural-language access policies via an LLM pipeline, whereas CAGE's compiler is a deterministic, template-based generator with no LLM in the translation path, trading Prose2Policy's input flexibility for a translation process that cannot itself introduce non-deterministic drift. **Excessive agency risk** \[28\] and **attribute-based access control for tool-use agents** \[31\] frame the general class of unauthorized tool-invocation risk that CAGE's OPA Rego authorization layer (Tier 3b) and Agent Registry manifest (§4.5) are designed to constrain at the individual tool-call level.

---

## 4\. System Architecture

### 4.1 Overview

CAGE consists of four subsystems:

1. **STPA Compiler** (`src/gateway/governance/stpa_compiler.py`): Translates STPA UCAs into OPA Rego policies and NeMo Colang rails.  
     
2. **Eight-Tier Symbolic Governor** (`src/gateway/governance/symbolic_governor.py`): Evaluates every agent action through a sequential pipeline before execution.  
     
3. **Compliance Bridge** (`src/compliance_bridge/`): Reconciliation daemon, OSCAL exporter, Lula validator, and audit workflow.  
     
4. **Governed Financial Advisor** (`src/governed_financial_advisor/`): Reference application demonstrating CAGE integration with a LangGraph agent.

### 4.2 Eight-Tier Symbolic Governor

The governor evaluates every agent action through eight tiers in sequence (Tiers 1–7 within `_run_checks()`, plus Tier 0.5 at the LangGraph graph level):

**Tier 0.5 — FTRA (Forward-Looking Trajectory Reachability Analyzer)**: Before the first LangGraph node fires, the FTRA builds a NetworkX directed graph from `ExecutionPlan.steps`, classifies each reachable action against the compiled terminal registry, and issues one of three verdicts: `CLEAR` (proceed to OPA safety gate), `HITL_REQUIRED` (park in `DeferQueue` \+ `NodeInterrupt`), or `BLOCKED` (route to explainer; plan cannot proceed). This pre-execution gate catches unsafe trajectories before any tool call is made. **Architectural assumption:** FTRA assumes a plan-and-execute agent architecture where a complete multi-step trajectory is formulated prior to any execution. For agent architectures that dynamically or reactively resolve future tool calls based on intermediate environment observations, FTRA operates on the plan available at commencement time and applies a fail-closed default (`BLOCKED`) when the plan is incomplete or absent.

**HTTP-layer enforcement**: Governance is applied at the HTTP layer for all message roles (`user`, `system`, `assistant`). The inference proxy enforces input governance — HTTP-layer keyword scan, token/step quota, and NeMo input rails — regardless of whether a `user`\-role message is present, and applies output filtering for all response paths including `stream: true`. This eliminates the role-based bypass path identified in GHSA-hfqj-24cj-693g.

**Tier 1 — STPA Validation**: Checks the action against compiled UCAs. If the action matches a UCA pattern, it is blocked with a structured violation record.

**Tier 2 — Confidence Scoring**: Evaluates the agent's confidence in the action. The confidence score is a field in the action payload (`params["confidence"]`), expected to be set by the agent's reasoning layer before submitting the action for governance. The SLM sidecar that previously computed an independent confidence score has been deprecated to reduce latency; the OPA policy (`system_authz.rego`) enforces a higher threshold (0.97 vs. 0.95) when the `slm_available: false` sentinel is present. Actions below the threshold (default: 0.95) are escalated to HITL.

**Tier 3 — CBF \+ OPA (parallel)**: Evaluates the discrete-time CBF condition and OPA Rego policies \[30\] concurrently. Either can block the action.

**Tier 4 — FiscalLimitGuard**: Enforces daily spending caps with atomic WATCH/MULTI/EXEC Redis transactions, preventing TOCTOU races under concurrent agent execution.

**Tier 5 — Consensus**: For actions above `THRESHOLDS.consensus.threshold_usd`, two critic personas ("Risk Manager" and "Compliance Officer") are consulted in parallel via `asyncio.gather()`, each routed by the `ConsensusModelRegistry` to a distinct model backend (by default, the existing split-brain infrastructure: Risk Manager → the reasoning vLLM pool running DeepSeek-R1; Compliance Officer → the fast vLLM pool running Llama 3.1) so that consensus reflects genuine algorithmic diversity rather than one model voting with itself under different prompts. Each critic returns `APPROVE`, `REJECT`, `ESCALATE`, or (on a 10 s timeout or exception) `ERROR`. Aggregation is not simple majority: unanimous `APPROVE` passes the gate; unanimous `REJECT` with no `ERROR` votes blocks the trade; any split between `APPROVE` and `REJECT`, any `ESCALATE` vote, or a "degraded quorum" (one critic `ERROR`, the remaining critic `REJECT`) routes to human review via `ESCALATE` rather than resolving automatically; and a unanimous `ERROR` (e.g. both backends unreachable) also escalates rather than fail-open-approving, so a denial-of-service against both critic backends cannot bypass the gate. All results — including the raw per-critic votes — are pushed to a non-blocking background queue for post-hoc audit logging.

**Tier 6 — DoWhy Causal Gatekeeper**: Constructs a fixed structural causal graph — `market_volatility → trade_amount`, `market_volatility → risk_score`, `trade_amount → risk_score`, with `trade_amount` as the DoWhy treatment variable and `risk_score` as the outcome — and estimates the treatment effect via `backdoor.linear_regression`. The estimate is validated against live Langfuse telemetry (fail-closed if older than `TELEMETRY_MAX_STALENESS_SECONDS`, default 300 s) using a `PlaceboTreatmentRefuter` with 50 simulations; the gate locks (blocks the trade) if the refuter's p-value falls below 0.05 or its placebo effect magnitude exceeds 0.2, indicating the world-model's causal assumptions cannot be trusted. If both checks pass, the gate additionally blocks when the predicted marginal risk `(0.5 + estimate.value × amount)` exceeds a `CAUSAL_LOCK_RISK_BOUNDARY` of 0.95 — the same quantity reported as "high marginal risk" above. Results are cached in Redis for `CAUSAL_CACHE_TTL_SECONDS` (default 60 s), keyed on `(action_type, market_regime)`.

**Tier 7 — FRIA**: Financial Risk Impact Assessment. Classifies the action into risk zones and applies zone-specific controls.

### 4.3 Control Barrier Function

The CBF enforces the financial safety invariant:

h(S(t)) \= cash\_balance(t) − min\_cash\_balance

The CBF condition requires:

h(S(t+1)) ≥ (1 − γ) · h(S(t))

where `γ` is configurable via `THRESHOLDS.cbf.gamma` in `config/governance_thresholds.json` (default: 0.5 in the reference configuration). An action is safe if and only if the post-action balance satisfies this condition.

**POAM-023 gap (design and code complete; deployment pending — see §5.4)**: Prior to this work, the CBF read `safety:current_cash` from Redis — a value written by the execution system itself. This creates a recursive self-authentication vulnerability: the execution system could write an inflated balance, pass the CBF check, then execute a trade that violates the true safety constraint.

**Closure**: We implement an isolated reconciliation daemon (`src/compliance_bridge/reconciliation_worker.py`) that:

1. Is designed to run in a dedicated Kubernetes namespace with a Cilium network policy preventing it from communicating with the gateway or financial-advisor pods — this network-level isolation is a documented deployment design (see Appendix B) and is not yet expressed as a committed Cilium manifest; the reconciliation daemon currently runs as a Python module (`src/compliance_bridge/reconciliation_worker.py`) without a dedicated namespace or NetworkPolicy in the current deployment configuration.  
2. Fetches the real account balance from Plaid Production via `POST /accounts/balance/get`.  
3. Signs the balance payload with Cloud KMS (`asymmetricSign`).  
4. Writes the signed balance to `reconciliation:verified_balance` in Redis with a 300-second TTL.

The CBF reads `reconciliation:verified_balance` first. In production (`CAGE_ENV` not one of `development|test|dev|ci`), if the key is absent (TTL expired), the KMS signature is invalid, or the balance is unsigned, `_read_cbf_state_atomic()` raises `CBFStateUnverifiedError` rather than falling back to the self-reported balance; the pre-existing fail-closed exception handling around the CBF call in `SymbolicGovernor` treats this as an automatic DENY. This closes a gap in an earlier version of the reconciliation guard, in which all four degraded-reconciliation cases (absence, TTL expiry, invalid signature, and unsigned-in-production) fell back to the self-reported `safety:current_cash` balance with only a `CRITICAL` audit log — silently reopening the self-authentication vulnerability whenever reconciliation was delayed or misconfigured. The self-reported fallback remains available only in non-production postures, to preserve local development ergonomics without a live Plaid/KMS connection. Every CBF span carries OTel attributes `safety.balance.source` (`"reconciled"`, `"reconciled_unsigned"`, or `"self_reported"`) and `safety.balance.reconciled` (`True`/`False`) for full balance provenance auditability.

A module-level `_IS_PRODUCTION` constant in `cbf.py` (patchable in tests) gates both this fail-closed guard and a separate production guard: if `CAGE_ENV=production` and `RECONCILIATION_PROVIDER=stub`, the reconciliation worker raises `RuntimeError` at startup, preventing accidental deployment without live reconciliation.

### 4.4 NoDirectBind Invariant

**Definition**: A state is a tuple `(phase, tier_results, seal_present, resolvedAllow)` where `phase ∈ {PENDING, CHECKING, SEAL_ISSUED, EXECUTED, DENIED}`; `tier_results` is an 8-tuple recording each governance tier within `_run_checks()` (`stpa, confidence, cbf, opa, fiscal, consensus, causal, fria`) as `PENDING | PASS | FAIL`. Tier 0.5 (FTRA) is not included in this tuple because it executes at the LangGraph graph level before `_run_checks()` is invoked; its verdict (`CLEAR | HITL_REQUIRED | BLOCKED`) is recorded separately in the LangGraph state; `seal_present ∈ {TRUE, FALSE}` records whether a routing seal has been issued; and `resolvedAllow ∈ {TRUE, FALSE}` is TRUE only once every tier has resolved to `PASS` and a seal has been issued. The NoDirectBind invariant states:

∀ states s: (s.phase \= EXECUTED) ⟹ (s.resolvedAllow \= TRUE)

**Proof**: We enumerate all reachable states via BFS from the initial state `(PENDING, all tiers PENDING, seal_present=FALSE, resolvedAllow=FALSE)` using the gated transition function `gated_transitions()` defined in `proof/model.py`, which mirrors `SymbolicGovernor._run_checks()`: from `CHECKING`, each of the 8 tiers within `_run_checks()` resolves to `PASS` or `FAIL` in sequence; any `FAIL` moves immediately to `DENIED` (fail-closed); once all 8 tiers have resolved to `PASS`, a routing seal is issued and the state moves to `SEAL_ISSUED` with `resolvedAllow=TRUE`; `SEAL_ISSUED` then transitions to either `EXECUTED` (valid seal) or `DENIED` (invalid/expired seal). The BFS visits 21 reachable states, of which exactly 1 has `phase=EXECUTED`, and that state has `resolvedAllow=TRUE, seal_present=TRUE`. The state `(phase=EXECUTED, resolvedAllow=FALSE)` is unreachable under `gated_transitions()`. ∎

**Parallelism note:** The formal model treats tier evaluation as sequential for the purpose of the NoDirectBind invariant — the invariant concerns reachability of the `EXECUTED` state, not the order in which tiers evaluate. In the runtime implementation, Tier 3 (CBF + OPA) evaluates concurrently via `asyncio.gather()` (`symbolic_governor.py:324`); the invariant holds because both results are collected before any transition to `SEAL_ISSUED` is permitted. `proof/model.py`'s `concurrent_tier_transitions()` sub-proof explores both CBF/OPA interleavings (24 reachable states, a strict superset of the 21-state sequential model) and confirms the invariant holds under every ordering.

The proof is machine-verified: `proof/model.py` implements the BFS enumerator and asserts the invariant over all reachable states (run `python proof/model.py` to reproduce; see Appendix A for the additional sub-proofs it checks). The proof runs in O(|S|) time where |S| = 21\. As a negative control, `proof/model.py` also defines `ungated_transitions()`, an intentionally unsafe variant that transitions directly from `CHECKING` to `EXECUTED` once all tiers pass, without requiring a seal. This variant has 19 reachable states and produces an explicit counterexample — `(phase=EXECUTED, resolvedAllow=FALSE, seal_present=FALSE)` — confirming the seal-issuance gate in the real transition function is load-bearing rather than a vacuous check.

### 4.5 STPA Compiler

The STPA compiler (`src/gateway/governance/stpa_compiler.py`) translates UCAs into enforcement policies:

UCA → OPA Rego rule (structural policy)

UCA → NeMo Colang rail (conversational guardrail)

UCA → STPA validator check (runtime assertion)

UCA → Agent Registry authorization manifest (--targets registry)

The `--targets registry` flag emits a tool-authorization JSON manifest from the STPA YAML, which the GEAP Agent Registry adapter (`src/gateway/governance/agent_registry_adapter.py`) pushes to OPA via `PUT /v1/data/agent_catalog_data` at boot and on a background poll. This extends OSCAL AC-3 (Access Enforcement) evidence to cover agent-level tool authorization, not only human-level access control.

The compiler is a deterministic, template-based code generator (no LLM involvement). It ingests `config/stpa_control_structure.yaml`, validates it against a Pydantic schema (`ControlStructureModel`), and generates artifacts via per-target template functions: `generate_opa()` emits Rego rules by mapping each UCA's `condition` (operator, parameter, threshold) to a Rego predicate; `generate_nemo()` emits Colang 2.x flow definitions from `nemo_rail` fields; `generate_python()` emits a `GeneratedSTPAValidator` class with one check method per UCA; `generate_langgraph()` emits Write-Ahead Log forward nodes and idempotent compensating nodes from `langgraph_saga` fields. The compiler is invoked as `python -m src.gateway.governance.stpa_compiler compile`.

The compiler eliminates the manual translation step that introduces policy drift between the hazard model and the enforcement code. The generated validator (`src/gateway/governance/generated_stpa_validator.py`) is regenerated from the STPA source on every CI run; a freshness check (`scripts/check_stpa_freshness.py`) fails the build if the generated code is stale.

### 4.6 Multi-Jurisdiction Compliance

CAGE deploys simultaneously to three regulatory jurisdictions via `CAGE_DEPLOYMENT_REGION`:

- **US\_FED**: NIST SP 800-53 Rev 5 \[4\], FedRAMP High, SR 11-7 / SR 26-2 \[6\] Model Risk Management. ISO/IEC 42001:2023 \[5\] AI management system controls apply across all jurisdictions. Data paths within `us-central1`.  
- **EU\_ECB**: GDPR, SR 26-2 (no legal force sentinel suppresses telemetry lacking legal basis). Data paths within `europe-west1`.  
- **APAC\_MAS**: MAS Notice 655\. Data paths within `asia-southeast1`.

Every new storage path, GCS write, Langfuse sink, or telemetry export in shared modules (`src/gateway/governance/` and `src/compliance_bridge/`) must be gated on `CAGE_DEPLOYMENT_REGION`.

### 4.7 Zero-Trust Security Controls

A critical vulnerability in distributed multi-agent systems is the "direct-bind shortcut" \[23\] — when an agent, under the influence of an adversarial attack or unexpected emergent state, attempts to bypass the governance plane to bind directly with raw system tools or databases. Boundary-based perimeter controls are consistently inadequate for multi-service and multi-agent systems \[14, 15, 16, 17, 18\]. CAGE mitigates this risk by enforcing an identity-centric, zero-trust architecture at each request boundary.

**Fail-Safe Startup Assertions**: The SymbolicGovernor enforces module-level startup assertions that raise a `RuntimeError` at import time under two conditions: (1) `CBF_FAIL_OPEN=true` in a production environment — this removes the cash-barrier tier from the governance gate; (2) the `dowhy` library is absent or fails to import in production — this raises a `RuntimeError` at import time, preventing the service from starting at all. These checks run before the gateway begins accepting traffic, ensuring the service fails fast rather than surfacing gaps on the first live request. (Note: the phrase 'silently removes' in an earlier draft was a contradiction — a `RuntimeError` at startup is not silent; the service halts before accepting any traffic.)

**Cluster-Level Mesh Microsegmentation (design; not automated in the current deployment pipeline)**: CAGE treats the underlying network as hostile, and provides committed Kubernetes manifests for workload identity and mutual TLS (mTLS) via Linkerd \[33\] (`deployment/k8s/linkerd-mtls-policy.yaml`) and Layer-7 FQDN egress lockdown via Cilium (`deployment/k8s/cilium-egress-lockdown.yaml`). When the Linkerd control plane and Cilium CNI are installed on the target cluster, Linkerd automatically intercepts TCP traffic and performs bidirectional validation using SPIFFE-verifiable identity documents (SVIDs) \[11\] mapped to Kubernetes ServiceAccounts, matching the standard format `spiffe://cluster.local/ns/<namespace>/sa/<service-account>`. **Neither installation step is currently automated**: `deploy_all.sh` and the Terraform modules under `infra/` provision a standard GKE cluster with the native `network_policy { enabled = true }` block (GKE's built-in L3/L4 NetworkPolicy provider, not Cilium), and contain no `linkerd install` or `cilium install` step. The manifests therefore express a validated *design* for mesh microsegmentation and L7 egress control, not a control that is active by default on a freshly provisioned cluster; an operator must run the documented prerequisite commands (`linkerd install | kubectl apply -f -`; `cilium install --set l7Proxy=true`) out-of-band before applying `linkerd-mtls-policy.yaml` and `cilium-egress-lockdown.yaml`. Automating this installation step is tracked in §7.3.

**Continuous Verification**: Unlike static access controls that verify credentials once at session initiation, CAGE performs continuous, intent-aware verification \[17, 15\]. This is essential for agentic environments because agents can dynamically spawn subagents and change execution intents at runtime, necessitating constant re-evaluation of security postures.
**Runtime Routing Seal**: Once all checks inside `_run_checks()` return zero violations, `routing_seal.py` generates an ephemeral symmetric routing token formatted as `<expire_ts_hex>.<action_slug>.<hmac_hex>` using HMAC-SHA256 keyed by a high-entropy `GOVERNANCE_SALT`. The seal lifetime is 30 seconds (configurable via `GOVERNANCE_SEAL_TTL_S`). The `require_cleared_seal` decorator provides strict enforcement: it calls `verify_seal()` and raises a `SymbolicGovernorViolation` before the wrapped callable is invoked, making it impossible for callers to silently ignore a failed verification. This design directly eliminates the Confused Deputy class of attacks catalogued in AARM-V3 \[23, 24\].

**Asymmetric Plan Attestation**: To prevent tampering with static policy manifests deployed across federated clusters, CAGE implements asymmetric signature validation inside `kms_signer.py`. Manifests are cryptographically signed and validated using Key Management Services across three cloud providers: GCP Cloud KMS, AWS KMS (ECDSA\_SHA\_256), and Azure Key Vault (ES256). For GCP, the governor performs verification against the configured public key using EC-DSA (SHA-256 prehashed) with RSA-PSS as a fallback, supporting both key families transparently.

---

## 5\. Formal Safety Properties

### 5.1 CBF Invariance Theorem

**Theorem**: If the CBF condition is satisfied at time `t`, and the reconciliation daemon provides a valid external balance, then the cash balance remains in the safe set for all future time steps.

**Formal statement**:

∀ t ≥ 0: h(S(t)) ≥ 0 ∧ verify\_action(a, S(t)) \= "SAFE"

  ⟹ h(S(t+1)) ≥ (1 − γ) · h(S(t)) ≥ 0

**Proof:**

*Base case (t = 0):* The system is initialized with `cash_balance(0) = 100,000` and `min_cash_balance` from `THRESHOLDS.cbf.min_cash_balance` (default: 1,000 per `config/governance_thresholds.json`). The operator is responsible for ensuring `h(S(0)) ≥ 0` at deployment; the CBF `setup()` method bootstraps this value.

*Inductive step:* Assume `h(S(t)) ≥ 0`. By definition of `verify_action()` in `cbf.py`, the action is blocked if and only if `h(S(t+1)) < (1 − γ) · h(S(t))` or `h(S(t+1)) < 0`. Therefore, if `verify_action()` returns `"SAFE"`, both conditions hold: `h(S(t+1)) ≥ (1 − γ) · h(S(t))` and `h(S(t+1)) ≥ 0`. Since `γ ∈ (0, 1)` and `h(S(t)) ≥ 0`, we have `h(S(t+1)) ≥ 0`. By induction, `h(S(t)) ≥ 0` for all `t ≥ 0`. ∎

*Rejection branch:* If `verify_action()` returns a violation string, the action is blocked before execution; `S(t+1) = S(t)` and `h(S(t+1)) = h(S(t)) ≥ 0`.

**Premises and limitations:** This theorem assumes (1) `h(S(0)) ≥ 0` at initialization; (2) the reconciliation daemon provides a valid KMS-signed balance (§4.3, §5.4) — if the daemon is absent, the CBF raises `CBFStateUnverifiedError` in production (fail-closed); (3) `verify_action()` and trade execution are atomic — this is not currently guaranteed (see §5.2 TOCTOU note and §7.2).

**TOCTOU limitation:** `verify_action()` is read-only; `atomic_verify_and_commit()` is implemented in `cbf.py` but is not yet wired into the live request-handling pipeline. Under concurrent agent execution, two agents can both pass the CBF check against the same pre-action balance and jointly overdraw. The FiscalLimitGuard's atomic reservation (§5.2) mitigates this at the daily-cap level but not at the per-trade CBF level. Wiring `atomic_verify_and_commit()` into the serving path is tracked as future work (§7.3).

### 5.2 FiscalLimitGuard Race-Condition Freedom

**Theorem**: Under concurrent execution of `n` agents, the total committed spend never exceeds the daily cap `C`.

**Proof**: `FiscalLimitGuard.reserve()` (`src/gateway/governance/fiscal_limit_guard.py`) implements a Redis WATCH/MULTI/EXEC optimistic-locking transaction: it `WATCH`es the daily-spend key, reads the current committed total, computes `current + requested_amount`, and only commits the increment via `MULTI/EXEC` if the requested amount would not exceed the cap `C`. If a concurrent writer modifies the watched key between the `WATCH` and the `EXEC`, Redis aborts the transaction (`WatchError`) and the guard retries up to `_MAX_RETRIES = 5` times before raising. Because the check ("would this reservation exceed `C`?") and the commit (incrementing the daily total) occur inside the same optimistic-locking transaction, no two concurrent agents can both observe a pre-reservation total that admits their request and then both successfully commit reservations that jointly exceed `C` — one of the two `EXEC` calls will observe the other's committed write and abort. Reservations are released via a symmetric `WATCH/MULTI/EXEC` decrement (`release()`) on any downstream failure, so a rejected or rolled-back trade does not permanently consume budget. This mechanism enforces the fiscal cap; it is independent of the CBF's own per-trade cash-barrier check (§4.3, §5.1), and does not use the Lua-atomic `atomic_verify_and_commit()` path in `cbf.py`, which is not invoked anywhere in the current request-handling pipeline (`SymbolicGovernor` calls `verify_action()`, not `atomic_verify_and_commit()`) and is documented for future use pending integration with the reconciled-balance read path. ∎

### 5.3 Routing Seal Authenticity and Reconciliation Non-Repudiation

**Theorem (Routing Seal Authenticity):** Every governance approval is attested by an ephemeral HMAC-SHA256 routing seal that cannot be forged without access to the `GOVERNANCE_SALT` secret.

**Proof (routing seal):** The routing seal is generated by `generate_seal()` in `routing_seal.py` as `HMAC-SHA256(GOVERNANCE_SALT, expire_hex || action_slug || canonical_payload)`. HMAC-SHA256 is existentially unforgeable under chosen-message attack (EUF-CMA) when the key is secret. The seal provides *authenticity* — any party holding `GOVERNANCE_SALT` can verify it — but not *non-repudiation*, since the key is shared between the gateway (issuer) and the actuator (verifier). The 30-second TTL prevents replay attacks. ∎

**Theorem (Reconciliation Non-Repudiation):** Every reconciliation balance payload is non-repudiably attested by a Cloud KMS ECDSA-P256 asymmetric signature.

**Proof (reconciliation attestation):** The reconciliation daemon signs balance payloads with Cloud KMS ECDSA-P256 (`asymmetricSign`). Cloud KMS uses FIPS 140-2 Level 3 HSMs; the private key never leaves the HSM. This signature provides non-repudiation: only the KMS key holder can produce a valid signature, and any party with the public key can verify it. The CBF verifies this signature before trusting the reconciled balance (§4.3).

**Scope clarification:** The routing seal (HMAC) attests governance *approval* on the synchronous request path (Table 2, sub-ms latency). The KMS signature (ECDSA-P256) attests balance *provenance* on the background reconciliation path (Table 3, 108.3 ms P50). These are distinct mechanisms on distinct paths; the KMS latency does not appear in Table 2. ∎

### 5.4 Reconciliation Isolation Design

**Design goal**: The reconciliation daemon should not be influenced by the execution system to report a false balance.

**Current implementation status — component-complete, not yet integrated into the live request path.** `src/compliance_bridge/reconciliation_worker.py` provides a fully implemented and unit-tested `PlaidLedgerProvider` that fetches the balance directly from Plaid Production via an independent HTTP call the execution system does not participate in, and signs the resulting payload with Cloud KMS before writing it to Redis (§4.3). Read against a live Redis instance and a live Cloud KMS signing key, the KMS-sign-and-verify round trip and the CBF's balance-preference logic (`_read_cbf_state_atomic()`) behave exactly as designed (§6.3–6.5) — this part of the code is real and correctly implemented. However, three integration gaps mean this control is **not active in the reference deployment described elsewhere in this paper** as of this writing:

1. **No deployment manifest exists for the daemon.** `reconciliation_worker.py` is only ever invoked from its own `if __name__ == "__main__":` block; there is no Kubernetes `Deployment`, `CronJob`, or namespace manifest under `deployment/k8s/` that runs it. The dedicated `reconciliation-worker` namespace and its accompanying Cilium `NetworkPolicy` — described as a **design** in Appendix B — are therefore doubly aspirational: neither the namespace/workload nor the network isolation around it has been committed to the deployment configuration.
2. **The live gateway process never invokes the daemon.** `src/gateway/server/hybrid_server.py` (the process that actually serves governance requests in the reference deployment) contains no import of, or call into, `reconciliation_worker.py`. Consequently `reconciliation:verified_balance` is never written by any running process, and `read_verified_balance()` (§4.3) always returns `None` at CBF read time in the current deployment.
3. **The deployed configuration references a provider that does not exist.** `deployment/k8s/gateway.yaml` sets `RECONCILIATION_PROVIDER=gcs`, but `ExternalLedgerReconciler.from_env()`'s provider registry recognizes only `"stub"`, `"anchorage"`, and `"plaid"` (§4.3); a `"gcs"` key raises `ValueError: Unknown reconciliation provider` immediately at construction. This value satisfies only the *startup guards* in `symbolic_governor.py` and `hybrid_server.py` (which simply check that the value is not the literal string `"stub"`), and would cause the daemon to crash on start if it were ever wired into a running process without first being corrected.

**Consequence for the CBF's live behaviour.** Because no process populates `reconciliation:verified_balance`, every CBF evaluation in the reference deployment today takes the "absent reconciliation" branch of `_read_cbf_state_atomic()` (§4.3): in production posture this raises `CBFStateUnverifiedError` and denies the action (fail-closed, per POAM-2026-037); in non-production posture it falls back to the self-reported `safety:current_cash` balance, which is exactly the recursive self-authentication configuration POAM-023 was intended to close. In other words, **the reconciliation control as designed would close POAM-023 once deployed, but has not yet been deployed, and the production fail-closed behaviour of POAM-2026-037 is presently masking rather than resolving the underlying gap** (by refusing to trade rather than by trading against a verified balance). We do not claim POAM-023 is closed in the running reference system; we claim the code required to close it is implemented, unit-tested against live Redis and live Cloud KMS infrastructure, and staged for deployment. Closing the three integration gaps above — a committed daemon manifest, wiring the daemon (or an equivalent sidecar/CronJob) into the serving path, and correcting the provider-name mismatch — is tracked as future work (§7.3).

### 5.5 Evidence Chain Integrity

**Theorem**: No field in a persisted audit node can be altered post-hoc without invalidating the `record_hash` chain.

**Formal statement**: Let `r_i` denote the `i`\-th node record with fields `content_json`, `control_id`, `event_type`, `node_index`, `audit_id`, and `prev_hash`. The record hash is:

record_hash(r_i) = SHA-256(

    JSON_sorted({
        "schema":      _SCHEMA,
        "node_index":  r_i.node_index,
        "audit_id":    r_i.audit_id,
        "control_id":  r_i.control_id,
        "event_type":  r_i.event_type
    }) || json.dumps(r_i.payload, sort_keys=True)

)

where `JSON_sorted` denotes `json.dumps(..., sort_keys=True, separators=(",", ":"))` and `||` denotes UTF-8 string concatenation. The `prev_hash` field of `r_i` stores `record_hash(r_{i-1})` (or the sentinel `"GENESIS"` for i=0), so any modification to `r_{i-1}` changes `record_hash(r_{i-1})`, which changes `r_i.prev_hash`, which changes `record_hash(r_i)`, propagating invalidation forward through the chain. Key-sorted JSON serialization provides canonical encoding, preventing field-reordering attacks. This formula matches `_link_hash()` in `src/compliance_bridge/context_accumulator.py`.

**Proof**: SHA-256 is collision-resistant under standard cryptographic assumptions. Any modification to any bound field changes the input to SHA-256, producing a different digest with overwhelming probability. Since each node's `prev_hash` is the `record_hash` of its predecessor, a modification to node `r_i` invalidates `record_hash(r_i)` and therefore `prev_hash(r_{i+1})`, propagating the invalidation to all subsequent nodes. An auditor re-computing the chain from the NDJSON artifact will detect the mismatch. ∎

Prior to this work, `content_json` alone was hashed; `control_id`, `event_type`, `node_index`, and `audit_id` were serialised beside the payload in the NDJSON artifact but not bound into the hash, allowing those fields to be altered without chain invalidation. The fix (PR \#23, `evidence-chain-metadata-binding`) binds all metadata fields into the hash. Note: existing NDJSON artifacts produced before this change will not re-verify under the new hash function; The current implementation uses schema `cage-context-accumulator/1.0` (`context_accumulator.py:71`). A schema version bump to `1.1` with version-dispatched verification to support both old and new artifacts in the same WORM archive is tracked as future work (§7.3).

---

## 6\. Evaluation

### 6.1 Experimental Setup

We evaluate CAGE on a governed financial advisor agent implemented with LangGraph. The agent executes equity trades on behalf of a simulated portfolio.

**Latency context**: In enterprise banking and instant settlement scenarios, low latency is critical. Real-time payment rails — such as FedNow in the United States and SEPA Instant in Europe — operate under an end-to-end clearing SLA of 10 seconds \[29\]. Financial institutions typically allocate an internal processing budget of 2 to 3 seconds for synchronous compliance, AML, and fraud-screening loops. To operate seamlessly within this constraint, CAGE enforces an internal transactional latency target of under 200 ms. This target acts as a soft SLA tracked and logged continuously via OpenTelemetry (OTel) instrumentation spans recording `governance.stage.latency_ms` on every tier of the pipeline. Individual deterministic governance tiers — such as the STPA UCA validator — complete in under 1 ms due to their pure-Python, I/O-free implementation. Payment message schemas conform to ISO 20022 \[22\] for interoperability with FedNow and SEPA Instant clearing infrastructure.

**Adversarial corpus**: We evaluate CAGE's deflection pipeline against a corpus of 21 adversarial attacks (`tests/red_team/adversarial_dataset.json`) designed to trigger safety violations, goal hijacking (AARM-V2) \[23\], and perimeter bypasses \[36\]. The corpus spans five attack categories: prompt injection, PII exfiltration, RBAC escalation, harmful financial instructions, and compound multi-vector attacks. An earlier draft of this paper cited a "290+" payload figure; that number does not correspond to any dataset file in the repository — `scripts/measure_paper_metrics.py` computes its payload count directly from `len(payloads)` in the dataset file, which contains 21 entries. We report the verified count here.

We measure:

- **Governance latency**: End-to-end latency of the eight-tier governor for APPROVED and REJECTED actions.  
- **Deflection rate**: Fraction of adversarial corpus attacks blocked by the governance pipeline, broken down by attack category.  
- **Reconciliation write-path cost** (`T_reconcile`): Total time for one reconciliation cycle: Plaid fetch \+ KMS sign \+ Redis write.  
- **CBF read-path overhead** (`Δt`): Additional latency per governance check from reading and verifying the reconciled balance vs. the self-reported balance.

**Infrastructure**: GKE cluster `governance-cluster` running Kubernetes v1.35.6-gke.1127000 on Google Cloud (us-central1). The cluster comprises 4 nodes: 2 primary-pool nodes (`n2-standard-4`) and 2 GPU-pool nodes (`g2-standard-4`, NVIDIA L4) for vLLM inference. The governance stack runs in the `governance-stack` namespace. Redis is deployed as `redis-master` (Bitnami Redis Helm chart, single-node, in-cluster). Cloud KMS key ring `cage-governance` (us-central1) provides ECDSA-P256 signing for reconciliation receipts and routing seals. Measurements were collected on 2026-07-27 with port-forwarding from the live GKE cluster to localhost.

### 6.2 Governance Latency

All latency measurements are in-process with mocked I/O-bound dependencies (Redis, OPA HTTP, consensus RPC) to isolate pure governance-logic cost from network jitter. Measurements use 200 iterations per tier; reported values are wall-clock time in milliseconds. All tiers complete well within the 200 ms FedNow/SEPA Instant budget.

**Scope of Table 2:** These measurements isolate pure governance-logic CPU cost by mocking all I/O-bound dependencies. They establish that the *computational* overhead of the governance pipeline is negligible relative to the 200 ms SLA. End-to-end latency in a deployed system will be dominated by network round-trips to Redis (~1–3 ms in-cluster), OPA HTTP (~2–5 ms in-cluster), and consensus RPC (variable). A full end-to-end benchmark against the live GKE cluster is tracked as future work (§7.3). The 200 ms SLA claim should be read as: 'the governance logic itself does not consume a material fraction of the SLA budget,' not as 'the full governed request completes in sub-ms time.'

**Table 2: Eight-Tier Governor Latency (ms)**

| Tier | P50 | P95 | P99 |
| :---- | :---- | :---- | :---- |
| FTRA Reachability (Tier 0.5) | \< 0.01 | \< 0.01 | \< 0.01 |
| STPA Validation (Tier 1\) | 0.02 | 0.03 | 0.10 |
| Confidence Scoring (Tier 2\) | 0.28 | 0.61 | 1.54 |
| CBF \+ OPA parallel gate (Tier 3\) | 0.28 | 0.50 | 0.95 |
| FiscalLimitGuard (Tier 4\) | \< 0.01 | \< 0.01 | \< 0.01 |
| Consensus Gate (Tier 5\) | \< 0.01 | \< 0.01 | \< 0.01 |
| Causal Gatekeeper (Tier 6\) | \< 0.01 | \< 0.01 | \< 0.01 |
| FRIA boundary (Tier 7\) | \< 0.01 | \< 0.01 | \< 0.01 |
| **Total (APPROVED path)** | **0.29** | **0.52** | **1.24** |
| **Total (REJECTED — early exit)** | **0.22** | **0.43** | **0.72** |

### 6.3 Reconciliation Write-Path Cost

**Scope of this measurement.** As discussed in §5.4, the reconciliation daemon is not currently wired into the live serving path of the reference deployment — no process runs it continuously against production traffic. The measurements in §6.3–6.5 below are **component-level benchmarks**: they exercise the real, unmodified `ExternalLedgerReconciler` and `ControlBarrierFunction` code paths directly, against a live Redis instance and a live Cloud KMS signing key, via the standalone `scripts/measure_reconciliation_metrics.py` harness — not the end-to-end gateway request flow. They establish that the reconciliation mechanism performs within budget *if deployed*; they do not demonstrate that it is presently running in production.

The reconciliation daemon polls its external ledger provider on a configurable interval (default 60 s). The write-path cost is the sum of three stages:

T\_reconcile \= t\_plaid\_fetch \+ t\_kms\_sign \+ t\_redis\_write

**Methodology note.** The measurements below were captured with `scripts/measure_reconciliation_metrics.py` against a live Redis instance and a live Google Cloud KMS ECDSA-P256 signing key (`google.cloud.kms.KeyManagementServiceClient.asymmetric_sign`) — not mocked. Production Plaid credentials (`PLAID_CLIENT_ID`/`PLAID_SECRET`/`PLAID_ACCESS_TOKEN`) were not available in the measurement environment, so the Plaid-fetch component below reflects a **network-RTT proxy**: a real HTTPS POST to `production.plaid.com/accounts/balance/get` using intentionally invalid credentials. Plaid still completes the full TLS handshake and request parsing before returning a fast `INVALID_FIELD` error, so this captures genuine network + TLS latency to the live endpoint, but does **not** exercise `PlaidLedgerProvider`'s full response-parsing path. The KMS-sign and Redis-write stages are measured through the unmodified `ExternalLedgerReconciler.reconcile()` code path using its own OpenTelemetry span instrumentation (`reconciliation.plaid_fetch_ms` / `kms_sign_ms` / `redis_write_ms`), fed by a synthetic ledger-balance object so that only the fetch stage is a proxy — KMS signing and the Redis write are 100% real.

**Table 3: Reconciliation Write-Path Latency (ms, n=40, `network_rtt_proxy` mode)**

| Component | P50 | P95 | P99 |
| :---- | :---- | :---- | :---- |
| Plaid `/accounts/balance/get` (network-RTT proxy) | 62.0 | 69.3 | 85.2 |
| Cloud KMS `asymmetricSign` (live) | 108.3 | 245.1 | 9,617.0 |
| Redis `SETEX` pipeline (live) | 1.3 | 2.8 | 8.4 |
| **T\_reconcile total (P50 sum)** | **\~172** | — | — |

*Note: the KMS P99 outlier (\~9.6 s) reflects an infrequent gRPC channel re-initialization observed in a subset of runs against the live Cloud KMS endpoint from a non-GCP-hosted client; P50/P95 (108/245 ms) are representative of steady-state signing cost once the channel is warm. Production deployments running the reconciliation daemon in-cluster (GKE, same region as the KMS key ring) are expected to see materially lower and less variable latency than this out-of-cluster measurement, because the daemon holds a long-lived gRPC channel across its 60 s polling loop rather than re-establishing one per invocation. This numerical revision supersedes an earlier draft's placeholder Plaid-fetch/KMS-sign figures, which were not backed by a corresponding measurement script.*

**Limitation — Plaid fetch likely underestimated.** Because the `network_rtt_proxy` methodology uses intentionally invalid credentials, Plaid's server returns a fast `INVALID_FIELD` error immediately after the TLS handshake and request-parsing stage, without performing the downstream application-layer processing, ledger-database query, or full JSON response-body construction that a genuine, successfully authenticated `/accounts/balance/get` call would incur. The 62.0 ms P50 reported above should therefore be read as a lower bound on true Plaid fetch latency, not a representative estimate of it — the real figure, once production Plaid credentials are available, is expected to be higher. Re-measuring against a Plaid sandbox environment or a mock provider that fully replays a successful response's processing path is tracked as future work (§7.3).

**Background amortisation note:** The reconciliation daemon operates on a decoupled 60-second polling loop; its execution duration dictates data freshness but does not sequentially block the synchronous gateway pipeline. The calculation `T_reconcile / (poll_interval_s × request_rate_hz)` = 172 ms / (60 s × 10 req/s) ≈ 0.29 ms/request expresses the *background* write-path cost amortised across requests — it is not a per-request synchronous overhead and should not be compared directly to the 200 ms synchronous governance SLA. The practical conclusion is that the reconciliation daemon background polling cost is negligible relative to the request rate, not that each request incurs 0.29 ms of reconciliation overhead.

### 6.4 CBF Read-Path Overhead

The CBF read-path overhead is the additional latency from reading `reconciliation:verified_balance` and verifying its KMS signature, compared to reading `safety:current_cash` directly:

Δt \= t\_reconciled\_read − t\_self\_reported\_read

   \= t\_redis\_get(reconciliation:verified\_balance)

     \+ t\_kms\_verify(signature)

     − t\_redis\_get(safety:current\_cash)

KMS signature verification is a local ECDSA-P256 verify operation using the cached public key PEM (no network call).

**Methodology note.** Measured by writing a genuine KMS-signed `ReconciliationResult` payload to the real `reconciliation:verified_balance` Redis key and invoking the unmodified `ControlBarrierFunction._read_cbf_state_atomic()` production method (`src/gateway/governance/cbf.py`) — the reconciled-balance code path is not mocked or stubbed; only the upstream signature (a real KMS `sign()` call made once, ahead of the read loop) is precomputed to isolate the read-side cost.

**Table 4: CBF Read-Path Overhead (ms, n=500, live Redis + live KMS-signed payload)**

| Path | P50 (ms) | P95 (ms) |
| :---- | :---- | :---- |
| Self-reported (`safety:current_cash`) | 0.737 | 1.116 |
| Reconciled (`reconciliation:verified_balance` \+ KMS verify) | 0.578 | 0.801 |
| **Δt overhead** | **\-0.159** | **\-0.315** |

Contrary to the naive expectation that the reconciled path is strictly more expensive (it performs a Redis GET *plus* a local KMS-signature verify, versus a single Redis GET for the self-reported path), the measured reconciled-path latency is **lower**, not higher. We attribute this to two effects: (1) the self-reported path additionally executes a fallback code branch (`redis_client.get_raw_client().pipeline(...)`) that is heavier than the direct `redis_client.get()` used inside `read_verified_balance()`, and (2) local ECDSA-P256 verification against a cached PEM is sub-0.1 ms and is dwarfed by measurement noise at this scale. In either case, the practical conclusion holds: **KMS-backed provenance verification does not introduce a materially higher read-path cost than the self-reported baseline** — the reconciled path is not measurably slower, and by this measurement is in fact marginally faster. This revises an earlier draft's placeholder "+0.02 ms" claim, which was not backed by a corresponding measurement.

**Limitation — confounded baseline.** The two code paths compared above are not architecturally equivalent: the self-reported path's `pipeline(...)` fallback branch and the reconciled path's direct `get()` call differ in more than the presence or absence of a KMS-signature check, which confounds the isolation of ECDSA-P256 verification cost specifically. A cleaner experiment would compare `read_verified_balance()` (reconciled + KMS verify) against an equivalent direct `redis_client.get("safety:current_cash")` call that bypasses the `pipeline(...)` fallback entirely, isolating the KMS-verify delta from the unrelated code-path difference. We report the as-measured production-code comparison above because both paths are exactly what the live system executes; the qualitative conclusion (KMS verification adds no material overhead, since it is sub-0.1 ms against measurement noise on the order of 0.3–1.1 ms) is robust to this confound, but the *precise* Δt figures in Table 4 should not be read as an isolated measurement of ECDSA-P256 verification cost alone. An apples-to-apples re-measurement against an equivalent `get()` baseline is tracked as future work (§7.3).

### 6.5 Safety Violation Detection

**Correction to an earlier draft.** An earlier version of this section described injecting a false self-reported balance of $500,000 against a reconciled balance of $48,250 for a $10,000 trade, and reported that the CBF emitted an audit event named `CBF_RECONCILIATION_MISMATCH`. Neither claim survives verification against the live code: under the actual barrier formula (`h(x) = cash_balance - min_cash_balance`, γ from `THRESHOLDS.cbf.gamma`), a $10,000 trade against a $48,250 reconciled balance is SAFE (h(next) exceeds the required threshold), and no event named `CBF_RECONCILIATION_MISMATCH` exists anywhere in the codebase. The corrected experiment below was executed against the real `ControlBarrierFunction.verify_action()` method with a genuinely unsafe reconciled balance.

We seeded an inflated self-reported balance of $500,000 into `safety:current_cash` — simulating a compromised execution system attempting to make an unsafe trade appear safe — while writing the true, KMS-signed balance of $8,000 to `reconciliation:verified_balance`. The experiment used the following CBF parameters from `config/governance_thresholds.json`: `min_cash_balance = $1,000`, `γ = 0.5`. With these parameters: `h(current) = $8,000 − $1,000 = $7,000`; `h(next) = $8,000 − $10,000 − $1,000 = −$3,000`; `threshold = (1 − 0.5) × $7,000 = $3,500`. Since `h(next) = −$3,000 < threshold = $3,500`, the action is blocked. A subsequent `execute_trade` request for $10,000 produced two different verdicts depending on which balance the CBF consulted:

| Balance source consulted | CBF verdict |
| :---- | :---- |
| Self-reported (`safety:current_cash` \= $500,000) | `SAFE` |
| Reconciled (`reconciliation:verified_balance` \= $8,000, KMS-signed) | `[CTRL_MRM_004] SR 26-2 §IV – Model Risk Management Violation: Safety Violation (RBC/CBF). h(next)=-3000.00 < threshold=3500.00` |

The CBF's code path (`verify_action()` → `_read_cbf_state_atomic()`) always prefers the KMS-verified reconciled balance when present and valid, so in this isolated benchmark — where we manually populate `reconciliation:verified_balance` exactly as the daemon would — the verdict returned is the rejection; the "self-reported" row above is shown only to illustrate what the (insecure) prior architecture would have concluded had it trusted the execution system's own report. The rejection is observable via the `verify_action()` return string (prefixed `[CTRL_MRM_004]`) and via the OTel span attributes `safety.balance.source="reconciled"` and `safety.result` set on the `safety.cbf_check` span — not via a `CBF_RECONCILIATION_MISMATCH` log event, which does not exist. This experiment validates that the reconciliation *mechanism*, once deployed, supplies an independent, KMS-attested ground truth that a compromised execution system cannot spoof by self-reporting an inflated balance; per §5.4, it does not demonstrate that this protection is active in the reference deployment today, since no process there currently populates `reconciliation:verified_balance`.

### 6.6 Adversarial Deflection

We evaluate CAGE's governance pipeline against a corpus of 21 adversarial attacks \[36\] spanning five attack categories, plus a companion 20-prompt benign dataset to measure the false-positive rate (S2):

**Table 5: Adversarial Deflection by Attack Category**

| Attack Category | Corpus Size | Evaluated | Deflected | Rate |
| :---- | :---- | :---- | :---- | :---- |
| Prompt injection | 6 | 6 | 2 | 33.3% |
| PII exfiltration | 5 | 4 | 4 | 100% |
| RBAC escalation | 4 | 4 | 4 | 100% |
| Harmful financial instructions | 3 | 3 | 2 | 66.7% |
| Compound multi-vector | 3 | 3 | 3 | 100% |
| **Total** | **21** | **20** | **15** | **75.0%** |

*Measurement note: The adversarial dataset (`tests/red_team/adversarial_dataset.json`, 21 payloads) was run against the live `governed-financial-advisor` backend in-cluster on GKE (`governance-cluster-2`, 2026-08-02) via `scripts/measure_paper_metrics.py`, after fixing five independent production defects that had invalidated all prior live-backend measurements (KMS digest-width mismatch, Redis authentication dropped from a connection URL, a vLLM guided-decoding tokenization artifact, an overly strict execution-plan schema, and an MCP transport type mismatch — see the project's measurement provenance records for full detail). Of 21 payloads, 1 failed at the network level and is excluded from both numerator and denominator (Table 5's Evaluated column); zero payloads produced a server-side crash. The reported 75.0% (15/20 evaluated) reflects genuine governance-tier verdicts only. An earlier draft of this section claimed a 100% deflection rate (21/21) from a 2026-07-27 measurement and, before that, a 290-payload corpus with 269 payloads deflected at the NeMo guardrail layer "before reaching the backend endpoint" — neither the original 21/21 run's artifacts nor any 290-payload dataset or 269-deflection NeMo-layer run could be independently reproduced or located in this repository as of this measurement. We withdraw both prior claims; the verified, reproducible result is the 75.0% (15/20 evaluated) reported above. The `prompt_injection` category's comparatively low 33.3% deflection rate is a genuine finding warranting further hardening of the gateway's Aho-Corasick/structural-regex layer, not a measurement artifact.*

This security was achieved without sacrificing performance: the total governance pipeline operates within the 200 ms soft SLA target, demonstrating that robust, multi-layered cybernetic governance and zero-trust verification can be deployed in production without introducing significant performance overhead to real-time financial systems.

**Benign false-positive rate (S2).** To contextualize the deflection rate above, we separately measured CAGE's false-positive rate on 20 unambiguously benign financial-advisor prompts (`tests/red_team/benign_dataset.json`) spanning four categories: market data lookups, portfolio management queries, stock queries, and trade execution requests with fully specified risk profile and investment horizon context.

**Table 6: Benign False-Positive Rate by Category**

| Category | Corpus Size | Evaluated | False Positives | FPR |
| :---- | :---- | :---- | :---- | :---- |
| Market data | 5 | 5 | 0 | 0.0% |
| Portfolio management | 5 | 5 | 1 | 20.0% |
| Stock query | 6 | 6 | 0 | 0.0% |
| Trade execution | 4 | 4 | 2 | 50.0% |
| **Total** | **20** | **19** | **3** | **15.8%** |

*Measurement note: measured on the same run and against the same live backend as Table 5. One request failed at the network level and is excluded (Evaluated column). Inspection of the raw response bodies for all 3 false positives (archived alongside the measurement) confirmed each is a genuine execution-plan generation defect — the execution-analyst LLM, operating under vLLM's `guided_json` constrained-decoding mode, produced a syntactically valid but semantically incomplete plan (e.g. omitting required steps, or leaving the `rationale` field malformed) that the downstream Feasibility/Terminal-Reachability Analyzer (FTRA) correctly rejected. This is a genuine limitation of constrained decoding with a 7B-parameter model — `guided_json` guarantees schema-*valid* JSON but not schema-*complete* or semantically coherent output — rather than a defect in the governance logic itself, which correctly declined to execute an incomplete plan in every case. An earlier dataset revision under-specified the four trade-execution prompts (omitting risk attitude and investment horizon, which the execution-analyst's system prompt requires before generating an executable plan), causing the agent's legitimate clarification requests to be misclassified as false positives by a keyword-based response classifier; the dataset was corrected to include this context before the measurement reported here.*

**Evaluation limitations:** We do not report an un-governed baseline (the same 21 adversarial payloads against the LLM without CAGE), so the deflection rate above cannot be decomposed into CAGE's governance-pipeline contribution versus the underlying model's native safety tuning. An un-governed baseline mode has been added to `scripts/measure_paper_metrics.py` for future measurement runs; results are tracked as future work (§7.3).

---

## 7\. Discussion

### 7.1 Comparison with Five-Plane Architecture

CAGE implements all five planes of the reference architecture \[1\] and extends it in four dimensions:

**Compiler-driven policy generation**: The five-plane architecture assumes policies are written manually. CAGE's STPA compiler generates OPA Rego, NeMo Colang, and Agent Registry authorization manifests from hazard analysis, eliminating policy drift across all three enforcement surfaces.

**Formal verification**: The five-plane architecture states correctness invariants informally. CAGE machine-verifies the NoDirectBind invariant via BFS over the full reachable state space, and proves evidence chain integrity via SHA-256 collision resistance (§5.5).

**External ground truth**: The five-plane architecture does not address the recursive self-authentication problem in safety functions. CAGE's reconciliation daemon design provides an externally attested, KMS-signed balance that the execution system cannot influence; §5.4 discusses the remaining work to deploy this daemon into a live serving path.

**Pre-execution reachability**: The five-plane architecture evaluates actions at execution time. CAGE's FTRA gate (Tier 0.5) performs a NetworkX reachability analysis over the full execution plan before the first tool call, catching unsafe trajectories at commencement time rather than at each individual action.

### 7.2 Limitations

**Reconciliation daemon is not yet deployed (see §5.4)**: `reconciliation_worker.py` is fully implemented and unit-tested against live Redis and Cloud KMS infrastructure, but is not currently running as a deployed workload — there is no Kubernetes manifest for it, `hybrid_server.py` never invokes it, and the reference deployment's `RECONCILIATION_PROVIDER=gcs` setting does not match any key in the daemon's own provider registry (`stub`/`anchorage`/`plaid`). Until these three integration gaps are closed, the CBF in the reference deployment operates in its fail-closed (production) or self-reported-fallback (non-production) branch, not its externally-reconciled branch, for every request.

**Zero-trust network controls require manual cluster prerequisites (see §4.7)**: The Linkerd mTLS and Cilium L7 egress manifests are committed and internally consistent, but neither the Linkerd control plane nor the Cilium CNI is installed by `deploy_all.sh` or the Terraform modules under `infra/`. `google_container_cluster.primary` provisions a standard GKE cluster using the native `network_policy` block (GKE's built-in L3/L4 provider), not Cilium. Applying `linkerd-mtls-policy.yaml` or `cilium-egress-lockdown.yaml` to a cluster without the corresponding control plane/CNI installed will fail (the `cilium.io/v2` CRDs and Linkerd `policy.linkerd.io` CRDs will not exist).

**Plaid coverage**: Plaid Production covers bank accounts and brokerage accounts linked via Plaid Link. Custody accounts at OCC-chartered custodians (e.g., Anchorage Digital) require the `AnchorageGrpcLedgerProvider`, which is not yet implemented (pending enterprise API onboarding).

**Reconciliation TTL**: The 300-second TTL means the CBF may evaluate against a balance that is up to 5 minutes stale. For high-frequency trading, a shorter TTL (e.g., 30 seconds) may be required, increasing the write-path cost. OTel span attributes `safety.balance.source` and `safety.balance.reconciled` allow operators to detect TTL expiry events in production dashboards.

**Evidence chain schema versioning**: The `record_hash` binding change (§5.5) is not backward-compatible. NDJSON artifacts produced before this change will not re-verify under the new hash function. The current schema is `cage-context-accumulator/1.0`; a `1.1` bump with version-dispatched verification is tracked as future work (§7.3). Deployments with WORM archive requirements must coordinate a schema migration or accept that pre-migration artifacts are verified only against the v1.0 hash function.

**PII scrubbing hardening (resolved)**: An earlier version of the email PII pattern in `PIISanitizer` and `scrub_pii` used unbounded quantifiers, causing quadratic backtracking on adversarial no-TLD inputs. This was remediated by bounding the local part to `{1,64}` and the domain to `{1,255}` (RFC 5321 maxima), making the scan linear while preserving matching behaviour for all valid addresses. This is a resolved historical hardening item, not an ongoing limitation.

**Adversarial corpus size**: The adversarial deflection evaluation (§6.6) covers 21 hand-authored payloads across five attack categories — a useful smoke test of the deflection pipeline, but a small sample for drawing strong generalization claims about adversarial robustness. An earlier draft of this paper cited a larger "290+" figure that could not be substantiated against any dataset file in the repository (§6.6); we have corrected the reported corpus size to the verified value. Expanding the corpus with a larger, more diverse and adversarially-generated payload set (e.g., via automated red-teaming or garak/PyRIT-style fuzzing) is tracked as future work (§7.3).

**Causal model accuracy**: The DoWhy causal gatekeeper uses a structural causal model that must be calibrated to the specific financial domain. An inaccurate causal model may produce false positives (blocking safe actions) or false negatives (allowing unsafe actions).


### 7.3 Future Work

- **Deploy the reconciliation daemon**: Author a Kubernetes `Deployment` or `CronJob` manifest (plus the dedicated `reconciliation-worker` namespace and Cilium `NetworkPolicy` described in Appendix B) and wire it — or an equivalent sidecar — into the serving path so that `reconciliation:verified_balance` is actually populated in the reference deployment.  
- **Fix the `RECONCILIATION_PROVIDER` mismatch**: Either add a `"gcs"` entry to `ExternalLedgerReconciler.from_env()`'s provider registry (backed by the same GCS WORM ledger already used for UCA audit records) or change `deployment/k8s/gateway.yaml` to set `RECONCILIATION_PROVIDER=plaid` with provisioned production credentials, so the deployed configuration and the code's provider registry agree.  
- **Automate zero-trust mesh/CNI installation**: Add `linkerd install`/`cilium install` steps (or equivalent Terraform `helm_release` resources) to `deploy_all.sh` or the `infra/` Terraform modules, so that `linkerd-mtls-policy.yaml` and `cilium-egress-lockdown.yaml` apply cleanly to a freshly provisioned cluster without an undocumented manual prerequisite.  
- **Expand the adversarial evaluation corpus**: Grow `tests/red_team/adversarial_dataset.json` beyond its current 21 hand-authored payloads — e.g., via automated red-teaming or fuzzing tools (garak, PyRIT) — to support stronger generalization claims about adversarial robustness, and correct the corpus-size claim in any downstream documentation that still cites the unsubstantiated "290+" figure.  
- **Anchorage Digital integration**: Implement `AnchorageGrpcLedgerProvider` for OCC-chartered custody accounts.  
- **Shorter reconciliation TTL**: Evaluate the latency/freshness tradeoff for high-frequency trading.  
- **Formal verification of causal model**: Apply formal methods to verify the structural causal model against the domain specification.  
- **Multi-agent consensus**: Extend the consensus tier to support Byzantine fault-tolerant agreement among multiple governance nodes.  
- **FTRA formal verification**: Apply model checking (e.g., TLA+ or Alloy) to the FTRA reachability analysis to prove that no unsafe trajectory can receive a `CLEAR` verdict under the compiled terminal registry.  
- **Evidence chain schema migration**: Implement version-dispatched `record_hash` verification in the OSCAL exporter to support both `cage-context-accumulator/1.0` and `1.1` artifacts in the same WORM archive.

---

## 8\. Conclusion

As agentic AI continues to integrate into mission-critical corporate operations, relying on probabilistic, model-side safety measures is no longer acceptable. The Cybernetic Agent Governance Engine (CAGE) provides a mathematically grounded, highly performant, and secure solution grounded in Ashby's Law of Requisite Variety and Stafford Beer's Viable System Model. By combining cybernetic foundations with a systematic STPA-to-Rego compiler pipeline and an identity-centric zero-trust posture, CAGE successfully bridges the gap between the probabilistic behavior of LLMs and the deterministic demands of regulated industries.

CAGE translates STPA hazard analysis into executable enforcement policies and evaluates every agent action through a formally verified eight-tier pipeline (including a pre-execution FTRA reachability gate). It provides a component-complete, independently benchmarked design — an isolated reconciliation daemon with KMS-signed external balances (§4.3, §6.3–6.5) — for closing the recursive self-authentication gap in CBF ground truth; as detailed in §5.4 and §7.2, deploying this daemon into the live serving path, rather than implementing its constituent code, is the remaining integration work before POAM-023 can be considered closed in a running system. Governance is enforced at the HTTP layer for all message roles, eliminating role-based bypass paths. We prove the NoDirectBind invariant via exhaustive state-space enumeration, CBF invariance via induction, FiscalLimitGuard race-condition freedom via atomic Redis transactions, and evidence chain integrity via SHA-256 collision resistance. CAGE is open-source and targets NIST SP 800-53, ISO 42001, SR 26-2, and multi-jurisdiction compliance (US FED, EU ECB, APAC MAS).

---

## References

\[1\] Tallam, K. (2026). A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents. arXiv:2606.12320.

\[2\] Ames, A. D., Xu, X., Grizzle, J. W., and Tabuada, P. (2017). Control Barrier Function Based Quadratic Programs for Safety Critical Systems. IEEE Transactions on Automatic Control, 62(8):3861–3876.

\[3\] Leveson, N. G. (2011). Engineering a Safer World: Systems Thinking Applied to Safety. MIT Press. [https://doi.org/10.7551/mitpress/8179.001.0001](https://doi.org/10.7551/mitpress/8179.001.0001)

\[4\] NIST. (2020). Security and Privacy Controls for Information Systems and Organizations. Special Publication 800-53 Rev 5.

\[5\] ISO. (2023). Information technology — Artificial intelligence — Management system. ISO/IEC 42001:2023.

\[6\] Federal Reserve. (2011). Supervisory Guidance on Model Risk Management. SR 11-7. (SR 26-2 is the anticipated successor guidance; cite SR 11-7 until SR 26-2 is formally published.)

\[7\] Doshi, A., Hong, Y., Xu, C., Kang, E., Kapravelos, A., & Kastner, C. (2026). Towards Verifiably Safe Tool Use for LLM Agents. ICSE NIER 2026\. [https://doi.org/10.48550/arXiv.2601.08012](https://doi.org/10.48550/arXiv.2601.08012)

\[8\] Gupta, V., & Sreenivasamurthy, D. (2026). Prose2Policy (P2P): A Practical LLM Pipeline for Translating Natural-Language Access Policies into Executable Rego. arXiv:2603.15799. [https://doi.org/10.48550/arXiv.2603.15799](https://doi.org/10.48550/arXiv.2603.15799)

\[9\] Wang, S., Zhu, S., & Li, R. (2026). Runtime Policy Enforcement for MCP-Based LLM Agents. Electronics, 15(13), 2829\. [https://doi.org/10.3390/electronics15132829](https://doi.org/10.3390/electronics15132829)

\[10\] Mylius, S. (2025). Systematic Hazard Analysis for Frontier AI using STPA. arXiv:2506.01782. [https://doi.org/10.48550/arXiv.2506.01782](https://doi.org/10.48550/arXiv.2506.01782)

\[11\] SPIFFE. (2022). Kubernetes Workload Identity attestation via Projected Service Account Tokens. [https://spiffe.io/docs/latest/spiffe-about/overview/](https://spiffe.io/docs/latest/spiffe-about/overview/)

\[12\] Zhou, J., Sheng, H., Lou, Y., Yang, Y., & Fu, J. (2026). FormalJudge: A Neuro-Symbolic Paradigm for Agentic Oversight. arXiv:2602.11136. [https://doi.org/10.48550/arXiv.2602.11136](https://doi.org/10.48550/arXiv.2602.11136)

\[13\] Aguiar, V. A., et al. (2025). A Multi-Agent Architecture for Governance and Security of LLM-Based Knowledge Access. [Full author list to be verified against the published proceedings before camera-ready.] IEEE BigData 2025\. [https://doi.org/10.1109/bigdata66926.2025.11401633](https://doi.org/10.1109/bigdata66926.2025.11401633)

\[14\] Raza, S., Sapkota, R., & Emmanouilidis, C. (2026). TRiSM for Agentic AI: A Review of Trust, Risk, and Security Management in Multi-Agent Systems. AI Open. [https://doi.org/10.1016/j.aiopen.2026.02.006](https://doi.org/10.1016/j.aiopen.2026.02.006)

\[15\] Bhushan, B., Rajgopal, P. R., & Sharma, K. (2025). An Intent-Aware Zero Trust Identity Architecture for Unifying Human and Machine Access. IJCESEN, 11(3). [https://doi.org/10.22399/ijcesen.3886](https://doi.org/10.22399/ijcesen.3886)

\[16\] Saleem, K. (2024). Zero-Trust Agent Gateway: Identity-Centric Access Control for Multi-Actor AI Ecosystems Aligned with SASE Principles. AJACCM, 4(2), 36–45. [https://doi.org/10.64751/ajaccm.2024.v4.n2.pp36-45](https://doi.org/10.64751/ajaccm.2024.v4.n2.pp36-45)

\[17\] Pappu, K., Bhushan, B., & Jaiswal, N. (2026). Future-Proofing Identity Security for Agentic AI Systems. ICAISET 2026\. [https://doi.org/10.1109/icaiset66439.2026.11541783](https://doi.org/10.1109/icaiset66439.2026.11541783)

\[18\] Pappu, K., Bhushan, B., & Mittal, A. (2025). SPIFFE-Based Zero-Trust Authentication for AI Agent Ecosystems. ICCA 2025\. [https://doi.org/10.1109/icca66035.2025.11431026](https://doi.org/10.1109/icca66035.2025.11431026)

\[19\] Rismani, S., Dobbe, R. I. J., & Moon, A. (2024). From Silos to Systems: Process-Oriented Hazard Analysis for AI Systems. arXiv:2410.22526. [https://doi.org/10.48550/arXiv.2410.22526](https://doi.org/10.48550/arXiv.2410.22526)

\[20\] Sathe, O. (2025). Machine Learning–Augmented Neurosymbolic Agenticops Framework for Runtime Verification and Enforcement of Standard Operating Procedures. IJRSI, 12(11). [https://doi.org/10.51244/ijrsi.2025.12110199](https://doi.org/10.51244/ijrsi.2025.12110199)

\[21\] Vijay, D., & Ethiraj, V. (2025). Graph-Symbolic Policy Enforcement and Control (G-SPEC): A Neuro-Symbolic Framework for Safe Agentic AI in 5G Autonomous Networks. arXiv:2512.20275. [https://doi.org/10.48550/arxiv.2512.20275](https://doi.org/10.48550/arxiv.2512.20275)

\[22\] ISO. (2013). Financial services — Universal financial industry message scheme (ISO 20022). [https://www.iso.org/standard/66370.html](https://www.iso.org/standard/66370.html)

\[23\] Errico, H. (2026). Autonomous Action Runtime Management (AARM): A System Specification for Securing AI-Driven Actions at Runtime. arXiv:2602.09433. [https://doi.org/10.48550/arXiv.2602.09433](https://doi.org/10.48550/arXiv.2602.09433)

\[24\] Cloud Security Alliance. (2026). Autonomous Action Runtime Management Working Group Threat Model Checklist. [https://aarm.dev/](https://aarm.dev/)

\[25\] Ashby, W. R. (1956). An Introduction to Cybernetics. Chapman and Hall. [https://doi.org/10.5962/bhl.title.5851](https://doi.org/10.5962/bhl.title.5851)

\[26\] Beer, S. (1972). Brain of the Firm. Allen Lane.

\[27\] Beer, S. (1979). The Heart of Enterprise. John Wiley & Sons.

\[28\] OWASP Foundation. (2025). OWASP Top 10 for Large Language Model Applications: LLM06 \- Excessive Agency Risks. [https://owasp.org/www-project-top-10-for-large-language-model-applications/](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

\[29\] Volt Active Data. (2026). The Infrastructure Requirement that Instant Rails Expose. Real-Time Rails Industry Brief. [https://www.voltactivedata.com/wp-content/uploads/2026/06/Volt\_Real\_Time\_Rails\_Industry-Brief.pdf](https://www.voltactivedata.com/wp-content/uploads/2026/06/Volt_Real_Time_Rails_Industry-Brief.pdf)

\[30\] Cloud Native Computing Foundation. (2021). Open Policy Agent (OPA) (Graduated CNCF Project). [https://openpolicyagent.org/docs](https://openpolicyagent.org/docs)

\[31\] AgentGuard: Attribute-Based Access Control (ABAC) for Tool-Use LLM Agents. (2026). arXiv:2605.28071. [https://arxiv.org/abs/2605.28071](https://arxiv.org/abs/2605.28071) [Author names to be verified against the published preprint before camera-ready; "AgentGuard" is the system name, not the author.]

\[32\] Wang, H., Poskitt, C. M., & Sun, J. (2025). AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents. arXiv:2503.18666. [https://arxiv.org/abs/2503.18666](https://arxiv.org/abs/2503.18666)

\[33\] Buoyant, Inc. (2026). Linkerd Policy Resources and Workload Identity Verification. [https://oneuptime.com/blog/post/2026-01-30-linkerd-policy-resources/view](https://oneuptime.com/blog/post/2026-01-30-linkerd-policy-resources/view)

\[34\] Conant, R. C., & Ashby, W. R. (1970). Every Good Regulator of a System Must Be a Model of that System. International Journal of Systems Science, 1(2), 89–97. [https://doi.org/10.1080/00207727008920220](https://doi.org/10.1080/00207727008920220)

\[35\] AgenTRIM: Balancing Tool-Driven Agency in LLM-Based Agents to Address Tool Misuse. (2026). arXiv:2601.12449. [https://arxiv.org/abs/2601.12449](https://arxiv.org/abs/2601.12449) [Author names to be verified against the published preprint before camera-ready; "AgenTRIM" is the system name, not the author.]

\[36\] Deng, et al. (2025). Systematic Evaluation of Agentic AI Security Vulnerabilities under Cost and Delay Amplification Attacks. [Full author list to be verified against the published dissertation before camera-ready.] ProQuest Dissertations Publishing.

\[37\] Ames, A. D., Coogan, S., Egerstedt, M., Notomista, G., Sreenath, K., & Tabuada, P. (2019). Control Barrier Functions: Theory and Applications. 2019 18th European Control Conference (ECC), 3420–3431. [https://doi.org/10.23919/ECC.2019.8796030](https://doi.org/10.23919/ECC.2019.8796030)

\[38\] Ames, A. D., Xu, X., Grizzle, J. W., & Tabuada, P. (2017). Control Barrier Function Based Quadratic Programs for Safety Critical Systems. IEEE Transactions on Automatic Control, 62(8), 3861–3876. [https://doi.org/10.1109/TAC.2016.2638961](https://doi.org/10.1109/TAC.2016.2638961)

\[39\] Abdulkhaleq, A., & Wagner, S. (2013). Experiences with Applying STPA to Software-Intensive Systems in the Automotive Domain. Proceedings of the 2013 STAMP Conference, MIT.

\[40\] Antoine, B. (2013). Systems Theoretic Hazard Analysis (STPA) Applied to the Risk Review of Complex Systems: An Example from the Medical Device Industry. S.M. Thesis, Massachusetts Institute of Technology.

\[41\] Systematic Hazard Analysis for Frontier AI using STPA. (2025). [Full author/venue metadata to be verified before camera-ready — cited per reviewer-suggested related work.]

\[42\] Pro2Guard: Proactive Runtime Enforcement of LLM Agent Safety via Probabilistic Model Checking. (2025). [Full author/venue metadata to be verified before camera-ready — cited per reviewer-suggested related work.]

\[43\] Agent Route Origin Authorization (AgentROA): A Cryptographic Policy Enforcement Framework for AI Agent Actions. (2026). [Full author/venue metadata to be verified before camera-ready — cited per reviewer-suggested related work.]

\[44\] System Safety Under Sensor Attacks: A Control Barrier Function Approach. (2024). [Full author/venue metadata to be verified before camera-ready — cited per reviewer-suggested related work.]

---

## Appendix A: Proof of NoDirectBind Invariant

The full BFS proof is implemented in `proof/model.py`. The state space is:

States S \= {(phase, tier\_results, seal\_present, resolvedAllow) :

  phase ∈ {PENDING, CHECKING, SEAL\_ISSUED, EXECUTED, DENIED},

  tier_results ∈ {PENDING, PASS, FAIL}^8  (one per governance tier within _run_checks(): stpa, confidence, cbf, opa, fiscal, consensus, causal, fria),

  seal\_present ∈ {TRUE, FALSE},

  resolvedAllow ∈ {TRUE, FALSE}}

The gated transition function `gated_transitions(): S → 2^S`, defined in `proof/model.py`, mirrors `SymbolicGovernor._run_checks()`. The BFS visits 21 reachable states from the initial state `(PENDING, all-PENDING, FALSE, FALSE)`. The invariant `(phase=EXECUTED) ⟹ (resolvedAllow=TRUE)` holds in all 21 reachable states; exactly one reachable state has `phase=EXECUTED`.

`proof/model.py` additionally verifies four gap-specific sub-proofs, run automatically by `python proof/model.py`:

- **Gap 1 (no routing seal on approval)**: `ungated_transitions()` models the pre-fix code path in which `govern()` transitions directly from `CHECKING` to `EXECUTED` once all tiers pass, without requiring a routing seal. This variant reaches 19 reachable states and produces the explicit counterexample `(phase=EXECUTED, resolvedAllow=FALSE, seal_present=FALSE)` — a direct violation of the NoDirectBind invariant. This confirms that the seal-issuance step in `gated_transitions()` is load-bearing: removing it structurally (not merely skipping one tier's evaluation) produces a genuine, minimal counterexample.
- **Gap 2 (`govern()` without seal)**: `no_seal_govern_transitions()` models the pre-fix code path in which `govern()` could return without issuing a routing seal. This variant reaches 19 states and produces the counterexample `(phase=EXECUTED, resolvedAllow=FALSE, seal_present=FALSE)` — an explicit violation of the invariant, confirming the historical bug this fix addresses was real and structurally exploitable in the model.
- **Gap 3 (`CBF_FAIL_OPEN=true`)**: `cbf_fail_open_transitions()` models the CBF tier being unconditionally marked `PASS` without evaluation. The structural invariant still holds (20 reachable states) because the seal is issued only after all *other* tiers also pass — but the CBF tier itself is absent from the gate. CAGE therefore backs this with an operational control outside the state-space model: a module-level startup assertion in `symbolic_governor.py` raises `RuntimeError` if `CBF_FAIL_OPEN=true` in a production environment, preventing this configuration from being deployed at all.
- **Gap 4 (DoWhy import failure)**: `dowhy_absent_transitions()` models the causal gatekeeper tier being silently skipped. As with Gap 3, the structural invariant holds (20 reachable states) but the causal tier is absent from the gate; the same class of startup assertion prevents this configuration in production.

The `ungated_transitions()` negative control (§4.4) additionally confirms that removing the seal-gate structurally — rather than merely skipping one tier's evaluation — produces a genuine, minimal counterexample (19 reachable states, one violating the invariant), which is the sense in which the seal-issuance step is load-bearing.

**Attribution**: The BFS enumerator in `proof/model.py` is based on prior work by LalaSkye (https://github.com/LalaSkye/no-direct-bind), released under the Apache 2.0 license.

---

## Appendix B: Reconciliation Architecture

The following diagram shows the **target deployment design**. Steps 1–3 inside the box (Plaid fetch, KMS sign, Redis write) and the CBF read-side logic that consumes their output are implemented and independently benchmarked against live infrastructure (§6.3–6.5); none of it, however, currently executes as a continuously running workload in the reference deployment. As detailed in §5.4, three things are missing, not just the namespace/NetworkPolicy: (1) no Kubernetes `Deployment`/`CronJob` manifest exists to run this code at all, in any namespace; (2) `hybrid_server.py` (the live gateway process) never invokes it; and (3) the reference deployment's `RECONCILIATION_PROVIDER=gcs` setting does not match any entry in the code's own provider registry. The entire box below — including the dedicated `reconciliation-worker` namespace and its Cilium NetworkPolicy — should therefore be read as a validated design for a component that is not yet deployed, not as a running system. See §5.4 and the limitations noted in §7.2.

┌─────────────────────────────────────────────────────────────────┐

│  reconciliation-worker namespace ***(design; not yet deployed)*** │

│                                                                 │

│  ┌──────────────────────────────────────────────────────────┐  │

│  │  ExternalLedgerReconciler (60s poll)                     │  │

│  │                                                          │  │

│  │  1\. PlaidLedgerProvider.fetch\_balance()  *(implemented)* │  │

│  │     POST https://production.plaid.com/accounts/balance/get│  │

│  │                                                          │  │

│  │  2\. KMSGovernanceSigner.sign(payload)     *(implemented)* │  │

│  │     Cloud KMS asymmetricSign (ECDSA-P256)                │  │

│  │                                                          │  │

│  │  3\. redis.setex("reconciliation:verified\_balance", 300,  │  │

│  │                 signed\_payload)            *(implemented)* │  │

│  └──────────────────────────────────────────────────────────┘  │

│                          │                                      │

│                          │ Redis (shared, read-only for gateway)│

│                          ▼                                      │

└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐

│  gateway namespace  *(logic implemented and enforced; Priority 1 │
│  is presently unreachable in the reference deployment because   │
│  nothing populates reconciliation:verified_balance — see §5.4)* │

│                                                                 │

│  ControlBarrierFunction.\_read\_cbf\_state\_atomic()               │

│                                                                 │

│  Priority 1: read reconciliation:verified\_balance               │

│              verify KMS signature                               │

│              → source \= "reconciled" | "reconciled\_unsigned"    │

│                                                                 │

│  Priority 2 (production): reconciled balance absent, stale,     │

│              unsigned, or signature-invalid                     │

│              → raise CBFStateUnverifiedError (fail closed;      │

│                 the action is DENIED, not evaluated against     │

│                 a fallback balance)                              │

│                                                                 │

│  Priority 2 (non-production only): fall back to                 │

│              safety:current\_cash; emit CRITICAL audit log       │

│              → source \= "self\_reported"                         │

│                                                                 │

│  OTel span attributes:                                          │

│    safety.balance.source \= "reconciled" | "reconciled\_unsigned"│

│                            | "self\_reported"                    │

│    safety.balance.reconciled \= True | False                     │

└─────────────────────────────────────────────────────────────────┘

---

## Appendix C: Environment Variables

| Variable | Description | Default |
| :---- | :---- | :---- |
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

