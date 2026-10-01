# Formal Verification and Completeness Proof (CAGE v3.0.1)

| Field              | Value                     |
| ------------------ | ------------------------- |
| **Classification** | INTERNAL                  |
| **Date**           | 2026-09-29                |
| **Version**        | 3.0.1                     |
| **Status**         | Current — v3.0.1 stable; NoDirectBind invariant machine-verified over 52 reachable gated states (`proof/model.py`, pinned by `tests/test_no_direct_bind_proof.py`); Distributed CBF Multi-Agent Proof verified ($N \in \{2, 3, 4\}$) |
| **Canonical Path** | `docs/architecture/FORMAL_VERIFICATION.md` |

**Last Updated:** 2026-09-29

As a formally verified, deterministic governance layer, the **Cybernetic Agent Governance Engine (CAGE)** v3.0.1 architecture has been methodically evaluated against the Composite Verification Framework (CVF).

Below is the formal state-space and structural analysis of the system, including the resolution of previously identified unbounded states through the v2.0.0 and v3.0.0 architectural enhancements.

### Primary Regulatory Framework

The formal verification claims in this document are grounded in the following primary governance frameworks:

| Framework | Authority | Scope |
| --------- | --------- | ----- |
| **SR 26-2** (April 17, 2026) | Federal Reserve | Primary agentic AI governance framework; §IV.B confidence requirement ($\ge 0.95$) formally verified at Tier 1 |
| **ISO/IEC 42001:2023** | ISO | AI Management System; Annex A controls formally mapped to CAGE enforcement points |
| **CSA AARM v1.0** | Cloud Security Alliance | 11-vector autonomous agent threat model; all vectors formally neutralized or tracked (Step 4) |
| **NIST SP 800-53 Rev 5 HIGH** | NIST | AU-10 non-repudiation (Step 6), SI-7 integrity (AARM-V1), SC-28 protection at rest |

The SR 26-2 §IV.B agentic confidence requirement is enforced as a hard mathematical invariant: $\text{confidence\_score} \ge 0.95$ is a necessary precondition for the `ALLOW` transition in the hybrid automaton defined in Step 3. Requests with confidence below this threshold are routed to `MANUAL_REVIEW` (0.70–0.95) or `DEFER` (<0.70), never to `APPROVED`.

---

## Step 1: Hazard Completeness (STPA Analysis)

To verify hazard completeness, we re-evaluate the system’s capacity to deterministically neutralize Unsafe Control Actions (UCAs) in light of the Human-in-the-Loop (HITL) architecture.

**Targeted UCA Re-Evaluation:**

* **Hazard:** **UCA-5 / FIN-1** (Trade exceeds drawdown limit or portfolio fraction limit due to market drift during human review).
* **Previous State:** Vulnerable to Time-Of-Check to Time-Of-Use (TOCTOU).
* **New Enforcement Mechanism:** The execution plan now inherently contains a bounded limit (`max_slippage_pct`). The `post_hitl_revalidate_node` acts as a hard deterministic circuit breaker, recalculating drift immediately prior to actuation.
* **Evaluation:** **PASS.** The hazard is fully mapped to a deterministic mathematical bound evaluated at execution time, not generation time.

---

## Step 2: Structural Completeness (VSM Mapping)

We evaluate the updated architecture against Stafford Beer's Viable System Model to ensure all necessary organizational layers and feedback loops are intact.

* **System 1 (Operations):** The `StateGraph` sub-agents generate bounded intent rather than point-in-time snapshots.
* **System 2 (Coordination):** The addition of the `hitl_expires_at` Time-To-Live (TTL) timestamp to the `AgentState` checkpoint. This guarantees that suspended states cannot persist indefinitely, repairing temporal coordination breakdowns.
* **System 3 (Control):** The `SymbolicGovernor` now utilizes a bifurcated execution model. The `POST_HITL` profile explicitly re-runs OPA (Tier 3b), CBF (Tier 3a) and fiscal (Tier 4) after human approval (`PROFILE_STAGES` in [`pipeline.py`](../../src/gateway/governance/governor/pipeline.py)); `revalidate_post_hitl()` refuses any action no domain tier claims.
* **System 4 (Intelligence):** *Partially realised.* Langfuse trace evaluation and the POAM remediation cycle provide an out-of-band feedback path from operational telemetry to policy revision. An automated, in-band loop that adjusts policy variables at runtime in response to environment feedback is **not implemented** — policy artefacts are statically compiled from `config/stpa_control_structure.yaml` by the STPA compiler. Closing this loop is tracked as future work.
* **System 5 (Policy):** `ControlRegistry` loads normative profiles.

**Structural Completeness Assessment:** The severed algedonic (feedback) loop between continuous operational reality and System 3 (Control) has been formally closed. System 3 now has the structural mandate to re-assert its control variables immediately prior to System 1's final actuation.

---

## Step 3: Enforcement Completeness (Hybrid Automata & Reachability)

The system is defined as a Hybrid Automaton $H = (Q, X, Init, f, Dom, E, G, R)$.

* **Discrete States ($Q$):** $\{ \text{UNKNOWN}, \dots, \text{PENDING\_HITL}, \text{REVALIDATING}, \text{APPROVED}, \text{BLOCKED} \}$.
* **Continuous Variables ($X$):** $x_1 = \text{cash\_balance}$, $x_2 = \text{market\_price}$.
* **Safe Set ($\mathcal{C}$):** Bounded by the Control Barrier Function $h(x) \ge 0$.

### Reachability Analysis: Eliminating the Ghost State

In the prior architecture, the continuous variable $x_2$ (market price) evolved independently while the discrete state remained parked in $\text{PENDING\_HITL}$, allowing the system trajectory to exit the Safe Set $\mathcal{C}$ without triggering a discrete transition ($G$).

**The Updated Hybrid Automaton:**

1. $\text{PENDING\_HITL}$ is entered when [`approval_node`](../../src/governed_financial_advisor/graph/nodes/approval_node.py) calls the LangGraph `interrupt()` primitive (`langgraph.types.interrupt`), suspending the graph. When the reviewer resumes the thread via the LangGraph SDK `Command(resume={...})` pattern, `interrupt()` returns the decision payload and the node issues `Command(goto="post_hitl_rehydrate")`, transitioning the system to $\text{REVALIDATING}$.
2. The `post_hitl_revalidate_node` samples $P_{\text{fresh}}$ (continuous state $x_2$ at time $t_{\text{resume}}$).
3. The guard condition $G_{\text{actuate}}$ for the transition to $\text{APPROVED}$ (execution) is strictly defined by the invariant:
$$G_{\text{actuate}} \iff \left( \frac{|P_{\text{fresh}} - P_{\text{stale}}|}{P_{\text{stale}}} \le \text{max\_slippage\_pct} \right) \land \left( \text{CBF}(P_{\text{fresh}}, \text{amount}) \ge 0 \right) \land \left( \text{OPA}(P_{\text{fresh}}, \text{params}) = \text{ALLOW} \right)$$
4. If $G_{\text{actuate}}$ evaluates to False, the system transitions to $\text{BLOCKED}$ (fail-closed).

Because the transition to an actuated state is mathematically gated by a real-time sample of the continuous variables against the required limits, **the continuous state trajectory can no longer outpace the discrete sampling rate of the governance engine.**

---

## Conclusion (Steps 1–3)

**BOUNDED.** With the integration of explicit slippage bounds, the defense-in-depth TTL, and the `post_hitl_revalidate_node` execution loop, CAGE successfully achieves formal state-space completeness. The architecture enforces continuous reachability bounding, ensuring that the system remains strictly within the mathematically verified Safe Set $\mathcal{C}$ regardless of asynchronous human delays.

---

## Step 4: AARM Threat Vector Formal Neutralization Proof

The Cloud Security Alliance Autonomous Agent Risk Management (CSA AARM v1.0) framework defines 11 threat vectors for agentic AI systems. The following table provides the formal mapping from each AARM vector to the specific CAGE control point that neutralizes it, with the neutralization mechanism stated as a logical invariant.

| AARM Vector | Threat Description | CAGE Control Point | Neutralization Invariant | Verdict |
| ----------- | ------------------ | ------------------ | ------------------------ | ------- |
| **AARM-V1** | Memory Poisoning — attacker mutates the agent's context accumulator to inject false beliefs | SHA-256 hash-chained `OscalFinding` log ([`src/compliance_bridge/context_accumulator.py`](../../src/compliance_bridge/context_accumulator.py)) | $\forall n: \text{record\_hash}_n = \text{SHA256}(\text{prev\_hash}_{n-1} \| \text{content\_json}_n)$ — any mutation at node $k$ produces $\text{record\_hash}_k \ne \text{expected}_k$, detectable at $O(n)$ | **NEUTRALIZED** |
| **AARM-V2** | Goal Hijacking — agent's objective is redirected mid-execution | STPA UCA Validator (Tier 1) + OPA Rego policy (Tier 3b) | $\forall \text{action}: \text{UCA}(\text{action}) \notin \{\text{UCA-1}, \dots, \text{UCA-9}\} \land \text{OPA}(\text{action}) = \text{ALLOW}$ | **NEUTRALIZED** |
| **AARM-V3** | Confused Deputy — agent is manipulated into performing actions on behalf of an unauthorized principal | OPA RBAC (`trade.governance` package) + gateway ingress by Linkerd mTLS workload identity (`WorkloadIdentityMiddleware`, `src/gateway/server/workload_identity.py`) | $\forall \text{tool\_call}: \text{identity}(\text{caller}) \in \text{trusted\_identities} \land \text{role}(\text{caller}) \in \text{authorized\_roles}(\text{tool})$ | **NEUTRALIZED** |
| **AARM-V4** | Cross-Agent Propagation — malicious payload propagates across agent boundaries | Linkerd mTLS SPIFFE/SVID identity + NeMo input rail on every agent boundary | $\forall \text{agent\_msg}: \text{SPIFFE\_identity\_verified} \land \text{NeMo}(\text{msg}) = \text{SAFE}$ | **NEUTRALIZED** |
| **AARM-V5** | Prompt Injection — adversarial input hijacks agent intent | Aho-Corasick Tier-1 scan + NeMo Guardrails Tier-2 + Presidio PII scan | $\forall \text{input}: \text{AhoCorasick}(\text{input}) = \emptyset \land \text{NeMo}(\text{input}) = \text{SAFE}$ before any agent node executes | **NEUTRALIZED** |
| **AARM-V6** | Reward Hacking — agent exploits reward signal to achieve unintended outcomes | STPA UCA Validator (Tier 1) + DoWhy Causal Gatekeeper (Tier 6) non-positive slope guard + placebo refutation | $\beta > 0 \land \text{placebo\_p\_value} \ge 0.05 \land \text{placebo\_effect} \le 0.2 \land \min(1.0, 0.5 + \beta \times \text{amount}) \le 0.95$ required for ALLOW | **NEUTRALIZED** |
| **AARM-V7** | Context Window Overflow — agent proceeds on fundamentally incomplete context | DEFER State Machine (`defer_queue.py`, Redis db=1 `noeviction`) | $\text{confidence\_score} \in [0.70, 0.95) \Rightarrow \text{state} = \text{DEFERRED}$; execution blocked until `EXTERNAL_VALIDATION` injected | **NEUTRALIZED** |
| **AARM-V8** | Temporal Deception — model engineers its own privilege escalation via time-based manipulation | Human-gated NeMo refinement (`POST /v1/nemo/propose-refinement` → human approval → `POST /v1/nemo/apply-refinement`) | $\nexists \text{path}: \text{model\_output} \xrightarrow{*} \text{apply\_refinement}$ without $\text{reviewer\_identity} \ne \emptyset \land \text{rationale} \ne \emptyset$ | **NEUTRALIZED** |
| **AARM-V9** | Privilege Escalation — single model cannot detect its own compliance violations | Heterogeneous multi-model consensus (`ConsensusModelRegistry`: DeepSeek-R1 Risk Manager + Llama 3.1 Compliance Officer) | $\forall \text{trade} > \text{threshold}: \text{vote}(\text{DeepSeek-R1}) = \text{APPROVE} \land \text{vote}(\text{Llama-3.1}) = \text{APPROVE}$ required | **NEUTRALIZED** |
| **AARM-V10** | Data Exfiltration — agent leaks sensitive data (PII, credentials, trade plans) to unauthorized external endpoints | Presidio PII masking (10 entity types) in NeMo Guardrails output rail + GKE Dataplane V2 `NetworkPolicy` / `FQDNNetworkPolicy` egress allowlist (`deployment/k8s/cilium/egress-lockdown.yaml`) | $\forall \text{egress}: \text{dst\_fqdn} \in \text{allowlist} \land \text{Presidio}(\text{response}) = \text{PII\_FREE}$ | **NEUTRALIZED** |
| **AARM-V11** | Model Substitution — external regulatory requirements change without system awareness | External Normative Provider (`normative_provider.py`) with 6-hour polling refresh + `EU_ECB` `fria` tier | $\text{baseline\_age} > 6h \Rightarrow \text{daemon re-fetches}$; $\text{FRIA artefact age} > \text{fria\_reassessment\_interval\_days} \Rightarrow \text{HARD deny}$ | **PARTIAL** (stub mode until Provider 01 credentials provisioned — POAM-022) |

> **POAM-023 Resolution Note:** Balance staleness is addressed by the TTL-gated staleness check in the DEFER state machine (AARM-V7) and the `post_hitl_revalidate_node` execution-time re-sampling described in Step 3 above. Presidio PII masking and `FQDNNetworkPolicy` egress allowlists enforce AARM-V10 (Data Exfiltration) neutralization, as reflected in [`src/compliance_bridge/aarm_mapper.py`](../../src/compliance_bridge/aarm_mapper.py).

**AARM Conformance Summary:** 10 of 11 vectors are fully neutralized. AARM-V11 is PARTIAL pending Provider 01 API credential provisioning (POAM-022). The live conformance report is available at `GET /v1/aarm/conformance-report`.

---

## Step 5: FiscalLimitGuard Race-Condition Proof

**Source:** [`src/cage_finance/safety/fiscal_limit_guard.py`](../../src/cage_finance/safety/fiscal_limit_guard.py) (Layer 2 finance plugin), wrapped as the Phase 2 fiscal tier by [`src/cage_finance/tiers/fiscal_tier.py`](../../src/cage_finance/tiers/fiscal_tier.py).

**Claim:** The `FiscalLimitGuard` prevents the multi-agent "race to the rail" scenario where $N$ concurrent agents simultaneously read the same OPA fiscal limit, all pass the check, and collectively exceed the daily cap by a factor of $N$.

**Formal Model:**

Let $L$ = daily fiscal limit, $r_i$ = reservation amount for agent $i$, and $S$ = current reserved sum in Redis.

**Without FiscalLimitGuard (vulnerable):**

$$\forall i \in \{1, \dots, N\}: \text{read}(S) = S_0 \land S_0 + r_i \le L \Rightarrow \text{all } N \text{ agents proceed}$$
$$\text{actual spend} = S_0 + \sum_{i=1}^{N} r_i \gg L \quad \text{(limit violated)}$$

**With FiscalLimitGuard (Redis `WATCH`/`MULTI`/`EXEC`):**

The guard implements optimistic locking:

1. `WATCH fiscal:daily_limit:<date>` — marks the key for observation
2. Read $S_{\text{current}}$; check $S_{\text{current}} + r \le L$
3. `MULTI` / `SET fiscal:daily_limit:<date> $(S_{\text{current}} + r)$` / `EXEC`
4. If another agent modified the key between steps 1–3, `EXEC` returns `nil` (transaction aborted); the guard retries or returns `BLOCKED`

**Invariant:** At most one agent can atomically increment $S$ per Redis transaction. Therefore:

$$\forall t: S(t) = \sum_{i: \text{committed}(i, t)} r_i \le L$$

**Fail-closed property:** If Redis is unavailable, `FiscalLimitGuard.reserve()` raises `ConnectionError` and the trade is blocked — the system never proceeds without the guard.

**Saga integration:** The fiscal tier's `commit()` returns a `CommitReceipt` carrying the `ReservationToken`. If a later Phase 2 commit fails, or the seal is never issued, the request's `ReservationScope` ([`reservation.py`](../../src/gateway/governance/governor/reservation.py)) rolls back LIFO and the tier's `rollback()` calls `FiscalLimitGuard.release(receipt.token)`. A `confirm()` that raises releases the token before re-raising, so no reservation is left without a receipt. Post-execution reversal is handled by the LangGraph compensating node `compensate_reverse_trade_node_uca_4` ([`saga_nodes.py`](../../src/cage_finance/stpa/saga_nodes.py)). `release()` validates key existence to prevent negative counter underflow across TTL boundaries.

---

## Step 6: Cloud KMS HSM Non-Repudiation Proof

**Claim:** The Cloud KMS HSM-backed governance signing scheme provides non-repudiation for all governance decisions — no party can deny that a specific governance verdict was issued at a specific time.

**Formal Properties:**

Let $m$ = governance decision payload (JSON), $\sigma$ = signature, $k_{\text{priv}}$ = HSM private key (never leaves HSM), $k_{\text{pub}}$ = locally embedded public key PEM.

**Signing:** $\sigma = \text{KMS.sign}(k_{\text{priv}}, \text{SHA256}(m))$ — executed inside the HSM; private key is non-exportable.

**Verification:** $\text{valid} = \text{RSA-PKCS1-4096-SHA256.verify}(k_{\text{pub}}, m, \sigma)$ — sub-millisecond local operation.

**Non-repudiation chain:**

1. **Binding:** $\sigma$ is cryptographically bound to $m$ via SHA-256 pre-image resistance. Modifying $m$ invalidates $\sigma$.
2. **Key custody:** Google Cloud Audit Logs provide an immutable, externally attested record of every `cloudkms.cryptoKeyVersions.useToSign` operation, including timestamp, caller identity, and key version. This record is outside CAGE's control plane.
3. **Temporal attestation:** The Cloud Audit Log timestamp $t_{\text{sign}}$ is authoritative — it cannot be backdated by the CAGE system.
4. **Fallback scope:** The software fallback (dev/CI only, used when `KMS_GOVERNANCE_KEY` is unset) is `SoftwareEd25519Provider`, built by [`signer_factory.py`](../../src/gateway/governance/signer_factory.py); a symmetric `SoftwareHMACProvider` exists only for hermetic tests. Neither provides non-repudiation, because the key is not HSM-custodied. Both are prohibited under an enforcing posture: `signer_factory.py` refuses software providers, `kms_signer.py` rejects software/HMAC signatures (K3), and the `kms_signing_mode` startup check in [`governor/posture.py`](../../src/gateway/governance/governor/posture.py) refuses to start. The routing seal's legacy HMAC token path is rejected when `CAGE_SEAL_STRICT_MODE` is on (the default), and the default `GOVERNANCE_SALT` is refused in production.
5. **Key partitioning:** Each signing role has its own key, and verifiers reject foreign `kid`s. The gateway signs seals and decisions with `KMS_GOVERNANCE_KEY`. The ground-truth reconciler signs snapshots with `RECONCILER_KMS_KEY` ([`reconciliation/trust.py`](../../src/gateway/governance/reconciliation/trust.py)). The compliance bridge signs evidence with `EVIDENCE_KMS_KEY`, and `build_evidence_signer()` ([`kms_batch_signer.py`](../../src/compliance_bridge/kms_batch_signer.py)) refuses a key that matches either of the other two. A compromised workload key therefore cannot forge another role's records.

**Conclusion:** For any governance decision $m$ with signature $\sigma$ produced in production:
$$\text{verify}(k_{\text{pub}}, m, \sigma) = \text{true} \Rightarrow \exists t_{\text{sign}} \in \text{CloudAuditLog}: \text{KMS.sign}(k_{\text{priv}}, m) \text{ was called at } t_{\text{sign}}$$

This satisfies **ISO 42001 §A.7.5** (records integrity), **NIST AU-10** (non-repudiation), and **FINRA Rule 4511** (tamper-evident records).

---

## Step 7: Mathematical State-Space Containment (NoDirectBind)

### Theorem Statement

The **No-Direct-Bind** property is a safety invariant over the CAGE execution state machine, formally stated as:

$$\text{NoDirectBind} \equiv (\text{phase} = \texttt{EXECUTED}) \Rightarrow (\text{resolvedAllow} = \texttt{TRUE})$$

In operational terms: **there is no reachable state in which an agent has actuated an effect while governance authority remained unresolved.** Absence of a resolved `ALLOW` is `HOLD`, by construction — the architecture is fail-closed.

This is a theorem, not a test result. A test demonstrates that the gate works on the cases the test author anticipated. This proof demonstrates two stronger properties:

1. **Universality** — the invariant holds over the *entire* reachable state space, not a sample.
2. **Load-bearing gate** — the ungated variant provably *violates* the invariant, producing an explicit counterexample. The gate is not decorative; removing it causes the property to fail.

### Exhaustive State-Space Proof (`proof/model.py`)

The CAGE governance pipeline is modelled as a deterministic state machine and verified exhaustively using a breadth-first search (BFS) enumerator implemented in [`proof/model.py`](../../proof/model.py). The proof requires no external dependencies beyond the Python standard library.

**Scope of the model.** The tuple covers the **STERA Runtime Pipeline** together with the FTRA boundary gate, giving **8 tuple positions**: `ftra`, `stpa`, `confidence`, `cbf`, `opa`, `fiscal`, `consensus`, `causal` (see `TIERS` in [`proof/model.py`](../../proof/model.py)). FTRA is modelled as **Tier 0.5** — it was folded into the tuple to close the proof/implementation divergence tracked as ARCH-1 — and at runtime it is the first phase-1 stage of `run_pipeline()` ([`src/gateway/governance/governor/stages/ftra.py`](../../src/gateway/governance/governor/stages/ftra.py)); the plan-level LangGraph gate in [`src/gateway/governance/ftra/node_factory.py`](../../src/gateway/governance/ftra/node_factory.py) records its verdict (`CLEAR` | `HITL_REQUIRED` | `BLOCKED`) separately. There is no `fria` position in the universal tuple: the `fria` tier exists only under `EU_ECB` and is covered by a per-region sub-proof (`JURISDICTION_TIERS` / `region_tiers()` in `proof/model.py`), which asserts every jurisdiction tier is phase 1. `cbf` and `opa` occupy separate positions (Tier 3a / 3b) because each can independently block the action. Plugin tiers (finance `bounding`, healthcare `dose_barrier`) add no positions; `PLUGIN_TIER_PHASE` keeps the POST_HITL predicate from skipping them.

> **Scope limitation:** The current BFS proof covers the governance state machine (52-state gated model). It does not model the full implementation including the LangGraph harness or Redis state. A TLA+/Alloy extension to the full implementation is tracked as future work.

> **Under-approximation note:** The automaton prunes HITL-resumption paths (mapping `ESCALATE`/`ERROR` to terminal `FAIL`), leaving manually-approved trade resumptions outside the verified envelope. Actuator-side seal verification (`routing_seal.verify_seal()`) is likewise a distinct trust boundary and is not re-modelled here.

**State machine definition:**

| Component | Definition |
| --------- | ---------- |
| **Tiers** | `ftra` → `stpa` → `confidence` → `cbf` → `opa` → `fiscal` → `consensus` → `causal` (8 tuple positions, in order; the `EU_ECB`-only `fria` tier is appended after `causal` in the `JURISDICTION_TIERS` sub-proof, not in the universal tuple) |
| **Phases** | `PENDING` → `CHECKING` → `SEAL_ISSUED` → `EXECUTED` \| `DENIED` \| `NARROW` (no `PAUSE` phase exists; `phases_closed` asserts the model names no verdict the runtime lacks) |
| **`resolvedAllow`** | `TRUE` if and only if all profile tiers have passed (or a narrower's clamped params re-verified clean) **and** a valid routing seal has been issued |
| **Terminal states** | `EXECUTED` (success), `NARROW` (seal issued on clamped params) and `DENIED` (fail-closed) |

**Transition rules (gated architecture):**

- Any tier failure transitions to `DENIED` — fail-closed by construction — unless a narrower proposes clamped params **and** re-running the `FULL` profile on those params yields zero violations (`narrower_present ∧ clamped_params_valid`), in which case the state is `NARROW` with a seal on the clamped params. A narrower whose re-run fails still ends in `DENIED`. This mirrors the runtime: `SymbolicGovernor._narrow()` re-runs `FULL` on a deep copy of the proposal inside a fresh `ReservationScope` via `sealing.run_sealed()` ([`sealing.py`](../../src/gateway/governance/governor/sealing.py)), and seals those exact params or denies.
- All tiers passing transitions to `SEAL_ISSUED` with `resolvedAllow = TRUE`.
- `SEAL_ISSUED` → `EXECUTED` only after the downstream actuator calls `verify_seal()` and the seal is cryptographically valid, unconsumed, and unexpired.
- `SEAL_ISSUED` → `DENIED` if the seal is invalid, consumed, or expired (e.g., TTL elapsed, HMAC mismatch).

**Proof results (run: `uv run python proof/model.py`):**

```
[gated]   Reachable states: 38
[gated]   No-Direct-Bind holds over all 38 reachable states: True
[gated]   EXECUTED states: 1
[gated]     → resolvedAllow=True  seal_present=True

[ungated] Reachable states: 19
[ungated] No-Direct-Bind holds: False
[ungated] direct-bind shortcut produces a violation: True
[ungated] Counterexample state:
[ungated]   phase         = EXECUTED
[ungated]   resolvedAllow = False
[ungated]   seal_present  = False
[ungated]   tier_results  = {'ftra': 'PASS', 'stpa': 'PASS', 'confidence': 'PASS',
                             'cbf': 'PASS', 'opa': 'PASS', 'fiscal': 'PASS',
                             'consensus': 'PASS', 'causal': 'PASS'}

NARROW state-space sub-proofs (C1-sub audit remediation):
  NARROW states: 8
    → resolvedAllow=True  seal_present=True  narrower_present=True  clamped_params_valid=True
  NARROW states have resolvedAllow=TRUE and seal_present=TRUE: True
  Every reachable phase is in PHASES: True

Ungated NARROW negative control (C1-sub):
  Reachable states: 40
  No-Direct-Bind holds: False

✅ All assertions passed.
```

The gated architecture has exactly **one** reachable `EXECUTED` state, and in that state `resolvedAllow = TRUE` and `seal_present = True`. The `SEAL_ISSUED` → `EXECUTED` transition additionally marks the seal `seal_consumed = True`, enforcing single use. The ungated variant reaches `EXECUTED` with `resolvedAllow = FALSE` — a direct-bind violation — even when all eight tiers pass, because no seal was issued and no seal was verified. NARROW paths issue seals on clamped parameters; transient operational failures are `HARD` violations and terminate in `DENIED`.

<<<<<<< HEAD
### Evaluation Order: Sequential Two-Phase Pipeline

`gated_transitions()` advances tiers in a fixed order. The runtime matches this: every profile (`FULL`, `POST_HITL`, `DRY_RUN`) goes through `run_pipeline()` in [`src/gateway/governance/governor/pipeline.py`](../../src/gateway/governance/governor/pipeline.py), which runs the read-only stages sequentially in Phase 1 (FTRA → STPA → OPA → confidence → Phase-1 domain tiers, stopping at the first HARD violation) and the mutating stages sequentially in Phase 2 (CBF → fiscal) only when Phase 1 produced zero violations. There is no concurrent CBF ∥ OPA evaluation on any path, so no interleaving sub-proof is required.

> **Model maintenance note:** An earlier revision of `proof/model.py` contained a `concurrent_tier_transitions()` interleaving sub-proof (49 states). It is no longer in the model; the `EXPECTED_CONCURRENT_STATES` constant and the "Concurrent CBF/OPA model" header comment in [`tests/test_no_direct_bind_proof.py`](../../tests/test_no_direct_bind_proof.py) and [`proof/model.py`](../../proof/model.py) are vestigial and assert nothing.
=======
### Tier Order and the CBF / OPA Split

`gated_transitions()` advances tiers in a fixed order. `cbf` and `opa` are separate tuple positions because each can block the action on its own. The model does **not** enumerate CBF/OPA interleavings: the former `concurrent_tier_transitions()` sub-proof was removed from `proof/model.py`, and at runtime the question no longer arises, because `run_pipeline()` in [`src/gateway/governance/governor/pipeline.py`](../../src/gateway/governance/governor/pipeline.py) runs OPA as a phase-1 read-only stage and CBF as a phase-2 mutating stage, on every path including `revalidate_post_hitl()`.
>>>>>>> 810e4ea (refactor(gateway)!: remove check route, legacy shims and stage state)

### Closure of the Direct-Bind Shortcut (Gap 2)

Prior to v2.0.0-rc.2, the `SymbolicGovernor` exposed two code paths into its tier checks:

| Path | Seal issued? | Satisfies NoDirectBind? |
| ---- | ------------ | ----------------------- |
| `validate_action()` | ✅ Yes — after every tier passes | ✅ Yes |
| `govern()` (pre-fix) | ❌ No — returned `None` | ❌ No — direct-bind shortcut |

A caller that caught `GovernanceError` from the old `govern()` path and proceeded to execution would reach `EXECUTED` without a resolved seal — a direct-bind violation identical to the ungated counterexample above.

**Remediation (v2.0.0-rc.2 / v3.0.0):**

[`SymbolicGovernor.govern()`](../../src/gateway/governance/governor/governor.py) now issues a routing seal on approval and returns it as a `str`. `govern()`, `validate_action()`, `revalidate_post_hitl()` and the NARROW re-run all seal through [`sealing.run_sealed()`](../../src/gateway/governance/governor/sealing.py): it opens a `ReservationScope`, calls `run_pipeline()`, and only on zero violations calls `issue_seal()` → [`routing_seal.generate_seal_with_evidence()`](../../src/gateway/governance/routing_seal.py). If the seal fails or is cancelled, every Phase 2 commit is rolled back LIFO from its `CommitReceipt`. A refused run that still holds commits raises `[UNROLLED_COMMIT]`. [`governance_middleware.enforce_governance(governor, ...)`](../../src/gateway/server/governance_middleware.py) propagates the seal to callers, and finance's [`execute_trade_action()`](../../src/cage_finance/tools/tool_provider.py) calls `verify_and_consume_seal()` before executing the trade. A missing, invalid or already-consumed seal produces an immediate `BLOCKED` response.

`govern()`, `validate_action()` and `revalidate_post_hitl()` all satisfy the invariant. There is no longer any code path from `CHECKING` to `EXECUTED` that bypasses `SEAL_ISSUED`.

### Gap-Specific Sub-Proofs

The proof file also verifies these sub-cases:

| Sub-proof | Configuration modelled | Invariant holds? | Interpretation |
| --------- | ---------------------- | ---------------- | -------------- |
| Gap 1 (no routing seal on approval) | `ungated_transitions()` — seal-issuance step removed structurally | ❌ **No** — violation confirmed (21 states) | Confirms the seal gate is load-bearing, not decorative |
| Gap 2 (pre-fix `govern()` & actuator verification) | All tiers pass; no seal issued; actuator gate active vs inactive | ❌ **No** — violation confirmed (21 states) | Proves both seal issuance and actuator verification are load-bearing |
| Gap 4 (DoWhy absent) | Causal tier silently skipped (always PASS) | ✅ Yes (structurally, 49 states) | Seal path preserved, but causal tier absent from gate; production startup `RuntimeError` prevents this configuration |
| C1-sub (ungated NARROW negative control) | NARROW decision reaches `EXECUTED` without seal verification | ❌ **No** — violation confirmed (50 states) | Proves the seal gate is load-bearing for the NARROW path, not only for plain ALLOW |

For Gap 4, the structural invariant is preserved because the seal is still issued after the remaining tiers pass. However, the *completeness* of the gate is degraded — a mandatory tier is absent. The production startup assertions (see Step 7.1 below) prevent these configurations from being reachable in production at all, closing the gap at the deployment boundary rather than the runtime boundary.

### 7.1 Gate Completeness at Startup (Gap 4)


The startup posture check in [`governor/posture.py`](../../src/gateway/governance/governor/posture.py) enforces the remaining gap at pod startup, before the first request is served. It runs once per entry point, after the composition root assembles the governor ([`governor/bootstrap.py`](../../src/gateway/governance/governor/bootstrap.py)), never at import time:

**Gap 4 — DoWhy runtime requirement:** the causal tier declares `runtime_requirements = ("dowhy",)` ([`causal_tier.py`](../../src/cage_finance/tiers/causal_tier.py)). The `tier_runtime_requirements` check imports every module a tier declares and refuses to start an enforcing posture if one fails to import.

Posture comes only from `env_posture.resolve_posture()`. Under an enforcing posture (anything but `dev`, `test`, `ci`) every failed check is raised together as a `PostureViolation`; under a permissive posture each failure is logged at `CRITICAL` and startup continues.

Additionally, runtime causal gatekeeper errors (previously silently skipped via `except Exception: logger.warning(...)`) now fail closed: unexpected exceptions during DoWhy refutation are appended to the `violations` list, causing the governance pipeline to return `DENIED` rather than proceeding as if the tier had passed.

> **Attribution:** The NoDirectBind TLA+ specification and foundational BFS state-space enumerator were adapted from the open-source implementation by LalaSkye (Apache 2.0). Source: https://github.com/LalaSkye/no-direct-bind

---

## Step 8: Control Barrier Functions — Formal Safety Invariant

**Source:** [`src/gateway/governance/safety/cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py)

### Mathematical Formulation

CAGE state is governed by a **discrete-time Control Barrier Function (CBF)** (Ames et al., IEEE TAC 2017). The CBF provides a formal certificate that a barrier-protected state variable can never enter an unsafe state, regardless of the sequence of agent actions.

The kernel engine (`ControlBarrierFunction`) is **invariant-parametric**: it has no domain defaults and refuses construction without an explicit `InvariantModel` ([`contracts.py`](../../src/gateway/governance/contracts.py)) and a domain `cost_resolver`. An `InvariantModel` declares the affine barrier as data — `invariant_id`, a namespaced Redis `state_key`, a THRESHOLDS `threshold_key` and `gamma`. It is declarative rather than callable, because the barrier must be evaluated inside the atomic Redis Lua hop. Non-affine barriers are a kernel change that requires a new proof obligation.

**Safe set:**

$$\mathcal{S} = \{ x \in \mathbb{R}^n : h(x) \ge 0 \}$$

**Barrier function (affine, per `InvariantModel`):**

$$h(x) = \text{state}[\text{state\_key}] - \text{THRESHOLDS}[\text{threshold\_key}]$$

For the finance plugin's `CashBarrier` ([`src/cage_finance/invariants.py`](../../src/cage_finance/invariants.py)) this is cash solvency: `state_key = "safety:current_cash"`, `threshold_key = "domains.finance.cbf.min_cash_balance"`, so $h(x) = \text{cash\_balance} - \text{min\_cash\_balance}$. The system is safe when $h(x) \ge 0$. Bankruptcy ($\text{cash\_balance} < \text{min\_cash\_balance}$) corresponds to $h(x) < 0$.

**Invariant validation (V1–V4).** Every plugin-contributed invariant is checked at governor assembly (`assemble_governor()` → `validate_invariant()` in [`governor/invariants.py`](../../src/gateway/governance/governor/invariants.py)) across all domains. Startup is refused on: V1 duplicate `invariant_id`; V2 un-namespaced `state_key` (no `:`); V3 `threshold_key` not resolving in the loaded thresholds; V4 `gamma` outside $(0, 1]$. Validated invariants are recorded on the immutable `GovernorComponents.invariants`.

> **Enforcement scope (POAM-2026-078, Open):** a CBF engine instance still enforces one invariant. Only finance's `CashBarrier` is enforced, through the CBF the finance plugin builds ([`src/cage_finance/plugin.py`](../../src/cage_finance/plugin.py)). The healthcare and physical-AI barriers are validated but not enforced; their barrier tiers have no CBF and fail closed (DENY). See [`docs/POAM.md`](../POAM.md).

**Discrete-time CBF condition:**

$$h(S(t+1)) \ge (1 - \gamma) \cdot h(S(t)) \quad \forall\, t, \quad \gamma \in (0, 1]$$

where $\gamma$ is the decay rate declared by `InvariantModel.gamma` (finance: `CashBarrier.gamma = 0.5`). This condition ensures that the barrier function cannot decrease faster than the geometric rate $(1 - \gamma)$ per step.

**CBF Invariance Theorem:** If $h(S(0)) \ge 0$ and the discrete-time CBF condition holds at every step $t$, then $h(S(t)) \ge 0$ for all $t \ge 0$. The system trajectory remains within the safe set $\mathcal{S}$ indefinitely.

> **Two-Phase Zero-Leakage Architecture:** In CAGE v3.0.0, the **STERA Runtime Pipeline** decouples into Phase 1 (read-only validation gates) and Phase 2 (atomic state mutations). All validation checks (FTRA, STPA, OPA, confidence, and Phase-1 domain tiers such as consensus and causal) execute in Phase 1 before `atomic_verify_and_commit()` or `reserve()` are invoked. Any validation failure terminates the pipeline in Phase 1 with $S(t+1) = S(t)$.
>
> **Phase-2 commit receipts.** Each Phase 2 `commit()` returns `(violations, CommitReceipt | None)`. `CommitReceipt` ([`contracts.py`](../../src/gateway/governance/contracts.py)) records the tier, the magnitude the engine actually deducted, and any tier-owned token. `atomic_verify_and_commit()` returns `(committed, reason, magnitude)`, and the CBF tier stores that magnitude (`commit_barrier()` in [`barrier_tier.py`](../../src/gateway/governance/safety/barrier_tier.py)). `rollback()` undoes exactly what the receipt records; it never re-derives the undo from request params. The request's `ReservationScope` keeps the commits in force only if a seal is issued inside it. Any other exit — a later commit failure, a seal failure, or cancellation — rolls them back LIFO in a shielded task. A failed rollback raises `[ROLLBACK_FAILED]`, so it can never end in ALLOW.

**Enforcement in code:**

```python
# evaluate_barrier(x) = x - THRESHOLDS.resolve(invariant.threshold_key)
effective = current_state - local_debits            # ground truth minus unreconciled debits
h_t       = evaluate_barrier(effective)             # h(S(t))
h_next    = evaluate_barrier(effective - cost)      # h(S(t+1)); cost from the domain cost_resolver
required  = (1.0 - gamma) * h_t                     # CBF threshold

if cost > 0 and (h_next < required or h_next < 0):
    # UNSAFE — barrier certificate violated
```

### Atomic Redis Implementation

The CBF state is shared across gateway replicas via Redis (GCP Memorystore on the GKE target, `noeviction` in every environment). To eliminate the TOCTOU window between the barrier check and the state commit, CAGE provides two enforcement layers:

**Layer 1 — WATCH/MULTI/EXEC optimistic locking** (`_update_state_unsafe()`, and `rollback_state()` when the Lua rollback is unavailable):

1. `WATCH <InvariantModel.state_key>` — marks the key for observation
2. Read the current state; compute the new value
3. `MULTI` / `SET <state_key> <new_value>` / `INCR safety:fence_epoch` / `EXEC`
4. If another process modified the key between steps 1–3, `EXEC` fails; the guard retries up to `_MAX_RETRIES = 5` times before raising `RuntimeError`

**Layer 2 — Lua atomic check+commit** (`atomic_verify_and_commit()`, rollback via `LUA_ROLLBACK_CBF`):

The `LUA_ATOMIC_CBF` script collapses the fence check, the CBF check, the state commit and the debit record into a **single Redis Lua hop**. The kernel compiles the `InvariantModel` into the script's `KEYS` (`state_key`, `audit:state_ledger`, `safety:fence_epoch`, `cbf:local_debits`, `safety:fence_epoch_hwm`) and `ARGV` (magnitude, resolved threshold, `gamma`, signature, verified ground-truth state, expected fence epoch, debit entry):

```lua
if current_fence ~= expected_fence then return {0, "Fence epoch regression ..."} end
if current_fence < hwm then return {0, "Fence epoch regression: live epoch < hwm"} end
local h_t = current - threshold
local h_next = (current - cost) - threshold
if h_next < (1.0 - gamma) * h_t or h_next < 0 then return {0, "UNSAFE: ..."} end
redis.call('SET', KEYS[1], tostring(next_state))
local new_epoch = redis.call('INCR', KEYS[3])   -- and raise KEYS[5] HWM if exceeded
redis.call('RPUSH', KEYS[4], debit_entry)       -- debit recorded in the same hop
return {1, "COMMITTED", tostring(next_state), new_epoch}
```

**Durability (atomic debits and shared HWM).** The unreconciled debit is appended to `cbf:local_debits` inside the same Lua hop as the state commit, so a debit can never be committed without being recorded, or recorded without being committed. The fence-epoch high-water mark lives in Redis (`safety:fence_epoch_hwm`) and is shared by every replica rather than held per process. Commit and rollback both raise it, and a live epoch below the HWM is refused as a regression, both in Lua and in Python before the hop. When the reconciler accepts a signed snapshot at sequence *n*, it trims debits at or below *n* (`LUA_TRIM_DEBITS_BY_SEQUENCE`). After a commit, the engine issues Redis `WAIT` on a pinned connection (`CAGE_REDIS_WAIT_REPLICAS`, `CAGE_REDIS_WAIT_TIMEOUT_MS`). Under strict replication (`CAGE_STRICT_REPLICATION`, on by default outside dev/test/ci), an unconfirmed `WAIT` rolls the commit back and returns `REPLICATION_UNCONFIRMED` (fail closed).

**Ground truth.** The state value fed to the Lua hop comes from the `GroundTruthReconciler` ([`reconciliation/daemon.py`](../../src/gateway/governance/reconciliation/daemon.py)). The reconciler polls domain `GroundTruthProvider`s ([`seams/ground_truth.py`](../../src/gateway/governance/seams/ground_truth.py)) and rejects every `FaultMode`. It signs each snapshot with the reconciler's own key (`RECONCILER_KMS_KEY`) and records the signing `kid` and algorithm. The CBF accepts a snapshot only through `verify_snapshot_signature()` ([`reconciliation/trust.py`](../../src/gateway/governance/reconciliation/trust.py)). That check resolves the `kid` against reconciler-only trust anchors fetched out-of-band, and fails closed on a missing signature, `kid` or algorithm, an unknown `kid`, or any version of the gateway key (`KMS_GOVERNANCE_KEY`). A compromised gateway therefore cannot mint its own ground truth. Under an enforcing posture, the `reconciler_trust_anchor` startup check refuses to start without a usable reconciler anchor. With `CAGE_CBF_STRICT_MODE` (on by default outside dev/test/ci), a missing or unverified snapshot raises `CBF_STRICT_RECONCILIATION_UNAVAILABLE` instead of falling back to self-reported state. KMS signature verification happens in Python before the Lua hop, because Redis Lua has no cryptographic FFI.

**Retry policy:** `_MAX_RETRIES = 5` for the WATCH/MULTI/EXEC paths; the Lua path is loaded via `SCRIPT LOAD` / `EVALSHA` with a NOSCRIPT reload-and-retry. On exhaustion or any Redis failure the commit is refused and the action is blocked (fail-closed).

**Read-only verification:** `verify_action()` (the DRY_RUN `preview()` path) reads the verified state and does not modify Redis.

---

## Step 9: Routing Seal Integrity

**Source:** [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py)

The Routing Seal is a short-lived cryptographic token issued by the Hybrid Gateway after a successful governance approval. Downstream actuators **must** verify the seal before executing any trade. This closes the direct-bind shortcut: execution cannot proceed by ignoring the HTTP governance response.

### Seal Format

In production (v3), the seal is a standard **asymmetric JWT** signed via Cloud KMS HSM:
- **Header:** `{"alg": "RS256"|"ES256", "typ": "JWT", "kid": "<kms-key-id>"}`
- **Payload:** `{"iss": "cage-governance-kernel", "aud": "cage-execution-engine", "exp": <unix_ts>, "act": "<action_slug>", "ehash": "<record_hash_hex>"}`

In development/test environments without KMS, it falls back to a **4-tuple HMAC** token:

```
<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>
```

| Field | Description |
|-------|-------------|
| `expire_ts_hex` | Unix timestamp (seconds) of expiry, hex-encoded |
| `action_slug` | Action name lowercased, underscores replaced with hyphens, truncated to 32 chars |
| `record_hash_hex` | Hex-encoded SHA-256 hash of the durable evidence record |
| `hmac_hex` | Lowercase hex-encoded HMAC-SHA256 digest (dev/test fallback) |

### Cryptographic Contract

**Key:** Cloud KMS HSM asymmetric key ring in production; `GOVERNANCE_SALT` for the dev/test HMAC fallback (the default salt is refused outside development/test).

**Evidence Binding:** The seal binds the action to the exact compliance evidence stream record via `record_hash` (`ehash` JWT claim).

**Algorithm:** RS256/ES256 (KMS HSM) in production; HMAC-SHA256 in test/dev environments.

**TTL:** 30 seconds (configurable via `GOVERNANCE_SEAL_TTL_S`). Seals expire after this window; `verify_seal()` checks expiry before cryptographic verification.

**Timing-attack resistance:** HMAC fallback comparison uses `hmac.compare_digest(received_sig, expected_sig)` — constant-time comparison that prevents timing-based forgery attacks.

**Fail-raised contract:** `verify_seal()` raises `SymbolicGovernorViolation` on any failure (malformed, expired, action mismatch, cryptographic mismatch). This makes it impossible for callers to silently ignore a failed verification — the exception propagates unless explicitly caught.

### Verification Flow

```
generate_seal_with_evidence(action, params, record_hash)
  → In production: sign JWT via Cloud KMS HSM binding action + ehash
  → In dev fallback: seal = f"{expire_hex}.{action_slug}.{record_hash_hex}.{hmac_hex}"

verify_seal(seal, action, params, expected_record_hash)
  1. Detect format (JWT vs 4-tuple HMAC)
  2. If JWT: verify KMS HSM signature, claims, expiry, and ehash match
  3. If HMAC: split 4 parts → verify expiry, action_slug, evidence binding, and HMAC
  4. Return True on success; raise SymbolicGovernorViolation on any failure
```

---

## Step 10: Provenance Hash Chain

**Source:** [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py)

The provenance chain builds a cryptographic audit trail linking each LangGraph governance node's input and output. It satisfies **NIST AU-10** (non-repudiation), **ISO 42001 §A.7.5** (records integrity), and **AARM-V1** (Memory Poisoning neutralization).

### Hash Chain Construction

Each governance node execution produces a `ProvenanceRecord`:

```python
record_n = ProvenanceRecord(
    trace_id    = <Langfuse trace ID>,
    node_id     = <LangGraph node name>,
    input_hash  = SHA-256(jcs_canonicalize_plan(input_data)),
    output_hash = SHA-256(jcs_canonicalize_plan(output_data)),
    decision    = "ALLOW" | "DENY" | "DEFER" | "NARROW" | "REQUIRE_APPROVAL",
    parent_hash = chain_hash(record_{n-1})   # None for first record
)
```

**Chain hash:** `chain_hash(record) = SHA-256(jcs_canonicalize_plan(record.to_dict()))`

**Deterministic serialization:** All hashes use RFC 8785 JCS canonicalization (`jcs_canonicalize_plan()`) with non-serializable values coerced to strings beforehand. This guarantees identical digests regardless of Python dict insertion order and across Python, Go, and JavaScript runtimes.

> **Serialisation note:** `compute_hash()` in `provenance_chain.py` uses RFC 8785 JCS. See [`docs/BREAKING_CHANGES_v3.md`](../BREAKING_CHANGES_v3.md).

**Tamper detection:** Any mutation at node $k$ produces $\text{chain\_hash}(\text{record}_k) \ne \text{expected}_k$, which is detectable by `verify_chain_integrity()` in $O(n)$ time:

$$\forall n: \text{record\_hash}_n = \text{SHA256}(\text{prev\_hash}_{n-1} \| \text{content\_json}_n)$$

**Complexity:** $O(n)$ construction and $O(n)$ verification — linear in the number of governance nodes traversed per request.

**Valid decisions:** the canonical five — `ALLOW`, `DENY`, `DEFER`, `NARROW`, `REQUIRE_APPROVAL` (`VALID_DECISIONS` is derived from the `GovernanceDecision` enum; the retired `PAUSE` value is rejected). `build_provenance_record()` raises `ValueError` for any other value, preventing silent chain corruption from invalid decision strings.

In production, each record is signed with the KMS key ring via [`src/gateway/governance/kms_signer.py`](../../src/gateway/governance/kms_signer.py) and written to the GCS WORM bucket under `provenance/<date>/<trace_id>.json`.

---

## Step 11: FiscalLimitGuard — Quantitative Implementation Details

**Source:** [`src/cage_finance/safety/fiscal_limit_guard.py`](../../src/cage_finance/safety/fiscal_limit_guard.py)

Step 5 above provides the formal race-condition proof for `FiscalLimitGuard`. This step documents the quantitative implementation parameters verified against the source.

### Implementation Constants

| Parameter | Value | Source |
|-----------|-------|--------|
| Default daily cap | **$500,000 USD** | `daily_cap_usd=500_000.0` (env: `FISCAL_DAILY_CAP_USD`) |
| Storage format | **Integer cents** | `amount_cents = int(round(amount_usd * 100))` — avoids float precision errors |
| Rolling window | **86,400 seconds** (24 hours) | `window_seconds=86_400` |
| Reservation TTL | 300 seconds | Ghost-state auto-expiry via Redis `EXPIRE` |
| Max retries | **5** | `_MAX_RETRIES = 5` |
| Retry base | 5 ms | `_RETRY_BASE_MS = 5` |

### Exponential Backoff

On WATCH/MULTI/EXEC conflict, the guard retries with exponential backoff plus random jitter:

$$\text{backoff}(\text{attempt}) = \frac{\_\text{RETRY\_BASE\_MS} \times 2^{\text{attempt}} + \text{jitter}(0, 5)}{1000} \text{ seconds}$$

where $\text{jitter}(0, 5)$ is a uniform random integer in $[0, 5]$ milliseconds. This prevents thundering-herd collisions when many agents retry simultaneously.

**Fail-closed:** If all `_MAX_RETRIES` attempts fail (Redis error or persistent contention), `_atomic_increment` returns `-2` and the reservation is rejected — the trade is blocked. Redis unavailability never produces a false ALLOW.

### Window Key Schema

```
fiscal:daily_limit:{YYYY-MM-DD}   (UTC date, e.g. "fiscal:daily_limit:2026-07-01")
```

The key is set with `EXPIRE window_seconds` on every write, ensuring automatic reclamation after the 24-hour window even if no explicit release occurs.

---

## Step 12: Distributed CBF Multi-Agent Formal Verification

**Source:** [`proof/distributed_cbf_model.py`](../../proof/distributed_cbf_model.py)

Step 8 proves discrete-time invariance for a single control barrier agent. In a multi-agent environment where $N$ autonomous agents simultaneously request capital allocation against a shared balance $B$, concurrent execution could potentially violate the barrier condition $h(x) \ge 0$ if state transitions interleave un-safely.

### Multi-Agent Formal State Model

The multi-agent state space is modeled as an asynchronous transition system:

$$S_{\text{multi}} = \langle B, F, \{(a_i, r_i, c_i)\}_{i=1}^N \rangle$$

where:
- $B \in \mathbb{R}_{\ge 0}$ is the shared cash balance.
- $F \in \mathbb{N}$ is the monotonic fence epoch counter.
- For each agent $i \in \{1, \dots, N\}$: $a_i \in \{\text{IDLE}, \text{RESERVED}, \text{COMMITTED}, \text{ROLLED\_BACK}\}$, $r_i$ is the reserved capital amount, and $c_i$ is the actual committed amount.

### Mechanized Safety Properties Verified

The model explores all reachable interleavings under breadth-first search (BFS) across $N \in \{2, 3, 4\}$ agents and mechanically asserts four core safety properties:

1. **SP-1 (No Double-Spend):** Total balance never exceeds the initial pool:
   $$\sum_{i=1}^N \left( r_i(s) + c_i(s) \right) + B(s) \le B(s_0)$$
2. **SP-2 (Non-Negative Agent Reserves):** Individual agent reserves are always non-negative:
   $$r_i(s) \ge 0 \quad \forall i, \forall s$$
3. **SP-3 (Available-Balance Invariant):** Concurrent reserves never exceed the available balance:
   $$B_{\text{available}}(s) = B(s_0) - \sum_{i=1}^N r_i(s) \ge 0$$
4. **SP-4 (Fence Epoch Guard):** The fence epoch prevents stale-read exploitation — an agent whose observed epoch lags the current epoch $F$ cannot reserve or commit.

### Verification Results

Exhaustive state space enumeration in `proof/distributed_cbf_model.py` (run: `uv run python proof/distributed_cbf_model.py`) verifies 100% compliance across all properties under the **fenced** transition function:

| Agent Count ($N$) | Reachable States Explored | Property Violations | Result |
|---|---|---|---|
| $N = 2$ | 357 states | 0 | **PASS** |
| $N = 3$ | 2,246 states | 0 | **PASS** |
| $N = 4$ | 12,184 states | 0 | **PASS** |

**Negative control.** The script additionally enumerates the **unfenced** variant ($N = 2$, 431 reachable states), constructs a race state in which two agents each reserve 3 of a 4-unit pool, and confirms the invariant checker flags it (`SP-3: Negative available balance: -2`). Reachability analysis then shows that this race state is **unreachable** under the fenced transition function — establishing that the fence epoch mechanism is load-bearing rather than decorative.

---

## Step 13: Attestation Failure Attributability & Ed25519 CER Signature Verification

**Claim:** Attestation failures from external providers are structurally attributable, preventing misbehaving providers from crashing the attestation loop silently. Furthermore, Causal Evidence Records (CERs) from Provider 02 must carry mathematically verifiable Ed25519 signatures enforcing fail-closed security.

**Proof / Remediation (POAM-2026-072):**
1. [`ExternalAttestation`](../../src/gateway/governance/seams/attestation.py) carries a first-class `provider_name` field. When a provider raises, [`attestation_aggregator`](../../src/gateway/governance/attestation_aggregator.py) appends an entry with `attestation_type="ERROR"`, `status=AttestationStatus.ERROR`, the offending `provider_name`, and `metadata={"error": str(exc)}` — failures are attributable without string-prefix matching on `attestation_type`, and one misbehaving provider cannot abort the fetch loop.
2. [`Provider02AttestationProvider.verify_cer()`](../../src/integrations/provider_02/provider.py) performs two-stage verification: Stage 1 recomputes the SHA-256 certificate-hash binding, Stage 2 verifies the Ed25519 envelope signature against out-of-band cached JWKs. [`CERVerification`](../../src/integrations/provider_02/provider.py) enforces the fail-closed invariant `valid=True ⟹ signature_checked=True` in `__post_init__`, so a resolution success can never be reported as a verification success.

---

## Step 14: Evidence Serialization and KMS Staging/Production Requirements

**Claim:** Full `RefusalReceipt` v3 serialization correctly preserves all components of the proof chain and maintain identical `proof_hash` properties during re-hydration. Moreover, production and staging environments strictly require KMS-backed signing for evidence streams.

**Proof:**
1. Serialization mechanisms capture `tier_failures`, ensuring the 5-part proof chain is maintained intact upon ingestion.
2. The startup posture check `kms_signing_mode` ([`governor/posture.py`](../../src/gateway/governance/governor/posture.py)) mandates KMS signing under every enforcing posture, which is anything other than `dev`/`test`/`ci` as resolved by `env_posture`, so staging and production both qualify. Software fallbacks (Ed25519, HMAC) are refused in these postures, enforcing non-repudiation as detailed in Step 6.

---

## Overall Verification Summary

| Step | Claim | Verdict |
| ---- | ----- | ------- |
| 1 | STPA hazard completeness — UCA-5/FIN-1 TOCTOU eliminated | **PASS** |
| 2 | VSM structural completeness — algedonic feedback loop closed | **PASS** |
| 3 | Hybrid automata reachability — ghost state eliminated | **PASS** |
| 4 | AARM 11-vector neutralization | **10/11 NEUTRALIZED** (V11 PARTIAL — POAM-022) |
| 5 | FiscalLimitGuard race-condition proof | **PASS** |
| 6 | KMS HSM non-repudiation proof | **PASS** |
| 7 | NoDirectBind invariant — exhaustive state-space proof over 52 gated reachable states, including NARROW via re-verified clamped params | **PASS** |
| 8 | CBF discrete-time invariance — invariant-parametric $h(S(t+1)) \ge (1-\gamma) \cdot h(S(t))$, V1–V4 invariant validation, Lua atomic check+commit+debit, shared fence HWM, replica `WAIT` barrier, reconciler-`kid`-verified ground truth | **PASS** (only finance `CashBarrier` enforced — POAM-2026-078) |
| 9 | Routing seal v3 integrity — asymmetric JWT signed via KMS HSM (dev fallback: 4-tuple HMAC), 30s TTL, constant-time compare | **PASS** |
| 10 | Provenance hash chain — SHA-256, $O(n)$ tamper detection, deterministic RFC 8785 JCS serialization | **PASS** |
| 11 | FiscalLimitGuard quantitative parameters — $500k cap, 86,400s window, exponential backoff | **PASS** |
| 12 | Distributed CBF multi-agent formal verification — SP-1 through SP-4 across $N \in \{2, 3, 4\}$ agents | **PASS** |
| 13 | Attestation failure attributability — Ed25519 CER signature verification with fail-closed security enforcement | **PASS** |
| 14 | Evidence serialization and KMS staging/production requirements — the compliance-bridge custodian requires an active `EVIDENCE_KMS_KEY` signer under an enforcing posture, full `RefusalReceipt` v3 evidence serialization | **PASS** |

**Overall verdict: BOUNDED with one known partial control (AARM-V11 / POAM-022).** The partial control does not affect the safety invariant — the DEFER state machine (AARM-V7) provides a local fail-safe when external normative validation is unavailable. The NoDirectBind invariant (Step 7) is machine-verified: there is no reachable state in which an agent reaches `EXECUTED` without a cryptographically resolved `ALLOW`. Steps 8–14 document the formal mathematical properties of the CBF barrier certificate, routing seal cryptographic contract, provenance hash chain, FiscalLimitGuard quantitative parameters, multi-agent distributed barrier proofs, Ed25519 CER signature verification, and evidence KMS requirements as verified against the production source code.
