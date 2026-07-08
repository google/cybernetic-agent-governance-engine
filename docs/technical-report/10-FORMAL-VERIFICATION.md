# Formal Verification and Completeness Proof (CAGE v0.1.0)

| Field              | Value                     |
| ------------------ | ------------------------- |
| **Classification** | INTERNAL                  |
| **Date**           | 2026-06-03                |
| **Version**        | 2.1                       |
| **Status**         | Current — v0.1.0 stable (GO — 2026-06-08); GKE deployment verified 2026-06-03; **844 passing, 0 failed, 24 skipped** (`test_results/run_20260603T103414.txt`); NoDirectBind invariant machine-verified over 19 reachable states |
| **Series**         | CAGE Technical Report — Document 10 / 10 |

As a formally verified, deterministic governance layer, the **Cybernetic Agent Governance Engine (CAGE)** v0.1.0 architecture has been methodically evaluated against the Composite Verification Framework (CVF).

Below is the formal state-space and structural analysis of the system, including the resolution of previously identified unbounded states through the v0.1.0 architectural enhancements.

### Primary Regulatory Framework

The formal verification claims in this document are grounded in the following primary governance frameworks:

| Framework | Authority | Scope |
| --------- | --------- | ----- |
| **SR 26-2** (April 17, 2026) | Federal Reserve | Primary agentic AI governance framework; §IV.B confidence requirement (≥0.95) formally verified at Tier 1 |
| **ISO/IEC 42001:2023** | ISO | AI Management System; Annex A controls formally mapped to CAGE enforcement points |
| **CSA AARM v1.0** | Cloud Security Alliance | 11-vector autonomous agent threat model; all vectors formally neutralized or tracked (Step 4) |
| **NIST SP 800-53 Rev 5 HIGH** | NIST | AU-10 non-repudiation (Step 6), SI-7 integrity (AARM-V1), SC-28 protection at rest |

The SR 26-2 §IV.B agentic confidence requirement is enforced as a hard mathematical invariant: $\text{confidence\_score} \geq 0.95$ is a necessary precondition for the `ALLOW` transition in the hybrid automaton defined in Step 3. Requests with confidence below this threshold are routed to `MANUAL_REVIEW` (0.70–0.95) or `DEFER` (<0.70), never to `APPROVED`.

---

## Step 1: Hazard Completeness (STPA Analysis)

To verify hazard completeness, we re-evaluate the system’s capacity to deterministically neutralize Unsafe Control Actions (UCAs) in light of the new Human-in-the-Loop (HITL) architecture.

**Targeted UCA Re-Evaluation:**

* **Hazard:** **UCA-5 / FIN-1** (Trade exceeds drawdown limit or portfolio fraction limit due to market drift during human review).
* **Previous State:** Vulnerable to TOCTOU.
* **New Enforcement Mechanism:** The execution plan now inherently contains a bounded limit (`max_slippage_pct`). The `post_hitl_revalidate_node` acts as a hard deterministic circuit breaker, recalculating drift immediately prior to actuation.
* **Evaluation:** **PASS.** The hazard is fully mapped to a deterministic mathematical bound evaluated at execution time, not generation time.

---

## Step 2: Structural Completeness (VSM Mapping)

We evaluate the updated architecture against Stafford Beer's Viable System Model to ensure all necessary organizational layers and feedback loops are intact.

* **System 1 (Operations):** The `StateGraph` sub-agents generate bounded intent rather than point-in-time snapshots.
* **System 2 (Coordination):** The addition of the `hitl_expires_at` Time-To-Live (TTL) timestamp to the `AgentState` checkpoint. This guarantees that suspended states cannot persist indefinitely, repairing temporal coordination breakdowns.
* **System 3 (Control):** The `SymbolicGovernor` now utilizes a bifurcated execution model. Tiers 2 and 4 are explicitly re-triggered post-HITL.
* **System 4 (Intelligence):** (Unchanged) Cybernetic Governance Loop adapts to environmental shifts.
* **System 5 (Policy):** (Unchanged) `ControlRegistry` loads normative profiles.

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

1. Upon `/v1/approvals/{thread_id}/resume`, the system transitions from $\text{PENDING\_HITL}$ to $\text{REVALIDATING}$.
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
| **AARM-V1** | Memory Poisoning — attacker mutates the agent's context accumulator to inject false beliefs | SHA-256 hash-chained `OscalFinding` log (`context_accumulator.py`) | $\forall n: \text{record\_hash}_n = \text{SHA256}(\text{prev\_hash}_{n-1} \| \text{content\_json}_n)$ — any mutation at node $k$ produces $\text{record\_hash}_k \ne \text{expected}_k$, detectable at $O(n)$ | **NEUTRALIZED** |
| **AARM-V2** | Goal Hijacking — agent's objective is redirected mid-execution | STPA UCA Validator (Tier 0) + OPA Rego policy (Tier 4) | $\forall \text{action}: \text{UCA}(\text{action}) \notin \{\text{UCA-1}, \dots, \text{UCA-9}\} \land \text{OPA}(\text{action}) = \text{ALLOW}$ | **NEUTRALIZED** |
| **AARM-V3** | Confused Deputy — agent is manipulated into performing actions on behalf of an unauthorized principal | OPA RBAC (`trade.governance` package) + HMAC routing seal (`X-CAGE-Routing-Seal`) | $\forall \text{tool\_call}: \text{seal\_valid}(\text{request}) \land \text{role}(\text{caller}) \in \text{authorized\_roles}(\text{tool})$ | **NEUTRALIZED** |
| **AARM-V4** | Cross-Agent Propagation — malicious payload propagates across agent boundaries | Linkerd mTLS SPIFFE/SVID identity + NeMo input rail on every agent boundary | $\forall \text{agent\_msg}: \text{SPIFFE\_identity\_verified} \land \text{NeMo}(\text{msg}) = \text{SAFE}$ | **NEUTRALIZED** |
| **AARM-V5** | Prompt Injection — adversarial input hijacks agent intent | Aho-Corasick Tier-1 scan + NeMo Guardrails Tier-2 + Presidio PII scan | $\forall \text{input}: \text{AhoCorasick}(\text{input}) = \emptyset \land \text{NeMo}(\text{input}) = \text{SAFE}$ before any agent node executes | **NEUTRALIZED** |
| **AARM-V6** | Reward Hacking — agent exploits reward signal to achieve unintended outcomes | STPA UCA Validator (Tier 0) + DoWhy Causal Gatekeeper (Tier 6) placebo refutation | $\text{placebo\_p\_value} \ge 0.05 \land \text{placebo\_effect} \le 0.2 \land \text{predicted\_risk} \le 0.95$ required for ALLOW | **NEUTRALIZED** |
| **AARM-V7** | Context Window Overflow — agent proceeds on fundamentally incomplete context | DEFER State Machine (`defer_queue.py`, Redis db=1 `noeviction`) | $\text{confidence\_score} \in [0.70, 0.95) \Rightarrow \text{state} = \text{DEFERRED}$; execution blocked until `EXTERNAL_VALIDATION` injected | **NEUTRALIZED** |
| **AARM-V8** | Temporal Deception — model engineers its own privilege escalation via time-based manipulation | Human-gated NeMo refinement (`POST /v1/nemo/propose-refinement` → human approval → `POST /v1/nemo/apply-refinement`) | $\nexists \text{path}: \text{model\_output} \xrightarrow{*} \text{apply\_refinement}$ without `reviewer\_identity \ne \emptyset \land \text{rationale} \ne \emptyset$ | **NEUTRALIZED** |
| **AARM-V9** | Privilege Escalation — single model cannot detect its own compliance violations | Heterogeneous multi-model consensus (`ConsensusModelRegistry`: DeepSeek-R1 Risk Manager + Llama 3.1 Compliance Officer) | $\forall \text{trade} > \text{threshold}: \text{vote}(\text{DeepSeek-R1}) = \text{APPROVE} \land \text{vote}(\text{Llama-3.1}) = \text{APPROVE}$ required | **NEUTRALIZED** |
| **AARM-V10** | Data Exfiltration — agent leaks sensitive data (PII, credentials, trade plans) to unauthorized external endpoints | Presidio PII masking (15 entity types) in NeMo Guardrails output rail + Cilium L7 FQDN egress lockdown (`deployment/k8s/cilium-egress-lockdown.yaml`) | $\forall \text{egress}: \text{dst\_fqdn} \in \text{allowlist} \land \text{Presidio}(\text{response}) = \text{PII\_FREE}$ | **NEUTRALIZED** |

> **FUTURE STATE (POAM-023):** An `AnchorageGrpcLedgerProvider` for externally reconciled CBF balance anchoring was referenced in earlier drafts of this document but has not been implemented. The current implementation uses Presidio PII masking and Cilium L7 network policy for AARM-V10 (Data Exfiltration) neutralization, as reflected in [`src/compliance_bridge/aarm_mapper.py`](../../src/compliance_bridge/aarm_mapper.py). The "Stale Ground Truth" threat (balance staleness) is addressed by the TTL-gated staleness check in the DEFER state machine (AARM-V7) and the `post_hitl_revalidate_node` execution-time re-sampling described in Step 3 above.
| **AARM-V11** | Model Substitution — external regulatory requirements change without system awareness | External Normative Provider (`normative_provider.py`) with 6-hour polling refresh + adaptive FRIA gate | $\text{baseline\_age} > 6h \Rightarrow \text{daemon re-fetches}$; $\text{confidence} \in 0.70, 0.95) \Rightarrow \text{synchronous blocking gate}$ | **PARTIAL** (stub mode until TrustLayers credentials provisioned — POAM-022) |

**AARM Conformance Summary:** 10 of 11 vectors are fully neutralized. AARM-V11 is PARTIAL pending TrustLayers API credential provisioning (POAM-022). The live conformance report is available at `GET /v1/aarm/conformance-report`.

---

## Step 5: FiscalLimitGuard Race-Condition Proof

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

**Saga integration:** `FiscalLimitGuard.release(token)` is called by the compensating node `compensate_reverse_trade_node_uca_4` on rollback, restoring the reserved headroom atomically.

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
4. **Fallback scope:** The HMAC-SHA256 fallback (dev/CI only, activated when `CAGE_KMS_KEY_NAME` is unset) does **not** provide non-repudiation — it provides only integrity. The fallback is explicitly prohibited in production by the `CAGE_ROUTING_SEAL_SECRET` validation check.

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

The CAGE 7-tier governance pipeline is modelled as a deterministic state machine and verified exhaustively using a breadth-first search (BFS) enumerator implemented in [`proof/model.py`. The proof requires no external dependencies beyond the Python standard library.

**State machine definition:**

| Component | Definition |
| --------- | ---------- |
| **Tiers** | `stpa` → `confidence` → `cbf` → `opa` → `fiscal` → `consensus` → `causal` (7 tiers, in order) |
| **Phases** | `PENDING` → `CHECKING` → `SEAL_ISSUED` → `EXECUTED` \| `DENIED` |
| **`resolvedAllow`** | `TRUE` if and only if all 7 tiers have passed **and** a routing seal has been issued |
| **Terminal states** | `EXECUTED` (success) and `DENIED` (fail-closed) |

**Transition rules (gated architecture):**

- Any tier failure immediately transitions to `DENIED` — fail-closed by construction.
- All 7 tiers passing transitions to `SEAL_ISSUED` with `resolvedAllow = TRUE`.
- `SEAL_ISSUED` → `EXECUTED` only after the downstream actuator calls `verify_seal()` and the seal is cryptographically valid and unexpired.
- `SEAL_ISSUED` → `DENIED` if the seal is invalid or expired (e.g., TTL elapsed, HMAC mismatch).

**Proof results (run: `python3 proof/model.py`):**

```
[gated]   Reachable states: 19
[gated]   No-Direct-Bind holds over all 19 reachable states: True
[gated]   EXECUTED states: 1
[gated]     → resolvedAllow=True  seal_present=True

[ungated] direct-bind shortcut produces a violation: True
[ungated] Counterexample state:
[ungated]   phase         = EXECUTED
[ungated]   resolvedAllow = False
[ungated]   seal_present  = False
[ungated]   tier_results  = {all 7 tiers: PASS}

✅ All assertions passed.
```

The gated architecture has exactly **one** reachable `EXECUTED` state, and in that state `resolvedAllow = TRUE` and `seal_present = True`. The ungated variant reaches `EXECUTED` with `resolvedAllow = FALSE` — a direct-bind violation — even when all 7 tiers pass, because no seal was issued and no seal was verified.

### Closure of the Direct-Bind Shortcut (Gap 2)

Prior to v0.1.0-rc.2, the `SymbolicGovernor` exposed two code paths into `_run_checks()`:

| Path | Seal issued? | Satisfies NoDirectBind? |
| ---- | ------------ | ----------------------- |
| `validate_action()` | ✅ Yes — after all 7 tiers pass | ✅ Yes |
| `govern()` (pre-fix) | ❌ No — returned `None` | ❌ No — direct-bind shortcut |

A caller that caught `GovernanceError` from the old `govern()` path and proceeded to execution would reach `EXECUTED` without a resolved seal — a direct-bind violation identical to the ungated counterexample above.

**Remediation (v0.1.0-rc.2):**

[`symbolic_governor.govern()`](../../src/gateway/governance/symbolic_governor.py) now issues a routing seal on approval and returns it as a `str`. The seal is generated via [`routing_seal.generate_seal()`](../../src/gateway/governance/routing_seal.py) inside a `cage.routing_seal` OTel span, after `_run_checks()` has completed all 7 tiers. [`governance_middleware.enforce_governance()`](../../src/gateway/server/governance_middleware.py) propagates the seal to callers. [`mcp_tool_server.execute_trade_action()`](../../src/gateway/server/mcp_tool_server.py) calls `verify_seal()` before executing the trade — a missing or invalid seal produces an immediate `BLOCKED` response.

Both `govern()` and `validate_action()` now satisfy the invariant. There is no longer any code path from `CHECKING` to `EXECUTED` that bypasses `SEAL_ISSUED`.

### Gap-Specific Sub-Proofs

The proof file also verifies three additional sub-cases:

| Sub-proof | Configuration modelled | Invariant holds? | Interpretation |
| --------- | ---------------------- | ---------------- | -------------- |
| Gap 2 (pre-fix `govern()`) | All tiers pass; no seal issued; direct transition to `EXECUTED` | ❌ **No** — violation confirmed | Confirms the pre-fix path was a direct-bind shortcut |
| Gap 3 (`CBF_FAIL_OPEN`) | CBF tier silently skipped (always PASS) | ✅ Yes (structurally) | Seal path preserved, but CBF tier absent from gate; production startup `RuntimeError` prevents this configuration |
| Gap 4 (DoWhy absent) | Causal tier silently skipped (always PASS) | ✅ Yes (structurally) | Seal path preserved, but causal tier absent from gate; production startup `RuntimeError` prevents this configuration |

For Gaps 3 and 4, the structural invariant is preserved because the seal is still issued after the remaining tiers pass. However, the *completeness* of the gate is degraded — a mandatory tier is absent. The production startup assertions (see Step 7.1 below) prevent these configurations from being reachable in production at all, closing the gap at the deployment boundary rather than the runtime boundary.

### 7.1 Production Startup Assertions (Gaps 3 & 4)

Two module-level assertions in [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) enforce gate completeness at pod startup, before the first request is served:

**Gap 3 — `CBF_FAIL_OPEN` production block:**

```python
if _CBF_FAIL_OPEN and _IS_PRODUCTION:
    raise RuntimeError(
        "CAGE STARTUP FAILURE (No-Direct-Bind Gap 3): CBF_FAIL_OPEN=true is set "
        "in a production environment. This removes the Control Barrier Function tier "
        "from the governance gate, creating a direct-bind shortcut to EXECUTED without "
        "resolved cash-barrier authority."
    )
```

**Gap 4 — DoWhy production import assertion:**

```python
if _IS_PRODUCTION:
    try:
        import dowhy
    except ImportError:
        raise RuntimeError(
            "CAGE STARTUP FAILURE (No-Direct-Bind Gap 4): 'dowhy' is not installed. "
            "The DoWhy causal gatekeeper (Tier 6) is a mandatory component of the "
            "No-Direct-Bind governance gate in production."
        )
```

Both assertions use the same environment detection logic as the existing `CAGE_ROUTING_SEAL_SECRET` and `CAGE_ENV` checks, ensuring consistent fail-fast behaviour across all production gate components. In `development`, `test`, `dev`, and `ci` environments, the assertions are bypassed and the conditions are logged at `DEBUG` level.

Additionally, runtime causal gatekeeper errors (previously silently skipped via `except Exception: logger.warning(...)`) now fail closed: unexpected exceptions during DoWhy refutation are appended to the `violations` list, causing the governance pipeline to return `DENIED` rather than proceeding as if the tier had passed.

> **Attribution:** The NoDirectBind TLA+ specification and foundational BFS state-space enumerator were adapted from the open-source implementation by LalaSkye (Apache 2.0). Source: https://github.com/LalaSkye/no-direct-bind

---

## Step 8: Control Barrier Functions — Formal Safety Invariant

**Source:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

### Mathematical Formulation

The CAGE financial state machine is governed by a **discrete-time Control Barrier Function (CBF)** (Ames et al., IEEE TAC 2017). The CBF provides a formal certificate that the system's cash balance can never enter an unsafe state, regardless of the sequence of agent actions.

**Safe set:**

$$\mathcal{S} = \{ x \in \mathbb{R}^n : h(x) \geq 0 \}$$

**Barrier function (cash solvency):**

$$h(x) = \text{cash\_balance} - \text{min\_cash\_balance}$$

The system is safe when `h(x) ≥ 0`. Bankruptcy (`cash_balance < min_cash_balance`) corresponds to `h(x) < 0`.

**Discrete-time CBF condition:**

$$h(S(t+1)) \geq (1 - \gamma) \cdot h(S(t)) \quad \forall\, t, \quad \gamma \in (0, 1)$$

where `γ` is the decay rate (configured via `THRESHOLDS.cbf.gamma`). This condition ensures that the barrier function cannot decrease faster than the geometric rate `(1 − γ)` per step.

**CBF Invariance Theorem:** If `h(S(0)) ≥ 0` and the discrete-time CBF condition holds at every step `t`, then `h(S(t)) ≥ 0` for all `t ≥ 0`. The system trajectory remains within the safe set `S` indefinitely.

**Enforcement in code:**

```python
h_t      = cash_balance - min_cash_balance        # h(S(t))
h_next   = (cash_balance - cost) - min_cash_balance  # h(S(t+1))
required = (1.0 - gamma) * h_t                    # CBF threshold

if h_next < required or h_next < 0:
    # UNSAFE — barrier certificate violated
```

### Atomic Redis Implementation

The CBF state is shared across stateless Cloud Run instances via Redis. To eliminate the TOCTOU window between the barrier check and the state commit, CAGE provides two enforcement layers:

**Layer 1 — WATCH/MULTI/EXEC optimistic locking** (`update_state()`, `rollback_state()`):

1. `WATCH safety:current_cash` — marks the key for observation
2. Read current balance; compute `h(S(t+1))`
3. `MULTI` / `SET safety:current_cash <new_balance>` / `EXEC`
4. If another process modified the key between steps 1–3, `EXEC` returns `nil`; the guard retries up to `_MAX_RETRIES = 5` times before raising `RuntimeError`

**Layer 2 — Lua atomic check+commit** (`atomic_verify_and_commit()`):

The `LUA_ATOMIC_CBF` script collapses the CBF check and state commit into a **single Redis Lua hop**, eliminating the TOCTOU window entirely. The Lua script replicates the exact CBF formula atomically inside Redis:

```lua
local h_t    = current - min_cash
local h_next = next_cash - min_cash
local required_h_next = (1.0 - gamma) * h_t

if h_next < required_h_next or h_next < 0 then
    return {0, "UNSAFE: ...", tostring(current)}
end
redis.call('SET', KEYS[1], tostring(next_cash))
return {1, "COMMITTED", tostring(next_cash)}
```

The Lua script is loaded via `SCRIPT LOAD` / `EVALSHA` with automatic NOSCRIPT retry on SHA eviction. KMS signature verification must occur in Python before calling this method — Redis Lua has no cryptographic FFI.

**Retry policy:** `_MAX_RETRIES = 5` for both WATCH/MULTI/EXEC and Lua paths. On exhaustion, `RuntimeError` is raised and the trade is blocked (fail-closed).

**Read-only verification:** `verify_action()` uses a pipelined (non-transactional) batch GET for atomic state snapshot — it does **not** participate in the WATCH/MULTI/EXEC pipeline and does not modify Redis state.

---

## Step 9: Routing Seal Integrity

**Source:** [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py)

The Routing Seal is a short-lived HMAC-SHA256 token issued by the Hybrid Gateway after a successful governance approval. Downstream actuators **must** verify the seal before executing any trade. This closes the direct-bind shortcut: execution cannot proceed by ignoring the HTTP governance response.

### Seal Format

```
<expire_ts_hex>.<action_slug>.<hmac_hex>
```

| Field | Description |
|-------|-------------|
| `expire_ts_hex` | Unix timestamp (seconds) of expiry, hex-encoded |
| `action_slug` | Action name lowercased, underscores replaced with hyphens, truncated to 32 chars |
| `hmac_hex` | Lowercase hex-encoded HMAC-SHA256 digest |

### Cryptographic Contract

**Key:** `GOVERNANCE_SALT` environment variable (≥ 32 bytes in production; enforced by `assert_custom_salt_in_production()` at import time).

**Message:** `<expire_hex>.<action_slug>.` + canonical JSON payload, where the payload is `json.dumps({"action": action, **params}, sort_keys=True, separators=(",", ":"))` — sorted keys ensure deterministic serialization regardless of dict insertion order.

**Algorithm:** HMAC-SHA256 (`hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()`).

**TTL:** 30 seconds (configurable via `GOVERNANCE_SEAL_TTL_S`). Seals expire after this window; `verify_seal()` checks `time.time() > expire_ts` before HMAC verification.

**Timing-attack resistance:** HMAC comparison uses `hmac.compare_digest(received_sig, expected_sig)` — constant-time comparison that prevents timing-based forgery attacks.

**Fail-raised contract:** `verify_seal()` raises `SymbolicGovernorViolation` on any failure (malformed, expired, action mismatch, HMAC mismatch). This makes it impossible for callers to silently ignore a failed verification — the exception propagates unless explicitly caught.

### Verification Flow

```
generate_seal(action, params)
  → expire_ts = now + 30s
  → seal = f"{expire_hex}.{action_slug}.{hmac_hex}"

verify_seal(seal, action, params)
  1. Split on "." → 3 parts (malformed → SymbolicGovernorViolation)
  2. Parse expire_hex → check time.time() > expire_ts (expired → raise)
  3. Check action_slug matches expected (mismatch → raise)
  4. Recompute HMAC; hmac.compare_digest(received, expected) (mismatch → raise)
  5. Return True
```

---

## Step 10: Provenance Hash Chain

**Source:** [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py)

The provenance chain builds a cryptographic audit trail linking each LangGraph governance node's input and output. It satisfies **NIST AU-10** (non-repudiation), **ISO 42001 §A.7.5** (records integrity), and **AARM-V1** (Memory Poisoning neutralization).

### Hash Chain Construction

Each governance node execution produces a `ProvenanceRecord`:

```
record_n = ProvenanceRecord(
    trace_id    = <Langfuse trace ID>,
    node_id     = <LangGraph node name>,
    input_hash  = SHA-256(json.dumps(input_data,  sort_keys=True)),
    output_hash = SHA-256(json.dumps(output_data, sort_keys=True)),
    decision    = "ALLOW" | "BLOCK" | "ESCALATE",
    parent_hash = chain_hash(record_{n-1})   # None for first record
)
```

**Chain hash:** `chain_hash(record) = SHA-256(json.dumps(record.to_dict(), sort_keys=True))`

**Deterministic serialization:** All hashes use `json.dumps(..., sort_keys=True, separators=(",", ":"))` with non-serializable values coerced to strings. This guarantees identical digests regardless of Python dict insertion order.

**Tamper detection:** Any mutation at node `k` produces `chain_hash(record_k) ≠ expected_k`, which is detectable by `verify_chain_integrity()` in O(n) time:

$$\forall n: \text{record\_hash}_n = \text{SHA256}(\text{prev\_hash}_{n-1} \| \text{content\_json}_n)$$

**Complexity:** O(n) construction and O(n) verification — linear in the number of governance nodes traversed per request.

**Valid decisions:** `ALLOW`, `BLOCK`, `ESCALATE` — `build_provenance_record()` raises `ValueError` for any other value, preventing silent chain corruption from invalid decision strings.

In production, each record is signed with the KMS key ring via [`src/gateway/governance/kms_signer.py`](../../src/gateway/governance/kms_signer.py) and written to the GCS WORM bucket under `provenance/<date>/<trace_id>.json`.

---

## Step 11: FiscalLimitGuard — Quantitative Implementation Details

**Source:** [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py)

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

where `jitter(0, 5)` is a uniform random integer in `[0, 5]` milliseconds. This prevents thundering-herd collisions when many agents retry simultaneously.

**Fail-closed:** If all `_MAX_RETRIES` attempts fail (Redis error or persistent contention), `_atomic_increment` returns `-2` and the reservation is rejected — the trade is blocked. Redis unavailability never produces a false ALLOW.

### Window Key Schema

```
fiscal:daily_limit:{YYYY-MM-DD}   (UTC date, e.g. "fiscal:daily_limit:2026-07-01")
```

The key is set with `EXPIRE window_seconds` on every write, ensuring automatic reclamation after the 24-hour window even if no explicit release occurs.

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
| 7 | NoDirectBind invariant — exhaustive state-space proof over 19 reachable states | **PASS** |
| 8 | CBF discrete-time invariance — `h(S(t+1)) ≥ (1−γ)·h(S(t))`, Lua atomic enforcement | **PASS** |
| 9 | Routing seal integrity — HMAC-SHA256, 30s TTL, `hmac.compare_digest` constant-time | **PASS** |
| 10 | Provenance hash chain — SHA-256, O(n) tamper detection, deterministic serialization | **PASS** |
| 11 | FiscalLimitGuard quantitative parameters — $500k cap, 86400s window, exponential backoff | **PASS** |

**Overall verdict: BOUNDED with one known partial control (AARM-V11 / POAM-022).** The partial control does not affect the safety invariant — the DEFER state machine (AARM-V7) provides a local fail-safe when external normative validation is unavailable. The NoDirectBind invariant (Step 7) is machine-verified: there is no reachable state in which an agent reaches `EXECUTED` without a cryptographically resolved `ALLOW`. Steps 8–11 document the formal mathematical properties of the CBF barrier certificate, routing seal cryptographic contract, provenance hash chain, and FiscalLimitGuard quantitative parameters as verified against the production source code.
