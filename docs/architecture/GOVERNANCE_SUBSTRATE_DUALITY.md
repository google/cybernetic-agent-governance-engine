# CAGE — Governance Layer vs. Enforcement Substrate: Architectural Analysis

**Document type:** Architectural Analysis & Strategic Positioning
**Status:** INTERNAL — For engineering and executive review
**Date:** 2026-07-18
**Authority:** Supplements `docs/architecture/SUBSTRATE_MOAT_STRATEGY.md` and
`docs/project/CAGE_ONE_PAGER.md`

> **Framing note:** This document analyses the "Governance Layer vs. Enforcement
> Substrate" duality as a new conceptual framework for positioning CAGE in
> enterprise AI conversations. It maps the duality directly to CAGE's existing
> codebase, identifies where CAGE already instantiates the substrate, and
> specifies the engineering work required to make the handshake between the two
> layers machine-readable and bidirectional.

---

## 1. The Duality Defined

The conversation framing introduces a two-layer model for enterprise AI
governance:

| Layer | Alias | Role | Industry examples |
|---|---|---|---|
| **Governance Layer** | The Specification | Defines policy, risk posture, and institutional intent | NIST RMF, OSCAL, ISO/IEC 42001, SR 26-2, EU AI Act |
| **Enforcement Substrate** | The Execution | Translates high-level policy declarations into machine-readable, out-of-process invariants that physically gate the runtime | CAGE |

The thesis is that the industry has spent years perfecting the Specification
Layer while leaving the Substrate Layer as a manual, post-hoc activity. The
most effective enterprise architectures will be those where **policy-as-code
(OSCAL/Lula) feeds directly into infrastructure-as-code (CAGE-style substrate
boundaries)**.

This is not a new claim for CAGE — it is the central thesis of
[`SUBSTRATE_MOAT_STRATEGY.md`](SUBSTRATE_MOAT_STRATEGY.md). What the framing
adds is a **vocabulary** that is legible to governance architects and compliance
officers who do not read Rego or Redis Lua scripts. This document maps that
vocabulary onto CAGE's concrete implementation.

---

## 2. Where CAGE Already Is the Substrate

The following table maps each substrate property claimed in the framing to the
specific CAGE implementation that instantiates it. Every claim is grounded in
committed code.

### 2.1 "Machine-readable, out-of-process invariants"

| Substrate property | CAGE implementation | File |
|---|---|---|
| Compiled hazard model (not interpreted at runtime) | STPA UCAs compiled to OPA Rego AST at build time via `stpa_compiler.py`; the compiled artifact is immutable at runtime — an agent cannot modify its own invariants even during a full container compromise | [`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) |
| Math-backed safety certificate | Discrete-time CBF: `h(S(t+1)) >= (1-γ)*h(S(t))` — a theorem, not a policy rule | [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) |
| Out-of-process policy engine | OPA runs as a separate process; CAGE calls it over HTTP — the agent cannot tamper with the policy evaluator | [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) |
| Multi-jurisdiction compliance registry | `ControlRegistry` resolves `CTRL_*` IDs to jurisdiction-specific regulatory citations at runtime from `config/compliance/{REGION}_BASELINE.json` | [`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py) |

### 2.2 "Physically gate the runtime"

| Substrate property | CAGE implementation | File |
|---|---|---|
| Zero-TOCTOU database commit gate | `atomic_verify_and_commit()` collapses CBF check and state commit into a single Redis Lua script — no Python round-trip between check and write | [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py) |
| Cryptographic routing seal | HMAC-SHA256 seal issued after full 7-tier pipeline approval; downstream actuators cannot execute without verifying the seal | [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py) |
| Fail-closed startup assertion | `RuntimeError` at module import time if `CBF_FAIL_OPEN=true` in production — the container fails to start rather than degrading to an unguarded state | [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py) |
| DEFER state machine | 4-state machine (PARK → HYDRATE → REPLAY) prevents binary forced decisions on incomplete context; parked in Redis `db=1` with 4-hour TTL | [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py) |
| Human-gated HITL interrupt | LangGraph `interrupt_before=["governed_trader"]` pauses execution; resumes only on explicit `POST /v1/approvals/{thread_id}/resume` with reviewer identity and rationale | [`src/governed_financial_advisor/graph/graph.py`](../../src/governed_financial_advisor/graph/graph.py) |

### 2.3 "Policy-as-code feeds into infrastructure-as-code"

This is the **handshake** the framing describes. CAGE already implements the
right half of this handshake (substrate enforcement). The left half — ingesting
OSCAL/Lula policy declarations and compiling them into CAGE enforcement
artifacts — is proposed future work (previously tracked as "Phase A" in a
now-removed implementation plan; see §9 for the current action items).

Current state of the handshake:

```
[OSCAL/Lula policy-as-code]
        │
        │  ← GAP: no machine-readable ingestion path (Phase A, Gap 1)
        ▼
[CAGE stpa_control_structure.yaml]  ← manual authoring today
        │
        │  stpa_compiler.py  ← IMPLEMENTED
        ▼
[OPA Rego AST + NeMo Colang + CBF + LangGraph Saga nodes]
        │
        │  SymbolicGovernor._run_checks()  ← IMPLEMENTED
        ▼
[Redis atomic Lua commit gate]  ← IMPLEMENTED
        │
        │  routing_seal.py  ← IMPLEMENTED
        ▼
[Tool execution / actuator endpoint]
```

**Update (v2.1.0):** The OSCAL and Lula ingress adapters are now implemented:
- [`src/gateway/governance/ingress/oscal_adapter.py`](../../src/gateway/governance/ingress/oscal_adapter.py) — `translate_oscal()` maps OSCAL implemented-requirements to CAGE UCAs via `_OSCAL_STATUS_TO_UCA_TYPE`
- [`src/gateway/governance/ingress/lula_adapter.py`](../../src/gateway/governance/ingress/lula_adapter.py) — `translate_lula()` extracts OPA Rego modules and Kubernetes resource specs from Lula validation manifests
- [`src/gateway/governance/ingress/aaif_adapter.py`](../../src/gateway/governance/ingress/aaif_adapter.py) — `translate_aaif()` maps AAIF stage names to CAGE tiers
- [`src/gateway/governance/ingress/agw_adapter.py`](../../src/gateway/governance/ingress/agw_adapter.py) — `AgwAdapter` with OIDC token validation for Agent Gateway Protocol absorption

The remaining gap is a `POST /governance/ingest-policy` CI/CD-callable endpoint (not yet implemented) and a bidirectional push webhook from CAGE to the Governance Layer.

---

## 3. The Handshake Architecture — What Needs to Be Built

To make the "policy-as-code feeds into infrastructure-as-code" claim
technically complete, three new components are required — see the action
items in §9.

### 3.1 OSCAL Policy Ingestion Adapter ✅ IMPLEMENTED

**Status:** Implemented in v2.1.0. See [`src/gateway/governance/ingress/oscal_adapter.py`](../../src/gateway/governance/ingress/oscal_adapter.py).

**What it does:** `translate_oscal()` accepts an OSCAL component definition and translates `implemented-requirements` to CAGE UCA format via `_OSCAL_STATUS_TO_UCA_TYPE` mapping. `oscal_to_control_structure_patch()` produces a partial `ControlStructureModel` dict from an OSCAL document.

### 3.2 Lula Validation Manifest Adapter ✅ IMPLEMENTED

**Status:** Implemented in v2.1.0. See [`src/gateway/governance/ingress/lula_adapter.py`](../../src/gateway/governance/ingress/lula_adapter.py).

**What it does:** `translate_lula()` extracts inline Rego from OSCAL-wrapped Lula back-matter and Kubernetes resource specs from Lula validation manifests. `lula_to_opa_bundle_patch()` produces an OPA bundle patch for the policy engine.

### 3.3 Policy Ingestion API Endpoint

**What it does:** Exposes `POST /governance/ingest-policy` on the Gateway
Service, accepting ACS/AAIF/OSCAL/Lula specs and returning a compiled artifact
bundle with a `policy_version_id`.

**Why it closes the gap:** Makes the handshake callable from CI/CD pipelines.
A governance architect authors controls in OSCAL; the CI/CD pipeline calls
`POST /governance/ingest-policy`; CAGE returns compiled OPA Rego + CBF
parameters + NeMo Colang rails; the pipeline deploys the compiled artifacts.
This is the "commit boundary" enforcement the framing describes.

**Proposed location:** Extend [`src/gateway/server/hybrid_server.py`](../../src/gateway/server/hybrid_server.py) with the new endpoint; add §11 to [`docs/CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md).

> **Note:** The individual ingress adapters (OSCAL, Lula, AAIF, AGW) are implemented in `src/gateway/governance/ingress/`. The unified `POST /governance/ingest-policy` HTTP endpoint is not yet implemented.

---

## 4. The Bidirectional Feedback Loop

The framing describes a one-way flow: Governance Layer → Enforcement Substrate.
CAGE's existing architecture already implements a **bidirectional** feedback
loop that the framing does not yet articulate. This is a differentiation
opportunity.

```
[Governance Layer: OSCAL/Lula/NIST RMF]
        │                        ▲
        │  policy-as-code        │  compliance evidence
        │  ingestion (Gap 1)     │  (IMPLEMENTED)
        ▼                        │
[CAGE Enforcement Substrate]     │
        │                        │
        ├─ OPA Rego AST          │
        ├─ CBF invariants        │
        ├─ NeMo Colang rails     │
        ├─ LangGraph Saga nodes  │
        │                        │
        ▼                        │
[Runtime enforcement]            │
        │                        │
        ├─ KMS-signed audit trail ──────────────────────────────────┐
        ├─ OSCAL Assessment Results export ─────────────────────────┤
        ├─ CSA AARM Conformance Report ─────────────────────────────┤
        ├─ SSE governance event stream ─────────────────────────────┤
        └─ Lula validation re-run trigger ──────────────────────────┘
                                                                    │
                                                                    ▼
                                              [compliance_bridge: oscal_exporter.py,
                                               aarm_report_generator.py,
                                               lula_scheduler.py]
```

The right side of this diagram — compliance evidence flowing back to the
Governance Layer — is **already implemented** in `src/compliance_bridge/`:

| Evidence output | Implementation | File |
|---|---|---|
| OSCAL 1.1.2 Assessment Results | `GET /v1/oscal/assessment-results` | [`src/compliance_bridge/oscal_exporter.py`](../../src/compliance_bridge/oscal_exporter.py) |
| CSA AARM Conformance Report | `GET /v1/aarm/conformance-report` | [`src/compliance_bridge/aarm_report_generator.py`](../../src/compliance_bridge/aarm_report_generator.py) |
| Lula validation scheduling | Background scheduler | [`src/compliance_bridge/lula_scheduler.py`](../../src/compliance_bridge/lula_scheduler.py) |
| KMS-signed audit trail | `audit:state_ledger` Redis list | [`src/gateway/governance/kms_signer.py`](../../src/gateway/governance/kms_signer.py) |
| Real-time governance events | SSE stream | [`src/compliance_bridge/sse_events.py`](../../src/compliance_bridge/sse_events.py) |

This bidirectional loop is the correct answer to the "why do you need both
layers?" question: the Governance Layer authors policy; the Substrate enforces
it and generates machine-readable evidence; the evidence feeds back into the
Governance Layer to close the audit cycle. Neither layer is complete without
the other, and CAGE is the only component that can generate the evidence the
Governance Layer needs to satisfy regulators.

---

## 5. Positioning Implications — What This Framing Enables

### 5.1 The "Handshake" Narrative

The framing positions CAGE not as an opponent of governance frameworks but as
the **essential infrastructure that makes governance actionable**. The
"handshake" metaphor is technically precise:

- The Governance Layer (NIST RMF/OSCAL/Lula) produces a **specification** —
  a machine-readable declaration of what controls are required.
- CAGE's substrate consumes that specification and produces **enforcement
  artifacts** — compiled OPA Rego AST, CBF parameters, NeMo Colang rails —
  that physically gate the runtime.
- The substrate then produces **compliance evidence** — KMS-signed audit
  trails, OSCAL Assessment Results, AARM Conformance Reports — that the
  Governance Layer consumes to close the audit cycle.

This is not a metaphor. It is a concrete data flow that CAGE already
implements on the right side (enforcement → evidence) and is building on the
left side (specification → enforcement, Phase A).

### 5.2 The "Commit Boundary" Claim

The framing uses the phrase "substrate engines to enforce the physics of
compliance at the commit boundary." This is technically precise for CAGE:

- [`atomic_verify_and_commit()`](../../src/gateway/governance/cbf.py) enforces
  the CBF invariant at the Redis commit boundary — the invariant is checked and
  the state is written in a single Lua script execution with zero TOCTOU window.
- The routing seal ([`routing_seal.py`](../../src/gateway/governance/routing_seal.py))
  enforces the governance pipeline approval at the actuator call boundary —
  the seal must be verified before any tool execution.
- The HITL interrupt enforces the human approval boundary — the LangGraph graph
  cannot proceed past `interrupt_before=["governed_trader"]` without an
  explicit human decision.

These are three distinct "commit boundaries" at three distinct layers of the
stack. The Governance Layer (OSCAL/Lula) can specify which boundaries apply to
which controls; CAGE enforces them.

### 5.3 The CISO Narrative — Technical Substantiation

The suggested response positions CAGE as the "missing piece" of enterprise AI
governance. The following table maps each claim in the suggested response to
its technical substantiation in the CAGE codebase:

| Suggested response claim | Technical substantiation | File |
|---|---|---|
| "machine-readable, out-of-process invariants" | OPA Rego AST compiled from STPA UCAs; OPA runs out-of-process | [`stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) |
| "physically gate the runtime" | Redis atomic Lua CBF check+commit; HMAC routing seal | [`cbf.py`](../../src/gateway/governance/cbf.py), [`routing_seal.py`](../../src/gateway/governance/routing_seal.py) |
| "policy-as-code feeds into infrastructure-as-code" | Ingress adapters proposed but not yet implemented; `stpa_compiler.py` already compiles CAGE YAML to enforcement artifacts | See §9 action items |
| "governance frameworks to manage the logic of risk" | `ControlRegistry` resolves CTRL_* IDs to NIST SP 800-53 / ISO 42001 / SR 26-2 citations | [`constants.py`](../../src/gateway/governance/constants.py) |
| "substrate engines to enforce the physics of compliance" | Discrete-time CBF (Ames et al. IEEE TAC 2017) — a mathematical theorem, not a policy rule | [`cbf.py`](../../src/gateway/governance/cbf.py) |
| "at the commit boundary" | `atomic_verify_and_commit()` — single Lua hop, zero TOCTOU | [`cbf.py`](../../src/gateway/governance/cbf.py) |

### 5.4 What the Framing Does NOT Yet Cover — IP Protection Boundary

The suggested response deliberately stays at the "why" and "where" level,
avoiding the "how." The following CAGE implementation details are the
proprietary "how" that should not be disclosed in external positioning:

| Implementation detail | Why it is proprietary |
|---|---|
| Redis Lua script for atomic CBF check+commit | The specific Lua implementation of `h(S(t+1)) >= (1-γ)*h(S(t))` at the database commit tier is the core substrate moat — it is not replicable without understanding the CBF formulation and the Redis WATCH/MULTI/EXEC interaction |
| 4-state DEFER router thresholds (0.95 / 0.70) | The specific FRIA zone thresholds and the PARK → HYDRATE → REPLAY state machine are implementation IP |
| DoWhy causal gatekeeper (placebo refutation, 50 sims, p < 0.05) | The causal world-model validation is a unique capability with no competitor equivalent |
| `CBF_FAIL_OPEN=true` startup assertion | The specific fail-closed mechanism at module import time is an implementation detail that should not be disclosed to adversaries |
| `ControlRegistry.active_hash` policy version pinning | The version pinning mechanism that detects runtime policy drift is implementation IP |

The framing correctly keeps the public narrative at the architectural level:
"CAGE translates high-level policy declarations into machine-readable,
out-of-process invariants that physically gate the runtime." This is accurate
and defensible without disclosing the implementation.

---

## 6. New Functionality Implied by the Framing

The framing implies three categories of new functionality that are not yet
fully implemented in CAGE. These are ordered by strategic priority.

### 6.1 Category 1: Specification Ingestion (Phase A — Q3 2026)

**What the framing implies:** "policy-as-code (OSCAL/Lula) feeds directly into
infrastructure-as-code (CAGE-style substrate boundaries)"

**What is missing:** CAGE has no native parser for OSCAL component definitions
or Lula validation manifests as policy ingestion inputs. The Phase A ingress
adapters (`acs_adapter.py`, `aaif_adapter.py`, `policy_translator.py`) address
ACS and AAIF formats but not OSCAL/Lula directly.

**New work implied:**

| New module | Purpose | Proposed location |
|---|---|---|
| `oscal_adapter.py` | Parse OSCAL component definitions → CAGE UCA YAML | `src/gateway/governance/ingress/oscal_adapter.py` |
| `lula_adapter.py` | Parse Lula validation manifests → OPA constraints | `src/gateway/governance/ingress/lula_adapter.py` |
| `POST /governance/ingest-policy` | CI/CD-callable policy ingestion endpoint | Extend `src/gateway/server/hybrid_server.py` |

**Change category:** Cat-N (Normal) — Python modules only, no new
infrastructure.

**Compliance note:** Adding `oscal_adapter.py` touches NIST SP 800-53 control
implementations. OSCAL component update in `compliance/oscal/` required within
2 business days of PR merge. Adding `lula_adapter.py` adds a new Kubernetes
resource reference; Lula validation update in `compliance/lula/` must be
included in the same PR or flagged for a follow-on PR.

### 6.2 Category 2: Bidirectional Evidence API (Phase A extension — Q3 2026)

**What the framing implies:** The Governance Layer needs machine-readable
evidence from the Substrate to close the audit cycle. The framing does not
articulate this explicitly, but it is the logical completion of the handshake.

**What is already implemented:** OSCAL Assessment Results export, AARM
Conformance Report, KMS-signed audit trail, SSE governance event stream — all
in `src/compliance_bridge/`.

**What is missing:** A **push notification** from CAGE to the Governance Layer
when a substrate enforcement event occurs (e.g., a CBF violation, a DEFER
parking, a HITL interrupt). The SSE stream (`GET /v1/events/stream`) provides
pull-based access; a webhook push would allow the Governance Layer to react
in real time without polling.

**New work implied:**

| New module | Purpose | Proposed location |
|---|---|---|
| `governance_webhook.py` | Push governance events to registered Governance Layer endpoints | `src/compliance_bridge/governance_webhook.py` |
| `POST /v1/webhooks/register` | Register a Governance Layer endpoint for push notifications | Extend `src/compliance_bridge/main.py` |

**Change category:** Cat-N (Normal).

### 6.3 Category 3: Substrate Contract Specification (Phase A — Q3 2026)

**What the framing implies:** Enterprise architects need a versioned,
documented contract for the handshake between the Governance Layer and the
Enforcement Substrate. Without this, the "handshake" is a narrative, not an
integration.

**What is missing:** A **Substrate Contract Specification** — a versioned
document (and corresponding OpenAPI schema) that defines:
1. The ingress surface: what policy formats CAGE accepts and what compiled
   artifacts it returns.
2. The egress surface: what compliance evidence CAGE produces and in what
   format.
3. The version pinning mechanism: how a Governance Layer author pins their
   policy to a specific CAGE baseline.

**New work implied:**

| New document | Purpose | Proposed location |
|---|---|---|
| `SUBSTRATE_CONTRACT.md` | Versioned substrate contract specification | `docs/SUBSTRATE_CONTRACT.md` |
| OpenAPI schema extension | Add `POST /governance/ingest-policy` to the interop spec | Extend `docs/CAGE_OPEN_INTEROP_SPEC.md` §11 |

**Change category:** Cat-S (Standard) — documentation only.

---

## 7. Relationship to Existing Architecture Documents

| Document | Relationship to this analysis |
|---|---|
| [`SUBSTRATE_MOAT_STRATEGY.md`](SUBSTRATE_MOAT_STRATEGY.md) | Parent document — this analysis extends the substrate moat framing with the Governance Layer / Enforcement Substrate vocabulary and maps it to new functionality |
| [`CAGE_OPEN_INTEROP_SPEC.md`](../CAGE_OPEN_INTEROP_SPEC.md) | The external API surface that exposes the substrate contract; needs §11 (Policy Ingestion API) and §12 (Governance Webhook) added |
| [`CAGE_ONE_PAGER.md`](../project/CAGE_ONE_PAGER.md) | The CISO-facing summary; the "Governance Layer vs. Enforcement Substrate" vocabulary should be incorporated into the Problem/Solution framing |
| [`SUBSTRATE_MOAT_STRATEGY.md` §9.6](SUBSTRATE_MOAT_STRATEGY.md#96-gap-6-no-agw-service-extension-integration-high--strategic-opportunity) | The AGW Service Extension (Phase B) is the network-layer instantiation of the substrate — AGW owns the identity and network moat; CAGE owns the state and invariant moat; the two-layer model maps directly onto the AGW + CAGE defense-in-depth stack |

---

## 8. Summary — What CAGE Is, Precisely

The "Governance Layer vs. Enforcement Substrate" framing provides a vocabulary
that maps precisely onto CAGE's architecture:

**CAGE is the Enforcement Substrate.** It is not a governance framework. It
does not define policy. It does not manage risk posture. It does not produce
institutional intent. Those are the responsibilities of NIST RMF, OSCAL, Lula,
ISO/IEC 42001, SR 26-2, and the governance architects who author them.

**What CAGE does:** It takes the output of the Governance Layer — machine-
readable policy declarations — and compiles them into enforcement artifacts
that physically gate the runtime at three distinct commit boundaries:

1. **The database commit boundary** — Redis atomic Lua CBF check+commit
   ([`cbf.py`](../../src/gateway/governance/cbf.py))
2. **The actuator call boundary** — HMAC-SHA256 routing seal
   ([`routing_seal.py`](../../src/gateway/governance/routing_seal.py))
3. **The human approval boundary** — LangGraph HITL interrupt
   ([`graph.py`](../../src/governed_financial_advisor/graph/graph.py))

And it produces compliance evidence that flows back to the Governance Layer to
close the audit cycle:

- OSCAL 1.1.2 Assessment Results
  ([`oscal_exporter.py`](../../src/compliance_bridge/oscal_exporter.py))
- CSA AARM Conformance Report
  ([`aarm_report_generator.py`](../../src/compliance_bridge/aarm_report_generator.py))
- KMS-signed audit trail
  ([`kms_signer.py`](../../src/gateway/governance/kms_signer.py))
- Real-time SSE governance event stream
  ([`sse_events.py`](../../src/compliance_bridge/sse_events.py))

The gap — the left side of the handshake — is the ingestion path from
Governance Layer outputs (OSCAL, Lula, ACS, AAIF) into CAGE enforcement
artifacts. Closing this gap (see the action items in §9) would complete the
handshake and technically substantiate the "policy-as-code feeds into
infrastructure-as-code" claim end-to-end.

---

## 9. Recommended Next Steps

| Action | Priority |
|---|---|
| Implement `oscal_adapter.py` and `lula_adapter.py` OSCAL/Lula policy ingestion adapters | HIGH |
| Add `POST /governance/ingest-policy` to `CAGE_OPEN_INTEROP_SPEC.md` §11 | HIGH |
| Incorporate "Governance Layer vs. Enforcement Substrate" vocabulary into `CAGE_ONE_PAGER.md` Problem/Solution framing | MEDIUM |
| Add `governance_webhook.py` and `POST /v1/webhooks/register` | MEDIUM |
| Update `CAGE_OPEN_INTEROP_SPEC.md` §12 with Governance Webhook specification | MEDIUM |

See [`SUBSTRATE_CONTRACT.md`](../SUBSTRATE_CONTRACT.md) for the current
versioned substrate contract specification, which already exists and
partially supersedes the ingestion-gap analysis above.

---

*End of CAGE — Governance Layer vs. Enforcement Substrate: Architectural Analysis*
