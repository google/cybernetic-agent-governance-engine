# Cybernetic Governance Engine (CAGE) - Presentation Prompts

These slide prompts and speaker notes translate the core architectural realities of the CAGE repository into high-level business value, explicitly verified against your codebase.

---

## Slide 1: The Paradigm Shift (From Linguistic to Deterministic)

**Visual Prompt / Concept:** 
A split-screen comparison. On the left, a traditional LLM interaction—an opaque, shifting "stochastic core" with linguistic instructions like "please do not trade." On the right, the CAGE architecture—a hardened vault where the LLM is tightly encased in deterministic logic, showing strict schema validations and rigid policy borders.

**Key Content (Slide Text):**
- **The Problem:** Linguistic constraints ("Prompt Engineering") fail to provide the deterministic guarantees required by **SR 26-2** (Federal Reserve's April 2026 guidance on agentic AI) and ISO 42001.
- **The Death of SR 11-7 for Agentic Systems:** The Fed explicitly declared that generative and agentic AI are *outside the prescriptive scope* of SR 11-7. Banks must apply their own rigorous internal frameworks — CAGE IS that framework.
- **The CAGE Paradigm:** Treat the LLM as an untrusted "Stochastic Core."
- **Deterministic Lockdown:** Wrap all LLM inputs and tool executions in mathematically verifiable boundaries.
- **Code-Level Reality:** Pydantic validation pipelines force structural conformity, while OPA Rego policies mathematically evaluate access and state before any API is reached.

**Speaker Notes (Verified against code):**
> "In a regulated environment, we cannot rely on asking an AI 'nicely' to behave. In the CAGE architecture, we treat the generative LLMs—our stochastic cores—as untrusted entities. As implemented in `src/gateway/core/structs.py` and our OPA configurations (`deployment/k8s/opa.yaml`), every single tool execution is intercepted. Before the model can interact with our financial APIs, the output must pass strict Pydantic structural validation. Only then does it hit our OPA policy engine, ensuring that governance is enforced deterministically via code, not linguistically via prompt."

---

## Slide 5: SR 26-2 Examination Readiness — The Four Gaps We Closed

**Visual Prompt / Concept:**
A 2×2 grid of examination dimensions, each showing the SR 26-2 gap description on the left and the CAGE remediation on the right. Each cell has a ✅ badge.

**Key Content (Slide Text):**
- **Gap 1 — World-Model Telemetry:** `LangfuseTelemetryProvider` replaces `generate_mock_telemetry()`. DoWhy now validates causal beliefs against live Langfuse governance spans.
- **Gap 2 — Saga WAL Compiler:** `stpa_control_structure.yaml` now drives the `stpa_compiler` to emit a real `GatewayMCPClient.call_tool()` invocation in the forward WAL node — not a stub. Reproduced at any time with: `python -m src.gateway.governance.stpa_compiler compile`.
- **Gap 3 — Regulatory Terminology:** All audit logs, OTel spans, and violation strings now reference `SR 26-2 §IV.B` rather than `SR 11-7`. The confidence threshold remains 0.95; the regulatory citation is now accurate.
- **Gap 4 — Agent Scope Declaration:** `config/agent_scope.yaml` is the machine-readable SR 26-2 scope boundary document — parsed by OPA as a data document, referenced by OSCAL, validated by Lula CronJob.

**Speaker Notes (Verified against code):**
> "The Federal Reserve's SR 26-2, issued April 17, 2026, hands us a massive competitive advantage. Because the Fed explicitly stated that generative and agentic AI are *outside* SR 11-7's prescriptive scope, every bank is now scrambling to build their own rigorous internal framework. CAGE is the exact scaffolding they need. We just closed all four SR 26-2 examination gaps in a single compilation cycle. The SR 26-2 examiner walks in and sees: a machine-readable scope declaration in `config/agent_scope.yaml`, a DoWhy causal gatekeeper validated against live Langfuse telemetry — not mock data — a Saga WAL compiler that proves atomicity in production rather than declaring it in a policy document, and audit logs that accurately cite `SR 26-2 §IV.B` throughout. That is what Compliance-as-Code means. Policy changes start in the YAML. The code follows the YAML. The audit trail traces back to the YAML."

---

## Slide 2: Symbolic Governor & Defense-in-Depth

**Visual Prompt / Concept:**
A multi-tiered architectural stack flowing from the top (User/Agent) down to the bottom (External Execution). The flow passes through a gauntlet of security layers: Schema Validation, gVisor Sandboxing, and a Cryptographic Gate (HMAC Signature), before finally hitting a physical "Circuit Breaker" at the edge.

**Key Content (Slide Text):**
- **Multi-Tier Security Stack:** No single point of failure.
- **Schema Validation & STPA:** Real-time semantic and hazard checks (`stpa_compiler.py`).
- **Sandboxing:** Network lockouts (implemented) and gVisor isolation (strategic roadmap per `RISK_ASSESSMENT_REPORT.md`).
- **Cryptographic Gates:** Human-in-the-loop (HITL) HMAC-SHA256 governance seals explicitly required for high-risk executions.
- **The Circuit Breaker:** Hard-stops deployed across application and gateway layers (`src/gateway/governance/nemo/manager.py` & `src/governed_financial_advisor/graph/nodes/agent_nodes.py`).

**Speaker Notes (Verified against code):**
> "Slide 2 illustrates our 'Defense-in-Depth' posture, governed by the Symbolic Governor. If a prompt injection bypasses the LLM, it hits our STPA hazard validators. To execute high-risk trades, the system enforces a strict Human-in-the-Loop workflow requiring an HMAC-SHA256 governance seal. Furthermore, our infrastructure utilizes strict network policies to sandbox workloads, neutralizing lateral movement, with gVisor isolation explicitly charted on our roadmap as a recommended risk mitigation. Finally, if anomalous behavior is detected, our Circuit Breaker logic—implemented across both the LangGraph application nodes and the NeMo guardrails manager—instantly severs the execution path, returning the system to a safe state."

---

## Slide 3: The Compliance Bridge & Out-of-Band Auditing

**Visual Prompt / Concept:**
A real-time data flow diagram. On the top path, fast-moving financial transactions flow unimpeded. Below it, an "out-of-band" fiber optic line continuously siphons execution traces (telemetry) into an encrypted ledger, parsing it into beautiful auditor dashboards. 

**Key Content (Slide Text):**
- **Zero-Latency Governance:** Auditing that never penalizes the critical path.
- **Non-Blocking Telemetry:** `asyncio.gather` parallel execution trace aggregation.
- **Continuous Compliance:** Real-time generation of NIST OSCAL and Lula validation files.
- **Envelope Protection:** CMEK (Customer-Managed Encryption Keys) securing the trust ledger natively out-of-band.

**Speaker Notes (Verified against code):**
> "Governance cannot come at the expense of performance. Our Compliance Bridge, detailed in `src/compliance_bridge/main.py`, operates entirely out-of-band. Using non-blocking concurrency loops (`asyncio.gather`), we parse execution traces from Langfuse in parallel to calculate safety posture metrics. This telemetry is immediately translated into NIST OSCAL and Lula validation schemas (`compliance/oscal/system-security-plan.yaml`). Furthermore, as enforced in `src/compliance_bridge/cmek_guard.py`, this entire audit ledger is protected by CMEK envelope encryption. The result? We serve continuous, mathematically verified compliance data to our low-latency auditor dashboards without adding a single millisecond to our first-line financial transactions."

---

## Slide 4: Thwarting Goal-Directed Persistence (Bifurcated Governance)

**Visual Prompt / Concept:**
Two distinct pathways. The top pathway shows a "White Box" internal planning loop where an agent refines its strategy based on safety feedback (a closed, internal circuit). The bottom pathway shows the "Black Box" graph edge: when the agent attempts an action that hits a hard OPA or NeMo guardrail, a guillotine drops, instantly severing the connection and routing to a terminal state.

**Key Content (Slide Text):**
- **The Threat:** "Goal-Directed Persistence"—verbose error messages teach LLMs how to bypass security (e.g., splitting trades to avoid limits).
- **Soft Planning Boundaries:** Feedback loops exist *only* during internal strategy planning, tightly capped by circuit breakers.
- **Hard Governance Black Boxes:** NeMo Guardrails and OPA gates.
- **Severing the Context:** When a hard policy is violated, the error is caught at the graph edge. The agent's context window is physically severed, and execution routes to a terminal state. The AI cannot negotiate with what it cannot see.

**Speaker Notes (Verified against code):**
> "In application security, returning a verbose stack trace to an attacker gives them the blueprint to bypass your firewall. The same is true for AI agents. If we tell an LLM it was blocked because a limit is 50,000, its goal-directed persistence will simply prompt it to split the trade in two. 
> 
> CAGE solves this through a Bifurcated Governance architecture. We allow feedback loops internally during the planning phase so the agent can refine its strategy. But for hard rules—like our OPA policy engine and NeMo Guardrails—we treat them as absolute black boxes. As implemented in `route_after_safety` and `route_after_guardrail`, if an action is denied, the error is caught at the graph edge. The agent's context window is physically severed, and it is instantly routed to a terminal state. It cannot learn to bypass the rules, because we never let it see the failure."
