# Partner Integrations & Governance Specifications

> **Architecture Standard — Generic in Code, Specific in Prose.**
> In accordance with CAGE architecture standards (ADR-008), core kernel code (Layer 1)
> and integration adapter packages (Layer 3) use anonymized provider namespaces (`provider_01`
> through `provider_07`). Partner brand names, technical contracts, and upstream alignment
> specifications belong in this directory.

This directory houses partner-specific documentation, wire contracts, compliance alignment
specifications, and technical exchange artifacts.

---

## Directory Index

| Provider Namespace | Partner / Vendor | Integration Role & Protocol | Documentation Directory | Adapter Implementation |
|---|---|---|---|---|
| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |
| `provider_02` | **InferTheta / NexArt / Vector3** | Attestation Provider & Cryptographic Evidence Resolver (CER) | [`provider_02/`](provider_02/) | [`src/integrations/provider_02/`](../../src/integrations/provider_02/) |
| `provider_03` | **Veritas** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_03/`](provider_03/) | [`src/integrations/provider_03/`](../../src/integrations/provider_03/) |
| `actuator_01` | **Archytan** | Downstream Execution Actuator (`ExecutionActuator`) | *(Reference)* | [`src/integrations/actuator_01/`](../../src/integrations/actuator_01/) |
| `provider_05` | **Veraxis Execution Integrity Protocol (VEIP)** | Attestation Provider & Execution Warrant Verification | [`provider_05/`](provider_05/) | [`src/integrations/provider_05/`](../../src/integrations/provider_05/) |
| `provider_06` | **Guardian Cyber Agent Integrity** | Synchronous Verifier & Conformance Harness (`1-alpha`) | [`provider_06/`](provider_06/) | [`src/integrations/provider_06/`](../../src/integrations/provider_06/) |
| `provider_07` | **InferTheta** | Graph Topology & Governance Schema Provider | [`provider_07/`](provider_07/) | [`src/integrations/provider_07/`](../../src/integrations/provider_07/) |

---

## Boundaries & Isolation Guidelines

1. **Vendor Isolation:** Partner-specific technical documentation and protocols must remain in `docs/partners/provider_XX/`. They must not mix into core engine architecture (`docs/architecture/`) or internal governance policies (`docs/governance/`).
2. **Fail-Closed Verification:** All partner providers adapt to canonical CAGE dataclasses (`NormativeBaseline`, `ValidationResult`, `EvidenceSeal`, `AttestationReceipt`). Domain execution must always fail closed if a partner verifier is unreachable, timed out, or unverified.
3. **No Domain Leakage:** Partner wire payloads and envelopes must not leak CAGE-specific Layer 2 financial domain concepts (`amount`, `symbol`, `portfolio_id`) into upstream verifiers unless specifically dictated by negotiated domain contracts.

