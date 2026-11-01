# Partner Integrations & Governance Specifications

> **Architecture Standard — Generic in Code, Specific in Prose.**
> In accordance with CAGE architecture standards (ADR-008), core kernel code (Layer 1)
> and integration adapter packages (Layer 3) use anonymized provider namespaces (`provider_01`
> through `provider_09`). Partner brand names, technical contracts, and upstream alignment
> specifications belong in this directory.

This directory houses partner-specific documentation, wire contracts, compliance alignment
specifications, and technical exchange artifacts.

Every document here except this index and digest-pinned deposits opens with a banner: it is
third-party integration material, its presence here is not a Google certification or
endorsement of the partner, and the integration's verification status is in
[Live Verification Status](#live-verification-status). CI enforces the banner with
[`check_partner_headers.py`](../../scripts/check_partner_headers.py); run it with `--apply` to
insert or refresh it.

---

## Directory Index

| Provider Namespace | Partner / Vendor | Integration Role & Protocol | Documentation Directory | Adapter Implementation |
|---|---|---|---|---|
| `provider_01` | **FlowSignal** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_01/`](provider_01/) | [`src/integrations/provider_01/`](../../src/integrations/provider_01/) |
| `provider_02` | **InferTheta / NexArt / Vector3** | Attestation Provider & Cryptographic Evidence Resolver (CER) | [`provider_02/`](provider_02/) | [`src/integrations/provider_02/`](../../src/integrations/provider_02/) |
| `provider_03` | **Veritas** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_03/`](provider_03/) | [`src/integrations/provider_03/`](../../src/integrations/provider_03/) |
| `actuator_01` | **Archytan** | Downstream Execution Actuator (`ExecutionActuator`) | *(Reference)* | [`src/integrations/actuator_01/`](../../src/integrations/actuator_01/) |
| `actuator_02` | **NVIDIA OpenShell** | Dynamic Sandbox Supervisor (`ExecutionActuator` + `PolicyAdvisorBridge`) | [`actuator_02/`](actuator_02/) | [`src/integrations/actuator_02/`](../../src/integrations/actuator_02/) |
| `actuator_03` | **NVIDIA Sentry / DOCA** | Out-of-Band Hardware Quarantine (`QuarantineActuator`) | [`actuator_03/`](actuator_03/) | [`src/integrations/actuator_03/`](../../src/integrations/actuator_03/) |
| `provider_05` | **Veraxis Execution Integrity Protocol (VEIP)** | Attestation Provider & Execution Warrant Verification | [`provider_05/`](provider_05/) | [`src/integrations/provider_05/`](../../src/integrations/provider_05/) |
| `provider_06` | **Guardian Cyber Agent Integrity** | Synchronous Verifier & Conformance Harness (`1-alpha`) | [`provider_06/`](provider_06/) | [`src/integrations/provider_06/`](../../src/integrations/provider_06/) |
| `provider_07` | **InferTheta** | Graph Topology & Governance Schema Provider | [`provider_07/`](provider_07/) | [`src/integrations/provider_07/`](../../src/integrations/provider_07/) |
| `provider_08` | **Verdict Systems** | Synchronous Normative Provider (`NormativeProvider`) + external evidence custody (Sigstore Rekor) | [`provider_08/`](provider_08/) | [`src/integrations/provider_08/`](../../src/integrations/provider_08/) |
| `provider_09` | **OpsCanvas** | Infrastructure Estate Provider (`EstateProvider`) — dated, confirmed CloudOps dependency graph over MCP | [`provider_09/`](provider_09/) | *(Planned — seam + factory in [`estate_provider.py`](../../src/gateway/governance/estate_provider.py))* |

---

## Live Verification Status

Latest over-the-wire result per adapter, as of 2026-10-31. A harness run ([`ci-partner-integration.yml`](../../.github/workflows/ci-partner-integration.yml)) passes only if every selected live test ran and passed ([`require_live`](../../tests/fixtures/require_live.py)), so a passing run means the tests ran rather than skipped. Results without a run ID come from a local run and are labelled as such.

| Adapter | Result | Run on `main` | Scope & what blocks a passing production-seam run |
|---|---|---|---|
| `provider_05` VEIP v0.2 | 10 passed, 0 not run | [`41234042599`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41234042599) at `5b0055ad` | Exercises the production `WarrantSource` seam (`Provider05WarrantSource`) across all 8 v0.2 scenarios (the v0.3 blueprint registry isn't deployed; its tests sit outside the harness) |
| `provider_01` FlowSignal | 8 passed, 0 not run | [`41233853779`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41233853779) at `5b0055ad` | Calls `provider.validate_fria(payload)` directly with FlowSignal's `AP-001` test vector (`action: "payment.release"`, not a registered `cage_finance` action) and top-level `target` and `approval_id` fields that `FriaTier._payload()` never sends |
| `provider_08` Verdict Systems | 4 passed, 0 not run | [`41233869303`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41233869303) at `5b0055ad` | Exercises `/.well-known/verdict-authority.json`, `fetch_baseline`, and unauthenticated `validate_fria` fail-closed (`HTTP 401/403`) only; authenticated `validate_fria` (`ALLOW` / `ConsequenceToken` mint) is blocked on `PROVIDER_08_API_KEY` in CI |
| `provider_02` NexArt | Local: 2 of 3 `test_provider_02_live.py` tests passed | none | A CAGE-side resolver defect fails `test_live_cer_verification_signature` ([open items](provider_02/nexart/HITL_INTEROP_STATUS.md#open-items)); `test_staging_e2e.py` needs `PROVIDER_02_API_KEY_SECRET` |
| `provider_07` InferTheta | Local: 2 of 8 passed (`/health`, JWKS); the other 6 got HTTP 401 `Invalid API key.` | none | A current `PROVIDER_07_API_KEY` |
| `provider_03` Veritas | Not run | none | No sandbox endpoint or key |
| `actuator_01` Archytan | Not run on `main`. Run `41125558418` on the #598 branch authenticated through WIF, then failed closed (5 skipped) | none | `ACTUATOR_01_ENDPOINT`, `ACTUATOR_01_TENANT_ID` and the mTLS PEM secrets |
| `actuator_02` NVIDIA OpenShell | Not run | none | No harness target; never deployed against a live OpenShell Supervisor ([seal profile](actuator_02/SEAL_VERIFICATION_PROFILE.md)) |
| `actuator_03` NVIDIA Sentry / DOCA | Not run | none | No harness target |
| `provider_06` Guardian Cyber Agent Integrity | Not run over the wire. Offline, the vendored `1-alpha` CLI matched 7 of 7 required scenarios ([result](provider_06/CONFORMANCE_RESULT.md)), a verification-capability result only | none | No harness target |
| `provider_09` OpsCanvas | Not run | none | No adapter yet ([decision points](provider_09/DECISION_POINTS.md)) |

---

## Boundaries & Isolation Guidelines

1. **Vendor Isolation:** Partner-specific technical documentation and protocols must remain in `docs/partners/provider_XX/`. They must not mix into core engine architecture (`docs/architecture/`) or internal governance policies (`docs/governance/`).
2. **Fail-Closed Verification:** All partner providers adapt to canonical CAGE dataclasses (`NormativeBaseline`, `ValidationResult`, `EvidenceSeal`, `AttestationReceipt`). Domain execution must always fail closed if a partner verifier is unreachable, timed out, or unverified.
3. **No Domain Leakage:** Partner wire payloads and envelopes must not leak CAGE-specific Layer 2 financial domain concepts (`amount`, `symbol`, `portfolio_id`) into upstream verifiers unless specifically dictated by negotiated domain contracts.

