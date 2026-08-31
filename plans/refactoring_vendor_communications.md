<!--
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Vendor Communication — CAGE Layered Refactoring (PR 1–3)

Impact was determined by reading each adapter against the refactoring scope: the `src/cage_finance/` extraction, the `amount`/`symbol` → `context`/`magnitude` contract generalization, the new domain plugin protocols, and possible payload-key drift in the `action_context` dict passed to [`enforce_fria_boundary()`](src/gateway/governance/normative_provider.py:435).

---

## Provider 01 — Normative Compliance Provider (Synchronous Legal-Baseline Gate)

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your integration implements the [`NormativeProvider`](src/gateway/governance/normative_provider.py:273) protocol and remains a first-class, supported seam — the three-method contract (`fetch_baseline`, `validate_fria`, `submit_evidence`), the `ALLOW`/`REFUSE`/`ESCALATE` verdict vocabulary, and the `/legal-baseline`, `/validate/fria`, `/evidence-chain` wire layout are all unchanged by this refactoring. **You are impacted in one narrow respect:** the FRIA payload delivered to `validate_fria()` is the kernel's `action_context` snapshot, and the finance-specific keys `amount` and `symbol` are being generalized to `magnitude` and `context`. Because [`_mint_consequence_token()`](src/integrations/provider_01/provider.py:86) computes the `act` claim as a SHA-256 over the JCS-canonicalized payload, any key rename changes the resulting action digest — previously recorded digests will not reproduce, and any server-side validation that reads `amount`/`symbol` by name will see them absent. Note that `actor_id`, `thread_id`, and the `authority_record_id`-required-on-`ALLOW` rule are all unaffected.

**Action Required**: YES — re-baseline stored `act` digests and golden fixtures against the renamed payload keys, and update any endpoint-side logic that reads `amount` or `symbol` by name to read `magnitude` and `context`. No protocol or endpoint changes.

**Questions for Your Team**:
1. Do the payload key renames (`amount`/`symbol` → `magnitude`/`context`) create significant coordination burden for your endpoint validation or stored fixtures? If so, we can provide a compatibility shim for a transition period.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 01" numbering scheme is incomplete — constants like `FLOWSIGNAL_ALLOW` in [`constants.py`](src/gateway/governance/constants.py), and the Lula validation filename [`lula-validation-flowsignal.yaml`](compliance/lula/lula-validation-flowsignal.yaml) still reference "FlowSignal" explicitly. Would you prefer we complete the anonymization, or switch to using "FlowSignal" consistently in committed code?
3. When would you like to review the final v4.0.0 wire contract before we freeze it? We're targeting freeze within the next 2-3 weeks.

---

## Provider 02 — Certified Evidence Receipt (CER) Attestation Provider

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your integration is **the one materially impacted by this refactoring.** [`adapter.py`](src/integrations/provider_02/adapter.py:111) hardcodes the Governed Financial Advisor graph topology in `_GRAPH_PARENTS` and `_ATTESTATION_NODES`, and [`_classify_terminal_path()`](src/integrations/provider_02/adapter.py:326) keys the `happy_path` classification on the presence of a `governed_trader` node — all of which move into the `src/cage_finance/` plugin and will be absent whenever CAGE runs bare-kernel or with a non-financial domain plugin. The consequence is silent rather than loud: `_build_parent_step_ids()` will produce empty parent lists for unknown nodes, yielding a structurally flat `AttestationBundle` DAG and an `unknown` terminal path, so bundles will still be submitted but their provenance graph will be wrong. Separately, the `stateHash` values in your bundles already shifted when [`_hash_state()`](src/integrations/provider_02/adapter.py:230) migrated to RFC 8785 JCS, and the finance key renames will shift them again for any state snapshot carrying `amount`/`symbol`. The `certifyDecision`, `verify`, and `registerProjectBundle` request/response shapes themselves are unchanged.

**Action Required**: YES — the node topology must become injected configuration rather than a module-level constant, supplied by the active domain plugin at registration time; until then, treat bundles produced under a non-finance plugin as having unverified DAG provenance. Also re-baseline any stored `stateHash` values. Please confirm your side does not reject a bundle whose `terminalPath` is `unknown`.

**Questions for Your Team**:
1. Does the node topology injection requirement (moving `_GRAPH_PARENTS` and `_ATTESTATION_NODES` from module constants to plugin-supplied configuration) create significant implementation burden? We can provide a migration guide and example plugin registration code.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 02" numbering is incomplete — the pre-anonymization package name "TrustLayers" still appears in coverage HTML reports and some historical git references. Would you prefer we complete the anonymization, or use "TrustLayers" consistently in committed code?
3. When would you like to review the final v4.0.0 wire contract and plugin configuration protocol before we freeze it? We're targeting freeze within the next 2-3 weeks.

---

## Provider 03 — Decision Governance & Bind Receipt Provider

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your integration implements the [`NormativeProvider`](src/gateway/governance/normative_provider.py:273) protocol against the `/baseline`, `/validate`, and `/evidence` paths, with the `APPROVED`/`ESCALATE`/`REJECTED` verdict vocabulary — none of which changes under this refactoring, and no further breaking changes are planned beyond the already-communicated BC-02 removal of the dict-returning compatibility aliases. **You are impacted only by payload key drift:** the `action_context` dict posted to `/validate` will carry `magnitude` and `context` where it previously carried `amount` and `symbol`. Your `ingest_bind_receipt()` extension method is unaffected in shape, though as with any JCS-canonicalized digest, receipts containing the renamed keys will hash differently. Your `verdict` catch-all `else` branch means an unrecognized payload fails closed as `REJECTED` without a distinguishable parse error, so a missed rename would surface as unexplained rejections rather than an explicit error.

**Action Required**: YES — audit any endpoint-side field access on `amount`/`symbol` and migrate to `magnitude`/`context`; re-baseline bind-receipt digests. No protocol, path, or verdict-vocabulary changes.

**Questions for Your Team**:
1. Do the payload key renames (`amount`/`symbol` → `magnitude`/`context`) create significant coordination burden for your endpoint validation or stored bind-receipt digests? If so, we can provide a compatibility shim for a transition period.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 03" numbering is incomplete — the name "VERITAS" still appears explicitly in boundary-mapping documents like [`plans/plugin_seam_orthogonality_analysis.md`](plans/plugin_seam_orthogonality_analysis.md). Would you prefer we complete the anonymization, or use "VERITAS" consistently in committed code?
3. When would you like to review the final v4.0.0 wire contract before we freeze it? We're targeting freeze within the next 2-3 weeks.

---

## Provider 04 — Attestation Provider + Envelope Mapper

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your integration subclasses the abstract [`AttestationProvider`](src/gateway/governance/attestation_provider.py:36) and supplies bidirectional `GovernanceEnvelope` translation, and **you are not impacted by this refactoring.** The `fetch_attestations(context) -> list[ExternalAttestation]` contract, the shared `AttestationStatus` vocabulary (`VERIFIED` / `DENIED` / `STALE` / `DRIFT_DETECTED` / `ERROR`), and the `cage_envelope` wrapping performed by [`Provider04EnvelopeMapper`](src/integrations/provider_04/envelope_mapper.py:44) all sit above the finance extraction boundary — the mapper treats the signed envelope as an opaque dict and never inspects domain fields. Because your fetch path is currently a stub returning `[]`, there is additionally no live wire contract exposed to drift. When you implement the real fetch, note only that the `context` dict is scoped metadata and should not be assumed to contain finance-specific keys.

**Action Required**: NO — None. The attestation and envelope-mapper contracts are stable across this refactoring.

**Questions for Your Team**:
1. While no immediate action is required, do you have any concerns about the domain-agnostic refactoring affecting future attestation fetch implementations? We want to ensure the `context` parameter remains sufficient for your use case.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 04" numbering is incomplete — the pre-anonymization package name "Archytan" still appears in old git branch names and some coverage reports. Would you prefer we complete the anonymization, or use "Archytan" consistently in committed code?
3. When would you like to review the final v4.0.0 attestation and envelope-mapper contracts before we freeze them? We're targeting freeze within the next 2-3 weeks.

---

## Provider 05 — Verifiable Execution Evidence Pack (Blueprint / Key / Physics Axioms)

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your three [`AttestationProvider`](src/gateway/governance/attestation_provider.py:36) subclasses — Blueprint (policy legitimacy), Key (SPIFFE identity genesis), and Physics (vTPM and eBPF substrate integrity) — together with the warrant module are **not impacted by this refactoring.** All three axioms are already domain-agnostic by construction: they attest signed risk-acceptance records, admissibility grants at a consequence class, and host-node substrate state, none of which reference instrument symbols, trade amounts, or any other financial concept being relocated to `src/cage_finance/`. The `AttestationStatus` vocabulary, the `WarrantStatus` and `RelianceStatus` enums, and the `to_canonical_bytes()` JCS digests over your own dataclasses are all stable. Blueprint drift detection compares a runtime threshold to a signed float within `1e-6` and is likewise indifferent to what that threshold governs.

**Action Required**: NO — None. Your contract surface is stable; no changes to seeded-store shapes or attestation semantics are required.

**Questions for Your Team**:
1. While no immediate action is required for this refactoring, do you have any concerns about the domain-agnostic architecture affecting your three axiom implementations or warrant module? We want to ensure the attestation framework remains robust across different domain plugins.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 05" numbering is incomplete — "VEIP" (Verifiable Execution Integrity Pack) is used verbatim in class names like `VEIPBlueprintAttestation`, `VEIPKeyAttestation`, and `VEIPPhysicsAttestation`, as well as in plan filenames like [`plans/veip_three_axioms_architecture.md`](plans/veip_three_axioms_architecture.md). Would you prefer we complete the anonymization, or continue using "VEIP" consistently in committed code?
3. When would you like to review the final v4.0.0 attestation contracts and warrant semantics before we freeze them? We're targeting freeze within the next 2-3 weeks.

---

## Provider 06 — Agent Integrity Verifier (Sidecar Verification Gate)

**Context**: CAGE is undergoing a significant refactoring to extract finance-specific logic into a plugin architecture, enabling domain-agnostic governance. This refactoring represents our last opportunity to introduce coordinated breaking changes before the v4.0.0 protocol stabilization and reference architecture freeze. We're reaching out now to give sufficient lead time for any adaptations on your side, as the window for API changes is closing rapidly after this release.

Your integration implements the [`NormativeProvider`](src/gateway/governance/normative_provider.py:273) protocol with the `PASS`/`REVIEW`/`BLOCKED` `IntegrityStatus` vocabulary at protocol version `1-alpha`, and that contract is preserved. **You are impacted by payload key drift, and materially so given your strict parsing:** the body posted to `/verify` derives from the kernel's `action_context`, where `amount` and `symbol` become `magnitude` and `context`, so the vendored JSON schema used to validate request bodies will need regeneration or every request will fail schema validation and fall through to `cage.parse_error` as a hard `blocked`. One architectural note specific to your integration: the refactoring introduces domain plugin protocols (`GovernanceTierPlugin`, `InvariantModel`, `DomainToolProvider`) that vendor adapters are explicitly **prohibited** from implementing — a CI grep gate over `src/integrations/` will enforce this. Although agent-integrity verification is arguably a governance semantic rather than a regulatory baseline, the correct path remains a first-party tier that delegates outward across the `NormativeProvider` seam; please do not register a `cage.plugins` entry point.

**Action Required**: YES — regenerate the vendored request-body JSON schema for the renamed payload keys and refresh the `pass` / `review` / `blocked` fixtures in [`mock_endpoint.py`](src/integrations/provider_06/mock_endpoint.py). Do not implement or register any domain plugin protocol.

**Questions for Your Team**:
1. Does the vendored JSON schema regeneration create significant coordination burden, especially given your strict parsing requirements? We can provide example schemas and test fixtures for the new payload structure to accelerate the migration.
2. Is vendor anonymity in the CAGE codebase important to you? The current "Provider 06" numbering is incomplete — the actual vendor name and GitHub repository URL (`github.com/guardian-cyber/agent-integrity`) appear explicitly in docstrings within [`src/integrations/provider_06/adapter.py`](src/integrations/provider_06/adapter.py), and the vendored repository at [`third_party/agent-integrity/`](third_party/agent-integrity/) preserves your original project structure. Would you prefer we complete the anonymization, or use "Guardian Cyber" / "Agent Integrity" consistently in committed code?
3. When would you like to review the final v4.0.0 wire contract and schema specifications before we freeze them? We're targeting freeze within the next 2-3 weeks.

---

## Impact Summary

| Provider | Role | Protocol | Impacted | Nature |
|---|---|---|---|---|
| 01 | Normative compliance gate | `NormativeProvider` | Yes | Payload key drift → `act` digest re-baseline |
| 02 | CER attestation | Vendor-specific attestation | **Yes (breaking)** | Hardcoded finance graph topology + `stateHash` drift |
| 03 | Decision governance / bind receipts | `NormativeProvider` | Yes | Payload key drift → receipt digest re-baseline |
| 04 | Attestation + envelope mapper | `AttestationProvider` | No | Envelope treated opaquely; fetch is a stub |
| 05 | Execution evidence pack (3 axioms) | `AttestationProvider` ×3 | No | Already domain-agnostic |
| 06 | Agent integrity verifier | `NormativeProvider` | Yes | Vendored schema regeneration; plugin-seam prohibition |
