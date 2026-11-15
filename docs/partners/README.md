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
| `provider_02` | **NexArt** | Attestation Provider & Cryptographic Evidence Resolver (`AttestationProvider`, CER) | [`provider_02/`](provider_02/) | [`src/integrations/provider_02/`](../../src/integrations/provider_02/) |
| `provider_03` | **Veritas** | Synchronous Normative Provider (`NormativeProvider`) | [`provider_03/`](provider_03/) | [`src/integrations/provider_03/`](../../src/integrations/provider_03/) |
| `actuator_01` | **Archytan** | Downstream Execution Actuator (`ExecutionActuator`) | [`actuator_01/`](actuator_01/) | [`src/integrations/actuator_01/`](../../src/integrations/actuator_01/) |
| `actuator_02` | **NVIDIA OpenShell** | Dynamic Sandbox Supervisor (`ExecutionActuator` + `PolicyAdvisorBridge`) | [`actuator_02/`](actuator_02/) | [`src/integrations/actuator_02/`](../../src/integrations/actuator_02/) |
| `actuator_03` | **NVIDIA Sentry / DOCA** | Out-of-Band Hardware Quarantine (`QuarantineActuator` + `ExecutionActuator`) | [`actuator_03/`](actuator_03/) | [`src/integrations/actuator_03/`](../../src/integrations/actuator_03/) |
| `provider_05` | **Veraxis Execution Integrity Protocol (VEIP)** | Execution Warrant Source (`WarrantSource`) & Attestation Provider (`AttestationProvider`) | [`provider_05/`](provider_05/) | [`src/integrations/provider_05/`](../../src/integrations/provider_05/) |
| `provider_06` | **Guardian Cyber Agent Integrity** | Synchronous Normative Verifier (`NormativeProvider`) & Conformance Harness (`1-alpha`) | [`provider_06/`](provider_06/) | [`src/integrations/provider_06/`](../../src/integrations/provider_06/) |
| `provider_07` | **InferTheta** | Synchronous Normative Provider (`NormativeProvider`) — Bayesian Causal Suitability Oracle | [`provider_07/`](provider_07/) | [`src/integrations/provider_07/`](../../src/integrations/provider_07/) |
| `provider_08` | **Verdict Systems** | Synchronous Normative Provider (`NormativeProvider`) & External Evidence Custody (Sigstore Rekor) | [`provider_08/`](provider_08/) | [`src/integrations/provider_08/`](../../src/integrations/provider_08/) |
| `provider_09` | **OpsCanvas** | Infrastructure Estate Provider (`EstateProvider`) — dated, confirmed CloudOps dependency graph over MCP | [`provider_09/`](provider_09/) | *(Planned — seam + factory in [`estate_provider.py`](../../src/gateway/governance/estate_provider.py))* |

---

## Live Verification Status

Latest recorded over-the-wire result per adapter, current to 2026-11-14. A harness run ([`ci-partner-integration.yml`](../../.github/workflows/ci-partner-integration.yml), driven by [`partner_harness.py`](../../scripts/partner_harness.py)) passes only if every selected live test ran and passed ([`require_live`](../../tests/fixtures/require_live.py)), so a passing run means the tests ran rather than skipped. Since `#750` the weekly schedule runs only the three provisioned partners (`provider_01`, `provider_05`, `provider_08`) and lists the other four harness targets (`provider_02`, `provider_03`, `provider_07`, `actuator_01`) as `NOT RUN` with their blockers. The `provider_01` result is from after [Plan D](#plan-d--over-the-wire-conformance--partner-adapter-hardening); the `provider_05` and `provider_08` results are from 2026-10-31 and predate it. Results without a run ID come from a local run and are labelled as such.

| Adapter | Result | Run on `main` | Scope & what blocks a passing production-seam run |
|---|---|---|---|
| `provider_05` VEIP v0.2 | 10 passed, 0 not run (provisioned) | [`41234042599`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41234042599) at `5b0055ad` | Exercises the production `WarrantSource` seam (`Provider05WarrantSource`) across all 8 v0.2 scenarios (the v0.3 blueprint registry isn't deployed; its staged tests in [`test_provider_05_blueprint_live.py`](../../tests/integrations/provider_05/test_provider_05_blueprint_live.py) sit outside the harness) |
| `provider_01` FlowSignal | 12 passed, 0 not run (provisioned), 2026-11-14. First recorded run that includes `test_cage_conformance_endpoint_profile_provider_01_v02`, which passed. Earlier: 8 passed, 0 not run in [`41233853779`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41233853779) at `5b0055ad` | [`43645575266`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/43645575266) at `9e17af09`, dispatched for `provider_01` alone on the tag ref `conformance-v0.4.1` (the commit `main` pointed to) | Calls `provider.validate_fria(payload)` directly with FlowSignal's `AP-001` test vector (`action: "payment.release"`, not a registered `cage_finance` action) and top-level `target` and `approval_id` fields that `FriaTier._payload()` never sends, over the 37-field v0.2 `POST /cage/validate` contract with a per-run Google ID token and the FlowSignal key. The `cage-conformance` 0.4.1 `provider-01-v0.2` endpoint profile also passed in that run; on a `conformance-v*` tag ref the test takes the verifier from the published release wheel. The strict `v0.3` path (`#756`, `5898c869`) is opt-in and has not run over the wire: it waits on FlowSignal's sandbox serving v0.3 (`POAM-2026-113`, `POAM-2026-156` item 2, `POAM-2026-218`) |
| `provider_08` Verdict Systems | 4 passed, 0 not run (provisioned) | [`41233869303`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/41233869303) at `5b0055ad` | Exercises `/.well-known/verdict-authority.json`, `fetch_baseline`, and unauthenticated `validate_fria` fail-closed (`HTTP 401/403`) only; authenticated `validate_fria` (`ALLOW` / `ConsequenceToken` mint) is blocked on a valid `PROVIDER_08_API_KEY` in GitHub Actions secrets |
| `provider_02` NexArt | Not run in CI (`UNPROVISIONED_PARTNER_REASONS`); local: 2 of 3 `test_provider_02_live.py` passed on 2026-10-31, and CAGE-side CER envelope unwrapping was remediated in `#753` (`9a5ad1ce`) | none | CAGE's `Provider02CERResolver` ([`resolver.py`](../../src/integrations/provider_02/resolver.py)) now unwraps `bundle` from `GET /v1/resolve/cer/:certificateHash` and verifies `cer.governed.execution.v1` RFC 8785 JCS digests ([open items](provider_02/nexart/HITL_INTEROP_STATUS.md#open-items)); live CI is blocked on populating `PROVIDER_02_API_ENDPOINT`, `PROVIDER_02_JWK_ENDPOINT`, `PROVIDER_02_API_KEY_SECRET`, and a `cer.governed.execution.v1` `PROVIDER_02_TEST_CERT_HASH` in GitHub Actions secrets |
| `provider_07` InferTheta | Not run in CI (`UNPROVISIONED_PARTNER_REASONS`); local: 2 of 8 passed (`/health`, JWKS) while 6 returned HTTP 401 `Invalid API key.` | none | Blocked on provisioning a current `PROVIDER_07_API_KEY` and sandbox secrets (`PROVIDER_07_ENDPOINT`, `PROVIDER_07_JWKS_URL`, `PROVIDER_07_EXPECTED_KID`) in GitHub Actions secrets |
| `provider_03` Veritas | Not run (`UNPROVISIONED_PARTNER_REASONS`) | none | Blocked on provisioning a live partner sandbox endpoint and API key (`PROVIDER_03_ENDPOINT`, `PROVIDER_03_API_KEY`) in GitHub Actions secrets |
| `actuator_01` Archytan | Not run on `main` (`UNPROVISIONED_PARTNER_REASONS`). Run `41125558418` on `#598` authenticated through WIF, then failed closed (5 skipped); CAGE-side `AR-1` `intent_hash` receipt verifier remediated in `#755` (`8b926201`) | none | CAGE's `verify_partner_receipt()` ([`receipt_verifier.py`](../../src/integrations/actuator_01/receipt_verifier.py)) now binds `SHA-256(intent_hash) == envelope_digest` and verifies `"ARCHYTAN_RECEIPT_V1:" \|\| SHA-256(intent_hash)`; live CI is blocked on `ACTUATOR_01_ENDPOINT`, `ACTUATOR_01_TENANT_ID`, and mTLS PEM secrets (`ACTUATOR_01_CLIENT_CERT`, `ACTUATOR_01_CLIENT_KEY`, `ACTUATOR_01_CA_CERT`) in GitHub Actions (`POAM-2026-098`) |
| `actuator_02` NVIDIA OpenShell | Not run (not in `PARTNER_TARGETS`) | none | No harness target; never deployed against a live OpenShell Supervisor ([seal profile](actuator_02/SEAL_VERIFICATION_PROFILE.md)) |
| `actuator_03` NVIDIA Sentry / DOCA | Not run over live partner hardware (staged mTLS suite in [`test_actuator_03_live.py`](../../tests/integrations/actuator_03/test_actuator_03_live.py), `#754` `8dfe443b`) | none | Staged live mTLS conformance suite (`GET /health`, `POST /v1/dpu/quarantine` with `CAGE_QUARANTINE_ASSERTION_V1:`, `X-CAGE-Envelope-Digest`, detached Ed25519 receipt verification, and `refusal_proof_hash` vs. `governance_decision_digest` exclusivity) is ready; blocked on a live partner DPU quarantine sandbox endpoint and mTLS secrets (`POAM-2026-166`) |
| `provider_06` Guardian Cyber Agent Integrity | Not run over the wire. Offline, the vendored `1-alpha` CLI matched 7 of 7 required scenarios ([result](provider_06/CONFORMANCE_RESULT.md)), a verification-capability result only | none | No harness target |
| `provider_09` OpsCanvas | Not run (not in `PARTNER_TARGETS`) | none | No adapter yet ([decision points](provider_09/DECISION_POINTS.md)) |

---

## Plan D — Over-the-Wire Conformance & Partner Adapter Hardening

Plan D (`#750`, `#752`–`#756` and `#758`, released as `conformance-v0.4.1`) reconciles the standalone conformance verifier, release automation, and Layer 3 partner adapters against live wire contracts and cryptographic receipt schemas while enforcing honest, fail-closed reporting of what runs over the wire versus what remains blocked on partner sandboxes or credentials.

### 1. `cage-conformance` `0.4.1` Live Endpoint Verification & Corrected Wire Vectors (`#752`, `16d60823`)

[`packages/cage-conformance/`](../../packages/cage-conformance/) (`v0.4.1`, zero third-party runtime dependencies in [`pyproject.toml`](../../packages/cage-conformance/pyproject.toml)) extends `cage-conformance verify --endpoint <url> --profile <substrate-v1|provider-01-v0.2>` ([`runner.py`](../../packages/cage-conformance/src/cage_conformance/runner.py)):

- **Corrected `provider-01-v0.2` Live Wire Profile ([`provider_01_v02.json`](../../packages/cage-conformance/src/cage_conformance/vectors/provider_01_v02.json))**: The earlier vector described a request shape the partner does not serve (a nested `payload` with a static `mandate_valid_until`). It now carries the live 37-field `CageAuthorityDetermineRequest` for `POST /cage/validate`:
  - **Cloud Run DRS Dual-Header Authentication**: Supports `X-Serverless-Authorization: Bearer <gcp_id_token>` (`--gcp-id-token-file` / `$CAGE_CONFORMANCE_GCP_ID_TOKEN`) alongside `Authorization: Bearer <api_key>` (`--api-key-file` / `$CAGE_CONFORMANCE_API_KEY`); secrets are read strictly from files or environment variables, never command-line arguments.
  - **Relative timestamps and six black-box HTTP vectors**: `mandate_valid_until` and `screening_captured_at` are computed from offsets at run time, so the vectors do not go stale. The six cases are `CASE-1A` (valid request returns `ALLOW` with an authority record and receipt), `CASE-1B` (an identical replay of `CASE-1A` returns `ALLOW` with a receipt: the endpoint itself does not refuse a replay, and single use is enforced on the CAGE side), `CASE-1C` (unsupported action returns `REFUSE`), `CASE-1D` (expired mandate returns `REFUSE`), `CASE-1E` (stale screening evidence returns `ESCALATE`) and `CASE-1F` (malformed body returns HTTP 422 with no determination).
  - **Live test**: `test_cage_conformance_endpoint_profile_provider_01_v02` in [`test_provider_01_live.py`](../../tests/integrations/provider_01/test_provider_01_live.py) runs the profile from an unpacked wheel, passing both credentials as `0600` files. It runs only in the partner harness. It first passed over the wire in run [`43645575266`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/43645575266) on 2026-11-14 (12 passed, 0 not run), dispatched on the tag ref `conformance-v0.4.1`, where the test downloads the published 0.4.1 release wheel instead of building one.
- **`substrate-v1` Well-Known JWKS Parity Vector ([`substrate_v1.json`](../../packages/cage-conformance/src/cage_conformance/vectors/substrate_v1.json))**: Adds `SUBSTRATE-WELL-KNOWN-JWKS` alongside `SUBSTRATE-POLICY-VERSION` (`GET /governance/policy-version` `active_hash` and `thresholds_digest` as 64-hex SHA-256 digests) and `SUBSTRATE-JWKS` (`GET /governance/jwks`), verifying that `GET /governance/.well-known/jwks.json` (the endpoint [`packages/cage-client`](../../packages/cage-client/) queries by default) returns a valid JWKS whose `kid` set matches `/governance/jwks`.

### 2. Standalone `conformance-v*` Release Pipeline & OIDC Attestation Smoke Gate (`#752` `16d60823`, `#758` `9e17af09`)

- **Tag-Scoped Release Automation ([`publish-client-sdk.yml`](../../.github/workflows/publish-client-sdk.yml))**: Triggers on `client-v*`, `conformance-v*`, and `workflow_dispatch`:
  - Enforces a fail-closed Python `tomllib` version guard requiring `refs/tags/client-v<X.Y.Z>` to match `packages/cage-client/pyproject.toml` and `refs/tags/conformance-v<X.Y.Z>` to match `packages/cage-conformance/pyproject.toml` before building.
  - Builds both wheel and sdist for `cage-conformance`, installs the `.tar.gz` sdist into an isolated `--no-deps` virtualenv to verify that `cage_conformance/vectors/*.json` are packaged, checks `cage-conformance --version`, and runs an offline `trace_v1.json` smoke check.
  - Publishes only the package the tag names: a GHCR image (`cage-conformance:<version>`, smoke-tested with `--version` and a trace vector before it is pushed) and the wheel and sdist attached to the GitHub Release. PyPI publishing is a separate step that runs only when the repository variable `PYPI_TRUSTED_PUBLISHING_ENABLED` is `true`. The tag `conformance-v0.4.1` is at `9e17af09`.
- **Conformance OIDC Attestation Smoke ([`ci.yml`](../../.github/workflows/ci.yml))**: verifies a trace, mints a GitHub Actions OIDC token whose audience is the report digest, runs `cage-conformance attest`, and requires `cage-conformance verify-report` to print `posture=AUTHOR_SELF_TEST`.

### 3. `provider_02` (NexArt) CER Resolution Envelope Unwrapping (`#753`, `9a5ad1ce`)

On `GET /v1/resolve/cer/:certificateHash`, the live NexArt Attestation Node returns a resolution envelope (`{"ok": true, "certificateHash": "sha256:...", "bundle": <cer>, ...}`) rather than a bare CER object. Previously, `Provider02CERResolver` in [`src/integrations/provider_02/resolver.py`](../../src/integrations/provider_02/resolver.py) hashed the outer wrapper and failed `test_live_cer_verification_signature` with `CER_DIGEST_MISMATCH`.

- `Provider02CERResolver` now unwraps `bundle` from the resolution envelope (or accepts a direct CER object), enforces outer-vs.-inner `certificateHash` parity, requires `bundleType == "cer.governed.execution.v1"` (failing closed with `CER_UNSUPPORTED_BUNDLE_TYPE` on non-governed CERs such as `cer.ai.execution.v1`), and recomputes `sha256:` + SHA-256 over the RFC 8785 JCS bytes of the inner `cer` without `certificateHash`.
- Verified across [`tests/integrations/provider_02/test_resolver.py`](../../tests/integrations/provider_02/test_resolver.py) and [`tests/integrations/provider_02/test_verification.py`](../../tests/integrations/provider_02/test_verification.py); live CI execution now awaits only GitHub Actions secrets (`PROVIDER_02_API_ENDPOINT`, `PROVIDER_02_JWK_ENDPOINT`, `PROVIDER_02_API_KEY_SECRET`, and a `cer.governed.execution.v1` `PROVIDER_02_TEST_CERT_HASH`).

### 4. `actuator_01` (Archytan) `AR-1` `intent_hash` Receipt Binding & Shared Key Manifest Client (`#755`, `8b926201`, `POAM-2026-098`)

Archytan's kernel signs `"ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)` (`kid = "archytan-sandbox-receipt-2026-01"` at `GET /v1/keys/receipt-manifest`) and returns `intent_hash` (the full RFC 8785 JCS-canonical governance envelope submitted by CAGE) rather than `envelope_digest`.

- [`verify_partner_receipt()`](../../src/integrations/actuator_01/receipt_verifier.py) and [`receipt_diagnostic.py`](../../packages/cage-conformance/src/cage_conformance/receipt_diagnostic.py) (`cage-conformance diagnose-receipt`) now require `intent_hash`, verify `SHA-256(intent_hash) == envelope_digest` to bind the receipt to the submitted governance envelope, and verify the detached Ed25519 signature over `"ARCHYTAN_RECEIPT_V1:" || SHA-256(intent_hash)` against out-of-band `kid`-resolved keys (`AR-1` in [`docs/BREAKING_CHANGES.md`](../BREAKING_CHANGES.md)).
- Retires `05275d02:src/integrations/provider_07/jwks_client.py` (`Provider07JwksClient`), consolidating both `actuator_01` and `provider_07` onto [`Ed25519KeyManifestClient`](../../src/integrations/trust/key_manifest.py) with `allowed_schemes` narrowing and single warm-cache refresh on rotated `kid` (`16/16` planted mutants killed across `RV-M1`–`RV-M10` and `KM-M1`–`KM-M6`).

### 5. `actuator_03` (NVIDIA Sentry / DOCA) Live mTLS Conformance Suite, Staged and Not Yet Run (`#754`, `8dfe443b`, `POAM-2026-166`)

[`tests/integrations/actuator_03/test_actuator_03_live.py`](../../tests/integrations/actuator_03/test_actuator_03_live.py) is a four-test suite written to run against a live partner endpoint. No such endpoint exists, so it has never run over the wire. [`test_actuator_03_live_contract.py`](../../tests/test_actuator_03_live_contract.py) runs the same four test functions against a local mTLS server over real sockets and checks that planted server defects fail them; that is evidence about the suite, not about the partner. The suite covers for out-of-band DPU quarantine (`Actuator03Adapter` in [`src/integrations/actuator_03/adapter.py`](../../src/integrations/actuator_03/adapter.py)):

- Exercises `GET /health` and `POST /v1/dpu/quarantine` over mTLS, signed with `CAGE_QUARANTINE_ASSERTION_V1:` and `X-CAGE-Envelope-Digest`.
- Verifies detached Ed25519 receipt signatures (`CAGE_QUARANTINE_RECEIPT_V1:`) via [`Ed25519KeyManifestClient`](../../src/integrations/trust/key_manifest.py) and enforces mutual exclusion between `refusal_proof_hash` (kernel refusal-triggered quarantines) and `governance_decision_digest` (clearance-bridged quarantines) per `POAM-2026-149`.
- Marked `live_external` and `partner` (without `partner_integration` until the partner DPU sandbox is provisioned under `POAM-2026-166`) so `require_live` remains strictly fail-closed on active targets.

### 6. `provider_01` (FlowSignal) Opt-In `v0.3` Strict-Fact Mode & Receipt-Validity TTL (`#756`, `5898c869`, `POAM-2026-113`, `POAM-2026-156` Item 2, `POAM-2026-218`)

Specified in [`FLOWSIGNAL_PHASE3_V03_ADDENDUM.md`](provider_01/FLOWSIGNAL_PHASE3_V03_ADDENDUM.md) and implemented in [`src/integrations/provider_01/provider.py`](../../src/integrations/provider_01/provider.py) behind `PROVIDER_01_CONTRACT_VERSION=v0.3` (while keeping `"v0.2"` as the default until FlowSignal cuts over its Cloud Run staging service):

- **Verified Caller Identity & Server-Bound `target` (`POAM-2026-113`)**: Under `v0.3`, `actor_id`, `actor_authenticated`, and `kya_status` derive strictly from CAGE's server-verified `operator_urn` / `actor_id` (failing closed with `PROVIDER_01_UNVERIFIED_CALLER` before any HTTP call when absent or conflicting), `target` is populated strictly from server-configured `PROVIDER_01_BOUND_TARGET` (`bound_target`), and all 14 institutional mandate, account, counterparty, and screening fields must be explicitly supplied with zero synthetic defaults (`PROVIDER_01_MISSING_VERIFIED_FACT`).
- **Receipt-Validity-Bounded Single-Use Marker Retention (`POAM-2026-156` Item 2)**: Under `v0.3`, every `ALLOW` response must carry a future RFC 3339 UTC-offset `authority_receipt.valid_until` (failing closed with `CONSEQUENCE_TOKEN_MINT_FAILED` otherwise), which CAGE embeds as `ConsequenceTokenClaims.rec_exp` ([`consequence_token.py`](../../src/gateway/governance/consequence_token.py)) so [`ConsequenceGateway.evaluate()`](../../src/gateway/governance/consequence_gateway.py) and [`ConsequenceAuthorityStore.consume_once()`](../../src/gateway/governance/consequence_authority_store.py) retain the replica-acknowledged `consequence:token:<rec>` single-use marker for `max(store.ttl_seconds, (rec_exp - now) + 30)`.
- **Self-Enforcing Cutover Gate (`POAM-2026-218`)**: `test_poam_218_forbids_closing_poam_113_while_v02_dual_path_exists` in [`tests/integrations/provider_01/test_provider_01_v03_readiness.py`](../../tests/integrations/provider_01/test_provider_01_v03_readiness.py) fails CI if `POAM-2026-113` or `POAM-2026-218` is marked closed while `"v0.2"` or `PROVIDER_01_CONTRACT_VERSION` remains in `provider.py`.

### 7. Summary of Weekly Harness Coverage (`PROVISIONED_PARTNERS` vs. `UNPROVISIONED_PARTNER_REASONS`)

Of the eleven partner slots, three have run live over the wire in the harness on `main`, four are harness targets that have not, and four have no harness target. [`partner_harness.py`](../../scripts/partner_harness.py) requires the first two groups to partition its seven targets, and a passing scheduled run reports `3 of 7 partners verified over the wire; 4 of 7 NOT RUN (unprovisioned)`. The partial local results for `provider_02` and `provider_07` in [Live Verification Status](#live-verification-status) are not harness passes. Plan D moved no partner between these groups. What it added over the wire is one result: the `provider-01-v0.2` endpoint profile passed against FlowSignal's sandbox from the published 0.4.1 wheel (run [`43645575266`](https://github.com/google/cybernetic-agent-governance-engine/actions/runs/43645575266)). The CAGE-side fixes for `provider_02` and `actuator_01` are verified hermetically only, and stay unverified over the wire until their sandboxes are provisioned.

- **Three partners live over the wire (`PROVISIONED_PARTNERS`, run with `-p tests.fixtures.require_live`)**:
  1. `provider_01` (**FlowSignal**): runs [`tests/integrations/provider_01`](../../tests/integrations/provider_01/) against the live Cloud Run DRS endpoint (minting `PROVIDER_01_GCP_ID_TOKEN` per run via WIF) including `cage-conformance verify --endpoint --profile provider-01-v0.2` (`CASE-1A`..`CASE-1F`).
  2. `provider_05` (**VEIP v0.2**): runs [`tests/integrations/provider_05`](../../tests/integrations/provider_05/) across all 8 v0.2 `WarrantSource` scenarios against `PROVIDER_05_ATTESTATION_ENDPOINT`.
  3. `provider_08` (**Verdict Systems**): runs [`tests/integrations/provider_08`](../../tests/integrations/provider_08/) against `PROVIDER_08_ENDPOINT` (discovery, `fetch_baseline`, and unauthenticated `validate_fria` fail-closed `401`/`403`; authenticated `ALLOW` awaits `PROVIDER_08_API_KEY`).
- **Four harness partners not run (`UNPROVISIONED_PARTNER_REASONS`)**:
  1. `provider_02` (**NexArt**): missing GitHub Actions sandbox secrets (`PROVIDER_02_API_ENDPOINT`, `PROVIDER_02_JWK_ENDPOINT`, `PROVIDER_02_API_KEY_SECRET`, and a `cer.governed.execution.v1` `PROVIDER_02_TEST_CERT_HASH`). The harness's own blocker text also still names an open CER signature verification defect; `#753` fixed the resolver hermetically, and the live test that failed has not been re-run.
  2. `provider_03` (**Veritas**): no live partner sandbox endpoint or API key provisioned in GitHub Actions secrets (`PROVIDER_03_ENDPOINT`, `PROVIDER_03_API_KEY`).
  3. `provider_07` (**InferTheta**): missing a valid `PROVIDER_07_API_KEY` and sandbox secrets (`PROVIDER_07_ENDPOINT`, `PROVIDER_07_JWKS_URL`, `PROVIDER_07_EXPECTED_KID`) in GitHub Actions secrets.
  4. `actuator_01` (**Archytan**): missing sandbox endpoint and mTLS PEM secrets in GitHub Actions (`ACTUATOR_01_ENDPOINT`, `ACTUATOR_01_TENANT_ID`, `ACTUATOR_01_CLIENT_CERT`, `ACTUATOR_01_CLIENT_KEY`, `ACTUATOR_01_CA_CERT`).
- **Four slots with no harness target**: `actuator_02`, `actuator_03` (suite staged, section 5), `provider_06` and `provider_09`.

---

## Boundaries & Isolation Guidelines

1. **Vendor Isolation:** Partner-specific technical documentation and protocols must remain in `docs/partners/provider_XX/` and `docs/partners/actuator_XX/`. They must not mix into core engine architecture (`docs/architecture/`) or internal governance policies (`docs/governance/`).
2. **Fail-Closed Verification:** All partner providers adapt to canonical CAGE dataclasses (`NormativeBaseline`, `ValidationResult`, `EvidenceSeal`, `AttestationReceipt`). Domain execution must always fail closed if a partner verifier is unreachable, timed out, or unverified.
3. **No Domain Leakage:** Partner wire payloads and envelopes must not leak CAGE-specific Layer 2 financial domain concepts (`amount`, `symbol`, `portfolio_id`) into upstream verifiers unless specifically dictated by negotiated domain contracts.

