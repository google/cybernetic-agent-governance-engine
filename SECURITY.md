# Security Policy

## Supported Versions

Security fixes land exclusively on `main`; older release tags do not receive backports.

| Version | Supported |
|---|---|
| `main` (post-`v4.1.0`) | ✅ Active (receives all security fixes) |
| `4.1.0` | ⚠️ Update to `main` (or the next release) for fixes published after `v4.1.0` |
| `< 4.1.0` (`4.0.x`, `3.x`, `2.x`) | ❌ No |

## Security Advisories

Published security advisories, affected ranges, CVSS vectors, and fix commits are maintained canonically on GitHub:

- **[Published GitHub Security Advisories](https://github.com/google/cybernetic-agent-governance-engine/security/advisories)**

Advisories published after `v4.1.0` (including internal maintainer findings that do not appear under external [Security Research Acknowledgments](#security-research-acknowledgments)):

| Advisory | Published | Severity | Fix on `main` | Summary |
|---|---|---|---|---|
| `GHSA-gc2v-v2jw-q499` | `2026-11-19` | Medium | `3feffdf6` (`#820`, `client-v0.4.0`) | `cage-client <= 0.3.0` and `GatewayClient`: HTTP `403` refusals and `202`/`409`/`422` deferrals accepted without `GovernanceEnvelope` signature verification |
| `GHSA-c9j3-q7hh-p95m` | `2026-11-19` | Medium | `dd27b66b` (`#815`, **AP-1** in [`docs/BREAKING_CHANGES.md`](docs/BREAKING_CHANGES.md)) | Governed financial advisor: `CAGE_ALLOW_ASSERTED_PRINCIPAL` accepted unverified end-user identities in enforcing postures (`production`/`staging`) despite documentation stating it was ignored there |
| `GHSA-5c7p-g73w-v4m3` | `2026-11-19` | Medium | `aa50d17d` (`#814`) | Governed inference proxy: non-`content` response fields bypassed output governance and PII redaction |
| `GHSA-797p-rrgm-4p56` | `2026-11-19` | High | `c145a9cc` (`#813`) | Governed financial advisor: `require_api_key()` accepted end-user OIDC tokens on service-only routes |
| `GHSA-cxxx-6xfq-vvp4` | `2026-11-18` | Medium | `f6313b20` (`#809`) | `provider_05` three-axiom attestation providers accepted live `/v0.3/` responses as `VERIFIED` when `v0.3` signature fields were stripped |
| `GHSA-5438-3wwf-qvcq` | `2026-11-18` | Medium | `1ad49289` (`#808`) | `actuator_03` quarantine adapter settled unsigned or unverifiable receipts as `ACCEPTED` without `ACTUATOR_03_REQUIRE_SIGNED_RECEIPTS=true` |
| `GHSA-348p-gfpg-qqm9` | `2026-11-18` | Medium | `1aeed422` (`#799`) | `provider_06` evidence adapter sealed receipts not bound to the submitted evidence and returned unverified seals without a key manifest |

Earlier fixes resolved through public issues, internal audits, or pre-publication tracker entries are recorded in [`CHANGELOG.md`](CHANGELOG.md) and [`docs/POAM.md`](docs/POAM.md).

> **⚠️ Reference architecture notice:** CAGE is a reference architecture and is
> not deployed to production. Advisories are published and fixed to ensure the
> codebase accurately represents the security posture claimed in associated
> research and compliance artifacts.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability, please use the GitHub Security Advisory
["Report a Vulnerability"](https://github.com/google/cybernetic-agent-governance-engine/security/advisories/new)
feature. Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code (if applicable)
- Your suggested fix (if you have one)

You should receive a response within **5 business days**. If you do not receive
a response, please follow up to ensure your report was received.

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. You report the vulnerability privately.
2. We confirm receipt and begin investigation within 5 business days.
3. We develop and test a fix.
4. We release the fix and publish a security advisory.
5. You may publicly disclose the vulnerability after the fix is released, or
   after 90 days from the initial report — whichever comes first.

## Landing an Advisory Fix (Maintainers)

### When this flow applies vs. a direct public PR

- **Use the private-fork `T=0` advisory flow below** whenever a fix alters a security, authentication, authorization, cryptographic, PII-redaction, or governance-tier boundary in a distributed artifact (`cage-client`, `cage-conformance`, container images) or in `main` enforcement/policy code, and the PR diff itself exposes a real bypass or forgeability gap in prior commits or releases.
- **Use a direct public PR (no advisory)** for hygiene cleanups, test-only or CI-gate additions, documentation/compliance updates, or structural refactors that close no bypass in any shipped artifact or `main` enforcement path. When uncertain whether an exposure warrants an advisory, default to the `T=0` flow.

### Procedure

GitHub Actions does not run on pull requests in temporary private forks, and
ruleset 25966171 (`Require status checks on main`, no bypass actor) requires nine
checks pinned to GitHub Actions — including `Approved review or recorded bypass`,
whose post-merge [`review-bypass-ledger.yml`](.github/workflows/review-bypass-ledger.yml)
check fails on `main` if a merge lacks a pre-merge review or Sigstore bypass
record. **Do not disable ruleset 25966171 or add a bypass actor.** Ruleset
26377312 (blocking non-fast-forward updates and deletion) also stays enabled
throughout.

Because pushing a fix branch to the public repository exposes the vulnerability
path before publication, publish first at `T=0` and land via normal public
pull request(s):

1. **Develop and rehearse off-public:** Stage fixes in the advisory's temporary
   private fork or a local isolated worktree. Before `T=0`, rebase onto current
   `origin/main`, run deterministic pre-commit checks and targeted security
   regression tests, and when landing multiple advisories together verify
   conflict-free multi-way merging across `git merge-tree --write-tree`
   (including shared files such as [`docs/BREAKING_CHANGES.md`](docs/BREAKING_CHANGES.md)).
2. **Pre-stage draft advisory metadata via the REST API:** Before `T=0`, `PATCH`
   each draft on `repos/google/cybernetic-agent-governance-engine/security-advisories/<GHSA_ID>`
   with its final public description (including a concrete non-code mitigation
   and with any `<!-- ... -->` comment templates removed), `ecosystem: "other"`
   structured range (`patched_versions: null` when remediating on `main` ahead
   of a tag), verified CVSS 3.1 vector, and reporter `.credits`. Confirm HTTP
   `200` on `GET` read-back so `T=0` requires only a state transition.
3. **Close all open PRs in the temporary private fork before publishing:**
   GitHub's advisory publish endpoint rejects `{"state": "published"}` with HTTP
   `422` while any pull request in the temporary private fork remains open.
   Close open private-fork PRs before switching the advisory state.
4. **At `T=0`, publish first, then open public PR(s):**
   - `PATCH` each draft with `{"state": "published"}` only (leaving `.credits`
     and pre-staged metadata untouched).
   - Immediately push the pre-verified fix branch(es) to `origin` and open
     public pull request(s) against `main`, then `PATCH` each live advisory's
     remediation line to cite the open PR (`Fix in flight in #<PR>` alongside
     the immediate mitigation).
5. **Run all checks, squash-merge, stamp, and verify read-back:**
   - Wait for all automated checks in ruleset 25966171 (strict up-to-date branch
     policy is disabled, so independent PRs can run checks in parallel). Never
     bypass a failing or pending check; rerun transient runner flakes, and if a
     PR stays stalled on CI past the disclosure window, update the in-flight
     advisory note to cite the staged PR commit SHA explicitly.
   - Squash-merge once checks pass (`gh pr merge <PR> --squash --admin`, where
     `--admin` in single-maintainer posture bypasses only ruleset 19769096's
     review rule while all nine checks in ruleset 25966171 pass).
   - Immediately stamp **`Fixed on main in <SHA> (#<PR>)`** onto the published
     advisory without disturbing `.credits`, and perform a **`GET` read-back** on
     the advisory endpoint to verify `state == "published"`, the landed `main`
     SHA, and intact `.credits`. Delete temporary branches and worktrees after
     post-merge checks pass on `main`.

## Package Distribution Channels

`cage-client` and `cage-conformance` are distributed exclusively via **GitHub Releases** (`client-v*` / `conformance-v*` tags with attached wheels/sdists) and **GitHub Packages (GHCR)** — **not** PyPI. `PYPI_TRUSTED_PUBLISHING_ENABLED` in [`.github/workflows/publish-client-sdk.yml`](.github/workflows/publish-client-sdk.yml) is intentionally left unset/disabled due to Google branding and package-publishing policy and must not be enabled without explicit branding sign-off. Security advisories therefore use `ecosystem: "other"` with commit-SHA / GitHub Release remediation, and [`scripts/check_client_sdk_sync.py`](scripts/check_client_sdk_sync.py) enforces `[tool.cage.release]` parity against GitHub release tags.

## Scope

The following are **in scope** for security reports:

- Remote code execution in the governance gateway or compliance bridge
- Authentication/authorisation bypass in the governance pipeline
- Governance tier bypass (violations of the NoDirectBind invariant)
- Injection vulnerabilities (prompt injection, SQL injection, etc.)
- Cryptographic weaknesses in the Cloud KMS signing, kid-resolved trust anchors,
  development-only software signers (Ed25519 / HMAC-SHA256), routing seals, or
  the SHA-256 hash-chain implementation
- Control Barrier Function (CBF) race conditions or invariant violations
- Secrets or credentials exposed in the repository

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these upstream)
- Denial-of-service attacks requiring physical access
- Social engineering attacks
- Issues in documentation only

## Security Hardening Notes

CAGE is a domain-agnostic governance substrate designed for regulated
environments generally; `finance` ([`src/cage_finance/`](src/cage_finance/)) is
the sole finalized, production-eligible domain plugin (`healthcare` in
[`src/cage_healthcare/`](src/cage_healthcare/) and `physical_ai` in
[`src/cage_physical_ai/`](src/cage_physical_ai/) ship as non-production
reference stubs; `POAM-2026-076`–`078`, `POAM-2026-198`), and the jurisdictional
region (`US_FED`, `EU_ECB` or `APAC_MAS`, set by `CAGE_DEPLOYMENT_REGION` and
read only by [`resolve_deployment_region()`](src/gateway/governance/env_posture.py);
unknown values are refused, and an unset value is refused in enforcing postures
and resolves to `US_FED` only in `dev`, `test` and `ci`) determines which
regulatory controls are in scope for a given deployment. Key security controls are documented in:

- [`docs/POAM.md`](docs/POAM.md) — open findings and accepted risks;
  [`OSCAL_EVIDENCE_CLAIM_REGISTER.md`](docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md)
  — whether each control claim's evidence holds;
  [`compliance/gate_w_certification.json`](compliance/gate_w_certification.json) —
  what was last certified, at which commit
- [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md) — a
  superseded v3.0.1 snapshot (2026-08-28), kept because other documents link to
  it; do not cite it as current status
- [`docs/operations/KEY_ROTATION.md`](docs/operations/KEY_ROTATION.md) — cryptographic key lifecycle and rotation runbooks (SC-12 / IA-5)
- [`docs/architecture/GATEWAY_ARCHITECTURE.md`](docs/architecture/GATEWAY_ARCHITECTURE.md)
- [`infra/targets/gcp-gke/network_policy.tf`](infra/targets/gcp-gke/network_policy.tf) — Kubernetes `NetworkPolicy` & GKE Dataplane V2 `FQDNNetworkPolicy` isolation
- [`COMPLIANCE.md`](COMPLIANCE.md)

### Implemented Controls Summary

| Control | Census Claim ID | Implementation |
|---|---|---|
| Governance signing | `sp800-53-component-definition.yaml#61c43f8a-6693-4049-ae09-edd8b22f500a` | Cloud KMS asymmetric signing (cloud providers in `src/integrations/{gcp,aws,azure}/kms_provider.py`, loaded via `signer_factory.py`); separate keys per role (gateway seal, reconciler snapshot, compliance-bridge evidence) with kid-resolved verification. Software Ed25519 / HMAC signers are refused under an enforcing posture and allowed only in dev/test/CI. 90-day rotation cadence per `KEY_ROTATION.md` |
| Routing seal (v3) | `sp800-53-component-definition.yaml#0c2d40d7-0d19-4b9d-9afa-6c80967b31b4` | Single-use JWT signed by the gateway's governance signer (Cloud KMS in enforcing postures), verified by `kid` against an independently resolved trust anchor and bound to the SHA-256 evidence `record_hash`. The HMAC v2 4-tuple is a legacy path `verify_seal()` rejects while `CAGE_SEAL_STRICT_MODE` is true (the default) and always in production. Internal to `/tools/execute` and `ConsequenceGateway` — **not** used for caller authentication |
| TLS & Transport Security | `sp800-53-component-definition.yaml#230de322-4b76-4a0d-b07d-267f4fa23769` | Redis TLS 1.2+ enforcement (`src/gateway/infrastructure/redis_client.py`), OIDC JWKS `verify=True` enforcement, and Linkerd mTLS across meshed pods (`tests/test_tls_enforcement.py`). Outbound HTTP client wiring for `create_hardened_client_context()` (`src/gateway/infrastructure/tls_context.py`) is open under reopened `POAM-2026-011` (`docs/POAM.md`) |
| Base Image Hardening | `system-security-plan.yaml#s3000001-plat-si3-8000-platform0001` | Advisor, gateway, compliance-bridge and NeMo Guardrails images use two-stage builds on a digest-pinned Wolfi base (`cgr.dev/chainguard/wolfi-base`) with no compiler, util-linux or package-manager cache in the runtime stage and a build-time `apk upgrade`; images are tagged by git SHA and their digests signed for Binary Authorization at build time (`scripts/build_images.sh`) (`lula-validation-si2.yaml` active; `SI-3` runtime admission stub open) |
| Prompt injection detection | `sp800-53-component-definition.yaml#8e46d991-dd78-416a-897d-f909cb63be8d` | Aho-Corasick O(n) scan; 14+ patterns (partially-implemented: Stage 1 deterministic scan active; semantic tier opt-in) |
| PII protection | `component-definition.yaml#e1f2a3b4-c5d6-7890-efab-901234567890` | Presidio; 15 entity types; input + output (`POAM-2026-146`, `POAM-2026-147` open) |
| Human-in-the-loop | `component-definition.yaml#aarm2026-v7-context-overflow` | Redis-persisted checkpoint; TOCTOU remediation via `post_hitl_rehydrate` + `post_hitl_revalidate` (advisor calls the gateway's `POST /governance/revalidate-post-hitl`) (`POAM-2026-196` open) |
| Control Barrier Function | `sp800-53-component-definition.yaml#943496c8-5b07-48e4-a175-731366d416fa` | Atomic Redis Lua (`atomic_verify_and_commit()`) with synchronous replica `WAIT` barrier, monotonic `safety:fence_epoch` with a shared high-water mark (`safety:fence_epoch_hwm`), and fail-closed state rollback |
| Evidence chain integrity | `sp800-53-component-definition.yaml#80d95b3a-12ae-4dd4-8db4-b52661335fa4` | SHA-256 hash-chained NDJSON & Redis Streams db=1 (`noeviction`, Lua compare-and-append); enforced blocking durability in production (`validate_evidence_stream_preconditions()`); compliance-bridge `EvidenceCustodian` KMS batch attestation (`EVIDENCE_KMS_KEY`) to WORM storage and `CustodyVerifier` read-back verification (`kid`-resolved trust anchors, `assert_citable()` OSCAL citation gate) |
| mTLS | `sp800-53-component-definition.yaml#5f386745-cdda-431b-adec-850cdd899f3e` | Linkerd mTLS with a Google CAS trust anchor and `defaultInboundPolicy = "all-authenticated"` (`infra/modules/service_mesh`); per-workload Linkerd `Server` / `HTTPRoute` / `AuthorizationPolicy` across gateway, compliance-bridge, `:9090` metrics, and `:4191` admin ports (`POAM-2026-007`, `POAM-2026-080`, `POAM-2026-195` closed `2026-11-13`; component-definition census `WEAKER` pending restatement) |
| Caller identity | `sp800-53-component-definition.yaml#ca8f96e2-69a3-4d6b-980c-962e73e075d8` | Gateway ingress requires a Linkerd-verified `l5d-client-id` that matches `CAGE_TRUSTED_CLIENT_IDENTITIES` ([`WorkloadIdentityMiddleware`](src/gateway/server/workload_identity.py)); enforced in every environment, **no** header/body identity fallback, fail-closed 403. An RFC 9449 `DPoPValidator` (`src/gateway/server/dpop_validator.py`) ships and is unit-tested but is **not yet wired into any ingress path**. See [`docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md`](docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md) (partially-implemented: SVID binding enforced; DPoP unwired) |
| Egress credentials (v3.1.0, seam only — `POAM-2026-072`) | `system-security-plan.yaml#h8000009-5000-4000-8000-000000000017` | `CredentialBrokerAdapter` `Protocol` in Layer 1 (`src/gateway/governance/seams/credential_broker.py`); when a concrete broker is supplied to `Actuator01BindingAdapter`, credentials are fetched per dispatch, masked in logs, excluded from `ActuationReceipt`, and fail closed on `CredentialNotFound` / `CredentialAccessDenied` via `ingest_actuation_receipt()`. At HEAD no concrete `CredentialBrokerAdapter` ships in `src/` and `BrokerActuator` reads `BROKER_API_KEY` from `os.environ` (`POAM-2026-072` reopened) |
| Egress lockdown | `system-security-plan.yaml#p7000001-plat-sc7-8000-platform0001` | GKE Dataplane V2 `NetworkPolicy` & `FQDNNetworkPolicy` resources in `infra/targets/gcp-gke/network_policy.tf` (`POAM-2026-190`, `POAM-2026-195` closed; L3/L4 FQDN wildcard scope open under `POAM-2026-152`) |
| Token quota enforcement | `component-definition.yaml#tqp007-req-0001-0000-0000-000000000001` | Per-session step-count (≤12) and token (≤100k) via Redis atomic Lua counters; fail-closed (partially-implemented: Lua quota enforced; `lula-validation-tqp007.yaml` is rated Stub: it checks only that the gateway is ready with a `REDIS_URL`, not fail-closed behaviour, POAM-2026-219) |

> **Note:** CAGE is a reference architecture. Regulated-environment deployers
> must conduct their own risk assessment before production use. For current
> status see [`docs/POAM.md`](docs/POAM.md) and the security and compliance
> status section of the root [`README.md`](README.md).

### KMS Cryptographic Signing Security

> **Replay-attack closure:** KMS-signed reconciliation payloads embed a `signed_at` Unix timestamp. The verifier (`KMSGovernanceSigner.verify()` in `kms_signer.py`) rejects any payload where `now - signed_at > 300 s` (`MAX_KMS_PAYLOAD_AGE_SECONDS`).

### Redis / Data-Layer Security

> **Strict Replication & Fence Epoch Hardening:** In production (`CAGE_ENV=prod`), `ControlBarrierFunction` asserts synchronous replica replication (`CAGE_STRICT_REPLICATION=true`). If replica synchronization fails during `WAIT`, the local balance debit is automatically rolled back (`rollback_state(cost)`) and fails closed. Monotonic `safety:fence_epoch` counters prevent stale-replica balance replays.

### Evidence Stream Precondition Hardening & Custody Verification

> **Audit Durability & Citation Guarantee:** `validate_evidence_stream_preconditions()` is posture-based: under an enforcing posture (anything but dev/test/ci; an unset `CAGE_ENV` is production) it halts startup if `EVIDENCE_STREAM_ENABLED=false`, or if `EVIDENCE_CHAIN_BLOCKING=false` without an explicit `CAGE_ALLOW_NONBLOCKING_PROD=true`. The gateway lifespan also starts the sink via `start_evidence_sink()` and fails closed, so no routing seal or `ConsequenceGateway` `EXECUTE` verdict is issued without durable evidence commitment to the tamper-evident log. In the compliance bridge, `EvidenceCustodian` signs batches with `EVIDENCE_KMS_KEY` and writes them via `put_if_absent()` to WORM cold storage, while `CustodyVerifier` (`evidence_verifier.py`) re-verifies the archive on `EVIDENCE_VERIFY_INTERVAL_S` against `kid`-resolved trust anchors and gates OSCAL assessment citations (`OSCAL_REQUIRE_VERIFIED_CUSTODY=true`).

### Zero-Trust Caller Identity

> **Header-spoofing closure:** Caller identity is never read from application-layer
> data. `X-Agent-ID` headers, body-supplied `agent_id` fields, and the
> `X-CAGE-Routing-Seal` header are not accepted as authentication. The sole source of
> truth is the `l5d-client-id` header, which the Linkerd inbound proxy sets from the
> verified mTLS peer certificate (or strips when there is none). The gateway accepts
> exactly one such header matching `CAGE_TRUSTED_CLIENT_IDENTITIES`, in every
> environment; anything else fails closed with 403 rather than falling back to an
> anonymous principal. The mesh `AuthorizationPolicy` independently admits only the
> advisor's service account (`POAM-2026-080` & `POAM-2026-167`, closed in certified Gate W `8956f505`).

### Egress Credential Brokerage Seam (v3.1.0 — `POAM-2026-072` Open)

> **Seam contract (concrete broker open under `POAM-2026-072`):** [`CredentialBrokerAdapter`](src/gateway/governance/seams/credential_broker.py) defines the Layer 1 per-dispatch credential seam: when a concrete broker is injected into [`Actuator01BindingAdapter`](src/integrations/actuator_01/adapter.py), credentials are requested per dispatch keyed on the calling agent's SVID and tool name, injected as request headers only in local scope, and excluded from `ActuationReceipt`, findings, and HTTP response bodies (`test_credential_headers_not_in_audit_record`). At HEAD zero concrete `CredentialBrokerAdapter` implementations ship in `src/`, `Actuator01BindingAdapter` skips the broker step when `broker=None`, and [`BrokerActuator`](src/cage_finance/actuators/broker_actuator.py) reads `BROKER_API_KEY` from `os.environ` (reopened `POAM-2026-072` in [`docs/POAM.md`](docs/POAM.md)).
>
> **Masking is prefix-preserving, not total.** Log masking applies `value[:8] + "****"`.
> For an `Authorization: Bearer <token>` header only the scheme survives, but a broker
> that returns a bare-token header will leak the first 8 characters of the secret into
> logs. Brokers should return scheme-prefixed header values.

## Prohibited Security Anti-Patterns

The following patterns are strictly forbidden in production code and will be rejected in review:

### 1. Hardcoded Cryptographic Secrets (CWE-798)
- **PROHIBITED:** `secret = os.environ.get("API_KEY", "default-secret")`
- **REQUIRED:** Fail-closed validation asserting `os.environ["API_KEY"]` exists and meets minimum entropy length (>= 32 chars).

### 2. Shell Injection Vectors (CWE-78)
- **PROHIBITED:** `subprocess.run(command, shell=True)`
- **REQUIRED:** `subprocess.run(shlex.split(command))` with direct argument lists.

### 3. TLS/SSL Verification Bypass (CWE-295)
- **PROHIBITED:** `requests.get(url, verify=False)`
- **REQUIRED:** Explicit TLS certificate verification (`verify=True`).

### 4. Insecure Deserialization (CWE-502)
- **PROHIBITED:** `pickle.loads(data)` or unconstrained `yaml.load(data)`
- **REQUIRED:** `json.loads(data)` or `yaml.safe_load(data)`.

## Enforcement
All prohibited patterns are enforced via static grep checks, pre-commit hooks, CI security jobs, and targeted unit regression suites in `tests/test_*_security.py`.

## Security Research Acknowledgments

The CAGE maintainers thank the following researchers for reporting security and governance boundary observations with reproducible test cases:

- **Daniel Fairbanks (`@danofairanks`)** — Boundary analyses and hardening reports across CAGE's runtime governance, provenance, and offline evaluation planes (`#379`, `#405`, `#406`, `#463`, `#464`, `#465`, `#472`, `#473`, `#511`, `#512`, `#513`, `#514`, `#516`), including trajectory `NARROW` vs. `ALLOW` metric separation, multi-turn shadow-state tier parity, `RefusalReceipt` `proof_hash` verification and DPO `chosen`-argument sanitization, offline drawback-detector, `SKILL.md` static-linter, rollout-runner symbol/HTTP bounds, fail-closed Stage 2 certification gating (`--stage0-only`), positive-lift and drawback enforcement in `run_certification_gate()`, `STPAValidator` action normalization / approval-token validation / core-rule preservation, `actuator_02` signed-receipt enforcement, FTRA `NaN`-confidence guards, FTRA registry `expires_at` enforcement, retry-safe evidence stream appends and chain-truncation detection, stage- and evidence-bound `.cer` skill-certification receipts (`cage.skill.cer.v2`), full-order routing-verdict reuse and multi-step trade plan previews, MCP send-phase retry boundaries and `ExecutionLedger` trade idempotency, and explicit end-user principal assertion boundaries.
- **`@moiznationzz`** — Reported the compliance-bridge dual-control quorum bypass via unverified `x-cage-source-principal` headers, `CAGE_ENV` default authentication bypass in `de5534ac:deployment/k8s/compliance-bridge.yaml`, and uninvoked `verify_webauthn_challenge()` in `DeferQueue.approve()` (`GHSA-529c-23c8-3m42`).
- **`@Zorta-Zenith`** — Independently reported the `x-cage-source-principal` multi-party quorum forgery and OIDC fallback gap in `src/compliance_bridge/auth.py` (`GHSA-qrg7-27x4-mq39`).
- **`@m0ssser`** — Reported the `docker-compose.yml` entrypoint override exposing `mcp_tool_server.py`'s `POST /tools/execute` (`trigger_safety_intervention`) without `WorkloadIdentityMiddleware` (`GHSA-4x3x-w2m3-8mfh`).
- **`@ArksherX`** — Reported Control Barrier Function (CBF) ground-truth balance verification and atomic reservation boundary findings (`GHSA-cmwm-295c-gjf6`, `GHSA-w7g7-wjj9-6j97`, `GHSA-w7f4-8grh-2xv8`).
- **`@uwezkhan`** — Reported the inference proxy multi-role / streaming governance bypass (`GHSA-hfqj-24cj-693g`) and `/governance/validate-action` ingress authentication boundary (`GHSA-v3h4-8458-5ww3`).
- **Dominik Blain (`@dom-omg`), Ironproof** — Reported, with step-by-step reproductions, that a normative-provider determination revoked during human review was never re-checked after approval (the EU_ECB `fria` tier did not run under POST_HITL), that `execute_trade_bounded` and case or whitespace variants of `BTC` bypassed `trade_governance.rego`, and that the FRIA payload named no caller and the provider_01 request relied on self-asserted mandate facts (`GHSA-f6xq-23f7-9grm`, POAM-2026-113). Thank you for a careful, clearly reasoned report.
- **`@kitkatt7`** — Reported and submitted remediations for partner adapter verification boundaries across `provider_06` evidence-hash binding (`GHSA-348p-gfpg-qqm9`, `#799`), `actuator_03` signed quarantine receipt enforcement (`GHSA-5438-3wwf-qvcq`, `#808`), and `provider_05` live `/v0.3/` attestation signatures (`GHSA-cxxx-6xfq-vvp4`, `#809`), as well as earlier public hardening submissions (`#517`; `#662`, consolidated into `#742`).
- **`@katesaikishore`** — Reported that non-content OpenAI-compatible response fields (`reasoning` aliases, `refusal`, `audio`, `annotations`, `logprobs`, legacy `function_call`, and raw SSE replay) bypassed governed inference proxy output governance and PII redaction (`GHSA-5c7p-g73w-v4m3`, fixed via explicit egress-allowlist response reconstruction in `#814`).
- **`@oyesanyf`** — Reported that `require_api_key()` in the governed financial advisor accepted end-user OIDC tokens on service-only routes (`GHSA-797p-rrgm-4p56`, fixed in `#813`).
