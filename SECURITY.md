# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.1.x   | ✅ Yes    |
| 3.0.x   | ⚠️ Critical fixes only |
| 2.1.x   | ⚠️ Critical fixes only |
| < 2.1.0 | ❌ No     |

## Resolved Security Advisories

The following advisories were identified and remediated prior to their
respective releases. Documented here for transparency.

| Advisory | CVSS | Component | Description | Status |
|----------|------|-----------|-------------|--------|
| GHSA-hfqj-24cj-693g | 9.4 Critical | `inference_proxy` | Governance bypass: crafted requests with no `role: "user"` message, or `stream: true` responses, could reach the LLM backend without passing input/output governance tiers (reported by `@uwezkhan`) | ✅ Fixed — input governance now applied to all message roles; output filtering applied to all response paths including streaming |
| GHSA-529c-23c8-3m42 / GHSA-qrg7-27x4-mq39 | 8.6 High | `compliance_bridge` / `defer_queue` | Dual-control quorum bypass via unverified `x-cage-source-principal` header in `require_operator_identity`, `CAGE_ENV="development"` default in `require_internal_token` / K8s manifest, and uninvoked `verify_webauthn_challenge()` in `DeferQueue.approve()` (independently reported by `@moiznationzz` and `@Zorta-Zenith`) | ✅ Fixed — `x-cage-source-principal` removed; operator SVID bound strictly to Linkerd proxy-verified `l5d-client-id` (or transport `request.attributes.source.principal`) with optional `CAGE_TRUSTED_OPERATOR_IDENTITIES` allowlist; `require_internal_token` defaults to fail-closed `"production"` and requires dual-condition opt-in (`CAGE_ALLOW_DEV_UNAUTHENTICATED=true`) in dev; `verify_webauthn_challenge()` enforced in `DeferQueue.approve()` |
| GHSA-4x3x-w2m3-8mfh | 7.5 High | `mcp_tool_server` / `docker-compose.yml` | Unauthenticated `trigger_safety_intervention` execution via `POST /tools/execute` when `docker-compose.yml` overrode the gateway entrypoint to `mcp_tool_server.py` (bypassing `hybrid_server.py`'s `WorkloadIdentityMiddleware`), setting a permanent Redis `safety_violation` lock (reported by `@m0ssser`) | ✅ Fixed — `docker-compose.yml` and `docker-compose.dev.yml` invoke `hybrid_server.py` with `127.0.0.1` host port binding; `mcp_tool_server.py` enforces Linkerd workload identity on `/tools/execute` and standalone `__main__`; `trigger_safety_intervention` sets bounded TTL (`CAGE_SAFETY_INTERVENTION_TTL_SECONDS`) |
| GHSA-cmwm-295c-gjf6 / GHSA-w7g7-wjj9-6j97 | 7.5 High | `cbf` | Reconciled/KMS-signed balance (`verified_balance_payload`) disconnected from `atomic_verify_and_commit()`, allowing Lua commit against raw `balance` key (reported by `@ArksherX`) | ✅ Fixed (ADR-010) — `_resolve_ground_truth_balance()` verifies KMS signature and syncs verified balance before Lua commit |
| GHSA-w7f4-8grh-2xv8 | 6.5 Medium | `governor` / `cbf` | Auto-approved trade path called stateless `cbf.evaluate()` without atomic Redis deduction (`atomic_verify_and_commit()`), enabling concurrent TOCTOU balance bypass (reported by `@ArksherX`) | ✅ Fixed — Phase-2 `commit_barrier` executes `atomic_verify_and_commit()` on the single committing run inside `SymbolicGovernor.govern()` |
| GHSA-v3h4-8458-5ww3 | 6.5 Medium | `governance_middleware` | Unauthenticated `POST /governance/validate-action` endpoint; undermined NIST IA-3/AC-3 control assertions (reported by `@uwezkhan`) | ✅ Fixed — callers must present a trusted Linkerd mTLS workload identity before any processing ([`WorkloadIdentityMiddleware`](src/gateway/server/workload_identity.py); POAM-2026-080 replaced the original HMAC routing-seal check); rate limiting added |
| GHSA-w39v-5v7h-fxg9 | 5.3 Medium | `execute_trade_action` / governed trader | Model-controlled `trader_role` raised OPA fiscal limits on the committing trade path: the role and `trader_id` were agent-facing tool arguments that reached [`trade_governance.rego`](src/cage_finance/opa/trade_governance.rego) unchanged, so a prompt-injected `senior` lifted the unreviewed limit from $5,000 to $500,000 (found during maintainer triage) | ✅ Fixed — role and trader bound server-side from the verified workload identity; removed from the tool schema; model-supplied deferred_id stripped |
| CAGE-AUDIT-B3 | 7.5 High | `attestation_provider` | Attestation Failure Attributability: Attestations lacked structural attribution, allowing misbehaving external providers to crash the aggregator silently and fail open or obscure the source. | ✅ Fixed (POAM-2026-072) — `provider_name` and `fetch_error` attribution added. Ed25519 CER signature verification added for fail-closed security enforcement. |
| CAGE-AUDIT-B2 | 7.5 High | `routing_seal` | Evidence sufficiency gap: un-bound seals could authorize execution without verifiable cryptographic link to durable audit record | ✅ Fixed — HMAC Routing Seal v2 embeds SHA-256 `record_hash` in 4-tuple token; binding is required by default in every posture (`CAGE_REQUIRE_EVIDENCE_BINDING=false` is honoured only outside production), and consumption checks the seal's `record_hash` against an issuance-time evidence index |
| CAGE-AUDIT-P0 | 7.8 High | `cbf` | Replication split-brain double-spend: async Redis failover could expose stale balance | ✅ Fixed — `_sync_to_replicas()` via `WAIT` with automatic fail-closed rollback (`rollback_state()`) on replica timeout in production |
| [#511](https://github.com/google/cybernetic-agent-governance-engine/issues/511) | — | `evidence stream` | Duplicate evidence records after a lost Redis reply (the re-sent compare-and-append re-sealed its own batch at the next sequence), and silent re-genesis of the chain after the stream was truncated or emptied (reported by `@danofairanks`) | ✅ Fixed — a re-sent batch answers `ALREADY`, a `CONFLICT` checks whether the batch already landed, and an unanswered append is re-sent verbatim, never re-sealed; restore verifies the head hash and raises `EvidenceChainCorruptError` instead of starting over under a live chain; the custodian records a chain rotation as a `CHAIN_ROTATION` gap |
| [#514](https://github.com/google/cybernetic-agent-governance-engine/issues/514) | — | `mcp_client` / `execute_trade_action` | MCP tool calls were blindly retried after an unknown outcome, and a retried trade was a second, fully governed execution (reported by `@danofairanks`) | ✅ Fixed — [`GatewayMCPClient.call_tool()`](src/gateway/infrastructure/mcp_client.py) resends a call only when nothing was sent or the gateway annotates the tool read-only or idempotent, and otherwise raises `MCPToolOutcomeUnknownError`; [`execute_trade_action`](src/cage_finance/tools/tool_provider.py) requires a UUIDv4 or UUIDv5 `transaction_id` and claims it in the kernel [`ExecutionLedger`](src/gateway/governance/execution_idempotency.py) before governance, so a resubmission gets the first outcome back instead of executing again |

> **⚠️ Reference architecture notice:** CAGE is a reference architecture and is
> not deployed to production. These advisories are tracked for completeness and
> to ensure the codebase accurately represents the security posture claimed in
> associated research publications.

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
environments generally; the shipped example domains (finance and healthcare)
and the selectable jurisdictional postures (`US_FED`, `EU_ECB`, `APAC_MAS`,
`LOCAL`) determine which regulatory controls are in scope for a given
deployment. Key security controls are documented in:

- [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md) — full
  security posture, NIST RMF status, and all open POA&M items
- [`docs/operations/KEY_ROTATION.md`](docs/operations/KEY_ROTATION.md) — cryptographic key lifecycle and rotation runbooks (SC-12 / IA-5)
- [`docs/architecture/GATEWAY_ARCHITECTURE.md`](docs/architecture/GATEWAY_ARCHITECTURE.md)
- [`deployment/k8s/K8S_SECURITY_HARDENING.md`](deployment/k8s/K8S_SECURITY_HARDENING.md)
- [`COMPLIANCE.md`](COMPLIANCE.md)

### Implemented Controls Summary

| Control | Implementation |
|---------|---------------|
| Governance signing | Cloud KMS asymmetric signing (cloud providers in `src/integrations/{gcp,aws,azure}/kms_provider.py`, loaded via `signer_factory.py`); separate keys per role (gateway seal, reconciler snapshot, compliance-bridge evidence) with kid-resolved verification. Software Ed25519 / HMAC signers are refused under an enforcing posture and allowed only in dev/test/CI. 90-day rotation cadence per `KEY_ROTATION.md` |
| Routing seal v2 | 4-tuple token `<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` binding SHA-256 evidence record hash (KMS-signed JWT seals when a KMS signer is active); internal to `/tools/execute` and `ConsequenceGateway` — **not** used for caller authentication |
| TLS & Transport Security | NIST SP 800-52 Rev. 2 minimum TLS 1.2+ validation, OIDC JWKS `verify=True` enforcement, and Linkerd mTLS manifest policies (`tests/test_tls_enforcement.py`) |
| Base Image Hardening | Advisor, gateway, compliance-bridge and NeMo Guardrails images use two-stage builds on a digest-pinned Wolfi base (`cgr.dev/chainguard/wolfi-base`) with no compiler, util-linux or package-manager cache in the runtime stage and a build-time `apk upgrade`; images are tagged by git SHA and their digests signed for Binary Authorization at build time (`scripts/build_images.sh`) |
| Prompt injection detection | Aho-Corasick O(n) scan; 14+ patterns |
| PII protection | Presidio; 15 entity types; input + output |
| Human-in-the-loop | Redis-persisted checkpoint; TOCTOU remediation via `post_hitl_rehydrate` + `post_hitl_revalidate` (advisor calls the gateway's `POST /governance/revalidate-post-hitl`) |
| Control Barrier Function | Atomic Redis Lua (`atomic_verify_and_commit()`) with synchronous replica `WAIT` barrier, monotonic `safety:fence_epoch` with a shared high-water mark (`safety:fence_epoch_hwm`), and fail-closed state rollback |
| Evidence chain integrity | SHA-256 hash-chained NDJSON & Redis Streams db=1 (`noeviction`, Lua compare-and-append); enforced blocking durability in production (`validate_evidence_stream_preconditions()`); compliance-bridge `EvidenceCustodian` KMS batch attestation (`EVIDENCE_KMS_KEY`) to WORM storage and `CustodyVerifier` read-back verification (`kid`-resolved trust anchors, `assert_citable()` OSCAL citation gate) |
| mTLS | Linkerd mTLS with a Google CAS trust anchor (`infra/modules/service_mesh`); gateway ingress restricted by Linkerd `Server` / `HTTPRoute` / `AuthorizationPolicy`; one KSA/GSA per workload |
| Caller identity | Gateway ingress requires a Linkerd-verified `l5d-client-id` that matches `CAGE_TRUSTED_CLIENT_IDENTITIES` ([`WorkloadIdentityMiddleware`](src/gateway/server/workload_identity.py)); enforced in every environment, **no** header/body identity fallback, fail-closed 403. An RFC 9449 `DPoPValidator` (`src/gateway/server/dpop_validator.py`) ships and is unit-tested but is **not yet wired into any ingress path**. See [`docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md`](docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md) |
| Egress credentials (v3.1.0) | `CredentialBrokerAdapter` protocol in Layer 1; the Layer 3 reference actuator fetches per dispatch, keyed on agent identity and tool name, and attaches the result as request headers. Values are masked in logs and absent from the audit record; fails closed on `CredentialNotFound` / `CredentialAccessDenied` and records `ACTUATION_REFUSAL_RECEIPT` via `ingest_actuation_receipt()` |
| Egress lockdown | GKE Dataplane V2 `NetworkPolicy` + `FQDNNetworkPolicy` allowlists; DNS egress restricted to kube-dns and Cloud DNS (`deployment/k8s/cilium/egress-lockdown.yaml`) |
| Token quota enforcement | Per-session step-count (≤12) and token (≤100k) via Redis atomic Lua counters; fail-closed |

> **Note:** CAGE v3.x is a reference architecture. Regulated-environment deployers
> must conduct their own risk assessment before production use. See
> [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md) for the complete
> posture breakdown and pre-deployment checklist.

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
> advisor's service account (POAM-2026-080).

### Egress Credential Brokerage (v3.1.0)

> **Ambient-credential closure:** Outbound API credentials are no longer held by
> adapters. They are requested per dispatch from a `CredentialBrokerAdapter`, keyed on
> the calling agent's SVID and the tool name, injected as request headers at dispatch
> time, and held only in local scope. Credential values never appear in
> `ActuationReceipt`, findings, or HTTP response bodies — asserted by
> `test_credential_headers_not_in_audit_record`.
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
- **`@moiznationzz`** — Reported the compliance-bridge dual-control quorum bypass via unverified `x-cage-source-principal` headers, `CAGE_ENV` default authentication bypass in `deployment/k8s/compliance-bridge.yaml`, and uninvoked `verify_webauthn_challenge()` in `DeferQueue.approve()` (`GHSA-529c-23c8-3m42`).
- **`@Zorta-Zenith`** — Independently reported the `x-cage-source-principal` multi-party quorum forgery and OIDC fallback gap in `src/compliance_bridge/auth.py` (`GHSA-qrg7-27x4-mq39`).
- **`@m0ssser`** — Reported the `docker-compose.yml` entrypoint override exposing `mcp_tool_server.py`'s `POST /tools/execute` (`trigger_safety_intervention`) without `WorkloadIdentityMiddleware` (`GHSA-4x3x-w2m3-8mfh`).
- **`@ArksherX`** — Reported Control Barrier Function (CBF) ground-truth balance verification and atomic reservation boundary findings (`GHSA-cmwm-295c-gjf6`, `GHSA-w7g7-wjj9-6j97`, `GHSA-w7f4-8grh-2xv8`).
- **`@uwezkhan`** — Reported the inference proxy multi-role / streaming governance bypass (`GHSA-hfqj-24cj-693g`) and `/governance/validate-action` ingress authentication boundary (`GHSA-v3h4-8458-5ww3`).


