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
| GHSA-hfqj-24cj-693g | 9.4 Critical | `inference_proxy` | Governance bypass: crafted requests with no `role: "user"` message, or `stream: true` responses, could reach the LLM backend without passing input/output governance tiers | ✅ Fixed — input governance now applied to all message roles; output filtering applied to all response paths including streaming |
| GHSA-v3h4-8458-5ww3 | 6.5 Medium | `governance_middleware` | Unauthenticated `POST /governance/validate-action` endpoint; undermined NIST IA-3/AC-3 control assertions | ✅ Fixed — routing seal enforcement (`enforce_routing_seal()`) now required before any processing; rate limiting added |
| CAGE-AUDIT-B3 | 7.5 High | `attestation_provider` | Attestation Failure Attributability: Attestations lacked structural attribution, allowing misbehaving external providers to crash the aggregator silently and fail open or obscure the source. | ✅ Fixed (POAM-2026-072) — `provider_name` and `fetch_error` attribution added. Ed25519 CER signature verification added for fail-closed security enforcement. |
| CAGE-AUDIT-B2 | 7.5 High | `routing_seal` | Evidence sufficiency gap: un-bound seals could authorize execution without verifiable cryptographic link to durable audit record | ✅ Fixed — HMAC Routing Seal v2 embeds SHA-256 `record_hash` in 4-tuple token; actuators fail closed when `CAGE_REQUIRE_EVIDENCE_BINDING=true` |
| CAGE-AUDIT-P0 | 7.8 High | `cbf` | Replication split-brain double-spend: async Redis failover could expose stale balance | ✅ Fixed — `_sync_to_replicas()` via `WAIT` with automatic fail-closed rollback (`rollback_state()`) on replica timeout in production |

> **⚠️ Reference architecture notice:** CAGE is a reference architecture and is
> not deployed to production. These advisories are tracked for completeness and
> to ensure the codebase accurately represents the security posture claimed in
> associated research publications.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability, please use the GitHub Security Advisory
["Report a Vulnerability"](https://github.com/google/cybernetic-governance-engine/security/advisories/new)
feature.

Alternatively, you may email the maintainers directly. Please include:

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
- Cryptographic weaknesses in the Cloud KMS signing, HMAC-SHA256 fallback, or
  SHA-256 hash-chain implementation
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
| Governance signing | Cloud KMS HSM-backed asymmetric signing; HMAC-SHA256 fallback in dev/CI; 90-day rotation cadence per `KEY_ROTATION.md` |
| Routing seal v2 | 4-tuple token `<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` binding SHA-256 evidence record hash; 30-day secret rotation cadence |
| TLS & Transport Security | NIST SP 800-52 Rev. 2 minimum TLS 1.2+ validation, OIDC JWKS `verify=True` enforcement, and Linkerd mTLS manifest policies (`tests/test_tls_enforcement.py`) |
| Base Image Hardening | Container images standardized on `python:3.12-slim-bookworm` with build-time security upgrade layers and pinned third-party tags |
| Prompt injection detection | Aho-Corasick O(n) scan; 14+ patterns |
| PII protection | Presidio; 15 entity types; input + output |
| Human-in-the-loop | Redis-persisted checkpoint; TOCTOU remediation via `post_hitl_rehydrate` + `post_hitl_revalidate` |
| Control Barrier Function | Atomic Redis Lua (`atomic_verify_and_commit()`) with synchronous replica `WAIT` barrier, monotonic `safety:fence_epoch`, and fail-closed state rollback |
| Evidence chain integrity | SHA-256 hash-chained NDJSON & Redis Streams db=1; enforced blocking durability in production (`validate_evidence_stream_preconditions()`) |
| mTLS | Linkerd SPIFFE/SVID; gateway↔OPA, gateway↔NeMo; ServiceAccounts annotated with compliance metadata (`POAM-007,POAM-011`) |
| Agent identity (v3.1.0) | SPIFFE SVID extracted from the verified mTLS client certificate SAN (`spiffe_extractor.py`); **no** header or body identity path, **no** anonymous fallback; fail-closed 401 `authentication_required` on both HTTP and ext_authz/gRPC ingress. An RFC 9449 `DPoPValidator` ships and is unit-tested but is **not yet wired into any ingress path**. See [`docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md`](docs/architecture/AGENT_IDENTITY_BINDING_SPEC.md) |
| Egress credentials (v3.1.0) | `CredentialBrokerAdapter` protocol in Layer 1; the Layer 3 reference actuator fetches per dispatch, keyed on agent SVID and tool name, and attaches the result as request headers. Values are masked in logs and absent from the audit record; fails closed on `CredentialNotFound` / `CredentialAccessDenied` |
| Egress lockdown | Cilium L7 FQDN allowlist |
| Token quota enforcement | Per-session step-count (≤12) and token (≤100k) via Redis atomic Lua counters; fail-closed |

> **Note:** CAGE v3.x is a reference architecture. Regulated-environment deployers
> must conduct their own risk assessment before production use. See
> [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md) for the complete
> posture breakdown and pre-deployment checklist.

### KMS Cryptographic Signing Security

> **Replay-attack closure:** KMS-signed reconciliation payloads embed a `signed_at` Unix timestamp. The verifier (`KmsSigner.verify()`) rejects any payload where `now - signed_at > 300 s` (`MAX_KMS_PAYLOAD_AGE_SECONDS`).

### Redis / Data-Layer Security

> **Strict Replication & Fence Epoch Hardening:** In production (`CAGE_ENV=prod`), `ControlBarrierFunction` asserts synchronous replica replication (`CAGE_STRICT_REPLICATION=true`). If replica synchronization fails during `WAIT`, the local balance debit is automatically rolled back (`rollback_state(cost)`) and fails closed. Monotonic `safety:fence_epoch` counters prevent stale-replica balance replays.

### Evidence Stream Precondition Hardening

> **Audit Durability Guarantee:** `validate_evidence_stream_preconditions()` halts startup in production if `EVIDENCE_CHAIN_BLOCKING=false`, ensuring no routing seal is issued without durable evidence commitment to the tamper-evident log.

### Zero-Trust Agent Identity (v3.1.0)

> **Header-spoofing closure:** Agent identity is no longer read from application-layer
> data. `X-Agent-ID` / `X-SPIFFE-ID` headers and body-supplied `agent_id` fields are
> ignored; the sole source of truth is the SPIFFE URI SAN of the verified mTLS client
> certificate. Because every downstream governance tier keys off `agent_id`, a forgeable
> identity previously undermined tier selection, quota accounting, and A2A authorization
> simultaneously. Unauthenticated requests now fail closed with 401 on both ingress paths rather
> than falling back to an anonymous principal.

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
