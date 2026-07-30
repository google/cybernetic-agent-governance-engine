# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | ✅ Yes    |
| 2.0.x   | ⚠️ Critical fixes only |
| < 2.0.0 | ❌ No     |

## Resolved Security Advisories

The following advisories were identified and remediated prior to their
respective releases. Documented here for transparency.

| Advisory | CVSS | Component | Description | Status |
|----------|------|-----------|-------------|--------|
| GHSA-hfqj-24cj-693g | 9.4 Critical | `inference_proxy` | Governance bypass: crafted requests with no `role: "user"` message, or `stream: true` responses, could reach the LLM backend without passing input/output governance tiers | ✅ Fixed — input governance now applied to all message roles; output filtering applied to all response paths including streaming |
| GHSA-v3h4-8458-5ww3 | 6.5 Medium | `governance_middleware` | Unauthenticated `POST /governance/validate-action` endpoint; undermined NIST IA-3/AC-3 control assertions | ✅ Fixed — routing seal enforcement (`enforce_routing_seal()`) now required before any processing; rate limiting added |

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

CAGE is designed for regulated financial services environments. Key security
controls are documented in:

- [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md) — full
  security posture, NIST RMF status, and all open POA&M items
- [`docs/architecture/GATEWAY_ARCHITECTURE.md`](docs/architecture/GATEWAY_ARCHITECTURE.md)
- [`deployment/k8s/K8S_SECURITY_HARDENING.md`](deployment/k8s/K8S_SECURITY_HARDENING.md)
- [`COMPLIANCE.md`](COMPLIANCE.md)

### Implemented Controls Summary

| Control | Implementation |
|---------|---------------|
| Governance signing | Cloud KMS HSM-backed asymmetric signing; HMAC-SHA256 fallback in dev/CI |
| Prompt injection detection | Aho-Corasick O(n) scan; 14+ patterns |
| PII protection | Presidio; 15 entity types; input + output |
| Human-in-the-loop | Redis-persisted checkpoint; TOCTOU remediation via `post_hitl_rehydrate` + `post_hitl_revalidate` |
| Control Barrier Function | Redis `WATCH/MULTI/EXEC` optimistic locking; externally attested balances via Plaid Production + Cloud KMS (POAM-023 closed) |
| Audit chain integrity | SHA-256 hash-chained NDJSON; 7-year retention |
| mTLS | Linkerd SPIFFE/SVID; gateway↔OPA, gateway↔NeMo |
| Egress lockdown | Cilium L7 FQDN allowlist |
| Token quota enforcement | Per-session step-count (≤12) and token (≤100k) via Redis atomic Lua counters; fail-closed |

> **Note:** CAGE v2.1.x has not received a NIST Authorization to Operate (ATO).
> Regulated-environment deployers must conduct their own risk assessment before
> production use. See [`docs/security/SECURITY_STATUS.md`](docs/security/SECURITY_STATUS.md)
> for the complete posture breakdown and pre-deployment checklist.
