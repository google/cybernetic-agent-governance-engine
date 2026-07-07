# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |
| < 0.1.0 | ❌ No     |

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
- Injection vulnerabilities (prompt injection, SQL injection, etc.)
- Cryptographic weaknesses in the KMS signing or hash-chain implementation
- Secrets or credentials exposed in the repository

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these upstream)
- Denial-of-service attacks requiring physical access
- Social engineering attacks
- Issues in documentation only

## Security Hardening Notes

CAGE is designed for regulated financial services environments. Key security
controls are documented in:

- [`docs/architecture/GATEWAY_ARCHITECTURE.md`](docs/architecture/GATEWAY_ARCHITECTURE.md)
- [`deployment/k8s/K8S_SECURITY_HARDENING.md`](deployment/k8s/K8S_SECURITY_HARDENING.md)
- [`COMPLIANCE.md`](COMPLIANCE.md)

> **Note:** CAGE v0.1.0 has not received a NIST Authorization to Operate (ATO).
> Regulated-environment deployers must conduct their own risk assessment before
> production use.
