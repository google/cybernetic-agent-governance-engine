# Security Policy

## Supported versions

Agent Integrity is alpha software. Until a stable release exists, only the latest published prerelease receives security fixes. Users should pin an exact version and review release notes before upgrading.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting after it is enabled on the repository. If that channel is unavailable, contact the maintainer using a security contact published on the repository owner’s verified GitHub profile.

Do not include credentials, confidential source documents, production response envelopes, personal data, or live signing material. Build the smallest synthetic reproduction that demonstrates the issue.

Include:

- affected package and version;
- runtime and operating system;
- attack prerequisites;
- exact reproduction steps using synthetic data;
- expected and observed status or release behavior;
- potential confidentiality, integrity, or availability impact;
- suggested remediation, if known;
- whether the issue is already public.

## In-scope security issues

- releasing response bytes for `REVIEW`, `BLOCKED`, malformed input, or checker failure;
- response, source, or trusted decision-registry mutation not invalidating a result;
- receipt forgery within the documented alpha guarantees;
- receipt replay, expiry bypass, duplicate run-ID acceptance, or overwrite;
- canonicalization differences that produce unsafe cross-runtime behavior;
- path traversal, absolute-path access, or symlink escape;
- an envelope decision snapshot differing from the current configured registry, or declared rejected/superseded decision references passing as active;
- missing substantive-section coverage incorrectly passing;
- parser confusion involving duplicate YAML keys, aliases, tags, or ambiguous values;
- leakage of source or response content from documented CLI output;
- dependency or build-chain compromise affecting published artifacts.

## Usually out of scope

- claims that `PASS` does not prove truth, because this is an explicit non-goal;
- decision dependencies omitted from a claim's declared `decisionIds` without a trusted host observation;
- cross-run registry truncation or rewriting by an actor trusted to control registry storage, because protocol `1-alpha` consults no prior authenticated checkpoint;
- an agent omitting a source from an envelope without a host collector;
- a malicious application intentionally bypassing an in-process library;
- denial of service requiring unbounded attacker-controlled local input unless a supported deployment exposes that input;
- vulnerabilities only in unsupported runtimes;
- social engineering, spam, or automated scanner reports without a reproduction.

## Safe research rules

- Use synthetic fixtures and accounts you control.
- Do not access other users’ data.
- Do not degrade services or publish exploit details before remediation.
- Stop if testing exposes confidential information.
- Give maintainers reasonable time to investigate and release a fix.

## Response process

Maintainers will acknowledge a complete report, reproduce it, assess affected versions, and coordinate remediation and disclosure. Timelines depend on severity and reproducibility. A fix may include tests, protocol clarification, documentation changes, and a patched release.

## Alpha receipt warning

Receipt `2-alpha` authenticates a configured producer with Ed25519, requires canonical base64 encoding of an exact 64-byte signature, protects the algorithm and key ID in the signed payload, checks explicit trust bindings, and supports atomic single-use consumption in one protected local filesystem registry. It does not provide a distributed registry, secure key custody, or trust-root distribution. A valid signature authenticates the configured key, not the truth of the response.

Read [Threat Model](docs/THREAT_MODEL.md) and [Limitations](docs/LIMITATIONS.md) before evaluating impact.
