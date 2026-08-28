# Contributing to Agent Integrity

Contributions are welcome when they strengthen deterministic response integrity, improve integration ergonomics, or clarify the guarantees and limits of the project.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Protocol and compatibility changes must update the schemas, conformance fixtures, changelog, and migration guidance.

## Before opening a pull request

For bug fixes, open an issue describing the observed behavior, expected behavior, affected version, and a minimal synthetic reproduction. For security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

For protocol or public API changes, open a design issue first. Protocol changes can affect independent implementations and stored receipts, so they require compatibility notes and conformance fixtures.

## Development setup

Requirements:

- Node.js 22+
- npm 10+
- Git

```bash
git clone https://github.com/SimranPabla/agent-integrity.git
cd agent-integrity
npm ci
npm run verify
```

Replace the placeholder owner after the public repository URL is finalized.

## Change workflow

1. Create a focused branch.
2. Add a failing test or language-neutral conformance fixture for the behavior.
3. Implement the smallest compatible change.
4. Add adversarial cases for security-sensitive behavior.
5. Update the protocol, threat model, limitations, integration guide, or examples when guarantees or usage change.
6. Run all checks:

   ```bash
   npm run verify
   npm run pack:check
   npm audit --audit-level=high
   ```

7. Open a pull request explaining the failure mode, the chosen behavior, compatibility impact, and test evidence.

## Repository guide

- `packages/protocol`: shared data structures and policy parsing.
- `packages/core`: deterministic verification and receipts.
- `packages/sdk`: agent-facing envelope and release APIs.
- `packages/cli`: language-neutral command interface.
- `tests/conformance`: cross-implementation fixtures.
- `examples`: runnable synthetic integrations and failure cases.
- `docs`: architecture, protocol, integration, security assumptions, and limits.

## Tests and compatibility

All behavior changes need tests. Protocol-visible changes also need a conformance fixture with a stable expected status and finding code. Do not silently reinterpret an existing protocol version; add an explicit version or documented compatibility rule.

The verifier must remain deterministic. Do not add LLM calls, network-dependent verdicts, locale-dependent serialization, or non-reproducible time behavior to the core engine.

## Safe fixtures

Use synthetic source documents, decisions, responses, identifiers, keys, and receipts. Never submit credentials, customer data, confidential policy, proprietary documents, production envelopes, or sensitive metadata.

## Documentation style

- Start with the user outcome and a runnable command.
- State requirements and supported environments.
- Show expected output or exit behavior.
- Explain failure modes and remediation.
- Link to complete runnable examples rather than leaving fragments unexplained.
- Update limitations whenever a change might widen how users interpret `PASS`.

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
