# Provider 06 Agent Integrity Conformance Result

## Result

**PASS — 7/7 required scenarios matched the frozen Agent Integrity CLI contract.**

A realistic CAGE governed-response fixture is compatible with the unchanged Agent
Integrity `1-alpha` envelope. The real vendored CLI produced deterministic `PASS`,
`REVIEW`, and `BLOCKED` outcomes, and every mutation, missing-source, and invalid
trusted-configuration scenario failed closed.

This is a verification-capability result only. It does not establish production
readiness or approve a runtime Provider 06 integration.

## Versions and commands

- CAGE base: `d069d9be85acede00d04dd887f61e5c9e2dbe1b3`
- Agent Integrity package: `0.1.0-alpha.0`
- Agent Integrity protocol: `1-alpha`
- Node.js: `v24.21.0`
- npm: `11.19.0`
- uv: `0.10.7`
- Python: `3.12.3`
- pytest: `9.1.1`

The locked vendored CLI was built with:

```text
cd third_party/agent-integrity
npm ci --ignore-scripts
npm run build
```

The machine-readable artifact additionally binds this result to the exact vendored
Agent Integrity Git tree, `package-lock.json` SHA-256, built CLI SHA-256, generator
version, fixed CAGE base, and protected-file SHA-256 values. The artifact does not
claim to embed its own final branch commit: that would be self-referential. Instead,
CI executes the committed generator and compares its complete output with the
committed artifact.

The conformance proof was run with:

```text
uv run --extra gateway pytest tests/test_provider_06_agent_integrity_conformance.py -v --no-cov -p no:langsmith -p no:langsmith_plugin
```

The `gateway` extra is required because CAGE's repository-wide autouse plugin-order
fixture imports the declared OIDC middleware dependency.

## Required scenarios

<!-- scenario:valid_fixture expected:0/PASS actual:0/PASS findings:- passed:true -->
- `valid_fixture` (`request-pass.json`): expected `0/PASS`; actual `0/PASS`; findings: none; passed.
<!-- scenario:ambiguous_support expected:2/REVIEW actual:2/REVIEW findings:claim.support_ambiguous passed:true -->
- `ambiguous_support` (`request-review.json`): expected `2/REVIEW`; actual `2/REVIEW`; findings: `claim.support_ambiguous`; passed.
<!-- scenario:blocked_decision expected:3/BLOCKED actual:3/BLOCKED findings:decision.rejected passed:true -->
- `blocked_decision` (`request-blocked.json`): expected `3/BLOCKED`; actual `3/BLOCKED`; findings: `decision.rejected`; passed.
<!-- scenario:response_mutation expected:3/BLOCKED actual:3/BLOCKED findings:checker.failure passed:true -->
- `response_mutation`: expected `3/BLOCKED`; actual `3/BLOCKED`; findings: `checker.failure`; passed.
<!-- scenario:source_mutation expected:3/BLOCKED actual:3/BLOCKED findings:source.size_mismatch,source.digest_mismatch,evidence.anchor_out_of_range passed:true -->
- `source_mutation`: expected `3/BLOCKED`; actual `3/BLOCKED`; findings: `source.size_mismatch`, `source.digest_mismatch`, `evidence.anchor_out_of_range`; passed.
<!-- scenario:missing_source expected:3/BLOCKED actual:3/BLOCKED findings:source.collection_failed passed:true -->
- `missing_source`: expected `3/BLOCKED`; actual `3/BLOCKED`; findings: `source.collection_failed`; passed.
<!-- scenario:invalid_trusted_config expected:3/BLOCKED actual:3/BLOCKED findings:trusted.context_invalid passed:true -->
- `invalid_trusted_config`: expected `3/BLOCKED`; actual `3/BLOCKED`; findings: `trusted.context_invalid`; passed.

The machine-readable source for this table is
`tests/integrations/provider_06/artifacts/provider_06_agent_integrity_conformance_result.json`. It contains
only scenario metadata, statuses, exit codes, finding codes, versions, and hashes.

## Protected boundary

The following files remain byte-identical to the fixed CAGE base. Their SHA-256
digests are recorded in the machine-readable artifact and verified against
`git show 94e9d717...:<path>` by the test suite:

- `src/integrations/provider_06/adapter.py`
- `src/integrations/provider_06/mock_endpoint.py`
- `third_party/agent-integrity/schemas/integrity-envelope.schema.json`
- `third_party/agent-integrity/schemas/integrity-receipt.schema.json`

The full branch diff and repository entry-point configuration were also checked:
this experiment introduces no Provider 06 domain-plugin implementation or
`cage.plugins` registration.

## Decision and next action

The experiment satisfies the approved **PASS** threshold: the existing envelope
honestly represents the frozen governed-response artifact, all seven required CLI
outcomes match, protected schemas and runtime files remain unchanged, and CAGE owns
the fixture evidence-completeness assertion.

The predetermined next action is a separate design/PR for CLI sidecar lifecycle,
request authentication, signed-receipt creation and verification, CAGE receipt
preservation, and exact-byte release. This result alone does not approve any of
those runtime changes.

## Limitations and unsupported claims

This experiment does not:

- verify or authorize arbitrary CAGE actions;
- modify Provider 06 runtime behavior;
- construct envelopes from live `action_context` payloads;
- create, authenticate, or preserve signed receipts;
- define an HTTP service, authentication, mTLS, deployment, or replay storage;
- prove evidence completeness in live CAGE runs;
- prove production reliability, acceptable operational latency, regulatory or
  legal correctness, commercial validation, or general action integrity.

Lifecycle scripts were disabled during the vendored clean install. The build itself
was then invoked explicitly with `npm run build`. The install requires network
access in a clean checkout. A runtime integration must separately review and accept
the vendored dependency and build-script trust boundary before production use.
