# Provider 06 Agent Integrity Conformance Design

## Status

- Design status: approved for implementation planning
- CAGE base: `94e9d717be22bafcf6307efd9434fdb04754ac6a`
- Contribution branch: `spike/provider-06-conformance`
- Related issue: `#126`
- Experiment type: capability and compatibility

## Decision this work informs

Based on this experiment, CAGE will decide whether its existing governed-response
artifact can be represented honestly by Agent Integrity protocol `1-alpha` and
verified by the real vendored CLI without changing either production Provider 06
runtime behavior or the Agent Integrity schema.

The result selects exactly one next action:

- **Pass:** plan a second PR that separately designs CLI lifecycle, signed-receipt
  creation/authentication, and CAGE receipt preservation. This experiment alone does
  not approve that runtime integration.
- **Fail:** stop adapting the response envelope and design a separately versioned
  Action Integrity Profile.
- **Inconclusive:** stop before runtime integration until CAGE assigns trusted
  evidence collection and completeness ownership.

This PR does not prove the full envelope-to-signed-receipt-to-CAGE lifecycle. It
does not decide whether arbitrary CAGE actions are safe to execute, whether Agent
Integrity is a normative or regulatory authority, or whether the integration is
production-ready.

## Problem and current evidence

CAGE Provider 06 currently demonstrates transport and verdict translation. Its
adapter posts the caller-supplied payload to `/verify`, and its mock maps Agent
Integrity `PASS`, `REVIEW`, and `BLOCKED` results into CAGE admission behavior.
The mock validates requests with the vendored envelope schema, but it does not run
the real verifier or issue a real signed receipt.

The vendored Agent Integrity implementation is a Node.js 22 local-first
library/CLI. The `verify` command accepts `{ "envelope": ... }` on stdin and
requires separately trusted `--trusted-policy` and `--trusted-config` files. The
trusted configuration controls the project root, allowed source roots, and
decision-registry path. Verification recollects source and decision-registry bytes
from that trusted project root. Agent Integrity is not currently an HTTP service.

The unresolved uncertainty is therefore semantic compatibility, not HTTP plumbing:
can a realistic CAGE-generated response artifact, its supporting source bytes, and
its approved decisions form an honest existing Agent Integrity envelope?

## Hypothesis and thresholds

### Hypothesis

A self-contained CAGE fixture project can represent one realistic governed response
with the unchanged Agent Integrity `1-alpha` envelope and produce deterministic
`PASS`, `REVIEW`, and `BLOCKED` results through the real vendored CLI. Mutating the
response or source, removing a source, or supplying invalid trusted configuration
will fail closed.

### Primary metric

The primary metric is the number of required conformance scenarios whose actual
CLI exit code and status match the frozen expected result, divided by seven required
scenarios.

Required scenarios:

1. valid fixture -> exit `0`, `PASS`;
2. ambiguous support -> exit `2`, `REVIEW`;
3. blocked decision/evidence condition -> exit `3`, `BLOCKED`;
4. response mutation -> non-PASS;
5. source mutation -> non-PASS;
6. missing source -> non-PASS;
7. invalid trusted configuration -> CLI error or non-PASS.

### Guardrails

- Agent Integrity envelope and receipt schemas remain byte-identical.
- `src/integrations/provider_06/adapter.py` and `mock_endpoint.py` remain unchanged.
- No domain-plugin protocol or `cage.plugins` entry point is introduced.
- No network service, authentication, deployment, or runtime dispatch is added.
- Fixture output contains no private keys, credentials, or private data.
- CAGE-only `amount`, `symbol`, `magnitude`, and `context` keys do not leak into the
  canonical Agent Integrity envelope.

### Verdict thresholds

- **Pass:** all seven scenarios match expected exit/status behavior, both schemas
  remain byte-identical, and the fixture represents the artifact without semantic
  distortion.
- **Fail:** any required CAGE meaning can only be represented by misusing an
  existing envelope field or changing the public schema.
- **Inconclusive:** the envelope is structurally valid but CAGE cannot identify a
  trusted owner for the source set, decision snapshot, or evidence-completeness
  assertion.

## Ownership and trust boundary

### CAGE owns

- selecting the governed response artifact;
- freezing the exact response bytes before verification;
- selecting approved source and decision-registry bytes;
- building the canonical envelope;
- defining the evidence set and asserting its completeness;
- invoking the verifier and interpreting its documented exit/status contract;
- releasing only the exact bytes that received `PASS` in a later runtime PR.

### Agent Integrity owns

- envelope and receipt protocol schemas;
- trusted-policy parsing;
- trusted-config interpretation;
- recollection of source and decision-registry bytes;
- deterministic claim/evidence/decision verification;
- `PASS`, `REVIEW`, and `BLOCKED` semantics;
- signed receipt behavior when receipt creation is invoked. Receipt creation and
  authentication are not exercised by this verification-only experiment.

### Provider 06 owns

In this PR, Provider 06 owns no new production behavior. The conformance harness
documents a candidate boundary beside the integration and invokes the vendored CLI
as a test process. Existing HTTP spike behavior is not modified.

### The model or incoming action payload must not control

- trusted policy;
- project root or allowed roots;
- decision-registry path;
- source selection or evidence-completeness assertion;
- signing keys or receipt storage;
- expected verdict.

## Verified artifact

The fixture verifies a CAGE-generated response or governance explanation, not the
permission to execute an arbitrary tool action. `response.content` is the exact
UTF-8 artifact under verification. Its sections use byte offsets and SHA-256
digests defined by Agent Integrity.

CAGE transaction fields such as `magnitude` and `context` may influence how CAGE
generates the response, but they are not Agent Integrity protocol fields and must
not appear in the canonical envelope unless represented as ordinary response bytes
or approved source bytes with truthful claims and evidence.

## Fixture project

Add a self-contained project root under
`tests/integrations/provider_06/fixtures/project/` containing:

- `docs/source.md`: approved source bytes;
- `integrity/decisions.yaml`: trusted decision-registry bytes;
- `integrity/policy.yaml`: trusted verification policy;
- `integrity/trusted-config.json`: trusted host paths relative to the fixture root;
- `request-pass.json`: `{ "envelope": ... }` for the valid case;
- `request-review.json`: an envelope that truthfully produces `REVIEW`;
- `request-blocked.json`: an envelope that truthfully produces `BLOCKED`.

The committed fixture must be deterministic. Tests may copy it to a temporary
directory before mutation so committed bytes never change during a test run.

## Harness

Add a Python test helper under `tests/support/` with one responsibility: invoke the
vendored Agent Integrity CLI with bounded subprocess behavior.

The helper will:

1. locate the CAGE repository and vendored Agent Integrity checkout;
2. require Node.js 22 or newer;
3. build the vendored CLI once per pytest session through the locked npm workflow,
   with bounded execution, so a clean clone does not depend on ignored `dist/` files;
4. invoke `node packages/cli/dist/cli.js verify`;
5. pass envelope JSON over stdin;
6. pass trusted policy and trusted config as explicit file paths;
7. enforce a bounded timeout;
8. capture stdout, stderr, and exit code;
9. cap captured stdout and stderr, parse exactly one JSON object with optional
   surrounding whitespace, and reject trailing non-whitespace content;
10. return a closed Python result object to tests.

The helper must not start an HTTP server, inspect external credentials, or translate
Agent Integrity verdicts into new semantics.

## Test flow

Each test copies the fixture project to a temporary directory and, when needed,
updates only the copied bytes and their explicitly intended envelope fields.

- The PASS case proves the unchanged fixture verifies.
- The REVIEW and BLOCKED cases prove stable CLI exit codes and status vocabulary.
- Response mutation changes `response.content` without changing its section digest.
- Source mutation changes trusted source bytes without changing the envelope digest.
- Missing-source removes a referenced trusted file.
- Invalid-config changes the temporary trusted configuration to an invalid or
  disallowed project boundary.
- Protected-file tests compare bytes directly with the fixed base commit rather than
  trusting editable constants in the new tests.
- Boundary tests inspect the full branch diff and repository plugin registrations,
  not only the Provider 06 directory, and prove that no domain-plugin protocol or
  `cage.plugins` entry point was introduced.

The test suite writes a bounded machine-readable JSON evidence artifact containing
the exact observed exit codes, statuses, and finding codes. The prose result
document is derived from that artifact and checked against it. Neither artifact
converts a passing capability experiment into a production-readiness claim.

## Failure behavior

The harness treats malformed stdout, timeout, process failure, unsupported runtime,
or missing build artifacts as test failures. The real CLI's documented exit codes
are preserved:

- `0`: `PASS`;
- `2`: `REVIEW`;
- `3`: `BLOCKED`;
- `1`: malformed request, invalid command/configuration, or CLI failure.

For mutation and missing-source cases, any `PASS` is a failed conformance test.
Tests may assert a more specific status or finding only when it is stable in the
vendored Agent Integrity contract.

## Result document
 
Add `docs/partners/provider_06/CONFORMANCE_RESULT.md` during
implementation. It must report:
 
- CAGE and Agent Integrity commit/package versions;
- commands executed;
- all required scenarios, actual exit codes, statuses, and finding codes;
- schema hashes before and after;
- pass/fail/inconclusive verdict;
- limitations and unsupported claims;
- the predetermined next action.
 
Add `tests/integrations/provider_06/artifacts/provider_06_agent_integrity_conformance_result.json` as the
machine-generated evidence source for the scenario table. It contains no response
or source bytes.

## Explicitly out of scope

- modifying Provider 06 runtime code;
- changing the Agent Integrity schema or verifier;
- building an envelope mapper for arbitrary `action_context` payloads;
- approving or executing CAGE actions;
- adding a public or private HTTP service;
- changing `/verify` or `/receipt` behavior;
- creating, authenticating, or preserving a signed receipt;
- adding authentication, mTLS, Kubernetes, persistent receipt storage, or replay
  infrastructure;
- claiming production readiness, legal correctness, commercial validation, or
  general action integrity.

## Limitations

This experiment uses one intentionally frozen fixture family. It establishes
verification capability and envelope compatibility only. It cannot prove the full
signed-receipt lifecycle, evidence completeness in live CAGE runs, realistic
operational latency, production reliability, user demand, or that the current
response envelope should be reused for pre-execution actions.
