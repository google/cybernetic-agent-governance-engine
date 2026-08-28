# Threat Model

This document defines the security claims Agent Integrity intends to make, the actors it trusts, the attacks it handles, and the attacks outside its scope.

## Protected subject

The protected subject is an exact agent response and its declared relationship to approved sources, active decisions, policy, claims, and evidence mappings.

The primary security goal is: **an application must not release a response as verified when the deterministic rules did not pass for those exact response bytes and bound inputs.**

## Assets

- Exact response bytes approved for release
- Project policy and policy digest
- Approved source bytes and digests
- Decision lifecycle history
- Claim-to-section and claim-to-evidence mappings
- Verification outcome and finding codes
- Receipt self-digest, expiry, and local create-time uniqueness
- Confidentiality of source and response content handled by the host

## Actors and trust assumptions

### Agent

The agent is untrusted for verdict calculation. It may draft responses, propose claims, and map evidence, but it cannot set or downgrade the verifier’s outcome.

The alpha system does not assume the agent provides a complete list of everything it saw. Stronger integrations use host-observed source collection.

### Application host

The host is trusted to:

- invoke the verifier on the final response;
- keep draft response bytes away from users;
- release only bytes returned by the release guard;
- preserve policy, decision, and receipt storage integrity;
- handle `REVIEW`, `BLOCKED`, and errors without bypass;
- protect confidential envelope content.

If the host is malicious or compromised, an in-process library cannot stop it from bypassing verification.

### Human policy owner

The policy owner is trusted to approve source roots, decision rules, and outcome behavior. Agent Integrity can enforce a poor policy consistently; it cannot decide whether the policy is wise.

### Deterministic verifier

The verifier is trusted to implement the documented protocol. Unexpected verifier errors fail closed.

## Threats handled

### Missing coverage

An agent may try to leave prose outside declared sections or leave a declared section without a claim. Complete-envelope validation requires sections to partition every UTF-8 response byte exactly once and requires claim coverage for every section.

### Evidence-role confusion

An agent may cite contextual or contradictory material as if it supports a claim. Role validation prevents contextual-only evidence from satisfying a support requirement and requires contradiction handling according to policy.

### Decision revival

An agent may omit events from its envelope snapshot, alter that snapshot, or declare a reference to a rejected decision or an older decision superseded by a replacement. Trusted verification loads the current configured YAML registry, binds its exact digest, compares the complete envelope snapshot, and rejects declared unknown or non-active references. Terminal historical decisions that are not referenced do not globally block unrelated claims.

This does not establish cross-run history integrity. The verifier consults no prior digest or authenticated checkpoint, so a trusted host/storage actor that truncates or rewrites the registry and supplies a matching envelope can remove history without detection. The host is responsible for preserving the registry across runs.

The verifier also cannot discover that a claim semantically depends on a decision omitted from `decisionIds`. Completeness of declared decision dependencies remains a trusted host/integration responsibility.

### Source mutation

Approved source bytes may change between collection and verification or recheck. Trusted verification recollects every declared file and compares its normalized path, size, SHA-256, and evidence-anchor digests. Release and CLI recheck use this live path.

### Response mutation

The model, formatter, application, or attacker may change the response after verification. Complete-envelope digest binding and the release guard prevent release under the previous result.

### Receipt replay

An old receipt may be presented for a new response. Trusted recheck rejects changed or expired input and consumes an authentic receipt exactly once only when every consumer uses the same protected, shared, monotonic local filesystem store. Concurrent or later reuse is blocked inside that store. Restoring older store state can reopen replay, and the local store does not provide distributed or multi-host replay protection.

An agent may also weaken the policy embedded in its envelope. Trusted verification rejects this by comparing the embedded policy with a normalized policy loaded independently by the host. If the host itself loads policy from attacker-controlled input, that trust boundary is already lost.

### Receipt overwrite

An attacker may replace a receipt at the same path. Receipt writers use create-new behavior and refuse overwrite.

### Path-boundary escape

A source path may attempt traversal, absolute access, or symlink escape outside approved roots. Source resolution rejects these cases.

There is a remaining local race on parent path components because portable Node.js does not provide descriptor-relative traversal. Approved source trees are assumed not to be writable by an attacker during collection. The final component uses `O_NOFOLLOW` where supported and the collector checks file identity before and after reading.

### Malformed-input downgrade

An attacker may send malformed YAML, duplicate keys, hostile protocol structures, or unsupported versions hoping for permissive defaults. Parsers reject the input and the release path fails closed.

### Checker failure interpreted as success

An unexpected exception must never release response bytes. CLI failure uses exit code `1`; SDK errors return no released response.

## Threats only partially handled

### Omitted evidence

The engine detects a contradiction included in the envelope but not disclosed. It cannot know that an agent found another source and omitted it entirely. Host-level retrieval observation can reduce this risk but is not included as a universal collector.

### Semantic support quality

The engine verifies declared mappings and deterministic metadata. It does not understand whether prose genuinely proves a claim. Integrators should route weak or ambiguous support to `REVIEW` and may add a separate human or model-assisted review layer without treating that layer as deterministic proof.

### Host compromise

An in-process integration cannot force a malicious application to call it. Process isolation and deployment controls can make bypass harder, but they are outside the package guarantees.

### Confidentiality

The verifier is local-first and does not intentionally transmit content. It does not encrypt envelopes, receipts, swap, logs, backups, or IPC. The host must protect them.

## Out of scope

Agent Integrity does not establish:

- objective truth or source completeness;
- logical soundness or recommendation quality;
- model safety or absence of harmful content;
- code correctness or safe tool execution;
- authorization to perform actions;
- truth or semantic correctness from a valid producer signature;
- protection against a malicious operating system or compromised verifier build;
- availability under denial-of-service attacks.

## Security invariants for integrators

1. Only the verifier calculates status.
2. Only an unchanged `PASS` can release response bytes.
3. `REVIEW`, `BLOCKED`, malformed input, and errors release nothing.
4. Every response byte and section is covered.
5. Source paths remain inside approved roots.
6. Declared references to rejected and superseded decisions cannot pass as active within the current trusted snapshot.
7. Receipt creation refuses an existing path or run-ID marker; repeated consumption is prevented only through one protected, shared, monotonic local store used by every consumer, and store rollback or distributed consumers can reopen replay.
8. Trusted receipt creation and recheck recollect declared source bytes; a successful recheck consumes the receipt exactly once in its configured local store.
9. Draft content is not streamed before verification.
10. A `PASS` is never described as proof of truth.

## Recommended adversarial tests

Every production integration should test:

- one-byte response mutation;
- source mutation after collection;
- omitted substantive section;
- contextual-only evidence;
- undisclosed included contradiction;
- rejected and superseded decisions;
- duplicate decision revisions;
- absolute path, traversal, and symlink escape;
- receipt expiry, changed-envelope reuse, and repeated-use behavior;
- duplicate run identifier and overwrite attempt;
- malformed policy and unsupported protocol version;
- verifier exception and unavailable subprocess;
- accidental draft streaming or alternate response path.

Use synthetic data. Never place production secrets into test fixtures or vulnerability reports.
