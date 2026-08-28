# Architecture

Agent Integrity separates agent-authored material from the deterministic component that decides whether an exact response may be released.

## Design goals

The architecture is designed to provide:

- deterministic results from identical inputs;
- complete-response binding rather than spot-checking selected claims;
- explicit decision lifecycle handling;
- a versioned JSON interchange format that other languages can implement experimentally;
- local-first verification without an LLM or hosted service;
- fail-closed behavior when input or checker state is invalid;
- integration with an agent without requiring a human-written manifest per run.

It is not an action-control framework, a truth oracle, or an autonomous fact checker.

## Components

### Protocol

`packages/protocol` defines the structures exchanged between agents, collectors, the verifier, and receipt stores. It also parses the one-time project policy using a restricted YAML subset.

The published envelope schema mirrors runtime structural rules where JSON Schema can express them, including role-dependent evidence metadata. The runtime response limit is measured in UTF-8 bytes; JSON Schema string lengths count Unicode characters, so the schema documents but does not attempt to encode that byte limit.

The protocol contains:

- source records with exact content digests;
- decision lifecycle events;
- response sections and exact response bytes;
- claims and claim types;
- evidence items and evidence roles;
- findings and outcomes;
- verification receipts and recheck requests.

The JSON protocol is the compatibility boundary. Other languages do not need to reproduce the TypeScript SDK; they can construct valid JSON and call the CLI.

### Core

`packages/core` is the independent deterministic engine. It:

- canonicalizes supported JSON values;
- calculates SHA-256 digests;
- structurally validates envelopes and, through `verifyTrustedEnvelope`, recollects allowed source files and validates exact bytes;
- compares the envelope policy to a normalized policy loaded independently by the trusted host;
- loads the current configured decision registry from the trusted project root, binds its exact YAML digest, requires the envelope snapshot to match, and rebuilds active, rejected, and superseded state for declared references;
- checks complete, ordered UTF-8 byte coverage, section digests, and claim coverage for every section;
- checks supporting, contradictory, and contextual evidence roles;
- calculates `PASS`, `REVIEW`, or `BLOCKED`;
- creates local create-once alpha receipt files after trusted source verification;
- rechecks envelope digests, expiry, recorded outcomes, and freshly recollected declared sources;
- refuses existing receipt paths and run-ID markers in the configured local store.

The core does not call a model or assign semantic truth scores. If a conclusion needs semantic judgment, the policy should route it to `REVIEW`.

### SDK

`packages/sdk` provides agent-facing helpers. `AgentIntegritySession` constructs a complete envelope incrementally while the agent runs. `releaseVerifiedResponse` requires a trusted project root and allowed roots, recollects every source, verifies that the supplied envelope still matches the checked result, and returns response bytes only for an unchanged `PASS`.

The SDK reduces integration mistakes, but it is not the trust boundary. The core verifier remains authoritative.

### CLI

`packages/cli` exposes the core through JSON stdin/stdout. This supports Python, Go, Rust, shell scripts, workflow engines, and framework adapters without duplicating verification logic.

The CLI deliberately avoids echoing source and response content. Integrators should still treat request files and receipts as potentially sensitive metadata.

## Verification flow

```text
Project owner configures policy and approved decision registry
                         |
                         v
Agent reads sources and drafts an exact response
                         |
                         v
Agent/collector creates claims, evidence records, and source hashes
                         |
                         v
SDK builds one complete canonical envelope
                         |
                         v
Core validates structure, policy, live sources, trusted decision registry, referenced active decisions, coverage, and evidence
                         |
             +-----------+-----------+
             |           |           |
           PASS        REVIEW      BLOCKED
             |           |           |
  exact response       held for      held with
  may be released      a human       findings
```

Before release, the SDK rechecks the bound envelope. If any byte or bound field changed, nothing is released.

## Trust boundaries

The agent may propose claims and evidence mappings. It cannot set the outcome. The deterministic core calculates the outcome from the full envelope and policy.

Decision checks cover declared `decisionIds` and event history inside the current registry snapshot. The core does not infer omitted semantic dependencies or compare the registry with a prior-run checkpoint. Cross-run append-only preservation belongs to trusted host storage.

For higher assurance, source observation should be collected independently of the model—for example, in the retrieval layer, tool middleware, or application host. If the model alone reports which sources it read, it can omit a source from the envelope. See [Limitations](LIMITATIONS.md).

The application host is responsible for ensuring users only receive `release.response`, never the pre-verification draft. Logging and streaming need the same discipline: do not stream unverified response bytes to the user and then attempt to retract them.

## Determinism and canonicalization

All bound structures are converted to canonical JSON before hashing. Object key order does not affect the digest; array order does. Unsupported JSON values, duplicate YAML keys, YAML aliases, unsafe tags, invalid paths, and malformed structures are rejected.

Sources are hashed from exact bytes. Trusted verification requires the host's project root and an allowed-root list that exactly matches policy. It resolves and opens each source, compares normalized path, size, and SHA-256, and checks each evidence anchor against the actual source bytes. Absolute paths, traversal, and symlink escapes are rejected.

The collector uses `O_NOFOLLOW` for the final path when the platform exposes it and compares file identity and timestamps before and after reading. Portable Node.js APIs cannot make traversal through every parent directory descriptor-relative, so the source tree must not be writable by an attacker during collection. Platforms without `O_NOFOLLOW` provide weaker race resistance; see [Limitations](LIMITATIONS.md#filesystem-races-and-platform-limits).

## Failure behavior

Known ambiguity becomes `REVIEW`. Definite rule violations become `BLOCKED`. Invalid input and checker failures fail closed and release no response.

Findings are machine-readable and should be surfaced to the agent developer or a human reviewer. Applications should never convert `REVIEW`, `BLOCKED`, or exceptions into a successful release.

## Deployment patterns

### In-process TypeScript

Use the SDK and core packages in the same Node.js process as the agent host. This has the lowest integration overhead.

### Sidecar CLI

Run the CLI as a child process and exchange JSON over stdin/stdout. This isolates the verifier from a Python, Go, or other host and preserves a single implementation of the rules.

### Service boundary

A future deployment can wrap the CLI/core in a service, but authentication, transport security, tenant isolation, and secure receipt storage are outside the alpha implementation. Local-first use is the supported pattern.

## Extending the system

Add integrations outside the core. Provider adapters should translate framework events into protocol records; they should not alter verdict semantics. Any new language implementation should run the conformance fixtures and reproduce canonical digests, statuses, and finding codes.
