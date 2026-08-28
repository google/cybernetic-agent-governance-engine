# Security Repair Implementation Plan

> **For agentic workers:** Implement each task test-first. Do not publish the repository. Commit each independently passing slice.

**Goal:** Close all release-blocking adversarial findings and align every public claim with tested behavior.

**Architecture:** Introduce a strict `2-alpha` protocol and trusted verification context. Keep pure structural verification separate from filesystem/registry collection, then expose only the trusted orchestration path through the SDK and CLI. Replace unsigned self-digest receipts with Ed25519-authenticated, audience-bound, single-use records.

**Tech stack:** TypeScript 5.8, Node.js 22, Vitest, YAML, Node crypto and filesystem APIs.

---

## Chunk 1: Safe input and response coverage

### Task 1: Canonical JSON and resource limits

**Files:** `packages/core/src/canonical-json.ts`, `packages/core/tests/canonical-json.test.ts`

- [ ] Add failing collision and hostile-shape tests.
- [ ] Reject non-plain objects, accessors, dangerous keys, excessive depth, and oversized values.
- [ ] Implement collision-free deterministic canonicalization.
- [ ] Run core tests, typecheck, and commit.

### Task 2: Strict versioned runtime schemas

**Files:** `packages/protocol/src/types.ts`, `packages/protocol/src/schema.ts`, `packages/protocol/tests/schema.test.ts`, all callers

- [ ] Add failing tests for missing, unknown, mistyped, and oversized fields.
- [ ] Define exact validators for policy, envelope, decision registry, result, and receipt objects.
- [ ] Route SDK, CLI, and core entry points through validators.
- [ ] Run all tests and commit.

### Task 3: Complete response-byte coverage

**Files:** protocol types/schema, `packages/core/src/claims/coverage.ts`, verification tests and fixtures

- [x] Add failing tests for zero sections, gaps, overlaps, wrong digests, trailing prose, invalid UTF-8 boundaries, and unclaimed sections.
- [x] Add section byte ranges and exact-byte digests.
- [x] Enforce complete non-overlapping coverage and claim coverage.
- [x] Migrate fixtures/examples, run all tests, and commit.

## Chunk 2: Trusted evidence and decisions

### Task 4: Trusted source recollection and evidence anchors

**Files:** source collection modules, verification context/orchestrator, SDK/CLI, tests

- [x] Add failing fabricated-record and post-verification mutation tests.
- [x] Require project root and validated allowed roots in trusted verification.
- [x] Recollect every source and compare normalized path, size, and digest.
- [x] Add evidence byte anchors and validate their digest against source bytes.
- [x] Harden open/race assumptions and document remaining platform limits.
- [x] Run all tests and commit.

### Task 5: Trusted decision registry and claim binding

**Files:** protocol types/schema, decision parser/loader/reducer, verifier, examples, tests

- [x] Add failing omission, stale-reference, unrelated-history, and registry-mutation tests.
- [x] Add `decisionIds` to claims.
- [x] Strictly load the configured registry, validate append order within its current snapshot, and bind its digest. Cross-run preservation remains a trusted storage responsibility.
- [x] Require referenced decisions to be active without globally blocking unrelated historical decisions.
- [x] Run all tests and commit.

## Chunk 3: Authenticated single-use receipts

### Task 6: Signed receipt protocol

**Files:** protocol receipt types/schema, receipt create/inspect/recheck modules, CLI/SDK, tests

- [x] Add failing forgery, wrong-key, wrong-audience, wrong-purpose, future-time, long-lifetime, and engine-version tests.
- [x] Define the signed body with Ed25519 key ID, issuer, audience, purpose, nonce, engine/policy/envelope digests, and timestamps.
- [x] Verify against a trusted key set and revocation configuration.
- [x] Rename digest-only inspection fields and remove validity claims.
- [x] Run all tests and commit.

### Task 7: Atomic issuance and consumption registry

**Files:** receipt store abstraction/filesystem store, release guard, CLI, concurrency tests

- [x] Add failing duplicate, copied-receipt, concurrent-consumption, orphan-write, and restored-store tests.
- [x] Atomically issue receipt plus run/nonce state.
- [x] Atomically consume once during release/recheck.
- [x] Make partial failures recoverable and enforce safe permissions.
- [x] Run all tests and commit.

## Chunk 4: Public usability and release gate

### Task 8: Documentation and examples

**Files:** README, all docs, package READMEs, examples, JSON Schema, changelog/compatibility/security/governance files

- [x] Rewrite guarantees from tested invariants and state semantic non-goals beside `PASS`.
- [x] Add a copy-paste 15-minute tutorial and end-to-end trusted-host example.
- [x] Publish tested compatibility matrix, protocol/package matrix, migration rules, and safe baseline policy.
- [x] Expand negative examples with finding codes and safe remediation.
- [x] Add package metadata and verify every `npm pack --dry-run` payload.
- [x] Add a pre-release placeholder/private-path scanner.
- [x] Run docs/examples/package checks and commit.

### Task 9: Final audit

- [x] Run typecheck, tests, build, examples, dependency audit, secret/provenance/license scans, and clean-install package tests.
- [x] Update the offline runbook with new keys, registry, commands, recovery, and rollback.
- [x] Request a fresh independent read-only code and documentation adversarial review.
- [x] Fix confirmed findings and repeat until no release blocker remains.
- [x] Keep GitHub private until explicit publication approval.
