# Unified CAGE Implementation Plan — Comprehensive Analysis Report

**Scope:** Independent codebase-grounded analysis of the 3-phase "Unified CAGE Implementation Plan" (Phase 1 — Provider 01 NormativeProvider adapter; Phase 2 — Luis's kernel integration / `X-Governance-Signatures` multi-sig; Phase 3 — Terry Snyder seam remediation for fail-closed seals and `RefusalReceipt` binding). This report was produced by directly inspecting the referenced source files, the `tmp/cage-provider_01-adapter-v0.3/` fidelity-review package, and existing test coverage — not by taking the unified plan's claims at face value.

**Method note:** Every finding below is cross-referenced to a specific file/line. Where the unified plan's open questions could not be resolved purely by inspection (i.e. they require a design decision, not a fact-check), this is flagged explicitly in Section 2 and Section 10.

---

## Section 1: Executive Summary

The 3-phase unified plan bundles three substantively different classes of work under one rollout umbrella:

1. **Phase 1 (Provider 01 adapter)** is, by its own author's framing in [`tmp/cage-provider_01-adapter-v0.3/README.md`](../tmp/cage-provider_01-adapter-v0.3/README.md:1), a **fidelity-review artifact** — a bounded experiment intended to validate CAGE-facing contract fidelity, not a production integration. Treating it as "ready to copy into `src/integrations/`" understates the remaining engineering work by a wide margin (see Section 3).
2. **Phase 2 (kernel integration / `X-Governance-Signatures`)** introduces a **net-new cryptographic multi-signature mechanism** that does not exist anywhere in the current codebase, and simultaneously requires migrating three independent, non-interoperable canonicalization implementations to RFC 8785 JCS. This is a breaking cryptographic change with no existing migration scaffold (see Section 4).
3. **Phase 3 (Terry Snyder remediation)** is the most concrete and lowest-risk of the three: it targets two confirmed, narrowly-scoped defects — a fail-open seal-consumption path and an incomplete `RefusalReceipt` cryptographic binding — both of which are verifiable directly in the current source (see Section 5).

**Critical risks identified:**
- **Fail-open by default:** [`verify_and_consume_seal()`](../src/gateway/governance/routing_seal.py:575) in both the gateway and the GFA mirror silently returns `True` when Redis is unavailable (`redis_client is None`) or throws (`except Exception: logger.warning(...)`), meaning the *entire* single-use replay defense (CAGE-SEC-008) degrades to no-op under Redis outage — this is a live security gap, not a hypothetical one.
- **Cryptographic binding gap:** `standing_at_refusal` (the payload field carrying the actual denied-transaction context) is excluded from `RefusalReceipt.proof_hash` computation in [`contracts.py:47-53`](../src/gateway/governance/contracts.py:47) — the receipt cryptographically attests to *that a refusal happened* but not to *what was refused*.
- **Net-new, unscoped cryptographic surface:** `X-Governance-Signatures` and the multi-sig kernel integration have zero precedent in the codebase; [`consensus.py`](../src/gateway/governance/consensus.py:1) is LLM-critic voting (a governance decision mechanism), not a cryptographic signature scheme, and conflating the two in planning risks a design that doesn't fit CAGE's existing HMAC-based seal architecture.
- **Non-atomic canonicalization migration:** at least seven independent `json.dumps(..., sort_keys=True, separators=(",", ":"))` call sites (not one shared helper — see Section 4.3) would all need simultaneous, coordinated migration to JCS or every existing seal/signature becomes unverifiable mid-rollout.

**Recommendation: Proceed, but only after decoupling the three phases into independently gated workstreams, re-sequencing Phase 3 first (Section 6, Section 9), and resolving the open items in Section 10 before any Phase 1/Phase 2 code lands.** The unified plan's own PAUSE/DEFER/NARROW precedent in [`plans/audit_remediation_implementation_plan.md`](../plans/audit_remediation_implementation_plan.md:1) demonstrates the project's established pattern of shipping narrowly-scoped, independently-tested PRs rather than a single cross-cutting rollout — that pattern should apply here too.

---

## Section 2: Open Questions Resolution

The unified plan poses 6 open questions. Each is answered below strictly from codebase evidence; where evidence is absent, that absence is itself the finding.

### 2.1 — `X-Governance-Signatures` delimiter format

**Finding: The header does not exist anywhere in the codebase.** A repository-wide search for `X-Governance-Signatures` returns zero matches in `src/`, `tests/`, `config/`, or `deployment/`. The only comparable existing header is `X-CAGE-Routing-Seal` (per [`plans/audit_remediation_implementation_plan.md:185`](../plans/audit_remediation_implementation_plan.md:185)), which carries a single HMAC value, not a multi-signature list — there is no delimiter precedent to inherit.

**Resolution:** This is not a fact that can be "looked up" in the codebase — it is a **net-new design decision** that must be made before Phase 2 implementation starts. Recommend following the existing seal wire-format convention (`.`-delimited fields, e.g. `<expire_hex>.<action_slug>.<record_hash>.<sig>` per [`routing_seal.py:446-447`](../src/gateway/governance/routing_seal.py:446)) for consistency, with signatures comma-separated within the final field (`sig1,sig2,sig3`) to avoid colliding with the existing `.` structural delimiter. This must be specified in a design doc before coding, not decided ad hoc in a PR.

### 2.2 — RFC 8785 (JCS) test vector requirement

**Finding: No JCS implementation or dependency exists anywhere in the codebase.** A search for `jcs`, `JCS`, and `RFC 8785` in `pyproject.toml` and `src/` returns zero matches. Every canonicalization site in the codebase (see Section 4.3) uses Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, which is **not** RFC 8785-compliant (it diverges on number formatting, Unicode normalization, and does not handle `NaN`/`Infinity` per the JCS spec).

**Resolution:** If JCS is adopted (Section 4), the official [RFC 8785 test vectors](https://github.com/cyberphone/json-canonicalization) must be added as a new test fixture (`tests/fixtures/rfc8785_vectors.json` or similar) and a new `tests/test_jcs_canonicalization.py` must assert byte-exact conformance. This is **required**, not optional — the existing `json.dumps(sort_keys=True)` sites have never been validated against JCS test vectors and cannot be assumed compatible for edge cases (large integers, surrogate pairs, `-0`).

### 2.3 — 30-second TTL assertion injection method

**Finding: The 30-second TTL is a real, existing constant, not a placeholder.** Per [`routing_seal.py:585`](../src/gateway/governance/routing_seal.py:584) and its GFA mirror at [`governed_financial_advisor/utils/routing_seal.py:341`](../src/governed_financial_advisor/utils/routing_seal.py:341), the seal's expiry window ("Even within the 30-second TTL window, a seal can only be executed once") is enforced via `expire_hex` embedded in the seal string itself (`int(expire_hex, 16)`, [`routing_seal.py:612`](../src/gateway/governance/routing_seal.py:612)) and the Redis burn-key TTL is derived from it (`ttl = max(int(expire_ts - time.time()), 1)`, [`routing_seal.py:613`](../src/gateway/governance/routing_seal.py:613)).

**Resolution:** Confirmed — `generate_seal(action, params, ttl_s=_TTL_S, record_hash=None)` ([`routing_seal.py:237-242`](../src/gateway/governance/routing_seal.py:237)) already accepts `ttl_s` as a caller-overridable keyword argument, defaulting to the module constant `_TTL_S` (the 30-second default). There is **no separate "assertion injection" mechanism** — tests that need deterministic expiry behavior should simply pass a small `ttl_s` value directly (e.g. `generate_seal(action, params, ttl_s=1)`) and sleep/monkeypatch `time.time()`, rather than inventing a new injection API. This open question appears to be based on a misunderstanding that TTL is hardcoded; it is not. No new mechanism is required — only test-code usage of the existing parameter.

### 2.4 — mTLS client cert loading (app vs. sidecar)

**Finding: No mTLS client-certificate loading code exists anywhere in `src/`.** A search for `mtls`, `ssl_context`, `client_cert`, and `SSLContext` across all Python source finds only:
- Comments/docstrings describing mTLS as a **service-mesh-terminated** concern (Linkerd), e.g. [`agent_gateway_adapter.py:29`](../src/gateway/server/agent_gateway_adapter.py:28) ("mTLS certificate provisioning via GCP Workload Identity or Cloud KMS... handled at the deployment layer") and [`agent_gateway_adapter.py:1124-1126`](../src/gateway/server/agent_gateway_adapter.py:1124) ("mTLS is enforced by the service mesh or AGW — the server itself does not terminate TLS").
- A **commented-out** mTLS gRPC channel construction for Anchorage Digital in [`reconciliation_worker.py:373-401`](../src/compliance_bridge/reconciliation_worker.py:373), which reads cert/key paths from env vars (`ANCHORAGE_CLIENT_CERT_PATH`, `ANCHORAGE_CLIENT_KEY_PATH`) but is explicitly `NotImplementedError`-gated and never activated.
- All existing HTTP-based `NormativeProvider` implementations ([`Provider01`](../src/integrations/provider_01/provider.py:73), [`Provider03`](../src/integrations/provider_03/provider.py:48)) use bearer-token `Authorization` headers via plain `httpx.AsyncClient`, with **no TLS client-cert configuration at all**.

**Resolution:** The established CAGE pattern is **sidecar/service-mesh-terminated mTLS** (Linkerd), not application-level client-cert loading. If Phase 1/2 require app-level mTLS (e.g. calling an external Provider 01/Luis endpoint that isn't behind the mesh), this would be a **new pattern with no precedent** — recommend following the Anchorage reconciliation worker's commented-out design (`ssl.create_default_context()` + `load_cert_chain()`) as the template, sourcing cert/key paths from Secret-Manager-mounted files per the existing convention, rather than inventing a new loading mechanism.

### 2.5 — `protected_consequence` taxonomy mapping

**Finding: `protected_consequence` does not exist anywhere in the codebase.** Zero matches for this exact string in `src/`, `tests/`, `config/`, `docs/`, or `tmp/`. It also does not appear in the Provider 01 adapter package (`tmp/cage-provider_01-adapter-v0.3/`), which uses `FlowDecision` (`ALLOW`/`ESCALATE`/`REFUSE`, per [`models.py:10-13`](../tmp/cage-provider_01-adapter-v0.3/adapter/models.py:10)) as its outcome taxonomy instead.

**Resolution:** This term appears to originate from the unified plan's own vocabulary (possibly from Luis's kernel design docs, which are not present in this repository) rather than from any existing CAGE or Provider 01 artifact. **This cannot be resolved by codebase inspection — it requires the source document/spec that defines `protected_consequence` to be supplied**, or an explicit mapping decision made against CAGE's existing `GovernanceDecision` enum (ALLOW/DENY/DEFER/NARROW/PAUSE/REQUIRE_APPROVAL, per the audit remediation plan's Chunk 1) and/or Provider 01's `FlowDecision` enum.

### 2.6 — Provider 01 authentication env vars

**Finding: The only Provider 01-related env var in the fidelity-review package is `PROVIDER_01_BASE_URL`**, read in [`provider_01_client.py:17`](../tmp/cage-provider_01-adapter-v0.3/adapter/provider_01_client.py:17) — there is **no authentication env var at all** in the current adapter. The `Provider 01BaselineClient.assess()` method ([`provider_01_client.py:36-54`](../tmp/cage-provider_01-adapter-v0.3/adapter/provider_01_client.py:36)) makes an unauthenticated `httpx.post()` call with no `Authorization` header, no API key, and no mTLS.

**Resolution:** Compare against the existing CAGE convention for vendor-provider auth — `CAGE_NORMATIVE_API_KEY_SECRET` (bearer token, per [`normative_provider.py:94`](../src/gateway/governance/normative_provider.py:94) and [`provider_01/provider.py:62`](../src/integrations/provider_01/provider.py:62)) or `PROVIDER_03_NORMATIVE_API_KEY_SECRET` (per [`provider_03/provider.py:42`](../src/integrations/provider_03/provider.py:42)). **A new `PROVIDER_01_API_KEY_SECRET` (or similar) env var must be defined from scratch** — it does not exist today, and the adapter as currently written would ship with zero authentication if adopted unmodified.

---

## Section 3: Phase 1 Analysis — Provider 01 Adapter

### 3.1 The adapter is explicitly not production-ready

The package's own [`README.md:1-5`](../tmp/cage-provider_01-adapter-v0.3/README.md:1) states its purpose plainly: *"This package is the lightweight Python adapter Lars requested for **CAGE-side fidelity review**."* Section "Review requested from Lars" ([README.md:53-63](../tmp/cage-provider_01-adapter-v0.3/README.md:53)) asks for review of contract *fidelity* — method signatures, request/response treatment, routing-threshold modeling — explicitly **not** a request to endorse the architecture for production use. Treating this artifact as a drop-in Phase 1 deliverable misreads its intended scope.

### 3.2 Return-type incompatibility with the kernel's `NormativeProvider` contract

The adapter defines its **own local dataclasses** — `NormativeBaseline`, `ValidationResult`, `EvidenceSeal` — in [`normative_provider_adapter.py:18-35`](../tmp/cage-provider_01-adapter-v0.3/adapter/normative_provider_adapter.py:18), which are structurally similar to but **not the same classes** as the kernel's actual [`NormativeBaseline`](../src/gateway/governance/normative_provider.py:167), [`ValidationResult`](../src/gateway/governance/normative_provider.py:199), and [`EvidenceSeal`](../src/gateway/governance/normative_provider.py:216) in `src/gateway/governance/normative_provider.py`. Field shapes diverge:

| Field | Kernel `NormativeBaseline` | Adapter `NormativeBaseline` |
|---|---|---|
| `region` | ✅ | ✅ |
| `profile: dict` | ✅ (required) | ❌ absent |
| `fetched_at`, `signature`, `etag`, `error` | ✅ | ❌ absent |
| `source`, `loaded` | ❌ | ✅ (adapter-only) |

Any code calling `enforce_fria_boundary()` in the real kernel ([`normative_provider.py:414`](../src/gateway/governance/normative_provider.py:414)) expects the real dataclasses — plugging the adapter's provider in directly would either fail type checks or silently produce objects missing fields the kernel's `NormativeProviderDaemon` relies on (e.g. `.profile_hash`, `.is_valid`).

### 3.3 `fetch_baseline()` is stub-only

The adapter's `fetch_baseline()` ([`normative_provider_adapter.py:53-54`](../tmp/cage-provider_01-adapter-v0.3/adapter/normative_provider_adapter.py:53)) returns `NormativeBaseline(region=region)` unconditionally — no network call, no file read, no actual baseline content. This means `NormativeProviderDaemon.boot_fetch()` ([`normative_provider.py:611`](../src/gateway/governance/normative_provider.py:611)) would receive an empty/placeholder baseline at container startup if this provider were wired in as-is, defeating the entire "Normative Data Supply" endpoint category.

### 3.4 `submit_evidence()` does no external call

[`normative_provider_adapter.py:98-105`](../tmp/cage-provider_01-adapter-v0.3/adapter/normative_provider_adapter.py:98) computes a local SHA-256 of `f"{thread_id}:{evidence_hash}"` and returns it as the "seal" — there is no HTTP call to any Provider 01 attestation endpoint. This satisfies the method signature but not the semantic contract ("Attestation Logging... externally sealed attestation for the audit trail" per [`normative_provider.py:39-41`](../src/gateway/governance/normative_provider.py:39)); a locally-computed hash is not an external attestation.

### 3.5 Blocking sync HTTP inside an async method

`Provider 01BaselineClient.assess()` ([`provider_01_client.py:36-54`](../tmp/cage-provider_01-adapter-v0.3/adapter/provider_01_client.py:36)) uses `httpx.post(...)` (the **synchronous** client), not `httpx.AsyncClient`. It is called synchronously from `validate_fria()` ([`normative_provider_adapter.py:61`](../tmp/cage-provider_01-adapter-v0.3/adapter/normative_provider_adapter.py:61): `self.baseline.assess(ctx)`), an `async def` method. A blocking network call inside an `async def` body will stall the event loop for the duration of the HTTP round-trip — directly contradicting the kernel's async-first design where `enforce_fria_boundary()` uses `asyncio.wait_for()` with a hard timeout ([`normative_provider.py:501-505`](../src/gateway/governance/normative_provider.py:501)) to bound blocking-gate latency. A synchronous call inside the coroutine defeats that timeout's ability to actually cancel the in-flight operation.

### 3.6 No authentication or mTLS support

Confirmed in Section 2.6 — `Provider 01BaselineClient` sends unauthenticated requests. There is no API key, bearer token, or client certificate anywhere in the adapter's HTTP path.

### 3.7 `EscalationSemanticGap` is unhandled in the kernel

The adapter deliberately raises `EscalationSemanticGap` ([`normative_provider_adapter.py:14-16`](../tmp/cage-provider_01-adapter-v0.3/adapter/normative_provider_adapter.py:14)) rather than collapsing Provider 01's `ESCALATE` outcome into a boolean — a documented, intentional design choice ([README.md:41](../tmp/cage-provider_01-adapter-v0.3/README.md:41)). However, the **kernel's real** `enforce_fria_boundary()` ([`normative_provider.py:414-565`](../src/gateway/governance/normative_provider.py:414)) has **no `except EscalationSemanticGap` clause anywhere** — it only wraps the `provider.validate_fria()` call in `asyncio.wait_for(...)` and catches `asyncio.TimeoutError` ([`normative_provider.py:537`](../src/gateway/governance/normative_provider.py:537)). An uncaught `EscalationSemanticGap` would propagate as an unhandled exception through the kernel's DEFER-zone synchronous gate, crashing the governance request rather than resolving to any defined `FRIAEnforcementResult`. The adapter's own `cage_router.py` (a **separate, non-kernel model** of the routing behavior) does catch it ([`cage_router.py:67-73`](../tmp/cage-provider_01-adapter-v0.3/adapter/cage_router.py:67)) — but that file is explicitly a *model* of kernel behavior for the fidelity experiment, not the kernel itself. This is the single most important unresolved fidelity gap: **the real kernel would crash on Provider 01's `ESCALATE` outcome today.**

### 3.8 Canonicalization is not JCS

`adapter/canonical.py`'s `_digest_action()` ([`canonical.py:9-16`](../tmp/cage-provider_01-adapter-v0.3/adapter/canonical.py:9)) uses `json.dumps(material, sort_keys=True, separators=(",", ":"))` — the same non-JCS pattern used throughout the existing kernel (Section 4.3). If Phase 2's JCS migration proceeds, this adapter's canonicalization would also need updating to stay consistent, adding a third dependency chain onto the JCS rollout.

### 3.9 Required work beyond "copy directory"

Given 3.1–3.8, adopting this adapter requires substantially more than copying `tmp/cage-provider_01-adapter-v0.3/adapter/` into `src/integrations/provider_01/`:

1. **Replace local dataclasses with kernel imports** — `from src.gateway.governance.normative_provider import NormativeBaseline, ValidationResult, EvidenceSeal`, and adapt field construction to match the kernel's actual shape (`profile`, `admitted`+`findings`+`sealed_at`, `seal_hash`, etc.).
2. **Implement actual `fetch_baseline()` network call** — an HTTP `GET` to a real Provider 01 baseline endpoint, following the `Provider01.fetch_baseline()` pattern ([`provider_01/provider.py:112-131`](../src/integrations/provider_01/provider.py:112)) as the template.
3. **Convert to async HTTP client** — replace `httpx.post(...)` with `async with httpx.AsyncClient(timeout=...) as client: await client.post(...)`, matching every other provider in `src/integrations/`.
4. **Add auth/mTLS support** — define `PROVIDER_01_API_KEY_SECRET` (bearer) or a client-cert loading path (Section 2.4), following existing conventions.
5. **Register in `get_normative_provider()` factory** — add a `"provider_01"` branch to [`normative_provider.py:825-833`](../src/gateway/governance/normative_provider.py:825), lazy-importing from `src.integrations.provider_01`.
6. **Handle `ESCALATE` semantic gap in the kernel** — either (a) extend `enforce_fria_boundary()` with an `except EscalationSemanticGap` clause mapping to a defined `ExecutionStatus` (likely `DEFER` with an escalation flag, or a new status value), or (b) require the adapter to resolve `ESCALATE` into `admitted=False` with a findings entry documenting the collapse — a deliberate semantic-fidelity trade-off that must be an explicit decision, not a silent default, given the adapter author's own stated objection to collapsing this value (Section 3.7).

---

## Section 4: Phase 2 Analysis — Luis's Kernel Integration

### 4.1 `X-Governance-Signatures` header does not exist in the codebase

As established in Section 2.1, this header — and any multi-signature verification logic behind it — is entirely net-new. There is no existing middleware, decorator, or contract file referencing it. Phase 2 is not "integrating" an existing mechanism; it is **designing and building one from zero**, which materially changes its risk profile relative to how a "kernel integration" phase is normally scoped (typically wiring an existing internal primitive to a new caller).

### 4.2 `consensus.py` is LLM-critic voting, not cryptographic multi-signature

[`consensus.py`](../src/gateway/governance/consensus.py:1) implements a **governance decision mechanism**: multiple LLM "critic" personas (Risk Manager, Compliance Officer, etc.) running on heterogeneous model backends vote on a proposed action, per the module docstring's "Priority 4 (Evidentiary Independence)" section ([`consensus.py:23-39`](../src/gateway/governance/consensus.py:23)). This is a **semantic/policy consensus** mechanism (agreement about whether an action is safe), entirely distinct from a **cryptographic multi-signature scheme** (multiple independent key-holders producing verifiable signatures over the same message, as `X-Governance-Signatures` would imply). If the unified plan's authors intended to reuse or extend `consensus.py` for Phase 2's multi-sig requirement, this is a **category error** — the two mechanisms solve different problems and have incompatible trust models (LLM votes are probabilistic and unauthenticated; cryptographic signatures are deterministic and key-authenticated). Any kernel integration work must build the multi-sig verification path as new code, most naturally alongside [`routing_seal.py`](../src/gateway/governance/routing_seal.py:1)'s existing HMAC seal infrastructure, not by extending `consensus.py`.

### 4.3 Three independent, non-JCS canonicalization implementations

A repository-wide search confirms canonicalization (`json.dumps(..., sort_keys=True, ...)`) is duplicated **independently** across at least these governance-critical sites, each with its own serialization call:

| Site | Location | Separators | Notes |
|---|---|---|---|
| `RefusalReceipt`/`PauseReceipt` proof hash | [`contracts.py:54,99`](../src/gateway/governance/contracts.py:54) | `(",", ":")` | Hashes a subset of fields only (see Section 5.2) |
| Gateway routing seal | [`routing_seal.py:225-227`](../src/gateway/governance/routing_seal.py:225) | `(",", ":")` | HMAC input for seal signature |
| GFA routing seal mirror | [`governed_financial_advisor/utils/routing_seal.py`](../src/governed_financial_advisor/utils/routing_seal.py:1) | `(",", ":")` (must match gateway exactly) | Duplicated logic, not shared code — per the file's own "SYNC NOTE" referenced in [`plans/audit_remediation_implementation_plan.md:71`](../plans/audit_remediation_implementation_plan.md:71) |
| `NormativeBaseline.profile_hash` | [`normative_provider.py:195`](../src/gateway/governance/normative_provider.py:195) | `(",", ":")` | Independent of the seal HMAC path |
| Evidence chain hash-linking | [`evidence_stream.py`](../src/compliance_bridge/evidence_stream.py:566) (multiple sites, e.g. lines 566, 671, 937, 1129) | `(",", ":")` and bare `sort_keys=True` (inconsistent) | Governs the audit evidence hash chain |
| Provenance chain | [`provenance_chain.py:161`](../src/gateway/governance/provenance_chain.py:160) | `(",", ":")` | |
| KMS signer | [`kms_signer.py:53`](../src/gateway/governance/kms_signer.py:52) | `(",", ":")` | Signs governance plans for KMS |

None of these currently import from a shared `canonical.py`/`canonicalize()` helper — each site reimplements the same `json.dumps` call independently. **This is not one migration; it is at minimum seven independent migrations that must land as a single atomic change**, because any two sites that disagree on canonicalization (one JCS, one legacy) would produce different hashes/signatures for logically identical data, breaking cross-verification (e.g. gateway-issued seal vs. GFA-side verification).

### 4.4 No existing mTLS/httpx client config in the specified files

Confirmed per Section 2.4 — no client-cert-based HTTP client configuration exists in any file that a Luis-kernel integration would plausibly touch (`routing_seal.py`, `contracts.py`, `consensus.py`, `normative_provider.py`). Any mTLS requirement for Phase 2's external kernel calls is net-new infrastructure.

### 4.5 A new `src/integrations/luis_kernel/` provider must be created from scratch

Following the established pattern in `src/integrations/{provider_01,provider_02,provider_03}/`, a Luis-kernel integration should be isolated as `src/integrations/luis_kernel/` (or similarly named) rather than embedded directly in `src/gateway/governance/`. This is consistent with the existing vendor-isolation architecture documented in [`normative_provider.py:59-60`](../src/gateway/governance/normative_provider.py:59) ("Vendor providers are isolated in `src/integrations/{vendor}/` and lazy-loaded by the factory to enforce supply-chain separation"). No such directory exists today.

### 4.6 Breaking change cascade

**JCS migration invalidates all existing seals/signatures.** Because HMAC and hash computations are input-dependent, any change to the canonical byte representation of a payload changes every subsequent signature/hash for that payload — this is not a compatible, additive change:

- Every routing seal issued before a JCS cutover uses the legacy `json.dumps(sort_keys=True, separators=(",", ":"))` byte representation; seals issued after the cutover would use JCS bytes. A seal verifier that doesn't know which canonicalization era a given seal belongs to cannot verify it — this is structurally identical to the evidence-chain schema v1.0→v1.1 migration risk already documented and flagged as **R-10 (Backward-Incompatibility Risk, non-reversible)** in [`tmp/MAJOR_VERSION_CLEANUP_PLAN.md:806`](../tmp/MAJOR_VERSION_CLEANUP_PLAN.md:806) ("the one non-trivial rollback in the program").
- Since routing seals have a 30-second TTL, the *in-flight* blast radius of a hard cutover is small (any seal issued before the flag flip simply expires within 30 seconds) — but the evidence-chain and `RefusalReceipt`/`PauseReceipt` hash sites have **no TTL** and are durably persisted for audit purposes indefinitely, meaning a JCS migration for those sites requires the same **versioned migration path** used for evidence schema v1.0→v1.1 (`migrate_record_1_0_to_1_1()`, dual-schema `verify_record()` per [`tmp/MAJOR_VERSION_CLEANUP_PLAN.md:116`](../tmp/MAJOR_VERSION_CLEANUP_PLAN.md:116)), i.e. a new discriminator field (e.g. `canon_version`) so historical records remain verifiable under their original canonicalization rule while new records use JCS.
- **Recommendation:** do not attempt a "flag-day" cutover. Add a `canon_version` discriminator to every affected payload/record type, implement JCS as an additive option gated by that discriminator, and only default new records to JCS after all seven sites (Section 4.3) have been updated and cross-verified in the same PR/release.

---

## Section 5: Phase 3 Analysis — Terry Snyder Remediation

### 5.1 Fail-closed seals: confirmed fail-OPEN in both code paths

`verify_and_consume_seal()` is duplicated in [`src/gateway/governance/routing_seal.py:575-645`](../src/gateway/governance/routing_seal.py:575) and its mirror [`src/governed_financial_advisor/utils/routing_seal.py:332-405`](../src/governed_financial_advisor/utils/routing_seal.py:332). Both copies exhibit the identical fail-open defect:

- **Path A — `redis_client is None`:** If no Redis client is supplied and the ambient client lookup fails (`except Exception: redis_client = None`, [`routing_seal.py:615-622`](../src/gateway/governance/routing_seal.py:615)), the function proceeds past the `if redis_client is not None:` gate entirely and reaches `return True` at [`routing_seal.py:645`](../src/gateway/governance/routing_seal.py:645) — **the single-use consumption check never ran**, and the function reports success anyway.
- **Path B — Redis operation raises:** The `redis_client.set(..., nx=True, ex=ttl)` call is wrapped in `try/except SymbolicGovernorViolation: raise / except Exception as exc: logger.warning(...)` ([`routing_seal.py:626-643`](../src/gateway/governance/routing_seal.py:626)) — any **non**-`SymbolicGovernorViolation` exception (connection refused, timeout, Redis cluster failover, etc.) is caught, logged as a warning, and swallowed. Execution falls through to `return True` regardless.

**Both paths cause `verify_and_consume_seal()` to return `True` (verification success) even though the atomic single-use consumption never actually occurred.** This means that under a Redis outage — the exact failure mode the "atomic single-use seal semantics" mechanism (CAGE-SEC-008, [`routing_seal.py:584`](../src/gateway/governance/routing_seal.py:584)) exists to survive gracefully — the system fails **open**: replay protection silently disables itself and every caller believes the seal was safely consumed.

### 5.2 Both gateway and GFA files must be updated in lockstep

Because the GFA-side `verify_and_consume_seal()` ([`governed_financial_advisor/utils/routing_seal.py:332`](../src/governed_financial_advisor/utils/routing_seal.py:332)) is a **hand-duplicated copy**, not a shared import, of the gateway version, fixing only one side leaves the other silently vulnerable. This mirrors the exact "SYNC NOTE" risk pattern already documented for the HMAC message-construction logic in [`plans/audit_remediation_implementation_plan.md:71,81`](../plans/audit_remediation_implementation_plan.md:71) — any fix here must ship as a single PR touching both files, with an explicit textual-parity assertion (a new `tests/test_routing_seal_mirror_parity.py`-style test, per the existing plan's own Section 2.8 recommendation) extended to also cover the fail-closed behavior, not just the HMAC message format.

### 5.3 No existing tests for Redis failure scenarios

A search of [`tests/test_routing_seal_security.py`](../tests/test_routing_seal_security.py:1) confirms existing replay tests (`test_gateway_verify_and_consume_seal_prevents_replay`, [line 459](../tests/test_routing_seal_security.py:459); `test_gfa_verify_and_consume_seal_prevents_replay`, [line 656](../tests/test_routing_seal_security.py:656)) exercise the **happy path plus the replay-detected path**, both using a live `fakeredis` instance. **No test in the suite constructs a Redis client that raises an exception or is unreachable** to exercise the fail-open branches described in 5.1 — this is a genuine, unguarded gap: the fail-open bug could regress silently even after a fix, because nothing asserts the fail-closed behavior today.

### 5.4 RefusalReceipt binding: confirmed exclusion of `standing_at_refusal`

`RefusalReceipt.__post_init__()` ([`contracts.py:45-57`](../src/gateway/governance/contracts.py:45)) computes `proof_hash` from a `payload` dict containing only `thread_id`, `action`, `violated_tier`, `violated_rule`, and `timestamp` ([`contracts.py:47-52`](../src/gateway/governance/contracts.py:47)) — **`standing_at_refusal` (the field carrying the actual denied-transaction context: symbol, amount, etc., per its usage at e.g. [`symbolic_governor.py:1743-1748`](../src/gateway/governance/symbolic_governor.py:1743)) is never included in the hashed payload.** The identical exclusion pattern exists in `PauseReceipt.__post_init__()` ([`contracts.py:90-102`](../src/gateway/governance/contracts.py:90)), which likewise omits `standing_at_pause` from its hash. Practical consequence: two `RefusalReceipt`s issued for the *same* `thread_id`/`action`/`violated_tier`/`violated_rule`/`timestamp` but *different* `standing_at_refusal` content (e.g. different trade amounts) would produce **identical `proof_hash` values** — the cryptographic proof does not actually bind to what was refused, only that a refusal of that shape occurred.

### 5.5 Five instantiation sites in `symbolic_governor.py`

`RefusalReceipt(...)` is constructed at five locations in [`symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py:1): lines [1738](../src/gateway/governance/symbolic_governor.py:1738), [1983](../src/gateway/governance/symbolic_governor.py:1983), [2426](../src/gateway/governance/symbolic_governor.py:2426), [2480](../src/gateway/governance/symbolic_governor.py:2480), and [2577](../src/gateway/governance/symbolic_governor.py:2577) — confirmed by direct grep. Every site populates `standing_at_refusal={"symbol": params.get("symbol"), ...}` and reads back `receipt.proof_hash` for OTel span attribution (`span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)`), meaning **any fix to the hash computation in `contracts.py` automatically propagates to all five call sites with no call-site code changes required** — this is a single-file, well-contained fix (the dataclass's own `__post_init__`), not a five-site refactor.

### 5.6 No existing unit tests for `RefusalReceipt`

A search of `tests/` for `RefusalReceipt(` (direct construction, not just import) returns **zero results** — the class has no dedicated unit test file or test class. By contrast, `PauseReceipt(` is directly constructed and tested extensively in [`tests/test_pause_primitive.py`](../tests/test_pause_primitive.py:1) (lines 1091, 1107, 1115, 1131, 1147, 1161), including an explicit `test_pause_receipt_generates_proof_hash` test ([line 1087](../tests/test_pause_primitive.py:1087)) and a determinism test comparing two receipts' `proof_hash` values ([line 1123](../tests/test_pause_primitive.py:1123)). **This asymmetry means `PauseReceipt` has direct test coverage that would need updating (and would presumably already reveal the same binding gap if it asserted standing-content sensitivity, which it does not appear to), while `RefusalReceipt` has no coverage at all to update or extend.** [`tests/test_governance_contracts.py`](../tests/test_governance_contracts.py:1) exists in the suite but contains zero references to either `RefusalReceipt` or `PauseReceipt` (confirmed by direct search) — the receipt-binding fix needs new test cases added to this file, not just an extension of `test_pause_primitive.py`.

---

## Section 6: Inter-Phase Dependencies

### 6.1 Critical dependency chain

1. **Phase 3 (fail-closed seals + receipt binding) should come FIRST.** Both defects (Section 5.1, 5.4) are narrowly-scoped, single/dual-file fixes with no dependency on any net-new infrastructure. More importantly, fixing the fail-open exception-handling pattern in `verify_and_consume_seal()` establishes the **fail-closed exception-handling convention** that Phase 1's kernel `EscalationSemanticGap` handling (Section 3.7) and Phase 2's multi-sig verification failure handling should both follow for consistency. Sequencing Phase 3 first means later phases inherit a proven pattern rather than each inventing their own error-handling convention independently.
2. **Phase 2 (JCS canonicalization) must be atomic across all identified sites.** As established in Section 4.3 and 4.6, partial JCS adoption breaks cross-verification between sites that must agree on canonical bytes (e.g. gateway seal vs. GFA seal verification). This phase cannot be split into independently-shippable PRs per canonicalization site — it requires either a single atomic PR touching all sites, or a versioned dual-canonicalization period (the `canon_version` discriminator approach recommended in 4.6) that itself must be designed and merged before any site starts emitting JCS-canonicalized output.
3. **Phase 1 (Provider 01) depends on both Phase 2 and Phase 3.** Concretely:
   - If the unified plan intends the Provider 01 adapter's evidence/attestation hashing to align with the rest of the kernel's canonicalization scheme (Section 3.8), it depends on Phase 2's canonicalization decision being finalized first — otherwise the adapter would need to be rewritten a second time once JCS lands.
   - The adapter's `EscalationSemanticGap` handling gap (Section 3.7) is structurally the same class of problem as Phase 3's fail-open exception handling (Section 5.1) — both are "an exception path exists but the caller doesn't handle it, so behavior silently defaults to something unintended." Phase 3 should establish the review pattern (add explicit handling, add a regression test for the previously-silent failure mode) that Phase 1's kernel-side fix then reuses.

### 6.2 Rollout risk matrix

| Phase | Risk Level | Reason |
|---|---|---|
| Phase 1 (Provider 01 adapter) | 🔴 HIGH | Adapter is a fidelity-review artifact, not production code (Section 3.1); return-type incompatibility (3.2); stub `fetch_baseline()` (3.3); no external call in `submit_evidence()` (3.4); blocking sync HTTP in an async method (3.5); zero authentication (3.6); and the unhandled `EscalationSemanticGap` would crash the kernel's DEFER-zone gate today (3.7) — this is the least mature of the three phases by a wide margin. |
| Phase 2 (JCS / kernel multi-sig) | 🔴 HIGH | Introduces a wholly net-new cryptographic mechanism (`X-Governance-Signatures`, Section 4.1) with no existing design to build from; conflates LLM-critic consensus with cryptographic multi-signature if `consensus.py` reuse is assumed (4.2); requires atomic, coordinated migration across at least seven independent canonicalization call sites (4.3) with no existing shared helper to centralize the change; breaking-change blast radius affects durably-persisted audit records with no TTL (4.6). |
| Phase 3 (fail-closed seals + receipt binding) | 🟡 MEDIUM | Both defects are confirmed, narrowly-scoped, and touch a small, well-understood surface (2 files for seals, 1 file + 5 call-sites for receipts, all of which auto-inherit the fix via `__post_init__`). Risk is "medium" rather than "low" only because of the fail-closed **availability trade-off** — making Redis outages hard-fail the actuation path is a deliberate security-vs-availability decision that must be explicitly signed off (a Redis outage would now block trade execution entirely, rather than degrading silently), and because it touches the actuation-critical path shared by both the gateway and GFA mirror. |

---

## Section 7: Verification Plan Assessment

Evaluating the unified plan's proposed test additions against the current test suite's actual state:

- ✅ **Valid: `test_routing_seal.py` JCS migration tests.** [`tests/test_routing_seal.py`](../tests/test_routing_seal.py:1) already exercises the v2 seal format end-to-end (generation, verification, HMAC message construction); extending it with JCS-canonicalization-specific cases (byte-exact comparison against RFC 8785 test vectors, per Section 2.2) is a sound, additive extension of existing test infrastructure.
- ✅ **Valid: `test_routing_seal_security.py` Redis failure tests (new).** Confirmed in Section 5.3 that no such tests currently exist — this is a real, identified gap, and the proposed new tests are correctly scoped to close it. Recommend explicitly testing: (a) `redis_client=None` with ambient lookup also failing, (b) a mock Redis client whose `.set()` raises `redis.exceptions.ConnectionError`, and (c) a mock client whose `.set()` raises a generic `Exception` — all three should be asserted to **raise**, not silently return `True`, once the fix lands.
- ✅ **Valid: `test_symbolic_governor_security.py` receipt binding tests (new).** [`tests/test_symbolic_governor_security.py`](../tests/test_symbolic_governor_security.py:1) already exists and covers `SymbolicGovernor` security properties (environment-gated `assert_safe_operational_state()`, fiscal guard await behavior per its own docstring, [lines 15-28](../tests/test_symbolic_governor_security.py:15)) — adding `RefusalReceipt` binding assertions here (two receipts with identical metadata but different `standing_at_refusal` must produce different `proof_hash`) is consistent with the file's existing scope and a reasonable location for the new coverage, though a case could also be made for adding it to `test_governance_contracts.py` since the defect is in `contracts.py`, not `symbolic_governor.py` — **recommend both**: a contract-level unit test in `test_governance_contracts.py` (isolated, fast) plus an integration-level assertion in `test_symbolic_governor_security.py` (confirms the fix propagates through the five real call sites, per Section 5.5).
- ⚠️ **Incomplete: Provider 01 tests need significant adaptation.** The existing [`tmp/cage-provider_01-adapter-v0.3/tests/test_adapter.py`](../tmp/cage-provider_01-adapter-v0.3/tests/test_adapter.py:1) tests the **adapter's own local dataclasses and its own modeled `cage_router.py`** — not the real kernel's `NormativeProvider` Protocol or `enforce_fria_boundary()`. Once the adapter is rewritten per Section 3.9's required changes, these tests must be rewritten against the actual kernel imports, not ported as-is. Any verification plan that treats the existing `test_adapter.py` file as sufficient coverage for a production Phase 1 rollout is understating the required test work.
- ⚠️ **Missing: Kernel-side exception handling for `EscalationSemanticGap`.** No verification plan item currently addresses Section 3.7's finding that the real kernel's `enforce_fria_boundary()` has no handling for this exception at all. This must be added as an explicit test case (`test_normative_provider.py`, extending existing coverage) asserting that a provider raising `EscalationSemanticGap` from `validate_fria()` during the DEFER-zone synchronous gate resolves to a defined, non-crashing `FRIAEnforcementResult` — this test would currently **fail** against the unmodified kernel, which is exactly the point: it should be written first (red), then the kernel fix implemented to make it pass (green).

---

## Section 8: Cross-Region Compliance Impact

Per [`AGENTS.md`](../AGENTS.md#architecture--design-standards), the following paths are **shared modules** that deploy simultaneously to all three regional postures and require an explicit four-point impact statement in every PR touching them:

- `src/gateway/governance/` — touched by **all three phases** (Phase 1's `normative_provider.py` factory registration; Phase 2's canonicalization sites in `contracts.py`, `routing_seal.py`, `kms_signer.py`; Phase 3's `contracts.py` and `routing_seal.py` fixes).
- `src/compliance_bridge/` — touched by Phase 2 (evidence-chain canonicalization in `evidence_stream.py`).
- `config/compliance/`, `config/thresholds/`, `config/oscal/` — not directly touched by any of the three phases based on current file evidence, but should be re-checked once the Provider 01 baseline-fetch and JCS migration designs are finalized, since both could plausibly introduce new config surface.

For every PR touching these paths, per AGENTS.md, the PR description must state:

1. **US_FED impact (NIST SP 800-53).** The fail-open seal defect (Section 5.1) is a control-implementation-relevant fix — likely maps to SC-4 (Information in Shared System Resources) or SI-2 (Flaw Remediation)-adjacent controls, following the precedent already set for the fence-epoch (B3) and HMAC-binding (B2) items in [`plans/audit_remediation_implementation_plan.md:288`](../plans/audit_remediation_implementation_plan.md:288) ("B2... and B3... touch NIST SP 800-53 control implementations... an OSCAL component update in `compliance/oscal/` is required within 2 business days of each merge"). The same obligation applies here.
2. **EU_ECB impact (GDPR/DORA).** A JCS canonicalization change to the evidence chain (Section 4.6) affects the durable audit trail's hash-chain integrity — DORA Article 10 (ICT risk management, record-keeping) relevance should be assessed explicitly, not assumed absent.
3. **APAC_MAS impact (MAS FEAT/TRM).** The fail-closed seal availability trade-off (Section 6.2) has direct MAS TRM (Technology Risk Management) relevance — a decision to fail-closed on Redis outage is exactly the class of availability-vs-integrity trade-off MAS TRM expects to see explicitly documented, not silently introduced.
4. **`CAGE_DEPLOYMENT_REGION` guard placement.** None of the three phases currently appear to introduce a *new data path* that would require a fresh `CAGE_DEPLOYMENT_REGION` guard (the existing guards in `normative_provider.py`, `contracts.py`'s consumers, etc. are unaffected by field-level hash-binding fixes or canonicalization format changes) — but this must be explicitly re-confirmed once the Provider 01 adapter's real network calls (Section 3.9, item 2) are implemented, since a new outbound HTTP call to an external Provider 01 endpoint is exactly the kind of new data path the guard convention exists to gate.

---

## Section 9: Recommended Implementation Order

1. **Phase 3a: Fail-closed seal consumption** (low risk, foundational). Fix both `verify_and_consume_seal()` copies (gateway + GFA) to raise on Redis unavailability/exception rather than falling through to `return True`. Add the missing Redis-failure test coverage (Section 5.3, Section 7). Ship as a single PR touching both files plus new tests, with an explicit availability-trade-off callout per Section 8, item 3.
2. **Phase 3b: RefusalReceipt complete binding** (low risk). Extend `RefusalReceipt.__post_init__()`'s hashed payload to include `standing_at_refusal` (and, for consistency, `PauseReceipt.__post_init__()`'s to include `standing_at_pause`). Since the hash is computed inside `__post_init__`, this requires **no changes to any of the five call sites** in `symbolic_governor.py` (Section 5.5) — purely a `contracts.py` change plus new tests in `test_governance_contracts.py` and `test_symbolic_governor_security.py` (Section 7).
3. **Phase 2a: Add JCS dependency + centralized `canonical.py`.** Before touching any of the seven existing canonicalization sites (Section 4.3), first introduce a single shared `src/gateway/governance/canonical.py` module exposing a `canonicalize(obj) -> bytes` function, backed by a vetted JCS library dependency, and validate it against the official RFC 8785 test vectors (Section 2.2) in a new `tests/test_jcs_canonicalization.py`. This step produces zero behavior change to existing code — it only adds new, tested infrastructure.
4. **Phase 2b: Atomic JCS migration with version flag.** Migrate all seven sites (Section 4.3) to call the new `canonicalize()` helper, gated behind a `canon_version` discriminator per the versioned-migration strategy in Section 4.6. This must land as a single coordinated PR (or a tightly-sequenced PR stack merged within the same release window) — partial migration is explicitly unsafe (Section 4.3, 4.6).
5. **Phase 2c: Luis kernel provider** (net-new, isolated). Build `src/integrations/luis_kernel/` following the `provider_01`/`provider_03` pattern (Section 4.5), including the net-new `X-Governance-Signatures` design (Section 2.1) as a standalone design doc reviewed before coding begins. This step depends on 2a/2b only if the kernel provider's own evidence/signature payloads must use JCS for cross-verification with the rest of the system — confirm this dependency explicitly before starting.
6. **Phase 1: Provider 01 adapter** (requires all prerequisites). Only after Phase 3 (exception-handling convention established) and Phase 2 (canonicalization scheme finalized) land, implement the full Provider 01 adapter rewrite per Section 3.9's six required changes, including the kernel-side `EscalationSemanticGap` handling fix, which should reuse the same review pattern established in Phase 3a.

---

## Section 10: Open Items for User Review

The following items require an explicit decision from the user/stakeholders before implementation can proceed — they cannot be resolved by further codebase inspection alone:

1. **`X-Governance-Signatures` wire format.** No precedent exists (Section 2.1). A concrete delimiter/encoding scheme must be specified in a short design note before Phase 2c coding starts.
2. **`protected_consequence` taxonomy definition.** This term does not appear anywhere in this codebase or the Provider 01 package (Section 2.5) — the source document defining it must be supplied, or an explicit mapping to CAGE's existing `GovernanceDecision`/`FlowDecision` enums must be authored.
3. **`EscalationSemanticGap` resolution strategy.** Should the kernel's `enforce_fria_boundary()` (a) add a new `ExecutionStatus` value to represent an unresolved escalation, (b) map it to the existing `DEFER` status with an additional flag/field, or (c) require providers to never raise it (i.e. push the collapse-to-boolean decision into the provider, contradicting the Provider 01 adapter author's stated design intent, Section 3.7)? This is a governance-semantics decision, not an engineering one.
4. **Fail-closed availability trade-off sign-off.** Making `verify_and_consume_seal()` fail-closed on Redis unavailability means a Redis outage now **blocks all trade actuation** rather than degrading silently (Section 5.1, Section 6.2). This must be explicitly acknowledged and accepted by whoever owns the availability SLA for the actuation path — it is a deliberate security-over-availability choice.
5. **JCS migration timeline and `canon_version` field naming.** Section 4.6 recommends a versioned dual-canonicalization approach rather than a flag-day cutover; the exact discriminator field name, its default value for pre-migration records, and the timeline for eventually retiring legacy-canonicalization support all need explicit decisions.
6. **Scope confirmation: is `consensus.py` in scope for Phase 2 at all?** Section 4.2 identifies a likely category error if the unified plan assumed `consensus.py`'s LLM-critic voting could be extended into a cryptographic multi-signature mechanism. Confirm whether Phase 2's kernel integration is intended to touch `consensus.py` at all, or whether it should be built exclusively alongside `routing_seal.py`'s existing HMAC infrastructure.
7. **Provider 01 production authentication mechanism.** Bearer token (`PROVIDER_01_API_KEY_SECRET`, matching the `Provider01`/`Provider03` pattern) vs. application-level mTLS (Section 2.4/2.6) — this depends on how the real Provider 01 production endpoint is deployed (behind the service mesh vs. external), which is outside this repository's visibility and must be confirmed with the Provider 01 team.
8. **Whether Phase 1 should proceed at all before Provider 01's production readiness improves.** Given the adapter's explicit "fidelity review, not endorsement" framing (Section 3.1) and the substantial gap between its current state and production-readiness (Section 3.9), consider whether Phase 1 should be re-scoped as a longer-running, lower-priority workstream rather than a peer phase to Phase 2/Phase 3, which are internal CAGE-only changes with no external-vendor dependency.
