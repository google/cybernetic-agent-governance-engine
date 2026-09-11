# Engineering Execution Brief — CAGE v3.0 Integrity & Layering

**Issued:** 2026-09-09
**Source of truth:** [`plans/consolidated_implementation_plan_2026-09-09.md`](consolidated_implementation_plan_2026-09-09.md)
**Status of X1:** RESOLVED — decision is **standardize on real vendor names**

> **Reference Architecture Note.** CAGE is an illustrative reference architecture,
> not a deployed service. Optimize for **structural clarity over operational
> continuity**. Breaking changes are acceptable and preferred over compatibility
> shims. No deprecation window is owed.

---

## 0. Read this before starting — two scope corrections

The X1 resolution is genuinely unblocking, but it does **not** mean what a literal
reading suggests. Two corrections, both verified against the tree.

### 0.1 "Standardize on real names" *shrinks* Phases 1–3; it does not authorize a rename sweep

Layer-Inversion Phases 1–3 were never primarily about naming. They fix a
**structural defect**: one vendor gets a privileged code path in the kernel.

[`enforce_fria_boundary()`](../src/gateway/governance/normative_provider.py:548)
special-cases the `FLOWSIGNAL_HOLD` finding code and hardcodes a 300s TTL, while
`provider_06`'s `REVIEW` verdict takes the generic `needs_human_review` path at
[line 592](../src/gateway/governance/normative_provider.py:592). Two providers,
two shapes, for the same semantic event.

**Renaming the symbol does not fix that.** Deleting the branch does.

Therefore:

| Phase | Original intent | Under "standardize on real names" |
|---|---|---|
| **LI-1** De-brand kernel vocabulary | Rename `FLOWSIGNAL_*` → `EXTERNAL_HOLD` | **Largely dropped.** Vendor names may remain in kernel identifiers. |
| **LI-2** Generalize the escalation branch | Delete the vendor-shaped branch | **UNCHANGED AND STILL REQUIRED.** This is the actual I1 fix. |
| **LI-3** Rename Redis namespace / env var | `flowsignal:token:*` → neutral | **Largely dropped.** |

**Do not perform a repo-wide `FLOWSIGNAL` → `EXTERNAL_HOLD` rename.** The decision
removed the need for it. The ~133 test references and the Lula/OSCAL/POAM artifacts
stay as they are.

### 0.2 The one rename that survives, and why

`DeferReason.FLOWSIGNAL_ESCALATION` must still be generalized — **not for
anonymity, but because LI-2 makes it factually wrong.**

After LI-2, `provider_06` and any future provider will produce that same
`DeferReason`. An enum member named for one vendor, describing a state four
providers can enter, is a correctness defect independent of naming policy.

Minimum viable change: `FLOWSIGNAL_ESCALATION` → `EXTERNAL_HOLD` **at the enum
member and the finding-code contract only**. Leave Redis keys, env vars, test
names, comments, and compliance artifacts untouched.

**Explicitly out of scope now:** the vocabulary mapping table, the AARM
re-alignment exercise, and the Lula/OSCAL/POAM artifact updates. `aarm_vector="AARM-V8"`
was always staying — it is a CSA specification identifier, not a vendor name.

### 0.3 What the decision *does* authorize — partner branding in adapter READMEs

The X1 decision has a positive deliverable, not only a scope reduction. Vendor
identity belongs in **prose at the Layer 3 boundary**, which is exactly where the
repo's own convention already puts it.

[`provider_05/README.md`](../src/integrations/provider_05/README.md:8) is the
reference implementation:

```markdown
> **Naming note:** The vendor name for this integration is **Veraxis Execution
> Integrity Protocol (VEIP)**. The package path `provider_05` is retained for
> import stability across branches and test fixtures.
```

Real name in prose, anonymized identifier in the import path. That satisfies both
the partner-attribution goal and the coupling test in §3 of the layer-inversion
plan — the code keeps working if the vendor disappears; only the prose is stale.

**Current state (audited):**

| Directory | README | Vendor named? |
|---|---|---|
| `provider_01` | ✅ | ❌ |
| `provider_02` | ✅ | ❌ |
| `provider_03` | ✅ | ❌ |
| ~~`provider_04`~~ | — | **retired — became `actuator_01`. See §0.3a** |
| `provider_05` | ✅ | ✅ **reference convention** |
| `provider_06` | ✅ | ❌ (names the upstream repo, not the vendor) |
| `actuator_01` | ❌ **missing** | ❌ (8 modules, no README) |
| `storage_gcs` / `storage_s3` | — | n/a — cloud SDKs, not partners |

This becomes **work item D1** in §5. It is documentation-only, touches no
executable code, and can proceed fully in parallel with every other wave.

### 0.3a `provider_04` is `actuator_01` — retired, not missing

`provider_04` was not deleted; it was **re-scoped**. Framed as an
`EnvelopeMapper`/`AttestationProvider`, it was architecturally a **downstream
execution actuator**, and was retired in favour of `actuator_01` per
[`cage_internal_blockers_implementation_plan.md`](cage_internal_blockers_implementation_plan.md) §1.

The evidence is unambiguous:

| Signal | Finding |
|---|---|
| Test vector names | `test_jcs_provider_04_reference_vector_1` → `test_jcs_actuator_01_reference_vector_1` — *renamed, same vectors* |
| Envelope version | `provider_04.envelope/v1` → `actuator_01.envelope/v1` |
| Operator URN namespace | `urn:provider_04:op:` → `urn:actuator_01:op:` |
| Vendor identity | Both trace to **Archytan** — [`.agents.local.md:14`](../.agents.local.md:14) maps `provider_04 → Archytan`; [`client.py:141`](../src/integrations/actuator_01/client.py:141) sends `X-Archytan-Signatures` |
| KMS signer | `sign_provider_04_digest()` removed from `KMSSigner` (CHANGELOG) |

Retirement is **complete in code** — verified: zero `provider_04` matches in
`src/`, the `p04` alias is gone from
[`normative_provider.py:915`](../src/gateway/governance/normative_provider.py:915),
and [`__init__.py:28`](../src/integrations/__init__.py:28) documents
`actuator_01/ — Downstream execution actuator`.

**The partner has approved the re-scope.** This is documentation drift, not an
unresolved partner issue. [`luis_actuator_01_response.md`](../docs/meetings/luis_actuator_01_response.md)
records active wire-protocol collaboration on the actuator integration — domain
tag corrected to `ARCHYTAN_QUORUM_V1:`, header corrected to
`X-Archytan-Signatures`, both matched against the partner's own verification
path. That level of detail is only reachable with a partner who has accepted the
actuator framing.

**Two pieces of residue remain, both documentation:**

1. **[`README.md:210`](../README.md:210)** still lists
   `provider_04/ (socket-level execution guillotine)` in the Layer 3 table and
   omits `actuator_01`, `storage_gcs`, `storage_s3`. Already catalogued in
   [`TECHNICAL_REPORT_GAP_ANALYSIS.md`](TECHNICAL_REPORT_GAP_ANALYSIS.md) §67.
2. **[`refactoring_vendor_communications.md`](refactoring_vendor_communications.md) §68**
   addresses the partner as "Provider 04 — Attestation Provider + Envelope
   Mapper" and cites a `Provider04EnvelopeMapper` class that **does not exist**
   (verified: zero `EnvelopeMapper` matches in `src/`).

Item 2 is a **stale draft**, not a miscommunication: the document describes
Archytan as an attestation provider and cites a `Provider04EnvelopeMapper` that
no longer exists (verified: zero `EnvelopeMapper` matches in `src/`). Reality
overtook the draft. Correct it in place — no partner follow-up is owed.

Two corrections to make while editing it:

1. **Re-scope the section** from "Provider 04 — Attestation Provider + Envelope
   Mapper" to "actuator_01 (formerly provider_04) — Downstream Execution
   Actuator", and drop the `Provider04EnvelopeMapper` reference.
2. **Delete the anonymization question for this partner.** It is already answered
   by the wire protocol: the header is `X-Archytan-Signatures` and the signing
   domain tag is `ARCHYTAN_QUORUM_V1:`. The vendor name is load-bearing in the
   protocol contract, so anonymization is not available without a coordinated
   protocol change. Asking a settled question invites a confusing answer.

Both fall inside D1's documentation scope.

### 0.4 Sequencing consequence

The original hold existed because a premature rename reaching the compliance layer
is expensive to redo. That risk is now gone, so **LI-2 can start immediately** and
does not need to wait behind LI-1.

---

## 1. Global engineering constraints — apply to every PR

**Branching.** Never commit to `main` or `rc-v*`. Create a compliant branch first:
`<type>/<lowercase-kebab-description>`, description ≤ 30 chars. Squash merge only.

**Commits.** Conventional Commits, subject ≤ 72 chars, imperative, no trailing
period. Breaking changes need both `!` and a `BREAKING CHANGE:` footer.

**License.** Apache 2.0 header on every new file under `src/`.

**Test markers.** Every new test module needs a selection marker or CI fails:

```python
pytestmark = [pytest.mark.unit, pytest.mark.local]
```

**Verification gate — run before declaring any item complete:**

```bash
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov \
  -p no:langsmith -p no:langsmith_plugin --tb=short
uv run python scripts/check_import_boundaries.py --verbose
uv run ruff check . && uv run ruff format --check .
uv run mypy src/
```

Always `uv run`. Never bare `pytest` or `python`. If the sandbox blocks `uv`
(exit 127 / socket reset), retry with sandbox bypass — do not switch runners.

**Before running local tests,** confirm no port-forwards are bridging localhost to
a live cluster (`ps aux | grep port-forward`), or tests will read live Redis state.

**Never disable a CI check to make a build pass.**

---

## 2. Wave 1 — Evidence-chain integrity (start here)

These are the only items where CAGE currently **misrepresents its own behaviour**.
Everything else in the roadmap is incomplete rather than incorrect.

### A1 — Idempotent cold flush

**Branch:** `fix/idempotent-cold-flush`

[`stream.py:1219`](../src/gateway/governance/evidence/stream.py:1219) calls
`put_batch()`. [`put_if_absent()`](../src/gateway/governance/evidence/cold_store.py:135)
is on the protocol and implemented atomically by both GCS (`if_generation_match=0`)
and S3 (`IfNoneMatch: "*"`). A crash mid-flush currently writes duplicate batches
into a hash-chained store, which makes chain verification ambiguous.

Swap the call. Add a test asserting a replayed flush does not duplicate.

**Commit:** `fix(governance): use put_if_absent in cold flush loop`

---

### A2 — Ingest the full `RefusalReceipt` v3 (highest priority in the roadmap)

**Branch:** `fix/refusal-receipt-ingestion`

**The defect.** [`_emit_refusal_receipt()`](../src/gateway/server/governance_middleware.py:541)
builds a seven-field summary dict and ingests *that*. The v3 `RefusalReceipt` —
`tier_failures`, the five-part proof chain, the JCS `proof_hash` — is constructed
at five sites in `symbolic_governor.py`, attached to `GovernanceError(receipt=...)`,
and **never reaches the stream**. `proof_hash` survives only as OTel span
attributes (lines 1827, 2067, 2511, 2566, 2672).

**Why it ranks first.** Only ALLOW decisions are guaranteed to enter the
tamper-evident chain. For a governance engine, refusals are the *primary* evidence
— proof the system intervened. An auditor reconstructing behaviour sees the allows
and must take CAGE's unsigned word on the blocks.

This is the same "signed facts, unsigned story" failure we are currently arguing
to an external partner about their bundle format. Fixing the external case while
leaving the internal one is not defensible.

**Approach.** `GovernanceError` already carries `receipt=receipt`. Have
`_emit_refusal_receipt()` serialize the real object rather than rebuild a lossy
summary. One serialization path, one place to keep correct — preferred over
editing five construction sites.

**Required test:** a DENY decision produces a stream entry containing
`tier_failures` and a `proof_hash` matching the receipt's computed value.

**Commit:** `fix(governance): ingest full refusal receipt into evidence chain`

---

### A3 — `PauseReceipt` stream emission

**Same branch and PR as A2** — shares the serialization path.

[`PauseReceipt`](../src/gateway/governance/contracts.py:139) is constructed at
[`symbolic_governor.py:2575`](../src/gateway/governance/symbolic_governor.py:2575)
and surfaced only as a span attribute. Give it parity with A2.

---

### A4 — Prod-enforce per-record KMS signing

**Branch:** `fix/enforce-kms-signing-prod`

`_KMS_SIGN` defaults `false` ([`stream.py:397`](../src/gateway/governance/evidence/stream.py:397)).
[`validate_evidence_stream_preconditions()`](../src/gateway/governance/evidence/stream.py:425)
already raises `ConfigurationError` on contradictory config but never checks
`EVIDENCE_STREAM_KMS_SIGN`. Add the clause for `CAGE_ENV=prod`.

**Honesty note worth fixing while you are here:** `kms_signature` is present as
`""` in every entry whether or not signing ran. An empty string in a signature
field invites a reader to assume the mechanism executed. Prefer omitting the field
when unsigned.

**Commit:** `fix(governance): require KMS signing in production evidence stream`

---

## 3. Wave 2 — Seam contracts

### C0 — Extract seam contracts

**Branch:** `refactor/extract-seam-contracts`

Create `seams/normative.py`, `seams/attestation.py`, `seams/actuation.py` per
LI-Phase 0. Resolves a latent circular import that currently forces inconsistent
function-scope imports. Gates C1.

---

### C1 (absorbs CER Phase 3) — Make `provider_02` satisfy `AttestationProvider`

**Branch:** `fix/provider-02-seam-contract`

> Two plans specified this differently. Resolution recorded in
> [`consolidated_implementation_plan_2026-09-09.md`](consolidated_implementation_plan_2026-09-09.md) §3
> and cross-referenced in both source plans. Implement it **once**, as below.

**Current state.** `Provider02AttestationProvider` implements `certify_decision`,
`verify_cer`, `register_project_bundle` — and none of `fetch_baseline`,
`validate_fria`, `submit_evidence`. Yet
[`normative_provider.py:940`](../src/gateway/governance/normative_provider.py:940)
returns it from `get_normative_provider()` behind `# type: ignore[return-value]`.
Any caller treating it as a `NormativeProvider` raises `AttributeError`. It also
lacks `fetch_attestations()` and `provider_name`, so it satisfies
`AttestationProvider` no better.

**Changes:**
1. Subclass the `AttestationProvider` ABC; `provider_name` → `"provider_02"`.
2. Implement `fetch_attestations(context)` wrapping `verify_cer`, returning
   `ExternalAttestation` with **`AttestationStatus.UNVERIFIED`**.
3. Remove the `provider_02` branch and its `type: ignore` from
   `get_normative_provider()`; drop `p02` from the alias map.
4. Raise a descriptive `ValueError` naming `AttestationAggregator` when
   `provider_02` is requested from the normative factory.

**Why `UNVERIFIED` and not `VERIFIED`.** After Phase 0,
[`_inspect_local()`](../src/integrations/provider_02/provider.py:289) genuinely
performs no signature check. `UNVERIFIED` states a true fact. Emitting `VERIFIED`
would reintroduce the exact fail-open Phase 0 removed.

**Required invariant test.** Add a test that **fails when Wave 3 lands** if the
status has not become `VERIFIED`. This converts a sequencing worry into an enforced
transition — the promotion becomes a visible, tested event rather than a status
that silently appears correct.

**Preserve untouched:** the `CERVerification.__post_init__` fail-closed invariant
at [`provider.py:115`](../src/integrations/provider_02/provider.py:115).

**Inverts** the test at
[`provider_02/tests/test_provider.py:259`](../src/integrations/provider_02/tests/test_provider.py:259),
which currently pins the incorrect wiring.

**Commit:** `fix(governance)!: make provider_02 satisfy AttestationProvider`

---

### C2 — Fail-closed aggregator registration

**Branch:** `fix/aggregator-register-typecheck`

[`AttestationAggregator.register()`](../src/gateway/governance/attestation_aggregator.py:84)
appends any object without validation; a non-conforming provider fails later at
`provider.provider_name` during `_do_fetch()`. Mirror
[`ActuatorRegistry.register()`](../src/gateway/governance/execution_actuator.py:196)
and raise `TypeError` at registration.

---

### LI-2 — Generalize the escalation branch (unblocked by the X1 decision)

**Branch:** `refactor/generic-external-hold`

**This is the real I1 fix and the only part of LI-1/2/3 that survives §0.1.**

Delete the vendor-shaped branch in
[`enforce_fria_boundary()`](../src/gateway/governance/normative_provider.py:548).
Drive TTL and `DeferReason` off declared finding fields any provider can populate:

```python
finding = next((f for f in result.findings if f.get("needs_human_review")), None)
if finding is not None:
    ttl = finding.get("hold_ttl_seconds", _DEFAULT_HOLD_TTL)
    reason = DeferReason.EXTERNAL_HOLD
```

Rename `DeferReason.FLOWSIGNAL_ESCALATION` → `EXTERNAL_HOLD` **as part of this
change** — after generalization the vendor-specific name is factually wrong, since
multiple providers reach that state. Scope the rename to the enum member and the
finding-code contract. **Do not** touch Redis keys, env vars, test names, comments,
or compliance artifacts.

**Two-sided contract:** `provider_01` emits the finding code and the kernel matches
it. **Both sides must change in the same commit** or the escalation path silently
fails open into the generic branch.

**Invariant to preserve:** quorum-3 for `EXTERNAL_HOLD`, per
[`defer_queue.py:265`](../src/gateway/governance/defer_queue.py:265). Do not let
the generalization silently downgrade quorum to 2.

**Required test:** `provider_06` REVIEW and `provider_01` ESCALATE produce
byte-identical `DeferToken` shapes apart from the finding message.

**Commit:** `refactor(governance)!: drive external hold TTL from finding fields`

---

## 4. Wave 3 — CER read path

Sequential: **B1 → B2 → B3+B4.**

| ID | Task | Notes |
|---|---|---|
| **B1** | `ContentAddress` kernel primitive + digest agility | Parse the algorithm prefix; replace the `len == 64` hardcode. Gates B2 and B6. |
| **B2** | `Provider02CERResolver` | Exact-hash GET, `If-None-Match`/`304`, error mapping. Contract fully specified by the captured live CER. |
| **B3** | Real Ed25519 verification | Resolve the key by `kid` from the key manifest. **Never verify against the receipt's embedded `publicKeyJwk`** — a forged receipt controls its own body including any key it carries. Fail closed on unknown `kid`; no fallback. |
| **B4** | JCS cross-implementation fixture test | Same PR as B3. |

**On landing B3:** the C1 invariant test must flip `UNVERIFIED` → `VERIFIED`. If it
does not, the wiring is incomplete — do not suppress the test.

---

## 5. Wave 4 — Reachability and hardening

| ID | Task | Gate |
|---|---|---|
| **B6** | Wire `cer_uris` so OSCAL evidence links are emitted | **Blocked on A2** — see below |
| **B7** | Fix the `cer-hash` prop `rsplit` bug | With B6 |
| **C4** | Inject graph topology into `provider_02` | Honours a commitment already made to the partner |
| **C7** | Wire Gate G6 into CI | Prevents C4-class regression |
| **C3, C5, C6** | Attributability, DI, `ConsequenceToken` relocation | |
| **C8** | Extend the conformance suite | Depends on C1 |
| **B8** | Document `PROVIDER_02_*` in `.env.example` | Independent |

**B6 hard ordering constraint.** The exporter already emits `rel="evidence"` links
([`oscal_exporter.py:207`](../src/compliance_bridge/oscal_exporter.py:207), seven
passing tests) but the only production caller
([`main.py:825`](../src/compliance_bridge/main.py:825)) never passes `cer_uris`, so
zero links are emitted at runtime. Built, tested, unreachable.

**Do not wire it until A2 has landed.** Evidence citations pointing into a chain
that omits every DENY event are worse than no citations — they look complete.

### D1 — Partner branding in adapter READMEs (parallel, documentation-only)

**Branch:** `docs/adapter-partner-branding`

The positive deliverable of the X1 decision. Follow the
[`provider_05`](../src/integrations/provider_05/README.md:8) convention exactly:
a **Naming note** block directly under the reference-architecture note, giving the
real vendor name in prose while the package path stays anonymized.

**Scope:**

1. Add the naming note to `provider_01`, `provider_02`, `provider_03`, `provider_06`.
2. **Create [`actuator_01/README.md`](../src/integrations/actuator_01/) from
   scratch** — eight modules, no README. Cover the `ExecutionActuator` protocol,
   the four declared capabilities (`MULTI_SIG_QUORUM`, `MTLS_REQUIRED`,
   `DIGEST_ONLY_PAYLOAD`, `REPLAY_PROTECTED`), and the KMS signing requirement in
   `health_check()`.
3. Leave `storage_gcs` / `storage_s3` alone — cloud SDKs, not partner integrations.
4. **`provider_04` needs no README — it *is* `actuator_01`** (§0.3a). Retirement
   is complete in code; nothing to delete. The `actuator_01` README created in
   step 2 should carry a short "formerly `provider_04`" note so the rename is
   discoverable from the package rather than only from a plan document.
5. **Fix [`README.md:210`](../README.md:210)** while you are here: the Layer 3
   table still lists `provider_04/ (socket-level execution guillotine)` and omits
   `actuator_01`, `storage_gcs`, `storage_s3`.
6. **Refresh [`refactoring_vendor_communications.md`](refactoring_vendor_communications.md) §68** —
   re-scope the section from "Provider 04 — Attestation Provider + Envelope
   Mapper" to "actuator_01 (formerly provider_04) — Downstream Execution
   Actuator", drop the non-existent `Provider04EnvelopeMapper` reference, and
   delete the anonymization question for this partner (already answered by the
   `X-Archytan-Signatures` header and `ARCHYTAN_QUORUM_V1:` domain tag). The
   re-scope is partner-approved; this is drift, not a live issue.

**Boundaries — do not exceed:**

- **Prose only.** No identifier, string literal, env var, Redis key, or test name
  changes. If a line would break when the vendor disappears, it is not in scope.
- **No real endpoint URLs, credentials, or contact details.** These READMEs are
  public. Keep the "no configured live endpoint" note in every file.
- **Verify each vendor name against a source you can point at** — the partner
  communications document or the adapter's own upstream reference. Do not infer a
  vendor name from a coverage report or a stale branch name.

**Why this is safe while LI-1/LI-3 were not:** vendor names in *prose* are
provenance and were always permitted, including under the anonymization branch —
Gate G6 explicitly excludes docstrings and comments. This work would have been
correct either way; the X1 decision simply makes it worth doing now.

**Commit:** `docs(imports): name partner vendors in adapter READMEs`

---

**C4 context.** [`adapter.py`](../src/integrations/provider_02/adapter.py:98)
hardcodes Layer 4 demo node names (`_ATTESTATION_NODES`, `_GRAPH_PARENTS`,
`_classify_terminal_path()` branching on `"governed_trader"`). The adapter works
for exactly one application; any other adopter gets an empty bundle, silently.
Gate G3 cannot catch it — it scans for illegal *imports*, and this is Layer 3
holding Layer 4 *string literals*. Hence C7.

---

## 6. Deliverables

1. **Wave 1 PRs** — A1, A2+A3, A4. Separate branches, squash-merged, full
   verification gate green on each.
2. **Wave 2 PRs** — C0, C1, C2, LI-2.
2a. **D1** — adapter README branding, including a new `actuator_01/README.md`.
   Documentation-only; may land at any point and needs no coordination.
3. **Plan status update** — in
   [`consolidated_implementation_plan_2026-09-09.md`](consolidated_implementation_plan_2026-09-09.md):
   move X1 from *Blocked* to *Resolved — standardize on real names*, and record
   the §0.1 scope reduction so nobody later executes the dropped rename sweep
   believing it was merely deferred.
4. **Compliance obligations** (per `AGENTS.md`):
   - Touching NIST SP 800-53 control implementations → OSCAL component update in
     `compliance/oscal/` within 2 business days of merge.
   - Adding/removing K8s resources referenced by Lula → Lula validation update in
     the same PR or an explicitly flagged follow-on.
   - **Note:** under the X1 decision, no Lula/OSCAL/POAM naming updates are
     required. That obligation was contingent on the anonymization branch.

---

## 7. Escalate rather than guess

Stop and raise if any of these appear:

- **A2 turns out to need changes at all five `symbolic_governor.py` sites** rather
  than one serialization path — that indicates the receipt is not reaching the
  middleware intact, which is a different and larger defect.
- **The LI-2 quorum invariant cannot be preserved** without special-casing a
  provider — that would mean the generalization is unsound as specified.
- **The C1 invariant test cannot be written** such that it fails before B3 and
  passes after — the status transition may not be observable, which needs design
  input.
- **Any Wave 1 item appears to require disabling a CI gate.** It does not; the
  requirement is wrong or the approach is.

**Not an escalation — documentation drift, fix it in place:**

- The `provider_04` → `actuator_01` re-scope is **partner-approved** (§0.3a).
  [`refactoring_vendor_communications.md`](refactoring_vendor_communications.md) §68
  is simply a stale draft that predates the change. Correct it as part of D1; no
  partner follow-up is owed.

**Process note worth acting on separately.** This drift was only detectable by
cross-referencing test-vector names against a plan document. The same class of
staleness applies to the other five partner sections in that file. Consider a
freshness check — the repo already runs `stpa-freshness-check` and
`nemo-freshness-check` for exactly this failure mode. A gate asserting that every
class and module path cited in `refactoring_vendor_communications.md` resolves in
the tree would have caught `Provider04EnvelopeMapper` immediately.
