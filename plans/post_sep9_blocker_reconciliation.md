# Post-Sep-9 Blocker Reconciliation

**Date:** 2026-09-09, after the NexArt sync
**Inputs:** `telemetry_pipeline_analysis.md` (v2) · [`plans/provider_02_cer_unblocked_work.md`](provider_02_cer_unblocked_work.md) · [`docs/meetings/nexart_sep9_prep.md`](../docs/meetings/nexart_sep9_prep.md)
**Question:** with the meeting done, what is still blocked?

---

## Answer

**Nothing is externally blocked. One item was never a blocker. Two are urgent for
a different reason than the telemetry analysis gives.**

The telemetry document's "🔴 This week (Sep 9 blocker)" line is now stale, and it
was mis-scoped even when written. Every remaining gap is CAGE-side work with no
vendor dependency.

---

## 1. The stated Sep 9 blocker was not a blocker

The telemetry analysis says:

> Decide OSCAL → NexArt CER URI strategy (CAGE-native vs. NexArt post-processing).
> Wire `provider_06.submit_evidence()` `receiptDigest` into `oscal_ssp_exporter.py`
> — directly load-bearing for the NexArt meeting.

Three corrections, all verified in code:

**(a) The strategy decision was already made and needed no vendor input.** The CER
work plan settled it: CAGE generates URIs natively. The rewriting hook already
exists — [`build_oscal_assessment_results()`](../src/compliance_bridge/oscal_exporter.py:115)
accepts `cer_uris` and emits `rel="evidence"` at
[line 207](../src/compliance_bridge/oscal_exporter.py:207), with seven passing
tests. A vendor-side rewriter was rejected on architectural grounds, not deferred
pending an answer.

**(b) It names the wrong exporter.** The gap is in
[`compliance_bridge/oscal_exporter.py`](../src/compliance_bridge/oscal_exporter.py)
(Assessment Results), not
[`gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py)
(System Security Plan). Different files, different documents. Wiring the SSP
exporter would not fix the emission gap.

**(c) It names the wrong provider.** `provider_06.submit_evidence()` returns an
`EvidenceSeal` whose `seal_hash` comes from a `receiptDigest`
([`provider_06/adapter.py:430`](../src/integrations/provider_06/adapter.py:430)) —
that is the Agent Integrity provider, a different trust service. NexArt CER hashes
come from `provider_02`. Conflating them would wire the wrong digest into the
`link[rel="evidence"]` href.

**The real gap is one line of plumbing:** the only production caller,
[`main.py:825`](../src/compliance_bridge/main.py:825), never passes `cer_uris`.
Verified — a search for `cer_uris` in that file returns nothing. At runtime,
**zero CER links are emitted**. The feature is built, tested and unreachable.

That is Phase 4 in the CER plan. Unblocked, unstarted, and not urgent in the way
the telemetry doc implies.

---

## 2. Confirmed gaps — all verified against code

I checked each claim rather than accepting it. All four hold.

| Gap | Claim | Verification |
|---|---|---|
| **#6** | `RefusalReceipt` v3 never reaches the stream | **Confirmed.** [`_emit_refusal_receipt()`](../src/gateway/server/governance_middleware.py:541) builds a 7-field dict — `action_id`, `refusal_reason`, `oscal_control_ref`, `kms_signature` — and ingests *that*. The v3 dataclass with `tier_failures` and the 5-part proof chain never appears. In `symbolic_governor.py`, `proof_hash` occurs only as OTel span attributes (lines 1827, 2067, 2511, 2566, 2672); there is no `ingest` call anywhere in the file. |
| **#3** | Cold flush is not idempotent | **Confirmed.** [`stream.py:1219`](../src/gateway/governance/evidence/stream.py:1219) calls `put_batch()`. [`put_if_absent()`](../src/gateway/governance/evidence/cold_store.py:135) exists on the protocol and is implemented atomically by both GCS and S3 adapters. Simply unused in the flush path. |
| **#4** | KMS signing not prod-enforced | **Confirmed.** `_KMS_SIGN` defaults `false` ([`stream.py:397`](../src/gateway/governance/evidence/stream.py:397)). [`validate_evidence_stream_preconditions()`](../src/gateway/governance/evidence/stream.py:425) checks `EVIDENCE_CHAIN_BLOCKING` and `EVIDENCE_STREAM_ENABLED` but never `EVIDENCE_STREAM_KMS_SIGN`. |
| **#7** | `PauseReceipt` has no emission path | **Confirmed.** Constructed at [`symbolic_governor.py:2575`](../src/gateway/governance/symbolic_governor.py:2575), surfaced only as a span attribute at line 2596. |

---

## 3. Reprioritisation

The telemetry document ranks by pillar completeness. That is the wrong axis. The
right one is **which gaps cause CAGE to assert something untrue**, because those
are the same class of defect as the `_verify_local()` fail-open already fixed in
Phase 0.

### 🔴 Highest priority — Gap #6, and not for the stated reason

The telemetry doc files this under "structural correctness." It is more serious
than that.

**Only ALLOW decisions are guaranteed to enter the tamper-evident chain.** DENY
events emit a simplified dict; the rich proof object stays in memory and in
traces. So the audit chain systematically over-represents permitted actions.

For a governance engine, refusals are the *primary* evidence — proof the system
intervened. An auditor reconstructing behaviour from the chain sees the allows and
must trust CAGE's word on the blocks. That is exactly the "signed facts, unsigned
story" failure identified in the NexArt bundle-shape analysis (§5 of the brief),
appearing here in CAGE's own evidence layer.

It also interacts with Phase 0. We just made CER verification fail closed rather
than assert unverified success. Gap #6 is the same pattern one layer up: the
system implies a complete audit chain while silently omitting a whole decision
class. Fixing one and not the other is inconsistent.

**Fix:** ingest the full v3 dataclass. Either at the five construction sites in
`symbolic_governor.py`, or — better — have `GovernanceError` carry the receipt
(it already does, via `receipt=receipt`) and let `_emit_refusal_receipt()`
serialize the real object instead of rebuilding a lossy summary.

### 🔴 Also high — Gap #3, one line

`put_batch()` → `put_if_absent()` in `_cold_flush_loop()`. Both adapters already
implement it atomically. A crash mid-flush currently writes duplicate batches into
what is supposed to be an exactly-once evidence store. Duplicates in a hash-chained
audit log are worse than ordinary data duplication: they make chain verification
ambiguous.

### 🟡 Gap #4 — prod enforcement of KMS signing

Add `EVIDENCE_STREAM_KMS_SIGN` to `validate_evidence_stream_preconditions()` as a
prod-required assertion. The function already exists and already raises
`ConfigurationError` for contradictory config, so this is an added clause, not new
machinery.

Worth noting the honesty point: the `kms_signature` field is present as `""` in
every entry whether or not signing is on. An empty string in a signature field is
weaker than an absent field — it invites a reader to assume the mechanism ran.

### 🟡 Gap #7 — `PauseReceipt` parity

Same shape as #6, lower volume. Do it in the same change; the serialization path is
shared.

### 🟢 Everything else

Gaps #1, #2, #5, #8–#12 are genuine but none is urgent, and none is blocked. Gap #12
(reconciliation daemon) is the largest but is honestly self-described as a skeleton
and fails closed in prod, which is the correct posture for an unimplemented
provider.

---

## 4. Interaction with the CER plan

The two workstreams are independent — no shared files, no ordering constraint.

| CER plan phase | Telemetry gap | Relationship |
|---|---|---|
| Phase 0 (done) | — | Set the precedent: fail closed, never assert unverified success |
| Phase 1–2b | — | No overlap |
| Phase 3 (`external_attestations[]`) | — | No overlap |
| **Phase 4 (OSCAL wiring)** | **Mis-stated Sep 9 "blocker"** | Same work, correctly scoped |
| Phase 5 (env docs) | — | No overlap |

One genuine sequencing note: **Gap #6 should land before Phase 4.** OSCAL evidence
links are only as good as the chain behind them. Emitting `link[rel="evidence"]`
entries while DENY events are missing from that chain produces citations pointing
at an incomplete record — a worse failure than emitting no links, because it looks
complete.

---

## 5. Recommended order

1. **Gap #3** — one line, immediate, no design work.
2. **Gap #6 + #7** — DENY and PAUSE receipts into the chain. The structural fix.
3. **Gap #4** — prod precondition for KMS signing.
4. **CER Phase 1 → 2 → 2b → 3** — as planned, in parallel; different files.
5. **CER Phase 4** — after Gap #6, so links reference a complete chain.
6. Everything else, unranked, unblocked.

---

## 6. Corrections to fold back into the telemetry document

- Remove the "Sep 9 blocker" framing — the meeting has happened and the item was
  never vendor-dependent.
- Fix the file reference: `compliance_bridge/oscal_exporter.py`, not
  `gateway/governance/oscal_ssp_exporter.py`.
- Fix the provider reference: `provider_02` (NexArt CER), not `provider_06`
  (Agent Integrity `receiptDigest`).
- Restate the OSCAL gap as *"`cer_uris` never passed by the only caller"* rather
  than *"strategy undecided"*.
- Promote Gap #6 from "short-term structural correctness" to highest priority, on
  the grounds that it makes the audit chain systematically misrepresent the
  system's behaviour.
