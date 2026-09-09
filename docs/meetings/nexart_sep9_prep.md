# CAGE ⇄ NexArt Technical Sync — Prep Brief

**Date:** Wednesday 9 September 2026, 15:00 UK (14:00 UTC) · 45 min
**Attendees:** Lars Ahlfors (CAGE) · Jeremy Bouedo (NexArt)
**Objective:** Ratify the CER handoff contract and agree the bundle-shape question.
Leave with a written boundary, not a to-do list.

> **Revision note.** This brief was rewritten after retrieving a live CER from the
> public resolver. The earlier draft contained several claims that did not match
> the codebase; those are corrected in §1 and the corrections are stated plainly
> rather than quietly dropped. Implementation detail lives in
> [`plans/provider_02_cer_unblocked_work.md`](../../plans/provider_02_cer_unblocked_work.md).
>
> **Second revision (pre-call).** Re-verified against the tree. Two changes:
> the verification fail-open in §1.3 is **now fixed** — it was in flight when the
> brief was written and has since landed, so it is stated as closed rather than
> pending. And the adapter defect in §5 has been promoted from an observation into
> a tracked finding with a sequenced phase — see
> [`plans/layer_inversion_remediation_plan.md`](../../plans/layer_inversion_remediation_plan.md).

### Framing

CAGE is an Apache 2.0 **reference architecture**, not a deployed service. Provider
integrations are anonymized in-repo (`provider_02`) and carry no configured live
endpoint. Everything here is an integration pattern for adopters to adapt.
Breaking changes are cheap; structural clarity beats operational continuity.

**CAGE is application-agnostic and ships zero built-in applications.** The kernel
is domain-neutral and vendor-neutral; CI fails the build if it imports a domain
plugin or reference application. The Governed Financial Advisor and the Healthcare
Clinical Agent are **Layer 4 demos** that exist to prove the same substrate governs
orthogonal domains without kernel change.

This matters for our session: where I previously described governance node
boundaries and a LangGraph DAG, that was **one demo's pipeline**, not CAGE's shape.
An adopter's control graph may look nothing like it. §5 reframes the bundle
question accordingly — we should be designing for arbitrary adopter topologies,
not for our finance demo.

---

## 1. Corrections to my earlier note

Three things I sent previously were wrong. Correcting them up front so the session
runs against reality.

**1. The resolver claim was overstated.** I said we had verified the callback
"under exact-hash and immutable ETag constraints." We had not. No code path in
CAGE constructs a `/v1/resolve/cer/...` URL. The ETag/`304` handling we do have is
on the **JWK sync loop**, not on CER resolution. Your resolver's cache contract is
currently unconsumed.

**2. The OSCAL description was wrong — and the real gap is worse.** I described our
SSP exporter as emitting GCS URIs. It does not; it emits relative repo paths. More
importantly, CER evidence links are **already implemented** in
[`oscal_exporter.py:207`](../../src/compliance_bridge/oscal_exporter.py:207),
accepting a `cer_uris` map and emitting `rel="evidence"`, covered by seven passing
tests. But the only production caller
([`main.py:825`](../../src/compliance_bridge/main.py:825)) never passes the
argument. **At runtime, zero CER links are emitted.** Built, tested, unreachable.

**3. Our signature verification did not verify signatures — now fixed.** The
method (since renamed
[`_inspect_local()`](../../src/integrations/provider_02/provider.py:289)) checked
that the JWK cache was non-empty and the hash was 64 characters, then returned
`valid=True`. A fail-open in an attestation path.

That has landed. Every path now returns `valid=False, signature_checked=False`,
including
[`_verify_remote()`](../../src/integrations/provider_02/provider.py:330) — so even
when *your* endpoint reports `valid=true`, CAGE reports `valid=False`, because CAGE
did not check the signature itself. The fail-open is closed by construction:
`CERVerification.__post_init__` raises if `valid=True` is ever set without
`signature_checked=True`
([`provider.py:115`](../../src/integrations/provider_02/provider.py:115)), so the
defect cannot reappear silently.

**What this means for the call:** we currently report every CER as unverified. That
is honest but not useful, and real Ed25519 verification (work item 4) is what makes
`valid=True` reachable. Your self-describing receipt is what unblocks it.

---

## 2. What the live CER settled

I pulled the receipt for
`sha256:54647b22bfbf7166613c12dabda026a6a21647d85f3e12de3206d8ebfbc066e6`.

It is fully self-describing, and it answers three of the four questions I was going
to bring. **Stating them as confirmations, not questions:**

| Was going to ask | Answered by the receipt |
|---|---|
| Ed25519 signed-payload spec | `verificationEnvelope.signedFields` names the covered fields; `canonical.envelope.payload` ships the literal signed bytes; signature is base64url-unpadded (86 chars → 64 bytes); `publicKeyJwk` is OKP/Ed25519. |
| JCS canonicalization agreement | `canonicalization: "jcs"` on both the certificate and the envelope. Same RFC 8785 CAGE uses. |
| Canonical colon form for emitted links | Your own `links.self` and `links.humanVerifier` use `sha256%3A`. CAGE will match your encoding. |

Consequence: the Ed25519 verification work I had scheduled as post-meeting is now
**buildable immediately**, and the JCS question becomes a fixture test rather than
a negotiation. Thank you for making the receipt self-describing — that is what
made the difference.

### The one thing I want to confirm out loud

The receipt embeds its own `publicKeyJwk`. **We will not verify against it.** A
forged receipt controls its entire body including any key it carries, so verifying
against the embedded key proves nothing. CAGE resolves the key by `kid` from
`links.keyManifest` (`/.well-known/nexart-node.json`), cached out-of-band with your
ETag/`304` semantics, and fails closed on an unknown `kid` rather than falling back.

I mention it because the embedded key is the obvious thing for an implementer to
reach for, and I would rather our verification model be explicit in the record.

---

## 3. Status of the integration

| Component | Status |
|---|---|
| Node-boundary callback (6 governance nodes) | ✅ Built, tested |
| `certifyDecision` / `registerProjectBundle` wrappers | ✅ Built, fail-closed |
| RFC 8785 JCS state hashing | ✅ v3.0.0 |
| JWK cache with ETag/`304`, 24h TTL, out-of-band | ✅ Built |
| OSCAL `rel="evidence"` emission | ⚠️ Built, **not wired** |
| Verification fail-open | ✅ **Closed** — invariant-enforced |
| Ed25519 signature verification | ❌ Stub — reports `valid=False` always |
| CER resolver client | ❌ Not built — now unblocked |
| CER → `external_attestations[]` | ❌ Not built — see below |

All of the ❌ items are now unblocked and sequenced. None of them wait on you.

**One correction to the row above.** `CER → external_attestations[]` is not merely
unbuilt — the class does not currently satisfy the interface it would plug into.
`Provider02AttestationProvider` implements neither of CAGE's two seam protocols:
it has no `fetch_attestations()`/`provider_name` (so it is not an
`AttestationProvider`), and no `fetch_baseline`/`validate_fria`/`submit_evidence`
(so it is not a `NormativeProvider`) — yet it is wired into the normative factory
behind a suppressed type error. Anything treating it as a normative provider raises
at runtime.

Entirely our defect, no interface change on your side, and it is sequenced ahead of
the seam work. Noting it because it is the actual blocker on item 7, not the seam
itself.

---

## 4. Ratify in one minute: the node-boundary position

Your position — attest at governance boundaries, not inline — is **already what
the code does**, not something we need to build toward:

- CERs emit only at governance-significant boundaries, after the decision is made.
- The synchronous gate (CBF, consensus, OPA) never calls NexArt. No hot-path
  dependency exists, in either direction.
- Attestation is opt-in, defaults to `false`, zero overhead when disabled.

The separation is structural rather than conventional: the kernel is barred by CI
from importing any integration, so an inline dependency on an evidence provider
could not be introduced accidentally even if someone tried.

**Proposed wording for the record:** *CAGE owns synchronous inline enforcement
(control plane). NexArt owns post-execution cryptographic anchoring at governance
boundaries (evidence plane). Inline signalling is out of scope absent a concrete
deployment requirement.*

Agree verbally and move on — the time is better spent on §5.

---

## 5. Main agenda item: bundle shape mismatch

The substantive gap, and the one thing I most want your read on. But first I need
to correct an impression my earlier notes will have given.

### What CAGE actually is

CAGE is an **application-agnostic governance substrate with zero built-in
applications**. The kernel ([`src/gateway/`](../../src/gateway/)) is domain-neutral
and vendor-neutral, operating on abstract action primitives. It is enforced by CI:
a boundary gate fails the build if kernel code imports a domain plugin or a
reference application.

The **Governed Financial Advisor** — the LangGraph pipeline with
`nemo_guardrail → thinker → doer → evaluator → safety_check → governed_trader` — is
a **Layer 4 demo application**. It exists to prove the substrate works, not to
define it. A Healthcare Clinical Agent traverses the identical kernel with
different domain nouns and no kernel change.

So when I described "a CAGE run" as producing six governance node boundaries with
a bounded `execution_analyst → evaluator` cycle, that was **one demo's graph**, not
CAGE's shape. An adopter's pipeline could be three nodes or thirty, LangGraph or
not. I should have been clearer, and it matters for how we scope this.

### The mismatch, correctly framed

Your bundle is `cer.ai.execution.v1` — a **single model execution**:

```
snapshot: { model, provider, prompt, parameters, inputHash, outputHash, executionId }
```

The general shape CAGE needs to attest is **a governed decision traversing a
control graph of arbitrary topology**:

```
steps[]: { stepId, nodeName, parentStepIds[], stateHash, signals{} }
```

The unit of evidence is not an inference call. It is *a decision, the control
checks applied to it, and the causal path through them*. Two properties hold for
any adopter, not just the finance demo:

1. **Governance events may involve no model call at all.** A fail-closed barrier
   block is among the most evidentially important outcomes we produce, and it has
   no `inputHash`/`outputHash`. `cer.ai.execution.v1` cannot express it.
2. **Causal structure is the evidence.** *Which* checks ran, in what order, and
   which path was taken is precisely what a regulator asks about. Flattening the
   DAG discards the substance.

### A defect on our side, worth naming

Reviewing this, our adapter
([`adapter.py`](../../src/integrations/provider_02/adapter.py:98)) hardcodes the
demo's node names — `_ATTESTATION_NODES` and a `_GRAPH_PARENTS` topology map
literally naming `governed_trader`, `nemo_guardrail`, `execution_analyst`.

That is a Layer 3 integration encoding Layer 4 demo vocabulary, and it means the
adapter as written **only works for the finance demo**. Any other adopter gets
nothing. That is our bug, not yours — the callback should take an injected graph
topology and node-significance predicate rather than hardcoding one application's
graph. I am raising it because it changes what we should ask of your schema: the
right question is what shape works for *any* adopter's control graph, not what
fits our demo.

The failure mode is worth stating precisely, because it is **silent rather than
loud**: `_build_parent_step_ids()` returns empty parent lists for unrecognised
nodes, so a non-finance adopter still gets a bundle — structurally flat, with
`terminalPath: "unknown"` and a provenance DAG that is wrong rather than absent.
Bundles keep flowing and keep verifying; only the causal claim is false. We are
making that fail closed as part of the fix.

Since preparing this brief the defect has been promoted from an observation into a
tracked finding with a sequenced remediation phase, alongside a CI gate that will
fail the build if application vocabulary reappears in an integration package. It is
recorded in
[`plans/layer_inversion_remediation_plan.md`](../../plans/layer_inversion_remediation_plan.md).

**One question for you, and it is the only thing here that touches your side:**
does your validation reject a bundle whose `terminalPath` is `unknown`? If it
accepts them, any bundles we have already sent under a non-finance graph carry
unreliable DAG provenance and we should agree how to mark them.

### Why this matters for the read path

Our `registerProjectBundle` payload does not conform to `cer.ai.execution.v1`.
Resolution and verification (read) are independent of registration (write), so
everything in §3 proceeds regardless — but until the write path is settled, CAGE's
own receipts will not be resolvable through the interface we are building against.

### Options — detailed analysis

Three shapes are available. (c) is a hybrid and is treated last.

---

#### Option (a) — One CER per governance boundary

Each boundary emits an independent `cer.ai.execution.v1`-style receipt. The DAG
stays in CAGE; ordering is reconstructed from the transparency log.

**Pros**

- **Zero schema change on your side.** Shippable this week; no dependency on your
  roadmap.
- **Granular resolution.** An auditor can dereference *one* decision point without
  pulling an entire run. For a long-running agent this is a real advantage.
- **Natural fit for streaming.** Receipts emit as boundaries complete. No need to
  hold state until run completion, which matters for agents that run for hours or
  never formally terminate.
- **Independent redaction scope.** Your confidential-commitment scheme applies
  per-receipt, so one sensitive step does not force redaction decisions across a
  whole run.
- **Partial-run evidence survives.** If a process crashes mid-run, the boundaries
  that completed are already attested. Option (b) loses everything before assembly.

**Cons**

- **Causal structure leaves the evidence layer.** This is the substantive
  objection. `parentStepIds` — which check ran *because of* which prior result — is
  the governance evidence. Under (a) the receipts are individually signed but their
  *relationships* are asserted by CAGE, unsigned. An auditor gets N trustworthy
  facts and one untrustworthy story connecting them.
- **Omission attacks are undetectable.** A malicious or buggy CAGE deployment can
  simply not emit the receipt for an inconvenient boundary. Nothing in the
  remaining receipts reveals a gap, because nothing binds the set. This is the
  strongest argument against (a) as-specified — see the mitigation below.
- **Log ordering is not causal ordering.** Transparency-log index gives *temporal*
  sequence. A DAG with parallel branches or a retry loop is not recoverable from
  timestamps: two concurrent boundaries have no defined order, and a repeated node
  in a loop is indistinguishable from a duplicate.
- **N× receipt volume.** Cost, latency and log growth scale with graph size.
  Modest for six boundaries, less so for a thirty-node adopter pipeline.
- **No atomic run identity.** "Show me everything about decision X" becomes a query
  CAGE must answer, not something the evidence layer can.

**Mitigation that changes the calculus.** CAGE already implements a hash chain —
[`ProvenanceRecord`](../../src/gateway/governance/provenance_chain.py:94) carries
`parent_hash`, with
[`verify_chain_integrity()`](../../src/gateway/governance/provenance_chain.py:220)
walking the links, canonicalized with the same RFC 8785 you use.

If each per-boundary receipt commits to its predecessor's certificate hash, the
causal edges become **signed** rather than asserted, and omission becomes
detectable: removing a receipt breaks the chain. That converts (a)'s two worst
cons into non-issues at essentially no schema cost — the parent hash is just a
field in the snapshot.

It does not fully solve branching (a chain is linear, a DAG is not), but a
`parentHashes[]` list generalizes cleanly.

---

#### Option (b) — A workflow bundle type

`cer.ai.workflow.v1`, whose snapshot is a step DAG rather than a single execution.

**Pros**

- **Causal structure is inside the signature.** The DAG is covered by
  `signedFields`, so edges are cryptographically attested, not asserted. This is
  the property (a) lacks and the reason to prefer (b) on the merits.
- **One receipt per decision.** Atomic identity — a single hash names the whole
  governed decision. Clean for OSCAL `link[rel="evidence"]`, where one control
  finding should reference one artifact rather than fifteen.
- **Tamper-evident as a set.** Omitting a step changes the bundle hash. No
  separate anti-omission mechanism needed.
- **Expresses non-inference events natively.** A barrier block with no model call
  is just a step with different signals — no schema contortion.
- **Likely generalizes.** Any agent framework with branching, retries or
  human-in-the-loop has this shape. LangGraph, and most orchestration frameworks,
  produce DAG traces. This is plausibly a broad market need rather than a CAGE
  accommodation.

**Cons**

- **Schema work on your side, on your timeline.** The critical practical
  objection — it blocks CAGE on your roadmap, and I would not want to design
  around a hypothetical.
- **Unbounded snapshot size.** A thirty-node run with per-step state hashes and
  signals produces a large canonical payload. JCS canonicalization and Ed25519
  signing over megabytes is workable but no longer trivially cheap.
- **Terminal-state semantics get awkward for long-running agents.** A bundle
  implies completion. An agent that runs indefinitely, or is interrupted for human
  approval and resumes days later, has no natural assembly point. Our own HITL
  interrupt already exposes this.
- **All-or-nothing redaction granularity.** With one signature over the whole DAG,
  selective disclosure per step needs care. Your commitment scheme handles it, but
  the design is more involved than per-receipt redaction.
- **Loses partial-run evidence.** Nothing is attested until assembly. A crash
  mid-run yields no receipt at all — precisely the runs where evidence matters most.
- **Requires a schema decision CAGE cannot make unilaterally**, so it cannot be a
  reference-architecture pattern until you ship it.

---

#### Option (c) — Bundle-of-bundles

A parent CER whose snapshot references child certificate hashes plus the edges
between them. Children are ordinary receipts under your existing schema.

**Pros**

- Gets (b)'s central property — **signed causal structure** — with a much smaller
  schema addition, since the parent snapshot is a list of hashes and edges rather
  than a new step type.
- Children remain independently resolvable and independently redactable, keeping
  (a)'s granularity.
- Parent stays small regardless of run size: N hashes, not N state snapshots.
- Composes with your transparency log, which already provides inclusion proofs for
  the children.
- Degrades gracefully: children are attested as they complete, and the parent seals
  the run afterward. A crash leaves valid children and no parent — strictly better
  than (b)'s nothing.

**Cons**

- Two-phase emission is more moving parts than either pure option.
- An auditor must fetch N+1 documents to see the whole picture (though only the
  parent to verify integrity).
- The parent's meaning needs definition: does it assert the run *completed*, or
  merely that these children belong together? These differ materially for
  interrupted runs.
- Still needs a schema decision from you, if a smaller one than (b).

---

### Recommendation

**Primary: (c), with (a)-plus-hash-chaining as the immediate path.**

The reasoning, in order of weight:

1. **Signed causal structure is not optional.** Under (a) as originally specified,
   the DAG is CAGE's unsigned claim. Given that CAGE exists to make governance
   verifiable by parties who do not trust the operator, shipping the causal graph
   as an unattested assertion undermines the point. This rules out plain (a).

2. **But (b) blocks us on your roadmap, and over-commits.** A new bundle type is
   the theoretically cleanest answer and the one most likely to sit unbuilt.
   Meanwhile CAGE's long-running-agent and HITL-resume cases fit (b) poorly — the
   assembly point genuinely does not exist for some adopters.

3. **(c) buys most of (b)'s value for a fraction of the schema change**, and its
   failure mode is the right one: partial evidence rather than none.

4. **(a) + hash chaining is available today and is a strict subset of (c).** Each
   receipt commits to its predecessor's certificate hash. Edges become signed,
   omission becomes detectable, and no schema change is required — the parent hash
   is a snapshot field. When (c)'s parent bundle arrives, the chained children are
   exactly the children it needs. **Nothing is thrown away.**

So: start with (a)+chaining now, converge on (c) when your schema allows.

**Questions this reduces to:**

1. Does a composite or workflow bundle type exist or is one planned? If (c) is
   already on your roadmap, we should design directly against it.
2. If a child CER's snapshot carries `parentCertificateHashes[]`, does that break
   any assumption in your resolver or transparency log? I do not think it should —
   it is opaque snapshot data — but I would rather ask than discover.
3. For (c): would the parent assert run *completion*, or just set membership? This
   matters for interrupted and long-running agents, where completion may never
   occur.

---

## 6. Key rotation

`kid: "k1"` and `scope: "whitelist"` suggest a first key with rotation still ahead.
Since CAGE will fail closed on an unknown `kid`, rotation mechanics matter to us
operationally:

1. When `k2` appears, does `/.well-known/nexart-node.json` serve **both** keys
   through an overlap window, or does it cut over?
2. Are historical CERs signed under a retired `kid` still verifiable — i.e. does
   the manifest retain retired public keys indefinitely?
3. Is there a revocation signal distinct from removal, so we can tell "this key was
   rotated normally" from "this key was compromised"?

Point 2 is the one that matters most for compliance. An OSCAL SSP may be audited
years after issue; if a retired key disappears from the manifest, every CER signed
under it becomes unverifiable and the evidence trail silently rots. Our 24h JWK
cache does not save us there.

---

## 7. Confidential-field commitments — better than expected

`snapshot.confidential` declares `fields: ["input", "output"]`, `scheme:
"hmac-sha256-v1"`, and the canonical payload carries HMAC commitments in place of
values while leaving prompt, model, parameters and timestamps in clear.

This is materially better than the binary public/private model I had assumed, and
it changes our OSCAL disclosure design. A redacted CER **verifies end-to-end** —
signature and certificate-hash binding both check out — while withholding only the
sensitive payload. So it should get a full `link[rel="evidence"]` in the SSP, not
be suppressed. Suppressing it would discard verifiable evidence for no privacy gain.

We are implementing three disclosure states rather than two: `PUBLIC`, `REDACTED`
(link emitted, plus a prop naming the commitment scheme and redacted fields), and
`PRIVATE` (no dereferenceable link). Unknown defaults to `PRIVATE`.

**Questions:**
1. How is the HMAC key managed — per-tenant, per-execution, held by you or by the
   emitting deployment?
2. What is the selective-disclosure flow for an auditor authorized to open a
   specific field? Is that a NexArt-mediated operation or does the deployment
   holding the key do it out of band?

### The 404 question, narrowed

Private and hidden records return `404`, identical to unknown-hash. Correct privacy
design. The compliance wrinkle: an auditor dereferencing a `link[rel="evidence"]`
that `404`s cannot distinguish *fabricated evidence* from *evidence they lack
visibility into*.

Given §7, this is much less pressing than I thought — `REDACTED` covers most of
what I was worried about. For genuinely private CERs we emit a `cer-hash` prop with
no link, which states honestly that evidence exists and is not publicly
dereferenceable. **Just confirm that reading is consistent with your intent.**

---

## 8. Anchors and timestamps — noting, not asking

The receipt carries two anchors CAGE has no model for yet:

- `trustedTimestamps[]` — RFC 3161 token, DigiCert TSA
- `bundle.anchors[]` — transparency log inclusion, `nexart-internal-v1` index 478

Both are stronger evidence than the signature alone. We will capture them verbatim
as opaque metadata and **not** claim we validate them, because we do not. Asserting
unperformed validation is exactly the mistake §1.3 exists to correct.

Worth 2 minutes if there is time: is the transparency log independently auditable,
and is a consistency-proof endpoint planned? That would let CAGE detect log
equivocation rather than trusting the inclusion claim.

---

## 9. Work split coming out of this

| # | Item | Owner |
|---|---|---|
| 1 | Fail-closed correction to the verification stub | CAGE — ✅ **done** |
| 2 | `ContentAddress` primitive; digest agility; `hmac-sha256` commitments | CAGE |
| 3 | CER resolver — exact-hash GET, `If-None-Match`/`304`, error mapping | CAGE |
| 4 | Real Ed25519 verification, key-manifest trust anchor | CAGE |
| 5 | JCS cross-implementation fixture test | CAGE |
| 6 | Wire `cer_uris` so OSCAL links are actually emitted | CAGE |
| 7 | CER → `external_attestations[]` seam | CAGE |
| 7a | **Make the provider satisfy `AttestationProvider`** — prerequisite for 7 | CAGE — new |
| 8 | Document `PROVIDER_02_*` configuration | CAGE |
| 9 | **De-hardcode demo node names from the adapter** (§5) | CAGE — tracked |
| 9a | CI gate rejecting application vocabulary in integration packages | CAGE — new |
| 10 | Bundle shape decision — (a)+chaining now, (c) as target | **Both — §5** |
| 10a | **Chain child receipts via `parentCertificateHashes[]`** — unblocks signed causal edges without schema change | CAGE — new |
| 11 | Key rotation and retired-key retention policy | NexArt — §6 |
| 12 | HMAC key management and selective disclosure | NexArt — §7 |
| 13 | Transparency log auditability | NexArt — §8 |
| 14 | Confirm whether `terminalPath: "unknown"` bundles are accepted | NexArt — §5 |

Items 2–8 are sequenced and start today. Nothing on the CAGE side is waiting.

Item 9 came out of preparing this brief: the adapter hardcodes the finance demo's
graph topology, so it works for exactly one application. It needs an injected
topology and node-significance predicate before any adopter other than our own demo
can use it. Sequencing depends on the §5 outcome — no point generalizing the bundle
assembler before we know what shape it assembles into.

Items 7a and 9a are new since the first draft. 7a is the real blocker on the
attestation seam. 9a exists so that once 9 is fixed it cannot silently regress —
the class of defect matters more than the instance, and a review-only fix would
have let it come back.

Item 10a is the practical output of the §5 analysis. It needs no schema change from
NexArt — a parent certificate hash is opaque snapshot data — and it converts the
causal DAG from CAGE's unsigned assertion into signed, omission-detectable
evidence. CAGE already has the primitive
([`ProvenanceRecord.parent_hash`](../../src/gateway/governance/provenance_chain.py:94),
RFC 8785 canonicalized), so this is wiring, not invention. It is also a strict
subset of option (c): chained children are exactly the children a parent bundle
would later seal, so nothing is wasted if (c) lands.

---

## 10. If we run short

Cut to these three, in order:

1. **§5 bundle shape.** The only genuine architectural gap. Reduce it to two
   questions if pressed: *does a composite/workflow bundle type exist or is one
   planned*, and *does a child snapshot carrying `parentCertificateHashes[]` break
   anything on your side*. A "no, it's opaque" on the second unblocks CAGE
   immediately regardless of the first. Also slip in the `terminalPath: "unknown"`
   acceptance question — ten seconds, and it determines whether previously sent
   bundles need marking.
2. **§6 key rotation, specifically retired-key retention** — silent long-term
   evidence rot if we get it wrong.
3. **§7 confidential commitments** — changes our OSCAL disclosure model.

Everything else can go to email.

---

## 11. What I am not asking you for

Stating this explicitly so the session does not drift into work that is ours:

- **Ed25519 verification, the resolver client, the OSCAL wiring, the attestation
  seam, and the node-name de-hardcoding are all CAGE-side.** None is blocked on
  NexArt. Your receipt already carries everything needed.
- **The verification fail-open is closed.** Raised previously as in flight; it has
  landed and is enforced by an invariant.
- **The bundle-shape question is genuinely open**, and I am not asking you to adopt
  option (c). I lean that way, but the constraint I cannot see from outside is what
  your schema and transparency log make cheap.

The single decision I would like to leave with is §5. Everything else is either
confirmation or ours.

---

## Pre-call checklist

- [x] Verify adapter class names and module paths — corrected
- [x] Verify the OSCAL CER link implementation — exists, unwired
- [x] Verify ETag/`304` handling — JWK sync only, not CER resolution
- [x] Verify hot-path isolation — confirmed, no kernel dependency
- [x] Retrieve and analyse a live CER — done; settles D3, Q1, D1b
- [x] Re-verify §1 claims against the tree — §1.3 fail-open now closed; brief updated
- [x] Confirm `cer_uris` is still unwired — confirmed, no production caller passes it
- [ ] Re-dereference the URI in both colon forms; capture response headers
- [ ] Have [`oscal_exporter.py:207`](../../src/compliance_bridge/oscal_exporter.py:207)
      and [`provider.py:289`](../../src/integrations/provider_02/provider.py:289)
      open — both come up directly
- [ ] Have [`adapter.py:102`](../../src/integrations/provider_02/adapter.py:102)
      open — the hardcoded node list, if §5 gets concrete
