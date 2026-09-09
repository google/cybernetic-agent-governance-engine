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

### Framing

CAGE is an Apache 2.0 **reference architecture**, not a deployed service. Provider
integrations are anonymized in-repo (`provider_02`) and carry no configured live
endpoint. Everything here is an integration pattern for adopters to adapt.
Breaking changes are cheap; structural clarity beats operational continuity.

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

**3. Our signature verification does not verify signatures.**
[`_verify_local()`](../../src/integrations/provider_02/provider.py:274) checks that
the JWK cache is non-empty and that the hash is 64 characters, then returns
`valid=True`. No signature is checked. It is a fail-open in an attestation path,
and it is being fixed as a standalone PR before anything else — that work does not
depend on you.

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
| Ed25519 signature verification | ❌ Stub — fix in flight |
| CER resolver client | ❌ Not built — now unblocked |
| CER → `external_attestations[]` | ❌ Not built |

All of the ❌ items are now unblocked and sequenced. None of them wait on you.

---

## 4. Ratify in one minute: the node-boundary position

Your position — attest at governance boundaries, not inline — is **already what
the code does**, not something we need to build toward:

- CERs emit on `on_chain_end` at six governance-significant nodes only.
- The synchronous gate (CBF, consensus, OPA) never calls NexArt. No hot-path
  dependency exists, in either direction.
- Attestation is opt-in, defaults to `false`, zero overhead when disabled.

**Proposed wording for the record:** *CAGE owns synchronous inline enforcement
(control plane). NexArt owns post-execution cryptographic anchoring at governance
node boundaries (evidence plane). Inline signalling is out of scope absent a
concrete deployment requirement.*

Agree verbally and move on — the time is better spent on §5.

---

## 5. Main agenda item: bundle shape mismatch

This is the substantive gap, and it is the one thing I most want your read on.

### The problem

Your bundle is `cer.ai.execution.v1` — a **single model execution**:

```
snapshot: { model, provider, prompt, parameters, inputHash, outputHash, executionId }
```

CAGE's [`AttestationBundle`](../../src/integrations/provider_02/adapter.py:161) is a
**multi-step governance DAG**:

```
steps[]: { stepId, nodeName, parentStepIds[], stateHash, signals{} }
terminalPath: happy_path | nemo_block | cbf_block | loop_breaker
```

Our unit of evidence is *a governed decision traversing a control graph*. Yours is
*an inference call*. A CAGE run produces up to six governance-significant node
boundaries, with a genuine DAG between them — including a bounded cycle
(`execution_analyst → evaluator → execution_analyst`) and four distinct terminal
paths, one of which is a fail-closed CBF block where **no model call happens at
all**.

That last case is the sharpest illustration: a CBF block is one of our most
evidentially important outcomes, and it has no `inputHash`/`outputHash` to report.
It does not fit `cer.ai.execution.v1` in any natural way.

### Why this matters for the read path

Right now our `registerProjectBundle` payload does not conform to
`cer.ai.execution.v1`. Resolution and verification (read) are independent of bundle
registration (write), so everything in §3 proceeds regardless — but if we do not
settle the write path, CAGE's own receipts will not be resolvable through the same
interface we are building against.

### Options I can see

**(a) One CER per governance node, linked externally.** Each boundary produces its
own receipt; the DAG lives in CAGE and the transparency log provides ordering.
Fits your existing schema unchanged. Costs: six receipts per decision, and the
causal structure — which is the actual governance evidence — lives outside the
attestation layer.

**(b) A workflow bundle type — `cer.ai.workflow.v1` or similar.** A bundle whose
snapshot is a DAG of steps rather than a single execution. Cleanest fit for what
CAGE produces. Costs: schema work on your side, and it is only worth it if other
adopters have the same shape. I suspect any agent framework with branching does.

**(c) Bundle-of-bundles.** A parent CER whose snapshot references child certificate
hashes. Composes with what you have, and the transparency log already gives you
inclusion proofs for the children.

I lean toward **(c)** as the lowest-schema-change path that still keeps causal
structure inside the evidence layer, but I have no strong view and you know your
schema's constraints. **Question:** does a workflow or composite bundle type exist
or is one planned, or is (a) the intended pattern?

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
| 1 | Fail-closed correction to the verification stub | CAGE — in flight |
| 2 | `ContentAddress` primitive; digest agility; `hmac-sha256` commitments | CAGE |
| 3 | CER resolver — exact-hash GET, `If-None-Match`/`304`, error mapping | CAGE |
| 4 | Real Ed25519 verification, key-manifest trust anchor | CAGE |
| 5 | JCS cross-implementation fixture test | CAGE |
| 6 | Wire `cer_uris` so OSCAL links are actually emitted | CAGE |
| 7 | CER → `external_attestations[]` seam | CAGE |
| 8 | Document `PROVIDER_02_*` configuration | CAGE |
| 9 | Bundle shape decision — (a), (b) or (c) | **Both — §5** |
| 10 | Key rotation and retired-key retention policy | NexArt — §6 |
| 11 | HMAC key management and selective disclosure | NexArt — §7 |
| 12 | Transparency log auditability | NexArt — §8 |

Items 1–8 are sequenced and start today. Nothing on the CAGE side is waiting.

---

## 10. If we run short

Cut to these three, in order:

1. **§5 bundle shape** — the only genuine architectural gap. Everything else is
   either settled or CAGE-side work.
2. **§6 key rotation, specifically retired-key retention** — silent long-term
   evidence rot if we get it wrong.
3. **§7 confidential commitments** — changes our OSCAL disclosure model.

Everything else can go to email.

---

## Pre-call checklist

- [x] Verify adapter class names and module paths — corrected
- [x] Verify the OSCAL CER link implementation — exists, unwired
- [x] Verify ETag/`304` handling — JWK sync only, not CER resolution
- [x] Verify hot-path isolation — confirmed, no kernel dependency
- [x] Retrieve and analyse a live CER — done; settles D3, Q1, D1b
- [ ] Re-dereference the URI in both colon forms; capture response headers
- [ ] Have [`oscal_exporter.py:207`](../../src/compliance_bridge/oscal_exporter.py:207)
      and [`provider.py:274`](../../src/integrations/provider_02/provider.py:274)
      open — both come up directly
