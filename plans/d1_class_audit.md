# D1-class audit — does untrusted input select its own validation path?

> **Scope:** `src/`, static review. Four findings, one of which is a live
> authentication bypass.
> **Origin:** the D1 defect in
> [`issue_107_pr2_registry_signing_plan.md`](issue_107_pr2_registry_signing_plan.md) §12 —
> `_load_registry()` gated verification on `if version == "2.0":`, so an
> attacker set `"version": "1.0"` and disabled the control protecting the file.
> **Status:** findings are **static, not yet demonstrated by exploit or
> mutation**. Each carries a proposed falsification test; none has been run.

---

## The shape being hunted

> A field inside an untrusted document determines whether, or how strictly,
> that document is validated.

Three variants, in descending order of how obvious they are in review:

1. **Explicit gate** — `if doc["version"] == X: verify()`. The original D1.
2. **Permissive default** — `doc.get("signature", "")`, where absent reads as
   empty and empty reads as acceptable somewhere downstream.
3. **Unenforced field** — a field the document declares, which the verifier
   parses but never checks. Looks like validation; is decoration.

Variant 3 is the hardest to see: the field's presence in the dataclass implies
it is enforced, and nothing contradicts that until you grep for its use.

---

## Finding A — envelope `expires_at` is never checked (variant 3)

**Severity: high.** `GovernanceEnvelope` carries `expires_at`
([`governance_envelope.py:239`](../src/gateway/governance/governance_envelope.py:239)),
set to `now + TTL` at build
([:396](../src/gateway/governance/governance_envelope.py:396)) and included in
the signed digest.

[`verify()`](../src/gateway/governance/governance_envelope.py:504) checks the
signature and **nothing else**. It never compares `expires_at` to the clock.

A search across `src/gateway/governance` for `envelope.expires_at`,
`is_expired`, or any comparison of that field returns **no verification-side
use** — the only `is_expired()` in the codebase belongs to
[`jwks.py`](../src/gateway/governance/jwks.py:161), which is JWKS key cache
expiry, an unrelated mechanism.

**Consequence.** A governance envelope is a bearer credential asserting that a
specific action passed specific tiers. Because it is signed, it is tamper-proof;
because its expiry is unenforced, it is **valid forever**. Anyone who captures
one — logs, evidence stream, a compromised downstream consumer — can replay it
indefinitely. The 30-second TTL exists in the data model and nowhere in the
enforcement.

Note the contrast with two sibling components that *do* get this right:
[`ConsequenceToken.verify()`](../src/gateway/governance/consequence_token.py:296)
checks `exp` **before** the signature, and the FTRA registry verifier checks
`expires_at` outside its digest cache precisely so a cached signature verdict
cannot serve an expired registry
([`registry_verifier.py`](../src/gateway/governance/ftra/registry_verifier.py)).
The envelope path is the odd one out, which is what makes this look like an
omission rather than a decision.

**Proposed fix.** Check expiry in `verify()`, before signature verification —
cheap check first, and an expired envelope should report `EXPIRED`, not burn a
crypto operation. Return a reason code rather than a bare `False`, for the same
reason the registry verifier does: an operator needs to tell clock skew from
forgery.

**Falsification test.** Build an envelope with `ttl_s=1`, sleep 2s, verify.
Currently returns `True`. Must return `False` with an expiry-specific reason.

---

## Finding B — `_envelope_from_dict` invents defaults for absent security fields (variant 2)

**Severity: medium**, and it is the mechanism that makes Finding A worse.

[`_envelope_from_dict()`](../src/gateway/governance/governance_envelope.py:603)
reconstructs an envelope from an untrusted dict using `.get()` with defaults
throughout:

| Field | Default when absent | Why it matters |
|---|---|---|
| `expires_at` | `""` | empty string; with Finding A fixed, must not parse as "never expires" |
| `envelope_version` | `_ENVELOPE_VERSION` | a v1 envelope is silently relabelled current |
| `signature.algorithm` | `"ES256"` | attacker-supplied field, though see below |
| `governance_context.tiers_passed` | `[]` | absent reads as "no tiers claimed" |
| `deployment_region` | `_DEPLOYMENT_REGION` | **an envelope from another region is silently relabelled as local** |

Defaults are correct for a *builder*. For a *parser of untrusted input* they
convert "the field is missing" into "the field says what we expected", which is
the same substitution D1 made.

The `deployment_region` default is the sharpest: an envelope issued in one
regulatory region, parsed in another, is relabelled to the parsing region before
any check sees it. Given the region-guard work in this repository, that default
deserves to be a rejection.

**Mitigating factor — and its limit.** These fields are inside the signed
digest, so an attacker cannot *change* them without breaking the signature. The
risk is not tampering; it is **absence being normalised into assertion** on a
path that also decides whether a signature is required at all. If `verify()` is
ever called after a partial parse, or a caller trusts the reconstructed object
without verifying, the defaults become load-bearing.

**Proposed fix.** Split parsing from construction: `_envelope_from_dict` should
reject absent security-relevant fields rather than default them. Keep defaults
only for genuinely optional metadata.

**Falsification test.** Parse `{}`. Currently yields a well-formed envelope
claiming the current version and local region. Must raise.

---

## Finding C — `signature.algorithm` is parsed from the document and never used

**Severity: low as written; a trap for the next contributor.**

[`:632`](../src/gateway/governance/governance_envelope.py:632) reads
`algorithm` from the untrusted `signature` block, defaulting to `"ES256"`.

[`verify()`](../src/gateway/governance/governance_envelope.py:562) then selects
its verification path by **inspecting the loaded public key type** — `ec`,
`ed25519`, `rsa` — and ignores `signature.algorithm` entirely.

**This is currently correct**, and for the right reason: the algorithm derives
from the trusted key, not the untrusted document. That is exactly the property
D1 lacked.

The hazard is that the field *exists*, is populated from attacker-controlled
input, and sits one plausible refactor away from being used — "we already parse
the algorithm, let's dispatch on it" is a natural-looking change that would
introduce textbook algorithm confusion.

Compare [`ConsequenceToken.verify()`](../src/gateway/governance/consequence_token.py:265),
which reads the header `alg` but only to **compare it against the signer's
expected algorithm** and reject a mismatch. That is the pattern: read the
claimed value, never trust it, use it solely to detect disagreement.

**Proposed fix.** Either apply the ConsequenceToken pattern — compare
`signature.algorithm` against the algorithm implied by the resolved key and
reject a mismatch — or delete the field from the parse path. Do not leave it
parsed-but-unused.

---

## Finding D — reconciliation snapshot signature defaults to empty (variant 2)

> **TRACED 2026-09-02 — reclassified. The empty-string bypass does not exist,
> because no bypass is possible: nothing verifies the signature at all.**
>
> `reconciliation:signature` is written to Redis by the daemon
> ([`daemon.py:1150`](../src/gateway/governance/reconciliation/daemon.py:1150))
> and **read by nothing**. A repository-wide search for
> `_REDIS_KEY_SIGNATURE`, `reconciliation:signature` and `kms_signature`
> returns writers only — no reader, no `verify()` call on that value.
> `cbf.py` contains no signature handling whatsoever, despite
> [`daemon.py:532`](../src/gateway/governance/reconciliation/daemon.py:532)
> documenting a "CBF read-path overhead: KMS verify ≈ 0.1-0.5 ms".
>
> So the `.get("signature", "")` default is harmless *as written* — the value
> is inert. But the underlying control is weaker than the audit assumed: the
> reconciled balance the CBF acts on is **not signature-checked on read**. That
> is variant 3, not variant 2 — an unenforced field, the same shape as Finding
> A, and it makes the daemon's KMS signing decorative.
>
> **Not fixed in this pass.** Adding read-path verification changes CBF
> behaviour and needs its own design; the balance is a fail-closed input, so
> the impact of getting it wrong is a trading halt. Recorded here and carried
> as a separate item rather than bolted onto an envelope-hardening change.
> Correcting my earlier framing: I called this "needs confirmation" and it
> needed tracing, which is now done.

**Original assessment (superseded):**

[`daemon.py:205`](../src/gateway/governance/reconciliation/daemon.py:205)
deserialises a balance snapshot from Redis with
`signature=data.get("signature", "")`.

An absent signature becomes `""`. Whether that is exploitable depends entirely
on the consumer: if any code treats empty-string as "unsigned, therefore skip
verification", this is D1 in a different file. `KMSGovernanceSigner.verify()`
returns `False` for an empty signature
([`kms_signer.py:881`](../src/gateway/governance/kms_signer.py:881)), which is
the correct behaviour — but only if the consumer calls it rather than
short-circuiting on the empty string first.

**I have not traced every consumer**, so this is recorded as *unconfirmed*
rather than asserted. Establishing it needs a read of the reconciliation
verification path.

**Falsification test.** Write a snapshot to Redis with no `signature` key; drive
the reconciliation path; confirm it is rejected rather than accepted-as-unsigned.

---

## Cleared

- **[`ConsequenceToken.verify()`](../src/gateway/governance/consequence_token.py:219)** —
  clean, and the reference implementation for this class of defect. Rejects
  `alg: none`, derives `expected_alg` from the signer, rejects mismatch, checks
  `exp` and `iat` before verifying, fails closed on a missing public key.
- **[`kms_signer.py`](../src/gateway/governance/kms_signer.py:500)** — the `alg`
  string mapping is driven by the **KMS key metadata**, not by any document.
- **[`registry_verifier.py:193`](../src/gateway/governance/ftra/registry_verifier.py:193)** —
  reads `version` from the untrusted registry, but on the trusted side of the
  boundary: a mismatch is `ENVELOPE_INVALID`, never a skip. This is the fixed D1.

---

## Priority

| # | Finding | Severity | Why this order |
|---|---|---|---|
| A | envelope expiry unenforced | **high** | live replay of a bearer credential; the TTL is fictional |
| B | parser defaults for absent fields | medium | enables A; region relabelling is independently wrong |
| D | reconciliation empty signature | unknown | cheap to confirm, cannot be sized until traced |
| C | parsed-but-unused `algorithm` | low | correct today, one refactor from algorithm confusion |

---

## Method note, and its limits

This audit is **static**. Findings A–D are read from the code, not demonstrated.
The D1 experience argues against trusting that: D1–D4 were also identified
statically and correctly, yet the *fix* was reported complete when three of the
four had not been applied — and a mutation was recorded as passing against a
guard that did not exist.

So the same discipline applies here. Each finding above carries a falsification
test, and **none of them has been run**. Until Finding A's test is observed
failing against current code and passing against a fix, "envelope expiry is
unenforced" is a well-supported reading, not a verified fact.

Recommended sequence per finding: write the falsification test → observe it fail
→ fix → observe it pass → mutate the fix → observe the test fail again. The last
step is the one that catches an unfalsifiable guard, and it is the step both M1
and M-B skipped.

---

## Implementation constraints found while scoping the fixes

Two facts that will shape the fixes, recorded now rather than discovered
half-way through — the R2 lesson, where a 19-site estimate turned out to be 26.

### Fix A — the 30-second TTL may be shorter than real verification latency

`_ENVELOPE_TTL_S` defaults to 30s. Enforcing expiry means **any** consumer that
verifies more than 30 seconds after issuance starts failing. Whether that
happens is an empirical question about the evidence-stream and reconciliation
paths, not something to assume either way.

Before enforcing, measure the issue→verify interval on every path that calls
`verify()`. If any legitimate path exceeds the window, the fix is to raise the
TTL to a defensible value **and say why**, not to skip the check. A TTL chosen
to make tests pass is not a security control.

Expect the same shape of surprise as R2: the true blast radius is measured, not
estimated.

### Fix B — `to_dict()` legitimately omits a field, so "reject all absences" is wrong

[`to_dict()`](../src/gateway/governance/governance_envelope.py:265) omits
`external_attestations` entirely when the list is empty, and
[`test_envelope_to_dict_omits_empty_attestations`](../tests/test_governance_envelope.py:737)
pins that as deliberate backward-compat behaviour.

So `_envelope_from_dict` cannot simply reject every missing key — it would break
the round-trip its own callers depend on, including the tamper-detection tests
at [`test_provider_05_synthetic_poc.py:282`](../tests/test_provider_05_synthetic_poc.py:282).

The fix must distinguish two categories explicitly:

| Category | Fields | On absence |
|---|---|---|
| **Security-relevant** | `envelope_version`, `expires_at`, `issued_at`, `deployment_region` | **reject** |
| **Genuinely optional** | `external_attestations`, `record_hash`, `agent_id` | default is correct |

Note also that `_ENVELOPE_VERSION` is `"2.1"` while the module docstring and
several tests still say `"2.0"`. Whatever strictness is applied to
`envelope_version`, that inconsistency needs resolving first — otherwise the
rejection rule will fire on the repository's own envelopes.
