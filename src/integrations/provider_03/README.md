# Provider 03 — Decision Governance & Bind Receipt Provider (Synchronous Gate)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint** — every URL below is a placeholder. Adopters
> should treat this as an integration pattern to adapt, not a hosted service.

| Property | Value |
|---|---|
| Protocol | [`NormativeProvider`](../../gateway/governance/normative_provider.py:273) |
| Integration style | Synchronous gate, remote HTTP, on the request hot path |
| Class | `Provider03NormativeProvider` ([`provider.py`](provider.py:62)) |
| Status | `INTERFACE READY` — HTTP client fully implemented; no endpoint configured |
| Factory names | `provider_03`, alias `p03` |
| Conformance suite | Registered in `NORMATIVE_PROVIDERS` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:48)) |

## Endpoints

Base URL from `PROVIDER_03_NORMATIVE_ENDPOINT` (placeholder:
`https://api.example.com/normative`). Auth is `Authorization: Bearer <key>`
from `PROVIDER_03_NORMATIVE_API_KEY_SECRET`. Timeout defaults to 5s
(`PROVIDER_03_NORMATIVE_TIMEOUT_SECONDS`).

Note the paths differ from Provider 01's — same protocol, different wire layout.

| Method | Path | Protocol method | Returns |
|---|---|---|---|
| `GET` | `/baseline/{region}` | `fetch_baseline()` | `NormativeBaseline` |
| `POST` | `/validate` | `validate_fria()` | `ValidationResult` |
| `POST` | `/evidence/{thread_id}` | `submit_evidence()` | `EvidenceSeal` |

## Verdict vocabulary

The field is **`verdict`**, not `decision`. It is upper-cased before comparison
in [`validate_fria()`](provider.py:190).

| `verdict` | `admitted` | Finding code | Effect |
|---|---|---|---|
| `APPROVED` | `True` | *(vendor `findings` passed through unchanged)* | Admitted |
| `ESCALATE` | `False` | `provider_03.escalate` (severity `review`) | `needs_human_review: True` → parks in `DeferQueue`; vendor findings appended |
| `REJECTED` | `False` | *(vendor `findings` passed through unchanged)* | Hard deny |
| Anything else, including absent | `False` | *(vendor `findings`, possibly empty)* | Hard deny — falls into the same `else` branch as `REJECTED` |

Two properties worth flagging to an implementer:

- **Unknown verdicts are silently treated as `REJECTED`.** There is no distinct
  parse-error path here — [`provider.py:217`](provider.py:217) is a catch-all
  `else`. This is fail-closed, but a typo in the verdict string will not be
  distinguishable from a genuine rejection in the findings.
- **A missing `verdict` key** resolves to `""` and lands in the same branch.

> This vocabulary is `APPROVED`/`ESCALATE`/`REJECTED` — it is not Provider 01's
> `ALLOW`/`REFUSE`/`ESCALATE`, and not Provider 06's `PASS`/`REVIEW`/`BLOCKED`.
> Only the `ESCALATE` token is shared with Provider 01, and only Provider 03
> and Provider 01 use it at all.

## Fail-closed behavior

| Condition | Finding code | Severity |
|---|---|---|
| Endpoint not configured | `ENDPOINT_ERROR` | `blocked` |
| Non-2xx status | `ENDPOINT_ERROR` | `blocked` |
| Transport error / timeout | `ENDPOINT_ERROR` | `blocked` |

`fetch_baseline()` additionally handles a JSON decode failure explicitly,
returning a `NormativeBaseline` with `error` populated
([`provider.py`](provider.py:125)).

## Extension method

`ingest_bind_receipt(receipt)` ([`provider.py`](provider.py:299)) is a
**Provider 03-specific** method outside the `NormativeProvider` protocol. It
canonicalizes a bind receipt with RFC 8785 JCS and returns its SHA-256 hex
digest.

## Wire contract change in the backward-compatibility remediation

**No change to the request/response wire shape.** Two changes affected callers
on the CAGE side:

- **BC-02** removed three dict-returning compatibility aliases —
  `fetch_legal_baseline()`, `validate_external_fria()`, `submit_evidence_chain()`.
  Callers must use the canonical protocol methods and read dataclass fields.
  `validate_external_fria()` had returned a hardcoded `APPROVED`, so switching
  to `validate_fria()` may surface previously invisible rejections.
- `ingest_bind_receipt()` migrated to JCS, changing the digest values it
  returns.

Both are documented in
[`docs/BREAKING_CHANGES_v3.md`](../../../docs/BREAKING_CHANGES_v3.md).

## Vendor isolation

Lazy-loaded by `get_normative_provider()`. Note that unlike Provider 01, this
module imports `jcs_canonicalize_plan` from the kernel at module top level
([`provider.py`](provider.py:48)); kernel dataclasses are still deferred to
call time.
