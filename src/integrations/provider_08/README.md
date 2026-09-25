# provider_08 — Verdict Runtime Evidence Normative Provider (Layer 3)

**Adapter Type**: Synchronous Normative Provider + external evidence custody
**Regulatory Scope**: EU AI Act Arts. 9, 12, 14, 26; DORA Art. 10; ISO/IEC 42001 §A.6.1 / §A.9.4; NIST AI RMF; MAS FEAT
**Architecture Layer**: Layer 3 (Integrations & Rails)
**Status**: `INTERFACE READY` — HTTP client and wire models implemented; live endpoint at `https://verdict.systems/api/cage` (public sandbox tier)

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized in code. This adapter
> ships with a **placeholder default endpoint** (`http://localhost:8088`) so the
> conformance suite is hermetic; the vendor's production base URL is set by the
> adopter through the environment.
>
> **Naming note:** The vendor for this integration is **Verdict Systems**
> (`verdict.systems`). The package path `provider_08` is retained for import
> stability across branches and test fixtures.

---

## Overview

Verdict is a runtime-evidence layer: it holds sealed governance records
**outside the system that produced them** and anchors every record commitment
to the public Sigstore Rekor transparency log. Under the `NormativeProvider`
seam it supplies three things to a CAGE deployment:

1. **Normative Data Supply** — the regional control-mapping profile
   (`US_FED`, `EU_ECB`, `APAC_MAS`) served under a strong ETag equal to the
   SHA-256 of the canonical profile, so `NormativeDaemon` change detection works
   on either the ETag or `profile_hash`.
2. **External Validation** — a synchronous, structural FRIA gate over CAGE's
   `action_context`. It answers `ALLOW` / `REFUSE` / `ESCALATE` with
   OSCAL-vocabulary findings and a deterministic `authority_record_id`. It checks
   record-completeness (thread id, action, action digest, actor attribution,
   policy version, human-oversight marker for high consequence ceilings); it does
   **not** adjudicate the substance of the action and says so in every response
   (`SUBSTANTIVE_REVIEW_NOT_EVALUATED`).
3. **Attestation Logging** — seals CAGE's JCS/SHA-256 evidence digest into a
   Sealed Evidence Record and returns the record commitment as `seal_hash`,
   alongside the Rekor anchor and a public verify URL.

| Property | Value |
|---|---|
| Protocol | [`NormativeProvider`](../../gateway/governance/seams/normative.py) |
| Integration style | Synchronous gate, remote HTTPS, on the request hot path (5 s default timeout) |
| Class | `Provider08NormativeProvider` ([`adapter.py`](adapter.py)) |
| Factory names | `provider_08`, aliases `p08`, `verdict`, `verdict_systems` |
| Conformance suite | Registered in `NORMATIVE_PROVIDERS` (`tests/test_normative_provider_conformance.py`) |
| Wire models | Pydantic v2 ([`schema.py`](schema.py)) |

---

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PROVIDER_08_ENDPOINT` | no | falls back to `CAGE_NORMATIVE_ENDPOINT`, then `http://localhost:8088` | Base URL, e.g. `https://verdict.systems/api/cage` |
| `PROVIDER_08_API_KEY` | prod | falls back to `CAGE_NORMATIVE_API_KEY_SECRET` | Bearer key issued by Verdict per deployment |
| `PROVIDER_08_TIMEOUT_SECONDS` | no | `5.0` | HTTP timeout for all three calls |
| `PROVIDER_08_REQUIRE_ANCHOR` | no | `false` | `true` → `submit_evidence` fails closed when Verdict reports the Rekor anchor as deferred |

Minimal production configuration:

```bash
CAGE_NORMATIVE_PROVIDER=provider_08
CAGE_NORMATIVE_ENDPOINT=https://verdict.systems/api/cage
CAGE_NORMATIVE_API_KEY_SECRET=<key issued by Verdict>
```

---

## Fail-Closed Behavior Specification

| Condition | `admitted` | Finding code | Severity |
|---|---|---|---|
| `ALLOW` + ConsequenceToken minted | `True` | `CONSEQUENCE_TOKEN` (+ Verdict findings) | info |
| `ALLOW` + mint failed (no signer / missing fields) | `False` | `CONSEQUENCE_TOKEN_MINT_FAILED` | blocked |
| `REFUSE` | `False` | `PROVIDER_08_REFUSE` | blocked |
| `ESCALATE` | `False` | `EXTERNAL_HOLD` (`needs_human_review=True`, `hold_ttl_seconds` from Verdict, default 300) | review |
| HTTP 4xx/5xx, timeout, connection error | `False` | `ENDPOINT_ERROR` | blocked |
| Unknown / missing `decision`, schema violation | `False` | `PARSE_ERROR` | blocked |
| `fetch_baseline` failure | `is_valid=False` | `NormativeBaseline.error` set | — |
| `submit_evidence` failure | — | `EvidenceSeal.error` set | — |
| Anchor deferred with `PROVIDER_08_REQUIRE_ANCHOR=true` | — | `EvidenceSeal.error = PROVIDER_08_ANCHOR_DEFERRED: <reason>` | — |

Every Verdict finding is passed through with `"provider": "provider_08"` so the
evidence stream records what the external gate saw, not only the verdict.

---

## Wire Protocol Summary

### Baseline: `GET /legal-baseline/{region}` (no key required)

```json
{
  "region": "EU_ECB",
  "provider": "verdict.systems",
  "profile": { "...": "upstream CAGE profile plus _provider/_upstream_* keys" },
  "profile_sha256": "<sha256 of sorted-key canonical profile>",
  "authority_state_version": "EU_ECB:<first 16 hex of profile_sha256>",
  "schema_version": "1.1.0",
  "issued_at": "2026-09-19T00:00:00.000Z"
}
```

Headers: `ETag: "<profile_sha256>"`, `Cache-Control: public, max-age=300, must-revalidate`; `If-None-Match` → `304`.

### Gate: `POST /validate/fria` (Bearer)

Request body: CAGE's `action_context`, unchanged. Response:

```json
{
  "decision": "ALLOW | REFUSE | ESCALATE",
  "admitted": true,
  "message": "…",
  "findings": [{ "code": "RECORD_THREAD_ID", "status": "pass", "severity": "info", "message": "…", "control_id": "CTRL_TEL_003", "reference": "EU AI Act Art. 12" }],
  "region": "EU_ECB",
  "authority_record_id": "vfria_<32 hex>",
  "authority_state_version": "EU_ECB:<16 hex>",
  "validation_hash": "<64 hex>",
  "validated_at": "…",
  "hold_ttl_seconds": 300
}
```

### Seal: `GET /evidence-chain/{thread_id}?evidence_hash=<64 hex>` (Bearer)

```json
{
  "thread_id": "…",
  "evidence_hash": "<64 hex>",
  "seal_hash": "<record commitment, 64 hex>",
  "seal_status": "RECORDED | RECORDED_ANCHOR_DEFERRED",
  "timestamp": 1800000000.5,
  "evidence_record_id": "ser_<32 hex>",
  "transparency_anchor": { "status": "anchored", "rekor_log_index": 42, "rekor_url": "…" },
  "verify_url": "https://verdict.systems/verify?…"
}
```

---

## Testing Strategy

### Unit Tests (Hermetic, `pytest.mark.unit + pytest.mark.local + pytest.mark.partner`)

`tests/integrations/provider_08/test_provider_08_adapter.py` — respx-mocked
coverage of every row in the fail-closed table, header propagation, and
`from_env()` precedence.

```bash
uv run pytest tests/integrations/provider_08 tests/test_normative_provider_conformance.py -m "unit or local" -q
```

### Live smoke (manual, needs a key)

```bash
curl -s https://verdict.systems/api/cage | jq .
curl -sI https://verdict.systems/api/cage/legal-baseline/EU_ECB | grep -i etag
```

---

## File Structure

```
src/integrations/provider_08/
├── __init__.py     — public exports
├── adapter.py      — Provider08NormativeProvider
├── schema.py       — Pydantic v2 wire models
└── README.md       — this file
tests/integrations/provider_08/
└── test_provider_08_adapter.py
docs/partners/provider_08/
└── VERDICT_PARTNER_SPECIFICATION.md
```

## References

- Verdict integration guide: https://verdict.systems/integrations/cage
- Sealed Evidence Record specification (Apache-2.0): https://github.com/Icon369/ser-spec
- Sigstore Rekor: https://docs.sigstore.dev/logging/overview/
