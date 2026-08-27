# PII Scrubbing Policy — CAGE Compliance Bridge

**Document:** AI600-002 / NIST AI 600-1 §2.2 / GDPR Art. 25 Data Minimisation
**Date:** 2026-06-23
**Status:** Active
**POAM:** AI600-002

---

## Purpose

This policy documents the Personally Identifiable Information (PII) scrubbing approach for Langfuse audit traces in the CAGE compliance bridge. It satisfies:

- **NIST AI 600-1 §2.2** — Data Privacy controls
- **GDPR Art. 25** — Data protection by design and by default (EU_ECB deployments)
- **MAS Notice 655 §9** — Customer data protection (APAC_MAS deployments)
- **ISO 42001 §A.6** — Data lineage and PII leak mitigation

---

## Scope

This policy applies to all Langfuse trace data emitted by:

1. **Gateway** (`src/gateway/server/governance_middleware.py`) — input/output spans for every governed request
2. **Compliance bridge** (`src/compliance_bridge/audit_workflow.py`) — audit finding spans
3. **Governed financial advisor** (`src/governed_financial_advisor/`) — financial advisory request spans

---

## PII Scrubbing Architecture

CAGE uses **two complementary scrubbing layers**:

### Layer 1: Pre-Ledger Regex Sanitization (`pii_sanitizer.py`)

The `PIISanitizer` class applies **8 regex patterns** plus a **key-based denylist** to all UCA compliance records **before** they are written to the WORM audit ledger:

| Pattern | Replacement | Example |
|---|---|---|
| US Social Security Number (SSN) | `[REDACTED_SSN]` | `123-45-6789` → `[REDACTED_SSN]` |
| Credit card numbers (Visa, MC, Amex, Discover) | `[REDACTED_CC]` | `4111-1111-1111-1111` → `[REDACTED_CC]` |
| IBAN (international bank account) | `[REDACTED_IBAN]` | `GB82WEST12345698765432` → `[REDACTED_IBAN]` |
| SWIFT/BIC code | `[REDACTED_SWIFT]` | `BOFAUS3N` → `[REDACTED_SWIFT]` |
| Email address | `[REDACTED_EMAIL]` | `user@example.com` → `[REDACTED_EMAIL]` |
| Phone number (US/international) | `[REDACTED_PHONE]` | `+1 (555) 867-5309` → `[REDACTED_PHONE]` |
| API keys / Bearer tokens | `[REDACTED_API_KEY]` | `pk-lf-abc123...` → `[REDACTED_API_KEY]` |
| **Compact JWS/JWT tokens (R5)** | `[REDACTED_JWS]` | `eyJhbGci...` → `[REDACTED_JWS]` |

**Key-based redaction (R5 — ConsequenceToken leakage mitigation):**

When `sanitize_dict()` encounters a key matching the denylist (case-insensitive), the value is unconditionally redacted to `[REDACTED_TOKEN]`, regardless of content. This ensures ConsequenceToken JWS strings are scrubbed even if format variations evade the regex pattern.

**Denylisted keys:** `token`, `consequence_token`, `jws`, `jwt`, `bearer_token`

**Configuration:** `PIISanitizer` is stateless; patterns compile once at import time.

### Layer 2: Langfuse Span-Level PII Scrubbing

When `LANGFUSE_PII_SCRUBBING_ENABLED=true` (default), the compliance bridge applies `PIISanitizer.sanitize()` to Langfuse span `input` and `output` fields before emitting them. This prevents PII from appearing in Langfuse compliance project traces.

> [!IMPORTANT]
> Langfuse Cloud redaction is **not relied upon** as the primary PII control. The CAGE architecture applies scrubbing at the span emission layer (before the data leaves the pod) to ensure PII never transits the network in plain form.

---

## Presidio Score Threshold (AI600-002)

The Microsoft Presidio NLP entity recognizer is used for PII detection in financial advisor outputs. The score threshold controls the false-positive/false-negative trade-off:

```
PRESIDIO_SCORE_THRESHOLD = 0.5 (default, configurable via env var)
```

| Deployment | Recommended Threshold | Rationale |
|---|---|---|
| US_FED | 0.5 | Strict detection; US financial data in English is unambiguous |
| EU_ECB | 0.65 | Higher threshold for multilingual contexts (French, German, Dutch) |
| APAC_MAS | 0.65 | Higher threshold for multilingual contexts (Mandarin, Malay, Tamil) |

The threshold is set via the `PRESIDIO_SCORE_THRESHOLD` environment variable in the gateway Deployment manifest.

---

## Langfuse Field Scrubbing Policy

The following Langfuse SDK fields are scrubbed before span emission:

| Langfuse Field | Scrubbed? | Method |
|---|---|---|
| `trace.input` | ✅ Yes | `PIISanitizer.sanitize()` |
| `trace.output` | ✅ Yes | `PIISanitizer.sanitize()` |
| `span.input` | ✅ Yes | `PIISanitizer.sanitize()` |
| `span.output` | ✅ Yes | `PIISanitizer.sanitize()` |
| `generation.prompt` | ✅ Yes | `PIISanitizer.sanitize()` |
| `generation.completion` | ✅ Yes | `PIISanitizer.sanitize()` |
| `trace.metadata.*` | ❌ No (structured JSON only) | No free-form PII in metadata |
| `span.metadata.*` | ❌ No (structured JSON only) | No free-form PII in metadata |

---

## Carlini Extraction Probes (Red Team Activity)

Carlini et al. (2021) extraction attacks attempt to recover training data from model weights by probing the model with crafted inputs. Detection and mitigation of Carlini probes is a **manual red team activity** tracked separately, not a real-time code control. The CAGE red team dataset extension plan (`docs/RED_TEAM_DATASET_EXTENSION.md`) includes Carlini extraction probe test cases.

---

## Audit Trail

PII sanitization events are logged to the compliance Langfuse project with:
- `pii_sanitizer.pattern_matched` — which regex pattern triggered redaction
- `pii_sanitizer.fields_sanitized` — list of fields scrubbed in this span
- `iso_control` — `A.6` (Data Lineage)

These log entries constitute evidence for ISO 42001 §A.6 and AI 600-1 §2.2 compliance.

---

## Related Documents

- `src/gateway/governance/pii_sanitizer.py` — PIISanitizer implementation
- `docs/AI_FAIRNESS_ASSESSMENT.md` — Bias assessment (ECOA/Reg B)
- `docs/POAM_US_FED.md` — AI600-002 POAM item
