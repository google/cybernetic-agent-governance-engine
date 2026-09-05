# CAGE Audit Log Schema Reference

**Schemas:** `cage-intent/1.0` · `cage-view-access/1.0`  
**Source of truth:** [`examples/telemetry.py`](../../examples/telemetry.py)  
**Output format:** [NDJSON](https://ndjson.org/) — one JSON object per line, append-only  
**Output paths:**
- Evidence chain: `examples/evidence/evidence_chain_<YYYY-MM-DD>.ndjson`
- View-access log: `examples/evidence/view_access_log_<YYYY-MM-DD>.ndjson`

---

## Overview

The CAGE audit log system produces two complementary NDJSON streams:

1. **Evidence chain (`cage-intent/1.0`)** — tamper-evident record of every governance decision and human-in-the-loop approval. Each record SHA-256 hashes its own payload and chains the previous record's hash, forming an append-only, verifiable audit trail.

2. **View-access log (`cage-view-access/1.0`)** — register of every read-access event against the evidence chain. Satisfies MiFID II Article 25 (recording of trade-related communications) and GDPR Article 30 (records of processing activities).

### Hash Chain Mechanics

> **Scope note.** This document describes the **playground telemetry** chains
> produced by [`examples/telemetry.py`](../../examples/telemetry.py), which are
> separate from the production audit chains in
> [`src/gateway/governance/evidence/stream.py`](../../src/gateway/governance/evidence/stream.py)
> (`cage-evidence-stream/2.0`) and
> [`src/compliance_bridge/context_accumulator.py`](../../src/compliance_bridge/context_accumulator.py)
> (`cage-context-accumulator/2.0`). Those production chains canonicalize with
> RFC 8785 JCS; the `sort_keys=True` serialization described below applies only
> to the playground chains and is **not** interchangeable with them. See
> [`docs/BREAKING_CHANGES_v3.md`](../BREAKING_CHANGES_v3.md) for the production
> canonicalization change.

```
record_hash = SHA-256( prev_hash || JSON(payload, sort_keys=True) )
```

- Genesis record: `prev_hash = SHA-256("GENESIS")`
- View-access genesis: `prev_hash = SHA-256("VIEW-GENESIS")`
- Payload is serialised with `sort_keys=True` and no extra whitespace to ensure deterministic hashing across platforms
- `record_hash` and `prev_hash` are excluded from the payload before hashing, then appended to the final record

Chain integrity can be verified programmatically:

```python
from examples.telemetry import PlaygroundTelemetry

tel = PlaygroundTelemetry()
valid, count = tel.verify_chain()
# valid=True means no record has been tampered with or inserted out of order
```

---

## Schema 1: `cage-intent/1.0`

Emitted for every **governance evaluation** (automated) and **HITL approval** (human).

### Governance Evaluation Record

```json
{
  "schema":           "cage-intent/1.0",
  "record_id":        "3f2a1b4c-...",
  "timestamp":        "2026-05-23T13:00:00.000000+00:00",
  "scenario_id":      "A",
  "action":           "execute_trade",
  "params_redacted":  { "ticker": "AAPL", "amount": 5000, "approval_token": "***REDACTED***" },
  "decision":         "BLOCKED",
  "blocking_tier":    3,
  "violations":       ["UCA-4: trade amount exceeds consensus threshold"],
  "elapsed_ms":       42.7,
  "nist_controls":    ["SC-4", "SC-8", "SC-7"],
  "iso_controls":     ["A.8.4", "A.6.2"],
  "otel_service":     "cage-playground",
  "prev_hash":        "a3f1b2c4...",
  "record_hash":      "d9e8f7a6..."
}
```

### HITL Approval Record

```json
{
  "schema":           "cage-intent/1.0",
  "record_id":        "8a9b0c1d-...",
  "timestamp":        "2026-05-23T13:05:00.000000+00:00",
  "event_type":       "hitl_approval",
  "thread_id":        "lg-thread-xyz",
  "decision":         "APPROVED",
  "reviewer":         "analyst@example.com",
  "rationale":        "Trade reviewed. Market conditions verified. Approved under Tier-2 authority.",
  "comment":          "",
  "nist_controls":    ["GOVERN-5", "SC-4"],
  "iso_controls":     ["A.8.4", "A.7.2", "A.6.2"],
  "iso_42001_clause": "6.1",
  "otel_service":     "cage-financial-advisor",
  "prev_hash":        "d9e8f7a6...",
  "record_hash":      "f0e1d2c3..."
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `schema` | `string` | Always `"cage-intent/1.0"` |
| `record_id` | `string (uuid4)` | Unique record identifier |
| `timestamp` | `string (ISO 8601)` | UTC timestamp of record creation |
| `event_type` | `string` | `"hitl_approval"` for HITL records; absent for governance evaluations |
| `scenario_id` | `string` | Playground scenario ID (`"A"`–`"E"`); `"live"` for production gateway |
| `action` | `string` | Tool or operation name (e.g., `"execute_trade"`) |
| `params_redacted` | `object` | Action parameters with sensitive fields replaced by `"***REDACTED***"` |
| `decision` | `string` | `"APPROVED"` or `"BLOCKED"` (governance) / `"APPROVED"` or `"REJECTED"` (HITL) |
| `blocking_tier` | `integer` | Governance tier that blocked (0–6); `-1` if approved. See tier index below |
| `violations` | `string[]` | List of UCA violation strings; empty array if approved |
| `elapsed_ms` | `float` | Total governance pipeline latency in milliseconds |
| `thread_id` | `string` | LangGraph thread ID (HITL records only) |
| `reviewer` | `string` | Human reviewer identity — email or employee ID (HITL records only) |
| `rationale` | `string` | Mandatory human justification text (HITL records only). Never redacted — the reviewer must not include PII. |
| `comment` | `string` | Optional supplementary note (HITL records only) |
| `nist_controls` | `string[]` | Applicable NIST SP 800-53 / NIST AI RMF control IDs |
| `iso_controls` | `string[]` | Applicable ISO 42001 Annex A control IDs |
| `iso_42001_clause` | `string` | Primary ISO 42001 main-body clause (HITL records only) |
| `otel_service` | `string` | `OTEL_SERVICE_NAME` env var value at record creation time |
| `prev_hash` | `string (sha256 hex)` | SHA-256 hash of the immediately preceding record |
| `record_hash` | `string (sha256 hex)` | SHA-256 hash of this record (see chain mechanics above) |

### Redacted Fields

The following `params` keys are automatically replaced with `"***REDACTED***"` before persisting:

```python
{"ssn", "account", "approval_token", "payload", "password", "secret"}
```

This prevents PII from appearing in the audit log. The log records the *decision*, not the sensitive input data.

### Governance Tier Index

The governance pipeline is an **8-tier symbolic governor** (FTRA pre-pipeline boundary gate at Tier 0.5 plus 7 in-pipeline tiers: Tiers 0–6). The SLM semantic similarity sidecar (formerly referenced as Tier 3) has been **deprecated** — `slm_available=false` is a permanent sentinel; it is not part of the active pipeline.

| Tier | Gate | Control | Source |
|------|------|---------|--------|
| 0 | STPA Unsafe Control Action validation | UCA-* (from `config/stpa_control_structure.yaml`) | `generated_stpa_validator.py` |
| 1 | Agentic model confidence threshold (`AGENT_CONFIDENCE_THRESHOLD=0.95`) | `CTRL_AGT_001` | `symbolic_governor.py` |
| 2/4 | Control Barrier Function (CBF) + OPA concurrent (`asyncio.gather`) | CBF: `h(x)≥0`, γ=0.5; OPA: `CTRL_OPA_005` | `cbf.py`, `core/policy.py` |
| 3 | Fiscal Limit Pre-Reservation (FiscalLimitGuard, daily cap $500k) | Redis atomic WATCH/MULTI/EXEC | `fiscal_limit_guard.py` |
| 5 | Multi-agent consensus (≥$10,000 USD) | ISO 42001 A.8.4 | `consensus.py` |
| 6 | DoWhy causal gatekeeper (placebo refutation, p<0.05) | `CTRL_MRM_004`, `CTRL_TEL_003` | `causal_gatekeeper.py` |
| 6b | Adaptive FRIA gate (EU_ECB only) | `CTRL_FRIA_006` | `normative_provider.py` |

---

## Schema 2: `cage-view-access/1.0`

Emitted every time the evidence chain is read via `PlaygroundTelemetry.read_evidence_log()`.

### View-Access Record

```json
{
  "schema":           "cage-view-access/1.0",
  "event_id":         "1a2b3c4d-...",
  "timestamp":        "2026-05-23T14:00:00.000000+00:00",
  "accessor_id":      "compliance-officer@example.com",
  "reason":           "quarterly audit review",
  "filter_scenario":  null,
  "records_accessed": 47,
  "read_fingerprint": "b2c3d4e5...",
  "prev_view_hash":   "a1b2c3d4...",
  "event_hash":       "c3d4e5f6..."
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `schema` | `string` | Always `"cage-view-access/1.0"` |
| `event_id` | `string (uuid4)` | Unique event identifier |
| `timestamp` | `string (ISO 8601)` | UTC timestamp of the read event |
| `accessor_id` | `string` | Identity of the reader — email, service account, or user ID |
| `reason` | `string` | Business justification for the access |
| `filter_scenario` | `string \| null` | Scenario filter applied; `null` if all records were read |
| `records_accessed` | `integer` | Number of evidence records returned to the accessor |
| `read_fingerprint` | `string (sha256 hex)` | SHA-256 hash of all `record_hash` values in the returned set — proves which exact records were read |
| `prev_view_hash` | `string (sha256 hex)` | Hash of the previous view-access event (genesis: `SHA-256("VIEW-GENESIS")`) |
| `event_hash` | `string (sha256 hex)` | Hash of this view-access event |

---

## Regulatory Compliance Mapping

> **Architecture Note:** ISO 42001 requirements are **universal** and apply to all `CAGE_DEPLOYMENT_REGION` values. All other frameworks are **jurisdictional** and apply only to the indicated region.

| Regulatory Requirement | Jurisdiction | How the Audit Log Satisfies It |
|------------------------|-------------|-------------------------------|
| **ISO 42001 §6.1** — Risk treatment documentation | **Universal** (all regions) | HITL approval records persist the human's risk treatment decision and rationale before graph resumption |
| **ISO 42001 A.7.2** — Accountability | **Universal** (all regions) | `reviewer` field attributes every HITL decision to a named individual |
| **ISO 42001 A.8.4** — AI system operation controls | **Universal** (all regions) | Governance evaluation records provide continuous evidence of operational control enforcement |
| **ISO 42001 A.9.2** — Evidence integrity | **Universal** (all regions) | SHA-256 hash chain ensures tamper-evident audit trail across all regions |
| **MiFID II Art. 25** — Recording of trade-related communications | **EU_ECB only** | View-access log registers every read of trade governance decisions, with accessor identity and timestamp |
| **GDPR Art. 30** — Records of processing activities | **EU_ECB only** | View-access log constitutes a record of who accessed personal-data-adjacent decision records and why |
| **DORA Art. 10** — ICT risk management continuity | **EU_ECB only** | Hash chain tamper evidence ensures log integrity cannot be silently compromised |
| **MAS Notice 655** — Audit logging requirements | **APAC_MAS only** | Append-only NDJSON evidence chain with 7-year retention satisfies MAS audit record requirements |
| **NIST AI RMF GOVERN-5** — Human oversight | **US_FED only** | HITL approval records prove human review occurred before high-risk execution |
| **FISMA AU-11** — Audit record retention | **US_FED only** | Evidence chain retained per US_FED baseline retention policy |

---

## OTel Span Attribute Alignment

The following OTel span attributes are emitted alongside every evidence record, using the same naming convention as `symbolic_governor.py` and `generated_stpa_validator.py`:

| OTel Attribute | Value | Notes |
|----------------|-------|-------|
| `langfuse.observation.type` | `"span"` | |
| `langfuse.observation.name` | `"governance_evaluation"` or `"hitl_approval"` | |
| `langfuse.observation.input` | JSON of scenario + action + params | |
| `langfuse.observation.output` | `"BLOCKED"` \| `"APPROVED"` | |
| `langfuse.trace.metadata.iso.control_id` | `"A.8.4"` | |
| `langfuse.trace.metadata.nist.control_id` | `"SC-4"` | |
| `cage.governance.decision` | `"BLOCKED"` \| `"APPROVED"` | |
| `cage.governance.blocking_tier` | `0`–`6` or `-1` | |
| `cage.governance.violation_count` | `integer` | |
| `cage.governance.elapsed_ms` | `float` | |
| `cage.evidence.chain_hash` | SHA-256 hex | Links OTel span to the NDJSON evidence record |
| `cage.evidence.record_id` | UUID4 | |
