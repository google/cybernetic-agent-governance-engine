# Pre-Release Documentation Audit — Remediation Plan

**Branch:** `fix/track-b-v2-release-gates`  
**Audit date:** 2026-06-08  
**Auditor:** CAGE Governance Agent  
**Authority:** `.clinerules` §8.5, `docs/CHANGE_MANAGEMENT_PROCESS.md` §9  
**Change category:** Cat-N (Normal) — documentation-only changes; no code logic altered  
**Commit type:** `docs`

---

## Executive Summary

The 20 commits on `fix/track-b-v2-release-gates` introduce three new governance modules
([`token_quota_proxy.py`](../src/gateway/governance/token_quota_proxy.py),
[`pii_sanitizer.py`](../src/gateway/governance/pii_sanitizer.py),
[`uca_logger.py`](../src/gateway/governance/uca_logger.py)), register `CTRL_TQP_007` in all
three regional compliance baselines, add POAM-023, and record Track C/D gate results in
`CHANGELOG.md`. The audit identified **9 documentation gaps** across 5 files. None are
blockers for the PR merge itself, but 4 are required before the `v2.0.0` stable tag is applied.

### Gap Severity Summary

| Priority | Count | Files Affected |
|----------|-------|----------------|
| P1 — Required before `v2.0.0` tag | 4 | `README.md`, `ARCHITECTURE.md`, `docs/SECURITY_STATUS.md` |
| P2 — Required before stable release announcement | 3 | `README.md`, `docs/SECURITY_STATUS.md`, `docs/POAM.md` |
| P3 — Follow-on PR within 2 business days | 2 | `ARCHITECTURE.md`, `docs/SECURITY_STATUS.md` |

---

## Gap Index

| # | File | Gap | Priority |
|---|------|-----|----------|
| G-01 | [`README.md`](../README.md) | Three new governance modules absent from Project Structure tree | P1 |
| G-02 | [`README.md`](../README.md) | Key Features list missing Token Quota Proxy, PII Sanitizer, UCA Logger | P1 |
| G-03 | [`README.md`](../README.md) | Environment Variables table missing `STEP_QUOTA_MAX`, `TOKEN_QUOTA_MAX`, `SESSION_TTL_SECONDS`, `OSCAL_S3_BUCKET_*` | P1 |
| G-04 | [`README.md`](../README.md) | POAM Closed badge count stale (shows 6; POAM-023 opened, count unchanged but total is now 23) | P2 |
| G-05 | [`ARCHITECTURE.md`](../ARCHITECTURE.md) | Governance Stack table missing Token Quota Proxy tier | P1 |
| G-06 | [`ARCHITECTURE.md`](../ARCHITECTURE.md) | Component Map Mermaid diagram missing `TQP` node and WORM ledger path | P3 |
| G-07 | [`ARCHITECTURE.md`](../ARCHITECTURE.md) | Footer summary line stale (test count, POAM list) | P2 |
| G-08 | [`docs/SECURITY_STATUS.md`](../docs/SECURITY_STATUS.md) | POAM table missing POAM-023; POAM-003 still shown as Open (it is Closed) | P2 |
| G-09 | [`docs/SECURITY_STATUS.md`](../docs/SECURITY_STATUS.md) | "What Is Fully Implemented" table missing Token Quota Proxy / PII Sanitizer / UCA Logger controls | P3 |

---

## Remediation Instructions

### File 1: `README.md`

#### G-01 — Add three new modules to Project Structure tree

**Location:** [`README.md`](../README.md) lines 219–228 (the `src/gateway/governance/` subtree block)

**Current text:**
```
│   │   ├── governance/               # SymbolicGovernor, STPAValidator, NeMo manager
│   │   │   ├── kms_signer.py         # v2.0.0: Cloud KMS HSM-backed governance signer
│   │   │   ├── consensus.py          # v2.0.0: ConsensusModelRegistry + heterogeneous consensus
│   │   │   ├── normative_provider.py  # v2.0.0: External Normative Provider + Adaptive Gating Primitive
│   │   │   ├── stpa_compiler.py      # STPA-to-Policy compiler CLI (OPA/NeMo/Python/LangGraph)
│   │   │   ├── oscal_ssp_exporter.py # Automated OSCAL SSP patcher
│   │   │   ├── generated_stpa_validator.py  # Auto-generated from YAML
│   │   │   ├── generated_saga_nodes.py      # Auto-generated LangGraph Saga nodes
│   │   │   └── fiscal_limit_guard.py        # Redis pre-reservation guard
```

**Replace with:**
```
│   │   ├── governance/               # SymbolicGovernor, STPAValidator, NeMo manager
│   │   │   ├── kms_signer.py         # v2.0.0: Cloud KMS HSM-backed governance signer
│   │   │   ├── consensus.py          # v2.0.0: ConsensusModelRegistry + heterogeneous consensus
│   │   │   ├── normative_provider.py  # v2.0.0: External Normative Provider + Adaptive Gating Primitive
│   │   │   ├── stpa_compiler.py      # STPA-to-Policy compiler CLI (OPA/NeMo/Python/LangGraph)
│   │   │   ├── oscal_ssp_exporter.py # Automated OSCAL SSP patcher
│   │   │   ├── generated_stpa_validator.py  # Auto-generated from YAML
│   │   │   ├── generated_saga_nodes.py      # Auto-generated LangGraph Saga nodes
│   │   │   ├── fiscal_limit_guard.py        # Redis pre-reservation guard
│   │   │   ├── token_quota_proxy.py  # CTRL_TQP_007: per-session step/token quota circuit breaker (ISO 42001 A.4)
│   │   │   ├── pii_sanitizer.py      # Pre-ledger PII sanitization pipeline (ISO 42001 A.6)
│   │   │   └── uca_logger.py         # ISO 42001 Clause 6.1 UCA record builder, KMS signer, WORM persister
```

---

#### G-02 — Add Token Quota Proxy to Key Features list

**Location:** [`README.md`](../README.md) — the `## Key Features` section, after the `FiscalLimitGuard` bullet (line 77).

**Insert the following bullet immediately after the `FiscalLimitGuard` bullet:**
```markdown
- **Token Quota Proxy (CTRL_TQP_007)** — `src/gateway/governance/token_quota_proxy.py` enforces hard per-session step-count (`≤12`) and token (`≤100,000`) quotas via Redis atomic Lua counters. Fail-CLOSED: Redis unavailability blocks the request (HTTP 429). Two-phase commit: `check_and_increment()` reserves quota before the vLLM call; `reconcile_actual_tokens()` corrects over-allocation after the response. `rollback_step()` atomically decrements counters on downstream failure. Implements ISO 42001 Annex A.4 (Resource Management). Governance control: `CTRL_TQP_007`.
- **PII Sanitizer** — `src/gateway/governance/pii_sanitizer.py` applies five compiled regex patterns (SSN, credit card, email, phone, API key/Bearer token) sequentially to every UCA compliance record before WORM persistence. Implements ISO 42001 Annex A.6 (Data Lineage and PII Leak Mitigation). Thread-safe; no per-call state.
- **UCA Logger** — `src/gateway/governance/uca_logger.py` builds, cryptographically signs (Cloud KMS in production; HMAC-SHA256 stub when `CAGE_ENV=test`), and persists 16-field ISO 42001 Clause 6.1 Unsafe Control Action records to a region-gated WORM bucket (`CAGE_DEPLOYMENT_REGION` → `OSCAL_S3_BUCKET_{REGION}`). Three UCA types: `quota_exceeded`, `prompt_injection`, `pii_sanitization`.
```

---

#### G-03 — Add new environment variables to Quick Start table

**Location:** [`README.md`](../README.md) — the `### Environment Variables` table (lines 165–181).

**Add the following rows to the table** (insert after the `REDIS_URL` row):

```markdown
| `STEP_QUOTA_MAX`                                 | Hard step-count limit per agent session for Token Quota Proxy (default: `12`) |
| `TOKEN_QUOTA_MAX`                                | Hard token limit per agent session for Token Quota Proxy (default: `100000`) |
| `SESSION_TTL_SECONDS`                            | Redis key TTL for Token Quota Proxy session counters (default: `3600`) |
| `OSCAL_S3_BUCKET_US_FED`                         | WORM bucket for UCA records in US_FED region (used by UCA Logger) |
| `OSCAL_S3_BUCKET_EU_ECB`                         | WORM bucket for UCA records in EU_ECB region (europe-west1; used by UCA Logger) |
| `OSCAL_S3_BUCKET_APAC_MAS`                       | WORM bucket for UCA records in APAC_MAS region (asia-southeast1; used by UCA Logger) |
| `CAGE_ENV`                                       | Set to `test` to enable HMAC-SHA256 stub signing in UCA Logger (suppresses KMS requirement) |
```

---

#### G-04 — Update POAM badge and POAM Status table

**Location:** [`README.md`](../README.md) line 5 (badge row) and lines 365–373 (POAM Status table).

**Badge — current:**
```
![POAM Closed 6](https://img.shields.io/badge/POAM%20Closed-6-brightgreen)
```

**Badge — no change needed** (6 closed items is still correct; POAM-023 is Open, not Closed).

**POAM Status table — current (lines 365–373):**
```markdown
| Metric | Count |
|--------|-------|
| Total Items | 22 |
| **Closed** | **6** (POAM-003 AU-12 closed in rc.3; POAM-007, POAM-010, POAM-016, POAM-020, POAM-021 previously closed) |
| Open | 11 |
| In Progress | 3 |
```

**Replace with:**
```markdown
| Metric | Count |
|--------|-------|
| Total Items | 23 |
| **Closed** | **6** (POAM-003 AU-12, POAM-007 IA-3, POAM-010 RA-5, POAM-016 SI-2, POAM-020 CM-3, POAM-021 SI-4) |
| Open | 13 |
| In Progress | 3 |
| Critical | 4 |
```

**Also update the Security & Compliance Status table row for "Infrastructure security" (line 143):**

Current:
```
| **Infrastructure security**                  | 🟡 Partial              | 11 of 22 POA&M open (6 Closed: POAM-003 AU-12, POAM-007, POAM-010, POAM-016, POAM-020, POAM-021; POAM-011 SC-8 and POAM-012 SC-12 remain Open) — see [`docs/SECURITY_STATUS.md`](docs/SECURITY_STATUS.md) |
```

Replace with:
```
| **Infrastructure security**                  | 🟡 Partial              | 13 of 23 POA&M open (6 Closed: POAM-003 AU-12, POAM-007 IA-3, POAM-010 RA-5, POAM-016 SI-2, POAM-020 CM-3, POAM-021 SI-4; POAM-023 SI-2 CVE-2025-13462 opened 2026-06-08) — see [`docs/SECURITY_STATUS.md`](docs/SECURITY_STATUS.md) |
```

---

### File 2: `ARCHITECTURE.md`

#### G-05 — Add Token Quota Proxy to Governance Stack table

**Location:** [`ARCHITECTURE.md`](../ARCHITECTURE.md) — the `## Governance Stack` table (lines 211–228). The table currently has 15 tiers ending with `FiscalLimitGuard` at Tier 15.

**Add the following row immediately after the FiscalLimitGuard row (Tier 15):**

```markdown
| 16   | Token Quota Proxy           | [`token_quota_proxy.py`](src/gateway/governance/token_quota_proxy.py)            | Redis atomic Lua counters; step-count ≤12 and token ≤100k per session; fail-CLOSED on Redis error; two-phase commit (reserve → reconcile); rollback on downstream failure | Every inference proxy request (Step 2 in `inference_proxy.py`) |
```

**Also add a note below the table** (after the existing `FiscalLimitGuard` row note, before the `### Multi-Jurisdiction Regional Compliance Profiles` heading):

```markdown
> **CTRL_TQP_007 — Token Quota Proxy:** Implements ISO 42001 Annex A.4 (Resource Management). Every blocked execution produces a KMS-signed UCA record persisted to the region-gated WORM ledger via `uca_logger.py`. Pre-ledger PII sanitization applied by `pii_sanitizer.py` (ISO 42001 Annex A.6). OPA `quota_within_limits` and `token_quota_within_limits` rules in `deployment/system_authz.rego` provide secondary declarative evidence; Python `TokenQuotaProxy` is the primary enforcer.
```

---

#### G-06 — Update Component Map Mermaid diagram

**Location:** [`ARCHITECTURE.md`](../ARCHITECTURE.md) — the `## Component Map` Mermaid block (lines 16–105).

**In the `gateway` subgraph block**, add `TQP` and `WORM` nodes and wire them into the pipeline. Find the existing gateway subgraph lines:

```
        FLG[fiscal_limit_guard.py\nRedis pre-reservation]
        SAGA[generated_saga_nodes.py\nsaga_router + compensating nodes]
```

**Replace with:**
```
        FLG[fiscal_limit_guard.py\nRedis pre-reservation]
        TQP[token_quota_proxy.py\nCTRL_TQP_007 step+token quota]
        PIISAN[pii_sanitizer.py\nISO 42001 A.6 pre-ledger redaction]
        UCALOG[uca_logger.py\nISO 42001 Clause 6.1 WORM records]
        SAGA[generated_saga_nodes.py\nsaga_router + compensating nodes]
```

**In the wiring section**, find:
```
    GW --> AC --> NEMO --> STPA --> OPA_C --> SYMGOV --> CBF --> CAUSAL --> FLG
    FLG --> SAGA
```

**Replace with:**
```
    GW --> TQP --> AC --> NEMO --> STPA --> OPA_C --> SYMGOV --> CBF --> CAUSAL --> FLG
    TQP --> PIISAN --> UCALOG
    UCALOG --> S3
    FLG --> SAGA
```

> **Note:** The `TQP` node is placed before `AC` (Aho-Corasick) because the Token Quota Proxy is Step 2 in `inference_proxy.py`, inserted between the keyword scan (Step 1) and NeMo (Step 3). Adjust if the actual pipeline ordering differs from the plan.

---

#### G-07 — Update ARCHITECTURE.md footer summary line

**Location:** [`ARCHITECTURE.md`](../ARCHITECTURE.md) — the final `_Architecture current as of...` line (line 399).

**Current:**
```
_Architecture current as of 2026-06-05. Canonical graph: 10 nodes including mandatory NeMo input/output rails. Governance tiers: **7** (SymbolicGovernor tiers 0–6) + FiscalLimitGuard pre-reservation + LangGraph Saga WAL. STPA compiler active: UCAs compiled from `config/stpa_control_structure.yaml`; LangGraph Saga target added (UCA-4 fully enforced via WAL + LIFO rollback + idempotent compensating nodes). Z3N: Linkerd + Cilium deployed. POAM-007 (IA-3), POAM-010 (RA-5), POAM-016 (SI-2), POAM-020 (CM-3), POAM-021 (SI-4) closed. POAM-011 (SC-8) and POAM-012 (SC-12) remain Open. Vendor integrations isolated in `src/integrations/{vendor}/` (NexArt, TrustLayers). Redis db=1 hardened with `noeviction` + Guaranteed QoS. Lula coverage: 15 validation manifests (4 Active, 11 Stub). FiscalLimitGuard: Redis WATCH/MULTI/EXEC atomic pre-reservation prevents multi-agent OPA limit collision. NoDirectBind safety invariant machine-verified over 19 reachable states (v2.0.0-rc.2). Test suite: **803 passing** (rc.3 — 2026-06-05). For architectural decisions, see [`docs/DEPLOYMENT_DECISION_RECORD.md`](docs/DEPLOYMENT_DECISION_RECORD.md)._
```

**Replace with:**
```
_Architecture current as of 2026-06-08. Canonical graph: 10 nodes including mandatory NeMo input/output rails. Governance tiers: **7** (SymbolicGovernor tiers 0–6) + FiscalLimitGuard pre-reservation + Token Quota Proxy (CTRL_TQP_007) + LangGraph Saga WAL. STPA compiler active: UCAs compiled from `config/stpa_control_structure.yaml`; LangGraph Saga target added (UCA-4 fully enforced via WAL + LIFO rollback + idempotent compensating nodes). Z3N: Linkerd + Cilium deployed. POAM-007 (IA-3), POAM-010 (RA-5), POAM-016 (SI-2), POAM-020 (CM-3), POAM-021 (SI-4) closed. POAM-023 (SI-2 CVE-2025-13462) opened 2026-06-08. POAM-011 (SC-8) and POAM-012 (SC-12) remain Open. Vendor integrations isolated in `src/integrations/{vendor}/` (NexArt, TrustLayers). Redis db=1 hardened with `noeviction` + Guaranteed QoS. Lula coverage: 15 validation manifests (4 Active, 11 Stub). FiscalLimitGuard: Redis WATCH/MULTI/EXEC atomic pre-reservation prevents multi-agent OPA limit collision. Token Quota Proxy: Redis Lua atomic step/token counters; fail-CLOSED; ISO 42001 A.4. NoDirectBind safety invariant machine-verified over 19 reachable states (v2.0.0-rc.2). Test suite: **796 passing, 0 failed** (Track D — 2026-06-08). For architectural decisions, see [`docs/DEPLOYMENT_DECISION_RECORD.md`](docs/DEPLOYMENT_DECISION_RECORD.md)._
```

---

### File 3: `docs/SECURITY_STATUS.md`

#### G-08 — Fix stale POAM table: add POAM-023, correct POAM-003 status

**Location:** [`docs/SECURITY_STATUS.md`](../docs/SECURITY_STATUS.md) — the "Infrastructure Security Gaps" table (lines 94–118).

**Three specific changes required:**

**Change 1 — POAM-003 row: update Status from Open to Closed.**

Current row:
```markdown
| POAM-003 | AU-12      | `automated_auditor.py` uses synthetic mock traces, not live OTLP      | High         | Open            | 2026-04-15  |
```

Replace with:
```markdown
| POAM-003 | AU-12      | ~~`automated_auditor.py` uses synthetic mock traces~~ **✅ Closed** — live OSCAL assessment results generated from Langfuse compliance metrics via compliance-bridge REST API | High | **Closed** | 2026-06-05 |
```

**Change 2 — Add POAM-023 row** (insert after the POAM-022 row):
```markdown
| POAM-023 | SI-2       | CVE-2025-13462 in `libpython3.11` (python:3.12-slim-bookworm base layer) — 19 CRITICAL CVEs; no Debian bookworm fix available as of 2026-06-08; suppressed via `.trivyignore`; Cilium egress lockdown reduces exploitability | **Critical** | Open | 2026-09-08 |
```

**Change 3 — Update the "Testing Gaps" section** (lines 119–124). Remove the stale POAM-003 reference:

Current:
```markdown
- **`automated_auditor.py` uses synthetic mock traces** — the continuous audit invariant checker (POAM-003) does not connect to a live OTLP source; its evidence does not reflect actual system behavior.
```

Replace with:
```markdown
- **~~`automated_auditor.py` uses synthetic mock traces`~~** — POAM-003 closed 2026-06-05. Live OSCAL assessment results now generated from Langfuse compliance metrics via compliance-bridge REST API.
```

---

#### G-09 — Add Token Quota Proxy / PII Sanitizer / UCA Logger to "What Is Fully Implemented" table

**Location:** [`docs/SECURITY_STATUS.md`](../docs/SECURITY_STATUS.md) — the `### AI Governance Enforcement (Strong)` table (lines 22–44).

**Add the following three rows** to the bottom of the AI Governance Enforcement table (before the closing `|` line):

```markdown
| Token Quota Proxy (CTRL_TQP_007)  | Per-session step-count (≤12) and token (≤100k) quota enforcement via Redis atomic Lua counters; fail-CLOSED; HTTP 429 on quota exceeded; two-phase commit (reserve → reconcile); rollback on downstream failure | ✅ Implemented (fix/track-b-v2-release-gates) |
| PII Sanitizer                     | Pre-ledger regex sanitization pipeline (SSN, CC, email, phone, API key/Bearer token) applied to all UCA records before WORM persistence; ISO 42001 Annex A.6 | ✅ Implemented (fix/track-b-v2-release-gates) |
| UCA Logger                        | ISO 42001 Clause 6.1 UCA record builder; KMS-signed (HMAC-SHA256 stub in `CAGE_ENV=test`); region-gated WORM persistence (`CAGE_DEPLOYMENT_REGION` → `OSCAL_S3_BUCKET_{REGION}`); three UCA types: `quota_exceeded`, `prompt_injection`, `pii_sanitization` | ✅ Implemented (fix/track-b-v2-release-gates) |
```

---

## Commit Strategy

All changes above are documentation-only. They must be committed as a single `docs` commit on the current branch before the PR is merged.

**Suggested commit message:**
```
docs(compliance): update readme, architecture, and security status for track-b

Add TokenQuotaProxy, PIISanitizer, and UCALogger to README project
structure, key features, and env vars table. Add CTRL_TQP_007 tier to
ARCHITECTURE.md governance stack table and update footer summary.
Fix stale POAM-003 status (Closed) and add POAM-023 (CVE-2025-13462)
to SECURITY_STATUS.md. Update POAM total count from 22 to 23 in README.

Refs #fix/track-b-v2-release-gates
[CR-2026-TQP-001]
```

> **Commit message check:** 72-char subject line: `docs(compliance): update readme, architecture, and security status for track-b` = 79 chars — **FAIL**.
>
> **Corrected subject line (≤72 chars):**
> `docs(compliance): sync docs to track-b new governance modules` (61 chars) ✓

---

## Deferred Items (Follow-on PR — within 2 business days of merge)

The following items are explicitly deferred per `plans/token-quota-proxy-impl-plan.md` §23.6 and `.clinerules` §11.1. They are **not blockers** for this PR but must be tracked:

| Item | File | Action | Deadline |
|------|------|--------|----------|
| OSCAL component definition for CTRL_TQP_007 | `compliance/oscal/component-definition.yaml` | Add component entry with `control-id: CTRL_TQP_007`, `iso-clause: A.4`, `enforcement-tier: 2`, `primary-enforcer: Python TokenQuotaProxy`, `secondary-enforcer: OPA quota_within_limits (pending runtime injection)` | 2 business days post-merge |
| OPA runtime injection of Redis session state | `src/gateway/server/governance_middleware.py` | Inject `sequence_step_count`, `accumulated_tokens`, `token_quota_max` into OPA `input` document so `quota_within_limits` and `token_quota_within_limits` Rego rules become active | Follow-on PR |
| UCA-4 addition to STPA model | `config/stpa_control_structure.yaml` | Add UCA-4 (token quota exceeded) to STPA control structure; regenerate `generated_stpa_validator.py` and `generated_saga_nodes.py` | Follow-on PR |
| `docs/PRODUCTION_READINESS_REPORT.md` update | `docs/PRODUCTION_READINESS_REPORT.md` | Update gate status table: U-06 Trivy → ⚠️ Risk Accepted (POAM-023); U-08 tests → ✅ 796 passed; U-15/U-16 seal enforcement → ✅ Green | Follow-on PR |

---

## Verification Checklist

After applying all changes, a code agent must verify:

- [ ] `grep -n "token_quota_proxy" README.md` returns ≥1 match in the Project Structure section
- [ ] `grep -n "STEP_QUOTA_MAX" README.md` returns ≥1 match in the Environment Variables table
- [ ] `grep -n "CTRL_TQP_007" ARCHITECTURE.md` returns ≥1 match in the Governance Stack table
- [ ] `grep -n "POAM-023" docs/SECURITY_STATUS.md` returns ≥1 match
- [ ] `grep -n "POAM-003.*Closed" docs/SECURITY_STATUS.md` returns ≥1 match
- [ ] `grep -n "Token Quota Proxy" docs/SECURITY_STATUS.md` returns ≥1 match in the AI Governance table
- [ ] `grep -n "Total Items | 23" README.md` returns ≥1 match in the POAM Status table
- [ ] Commit subject line is ≤72 characters
- [ ] No secrets or credentials introduced in any changed file

---

_Plan prepared 2026-06-08. Execute in Code mode. All file paths are relative to the repository root `/Users/larsahlfors/Code/cybernetic-governance-engine`._
