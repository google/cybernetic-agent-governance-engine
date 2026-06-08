# POAM Framework Redesign — ISO 42001 Alignment Analysis & Multi-Posture Strategy

**Date:** 2026-06-08
**Branch:** `fix/track-b-v2-release-gates`
**Status:** DRAFT — awaiting approval before implementation

---

## 1. Executive Summary

The current [`docs/POAM.md`](../docs/POAM.md) is structurally a **US_FED-only document** masquerading as a universal one. Its header declares `Reference: NIST SP 800-37 Rev. 2, NIST SP 800-53 Rev. 5 CA-5`, and all 23 entries are anchored to NIST SP 800-53 control IDs. Zero entries reference ISO 42001 Annex A controls, EU AI Act articles, MAS FEAT principles, or DORA articles as their primary framework.

This creates three concrete problems:

1. **False universality** — EU_ECB and APAC_MAS deployers reading `docs/POAM.md` see a document that implies their compliance posture is captured, but it is not. Their regional obligations (EU AI Act Art. 9, DORA Art. 12, MAS FEAT F1/F2, MAS Notice 655) have no POAM tracking at all.
2. **ISO 42001 gap** — ISO 42001 is the declared global baseline (`_global_baseline: "ISO_42001"` in all three regional baselines), yet no POAM entry is anchored to an ISO 42001 Annex A control. Weaknesses in the ISO 42001 AIMS (e.g., incomplete Annex A.4 resource management documentation, missing Clause 9 management review records) are invisible.
3. **Architectural constraint violation** — the `.clinerules` §5 and the regional baseline JSON files explicitly state that regional gates are **additive layers** on top of ISO 42001. The POAM inverts this: it treats NIST SP 800-53 as the universal baseline and has no ISO 42001 layer at all.

The fix is a **three-file POAM architecture** that preserves the monorepo as the single source of truth while enforcing strict posture separation.

---

## 2. Current POAM Entry Classification

### 2.1 Full Classification Table

| ID | Control | Weakness Summary | Primary Framework | ISO 42001? | Region Scope | Status |
|---|---|---|---|---|---|---|
| POAM-001 | AC-2 | No account management procedures | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-002 | AC-6 | Overly broad IAM role bindings | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-003 | AU-12 | Synthetic mock traces in auditor | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-004 | CA-5 | No formal POA&M process | NIST SP 800-53 | ❌ | US_FED only | In Progress |
| POAM-005 | CA-6 | No ATO letter | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-006 | CM-8 | No SBOM in CI/CD | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-007 | IA-3 | No intra-cluster mTLS | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-008 | IR-1 | No formal Incident Response Plan | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-009 | RA-2 | FIPS 199 categorization unsigned | NIST SP 800-53 | ❌ | US_FED only | In Progress |
| POAM-010 | RA-5 | No vulnerability scanning in CI | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-011 | SC-8 | No TLS enforcement test | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-012 | SC-12 | Routing seal bypass | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-013 | SI-2 | Unpinned `>=` version specifiers | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-014 | SC-28 | No CMEK validation | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-015 | PL-2 | No signed SSP | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-016 | SI-2 | CVE-2025-69872 diskcache RCE | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-017 | SI-2 | CVE-2026-4810 google-adk injection | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-018 | AU-9 | Langfuse compliance creds silent fail | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-019 | AU-9, SC-7 | Terraform telemetry isolation collapse | NIST SP 800-53 | ❌ | US_FED only | Open |
| POAM-020 | CM-3 | Technical report version mismatch | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-021 | SI-4 | AgentSight exporter in console mode | NIST SP 800-53 | ❌ | US_FED only | **Closed** |
| POAM-022 | SA-9, CA-7 | Normative Provider in stub mode | NIST SP 800-53 + EU AI Act | ⚠️ Partial | ALL (EU_ECB primary) | In Progress |
| POAM-023 | SI-2 | CVE-2025-13462 libpython3.11 | NIST SP 800-53 | ❌ | US_FED only | Open |

### 2.2 Key Findings

**Finding 1 — 100% NIST SP 800-53 anchoring:** Every entry uses a NIST SP 800-53 control ID as its primary identifier. This is correct for US_FED but incorrect as a universal posture.

**Finding 2 — Zero ISO 42001 entries:** ISO 42001 is the declared `_global_baseline` in all three regional baselines. Yet no POAM entry tracks weaknesses against ISO 42001 Annex A controls (e.g., A.4 Resource Management, A.5.2 Social Impact, A.6.1 Policy Enforcement, A.9.4 Telemetry). The CTRL_TQP_007 control (ISO 42001 §A.4) has no POAM entry despite having known gaps (OPA runtime injection of session state is deferred; UCA-4 STPA model not yet updated).

**Finding 3 — POAM-022 is the only cross-regional entry** but is still anchored to NIST SA-9/CA-7. The EU AI Act Art. 29a obligation (FRIA gating) is the actual driver, but it has no EU AI Act article as its primary ID.

**Finding 4 — EU_ECB and APAC_MAS have zero POAM coverage:** Known gaps in EU_ECB posture (DORA Art. 12 resilience testing not started, EU AI Office registration pending, GDPR DPIA integration pending) and APAC_MAS posture (MAS FEAT F2 quantitative fairness metrics pending, MAS Notice 655 certification pending) are tracked nowhere in the monorepo.

**Finding 5 — POAM-018 and POAM-019 are cross-regional in practice:** Silent Langfuse credential failure and Terraform telemetry isolation collapse affect all three regions (all regions use Langfuse dual-project architecture), but are tagged US_FED-only via their NIST control IDs.

---

## 3. Proposed Framework: Three-File POAM Architecture

### 3.1 Design Principles

Four constraints must all be satisfied simultaneously:

1. **ISO 42001 is the universal baseline.** Every POAM entry that applies to all regions must be anchored to an ISO 42001 Annex A or Clause control ID as its primary identifier. NIST SP 800-53, EU AI Act, and MAS FEAT control IDs are co-framework citations only.
2. **Regional postures are additive, modular, and non-merged.** A weakness that only exists in US_FED (e.g., ATO process) must never appear in the EU_ECB or APAC_MAS POAM files. A weakness that exists in all regions must appear in the global ISO 42001 POAM with `regions: ALL`.
3. **Monorepo is the single source of truth.** All POAM files live in `docs/` and are cross-referenced by `docs/SECURITY_STATUS.md`, `ARCHITECTURE.md`, and `README.md`.
4. **Traceability and auditability are preserved.** Every entry retains its original POAM-NNN ID (for audit trail continuity), gains a new `iso42001_id` field, and gains a `regions` tag.

### 3.2 Target File Layout

```
docs/
├── POAM.md              → RENAMED to docs/POAM_US_FED.md
├── POAM_US_FED.md       # NIST SP 800-53 / ATO track (US_FED only)
├── POAM_ISO42001.md     # NEW — universal ISO 42001 AIMS weaknesses (all regions)
├── POAM_EU_ECB.md       # NEW — EU AI Act / DORA / GDPR weaknesses (EU_ECB only)
├── POAM_APAC_MAS.md     # NEW — MAS FEAT / Notice 655 / TRM weaknesses (APAC_MAS only)
└── POAM_INDEX.md        # NEW — master index with cross-region traceability matrix
```

The existing [`docs/POAM.md`](../docs/POAM.md) is **renamed** to `docs/POAM_US_FED.md` and its header is updated to declare `Region: US_FED`. Its 23 entries are retained verbatim — no content is lost.

### 3.3 Metadata Schema

Every entry in every POAM file gains two new columns in its Markdown table:

| New Column | Values | Description |
|---|---|---|
| `ISO 42001 Ref` | `§A.X.Y` or `§N.N` | Primary ISO 42001 Annex A or Clause reference |
| `Regions` | `ALL`, `US_FED`, `EU_ECB`, `APAC_MAS` | Deployment regions where this weakness applies |

Each file also gains a YAML front-matter block at the top:

```yaml
---
poam_file: POAM_US_FED        # or POAM_ISO42001, POAM_EU_ECB, POAM_APAC_MAS
region_scope: US_FED          # or ALL, EU_ECB, APAC_MAS
primary_framework: NIST SP 800-53 Rev. 5   # or ISO 42001, EU AI Act, MAS FEAT
global_baseline: ISO 42001
version: "2.0"
date: 2026-06-08
---
```

### 3.4 Entry Routing Decision Tree

```
Does the weakness apply to ALL deployment regions?
├── YES → docs/POAM_ISO42001.md
│         Primary ID: ISO 42001 Annex A or Clause
│         Example: Langfuse credential silent failure (all regions lose audit evidence)
│
└── NO → Is it US_FED-specific (NIST RMF / ATO / FIPS 199)?
          ├── YES → docs/POAM_US_FED.md
          │         Primary ID: NIST SP 800-53 control
          │         Example: ATO letter (POAM-005), SSP (POAM-015)
          │
          └── NO → Is it EU_ECB-specific (EU AI Act / DORA / GDPR)?
                    ├── YES → docs/POAM_EU_ECB.md
                    │         Primary ID: EU AI Act article or DORA article
                    │         Example: DORA Art. 12 resilience testing not started
                    │
                    └── NO → docs/POAM_APAC_MAS.md
                              Primary ID: MAS FEAT principle or MAS Notice 655 section
                              Example: MAS FEAT F2 quantitative fairness metrics pending
```

---

## 4. Entry Migration Map

### 4.1 Entries Moving to `docs/POAM_ISO42001.md` (universal — all regions)

These entries describe weaknesses in the ISO 42001 AIMS that affect every deployment region. They are **moved out** of `POAM_US_FED.md` and re-anchored to ISO 42001 primary IDs. Their original POAM-NNN IDs are preserved for audit continuity.

| Original ID | New ISO 42001 Primary ID | Weakness | Co-framework (NIST) | Regions |
|---|---|---|---|---|
| POAM-018 | ISO 42001 §A.9.4 | Langfuse compliance credentials fail silently | AU-9 | ALL |
| POAM-019 | ISO 42001 §A.9.4 | Terraform telemetry isolation collapse | AU-9, SC-7 | ALL |
| *(new)* ISO-001 | ISO 42001 §A.4 | CTRL_TQP_007 OPA runtime injection deferred — `quota_within_limits` rule lacks live Redis session state | SC-5 | ALL |
| *(new)* ISO-002 | ISO 42001 §6.1 | UCA-4 not yet added to `config/stpa_control_structure.yaml` | SI-2 | ALL |
| *(new)* ISO-003 | ISO 42001 §9.1 | No Clause 9 management review records exist for any region | CA-5 | ALL |
| *(new)* ISO-004 | ISO 42001 §A.6.1 | `compliance/oscal/component-definition.yaml` missing CTRL_TQP_007 entry | CA-7 | ALL |

### 4.2 Entries Staying in `docs/POAM_US_FED.md` (US_FED only)

All 23 existing entries remain in `POAM_US_FED.md`. POAM-018 and POAM-019 are **moved** to `POAM_ISO42001.md` (see above) and replaced with `see-also` cross-references in `POAM_US_FED.md`. All other entries stay unchanged.

POAM-022 is **split**: the NIST SA-9/CA-7 aspect stays in `POAM_US_FED.md`; a new `EU-001` entry in `POAM_EU_ECB.md` tracks the EU AI Act Art. 29a FRIA gating gap specifically.

Two new columns are added to the existing table: `ISO 42001 Ref` and `Regions`.

| ID | ISO 42001 Ref | Regions | Notes |
|---|---|---|---|
| POAM-001 | §A.9.2 | US_FED | Account management maps to ISO 42001 §A.9.2 (access control) |
| POAM-002 | §A.9.2 | US_FED | IAM least-privilege maps to ISO 42001 §A.9.2 |
| POAM-003 | §A.9.4 | US_FED | Closed — live OSCAL assessment confirmed |
| POAM-004 | §10.2 | US_FED | POA&M process maps to ISO 42001 §10.2 (nonconformity and corrective action) |
| POAM-005 | N/A | US_FED | ATO has no ISO 42001 equivalent — US_FED-only regulatory obligation |
| POAM-006 | §A.8.3 | US_FED | SBOM maps to ISO 42001 §A.8.3 (supply chain) |
| POAM-007 | §A.9.3 | US_FED | Closed — Linkerd mTLS deployed |
| POAM-008 | §6.1 | US_FED | IRP maps to ISO 42001 §6.1 (risk treatment) |
| POAM-009 | N/A | US_FED | FIPS 199 has no ISO 42001 equivalent — US_FED-only |
| POAM-010 | §A.8.3 | US_FED | Closed — pip-audit, Trivy, Grype active |
| POAM-011 | §A.9.3 | US_FED | TLS enforcement maps to ISO 42001 §A.9.3 (network security) |
| POAM-012 | §A.6.1 | US_FED | Routing seal bypass maps to ISO 42001 §A.6.1 (policy enforcement) |
| POAM-013 | §A.8.3 | US_FED | Unpinned deps maps to ISO 42001 §A.8.3 (supply chain) |
| POAM-014 | §A.9.3 | US_FED | CMEK maps to ISO 42001 §A.9.3 (data protection) |
| POAM-015 | N/A | US_FED | SSP has no ISO 42001 equivalent — US_FED-only |
| POAM-016 | §A.8.3 | US_FED | Closed — diskcache removed |
| POAM-017 | §A.8.3 | US_FED | CVE-2026-4810 maps to ISO 42001 §A.8.3 |
| POAM-018 | → moved to POAM_ISO42001.md | ALL | See ISO 42001 §A.9.4 entry |
| POAM-019 | → moved to POAM_ISO42001.md | ALL | See ISO 42001 §A.9.4 entry |
| POAM-020 | §10.2 | US_FED | Closed — version mismatch corrected |
| POAM-021 | §A.9.4 | US_FED | Closed — remote exporter confirmed |
| POAM-022 | §A.6.1 | US_FED | NIST SA-9/CA-7 aspect; EU AI Act Art. 29a aspect → EU-001 |
| POAM-023 | §A.8.3 | US_FED | CVE-2025-13462 maps to ISO 42001 §A.8.3 |

### 4.3 New entries for `docs/POAM_EU_ECB.md` (EU_ECB only)

| New ID | Primary Framework | ISO 42001 Co-ref | Weakness | Status |
|---|---|---|---|---|
| EU-001 | EU AI Act Art. 29a | §A.6.1 | FRIA gating in stub mode — TrustLayers credentials not provisioned | In Progress |
| EU-002 | DORA Art. 12 | §A.8.4 | No DORA resilience testing performed | Open |
| EU-003 | EU AI Act Art. 6 + Annex III §5(b) | §A.5.2 | EU AI Office registration pending | Open |
| EU-004 | GDPR Art. 35 | §A.6.2 | DPIA not integrated with CAGE deployment | Open |
| EU-005 | EU AI Act Art. 12 | §A.9.4 | GDPR-compliant audit log retention schedule not documented | Open |

### 4.4 New entries for `docs/POAM_APAC_MAS.md` (APAC_MAS only)

| New ID | Primary Framework | ISO 42001 Co-ref | Weakness | Status |
|---|---|---|---|---|
| MAS-001 | MAS FEAT F2 | §A.5.2 | Quantitative fairness metrics not computed (demographic parity, equalized odds) | Open |
| MAS-002 | MAS Notice 655 §12 | §A.9.4 | MAS Notice 655 audit certification not obtained | Open |
| MAS-003 | MAS TRM §6.3 | §A.6.2 | MAS ENRM validation not performed | Open |
| MAS-004 | MAS FEAT T1 | §A.9.4 | Formal transparency report not produced | Open |

---

## 5. Cross-Region Traceability: `docs/POAM_INDEX.md`

The index file provides a single-page view across all four POAM files. It contains:

1. **Summary counts table** — Open/Closed/In Progress per file and per region
2. **Cross-reference matrix** — entries that appear in multiple files (e.g., POAM-018 in ISO42001 + referenced in US_FED)
3. **ISO 42001 Annex A coverage map** — which Annex A controls have POAM entries vs. which are untracked
4. **Lula validation linkage** — which POAM entries have a corresponding Lula validation manifest

Example Annex A coverage map (partial):

| ISO 42001 Control | Description | POAM Entry | Lula Manifest |
|---|---|---|---|
| §A.4 | Resource Management | ISO-001 | *(none — to be created)* |
| §A.5.2 | Social Impact Assessment | POAM-001 (US_FED), MAS-001 | `lula-validation-a52.yaml` |
| §A.6.1 | Policy Enforcement | POAM-012, EU-001, ISO-004 | `lula-validation-sc4.yaml` |
| §A.8.3 | Supply Chain | POAM-006, POAM-013, POAM-017, POAM-023 | *(none)* |
| §A.8.4 | WAL / Continuity | EU-002 | *(none)* |
| §A.9.2 | Access Control | POAM-001, POAM-002 | `lula-validation-ac2.yaml`, `lula-validation-ac3.yaml` |
| §A.9.3 | Network / Data Protection | POAM-011, POAM-014 | `lula-validation-sc8.yaml` |
| §A.9.4 | Telemetry / Monitoring | POAM-018→ISO, POAM-019→ISO, EU-005, MAS-002, MAS-004 | `lula-validation-a53.yaml` |
| §6.1 | Risk Treatment / IRP | POAM-008, ISO-002 | *(none)* |
| §9.1 | Management Review | ISO-003 | *(none)* |
| §10.2 | Corrective Action | POAM-004, POAM-020 | *(none)* |

---

## 6. Implementation Plan

### Phase 1 — Rename and annotate (no content loss)

- [ ] Rename `docs/POAM.md` → `docs/POAM_US_FED.md`
- [ ] Add YAML front-matter block to `docs/POAM_US_FED.md` declaring `region_scope: US_FED`
- [ ] Add `ISO 42001 Ref` and `Regions` columns to the existing 23-entry table in `POAM_US_FED.md`
- [ ] Add `see-also` cross-reference notes for POAM-018 and POAM-019 (moved to ISO42001 file)
- [ ] Update all existing cross-references in `README.md`, `ARCHITECTURE.md`, `docs/SECURITY_STATUS.md` from `docs/POAM.md` → `docs/POAM_US_FED.md`

### Phase 2 — Create `docs/POAM_ISO42001.md`

- [ ] Create `docs/POAM_ISO42001.md` with YAML front-matter (`region_scope: ALL`, `primary_framework: ISO 42001`)
- [ ] Migrate POAM-018 and POAM-019 entries (verbatim content, new ISO 42001 primary IDs)
- [ ] Add new entries ISO-001 through ISO-004 (CTRL_TQP_007 OPA injection, UCA-4, Clause 9 review, OSCAL component definition)
- [ ] Add `ISO 42001 Ref` and `Regions` columns

### Phase 3 — Create `docs/POAM_EU_ECB.md`

- [ ] Create `docs/POAM_EU_ECB.md` with YAML front-matter (`region_scope: EU_ECB`, `primary_framework: EU AI Act / DORA / GDPR`)
- [ ] Add entries EU-001 through EU-005 (FRIA stub, DORA Art. 12, EU AI Office, DPIA, retention schedule)
- [ ] Split POAM-022: add `see-also: POAM_US_FED.md#POAM-022` cross-reference

### Phase 4 — Create `docs/POAM_APAC_MAS.md`

- [ ] Create `docs/POAM_APAC_MAS.md` with YAML front-matter (`region_scope: APAC_MAS`, `primary_framework: MAS FEAT / Notice 655 / TRM`)
- [ ] Add entries MAS-001 through MAS-004 (F2 fairness metrics, Notice 655 cert, ENRM, transparency report)

### Phase 5 — Create `docs/POAM_INDEX.md`

- [ ] Create `docs/POAM_INDEX.md` with summary counts, cross-reference matrix, ISO 42001 Annex A coverage map, and Lula linkage table
- [ ] Add `POAM_INDEX.md` link to `docs/SECURITY_STATUS.md` References section

### Phase 6 — Update `docs/SECURITY_STATUS.md`

- [ ] Update the Infrastructure Security Gaps section header to reference `POAM_US_FED.md` (not `POAM.md`)
- [ ] Add a new "ISO 42001 AIMS Gaps" subsection referencing `POAM_ISO42001.md`
- [ ] Add "EU_ECB POAM" and "APAC_MAS POAM" links in the respective regional compliance sections

### Phase 7 — Commit

Suggested commit message:
```
docs(compliance): restructure POAM into multi-posture framework

Rename docs/POAM.md → docs/POAM_US_FED.md (NIST SP 800-53 / ATO track).
Create docs/POAM_ISO42001.md (universal ISO 42001 AIMS weaknesses, all regions).
Create docs/POAM_EU_ECB.md (EU AI Act / DORA / GDPR, EU_ECB only).
Create docs/POAM_APAC_MAS.md (MAS FEAT / Notice 655 / TRM, APAC_MAS only).
Create docs/POAM_INDEX.md (cross-region traceability matrix).

Migrate POAM-018 and POAM-019 to POAM_ISO42001.md (universal Langfuse
telemetry isolation gaps). Add ISO-001 through ISO-004 (CTRL_TQP_007 OPA
injection, UCA-4 STPA, Clause 9 review, OSCAL component definition).
Add EU-001 through EU-005 and MAS-001 through MAS-004.

Add ISO 42001 Ref and Regions columns to all POAM tables.
Update cross-references in README.md, ARCHITECTURE.md, SECURITY_STATUS.md.

[CR-2026-TQP-001]
```

---

## 7. Architectural Invariants Preserved

| Invariant | How preserved |
|---|---|
| Monorepo is single source of truth | All five POAM files live in `docs/`; no external tracking |
| ISO 42001 is universal baseline | `POAM_ISO42001.md` is the root document; all regional files declare `global_baseline: ISO 42001` |
| Regional postures are additive and modular | `POAM_EU_ECB.md` and `POAM_APAC_MAS.md` contain only region-specific entries; no NIST control IDs appear as primary IDs |
| Audit trail continuity | All original POAM-NNN IDs retained; moved entries carry `originally-in: POAM_US_FED.md` annotation |
| Traceability | `POAM_INDEX.md` provides cross-file matrix; `see-also` links connect split entries |
| Lula validation alignment | Lula manifests already use `cage.region` annotations (ALL / US_FED / EU_ECB / APAC_MAS); POAM `Regions` column mirrors this pattern exactly |
| `.clinerules` §5 compliance | Universal gates remain ISO 42001-only; regional gates are additive layers — POAM structure now matches this architecture |
