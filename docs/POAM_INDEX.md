---
poam_file: POAM_INDEX
region_scope: ALL
version: "1.0"
date: 2026-06-08
---

# POA&M Master Index — Cross-Region Traceability Matrix

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Date:** 2026-06-08
**Status:** ACTIVE

This index provides a single-page view across all four POAM files. It is the authoritative cross-region traceability document. All POAM files are in `docs/` and are the single source of truth — no external tracking system is used.

---

## File Registry

| File | Region Scope | Primary Framework | Entries | Open | In Progress | Closed |
|---|---|---|---|---|---|---|
| [`docs/POAM_ISO42001.md`](POAM_ISO42001.md) | ALL | ISO/IEC 42001:2023 | 6 | 5 | 1 | 0 |
| [`docs/POAM_US_FED.md`](POAM_US_FED.md) | US_FED | NIST SP 800-53 Rev. 5 | 23 | 12 | 3 | 6 |
| [`docs/POAM_EU_ECB.md`](POAM_EU_ECB.md) | EU_ECB | EU AI Act / DORA / GDPR | 5 | 4 | 1 | 0 |
| [`docs/POAM_APAC_MAS.md`](POAM_APAC_MAS.md) | APAC_MAS | MAS FEAT / Notice 655 / TRM | 4 | 4 | 0 | 0 |
| **Total** | | | **38** | **25** | **5** | **6** |

> **Note:** POAM-018 and POAM-019 appear in both `POAM_US_FED.md` (NIST AU-9/SC-7 aspect) and `POAM_ISO42001.md` (ISO 42001 §A.9.4 universal aspect). They are counted once in the totals above (under ISO42001). POAM-022 appears in `POAM_US_FED.md` (NIST SA-9/CA-7 aspect) and is cross-referenced to `POAM_EU_ECB.md#EU-001` (EU AI Act Art. 29a aspect).

---

## Cross-Reference Matrix

Entries that appear in multiple files or have explicit `see-also` relationships:

| Entry | File | Cross-Reference | Relationship |
|---|---|---|---|
| POAM-018 | `POAM_US_FED.md` | `POAM_ISO42001.md#POAM-018` | Same weakness; NIST AU-9 aspect (US_FED) + ISO 42001 §A.9.4 aspect (ALL) |
| POAM-019 | `POAM_US_FED.md` | `POAM_ISO42001.md#POAM-019` | Same weakness; NIST AU-9/SC-7 aspect (US_FED) + ISO 42001 §A.9.4 aspect (ALL) |
| POAM-022 | `POAM_US_FED.md` | `POAM_EU_ECB.md#EU-001` | Split entry; NIST SA-9/CA-7 aspect (US_FED) + EU AI Act Art. 29a aspect (EU_ECB) |
| EU-001 | `POAM_EU_ECB.md` | `POAM_US_FED.md#POAM-022` | Split entry; EU AI Act Art. 29a aspect (EU_ECB) + NIST SA-9/CA-7 aspect (US_FED) |

---

## ISO 42001 Annex A Coverage Map

Which ISO 42001 Annex A controls and Clauses have POAM entries vs. which are untracked:

| ISO 42001 Control | Description | POAM Entries | Lula Manifest | Coverage |
|---|---|---|---|---|
| §4 (Clause) | Context of the organization | — | — | ⬜ Not tracked |
| §6.1 (Clause) | Risk treatment / STPA | ISO-002, POAM-008 (US_FED) | — | 🟡 Partial |
| §6.2 (Clause) | AI objectives | — | — | ⬜ Not tracked |
| §8 (Clause) | Operational planning | — | — | ⬜ Not tracked |
| §9.1 (Clause) | Performance evaluation | ISO-003 | — | 🟡 Partial |
| §9.3 (Clause) | Management review | ISO-003 | — | 🟡 Partial |
| §10.2 (Clause) | Corrective action | POAM-004, POAM-020 (US_FED) | — | 🟡 Partial |
| §A.4 | Resource Management | ISO-001 | — | 🟡 Partial |
| §A.5.2 | Social Impact Assessment | POAM-001 (US_FED), MAS-001 (APAC_MAS) | [`lula-validation-a52.yaml`](../compliance/lula/lula-validation-a52.yaml) | ✅ Active Lula |
| §A.5.3 | Logging and Monitoring | — | [`lula-validation-a53.yaml`](../compliance/lula/lula-validation-a53.yaml) | ✅ Active Lula |
| §A.6.1 | Policy Enforcement | POAM-012 (US_FED), EU-001 (EU_ECB), ISO-004 | [`lula-validation-sc4.yaml`](../compliance/lula/lula-validation-sc4.yaml) | ✅ Active Lula |
| §A.6.2 | Data Governance | EU-004 (EU_ECB), MAS-003 (APAC_MAS) | — | 🟡 Partial |
| §A.8.3 | Supply Chain | POAM-006, POAM-013, POAM-017, POAM-023 (US_FED) | — | 🟡 Partial |
| §A.8.4 | WAL / Continuity | EU-002 (EU_ECB) | — | 🟡 Partial |
| §A.9.2 | Access Control | POAM-001, POAM-002 (US_FED) | [`lula-validation-ac2.yaml`](../compliance/lula/lula-validation-ac2.yaml), [`lula-validation-ac3.yaml`](../compliance/lula/lula-validation-ac3.yaml) | 🔶 Stub Lula |
| §A.9.3 | Network / Data Protection | POAM-007, POAM-011, POAM-014 (US_FED) | [`lula-validation-sc8.yaml`](../compliance/lula/lula-validation-sc8.yaml) | 🔶 Stub Lula |
| §A.9.4 | Telemetry / Monitoring | POAM-018→ISO, POAM-019→ISO, EU-005 (EU_ECB), MAS-002, MAS-004 (APAC_MAS) | [`lula-validation-a53.yaml`](../compliance/lula/lula-validation-a53.yaml) | ✅ Active Lula |
| §A.9.2 (privacy) | Data Privacy / PII | — | [`lula-validation-a92.yaml`](../compliance/lula/lula-validation-a92.yaml) | ✅ Active Lula |

**Legend:** ✅ Active Lula = production-ready Lula manifest | 🔶 Stub Lula = manifest exists but requires cluster configuration | 🟡 Partial = POAM entry exists but no Lula manifest | ⬜ Not tracked = no POAM entry and no Lula manifest

---

## Severity Summary by Region

| Severity | ISO42001 (ALL) | US_FED | EU_ECB | APAC_MAS | Total |
|---|---|---|---|---|---|
| **Critical** | 0 | 4 | 1 | 0 | 5 |
| **High** | 2 | 13 | 2 | 2 | 19 |
| **Moderate** | 4 | 6 | 2 | 2 | 14 |
| **Low** | 0 | 0 | 0 | 0 | 0 |
| **Total** | 6 | 23 | 5 | 4 | 38 |

---

## Status Summary by Region

| Status | ISO42001 (ALL) | US_FED | EU_ECB | APAC_MAS | Total |
|---|---|---|---|---|---|
| **Open** | 5 | 12 | 4 | 4 | 25 |
| **In Progress** | 1 | 3 | 1 | 0 | 5 |
| **Closed** | 0 | 6 | 0 | 0 | 6 |
| **Total** | 6 | 23 | 5 | 4 | 38 |

---

## Lula Validation Linkage

Which POAM entries have a corresponding Lula validation manifest:

| Lula Manifest | Region | ISO 42001 Control | NIST Control | POAM Entries Covered |
|---|---|---|---|---|
| [`lula-validation-a52.yaml`](../compliance/lula/lula-validation-a52.yaml) | ALL | §A.5.2 | — | POAM-001 (US_FED), MAS-001 (APAC_MAS) |
| [`lula-validation-a53.yaml`](../compliance/lula/lula-validation-a53.yaml) | ALL | §A.5.3 | AU-12 | POAM-003 (US_FED, Closed) |
| [`lula-validation-a92.yaml`](../compliance/lula/lula-validation-a92.yaml) | ALL | §A.9.2 | — | — |
| [`lula-validation-aarm-vectors.yaml`](../compliance/lula/lula-validation-aarm-vectors.yaml) | ALL | §A.5.2, §A.9.4 | — | — |
| [`lula-validation-sc4.yaml`](../compliance/lula/lula-validation-sc4.yaml) | US_FED | §A.6.1 | SC-4 | POAM-012 (US_FED) |
| [`lula-validation-ac2.yaml`](../compliance/lula/lula-validation-ac2.yaml) | US_FED | §A.9.2 | AC-2 | POAM-001 (US_FED) |
| [`lula-validation-ac3.yaml`](../compliance/lula/lula-validation-ac3.yaml) | US_FED | §A.9.2 | AC-3 | POAM-002 (US_FED) |
| [`lula-validation-au12.yaml`](../compliance/lula/lula-validation-au12.yaml) | US_FED | §A.9.4 | AU-12 | POAM-003 (US_FED, Closed) |
| [`lula-validation-cm6.yaml`](../compliance/lula/lula-validation-cm6.yaml) | US_FED | §10.2 | CM-6 | — |
| [`lula-validation-ia3.yaml`](../compliance/lula/lula-validation-ia3.yaml) | US_FED | §A.9.3 | IA-3 | POAM-007 (US_FED, Closed) |
| [`lula-validation-ia5.yaml`](../compliance/lula/lula-validation-ia5.yaml) | US_FED | §A.9.3 | IA-5 | — |
| [`lula-validation-ir6.yaml`](../compliance/lula/lula-validation-ir6.yaml) | US_FED | §6.1 | IR-6 | POAM-008 (US_FED) |
| [`lula-validation-ra5.yaml`](../compliance/lula/lula-validation-ra5.yaml) | US_FED | §A.8.3 | RA-5 | POAM-010 (US_FED, Closed) |
| [`lula-validation-sc8.yaml`](../compliance/lula/lula-validation-sc8.yaml) | US_FED | §A.9.3 | SC-8 | POAM-011 (US_FED) |
| [`lula-validation-si2.yaml`](../compliance/lula/lula-validation-si2.yaml) | US_FED | §A.8.3 | SI-2 | POAM-013, POAM-017, POAM-023 (US_FED) |
| *(to be created)* `lula-validation-tqp007.yaml` | ALL | §A.4 | SC-5 | ISO-001, ISO-004 |

---

## Architectural Invariants

| Invariant | Status |
|---|---|
| ISO 42001 is the universal baseline | ✅ `POAM_ISO42001.md` is the root document; all regional files declare `global_baseline: ISO 42001` |
| Regional postures are additive and modular | ✅ `POAM_EU_ECB.md` and `POAM_APAC_MAS.md` contain only region-specific entries; no NIST control IDs appear as primary IDs |
| Monorepo is single source of truth | ✅ All five POAM files live in `docs/`; no external tracking system |
| Audit trail continuity | ✅ All original POAM-NNN IDs retained; moved entries carry `originally-in` annotations |
| Lula validation alignment | ✅ Lula manifests use `cage.region` annotations (ALL / US_FED); POAM `Regions` column mirrors this pattern |
| `.clinerules` §5 compliance | ✅ Universal gates remain ISO 42001-only; regional gates are additive layers — POAM structure matches this architecture |
| SR 26-2 suppression | ✅ US Federal Reserve guidance suppressed in EU_ECB and APAC_MAS OTel spans via sentinel mechanism; not referenced as primary framework in EU/APAC POAM files |

---

_This index is updated whenever any POAM file is modified. Last updated: 2026-06-08._
