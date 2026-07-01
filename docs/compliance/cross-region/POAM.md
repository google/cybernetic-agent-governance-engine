# Plan of Action and Milestones (POA&M) — Redirect Notice

> **⚠️ This file has been superseded.** As of 2026-06-08, the POAM has been restructured into a multi-posture framework. This file is retained for backward compatibility with historical document cross-references only.

## New POAM Structure

| File | Region Scope | Primary Framework |
|---|---|---|
| [`docs/POAM_INDEX.md`](POAM_INDEX.md) | ALL | Cross-region traceability matrix |
| [`docs/POAM_ISO42001.md`](../universal/POAM_ISO42001.md) | ALL | ISO/IEC 42001:2023 universal AIMS weaknesses |
| [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md) | US_FED | NIST SP 800-53 Rev. 5 / NIST RMF |
| [`docs/POAM_EU_ECB.md`](../eu_ecb/POAM_EU_ECB.md) | EU_ECB | EU AI Act / DORA / GDPR |
| [`docs/POAM_APAC_MAS.md`](../apac_mas/POAM_APAC_MAS.md) | APAC_MAS | MAS FEAT / Notice 655 / TRM |

**Start here:** [`docs/POAM_INDEX.md`](POAM_INDEX.md)

For the original NIST SP 800-53 / US_FED content (all 23 original entries), see [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md).

---

## Notable Items Added in v0.1.0 (2026-06-08)

| ID | Control | Weakness | Severity | Status | Target Date |
|----|---------|----------|----------|--------|-------------|
| POAM-023 | SI-2 | CVE-2025-13462 in `libpython3.11` (python:3.12-slim-bookworm base layer) — 19 CRITICAL CVEs; no Debian bookworm fix available as of 2026-06-08; suppressed via `.trivyignore`; Cilium egress lockdown reduces exploitability; risk accepted with review date 2026-09-08 | Critical | Open | 2026-09-08 |

> POAM-023 is tracked in [`docs/POAM_US_FED.md`](../us_fed/POAM_US_FED.md) and [`docs/SECURITY_STATUS.md`](../../security/SECURITY_STATUS.md). The gateway Dockerfile was pinned to `python:3.12-slim-bookworm` with `apt-get upgrade -y` applied at build time; residual CVE-2025-13462 (`libpython3.11`) has no Debian bookworm fix as of 2026-06-08 and is suppressed via `.trivyignore` with Cilium egress lockdown reducing exploitability. The OPA runtime injection deferral (CTRL_TQP_007 secondary enforcement) is tracked separately as ISO-001 in [`docs/POAM_ISO42001.md`](../universal/POAM_ISO42001.md).

---

_Superseded by `docs/POAM_US_FED.md` v2.0 (2026-06-08). See [`plans/poam-framework-redesign.md`](../plans/poam-framework-redesign.md) for the redesign rationale._
