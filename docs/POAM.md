# Plan of Action and Milestones (POA&M) — Redirect Notice

> **⚠️ This file has been superseded.** As of 2026-06-08, the POAM has been restructured into a multi-posture framework. This file is retained for backward compatibility with historical document cross-references only.

## New POAM Structure

| File | Region Scope | Primary Framework |
|---|---|---|
| [`docs/POAM_INDEX.md`](POAM_INDEX.md) | ALL | Cross-region traceability matrix |
| [`docs/POAM_ISO42001.md`](POAM_ISO42001.md) | ALL | ISO/IEC 42001:2023 universal AIMS weaknesses |
| [`docs/POAM_US_FED.md`](POAM_US_FED.md) | US_FED | NIST SP 800-53 Rev. 5 / NIST RMF |
| [`docs/POAM_EU_ECB.md`](POAM_EU_ECB.md) | EU_ECB | EU AI Act / DORA / GDPR |
| [`docs/POAM_APAC_MAS.md`](POAM_APAC_MAS.md) | APAC_MAS | MAS FEAT / Notice 655 / TRM |

**Start here:** [`docs/POAM_INDEX.md`](POAM_INDEX.md)

For the original NIST SP 800-53 / US_FED content (all 23 original entries), see [`docs/POAM_US_FED.md`](POAM_US_FED.md).

---

## Notable Items Added in v2.0.0 (2026-06-08)

| ID | Control | Weakness | Severity | Status | Target Date |
|----|---------|----------|----------|--------|-------------|
| POAM-023 | SI-2 | CTRL_TQP_007 OPA runtime injection deferred — Token Quota Proxy enforces budget via Redis counters; OPA policy injection is a follow-on task | Open | Open | 2026-08-01 |

> POAM-023 is tracked in [`docs/POAM_US_FED.md`](POAM_US_FED.md) and [`docs/SECURITY_STATUS.md`](SECURITY_STATUS.md). The gateway Dockerfile was pinned to `python:3.12-slim-bookworm` with `apt-get upgrade` applied; residual CVE-2025-13462 (`libpython3.11`) has no Debian bookworm fix as of 2026-06-08 and is suppressed via `.trivyignore` with Cilium egress lockdown reducing exploitability.

---

_Superseded by `docs/POAM_US_FED.md` v2.0 (2026-06-08). See [`plans/poam-framework-redesign.md`](../plans/poam-framework-redesign.md) for the redesign rationale._
