# Regional Posture Validation Report

> **Correction Notice (`POAM-2026-121` / `POAM-2026-123`):** The independent-composability claims in the original v3.0.1 publication (Executive Summary, §3 `Independence Guarantee` / `Key Finding`, and §7 Conclusion) are **withdrawn**, the superseded §3 12-cell hash table (computed against `3b69207c`) is **removed**, and §5.2's nonexistent ISO 42001 JSON path is corrected to `config/oscal/framework_mappings/ISO_42001.json` and `compliance/oscal/component-definition.yaml`. Under `POAM-2026-123`, [`ControlRegistry`](../../src/gateway/governance/constants.py) now fails closed with `ControlOverlayCollisionError` on undeclared collisions, the duplicate `CTRL_FTRA_001` override has been removed from `src/cage_finance/config/compliance/US_FED_OVERLAY.json`, and collision + multi-plugin composition enforcement is tested in [`tests/test_regional_overlay_merge.py`](../../tests/test_regional_overlay_merge.py) (`pytest-logic`). The remaining sections retain the historical v3.0.1 test/posture record; `.github/workflows/regional-posture.yml` watches plugin overlay/threshold paths and runs as a post-merge/dispatch check rather than a PR-blocking gate.

**Date:** 2026-09-04 (withdrawal applied under `POAM-2026-121`)
**CAGE Version:** v3.0.1 (historical snapshot; overlay enforcement updated in `ControlRegistry`)
**Validator:** Automated Test Suite + Manual Verification
**Scope:** Task C2 — Regional Compliance Posture Validation

---

## Executive Summary

All three regional compliance postures (`US_FED`, `EU_ECB`, `APAC_MAS`) ran their v3.0.1 regional marker suites and posture checks. **Withdrawn claim (`POAM-2026-121`):** the original statement asserting *"confirming independent composability of domain plugins and jurisdictional overlays"* is withdrawn. Runtime additive-only overlay composition is now enforced fail-closed by [`ControlRegistry`](../../src/gateway/governance/constants.py) (`ControlOverlayCollisionError`) and verified on PRs in [`tests/test_regional_overlay_merge.py`](../../tests/test_regional_overlay_merge.py).

**Overall Status (Historical v3.0.1 Snapshot):** ⚠️ **RETAINED WITH §3 INDEPENDENCE CLAIM WITHDRAWN (`POAM-2026-121`)**

| Region | Test Suite | Posture Checker | Status |
|--------|-----------|-----------------|--------|
| **US_FED** | 18 passed | N/A (implicit in baseline) | ✅ PASS |
| **EU_ECB** | 10 passed, 3 skipped | All checks passed | ✅ PASS |
| **APAC_MAS** | 12 passed | All checks passed | ✅ PASS |

---

## 1. Regional Test Suite Results

### 1.1 US_FED (United States Federal)

**Regulatory Framework:** NIST SP 800-53 Rev. 5, FISMA, FedRAMP

```bash
CAGE_DEPLOYMENT_REGION=US_FED uv run pytest tests/ -m us_fed -v
```

**Results:**
- **Total:** 18 tests
- **Passed:** 18 ✅
- **Failed:** 0
- **Duration:** 28.50s

**Key Validations:**
- ✅ US_FED thresholds file exists and is valid JSON
- ✅ NIST SP 800-53 control mappings are complete
- ✅ Tier 1 governance keywords present
- ✅ STPA, consensus, and CBF sections configured
- ✅ Regional marker correctly set to `US_FED`
- ✅ UCA-4 (unsafe control action) maps to NIST controls
- ✅ Jurisdiction field correctly specified
- ✅ All three regional baselines present in thresholds directory

**Compliance Artifacts Verified:**
- `config/compliance/US_FED_BASELINE.json`
- `config/thresholds/US_FED_BASELINE.json`
- `config/oscal/framework_mappings/NIST_SP800_53.json`

---

### 1.2 EU_ECB (European Union - European Central Bank)

**Regulatory Framework:** EU AI Act, GDPR, DORA, ECB Banking Supervision

```bash
CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/ -m eu_ecb -v
```

**Results:**
- **Total:** 13 tests
- **Passed:** 10 ✅
- **Skipped:** 3 (infrastructure-specific)
- **Failed:** 0
- **Duration:** 37.97s

**Key Validations:**
- ✅ GCS storage paths reference `europe-west1` region
- ✅ Cold-tier bucket does not reference non-EU regions
- ✅ Google Cloud location is `europe-west1`
- ✅ OSCAL S3 bucket (when explicit) references EU region
- ✅ EU_ECB baseline config loads successfully
- ✅ Terraform dev/prod tfvars reference `europe-west1`

**Skipped Tests (Expected):**
- Infrastructure provisioning tests requiring live GCP credentials
- Cross-region replication tests (not applicable to EU data residency requirements)

**Compliance Artifacts Verified:**
- `config/compliance/EU_ECB_BASELINE.json`
- `infra/targets/gcp-gke/eu-dev.tfvars`
- `infra/targets/gcp-gke/eu-prod.tfvars`
- `compliance/lula/lula-validation-eu-ai-act-art9.yaml`
- `compliance/lula/lula-validation-eu-fria.yaml`

---

### 1.3 APAC_MAS (Asia-Pacific - Monetary Authority of Singapore)

**Regulatory Framework:** MAS FEAT, MAS TRM, MAS Notice 655

```bash
CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -m apac_mas -v
```

**Results:**
- **Total:** 12 tests
- **Passed:** 12 ✅
- **Failed:** 0
- **Duration:** 35.61s

**Key Validations:**
- ✅ Google Cloud location is `asia-southeast1`
- ✅ GCS storage paths reference APAC region
- ✅ `CAGE_DEPLOYMENT_REGION` environment variable correctly set
- ✅ Cold-tier bucket references APAC region when explicit
- ✅ APAC_MAS baseline config is loadable
- ✅ Cold-tier bucket does not reference non-APAC regions
- ✅ Terraform prod tfvars reference `asia-southeast1`

**Compliance Artifacts Verified:**
- `config/compliance/APAC_MAS_BASELINE.json`
- `infra/targets/gcp-gke/apac-prod.tfvars`
- `compliance/lula/lula-validation-mas-feat.yaml`
- `compliance/lula/lula-validation-mas-notice655.yaml`
- `compliance/lula/lula-validation-mas-trm-s6.yaml`

---

## 2. Posture Checker Results

### 2.1 EU_ECB Posture Checker

```bash
uv run python scripts/check_eu_ecb_posture.py
```

**Status:** ✅ **PASS** — All EU_ECB compliance posture checks passed

**Detailed Checks:**

| Check Category | Validation | Status |
|----------------|------------|--------|
| **EU AI Act Lula Manifests** | Structure validity of `lula-validation-eu-ai-act-art9.yaml`, `lula-validation-eu-fria.yaml` | ✅ PASS (2/2) |
| **GDPR Art. 44 Data Residency** | Region = `europe-west1`, `cage_deployment_region=EU_ECB`, `enable_eu_ecb_compliance=true` | ✅ PASS |
| **DORA Art. 10 Audit Logging** | Configuration present | ✅ PASS |
| **SR 26-2 Telemetry Suppression** | Sentinel present in `EU_ECB_BASELINE.json` | ✅ PASS |
| **ISO 42001 Universal Lula Manifests** | `lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-a92.yaml`, `lula-validation-aarm-vectors.yaml` | ✅ PASS (4/4) |

---

### 2.2 APAC_MAS Posture Checker

```bash
uv run python scripts/check_apac_mas_posture.py
```

**Status:** ✅ **PASS** — All APAC_MAS compliance posture checks passed

**Detailed Checks:**

| Check Category | Validation | Status |
|----------------|------------|--------|
| **MAS FEAT Lula Manifests** | Structure validity of `lula-validation-mas-feat.yaml`, `lula-validation-mas-notice655.yaml`, `lula-validation-mas-trm-s6.yaml` | ✅ PASS (3/3) |
| **MAS TRM §4.2 Data Residency** | Region = `asia-southeast1`, `cage_deployment_region=APAC_MAS`, `enable_apac_mas_compliance=true` | ✅ PASS |
| **MAS Notice 655 Audit Logging** | Configuration present | ✅ PASS |
| **SR 26-2 Telemetry Suppression** | Sentinel present in `APAC_MAS_BASELINE.json` | ✅ PASS |
| **ISO 42001 Universal Lula Manifests** | `lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-a92.yaml`, `lula-validation-aarm-vectors.yaml` | ✅ PASS (4/4) |

---

### 2.3 Langfuse Posture Checker

```bash
uv run python scripts/verify_langfuse_posture.py --dry-run --posture development
```

**Status:** ⚠️ **SKIPPED** — Missing environment variables (expected in local dev environment)

**Note:** This check requires live Langfuse credentials (`LANGFUSE_HOST`, `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, etc.) which are not available in the local development environment. This is expected and does not indicate a posture failure. Live Langfuse validation is performed in GKE integration tests with proper credentials.

**Missing Variables:**
- `GOOGLE_CLOUD_PROJECT`
- `GOOGLE_CLOUD_LOCATION`
- `LANGFUSE_HOST`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_COMPLIANCE_HOST`
- `LANGFUSE_COMPLIANCE_PUBLIC_KEY`
- `LANGFUSE_COMPLIANCE_SECRET_KEY`

---

## 3. Plugin × Region Composition Matrix (**§3 Independence Claim Withdrawn**)

> **Withdrawn Claim (`POAM-2026-121` / `POAM-2026-123`):** Both the *"Independence Guarantee"* and *"Key Finding"* originally published in this section are **withdrawn**, and the 12-cell RFC 8785 JCS hash table originally published here has been **removed**. When published, `src/cage_finance/config/compliance/US_FED_OVERLAY.json` redefined the kernel's `CTRL_FTRA_001` (with colliding `internal_id`, `primary_framework`, `co_frameworks`, `legacy_citation`, and `description`), and [`ControlRegistry`](../../src/gateway/governance/constants.py) logged `"Control mapping collision"` at `WARNING` without failing. The removed 12-cell hashes reproduced only against `3b69207c` (the parent of the commit that published them) and matched no tree containing this report.
>
> **Current Enforcement (`HEAD`):** [`ControlRegistry`](../../src/gateway/governance/constants.py) enforces additive-only overlay composition (`ControlOverlayCollisionError` on undeclared collisions, protected-field writes, or `_`-meta overwrites), the stale `CTRL_FTRA_001` override is removed from `US_FED_OVERLAY.json`, and collision + multi-plugin composition enforcement is pinned in [`tests/test_regional_overlay_merge.py`](../../tests/test_regional_overlay_merge.py) (`pytest-logic`, required PR check). `.github/workflows/regional-posture.yml` watches `src/cage_*/config/compliance/**` and `src/cage_*/config/thresholds/**` alongside kernel baselines and runs post-merge/dispatch regional marker suites across `US_FED`, `EU_ECB`, and `APAC_MAS` (`continue-on-error: false`), not as a PR gate.

---

## 4. Universal vs. Regional Gate Results

Per [`AGENTS.md`](../../AGENTS.md), regional gates are **additive** — an ISO 42001 universal failure is disqualifying, while a region-specific failure blocks only that regional deployment posture.

### 4.1 Universal Gates (ISO 42001)

These gates apply to **all** regions and block the global stable tag if failed:

| Gate | Status | Scope |
|------|--------|-------|
| **ISO 42001 §A.5.2 (Operational Governance)** | ✅ PASS | Universal |
| **ISO 42001 §A.5.3 (Monitoring & Review)** | ✅ PASS | Universal |
| **ISO 42001 §A.9.2 (Documented Procedures)** | ✅ PASS | Universal |
| **AARM Attack Vectors** | ✅ PASS | Universal |

**Verdict:** No universal gate failures detected. Global stable tag is not blocked.

---

### 4.2 Regional Gates

These gates apply **only** to specific regional deployments:

#### US_FED Regional Gates

| Gate | Framework | Status |
|------|-----------|--------|
| **NIST SP 800-53 AC-3 (Access Enforcement)** | US_FED only | ✅ PASS |
| **NIST SP 800-53 AU-11 (Audit Record Retention)** | US_FED only | ✅ PASS |
| **FISMA Moderate Baseline** | US_FED only | ✅ PASS |

#### EU_ECB Regional Gates

| Gate | Framework | Status |
|------|-----------|--------|
| **EU AI Act Art. 9 (Risk Management)** | EU_ECB only | ✅ PASS |
| **GDPR Art. 44 (Data Residency)** | EU_ECB only | ✅ PASS |
| **DORA Art. 10 (Audit Logging)** | EU_ECB only | ✅ PASS |

#### APAC_MAS Regional Gates

| Gate | Framework | Status |
|------|-----------|--------|
| **MAS FEAT (Fairness, Ethics, Accountability, Transparency)** | APAC_MAS only | ✅ PASS |
| **MAS TRM §4.2 (Data Residency)** | APAC_MAS only | ✅ PASS |
| **MAS Notice 655 (Audit Logging)** | APAC_MAS only | ✅ PASS |

**Verdict:** No regional gate failures detected. All three regional deployment postures are approved.

---

## 5. Compliance Artifact Coverage

### 5.1 Lula Validation Manifests & POAM Coverage

Validated via `scripts/check_lula_stub_count.py` and `scripts/check_poam_lula_divergence.py`:

| Metric | Result | Status |
|--------|--------|--------|
| **Total Lula Validation Manifests on Disk** | 31 manifests | ✅ PASS |
| **Lula Stubs Count** | 0 stubs (baseline: 1) | ✅ PASS (0 stubs) |
| **POAM Closed Findings Mapped** | 36 covered, 14 skipped (structural) | ✅ 100% covered |
| **Uncovered POAM Findings** | 0 uncovered out of 50 closed findings | ✅ 0 uncovered |

**Regional & Universal Manifest Breakdown:**
- **Universal ISO 42001 & AI 600-1**: 11 manifests (`a52`, `a53`, `a92`, `aarm-vectors`, `ai600-cbrn`, `ai600-confabulation`, `ai600-data-privacy`, `ai600-human-ai-config`, `ai600-prompt-injection`, `iso001-token-quota`, `tqp007`)
- **NIST SP 800-53 Core Controls**: 13 manifests (`ac2`, `ac3`, `au12`, `cm6`, `ia3`, `ia5`, `ir6`, `ra5`, `sc4`, `sc8`, `si2`, etc.)
- **EU AI Act / GDPR / DORA**: 4 manifests (`eu-ai-act-art9`, `eu-fria`, `dora-art10`, `gdpr-art22`)
- **MAS FEAT / TRM / Notice 655**: 3 manifests (`mas-feat`, `mas-notice655`, `mas-trm-s6`)

**All 31 Lula manifests pass YAML structure validation and POAM traceability.**

---

### 5.2 OSCAL Component Definitions & Framework Mappings

| Framework | File Path | Status |
|-----------|-----------|--------|
| **ISO 42001** | `config/oscal/framework_mappings/ISO_42001.json`, `compliance/oscal/component-definition.yaml` | ✅ Present (corrected under `POAM-2026-121`; original report cited a nonexistent JSON component path) |
| **NIST SP 800-53** | `config/oscal/framework_mappings/NIST_SP800_53.json` | ✅ Present |
| **EU AI Act** | `config/oscal/framework_mappings/EU_AI_ACT.json` | ✅ Present |
| **MAS FEAT** | `config/oscal/framework_mappings/MAS_FEAT.json` | ✅ Present |

---

### 5.3 Regional Baseline Configurations

| Region | Baseline Path | Thresholds Path | Status |
|--------|---------------|-----------------|--------|
| **US_FED** | `config/compliance/US_FED_BASELINE.json` | `config/thresholds/US_FED_BASELINE.json` | ✅ Valid |
| **EU_ECB** | `config/compliance/EU_ECB_BASELINE.json` | `config/thresholds/EU_ECB_BASELINE.json` | ✅ Valid |
| **APAC_MAS** | `config/compliance/APAC_MAS_BASELINE.json` | `config/thresholds/APAC_MAS_BASELINE.json` | ✅ Valid |

All baseline files are valid JSON and contain required sections (`hitl`, `stpa`, `consensus`, `cbf`, `jurisdiction`).

---

## 6. Recommendations

### 6.1 Immediate Actions

1. **None required.** All regional postures pass validation.

### 6.2 Future Enhancements

1. **Live Langfuse Integration Tests:** Add CI job with secured environment variables to validate Langfuse posture in automated pipeline.
2. **Cross-Region Failover Tests:** Validate data residency constraints during regional failover scenarios (currently skipped).
3. **Plugin × Region Matrix Expansion:** If a third domain plugin is added (e.g., `cage_supply_chain`), expand the composition matrix to 4×3.

---

## 7. Conclusion

The three regional posture test runs from v3.0.1 ran with 40 passing and 3 skipped cases across `US_FED`, `EU_ECB`, and `APAC_MAS`. **Withdrawn claim (`POAM-2026-121`):** the original conclusion asserting **true composability** across all 12 matrix cells is withdrawn. Active fail-closed overlay enforcement (`ControlOverlayCollisionError` in [`ControlRegistry`](../../src/gateway/governance/constants.py)) and cross-plugin overlay checks run on every PR via [`tests/test_regional_overlay_merge.py`](../../tests/test_regional_overlay_merge.py) (`pytest-logic`), with post-merge/dispatch regional marker suites in `.github/workflows/regional-posture.yml`.

**Regional test suites (historical v3.0.1 run):** 40 passed, 3 skipped (infrastructure-specific), 0 failed.

**Posture checkers:** EU_ECB and APAC_MAS posture checkers pass all validation gates.

---

**Last Updated:** 2026-11-24 (`POAM-2026-121` withdrawal applied)
**Validator:** CAGE Automated Compliance Pipeline
