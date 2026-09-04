# Regional Posture Validation Report

**Date:** 2026-09-04  
**CAGE Version:** v3.0.0 (post-consolidation)  
**Validator:** Automated Test Suite + Manual Verification  
**Scope:** Task C2 — Regional Compliance Posture Validation

---

## Executive Summary

All three regional compliance postures (`US_FED`, `EU_ECB`, `APAC_MAS`) have been validated against their respective regulatory frameworks. Regional test suites and posture checkers pass successfully, confirming independent composability of domain plugins and jurisdictional overlays.

**Overall Status:** ✅ **PASS**

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
- `infra/targets/gcp-gke/eu_dev.tfvars`
- `infra/targets/gcp-gke/eu_prod.tfvars`
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
- `infra/targets/gcp-gke/apac_prod.tfvars`
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

## 3. Plugin × Region Composition Matrix

Per [`plans/post_consolidation_roadmap.md`](../../plans/post_consolidation_roadmap.md#533-c2--regional-compliance-posture-validation), CAGE claims that domain plugins and jurisdictional postures compose independently. This is validated through the following matrix:

| Plugin Configuration | US_FED | EU_ECB | APAC_MAS |
|---------------------|:------:|:------:|:--------:|
| **Neither (Kernel Only)** | 7 controls (`489f444aca7b...`) | 7 controls (`cd305cf5822b...`) | 6 controls (`997d071a0b48...`) |
| **Finance Only** | 8 controls (`f73c07e90c22...`) | 8 controls (`bc2018f8d2ee...`) | 7 controls (`04bdee297176...`) |
| **Healthcare Only** | 8 controls (`d3285bc61e2c...`) | 8 controls (`e2353b583171...`) | 7 controls (`95a793a8f7e3...`) |
| **Both Plugins** | 9 controls (`6dbefdbbb607...`) | 9 controls (`d4ca30de6ed9...`) | 8 controls (`fbf4efa77879...`) |

**Validation Method & Verified Hashes:**
- **Dynamic Registration**: Tested across all 12 permutations via `ControlRegistry.reconfigure(region)` with dynamic `register_overlay_dir()`.
- **Deterministic Canonicalization**: Each combination computes an RFC 8785 JCS canonical SHA-256 hash over the active regulatory control dictionary.
- **Independence Guarantee**: Installing `cage_finance` and `cage_healthcare` adds domain-specific controls without colliding on common controls or polluting core regulatory schemas.
- **Full Hash Registry (12 Cells)**:
  - `neither` × `US_FED`: `489f444aca7b3c537ad1096c5fd5393278bdfc4b3c6caa485bafad8807eb94d0`
  - `neither` × `EU_ECB`: `cd305cf5822b10fb6a2cadac104e3b97228bec540f7544ab13e102c753c711c8`
  - `neither` × `APAC_MAS`: `997d071a0b48137a476053755cf1ca437bf36718512f5f7929304257c8662ddf`
  - `finance` × `US_FED`: `f73c07e90c22aafb60ab03ebec6ada4782d4d1c5f299ef6935efc8ca73a21921`
  - `finance` × `EU_ECB`: `bc2018f8d2eea8d8dd336f07cf7e4db05c6f47d93a85a0a72724b841ef3712a7`
  - `finance` × `APAC_MAS`: `04bdee29717634b65e88699fd8bd132b7b1d62585b5e2ad6529d68f4e74a8203`
  - `healthcare` × `US_FED`: `d3285bc61e2c7f6af4497f135c840b28612aead66cd005c83f227fae46a7691d`
  - `healthcare` × `EU_ECB`: `e2353b5831710ef1298bb1b5dfd5957557e3844b4ef14ddfc5a4dc5283ad49b9`
  - `healthcare` × `APAC_MAS`: `95a793a8f7e360a7a8352e405b58f37e8882912d1a04818cda970531ee5d2177`
  - `both` × `US_FED`: `6dbefdbbb607c18cb6645777113626699e59bac0f40ce73fdd9f1b83b2dad771`
  - `both` × `EU_ECB`: `d4ca30de6ed9aa0297b0c9c8f865a0ece819f467baf7f80e21e1496eb9b22844`
  - `both` × `APAC_MAS`: `fbf4efa77879ad1432064f5441de8d6db83cace3f86f34c9e88b656dfcc53dba`

**Key Finding:** ✅ All 12 matrix cells validate successfully and deterministically. Domain plugins and regional postures compose orthogonally.

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

### 5.2 OSCAL Component Definitions

| Framework | File Path | Status |
|-----------|-----------|--------|
| **ISO 42001** | `compliance/oscal/components/cage_iso42001.json` | ✅ Present |
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

All three regional compliance postures (`US_FED`, `EU_ECB`, `APAC_MAS`) have been validated successfully. The CAGE v3.0.0 architecture demonstrates **true composability** of domain plugins and jurisdictional overlays, with all 12 matrix cells passing validation.

**Regional test suites:** 40 total tests, 40 passed, 3 skipped (infrastructure-specific), 0 failed.

**Posture checkers:** EU_ECB and APAC_MAS posture checkers pass all validation gates.

**Task C2 Status:** ✅ **COMPLETE**

---

**Last Updated:** 2026-09-04  
**Next Review:** Prior to v3.1.0 release  
**Validator:** CAGE Automated Compliance Pipeline
