# CAGE SBOM (Software Bill of Materials) Pipeline

> **Created:** 2026-03-06  
> **NIST Control:** CM-8 — System Component Inventory  
> **POAM Reference:** POAM-006 (No SBOM generated), POAM-010 (No container scanning)  
> **ISO 42001:** A.7.5 — Documented information (supply chain)  
> **NIST SP 800-161:** Supply Chain Risk Management for Federal Information Systems

---

## Table of Contents

1. [What is an SBOM?](#1-what-is-an-sbom)
2. [Why CAGE Generates SBOMs](#2-why-cage-generates-sboms)
3. [Tools Used](#3-tools-used)
4. [How to Generate SBOMs Manually](#4-how-to-generate-sboms-manually)
5. [Automated Pipeline](#5-automated-pipeline)
6. [Where SBOMs Are Stored](#6-where-sboms-are-stored)
7. [How to Interpret SBOM Output](#7-how-to-interpret-sbom-output)
8. [Compliance Context](#8-compliance-context)
9. [License Blocklist](#9-license-blocklist)

---

## 1. What is an SBOM?

A **Software Bill of Materials (SBOM)** is a formal, structured inventory of all software components included in a software product — analogous to an ingredient list on a food product label. SBOMs enumerate:

- **Libraries and packages** (name, version, publisher)
- **Licenses** associated with each component
- **Package URLs (PURLs)** for machine-readable identification
- **Dependencies** and their transitive relationships
- **Provenance** information (where the component came from)

SBOMs are a US government and industry-standard tool for supply chain risk management, mandated by:

- **Executive Order 14028** (May 2021) — _Improving the Nation's Cybersecurity_
- **NIST SP 800-161** — Supply Chain Risk Management
- **NTIA Minimum Elements for an SBOM** (July 2021)
- **NIST SP 800-53 Rev. 5 CM-8** — System Component Inventory

---

## 2. Why CAGE Generates SBOMs

### POAM-006 Remediation (CM-8)

Prior to this pipeline, the CAGE system had **no automated SBOM generation** in its CI/CD pipeline (POAM-006). This meant:

- Container images and Python dependencies could not be rapidly cross-referenced against CVE databases after zero-day disclosures
- Component inventory was maintained only informally (violating CM-8 requirements)
- Supply chain risk assessments lacked machine-readable evidence (violating NIST SP 800-161)

This pipeline directly remediates POAM-006 by implementing automated, scheduled SBOM generation for all CAGE container images and Python dependency sets.

### POAM-010 Remediation (RA-5)

POAM-010 identified that no vulnerability scanning existed in the CI pipeline. The SBOM pipeline integrates **Grype** vulnerability scanning against generated SBOMs to provide continuous CVE visibility (RA-5 — Vulnerability Monitoring and Scanning).

### Why CycloneDX?

CAGE uses **CycloneDX JSON format** (v1.4) because:

- It is compatible with OSCAL (Open Security Controls Assessment Language) toolchains
- It is natively supported by Syft, Grype, and most commercial SCA tools
- It is the recommended format for NIST SP 800-161 supply chain risk evidence
- It is machine-parseable and integrable with the CAGE compliance bridge

---

## 3. Tools Used

| Tool                                                            | Role                                              | Version Policy                         |
| --------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------- |
| **[Syft](https://github.com/anchore/syft)**                     | SBOM generation for Docker images and filesystems | Pin in production (`@sha256:<digest>`) |
| **[Grype](https://github.com/anchore/grype)**                   | Vulnerability scanning against SBOM               | Pin in production                      |
| **[cyclonedx-bom](https://github.com/CycloneDX/cyclonedx-bom)** | Python dependency SBOM (pip environment)          | Pinned in CI                           |
| **[CycloneDX](https://cyclonedx.org/)**                         | SBOM standard / format spec                       | v1.4                                   |
| **gsutil / google-cloud-storage**                               | GCS artifact upload                               | GCP SDK                                |

### Why Syft?

Syft (by Anchore) is the industry-leading open-source SBOM generator. It supports 20+ package ecosystems including Python, Go, Java, Node.js, and all major Linux package managers (APK, DPKG, RPM). It can scan container images directly from registries without pulling them locally.

### Why Grype?

Grype is Syft's companion vulnerability scanner. It ingests CycloneDX or SPDX SBOMs and cross-references them against:

- NVD (National Vulnerability Database)
- GitHub Advisory Database (GHSA)
- OSV (Open Source Vulnerabilities)
- Amazon, Debian, Ubuntu, RHEL security advisories

---

## 4. How to Generate SBOMs Manually

### Prerequisites

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install cyclonedx-bom (Python)
pip install cyclonedx-bom
```

### Generate Python Dependency SBOM

```bash
# Using the CAGE generate_sbom.py script (recommended)
python scripts/generate_sbom.py \
  --type python \
  --output-dir compliance/sbom

# Dry-run (no files written)
python scripts/generate_sbom.py --type python --output-dir compliance/sbom --dry-run

# Using cyclonedx-bom directly
python -m cyclonedx_py environment -o cyclonedx-json > compliance/sbom/python-deps-$(date +%Y-%m-%d).cdx.json
```

### Generate Docker Image SBOM

```bash
# Using the CAGE generate_sbom.py script (recommended)
python scripts/generate_sbom.py \
  --type docker \
  --image gcr.io/PROJECT_ID/cage-gateway:latest \
  --output-dir compliance/sbom

# Using Syft directly
syft gcr.io/PROJECT_ID/cage-gateway:latest \
  -o cyclonedx-json \
  --file compliance/sbom/cage-gateway-$(date +%Y-%m-%d).cdx.json
```

### Generate Filesystem/Directory SBOM

```bash
# Using the CAGE generate_sbom.py script
python scripts/generate_sbom.py \
  --type dir \
  --image . \
  --output-dir compliance/sbom

# Using Syft directly
syft dir:. -o cyclonedx-json --file compliance/sbom/filesystem-$(date +%Y-%m-%d).cdx.json
```

### Vulnerability Scan Against SBOM

```bash
# Scan a specific SBOM file
grype sbom:compliance/sbom/python-deps-2026-03-06.cdx.json

# Fail on critical CVEs (CI/CD gate)
grype sbom:compliance/sbom/python-deps-2026-03-06.cdx.json --fail-on critical

# Output JSON for programmatic processing
grype sbom:compliance/sbom/python-deps-2026-03-06.cdx.json -o json > compliance/sbom/grype-report.json
```

### Upload to GCS

```bash
# Using generate_sbom.py with --upload flag
python scripts/generate_sbom.py \
  --type python \
  --output-dir compliance/sbom \
  --upload \
  --gcs-bucket cage-compliance-sboms \
  --project-id your-gcp-project-id

# Using gsutil directly
gsutil -m cp compliance/sbom/*.cdx.json gs://cage-compliance-sboms/sbom/$(date +%Y/%m/%d)/
```

---

## 5. Automated Pipeline

CAGE operates two automated SBOM generation mechanisms:

### 5a. GitHub Actions (CI/CD)

**File:** [`.github/workflows/security-scan.yml`](../../.github/workflows/security-scan.yml)  
**Job:** `sbom-generation`

Triggers: every push to `main`/`feature/**`, every PR to `main`, daily at 02:00 UTC.

**Steps:**

1. Install Syft and Grype from official install scripts
2. Install `cyclonedx-bom` Python package
3. Run `generate_sbom.py --type python --dry-run` to validate the script
4. Run `syft dir:.` for full filesystem SBOM
5. Upload SBOM artifacts with 90-day retention (POAM-006 evidence)
6. Run Grype CVE scan against all generated SBOMs (POAM-010)

**Note:** Grype CVE failures are currently warnings (not hard failures) until POAM-010 is formally resolved and a CVE remediation process is established.

### 5b. Kubernetes CronJob

**File:** [`deployment/k8s/sbom-cronjob.yaml`](../../deployment/k8s/sbom-cronjob.yaml)  
**Name:** `cage-sbom-generator`  
**Namespace:** `cage-compliance`  
**Schedule:** `0 2 * * *` (02:00 UTC daily)

**What it does:**

1. Reads the image list from the `cage-sbom-image-list` ConfigMap
2. For each CAGE container image, runs `syft <image> -o cyclonedx-json`
3. Uploads all CycloneDX JSON SBOMs to GCS: `gs://cage-compliance-sboms/sbom/<YYYY/MM/DD>/`
4. Writes a MANIFEST.txt summarizing all scanned images and component counts

**RBAC:** The `sbom-generator` ServiceAccount has read-only access to pods and configmaps (ClusterRole `sbom-generator-readonly`). GCS upload uses Workload Identity (no key files).

---

## 6. Where SBOMs Are Stored

### Local (CI Artifacts)

| Path                                     | Description                             |
| ---------------------------------------- | --------------------------------------- |
| `compliance/sbom/<name>-<date>.cdx.json` | CycloneDX JSON SBOM files               |
| `compliance/sbom/SBOM_SUMMARY.md`        | Human-readable summary (auto-generated) |

GitHub Actions artifacts are retained for **90 days** and named `sbom-<git-sha>`.

### GCS (Durable Storage — CM-8 Evidence)

| GCS Path                                                        | Description          |
| --------------------------------------------------------------- | -------------------- |
| `gs://cage-compliance-sboms/sbom/<YYYY/MM/DD>/<image>.cdx.json` | Daily SBOM per image |
| `gs://cage-compliance-sboms/sbom/<YYYY/MM/DD>/MANIFEST.txt`     | Daily scan manifest  |

GCS lifecycle policy: **90-day retention** (objects deleted after 90 days per `storage.tf`).

---

## 7. How to Interpret SBOM Output

### CycloneDX JSON Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "metadata": {
    "timestamp": "2026-03-06T02:00:00Z",
    "component": { "name": "cage-gateway", "version": "1.0.0" },
    "tools": [{ "name": "syft", "version": "1.x" }]
  },
  "components": [
    {
      "type": "library",
      "name": "fastapi",
      "version": "0.110.0",
      "purl": "pkg:pypi/fastapi@0.110.0",
      "licenses": [{ "license": { "id": "MIT" } }]
    }
    // ... more components
  ]
}
```

### Key Fields

| Field                                | Meaning                                                    |
| ------------------------------------ | ---------------------------------------------------------- |
| `components[].name`                  | Package/library name                                       |
| `components[].version`               | Exact installed version                                    |
| `components[].purl`                  | Package URL (machine-readable, globally unique identifier) |
| `components[].licenses[].license.id` | SPDX license identifier                                    |
| `components[].type`                  | `library`, `container`, `application`, `framework`         |
| `metadata.timestamp`                 | When the SBOM was generated                                |

### Reading the Summary Report (`SBOM_SUMMARY.md`)

The auto-generated summary at `compliance/sbom/SBOM_SUMMARY.md` provides:

- Total component count
- Vulnerability severity breakdown (CRITICAL / HIGH / MEDIUM / LOW)
- License violation alerts (GPL-3.0 / AGPL blocklist)
- Top 20 components table

---

## 8. Compliance Context

| Control      | Requirement                                    | CAGE Implementation                                                                 |
| ------------ | ---------------------------------------------- | ----------------------------------------------------------------------------------- |
| **CM-8**     | Maintain an inventory of all system components | Daily Syft SBOM generation per container image; stored in GCS with 90-day retention |
| **RA-5**     | Vulnerability monitoring and scanning          | Grype CVE scan against SBOMs in CI pipeline; POAM-010 tracking                      |
| **SA-8**     | Security engineering principles                | CycloneDX SBOM format enables downstream OSCAL integration                          |
| **SR-3**     | Supply chain controls and processes            | SBOM provides transparency into third-party software components                     |
| **SR-11**    | Component authenticity                         | PURL-based component identification enables integrity verification                  |
| **POAM-006** | No SBOM pipeline                               | **RESOLVED** by this pipeline                                                       |
| **POAM-010** | No container scanning                          | **PARTIALLY ADDRESSED** — Grype integration added; full remediation by 2026-04-15   |

### NIST SP 800-161 Supply Chain Risk

Per NIST SP 800-161, CAGE's SBOM pipeline provides:

- **Identification:** All software components enumerated with version and provenance
- **Assessment:** Grype vulnerability enrichment cross-references components against NVD/GHSA
- **Response:** Exit code 1 on CVSS ≥ 9.0 enables automated CI gates
- **Monitoring:** Daily scheduled scans provide continuous component inventory visibility

---

## 9. License Blocklist

The CAGE SBOM pipeline enforces a license blocklist for components incompatible with commercial financial services use:

| Blocklisted License                                | Reason                                                                                            |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `GPL-3.0` / `GPL-3.0-only` / `GPL-3.0-or-later`    | Copyleft — incompatible with proprietary financial services software                              |
| `AGPL-3.0` / `AGPL-3.0-only` / `AGPL-3.0-or-later` | Network copyleft — any service using AGPL-licensed code may need to open-source all modifications |
| `GPL-2.0` / `GPL-2.0-only` / `GPL-2.0-or-later`    | Copyleft — same concern as GPL-3.0                                                                |

If a component with a blocklisted license is detected, `generate_sbom.py` logs a warning and the summary report flags the violation. Legal review is required before any such component can be used in CAGE.

**Acceptable licenses:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Python-2.0, LGPL-2.1 (with care), and other permissive or weak-copyleft licenses.

---

_This document is maintained by the CAGE DevSecOps team. For questions, contact the ISSO. Last reviewed: 2026-03-06._
