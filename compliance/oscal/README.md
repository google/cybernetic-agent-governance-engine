# OSCAL Compliance Artifacts

This directory contains **OSCAL (Open Security Controls Assessment Language)** artifacts for the Cybernetic Governance Engine. OSCAL is a NIST-standardized machine-readable format for expressing security controls, component definitions, system security plans, and assessment results.

---

## What is OSCAL?

OSCAL provides a standardized, machine-readable framework for documenting and assessing security and privacy controls. Instead of static Word documents, OSCAL enables:

- **Automated assessment** via tools like [Lula](https://github.com/defenseunicorns/lula) and `oscal-cli`
- **Cross-framework traceability** between ISO 42001, NIST SP 800-53, FedRAMP, and CMMC
- **Continuous compliance** by linking control documentation to live Kubernetes assertions
- **ATO support** by generating Assessment Results in formats accepted by authorization officials

---

## OSCAL Artifacts in This Directory

| File                                                                         | Standard             | Purpose                                                                                                       | Status    |
| ---------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------- | --------- |
| [`component-definition.yaml`](./component-definition.yaml)                   | ISO/IEC 42001:2023   | Maps ISO 42001 Annex A controls (A.5.2, A.5.3, A.9.2, SC-4) to gateway, OPA, and NeMo components              | ✅ Active |
| [`sp800-53-component-definition.yaml`](./sp800-53-component-definition.yaml) | NIST SP 800-53 Rev 5 | Maps 15 HIGH-baseline SP 800-53 controls across 6 system components (see table below)                         | ✅ Active |
| [`information-type-registry.yaml`](./information-type-registry.yaml)         | NIST SP 800-60       | Defines information types processed by the system with confidentiality/integrity/availability categorizations | ✅ Active |

---

## SP 800-53 Controls Mapped

The [`sp800-53-component-definition.yaml`](./sp800-53-component-definition.yaml) covers these 15 HIGH-baseline controls across 6 components:

| Control | Title                                      | Component                | Status             |
| ------- | ------------------------------------------ | ------------------------ | ------------------ |
| AC-3    | Access Enforcement                         | Governance Gateway + OPA | implemented        |
| AC-6    | Least Privilege                            | OPA Policy Engine        | implemented        |
| AU-9    | Protection of Audit Information            | Compliance Bridge        | partial (see POAM) |
| AU-12   | Audit Record Generation                    | Governance Gateway       | implemented        |
| CA-7    | Continuous Monitoring                      | Compliance Bridge        | implemented        |
| IA-2    | Identification and Authentication          | GCP/GKE (inherited)      | inherited          |
| IA-3    | Device Identification and Authentication   | OPA Policy Engine        | implemented        |
| IR-6    | Incident Reporting                         | Compliance Bridge        | implemented        |
| RA-3    | Risk Assessment                            | STPA Safety Validator    | implemented        |
| SC-7    | Boundary Protection                        | GCP/GKE (inherited)      | inherited          |
| SC-8    | Transmission Confidentiality and Integrity | GCP/GKE (inherited)      | inherited          |
| SC-12   | Cryptographic Key Establishment            | Governance Gateway       | implemented        |
| SI-3    | Malicious Code Protection                  | NeMo Guardrails          | implemented        |
| SI-4    | System Monitoring                          | STPA Safety Validator    | implemented        |
| SI-10   | Information Input Validation               | NeMo Guardrails          | implemented        |

---

## ISO 42001 Controls Mapped

The [`component-definition.yaml`](./component-definition.yaml) covers these ISO 42001 Annex A controls:

| Control | Title                      | Component                      | Status      |
| ------- | -------------------------- | ------------------------------ | ----------- |
| A.5.2   | Social Impact Assessment   | TypeScript Governance Gateway  | implemented |
| A.5.3   | Logging and Monitoring     | TypeScript Governance Gateway  | implemented |
| A.9.2   | Data Transfer to Suppliers | NeMo Guardrails + Presidio PII | implemented |
| SC-4    | Fiscal Limits (custom)     | OPA Policy Engine              | implemented |

---

## How to Validate OSCAL Files

### Using Lula (Kubernetes-native)

```bash
# Validate against a running cluster
lula validate --input compliance/oscal/component-definition.yaml

# Validate the SP 800-53 definition
lula validate --input compliance/oscal/sp800-53-component-definition.yaml

# Run all Lula validations and generate Assessment Results
lula validate \
  --input compliance/oscal/sp800-53-component-definition.yaml \
  --output compliance/oscal/assessment-results.yaml
```

### Using oscal-cli (offline schema validation)

```bash
# Install oscal-cli
brew install oscal-cli  # macOS
# or: https://github.com/usnistgov/oscal-cli/releases

# Validate component definition schema
oscal-cli component-definition validate compliance/oscal/component-definition.yaml
oscal-cli component-definition validate compliance/oscal/sp800-53-component-definition.yaml
```

### Python YAML syntax check

```bash
python3 -c "
import yaml
files = [
    'compliance/oscal/component-definition.yaml',
    'compliance/oscal/sp800-53-component-definition.yaml',
    'compliance/oscal/information-type-registry.yaml',
]
for f in files:
    try:
        yaml.safe_load(open(f))
        print(f'OK: {f}')
    except Exception as e:
        print(f'ERROR: {f}: {e}')
"
```

### Automated validation (Kubernetes CronJob)

The Lula CronJob in [`deployment/k8s/lula-cron.yaml`](../../deployment/k8s/lula-cron.yaml) runs validation every 6 hours and stores results to MinIO/GCS. Results are ingested by the compliance bridge audit workflow.

---

## How ISO 42001 and SP 800-53 Definitions Relate

The two component definition files are **complementary, not redundant**:

```
component-definition.yaml          sp800-53-component-definition.yaml
(ISO 42001 controls)               (NIST SP 800-53 controls)
       │                                        │
       ▼                                        ▼
  A.5.2: Social Impact          AC-3: Access Enforcement
  A.5.3: Logging & Monitoring   AU-12: Audit Record Generation
  A.9.2: Data to Suppliers      SI-10: Input Validation
  SC-4:  Fiscal Limits          CA-7: Continuous Monitoring
       │                                        │
       └──────────────┬─────────────────────────┘
                      ▼
            Lula Validation Files
            (compliance/lula/)
                      │
                      ▼
            OSCAL Assessment Results
            (MinIO/GCS object storage)
```

The ISO 42001 definition (`component-definition.yaml`) has `props` linking to its SP 800-53 companion via `sp800-53-companion-definition`. Both files share the same Lula validation stubs in [`compliance/lula/`](../lula/).

---

## Related Documents

| Document                                                                                             | Purpose                                                                      |
| ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [`compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md`](../ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md)           | System Security Plan (SSP) outline — full security posture narrative         |
| [`compliance/categorization/FIPS199_CATEGORIZATION.md`](../categorization/FIPS199_CATEGORIZATION.md) | FIPS 199 system categorization: **HIGH** (C), **HIGH** (I), **MODERATE** (A) |
| [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../continuous-monitoring/ISCM_STRATEGY.md)     | Information Security Continuous Monitoring (ISCM) strategy                   |
| [`compliance/lula/`](../lula/)                                                                       | Lula validation manifests for automated control assertions                   |
| [`docs/POAM.md`](../../docs/POAM.md)                                                                 | Plan of Action and Milestones — open findings and remediation timelines      |
| [`docs/GOVERNANCE_CROSSWALK.md`](../../docs/GOVERNANCE_CROSSWALK.md)                                 | Cross-framework mapping: ISO 42001 ↔ NIST SP 800-53 ↔ NIST AI RMF            |

---

## OSCAL Control Origination Legend

| Value             | Meaning                                                     |
| ----------------- | ----------------------------------------------------------- |
| `system-specific` | Control is implemented entirely by this system's components |
| `inherited`       | Control is provided by an underlying platform (GCP/GKE)     |
| `hybrid`          | Control is partially implemented here, partially inherited  |

---

## Lula Validation Files

| File                                                             | Controls              | Type             |
| ---------------------------------------------------------------- | --------------------- | ---------------- |
| [`lula-validation-a52.yaml`](../lula/lula-validation-a52.yaml)   | ISO 42001 A.5.2       | ISO 42001        |
| [`lula-validation-a53.yaml`](../lula/lula-validation-a53.yaml)   | ISO 42001 A.5.3       | ISO 42001        |
| [`lula-validation-a92.yaml`](../lula/lula-validation-a92.yaml)   | ISO 42001 A.9.2       | ISO 42001        |
| [`lula-validation-sc4.yaml`](../lula/lula-validation-sc4.yaml)   | SC-4 Fiscal Limits    | ISO 42001/Custom |
| [`lula-validation-au12.yaml`](../lula/lula-validation-au12.yaml) | SP 800-53 AU-12       | SP 800-53        |
| [`lula-validation-ac3.yaml`](../lula/lula-validation-ac3.yaml)   | SP 800-53 AC-3        | SP 800-53        |
| [`lula-validation-ra5.yaml`](../lula/lula-validation-ra5.yaml)   | SP 800-53 RA-5        | SP 800-53        |
| [`lula-validation-cm6.yaml`](../lula/lula-validation-cm6.yaml)   | SP 800-53 CM-6 / CA-7 | SP 800-53        |
| [`lula-validation-ir6.yaml`](../lula/lula-validation-ir6.yaml)   | SP 800-53 IR-6        | SP 800-53        |
