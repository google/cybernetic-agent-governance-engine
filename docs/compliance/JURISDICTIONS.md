# CAGE Jurisdictional Compliance Profiles

**Version:** 3.1.5  
**Status:** Authoritative  
**Last Modified:** 2026-09-14

## Purpose

This document provides lean technical profiles for CAGE's jurisdiction-specific compliance frameworks. Each profile tabulates regulatory context, registered controls, governance event hooks, OSCAL exporter invocations, and output paths.

---

## US_FED: FedRAMP / NIST SP 800-53

### Regulatory Context

| Framework | Applicability | Authority |
|-----------|---------------|-----------|
| **FedRAMP HIGH** | Cloud services processing federal data | FedRAMP PMO, NIST SP 800-53 Rev 5 |
| **NIST AI 600-1** | AI/ML systems in federal agencies | NIST AI Risk Management Framework 1.0 |
| **NIST SP 800-53 Rev 5** | Federal information systems | FISMA, OMB A-130 |

**Deployment Region:** `CAGE_DEPLOYMENT_REGION=US_FED`  
**Active Frameworks:** `fedramp`, `nist_ai_rmf`  
**Control Baseline:** FedRAMP HIGH (325 controls)

### Registered Controls

| Control ID | Name | Evidence Source | SLA (seconds) |
|------------|------|-----------------|---------------|
| **SA-11** | STPA Compiler — Developer Safety Testing | STPA compiler output | N/A (compile-time) |
| **SC-7** | Boundary Protection — Cilium L7 Egress Lockdown | Cilium L7 flow logs | 86,400 (24h) |
| **SC-8** | Transmission Confidentiality — Linkerd mTLS | Linkerd proxy telemetry | 86,400 (24h) |
| **AC-2** | Account Management | Kubernetes RBAC audit logs | N/A |
| **IR-1** | Incident Response Policy and Procedures | POAM, runbooks | N/A |
| **AU-2** | Audit Events — AgentSight Kernel + Cilium L7 Flows | AgentSight syscall traces | 3,600 (1h) |
| **SI-7** | Software Integrity — AgentSight File Integrity Monitoring | AgentSight FIM events | 14,400 (4h) |
| **AC-4** | Information Flow Enforcement — FTRA Parameter Smuggling Protection | FTRA flow enforcement traces | N/A |
| **SI-10** | Input Validation — Multi-Component Protection | NeMo + FTRA validation traces | N/A |

**Note:** Universal ISO/IEC 42001 controls (A.5.2, A.5.3, A.6.2, A.8.4, A.9.2, SC-4) also apply. See [Universal Controls](#universal-controls-isoiec-42001).

### Event Hooks

Governance events emitted by US_FED deployments that map to registered controls:

| Event Name | Control ID | Source Component | Langfuse Score Name |
|------------|------------|------------------|---------------------|
| `stpa_compile` | SA-11 | STPA compiler CLI | `nist.SA-11.passed` |
| `linkerd_mtls` | SC-8 | Linkerd proxy sidecar | `nist.SC-8.passed` |
| `cilium_l7_egress` | SC-7 | Cilium L7 network policy | `nist.SC-7.passed` |
| `cilium_l7_flow` | SC-7 | Cilium Hubble flow logs | `nist.SC-7.passed` |
| `agentsight_syscall` | AU-2 | AgentSight eBPF daemon | `nist.AU-2.passed` |
| `agentsight_fim` | SI-7 | AgentSight file integrity monitor | `nist.SI-7.passed` |
| `ftra_boundary_check` | SI-10 | FTRA semantic validator | `nist.SI-10.passed` |
| `ftra_semantic_validation` | SI-10 | FTRA ActionSchema validator | `nist.SI-10.passed` |
| `ftra_flow_enforcement` | AC-4 | FTRA parameter flow enforcer | `nist.AC-4.passed` |

**Universal events** (all regions): `nemo_input_scan`, `nemo_output_rail`, `opa_policy_check`, `otel_trace`, `stpa_validation`, `causal_gatekeeper`, `saga_rollback`, `context_accumulate`, `defer_parking`

### Exporter Invocations

```bash
# Generate US_FED OSCAL SSP
uv run python -m src.gateway.governance.oscal_ssp_exporter export \
  --region US_FED \
  --ssp compliance/oscal/us_fed/system-security-plan.yaml

# Validate with Lula
lula validate -f compliance/lula/us_fed/component-validations.yaml
```

### Output Paths

| Artifact | Path | Format |
|----------|------|--------|
| **System Security Plan** | `compliance/oscal/us_fed/system-security-plan.yaml` | OSCAL SSP |
| **Component Definition** | `compliance/oscal/us_fed/component-definition.yaml` | OSCAL Component |
| **Lula Validations** | `compliance/lula/us_fed/component-validations.yaml` | Lula OSCAL |
| **POAM** | `docs/compliance/us_fed/POAM_US_FED.md` | Markdown |
| **NIST AI 600-1 Plan** | `docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md` | Markdown |
| **FedRAMP SSP Export** | Generated on-demand via exporter | OSCAL SSP |

### Additional Resources

- [AI 600-1 Implementation Plan](us_fed/AI_600_1_IMPLEMENTATION_PLAN.md)
- [NIST RMF Assessment Artifacts](us_fed/)
- [US_FED POAM](us_fed/POAM_US_FED.md)

---

## EU_ECB: EU AI Act / GDPR / DORA

### Regulatory Context

| Framework | Applicability | Authority |
|-----------|---------------|-----------|
| **EU AI Act** | High-risk AI systems (Annex III) | Regulation (EU) 2024/1689 |
| **GDPR** | Personal data processing | Regulation (EU) 2016/679 |
| **DORA** | Digital operational resilience (financial sector) | Regulation (EU) 2022/2554 |

**Deployment Region:** `CAGE_DEPLOYMENT_REGION=EU_ECB`  
**Active Frameworks:** `eu_ai_act`, `iso42001`  
**Control Baseline:** EU AI Act Annex IV + ISO/IEC 42001:2023

### Registered Controls

| Control ID | Name | Evidence Source | SLA (seconds) |
|------------|------|-----------------|---------------|
| **Article 12** | Record-Keeping | Langfuse audit trails, OSCAL findings | 14,400 (4h) |
| **Article 13** | Transparency & Human Oversight | DEFER queue telemetry, HITL logs | N/A |

**Note:** Universal ISO/IEC 42001 controls (A.5.2, A.5.3, A.6.2, A.8.4, A.9.2, SC-4) also apply. See [Universal Controls](#universal-controls-isoiec-42001).

### Event Hooks

Governance events emitted by EU_ECB deployments that map to registered controls:

| Event Name | Control ID | Source Component | Evidence Type |
|------------|------------|------------------|---------------|
| *(EU_ECB has no jurisdiction-specific events)* | — | — | — |

**Universal events apply:** `nemo_input_scan`, `nemo_output_rail`, `opa_policy_check`, `otel_trace`, `stpa_validation`, `causal_gatekeeper`, `saga_rollback`, `context_accumulate`, `defer_parking`

**Note:** US_FED-specific events (`stpa_compile`, `linkerd_mtls`, `cilium_l7_egress`, `agentsight_syscall`, `agentsight_fim`, `ftra_*`) do **NOT** appear in EU_ECB telemetry. FTRA controls are not applicable outside US_FED.

### Exporter Invocations

```bash
# Generate EU_ECB OSCAL SSP
uv run python -m src.gateway.governance.oscal_ssp_exporter export \
  --region EU_ECB \
  --ssp compliance/oscal/eu_ecb/system-security-plan.yaml

# Validate with Lula
lula validate -f compliance/lula/eu_ecb/component-validations.yaml
```

### Output Paths

| Artifact | Path | Format |
|----------|------|--------|
| **System Security Plan** | `compliance/oscal/eu_ecb/system-security-plan.yaml` | OSCAL SSP |
| **Component Definition** | `compliance/oscal/eu_ecb/component-definition.yaml` | OSCAL Component |
| **Lula Validations** | `compliance/lula/eu_ecb/component-validations.yaml` | Lula OSCAL |
| **FRIA Attestation** | `docs/compliance/eu_ecb/FRIA_ATTESTATION.md` | Markdown |
| **GDPR DPIA** | `docs/compliance/eu_ecb/GDPR_DPIA.md` | Markdown |
| **DORA Resilience Plan** | `docs/compliance/eu_ecb/DORA_RESILIENCE_TESTING_PROGRAMME.md` | Markdown |
| **POAM** | `docs/compliance/eu_ecb/POAM_EU_ECB.md` | Markdown |

### Additional Resources

- [FRIA Attestation](eu_ecb/FRIA_ATTESTATION.md)
- [GDPR DPIA](eu_ecb/GDPR_DPIA.md)
- [DORA Resilience Testing Programme](eu_ecb/DORA_RESILIENCE_TESTING_PROGRAMME.md)
- [EU AI Office Registration](eu_ecb/EU_AI_OFFICE_REGISTRATION.md)
- [EU_ECB POAM](eu_ecb/POAM_EU_ECB.md)

---

## APAC_MAS: MAS FEAT / MAS Notice 655

### Regulatory Context

| Framework | Applicability | Authority |
|-----------|---------------|-----------|
| **MAS FEAT** | AI/ML systems in financial services | Monetary Authority of Singapore FEAT Principles |
| **MAS Notice 655** | Technology risk management (financial institutions) | MAS Technology Risk Management Guidelines |
| **MAS TRM Section 14** | AI/ML governance controls | MAS TRM Guidelines 2021 |

**Deployment Region:** `CAGE_DEPLOYMENT_REGION=APAC_MAS`  
**Active Frameworks:** `mas_feat`, `iso42001`  
**Control Baseline:** MAS FEAT Principles 1-4 + ISO/IEC 42001:2023

### Registered Controls

| Control ID | Name | Evidence Source | SLA (seconds) |
|------------|------|-----------------|---------------|
| **MAS-FEAT-1** | Fairness Assessment | Langfuse fairness metrics, bias telemetry | 86,400 (24h) |

**Note:** Universal ISO/IEC 42001 controls (A.5.2, A.5.3, A.6.2, A.8.4, A.9.2, SC-4) also apply. See [Universal Controls](#universal-controls-isoiec-42001).

### Event Hooks

Governance events emitted by APAC_MAS deployments that map to registered controls:

| Event Name | Control ID | Source Component | Evidence Type |
|------------|------------|------------------|---------------|
| *(APAC_MAS has no jurisdiction-specific events)* | — | — | — |

**Universal events apply:** `nemo_input_scan`, `nemo_output_rail`, `opa_policy_check`, `otel_trace`, `stpa_validation`, `causal_gatekeeper`, `saga_rollback`, `context_accumulate`, `defer_parking`

**Note:** US_FED-specific events (`stpa_compile`, `linkerd_mtls`, `cilium_l7_egress`, `agentsight_syscall`, `agentsight_fim`, `ftra_*`) do **NOT** appear in APAC_MAS telemetry. FTRA controls are not applicable outside US_FED.

### Exporter Invocations

```bash
# Generate APAC_MAS OSCAL SSP
uv run python -m src.gateway.governance.oscal_ssp_exporter export \
  --region APAC_MAS \
  --ssp compliance/oscal/apac_mas/system-security-plan.yaml

# Validate with Lula
lula validate -f compliance/lula/apac_mas/component-validations.yaml
```

### Output Paths

| Artifact | Path | Format |
|----------|------|--------|
| **System Security Plan** | `compliance/oscal/apac_mas/system-security-plan.yaml` | OSCAL SSP |
| **Component Definition** | `compliance/oscal/apac_mas/component-definition.yaml` | OSCAL Component |
| **Lula Validations** | `compliance/lula/apac_mas/component-validations.yaml` | Lula OSCAL |
| **MAS FEAT Report** | `docs/compliance/apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md` | Markdown |
| **Notice 655 Cert** | `docs/compliance/apac_mas/MAS_NOTICE_655_CERTIFICATION.md` | Markdown |
| **POAM** | `docs/compliance/apac_mas/POAM_APAC_MAS.md` | Markdown |

### Additional Resources

- [MAS FEAT Transparency Report](apac_mas/MAS_FEAT_T1_TRANSPARENCY_REPORT.md)
- [MAS Notice 655 Certification](apac_mas/MAS_NOTICE_655_CERTIFICATION.md)
- [APAC_MAS POAM](apac_mas/POAM_APAC_MAS.md)

---

## UK_DSIT: UK AI Safety Institute (Placeholder)

### Regulatory Context

**Status:** Placeholder. UK AI Assurance Roadmap not yet published.

| Framework | Applicability | Authority |
|-----------|---------------|-----------|
| **UK AI Regulation** | AI systems deployed in UK (anticipated 2027) | UK Department for Science, Innovation and Technology (DSIT) |
| **UK AI Safety Institute** | High-risk AI registration | UK AISI (established 2023) |
| **UK AI Assurance Roadmap** | Conformity assessment pathway | DSIT (expected Q2 2027) |

**Deployment Region:** `CAGE_DEPLOYMENT_REGION=UK_DSIT` (reserved)  
**Active Frameworks:** TBD  
**Control Baseline:** TBD

### Registered Controls

*To be populated in Sprint 2 when UK AI Assurance Roadmap is published.*

### Event Hooks

*To be populated in Sprint 2.*

### Exporter Invocations

```bash
# Placeholder (UK_DSIT not yet implemented)
uv run python -m src.gateway.governance.oscal_ssp_exporter export \
  --region UK_DSIT \
  --ssp compliance/oscal/uk_dsit/system-security-plan.yaml
```

### Output Paths

*To be populated in Sprint 2.*

### Additional Resources

- UK AI Safety Institute: https://www.aisi.gov.uk/
- UK DSIT AI White Paper (2023): https://www.gov.uk/government/publications/ai-regulation-a-pro-innovation-approach

---

## Universal Controls: ISO/IEC 42001

The following controls apply to **ALL** deployment regions:

| Control ID | Name | Evidence Source | SLA (seconds) |
|------------|------|-----------------|---------------|
| **A.5.2** | Social Impact Assessment | NeMo output rails | N/A |
| **A.5.3** | Logging and Monitoring | OTel traces, Context Accumulator | 14,400 (4h) |
| **A.6.2** | AI System Lifecycle Controls | Causal Gatekeeper refutation | N/A |
| **A.8.4** | AI System Operation Controls | STPA UCA validation, DEFER state machine | 3,600 (1h) |
| **A.9.2** | Data Transfer to Suppliers | NeMo PII masking | 3,600 (1h) |
| **SC-4** | Fiscal Limits and RBAC | OPA policy checks | 7,200 (2h) |

**Universal event hooks:** `nemo_input_scan`, `nemo_output_rail`, `opa_policy_check`, `otel_trace`, `stpa_validation`, `causal_gatekeeper`, `saga_rollback`, `context_accumulate`, `defer_parking`

---

## Cross-Region Governance

### Jurisdictional Isolation Invariants

1. **US_FED-only controls** (SA-11, SC-7, SC-8, AC-2, IR-1, AU-2, SI-7, AC-4, SI-10) must **NOT** appear in EU_ECB or APAC_MAS SSPs.
2. **EU_ECB-only controls** (Article 12, Article 13) must **NOT** appear in US_FED or APAC_MAS SSPs.
3. **APAC_MAS-only controls** (MAS-FEAT-1) must **NOT** appear in US_FED or EU_ECB SSPs.
4. **Universal controls** (A.5.2, A.5.3, A.6.2, A.8.4, A.9.2, SC-4) apply to **ALL** regions.

### Region-Aware Accessor Functions

Code must use region-aware accessor functions from [`src/compliance_bridge/types.py`](../../src/compliance_bridge/types.py):

```python
from src.compliance_bridge.types import (
    get_control_meta,      # Returns universal + jurisdictional controls
    get_iso_control_map,   # Returns universal + jurisdictional event mappings
    get_sla_seconds,       # Returns universal + jurisdictional SLA targets
)

# Correct (region-filtered)
us_fed_controls = get_control_meta("US_FED")
eu_ecb_controls = get_control_meta("EU_ECB")

# Forbidden (raw dict access bypasses jurisdictional filtering)
# from src.compliance_bridge.types import _JURISDICTIONAL_CONTROLS  # ❌ Private API
```

### Testing Jurisdictional Isolation

CI enforces jurisdictional separation via [`tests/test_compliance_bridge.py::TestFtraControlMappings`](../../tests/test_compliance_bridge.py):

```python
def test_ac4_not_in_eu_ecb():
    """AC-4 must NOT be present in EU_ECB controls (jurisdictional isolation)."""
    eu_ecb_controls = get_control_meta("EU_ECB")
    assert "AC-4" not in eu_ecb_controls
```

---

## References

- [Assurance Status Guide](ASSURANCE_STATUS_GUIDE.md) — Lifecycle and legal boundaries
- [POAM Index](cross-region/POAM_INDEX.md) — Cross-region POAM aggregation
- [Jurisdictional Separation Analysis](cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) — FINDING-01 remediation
- [CAGE Architecture](../architecture/ARCHITECTURE.md) — System overview

---

**Document Control:**
- **Owner:** CAGE Compliance Team
- **Review Cycle:** Quarterly or upon regulatory change
- **Next Review:** 2026-12-14
