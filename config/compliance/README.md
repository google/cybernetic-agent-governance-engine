# Regulatory Compliance Profiles

This directory contains regional control-mapping profiles for the CAGE Governance Engine.
Each profile is a JSON file that maps stable Internal Control IDs (`CTRL_*`) to the
authoritative regulatory framework citations for a specific jurisdiction.

## Directory Structure

```
config/
├── compliance/                      ← This directory
│   ├── US_FED_BASELINE.json         # US Federal Reserve / OCC / FDIC (SR 26-2 / NIST)
│   ├── EU_ECB_BASELINE.json         # European Central Bank / EBA / EU AI Office
│   └── APAC_MAS_BASELINE.json       # Monetary Authority of Singapore (FEAT / TRM)
└── thresholds/
    ├── US_FED_BASELINE.json         # Quantitative thresholds for US deployment
    ├── EU_ECB_BASELINE.json         # Quantitative thresholds for EU deployment
    └── APAC_MAS_BASELINE.json       # Quantitative thresholds for APAC deployment
```

## Activation

Set the `CAGE_DEPLOYMENT_REGION` environment variable before starting the gateway:

```bash
# US Federal Reserve deployment (default if unset)
export CAGE_DEPLOYMENT_REGION=US_FED

# European Central Bank / EBA deployment
export CAGE_DEPLOYMENT_REGION=EU_ECB

# MAS Singapore / APAC deployment
export CAGE_DEPLOYMENT_REGION=APAC_MAS
```

The `ControlRegistry` singleton reads this variable at instantiation time and loads
the corresponding `{REGION}_BASELINE.json` file. If the regional file is absent, it
falls back to `config/control_mappings.json` for backward compatibility.

For container deployments, set this in your `values.yaml` or Kubernetes ConfigMap:
```yaml
env:
  - name: CAGE_DEPLOYMENT_REGION
    value: "EU_ECB"
```

## Regional Summary

### US_FED — United States

| Control | Primary Framework |
|---|---|
| `CTRL_AGT_001` | ISO 42001 §A.5.2 (SR 26-2 agentic exclusion applies) |
| `CTRL_WAL_002` | ISO 42001 §A.8.4 |
| `CTRL_TEL_003` | ISO 42001 §A.9.4 |
| `CTRL_MRM_004` | **SR 26-2 §IV** — Model Risk Management |
| `CTRL_OPA_005` | ISO 42001 §A.6.1 |

### EU_ECB — European Union

| Control | Primary Framework |
|---|---|
| `CTRL_AGT_001` | **EU AI Act Art. 6 + Annex III §5(b)** — High-Risk AI Classification |
| `CTRL_WAL_002` | **DORA Art. 12** — Backup and Recovery |
| `CTRL_TEL_003` | **DORA Art. 10** — ICT Incident Detection + EU AI Act Art. 12 Logging |
| `CTRL_MRM_004` | **EBA/GL/2023/02** — Guidelines on Internal Models (replaces SR 26-2) |
| `CTRL_OPA_005` | **EU AI Act Art. 9(5)** + GDPR Art. 22 |
| `CTRL_FRIA_006` | **EU AI Act Art. 29a** — Fundamental Rights Impact Assessment *(EU only)* |

> **Note:** `CTRL_FRIA_006` only exists in the EU_ECB profile. Use
> `registry.get_mapping_safe(GovernanceControl.FRIA_ASSESSMENT)` to handle
> regions where this control is absent without raising a `KeyError`.

### APAC_MAS — Singapore

| Control | Primary Framework |
|---|---|
| `CTRL_AGT_001` | **MAS FEAT** — Fairness Principle F1 |
| `CTRL_WAL_002` | **MAS TRM Guidelines §9.1** — Business Continuity |
| `CTRL_TEL_003` | **MAS TRM Guidelines §6.4** — Model Risk Monitoring |
| `CTRL_MRM_004` | **MAS TRM Guidelines §6.3** — AI/ML Controls |
| `CTRL_OPA_005` | **MAS FEAT** — Accountability Principle A1 |

## Adding a New Region

1. Create `config/compliance/{REGION_CODE}_BASELINE.json` using an existing profile as a template.
2. Create `config/thresholds/{REGION_CODE}_BASELINE.json` with regional quantitative values.
3. Add the region code to `SUPPORTED_REGIONS` in
   [`src/gateway/governance/constants.py`](../src/gateway/governance/constants.py).
4. Update `_EU_LEGACY_CITATION_OVERRIDE` in
   [`src/gateway/governance/causal_gatekeeper.py`](../src/gateway/governance/causal_gatekeeper.py)
   if the new region requires SR 26-2 citation suppression.
5. Add UCA cross-walk tables to
   [`src/gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py)
   if the region requires framework-specific OSCAL output.

## Schema

Each baseline JSON file must contain the following top-level keys:

```json
{
  "_comment": "Human-readable description",
  "_schema_version": "1.1.0",
  "_region": "REGION_CODE",
  "_jurisdiction": "Country or region name",
  "_primary_prudential_authority": "Regulator name",
  "_references": ["List of authoritative regulatory documents"],
  "CTRL_AGT_001": { ... },
  "CTRL_WAL_002": { ... },
  "CTRL_TEL_003": { ... },
  "CTRL_MRM_004": { ... },
  "CTRL_OPA_005": { ... }
}
```

Each control entry must contain:
- `internal_id` — stable `THR-*` identifier
- `primary_framework` — the authoritative regulatory citation for this region
- `co_frameworks` — list of supplementary framework citations
- `legacy_citation` — backward-compat citation for SIEM consumers (suppress SR 26-2 in non-US regions)
- `scope` — `"agentic"` or `"traditional_ml"`
- `description` — human-readable explanation including regional regulatory context

## Layered Compliance Architecture

CAGE uses a strictly layered compliance architecture:

### Global Baseline (ISO 42001)
The global baseline posture is **ISO 42001 only**. All deployments — regardless of region or jurisdiction — must satisfy the ISO 42001 universal release gates before the stable tag is applied. These gates are defined in `.roo/rules` §5.1.

### Regional Additive Layers
Geographic- and jurisdiction-specific compliance postures are implemented as **strictly additive, independently configurable layers** on top of the ISO 42001 baseline. They are activated by the `CAGE_DEPLOYMENT_REGION` environment variable.

| File | Region | Activation | Frameworks |
|------|--------|------------|------------|
| `US_FED_BASELINE.json` | US Federal | `CAGE_DEPLOYMENT_REGION=US_FED` | NIST SP 800-53, FedRAMP |
| `EU_ECB_BASELINE.json` | EU/ECB | `CAGE_DEPLOYMENT_REGION=EU_ECB` | EU AI Act, GDPR, DORA, SR 26-2 |
| `APAC_MAS_BASELINE.json` | APAC/MAS | `CAGE_DEPLOYMENT_REGION=APAC_MAS` | MAS FEAT, MAS TRM, MAS Notice 655, SR 26-2 |

### Non-Negotiable Rules
1. Regional postures **must never** be embedded in, required by, or merged into the global ISO 42001 posture.
2. Regional gates **must not** be treated as prerequisites for the global stable tag.
3. The global stable tag `v<X.Y.Z>` is applied when all universal gates (`.roo/rules` §5.1) pass.
4. Regional deployment gates (`.roo/rules` §5.2–5.4) block region-specific deployment only.
5. All regional baseline files carry `"_baseline_type": "additive_regional_layer"` to make this relationship machine-readable and self-documenting.
