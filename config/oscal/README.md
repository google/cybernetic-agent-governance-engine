# OSCAL Framework Routing Configuration

This directory contains the external JSON framework routing tables consumed by the **OSCAL SSP Exporter** (`src/gateway/governance/oscal_ssp_exporter.py`).

## Purpose

In CAGE v2.0.0, the UCA-to-control cross-walk tables that previously lived as hardcoded Python dicts (`_UCA_TO_NIST`, `_UCA_TO_EU_AI_ACT`, etc.) have been **fully decoupled** into these data files.

This is the "Crown Jewel Decoupling" described in the v2.0.0 architecture brief:
- Adding a new jurisdiction requires only a new JSON file — zero Python changes.
- Regulatory updates (e.g. a new EU AI Act amendment) are a config PR, not a code PR.
- CI pipelines can validate JSON schema independently of unit tests.

## Files

| File | Framework | Authority |
|------|-----------|-----------|
| `NIST_SP800_53.json` | NIST SP 800-53 Rev 5 | NIST / FedRAMP |
| `ISO_42001.json` | ISO/IEC 42001:2023 | ISO AI MSMS |
| `EU_AI_ACT.json` | EU AI Act (Regulation (EU) 2024/1689) | EU AI Office / EBA / ECB |
| `MAS_FEAT.json` | MAS FEAT Principles | Monetary Authority of Singapore |

## JSON Schema

Each file follows this schema:

```json
{
  "_schema_version": "2.0.0",
  "_framework_id": "FRAMEWORK_ID",
  "_framework_label": "Human-readable framework name",
  "_framework_source": "https://canonical-url",

  "uca_mappings": {
    "UCA-N": ["control-id-1", "control-id-2"]
  },

  "control_descriptions": {
    "control-id": "Human-readable description of the control"
  },

  "narrative_template": "Template string with {control_id}, {control_description}, {uca_list} placeholders."
}
```

## Adding a New Framework

1. Create `config/oscal/framework_mappings/NEW_FRAMEWORK.json` following the schema above.
2. The `FrameworkRouter` in `oscal_ssp_exporter.py` will discover and load it automatically when `--framework NEW_FRAMEWORK` is passed.
3. Update the `--framework` CLI choices list in `oscal_ssp_exporter.py`.
4. No other Python changes required.

## Relationship to Regional Compliance Profiles

These files govern **OSCAL SSP output** (compliance documentation export).

The **operational control mappings** (what framework governs live runtime decisions) live in:
`config/compliance/{REGION}_BASELINE.json` — loaded by `ControlRegistry` at boot time.

They are intentionally separate concerns:
- `config/compliance/` → runtime governance engine data
- `config/oscal/framework_mappings/` → compliance artifact generation data
