## Summary

<!-- One paragraph: what does this PR do and why? -->

## Type of Change

<!-- Check all that apply -->
- [ ] `feat` — new feature
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `refactor` — no feature/fix, code restructuring
- [ ] `perf` — performance improvement
- [ ] `test` — test additions or corrections
- [ ] `chore` — build, deps, tooling
- [ ] `ci` — CI/CD pipeline
- [ ] `BREAKING CHANGE` — existing behaviour changes

## Related Issues / ADRs

<!-- Closes #<n> | Refs #<n> | N/A -->

## Changes Made

<!-- Bullet list of specific files / components changed and why -->
-
-

## Testing

<!-- How was this tested? Check all that apply -->
- [ ] Unit tests added / updated (`pytest tests/`)
- [ ] Integration tests pass (`make test-integration`)
- [ ] Manual smoke test performed (describe below)
- [ ] No tests needed (docs/config only — explain why)

**Manual test steps (if applicable):**
```
# paste commands here
```

## Compliance & Security Checklist

### 🔒 Universal — All contributors must verify (all regions affected)

- [ ] No secrets, credentials, or PII in committed files
- [ ] Network policy unchanged **or** reviewed by security owner
- [ ] OPA policy changes reviewed for correctness (`src/governed_financial_advisor/graph/governance/trade_policy.rego`)
- [ ] **Data residency:** Any new storage path, GCS write, Langfuse sink, or telemetry export is guarded by `CAGE_DEPLOYMENT_REGION` (prevents silent cross-region data leakage — GDPR Art. 44 / MAS TRM §4.2)
- [ ] **ISO 42001 / CSA AARM:** Lula assertions unaffected — `lula validate` passes for `lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-aarm-vectors.yaml`
- [ ] **No region-specific behaviour introduced without a `cage_deployment_region` guard** — changes to `src/gateway/governance/`, `src/compliance_bridge/`, or `config/` that alter runtime behaviour must branch on `CAGE_DEPLOYMENT_REGION`

> **Why universal?** This is a shared monorepo. The same source (`src/gateway/governance/`, `src/compliance_bridge/`) deploys to US_FED, EU_ECB, and APAC_MAS simultaneously via `CAGE_DEPLOYMENT_REGION`. A change to any shared module affects all three compliance postures.

---

### 🎯 Region-specific depth — Check only your target deployment

> Skip sections that do not apply to your PR's target region. If your change touches shared modules (e.g., `src/gateway/governance/iso_control.py`, `src/compliance_bridge/oscal_parser.py`), check **all** applicable sections.

**US_FED** (`CAGE_DEPLOYMENT_REGION=US_FED` / `infra/targets/gcp-gke/us-dev.tfvars`)
- [ ] N/A — not targeting US_FED
- [ ] NIST SP 800-53 control mappings updated if behaviour changed (`compliance/oscal/sp800-53-component-definition.yaml`)
- [ ] Lula validation passes for NIST controls: `lula validate` (`lula-validation-au12.yaml`, `lula-validation-ac2.yaml`, `lula-validation-sc4.yaml`, etc.)
- [ ] NIST SP 800-53 coverage % unaffected or improved (currently 24% — do not regress)
- [ ] SR 26-2 / FINRA / SEC Reg S-P implications considered if audit pipeline or retention logic changed

**EU_ECB** (`CAGE_DEPLOYMENT_REGION=EU_ECB` / `infra/targets/gcp-gke/eu-dev.tfvars`)
- [ ] N/A — not targeting EU_ECB
- [ ] EU AI Act (Reg. 2024/1689) compliance posture unaffected — no new High-Risk AI behaviour introduced without FRIA attestation
- [ ] GDPR data residency preserved — all data paths remain within `europe-west1` (EEA); no new cross-border transfer without Art. 46 mechanism
- [ ] DORA Art. 10 audit logging still enabled (`enable_audit_logging = true` in `eu-dev.tfvars`)
- [ ] SR 26-2 telemetry suppression intact — `"no legal force"` sentinel in EU baseline not removed

**APAC_MAS** (`CAGE_DEPLOYMENT_REGION=APAC_MAS` / `infra/targets/gcp-gke/apac-dev.tfvars`)
- [ ] N/A — not targeting APAC_MAS
- [ ] MAS FEAT compliance posture unaffected — no new fairness-relevant behaviour introduced without FIA update
- [ ] MAS TRM §4.2 data residency preserved — all data paths remain within `asia-southeast1` (Singapore)
- [ ] MAS Notice 655 audit logging still enabled (`enable_audit_logging = true` in `apac-dev.tfvars`)
- [ ] SR 26-2 telemetry suppression intact — `"no legal force"` sentinel in APAC baseline not removed

---

### 📋 Shared-module impact declaration

> Complete this section if your PR touches any file under `src/gateway/governance/`, `src/compliance_bridge/`, `config/compliance/`, `config/thresholds/`, or `config/oscal/`.

- [ ] Not applicable — PR does not touch shared compliance modules
- [ ] **Impact assessed across all three regions:** Describe below how this change affects US_FED, EU_ECB, and APAC_MAS posture

**Cross-region impact summary (if applicable):**
```
US_FED impact:
EU_ECB impact:
APAC_MAS impact:
```

## Deployment Notes

<!-- Any migration steps, env var changes, or rollout considerations? -->
N/A

## PR Title Format

> Ensure your PR title follows Conventional Commits: `type(scope): description`
> It will become the squash-merge commit message on the integration branch.
