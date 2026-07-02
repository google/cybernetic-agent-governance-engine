# CAGE — Architect Mode Rules

> These rules apply **only** in Architect mode (🏗️). They supplement the
> global standards in `.roo/rules/00-global-standards.md`, which also apply.
>
> Authority: `docs/operations/GIT_WORKFLOW_STANDARDS.md`,
> `docs/governance/CHANGE_MANAGEMENT_PROCESS.md`,
> `docs/DEPLOYMENT_RULES.md`, `docs/operations/RELEASE_RUNBOOK.md`

---

## Change Classification — Before Any Design Work

Before producing any architectural plan or design document, classify the
change using the CAGE change management categories:

| Category | Triggers | Action required |
|---|---|---|
| Cat-M (Major) | New GCP services, new K8s namespaces, new AI models, new external APIs, HIGH-impact NIST control changes, significant security architecture changes | **Flag explicitly. State AO pre-approval is required. Do not produce implementation steps without noting this.** |
| Cat-N (Normal) | Standard feature additions, non-breaking infrastructure changes | Note 5-business-day CAB review window |
| Cat-S (Standard) | Pre-approved patterns already in the change catalogue | Proceed; note pre-approved status |
| Cat-E (Emergency) | Production incidents requiring immediate architectural response | Expedited approval; format requirements still apply |

**Never produce a detailed implementation plan for a Cat-M change without
first stating the Cat-M classification and AO pre-approval requirement.**

---

## Architecture Decision Records (ADRs)

When proposing a significant architectural change:
- Reference or propose an ADR in `docs/adr/` for any decision that affects
  the authorization boundary, data residency, or compliance posture.
- ADR titles follow the pattern: `ADR-NNN-short-description.md`
- ADR body must include: Context, Decision, Consequences, Compliance impact.

---

## Shared-Module Impact Assessment

Before designing any change to shared modules, declare the cross-region impact:

**Shared modules** (deploy simultaneously to US_FED, EU_ECB, APAC_MAS):
- `src/gateway/governance/`
- `src/compliance_bridge/`
- `config/compliance/`
- `config/thresholds/`
- `config/oscal/`

For any change to these paths, the architectural plan must include:
1. Impact statement for US_FED (NIST SP 800-53 posture)
2. Impact statement for EU_ECB (GDPR / EU AI Act / DORA posture)
3. Impact statement for APAC_MAS (MAS FEAT / MAS Notice 655 / MAS TRM posture)
4. `CAGE_DEPLOYMENT_REGION` guard placement for any new data paths

---

## Deployment Architecture Constraints

**GKE targets always use Cloud Build.** Never design a deployment pipeline
that uses local `docker build` + `docker push` for GKE targets.

**Approved deployment patterns:**
- `./deploy_all.sh --target gcp-gke --env <dev|prod>` (Cloud Build)
- `gcloud builds submit --config deployment/docker/cloudbuild_gateway.yaml`
- Local: `./deploy_all.sh --target agnostic --env dev` (k3d/kind)

**Terraform state** is in GCS backend (`infra/targets/gcp-gke/backend.tf`).
Active IaC is under `infra/`. Never reference `deployment/terraform/` for
new designs — it is historical reference only.

---

## Release Architecture

When designing a release process or versioning strategy:
- All releases follow SemVer (MAJOR.MINOR.PATCH)
- Release branches: `rc-v<X.Y.Z>` branched from `main`
- Feature freeze applies immediately when `rc-v<X.Y.Z>` is created
- Stable tags are annotated: `git tag -a v<X.Y.Z> -m "chore(release): ..."`
- Regional gates (US_FED, EU_ECB, APAC_MAS) are additive — they do not
  block the global stable tag; they block regional deployment only

---

## Compliance Architecture Obligations

When designing changes that affect compliance posture:
- NIST SP 800-53 control changes → OSCAL update in `compliance/oscal/`
  required within 2 business days of merge
- Kubernetes resource changes referenced by Lula → Lula validation update
  in `compliance/lula/` in the same PR or follow-on PR
- STPA source changes → STPA artifact regeneration required before commit
- Any design that remediates a POAM finding → note `docs/POAM.md` update
  requirement (commit SHA, Lula result, closure date)
