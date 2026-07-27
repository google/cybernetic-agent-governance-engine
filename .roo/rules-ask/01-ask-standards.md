# CAGE — Ask Mode Rules

> **⚠️ REFERENCE ARCHITECTURE ONLY — NOT FOR PRODUCTION USE**
> CAGE is a reference architecture demonstrating governance patterns for
> AI systems. It is **not** intended for, and will **not** be deployed to,
> any production environment. All deployment, change-management, and
> region-guard rules below exist to illustrate best-practice patterns
> only — they carry no operational obligation.

> These rules apply **only** in Ask mode (❓). They supplement the global
> standards in `.roo/rules/00-global-standards.md`, which also apply.
>
> Authority: `docs/operations/GIT_WORKFLOW_STANDARDS.md`,
> `docs/governance/CHANGE_MANAGEMENT_PROCESS.md`

---

## Answering Questions About This Repository

When explaining repository concepts, always reference the authoritative
source documents rather than paraphrasing from memory:

| Topic | Authoritative source |
|---|---|
| Git workflow, branching, commits | `docs/operations/GIT_WORKFLOW_STANDARDS.md` |
| Deployment procedures | `docs/DEPLOYMENT_RULES.md` |
| Change management categories | `docs/governance/CHANGE_MANAGEMENT_PROCESS.md` |
| Release process and gates | `docs/operations/RELEASE_RUNBOOK.md` |
| PR requirements | `.github/pull_request_template.md` |
| CI pipeline | `.github/workflows/ci.yml` |
| Compliance obligations | `compliance/lula/`, `compliance/oscal/` |
| POAM tracking | `docs/POAM.md` |

---

## Commit and Branch Guidance

When asked to explain or suggest commit messages or branch names, apply
the same validation rules as Code mode:

- Commit type must be one of: `feat | fix | docs | style | refactor | perf | test | chore | ci | revert`
- Subject line ≤ 72 characters, imperative mood, no trailing period
- Branch names: lowercase kebab-case, one of the 9 permitted prefixes,
  description segment ≤ 30 characters

Never suggest a prohibited commit subject even in an explanatory context.

---

## Compliance and Security Explanations

When explaining compliance posture or security controls:
- Distinguish clearly between universal gates (ISO 42001) and regional
  gates (US_FED / EU_ECB / APAC_MAS)
- Regional gates do not block the global stable tag — they block regional
  deployment only
- Always note that `CAGE_DEPLOYMENT_REGION` guards are required for any
  new data path in shared modules
- Always clarify that CAGE is a **reference architecture** — region gates,
  CAB approvals, and deployment promotion rules are **illustrative patterns**,
  not operational obligations for this repository.

When asked about secrets or credentials:
- Never provide example values that resemble real credentials
- Always direct to `terraform.auto.tfvars` for secret storage
- Always note that `secretKeyRef` / `secretRef` is required in Kubernetes

---

## Change Category Guidance

When asked whether a change requires CAB approval or AO sign-off:
- Classify using Cat-E / Cat-S / Cat-N / Cat-M
- For Cat-M: explicitly state AO pre-approval is required before implementation
- For Cat-N: note the 5-business-day minimum CAB review window
- For Cat-E: note expedited approval but unchanged format requirements
- Always note that CAGE is a reference architecture; no formal CAB or AO
  approval is required for changes to this repository — the categories are
  illustrative only.
