# CAGE — Global Agent Standards (All Modes)

> Authority: `docs/operations/GIT_WORKFLOW_STANDARDS.md`,
> `docs/DEPLOYMENT_RULES.md`, `docs/governance/CHANGE_MANAGEMENT_PROCESS.md`,
> `.github/pull_request_template.md`, `.github/workflows/ci.yml`,
> `docs/operations/RELEASE_RUNBOOK.md`
>
> These rules are NON-NEGOTIABLE and apply in every Roo mode.

---

## Commit Message Rules (Conventional Commits v1.0)

**Format:** `<type>(<scope>): <short summary>` — entire subject line ≤ 72 characters.

**Valid types (exactly these 10):**
`feat` | `fix` | `docs` | `style` | `refactor` | `perf` | `test` | `chore` | `ci` | `revert`

**Valid scopes (use exactly one when applicable):**
`gateway` | `compliance` | `infra` | `governance` | `tests` | `docs` | `ci` | `agentsight` | `advisor` | `nemo` | `opa`

**Subject line — always:**
- Use imperative mood: "add rate limiter" NOT "added" or "adds"
- No period at the end
- No capitalisation of the first word
- Be specific: convey WHAT changed, not just that something changed

**Prohibited subjects (pre-commit hook rejects these — never suggest them):**
`fix stuff` | `update` | `WIP` | `fixup!` | `squash!` | `done` | `misc changes` | `addressing review comments`

**Body (required when subject is not self-evident):**
- Separate from subject with exactly one blank line
- Wrap every line at 72 characters
- Explain WHAT changed and WHY — not how

**Footer tokens:**
- `Closes #<n>` or `Refs #<n>` for issue references
- `BREAKING CHANGE: <description>` or `feat(gateway)!:` shorthand
- `Co-authored-by: Name <email>`
- `[CR-YYYY-NNN] <description>` when a Change Request ID exists

**Never suggest a mega-commit.** A single commit touching > ~20 files or > ~500 lines (excluding generated files) must be decomposed.

---

## Branch Naming Rules

**All branch names must use lowercase kebab-case. No underscores. No uppercase. No spaces.**

**Required prefixes:**

| Prefix | Use case | Ticket ID required? |
|---|---|---|
| `feat/<ticket-id>-description` | New feature | Yes |
| `fix/<ticket-id>-description` | Bug fix | Yes |
| `hotfix/<ticket-id>-description` | Production hotfix | Yes |
| `chore/<description>` | Tooling, deps, build | No |
| `docs/<description>` | Documentation only | No |
| `release/v<X.Y.Z>` | Release candidate | No |
| `refactor/<description>` | Code restructuring | No |
| `ci/<description>` | CI/CD pipeline changes | No |
| `spike/<description>` | Experiment / PoC | No |

- Description segment after the prefix must be ≤ 30 characters.
- Delete feature/fix branches from the remote immediately after PR merge.
- **Protected branches — never push directly:** `main` | `rc-v2.0.0` | `release/**`
- Always branch from the latest integration branch: `git checkout main && git pull origin main`

---

## Secret & Credential Hygiene

**Never commit secrets, credentials, API keys, passwords, tokens, or PII.**

This includes:
- Hardcoded fallback values: `os.environ.get("KEY", "secret")`
- Inline values in Kubernetes manifests, Helm values, or Terraform `.tf` files
- Any value matching: `pk-lf-*` | `sk-lf-*` | `hf_*` | `GOOG*` | `redis://*:*@*`

**`terraform.auto.tfvars` is always gitignored.** Secret values belong there only.

**Kubernetes Secrets must use `secretKeyRef` or `secretRef`** — never hardcoded `value:` fields.

If a secret is accidentally committed, treat it as compromised immediately. Rotate before rewriting history.

---

## License Header Requirements

All new source files in `src/` must include an Apache 2.0 license header.
The CI license-check job enforces this for `*.py`, `*.js`, `*.ts`, `*.tsx` files.

**Always prepend this header to any new `.py`, `.ts`, `.tsx`, or `.js` file under `src/`:**

```python
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
```

---

## Change Management Categories

| Category | Approval window | CHANGELOG.md required? |
|---|---|---|
| Cat-E (Emergency) | 2-hour verbal auth; AO notified within 1 hour | Yes (within 4 hours) |
| Cat-S (Standard) | Pre-approved; no individual CAB needed | No |
| Cat-N (Normal) | 5 business days minimum; full CAB review | Yes |
| Cat-M (Major) | 30 calendar days minimum; CAB + AO review | Yes |

**Cat-M triggers (AO pre-approval required before any implementation):**
- New GCP services or Kubernetes namespaces
- New external API integrations
- New AI models or inference services
- Changes to HIGH-impact NIST SP 800-53 controls
- Significant security architecture changes

**Always flag Cat-M changes explicitly. Refuse to generate implementation steps without noting the Cat-M requirement.**

**Environment promotion order: dev → staging → production.** No direct dev-to-production promotion.

---

## Shared-Module Region Guard Obligations

`src/gateway/governance/` and `src/compliance_bridge/` deploy simultaneously to US_FED, EU_ECB, and APAC_MAS via `CAGE_DEPLOYMENT_REGION`.

**Any new storage path, GCS write, Langfuse sink, or telemetry export in shared modules MUST be gated on `CAGE_DEPLOYMENT_REGION`.**

- EU_ECB data paths must remain within `europe-west1`
- APAC_MAS data paths must remain within `asia-southeast1`
- US_FED data paths must remain within `us-central1` or approved US regions

**Never remove the "no legal force" SR 26-2 sentinel** in EU and APAC baselines. It suppresses telemetry lacking legal basis under GDPR / MAS Notice 655.
