# CAGE — Code Mode Rules

> **⚠️ REFERENCE ARCHITECTURE ONLY — NOT FOR PRODUCTION USE**
> CAGE is a reference architecture demonstrating governance patterns for
> AI systems. It is **not** intended for, and will **not** be deployed to,
> any production environment. All deployment, change-management, and
> region-guard rules below exist to illustrate best-practice patterns
> only — they carry no operational obligation.

> These rules apply **only** in Code mode (💻). They supplement the global
> standards in `.roo/rules/00-global-standards.md`, which also apply.
>
> Authority: `docs/operations/GIT_WORKFLOW_STANDARDS.md`,
> `.github/workflows/ci.yml`, `docs/DEPLOYMENT_RULES.md`

---

## Hard-Stop Checklist — Before Writing Any Code

Run through every applicable item before producing output.

### Before writing any commit message
- Verify type is one of the 10 permitted types: `feat | fix | docs | style | refactor | perf | test | chore | ci | revert`
- Verify subject line ≤ 72 characters total
- Verify imperative mood, no trailing period, no capitalised first word
- Reject prohibited subjects outright — never suggest them

### Before suggesting any branch name
- Verify pattern matches one of the 9 permitted prefixes
- Verify description segment ≤ 30 characters
- Verify lowercase kebab-case only — no underscores, no uppercase

### Before creating any file in `src/`
- Prepend the Apache 2.0 license header for `.py`, `.ts`, `.tsx`, `.js` files
- Verify no secrets, credentials, or PII are embedded anywhere in the file

### Before suggesting any GKE deployment command
- Verify Cloud Build is used — never `docker build` + `docker push` for GKE
- Reject any suggestion of local Docker build for GKE targets

### Before suggesting any Terraform change
- Verify secret values are in `terraform.auto.tfvars` (gitignored)
- Verify no sensitive values appear in committed `.tf` files
- Always remind: `terraform plan` must precede `terraform apply`

### Before suggesting any change to shared compliance modules
- Flag `CAGE_DEPLOYMENT_REGION` guard requirement
- Flag cross-region impact declaration requirement for the PR
- Flag that Lula validation must be re-run post-merge

---

## Deployment Rules (Code Mode)

**GKE targets — Cloud Build only. No exceptions.**

```bash
# APPROVED for GKE
./deploy_all.sh --target gcp-gke --env dev
./deploy_all.sh --target gcp-gke --env prod
gcloud builds submit --config deployment/docker/cloudbuild_gateway.yaml

# APPROVED for local/agnostic
./deploy_all.sh --target agnostic --env dev
./deploy_all.sh
```

**Never suggest for GKE:**
- `docker build ... && docker push ...`
- `docker-compose build && docker-compose push`
- `kubectl apply` without a preceding Cloud Build step

**Cloud Build config files:**
- Gateway: `deployment/docker/cloudbuild_gateway.yaml`
- vLLM: `deployment/docker/cloudbuild.vllm.yaml`
- LULA: `deployment/docker/cloudbuild.lula.yaml`

---

## License Header — Python Template

Always prepend to new `.py` files under `src/`:

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

For `.ts`, `.tsx`, `.js` files, use the same text with `//` comment prefix.

---

## Compliance Artifact Obligations (Code Mode)

When writing code that touches NIST SP 800-53 control implementations:
- Note that an OSCAL component update in `compliance/oscal/` is required within 2 business days of PR merge.

When adding or removing Kubernetes resources referenced by Lula validation files:
- Include a Lula validation update in `compliance/lula/` in the same PR or flag it for a follow-on PR.

When remediating an open POAM finding:
- Remind the operator to update `docs/POAM.md` with: commit SHA, Lula result, closure date.

When modifying STPA source files:
- Remind the operator to regenerate STPA artifacts before committing (`scripts/check_stpa_freshness.py`).

---

## Secret Hygiene (Code Mode)

Never write code that embeds secrets. Specifically:
- Never use `os.environ.get("KEY", "hardcoded-fallback")`
- Never hardcode connection strings, tokens, or API keys
- Always use environment variable references without defaults for sensitive values
- Kubernetes manifests must use `secretKeyRef` or `secretRef` — never `value: <secret>`

Credential patterns that must never appear in committed files:
- `pk-lf-*` or `sk-lf-*` (Langfuse keys)
- `hf_*` (HuggingFace tokens)
- `GOOG*` (Google credentials)
- `redis://*:*@*` (Redis connection strings with credentials)
