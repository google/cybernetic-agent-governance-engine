# CAGE — Debug Mode Rules

> **⚠️ REFERENCE ARCHITECTURE ONLY — NOT FOR PRODUCTION USE**
> CAGE is a reference architecture demonstrating governance patterns for
> AI systems. It is **not** intended for, and will **not** be deployed to,
> any production environment. All deployment, change-management, and
> region-guard rules below exist to illustrate best-practice patterns
> only — they carry no operational obligation.

> These rules apply **only** in Debug mode (🪲). They supplement the global
> standards in `.roo/rules/00-global-standards.md`, which also apply.
>
> Authority: `docs/operations/GIT_WORKFLOW_STANDARDS.md`,
> `docs/DEPLOYMENT_RULES.md`, `docs/governance/CHANGE_MANAGEMENT_PROCESS.md`

---

## Debugging Constraints — Secret & Credential Safety

When adding diagnostic logging, tracing, or debug output:
- **Never log secrets, tokens, credentials, or PII** — even temporarily.
- Never suggest `print(os.environ)` or equivalent full-environment dumps.
- Never suggest logging request headers wholesale without first filtering
  `Authorization`, `X-Api-Key`, `Cookie`, and similar sensitive headers.
- If a debug statement would expose a credential pattern
  (`pk-lf-*`, `sk-lf-*`, `hf_*`, `GOOG*`, `redis://*:*@*`),
  mask it before logging: `value[:4] + "****"`.

---

## Diagnosing CI Failures

When investigating a CI failure, check these jobs in order:

1. **license-check** (`.github/workflows/ci.yml`) — missing Apache 2.0 header
   in a new `src/` file. Fix: prepend the standard header.
2. **stpa-freshness-check** — STPA source changed without regenerating
   artifacts. Fix: run `scripts/check_stpa_freshness.py`.
3. **langfuse-posture-check** — Langfuse posture drift. Fix: run
   `scripts/verify_langfuse_posture.py`.
4. **pytest** — unit or integration test failure. Fix: address the failing
   test before suggesting any workaround.
5. **security-scan** — secret detected or vulnerability found. Fix: rotate
   the credential; never suggest suppressing the scan.

**Never suggest disabling or skipping a CI check as a fix.**

---

## Diagnosing Deployment Failures

When debugging a GKE deployment failure:
- Verify the deployment used Cloud Build, not local `docker build`.
- Check Cloud Build logs: `gcloud builds list --limit=5`
- Check pod status: `kubectl get pods -n governance-stack`
- Check events: `kubectl describe pod <pod-name> -n governance-stack`

When debugging Terraform failures:
- Never suggest `terraform apply` without a preceding `terraform plan`.
- Never suggest editing Terraform state directly.
- Verify `terraform.auto.tfvars` exists and is not committed.

---

## Diagnosing Compliance Failures

When a Lula validation fails:
- Identify which assertion file failed: `lula-validation-*.yaml`
- Distinguish universal gates (ISO 42001) from regional gates
  (US_FED / EU_ECB / APAC_MAS) — regional failures do not block the
  global stable tag.
- Check whether the Kubernetes resource referenced by the assertion exists
  and has the expected labels/annotations.

When OSCAL coverage is below threshold:
- Run `src/gateway/governance/oscal_ssp_exporter.py` to regenerate the SSP.
- Check `compliance/oscal/` for stale component definitions.

---

## Fix Commit Standards (Debug Mode)

When producing a fix commit message after diagnosing an issue:
- Type must be `fix` (not `chore`, not `patch`)
- Scope should identify the affected component
- Subject must describe the specific defect corrected, not just "fix bug"
- Example: `fix(gateway): correct missing secretKeyRef in advisor-secrets`

Never suggest a fix commit with a prohibited subject such as `fix stuff`
or `addressing review comments`.
