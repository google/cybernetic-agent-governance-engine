<!--
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Jurisdiction Inventory: US_FED, EU_ECB, APAC_MAS

> **What this is.** A record of what each jurisdictional posture actually configures, extracted from the code rather than designed. It is the evidence behind the GKE deployment profiles, and it is meant to outlive the people who know the wiring.
>
> **Provenance.** Extracted read-only on 2026-10-28 at `9109d914`, re-checked at `d830249c`. Between those commits, the only changes under `infra/`, `config/`, `compliance/`, `.github/` and `scripts/` are the POAM-2026-126 fix and five lines in a POA&M script.
>
> **Labels.**
> - **verified:** something was run and its output seen.
> - **read:** read in code or configuration.
> - **inferred:** reasoning, not observation.
>
> Nothing here was planned, applied or run against a cluster unless it says so.

## 1. How a process learns its jurisdiction

- **One key carries it:** `CAGE_DEPLOYMENT_REGION` in the `cage-deployment` ConfigMap ([`deployment_config`](../../infra/modules/deployment_config/main.tf)). It reaches the gateway, the advisor, the compliance bridge and the Lula cron (read).
- **In process,** `ControlRegistry` ([`constants.py`](../../src/gateway/governance/constants.py)) reads it and falls back to US_FED when it is unset or unknown. The threshold loader and `resolve_jurisdiction` ([`registry.py`](../../src/gateway/governance/jurisdiction/registry.py)) take the region from `ControlRegistry`. Thresholds are resolved once per process (read).
- **The regional overlay merges only `domains.*`** from `config/thresholds/<REGION>_BASELINE.json` ([`regional_overlay.py`](../../src/gateway/governance/schemas/regional_overlay.py)). Everything else in those files has no reader (section 7, read).
- **Hermetic tests run under US_FED** unless marked `us_fed`, `eu_ecb` or `apac_mas`; a marked test runs under its own region ([`conftest.py`](../../tests/conftest.py), read).

## 2. What changes with the jurisdiction at runtime

All values verified by loading them through the threshold loader, `ControlRegistry` and `resolve_jurisdiction`.

| | US_FED | EU_ECB | APAC_MAS |
|---|---|---|---|
| Consensus threshold (USD) | 10,000 | 7,500 | 8,500 |
| CBF gamma / drawdown limit | 0.5 / 0.05 | 0.6 / 0.04 | 0.55 / 0.045 |
| STPA: UCA-5 drawdown % / UCA-6 max order fraction | 4.5 / 0.01 | 3.5 / 0.005 | 4.0 / 0.008 |
| Min trade confidence | 0.95 | 0.97, warrant required | 0.96 |
| Jurisdiction tiers | none | `fria` (CTRL_FRIA_006); refuses an enforcing start on the stub provider | none |
| Kernel control IDs | 7 shared + `agentic_scope_statement` | 7 shared + CTRL_FRIA_006 | 7 shared |
| HITL SLA at runtime | 4 h | 8 h | 12 h (see section 7) |
| OSCAL profile | NIST SP 800-53 | EU AI Act | MAS FEAT |
| Compliance-bridge control set | 14 | 8 | 7 |
| Plugin compliance overlays | finance, healthcare, physical_ai | healthcare | healthcare |

- **Regional policy.** The only regional Rego is the US_FED test bundle under `compliance/postures/us_fed/opa/`. There is no EU or APAC Rego and no per-region OPA data (verified, `git ls-files`).
- **The finance overlay redefines a kernel control.** Its US_FED overlay redefines `CTRL_FTRA_001`; see POAM-2026-121 and POAM-2026-123.

## 3. Deployment profiles (`infra/targets/gcp-gke/`)

| Profile | Jurisdiction | State prefix | Posture | In-cluster vLLM / GPU pool | Referenced by |
|---|---|---|---|---|---|
| `dev.tfvars` | none in the file; set at deploy time | `cage-dev`, shared with `us-dev` | dev | on; L4 0–2 | `Makefile` default; deploy examples; tests |
| `us-dev.tfvars` | US_FED | `cage-dev` | dev | on | PR template; GKE test runbook; tests |
| `eu-dev.tfvars` | EU_ECB | `cage-eu-dev` | dev with compliance hardening | on; zones include `europe-west1-d` | EU workflow (warning only); tests |
| `apac-dev.tfvars` | APAC_MAS | `cage-apac-dev` | dev with compliance hardening | on | APAC workflow (warning only); tests |
| `staging.tfvars` | US_FED | `cage-staging` | full; zonal; Binary Authorization dry-run | on; L4 0–2 | staging scripts; tests |
| `prod.tfvars` | US_FED (DEP-12) | `cage-prod` | full; regional; HA; Binary Authorization enforced | on, 2 replicas | deploy usage; tests |
| `eu-prod.tfvars` | EU_ECB | `cage-eu-prod` | as prod | on, 2; zones include `europe-west1-d` | EU workflow (can fail); tests |
| `apac-prod.tfvars` | APAC_MAS | `cage-apac-prod` | as prod | on, 2 | APAC workflow (can fail); tests |

- **Placeholders.**
  - Every profile except `dev.tfvars` carries a placeholder `project_id`.
  - Every profile except `staging.tfvars` inherits placeholder image digests (section 7).
- **No repository consumer reads a profile's GPU or vLLM settings.** No workflow, script or test reads `enable_vllm`, `enable_gpu_node_pool`, `gpu_node_locations` or `vllm_replicas` from a profile. Tests assert module wiring only (verified, grep). That is not evidence that nothing outside the repository depends on them.
- **Control-plane access.** Every profile with a compliance posture active must name operator CIDRs and no `/0`; the plan refuses otherwise (POAM-2026-126, [`test_control_plane_access.py`](../../tests/infrastructure/test_control_plane_access.py)). `staging.tfvars` sets no list, so supply one with `TF_VAR_authorized_networks`.

## 4. Jurisdiction and geography: postures do not float

Read at `d830249c`; nothing was planned.

| Resource | Location comes from | Jurisdiction check |
|---|---|---|
| CMEK key ring ([`kms`](../../infra/modules/kms/main.tf)) | `var.region` | precondition: EU_ECB and APAC_MAS refused in `us-central1` only |
| Signing key ring ([`kms_signing.tf`](../../infra/targets/gcp-gke/kms_signing.tf)) | `var.region` | none |
| WORM evidence bucket ([`worm_bucket`](../../infra/modules/worm_bucket/main.tf)) | `var.region` | precondition: `europe-*`, `asia-*` or `us-*` must match the jurisdiction |
| Memorystore, both instances ([`memorystore_valkey`](../../infra/modules/memorystore_valkey/main.tf)) | `var.region` | none |
| Langfuse events and ClickHouse cold-tier buckets ([`main.tf`](../../infra/targets/gcp-gke/main.tf)) | `var.region` | the same prefix precondition |

- **Where the binding is.** No location is derived from `CAGE_DEPLOYMENT_REGION`, and none is a literal. Jurisdiction is bound to geography only through preconditions.
- **Every tier.** None of the preconditions depends on the environment, so `EU_ECB` outside `europe-*` fails at plan in dev and staging as well as prod.
- **Deliberate.** The binding cites GDPR Art. 44 and MAS TRM §4.2 (DEP-10).
- **Decided 2026-10-28: postures stay bound to their geography.** Residency is enforced in every tier, dev included, with no bypass. Assessing a posture therefore needs capacity in its region, and the GKE guide states this as a feature.
- **At runtime,** the evidence cold store refuses a location its jurisdiction doesn't allow ([`residency.py`](../../src/gateway/governance/evidence/residency.py), [`residency.json`](../../config/compliance/residency.json); read).
- **Elsewhere.** OPA has no residency assertion (verified, grep). The two APAC Lula manifests check `asia-southeast1` through their status endpoints.

## 5. Compliance artifacts

- **Lula:** 33 manifests in `compliance/lula/` (verified). By scope: all regions 8, US_FED 18, EU_ECB 4, APAC_MAS 3. Most are stubs; `eu-fria` is active.
- **Lula runs:**
  - [`lula-validate.yml`](../../.github/workflows/lula-validate.yml) loops over all 33 with `continue-on-error`.
  - The regional workflows only check YAML structure.
- **OSCAL:** the SSPs list 15 (US), 7 (EU) and 5 (APAC) control IDs (verified). The EU and APAC profiles import stub catalogs and select no controls (verified).
- **Region-specific POA&M files** exist under `docs/compliance/us_fed/`, `docs/compliance/eu_ecb/` and `docs/compliance/apac_mas/`.

## 6. CI per jurisdiction

- **Required checks** (branch ruleset, verified 2026-10-28):
  - Lint
  - AI 600-1 Unit Tests
  - OPA Rego Policy Lint and Test (Universal — NIST CM-6/SI-7 reporting: US_FED only)
  - Secret Scanning (Gitleaks)
  - license-check
  - Pytest Logic Tests
- **Region-pinned tests in the required job:** US_FED 18, EU_ECB 48, APAC_MAS 7, plus about 150 region-parametrized items per region (verified, collection). The asymmetry is POAM-2026-122.
- **Regional workflows that cannot fail the build:**
  - the EU and APAC legs of [`regional-posture.yml`](../../.github/workflows/regional-posture.yml), which are hermetic, marker-pinned pytest runs;
  - the test step of [`compliance-matrix.yml`](../../.github/workflows/compliance-matrix.yml), which also installs from `requirements*.txt` files that don't exist;
  - `lula-validate.yml`;
  - `ci-integration.yml`, which runs on dispatch only.

  POAM-2026-121 records the first two. POAM-2026-150 records the pattern, with `ci.yml`'s `integration-smoke` job, which skips all 153 tests it selects.
- **Regional workflows that can fail:** [`eu-ecb-compliance.yml`](../../.github/workflows/eu-ecb-compliance.yml) and [`apac-mas-compliance.yml`](../../.github/workflows/apac-mas-compliance.yml) check the prod profiles' residency, jurisdiction and compliance flag.

## 7. Inference consumers

Read at `211f7155`, with routing verified by stubbing the model client. Every row describes the gcp-gke wiring.

| Consumer | Endpoint and model | Owner | Model text becomes | Behaviour when absent |
|---|---|---|---|---|
| Agent execution (tool calls) | `VLLM_FAST_API_BASE`, `MODEL_FAST`: Qwen2.5-1.5B-Instruct on `vllm-service` | agent | a proposal, gated by the gateway | node build raises |
| Agent reasoning | `VLLM_REASONING_API_BASE`, `MODEL_REASONING`: DeepSeek-R1-Distill-Llama-8B on `vllm-reasoning` | agent | a plan, dry-run by the gateway | the supervisor silently uses a mock model; other nodes raise |
| Graph input and output rails (advisor process) | the advisor's `MODEL_FAST` on `VLLM_FAST_API_BASE`: the agent's execution model | agent environment | a verdict | input: refuse on `none` or judge failure. Output: has never put its question to a model, and always reads safe (POAM-2026-125) |
| Gateway rails and `verify_content_safety` | `GUARDRAILS_MODEL_NAME` = `served_model_fast`, on `vllm-service` | gateway | a verdict | refuse (POAM-2026-124 fix) |
| Consensus critics | `CONSENSUS_<ROLE>_URL`, else the routed endpoint, else `VLLM_BASE_URL` (POAM-2026-127); model `CONSENSUS_<ROLE>_MODEL`, else `MODEL_*`, else `gemini-2.5-pro` | gateway | a verdict, parsed strictly | `none`: DENY at or above the threshold. No endpoint: ERROR, so escalate |
| Compliance-bridge advisory and AARM narratives | `VLLM_BASE_URL`, `REMEDIATION_MODEL` = `served_model_fast` | bridge | a governance artifact, unparsed | `NOT_PERFORMED` or a template |

- **No setting means "the model governance uses."** `VLLM_BASE_URL`, `VLLM_FAST_API_BASE` and `VLLM_REASONING_API_BASE` are named by model, not by consumer.
- **The judges are the agent's own model.** Every governance consumer that reaches a verdict uses the agent's execution model on the agent's execution endpoint, so correlated blind spots between judge and agent can't be measured on a shipped surface.
- **The advisor's graph rails can't be separated by configuration.** They read the advisor's own environment.
- **One tfvar sets five values.** `served_model_fast` sets the agent's model, the gateway's guardrail model, the bridge's remediation model, the standalone NeMo model and the name `vllm-service` serves.
- **The NeMo config's DeepSeek model is a label only.** Requests use `GUARDRAILS_MODEL_NAME`, else `MODEL_FAST` (verified).

## 8. Where the repository contradicts itself

Each has a one-line POA&M entry except the stale numbers. Several are one class: declared, never consumed. A mechanical detector (declaration sites minus usage sites) is a candidate gate; it is not scheduled.

- **Regional tier-1 keywords are not loaded (POAM-2026-128).** EU and APAC extras such as `BYPASS FRIA` are listed in the overlay files, but every region loads the same 14 global keywords (verified).
- **Two HITL SLA sets (POAM-2026-129).** The runtime uses 4, 8 and 12 hours; the thresholds files say 4, 2 and 1, citing DORA and MAS FEAT. Which is intended is being established.
- **The EU and APAC compliance flags do in Terraform exactly what the NIST flag does (POAM-2026-130),** although their descriptions claim distinct effects (verified, grep).
- **Placeholder image digests (POAM-2026-131).** Every profile except staging inherits `sha256:e3b0c442…`, the hash of empty input. That includes the three Binary-Authorization-enforcing prod profiles (verified).
- **No L4 in one EU zone (POAM-2026-132).** `europe-west1-d` offers neither L4 nor `g2-standard-8`, but `eu-dev` and `eu-prod` list it for their GPU pools. `europe-west1-b` and `-c` offer both (verified, Compute API). Node-pool creation failing is inferred.
- **The documented required-check lists disagree with the ruleset (POAM-2026-133).** See section 6.
- **Consensus on gcp-gke has never produced an automated verdict (POAM-2026-134).** The gateway pod has no `MODEL_*`, so both critics ask for `gemini-2.5-pro`, and every triggered consensus escalates. The 404 is inferred. The critics' prompt format also disagrees with their parser. `MODEL_CONSENSUS` and `CONSENSUS_<ROLE>_*` are set by no surface.
- **The default advisor runtime (GEAP) can't call a model (POAM-2026-135).** It has no `OPENAI_API_KEY`, and its endpoints are cluster-local names (verified for the key; reachability open).
- **Declared, never read (POAM-2026-136).** `vllm_fast_url`, `vllm_reasoning_url` and `vllm_gateway_url` are declared in `variables.tf` and filled by `deploy_all.sh`, but nothing reads them.
- **Model output enters compliance records with its provenance suppressed (POAM-2026-137).** The remediation advisory is scored as a completed control in the compliance trace, and AARM narratives are written by a model told not to say so.
- **Correlated blind spots between judges and the agent can't be measured on any shipped surface (POAM-2026-139).** See section 7.
- **The advisor's supervisor falls back silently to a mock model (POAM-2026-138)** when its reasoning endpoint is unset or contains "mock"; other nodes raise (read).
- **Stale numbers.**
  - Three places say 31 Lula manifests.
  - The GKE test runbook names a GPU pool and a `vllm_replicas` value that staging doesn't use.

## 9. Open questions

1. Which HITL SLA do DORA and MAS FEAT actually require, if either sets one?
2. Are the unread regional sections (`tier1_keywords`, `fria.*`, `feat.*`, `governance_controls.*`) meant to be loaded?
3. Does any caller outside the repository use the standalone `nemo-guardrails` deployment? None inside it does.
