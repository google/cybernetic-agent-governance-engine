# AGENTS.md — Contributor & AI-Agent Standards

> **Reference Architecture — Clean Architecture Over Operational Continuity.** CAGE demonstrates AI governance patterns; it is not a deployed production service. Optimize for clean code structure, modularity, and architectural clarity over operational safety, uptime, or backward compatibility. Breaking changes are desirable when they remove legacy designs.

This file defines standards for human and AI contributors. Full contributor details live in [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Commit Message Standard

Follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/): `<type>(<scope>): <short summary>` (subject ≤ 72 chars, imperative mood, no trailing period).
- **Types (only):** `feat` | `fix` | `docs` | `style` | `refactor` | `perf` | `test` | `chore` | `ci` | `revert`
- **Scopes (at most one):** `gateway` | `compliance` | `infra` | `governance` | `tests` | `docs` | `ci` | `agentsight` | `advisor` | `nemo` | `opa` | `ftra` | `finance` | `healthcare` | `security` | `imports`
- **Breaking changes:** `!` after type/scope + `BREAKING CHANGE:` footer + entry under `# Unreleased (v<next_major>.x)` in [`docs/BREAKING_CHANGES.md`](docs/BREAKING_CHANGES.md). PR titles must match.

---

## Branch Naming & Merge Strategy

Patterns (lowercase kebab-case, ≤ 30 chars after prefix): `feat/<desc>`, `fix/<desc>`, `docs/<desc>`, `refactor/<desc>`, `ci/<desc>`, `chore/<desc>`, `test/<desc>`, `hotfix/<ver>-<desc>`, `rc-v<semver>`, `spike/<desc>`. Delete branches after merge. Never work directly on `main` or `rc-v*`.

**Merge strategy: squash merge only into `main` (`squash-merge-guard` fails on two-parent merges).** When asked to commit or push directly to `main` or `rc-v*`, **refuse**:
```text
Direct commits to `main` are not allowed. I'll create a feature branch instead:
git checkout -b <type>/<description>
After committing your changes, I'll push this branch and open a pull request.
```
Hooks setup: `bash scripts/setup_git_hooks.sh`. See [`docs/operations/GIT_WORKFLOW_STANDARDS.md`](docs/operations/GIT_WORKFLOW_STANDARDS.md).

---

## Code Standards

### License Headers & New `src/` Files
Prepend the Apache 2.0 header (`# Copyright 2026 Google LLC` / `https://www.apache.org/licenses/LICENSE-2.0`, `#` for `.py`, `//` for `.ts`/`.tsx`/`.js`; enforced by `license-check`) and verify no secrets or PII are embedded.

### Secret Hygiene
Never use `os.environ.get("KEY", "hardcoded-fallback")` for sensitive values, hardcode credentials/URIs, or dump `os.environ`. K8s manifests must use `secretKeyRef`/`secretRef`. Prohibited patterns: `pk-lf-*`/`sk-lf-*`, `hf_*`, `GOOG*`, `redis://*:*@*`. Mask credentials before logging (`value[:4] + "****"`).

### Terraform Invariants
- Secrets belong in gitignored `terraform.auto.tfvars`, never in committed `.tf` files. Run `terraform plan` before `apply`; never edit state directly.
- Place plan-time guards in a resource `lifecycle` `precondition` or a guard `depends_on` (not standalone `terraform_data`, which targeted plans skip, or variable validation, which breaks `destroy`). See `terraform_data.control_plane_access_guard` in [`infra/targets/gcp-gke/main.tf`](infra/targets/gcp-gke/main.tf); [`test_guard_placement.py`](tests/infrastructure/test_guard_placement.py) fails on new standalone guards (`POAM-2026-180`).

### Mandatory Pre-Commit Code & Security Review
Every uncommitted diff (`git diff HEAD`) must pass both reviews before committing or declaring done:
- **Code Review:** Verify 3-layer isolation ([`scripts/check_import_boundaries.py`](scripts/check_import_boundaries.py)), doc/symbol sync ([`scripts/check_doc_references.py`](scripts/check_doc_references.py)), ADR-008 invariants, Apache 2.0 headers, and pytest markers.
- **Security Review:** Audit against [`.agents/rules/security.md`](.agents/rules/security.md) (no fallback secrets, no `shell=True`, no insecure deserialization, out-of-band `kid` resolution, B310 URL scheme validation) + `uv run --with bandit bandit -r src/ scripts/ -c pyproject.toml -ll -ii`. Never rely on `SECURECODER_API_PORT`.
- **Fail-Closed:** Resolve all `HIGH`/`MEDIUM` findings before `git commit`.

---

## Deployment Rules

See [`docs/operations/DEPLOYMENT_RULES.md`](docs/operations/DEPLOYMENT_RULES.md). Summary:
- **GKE targets — Cloud Build only (`staging` is the maintained profile).** Never use local `docker build` for GKE images (ARM64/x86 mismatch):
  ```bash
  ./deploy_all.sh --target gcp-gke --env staging --var project_id=<PROJECT_ID>
  gcloud builds submit --config deployment/docker/cloudbuild.image.yaml \
    --substitutions="_IMAGE_NAME=gateway,_DOCKERFILE=src/gateway/Dockerfile,_SHORT_SHA=$(git rev-parse --short HEAD)" .
  ```
- **DNS:** Manage custom subdomains in Cloud DNS with upstream NS delegation on persistent foundational zones, not ephemeral workload stacks.
- Active IaC lives exclusively under [`infra/targets/gcp-gke/`](infra/targets/gcp-gke/main.tf) and [`infra/modules/`](infra/modules/).

---

## Debugging Standards

### Diagnosing CI Failures (Check in Order)
1. **squash-merge-guard** — Use GitHub "Squash and merge".
2. **license-check** — Prepend Apache 2.0 header in `src/`.
3. **marker-contract-check** — Add `pytestmark = [pytest.mark.unit, pytest.mark.local]`.
4. **Import boundary check (G3)** — Run `uv run python scripts/check_import_boundaries.py --verbose`; sever upward imports.
5. **nemo-freshness-check** — Run `make update-nemo-configmap`.
6. **stpa-freshness-check** — Run `uv run python scripts/check_stpa_freshness.py`.
7. **pytest-logic** — Fix failing test; confirm no `kubectl port-forward` leaks into local tests.
8. **Bandit / security-scan** — Fix SAST/CVE finding; never suppress. Always pass `-c pyproject.toml` to `bandit` and validate `http://`/`https://` before `urllib.request.urlopen` (B310).
9. **Doc reference check (G9)** — Run `make docs-check` (`uv run python scripts/check_doc_references.py --path <scope>`); fix dangling paths/symbols without shrinking `DOC_SCOPE`. Removed-at-HEAD paths must be pinned as `<sha>^:<path>`; retracted records move under `compliance/archive/retracted/` with `> **RETRACTED <date>**`. Never disable or skip a CI check.

---

## Compliance Artifact Obligations

- **NIST SP 800-53 & OSCAL:** Update `compliance/oscal/` within 2 business days of merge, refresh `description_sha256` in [`compliance/oscal/evidence_claim_census.jsonl`](compliance/oscal/evidence_claim_census.jsonl), and regenerate [`docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md`](docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md) via `uv run python scripts/check_oscal_claim_census.py --render docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md`.
- **Kubernetes / Lula:** Update `compliance/lula/` when adding/removing referenced K8s resources.
- **POAM & OSCAL Guardrails:** Never backdate [`docs/POAM.md`](docs/POAM.md) closure dates. Before closing POAM items, pass OSCAL SSP export (`uv run python -m src.gateway.governance.oscal_ssp_exporter export --check` across `US_FED`, `EU_ECB`, `APAC_MAS` — omit `--ssp` for default discovery), [`tests/test_oscal_ssp_exporter.py`](tests/test_oscal_ssp_exporter.py), [`scripts/check_poam_lula_divergence.py`](scripts/check_poam_lula_divergence.py), and [`scripts/check_doc_references.py`](scripts/check_doc_references.py).
- **STPA:** Run `uv run python scripts/check_stpa_freshness.py` before committing STPA source changes.

---

## Architecture & Design Standards

### Core Principle: Clean Architecture Over Operational Continuity
Optimize for structural clarity and modularity; breaking changes are acceptable to remove legacy baggage.

### The Three-Layer Architecture (Kernel vs. Domain Plugins vs. Rails)

| Layer | Path | Role | Invariants (Enforced by Gate G3) |
|---|---|---|---|
| **Layer 1: Kernel** | `src/gateway/` | **STERA Admissibility Engine**, dispatch loop, standing assembly, consensus, CBF, evidence accumulator, routing, audit rails. | Strictly domain-agnostic & vendor-neutral. Never import `src/cage_*`, `src/compliance_bridge/`, `src/governed_financial_advisor/`, `src/eval_harness/`, or `FORBIDDEN_VENDOR_SDKS` (`google.cloud`, `boto3`, `azure`, `langfuse`, `nemoguardrails`, Presidio, `openai`, `litellm`, `anthropic`, `transformers`, kept out of base install & gateway image by `scripts/check_model_free_install.py`). Function-scoped lazy imports allowed only from `INTEGRATIONS_FACTORY_ALLOWLIST` / `COMPLIANCE_BRIDGE_FACTORY_ALLOWLIST` in `scripts/check_import_boundaries.py`. No `FORBIDDEN_DOMAIN_LITERALS` or `FORBIDDEN_KERNEL_DEFINITIONS`. |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` | Domain tiers (`ReadOnlyTier` / `MutatingTier`, ADR-009), action registries, ontologies, policies, causal graphs. | One domain per process (`CAGE_DOMAIN`). Returns frozen `PluginContribution` from `CagePlugin.contribute()` to `assemble_governor()`. |
| **Layer 3: Integrations & Rails** | `src/integrations/`, `src/cage_finance/rails/`, `src/compliance_bridge/` | External vendor adapters, GCP eval/GEPA (`src/integrations/gcp_eval/`), Presidio PII (`src/integrations/presidio/`), cold stores, NeMo, Langfuse. | Implements canonical dataclasses and Secure Plugin & Adapter Architecture Spec. |
| **Offline Eval Plane** | `src/eval_harness/` | Offline eval, GEPA optimizer, `SKILL.md` linter, ATIF/rollouts, `cage-skill-eval`, RLVR/DPO export. | Strictly separated from Online Enforcement (`src/gateway/`); never in `src/gateway/Dockerfile`. |

**Decision test:** *"If two domains had different copies of this, would a security fix have to be applied twice?"* If yes → Layer 1 (Kernel).

### Canonical Module Namespaces (v3.2.0 Architecture)
- Causal Gatekeeper & World-Model Refresher: `src.gateway.governance.causal.gatekeeper`, `src.gateway.governance.causal.world_model_refresher`
- Reconciliation & FTRA: `src.gateway.governance.reconciliation.daemon`, `src.gateway.governance.ftra`
- Warrant & Evidence: `src.gateway.governance.warrant`, `src.gateway.governance.governor.stages.warrant`, `src.gateway.governance.evidence.stream`, `src.gateway.governance.evidence.state_commitment`, `src.gateway.governance.evidence.cold_store`
- Rate Limiter: `src.gateway.server.rate_limit`

### Observability: Langfuse, Prometheus, and LangSmith
- **Langfuse:** Self-hosted per region (`europe-west1`, `asia-southeast1`, `us-central1`) for sovereign compliance trace telemetry.
- **Prometheus:** GKE Managed Prometheus (`monitoring_config.managed_prometheus` in [`infra/modules/gcp_gke_cluster/main.tf`](infra/modules/gcp_gke_cluster/main.tf), scraped via `PodMonitoring/gateway-metrics` in [`monitors.yaml`](infra/modules/gateway/metrics-monitors/templates/monitors.yaml), validated by [`lula-validation-metrics.yaml`](compliance/lula/lula-validation-metrics.yaml)). Optional `prometheus_client` in Python degrades to no-op when absent.
- **LangSmith:** **Strictly forbidden in CAGE application code.** Disable via `LANGSMITH_TRACING=false` and `LANGCHAIN_TRACING_V2=false`.

### External Vendor Adapter Standards (Plugin Architecture)
- **Isolation & Seam:** Vendor code lives in `src/integrations/{provider_name}/` (never imported by `src/gateway/`). Synchronous gate adapters implement `NormativeProvider` (`fetch_baseline`, `validate_fria`, `submit_evidence`).
- **Trust Anchors:** Never verify a signature against an embedded public key. Resolve keys by `kid` from an independently fetched out-of-band key manifest; fail closed on unknown `kid`.
- **Verification & Evidence:** Resolution (`UNVERIFIED`) is not cryptographic verification. `DENY`, `DEFER`, and `REQUIRE_APPROVAL` receipts must enter the tamper-evident chain with the same completeness as `ALLOW`.
- **Generic in Code, Specific in Prose (Gate G8):** All code/test paths, identifiers, CLI choices, env vars, and non-wire literals in `src/gateway/`, `packages/cage-conformance/src/`, `src/integrations/`, `scripts/`, and `tests/` use anonymized namespaces (`provider_01`..`provider_08`, `actuator_01`); brand names belong only in docstrings, comments, and `docs/partners/`. External wire-protocol constants must be registered in `LAYER3_WIRE_PROTOCOL_PROVENANCE` in [`scripts/check_vendor_brands.py`](scripts/check_vendor_brands.py) with a matching committed `.md`/`.json` artifact and an active Python reference.
- **Completeness Principle & Tiering:** CAGE is *safety- and security-complete*, not *commercially complete*. Tier 2 data backends may be simulated; security primitives (KMS signing, out-of-band `kid` verification, Linkerd mTLS, single-use Redis seals, WORM custody) are always real in enforcing postures. **Symmetric or software fallbacks (HMAC, local keys) are allowed only in dev/hermetic tests and never count as evidence for POAM closure or OSCAL implementation statements.** Tier 1 partner adapters must pass **over-the-wire** tests against live staging/sandbox endpoints (no mocks/stubs/`ASGITransport`/`TestClient`). Full Tier 1–3 rules: [`VENDOR_NEUTRALITY_CONTRACT.md`](docs/architecture/VENDOR_NEUTRALITY_CONTRACT.md#5-completeness-principle--interface-tiering).

### Governance Gate Invariants (ADR-008 Enforcement)
- **Fail-Closed Execution Boundary:** All Layer 2 tool executions must route through [`verify_and_consume_seal()`](src/gateway/governance/routing_seal.py) (verify seal, atomically consume nonce) and [`ActuatorRegistry`](src/gateway/governance/execution_actuator.py) dispatch (Layer 1). [`ConsequenceGateway`](src/gateway/governance/consequence_gateway.py) is the single-use boundary for normative-provider `ConsequenceToken`s and is **not** on the governor `ALLOW` path.
- **Private Queue Resolution:** Deferral resolution remains private (`_resolve()` in [`DeferQueue`](src/gateway/governance/defer_queue.py)); no public bypasses.
- **Envelope Integrity:** Production requests traversing middleware must be wrapped via [`GovernanceEnvelopeBuilder`](src/gateway/governance/governance_envelope.py).
- **Composition Root Only:** Build `SymbolicGovernor` solely via `assemble_governor()` ([`assembly.py`](src/gateway/governance/governor/assembly.py)) or `bootstrap_governor()` ([`bootstrap.py`](src/gateway/governance/governor/bootstrap.py)). Governors are immutable, passed explicitly, and read via `governor_of()` ([`app_state.py`](src/gateway/server/app_state.py)); no module-level singletons.
- **Advisor Holds No Governance State:** `src/governed_financial_advisor/` hosts no `SymbolicGovernor`, `DeferQueue`, signing key, or GCP identity, and never imports `src.integrations.nemo` directly (in-process rails run via kernel `langgraph_harness`). Gateway authenticates callers via Linkerd mTLS workload identity (`l5d-client-id` in [`workload_identity.py`](src/gateway/server/workload_identity.py)), never HMAC routing seals.

---

## Documentation Standards

Sync docs with code in the same PR, citing exact paths/keys/lines. Never embed version suffixes (`_v3`, `-v4`) in living filenames; organize versioned history in [`docs/BREAKING_CHANGES.md`](docs/BREAKING_CHANGES.md) (Gate G9, [`scripts/check_doc_references.py`](scripts/check_doc_references.py)).

## Answering Questions About This Repository

Ground answers in code at `HEAD`, cite clickable `file://` paths, remember CAGE is a reference architecture, and never guess on safety invariants (check `proof/model.py` and fail closed). Tool-specific pointers (e.g., `CLAUDE.md`) should link back here.

---

## Test Execution

Always prefix test commands with `uv run`, and parallelize local runs with `--dist loadscope`:
- **Fast unit suite:** `make test-fast` (`uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short`)
- **Single test / marker check / coverage:** `uv run pytest tests/<path>::<test_name> -v` | `uv run pytest tests/ --collect-only -q --no-cov -n0` | `make test-coverage`
- **Two-Phase Lifecycle:** Inner loop targets only the edited unit test; gate phase runs `make test-fast` + pre-commit code/security review + Bandit once before committing or opening a PR.

### Verification Rules (fail-closed)
- **Full-gate before green:** Not green until `make test-fast` and pre-commit code/security review (`uv run --with bandit bandit -r src/ scripts/ -c pyproject.toml -ll -ii`) pass with zero unresolved `HIGH`/`MEDIUM` findings.
- **Re-derive identifiers after compaction:** Re-query SHAs, branches, PRs, run IDs, and check-run IDs from tools (`git rev-parse`, `gh pr list`, `gh run list --json databaseId`); never recall from memory.
- **Attribute failures to merge base & grep renames:** Verify claimed pre-existing failures against the merge base; run `rg -n '<old_symbol>' src/` after cross-module renames (expect zero hits).
- **Test every fail-closed path & partner over-the-wire:** No `pass # TODO` placeholders. Tier 1 `partner_integration` / `live_external` tests must run live over HTTPS/mTLS with authentic remote headers/trace IDs (`ASGITransport`/`TestClient`/mocks forbidden).

### Pytest Marker & Region Contracts (fail-closed)
- **Markers:** Every test needs a selection marker (`local`, `unit`, `integration`, `live_external`, `partner_integration`, `chaos`, `load`); default: `pytestmark = [pytest.mark.unit, pytest.mark.local]`.
- **Region ([`tests/fixtures/deployment_region.py`](tests/fixtures/deployment_region.py)):** Hermetic runs pin `US_FED` (ignoring shell `CAGE_DEPLOYMENT_REGION`); use `us_fed`/`eu_ecb`/`apac_mas` markers or `each_region` (never `skipif`). Live runs (`--run-integration` / `--run-e2e`) read `cage-deployment` ConfigMap and fail closed on mismatch.

### Live GKE Cluster & Staging Runbooks
See [`docs/operations/GKE_TEST_RUNBOOK.md`](docs/operations/GKE_TEST_RUNBOOK.md). Never use `-n auto` on port-forward tunnels (use `-n 2 --dist loadscope` or `-n0`), launch tunnels detached (`scripts/port_forward_staging.sh --daemon`), verify via `scripts/test_live_gke_services.py`, never commit cluster secrets, and allow `@pytest.mark.timeout(600)` for `tests/test_agent_accuracy.py`.

---

## Agent Governance & Cost Guardrails

Keep active sessions `< 200k` tokens, fail fast after 2 related stack traces (root-cause before patching), clear stale context after tests pass, maintain byte-for-byte prefix stability for prompt caching (no dynamic timestamps/paths in headers), and write complete error-handling code (no `# TODO` shims). Full setup: [`docs/operations/AGENT_COST_GUARDRAILS.md`](docs/operations/AGENT_COST_GUARDRAILS.md).
