# Contributing to CAGE (Cybernetic Agent Governance Engine)

Thank you for contributing to CAGE. This document describes the development workflow, coding standards, and required practices for contributors.

---

## Deployment Policy

**🚨 CRITICAL:** Before making any infrastructure changes or deployments, review:
- [Deployment Rules](docs/DEPLOYMENT_RULES.md) - Mandatory deployment policies
- [Agent Ops Architecture](docs/AGENT_OPS_ARCHITECTURE.md) - Defense-in-depth governance pattern

**Key Rule:** When deploying to GKE, ALWAYS use Cloud Build via `./deploy_all.sh --target gcp-gke`. Never use local Docker builds for GKE deployments.

---

## Development Setup

**1. Install dependencies:**

```bash
uv sync --all-groups --all-extras
```

> **Build system:** CAGE uses `uv` as its build frontend. The `pyproject.toml` requires `uv_build>=0.8.14`. Ensure your local `uv` installation is up to date (`uv self update`) before running `uv sync`.

**2. Configure environment:**

```bash
cp .env.example .env
# Populate required env vars — see README.md for the full list
```

**3. Run the test suite:**

```bash
bash setup_test_env.sh && python -m pytest tests/
```

All 644 tests must pass before opening a PR. The test suite covers guardrail nodes, OPA policy evaluation, governance client, NeMo actions, STPA compiler code generation, causal gatekeeper, evidence chain integrity, and the LangGraph pipeline.

> **Observability note:** The standalone OpenTelemetry Collector sidecar was **deprecated 2026-05-31**. All OTel spans are now exported directly to Langfuse via OTLP. Do not add new configuration that references a standalone `otel-collector` endpoint; use `LANGFUSE_OTLP_ENDPOINT` instead.


---

## Coding Standards

### Security-Critical Paths: Fail-Closed

Any code on a security-critical enforcement path must fail closed. This means:

- On any exception, the default return is **DENY / BLOCKED** — never ALLOW
- No raw LLM output is returned if a guardrail raises an exception
- OPA circuit breaker defaults to `"DENY"` when open

```python
# Correct pattern for fail-closed enforcement
try:
    decision = await opa_client.evaluate_policy(opa_input)
except Exception as e:
    logger.critical("OPA call failed: %s — DENY (fail-closed)", e)
    decision = "DENY"
```

### Guardrail Nodes

NeMo input and output guardrail nodes are mandatory infrastructure-level nodes in the LangGraph pipeline. They are not optional or agent-callable. See:

- [`src/governed_financial_advisor/graph/nodes/guardrail_node.py`](src/governed_financial_advisor/graph/nodes/guardrail_node.py) — input gate
- [`src/governed_financial_advisor/graph/nodes/`](src/governed_financial_advisor/graph/nodes/) — all LangGraph nodes

Do not add agent-callable tools that replicate or bypass guardrail behavior. OPA evaluation must remain in the infrastructure enforcement path, not the MCP tool manifest.

### Secret Management

All secrets must be injected as environment variables:

- Local/dev: `.env` file via `python-dotenv`
- Docker Compose: `env_file` or `environment` section
- Kubernetes production: `Secret` objects mounted as env vars

**Do not use Google Secret Manager.** It was removed in v1.0.0. Use `os.getenv()` or `ConfigManager.get()` for all secret resolution.

### Provider-Agnostic Infrastructure

- Do not hardcode cloud-provider specifics (GCS bucket names, GCP project IDs) inside application code
- Use environment variables for all endpoints, credentials, and routing
- Use portable Kubernetes primitives — no GKE-proprietary annotations in application manifests

---

## STPA Compiler Contract

`config/stpa_control_structure.yaml` is the **single source of truth** for all Unsafe Control Actions. It is the only file contributors should edit when adding or modifying safety constraints. Never hand-edit the generated artifacts:

| Artifact | Path | Generator |
|---|---|---|
| OPA Rego policy | `config/opa/generated_stpa_policy.rego` | `stpa_compiler compile` |
| NeMo Colang rails | `config/rails/generated_stpa_rails.co` | `stpa_compiler compile` |
| Python validator | `src/gateway/governance/generated_stpa_validator.py` | `stpa_compiler compile` |

After editing `stpa_control_structure.yaml`, always re-compile:

```bash
uv run python -m src.gateway.governance.stpa_compiler compile
```

Commit all three generated artifacts in the same PR as the YAML change. CI will verify that the artifacts are in sync.

---

## Evidence Chain and Telemetry

The playground telemetry module (`examples/telemetry.py`) writes a SHA-256 hash-chained NDJSON evidence log. When adding new governance tiers or modifying existing ones:

- Update `PlaygroundTelemetry.scenario_span()` attribute set to include any new NIST/ISO control IDs.
- Do not bypass `_redact_params()` — PII fields must never appear in the evidence chain.
- Verify chain integrity with `tel.verify_chain()` in tests (see `tests/test_playground_telemetry.py`).

---

## Development Workflow

1. **Fork and branch** — branch from `main`; use a descriptive branch name
2. **Write tests** — all new behavior must be covered by tests in `tests/`
3. **Run the test suite** — `bash setup_test_env.sh && python -m pytest tests/`
4. **Recompile STPA artifacts** — if you edited `config/stpa_control_structure.yaml`, run `uv run python -m src.gateway.governance.stpa_compiler compile` and commit all three generated artifacts
5. **Check for stale artifacts** — remove any `# TODO`, `# FIXME`, debug prints, hardcoded paths, or unapproved credentials before opening a PR
6. **Update docs** — if your change affects architecture, update the relevant doc in `docs/` and `ARCHITECTURE.md`

### Pre-PR Checklist

- [ ] All 644 tests pass (or new tests added for new behavior)

- [ ] No `# TODO` / `# FIXME` / `# HACK` comments without a linked GitHub issue
- [ ] No hardcoded credentials, project IDs, or cloud-provider paths
- [ ] STPA YAML edited → compiler re-run → all three artifacts committed
- [ ] Architecture docs updated if behavior changed
- [ ] `THIRD_PARTY_NOTICES.md` regenerated if dependencies changed

---

## License Compliance

This project tracks all third-party dependency licenses in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Regenerate it whenever you add, remove, or update a dependency:

```bash
make notices
```

Or directly:

```bash
bash scripts/generate_notices.sh
```

Commit the updated `THIRD_PARTY_NOTICES.md` in the same PR as the dependency change. Do not edit `THIRD_PARTY_NOTICES.md` manually.

The script scans four environments:

1. **Root Python environment** — `pyproject.toml` / `uv.lock`
2. **`src/compliance_bridge`** — `src/compliance_bridge/requirements.txt`
3. **`src/governed_financial_advisor`** — `src/governed_financial_advisor/requirements.txt`
4. **`src/agentsight-ui`** — `src/agentsight-ui/package.json` via `generate-license-file`

---

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License Agreement. You (or your employer) retain the copyright to your contribution; this simply gives us permission to use and redistribute your contributions as part of the project. Head over to <https://cla.developers.google.com/> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for a different project), you probably don't need to do it again.

---

## Code of Conduct

Contributions must maintain the same standard of precision as the existing codebase. Commit history must be clean — no debug artifacts, stray credentials, or commented-out dead code.
