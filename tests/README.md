# CAGE Test Suite

This document describes how to configure and run the **Cybernetic Agent Governance Engine** test suite.

---

## Quick Start

```bash
# 1. Copy and populate environment variables
cp .env.example .env
#    — fill in LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, etc.

# 2. (Integration tests only) Start port-forwards to the K8s cluster
./setup_test_env.sh

# 3. Run all unit/local tests (no services required)
uv run pytest tests/

# 4. Run integration tests (live services required)
uv run pytest tests/ --run-integration
```

---

## Running Tests

### Unit tests only (default)

```bash
uv run pytest tests/
```

No external services are required. Integration-marked tests are automatically
skipped unless you pass `--run-integration`.

### Integration tests

```bash
# Requires live services — start port-forwards first:
./setup_test_env.sh

uv run pytest tests/ --run-integration
```

### Filter by marker

```bash
# Only run fast unit tests
uv run pytest tests/ -m unit

# Only run integration tests (also requires --run-integration)
uv run pytest tests/ --run-integration -m integration

# Skip slow tests
uv run pytest tests/ -m "not slow"

# Red-team / adversarial tests
uv run pytest tests/ --run-integration -m red_team
```

### Verbose output with captured stdout

```bash
uv run pytest tests/ -v -s
```

---

## Pytest Markers

| Marker        | Description                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------- |
| `unit`        | Pure logic tests — no I/O, no network, no external services. Alias for `local`.                                 |
| `local`       | Same as `unit`. Legacy name kept for backwards compatibility.                                                   |
| `integration` | Requires live external services (backend, vLLM, Langfuse). Skipped by default — pass `--run-integration`. |
| `regression`  | "Golden Questions" that verify model behaviour after updates.                                                   |
| `slow`        | Tests that take >30 s. May be excluded with `-m "not slow"`.                                                    |
| `red_team`    | Adversarial / prompt-injection tests for the governance layer.                                                  |
| `load`        | Load and stress tests — run in CI with dedicated infrastructure.                                                |
| `causal`      | Tests requiring `dowhy` — causal inference gatekeeper validation.                                               |

---

## Environment Variables

All variables are read from the shell environment or a `.env` file at the project root.
Copy [`.env.example`](../.env.example) to `.env` and fill in your values.

`conftest.py` loads `.env` automatically at the start of every test run using
`python-dotenv` with `override=False`, meaning **shell / CI env vars always win**.

### Service URLs

| Variable                      | Default                           | Description                           |
| ----------------------------- | --------------------------------- | ------------------------------------- |
| `BACKEND_URL`                 | `http://localhost:8081`           | Governed Financial Advisor backend    |
| `LANGFUSE_HOST`               | `http://localhost:3001`           | Self-hosted Langfuse instance         |
| `COMPLIANCE_BRIDGE_URL`       | `http://localhost:3002`           | Compliance Bridge API (port-forward)  |
| `VLLM_REASONING_API_BASE`     | `http://localhost:8000/v1`        | vLLM OpenAI-compat inference endpoint |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:3001/api/public/otel/v1/traces` | Langfuse integrated OTLP ingestion endpoint (standalone collector deprecated 2026-05-31) |

### Langfuse Credentials

| Variable                         | Required              | Description                         |
| -------------------------------- | --------------------- | ----------------------------------- |
| `LANGFUSE_PUBLIC_KEY`            | For Langfuse tests    | Public API key                      |
| `LANGFUSE_SECRET_KEY`            | For Langfuse tests    | Secret API key                      |
| `LANGFUSE_COMPLIANCE_PUBLIC_KEY` | For compliance bridge | Dedicated compliance project key    |
| `LANGFUSE_COMPLIANCE_SECRET_KEY` | For compliance bridge | Dedicated compliance project secret |

### Model Configuration

| Variable          | Default                                    | Description                                |
| ----------------- | ------------------------------------------ | ------------------------------------------ |
| `MODEL_REASONING` | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` | LLM-as-Judge / reasoning model             |
| `MODEL_FAST`      | `Qwen/Qwen2.5-1.5B-Instruct`               | Fast tasks (FSM, classification)           |
| `OPENAI_API_KEY`  | `not-needed-for-local-vllm`                | Set to any non-empty string for local vLLM |

### Governance & Infra

| Variable          | Default                                       | Description                                        |
| ----------------- | --------------------------------------------- | -------------------------------------------------- |
| `OPA_URL`         | `http://localhost:8181/v1/data/trade/governance` | OPA policy engine endpoint                         |
| `REDIS_URL`       | `redis://localhost:6379`                      | Redis for state management                         |
| `GOVERNANCE_SALT` | _(required)_                                  | HMAC salt for the governance gateway               |
| `K8S_NAMESPACE`   | `governance-stack`                            | Kubernetes namespace (used by `setup_test_env.sh`) |
| `CAGE_DEPLOYMENT_REGION` | `US_FED`                             | Regional compliance profile (`US_FED` \| `EU_ECB` \| `APAC_MAS`). Required by the CAGE boot contract. |

---

## Port-Forward Requirements (Integration Tests)

Integration tests communicate with services running in Kubernetes.
Start all required port-forwards with:

```bash
./setup_test_env.sh
```

The script maps the following ports:

| Local Port | K8s Service                      | Purpose                             |
| ---------- | -------------------------------- | ----------------------------------- |
| `8081`     | `svc/governed-financial-advisor` | Backend API                         |
| `8000`     | `svc/vllm-reasoning`             | vLLM reasoning (LLM judge)          |
| `8001`     | `svc/vllm-service`               | vLLM fast inference (Qwen)          |
| `3001`     | `svc/langfuse-web`               | Langfuse UI & scoring API           |
| `3002`     | `svc/compliance-bridge`          | Compliance Bridge API               |
| ~~`4318`~~ | ~~`svc/otel-collector`~~         | **Deprecated** (best-effort, forwarded by `setup_test_env.sh` if available) |
| `8181`     | `svc/opa`                        | OPA policy engine                   |
| `8080`     | `svc/gateway`                    | Inference Gateway                   |
| `6379`     | `svc/redis`                      | Redis cache                         |
| ~~`5001`~~ | ~~`svc/governed-financial-advisor-slm`~~ | **SLM service is permanently deprecated (`slm_available=False`). Port 5001 is no longer forwarded.** |


The script accepts `--namespace <ns>` and `--dry-run` flags:

```bash
# Override the K8s namespace
./setup_test_env.sh --namespace my-namespace

# Preview what the script would do without executing
./setup_test_env.sh --dry-run
```

Port-forward logs are written to `/tmp/pf-*.log`.

---

## Fixtures Reference (`tests/conftest.py`)

| Fixture                 | Scope   | Description                                                                                                                     |
| ----------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `backend_url`           | session | Returns `os.environ["BACKEND_URL"]`.                                                                                            |
| `langfuse_client`       | session | Constructs and returns a `Langfuse` SDK client. Skips the test if credentials are missing.                                      |
| `requires_port_forward` | session | Checks connectivity to `BACKEND_URL` and `LANGFUSE_HOST`. Skips the test with a clear message if either service is unreachable. |

---

## Test Files

| File                                  | Markers                    | Description                                                        |
| ------------------------------------- | -------------------------- | ------------------------------------------------------------------ |
| `test_cage_graph.py`                  | `unit`                     | Canonical CAGE graph compilation and 8-node structure verification |
| `test_guardrail_node.py`              | `unit`                     | NeMo input gate — fail-closed behavior, Presidio PII scan          |
| `test_output_rail_node.py`            | `unit`                     | NeMo output rail — PII egress filter, mandatory final node         |
| `test_safety_node.py`                 | `unit`                     | `safety_check_node` — OPA gate, BLOCKED/ESCALATED routing          |
| `test_governance_client.py`           | `unit`                     | `GovernanceClient` structured generation, schema constraints       |
| `test_opa_client.py`                  | `unit`                     | OPA circuit breaker — open/close behavior, DENY-on-failure         |
| `test_symbolic_governor.py`           | `unit`                     | `SymbolicGovernor` OPA + CBF + STPA integration; validates `[CTRL_*]` structured violation payloads |
| `test_consensus_engine.py`            | `unit`                     | Multi-agent consensus engine, unanimity requirement                |
| `test_nemo_actions.py`                | `unit`                     | NeMo Guardrails action handlers                                    |
| `test_pii_integration.py`             | `unit`                     | Presidio PII detection regression guard (PII-004)                  |
| `test_ontology.py`                    | `unit`                     | STPA UCA ontology validation                                       |
| `test_compliance_bridge.py`           | `unit`                     | OSCAL YAML parsing, Pydantic models, FastAPI endpoints             |
| `test_trade_governance_rego.py`       | `unit`                     | `finance_policy.rego` RBAC rule evaluation                         |
| `test_config_manager.py`              | `unit`                     | `ConfigManager` env var resolution                                 |
| `test_redis_config.py`                | `unit`                     | `AsyncRedisClient` configuration and failover behavior             |
| `test_pipeline_compilation.py`        | `unit`                     | KFP v2 Green-Stack pipeline compilation                            |
| `test_profile_check.py`               | `unit`                     | Risk profile check node logic                                      |
| `test_governance_contracts.py`        | `unit`                     | Cross-subsystem governance API contracts                           |
| `test_refactor_integrity.py`          | `unit`                     | Import-level regression checks across refactored modules           |
| `test_transpiler_llm.py`              | `unit`                     | Policy transpiler — UCA → Rego and NeMo action codegen             |
| `test_iso_control.py`                 | `unit`                     | ISO 42001 OTel span tagging and control ID propagation             |
| `test_demo.py`                        | `unit`                     | Demo pipeline manager                                              |
| `test_optimistic_graph.py`            | `unit`                     | Legacy `src/graph` shim compilation — 4 nodes, no `safety_check`   |
| `test_optimistic_execution.py`        | `unit`                     | Optimistic concurrency: Redis hazard flag interrupt                |
| `test_evaluator_mcp.py`               | `integration`              | Evaluator → gateway MCP round-trip                                 |
| `test_trades_mcp.py`                  | `integration`              | `execute_trade_action` MCP tool full governance pipeline           |
| `test_gateway_connectivity.py`        | `integration`              | Gateway endpoint availability and health checks                    |
| `test_agent_accuracy.py`              | `integration`              | End-to-end agent response accuracy                                 |
| `test_agent_performance.py`           | `integration` / `slow`     | Latency and throughput benchmarks                                  |
| `test_gateway_client_perf.py`         | `integration` / `slow`     | `GatewayClient` performance under concurrent load                  |
| `test_deployment_verification.py`     | `integration`              | Post-deployment pod health and service availability                |
| `test_langfuse_evaluation.py`         | `integration`              | LLM-as-Judge evaluation via Langfuse scoring API                   |
| `test_langfuse_smoke.py`              | `unit`                     | Langfuse SDK connectivity and basic configuration checks           |
| `test_causal_gatekeeper.py`           | `unit`                     | DoWhy causal safety check + SymbolicGovernor integration; dual OTel span (`CTRL_MRM_004` Phase 1, `CTRL_TEL_003` Phase 2) |
| `test_governance_architecture.py`     | `unit`                     | 5-test permanent CI guardrail: no hardcoded regulatory strings, control_mappings.json schema, enum/registry parity, SIEM legacy citation, and orphaned-control detection |
| `test_framework_router.py`            | `unit`                     | 41-test FrameworkRouter matrix: JSON schema integrity (4 frameworks), cache identity, cache isolation, UCA-1–9 coverage, description completeness, narrative rendering, build_summary(), deduplication, unknown-framework error, and sentinel-driven SR 26-2 suppression across US_FED / EU_ECB / APAC_MAS |
| `test_compliance_bridge_smoke.py`     | `integration`              | Compliance Bridge health, SSE, and metrics API smoke tests         |
| `test_harness_nemo_factory.py`        | `unit`                     | LangGraph NeMo harness factory node generation                     |
| `test_harness_opa_factory.py`         | `unit`                     | LangGraph OPA harness factory node generation                      |
| `test_red_teaming.py`                 | `unit`                     | Prompt injection regression tests                                  |
| `red_team/adversarial_red_team.py`    | `red_team` / `integration` | Adversarial jailbreak and prompt injection against full gateway    |
| `governance/test_automated_loop.py`   | `integration`              | End-to-end cybernetic governance feedback loop                     |
| `governance/test_nemo_refinements.py` | `integration`              | NeMo Guardrails refinement trigger via compliance bridge           |
| `test_context_accumulator.py`         | `unit`                     | 15 tests: SHA-256 hash chain construction, tamper detection (node mutation → `verify_integrity()` returns `(False, 0)`), CHAIN_SEALED sentinel, NDJSON export, `chain_root()` genesis seed |
| `test_defer_queue.py`                 | `unit`                     | Hermetic `fakeredis` DeferQueue tests: park/resolve/get/list/expire, `DEFER_CONFIDENCE_THRESHOLD == 0.70`, `db=1` isolation, 4-hour TTL default |
| `test_aarm_mapper.py`                 | `unit`                     | 11-vector ledger completeness, NEUTRALIZED/PARTIAL/EXPOSED scoring, SECURE/DEGRADED/CRITICAL posture classification |
| `test_compliance_bridge_integration.py` | `integration`            | **104-test live GKE suite** (Groups 1–17): audit ingest, controls API, OSCAL export, SSE stream, Langfuse eval dataset, AARM conformance report, Context Accumulator chain integrity, DEFER queue endpoints |
| `load/locustfile.py`                  | `load`                     | Locust load test — sustained concurrent inference traffic          |

---

## CI / CD Notes

- In CI, set all required env vars as repository secrets.
- Integration tests are opt-in via `--run-integration`; they are **not** run in the default
  `pytest tests/` invocation, making the default CI check fast and service-independent.
- To run integration tests in CI, provision a kubeconfig with access to the governance cluster
  and add `./setup_test_env.sh && uv run pytest tests/ --run-integration` as a separate job step.
