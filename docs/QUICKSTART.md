# Quick Start — v4.0.0

Get CAGE running locally in under 10 minutes using Docker Compose.

> **Domain-agnostic by default.** The governance kernel is domain-neutral. Domain behaviour comes from exactly one plugin per process (§8), and jurisdictional compliance is opt-in configuration (§9). The gateway stack in §2–3 still needs one plugin selected (`CAGE_DOMAIN`, `finance` by default), and the demo in §4 uses finance-example components as concrete instances of domain-neutral mechanisms.

## Prerequisites

- Docker and Docker Compose, only for the gateway stack (§2–3) and the `docker compose` commands in §8. §4, §6, §7 and §9 run without Docker.
- Python >=3.10, <3.13 with `uv` (`pip install uv`)
- **No LLM API key is needed for §1–9.** Only the optional finance advisor container (`--profile advisor`) reads `OPENAI_API_KEY` (an OpenAI-compatible key or local model endpoint).

## 1. Clone and configure

```bash
git clone https://github.com/google/cybernetic-agent-governance-engine.git
cd cybernetic-agent-governance-engine

# Copy environment template
cp .env.example .env
```

The template already sets the values the gateway needs. Check that `.env` contains:

```bash
# Exactly one domain per process (required). Both `finance` and `healthcare`
# ship a complete DomainConfig today; see §8 for why `physical_ai` refuses to start.
CAGE_DOMAIN=finance
CAGE_DEPLOYMENT_REGION=US_FED
# A development posture enables local software fallbacks (HMAC seal, optional Redis).
# The template sets `dev`; `development` is equivalent.
# Note: CAGE_ENV=local / production / staging are enforcing postures that require
# live Cloud KMS, Redis, and GroundTruthReconciler.
CAGE_ENV=dev
CAGE_TRUSTED_CLIENT_IDENTITIES=cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local
```

Set `OPENAI_API_KEY` only if you will start the optional advisor container (§2).

`CAGE_TRUSTED_CLIENT_IDENTITIES` is required in every environment and the
gateway always enforces workload identity. `WorkloadIdentityMiddleware` and
`load_identity_policy()` in
[`src/gateway/server/workload_identity.py`](../src/gateway/server/workload_identity.py)
refuse to start if `CAGE_TRUSTED_CLIENT_IDENTITIES` is unset, and refuse
(HTTP 403) every request that does not carry exactly one trusted Linkerd
`l5d-client-id` header. The only exemptions are the exact URL paths in
`OPEN_EXACT_PATHS` (no prefix match; a non-canonical form such as `//health`
is not exempt):

```text
/health
/healthz
/metrics
/governance/jwks
/governance/.well-known/jwks.json
```

## 2. Start the stack

```bash
docker compose up -d
```

This starts:
- **Gateway** (`localhost:8080`) — Gateway: 8080 (REST Ingress / Stateless FastMCP Streamable HTTP / In-Process Tier Pipeline)
- **OPA** (`localhost:8181`) — Policy engine with Rego authorization policies (mounts only `src/cage_${CAGE_DOMAIN}/opa`)
- *(Optional)* **Governed Financial Advisor (`app`)** (`localhost:3000`) — Finance reference application container (`docker compose --profile advisor up -d`)

## 3. Verify the gateway is running

`/health` is one of the open paths listed in §1, so it needs no `l5d-client-id` header. Every other route does.

```bash
curl http://localhost:8080/health
# Expected: {"status":"ok","mode":"mcp-tool-server","nemo":"active"}
# (a static liveness response; it does not probe NeMo or OPA)

# A gated route without an identity header is refused
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/mcp/
# Expected: 403

# Verify the Stateless FastMCP Streamable HTTP transport is ready.
# Locally you supply the header that the Linkerd proxy sets inside the mesh.
curl -s -X POST http://localhost:8080/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "l5d-client-id: cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## 4. Run the governance demo

```bash
uv sync --all-groups --all-extras
uv run python examples/governance_demo.py --no-pause
```

The demo runs in-process with no external services. It uses `fakeredis`, does not call the gateway from §2, and needs no Docker or API key. It prints the decision trace for three mechanisms:

| Act | Mechanism exercised | Concrete instance used |
|---|---|---|
| 1 | Atomic resource pre-reservation under concurrent agents | `FiscalLimitGuard` from the finance example (`src/cage_finance/safety/fiscal_limit_guard.py`) with a USD daily cap |
| 2 | HITL interrupt with mandatory rationale hashed into the evidence chain | Approval contract from the finance reference application (`src/governed_financial_advisor/graph/nodes/approval_contract.py`) |
| 3 | SHA-256 tamper-evident evidence chain verification | Records written by Acts 1–2; payloads are opaque to the verifier |

The mechanisms are domain-neutral, but the demo uses finance components to make them concrete. Another domain supplies its own guard and quantities, and the enforcement path stays the same.

> **The output ends with OpenTelemetry span JSON.** This is expected. [`tracing_setup.py`](../src/gateway/tracing_setup.py) registers a console span exporter alongside any OTLP exporter, so finished spans print after the PASS summary. The §8a playground does the same.

## 5. Observability dashboard (optional, not part of the Compose stack)

`docker compose up` does **not** start the AgentSight dashboard, and nothing in §2 listens on port 5173. The dashboard is a Vite dev server (`src/agentsight-ui`, `npm run dev`). It reads from the compliance bridge (`src/compliance_bridge/`, port 3001), which in turn reads Langfuse. To run it, follow [`src/agentsight-ui/README.md`](../src/agentsight-ui/README.md). None of the other steps in this guide need it.

## 6. Run the test suite

The suite needs every dependency group and extra. With a bare `uv sync`, `mcp` is missing and test collection fails.

```bash
uv sync --all-groups --all-extras
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
```

> **Run the hermetic suite without the §1 `.env`.** `tests/conftest.py` loads `.env` from the repository root. The template's runtime values (for example `EVIDENCE_CHAIN_BLOCKING=false` and placeholder provider API keys) then replace the hermetic defaults the tests expect, and dozens of tests fail. Move `.env` aside while the tests run (`mv .env .env.local-stack`) and restore it afterwards.

> **Local Development Postures:** For details on developing with the offline hermetic test loop vs. the full containerized LangGraph SDK runtime with host Ollama, see [`docs/guides/LOCAL_DEVELOPMENT_POSTURES.md`](guides/LOCAL_DEVELOPMENT_POSTURES.md).

## 7. Confirm the substrate is domain-independent

```bash
uv run pytest tests/test_tier_registry_contract.py -v
```

This asserts that each shipped example plugin contributes its tiers without a kernel modification, that domain plugins live under `src/cage_*`, and that the kernel contains no hard-coded domain verbs. If it passes, the kernel the gateway in §2–3 runs carries no domain vocabulary of its own. The domain-specific parts come only from the plugin named by `CAGE_DOMAIN`.

---

## 8. Add a domain (optional)

Domain behaviour is contributed by packages registered in the `cage.plugins` entry-point group. A CAGE process runs **exactly one** domain, named by the required `CAGE_DOMAIN` environment variable ([`env_posture.py`](../src/gateway/governance/env_posture.py)). An unset value, a comma-separated list, or a name matching no registered plugin aborts startup. The example domains are equal-standing illustrations of the same extension contract.

```bash
export CAGE_DOMAIN=finance        # runnable: ships full DomainConfig (trade.governance)
export CAGE_DOMAIN=healthcare     # runnable: ships full DomainConfig (dosing.governance)
export CAGE_DOMAIN=physical_ai    # refuses to start: no FTRA registry yet (POAM-2026-077)
```

Each plugin must declare a `DomainConfig`: its FTRA terminal registry, an optional causal graph, and the Rego package (plus required rules) the kernel queries on the OPA server. The kernel reads its FTRA registry and causal graph only from the active domain, so a plugin without one fails closed at startup rather than borrowing another domain's configuration. `OPA_URL` is a base URL only (e.g. `http://localhost:8181`); at startup the gateway lists OPA's loaded policies and refuses to start unless the domain's package and every required rule are present (finance: `trade.governance` with `allow`; healthcare: `dosing.governance` with `allow`).

### 8a. Domain Plugin Example: Finance

**Package:** [`src/cage_finance/`](../src/cage_finance/) · **Status:** example domain, not a turnkey trading system

```bash
# In-process scenario run (no Docker, no gateway, no API key)
uv run python examples/chaos_agent_playground.py --scenario A

# Or boot OPA + Gateway with ONLY the finance policy bundle mounted
CAGE_DOMAIN=finance docker compose up -d opa gateway
```

| Contribution | Concrete artifact |
|---|---|
| Governed actions | `execute_trade`, `get_market_data`, `get_portfolio` |
| Barrier | `CashBarrier` watching the `safety:current_cash` scalar |
| Tiers | CBF tier, fiscal pre-reservation tier, consensus tier, causal tier |
| Critics | Risk Manager, Compliance Officer |
| Policy | `src/cage_finance/opa/trade_governance.rego` |

### 8b. Domain Plugin Example: Healthcare

**Package:** [`src/cage_healthcare/`](../src/cage_healthcare/) · **Status:** example domain, not a clinical device

The healthcare plugin ships a complete `DomainConfig` (FTRA terminal registry, `dosing.governance` OPA package, and causal graph) and wires `DoseBarrierTier` with an invariant-parametric `ControlBarrierFunction` over `SerumConcentrationBarrier`. Note that the `app` service (`governed_financial_advisor`) in `docker-compose.yml` is finance-specific; to run the healthcare gateway stack or its hermetic test suite:

```bash
# Run the hermetic plugin + end-to-end governor suite
uv run pytest tests/test_healthcare_plugin.py -v

# Or boot OPA + Gateway with ONLY the healthcare policy bundle mounted
CAGE_DOMAIN=healthcare docker compose up -d --force-recreate opa gateway
```

| Contribution | Concrete artifact |
|---|---|
| Governed actions | `administer_dose` and the rest of `HEALTHCARE_GOVERNED_ACTIONS` |
| Barrier | `SerumConcentrationBarrier` watching a serum-concentration scalar |
| Tiers | Dose barrier tier, clinical consensus tier |
| Critics | Clinical reviewer personas from `src/cage_<domain>/config/critics.yaml` |
| Policy | `src/cage_healthcare/opa/dosing_governance.rego` |

The healthcare package exists specifically to falsify the "it's really a finance product" claim by construction. It names things; it implements no mechanism.

### 8c. Domain Plugin Example: Your Own

Manufacturing, logistics, energy dispatch, customer service, critical infrastructure — create `src/cage_<domain>/` mirroring either example, declare your governed actions and barrier parameters, register the entry point, and add independence tests. The extension contract is described in [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](architecture/EXTENSIBILITY_ARCHITECTURE.md). For a worked example, see [`src/cage_healthcare/`](../src/cage_healthcare/).

---

## 9. Select a jurisdictional posture (optional)

Regional compliance is configuration, independent of which domain plugin you loaded. Any plugin runs under any posture.

```bash
export CAGE_DEPLOYMENT_REGION=US_FED      # NIST AI 600-1, SP 800-53, AI RMF, FedRAMP, SR 26-2 (default)
export CAGE_DEPLOYMENT_REGION=EU_ECB      # GDPR, DORA, EU AI Act, MiFID II
export CAGE_DEPLOYMENT_REGION=APAC_MAS    # MAS Notice 655, FEAT principles, MAS TRM
```

Verify each posture's profile. The test harness runs every region-marked test under its own region, so no export is needed. See [`tests/README.md`](../tests/README.md#deployment-region). As in §6, move the §1 `.env` aside first; otherwise its runtime values make the `us_fed` and `eu_ecb` runs fail.

```bash
uv run pytest tests/ -m us_fed -v
uv run pytest tests/ -m eu_ecb -v
uv run pytest tests/ -m apac_mas -v
```

On Kubernetes, the region is set once per deployment in the `cage-deployment` ConfigMap, and every workload reads it from there.

Each posture resolves thresholds from `config/thresholds/<REGION>_BASELINE.json` and control profiles from `config/compliance/<REGION>_BASELINE.json`. **To add a jurisdiction of your own**, create those two files following the existing schema, add region Rego under `config/opa/` and Lula assertions under `compliance/lula/`, ship a `<REGION>_OVERLAY.json` in each active plugin, and set `CAGE_DEPLOYMENT_REGION=<REGION>`. No Python changes are required. See [`docs/compliance/REGION_GUARD_AUDIT.md`](compliance/REGION_GUARD_AUDIT.md).

---

## Next Steps

- **Deploy to GKE**: See [`infra/QUICK_START.md`](../infra/QUICK_START.md)
- **Understand Layer 1 kernel architecture**: See [`docs/architecture/GATEWAY_ARCHITECTURE.md`](architecture/GATEWAY_ARCHITECTURE.md)
- **Understand Layer 4 reference application**: See [`docs/examples/governed-financial-advisor/ARCHITECTURE.md`](examples/governed-financial-advisor/ARCHITECTURE.md)
- **Configure governance policies**: See [`docs/governance/GOVERNANCE_OVERVIEW.md`](governance/GOVERNANCE_OVERVIEW.md)
- **Connect an MCP client**: See [`docs/MCP_SETUP.md`](MCP_SETUP.md)
- **Author a domain plugin**: See [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](architecture/EXTENSIBILITY_ARCHITECTURE.md)
- **Understand the domain-agnostic kernel thesis**: See [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](architecture/EXTENSIBILITY_ARCHITECTURE.md)
- **Run the finance example application**: See [`src/governed_financial_advisor/`](../src/governed_financial_advisor/) — a reference application for the finance example domain, not a required component
- **Inspect the healthcare example plugin**: See [`src/cage_healthcare/`](../src/cage_healthcare/)
- **Explore the multi-jurisdiction compliance matrix**: See [`compliance/lula/README.md`](../compliance/lula/README.md) for EU_ECB, APAC_MAS, and US_FED Lula manifests
- **Contribute**: See [`CONTRIBUTING.md`](../CONTRIBUTING.md)
