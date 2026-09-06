# Quick Start — v3.0.0

Get CAGE running locally in under 10 minutes using Docker Compose.

> **Domain-agnostic by default.** Steps 1–7 exercise the **domain-neutral governance substrate** — no finance, no healthcare, no domain assumptions of any kind. Domain behaviour is added afterwards, and only if you want it, by activating an optional plugin (§8). Jurisdictional compliance is likewise opt-in configuration (§9).

## Prerequisites

- Docker and Docker Compose
- Python >=3.10, <3.13 with `uv` (`pip install uv`)
- An OpenAI-compatible API key (or local model endpoint)

## 1. Clone and configure

```bash
git clone https://github.com/your-org/cybernetic-governance-engine.git
cd cybernetic-governance-engine

# Copy environment template
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
OPENAI_API_KEY=<your-api-key>          # Or your LLM provider key
CAGE_ROUTING_SEAL_SECRET=<random-32-char-string>

# Domain-neutral defaults — no domain plugin, universal ISO 42001 baseline only
CAGE_ACTIVE_PLUGINS=""
CAGE_DEPLOYMENT_REGION=LOCAL
```

Generate a routing seal secret:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 2. Start the stack

```bash
docker compose up -d
```

This starts:
- **Gateway** (`localhost:8080`) — Governance enforcement proxy with 8-tier governance pipeline (FTRA pre-pipeline boundary gate + 7 in-pipeline tiers via SymbolicGovernor), and Phase A/B ingress adapters
- **Governed Application (`app`)** (`localhost:3000`) — Governed application service container
- **OPA** (`localhost:8181`) — Policy engine with Rego authorization policies
- **SLM Sidecar** (`localhost:5000`) — Sentence-transformers similarity scoring service

## 3. Verify the gateway is running

```bash
curl http://localhost:8080/health
# Expected: {"status": "healthy", "governance": "active"}
```

## 4. Run the domain-neutral governance demo

```bash
uv sync
uv run python examples/governance_demo.py
```

This exercises the **domain-neutral substrate** end to end and prints the decision trace. All three acts are domain-independent mechanisms:

| Act | Mechanism exercised | Domain knowledge required |
|---|---|---|
| 1 | Atomic resource pre-reservation under concurrent agents | None — the guard reserves abstract budget tokens |
| 2 | HITL interrupt with mandatory rationale hashed into the evidence chain | None — the gate is action-agnostic |
| 3 | SHA-256 tamper-evident evidence chain verification | None — records are opaque payloads |

The scenario labels in the demo output name concrete quantities for readability. Substituting a different domain's quantities (medication concentration, machine-hours, energy dispatch) changes only the label — the enforcement path is identical.

## 5. Open the observability dashboard

Navigate to `http://localhost:5173` to see:
- Real-time governance decisions
- Policy evaluation traces
- Compliance posture summary
- HITL escalation queue

## 6. Run the test suite

```bash
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
```

## 7. Confirm the substrate is domain-independent

```bash
uv run pytest tests/test_domain_independence.py -v
```

This asserts that both shipped example plugins co-load, that neither required a kernel modification, and that a domain package contains zero Lua scripts and zero KMS imports. If it passes, everything you ran in §1–6 was domain-neutral.

---

## 8. Add a domain (optional)

Domain behaviour is contributed by optional packages discovered through the `cage.plugins` entry-point group and gated by `CAGE_ACTIVE_PLUGINS`. Two example domains ship in-tree. **They are equal-standing illustrations of the same extension contract — pick either, both, or neither.**

```bash
export CAGE_ACTIVE_PLUGINS=""                     # no domain (default for this quickstart)
export CAGE_ACTIVE_PLUGINS=finance                # finance example only
export CAGE_ACTIVE_PLUGINS=healthcare             # healthcare example only
export CAGE_ACTIVE_PLUGINS=finance,healthcare     # both, side by side
```

### 8a. Domain Plugin Example: Finance

**Package:** [`src/cage_finance/`](../src/cage_finance/) · **Status:** example domain, not a turnkey trading system

```bash
export CAGE_ACTIVE_PLUGINS=finance
docker compose restart gateway
uv run python examples/chaos_agent_playground.py --scenario A
```

| Contribution | Concrete artifact |
|---|---|
| Governed actions | `execute_trade`, `get_market_data`, `get_portfolio` |
| Barrier | `CashBarrier` watching the `safety:current_cash` scalar |
| Tiers | CBF tier, fiscal pre-reservation tier, consensus tier, causal tier |
| Critics | Risk Manager, Compliance Officer |
| Policy | `opa/trade_governance.rego` |

### 8b. Domain Plugin Example: Healthcare

**Package:** [`src/cage_healthcare/`](../src/cage_healthcare/) · **Status:** example domain, not a clinical device

```bash
export CAGE_ACTIVE_PLUGINS=healthcare
docker compose restart gateway
uv run pytest tests/test_healthcare_plugin.py -v
```

| Contribution | Concrete artifact |
|---|---|
| Governed actions | `dose_order` and the rest of `HEALTHCARE_GOVERNED_ACTIONS` |
| Barrier | `SerumConcentrationBarrier` watching a serum-concentration scalar |
| Tiers | Dose barrier tier, clinical consensus tier |
| Critics | Clinical reviewer personas from `config/critics.yaml` |
| Policy | `opa/dosing_governance.rego` |

The healthcare package exists specifically to falsify the "it's really a finance product" claim by construction. It names things; it implements no mechanism.

### 8c. Domain Plugin Example: Your Own

Manufacturing, logistics, energy dispatch, customer service, critical infrastructure — create `src/cage_<domain>/` mirroring either example, declare your governed actions and barrier parameters, register the entry point, and add independence tests. The full step-by-step authoring guide is in [`docs/architecture/DOMAIN_PLUGIN_ARCHITECTURE.md`](architecture/DOMAIN_PLUGIN_ARCHITECTURE.md) §10.

---

## 9. Select a jurisdictional posture (optional)

Regional compliance is configuration, independent of which domain plugin you loaded. Any plugin runs under any posture.

```bash
export CAGE_DEPLOYMENT_REGION=LOCAL       # universal ISO 42001 baseline only (default)
export CAGE_DEPLOYMENT_REGION=US_FED      # + NIST AI 600-1, SP 800-53, AI RMF, FedRAMP, SR 26-2
export CAGE_DEPLOYMENT_REGION=EU_ECB      # + GDPR, DORA, EU AI Act, MiFID II
export CAGE_DEPLOYMENT_REGION=APAC_MAS    # + MAS Notice 655, FEAT principles, MAS TRM
```

Verify the posture loaded correctly:

```bash
CAGE_DEPLOYMENT_REGION=US_FED   uv run pytest tests/ -m us_fed -v
CAGE_DEPLOYMENT_REGION=EU_ECB   uv run pytest tests/ -m eu_ecb -v
CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -m apac_mas -v
```

Each posture resolves thresholds from `config/thresholds/<REGION>_BASELINE.json` and control profiles from `config/compliance/<REGION>_BASELINE.json`. **To add a jurisdiction of your own**, create those two files following the existing schema, add region Rego under `config/opa/` and Lula assertions under `compliance/lula/`, ship a `<REGION>_OVERLAY.json` in each active plugin, and set `CAGE_DEPLOYMENT_REGION=<REGION>`. No Python changes are required. See [`docs/compliance/REGION_GUARD_AUDIT.md`](compliance/REGION_GUARD_AUDIT.md).

---

## Next Steps

- **Deploy to GKE**: See [`infra/QUICK_START.md`](../infra/QUICK_START.md)
- **Understand the architecture**: See [`docs/architecture/GATEWAY_ARCHITECTURE.md`](architecture/GATEWAY_ARCHITECTURE.md)
- **Configure governance policies**: See [`docs/governance/GOVERNANCE_OVERVIEW.md`](governance/GOVERNANCE_OVERVIEW.md)
- **Connect an MCP client**: See [`docs/MCP_SETUP.md`](MCP_SETUP.md)
- **Author a domain plugin**: See [`docs/architecture/DOMAIN_PLUGIN_ARCHITECTURE.md`](architecture/DOMAIN_PLUGIN_ARCHITECTURE.md)
- **Understand the domain-agnostic kernel thesis**: See [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](architecture/EXTENSIBILITY_ARCHITECTURE.md)
- **Run the finance example application**: See [`src/governed_financial_advisor/`](../src/governed_financial_advisor/) — a reference application for the finance example domain, not a required component
- **Inspect the healthcare example plugin**: See [`src/cage_healthcare/`](../src/cage_healthcare/)
- **Explore the multi-jurisdiction compliance matrix**: See [`compliance/lula/README.md`](../compliance/lula/README.md) for EU_ECB, APAC_MAS, and US_FED Lula manifests
- **Contribute**: See [`CONTRIBUTING.md`](../CONTRIBUTING.md)
