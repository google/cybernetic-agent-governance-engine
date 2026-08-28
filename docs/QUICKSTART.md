# Quick Start — v3.0.0

Get CAGE running locally in under 10 minutes using Docker Compose.

## Prerequisites

- Docker and Docker Compose
- Python 3.11+ with `uv` (`pip install uv`)
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
- **Compliance Bridge** (`localhost:8081`) — OSCAL/compliance automation; CBF reconciliation worker; AARM 11-vector conformance engine
- **AgentSight UI** (`localhost:5173`) — React/TypeScript real-time governance dashboard (`KernelDashboard` with slippage slider, price drift badges, HITL TTL countdown)
- **Governed Financial Advisor** (`localhost:8000`) — Full multi-agent LangGraph reference implementation with NeMo Guardrails and OPA policy enforcement
- **Redis** — State and quota management
- **OPA** — Policy engine

## 3. Verify the gateway is running

```bash
curl http://localhost:8080/health
# Expected: {"status": "healthy", "governance": "active"}
```

## 4. Run the governance demo

```bash
uv sync
uv run python examples/governance_demo.py
```

This runs a sample governed financial advisor query through the full governance pipeline and prints the decision trace.

## 5. Open the observability dashboard

Navigate to `http://localhost:5173` to see:
- Real-time governance decisions
- Policy evaluation traces
- Compliance posture summary
- HITL escalation queue

## 6. Run the test suite

```bash
uv run pytest tests/ -x -q
```

## Next Steps

- **Deploy to GKE**: See [`infra/QUICK_START.md`](../infra/QUICK_START.md)
- **Understand the architecture**: See [`docs/architecture/GATEWAY_ARCHITECTURE.md`](architecture/GATEWAY_ARCHITECTURE.md)
- **Configure governance policies**: See [`docs/governance/GOVERNANCE_OVERVIEW.md`](governance/GOVERNANCE_OVERVIEW.md)
- **Connect an MCP client**: See [`docs/MCP_SETUP.md`](MCP_SETUP.md)
- **Run the Governed Financial Advisor**: See [`src/governed_financial_advisor/`](../src/governed_financial_advisor/)
- **Explore the three-region compliance matrix**: See [`compliance/lula/README.md`](../compliance/lula/README.md) for EU_ECB, APAC_MAS, and US_FED Lula manifests
- **Contribute**: See [`CONTRIBUTING.md`](../CONTRIBUTING.md)
