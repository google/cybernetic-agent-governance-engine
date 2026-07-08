# Quick Start

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
- **Gateway** (`localhost:8080`) — Governance enforcement proxy
- **Compliance Bridge** (`localhost:8081`) — OSCAL/compliance automation
- **AgentSight UI** (`localhost:5173`) — Observability dashboard
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
- **Understand the architecture**: See [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)
- **Configure governance policies**: See [`docs/governance/GOVERNANCE_OVERVIEW.md`](governance/GOVERNANCE_OVERVIEW.md)
- **Connect an MCP client**: See [`docs/MCP_SETUP.md`](MCP_SETUP.md)
- **Contribute**: See [`CONTRIBUTING.md`](../CONTRIBUTING.md)
