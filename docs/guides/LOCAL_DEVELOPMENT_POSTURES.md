# Local Development Postures: Pure Dev vs. CAGE SDK Host

CAGE supports two complementary local operating postures on a developer workstation. They are designed to coexist without port collisions, process friction, or unnecessary computational overhead.

---

## 1. Overview of the Two Postures

```
                     DEVELOPER WORKSTATION / LOCAL HOST
┌────────────────────────────────────────────────────────────────────────┐
│                                                                        │
│ 1. PURE LOCAL DEV POSTURE (Default / Offline Inner Loop)               │
│    • Executed via host shell & virtual environment (uv run pytest)     │
│    • Zero background daemons, zero containers                          │
│    • In-memory mocks (MockChatModel, MemorySaver)                      │
│    • Sub-second test execution (<30s full suite)                       │
│                                                                        │
│          │                                      ▲                      │
│          │ Bind Mounts                          │ HTTP / REST          │
│          │ (Hot-Reload)                         │ (Local Client Calls) │
│          ▼                                      │                      │
│                                                                        │
│ 2. CAGE SDK HOST RUNTIME (Activated via scripts/dev_local.sh)          │
│    • graph-engine container (LangGraph SDK Server at :2024)            │
│    • gateway container (CAGE PDP at :8080)                             │
│    • opa container (Rego Policy Engine at :8181)                       │
│    • Host Ollama daemon (:11434 with qwen2.5:3b)                       │
│    • Optional Redis container (:6380 via --with-redis)                 │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

| Dimension | Posture 1: Pure Local Dev | Posture 2: Combined Local Dev + CAGE SDK Host |
|---|---|---|
| **Primary Use Case** | TDD inner loop, unit testing, policy authoring, boundary & contract checks | End-to-end multi-agent execution, LangGraph Studio UI, real tool calling & HITL flow testing |
| **Active Stack** | Pure Python (`uv run`) | Docker Compose (`docker-compose.local-dev.yml`) + Host Ollama |
| **Model Backend** | In-memory mocks (`MockChatModel`), zero GPU/CPU inference load | Real inference via host Ollama (`qwen2.5:3b` at `localhost:11434`) |
| **Running Services** | **None** (zero background processes) | • `graph-engine` (`:2024`)<br>• `gateway` (`:8080`)<br>• `opa` (`:8181`)<br>• `ollama` (`:11434`)<br>• `redis` (optional `:6380`) |
| **How to Launch** | Directly run tests (e.g. `make test-fast`) | `bash scripts/dev_local.sh` |
| **Verification Gate** | `make test-fast`<br>`uv run python scripts/check_import_boundaries.py` | `uv run pytest tests/test_langgraph_sdk_local.py --run-integration` |
| **Network Footprint** | Completely offline | Binds ports `2024`, `8080`, `8181`, `11434` |

---

## 2. Posture 1: Pure Local Development (Hermetic Inner Loop)

Posture 1 is the default state of the repository. No services need to be started.

### When to Use
* Rapid test-driven development (TDD).
* Adding or editing graph topology, symbolic governor tiers, or OPA policies.
* Checking import boundary contracts (`scripts/check_import_boundaries.py`).
* Working disconnected on battery or without network access.

### How It Works
* Graph nodes utilize lazy factories (e.g. `_build_fast_llm()` and `_build_reasoner_llm()` in [`src/governed_financial_advisor/graph/nodes/supervisor_node.py`](../../src/governed_financial_advisor/graph/nodes/supervisor_node.py)). When `USE_MOCK_LLM=true` or when no live model base URL is configured, they automatically substitute in-memory [`MockChatModel`](../../src/governed_financial_advisor/graph/nodes/supervisor_node.py) stubs.
* State checkpointing falls back to in-memory `MemorySaver`.

### Canonical Commands
```bash
# Run full local hermetic unit suite
make test-fast

# Or run a single isolated unit test
uv run pytest tests/test_cage_graph.py -v
```

---

## 3. Posture 2: Combined Local Dev + CAGE SDK Host

Posture 2 extends your local development environment by turning your machine into a **CAGE SDK Runtime Host**.

### When to Use
* Interacting with the agent graph using the **LangGraph Studio UI** or the `langgraph_sdk` Python client.
* Validating end-to-end multi-agent execution with real reasoning models.
* Testing the out-of-process Human-In-The-Loop (HITL) interrupt and deferral queue workflows.
* Executing full integration tests: `tests/test_langgraph_sdk_local.py`.

### Architecture & Container Boundary

1. **Inside Docker (`graph-engine`, `gateway`, `opa`):**
   * Configured via [`docker-compose.local-dev.yml`](../../docker-compose.local-dev.yml) and [`deployment/docker/Dockerfile.local-dev`](../../deployment/docker/Dockerfile.local-dev).
   * Runs the LangGraph SDK server on port `2024`, targeting the uncheckpointed graph factory declared in [`langgraph.json`](../../langgraph.json).
   * Runs the CAGE Gateway on port `8080` and OPA on port `8181`.
2. **Outside Docker on Host OS (`ollama`):**
   * Ollama runs directly on your host machine at `http://localhost:11434` to leverage host hardware acceleration (Metal, CUDA, ROCm).
   * Containers reach the host Ollama instance via Docker's bridge: `http://host.docker.internal:11434/v1` enabled by `extra_hosts: ["host.docker.internal:host-gateway"]`.
3. **Hot-Reloading Bind Mounts:**
   * Local directories `./src`, `./config`, and `./policies` are mounted read-only into the containers.
   * Edits made in your local editor on the host are immediately reflected inside the running LangGraph SDK server without rebuilding images.

### Launching Posture 2

Run the automated launch script:

```bash
# Start with in-memory checkpointer
bash scripts/dev_local.sh

# Or start with Redis checkpointer for persistent state
bash scripts/dev_local.sh --with-redis
```

The script automatically:
1. Verifies Docker and Docker Compose are running.
2. Checks if host Ollama is responding at `http://localhost:11434` (auto-installs and launches it if absent).
3. Ensures model `qwen2.5:3b` is present (auto-pulls if missing).
4. Creates `config/environments/local-dev.env` from `.example` if needed.
5. Builds and launches the Docker Compose overlay.

### Stopping Posture 2

Press `Ctrl+C` in the terminal running `dev_local.sh`, or execute:

```bash
docker compose -f docker-compose.yml -f docker-compose.local-dev.yml down
```

Your workstation immediately returns to Posture 1 (Pure Local Dev).

---

## 4. Coexistence & Interworking

Both postures coexist harmoniously:

1. **Zero False Failures in Posture 1:**
   * [`tests/test_langgraph_sdk_local.py`](../../tests/test_langgraph_sdk_local.py) includes connectivity smoke tests that execute `pytest.skip()` if `http://localhost:2024` or `http://localhost:8080` is not active. Running `make test-fast` never fails because Posture 2 is stopped.
2. **Side-by-Side Execution in Posture 2:**
   * When Posture 2 is active, you can still run `make test-fast` in another host terminal.
   * You can run the live integration tests that verify real inference and gateway traversal:
     ```bash
     uv run pytest tests/test_langgraph_sdk_local.py --run-integration -v
     ```
3. **Anti-Mock Verification:**
   * The live suite contains `test_anti_mock_model_guard`, which asserts that responses received from the SDK server do *not* contain mock sentinels and originate from real local inference through `qwen2.5:3b`.

---

## 5. Troubleshooting & Diagnostics

| Symptom | Cause | Resolution |
|---|---|---|
| `Ollama is not responding at http://localhost:11434` | Host daemon is not running | Run `ollama serve` on the host, or let `bash scripts/dev_local.sh` start it. |
| `Model qwen2.5:3b not found` | Model has not finished downloading | Run `ollama pull qwen2.5:3b` on the host. |
| Port `2024` / `8080` already in use | Stale container or previous dev session | Run `docker compose -f docker-compose.yml -f docker-compose.local-dev.yml down`. |
| `test_anti_mock_model_guard` fails | `USE_MOCK_LLM=true` in `local-dev.env` | Set `USE_MOCK_LLM=false` in `config/environments/local-dev.env` to enforce real Ollama validation. |

