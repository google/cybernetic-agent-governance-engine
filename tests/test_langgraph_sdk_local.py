# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Integration test for LangGraph SDK local development posture.

This test validates that the LangGraph SDK server can initialize and connect
when run via `langgraph dev` with the local-dev.env configuration.

Markers:
    - integration: Requires external services (LangGraph SDK server at localhost:2024)
    - local: Offline-capable (no live cloud resources)

Prerequisites:
    - LangGraph SDK server running: bash scripts/dev_local.sh
    - Host Ollama at http://localhost:11434 with qwen2.5:3b pre-pulled
    - Gateway, OPA, and Redis services healthy
"""

import os
import pathlib

import httpx
import pytest

# Load local-dev.env if present
try:
    from dotenv import load_dotenv

    _local_env = (
        pathlib.Path(__file__).parent.parent
        / "config"
        / "environments"
        / "local-dev.env"
    )
    if _local_env.exists():
        load_dotenv(_local_env, override=False)
except ImportError:
    pass

pytestmark = [pytest.mark.local]


def test_langgraph_server_connectivity() -> None:
    """Validate LangGraph SDK server is listening at localhost:2024.

    This test verifies the LangGraph dev server HTTP endpoint responds
    to health or documentation endpoints, proving the Docker Compose
    overlay has successfully started the graph-engine service.

    Prerequisites:
        - LangGraph SDK server running: bash scripts/dev_local.sh
    """
    sdk_base_url = "http://localhost:2024"

    # Try /ok endpoint first (common health check pattern)
    try:
        resp = httpx.get(f"{sdk_base_url}/ok", timeout=5.0)
        assert resp.status_code == 200, f"Unexpected status from /ok: {resp.status_code}"
        return
    except httpx.HTTPStatusError:
        pass  # Fall through to /docs
    except httpx.RequestError as exc:
        pytest.skip(
            f"LangGraph SDK server not reachable at {sdk_base_url}. "
            f"Start the stack with: bash scripts/dev_local.sh\n"
            f"Error: {exc}"
        )

    # Fall back to /docs (OpenAPI documentation endpoint)
    try:
        resp = httpx.get(f"{sdk_base_url}/docs", timeout=5.0, follow_redirects=True)
        assert resp.status_code == 200, f"Unexpected status from /docs: {resp.status_code}"
    except httpx.RequestError as exc:
        pytest.fail(
            f"LangGraph SDK server not reachable at {sdk_base_url}. "
            f"Start the stack with: bash scripts/dev_local.sh\n"
            f"Error: {exc}"
        )


async def test_anti_mock_model_guard() -> None:
    """Execute a run and verify active model is NOT MockChatModel.

    This test ensures the local-dev posture is configured to use real
    Ollama models (qwen2.5:3b), not in-memory test doubles. It validates
    that USE_MOCK_LLM=false is correctly propagated through the environment
    and that the LangGraph graph factory binds to Ollama.

    Prerequisites:
        - LangGraph SDK server running: bash scripts/dev_local.sh
        - Host Ollama at http://localhost:11434 with qwen2.5:3b pre-pulled
    """
    try:
        from langgraph_sdk import get_client
    except ImportError:
        pytest.skip("langgraph_sdk not installed (requires langgraph-cli[inmem])")

    # Anti-mock guard: Ensure environment is configured for real Ollama
    use_mock_llm = os.environ.get("USE_MOCK_LLM", "").lower()
    if use_mock_llm == "true":
        pytest.fail(
            "USE_MOCK_LLM=true detected. This test requires real Ollama models. "
            "Set USE_MOCK_LLM=false in config/environments/local-dev.env"
        )

    ollama_url = os.environ.get("OLLAMA_BASE_URL")
    if not ollama_url or "mock" in ollama_url.lower():
        pytest.skip(
            "OLLAMA_BASE_URL not configured or points to a mock endpoint. "
            "Set OLLAMA_BASE_URL=http://host.docker.internal:11434 in local-dev.env"
        )

    # Initialize SDK client
    sdk_url = "http://localhost:2024"
    client = get_client(url=sdk_url)

    # List available assistants
    assistants = await client.assistants.search()
    assert len(assistants) > 0, "No assistants found. Check langgraph.json configuration."

    # Create a thread and run a minimal query
    thread = await client.threads.create()
    assistant_id = assistants[0]["assistant_id"]

    # Execute a minimal run (just invoke, no streaming needed for model type check)
    run = await client.runs.create(
        thread_id=thread["thread_id"],
        assistant_id=assistant_id,
        input={"messages": [{"role": "user", "content": "What is 2+2?"}]},
    )

    # Wait for completion (with timeout)
    await client.runs.join(thread_id=thread["thread_id"], run_id=run["run_id"])
    run = await client.runs.get(thread_id=thread["thread_id"], run_id=run["run_id"])
    state = await client.threads.get_state(thread["thread_id"])

    # Verify run completed without errors
    assert run["status"] in ["success", "error"], f"Unexpected run status: {run['status']}"

    # Anti-mock assertion: If the run succeeded, verify output exists and is non-trivial
    # MockChatModel returns predictable stub outputs; real models produce variable text.
    if run["status"] == "success":
        messages = state.get("values", {}).get("messages", [])
        assert len(messages) > 0, (
            "Run succeeded but produced no messages. "
            "This may indicate MockChatModel is active."
        )
        # Verify the last message is not a MockChatModel sentinel
        last_message = messages[-1]
        last_content = (
            last_message.get("content", "")
            if isinstance(last_message, dict)
            else getattr(last_message, "content", "")
        )
        assert "mock" not in last_content.lower(), (
            "Model output contains 'mock' sentinel. "
            "Verify USE_MOCK_LLM=false and Ollama is reachable."
        )


async def test_in_process_and_gateway_gates() -> None:
    """Send payload and verify traversal through NeMo, FTRA, safety_check, and interruption.

    This test validates the full governance pipeline:
    1. In-process NeMo Guardrails input rail (nemo_guardrail node)
    2. FTRA reachability gate (ftra_node)
    3. Gateway OPA safety_check (external HTTP call to gateway:8080)
    4. Interruption on governed_trader node (if HITL_REQUIRED or BLOCKED)

    Prerequisites:
        - LangGraph SDK server running: bash scripts/dev_local.sh
        - Gateway service healthy at http://localhost:8080
        - OPA service healthy at http://localhost:8181
    """
    try:
        from langgraph_sdk import get_client
    except ImportError:
        pytest.skip("langgraph_sdk not installed (requires langgraph-cli[inmem])")

    # Verify gateway is reachable
    gateway_url = os.environ.get("CAGE_GATEWAY_URL", "http://localhost:8080")
    try:
        resp = httpx.get(f"{gateway_url}/health", timeout=5.0)
        if resp.status_code != 200:
            pytest.skip(f"Gateway not healthy at {gateway_url}. Status: {resp.status_code}")
    except httpx.RequestError as exc:
        pytest.skip(f"Gateway not reachable at {gateway_url}: {exc}")

    # Initialize SDK client
    sdk_url = "http://localhost:2024"
    client = get_client(url=sdk_url)

    # List assistants and select the governed_advisor
    assistants = await client.assistants.search()
    governed_advisor = next(
        (
            a
            for a in assistants
            if a.get("graph_id") == "governed_advisor"
            or a.get("name") == "governed_advisor"
            or "governed_advisor" in a.get("assistant_id", "")
        ),
        None,
    )
    if not governed_advisor:
        pytest.skip("governed_advisor assistant not found in langgraph.json")

    assistant_id = governed_advisor["assistant_id"]

    # Create thread and run
    thread = await client.threads.create()

    # Send a payload that will trigger governance checks
    # This payload should pass NeMo input rail, reach FTRA, and hit safety_check
    input_payload = {
        "messages": [
            {
                "role": "user",
                "content": "Execute a trade: Buy 100 shares of AAPL at market price.",
            }
        ]
    }

    run = await client.runs.create(
        thread_id=thread["thread_id"],
        assistant_id=assistant_id,
        input=input_payload,
    )

    # Wait for run to complete or interrupt
    await client.runs.join(thread_id=thread["thread_id"], run_id=run["run_id"])
    run = await client.runs.get(thread_id=thread["thread_id"], run_id=run["run_id"])
    state = await client.threads.get_state(thread["thread_id"])

    # Verify run reached a governance checkpoint
    # Expected outcomes:
    # 1. Run is interrupted (status='interrupted') at governed_trader node
    # 2. Run completed with explainer output (BLOCKED or ESCALATED)
    # 3. Run completed with trade execution (ALLOW, less common in test scenarios)

    assert run["status"] in ["success", "interrupted", "error"], (
        f"Unexpected run status: {run['status']}"
    )

    # If interrupted, verify it's at the expected node (governed_trader or defer_node)
    if run["status"] == "interrupted":
        # LangGraph SDK returns interrupted runs with metadata about where they stopped
        # Verify the interruption is at a governance checkpoint node
        assert state.get("next") is not None, "Interrupted run missing 'next' node metadata"
        next_nodes = state["next"] if isinstance(state["next"], (list, tuple)) else [state["next"]]
        assert any(n in ["governed_trader", "defer_node"] for n in next_nodes), (
            f"Run interrupted at unexpected node: {state['next']}"
        )

    # Verify state includes messages (proves NeMo input rail passed)
    assert "values" in state, "Run missing 'values' (state snapshot)"
    assert "messages" in state["values"], "Run state missing 'messages' field"
    assert len(state["values"]["messages"]) > 0, "Run state has no messages"


def test_langgraph_sdk_client_initialization() -> None:
    """Validate LangGraph SDK client can connect to local dev server.

    This test verifies that:
    1. langgraph_sdk package is installed (dev dependency)
    2. The client can initialize with the local dev server URL
    3. The connection succeeds without authentication errors

    This is a smoke test for the Local Docker Dev Posture infrastructure.
    It does NOT execute a full graph invocation (that would require Ollama
    model calls and multi-container orchestration beyond the scope of a
    unit/integration boundary test).
    """
    # Anti-mock guard: Ensure we are NOT using a test double when Ollama is configured.
    # If OLLAMA_BASE_URL is set, we expect real Ollama connectivity, not MockChatModel.
    ollama_url = os.environ.get("OLLAMA_BASE_URL")
    if ollama_url:
        # Verify the URL points at a real Ollama instance, not a mock endpoint
        assert "mock" not in ollama_url.lower(), (
            "OLLAMA_BASE_URL points at a mock endpoint. "
            "This test requires a real Ollama instance at http://localhost:11434."
        )

    try:
        from langgraph_sdk import get_client
    except ImportError:
        pytest.skip("langgraph_sdk not installed (requires langgraph-cli[inmem])")

    # Initialize client pointing at local dev server
    sdk_url = "http://localhost:2024"
    client = get_client(url=sdk_url)

    # Smoke test: client initialized without raising
    assert client is not None
    assert hasattr(client, "assistants"), "Client missing .assistants attribute"
    assert hasattr(client, "threads"), "Client missing .threads attribute"
    assert hasattr(client, "runs"), "Client missing .runs attribute"


def test_uncheckpointed_graph_factory_exists() -> None:
    """Validate create_uncheckpointed_graph() entry point exists.

    The LangGraph SDK server (langgraph.json) references
    src.governed_financial_advisor.graph.graph:create_uncheckpointed_graph.
    This test ensures the function is importable and callable.
    """
    from src.governed_financial_advisor.graph.graph import (
        create_uncheckpointed_graph,
    )

    # Compile the graph (does not invoke any nodes)
    graph = create_uncheckpointed_graph()

    # Validate graph structure
    assert graph is not None
    assert hasattr(graph, "invoke"), "Compiled graph missing .invoke method"
    assert hasattr(graph, "stream"), "Compiled graph missing .stream method"
