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

"""GEAP Agent Runtime (Vertex AI Agent Engine) entrypoint for Governed Financial Advisor.

Used for GCP deployments (`infra/targets/gcp-gke/`) so the orchestration layer
runs as a serverless managed agent on GEAP Agent Runtime while all governance
gates (`SymbolicGovernor`, `DeferQueue`, `ActuatorRegistry`, KMS signing)
remain in the GKE-hosted CAGE Hybrid Gateway.

Security invariants enforced at runtime:
- POAM-2026-079: `assert_no_signing_identity()` refuses startup if any signing
  key, governance salt, or cloud service account material is present.
- AI600-003 (M6): `GovernedMemoryBankGuard` sanitizes retrieved Memory Bank
  snippets (`PreloadMemoryTool`) and gates session persistence
  (`add_session_to_memory`) before any cross-session state write.
- LangSmith Prohibition: `LANGSMITH_TRACING` and `LANGCHAIN_TRACING_V2` are
  explicitly forced to `"false"`.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from langgraph.types import Command

from config.settings import Config
from src.governed_financial_advisor.graph.nodes.approval_contract import (
    ApprovalDecision,
)
from src.governed_financial_advisor.infrastructure.auth import (
    requires_verified_principal,
    resolve_request_principal,
    verify_user_oidc_token,
)
from src.governed_financial_advisor.infrastructure.identity_guard import (
    assert_no_signing_identity,
)
from src.governed_financial_advisor.utils.context import (
    principal_verified_context,
    user_context,
)
from src.integrations.gcp_geap.runtime_guards import (
    GovernedMemoryBankGuard,
    MemoryBankGuardResult,
)

logger = logging.getLogger(__name__)

# Lazily resolved in `set_up()` so importing `geap_app` during GEAP Agent
# Runtime build introspection has zero side effects (no Presidio/spaCy load at
# import time), while remaining monkeypatchable in unit tests.
configure_telemetry: Any = None
create_graph: Any = None

# Official GEAP Agent Runtime reserved environment variables that must NEVER be
# overridden in deployment specifications (per
# https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/deploy-an-agent#environment-variables).
GEAP_RESERVED_ENV_VARS: frozenset[str] = frozenset(
    {
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_QUOTA_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "PORT",
        "K_SERVICE",
        "K_REVISION",
        "K_CONFIGURATION",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }
)
GEAP_RESERVED_ENV_PREFIX: str = "GOOGLE_CLOUD_AGENT_ENGINE"

# Canonical `class_methods` specification for `client.runtimes.create`
# (`agent_framework="langgraph"`, `identity_type="AGENT_IDENTITY"`).
CLASS_METHODS: tuple[dict[str, Any], ...] = (
    {
        "name": "query",
        "api_mode": "",
        "description": "Synchronous governed financial advisor query.",
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "user_id": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "async_query",
        "api_mode": "async",
        "description": "Asynchronous governed financial advisor query.",
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "user_id": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "stream_query",
        "api_mode": "stream",
        "description": "Synchronous streaming governed financial advisor query (required for GEAP Playground & SDK).",
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "user_id": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "async_stream_query",
        "api_mode": "async_stream",
        "description": "Asynchronous streaming governed financial advisor query.",
        "parameters": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "user_id": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "resume_approval",
        "api_mode": "async",
        "description": "Resume a paused HITL approval graph checkpoint on GEAP Agent Runtime.",
        "parameters": {
            "type": "object",
            "properties": {
                "thread_id": {"type": "string"},
                "decision": {"type": "string"},
                "approver_id": {"type": "string"},
                "deferred_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["thread_id", "decision", "approver_id"],
        },
    },
)


class GovernedFinancialAdvisorGeapApp:
    """GEAP Agent Runtime (`ReasoningEngine`) template for the advisor graph."""

    agent_framework: str = "langgraph"

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        gateway_url: str | None = None,
        enable_tracing: bool = True,
    ) -> None:
        self._redis_url = redis_url
        self._gateway_url = gateway_url
        self._enable_tracing = enable_tracing
        self._graph: Any = None
        self._memory_guard: GovernedMemoryBankGuard | None = None
        self._initialized = False

    def set_up(self) -> None:
        """Initialize the advisor inside the managed GEAP Agent Runtime container.

        Enforces POAM-2026-079 zero-signing-authority invariants, disables
        LangSmith tracing, and initializes `GovernedMemoryBankGuard`. Graph
        compilation and telemetry export are initialized lazily on first query
        (or immediately when `create_graph` is explicitly bound) so container
        startup never blocks on VPC/DNS readiness.
        """
        # Enforce strict LangSmith prohibition
        os.environ["LANGSMITH_TRACING"] = "false"
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        os.environ.setdefault("CAGE_ADVISOR_RUNTIME", "geap")

        if self._gateway_url:
            os.environ["GATEWAY_URL"] = self._gateway_url

        # POAM-2026-079: Fail closed if any signing key or cloud SA is present
        assert_no_signing_identity()

        self._memory_guard = GovernedMemoryBankGuard()
        if create_graph is not None:
            redis_url = (
                self._redis_url if self._redis_url is not None else Config.REDIS_URL
            )
            self._graph = create_graph(redis_url=redis_url)

        self._initialized = True
        logger.info(
            "GovernedFinancialAdvisorGeapApp initialized (runtime=geap, gateway_url=%s)",
            os.environ.get("GATEWAY_URL", "http://localhost:8080"),
        )

    def _ensure_ready(self) -> None:
        if not self._initialized or self._memory_guard is None:
            self.set_up()

    def _ensure_graph(self) -> Any:
        self._ensure_ready()
        if self._graph is None:
            if self._enable_tracing and (
                os.environ.get("ENABLE_TRACING", "true").lower() == "true"
            ):
                telemetry_fn = configure_telemetry
                if telemetry_fn is None:
                    from src.gateway.infrastructure.telemetry_client import (
                        configure_telemetry as telemetry_fn,
                    )
                telemetry_fn()

            redis_url = (
                self._redis_url if self._redis_url is not None else Config.REDIS_URL
            )
            graph_fn = create_graph
            if graph_fn is None:
                from src.governed_financial_advisor.graph.graph import (
                    create_graph as graph_fn,
                )
            self._graph = graph_fn(redis_url=redis_url)
        return self._graph

    def register_operations(self) -> dict[str, Sequence[str]]:
        """Declare supported GEAP Agent Runtime operation modes."""
        return {
            "": ["query"],
            "async": ["async_query", "resume_approval"],
            "stream": ["stream_query"],
            "async_stream": ["async_stream_query"],
        }

    def guard_preloaded_memories(
        self,
        memories: Sequence[str],
        *,
        strict_block_on_injection: bool = False,
    ) -> MemoryBankGuardResult:
        """Sanitize `PreloadMemoryTool` entries via M4 `GovernedMemoryBankGuard`."""
        self._ensure_ready()
        assert self._memory_guard is not None
        return self._memory_guard.guard_preloaded_memories(
            memories, strict_block_on_injection=strict_block_on_injection
        )

    def guard_save_session_to_memory(
        self,
        session_events: Sequence[dict[str, Any] | str],
    ) -> MemoryBankGuardResult:
        """Gate `add_session_to_memory` callbacks via M4 `GovernedMemoryBankGuard`."""
        self._ensure_ready()
        assert self._memory_guard is not None
        return self._memory_guard.guard_save_session_to_memory(session_events)

    def _resolve_geap_principal(
        self,
        user_id: str,
        user_oidc_token: str | None = None,
    ) -> tuple[str, bool]:
        """Resolve and verify the end-user principal for a GEAP Agent Runtime turn."""
        if user_oidc_token:
            verified = verify_user_oidc_token(user_oidc_token)
            if user_id and user_id != "demo_user" and user_id != verified.user_id:
                raise ValueError(
                    "Asserted user_id does not match authenticated principal"
                )
            return verified.user_id, True
        if principal_verified_context.get():
            return user_id, True
        if requires_verified_principal():
            raise ValueError("Verified end-user principal required")
        return user_id, False

    async def async_query(
        self,
        *,
        prompt: str,
        user_id: str = "demo_user",
        session_id: str | None = None,
        preloaded_memories: Sequence[str] = (),
        user_oidc_token: str | None = None,
    ) -> dict[str, Any]:
        """Execute a governed financial advisor turn on GEAP Agent Runtime."""
        effective_user_id, is_verified = self._resolve_geap_principal(
            user_id, user_oidc_token
        )
        graph = self._ensure_graph()
        guard_result = self.guard_preloaded_memories(preloaded_memories)
        safe_memories = [str(m) for m in guard_result.sanitized_events]
        thread_id = session_id or f"geap_session_{effective_user_id}"

        token = user_context.set(effective_user_id)
        verified_token = principal_verified_context.set(is_verified)
        try:
            config = {"configurable": {"thread_id": thread_id}}
            inputs: dict[str, Any] = {
                "messages": [("user", prompt)],
                "user_id": effective_user_id,
                "execution_Mode": "advisor",
                "Explainability_Mode": "verbose",
            }
            if safe_memories:
                inputs["preloaded_memories"] = safe_memories

            final_state = await graph.ainvoke(inputs, config=config)
            messages = final_state.get("messages", [])
            response_text = ""
            if messages:
                last_msg = messages[-1]
                response_text = getattr(last_msg, "content", str(last_msg))

            return {
                "session_id": thread_id,
                "user_id": effective_user_id,
                "user_verified": is_verified,
                "response": response_text,
                "transaction_status": final_state.get("transaction_status"),
                "governance_verdict": final_state.get("governance_verdict"),
                "sanitized_memory_count": len(safe_memories),
            }
        finally:
            principal_verified_context.reset(verified_token)
            user_context.reset(token)

    def query(
        self,
        *,
        prompt: str,
        user_id: str = "demo_user",
        session_id: str | None = None,
        preloaded_memories: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Synchronous wrapper around `async_query` for Vertex AI ReasoningEngine."""
        return asyncio.run(
            self.async_query(
                prompt=prompt,
                user_id=user_id,
                session_id=session_id,
                preloaded_memories=preloaded_memories,
            )
        )

    async def async_stream_query(
        self,
        *,
        prompt: str,
        user_id: str = "demo_user",
        session_id: str | None = None,
        preloaded_memories: Sequence[str] = (),
        user_oidc_token: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream LangGraph node updates for GEAP Agent Runtime async streaming sessions."""
        effective_user_id, is_verified = self._resolve_geap_principal(
            user_id, user_oidc_token
        )
        graph = self._ensure_graph()
        guard_result = self.guard_preloaded_memories(preloaded_memories)
        safe_memories = [str(m) for m in guard_result.sanitized_events]
        thread_id = session_id or f"geap_session_{effective_user_id}"

        token = user_context.set(effective_user_id)
        verified_token = principal_verified_context.set(is_verified)
        try:
            config = {"configurable": {"thread_id": thread_id}}
            inputs: dict[str, Any] = {
                "messages": [("user", prompt)],
                "user_id": effective_user_id,
                "execution_Mode": "advisor",
                "Explainability_Mode": "verbose",
            }
            if safe_memories:
                inputs["preloaded_memories"] = safe_memories

            async for chunk in graph.astream(
                inputs, config=config, stream_mode="updates"
            ):
                yield {"session_id": thread_id, "event": chunk}
        finally:
            principal_verified_context.reset(verified_token)
            user_context.reset(token)

    def stream_query(
        self,
        *,
        prompt: str,
        user_id: str = "demo_user",
        session_id: str | None = None,
        preloaded_memories: Sequence[str] = (),
    ) -> Iterator[dict[str, Any]]:
        """Synchronous streaming query required by GEAP Runtime Contract & Playground."""

        async def _collect() -> list[dict[str, Any]]:
            items: list[dict[str, Any]] = []
            async for item in self.async_stream_query(
                prompt=prompt,
                user_id=user_id,
                session_id=session_id,
                preloaded_memories=preloaded_memories,
            ):
                items.append(item)
            return items

        yield from asyncio.run(_collect())

    async def resume_approval(
        self,
        *,
        thread_id: str,
        decision: str,
        approver_id: str,
        deferred_id: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Resume a paused HITL approval graph checkpoint on GEAP Agent Runtime."""
        graph = self._ensure_graph()
        clean_thread_id = str(thread_id or "").strip()
        if not clean_thread_id:
            raise ValueError("thread_id must be a non-empty string")
        normalized_decision = str(decision or "").strip().upper()
        if normalized_decision in {"APPROVE", "APPROVED", "TRUE", "ALLOW"}:
            approved = True
        elif normalized_decision in {"REJECT", "REJECTED", "FALSE", "DENY", "DENIED"}:
            approved = False
        else:
            raise ValueError(
                f"Invalid decision {decision!r}; expected APPROVE/APPROVED or REJECT/REJECTED."
            )
        validated = ApprovalDecision(
            ticket_id=deferred_id,
            approved=approved,
            reviewer=approver_id,
            rationale=reason
            if reason is not None
            else f"Decision: {normalized_decision}",
        )
        config = {"configurable": {"thread_id": clean_thread_id}}
        resume_payload = {
            **validated.model_dump(),
            "decision": normalized_decision,
            "approver_id": validated.reviewer,
            "deferred_id": validated.ticket_id,
            "reason": validated.rationale,
        }
        final_state = await graph.ainvoke(Command(resume=resume_payload), config=config)
        messages = final_state.get("messages", [])
        response_text = ""
        if messages:
            last_msg = messages[-1]
            response_text = getattr(last_msg, "content", str(last_msg))
        return {
            "thread_id": clean_thread_id,
            "status": "resumed",
            "decision": "APPROVED" if validated.approved else "REJECTED",
            "approved": validated.approved,
            "response": response_text,
            "transaction_status": final_state.get("transaction_status"),
        }


_UNARY_METHODS: frozenset[str] = frozenset({"query", "async_query", "resume_approval"})
_STREAM_METHODS: frozenset[str] = frozenset({"stream_query", "async_stream_query"})


def create_geap_runtime_router(
    agent: GovernedFinancialAdvisorGeapApp | None = None,
) -> APIRouter:
    """Create a FastAPI router implementing the GEAP Custom Container Runtime Contract.

    Reference:
    https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/runtime-contract

    Endpoints:
    - `POST /api/reasoning_engine`: Unary execution (`reasoningEngines:query`).
      Accepts `{"class_method": "<method_name>", "input": {...}}` and returns
      `{"output": <result>}` (or HTTP 400 `{"error": ...}` if invalid).
    - `POST /api/stream_reasoning_engine`: Streaming execution (`reasoningEngines:streamQuery`).
      Accepts `{"class_method": "<stream_method_name>", "input": {...}}` and returns
      newline-delimited JSON (`ndjson`) chunks via `StreamingResponse`.
    """
    router = APIRouter()
    runtime_agent = agent or GovernedFinancialAdvisorGeapApp()

    @router.post("/api/reasoning_engine")
    async def handle_reasoning_engine(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except (ValueError, TypeError) as exc:
            return JSONResponse(
                {"error": f"Invalid JSON request body: {exc}"}, status_code=400
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "Request body must be a JSON object."}, status_code=400
            )
        method_name = str(body.get("class_method") or "query")
        input_kwargs = body.get("input") or {}
        if not isinstance(input_kwargs, dict):
            return JSONResponse(
                {"error": "Field 'input' must be a JSON object."},
                status_code=400,
            )

        if method_name not in _UNARY_METHODS or not hasattr(runtime_agent, method_name):
            return JSONResponse(
                {"error": f"Method '{method_name}' not found on agent."},
                status_code=400,
            )

        # Prefer async_query when "query" is invoked inside an active event loop
        target_name = "async_query" if method_name == "query" else method_name
        method = getattr(runtime_agent, target_name)
        verified_token = None
        if method_name in {"query", "async_query"}:
            principal = resolve_request_principal(
                request, str(input_kwargs.get("user_id") or "")
            )
            if principal.user_id:
                input_kwargs = {**input_kwargs, "user_id": principal.user_id}
            verified_token = principal_verified_context.set(principal.verified)
        try:
            result = method(**input_kwargs)
            if inspect.isawaitable(result):
                result = await result
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            if verified_token is not None:
                principal_verified_context.reset(verified_token)
        return JSONResponse({"output": jsonable_encoder(result)})

    @router.post("/api/stream_reasoning_engine")
    async def handle_stream_reasoning_engine(request: Request) -> Any:
        try:
            body = await request.json()
        except (ValueError, TypeError) as exc:
            return JSONResponse(
                {"error": f"Invalid JSON request body: {exc}"}, status_code=400
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "Request body must be a JSON object."}, status_code=400
            )
        method_name = str(body.get("class_method") or "stream_query")
        input_kwargs = body.get("input") or {}
        if not isinstance(input_kwargs, dict):
            return JSONResponse(
                {"error": "Field 'input' must be a JSON object."},
                status_code=400,
            )

        if method_name not in _STREAM_METHODS or not hasattr(
            runtime_agent, method_name
        ):
            return JSONResponse(
                {"error": f"Stream method '{method_name}' not found on agent."},
                status_code=400,
            )

        principal = resolve_request_principal(
            request, str(input_kwargs.get("user_id") or "")
        )
        if principal.user_id:
            input_kwargs = {**input_kwargs, "user_id": principal.user_id}

        try:
            inspect.signature(runtime_agent.async_stream_query).bind(**input_kwargs)
        except TypeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        async def _ndjson_generator() -> AsyncIterator[str]:
            # Execute via async_stream_query when running inside FastAPI's event loop
            v_tok = principal_verified_context.set(principal.verified)
            try:
                async for chunk in runtime_agent.async_stream_query(**input_kwargs):
                    yield json.dumps(jsonable_encoder(chunk)) + "\n"
            finally:
                principal_verified_context.reset(v_tok)

        return StreamingResponse(
            _ndjson_generator(),
            media_type="application/json",
        )

    return router


def create_geap_runtime_app(
    agent: GovernedFinancialAdvisorGeapApp | None = None,
) -> FastAPI:
    """Build a standalone FastAPI application satisfying the GEAP Runtime Contract."""
    runtime_agent = agent or GovernedFinancialAdvisorGeapApp()
    app = FastAPI(title="CAGE Governed Financial Advisor — GEAP Agent Runtime")
    app.include_router(create_geap_runtime_router(runtime_agent))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "runtime": "geap"}

    return app


# Canonical GEAP `PythonSpec.entrypointObject` instance (`set_up()` runs on the
# remote GEAP Agent Runtime container, not during `__init__`).
root_agent = GovernedFinancialAdvisorGeapApp()
