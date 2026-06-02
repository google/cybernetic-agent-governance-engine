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

"""
Inference Proxy (Phase 3.1)
============================
Dedicated module for routing ``/v1/chat/completions`` to the appropriate
vLLM reasoning or governance node.  Contains no MCP tool definitions or
governance middleware logic.

Governance pipeline applied here:
  1. Tier-1 Aho-Corasick keyword scan on last user message.
  2. NeMo Guardrails input verification.
  3. ISO 42001 evidence stamps.
  4. Forward to vLLM backend.
  5. Output scanning / PII masking via NeMo before returning.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace
from pydantic import BaseModel, Field

from src.gateway.governance.safety import ac_keyword_scan
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.nemo.manager import verify_input, verify_and_mask_output
from src.governed_financial_advisor.infrastructure.config_manager import config_manager
from src.governed_financial_advisor.utils.privacy import scrub_pii

# ---------------------------------------------------------------------------
# SymbolicGovernor singleton — imported lazily to avoid circular imports.
# Used to call pre_check() before NeMo rails so actions receive pre-computed
# STPA/CBF results via context instead of calling back into the governor.
# ---------------------------------------------------------------------------
_symbolic_governor = None


def _get_symbolic_governor():
    """Return the SymbolicGovernor singleton, or None if unavailable."""
    global _symbolic_governor
    if _symbolic_governor is None:
        try:
            from src.gateway.governance.singletons import symbolic_governor
            _symbolic_governor = symbolic_governor
        except Exception as exc:
            logger.warning(
                "⚠️ InferenceProxy: Could not import symbolic_governor (%s) — "
                "NeMo actions will use fail-open defaults.", exc
            )
    return _symbolic_governor

logger = logging.getLogger("Gateway.InferenceProxy")

inference_app = FastAPI(title="CAGE Inference Proxy")

# ---------------------------------------------------------------------------
# Module-level pooled httpx client (R-06 fix — connection pooling)
# ---------------------------------------------------------------------------
# A single AsyncClient is reused across all requests, enabling HTTP/1.1
# keep-alive and connection pooling to vLLM backends.  The client is
# initialised lazily on first use and lives for the process lifetime.
_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    """Return (or lazily create) the shared pooled httpx.AsyncClient."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
                keepalive_expiry=30,
            ),
            timeout=httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0),
        )
    return _http_client


@inference_app.on_event("shutdown")
async def _shutdown_http_client() -> None:
    """Close the shared httpx client on app shutdown."""
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()
        _http_client = None


async def _stream_vllm(
    target_url: str,
    body: Dict[str, Any],
    api_key: str,
    span: Any = None,
    request_start_ns: int = 0,
) -> AsyncIterator[bytes]:
    """Proxy a streaming SSE response from vLLM to the client verbatim.

    When *span* and *request_start_ns* are provided, captures the time-to-
    first-token (TTFT) on the first non-empty chunk and records it on the span
    as ``gen_ai.ttft_ms`` and ``gen_ai.completion_start_time``.
    """
    client = _get_http_client()
    _ttft_recorded = False
    async with client.stream(
        "POST",
        target_url,
        json=body,
        headers={"Authorization": f"Bearer {api_key}"},
    ) as resp:
        if resp.status_code >= 400:
            error_body = await resp.aread()
            logger.error("vLLM streaming backend returned %s", resp.status_code)
            # Emit a single SSE error event so the client can surface it
            yield (
                f"data: {{\"error\": \"vLLM backend error {resp.status_code}\", "
                f"\"detail\": {json.dumps(error_body.decode(errors='replace'))}}}\n\n"
            ).encode()
            return
        async for chunk in resp.aiter_bytes():
            if chunk:
                # ── TTFT capture ───────────────────────────────────────
                # Record TTFT on the first non-empty chunk from vLLM.
                # This is the time from request ingress to first token delivered.
                if not _ttft_recorded and span is not None and span.is_recording():
                    now_ns = time.perf_counter_ns()
                    ttft_ms = (now_ns - request_start_ns) / 1_000_000
                    completion_start_iso = datetime.now(timezone.utc).isoformat()
                    span.set_attribute("gen_ai.ttft_ms", round(ttft_ms, 2))
                    span.set_attribute("gen_ai.completion_start_time", completion_start_iso)
                    logger.debug(
                        "⚡ TTFT captured: %.1fms (streaming, model=%s)",
                        ttft_ms, body.get("model", "unknown"),
                    )
                    _ttft_recorded = True
                yield chunk


def _resolve_backend_url(model_id: str) -> str:
    """Select the appropriate vLLM endpoint based on model identifier."""
    base = config_manager.get("VLLM_BASE_URL", "http://localhost:8000/v1")
    if "deepseek" in model_id.lower() or "reasoning" in model_id.lower():
        return config_manager.get("VLLM_REASONING_API_BASE", base)
    return config_manager.get("VLLM_FAST_API_BASE", base)


def _create_blocked_response(reason: str) -> Dict[str, Any]:
    import time
    ts = int(time.time())
    return {
        "id": f"chatcmpl-{ts}",
        "object": "chat.completion",
        "created": ts,
        "model": "nemo-guardrails",
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": f"I cannot fulfill this request due to security policies: {reason}",
            },
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


@inference_app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    """OpenAI-compatible governed inference endpoint."""
    from src.gateway.governance.nemo.manager import initialize_rails as _init_rails

    # Rails are initialised externally at startup and stored on app.state.
    # Fall back to on-demand init if not set (e.g. during testing).
    rails = getattr(request.app.state, "nemo_rails", None)
    if rails is None:
        rails = _init_rails()

    body = await request.json()
    requested_model = body.get("model", "default")
    model_id = os.getenv("MODEL_FAST", "default") if requested_model == "default" else requested_model
    body["model"] = model_id
    messages = body.get("messages", [])

    logger.info("Chat Request: Model=%s (requested: %s)", model_id, requested_model)

    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("inference_proxy.chat") as span:
        request_start_ns = time.perf_counter_ns()
        # Attach GenAI tracking
        if span.is_recording():
            safe_messages = [
                {**m, "content": scrub_pii(m.get("content", ""))}
                if isinstance(m.get("content"), str) else m
                for m in messages
            ]
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("gen_ai.system", "cage-inference-proxy")
            span.set_attribute("gen_ai.request.model", model_id)
            span.set_attribute("gen_ai.input.messages", json.dumps(safe_messages))
            span.set_attribute("gen_ai.request.streaming", body.get("stream", False) is True)

        last_user_msg = next(
            (m.get("content", "") for m in reversed(messages)
             if m.get("role") == "user" and m.get("content")),
            "",
        )

        if last_user_msg:
            # 1. Tier-1 keyword scan
            if ac_keyword_scan(last_user_msg):
                stamp_iso_control(span, tier=1, control="A.5.2", outcome="BLOCK")
                blocked = _create_blocked_response("Tier-1 keyword match")
                return JSONResponse(content=blocked, status_code=403)
            stamp_iso_control(span, tier=1, control="A.5.2", outcome="PASS")

            # 2. NeMo input verification — with pre-check injection
            # Call pre_check() once here so NeMo actions read pre-computed
            # STPA/CBF results from context instead of calling back into the
            # governor (breaks the re-entrant dependency loop).
            pre_check_results: Optional[dict] = None
            governor = _get_symbolic_governor()
            if governor is not None:
                # Extract governance params from the request body
                governance_params = {
                    k: body[k]
                    for k in (
                        "approval_token", "amount", "symbol", "latency_ms",
                        "drawdown_pct", "order_size", "daily_vol",
                        "confidence", "risk_assessed", "compliance_checked",
                    )
                    if k in body
                }
                try:
                    pre_check_results = await governor.pre_check(governance_params)
                    logger.debug(
                        "🔍 InferenceProxy: pre_check complete "
                        "(stpa_allowed=%s, cbf_allowed=%s)",
                        pre_check_results.get("stpa_result", {}).get("allowed", "?"),
                        pre_check_results.get("cbf_result", {}).get("allowed", "?"),
                    )
                except Exception as pre_exc:
                    logger.warning(
                        "⚠️ InferenceProxy: pre_check failed (%s) — "
                        "NeMo actions will use fail-open defaults.", pre_exc
                    )
            nemo_result = await verify_input(rails, last_user_msg, pre_check_results=pre_check_results)
            if not nemo_result.is_safe:
                stamp_iso_control(span, tier=3, control="A.6.1.2", outcome="BLOCK")
                blocked = _create_blocked_response(nemo_result.reason)
                return JSONResponse(content=blocked, status_code=403)
            stamp_iso_control(span, tier=3, control="A.6.1.2", outcome="PASS")

        # 3. Forward to vLLM (R-06 fix — pooled client, streaming support)
        api_base = _resolve_backend_url(model_id)
        api_key = config_manager.get("VLLM_API_KEY") or "EMPTY"
        target_url = f"{api_base.rstrip('/')}/chat/completions"
        client = _get_http_client()

        # Respect the caller's streaming preference.  When stream=True the
        # response is proxied byte-for-byte as an SSE stream so the frontend
        # receives real-time tokens.
        want_stream: bool = body.get("stream", False) is True

        if want_stream:
            stamp_iso_control(span, tier=4, control="A.5.3", outcome="STREAM")
            logger.info("Streaming response: model=%s", model_id)
            return StreamingResponse(
                _stream_vllm(target_url, body, api_key, span=span, request_start_ns=request_start_ns),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                },
            )

        # Non-streaming path — full response buffered before output filtering.
        try:
            resp = await client.post(
                target_url,
                json=body,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code >= 400:
                logger.error("vLLM backend returned %s: %s", resp.status_code, resp.text[:200])
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=resp.json() if resp.text else {"error": "vLLM backend error"},
                )
            vllm_response = resp.json()
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("vLLM Proxy Error: %s", exc)
            raise HTTPException(status_code=500, detail=f"LLM backend connection error: {exc}")

        # 4. Output filtering / PII masking
        if "choices" in vllm_response and vllm_response["choices"]:
            choice = vllm_response["choices"][0]
            message = choice.get("message", {})

            if choice.get("finish_reason") == "tool_calls" or "tool_calls" in message:
                for tool_call in message.get("tool_calls", []):
                    if "function" in tool_call and "arguments" in tool_call["function"]:
                        raw_args = tool_call["function"]["arguments"]
                        if raw_args:
                            safe_args = await verify_and_mask_output(rails, raw_args)
                            tool_call["function"]["arguments"] = (
                                safe_args.strip() if isinstance(safe_args, str) else str(safe_args)
                            )
            elif message.get("content"):
                safe_content = await verify_and_mask_output(rails, message["content"])
                message["content"] = safe_content

        if span.is_recording():
            choice_msg = vllm_response.get("choices", [{}])[0].get("message", {})
            safe_choice = {**choice_msg}
            if "content" in safe_choice and isinstance(safe_choice["content"], str):
                safe_choice["content"] = scrub_pii(safe_choice["content"])
            span.set_attribute("gen_ai.output.messages", json.dumps([safe_choice]))
            span.set_attribute("gen_ai.response.model", vllm_response.get("model", model_id))

        return JSONResponse(content=vllm_response)
