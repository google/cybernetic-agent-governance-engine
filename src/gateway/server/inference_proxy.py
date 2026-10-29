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
  1. Ingress Stage 1 Aho-Corasick keyword scan on ALL messages (not just user role).
  2. Token Quota Enforcement (ISO 42001 Annex A.4) — CTRL_TQP_007.
  3. NeMo Guardrails input verification on ALL messages, when semantic rails
     are on. When ``semantic_rails_refusal()`` reports them off, no input rail
     runs: A.6.1.2 is stamped ``SKIPPED`` with the reason code, and no rails
     are built on demand.
  4. ISO 42001 evidence stamps.
  5. Forward to vLLM backend.
  6. Output scanning / PII masking before returning: the NeMo output rail
     when semantic rails are on (it applies ``scrub_pii()`` first), else the
     same deterministic ``scrub_pii()`` pass alone.
     For streaming: collect full response, filter, then return.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
import uuid as _uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace

from src.gateway.governance.inference_backend import (
    INFERENCE_BACKEND_NONE,
    INFERENCE_BACKEND_URL_MISSING,
    InferenceBackendUnavailable,
    inference_disabled,
)
from src.gateway.governance.iso_control import stamp_iso_control
from src.gateway.governance.text_filter import ac_keyword_scan
from src.gateway.governance.token_quota_proxy import _get_token_quota_proxy
from src.gateway.governance.uca_logger import _get_uca_logger
from src.gateway.infrastructure.config_manager import config_manager
from src.gateway.infrastructure.privacy import scrub_pii

logger = logging.getLogger("Gateway.InferenceProxy")

inference_app = FastAPI(title="CAGE Inference Proxy")


def _safe_error_response(exc: Exception, status_code: int = 500) -> dict:
    """Return a sanitized error response with correlation ID.

    Log full details server-side so operators can trace the issue without
    exposing raw exception messages (including stack traces) to API callers.
    """
    correlation_id = str(_uuid.uuid4())
    logger.error("Request failed [correlation_id=%s]", correlation_id, exc_info=exc)
    return {"error": "Internal server error", "correlation_id": correlation_id}


# ---------------------------------------------------------------------------
# Module-level pooled httpx client (R-06 fix — connection pooling)
# ---------------------------------------------------------------------------
# A single AsyncClient is reused across all requests, enabling HTTP/1.1
# keep-alive and connection pooling to vLLM backends.  The client is
# initialised lazily on first use and lives for the process lifetime.
_http_client: httpx.AsyncClient | None = None
_http_client_loop: asyncio.AbstractEventLoop | None = None


def _get_http_client() -> httpx.AsyncClient:
    """Return (or lazily create) the shared pooled httpx.AsyncClient."""
    global _http_client, _http_client_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if (
        _http_client is None
        or _http_client.is_closed
        or (_http_client_loop is not None and _http_client_loop != current_loop)
        or (_http_client_loop is not None and _http_client_loop.is_closed())
    ):
        _http_client_loop = current_loop
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
    global _http_client, _http_client_loop
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()
    _http_client = None
    _http_client_loop = None


async def _stream_vllm(
    target_url: str,
    body: dict[str, Any],
    api_key: str,
    span: Any = None,
    request_start_ns: int = 0,
) -> AsyncIterator[bytes]:
    """Proxy a streaming SSE response from vLLM to the client verbatim.

    When *span* and *request_start_ns* are provided, captures the time-to-
    first-token (TTFT) on the first non-empty chunk and records it on the span
    as ``gen_ai.ttft_ms`` and ``gen_ai.completion_start_time``.
    """
    raw_client = _get_http_client()
    client = await raw_client if inspect.isawaitable(raw_client) else raw_client
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
                f'data: {{"error": "vLLM backend error {resp.status_code}", '
                f'"detail": {json.dumps(error_body.decode(errors="replace"))}}}\n\n'
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
                    span.set_attribute(
                        "gen_ai.completion_start_time", completion_start_iso
                    )
                    logger.debug(
                        "⚡ TTFT captured: %.1fms (streaming, model=%s)",
                        ttft_ms,
                        body.get("model", "unknown"),
                    )
                    _ttft_recorded = True
                yield chunk


def _resolve_backend_url(model_id: str) -> str:
    """Select the vLLM endpoint for *model_id*.

    There is no default URL: a missing endpoint raises instead of
    reaching for ``localhost``.

    Raises:
        InferenceBackendUnavailable: ``INFERENCE_BACKEND_URL_MISSING`` when
            no endpoint is configured for the model.
    """
    base = config_manager.get("VLLM_BASE_URL")
    if "deepseek" in model_id.lower() or "reasoning" in model_id.lower():
        url = config_manager.get("VLLM_REASONING_API_BASE", base)
    else:
        url = config_manager.get("VLLM_FAST_API_BASE", base)
    if not url:
        raise InferenceBackendUnavailable(
            INFERENCE_BACKEND_URL_MISSING,
            "no inference endpoint is configured (VLLM_BASE_URL is unset).",
        )
    return url


def _backend_unavailable_response(reason_code: str, message: str) -> JSONResponse:
    """Return the 503 for a request no model can serve."""
    return JSONResponse(
        status_code=503,
        content={
            "error": "inference_backend_unavailable",
            "reason_code": reason_code,
            "message": message,
        },
    )


def _create_blocked_response(reason: str) -> dict[str, Any]:
    import time

    ts = int(time.time())
    return {
        "id": f"chatcmpl-{ts}",
        "object": "chat.completion",
        "created": ts,
        "model": "nemo-guardrails",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": f"I cannot fulfill this request due to security policies: {reason}",
                },
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


async def _mask_output(rails: Any, text: str) -> str:
    """Mask *text* before it leaves the proxy.

    With semantic rails on, the NeMo output rail runs. It applies
    ``scrub_pii()`` first and its LLM rail after. With them off (``rails`` is
    ``None``), only the deterministic ``scrub_pii()`` pass runs and no model
    is called.
    """
    if rails is None:
        return scrub_pii(text)
    from src.gateway.governance.semantic_rail_factory import (
        verify_and_mask_semantic_output,
    )

    return await verify_and_mask_semantic_output(rails, text)


@inference_app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """OpenAI-compatible governed inference endpoint."""
    from src.gateway.governance.semantic_rail_factory import (
        initialize_semantic_rails as _init_rails,
    )
    from src.gateway.governance.semantic_rail_factory import (
        semantic_rails_refusal,
    )
    from src.gateway.governance.semantic_rail_factory import (
        verify_semantic_input as verify_input,
    )

    # No model by design (CAGE_INFERENCE_BACKEND=none): refuse before
    # building rails or reading the request, with a reason code.
    if inference_disabled():
        return _backend_unavailable_response(
            INFERENCE_BACKEND_NONE,
            "No inference backend is configured (CAGE_INFERENCE_BACKEND=none).",
        )

    # Semantic rails run only when semantic_rails_refusal() allows them. Gateway
    # startup checks the same predicate, so this request path cannot build
    # rails the configuration turned off. When they are off, ``rails`` stays
    # None and the proxy runs deterministic-only (steps 4 and 6).
    rails_refusal = semantic_rails_refusal()
    rails: Any = None
    if rails_refusal is None:
        # Rails are initialised at startup and stored on app.state. Fall back
        # to on-demand init if not set (e.g. during testing).
        rails = getattr(request.app.state, "nemo_rails", None)
        if rails is None:
            rails = _init_rails()

    body = await request.json()
    requested_model = body.get("model", "default")
    model_id = (
        os.getenv("MODEL_FAST", "default")
        if requested_model == "default"
        else requested_model
    )
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
                if isinstance(m.get("content"), str)
                else m
                for m in messages
            ]
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("gen_ai.system", "cage-inference-proxy")
            span.set_attribute("gen_ai.request.model", model_id)
            span.set_attribute("gen_ai.input.messages", json.dumps(safe_messages))
            span.set_attribute(
                "gen_ai.request.streaming", body.get("stream", False) is True
            )

        # Extract the last user message for NeMo context (used as the primary
        # input text for NeMo rails, which expect a single string).
        # ALL governance checks run regardless of whether a user message exists —
        # system-only, assistant-only, and mixed message sets are all governed.
        last_user_msg = next(
            (
                m.get("content", "")
                for m in reversed(messages)
                if m.get("role") == "user" and m.get("content")
            ),
            "",
        )

        # Build a combined text representation of ALL messages for Ingress Stage 1 scan.
        # This prevents system-only or assistant-only requests from bypassing
        # the keyword filter (GHSA-hfqj-24cj-693g).
        all_messages_text = " ".join(
            m.get("content", "") for m in messages if isinstance(m.get("content"), str)
        )

        # 1. Ingress Stage 1 keyword scan — applied to ALL messages, not just user role.
        if ac_keyword_scan(all_messages_text):
            stamp_iso_control(span, ingress_stage=1, control="A.5.2", outcome="BLOCK")
            blocked = _create_blocked_response("Ingress Stage 1 keyword match")
            return JSONResponse(content=blocked, status_code=403)
        stamp_iso_control(span, ingress_stage=1, control="A.5.2", outcome="PASS")

        # ── Step 2: Agent Identity Extraction (SC-8 / POAM-2026-080) ──
        # Extract verified Linkerd workload identity from l5d-client-id header.
        # Requests without a verified identity fail closed (401).
        try:
            from src.gateway.server.workload_identity import extract_client_identity

            agent_id = extract_client_identity(request.scope)
        except Exception as identity_exc:
            logger.error(
                "Failed to extract workload identity from l5d-client-id: %s — failing closed",
                identity_exc,
            )
            stamp_iso_control(span, ingress_stage=0, control="SC-8", outcome="BLOCK")
            return JSONResponse(
                content={
                    "error": "authentication_required",
                    "message": "Verified Linkerd workload identity (l5d-client-id) required",
                    "detail": str(identity_exc),
                },
                status_code=401,
            )

        # ── Step 2.5: Out-of-Band Quarantine Enforcement (SC-7 / AC-3) ──
        from src.gateway.governance.quarantine_actuator import is_workload_quarantined

        request_thread_id = body.get("thread_id") or request.headers.get(
            "x-cage-thread-id"
        )
        app_state = getattr(getattr(request, "app", None), "state", None)
        shared_redis = getattr(app_state, "redis", None)
        if await is_workload_quarantined(
            thread_id=str(request_thread_id) if request_thread_id else None,
            agent_svid=agent_id,
            redis_client=shared_redis,
        ):
            stamp_iso_control(span, ingress_stage=1, control="SC-7", outcome="BLOCK")
            return JSONResponse(
                content={
                    "error": "workload_quarantined",
                    "message": "Workload SVID or thread is quarantined by CAGE out-of-band governance",
                    "agent_id": agent_id,
                    "thread_id": request_thread_id,
                },
                status_code=403,
            )

        # ── Step 3: Token Quota Enforcement (ISO 42001 Annex A.4) ──
        # Runs for ALL requests regardless of message role composition.
        raw_max_tokens = body.get("max_tokens")
        if raw_max_tokens is None:
            token_delta = 0
        elif isinstance(raw_max_tokens, bool) or not isinstance(
            raw_max_tokens, (int, float, str)
        ):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request_error",
                    "message": "max_tokens must be a non-negative integer",
                },
            )
        else:
            try:
                parsed_max_tokens = int(raw_max_tokens)
            except (TypeError, ValueError, OverflowError) as exc:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request_error",
                        "message": "max_tokens must be a non-negative integer",
                    },
                ) from exc
            if parsed_max_tokens < 0:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request_error",
                        "message": "max_tokens must be non-negative",
                    },
                )
            token_delta = parsed_max_tokens

        quota_result = await _get_token_quota_proxy().check_and_increment(
            agent_id=agent_id,
            token_delta=token_delta,
        )
        if not quota_result.allowed:
            stamp_iso_control(span, ingress_stage=2, control="A.4", outcome="BLOCK")
            # Awaited inline — WORM write must complete before 429 is
            # returned to guarantee ISO 42001 Clause 6.1 audit lineage
            # survives spot-instance eviction.
            await _get_uca_logger().log_quota_exceeded(quota_result, body)
            return JSONResponse(
                content={
                    "error": "quota_exceeded",
                    "reason": quota_result.block_reason,
                    "step_count": quota_result.step_count,
                    "accumulated_tokens": quota_result.accumulated_tokens,
                    "quota_max_steps": quota_result.step_quota_max,
                    "quota_max_tokens": quota_result.token_quota_max,
                    "agent_id": agent_id,
                    "iso42001_control": "A.4",
                    "dge_action": "TERMINATED_WITH_ROLLBACK",
                },
                status_code=429,
            )
        stamp_iso_control(span, ingress_stage=2, control="A.4", outcome="PASS")

        # 4. NeMo input verification — runs for ALL requests while semantic
        # rails are on. Uses the full message list; falls back to last_user_msg
        # for NeMo rails that expect a single string (NeMo context is the last
        # user msg or a concatenation of all messages when no user message
        # exists). With rails off no input rail runs, and the evidence records
        # SKIPPED with the reason code instead of a PASS that never happened.
        # Steps 4-7 are wrapped in a try/except so that any downstream
        # failure triggers a quota rollback (CTRL_TQP_007 §5.3).
        nemo_input_text = last_user_msg if last_user_msg else all_messages_text
        try:
            if rails_refusal is not None:
                # Off by configuration. An enabled-but-absent rail (rails
                # None, refusal None) takes the else branch, where
                # verify_input(None, ...) blocks with RAILS_UNAVAILABLE.
                stamp_iso_control(
                    span, ingress_stage=3, control="A.6.1.2", outcome="SKIPPED"
                )
                span.set_attribute("cage.content_safety.reason_code", rails_refusal[0])
            else:
                nemo_result = await verify_input(rails, nemo_input_text)
                if not nemo_result.is_safe:
                    stamp_iso_control(
                        span, ingress_stage=3, control="A.6.1.2", outcome="BLOCK"
                    )
                    blocked = _create_blocked_response(nemo_result.reason)
                    return JSONResponse(content=blocked, status_code=403)
                stamp_iso_control(
                    span, ingress_stage=3, control="A.6.1.2", outcome="PASS"
                )

            # 5. Forward to vLLM (R-06 fix — pooled client, streaming support)
            api_base = _resolve_backend_url(model_id)
            api_key = config_manager.get("VLLM_API_KEY") or "EMPTY"
            target_url = f"{api_base.rstrip('/')}/chat/completions"
            raw_client = _get_http_client()
            client = await raw_client if inspect.isawaitable(raw_client) else raw_client
        except InferenceBackendUnavailable as exc:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            logger.error("Inference proxy cannot forward: %s", exc)
            return _backend_unavailable_response(exc.reason_code, str(exc))
        except Exception:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            raise

        # Respect the caller's streaming preference.  When stream=True the
        # response is proxied byte-for-byte as an SSE stream so the frontend
        # receives real-time tokens.
        # Use explicit truthiness check instead of identity comparison to handle
        # string "true", int 1, or bool True from various client serializers.
        stream_val = body.get("stream", False)
        want_stream: bool = (
            stream_val is True
            or stream_val == 1
            or (isinstance(stream_val, str) and stream_val.lower() == "true")
        )

        if want_stream:
            stamp_iso_control(span, ingress_stage=4, control="A.5.3", outcome="STREAM")
            logger.info("Streaming response: model=%s", model_id)
            # Collect the full streamed response so output filtering can be
            # applied before returning to the client.  Streaming responses
            # previously bypassed NeMo output filtering (GHSA-hfqj-24cj-693g).
            collected_chunks: list[bytes] = []
            try:
                async for chunk in _stream_vllm(
                    target_url,
                    body,
                    api_key,
                    span=span,
                    request_start_ns=request_start_ns,
                ):
                    collected_chunks.append(chunk)
            except HTTPException:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                raise
            except Exception as exc:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                safe_err = _safe_error_response(exc)
                raise HTTPException(status_code=500, detail=safe_err) from exc

            # Reassemble and attempt to extract the assistant content and
            # tool_calls arguments for output filtering.  SSE chunks are
            # "data: {...}\n\n" lines.
            raw_stream = b"".join(collected_chunks).decode(errors="replace")
            filtered_content: str | None = None
            streamed_tool_calls: dict[int, dict[str, str]] = {}
            stream_backend_error = False
            for line in raw_stream.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                data_str = line[len("data:") :].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk_json = json.loads(data_str)
                    if isinstance(chunk_json, dict) and str(
                        chunk_json.get("error", "")
                    ).startswith("vLLM backend error"):
                        stream_backend_error = True
                    delta_obj = chunk_json.get("choices", [{}])[0].get("delta", {})
                    delta = delta_obj.get("content", "")
                    if delta:
                        filtered_content = (filtered_content or "") + delta
                    for idx, tc in enumerate(delta_obj.get("tool_calls", []) or []):
                        if not isinstance(tc, dict):
                            continue
                        tc_idx = int(tc.get("index", idx))
                        entry = streamed_tool_calls.setdefault(
                            tc_idx,
                            {"id": "", "name": "", "arguments": ""},
                        )
                        if tc.get("id"):
                            entry["id"] = str(tc["id"])
                        fn = tc.get("function") or {}
                        if isinstance(fn, dict):
                            if fn.get("name"):
                                entry["name"] += str(fn["name"])
                            if fn.get("arguments"):
                                entry["arguments"] += str(fn["arguments"])
                except (
                    json.JSONDecodeError,
                    IndexError,
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    pass

            if stream_backend_error:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )

            try:
                # Apply NeMo output filtering to streamed tool_calls arguments
                if streamed_tool_calls:
                    tool_calls_modified = False
                    sanitized_tool_calls: list[dict[str, Any]] = []
                    for tc_idx in sorted(streamed_tool_calls):
                        tc_entry = streamed_tool_calls[tc_idx]
                        raw_args = tc_entry["arguments"]
                        safe_args_str = raw_args
                        if raw_args:
                            safe_args = await _mask_output(rails, raw_args)
                            safe_args_str = (
                                safe_args.strip()
                                if isinstance(safe_args, str)
                                else str(safe_args)
                            )
                            if safe_args_str != raw_args:
                                tool_calls_modified = True
                        sanitized_tool_calls.append(
                            {
                                "id": tc_entry["id"] or f"call-{tc_idx}",
                                "type": "function",
                                "function": {
                                    "name": tc_entry["name"],
                                    "arguments": safe_args_str,
                                },
                            }
                        )
                    if tool_calls_modified:
                        logger.info(
                            "Streaming tool_calls filtered by NeMo: model=%s", model_id
                        )
                        ts = int(time.time())
                        filtered_response = {
                            "id": f"chatcmpl-{ts}",
                            "object": "chat.completion",
                            "created": ts,
                            "model": model_id,
                            "choices": [
                                {
                                    "index": 0,
                                    "finish_reason": "tool_calls",
                                    "message": {
                                        "role": "assistant",
                                        "content": safe_content
                                        if filtered_content
                                        and (
                                            safe_content := await _mask_output(
                                                rails, filtered_content
                                            )
                                        )
                                        else filtered_content,
                                        "tool_calls": sanitized_tool_calls,
                                    },
                                }
                            ],
                            "usage": {
                                "prompt_tokens": 0,
                                "completion_tokens": 0,
                                "total_tokens": 0,
                            },
                        }
                        return JSONResponse(content=filtered_response)

                # Apply NeMo output filtering to the assembled content
                if filtered_content:
                    safe_content = await _mask_output(rails, filtered_content)
                    if safe_content != filtered_content:
                        logger.info(
                            "Streaming output filtered by NeMo: model=%s", model_id
                        )
                        # Return filtered content as a non-streaming JSON response
                        # LOW-5 fix: removed inline `import time as _time` — time is
                        # already imported at module level.
                        ts = int(time.time())
                        filtered_response = {
                            "id": f"chatcmpl-{ts}",
                            "object": "chat.completion",
                            "created": ts,
                            "model": model_id,
                            "choices": [
                                {
                                    "index": 0,
                                    "finish_reason": "stop",
                                    "message": {
                                        "role": "assistant",
                                        "content": safe_content,
                                    },
                                }
                            ],
                            "usage": {
                                "prompt_tokens": 0,
                                "completion_tokens": 0,
                                "total_tokens": 0,
                            },
                        }
                        return JSONResponse(content=filtered_response)
            except Exception:
                if not stream_backend_error:
                    await _get_token_quota_proxy().rollback_step(
                        agent_id, reserved_tokens=token_delta
                    )
                raise

            # Content passed output filtering — re-stream the collected chunks
            async def _replay_chunks() -> AsyncIterator[bytes]:
                for c in collected_chunks:
                    yield c

            return StreamingResponse(  # type: ignore[return-value]
                _replay_chunks(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                },
            )

        # Non-streaming path — full response buffered before output filtering.
        # MED-6 fix: vLLM failures now trigger quota rollback so the step counter
        # is not permanently incremented when the downstream call fails.
        try:
            resp = await client.post(
                target_url,
                json=body,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code >= 400:
                logger.error(
                    "vLLM backend returned %s: %s", resp.status_code, resp.text[:200]
                )
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=resp.json()
                    if resp.text
                    else {"error": "vLLM backend error"},
                )
            vllm_response = resp.json()
        except HTTPException:
            # MED-6 fix: roll back quota on vLLM HTTP errors (4xx/5xx).
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            raise
        except Exception as exc:
            # MED-6 fix: roll back quota on connection/timeout errors.
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            safe_err = _safe_error_response(exc)
            raise HTTPException(status_code=500, detail=safe_err)

        # 6. Output filtering / PII masking
        try:
            if vllm_response.get("choices"):
                choice = vllm_response["choices"][0]
                message = choice.get("message", {})

                if (
                    choice.get("finish_reason") == "tool_calls"
                    or "tool_calls" in message
                ):
                    for tool_call in message.get("tool_calls", []):
                        if (
                            "function" in tool_call
                            and "arguments" in tool_call["function"]
                        ):
                            raw_args = tool_call["function"]["arguments"]
                            if raw_args:
                                safe_args = await _mask_output(rails, raw_args)
                                tool_call["function"]["arguments"] = (
                                    safe_args.strip()
                                    if isinstance(safe_args, str)
                                    else str(safe_args)
                                )
                elif message.get("content"):
                    safe_content = await _mask_output(rails, message["content"])
                    message["content"] = safe_content
        except Exception:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            raise

        if span.is_recording():
            choice_msg = vllm_response.get("choices", [{}])[0].get("message", {})
            safe_choice = {**choice_msg}
            if "content" in safe_choice and isinstance(safe_choice["content"], str):
                safe_choice["content"] = scrub_pii(safe_choice["content"])
            span.set_attribute("gen_ai.output.messages", json.dumps([safe_choice]))
            span.set_attribute(
                "gen_ai.response.model", vllm_response.get("model", model_id)
            )

        return JSONResponse(content=vllm_response)
