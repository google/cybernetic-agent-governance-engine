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
import re
import time
import uuid as _uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace

from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
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
from src.gateway.observability.attributes import (
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
)

logger = logging.getLogger("Gateway.InferenceProxy")

inference_app = FastAPI(title="CAGE Inference Proxy")

_DEFAULT_MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_STREAM_BUFFER_BYTES = 16 * 1024 * 1024
_DEFAULT_RESERVED_COMPLETION_TOKENS = 1024

# WHATWG HTML §9.2.6 SSE line breaks: CRLF, CR, or LF only — NEVER Python
# str.splitlines(), which splits on U+2028 / U+2029 and breaks JSON data: framing
# (GHSA-xm4c-x85r-38fp).
_SSE_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")


def _iter_sse_data_payloads(raw_stream: str) -> list[str]:
    """Extract SSE ``data:`` payloads strictly under WHATWG CRLF/CR/LF framing."""
    payloads: list[str] = []
    event_data_lines: list[str] = []

    def _flush_event_block() -> bool:
        """Flush buffered data: lines for one SSE event; return True if [DONE] seen."""
        if not event_data_lines:
            return False
        if len(event_data_lines) == 1:
            single = event_data_lines[0].strip()
            event_data_lines.clear()
            if not single:
                return False
            if single == "[DONE]":
                return True
            payloads.append(single)
            return False

        joined = "\n".join(event_data_lines).strip()
        lines_copy = list(event_data_lines)
        event_data_lines.clear()
        if joined == "[DONE]":
            return True
        try:
            json.loads(joined)
            payloads.append(joined)
            return False
        except ValueError:
            pass

        for item in lines_copy:
            stripped = item.strip()
            if not stripped:
                continue
            if stripped == "[DONE]":
                return True
            payloads.append(stripped)
        return False

    for raw_line in _SSE_LINE_SPLIT_RE.split(raw_stream):
        if raw_line == "":
            if _flush_event_block():
                return payloads
            continue
        if raw_line.startswith(":"):
            continue
        field, sep, value = raw_line.partition(":")
        if field.strip() == "data" and sep == ":":
            if value.startswith(" "):
                value = value[1:]
            event_data_lines.append(value)

    _flush_event_block()
    return payloads


def _reject_non_finite_json(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant {token!r} is not permitted")


async def _read_validated_chat_body(
    request: Request,
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    """Read a bounded JSON object body, returning ``(body, None)`` or ``(None, error_response)``."""
    max_bytes = max(
        1024,
        int(
            os.environ.get(
                "CAGE_INFERENCE_MAX_REQUEST_BYTES",
                str(_DEFAULT_MAX_REQUEST_BODY_BYTES),
            )
        ),
    )
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            parsed_len = int(content_length)
            if parsed_len < 0:
                raise ValueError("negative content-length")
            if parsed_len > max_bytes:
                return None, JSONResponse(
                    status_code=413,
                    content={
                        "error": "payload_too_large",
                        "message": f"Request body exceeds maximum size of {max_bytes} bytes",
                    },
                )
        except ValueError:
            return None, JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request_error",
                    "message": "Invalid Content-Length header",
                },
            )

    if hasattr(request, "stream"):
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    return None, JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "message": f"Request body exceeds maximum size of {max_bytes} bytes",
                        },
                    )
                chunks.append(bytes(chunk))
            raw_bytes = b"".join(chunks)
            parsed = json.loads(
                raw_bytes.decode("utf-8"),
                parse_constant=_reject_non_finite_json,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            return None, JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request_error",
                    "message": "Malformed JSON request body",
                },
            )
    else:
        try:
            parsed = await request.json()
        except Exception:
            return None, JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request_error",
                    "message": "Malformed JSON request body",
                },
            )

    if not isinstance(parsed, dict):
        return None, JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request_error",
                "message": "Request body must be a JSON object",
            },
        )
    if "messages" in parsed and not isinstance(parsed.get("messages"), list):
        return None, JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request_error",
                "message": "messages must be a list",
            },
        )
    if (
        "stream_options" in parsed
        and parsed.get("stream_options") is not None
        and not isinstance(parsed.get("stream_options"), dict)
    ):
        return None, JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request_error",
                "message": "stream_options must be an object",
            },
        )
    return parsed, None


def _parse_strict_token_limit(body: dict[str, Any], field_name: str) -> int | None:
    """Validate an optional OpenAI token limit field as a strict non-negative int."""
    if field_name not in body or body[field_name] is None:
        return None
    raw_val = body[field_name]
    if isinstance(raw_val, bool) or not isinstance(raw_val, int) or raw_val < 0:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request_error",
                "message": f"{field_name} must be a non-negative integer",
            },
        )
    return raw_val


def _compute_token_reservation(body: dict[str, Any], scannable_prompt_text: str) -> int:
    """Compute a positive token reservation covering max_tokens / max_completion_tokens."""
    parsed_max_tokens = _parse_strict_token_limit(body, "max_tokens")
    parsed_max_completion = _parse_strict_token_limit(body, "max_completion_tokens")

    raw_n = body.get("n", 1)
    if raw_n is None:
        num_choices = 1
    elif isinstance(raw_n, bool) or not isinstance(raw_n, int) or raw_n < 1:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request_error",
                "message": "n must be a positive integer",
            },
        )
    else:
        num_choices = min(raw_n, 128)

    prompt_estimate = max(1, (len(scannable_prompt_text.encode("utf-8")) + 3) // 4)
    explicit_limits = [
        v for v in (parsed_max_tokens, parsed_max_completion) if v is not None
    ]
    if not explicit_limits:
        default_comp = max(
            1,
            int(
                os.environ.get(
                    "CAGE_DEFAULT_COMPLETION_TOKEN_RESERVATION",
                    str(_DEFAULT_RESERVED_COMPLETION_TOKENS),
                )
            ),
        )
        return prompt_estimate + (default_comp * num_choices)

    explicit_max = max(explicit_limits)
    if explicit_max == 0:
        return prompt_estimate
    return explicit_max * num_choices


async def _reconcile_actual_usage(
    agent_id: str, reserved_tokens: int, usage: Any
) -> None:
    """Reconcile reserved token quota against actual vLLM usage.total_tokens when present."""
    if not isinstance(usage, dict):
        return
    total_tokens = usage.get("total_tokens")
    if (
        isinstance(total_tokens, bool)
        or not isinstance(total_tokens, int)
        or total_tokens < 0
    ):
        return
    quota_proxy = _get_token_quota_proxy()
    reconcile_fn = getattr(quota_proxy, "reconcile_actual_tokens", None)
    if callable(reconcile_fn):
        res = reconcile_fn(agent_id, reserved_tokens, total_tokens)
        if inspect.isawaitable(res):
            await res


def _build_redacted_sse_bytes(
    *,
    stream_id: str,
    created: int,
    model_id: str,
    sanitized_choices: list[dict[str, Any]],
    usage: dict[str, Any] | None,
) -> list[bytes]:
    """Encode sanitized streaming choices as valid OpenAI chat.completion.chunk SSE frames."""
    frames: list[bytes] = []
    delta_choices: list[dict[str, Any]] = []
    finish_choices: list[dict[str, Any]] = []
    for item in sanitized_choices:
        idx = int(item["index"])
        delta_obj: dict[str, Any] = {"role": "assistant"}
        if item.get("reasoning_content") is not None:
            delta_obj["reasoning_content"] = item["reasoning_content"]
        if item.get("content") is not None:
            delta_obj["content"] = item["content"]
        if item.get("tool_calls"):
            tc_deltas: list[dict[str, Any]] = []
            for tc_pos, tc in enumerate(item["tool_calls"]):
                tc_deltas.append(
                    {
                        "index": tc_pos,
                        "id": tc["id"],
                        "type": tc.get("type", "function"),
                        "function": tc["function"],
                    }
                )
            delta_obj["tool_calls"] = tc_deltas
        delta_choices.append(
            {
                "index": idx,
                "delta": delta_obj,
                "finish_reason": None,
            }
        )
        finish_choices.append(
            {
                "index": idx,
                "delta": {},
                "finish_reason": item.get("finish_reason") or "stop",
            }
        )

    content_chunk: dict[str, Any] = {
        "id": stream_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model_id,
        "choices": delta_choices,
    }
    frames.append(f"data: {json.dumps(content_chunk)}\n\n".encode())

    finish_chunk: dict[str, Any] = {
        "id": stream_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model_id,
        "choices": finish_choices,
    }
    if isinstance(usage, dict):
        finish_chunk["usage"] = usage
    frames.append(f"data: {json.dumps(finish_chunk)}\n\n".encode())
    frames.append(b"data: [DONE]\n\n")
    return frames


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


def _map_upstream_error_status(upstream_status: int) -> int:
    """Map an upstream inference HTTP error to a gateway HTTP status code (F-15).

    Upstream 4xx responses (especially 401, 403, 429) must never be passed
    through verbatim as the gateway's own authentication, governance refusal,
    or token-quota status codes; they are mapped to 502 Bad Gateway.
    Server-side upstream 5xx codes in {500, 502, 503, 504} are preserved, and
    all other statuses default to 502.
    """
    if upstream_status in {500, 502, 503, 504}:
        return upstream_status
    return 502


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
            correlation_id = str(_uuid.uuid4())
            logger.error(
                "vLLM streaming backend returned %s [correlation_id=%s]: %s",
                resp.status_code,
                correlation_id,
                scrub_pii(error_body.decode(errors="replace")[:200]),
            )
            err_event = {
                "error": f"vLLM backend error {resp.status_code}",
                "status_code": int(resp.status_code),
                "correlation_id": correlation_id,
            }
            yield f"data: {json.dumps(err_event)}\n\n".encode()
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
    configured_reasoning = (
        config_manager.get("MODEL_REASONING")
        or config_manager.get("VLLM_REASONING_MODEL")
        or ""
    ).strip()
    is_reasoning_model = (
        "deepseek" in model_id.lower()
        or "reasoning" in model_id.lower()
        or (bool(configured_reasoning) and model_id == configured_reasoning)
    )
    if is_reasoning_model:
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


def _evidence_unavailable_response(exc: EvidenceChainUnavailableError) -> JSONResponse:
    """Return the 503 for a refusal whose evidence could not be committed."""
    return JSONResponse(
        status_code=503,
        content={"error": "evidence_chain_unavailable", "detail": str(exc)},
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


async def _mask_json_value(rails: Any, value: Any) -> tuple[Any, bool]:
    """Mask only ``str`` leaves inside parsed JSON so structure/numbers survive."""
    if isinstance(value, str):
        masked = await _mask_output(rails, value)
        masked_str = masked if isinstance(masked, str) else str(masked)
        return masked_str, masked_str != value
    if isinstance(value, list):
        modified = False
        out_list: list[Any] = []
        for item in value:
            new_item, item_mod = await _mask_json_value(rails, item)
            out_list.append(new_item)
            modified = modified or item_mod
        return out_list, modified
    if isinstance(value, dict):
        modified = False
        out_dict: dict[str, Any] = {}
        for key, item in value.items():
            new_item, item_mod = await _mask_json_value(rails, item)
            out_dict[str(key)] = new_item
            modified = modified or item_mod
        return out_dict, modified
    return value, False


async def _mask_tool_arguments(rails: Any, raw_args: str) -> tuple[str, bool]:
    """Sanitize ``tool_calls[].function.arguments`` without corrupting JSON numbers.

    ``scrub_pii`` replaces bare 9-to-16-digit sequences with unquoted tokens
    such as ``[REDACTED-PHONE-UCA-3]``, which breaks valid JSON numeric fields
    when applied to raw JSON text. Parsing first restricts masking to string
    leaves while keeping numeric, boolean, and structural tokens valid JSON.
    """
    try:
        parsed = json.loads(raw_args)
    except (json.JSONDecodeError, TypeError):
        masked = await _mask_output(rails, raw_args)
        masked_str = masked.strip() if isinstance(masked, str) else str(masked)
        return masked_str, masked_str != raw_args

    sanitized, modified = await _mask_json_value(rails, parsed)
    if not modified:
        return raw_args, False
    return json.dumps(sanitized), True


def _extract_message_content_text(content: Any) -> str:
    """Extract text from an OpenAI string, multi-part content array, or structured value."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                text_val = part.get("text")
                if isinstance(text_val, str) and text_val:
                    parts.append(text_val)
                input_text_val = part.get("input_text")
                if (
                    isinstance(input_text_val, str)
                    and input_text_val
                    and input_text_val != text_val
                ):
                    parts.append(input_text_val)
            elif isinstance(part, str) and part:
                parts.append(part)
        return " ".join(parts)
    return json.dumps(content, default=str)


def _extract_scannable_messages_text(messages: Any) -> str:
    """Collect all scannable text from messages and assistant tool_calls."""
    if not isinstance(messages, list):
        return ""
    fragments: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        text = _extract_message_content_text(msg.get("content"))
        if text:
            fragments.append(text)
        reasoning_text = _extract_message_content_text(msg.get("reasoning_content"))
        if reasoning_text:
            fragments.append(reasoning_text)
        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function")
                if isinstance(fn, dict):
                    if isinstance(fn.get("name"), str):
                        fragments.append(fn["name"])
                    if isinstance(fn.get("arguments"), str):
                        fragments.append(fn["arguments"])
    return " ".join(fragments)


def _resolve_proxy_trace_id(request: Request, body: Any, span: Any) -> str:
    """Guarantee a non-empty trace_id for cage-audit/3.0 DDL compliance."""
    try:
        span_ctx = span.get_span_context() if span is not None else None
        if span_ctx is not None and getattr(span_ctx, "is_valid", False):
            trace_int = int(getattr(span_ctx, "trace_id", 0) or 0)
            if trace_int > 0:
                return f"{trace_int:032x}"
    except Exception:
        pass
    hdr = request.headers.get("x-cage-trace-id")
    if hdr and hdr.strip():
        return hdr.strip()
    if isinstance(body, dict):
        raw = body.get("trace_id") or body.get("thread_id")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return str(_uuid.uuid4())


async def _emit_proxy_evidence(
    request: Request,
    *,
    span: Any,
    body: Any,
    event_type: str,
    control_id: str,
    status_code: int,
    reason: str,
    model_id: str,
    agent_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Commit a fail-closed inference-proxy refusal to ``cage_evidence``.

    Routes through :func:`commit_decision_evidence` so that when
    :func:`is_evidence_chain_blocking` is ``True``, a missing, stopped, or
    failing evidence sink raises :class:`EvidenceChainUnavailableError`
    instead of returning an un-evidenced 403/429 refusal.
    """
    from src.gateway.governance.evidence.stream import (
        commit_decision_evidence,
        get_evidence_sink,
        is_evidence_chain_blocking,
    )
    from src.gateway.governance.governor.metrics import (
        governor_metrics,
        mark_request_evidenced,
    )

    mark_request_evidenced()
    blocking = is_evidence_chain_blocking()
    sink = get_evidence_sink()
    if not blocking and (sink is None or not getattr(sink, "_running", False)):
        return

    event: dict[str, Any] = {
        "type": event_type,
        "control_id": control_id,
        "trace_id": _resolve_proxy_trace_id(request, body, span),
        "decision": "DENY",
        "surface": "inference_proxy",
        "status_code": status_code,
        "model": model_id,
        "reason": scrub_pii(reason),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if agent_id:
        event["agent_id"] = agent_id
    if extra:
        event.update(extra)

    try:
        if blocking:
            await commit_decision_evidence(
                event,
                label=event_type,
                sink=sink,
                sentinel_unset=False,
            )
        else:
            ingest_res = sink.ingest(event)
            if inspect.isawaitable(ingest_res):
                await ingest_res
    except EvidenceChainUnavailableError:
        governor_metrics().evidence_publish_failure("inference_proxy_refusal")
        logger.error(
            "Inference proxy evidence emission failed closed (control=%s)",
            control_id,
        )
        if blocking:
            raise
    except Exception as exc:
        governor_metrics().evidence_publish_failure("inference_proxy_refusal")
        logger.error(
            "Inference proxy evidence emission failed (control=%s): %s",
            control_id,
            exc,
        )
        if blocking:
            raise EvidenceChainUnavailableError(
                f"Evidence sink failed to commit {event_type}: {exc}", exc
            ) from exc


async def _emit_proxy_pass_evidence(
    request: Request,
    *,
    span: Any,
    body: Any,
    model_id: str,
    agent_id: str | None = None,
    pii_redacted: bool = False,
) -> None:
    """Commit hash-chained A.5.2 (Stage 1) and A.9.2 (Stage 4 PII) pass records.

    When :func:`is_evidence_chain_blocking` is ``True``, routes both pass
    records through :func:`commit_decision_evidence` so a missing, stopped,
    disconnected, or corrupt evidence sink raises
    :class:`EvidenceChainUnavailableError` (HTTP ``503``) before any completion
    bytes are returned to the caller (POAM-2026-217).
    """
    from src.gateway.governance.evidence.stream import (
        commit_decision_evidence,
        get_evidence_sink,
        is_evidence_chain_blocking,
    )
    from src.gateway.governance.governor.metrics import (
        governor_metrics,
        mark_request_evidenced,
    )

    mark_request_evidenced()
    blocking = is_evidence_chain_blocking()
    sink = get_evidence_sink()
    if not blocking and (sink is None or not getattr(sink, "_running", False)):
        return

    trace_id = _resolve_proxy_trace_id(request, body, span)
    now_iso = datetime.now(timezone.utc).isoformat()
    stage1_event: dict[str, Any] = {
        "type": "INFERENCE_PROXY_STAGE1_PASS",
        "control_id": "A.5.2",
        "trace_id": trace_id,
        "decision": "PASS",
        "surface": "inference_proxy",
        "status_code": 200,
        "model": model_id,
        "reason": "Ingress Stage 1 keyword scan clean",
        "timestamp": now_iso,
    }
    pii_event: dict[str, Any] = {
        "type": "INFERENCE_PROXY_PII_SCRUB_PASS",
        "control_id": "A.9.2",
        "trace_id": trace_id,
        "decision": "PASS",
        "surface": "inference_proxy",
        "status_code": 200,
        "model": model_id,
        "pii_redacted": bool(pii_redacted),
        "reason": "Stage 4 output PII sanitization verified",
        "timestamp": now_iso,
    }
    if agent_id:
        stage1_event["agent_id"] = agent_id
        pii_event["agent_id"] = agent_id

    for ev in (stage1_event, pii_event):
        try:
            if blocking:
                await commit_decision_evidence(
                    ev,
                    label=str(ev["type"]),
                    sink=sink,
                    sentinel_unset=False,
                )
            else:
                ingest_res = sink.ingest(ev)
                msg_id = (
                    await ingest_res if inspect.isawaitable(ingest_res) else ingest_res
                )
                if msg_id is None and getattr(sink, "_redis", None) is not None:
                    governor_metrics().evidence_publish_failure("inference_proxy_pass")
        except EvidenceChainUnavailableError:
            governor_metrics().evidence_publish_failure("inference_proxy_pass")
            logger.error(
                "Inference proxy pass-evidence emission failed closed (control=%s)",
                ev["control_id"],
            )
            if blocking:
                raise
        except Exception as exc:
            governor_metrics().evidence_publish_failure("inference_proxy_pass")
            logger.error(
                "Inference proxy pass-evidence emission failed (control=%s): %s",
                ev["control_id"],
                exc,
            )
            if blocking:
                raise EvidenceChainUnavailableError(
                    f"Evidence sink failed to commit {ev['type']}: {exc}", exc
                ) from exc


@inference_app.post("/v1/chat/completions", response_model=None)
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
) -> JSONResponse | StreamingResponse:
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

    parsed_body, body_err_resp = await _read_validated_chat_body(request)
    if body_err_resp is not None:
        return body_err_resp
    assert parsed_body is not None
    body = parsed_body

    raw_requested_model = body.get("model", "default")
    if not isinstance(raw_requested_model, str) or not raw_requested_model.strip():
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request_error",
                "message": "model must be a non-empty string",
            },
        )
    requested_model = raw_requested_model
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
        # GenAI metadata only: message content never goes on the span.
        if span.is_recording():
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("gen_ai.system", "cage-inference-proxy")
            span.set_attribute("gen_ai.request.model", model_id)
            span.set_attribute(
                "gen_ai.request.streaming", body.get("stream", False) is True
            )

        # Extract the last user message for NeMo context (used as the primary
        # input text for NeMo rails, which expect a single string).
        # ALL governance checks run regardless of whether a user message exists —
        # system-only, assistant-only, and mixed message sets are all governed.
        last_user_msg = next(
            (
                text
                for m in reversed(messages)
                if isinstance(m, dict)
                and m.get("role") == "user"
                and (text := _extract_message_content_text(m.get("content")))
            ),
            "",
        )

        # Build a combined text representation of ALL messages (including multi-part
        # content arrays and prior tool_calls arguments) for Ingress Stage 1 scan.
        # This prevents system-only, assistant-only, or structured content arrays
        # from bypassing the keyword filter (GHSA-hfqj-24cj-693g).
        all_messages_text = _extract_scannable_messages_text(messages)
        span.set_attribute(SPAN_ATTR_CONTENT_INPUT_LENGTH, len(all_messages_text))

        # 1. Ingress Stage 1 keyword scan — applied to ALL messages, not just user role.
        if ac_keyword_scan(all_messages_text):
            stamp_iso_control(span, ingress_stage=1, control="A.5.2", outcome="BLOCK")
            try:
                await _emit_proxy_evidence(
                    request,
                    span=span,
                    body=body,
                    event_type="INFERENCE_PROXY_BLOCK",
                    control_id="A.5.2",
                    status_code=403,
                    reason="Ingress Stage 1 keyword match",
                    model_id=model_id,
                    extra={"iso42001_control": "A.5.2", "ingress_stage": 1},
                )
            except EvidenceChainUnavailableError as exc:
                return _evidence_unavailable_response(exc)
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
            try:
                await _emit_proxy_evidence(
                    request,
                    span=span,
                    body=body,
                    event_type="INFERENCE_PROXY_BLOCK",
                    control_id="SC-7",
                    status_code=403,
                    reason="Workload SVID or thread is quarantined",
                    model_id=model_id,
                    agent_id=agent_id,
                    extra={"thread_id": request_thread_id},
                )
            except EvidenceChainUnavailableError as exc:
                return _evidence_unavailable_response(exc)
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
        token_delta = _compute_token_reservation(body, all_messages_text)

        quota_result = await _get_token_quota_proxy().check_and_increment(
            agent_id=agent_id,
            token_delta=token_delta,
        )
        if not quota_result.allowed:
            stamp_iso_control(span, ingress_stage=2, control="A.4", outcome="BLOCK")
            # Awaited inline — WORM and evidence stream writes must complete before
            # 429 is returned to guarantee ISO 42001 Clause 6.1 / R-16 audit lineage
            # survives spot-instance eviction.
            await _get_uca_logger().log_quota_exceeded(quota_result, body)
            try:
                await _emit_proxy_evidence(
                    request,
                    span=span,
                    body=body,
                    event_type="TOKEN_QUOTA_DENIED",
                    control_id="TQP-007",
                    status_code=429,
                    reason=str(quota_result.block_reason or "quota_exceeded"),
                    model_id=model_id,
                    agent_id=agent_id,
                    extra={
                        "governance_control_id": "CTRL_TQP_007",
                        "iso42001_control": "A.4",
                        "aarm_ref": "A.8.4",
                        "step_count": quota_result.step_count,
                        "accumulated_tokens": quota_result.accumulated_tokens,
                        "quota_max_steps": quota_result.step_quota_max,
                        "quota_max_tokens": quota_result.token_quota_max,
                    },
                )
            except EvidenceChainUnavailableError as exc:
                return _evidence_unavailable_response(exc)
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
        # rails are on. Evaluates all_messages_text across the full conversation
        # history (falling back to last_user_msg if needed) so earlier turns
        # cannot hide adversarial instructions behind a benign trailing user turn
        # (POAM-2026-209). With rails off no input rail runs, and the evidence
        # records SKIPPED with the reason code instead of a PASS that never
        # happened. Steps 4-7 are wrapped in a try/except so that any downstream
        # failure triggers a quota rollback (CTRL_TQP_007 §5.3).
        nemo_input_text = all_messages_text if all_messages_text else last_user_msg
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
                    await _emit_proxy_evidence(
                        request,
                        span=span,
                        body=body,
                        event_type="INFERENCE_PROXY_BLOCK",
                        control_id="A.6.1.2",
                        status_code=403,
                        reason=str(nemo_result.reason),
                        model_id=model_id,
                        agent_id=agent_id,
                        extra={"iso42001_control": "A.6.1.2", "ingress_stage": 3},
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
        except EvidenceChainUnavailableError as exc:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            logger.error(
                "Inference proxy refusal failed closed: evidence chain unavailable: %s",
                exc,
            )
            return _evidence_unavailable_response(exc)
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
            upstream_stream_body = dict(body)
            raw_stream_opts = upstream_stream_body.get("stream_options")
            if raw_stream_opts is None:
                upstream_stream_body["stream_options"] = {"include_usage": True}
            elif isinstance(raw_stream_opts, dict):
                upstream_stream_body["stream_options"] = {
                    **raw_stream_opts,
                    "include_usage": True,
                }

            max_stream_bytes = max(
                1024,
                int(
                    os.environ.get(
                        "CAGE_INFERENCE_MAX_STREAM_BYTES",
                        str(_DEFAULT_MAX_STREAM_BUFFER_BYTES),
                    )
                ),
            )
            collected_chunks: list[bytes] = []
            stream_bytes_total = 0
            stream_overflow = False
            try:
                async for chunk in _stream_vllm(
                    target_url,
                    upstream_stream_body,
                    api_key,
                    span=span,
                    request_start_ns=request_start_ns,
                ):
                    stream_bytes_total += len(chunk)
                    if stream_bytes_total > max_stream_bytes:
                        stream_overflow = True
                        break
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

            if stream_overflow:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "payload_too_large",
                        "message": f"Streaming response exceeded maximum buffer size ({max_stream_bytes} bytes)",
                    },
                )

            raw_stream = b"".join(collected_chunks).decode(errors="replace")
            choice_buffers: dict[int, dict[str, Any]] = {}
            unparsed_payloads: list[str] = []
            stream_backend_error = False
            stream_backend_status = 502
            stream_error_correlation_id: str | None = None
            stream_id: str | None = None
            stream_created: int | None = None
            stream_model: str = model_id
            stream_usage: dict[str, Any] | None = None

            for data_str in _iter_sse_data_payloads(raw_stream):
                try:
                    chunk_json = json.loads(data_str)
                except json.JSONDecodeError:
                    unparsed_payloads.append(data_str)
                    continue

                if not isinstance(chunk_json, dict):
                    unparsed_payloads.append(data_str)
                    continue

                err_field = str(chunk_json.get("error", ""))
                if err_field.startswith("vLLM backend error"):
                    stream_backend_error = True
                    raw_status = chunk_json.get("status_code")
                    if isinstance(raw_status, int) and not isinstance(raw_status, bool):
                        stream_backend_status = raw_status
                    else:
                        parts = err_field.rsplit(" ", 1)
                        if len(parts) == 2 and parts[1].isdigit():
                            stream_backend_status = int(parts[1])
                    if isinstance(chunk_json.get("correlation_id"), str):
                        stream_error_correlation_id = chunk_json["correlation_id"]
                    continue

                if stream_id is None and isinstance(chunk_json.get("id"), str):
                    stream_id = chunk_json["id"]
                if (
                    stream_created is None
                    and isinstance(chunk_json.get("created"), int)
                    and not isinstance(chunk_json.get("created"), bool)
                ):
                    stream_created = chunk_json["created"]
                if isinstance(chunk_json.get("model"), str) and chunk_json["model"]:
                    stream_model = chunk_json["model"]
                if isinstance(chunk_json.get("usage"), dict):
                    stream_usage = chunk_json["usage"]

                choices_list = chunk_json.get("choices")
                if not isinstance(choices_list, list):
                    continue
                for pos, choice_obj in enumerate(choices_list):
                    if not isinstance(choice_obj, dict):
                        continue
                    raw_c_idx = choice_obj.get("index", pos)
                    c_idx = (
                        raw_c_idx
                        if isinstance(raw_c_idx, int)
                        and not isinstance(raw_c_idx, bool)
                        else pos
                    )
                    c_buf = choice_buffers.setdefault(
                        c_idx,
                        {
                            "content": None,
                            "reasoning_content": None,
                            "tool_calls": {},
                            "finish_reason": None,
                        },
                    )
                    if choice_obj.get("finish_reason"):
                        c_buf["finish_reason"] = str(choice_obj["finish_reason"])
                    delta_obj = choice_obj.get("delta")
                    if not isinstance(delta_obj, dict):
                        continue
                    delta_content = delta_obj.get("content")
                    if isinstance(delta_content, str) and delta_content:
                        c_buf["content"] = (c_buf["content"] or "") + delta_content
                    delta_reasoning = delta_obj.get("reasoning_content")
                    if isinstance(delta_reasoning, str) and delta_reasoning:
                        c_buf["reasoning_content"] = (
                            c_buf["reasoning_content"] or ""
                        ) + delta_reasoning
                    for idx, tc in enumerate(delta_obj.get("tool_calls") or []):
                        if not isinstance(tc, dict):
                            continue
                        raw_tc_idx = tc.get("index", idx)
                        tc_idx = (
                            int(raw_tc_idx)
                            if isinstance(raw_tc_idx, int)
                            and not isinstance(raw_tc_idx, bool)
                            else idx
                        )
                        entry = c_buf["tool_calls"].setdefault(
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

            # [KC-01] / [F-15] FIRST: Abort on streaming backend >= 400 error BEFORE emitting PASS evidence!
            if stream_backend_error:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                upstream_status = (
                    stream_backend_status if 400 <= stream_backend_status < 600 else 502
                )
                gateway_status = _map_upstream_error_status(upstream_status)
                return JSONResponse(
                    status_code=gateway_status,
                    content={
                        "error": "upstream_inference_error",
                        "upstream_status": upstream_status,
                        "message": f"vLLM backend error {upstream_status}",
                        "correlation_id": stream_error_correlation_id
                        or str(_uuid.uuid4()),
                    },
                )

            stream_pii_redacted = False
            sanitized_choices: list[dict[str, Any]] = []
            try:
                if unparsed_payloads:
                    joined_unparsed = "\n".join(unparsed_payloads)
                    safe_unparsed = await _mask_output(rails, joined_unparsed)
                    if safe_unparsed != joined_unparsed:
                        stream_pii_redacted = True
                        if not choice_buffers:
                            sanitized_choices.append(
                                {
                                    "index": 0,
                                    "content": safe_unparsed,
                                    "reasoning_content": None,
                                    "tool_calls": [],
                                    "finish_reason": "stop",
                                }
                            )

                for c_idx in sorted(choice_buffers):
                    c_buf = choice_buffers[c_idx]
                    raw_c_content: str | None = c_buf["content"]
                    safe_c_content: str | None = raw_c_content
                    if raw_c_content:
                        safe_c_content = await _mask_output(rails, raw_c_content)
                        if safe_c_content != raw_c_content:
                            stream_pii_redacted = True

                    raw_c_reasoning: str | None = c_buf["reasoning_content"]
                    safe_c_reasoning: str | None = raw_c_reasoning
                    if raw_c_reasoning:
                        safe_c_reasoning = await _mask_output(rails, raw_c_reasoning)
                        if safe_c_reasoning != raw_c_reasoning:
                            stream_pii_redacted = True

                    tc_map: dict[int, dict[str, str]] = c_buf["tool_calls"]
                    sanitized_tcs: list[dict[str, Any]] = []
                    for tc_idx in sorted(tc_map):
                        tc_entry = tc_map[tc_idx]
                        raw_args = tc_entry["arguments"]
                        safe_args_str = raw_args
                        if raw_args:
                            safe_args_str, was_modified = await _mask_tool_arguments(
                                rails, raw_args
                            )
                            if was_modified:
                                stream_pii_redacted = True
                        sanitized_tcs.append(
                            {
                                "id": tc_entry["id"] or f"call-{tc_idx}",
                                "type": "function",
                                "function": {
                                    "name": tc_entry["name"],
                                    "arguments": safe_args_str,
                                },
                            }
                        )

                    finish_reason = c_buf["finish_reason"] or (
                        "tool_calls" if sanitized_tcs else "stop"
                    )
                    sanitized_choices.append(
                        {
                            "index": c_idx,
                            "content": safe_c_content,
                            "reasoning_content": safe_c_reasoning,
                            "tool_calls": sanitized_tcs,
                            "finish_reason": finish_reason,
                        }
                    )
            except Exception:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                raise

            # Record lengths ONLY — never message/response content on OTel spans (#774).
            if span.is_recording():
                stream_output_length = sum(
                    len(sc.get("content") or "")
                    + len(sc.get("reasoning_content") or "")
                    for sc in sanitized_choices
                )
                span.set_attribute(
                    SPAN_ATTR_CONTENT_OUTPUT_LENGTH, stream_output_length
                )
                span.set_attribute("gen_ai.response.model", stream_model)

            try:
                await _emit_proxy_pass_evidence(
                    request,
                    span=span,
                    body=body,
                    model_id=model_id,
                    agent_id=agent_id,
                    pii_redacted=stream_pii_redacted,
                )
            except EvidenceChainUnavailableError as exc:
                await _get_token_quota_proxy().rollback_step(
                    agent_id, reserved_tokens=token_delta
                )
                logger.error(
                    "Inference proxy streaming pass failed closed: evidence chain unavailable: %s",
                    exc,
                )
                return _evidence_unavailable_response(exc)

            await _reconcile_actual_usage(agent_id, token_delta, stream_usage)

            if stream_pii_redacted:
                logger.info(
                    "Streaming output redacted by Stage 4 guardrails: model=%s",
                    model_id,
                )
                ts_now = int(time.time())
                sse_frames = _build_redacted_sse_bytes(
                    stream_id=stream_id or f"chatcmpl-{ts_now}",
                    created=stream_created if stream_created is not None else ts_now,
                    model_id=stream_model,
                    sanitized_choices=sanitized_choices,
                    usage=stream_usage,
                )

                async def _replay_redacted() -> AsyncIterator[bytes]:
                    for frame in sse_frames:
                        yield frame

                return StreamingResponse(
                    _replay_redacted(),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                    },
                )

            # Content passed output filtering — re-stream the collected chunks
            async def _replay_chunks() -> AsyncIterator[bytes]:
                for c in collected_chunks:
                    yield c

            return StreamingResponse(
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
                correlation_id = str(_uuid.uuid4())
                logger.error(
                    "vLLM backend returned %s [correlation_id=%s]: %s",
                    resp.status_code,
                    correlation_id,
                    scrub_pii((resp.text or "")[:200]),
                )
                gateway_status = _map_upstream_error_status(resp.status_code)
                raise HTTPException(
                    status_code=gateway_status,
                    detail={
                        "error": "upstream_inference_error",
                        "upstream_status": int(resp.status_code),
                        "message": f"vLLM backend error {resp.status_code}",
                        "correlation_id": correlation_id,
                    },
                )
            vllm_response = resp.json()
            if not isinstance(vllm_response, dict):
                raise ValueError("Upstream inference response was not a JSON object")
        except HTTPException:
            # MED-6 fix: roll back quota on vLLM HTTP errors (4xx/5xx).
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            raise
        except Exception as exc:
            # MED-6 fix: roll back quota on connection/timeout/parse errors.
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            safe_err = _safe_error_response(exc)
            raise HTTPException(status_code=500, detail=safe_err) from exc

        # 6. Output filtering / PII masking across ALL completion choices (POAM-2026-209)
        non_stream_pii_redacted = False
        try:
            for choice in vllm_response.get("choices") or []:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message")
                if not isinstance(message, dict):
                    continue

                if (
                    choice.get("finish_reason") == "tool_calls"
                    or "tool_calls" in message
                ):
                    for tool_call in message.get("tool_calls") or []:
                        if (
                            isinstance(tool_call, dict)
                            and isinstance(tool_call.get("function"), dict)
                            and "arguments" in tool_call["function"]
                        ):
                            raw_args = tool_call["function"]["arguments"]
                            if raw_args and isinstance(raw_args, str):
                                safe_args_str, args_mod = await _mask_tool_arguments(
                                    rails, raw_args
                                )
                                if args_mod:
                                    non_stream_pii_redacted = True
                                tool_call["function"]["arguments"] = safe_args_str
                orig_content = message.get("content")
                if isinstance(orig_content, str) and orig_content:
                    safe_content = await _mask_output(rails, orig_content)
                    if safe_content != orig_content:
                        non_stream_pii_redacted = True
                    message["content"] = safe_content
                elif isinstance(orig_content, list) and orig_content:
                    safe_list, list_mod = await _mask_json_value(rails, orig_content)
                    if list_mod:
                        non_stream_pii_redacted = True
                    message["content"] = safe_list

                orig_reasoning = message.get("reasoning_content")
                if isinstance(orig_reasoning, str) and orig_reasoning:
                    safe_reasoning = await _mask_output(rails, orig_reasoning)
                    if safe_reasoning != orig_reasoning:
                        non_stream_pii_redacted = True
                    message["reasoning_content"] = safe_reasoning
                elif isinstance(orig_reasoning, list) and orig_reasoning:
                    safe_r_list, r_mod = await _mask_json_value(rails, orig_reasoning)
                    if r_mod:
                        non_stream_pii_redacted = True
                    message["reasoning_content"] = safe_r_list
        except Exception:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            raise

        # Record lengths ONLY — never message/response content on OTel spans (#774).
        if span.is_recording():
            output_length = sum(
                len(_extract_message_content_text(choice["message"].get("content")))
                + len(
                    _extract_message_content_text(
                        choice["message"].get("reasoning_content")
                    )
                )
                for choice in vllm_response.get("choices") or []
                if isinstance(choice, dict) and isinstance(choice.get("message"), dict)
            )
            span.set_attribute(SPAN_ATTR_CONTENT_OUTPUT_LENGTH, output_length)
            span.set_attribute(
                "gen_ai.response.model", vllm_response.get("model", model_id)
            )

        try:
            await _emit_proxy_pass_evidence(
                request,
                span=span,
                body=body,
                model_id=model_id,
                agent_id=agent_id,
                pii_redacted=non_stream_pii_redacted,
            )
        except EvidenceChainUnavailableError as exc:
            await _get_token_quota_proxy().rollback_step(
                agent_id, reserved_tokens=token_delta
            )
            logger.error(
                "Inference proxy pass failed closed: evidence chain unavailable: %s",
                exc,
            )
            return _evidence_unavailable_response(exc)

        await _reconcile_actual_usage(agent_id, token_delta, vllm_response.get("usage"))
        return JSONResponse(content=vllm_response)
