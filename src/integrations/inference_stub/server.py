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

"""OpenAI-compatible FastAPI server for the deterministic inference stub.

Serves ``POST /v1/chat/completions`` (both JSON and ``stream=true`` SSE with
``tool_calls`` delta chunks), ``GET /v1/models``, and ``GET /health``. Refuses
to start in ``prod`` / ``production`` environments as defense-in-depth behind
the Kubernetes Deployment ``lifecycle { precondition }`` (S-12 / POAM-2026-191).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import deque
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.integrations.inference_stub.scenarios import (
    StubTurnDecision,
    resolve_chat_completion,
)

logger = logging.getLogger("cage.inference_stub")

_FIXED_CREATED_EPOCH: Final[int] = 1_767_225_600  # 2026-01-01T00:00:00Z
_FORBIDDEN_ENVS: Final[frozenset[str]] = frozenset({"prod", "production"})
_MAX_RECORDED_REQUESTS: Final[int] = 256


def _assert_non_production_env(environ: Mapping[str, str] | None = None) -> None:
    """Fail closed if launched in a production environment."""
    env = os.environ if environ is None else environ
    for key in ("CAGE_ENV", "ENVIRONMENT", "APP_ENV"):
        val = (env.get(key) or "").strip().lower()
        if val in _FORBIDDEN_ENVS:
            raise RuntimeError(
                f"cage-inference-stub refused startup: {key}={val!r} is forbidden "
                "(test/staging conformance backend only; POAM-2026-191)."
            )


def _is_streaming_requested(body: Mapping[str, Any]) -> bool:
    val = body.get("stream", False)
    return (
        val is True
        or val == 1
        or (isinstance(val, str) and val.strip().lower() == "true")
    )


def _completion_id(decision: StubTurnDecision) -> str:
    material = json.dumps(
        {
            "scenario_id": decision.scenario.scenario_id,
            "finish_reason": decision.finish_reason,
            "content": decision.content,
            "tool_calls": list(decision.tool_calls),
        },
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:16]
    return f"chatcmpl-stub-{digest}"


def _build_json_response(model_id: str, decision: StubTurnDecision) -> dict[str, Any]:
    message: dict[str, Any] = {
        "role": "assistant",
        "content": decision.content,
    }
    if decision.tool_calls:
        message["tool_calls"] = [dict(tc) for tc in decision.tool_calls]
    completion_text = decision.content or json.dumps(list(decision.tool_calls))
    completion_tokens = max(1, len(completion_text.split()))
    return {
        "id": _completion_id(decision),
        "object": "chat.completion",
        "created": _FIXED_CREATED_EPOCH,
        "model": model_id,
        "choices": [
            {
                "index": 0,
                "finish_reason": decision.finish_reason,
                "message": message,
            }
        ],
        "usage": {
            "prompt_tokens": 16,
            "completion_tokens": completion_tokens,
            "total_tokens": 16 + completion_tokens,
        },
    }


async def _stream_sse_chunks(
    model_id: str, decision: StubTurnDecision
) -> AsyncIterator[bytes]:
    cmpl_id = _completion_id(decision)
    base = {
        "id": cmpl_id,
        "object": "chat.completion.chunk",
        "created": _FIXED_CREATED_EPOCH,
        "model": model_id,
    }

    role_chunk = {
        **base,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant"},
                "finish_reason": None,
            }
        ],
    }
    yield f"data: {json.dumps(role_chunk)}\n\n".encode()

    if decision.tool_calls:
        delta_calls = [
            {
                "index": idx,
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                },
            }
            for idx, tc in enumerate(decision.tool_calls)
        ]
        tc_chunk = {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": delta_calls},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(tc_chunk)}\n\n".encode()

    if decision.content:
        content_chunk = {
            **base,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": decision.content},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(content_chunk)}\n\n".encode()

    done_chunk = {
        **base,
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": decision.finish_reason,
            }
        ],
    }
    yield f"data: {json.dumps(done_chunk)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def create_stub_app(environ: Mapping[str, str] | None = None) -> FastAPI:
    """Create a deterministic OpenAI-compatible inference stub FastAPI app."""
    _assert_non_production_env(environ)

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        _assert_non_production_env(environ)
        yield

    app = FastAPI(title="CAGE Deterministic Inference Stub", lifespan=_lifespan)
    app.state.request_count = 0
    app.state.requests = deque(maxlen=_MAX_RECORDED_REQUESTS)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "cage-inference-stub",
            "backend": "stub",
            "request_count": app.state.request_count,
        }

    @app.get("/v1/models")
    async def list_models() -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": "cage-stub-v1",
                    "object": "model",
                    "created": _FIXED_CREATED_EPOCH,
                    "owned_by": "cage-conformance",
                },
                {
                    "id": "default",
                    "object": "model",
                    "created": _FIXED_CREATED_EPOCH,
                    "owned_by": "cage-conformance",
                },
            ],
        }

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(request: Request) -> JSONResponse | StreamingResponse:
        try:
            body = await request.json()
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail={"error": "invalid_json"}
            ) from exc
        if not isinstance(body, Mapping):
            raise HTTPException(
                status_code=400, detail={"error": "request_body_must_be_object"}
            )

        model_id = str(body.get("model") or "cage-stub-v1")
        decision = resolve_chat_completion(body)

        app.state.request_count += 1
        app.state.requests.append(
            {
                "model": model_id,
                "scenario_id": decision.scenario.scenario_id,
                "finish_reason": decision.finish_reason,
                "tool_names": [tc["function"]["name"] for tc in decision.tool_calls],
                "stream": _is_streaming_requested(body),
            }
        )
        logger.info(
            "stub completion #%d: model=%s scenario=%s finish=%s",
            app.state.request_count,
            model_id,
            decision.scenario.scenario_id,
            decision.finish_reason,
        )

        if _is_streaming_requested(body):
            return StreamingResponse(
                _stream_sse_chunks(model_id, decision),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                },
            )
        return JSONResponse(content=_build_json_response(model_id, decision))

    return app


def main() -> None:
    """Container entrypoint (``python -m src.integrations.inference_stub.server``)."""
    import uvicorn

    _assert_non_production_env()
    # Binds inside non-root ClusterIP container pod; NetworkPolicy limits ingress.
    host = os.environ.get("INFERENCE_STUB_HOST", "0.0.0.0")  # nosec B104  # non-root ClusterIP pod listener guarded by NetworkPolicy and Linkerd mTLS
    port = int(os.environ.get("INFERENCE_STUB_PORT", "8000"))
    uvicorn.run(
        create_stub_app(), host=host, port=port, log_level="info", proxy_headers=False
    )


if __name__ == "__main__":
    main()
