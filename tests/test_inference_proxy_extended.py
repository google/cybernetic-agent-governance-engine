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

"""Extended unit tests for src/gateway/server/inference_proxy.py.

Covers the chat_completions endpoint, streaming path, error propagation, and
governance pipeline tiers.  All heavy dependencies (NeMo, httpx backend,
token quota, config_manager) are patched at the *point of use* in the
inference_proxy module so tests run without live services.

Key convention: because inference_proxy.py uses ``from <mod> import <name>``,
all patches must target ``src.gateway.server.inference_proxy.<name>``, not the
originating module — otherwise the locally-bound name is not replaced.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytestmark = pytest.mark.local

# ---------------------------------------------------------------------------
# Constants used as patch targets (all in the inference_proxy namespace)
# ---------------------------------------------------------------------------
_MODULE = "src.gateway.server.inference_proxy"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _make_quota_result(allowed: bool = True, reason: str = ""):
    r = MagicMock()
    r.allowed = allowed
    r.block_reason = reason
    r.step_count = 1
    r.accumulated_tokens = 100
    r.step_quota_max = 1000
    r.token_quota_max = 100_000
    return r


def _make_quota_proxy(allowed: bool = True, reason: str = "") -> MagicMock:
    proxy = MagicMock()
    proxy.check_and_increment = AsyncMock(
        return_value=_make_quota_result(allowed, reason)
    )
    proxy.rollback_step = AsyncMock()
    return proxy


def _make_uca_logger() -> MagicMock:
    logger = MagicMock()
    logger.log_quota_exceeded = AsyncMock()
    return logger


def _vllm_json_response(content: str = "Hello!", model: str = "test-model") -> dict:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


def _chat_body(**kwargs) -> dict:
    base: dict = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Fake httpx client that returns a successful vLLM response by default
# ---------------------------------------------------------------------------


def _make_http_client_mock(response_json: dict | None = None) -> MagicMock:
    if response_json is None:
        response_json = _vllm_json_response()
    fake_resp = MagicMock(spec=httpx.Response)
    fake_resp.status_code = 200
    fake_resp.text = json.dumps(response_json)
    fake_resp.json = MagicMock(return_value=response_json)

    client = MagicMock(spec=httpx.AsyncClient)
    client.is_closed = False
    client.post = AsyncMock(return_value=fake_resp)
    client.stream = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Core fixture — patches everything in the inference_proxy module namespace
# ---------------------------------------------------------------------------


@pytest.fixture()
def proxy_deps(monkeypatch):
    """
    Patch all external collaborators in the inference_proxy module namespace.

    Yields a dict with the key mock objects so tests can inspect / override them.
    """
    import src.gateway.server.inference_proxy as _mod

    quota_proxy = _make_quota_proxy(allowed=True)
    uca_logger = _make_uca_logger()
    http_client = _make_http_client_mock()

    nemo_safe = MagicMock(is_safe=True, reason="")

    # Patch at the point-of-use (the imported name in the module)
    monkeypatch.setattr(_mod, "ac_keyword_scan", MagicMock(return_value=False))
    monkeypatch.setattr(_mod, "_get_token_quota_proxy", lambda: quota_proxy)
    monkeypatch.setattr(_mod, "_get_uca_logger", lambda: uca_logger)
    monkeypatch.setattr(_mod, "verify_input", AsyncMock(return_value=nemo_safe))
    monkeypatch.setattr(
        _mod,
        "verify_and_mask_output",
        AsyncMock(side_effect=lambda _rails, text: text),
    )
    monkeypatch.setattr(_mod, "stamp_iso_control", MagicMock())
    monkeypatch.setattr(_mod, "scrub_pii", lambda x: x)
    monkeypatch.setattr(_mod, "_get_http_client", lambda: http_client)
    monkeypatch.setattr(_mod, "_get_symbolic_governor", lambda: None)

    # Patch config_manager.get so _resolve_backend_url returns fake URLs
    cfg_map = {
        "VLLM_BASE_URL": "http://fake-vllm:8000/v1",
        "VLLM_FAST_API_BASE": "http://fake-vllm:8000/v1",
        "VLLM_REASONING_API_BASE": "http://fake-reasoning:8000/v1",
        "VLLM_API_KEY": "test-key",
    }
    monkeypatch.setattr(
        _mod.config_manager, "get", lambda key, default=None: cfg_map.get(key, default)
    )

    # Stub initialize_rails so the endpoint doesn't try to load NeMo
    def _mock_init_rails():
        return MagicMock()

    # chat_completions imports initialize_rails locally; patch via sys.modules
    import src.gateway.governance.nemo.manager as _nemo_mgr

    monkeypatch.setattr(_nemo_mgr, "initialize_rails", _mock_init_rails)

    yield {
        "app": _mod.inference_app,
        "module": _mod,
        "quota_proxy": quota_proxy,
        "uca_logger": uca_logger,
        "http_client": http_client,
    }


# ---------------------------------------------------------------------------
# Tests — basic proxying
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_basic_request_proxied_to_upstream(proxy_deps):
    """A well-formed request reaches the upstream vLLM POST and returns 200."""
    app = proxy_deps["app"]
    http_client = proxy_deps["http_client"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 200
    body = resp.json()
    assert "choices" in body
    assert body["choices"][0]["message"]["role"] == "assistant"
    http_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_authorization_header_sent_to_upstream(proxy_deps):
    """The Authorization header with the configured API key is forwarded."""
    app = proxy_deps["app"]
    http_client = proxy_deps["http_client"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    call_kwargs = http_client.post.call_args
    headers_sent = call_kwargs.kwargs.get("headers", {})
    assert headers_sent.get("Authorization") == "Bearer test-key"


@pytest.mark.asyncio
async def test_model_id_forwarded_in_body(proxy_deps):
    """The resolved model ID is written into the body before proxying."""
    app = proxy_deps["app"]
    http_client = proxy_deps["http_client"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/v1/chat/completions", json=_chat_body(model="my-custom-model")
        )

    call_kwargs = http_client.post.call_args
    forwarded_body = call_kwargs.kwargs.get("json", {})
    assert forwarded_body["model"] == "my-custom-model"


# ---------------------------------------------------------------------------
# Tests — tier-1 keyword block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tier1_keyword_match_returns_403(proxy_deps):
    """When ac_keyword_scan returns True the request is blocked with 403."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    # Override the already-patched ac_keyword_scan to return True
    mod.ac_keyword_scan = MagicMock(return_value=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 403
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert "Tier-1 keyword match" in content


@pytest.mark.asyncio
async def test_tier1_block_does_not_call_upstream(proxy_deps):
    """When tier-1 blocks, the upstream vLLM is never called."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    http_client = proxy_deps["http_client"]
    mod.ac_keyword_scan = MagicMock(return_value=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    http_client.post.assert_not_awaited()


# ---------------------------------------------------------------------------
# Tests — token quota
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quota_exceeded_returns_429(proxy_deps):
    """When quota is exceeded the endpoint returns 429 with quota details."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    denied_proxy = _make_quota_proxy(allowed=False, reason="daily quota hit")
    mod._get_token_quota_proxy = lambda: denied_proxy

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body(max_tokens=100)
        )

    assert resp.status_code == 429
    body = resp.json()
    assert body["error"] == "quota_exceeded"
    assert body["iso42001_control"] == "A.4"
    assert "daily quota hit" in body["reason"]


@pytest.mark.asyncio
async def test_quota_exceeded_calls_uca_logger(proxy_deps):
    """When quota is exceeded _get_uca_logger().log_quota_exceeded is called."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    denied_proxy = _make_quota_proxy(allowed=False, reason="exceeded")
    new_uca = _make_uca_logger()
    mod._get_token_quota_proxy = lambda: denied_proxy
    mod._get_uca_logger = lambda: new_uca

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    new_uca.log_quota_exceeded.assert_awaited_once()


# ---------------------------------------------------------------------------
# Tests — NeMo block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nemo_block_returns_403(proxy_deps):
    """When NeMo verify_input blocks, the endpoint returns 403."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    blocked_result = MagicMock(is_safe=False, reason="test-block-reason")
    mod.verify_input = AsyncMock(return_value=blocked_result)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 403
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert "test-block-reason" in content


@pytest.mark.asyncio
async def test_nemo_exception_triggers_quota_rollback(proxy_deps):
    """When verify_input raises, quota is rolled back before re-raising.

    The endpoint wraps the NeMo call in try/except so that any downstream
    failure triggers rollback_step before the exception propagates.  We call
    the underlying handler directly so we can catch the re-raised error and
    still assert on rollback.
    """
    mod = proxy_deps["module"]
    quota_proxy = proxy_deps["quota_proxy"]

    async def _bad_verify(rails, text, **kw):
        raise RuntimeError("nemo exploded")

    mod.verify_input = _bad_verify

    # Build a minimal fake Request so we can call chat_completions directly.
    # The scope must include "app" so request.app.state is accessible.
    from starlette.background import BackgroundTasks
    from starlette.datastructures import Headers, State
    from starlette.requests import Request

    app = proxy_deps["app"]
    # Ensure nemo_rails is set on app.state so the local init_rails branch is skipped
    app.state.nemo_rails = MagicMock()

    body_bytes = json.dumps(_chat_body()).encode()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "query_string": b"",
        "headers": Headers({"content-type": "application/json"}).raw,
        "app": app,
    }

    async def _receive():
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    request = Request(scope, _receive)

    with pytest.raises(RuntimeError, match="nemo exploded"):
        await mod.chat_completions(request, BackgroundTasks())

    # The rollback must fire before the exception propagates
    quota_proxy.rollback_step.assert_awaited_once()


# ---------------------------------------------------------------------------
# Tests — upstream error propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upstream_500_propagated_to_client(proxy_deps):
    """A 500 from vLLM is surfaced as an HTTP 500 and rolls back quota."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    quota_proxy = proxy_deps["quota_proxy"]

    error_resp = MagicMock(spec=httpx.Response)
    error_resp.status_code = 500
    error_resp.text = '{"error": "vllm crash"}'
    error_resp.json = MagicMock(return_value={"error": "vllm crash"})

    bad_client = _make_http_client_mock()
    bad_client.post = AsyncMock(return_value=error_resp)
    mod._get_http_client = lambda: bad_client

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 500
    quota_proxy.rollback_step.assert_awaited_once()


@pytest.mark.asyncio
async def test_upstream_connection_error_returns_500(proxy_deps):
    """A connection error to vLLM returns 500 and rolls back quota (MED-6)."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]
    quota_proxy = proxy_deps["quota_proxy"]

    bad_client = _make_http_client_mock()
    bad_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    mod._get_http_client = lambda: bad_client

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 500
    quota_proxy.rollback_step.assert_awaited_once()


# ---------------------------------------------------------------------------
# Tests — output filtering / PII masking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_output_content_passed_through_nemo_filter(proxy_deps):
    """The assistant content from vLLM is passed through verify_and_mask_output."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]

    vllm_resp = _vllm_json_response(content="Sensitive content here")
    good_client = _make_http_client_mock(response_json=vllm_resp)
    mod._get_http_client = lambda: good_client

    masked_calls: list[str] = []

    async def _capture_mask(rails, text):
        masked_calls.append(text)
        return text

    mod.verify_and_mask_output = _capture_mask

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 200
    assert any("Sensitive content here" in c for c in masked_calls)


@pytest.mark.asyncio
async def test_masked_content_replaces_original(proxy_deps):
    """If verify_and_mask_output changes content, the masked version is returned."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]

    vllm_resp = _vllm_json_response(content="raw PII data")
    good_client = _make_http_client_mock(response_json=vllm_resp)
    mod._get_http_client = lambda: good_client

    async def _mask(_rails, text):
        return text.replace("raw PII data", "[REDACTED]")

    mod.verify_and_mask_output = _mask

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 200
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert content == "[REDACTED]"
    assert "raw PII data" not in content


# ---------------------------------------------------------------------------
# Tests — streaming path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_streaming_request_returns_event_stream(proxy_deps):
    """When stream=True, the response content-type is text/event-stream."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]

    sse_chunks = [
        b'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n',
        b'data: {"choices": [{"delta": {"content": " world"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    async def _fake_aiter_bytes():
        for chunk in sse_chunks:
            yield chunk

    fake_stream_resp = MagicMock()
    fake_stream_resp.status_code = 200
    fake_stream_resp.aiter_bytes = _fake_aiter_bytes
    fake_stream_resp.aread = AsyncMock(return_value=b"")

    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=fake_stream_resp)
    fake_cm.__aexit__ = AsyncMock(return_value=False)

    stream_client = MagicMock(spec=httpx.AsyncClient)
    stream_client.is_closed = False
    stream_client.stream = MagicMock(return_value=fake_cm)
    mod._get_http_client = lambda: stream_client

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body(stream=True))

    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_streaming_upstream_4xx_yields_error_event(proxy_deps):
    """When vLLM streaming returns 4xx, an SSE error event is yielded."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]

    async def _empty_aiter():
        return
        yield  # make it an async generator

    fake_stream_resp = MagicMock()
    fake_stream_resp.status_code = 503
    fake_stream_resp.aiter_bytes = _empty_aiter
    fake_stream_resp.aread = AsyncMock(return_value=b"Service Unavailable")

    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=fake_stream_resp)
    fake_cm.__aexit__ = AsyncMock(return_value=False)

    stream_client = MagicMock(spec=httpx.AsyncClient)
    stream_client.is_closed = False
    stream_client.stream = MagicMock(return_value=fake_cm)
    mod._get_http_client = lambda: stream_client

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body(stream=True))

    assert resp.status_code == 200  # streaming path always 200
    body_bytes = resp.content
    assert b"vLLM backend error 503" in body_bytes


# ---------------------------------------------------------------------------
# Tests — agent_id extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_id_from_body_used_for_quota(proxy_deps):
    """agent_id from the request body is passed to quota check_and_increment."""
    app = proxy_deps["app"]
    quota_proxy = proxy_deps["quota_proxy"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/v1/chat/completions",
            json=_chat_body(agent_id="agent-xyz"),
        )

    call_args = quota_proxy.check_and_increment.call_args
    assert call_args.kwargs.get("agent_id") == "agent-xyz"


@pytest.mark.asyncio
async def test_anonymous_agent_id_when_not_provided(proxy_deps):
    """When no agent_id is in body or headers, 'anonymous' is used."""
    app = proxy_deps["app"]
    quota_proxy = proxy_deps["quota_proxy"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/v1/chat/completions", json=_chat_body())

    call_args = quota_proxy.check_and_increment.call_args
    assert call_args.kwargs.get("agent_id") == "anonymous"


@pytest.mark.asyncio
async def test_agent_id_from_header_used_when_body_omits_it(proxy_deps):
    """X-Agent-ID header is respected when body lacks agent_id."""
    app = proxy_deps["app"]
    quota_proxy = proxy_deps["quota_proxy"]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post(
            "/v1/chat/completions",
            json=_chat_body(),
            headers={"X-Agent-ID": "header-agent"},
        )

    call_args = quota_proxy.check_and_increment.call_args
    assert call_args.kwargs.get("agent_id") == "header-agent"


# ---------------------------------------------------------------------------
# Tests — tool_call output filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_call_arguments_filtered_by_nemo(proxy_deps):
    """Tool call function arguments are passed through verify_and_mask_output."""
    app = proxy_deps["app"]
    mod = proxy_deps["module"]

    vllm_resp: dict = {
        "id": "chatcmpl-tool",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "do_something",
                                "arguments": '{"account": "PII-123"}',
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 20, "total_tokens": 25},
    }
    good_client = _make_http_client_mock(response_json=vllm_resp)
    mod._get_http_client = lambda: good_client

    filtered_args: list[str] = []

    async def _capture_tool_mask(rails, text):
        filtered_args.append(text)
        return text.replace("PII-123", "REDACTED")

    mod.verify_and_mask_output = _capture_tool_mask

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())

    assert resp.status_code == 200
    assert any("PII-123" in a for a in filtered_args)
    body = resp.json()
    tool_args = body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert "REDACTED" in tool_args
    assert "PII-123" not in tool_args


# ---------------------------------------------------------------------------
# Tests — _stream_vllm unit tests (isolated, no FastAPI)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_vllm_yields_chunks_on_success():
    """_stream_vllm yields raw bytes from the backend on a 200 response."""
    chunks = [b"data: chunk1\n\n", b"data: chunk2\n\n"]

    async def _aiter():
        for c in chunks:
            yield c

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.aiter_bytes = _aiter

    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=fake_resp)
    fake_cm.__aexit__ = AsyncMock(return_value=False)

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.stream = MagicMock(return_value=fake_cm)

    import src.gateway.server.inference_proxy as _mod

    with patch.object(_mod, "_get_http_client", return_value=mock_client):
        from src.gateway.server.inference_proxy import _stream_vllm

        collected: list[bytes] = []
        async for chunk in _stream_vllm(
            "http://fake/chat/completions", {"model": "m"}, "key"
        ):
            collected.append(chunk)

    assert collected == chunks


@pytest.mark.asyncio
async def test_stream_vllm_emits_error_event_on_4xx():
    """_stream_vllm emits a single error SSE event when backend returns 4xx."""

    async def _empty_aiter():
        return
        yield

    fake_resp = MagicMock()
    fake_resp.status_code = 503
    fake_resp.aiter_bytes = _empty_aiter
    fake_resp.aread = AsyncMock(return_value=b"Service Unavailable")

    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=fake_resp)
    fake_cm.__aexit__ = AsyncMock(return_value=False)

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.stream = MagicMock(return_value=fake_cm)

    import src.gateway.server.inference_proxy as _mod

    with patch.object(_mod, "_get_http_client", return_value=mock_client):
        from src.gateway.server.inference_proxy import _stream_vllm

        collected: list[bytes] = []
        async for chunk in _stream_vllm(
            "http://fake/chat/completions", {"model": "m"}, "key"
        ):
            collected.append(chunk)

    assert len(collected) == 1
    assert b"vLLM backend error 503" in collected[0]


# ---------------------------------------------------------------------------
# Tests — _get_symbolic_governor caching
# ---------------------------------------------------------------------------


def test_get_symbolic_governor_returns_none_on_import_failure():
    """_get_symbolic_governor returns None when singletons cannot be imported."""
    import src.gateway.server.inference_proxy as _mod

    original = _mod._symbolic_governor
    _mod._symbolic_governor = None
    try:
        with patch.dict(
            "sys.modules",
            {"src.gateway.governance.singletons": None},
        ):
            result = _mod._get_symbolic_governor()
        assert result is None
    finally:
        _mod._symbolic_governor = original


# ---------------------------------------------------------------------------
# Tests — shutdown handler
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shutdown_closes_http_client():
    """_shutdown_http_client closes the shared client and resets it to None."""
    import src.gateway.server.inference_proxy as _mod

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.is_closed = False
    mock_client.aclose = AsyncMock()

    original_client = _mod._http_client
    _mod._http_client = mock_client
    try:
        await _mod._shutdown_http_client()
        mock_client.aclose.assert_awaited_once()
        assert _mod._http_client is None
    finally:
        _mod._http_client = original_client
