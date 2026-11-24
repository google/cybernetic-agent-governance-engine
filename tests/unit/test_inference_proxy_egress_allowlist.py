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

"""Egress allowlist on ``/v1/chat/completions`` responses, both modes.

The proxy builds every response from the allowlist in
``src/gateway/server/completion_egress.py``: allowlisted text is masked,
everything else is dropped, and streamed output is always re-serialized from
the sanitized completion. Each regression places PII *only* in the field
under test, so a failure isolates that field.

Covered:

- Fields masked and kept: ``refusal``, legacy ``function_call``, the
  ``reasoning`` alias, tool-call names, content parts, identifiers.
- Fields dropped: ``logprobs``, ``audio``, ``annotations``, vLLM extensions,
  and an unknown future field at every level (top, choice, message, delta).
- No code path returns upstream bytes or the upstream JSON verbatim, and an
  upstream error frame cannot pass a string back through its correlation id.
- Unparseable stream payloads fail closed with HTTP 502.
- The A.9.2 PASS record describes the body actually returned.
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.gateway.infrastructure.privacy import scrub_pii
from src.gateway.server import completion_egress, inference_proxy

pytestmark = [pytest.mark.unit, pytest.mark.local]

ADVISOR_ID = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
PII = "123-45-6789"
MASKED = "[REDACTED-SSN-UCA-3]"
UNKNOWN_FIELD = "some_new_field"

TOP_LEVEL_KEYS = {"id", "object", "created", "model", "choices", "usage"}
CHOICE_KEYS = {"index", "message", "finish_reason"}
CHUNK_CHOICE_KEYS = {"index", "delta", "finish_reason"}
MESSAGE_KEYS = {
    "role",
    "content",
    "refusal",
    "reasoning_content",
    "reasoning",
    "tool_calls",
    "function_call",
}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture()
def proxy(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Deterministic proxy: rails off, real ``scrub_pii()``, mocked upstream."""
    monkeypatch.setenv("CAGE_NEMO_ENABLED", "false")
    monkeypatch.delenv("CAGE_INFERENCE_BACKEND", raising=False)
    monkeypatch.setattr(
        "src.gateway.server.workload_identity.extract_client_identity",
        lambda _scope: ADVISOR_ID,
    )
    quota = MagicMock()
    quota.check_and_increment = AsyncMock(
        return_value=SimpleNamespace(
            allowed=True,
            block_reason="",
            step_count=1,
            accumulated_tokens=100,
            step_quota_max=100,
            token_quota_max=100_000,
        )
    )
    quota.rollback_step = AsyncMock()
    quota.reconcile_actual_tokens = AsyncMock()
    monkeypatch.setattr(inference_proxy, "_get_token_quota_proxy", lambda: quota)
    monkeypatch.setattr(inference_proxy, "scrub_pii", scrub_pii)
    monkeypatch.setattr(inference_proxy, "stamp_iso_control", MagicMock())
    cfg = {
        "VLLM_BASE_URL": "http://vllm.internal:8000/v1",
        "VLLM_FAST_API_BASE": "http://vllm.internal:8000/v1",
        "VLLM_REASONING_API_BASE": "http://vllm-reasoning.internal:8000/v1",
        "VLLM_API_KEY": "test-vllm-key",
    }
    monkeypatch.setattr(
        inference_proxy.config_manager,
        "get",
        lambda key, default=None: cfg.get(key, default),
    )
    sink = MagicMock(name="evidence_sink")
    sink._running = True
    sink.ingest = AsyncMock(return_value="1-0")
    monkeypatch.setattr("src.gateway.governance.evidence.stream._evidence_sink", sink)
    monkeypatch.setattr(
        "src.gateway.governance.evidence.stream.is_evidence_chain_blocking",
        lambda: False,
    )
    monkeypatch.setattr(
        inference_proxy.inference_app.state, "redis", None, raising=False
    )
    monkeypatch.setattr(
        "src.gateway.governance.quarantine_actuator._default_quarantine_redis", None
    )

    def upstream_json(payload: dict[str, Any]) -> MagicMock:
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # The proxy must build its body from resp.json(); these canaries would
        # surface if any path returned the upstream text or bytes instead.
        resp.text = "upstream-text-canary"
        resp.content = b"upstream-bytes-canary"
        resp.json = MagicMock(return_value=payload)
        client = MagicMock(spec=httpx.AsyncClient)
        client.is_closed = False
        client.post = AsyncMock(return_value=resp)
        monkeypatch.setattr(inference_proxy, "_get_http_client", lambda: client)
        return client

    def upstream_stream(chunks: list[bytes]) -> MagicMock:
        async def _aiter() -> Any:
            for chunk in chunks:
                yield chunk

        resp = MagicMock()
        resp.status_code = 200
        resp.aiter_bytes = _aiter
        resp.aread = AsyncMock(return_value=b"")
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)
        client = MagicMock(spec=httpx.AsyncClient)
        client.is_closed = False
        client.stream = MagicMock(return_value=ctx)
        monkeypatch.setattr(inference_proxy, "_get_http_client", lambda: client)
        return client

    return SimpleNamespace(
        quota=quota,
        sink=sink,
        upstream_json=upstream_json,
        upstream_stream=upstream_stream,
    )


async def _post(*, stream: bool, **extra: Any) -> httpx.Response:
    body = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": stream,
        **extra,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=inference_proxy.inference_app),
        base_url="http://test",
    ) as client:
        return await client.post("/v1/chat/completions", json=body)


def _completion(
    message: dict[str, Any],
    *,
    choice_extra: dict[str, Any] | None = None,
    top_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    choice = {"index": 0, "finish_reason": "stop", "message": message}
    choice.update(choice_extra or {})
    payload = {
        "id": "chatcmpl-egress",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "test-model",
        "choices": [choice],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
    }
    payload.update(top_extra or {})
    return payload


def _frame(chunk: dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(chunk).encode() + b"\n\n"


def _chunk(
    delta: dict[str, Any],
    *,
    choice_extra: dict[str, Any] | None = None,
    top_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    choice = {"index": 0, "delta": delta, "finish_reason": None}
    choice.update(choice_extra or {})
    chunk = {
        "id": "chatcmpl-egress-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_001,
        "model": "test-model",
        "choices": [choice],
    }
    chunk.update(top_extra or {})
    return chunk


def _sse_payloads(raw: bytes) -> list[dict[str, Any]]:
    """Parse the proxy's own frames (it always emits ``data: <json>\\n\\n``)."""
    payloads: list[dict[str, Any]] = []
    for line in raw.decode("utf-8").split("\n"):
        if line.startswith("data: ") and line != "data: [DONE]":
            payloads.append(json.loads(line[len("data: ") :]))
    return payloads


def _deltas(raw: bytes) -> list[dict[str, Any]]:
    return [choice["delta"] for p in _sse_payloads(raw) for choice in p["choices"]]


def _a92_record(sink: MagicMock) -> dict[str, Any]:
    (record,) = [
        call.args[0]
        for call in sink.ingest.await_args_list
        if call.args[0].get("type") == "INFERENCE_PROXY_PII_SCRUB_PASS"
    ]
    return record


def _assert_allowlisted_body(body: dict[str, Any]) -> None:
    assert set(body) <= TOP_LEVEL_KEYS
    for choice in body["choices"]:
        assert set(choice) <= CHOICE_KEYS
        assert set(choice["message"]) <= MESSAGE_KEYS


def _assert_allowlisted_stream(raw: bytes) -> None:
    for payload in _sse_payloads(raw):
        assert set(payload) <= TOP_LEVEL_KEYS
        for choice in payload["choices"]:
            assert set(choice) <= CHUNK_CHOICE_KEYS
            assert set(choice["delta"]) <= MESSAGE_KEYS


# ---------------------------------------------------------------------------
# Non-streaming: every field the old denylist passed through
# ---------------------------------------------------------------------------


class TestNonStreamingFieldDispositions:
    @pytest.mark.asyncio
    async def test_refusal_is_masked_and_kept(self, proxy: SimpleNamespace) -> None:
        proxy.upstream_json(
            _completion({"role": "assistant", "content": None, "refusal": f"No: {PII}"})
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        assert resp.json()["choices"][0]["message"]["refusal"] == f"No: {MASKED}"

    @pytest.mark.asyncio
    async def test_legacy_function_call_is_masked_and_kept(
        self, proxy: SimpleNamespace
    ) -> None:
        arguments = json.dumps({"ssn": PII, "account": 1234567890})
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": None,
                    "function_call": {"name": "lookup_account", "arguments": arguments},
                },
                choice_extra={"finish_reason": "function_call"},
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        choice = resp.json()["choices"][0]
        assert choice["finish_reason"] == "function_call"
        function_call = choice["message"]["function_call"]
        assert function_call["name"] == "lookup_account"
        assert json.loads(function_call["arguments"]) == {
            "ssn": MASKED,
            "account": 1234567890,
        }

    @pytest.mark.asyncio
    async def test_reasoning_alias_is_masked_and_kept(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(
            _completion(
                {"role": "assistant", "content": "ok", "reasoning": f"think {PII}"}
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        assert resp.json()["choices"][0]["message"]["reasoning"] == f"think {MASKED}"

    @pytest.mark.asyncio
    async def test_tool_call_name_is_masked(self, proxy: SimpleNamespace) -> None:
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": f"lookup-{PII}", "arguments": "{}"},
                        }
                    ],
                },
                choice_extra={"finish_reason": "tool_calls"},
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        (call,) = resp.json()["choices"][0]["message"]["tool_calls"]
        assert call == {
            "id": "call_1",
            "type": "function",
            "function": {"name": f"lookup-{MASKED}", "arguments": "{}"},
        }

    @pytest.mark.asyncio
    async def test_audio_is_dropped(self, proxy: SimpleNamespace) -> None:
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": None,
                    "audio": {
                        "id": "audio_1",
                        "data": "UklGRg==",
                        "expires_at": 0,
                        "transcript": f"Your SSN is {PII}",
                    },
                }
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        assert "audio" not in resp.json()["choices"][0]["message"]

    @pytest.mark.asyncio
    async def test_annotations_are_dropped(self, proxy: SimpleNamespace) -> None:
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": "see source",
                    "annotations": [
                        {
                            "type": "url_citation",
                            "url_citation": {
                                "url": f"https://example.test/{PII}",
                                "title": f"Record {PII}",
                                "start_index": 0,
                                "end_index": 3,
                            },
                        }
                    ],
                }
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        message = resp.json()["choices"][0]["message"]
        assert "annotations" not in message
        assert message["content"] == "see source"

    @pytest.mark.asyncio
    async def test_logprobs_are_dropped_while_content_is_masked(
        self, proxy: SimpleNamespace
    ) -> None:
        token = {"token": PII, "logprob": -0.1, "bytes": list(PII.encode())}
        proxy.upstream_json(
            _completion(
                {"role": "assistant", "content": f"SSN {PII}"},
                choice_extra={
                    "logprobs": {
                        "content": [{**token, "top_logprobs": [token]}],
                        "refusal": None,
                    }
                },
            )
        )
        resp = await _post(stream=False, logprobs=True, top_logprobs=1)
        assert resp.status_code == 200
        assert PII not in resp.text
        choice = resp.json()["choices"][0]
        assert "logprobs" not in choice
        assert choice["message"]["content"] == f"SSN {MASKED}"

    @pytest.mark.asyncio
    async def test_unknown_future_field_is_dropped_at_every_level(
        self, proxy: SimpleNamespace
    ) -> None:
        leak = {UNKNOWN_FIELD: f"PII {PII}"}
        proxy.upstream_json(
            _completion(
                {"role": "assistant", "content": "clean", **leak},
                choice_extra=leak,
                top_extra=leak,
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        assert UNKNOWN_FIELD not in resp.text
        body = resp.json()
        _assert_allowlisted_body(body)
        assert body["choices"][0]["message"]["content"] == "clean"
        assert _a92_record(proxy.sink)["output_fields_dropped"] == 3

    @pytest.mark.asyncio
    async def test_server_extension_fields_are_dropped(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(
            _completion(
                {"role": "assistant", "content": "clean"},
                choice_extra={
                    "stop_reason": f"stop {PII}",
                    "token_ids": [101, 102],
                    "logprobs": None,
                },
                top_extra={
                    "system_fingerprint": "fp-upstream",
                    "service_tier": "default",
                    "prompt_logprobs": [None, {"42": {"decoded_token": PII}}],
                    "prompt_token_ids": [1, 2, 3],
                    "kv_transfer_params": {"remote_host": "10.0.0.9"},
                },
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        body = resp.json()
        _assert_allowlisted_body(body)
        assert set(body) == TOP_LEVEL_KEYS
        assert body["usage"] == {
            "prompt_tokens": 5,
            "completion_tokens": 7,
            "total_tokens": 12,
        }

    @pytest.mark.asyncio
    async def test_content_parts_keep_only_masked_text_parts(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": f"SSN {PII}", "annotations": [PII]},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"https://x.test/{PII}"},
                        },
                        {"type": "custom", UNKNOWN_FIELD: PII},
                    ],
                }
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        assert resp.json()["choices"][0]["message"]["content"] == [
            {"type": "text", "text": f"SSN {MASKED}"}
        ]

    @pytest.mark.asyncio
    async def test_identifiers_are_scrubbed_or_replaced(
        self, proxy: SimpleNamespace
    ) -> None:
        payload = _completion(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call-{PII}",
                        "type": "function",
                        "function": {"name": "get_balance", "arguments": "{}"},
                    }
                ],
            },
            choice_extra={"finish_reason": f"done {PII}"},
        )
        payload["id"] = f"chatcmpl-{PII}"
        payload["model"] = f"model with {PII}"
        proxy.upstream_json(payload)
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        body = resp.json()
        assert body["id"] == f"chatcmpl-{MASKED}"
        # Not a printable token without spaces: replaced by the requested model.
        assert body["model"] == "test-model"
        assert body["choices"][0]["finish_reason"] is None
        assert body["choices"][0]["message"]["tool_calls"][0]["id"] == f"call-{MASKED}"
        assert _a92_record(proxy.sink)["pii_redacted"] is True

    @pytest.mark.asyncio
    async def test_body_is_built_new_and_upstream_text_never_returned(
        self, proxy: SimpleNamespace
    ) -> None:
        payload = _completion(
            {"role": "assistant", "content": f"SSN {PII}", UNKNOWN_FIELD: "x"}
        )
        pristine = copy.deepcopy(payload)
        proxy.upstream_json(payload)
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert "upstream-text-canary" not in resp.text
        assert "upstream-bytes-canary" not in resp.text
        # The old path masked the upstream dict in place and returned it.
        assert payload == pristine
        assert resp.json()["choices"][0]["message"]["content"] == f"SSN {MASKED}"


# ---------------------------------------------------------------------------
# Streaming: the same fields as deltas
# ---------------------------------------------------------------------------


class TestStreamingFieldDispositions:
    @pytest.mark.asyncio
    async def test_delta_refusal_is_masked_and_kept(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_stream(
            [_frame(_chunk({"refusal": f"No: {PII}"})), b"data: [DONE]\n\n"]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        assert [d["refusal"] for d in _deltas(resp.content) if "refusal" in d] == [
            f"No: {MASKED}"
        ]

    @pytest.mark.asyncio
    async def test_delta_function_call_split_across_frames_is_masked(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_stream(
            [
                _frame(
                    _chunk(
                        {
                            "function_call": {
                                "name": "lookup_account",
                                "arguments": '{"ssn": "123-',
                            }
                        }
                    )
                ),
                _frame(_chunk({"function_call": {"arguments": '45-6789"}'}})),
                _frame(_chunk({}, choice_extra={"finish_reason": "function_call"})),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        (function_call,) = [
            d["function_call"] for d in _deltas(resp.content) if "function_call" in d
        ]
        assert function_call["name"] == "lookup_account"
        assert json.loads(function_call["arguments"]) == {"ssn": MASKED}
        finishes = [
            c["finish_reason"]
            for p in _sse_payloads(resp.content)
            for c in p["choices"]
        ]
        assert finishes[-1] == "function_call"

    @pytest.mark.asyncio
    async def test_delta_reasoning_alias_is_masked_and_kept(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_stream(
            [_frame(_chunk({"reasoning": f"think {PII}"})), b"data: [DONE]\n\n"]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        assert [d["reasoning"] for d in _deltas(resp.content) if "reasoning" in d] == [
            f"think {MASKED}"
        ]

    @pytest.mark.asyncio
    async def test_delta_audio_is_dropped(self, proxy: SimpleNamespace) -> None:
        proxy.upstream_stream(
            [
                _frame(_chunk({"audio": {"id": "a1", "transcript": f"SSN {PII}"}})),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        assert all("audio" not in d for d in _deltas(resp.content))
        _assert_allowlisted_stream(resp.content)

    @pytest.mark.asyncio
    async def test_logprobs_are_dropped_while_content_is_masked(
        self, proxy: SimpleNamespace
    ) -> None:
        token = {"token": PII, "logprob": -0.1, "bytes": None, "top_logprobs": []}
        proxy.upstream_stream(
            [
                _frame(
                    _chunk(
                        {"content": f"SSN {PII}"},
                        choice_extra={"logprobs": {"content": [token]}},
                    )
                ),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True, logprobs=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        assert b"logprobs" not in resp.content
        assert [d["content"] for d in _deltas(resp.content) if "content" in d] == [
            f"SSN {MASKED}"
        ]

    @pytest.mark.asyncio
    async def test_unknown_future_field_is_dropped_at_every_level(
        self, proxy: SimpleNamespace
    ) -> None:
        leak = {UNKNOWN_FIELD: f"PII {PII}"}
        proxy.upstream_stream(
            [
                _frame(
                    _chunk(
                        {"content": "clean", **leak},
                        choice_extra=leak,
                        top_extra=leak,
                    )
                ),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        assert UNKNOWN_FIELD.encode() not in resp.content
        _assert_allowlisted_stream(resp.content)
        assert [d["content"] for d in _deltas(resp.content) if "content" in d] == [
            "clean"
        ]
        assert _a92_record(proxy.sink)["output_fields_dropped"] == 3


# ---------------------------------------------------------------------------
# No path returns upstream bytes verbatim; unparseable payloads fail closed
# ---------------------------------------------------------------------------


class TestNoVerbatimUpstreamBytes:
    @pytest.mark.asyncio
    async def test_clean_stream_is_reserialized_not_replayed(
        self, proxy: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stream with nothing to mask used to be replayed byte for byte."""
        encoded: list[bytes] = []
        real_encode = inference_proxy.encode_sse_frames

        def _spy(completion: dict[str, Any]) -> list[bytes]:
            frames = real_encode(completion)
            encoded.extend(frames)
            return frames

        monkeypatch.setattr(inference_proxy, "encode_sse_frames", _spy)
        # Framing only an upstream produces: CRLF, a comment, an event field,
        # odd JSON spacing and a field the allowlist drops.
        spaced = {"separators": (",   ", ":   ")}
        first = _chunk({"role": "assistant", "content": "Hello"})
        first["system_fingerprint"] = "fp-upstream-canary"
        last = _chunk({"content": " world"}, choice_extra={"finish_reason": "stop"})
        upstream = [
            b": keepalive-canary\r\n\r\n",
            b"event: completion\r\ndata: "
            + json.dumps(first, **spaced).encode()
            + b"\r\n\r\n",
            b"data: " + json.dumps(last, **spaced).encode() + b"\r\n\r\n",
            b"data: [DONE]\r\n\r\n",
        ]
        proxy.upstream_stream(upstream)

        resp = await _post(stream=True)

        assert resp.status_code == 200
        assert resp.content != b"".join(upstream)
        assert resp.content == b"".join(encoded)
        for canary in (b"keepalive-canary", b"fp-upstream-canary", b"\r", b":   "):
            assert canary not in resp.content
        assert [d["content"] for d in _deltas(resp.content) if "content" in d] == [
            "Hello world"
        ]
        record = _a92_record(proxy.sink)
        assert record["pii_redacted"] is False
        assert record["output_fields_dropped"] == 1

    def test_upstream_chunk_buffer_is_only_appended_and_joined(self) -> None:
        """Structural guard: raw upstream bytes are buffered for parsing only.

        ``collected_chunks`` holds what ``_stream_vllm()`` yields. Any use other
        than ``.append()`` and ``b"".join()`` would be a path that can hand the
        raw bytes back to the caller (the removed ``_replay_chunks``).
        """
        tree = ast.parse(pathlib.Path(inference_proxy.__file__).read_text("utf-8"))
        parents = {
            child: node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        uses = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "collected_chunks"
            and isinstance(node.ctx, ast.Load)
        ]
        assert uses, "the upstream chunk buffer was renamed; update this guard"
        for use in uses:
            parent = parents[use]
            appended = isinstance(parent, ast.Attribute) and parent.attr == "append"
            joined = (
                isinstance(parent, ast.Call)
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "join"
                and use in parent.args
            )
            assert appended or joined, (
                f"line {use.lineno}: upstream chunks used outside append/join"
            )
        streaming_responses = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "StreamingResponse"
        ]
        assert len(streaming_responses) == 1, "one streaming egress path only"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_payload",
        [
            b"data: not json " + PII.encode() + b"\n\n",
            b'data: ["' + PII.encode() + b'"]\n\n',
            b'data: "' + PII.encode() + b'"\n\n',
        ],
        ids=["not_json", "json_array", "json_string"],
    )
    async def test_unparseable_stream_payload_fails_closed(
        self, proxy: SimpleNamespace, bad_payload: bytes
    ) -> None:
        proxy.upstream_stream(
            [_frame(_chunk({"content": "clean"})), bad_payload, b"data: [DONE]\n\n"]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 502
        assert resp.json()["error"] == "upstream_protocol_error"
        assert PII not in resp.text
        proxy.quota.rollback_step.assert_awaited_once()
        proxy.sink.ingest.assert_not_awaited()

    @pytest.mark.covers(
        "src.gateway.server.inference_proxy:chat_completions#if stream_sse_error:",
    )
    @pytest.mark.asyncio
    async def test_error_frame_correlation_id_from_upstream_is_not_echoed(
        self, proxy: SimpleNamespace
    ) -> None:
        """Only the proxy's own reader mints error correlation ids and status (POAM-2026-237)."""
        proxy.upstream_stream(
            [
                _frame(
                    {
                        "error": "vLLM backend error 418",
                        "status_code": 418,
                        "correlation_id": f"SSN {PII}",
                    }
                )
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 502
        body = resp.json()
        assert body["error"] == "upstream_inference_error"
        assert body["upstream_status"] == 502
        assert PII not in resp.text
        assert "418" not in resp.text
        assert str(uuid.UUID(body["correlation_id"])) == body["correlation_id"]
        proxy.quota.rollback_step.assert_awaited_once()
        proxy.sink.ingest.assert_not_awaited()

    @pytest.mark.parametrize(
        "error_value",
        [
            {"message": f"overloaded: {PII}", "type": "server_error"},
            f"rate_limit_exceeded ({PII})",
        ],
        ids=["dict-error", "str-error"],
    )
    @pytest.mark.asyncio
    async def test_http_200_midstream_sse_error_frame_fails_closed_before_pass_evidence(
        self, proxy: SimpleNamespace, error_value: Any
    ) -> None:
        """HTTP-200 SSE frames with non-null 'error' fail closed with rollback and zero PASS evidence."""
        proxy.upstream_stream(
            [
                _frame(_chunk({"content": "Hello "})),
                _frame({"error": error_value}),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 502
        body = resp.json()
        assert body["error"] == "upstream_inference_error"
        assert body["upstream_status"] == 502
        assert PII not in resp.text
        proxy.quota.rollback_step.assert_awaited_once()
        proxy.sink.ingest.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_http_200_sse_null_error_key_still_succeeds(
        self, proxy: SimpleNamespace
    ) -> None:
        """Explicit JSON {'error': null} alongside valid delta content does not trigger failure."""
        proxy.upstream_stream(
            [
                _frame({"choices": [{"delta": {"content": "ok"}}], "error": None}),
                _frame({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert "ok" in resp.text
        proxy.quota.rollback_step.assert_not_called()


# ---------------------------------------------------------------------------
# A.9.2 PASS evidence describes the body actually returned
# ---------------------------------------------------------------------------


class TestPassEvidenceMatchesReturnedBody:
    @pytest.mark.asyncio
    async def test_non_streaming_masked_field_records_redaction(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(
            _completion({"role": "assistant", "content": None, "refusal": f"No: {PII}"})
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        record = _a92_record(proxy.sink)
        assert record["pii_redacted"] is True
        assert record["output_fields_dropped"] == 0

    @pytest.mark.asyncio
    async def test_non_streaming_dropped_field_records_drop_not_redaction(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": "clean",
                    "audio": {"transcript": f"SSN {PII}"},
                }
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert PII not in resp.text
        record = _a92_record(proxy.sink)
        assert record["pii_redacted"] is False
        assert record["output_fields_dropped"] == 1

    @pytest.mark.asyncio
    async def test_streaming_masked_and_dropped_fields_are_both_recorded(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_stream(
            [
                _frame(_chunk({"refusal": f"No: {PII}"})),
                _frame(_chunk({"audio": {"transcript": f"SSN {PII}"}})),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert PII.encode() not in resp.content
        record = _a92_record(proxy.sink)
        assert record["pii_redacted"] is True
        assert record["output_fields_dropped"] == 1

    @pytest.mark.asyncio
    async def test_clean_response_records_no_redaction_and_no_drop(
        self, proxy: SimpleNamespace
    ) -> None:
        proxy.upstream_json(_completion({"role": "assistant", "content": "clean"}))
        resp = await _post(stream=False)
        assert resp.status_code == 200
        record = _a92_record(proxy.sink)
        assert record["pii_redacted"] is False
        assert record["output_fields_dropped"] == 0

    @pytest.mark.asyncio
    async def test_explicit_null_fields_are_omitted_and_not_counted(
        self, proxy: SimpleNamespace
    ) -> None:
        """Servers send ``"logprobs": null`` and similar on every response."""
        proxy.upstream_json(
            _completion(
                {
                    "role": "assistant",
                    "content": "clean",
                    "refusal": None,
                    "reasoning_content": None,
                    "audio": None,
                    "annotations": None,
                    "tool_calls": [],
                },
                choice_extra={"logprobs": None, "stop_reason": None},
                top_extra={
                    "system_fingerprint": None,
                    "service_tier": None,
                    "prompt_logprobs": None,
                    "kv_transfer_params": None,
                },
            )
        )
        resp = await _post(stream=False)
        assert resp.status_code == 200
        assert resp.json()["choices"][0]["message"] == {
            "role": "assistant",
            "content": "clean",
            "tool_calls": [],
        }
        assert _a92_record(proxy.sink)["output_fields_dropped"] == 0

    @pytest.mark.asyncio
    async def test_stream_explicit_null_fields_are_not_counted(
        self, proxy: SimpleNamespace
    ) -> None:
        nulls = {"logprobs": None, "stop_reason": None}
        proxy.upstream_stream(
            [
                _frame(
                    _chunk(
                        {"role": "assistant", "content": "clean", "reasoning": None},
                        choice_extra=nulls,
                        top_extra={"system_fingerprint": None, "usage": None},
                    )
                ),
                b"data: [DONE]\n\n",
            ]
        )
        resp = await _post(stream=True)
        assert resp.status_code == 200
        assert _a92_record(proxy.sink)["output_fields_dropped"] == 0


# ---------------------------------------------------------------------------
# Projection unit behaviour (no HTTP)
# ---------------------------------------------------------------------------


class _MarkingMasker:
    """Appends a marker to text so the test can see which primitive ran."""

    async def text(self, value: str) -> str:
        return value + "#text"

    async def arguments(self, value: str) -> str:
        return value + "#args"

    def identifier(self, value: str) -> str:
        return value


@pytest.mark.asyncio
async def test_identifiers_never_reach_the_text_masker() -> None:
    """The LLM rail must not see (and so cannot rewrite) ids clients echo back."""
    upstream = {
        "id": "chatcmpl-1",
        "model": "served-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "hi",
                    "tool_calls": [
                        {
                            "id": "call_9",
                            "type": "function",
                            "function": {"name": "f", "arguments": "{}"},
                        }
                    ],
                },
            }
        ],
    }
    pristine = copy.deepcopy(upstream)
    body, report = await completion_egress.sanitize_completion(
        upstream, _MarkingMasker(), fallback_model="fallback", now=7
    )
    assert upstream == pristine
    assert body["id"] == "chatcmpl-1"
    assert body["model"] == "served-model"
    assert body["created"] == 7
    message = body["choices"][0]["message"]
    assert message["content"] == "hi#text"
    assert message["tool_calls"] == [
        {
            "id": "call_9",
            "type": "function",
            "function": {"name": "f#text", "arguments": "{}#args"},
        }
    ]
    assert report.pii_redacted is True
    assert report.fields_dropped == 0
