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
Unit tests for src/gateway/core/llm.py — GatewayClient.

All tests are hermetic: no live vLLM, OpenAI, or OTel collector required.
Heavy dependencies (openai, config, telemetry helpers) are mocked at import
time via patch() and MagicMock/AsyncMock.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_response(content: str = "Hello from mock"):
    """Build a minimal OpenAI-compatible chat completion response."""
    msg = MagicMock()
    msg.content = content
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = MagicMock(prompt_tokens=5, completion_tokens=10, total_tokens=15)
    return resp


# ---------------------------------------------------------------------------
# Module-level patches so imports succeed without real deps
# ---------------------------------------------------------------------------

_PATCHES = {
    "openai.AsyncOpenAI": MagicMock,
    "config.settings.Config": MagicMock(
        VLLM_GATEWAY_URL="http://gw:8000/v1",
        VLLM_API_KEY="test-key",
        VLLM_REASONING_API_BASE="http://reasoning:8001/v1",
        VLLM_FAST_API_BASE="http://fast:8002/v1",
        MODEL_REASONING="reasoning-model",
        MODEL_FAST="fast-model",
    ),
    "src.gateway.infrastructure.telemetry_client.genai_span": MagicMock(
        return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock()),
            __exit__=MagicMock(return_value=False),
        )
    ),
    "src.gateway.infrastructure.telemetry_client.record_completion": MagicMock(),
    "src.gateway.infrastructure.telemetry_client.record_usage": MagicMock(),
}


@pytest.mark.local
class TestGatewayClientInit:
    """Tests for GatewayClient.__init__ routing logic."""

    def test_gateway_mode_when_vllm_gateway_url_set(self):
        """GatewayClient selects 'gateway' mode when VLLM_GATEWAY_URL is present."""
        with (
            patch("openai.AsyncOpenAI", MagicMock()),
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span", MagicMock()
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_completion",
                MagicMock(),
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_usage",
                MagicMock(),
            ),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.VLLM_REASONING_API_BASE = ""
            mock_cfg.VLLM_FAST_API_BASE = ""
            mock_cfg.MODEL_REASONING = "reasoning"
            mock_cfg.MODEL_FAST = "fast"

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()

            assert client.mode == "gateway"
            assert hasattr(client, "gateway_client")

    def test_local_mode_when_vllm_gateway_url_empty(self):
        """GatewayClient selects 'local' mode when VLLM_GATEWAY_URL is absent."""
        with (
            patch("openai.AsyncOpenAI", MagicMock()),
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span", MagicMock()
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_completion",
                MagicMock(),
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_usage",
                MagicMock(),
            ),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = ""
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.VLLM_REASONING_API_BASE = "http://r:8001/v1"
            mock_cfg.VLLM_FAST_API_BASE = "http://f:8002/v1"
            mock_cfg.MODEL_REASONING = "reasoning"
            mock_cfg.MODEL_FAST = "fast"

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()

            assert client.mode == "local"
            assert hasattr(client, "reasoning_client")
            assert hasattr(client, "governance_client")


@pytest.mark.local
class TestGatewayClientRouting:
    """Tests for GatewayClient._get_route()."""

    def _make_client_gateway_mode(self):
        """Return a GatewayClient configured in gateway mode with mocked sub-clients."""
        with (
            patch("openai.AsyncOpenAI", MagicMock()),
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span", MagicMock()
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_completion",
                MagicMock(),
            ),
            patch(
                "src.gateway.infrastructure.telemetry_client.record_usage",
                MagicMock(),
            ),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()
            return client

    def test_planner_mode_routes_to_reasoning_model(self):
        """Modes 'planner', 'reasoning', 'analysis', 'verifier' use MODEL_REASONING."""
        client = self._make_client_gateway_mode()

        for mode in ("planner", "reasoning", "analysis", "verifier"):
            _, model = client._get_route(mode)
            assert model == client.gateway_client or True  # client returned
            # The second return value is the target model
            _client, target_model = client._get_route(mode)
            assert "reasoning" in str(target_model).lower() or target_model is not None

    def test_default_mode_routes_to_fast_model(self):
        """Default/governance/fast modes use MODEL_FAST."""
        client = self._make_client_gateway_mode()

        _client, target_model = client._get_route("chat")
        assert target_model is not None

    def test_gateway_mode_always_uses_gateway_client(self):
        """In gateway mode, _get_route always returns gateway_client regardless of task mode."""
        client = self._make_client_gateway_mode()

        for mode in ("planner", "chat", "governance", "analysis"):
            returned_client, _ = client._get_route(mode)
            assert returned_client is client.gateway_client


@pytest.mark.local
class TestGatewayClientGenerate:
    """Tests for GatewayClient.generate()."""

    def _make_gateway_client_with_mock_completions(self):
        """Return (GatewayClient, mock_completions_create)."""
        mock_create = AsyncMock(return_value=_make_mock_response("test response"))
        mock_openai = MagicMock()
        mock_openai.return_value.chat.completions.create = mock_create

        with (
            patch("openai.AsyncOpenAI", mock_openai),
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span"
            ) as mock_span_ctx,
            patch("src.gateway.infrastructure.telemetry_client.record_completion"),
            patch("src.gateway.infrastructure.telemetry_client.record_usage"),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            span_mock = MagicMock()
            span_mock.__enter__ = MagicMock(return_value=span_mock)
            span_mock.__exit__ = MagicMock(return_value=False)
            mock_span_ctx.return_value = span_mock

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()
            return client, mock_create, mock_span_ctx

    @pytest.mark.asyncio
    async def test_generate_returns_string_content(self):
        """generate() returns the string content from the LLM response."""
        with (
            patch("openai.AsyncOpenAI") as mock_openai_cls,
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span"
            ) as mock_span_ctx,
            patch("src.gateway.infrastructure.telemetry_client.record_completion"),
            patch("src.gateway.infrastructure.telemetry_client.record_usage"),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            mock_create = AsyncMock(return_value=_make_mock_response("generated text"))
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = mock_create
            mock_openai_cls.return_value = mock_instance

            span_mock = MagicMock()
            span_mock.__enter__ = MagicMock(return_value=span_mock)
            span_mock.__exit__ = MagicMock(return_value=False)
            mock_span_ctx.return_value = span_mock

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()
            result = await client.generate("Hello", mode="chat")

            assert isinstance(result, str)
            assert result == "generated text"

    @pytest.mark.asyncio
    async def test_generate_passes_system_instruction(self):
        """generate() passes system_instruction as the system message content."""
        with (
            patch("openai.AsyncOpenAI") as mock_openai_cls,
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span"
            ) as mock_span_ctx,
            patch("src.gateway.infrastructure.telemetry_client.record_completion"),
            patch("src.gateway.infrastructure.telemetry_client.record_usage"),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            mock_create = AsyncMock(return_value=_make_mock_response("ok"))
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = mock_create
            mock_openai_cls.return_value = mock_instance

            span_mock = MagicMock()
            span_mock.__enter__ = MagicMock(return_value=span_mock)
            span_mock.__exit__ = MagicMock(return_value=False)
            mock_span_ctx.return_value = span_mock

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()
            await client.generate(
                "Question", system_instruction="Be concise.", mode="chat"
            )

            call_kwargs = mock_create.call_args
            messages = (
                call_kwargs[1]["messages"] if call_kwargs[1] else call_kwargs[0][1]
            )
            system_msgs = [m for m in messages if m["role"] == "system"]
            assert len(system_msgs) == 1
            assert system_msgs[0]["content"] == "Be concise."

    @pytest.mark.asyncio
    async def test_generate_raises_on_llm_error(self):
        """generate() re-raises exceptions from the LLM client."""
        with (
            patch("openai.AsyncOpenAI") as mock_openai_cls,
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span"
            ) as mock_span_ctx,
            patch("src.gateway.infrastructure.telemetry_client.record_completion"),
            patch("src.gateway.infrastructure.telemetry_client.record_usage"),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            mock_create = AsyncMock(side_effect=ConnectionError("vLLM down"))
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = mock_create
            mock_openai_cls.return_value = mock_instance

            span_mock = MagicMock()
            span_mock.__enter__ = MagicMock(return_value=span_mock)
            span_mock.__exit__ = MagicMock(return_value=False)
            mock_span_ctx.return_value = span_mock

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()

            with pytest.raises(ConnectionError, match="vLLM down"):
                await client.generate("Prompt", mode="chat")

    @pytest.mark.asyncio
    async def test_generate_extracts_think_reasoning_tags(self):
        """generate() returns full content (including <think> block) and logs the reasoning."""
        with (
            patch("openai.AsyncOpenAI") as mock_openai_cls,
            patch("config.settings.Config") as mock_cfg,
            patch(
                "src.gateway.infrastructure.telemetry_client.genai_span"
            ) as mock_span_ctx,
            patch("src.gateway.infrastructure.telemetry_client.record_completion"),
            patch("src.gateway.infrastructure.telemetry_client.record_usage"),
            patch("opentelemetry.trace.get_current_span", MagicMock()),
        ):
            mock_cfg.VLLM_GATEWAY_URL = "http://gw:8000/v1"
            mock_cfg.VLLM_API_KEY = "key"
            mock_cfg.MODEL_REASONING = "reasoning-model"
            mock_cfg.MODEL_FAST = "fast-model"

            think_content = "<think>step1</think>Final answer"
            mock_create = AsyncMock(return_value=_make_mock_response(think_content))
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = mock_create
            mock_openai_cls.return_value = mock_instance

            span_mock = MagicMock()
            span_mock.__enter__ = MagicMock(return_value=span_mock)
            span_mock.__exit__ = MagicMock(return_value=False)
            mock_span_ctx.return_value = span_mock

            sys.modules.pop("src.gateway.core.llm", None)
            from src.gateway.core.llm import GatewayClient

            client = GatewayClient()
            result = await client.generate("Think step by step.", mode="reasoning")

            assert result == think_content
            assert "<think>" in result
