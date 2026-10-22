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

"""Unit tests for PR B5: advisor and NeMo hot-path non-blocking execution."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.observability.langfuse_utils import (
    PromptRegistry,
    get_managed_prompt,
    get_prompt_registry,
)
from src.governed_financial_advisor.infrastructure.llm.models import (
    DEFAULT_LLM_MAX_RETRIES,
    DEFAULT_LLM_TIMEOUT,
    chat_model,
    clear_chat_model_cache,
)
from src.governed_financial_advisor.utils.text_utils import strip_thinking_tags

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestStripThinkingTagsLinear:
    """Verify linear-time O(N) strip_thinking_tags implementation."""

    def test_empty_and_plain_text(self) -> None:
        assert strip_thinking_tags("") == ""
        assert strip_thinking_tags("Hello world") == "Hello world"

    def test_single_and_multiple_complete_think_blocks(self) -> None:
        raw = "<think>internal reasoning</think>Final answer."
        assert strip_thinking_tags(raw) == "Final answer."

        multi = "Prefix <think>one</think> middle <think>two\nmultiline</think> suffix"
        assert strip_thinking_tags(multi) == "Prefix  middle  suffix"

    def test_unclosed_trailing_think_tag_stripped_to_end(self) -> None:
        raw = "Visible prefix <think>truncated reasoning without closing tag"
        assert strip_thinking_tags(raw) == "Visible prefix"

    def test_orphan_closing_think_tag_strips_prefix(self) -> None:
        raw = "leaked chain of thought</think>Clean user-visible answer"
        assert strip_thinking_tags(raw) == "Clean user-visible answer"

    def test_32k_unclosed_and_nested_tags_under_10ms(self) -> None:
        payload = "<think>" + ("reasoning token " * 2048)
        assert len(payload) >= 32768
        start = time.perf_counter()
        result = strip_thinking_tags(payload)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert result == ""
        assert elapsed_ms < 10.0, f"strip_thinking_tags took {elapsed_ms:.2f}ms"


class TestPromptRegistryMemoryLookup:
    """Verify PromptRegistry serves prompts from memory without synchronous HTTP."""

    def test_get_managed_prompt_returns_fallback_with_zero_http_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = get_prompt_registry()
        registry.clear()
        monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
        monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-test")
        monkeypatch.setenv("LANGFUSE_HOST", "http://langfuse.invalid:3000")

        with patch("httpx.get", side_effect=AssertionError("sync httpx.get forbidden")):
            result = get_managed_prompt("agent/supervisor", "FALLBACK_PROMPT")
        assert result == "FALLBACK_PROMPT"

    def test_prompt_registry_refresh_populates_cache_and_serves_from_memory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPLIANCE_BRIDGE_URL", "http://bridge.local:3001")

        registry = PromptRegistry(refresh_interval_seconds=60.0)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"text": "MANAGED_EXPLAINER_PROMPT"}

        async def _run() -> None:
            mock_client = AsyncMock()
            mock_client.is_closed = False
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.aclose = AsyncMock()
            registry._client = mock_client

            await registry.refresh_all(names=("agent/explainer",))
            assert (
                registry.get("agent/explainer", "FALLBACK")
                == "MANAGED_EXPLAINER_PROMPT"
            )
            await registry.stop()

        asyncio.run(_run())

    def test_prompt_registry_start_and_stop_lifecycle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = PromptRegistry(refresh_interval_seconds=300.0)

        async def _run() -> None:
            with patch.object(registry, "refresh_all", new=AsyncMock()):
                await registry.start(names=("agent/supervisor",))
                assert registry._task is not None
                await registry.stop()
                assert registry._task is None

        asyncio.run(_run())


class TestChatModelCachingAndTimeouts:
    """Verify chat_model() caches instances and sets explicit timeouts/retries."""

    def setup_method(self) -> None:
        clear_chat_model_cache()

    def teardown_method(self) -> None:
        clear_chat_model_cache()

    def test_chat_model_reuses_cached_instance_and_sets_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VLLM_FAST_API_BASE", "http://vllm-fast.local:8000/v1")
        monkeypatch.setenv(
            "VLLM_REASONING_API_BASE", "http://vllm-reason.local:8000/v1"
        )
        monkeypatch.setenv("MODEL_FAST", "Qwen/Qwen2.5-7B")
        monkeypatch.setenv("MODEL_REASONING", "DeepSeek-R1")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        m1 = chat_model("fast", temperature=0.0)
        m2 = chat_model("fast", temperature=0.0)
        m3 = chat_model("reasoning", temperature=0.6)

        assert m1 is m2
        assert m1 is not m3
        assert m1.request_timeout == DEFAULT_LLM_TIMEOUT
        assert m1.max_retries == DEFAULT_LLM_MAX_RETRIES

    def test_explainer_and_execution_analyst_reuse_chat_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VLLM_FAST_API_BASE", "http://vllm-fast.local:8000/v1")
        monkeypatch.setenv(
            "VLLM_REASONING_API_BASE", "http://vllm-reason.local:8000/v1"
        )
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        from src.governed_financial_advisor.agents.explainer.agent import (
            create_explainer_agent,
        )

        e1 = create_explainer_agent("test-fast-model")
        e2 = create_explainer_agent("test-fast-model")
        assert e1 is e2


class TestAsyncGraphNodesAndThreadOffload:
    """Verify graph nodes are async coroutines and offload blocking work."""

    def test_supervisor_and_analyst_nodes_are_async_and_await_ainvoke(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.governed_financial_advisor.graph.nodes.supervisor_node import (
            doer_node,
            thinker_node,
        )
        from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
            analyst_reporter_node,
            analyst_thinker_node,
        )

        assert inspect.iscoroutinefunction(thinker_node)
        assert inspect.iscoroutinefunction(doer_node)
        assert inspect.iscoroutinefunction(analyst_thinker_node)
        assert inspect.iscoroutinefunction(analyst_reporter_node)

        monkeypatch.setenv(
            "VLLM_REASONING_API_BASE", "http://vllm-reason.local:8000/v1"
        )
        monkeypatch.setenv("VLLM_FAST_API_BASE", "http://vllm-fast.local:8000/v1")

        fake_response = MagicMock()
        fake_response.content = "<think>plan</think>Analysis complete"
        fake_llm = MagicMock()
        fake_llm.ainvoke = AsyncMock(return_value=fake_response)

        msg = MagicMock()
        msg.content = "Check AAPL fundamentals"

        async def _run() -> None:
            with patch(
                "src.governed_financial_advisor.graph.subgraphs.data_analyst_graph.chat_model",
                return_value=fake_llm,
            ):
                out = await analyst_thinker_node(
                    {"messages": [msg], "reasoning_output": None}
                )
                assert out["reasoning_output"] == "<think>plan</think>Analysis complete"
                fake_llm.ainvoke.assert_awaited_once()

                rep = await analyst_reporter_node(
                    {"messages": [msg], "reasoning_output": " some thoughts "}
                )
                assert len(rep["messages"]) == 1

        asyncio.run(_run())

    def test_presidio_init_lock_blocks_concurrent_readers_until_initialized(
        self,
    ) -> None:
        import src.integrations.presidio.redactor as redactor_mod

        barrier = threading.Event()
        proceed = threading.Event()
        observed_mid_init: list[tuple[bool, Any]] = []

        orig_done = redactor_mod._presidio_init_done
        orig_analyzer = redactor_mod._presidio_analyzer
        orig_anonymizer = redactor_mod._presidio_anonymizer
        try:
            redactor_mod._presidio_init_done = False
            redactor_mod._presidio_analyzer = None
            redactor_mod._presidio_anonymizer = None

            fake_analyzer = object()
            fake_anonymizer = object()

            def _slow_init() -> tuple[Any, Any]:
                with redactor_mod._presidio_init_lock:
                    if redactor_mod._presidio_init_done:
                        return (
                            redactor_mod._presidio_analyzer,
                            redactor_mod._presidio_anonymizer,
                        )
                    barrier.set()
                    proceed.wait(timeout=2.0)
                    redactor_mod._presidio_analyzer = fake_analyzer
                    redactor_mod._presidio_anonymizer = fake_anonymizer
                    redactor_mod._presidio_init_done = True
                    return fake_analyzer, fake_anonymizer

            with patch.object(
                redactor_mod, "get_presidio_engines", side_effect=_slow_init
            ):
                t1 = threading.Thread(target=redactor_mod.get_presidio_engines)
                t1.start()
                assert barrier.wait(timeout=2.0)
                # While t1 holds the lock inside initialization, _presidio_init_done is Still False
                observed_mid_init.append(
                    (redactor_mod._presidio_init_done, redactor_mod._presidio_analyzer)
                )
                proceed.set()
                t1.join(timeout=2.0)

            assert observed_mid_init == [(False, None)]
            assert redactor_mod._presidio_init_done is True
            assert redactor_mod._presidio_analyzer is fake_analyzer
        finally:
            redactor_mod._presidio_init_done = orig_done
            redactor_mod._presidio_analyzer = orig_analyzer
            redactor_mod._presidio_anonymizer = orig_anonymizer
