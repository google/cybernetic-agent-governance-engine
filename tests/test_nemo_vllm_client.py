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
Unit tests for src/integrations/nemo/vllm_client.py — VLLMLLM and helpers.

All tests are hermetic:
- litellm is mocked so no real vLLM inference is triggered.
- langchain_core imports are allowed (they are pure Python).
- opentelemetry is mocked to avoid requiring a running collector, except in
  the span-content test, which records real spans in memory.
"""

from __future__ import annotations

import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.observability.attributes import (
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
)
from tests.fixtures.telemetry_canary import CanaryCapture, leaks

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Warm the real parent-package cache (src.gateway.governance, .nemo, etc.)
# *before* any test stubs sys.modules["opentelemetry"] with a bare MagicMock.
# src.gateway.governance.__init__ does `from . import langgraph_harness`,
# which performs real imports (opentelemetry, langgraph, ...). If that
# package hierarchy has never been imported yet when a test's
# patch.dict("sys.modules", {"opentelemetry": MagicMock(), ...}) is active,
# the parent-package import machinery re-executes __init__.py under the
# stubbed (path-less) "opentelemetry" mock and raises AttributeError:
# '__path__'. Importing eagerly here — with the real opentelemetry package —
# ensures the parent packages are already cached in sys.modules by the time
# any per-test stubbing pops only the leaf "vllm_client" module.
try:
    import src.integrations.nemo.vllm_client  # noqa: F401
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_stubs():
    """Return sys.modules patches for heavy optional deps."""
    mock_trace = MagicMock()
    mock_span = MagicMock()
    mock_span.__enter__ = MagicMock(return_value=mock_span)
    mock_span.__exit__ = MagicMock(return_value=False)
    mock_span.set_attribute = MagicMock()
    mock_span.record_exception = MagicMock()
    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.return_value = mock_span
    mock_trace.get_tracer.return_value = mock_tracer

    otel_stub = MagicMock()
    otel_stub.trace = mock_trace
    otel_stub.trace.Status = MagicMock()
    otel_stub.trace.StatusCode = MagicMock(ERROR="ERROR")

    return {
        "opentelemetry": otel_stub,
        "opentelemetry.trace": mock_trace,
        "opentelemetry.trace.Status": MagicMock(),
        "opentelemetry.trace.StatusCode": MagicMock(),
        "src.gateway.infrastructure.config_manager": MagicMock(
            config_manager=MagicMock(
                get=MagicMock(
                    side_effect=lambda k, d=None: {
                        "GUARDRAILS_MODEL_NAME": "test-model",
                        "MODEL_FAST": "fast-model",
                        "VLLM_BASE_URL": "http://vllm:8000/v1",
                        "VLLM_API_KEY": "test-key",
                    }.get(k, d)
                )
            )
        ),
    }


def _make_litellm_response(content: str = "mock output"):
    """Build a minimal litellm completion response mock."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = None
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = MagicMock(prompt_tokens=10, completion_tokens=20)
    return resp


# ---------------------------------------------------------------------------
# Tests: span content (character lengths, never message text)
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestSpanContent:
    """Generation spans record character lengths, never prompt or response text."""

    def test_content_length_counts_only_string_content(self):
        """Multimodal parts and missing content add nothing to the length."""
        from src.integrations.nemo.vllm_client import _content_length

        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world!"},
            {"role": "user", "content": [{"type": "text", "text": "skipped"}]},
            {"role": "system"},
        ]

        assert _content_length(messages) == len("hello") + len("world!")
        assert _content_length([]) == 0

    @pytest.mark.asyncio
    async def test_agenerate_span_carries_lengths_not_content(self):
        """The prompt and the completion reach neither the raw nor the exported span."""
        import sys

        from langchain_core.messages import HumanMessage

        prompt = "canary-prompt-5f1d"
        answer = "canary-answer-a83c"
        stubs = {
            name: module
            for name, module in _minimal_stubs().items()
            if not name.startswith("opentelemetry")
        }
        stubs["litellm"] = MagicMock(
            acompletion=AsyncMock(return_value=_make_litellm_response(answer))
        )
        capture = CanaryCapture()

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            vllm_client = importlib.import_module("src.integrations.nemo.vllm_client")
            llm = vllm_client.VLLMLLM(
                model_name="m", api_base="http://vllm:8000/v1", api_key="k"
            )
            with patch.object(vllm_client, "tracer", capture.tracer):
                result = await llm._agenerate([HumanMessage(content=prompt)])

        assert result.generations[0].message.content == answer
        (span,) = capture.raw_spans()
        assert span.attributes[SPAN_ATTR_CONTENT_INPUT_LENGTH] == len(prompt)
        assert span.attributes[SPAN_ATTR_CONTENT_OUTPUT_LENGTH] == len(answer)
        assert leaks(capture.raw_spans(), prompt, answer) == []
        assert leaks(capture.exported_spans(), prompt, answer) == []


# ---------------------------------------------------------------------------
# Tests: VLLMLLM initialization
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestVLLMLLMInit:
    """Tests for VLLMLLM.__init__()."""

    def test_raises_when_api_base_is_empty(self):
        """VLLMLLM raises RuntimeError when VLLM_BASE_URL is empty/None.

        Note: ``api_base`` is a non-Optional pydantic ``str`` field, so passing
        ``api_base=None`` explicitly raises a pydantic ValidationError before
        the custom RuntimeError guard in __init__ ever runs. To exercise the
        RuntimeError guard, we instead rely on the class-level default (which
        reads VLLM_BASE_URL via config_manager) being empty, and simply omit
        api_base from the constructor call so pydantic uses that falsy default.
        """
        import sys

        stubs = _minimal_stubs()
        stubs["src.gateway.infrastructure.config_manager"] = MagicMock(
            config_manager=MagicMock(
                get=MagicMock(
                    side_effect=lambda k, d=None: {
                        "GUARDRAILS_MODEL_NAME": "model",
                        "MODEL_FAST": "fast",
                        "VLLM_BASE_URL": "",  # ← missing/empty
                        "VLLM_API_KEY": "key",
                    }.get(k, d)
                )
            )
        )

        with patch.dict("sys.modules", stubs):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            from src.integrations.nemo.vllm_client import VLLMLLM

            with pytest.raises(RuntimeError, match="VLLM_BASE_URL"):
                VLLMLLM(model_name="model", api_key="key")

    def test_llm_type_is_vllm(self):
        """_llm_type property returns 'vllm'."""
        import sys

        with patch.dict("sys.modules", _minimal_stubs()):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            from src.integrations.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM(
                model_name="test-model",
                api_base="http://vllm:8000/v1",
                api_key="key",
            )

        assert llm._llm_type == "vllm"

    def test_identifying_params_contains_model_and_base(self):
        """_identifying_params includes model and api_base."""
        import sys

        with patch.dict("sys.modules", _minimal_stubs()):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            from src.integrations.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM(
                model_name="llama-3",
                api_base="http://vllm:8000/v1",
                api_key="key",
            )

        params = llm._identifying_params
        assert "model" in params
        assert "api_base" in params
        assert params["model"] == "llama-3"


# ---------------------------------------------------------------------------
# Tests: VLLMLLM._acall
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestVLLMLLMAcall:
    """Tests for VLLMLLM._acall() (NeMo async string interface)."""

    @pytest.mark.asyncio
    async def test_acall_returns_empty_string_for_empty_messages(self):
        """_acall returns '' when messages list is empty."""
        import sys

        with patch.dict("sys.modules", _minimal_stubs()):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            from src.integrations.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM(
                model_name="m",
                api_base="http://vllm:8000/v1",
                api_key="k",
            )

        result = await llm._acall([])
        assert result == ""

    @pytest.mark.asyncio
    async def test_acall_delegates_to_agenerate(self):
        """_acall delegates to _agenerate and returns the generated content."""
        import sys

        from langchain_core.messages import AIMessage, HumanMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        with patch.dict("sys.modules", _minimal_stubs()):
            sys.modules.pop("src.integrations.nemo.vllm_client", None)
            from src.integrations.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM(
                model_name="m",
                api_base="http://vllm:8000/v1",
                api_key="k",
            )

        expected = "this is the answer"
        mock_result = ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=expected))]
        )

        with patch.object(llm, "_agenerate", AsyncMock(return_value=mock_result)):
            result = await llm._acall([HumanMessage(content="question")])

        assert result == expected


# ---------------------------------------------------------------------------
# Tests: timeout constants
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestTimeoutConstants:
    """Tests for the per-rail timeout constants."""

    def test_nemo_timeout_default_is_45(self):
        """NEMO_VLLM_TIMEOUT_SECONDS defaults to 45.0."""
        import os
        import sys

        env = {k: v for k, v in os.environ.items() if k != "NEMO_VLLM_TIMEOUT_SECONDS"}

        with patch.dict("sys.modules", _minimal_stubs()):
            with patch.dict(os.environ, env, clear=True):
                sys.modules.pop("src.integrations.nemo.vllm_client", None)
                from src.integrations.nemo.vllm_client import (
                    NEMO_VLLM_TIMEOUT_SECONDS,
                )

        assert NEMO_VLLM_TIMEOUT_SECONDS == 45.0

    def test_advisor_timeout_default_is_90(self):
        """ADVISOR_VLLM_TIMEOUT_SECONDS defaults to 90.0."""
        import os
        import sys

        env = {
            k: v for k, v in os.environ.items() if k != "ADVISOR_VLLM_TIMEOUT_SECONDS"
        }

        with patch.dict("sys.modules", _minimal_stubs()):
            with patch.dict(os.environ, env, clear=True):
                sys.modules.pop("src.integrations.nemo.vllm_client", None)
                from src.integrations.nemo.vllm_client import (
                    ADVISOR_VLLM_TIMEOUT_SECONDS,
                )

        assert ADVISOR_VLLM_TIMEOUT_SECONDS == 90.0

    def test_nemo_timeout_respects_env_override(self):
        """NEMO_VLLM_TIMEOUT_SECONDS can be overridden by environment variable."""
        import os
        import sys

        with patch.dict("sys.modules", _minimal_stubs()):
            with patch.dict(os.environ, {"NEMO_VLLM_TIMEOUT_SECONDS": "30"}):
                sys.modules.pop("src.integrations.nemo.vllm_client", None)
                from src.integrations.nemo.vllm_client import (
                    NEMO_VLLM_TIMEOUT_SECONDS,
                )

        assert NEMO_VLLM_TIMEOUT_SECONDS == 30.0
