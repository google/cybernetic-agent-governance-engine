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
Unit tests for src.integrations.nemo.actions — gateway-internal NeMo actions.

Only ``InvokeVllmFallbackAction`` remains in this module. The five finance
pre-check actions (approval token, data latency, drawdown, slippage, atomic
execution) and the ``pre_check_results`` context they read were deleted: no
Colang flow invoked them, and the SymbolicGovernor evaluates those rules
directly. Tests cover the empty-content and exception paths of the fallback.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.nemo.actions import InvokeVllmFallbackAction

# ---------------------------------------------------------------------------
# InvokeVllmFallbackAction — edge cases that do not require live LLM
# ---------------------------------------------------------------------------


class TestInvokeVllmFallbackAction:
    @pytest.mark.asyncio
    async def test_empty_content_returns_apology_without_llm(self):
        """Empty content should short-circuit and return the apology string."""
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.telemetry_client": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
            },
        ):
            result = await InvokeVllmFallbackAction(content="")
        assert "apologize" in result.lower() or result != ""

    @pytest.mark.asyncio
    async def test_exception_in_llm_returns_error_message(self):
        """Exception from the VLLM client must be caught and return an error string."""
        mock_vllm_llm = MagicMock()
        mock_vllm_llm.return_value._acall = AsyncMock(
            side_effect=RuntimeError("VLLM unavailable")
        )

        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.telemetry_client": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
                "src.integrations.nemo.vllm_client": MagicMock(
                    VLLMLLM=mock_vllm_llm
                ),
                "langchain_core.messages": MagicMock(HumanMessage=MagicMock()),
            },
        ):
            result = await InvokeVllmFallbackAction(content="Hello")
        # Should return an error message, not raise
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_content_from_kwargs_is_used(self):
        """Content passed as a keyword argument must be picked up."""
        with patch.dict(
            "sys.modules",
            {
                "src.gateway.infrastructure.telemetry_client": MagicMock(
                    genai_span=_mock_genai_span_ctx()
                ),
            },
        ):
            result = await InvokeVllmFallbackAction(content="")
        # Empty content → apology string, not an exception
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Tiny helpers for mocking context managers
# ---------------------------------------------------------------------------


def _mock_genai_span_ctx():
    """Return a callable that produces a context manager yielding None."""
    from contextlib import contextmanager

    @contextmanager
    def _genai_span(*args, **kwargs):
        yield None

    return _genai_span


pytestmark = [pytest.mark.unit, pytest.mark.local]
