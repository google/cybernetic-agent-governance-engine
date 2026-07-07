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

import os
import sys

import pytest

pytest.importorskip("nemoguardrails")
pytestmark = pytest.mark.unit
from unittest.mock import patch

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from nemoguardrails.llm.providers import register_llm_provider

from src.gateway.governance.nemo.manager import create_nemo_manager


class MockLLM(BaseChatModel):
    """Mocks the LLM to echo the input."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._create_response(messages)

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._create_response(messages)

    def _create_response(self, messages):
        last_msg = messages[-1].content
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=f"Echo: {last_msg}"))]
        )

    @property
    def _llm_type(self):
        return "mock"

    async def _acall(
        self,
        messages: list[Any],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> str:
        return f"Echo: {messages[-1].content}"

    def _call(
        self,
        messages: list[Any],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> str:
        return f"Echo: {messages[-1].content}"


@pytest.fixture
def rails():
    # Pre-register our mock LLM
    register_llm_provider("vllm_llama", MockLLM)

    # Patch register_llm_provider to prevent re-registration or errors
    with patch("src.gateway.governance.nemo.manager.register_llm_provider"):
        app = create_nemo_manager()
        return app


def test_pii_activation_logic(rails):
    """
    Verifies that PII filtering logic is correctly activated and monkeypatched.
    """
    # 1. Verify Monkeypatch
    from nemoguardrails.library.sensitive_data_detection.actions import _get_analyzer

    assert _get_analyzer.__name__ == "_get_analyzer_patch", (
        "Presidio Analyzer should be monkeypatched to use en_core_web_sm"
    )

    # 3. Verify Direct Action Execution (Unit Test Style)
    # This ensures the logic works, avoiding the fragile 'input rails' flow integration in mock environment
    import asyncio

    from nemoguardrails.library.sensitive_data_detection.actions import (
        mask_sensitive_data,
    )

    text = "My name is John Doe."
    masked = asyncio.run(
        mask_sensitive_data(source="input", text=text, config=rails.config)
    )

    print(f"Masked Output: {masked}")
    assert "<PERSON>" in masked
