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

import logging
import json
from typing import Any, List, Optional, AsyncIterator
import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessageChunk, AIMessage
from langchain_core.outputs import ChatGenerationChunk, ChatResult, ChatGeneration
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

try:
    from src.governed_financial_advisor.infrastructure.config_manager import config_manager
except ImportError:
    class _MockConfigManager:
        def get(self, key: str, default: Any = None) -> Any:
            return os.environ.get(key, default)
    config_manager = _MockConfigManager()

# Configure Logging
logger = logging.getLogger("NeMo.LLM")
tracer = trace.get_tracer("src.gateway.governance.nemo.vllm_client")

# Maximum characters for span string attributes (mirrors telemetry.py limit).
_VLLM_SPAN_ATTR_MAX_CHARS = 8_000


def _truncate(value: str, max_chars: int = _VLLM_SPAN_ATTR_MAX_CHARS) -> str:
    """Truncate a string to *max_chars* with a [TRUNCATED] suffix."""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + " [TRUNCATED]"

# ---------------------------------------------------------------------------
# Per-rail timeout constants
# ---------------------------------------------------------------------------
# NeMo guardrail rail calls (input + output).  Two rails at 45 s each = 90 s
# max combined, well within the 110 s graph deadline in server.py.
NEMO_VLLM_TIMEOUT_SECONDS: float = float(
    os.environ.get("NEMO_VLLM_TIMEOUT_SECONDS", "45")
)
# Financial advisor's direct LLM calls (may use a larger reasoning model).
ADVISOR_VLLM_TIMEOUT_SECONDS: float = float(
    os.environ.get("ADVISOR_VLLM_TIMEOUT_SECONDS", "90")
)


class VLLMLLM(BaseChatModel):
    """Custom LangChain-compatible wrapper for vLLM using LiteLLM."""

    model_name: str = config_manager.get("GUARDRAILS_MODEL_NAME", config_manager.get("MODEL_FAST"))
    api_base: str = config_manager.get("VLLM_BASE_URL")
    api_key: str = config_manager.get("VLLM_API_KEY", "EMPTY")
    # Per-instance timeout — defaults to NeMo rail budget since this class is
    # primarily constructed by the NeMo guardrail manager.  Advisor-side callers
    # should pass timeout=ADVISOR_VLLM_TIMEOUT_SECONDS at construction time.
    timeout: float = NEMO_VLLM_TIMEOUT_SECONDS

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.api_base:
            raise RuntimeError("VLLM_BASE_URL must be set — no localhost fallback in production")
        logger.debug("VLLMLLM initialized with model=%s, base=%s", self.model_name, self.api_base)

    @property
    def _llm_type(self) -> str:
        return "vllm"

    def _generate(self, messages: List[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        """Call the vLLM model via LiteLLM."""
        with tracer.start_as_current_span("nemo.guardrails.llm.generate") as span:
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("langfuse.observation.type", "generation")
            span.set_attribute("gen_ai.system", "nemo-guardrails")
            span.set_attribute("nemo.vllm.timeout", self.timeout)
            try:
                import litellm

                # Enable generic vLLM support via OpenAI protocol
                # We use custom_llm_provider="openai" instead of prefixing model_name
                # to avoid sending "openai/" prefix to the vLLM server (which causes 404).
                model_id = self.model_name

                # Dynamic Routing Logic
                api_base = self.api_base
                if "deepseek" in model_id.lower() or "reasoning" in model_id.lower():
                    reasoning_base = config_manager.get("VLLM_REASONING_API_BASE")
                    if reasoning_base:
                        api_base = reasoning_base
                        logger.debug("Routing to Reasoning Service: %s", api_base)
                else:
                    fast_base = config_manager.get("VLLM_FAST_API_BASE")
                    if fast_base:
                        api_base = fast_base
                        logger.debug("Routing to Fast/Governance Service: %s", api_base)

                span.set_attribute("gen_ai.request.model", model_id)
                span.set_attribute("nemo.vllm.api_base", api_base)

                logger.debug("Calling vLLM via litellm... model=%s base=%s", model_id, api_base)

                # Format messages for litellm
                formatted_messages = [{"role": m.type if m.type != "ai" else "assistant", "content": m.content} for m in messages]
                # Map 'human' to 'user' if needed
                for m in formatted_messages:
                    if m["role"] == "human":
                        m["role"] = "user"

                span.set_attribute(
                    "gen_ai.input.messages",
                    _truncate(json.dumps(formatted_messages)),
                )

                response = litellm.completion(
                    model=model_id,
                    custom_llm_provider="openai",
                    api_base=api_base,
                    api_key=self.api_key,
                    messages=formatted_messages,
                    stop=stop,
                    **kwargs
                )

                content = response.choices[0].message.content
                span.set_attribute(
                    "gen_ai.output.messages",
                    _truncate(json.dumps([{"role": "assistant", "content": content}])),
                )
                # Record token usage when available
                if getattr(response, "usage", None):
                    span.set_attribute("gen_ai.usage.input_tokens", response.usage.prompt_tokens or 0)
                    span.set_attribute("gen_ai.usage.output_tokens", response.usage.completion_tokens or 0)
                return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                logger.error("Failed to call vLLM: %s", e)
                raise

    async def _acall(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, run_manager: Any = None, **kwargs: Any) -> str:
        """NeMo 0.10.0+ Compat: Wraps _agenerate to return string."""
        if not messages:
            return ""
            
        result = await self._agenerate(messages, stop=stop, run_manager=run_manager, **kwargs)
        return result.generations[0].message.content

    async def _agenerate(self, messages: List[BaseMessage], stop: list[str] | None = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        """Async call to the vLLM model via LiteLLM."""
        with tracer.start_as_current_span("nemo.guardrails.llm.agenerate") as span:
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("langfuse.observation.type", "generation")
            span.set_attribute("gen_ai.system", "nemo-guardrails")
            span.set_attribute("nemo.vllm.timeout", self.timeout)
            try:
                import litellm

                model_id = self.model_name.replace("openai/", "")

                logger.debug("VLLMLLM using model_id='%s' (original='%s')", model_id, self.model_name)

                # Dynamic Routing Logic (Async)
                api_base = self.api_base
                if "deepseek" in model_id.lower() or "reasoning" in model_id.lower():
                    reasoning_base = config_manager.get("VLLM_REASONING_API_BASE")
                    if reasoning_base:
                        api_base = reasoning_base
                        logger.debug("Routing to Reasoning Service: %s", api_base)
                else:
                    fast_base = config_manager.get("VLLM_FAST_API_BASE")
                    if fast_base:
                        api_base = fast_base
                        logger.debug("Routing to Fast/Governance Service: %s", api_base)

                span.set_attribute("gen_ai.request.model", model_id)
                span.set_attribute("nemo.vllm.api_base", api_base)

                logger.debug("Async Calling vLLM via litellm... model=%s base=%s", model_id, api_base)

                formatted_messages = [{"role": m.type if m.type != "ai" else "assistant", "content": m.content} for m in messages]
                for m in formatted_messages:
                    if m["role"] == "human":
                        m["role"] = "user"

                span.set_attribute(
                    "gen_ai.input.messages",
                    _truncate(json.dumps(formatted_messages)),
                )

                # Use per-instance timeout (set at construction time).
                # Defaults to NEMO_VLLM_TIMEOUT_SECONDS (45 s) for NeMo rail calls.
                # Advisor-side callers pass timeout=ADVISOR_VLLM_TIMEOUT_SECONDS (90 s).
                # Two NeMo rails at 45 s each = 90 s max combined, within the
                # 110 s graph deadline enforced by asyncio.wait_for() in server.py.
                response = await litellm.acompletion(
                    model=model_id,
                    custom_llm_provider="openai",
                    api_base=api_base,
                    api_key=self.api_key,
                    messages=formatted_messages,
                    stop=stop,
                    timeout=self.timeout,
                    **kwargs
                )
                completion_message = response.choices[0].message
                content = completion_message.content or ""

                # Record token usage when available
                if getattr(response, "usage", None):
                    span.set_attribute("gen_ai.usage.input_tokens", response.usage.prompt_tokens or 0)
                    span.set_attribute("gen_ai.usage.output_tokens", response.usage.completion_tokens or 0)

                tool_calls = getattr(completion_message, "tool_calls", None)
                if tool_calls:
                    lc_tool_calls = []
                    for t in tool_calls:
                        args = t.function.arguments
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError as e:
                                logger.warning("Failed to parse tool_call arguments as JSON: %s. args=%r", e, args)
                        lc_tool_calls.append({
                            "name": t.function.name,
                            "args": args,
                            "id": t.id
                        })
                    logger.debug("vLLM Response Tool Calls: %s", lc_tool_calls)
                    span.set_attribute(
                        "gen_ai.output.messages",
                        _truncate(json.dumps([{"role": "assistant", "content": content, "tool_calls": lc_tool_calls}])),
                    )
                    return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content, tool_calls=lc_tool_calls))])
                else:
                    logger.debug("vLLM Response Content: %s...", content[:100])
                    span.set_attribute(
                        "gen_ai.output.messages",
                        _truncate(json.dumps([{"role": "assistant", "content": content}])),
                    )
                    return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                logger.error("❌ Failed to initialize/call vLLM: %s", e)
                raise

    async def _astream(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, run_manager: Any = None, **kwargs: Any) -> AsyncIterator[ChatGenerationChunk]:
        """
        Enables Optimistic Streaming for NeMo Guardrails.
        """
        with tracer.start_as_current_span("nemo.guardrails.llm.astream") as span:
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("langfuse.observation.type", "generation")
            span.set_attribute("gen_ai.system", "nemo-guardrails")
            span.set_attribute("gen_ai.request.model", self.model_name)
            try:
                import litellm

                model_id = self.model_name
                if not model_id.startswith("/") and not model_id.startswith("openai/") and "gpt" not in model_id:
                    model_id = f"openai/{model_id}"

                formatted_messages = [{"role": m.type if m.type != "ai" else "assistant", "content": m.content} for m in messages]
                for m in formatted_messages:
                    if m["role"] == "human":
                        m["role"] = "user"

                span.set_attribute(
                    "gen_ai.input.messages",
                    _truncate(json.dumps(formatted_messages)),
                )

                # Use litellm with stream=True
                stream = await litellm.acompletion(
                    model=model_id,
                    messages=formatted_messages,
                    api_base=self.api_base,
                    api_key=self.api_key,
                    stream=True,
                    stop=stop,
                    **kwargs
                )

                collected_content: list[str] = []
                async for chunk in stream:
                    content = chunk.choices[0].delta.content
                    if content:
                        collected_content.append(content)
                        # Yield it as a LangChain Chunk for NeMo
                        yield ChatGenerationChunk(message=AIMessageChunk(content=content))
                        # Optional: Notify callbacks
                        if run_manager:
                            await run_manager.on_llm_new_token(content)

                span.set_attribute(
                    "gen_ai.output.messages",
                    _truncate(json.dumps([{"role": "assistant", "content": "".join(collected_content)}])),
                )

            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                logger.error("vLLM streaming failed: %s", e)
                raise

    @property
    def _identifying_params(self) -> dict:
        return {"model": self.model_name, "api_base": self.api_base}
