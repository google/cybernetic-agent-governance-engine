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

"""Gateway-internal NeMo action: vLLM fallback.

``InvokeVllmFallbackAction`` is registered with NeMo by
``src.integrations.nemo.action_registry.get_all_actions()``.

The finance safety actions that used to live here (approval token, data
latency, drawdown, slippage, atomic execution) were deleted. No Colang flow
called them (the flows were removed on 2026-03-10; see
``config/rails/definitions.co``), so the per-request STPA/CBF probe that fed
them had no effect. Financial policy is enforced at tool dispatch by the
governor pipeline (safety_check_node -> OPA / STPA / CBF).
"""

import logging
import os

from src.gateway.observability.attributes import (
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
    TRACE_METADATA_GUARDRAILS_INTERVENTION,
    TRACE_METADATA_ISO_CONTROL_ID,
    TRACE_METADATA_ISO_REQUIREMENT,
)

logger = logging.getLogger("NeMo.Actions")


async def InvokeVllmFallbackAction(  # type: ignore[no-untyped-def]
    context: dict | None = None,
    events: list | None = None,
    content: str | None = None,
    **kwargs,  # type: ignore[assignment]
) -> str:
    """
    Action to call vLLM directly for fallback responses.
    Accepts context/events to satisfy NeMo's potential automatic injection, plus explicit content.
    """
    logger.debug(
        "ACTION ARGS: context=%s, events=%s, content=%s, kwargs=%s",
        context,
        events,
        content,
        kwargs,
    )
    # Handle case where content might be passed as positional or keyword, or missing
    # formatting content to be safe
    final_content = content or kwargs.get("content", "")

    logger.warning(f"🔔 InvokeVllmFallbackAction CALLED. content='{final_content}'")

    from src.gateway.infrastructure.telemetry_client import genai_span

    with genai_span(
        "guardrails.vllm_fallback",
        prompt=final_content,
        model=os.environ.get("MODEL_FAST", "vllm-fast"),
    ) as span:
        if span:
            # ISO 42001 Compliance: Transparency & Explainability
            span.set_attribute(TRACE_METADATA_ISO_CONTROL_ID, "A.10.1")
            span.set_attribute(TRACE_METADATA_ISO_REQUIREMENT, "Transparency")
            span.set_attribute(TRACE_METADATA_GUARDRAILS_INTERVENTION, "fallback")
            span.set_attribute(OBSERVATION_TYPE, "generation")

        try:
            if not final_content:
                logger.warning(
                    "InvokeVllmFallbackAction returning default due to empty content"
                )
                return "I apologize, but I didn't catch that."

            logger.debug(
                "Executing InvokeVllmFallbackAction with content='%s'", final_content
            )

            # Restore actual VLLM call for fallback
            from langchain_core.messages import HumanMessage

            from src.integrations.nemo.vllm_client import VLLMLLM

            llm = VLLMLLM()
            # Create a simple message list
            messages = [HumanMessage(content=final_content)]

            # Use _acall (or _agenerate) directly
            response = await llm._acall(messages)  # type: ignore[arg-type]

            if span:
                span.set_attribute(OBSERVATION_OUTPUT, response)

            logger.debug(
                "InvokeVllmFallbackAction returning response length=%d", len(response)
            )
            return response

        except Exception as e:
            logger.error(f"❌ InvokeVllmFallbackAction failed: {e}")
            logger.debug("InvokeVllmFallbackAction EXCEPTION: %s", e)
            import traceback

            traceback.print_exc()
            return "I apologize, but I encountered an error generating a response."
