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

from openai import AsyncOpenAI
from opentelemetry import trace

from config.settings import Config
from src.governed_financial_advisor.utils.telemetry import (
    genai_span,
    record_completion,
    record_usage,
)

logger = logging.getLogger(__name__)


class GatewayClient:
    def __init__(self):
        # Mode 1: Kubernetes Inference Gateway (Unified Endpoint) - Production
        # Supports any Kubernetes-hosted vLLM/inference server (GKE, EKS, AKS, on-prem, etc.)
        if Config.VLLM_GATEWAY_URL:
            logger.info(
                f"🚀 Using Kubernetes Inference Gateway: {Config.VLLM_GATEWAY_URL}"
            )
            self.mode = "gateway"
            self.gateway_client = AsyncOpenAI(
                base_url=Config.VLLM_GATEWAY_URL,
                api_key=Config.VLLM_API_KEY or "EMPTY",
            )
        else:
            # Mode 2: Local / Direct Split-Brain (Dev/Test)
            logger.info("🔧 Using Local Split-Brain Mode (Direct Connection)")
            self.mode = "local"
            # Node A: The Brain
            self.reasoning_client = AsyncOpenAI(
                base_url=Config.VLLM_REASONING_API_BASE,
                api_key=Config.VLLM_API_KEY or "EMPTY",
            )
            # Node B: The Police
            self.governance_client = AsyncOpenAI(
                base_url=Config.VLLM_FAST_API_BASE,
                api_key=Config.VLLM_API_KEY or "EMPTY",
            )

    def _get_route(self, mode: str):
        """
        Determines the (client, model) tuple based on the task mode.
        """
        if mode in ["planner", "reasoning", "analysis", "verifier"]:
            target_model = Config.MODEL_REASONING
            # In gateway mode, we always use the single client.
            # In local mode, we route to the reasoning service.
            client = (
                self.gateway_client if self.mode == "gateway" else self.reasoning_client
            )
            return client, target_model

        # Default / Governance / Fast tasks
        target_model = Config.MODEL_FAST
        client = (
            self.gateway_client if self.mode == "gateway" else self.governance_client
        )
        return client, target_model

    async def generate(
        self, prompt: str, system_instruction: str = None, mode: str = "chat", **kwargs
    ) -> str:
        client, model = self._get_route(mode)

        # Use GenAI Span for Langfuse/OTLP Tracing
        with genai_span(
            name=f"llm.generate.{mode}", prompt=prompt, model=model
        ) as span:
            # Handle FSM / Guided Generation
            extra_body = {}
            if "guided_json" in kwargs:
                extra_body["guided_json"] = kwargs.pop("guided_json")
            elif "guided_regex" in kwargs:
                extra_body["guided_regex"] = kwargs.pop("guided_regex")

            # In Gateway mode, we might want to pass priority headers in the future.
            # For now, relying on the model name in the body is sufficient for Kubernetes routing.

            if extra_body:
                kwargs["extra_body"] = extra_body

            # Inject Trace Context for AgentSight Correlation (Hybrid Strategy)
            extra_headers = kwargs.get("extra_headers", {})
            try:
                current_span = trace.get_current_span()
                if current_span and current_span.get_span_context().is_valid:
                    trace_id = format(current_span.get_span_context().trace_id, "032x")
                    extra_headers["X-Trace-Id"] = trace_id
                    # Also inject full traceparent for standard propagation
                    # extra_headers["traceparent"] = ... (Optional, X-Trace-Id is enough for AgentSight)
            except Exception as e:
                logger.debug(
                    "OTel context extraction failed (non-fatal): %s", e, exc_info=True
                )

            try:
                response = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {
                            "role": "system",
                            "content": system_instruction
                            or "You are a helpful assistant.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    extra_headers=extra_headers,
                    **kwargs,
                )

                # Capture Token Usage
                if getattr(response, "usage", None):
                    record_usage(span, response.usage)

                content = response.choices[0].message.content
                record_completion(span, content)

                # Partition reasoning if present for better logging
                if "<think>" in content:
                    parts = content.split("</think>")
                    if len(parts) > 1:
                        reasoning = parts[0].replace("<think>", "").strip()
                        logger.info(f"🧠 [Reasoning]: {reasoning}")
                    else:
                        logger.info(
                            f"🧠 [Reasoning] (Unterminated): {content[:500]}..."
                        )
                else:
                    logger.info(f"ℹ️ [Response]: {content[:200]}...")

                return content
            except Exception as e:
                logger.error(
                    f"LLM Generation Failed (Mode={mode}, Gateway={self.mode == 'gateway'}): {e}"
                )
                # Span automatically records exception via context manager if we re-raise
                raise
