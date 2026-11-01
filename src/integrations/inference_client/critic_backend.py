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

"""Consensus critic backend over OpenAI-compatible chat completions (Layer 3).

Implements the kernel's ``CriticBackend`` seam
(``src.gateway.governance.seams.critic``). The kernel renders each critic's
prompt and parses its reply. This module only carries the request to a model.

Priority 4 (Evidentiary Independence): each critic role can run on its own
model backend, configured per role ``{ROLE}`` (upper snake case):

- ``CONSENSUS_{ROLE}_URL``: the base URL for the role.
- ``CONSENSUS_{ROLE}_MODEL``: the model for the role.

Without a dedicated URL, roles alternate between the split-brain
``VLLM_REASONING_API_BASE`` and ``VLLM_FAST_API_BASE`` endpoints. A role with
neither falls back to :class:`InferenceClient` in ``verifier`` mode. That
client raises :class:`InferenceEndpointMissing` when no endpoint is configured
(IB-4); the kernel turns the exception into an ``ERROR`` vote.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, cast

from openai import AsyncOpenAI

from config.settings import Config
from src.gateway.governance.seams.critic import CriticRequest
from src.integrations.inference_client.client import InferenceClient

if TYPE_CHECKING:
    from openai.types.chat import ChatCompletionMessageParam
    from openai.types.shared_params import ResponseFormatJSONSchema

logger = logging.getLogger(__name__)

_SPLIT_BRAIN_FALLBACKS: tuple[tuple[str, str], ...] = (
    ("VLLM_REASONING_API_BASE", "MODEL_REASONING"),
    ("VLLM_FAST_API_BASE", "MODEL_FAST"),
)


def role_env_key(role: str) -> str:
    """``CONSENSUS_{ROLE}_*`` key for a critic role."""
    return role.upper().replace(" ", "_").replace("-", "_")


class RoutedCriticBackend:
    """Route each critic role to its own model, else to the shared client.

    Args:
        persona_configs: Role name to a mapping with ``base_url`` and
            ``model`` keys. A role with no ``base_url`` uses ``fallback``.
        fallback: The shared client for roles without a dedicated endpoint.
            Built from ``Config`` when omitted.
    """

    def __init__(
        self,
        persona_configs: Mapping[str, Mapping[str, str]],
        fallback: InferenceClient | None = None,
    ) -> None:
        self._clients: dict[str, AsyncOpenAI] = {}
        self._models: dict[str, str] = {}
        for role, config in persona_configs.items():
            base_url = config.get("base_url", "")
            self._models[role] = config.get("model", "")
            if base_url:
                self._clients[role] = AsyncOpenAI(
                    base_url=base_url,
                    api_key=Config.VLLM_API_KEY or "EMPTY",
                )
                logger.info(
                    "[critic-backend] %s → %s (model=%s)",
                    role,
                    base_url,
                    self._models[role] or "default",
                )
            else:
                logger.warning(
                    "[critic-backend] %s has no dedicated URL — it will use the "
                    "shared inference client. This reduces model diversity and "
                    "weakens consensus independence.",
                    role,
                )
        self._fallback = fallback if fallback is not None else InferenceClient()

    @classmethod
    def from_env(cls, roles: Sequence[str] = ()) -> RoutedCriticBackend:
        """Read ``CONSENSUS_{ROLE}_URL`` and ``CONSENSUS_{ROLE}_MODEL`` per role."""
        persona_configs: dict[str, dict[str, str]] = {}
        for idx, role in enumerate(roles):
            key = role_env_key(role)
            fb_url_var, fb_model_var = _SPLIT_BRAIN_FALLBACKS[
                idx % len(_SPLIT_BRAIN_FALLBACKS)
            ]
            persona_configs[role] = {
                "base_url": os.environ.get(
                    f"CONSENSUS_{key}_URL", os.environ.get(fb_url_var, "")
                ),
                "model": os.environ.get(
                    f"CONSENSUS_{key}_MODEL", os.environ.get(fb_model_var, "")
                ),
            }
        return cls(persona_configs)

    def has_dedicated_backend(self, role: str) -> bool:
        """True if the role has its own endpoint rather than the shared client."""
        return role in self._clients

    def model_for(self, role: str) -> str:
        """The model configured for the role, or an empty string."""
        return self._models.get(role, "")

    async def complete(self, request: CriticRequest) -> str | None:
        """Send one rendered critic request and return the raw reply."""
        response_format: dict[str, Any] = dict(request.response_format)
        dedicated = self._clients.get(request.role)
        if dedicated is not None:
            messages: list[ChatCompletionMessageParam] = [
                {"role": "system", "content": request.system_instruction},
                {"role": "user", "content": request.prompt},
            ]
            response = await dedicated.chat.completions.create(
                model=self._models.get(request.role) or request.model or "default",
                messages=messages,
                temperature=0.0,
                # The kernel's schema is a json_schema response format.
                response_format=cast("ResponseFormatJSONSchema", response_format),
                timeout=request.timeout_s,
            )
            choices = getattr(response, "choices", None)
            return choices[0].message.content if choices else None
        return await self._fallback.generate(
            prompt=request.prompt,
            system_instruction=request.system_instruction,
            mode="verifier",
            temperature=0.0,
            response_format=response_format,
        )
