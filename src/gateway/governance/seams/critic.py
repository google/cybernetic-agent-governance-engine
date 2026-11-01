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
CriticBackend Seam Protocol (Layer 1 Kernel)
============================================

The consensus gate's deterministic half stays in the kernel:

- which actions trigger a check;
- what context each critic may see;
- how the prompt is rendered;
- how a reply is parsed into a vote;
- how votes become a decision.

Only the model call crosses this seam. A concrete backend, such as the
OpenAI-compatible chat-completions client in ``src/integrations/inference_client/``,
lives in Layer 3. It is bound lazily through
``src.gateway.governance.critic_backend_factory``, and only when critics are
enabled and an inference backend exists. The kernel therefore never imports a
model client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Raised when critics are enabled and an inference backend is configured, but
# no critic backend can be bound (for example, the ``inference`` extra is not
# installed). Assembly fails closed rather than escalating every check.
CONSENSUS_CRITIC_BACKEND_UNAVAILABLE = "CONSENSUS_CRITIC_BACKEND_UNAVAILABLE"


@dataclass(frozen=True)
class CriticRequest:
    """One critic consultation, fully rendered by the kernel.

    ``model`` is the critic specification's model. The backend may route a
    role to a dedicated model instead. ``response_format`` is the structured
    output schema the kernel parses against.
    """

    role: str
    model: str
    system_instruction: str
    prompt: str
    timeout_s: float
    response_format: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class CriticBackend(Protocol):
    """Vendor-neutral transport for one critic's reply."""

    async def complete(self, request: CriticRequest) -> str | None:
        """Return the critic's raw reply, or ``None`` when it gave none.

        The kernel parses the reply. A raised exception is an ``ERROR`` vote.
        """
        ...


class CriticBackendUnavailable(RuntimeError):
    """Critics are on and a model exists, but no critic backend can be bound."""

    reason_code = CONSENSUS_CRITIC_BACKEND_UNAVAILABLE

    def __init__(self, detail: str) -> None:
        super().__init__(f"{CONSENSUS_CRITIC_BACKEND_UNAVAILABLE}: {detail}")
