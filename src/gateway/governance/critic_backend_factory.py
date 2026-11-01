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
Critic Backend Factory (Layer 1 Kernel)
=======================================

Single allowlisted factory module in Layer 1 that lazily binds the Layer 3
consensus critic backend (default: ``src.integrations.inference_client``).

``ConsensusGate`` calls :func:`load_critic_backend` only when critics are
enabled (``CAGE_CONSENSUS_CRITICS_ENABLED=true``) and an inference backend
exists (``CAGE_INFERENCE_BACKEND`` is not ``none``). On every other path,
including the default one, no model client package is imported.
"""

from __future__ import annotations

from collections.abc import Sequence

from src.gateway.governance.seams.critic import (
    CriticBackend,
    CriticBackendUnavailable,
)


def load_critic_backend(roles: Sequence[str]) -> CriticBackend:
    """Bind the Layer 3 critic backend for the given critic roles.

    Raises:
        CriticBackendUnavailable: The backend's package is not installed (the
            ``inference`` extra). Assembly fails closed: critics were asked
            for and a model exists, so silently escalating every check would
            misreport the configuration.
    """
    try:
        from src.integrations.inference_client.critic_backend import (
            RoutedCriticBackend,
        )
    except ModuleNotFoundError as exc:
        raise CriticBackendUnavailable(
            "consensus critics are enabled and an inference backend is "
            f"configured, but the critic backend cannot be imported (missing "
            f"module {exc.name!r}); install the 'inference' extra"
        ) from exc
    return RoutedCriticBackend.from_env(roles)
