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
Semantic Rail Factory (Layer 1 Kernel)
======================================

Single allowlisted factory module in Layer 1 that lazily binds the configured
Layer 3 semantic dialogue rail provider (default: ``src.integrations.nemo``).
All Layer 1 servers and LangGraph harness factories route through this module
so that ``src/gateway/`` never imports ``src.integrations.nemo`` directly.

Every rail construction passes through :func:`semantic_rails_refusal`. That
includes gateway startup, the inference proxy's on-demand build, the
LangGraph rail nodes and the hot-reload path. Rails the configuration turned
off therefore cannot be built at runtime, whichever path asks for them.
"""

from __future__ import annotations

from typing import Any

from src.gateway.governance.content_safety import (
    CONTENT_SAFETY_NO_INFERENCE_BACKEND,
    CONTENT_SAFETY_RAILS_DISABLED,
)
from src.gateway.governance.feature_flags import nemo_rails_enabled
from src.gateway.governance.inference_backend import (
    InferenceBackendUnavailable,
    inference_disabled,
)


class SemanticRailsDisabled(RuntimeError):
    """The semantic rails are off by configuration (``CAGE_NEMO_ENABLED=false``).

    Not a failure: no rails were asked for. ``str()`` leads with
    :data:`~src.gateway.governance.content_safety.CONTENT_SAFETY_RAILS_DISABLED`,
    so a caller that records the error text records the reason code too.
    """

    reason_code = CONTENT_SAFETY_RAILS_DISABLED

    def __init__(self, message: str) -> None:
        super().__init__(f"{CONTENT_SAFETY_RAILS_DISABLED}: {message}")


def semantic_rails_refusal() -> tuple[str, str] | None:
    """Return ``(reason_code, detail)`` when no semantic rails may be built, else ``None``.

    This is the runtime counterpart of the ``nemo_rails_backend`` startup check
    in ``governor/posture.py``. Both read :func:`nemo_rails_enabled` and
    :func:`inference_disabled`. A runtime path therefore cannot build rails
    that startup left off.

    - ``CAGE_INFERENCE_BACKEND=none`` returns ``CONTENT_SAFETY_NO_INFERENCE_BACKEND``,
      because no model exists.
    - ``CAGE_NEMO_ENABLED`` off returns ``CONTENT_SAFETY_RAILS_DISABLED``,
      because the rails were not asked for.
    """
    if inference_disabled():
        return (
            CONTENT_SAFETY_NO_INFERENCE_BACKEND,
            "CAGE_INFERENCE_BACKEND=none: no semantic rails are built.",
        )
    if not nemo_rails_enabled():
        return (
            CONTENT_SAFETY_RAILS_DISABLED,
            "CAGE_NEMO_ENABLED=false: semantic rails are off by configuration.",
        )
    return None


def refuse_unless_semantic_rails_enabled() -> None:
    """Raise unless :func:`semantic_rails_refusal` allows building rails.

    Raises:
        InferenceBackendUnavailable: under ``CAGE_INFERENCE_BACKEND=none``.
        SemanticRailsDisabled: when ``CAGE_NEMO_ENABLED`` is off.
    """
    refusal = semantic_rails_refusal()
    if refusal is None:
        return
    reason_code, detail = refusal
    if reason_code == CONTENT_SAFETY_NO_INFERENCE_BACKEND:
        raise InferenceBackendUnavailable(reason_code, detail)
    raise SemanticRailsDisabled(detail)


def initialize_semantic_rails() -> Any:
    """Initialize and return the runtime semantic rail engine instance.

    Raises:
        InferenceBackendUnavailable: under ``CAGE_INFERENCE_BACKEND=none``.
        SemanticRailsDisabled: when ``CAGE_NEMO_ENABLED`` is off.
    """
    refuse_unless_semantic_rails_enabled()
    from src.integrations.nemo.manager import initialize_rails

    return initialize_rails()


def create_semantic_rail_manager(config_path: str = "config/rails") -> Any:
    """Create a semantic rail manager from *config_path*.

    Raises:
        InferenceBackendUnavailable: under ``CAGE_INFERENCE_BACKEND=none``.
        SemanticRailsDisabled: when ``CAGE_NEMO_ENABLED`` is off.
    """
    refuse_unless_semantic_rails_enabled()
    from src.integrations.nemo.manager import create_nemo_manager

    return create_nemo_manager(config_path)


async def verify_semantic_input(rails: Any, user_input: str) -> Any:
    """Validate *user_input* against the active semantic input rails."""
    from src.integrations.nemo.manager import verify_input

    return await verify_input(rails, user_input)


async def validate_with_semantic_rail(
    user_input: str, rails: Any
) -> tuple[bool, str, bool]:
    """Validate *user_input* and return ``(is_safe, response, deterministic)``."""
    from src.integrations.nemo.manager import validate_with_nemo

    return await validate_with_nemo(user_input, rails)


async def verify_and_mask_semantic_output(rails: Any, output_text: str) -> str:
    """Validate and PII-mask *output_text* via the active semantic output rail."""
    from src.integrations.nemo.manager import verify_and_mask_output

    return await verify_and_mask_output(rails, output_text)


async def validate_semantic_output_semantics(
    rails: Any, output_text: str
) -> tuple[bool, str]:
    """Validate *output_text* semantics and return ``(is_safe, response)``."""
    from src.integrations.nemo.manager import validate_output_semantics

    return await validate_output_semantics(rails, output_text)


def register_semantic_rail_provider(provider: Any) -> None:
    """Register a domain-contributed semantic rail action provider."""
    from src.integrations.nemo.action_registry import register_rail_provider

    register_rail_provider(provider)
