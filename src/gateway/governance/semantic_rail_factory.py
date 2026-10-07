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
"""

from __future__ import annotations

from typing import Any


def initialize_semantic_rails() -> Any:
    """Initialize and return the runtime semantic rail engine instance."""
    from src.integrations.nemo.manager import initialize_rails

    return initialize_rails()


def create_semantic_rail_manager(config_path: str = "config/rails") -> Any:
    """Create a semantic rail manager from *config_path*."""
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
