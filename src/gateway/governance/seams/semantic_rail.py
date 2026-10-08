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
SemanticRailProvider Seam Protocol (Layer 1 Kernel)
===================================================

Defines the vendor-neutral protocol for pre- and post-inference semantic
dialogue rails (e.g., Colang dialogue flows, prompt-injection checks, and PII
masking). Concrete implementations (such as NVIDIA NeMo Guardrails in
``src/integrations/nemo/``) reside in Layer 3 and are loaded lazily through
``src.gateway.governance.semantic_rail_factory``.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SemanticRailVerdict(Protocol):
    """Result of an input semantic rail evaluation."""

    @property
    def is_safe(self) -> bool:
        """True if the input passed all semantic dialogue rails."""
        ...

    @property
    def reason(self) -> str:
        """Refusal reason or sanitized response text."""
        ...


@runtime_checkable
class SemanticRailProvider(Protocol):
    """Vendor-neutral interface for semantic dialogue guardrail providers."""

    def initialize_rails(self) -> Any:
        """Initialize and return the runtime rail engine instance."""
        ...

    def create_manager(self, config_path: str = "config/rails") -> Any:
        """Create a rail manager from the specified configuration directory."""
        ...

    async def verify_input(self, rails: Any, user_input: str) -> SemanticRailVerdict:
        """Validate user input against configured semantic input rails."""
        ...

    async def validate_input(
        self, user_input: str, rails: Any
    ) -> tuple[bool, str, bool]:
        """Validate user input and return ``(is_safe, response, deterministic)``."""
        ...

    async def verify_and_mask_output(self, rails: Any, output_text: str) -> str:
        """Validate and PII-mask LLM output text before returning to caller."""
        ...

    async def validate_output_semantics(
        self, rails: Any, output_text: str
    ) -> tuple[bool, str]:
        """Validate output semantics and return ``(is_safe, response)``."""
        ...

    def register_rail_provider(self, provider: Any) -> None:
        """Register a domain-contributed rail action provider."""
        ...
