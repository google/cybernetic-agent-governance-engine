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

"""NeMo Guardrails action registry.

PR D (rail seam): Domain plugins contribute actions via RailProvider;
the kernel owns the registry and contributes generic rails (self-check,
PII masking, knowledge retrieval, approval token, atomic execution).
"""

from collections.abc import Callable
from typing import Any

_actions: list[tuple[str, Callable[..., Any]]] = []
_rail_providers: list[Any] = []  # list[RailProvider]


def register_nemo_action(name: str, fn: Callable[..., Any]) -> None:
    _actions.append((name, fn))


def register_rail_provider(provider: Any) -> None:
    """Register a RailProvider instance (PR D, T-D3).

    Called by SymbolicGovernor.register_rail_provider() to make plugin-
    contributed rails visible to the NeMo action registry.
    """
    if provider not in _rail_providers:
        _rail_providers.append(provider)


def get_all_actions() -> list[tuple[str, Callable[..., Any]]]:
    actions = list(_actions)

    try:
        from src.gateway.governance.nemo.actions import InvokeVllmFallbackAction

        actions.append(("InvokeVllmFallbackAction", InvokeVllmFallbackAction))
    except ImportError:
        pass

    # Generic kernel rails — always loaded, independent of any plugin.
    # These are domain-agnostic guardrails: PII masking is regulatory,
    # not financial; knowledge retrieval is generic RAG; approval token
    # and atomic execution are governance primitives.
    try:
        from config.rails.actions import (
            check_approval_token_action,
            check_atomic_execution_action,
            custom_self_check_input,
            custom_self_check_output,
            mask_pii_action,
            retrieve_knowledge,
        )

        actions.extend(
            [
                ("CustomSelfCheckInputAction", custom_self_check_input),
                ("CustomSelfCheckOutputAction", custom_self_check_output),
                ("MaskPIIAction", mask_pii_action),
                ("mask_sensitive_data", mask_pii_action),
                ("detect_sensitive_data", mask_pii_action),
                ("RetrieveKnowledgeAction", retrieve_knowledge),
                ("CheckApprovalTokenAction", check_approval_token_action),
                ("CheckAtomicExecutionAction", check_atomic_execution_action),
            ]
        )
    except ImportError as exc:
        # PR D (T-D3): a missing generic rail module is a configuration error,
        # not a silent degradation. Guardrails that fail to load must fail loudly.
        raise RuntimeError(f"NeMo generic rails could not be imported: {exc}") from exc

    # PR D (T-D3): append rails from all registered RailProvider instances.
    # Domain-specific UCA checks (drawdown limits, slippage risk, data latency
    # for finance; contraindication checks for healthcare) are contributed by
    # the plugin, not hardcoded in the kernel.
    for provider in _rail_providers:
        actions.extend(provider.provide_rail_actions())

    # De-duplicate actions by name, preserving first registered instance
    seen: set[str] = set()
    deduped: list[tuple[str, Callable[..., Any]]] = []
    for name, fn in actions:
        if name not in seen:
            seen.add(name)
            deduped.append((name, fn))

    return deduped
