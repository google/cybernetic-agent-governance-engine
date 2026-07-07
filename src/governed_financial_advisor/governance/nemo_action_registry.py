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
NeMo Action Registry — consolidates all NeMo Guardrails action implementations.

Import sources (in priority order):
1. config.rails.actions — HTTP-delegating gateway actions (production, canonical)
2. src.gateway.governance.nemo.actions — async gateway singletons (loaded lazily)
3. src.governed_financial_advisor.governance.nemo_actions — synchronous fallbacks

Gateway actions (source 2) are loaded lazily inside get_all_actions() to
prevent circular imports: nemo_action_registry → gateway → nemo_action_registry.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Re-exports from src/governed_financial_advisor/governance/nemo_actions.py
# (canonical synchronous, fail-closed, in-process implementations — module 3)
# ---------------------------------------------------------------------------
from src.governed_financial_advisor.governance.nemo_actions import (  # noqa: F401
    check_approval_token,          # SC-1: approval token validation
    check_atomic_execution,        # multi-leg trade atomicity check
    check_data_latency,            # FIN-2: market data freshness
    check_drawdown_limit,          # UCA-5: portfolio drawdown limit
    check_slippage_risk,           # UCA-6: order slippage risk
    DEFAULT_DRAWDOWN_LIMIT,
    DEFAULT_MAX_LATENCY_MS,
    _load_safety_params,
)

# ---------------------------------------------------------------------------
# Re-exports from config/rails/actions.py
# (gateway-delegating versions with in-process fallback — module 1)
# ---------------------------------------------------------------------------
from config.rails.actions import (  # noqa: F401
    retrieve_knowledge as RetrieveKnowledgeAction,   # Knowledge retrieval for NeMo flows
    mask_pii_action as MaskPIIAction,                # Presidio-backed PII masking
    custom_self_check_input as CustomSelfCheckInputAction,   # Self-check input rail
    custom_self_check_output as CustomSelfCheckOutputAction, # Self-check output rail
)

# Gateway-delegating check actions (check_approval_token_action etc.) are only
# available lazily inside get_all_actions() — they are NOT exported from
# config.rails.actions at module level.
CheckApprovalTokenAction = None   # populated lazily via get_all_actions()
CheckDataLatencyAction = None
CheckDrawdownLimitAction = None
CheckSlippageRiskAction = None

# ---------------------------------------------------------------------------
# NOTE: src.gateway.governance.nemo.actions is NOT imported at module level.
# It is loaded lazily inside get_all_actions() to prevent circular imports:
#   nemo_action_registry → gateway.nemo.actions → gateway → nemo_action_registry
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Public action registry
# ---------------------------------------------------------------------------

__all__ = [
    # In-process synchronous (module 3 — canonical implementations)
    "check_approval_token",
    "check_atomic_execution",
    "check_data_latency",
    "check_drawdown_limit",
    "check_slippage_risk",
    # Gateway-delegating async (module 1)
    "RetrieveKnowledgeAction",
    "CheckApprovalTokenAction",
    "CheckDataLatencyAction",
    "CheckDrawdownLimitAction",
    "CheckSlippageRiskAction",
    # Symbolic-governor async (module 2) — available via get_all_actions()
    "get_all_actions",
]


def get_all_actions() -> List[Tuple[str, Callable[..., Any]]]:
    """Return the complete deduplicated list of NeMo actions.

    Each tuple is ``(registration_name: str, action_callable)``.

    The list is ordered so that:
      1. Gateway-delegating async actions (config.rails.actions) come first
         — these are the canonical production implementations.
      2. Symbolic-governor async actions come next — gateway-scoped only,
         loaded lazily to prevent circular imports.
      3. Pure in-process sync checks are NOT registered here by default because
         NeMo expects async actions; they are available for import by callers
         that need sync fallbacks.

    Returns:
        List of (name, callable) pairs suitable for
        ``rails.register_action(callable, name)``.
    """
    # ACTION PRIORITY:
    # 1. config.rails.actions — HTTP-delegating, canonical production implementation
    # 2. src.governed_financial_advisor.governance.nemo_actions — synchronous fallbacks (testing/offline)
    # Gateway actions (src.gateway.governance.nemo.actions) are gateway-scoped only, not registered here.

    # --- Priority 1: Gateway-delegating actions (config/rails/actions.py) ---
    try:
        from config.rails.actions import (  # noqa: PLC0415
            retrieve_knowledge as _RetrieveKnowledgeAction,
            check_approval_token_action as _CheckApprovalTokenAction,
            check_data_latency_action as _CheckDataLatencyAction,
            check_drawdown_limit_action as _CheckDrawdownLimitAction,
            check_slippage_risk_action as _CheckSlippageRiskAction,
            mask_pii_action as _MaskPIIAction,
            custom_self_check_input as _CustomSelfCheckInputAction,
            custom_self_check_output as _CustomSelfCheckOutputAction,
        )
        actions: List[Tuple[str, Callable[..., Any]]] = [
            ("RetrieveKnowledgeAction",   _RetrieveKnowledgeAction),
            ("CheckApprovalTokenAction",  _CheckApprovalTokenAction),
            ("CheckDataLatencyAction",    _CheckDataLatencyAction),
            ("CheckDrawdownLimitAction",  _CheckDrawdownLimitAction),
            ("CheckSlippageRiskAction",   _CheckSlippageRiskAction),
            ("MaskPIIAction",             _MaskPIIAction),
            ("CustomSelfCheckInputAction", _CustomSelfCheckInputAction),
            ("CustomSelfCheckOutputAction", _CustomSelfCheckOutputAction),
            ("mask_sensitive_data",       _MaskPIIAction),
            ("detect_sensitive_data",      _MaskPIIAction),
        ]
    except ImportError as e:
        import logging
        logging.getLogger(__name__).warning(
            "config.rails.actions unavailable (%s) — falling back to synchronous in-process actions.", e
        )
        # --- Priority 2: Synchronous in-process fallbacks ---
        from src.governed_financial_advisor.governance.nemo_actions import (  # noqa: PLC0415
            check_approval_token,
            check_data_latency,
            check_drawdown_limit,
            check_slippage_risk,
        )
        actions = [
            ("CheckApprovalTokenAction",  check_approval_token),
            ("CheckDataLatencyAction",    check_data_latency),
            ("CheckDrawdownLimitAction",  check_drawdown_limit),
            ("CheckSlippageRiskAction",   check_slippage_risk),
        ]

    # --- Gateway-internal actions (src.gateway.governance.nemo.actions) — loaded lazily ---
    # Lazy import to break circular:
    #   nemo_action_registry → gateway.nemo.actions → gateway → nemo_action_registry
    try:
        from src.gateway.governance.nemo.actions import (  # noqa: PLC0415
            CheckAtomicExecutionAction,
            InvokeVllmFallbackAction,
            CheckLatencyAction,
        )
        actions += [
            ("CheckAtomicExecutionAction", CheckAtomicExecutionAction),
            ("CheckLatencyAction",         CheckLatencyAction),
            ("InvokeVllmFallbackAction",   InvokeVllmFallbackAction),
        ]
    except ImportError as e:
        import logging
        logging.getLogger(__name__).warning(
            "Gateway NeMo actions unavailable: %s. Using fallback actions.", e
        )

    return actions
