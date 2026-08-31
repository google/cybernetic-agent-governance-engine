from collections.abc import Callable
from typing import Any

_actions: list[tuple[str, Callable[..., Any]]] = []

def register_nemo_action(name: str, fn: Callable[..., Any]) -> None:
    _actions.append((name, fn))

def get_all_actions() -> list[tuple[str, Callable[..., Any]]]:
    actions = list(_actions)

    try:
        from src.gateway.governance.nemo.actions import InvokeVllmFallbackAction
        actions.append(("InvokeVllmFallbackAction", InvokeVllmFallbackAction))
    except ImportError:
        pass

    try:
        from config.rails.actions import (
            custom_self_check_input,
            custom_self_check_output,
            mask_pii_action,
            retrieve_knowledge,
            check_approval_token_action,
            check_data_latency_action,
            check_drawdown_limit_action,
            check_slippage_risk_action,
            check_atomic_execution_action,
        )

        actions.extend([
            ("CustomSelfCheckInputAction", custom_self_check_input),
            ("CustomSelfCheckOutputAction", custom_self_check_output),
            ("MaskPIIAction", mask_pii_action),
            ("mask_sensitive_data", mask_pii_action),
            ("detect_sensitive_data", mask_pii_action),
            ("RetrieveKnowledgeAction", retrieve_knowledge),
            ("CheckApprovalTokenAction", check_approval_token_action),
            ("CheckDataLatencyAction", check_data_latency_action),
            ("CheckDrawdownLimitAction", check_drawdown_limit_action),
            ("CheckSlippageRiskAction", check_slippage_risk_action),
            ("CheckAtomicExecutionAction", check_atomic_execution_action),
        ])
    except ImportError:
        pass

    return actions
