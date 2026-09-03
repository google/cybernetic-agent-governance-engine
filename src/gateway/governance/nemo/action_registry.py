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
            check_approval_token_action,
            check_atomic_execution_action,
            check_data_latency_action,
            check_drawdown_limit_action,
            check_slippage_risk_action,
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
                ("CheckDataLatencyAction", check_data_latency_action),
                ("CheckDrawdownLimitAction", check_drawdown_limit_action),
                ("CheckSlippageRiskAction", check_slippage_risk_action),
                ("CheckAtomicExecutionAction", check_atomic_execution_action),
            ]
        )
    except ImportError:
        pass

    return actions
