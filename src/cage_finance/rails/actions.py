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

"""Finance-specific NeMo Guardrails UCA checks.

Moved unchanged from config/rails/actions.py as part of the rail seam
implementation (PR D). These three actions are finance UCA checks and
belong in the finance plugin, not the kernel.
"""

import logging
from collections.abc import Callable
from typing import Any

from opentelemetry import trace as _otel_trace

try:
    from nemoguardrails.actions import action as _nemo_action

    def action(name: str) -> Any:
        """Thin wrapper that delegates to nemoguardrails.actions.action."""
        return _nemo_action(name=name)
except ImportError:
    # nemoguardrails not installed (e.g. in unit-test environments).
    # Provide a no-op decorator so the module can still be imported and
    # all action functions remain callable.
    def action(name: str) -> Any:
        """No-op decorator used when nemoguardrails is not installed."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


logger = logging.getLogger(__name__)

_tracer = _otel_trace.get_tracer("cage_finance.rails.actions")


@action(name="CheckDataLatencyAction")
async def check_data_latency_action(
    context: dict[str, Any] | None = None, **kwargs: Any
) -> bool:
    """Pass-through stub — market data latency enforcement owned by OPA safety_check_node.

    Financial policy (FIN-2) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_data_latency") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckDataLatencyAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "FIN-2")
        logger.debug(
            "CheckDataLatencyAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckDrawdownLimitAction")
async def check_drawdown_limit_action(
    context: dict[str, Any] | None = None, **kwargs: Any
) -> bool:
    """Pass-through stub — drawdown limit enforcement owned by OPA safety_check_node.

    Financial policy (UCA-5) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_drawdown_limit") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckDrawdownLimitAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "UCA-5")
        logger.debug(
            "CheckDrawdownLimitAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True


@action(name="CheckSlippageRiskAction")
async def check_slippage_risk_action(
    context: dict[str, Any] | None = None, **kwargs: Any
) -> bool:
    """Pass-through stub — slippage risk enforcement owned by OPA safety_check_node.

    Financial policy (UCA-6) is enforced by the safety_check_node → OPA path.
    See CheckApprovalTokenAction for rationale.
    """
    with _tracer.start_as_current_span("nemo.action.check_slippage_risk") as span:
        span.set_attribute("langfuse.observation.type", "span")
        span.set_attribute(
            "langfuse.trace.metadata.guardrail.action", "CheckSlippageRiskAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", "PASS_THROUGH_OPA_AUTHORITATIVE")
        span.set_attribute("nemo.action.stpa_ref", "UCA-6")
        logger.debug(
            "CheckSlippageRiskAction: pass-through (OPA/safety_check_node is authoritative)"
        )
        return True
