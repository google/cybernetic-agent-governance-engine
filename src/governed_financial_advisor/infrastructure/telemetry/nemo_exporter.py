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

import logging
from contextvars import ContextVar
from typing import Any, Optional

from nemoguardrails.streaming import StreamingHandler
from opentelemetry import trace
from opentelemetry.trace import Span

logger = logging.getLogger("NeMoOTelExporter")
tracer = trace.get_tracer("src.governance.nemo")

# ---------------------------------------------------------------------------
# GAP-2 fix: ISO 42001 control mapping per NeMo action name.
# Used to stamp iso42001.control_id on every guardrail intervention span.
# ---------------------------------------------------------------------------
_ACTION_TO_ISO_CONTROL: dict[str, str] = {
    "self_check_input":           "A.6.1.2",
    "self_check_output":          "A.6.1.2",
    "check_approval_token":       "SC-1",
    "CheckApprovalTokenAction":   "SC-1",
    "check_data_latency":         "FIN-2",
    "CheckDataLatencyAction":     "FIN-2",
    "check_drawdown_limit":       "UCA-5",
    "CheckDrawdownLimitAction":   "UCA-5",
    "check_slippage_risk":        "UCA-6",
    "CheckSlippageRiskAction":    "UCA-6",
    "check_atomic_execution":     "SC-4",
    "CheckAtomicExecutionAction": "SC-4",
    "detect_sensitive_data":      "A.6.2.8",
    "InvokeVllmFallbackAction":   "A.6.1.2",
}

# Explicit whitelist of action names that must always be traced, even when they
# do not match the "check" / "guard" / "detect" keyword heuristic.
_TRACED_ACTION_NAMES: frozenset[str] = frozenset(_ACTION_TO_ISO_CONTROL.keys())

# ---------------------------------------------------------------------------
# R-21 Fix: ContextVar-based span storage
# ---------------------------------------------------------------------------
# Using a module-level ContextVar instead of an instance variable means each
# async task (and therefore each concurrent guardrail action) gets its own
# independent span reference, eliminating the race condition that existed when
# multiple concurrent on_action_start / on_action_end calls shared
# self.current_span on the same NeMoOTelCallback instance.
# ---------------------------------------------------------------------------
_current_nemo_span: ContextVar[Optional[Span]] = ContextVar(
    "_current_nemo_span", default=None
)


class NeMoOTelCallback(StreamingHandler):
    """
    ISO 42001 Compliance Exporter for NeMo Guardrails.

    Hooks into the NeMo event loop to create OpenTelemetry spans for every
    guardrail intervention, satisfying Annex A.6.2.8 (Event Logging).

    Concurrency safety: span state is stored in the module-level ContextVar
    ``_current_nemo_span`` so that concurrent async guardrail actions running
    in separate asyncio Tasks each maintain their own isolated span reference.
    """

    def __init__(self):
        super().__init__()
        # NOTE: self.current_span has been removed (R-21).
        # All span references now go through _current_nemo_span ContextVar.

    async def on_action_start(self, action: str, **kwargs: Any):
        """
        Called when a guardrail action starts.
        We start a span to track the execution of this specific control.

        GAP-2 fix: the filter now also captures actions listed explicitly in
        ``_TRACED_ACTION_NAMES`` (e.g. InvokeVllmFallbackAction) in addition
        to the keyword-based heuristic.
        """
        # We focus on "check" actions which usually imply a guardrail
        # e.g., 'self_check_input', 'detect_jailbreak', 'check_hallucination'
        # and on any explicitly whitelisted safety action names.
        if "check" in action or "guard" in action or "detect" in action or action in _TRACED_ACTION_NAMES:
            iso_control = _ACTION_TO_ISO_CONTROL.get(action, "A.6.2.8")
            span = tracer.start_span(f"guardrail.intervention.{action}")
            span.set_attribute("langfuse.trace.metadata.guardrail.id", action)
            span.set_attribute("langfuse.trace.metadata.iso.control_id", iso_control)
            span.set_attribute("langfuse.trace.metadata.iso.requirement", "Transparency of AI Systems")
            span.set_attribute("iso42001.control_id", iso_control)
            _current_nemo_span.set(span)
            logger.info(f"🛡️ Guardrail Started: {action} (ISO {iso_control})")

    async def on_action_end(self, action: str, result: Any = None, **kwargs: Any):
        """
        Called when a guardrail action finishes.
        We record the outcome (Allowed/Blocked) and close the span.

        The span is always ended in a finally block to avoid leaked spans even
        if an unexpected exception occurs during outcome tagging.

        GAP-2 fix: BLOCKED detection extended to handle str outcomes containing
        denial keywords (e.g. "DENY", "UNSAFE", "BLOCKED", "VIOLATION").
        """
        span = _current_nemo_span.get()
        if span is None:
            return

        try:
            outcome = "ALLOWED"

            # Heuristic: If the result is explicitly False (often used in boolean rails)
            # or if the result contains specific "block" signals.
            # NeMo actions return varied types, so we need to be defensive.
            if result is False:
                outcome = "BLOCKED"
            elif isinstance(result, dict) and result.get("status") == "blocked":
                outcome = "BLOCKED"
            elif isinstance(result, str) and any(
                kw in result.upper() for kw in ("DENY", "UNSAFE", "BLOCKED", "VIOLATION")
            ):
                outcome = "BLOCKED"

            iso_control = _ACTION_TO_ISO_CONTROL.get(action, "A.6.2.8")
            span.set_attribute("langfuse.trace.metadata.guardrail.outcome", outcome)
            span.set_attribute("iso42001.control_id", iso_control)
            span.set_attribute("iso42001.outcome", "BLOCK" if outcome == "BLOCKED" else "PASS")

            if outcome == "BLOCKED":
                span.set_attribute("langfuse.trace.metadata.guardrail.block_reason", str(result))
                logger.warning(f"⛔ Guardrail BLOCKED: {action} | Result: {result}")
            else:
                logger.info(f"✅ Guardrail PASSED: {action}")
        finally:
            span.end()
            _current_nemo_span.set(None)
