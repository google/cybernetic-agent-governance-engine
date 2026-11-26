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

"""Advisor-specific governance policy hooks for ``cage_client.langgraph.governed_tool_node``.

Generic preview/execute mediation, batch idempotency key derivation, ``ToolMessage``
pairing, single-use ``approval_token`` redemption, and retryable vs. terminal
``CommitOutcome`` branching live in ``cage_client.langgraph.governed_tool_node``.
This module holds **only** advisor-specific policy:

1. **Drift revalidation:** single-trade ``routing_verdict_cache`` reuse
   (:func:`lookup_cached_trade_preview`), substrate ``policy_version_id`` drift
   recovery (:func:`preview_trade_with_drift_revalidation`), and canonical trade
   plan/intent extraction (:func:`extract_trader_plan_steps`, :func:`canonical_trade_intent`).
2. **``REFUSAL_DESCRIPTIONS``:** imported canonically from ``cage_client.outcomes``.
3. **Trade-description allowlisting:** :func:`describe_trade` reads only
   ``side``, ``symbol``, ``amount``, and ``currency`` so no ``deferred_id`` or
   internal handle can enter LangGraph ``ToolMessage`` prompts (:func:`advisor_tool_message`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from cage_client import CageClient, GovernanceDecision, PreviewResult
from cage_client.outcomes import (
    INDETERMINATE_STATUSES,
    REFUSAL_DESCRIPTIONS,
    CommitOutcome,
    CommitStatus,
)

from src.governed_financial_advisor.graph.nodes.trade_contract import (
    TRADE_ACTION,
    extract_trade_steps,
    reusable_allow_verdict,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.governed_financial_advisor.models.principal import principal_header_value
from src.governed_financial_advisor.utils.context import user_context

logger = logging.getLogger(__name__)

GOVERNANCE_ALLOWED = "ALLOWED"
GOVERNANCE_DENIED = "DENIED"
GOVERNANCE_UNAVAILABLE = "UNAVAILABLE"
GOVERNANCE_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

#: State key under which governed_tool_node stores per-call CommitOutcome dicts.
COMMIT_OUTCOMES = "commit_outcomes"

#: Advisor-owned state fields cleared on every governance mediation exit.
ADVISOR_EXTRA_CLEAR_KEYS: tuple[str, ...] = (
    "deferred_step_ids",
    "routing_verdict_cache",
    "governance_envelope",
)

#: Advisor-owned TOCTOU state cleared only on terminal completion/refusal (preserved across HITL park).
ADVISOR_TERMINAL_CLEAR_KEYS: tuple[str, ...] = ("hitl_reference_quote",)


def advisor_principal_extractor(state: Mapping[str, Any]) -> str:
    """Resolve the active advisor caller principal without fabricating a default."""
    explicit = state.get("principal")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    if explicit is not None and (not isinstance(explicit, str) or not explicit.strip()):
        return ""
    resolved = principal_header_value(user_context.get())
    return resolved if resolved else ""


def canonical_trade_intent(args: Any) -> tuple[str, str, str, str]:
    """Extract normalized ``(symbol, currency, side, amount_key)`` from trade tool args."""
    mapping = args if isinstance(args, Mapping) else {}
    symbol = str(mapping.get("symbol") or "").strip().upper()
    currency = str(mapping.get("currency") or "USD").strip().upper()
    side = str(mapping.get("side") or "buy").strip().lower()
    raw_amount = mapping.get("amount")
    if isinstance(raw_amount, (int, float)) and not isinstance(raw_amount, bool):
        amount_key = f"{float(raw_amount):.8f}"
    else:
        amount_key = str(raw_amount or "").strip()
    return (symbol, currency, side, amount_key)


def extract_trader_plan_steps(plan: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """Extract canonical ``execute_trade`` steps from a parsed advisor execution plan."""
    return extract_trade_steps(plan)


def describe_trade(call: Mapping[str, Any]) -> str:
    """Render a trade description from allowlisted params alone.

    Only ``side``, ``symbol``, ``amount``, and ``currency`` are read, so no
    other argument (in particular a ``deferred_id``) can reach prompt prose.
    """
    raw_args = call.get("args")
    args = raw_args if isinstance(raw_args, Mapping) else {}
    side = str(args.get("side") or "buy").upper()
    symbol = str(args.get("symbol") or "?")
    amount, currency = args.get("amount"), args.get("currency")
    notional = f" for {amount} {currency}" if amount is not None and currency else ""
    return f"{side} {symbol}{notional}"


def advisor_tool_message(
    call: Mapping[str, Any], event: str, outcome: CommitOutcome | None
) -> str | None:
    """Format handle-free advisor ``ToolMessage`` copy using :func:`describe_trade` and ``REFUSAL_DESCRIPTIONS``."""
    trade = describe_trade(call)
    if event == "approval_required":
        return (
            f"Nothing was executed. Your {trade} trade needs reviewer "
            "approval at the compliance bridge; it is in your pending approvals."
        )
    if event == "awaiting_same_ticket" and outcome is not None:
        if outcome.status is CommitStatus.DEFERRED:
            return (
                f"Nothing was executed. The gateway deferred your {trade} trade "
                "after its approval; the approval is retained and nothing was spent. "
                "Resume once the deferral has cleared; it remains in your pending approvals."
            )
        return (
            f"Nothing was executed. Your {trade} trade is still awaiting reviewer "
            "approval at the compliance bridge. Resume after a reviewer has "
            "approved it; it remains in your pending approvals."
        )
    if event == "terminal_outcome":
        if outcome is None or outcome.status in INDETERMINATE_STATUSES:
            return (
                f"The outcome of your {trade} trade could not be confirmed. Do not "
                "submit it again until it has been reconciled."
            )
        if outcome.status is CommitStatus.DEFERRED:
            reason = "the gateway deferred it and holds no approval for it"
        elif outcome.redemption_refusal is not None:
            reason = REFUSAL_DESCRIPTIONS.get(
                outcome.redemption_refusal, outcome.redemption_refusal.value
            )
        else:
            reason = "the gateway refused it"
        return (
            f"Nothing was executed. Your {trade} trade can't proceed: {reason}. "
            "Submit a new request if you still want it."
        )
    return None


def lookup_cached_trade_preview(
    state: Mapping[str, Any], preview_params: Mapping[str, Any], batch_len: int
) -> Mapping[str, Any] | None:
    """Reuse a non-drifted single-trade ``ALLOW`` verdict cached by upstream gates."""
    if batch_len != 1 or preview_params.get("action") != TRADE_ACTION:
        return None
    cached_cache = state.get("routing_verdict_cache")
    if cached_cache is None:
        return None
    return reusable_allow_verdict(cached_cache, dict(preview_params))


async def preview_trade_with_drift_revalidation(
    client: CageClient,
    action: str,
    params: Mapping[str, Any],
    principal: str,
    state: Mapping[str, Any],
) -> PreviewResult:
    """Call ``client.preview()`` and recover once on verified substrate policy-version drift."""
    pin = state.get("policy_version_id")
    active_pin = str(pin) if isinstance(pin, str) and pin.strip() else None

    for attempt in range(2):
        token, _ = GatewayClient._set_preview_pin(active_pin)
        try:
            result = await client.preview(
                action=action, parameters=dict(params), agent_id=principal
            )
        finally:
            GatewayClient._reset_preview_pin(token)

        if (
            attempt == 0
            and result.decision is GovernanceDecision.DENIED
            and any(
                "Substrate Policy Drift Detected" in str(v) for v in result.violations
            )
        ):
            logger.warning(
                "Substrate drift caught on verified 403 envelope; refreshing policy pin and replaying preview."
            )
            active_pin = await GatewayClient().get_policy_version()
            continue
        return result

    return result
