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

"""Gateway pre-execution guard for advisor tool-executor nodes.

The advisor is an untrusted, zero-identity client of the CAGE gateway
(POAM-2026-080): it holds no governor, no signer and no routing-seal secret.
Every tool call a subgraph wants to run is therefore submitted to the
gateway's ``POST /governance/validate-action`` endpoint through the advisor's
standard :class:`GatewayClient` before the wrapped node may execute it. The
gateway authenticates this caller by its mesh workload identity, not by any
secret the advisor holds.

``validate-action`` only routes: it commits nothing and mints no seal. The
committing run happens in the gateway when the governed tool executes, so an
ALLOW here is advice, never authority.

Fail-closed contract, per batch:

* every call ``ALLOW`` or ``NARROW`` → the wrapped node runs the batch;
* in a graph with an approval path, a single-call batch answered
  ``REQUIRE_APPROVAL`` with a ``deferred_id`` →
  no tool runs; ``governance_status`` becomes ``REQUIRE_APPROVAL`` and the
  ``deferred_id`` is stored so the graph can pause for a human;
* a refusal (403 / DENY), DEFER, an unknown verdict, a
  ``REQUIRE_APPROVAL`` without a ``deferred_id``, an HTTP error, a timeout or
  an unreachable gateway → the whole batch is refused.

Once a human has approved (``approval_decision.approved`` and a
``deferred_id`` in state), the guard does not re-ask ``validate-action``: it
forwards the ``deferred_id`` in each tool call's arguments and the gateway
consumes that approval exactly once, re-validating the fresh params. The
advisor never decides that an approval holds.

The committing run answers with a typed ``CommitOutcome``
(``src.gateway.governance.commit_outcome``), which the wrapped node hands
back under :data:`COMMIT_OUTCOMES`. The guard decides on its fields only,
never on message text (POAM-2026-245):

* ``EXECUTED`` / ``DRY_RUN`` → ``ALLOWED``;
* the approval is not redeemable *yet* (a retryable ``redemption_refusal``)
  or the run deferred and retained the approval → ``REQUIRE_APPROVAL`` on the
  **same** ``deferred_id``, with ``approval_decision`` cleared, so the graph
  re-interrupts on that ticket (no new deferral, nothing spent);
* anything else (a terminal refusal, a deferral without a retained approval,
  or no decodable outcome) → ``DENIED`` and the subgraph ends.

No message the advisor writes names a ``deferred_id``: the handle belongs to
reviewers at the compliance bridge (BREAKING_CHANGES SA-1). The trade is
identified by its own params instead.

A ``deferred_id`` the model put in a tool call never counts: it is removed
from the call ``validate-action`` previews and from every call the wrapped
node executes. Only the approved resume above adds one, so an ALLOW for one
call can never redeem an approval the model named (GHSA-w39v-5v7h-fxg9).

Every refused call is answered with a ``ToolMessage`` so the conversation
stays well-formed.

Before anything else, every ``execute_trade_action`` call's ``transaction_id``
is replaced by a UUIDv5 derived from the LangGraph thread and the tool call
id, whatever the model supplied. A re-run of the same tool call (a graph
retry or a resumed checkpoint) therefore resubmits the same idempotency key,
and the gateway executes that trade at most once. The key names the call,
not the order, so the guard previews, and reuses verdicts for, the order
without it.
"""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.config import get_config

from src.gateway.governance.commit_outcome import (
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitStatus,
    is_retryable_refusal,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    TRADE_ACTION,
    TRADE_TOOL,
    reusable_allow_verdict,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger(__name__)


class NodeFn(Protocol):
    """A LangGraph node: called with the graph state (by name), returns an update."""

    def __call__(self, state: Any) -> Awaitable[dict[str, Any]]: ...


GOVERNANCE_ALLOWED = "ALLOWED"
GOVERNANCE_DENIED = "DENIED"
GOVERNANCE_REQUIRE_APPROVAL = GovernanceDecision.REQUIRE_APPROVAL.value

#: Verdicts under which the wrapped node may execute the batch.
_EXECUTABLE_VERDICTS = frozenset({GovernanceDecision.ALLOW, GovernanceDecision.NARROW})

#: Key under which a wrapped node returns ``{tool_call_id: CommitOutcome | None}``
#: for the committing calls it ran (``None``: no decodable outcome). The guard
#: consumes it; it never reaches graph state.
COMMIT_OUTCOMES = "commit_outcomes"

#: Commit statuses after which the batch counts as executed as routed.
_COMPLETED_STATUSES = frozenset({CommitStatus.EXECUTED, CommitStatus.DRY_RUN})

#: Why a ticket can't be redeemed, as told to the trade's owner.
REFUSAL_DESCRIPTIONS: dict[ApprovalRedemptionRefusal, str] = {
    ApprovalRedemptionRefusal.PENDING: "it has no reviewer approval yet",
    ApprovalRedemptionRefusal.QUORUM_INCOMPLETE: (
        "it does not have all the reviewer approvals it needs yet"
    ),
    ApprovalRedemptionRefusal.UNKNOWN_OR_EXPIRED: (
        "its approval request no longer exists (it expired or was never recorded)"
    ),
    ApprovalRedemptionRefusal.NOT_AN_APPROVAL: (
        "the hold on it is not one a reviewer approval can release"
    ),
    ApprovalRedemptionRefusal.CONSUMED: "its approval has already been used",
    ApprovalRedemptionRefusal.EXPIRED: (
        "its approval request expired before reviewers approved it"
    ),
    ApprovalRedemptionRefusal.RESOLVED_WITHOUT_APPROVAL: (
        "its approval request was closed without a reviewer approval"
    ),
    ApprovalRedemptionRefusal.QUORUM_NOT_DISTINCT: (
        "its approvals did not come from enough distinct reviewers"
    ),
    ApprovalRedemptionRefusal.UNRECOGNIZED_STATE: (
        "its approval request is in a state the gateway does not recognise"
    ),
    ApprovalRedemptionRefusal.ACTION_MISMATCH: (
        "its approval was granted for a different action"
    ),
    ApprovalRedemptionRefusal.STALE_BARRIER_PREVIEW: (
        "it was approved against conditions that have since changed"
    ),
    ApprovalRedemptionRefusal.NO_APPROVED_PARAMS: (
        "its approval does not record what was approved"
    ),
    ApprovalRedemptionRefusal.PARAMS_NOT_COVERED: (
        "it no longer matches what reviewers approved"
    ),
}

#: Namespace of the UUIDv5 transaction ids derived for trade tool calls.
_TRANSACTION_ID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "urn:cage:advisor:execute_trade_action:transaction_id"
)


async def authorize_action(
    action: str, params: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask the gateway how one action must be routed.

    Returns:
        ``(result, None)`` when the gateway answered ``ALLOW``/``NARROW``, or
        ``REQUIRE_APPROVAL`` with a ``deferred_id``; otherwise
        ``(None, reason)``. Never raises: every failure mode is reported as a
        refusal reason so callers cannot fail open by accident.
    """
    try:
        result = await GatewayClient().validate_action(action=action, params=params)
    except Exception as exc:  # refusal (PermissionError), HTTP error, timeout: refuse
        return None, f"{type(exc).__name__}: {exc}"
    verdict = result.get("verdict") if isinstance(result, dict) else None
    if verdict in _EXECUTABLE_VERDICTS:
        return result, None
    if verdict == GovernanceDecision.REQUIRE_APPROVAL:
        if result.get("deferred_id"):
            return result, None
        return None, "gateway requires approval but parked no deferred_id"
    return None, f"gateway returned verdict {verdict!r}, not ALLOW or NARROW"


def _pending_tool_calls(state: Any) -> list[dict[str, Any]]:
    messages = state.get("messages") or []
    if not messages:
        return []
    return list(getattr(messages[-1], "tool_calls", None) or [])


def _approved_deferred_id(state: Any) -> str | None:
    decision = state.get("approval_decision") or {}
    deferred_id = state.get("deferred_id")
    if deferred_id and isinstance(decision, dict) and decision.get("approved") is True:
        return str(deferred_id)
    return None


def _answer_all(
    tool_calls: list[dict[str, Any]], reasons: dict[str, str], default: str
) -> list[ToolMessage]:
    return [
        ToolMessage(
            content=reasons.get(str(call.get("id")), default),
            tool_call_id=call.get("id"),
            name=call.get("name"),
        )
        for call in tool_calls
    ]


def _run_thread_id() -> str | None:
    """The LangGraph ``thread_id`` of the current run, if there is one."""
    try:
        config = get_config()
    except RuntimeError:  # not inside a LangGraph run
        return None
    thread_id = (config.get("configurable") or {}).get("thread_id")
    return str(thread_id) if thread_id else None


def derive_transaction_id(
    tool_call_id: str, *, thread_id: str | None, message_id: str | None
) -> str:
    """The deterministic UUIDv5 idempotency key of one trade tool call.

    Scoped by the LangGraph thread; without one, by the ``AIMessage`` id.
    """
    scope = f"thread:{thread_id}" if thread_id else f"message:{message_id}"
    return str(uuid.uuid5(_TRANSACTION_ID_NAMESPACE, f"{scope}|call:{tool_call_id}"))


def _with_derived_transaction_ids(state: Any) -> Any:
    """Return ``state`` whose trade tool calls carry derived ``transaction_id``s.

    Only ``transaction_id`` changes; a model-supplied value is overridden.
    """
    messages = list(state.get("messages") or [])
    if not messages:
        return state
    last = messages[-1]
    calls = list(getattr(last, "tool_calls", None) or [])
    if not any(call.get("name") == TRADE_TOOL for call in calls):
        return state
    thread_id = _run_thread_id()
    message_id = getattr(last, "id", None)
    rewritten = []
    for call in calls:
        if call.get("name") == TRADE_TOOL:
            args = call.get("args")
            call = {
                **call,
                "args": {
                    **(args if isinstance(args, dict) else {}),
                    "transaction_id": derive_transaction_id(
                        str(call.get("id")), thread_id=thread_id, message_id=message_id
                    ),
                },
            }
        rewritten.append(call)
    messages[-1] = last.model_copy(update={"tool_calls": rewritten})
    return {**state, "messages": messages}


def _without_model_deferred_id(args: Any) -> dict[str, Any]:
    """Return a copy of a tool call's ``args`` without a ``deferred_id``."""
    return {
        k: v
        for k, v in (args if isinstance(args, dict) else {}).items()
        if k != "deferred_id"
    }


def _cleared_guard_hitl_state() -> dict[str, Any]:
    """Return cleared HITL fields after consuming or refusing an approved batch."""
    return {
        "governance_envelope": None,
        "deferred_id": None,
        "deferred_step_ids": None,
        "approval_decision": None,
        "hitl_reference_quote": None,
        "routing_verdict_cache": None,
    }


def describe_trade(call: dict[str, Any]) -> str:
    """The trade a tool call asks for, rendered from its params alone.

    Only ``side``, ``symbol``, ``amount`` and ``currency`` are read, so no
    other argument (in particular a ``deferred_id``) can reach the text.
    """
    args = call.get("args")
    args = args if isinstance(args, dict) else {}
    side = str(args.get("side") or "buy").upper()
    symbol = str(args.get("symbol") or "?")
    amount, currency = args.get("amount"), args.get("currency")
    notional = f" for {amount} {currency}" if amount is not None and currency else ""
    return f"{side} {symbol}{notional}"


def _awaiting_approval_message(call: dict[str, Any]) -> str:
    return (
        f"Nothing was executed. Your {describe_trade(call)} trade needs reviewer "
        "approval at the compliance bridge; it is in your pending approvals."
    )


def _still_awaiting_message(call: dict[str, Any], outcome: CommitOutcome) -> str:
    if outcome.status is CommitStatus.DEFERRED:
        return (
            f"Nothing was executed. The gateway deferred your "
            f"{describe_trade(call)} trade after its approval; the approval is "
            "retained and nothing was spent. Resume once the deferral has "
            "cleared; it remains in your pending approvals."
        )
    return (
        f"Nothing was executed. Your {describe_trade(call)} trade is still "
        "awaiting reviewer approval at the compliance bridge. Resume after a "
        "reviewer has approved it; it remains in your pending approvals."
    )


def _terminal_message(call: dict[str, Any], outcome: CommitOutcome | None) -> str:
    trade = describe_trade(call)
    if outcome is None:
        # The run may have executed: never invite a resubmission.
        return (
            f"The outcome of your {trade} trade could not be confirmed. Do not "
            "submit it again until it has been reconciled."
        )
    if outcome.status is CommitStatus.DEFERRED:
        reason = "the gateway deferred it and holds no approval for it"
    elif outcome.redemption_refusal is not None:
        reason = REFUSAL_DESCRIPTIONS[outcome.redemption_refusal]
    else:
        reason = "the gateway refused it"
    return (
        f"Nothing was executed. Your {trade} trade can't proceed: {reason}. "
        "Submit a new request if you still want it."
    )


def _awaits_same_ticket(outcome: CommitOutcome | None) -> bool:
    """Whether ``outcome`` leaves the approval it redeemed redeemable later."""
    if outcome is None:
        return False
    if outcome.status is CommitStatus.DEFERRED:
        return outcome.approval_retained
    return outcome.status is CommitStatus.REFUSED and is_retryable_refusal(
        outcome.redemption_refusal
    )


def _split_outcomes(
    result: dict[str, Any], tool_calls: list[dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, CommitOutcome | None]]:
    """Separate the wrapped node's state update from its commit outcomes.

    Returns the update without :data:`COMMIT_OUTCOMES` and the outcome of
    every committing call in the batch. A committing call the node reported
    no outcome for maps to ``None``.
    """
    update = dict(result)
    reported = update.pop(COMMIT_OUTCOMES, None)
    reported = reported if isinstance(reported, dict) else {}
    outcomes: dict[str, CommitOutcome | None] = {}
    for call in tool_calls:
        if call.get("name") != TRADE_TOOL:
            continue
        call_id = str(call.get("id"))
        outcome = reported.get(call_id)
        outcomes[call_id] = outcome if isinstance(outcome, CommitOutcome) else None
    return update, outcomes


def _with_messages(
    update: dict[str, Any],
    tool_calls: list[dict[str, Any]],
    texts: dict[str, str],
) -> dict[str, Any]:
    """``update`` whose answer to each call in ``texts`` is replaced by that text."""
    if not texts:
        return update
    by_id = {str(c.get("id")): c for c in tool_calls}
    messages = [
        message
        for message in update.get("messages") or []
        if str(getattr(message, "tool_call_id", "")) not in texts
    ]
    messages.extend(
        ToolMessage(
            content=text,
            tool_call_id=by_id[call_id].get("id"),
            name=by_id[call_id].get("name"),
        )
        for call_id, text in texts.items()
    )
    return {**update, "messages": messages}


def _refused_batch(
    update: dict[str, Any],
    tool_calls: list[dict[str, Any]],
    outcomes: dict[str, CommitOutcome | None],
) -> dict[str, Any] | None:
    """The terminal ``DENIED`` update when a committing call did not complete, else ``None``."""
    unfinished = {
        call_id: outcome
        for call_id, outcome in outcomes.items()
        if outcome is None or outcome.status not in _COMPLETED_STATUSES
    }
    if not unfinished:
        return None
    by_id = {str(c.get("id")): c for c in tool_calls}
    refusal = next(
        (
            o.redemption_refusal
            for o in unfinished.values()
            if o is not None and o.redemption_refusal is not None
        ),
        None,
    )
    logger.warning(
        "Committing run did not complete for %d of %d call(s): %s",
        len(unfinished),
        len(tool_calls),
        {k: (o.status.value if o else None) for k, o in unfinished.items()},
    )
    return {
        **_with_messages(
            update,
            tool_calls,
            {k: _terminal_message(by_id[k], o) for k, o in unfinished.items()},
        ),
        "governance_status": GOVERNANCE_DENIED,
        **_cleared_guard_hitl_state(),
        "redemption_refusal": refusal.value if refusal is not None else None,
    }


def _after_approved_redemption(
    update: dict[str, Any],
    call: dict[str, Any],
    outcome: CommitOutcome | None,
    deferred_id: str,
) -> dict[str, Any]:
    """Route one approved call on the typed outcome of redeeming ``deferred_id``."""
    if outcome is not None and outcome.status in _COMPLETED_STATUSES:
        return {
            **update,
            "governance_status": GOVERNANCE_ALLOWED,
            **_cleared_guard_hitl_state(),
            "redemption_refusal": None,
        }
    if outcome is not None and _awaits_same_ticket(outcome):
        # Not redeemable yet: keep the ticket, require a fresh resume. Nothing
        # was spent and the gateway's ticket is left exactly as it is.
        logger.info(
            "Approved %s not redeemable yet (%s) — re-interrupting on the same ticket",
            call.get("name"),
            outcome.redemption_refusal.value
            if outcome.redemption_refusal is not None
            else outcome.status.value,
        )
        return {
            **_with_messages(
                update,
                [call],
                {str(call.get("id")): _still_awaiting_message(call, outcome)},
            ),
            "governance_status": GOVERNANCE_REQUIRE_APPROVAL,
            "governance_envelope": None,
            "routing_verdict_cache": None,
            "deferred_id": deferred_id,
            "deferred_step_ids": None,
            "approval_decision": None,
            "approval_required": True,
            "redemption_refusal": (
                outcome.redemption_refusal.value
                if outcome.redemption_refusal is not None
                else None
            ),
        }
    return _refused_batch(update, [call], {str(call.get("id")): outcome}) or {
        **update,
        "governance_status": GOVERNANCE_DENIED,
        **_cleared_guard_hitl_state(),
    }  # unreachable: an outcome that did not complete always refuses


def _with_deferred_id(state: Any, deferred_id: str | None) -> Any:
    """Return ``state`` whose last message's tool calls carry only ``deferred_id``.

    Any ``deferred_id`` the model wrote into a call is dropped first. With
    ``deferred_id=None`` (no human approval) the calls carry none at all.
    """
    messages = list(state.get("messages") or [])
    last = messages[-1]
    calls = []
    for call in getattr(last, "tool_calls", None) or []:
        args = _without_model_deferred_id(call.get("args"))
        if deferred_id is not None:
            args["deferred_id"] = deferred_id
        calls.append({**call, "args": args})
    messages[-1] = AIMessage(content=getattr(last, "content", ""), tool_calls=calls)
    return {**state, "messages": messages}


def _with_step_deferred_ids(state: Any, step_ids: list[str | None]) -> Any:
    """Return ``state`` where each tool call carries its step-bound ``deferred_id``."""
    messages = list(state.get("messages") or [])
    last = messages[-1]
    raw_calls = list(getattr(last, "tool_calls", None) or [])
    calls = []
    for call, step_def_id in zip(raw_calls, step_ids, strict=True):
        args = _without_model_deferred_id(call.get("args"))
        if step_def_id is not None:
            args["deferred_id"] = step_def_id
        calls.append({**call, "args": args})
    messages[-1] = AIMessage(content=getattr(last, "content", ""), tool_calls=calls)
    return {**state, "messages": messages}


def _parse_approved_step_ids(state: Any) -> tuple[bool, list[str | None] | None]:
    """Validate ``state['deferred_step_ids']`` when ``approval_decision.approved`` is True.

    Returns ``(present, validated_step_ids)``. When ``present`` is True and
    ``validated_step_ids`` is None, ``deferred_step_ids`` was malformed and the
    caller must refuse the batch fail-closed.
    """
    decision = state.get("approval_decision") or {}
    if not (isinstance(decision, dict) and decision.get("approved") is True):
        return False, None
    raw = state.get("deferred_step_ids")
    if raw is None:
        return False, None
    if not isinstance(raw, list) or not raw:
        return True, None
    parsed: list[str | None] = []
    has_deferred = False
    for item in raw:
        if item is None:
            parsed.append(None)
        elif isinstance(item, str) and item.strip():
            parsed.append(item.strip())
            has_deferred = True
        else:
            return True, None
    return (True, parsed) if has_deferred else (True, None)


def _preview_call_params(call: dict[str, Any], action: str) -> dict[str, Any]:
    """Build gateway ``validate-action`` params for one tool call without model ``deferred_id``."""
    params: dict[str, Any] = {
        **_without_model_deferred_id(call.get("args")),
        "tool_name": call.get("name", ""),
    }
    if call.get("name") == TRADE_TOOL:
        params.pop("transaction_id", None)
    params.setdefault("action", action)
    return params


async def _execute_approved_step_batch(
    func: NodeFn,
    state: Any,
    tool_calls: list[dict[str, Any]],
    step_ids: list[str | None] | None,
    *,
    action: str,
) -> dict[str, Any]:
    """Execute a multi-step HITL-approved batch with per-step ``deferred_id`` binding."""
    if step_ids is None or len(tool_calls) != len(step_ids):
        return {
            "messages": _answer_all(
                tool_calls,
                {},
                "Governance refused this action: tool calls do not match approved plan steps",
            ),
            "governance_status": GOVERNANCE_DENIED,
            **_cleared_guard_hitl_state(),
        }

    refusals: dict[str, str] = {}
    verdicts: list[dict[str, Any]] = []
    for call, step_def_id in zip(tool_calls, step_ids, strict=True):
        if step_def_id is not None:
            continue
        params = _preview_call_params(call, action)
        verdict, reason = await authorize_action(action, params)
        if verdict is None:
            refusals[str(call.get("id"))] = reason or "refused"
        elif verdict.get("verdict") not in _EXECUTABLE_VERDICTS:
            refusals[str(call.get("id"))] = (
                "gateway requires human approval for an unapproved step"
            )
        else:
            verdicts.append(verdict)

    if refusals:
        return {
            "messages": _answer_all(
                tool_calls,
                {
                    k: f"Governance refused this action: {v}"
                    for k, v in refusals.items()
                },
                "Governance refused this action: another tool call in the same batch was refused",
            ),
            "governance_status": GOVERNANCE_DENIED,
            **_cleared_guard_hitl_state(),
        }

    update, outcomes = _split_outcomes(
        await func(_with_step_deferred_ids(state, step_ids)), tool_calls
    )
    # A multi-step batch may already have executed some steps, so it is never
    # re-run: any step that did not complete ends it (DENIED).
    denied = _refused_batch(update, tool_calls, outcomes)
    if denied is not None:
        return denied
    return {
        **update,
        "governance_status": GOVERNANCE_ALLOWED,
        **_cleared_guard_hitl_state(),
        "governance_envelope": verdicts[-1] if verdicts else None,
        "redemption_refusal": None,
    }


def gateway_tool_guard(
    action: str, *, approvable: bool = False
) -> Callable[[NodeFn], NodeFn]:
    """Wrap a tool-executor node so it runs only as the gateway routes it.

    Args:
        action: Governance action name submitted to the gateway for every tool
            call in the batch (e.g. ``"execute_trade"``).
        approvable: Whether the wrapping graph has a human-approval path. When
            False, ``REQUIRE_APPROVAL`` refuses the batch like any other
            non-executable verdict.
    """

    def decorator(func: NodeFn) -> NodeFn:
        @functools.wraps(func)
        async def wrapper(state: Any) -> dict[str, Any]:
            state = _with_derived_transaction_ids(state)
            tool_calls = _pending_tool_calls(state)
            if not tool_calls:
                return {"messages": []}

            if approvable:
                has_step_ids, step_ids = _parse_approved_step_ids(state)
                if has_step_ids:
                    return await _execute_approved_step_batch(
                        func, state, tool_calls, step_ids, action=action
                    )

            approved_id = _approved_deferred_id(state) if approvable else None
            if approved_id is not None and len(tool_calls) > 1:
                return {
                    "messages": _answer_all(
                        tool_calls,
                        {},
                        "Governance refused this action: an approval covers exactly one call",
                    ),
                    "governance_status": GOVERNANCE_DENIED,
                    **_cleared_guard_hitl_state(),
                }
            if approved_id is not None:
                # The gateway, not the advisor, decides whether the approval
                # covers these params; the id is single-use on both sides.
                # The route follows the typed outcome of the redemption.
                (call,) = tool_calls
                update, outcomes = _split_outcomes(
                    await func(_with_deferred_id(state, approved_id)), tool_calls
                )
                return _after_approved_redemption(
                    update, call, outcomes.get(str(call.get("id"))), approved_id
                )

            verdicts: list[dict[str, Any]] = []
            refusals: dict[str, str] = {}
            deferred_ids: dict[str, str] = {}
            cached_cache = (
                state.get("routing_verdict_cache")
                if action == TRADE_ACTION and len(tool_calls) == 1
                else None
            )

            for call in tool_calls:
                params: dict[str, Any] = {
                    # never self-asserted by the model
                    **_without_model_deferred_id(call.get("args")),
                    "tool_name": call.get("name", ""),
                }
                if call.get("name") == TRADE_TOOL:
                    # The derived idempotency key names the call, not the order.
                    params.pop("transaction_id", None)
                params.setdefault("action", action)
                reused = (
                    reusable_allow_verdict(cached_cache, params)
                    if cached_cache is not None
                    else None
                )
                if reused is not None:
                    verdicts.append(reused)
                    continue
                verdict, reason = await authorize_action(action, params)
                if verdict is None:
                    refusals[str(call.get("id"))] = reason or "refused"
                elif verdict.get("verdict") == GovernanceDecision.REQUIRE_APPROVAL:
                    if not approvable:
                        refusals[str(call.get("id"))] = (
                            "gateway requires human approval"
                        )
                        continue
                    deferred_ids[str(call.get("id"))] = str(verdict["deferred_id"])
                else:
                    verdicts.append(verdict)

            if deferred_ids and len(tool_calls) > 1:
                # An approval binds one call's params; batching it with others
                # would forward the deferred_id to calls it does not cover.
                for call_id in deferred_ids:
                    refusals.setdefault(
                        call_id, "a call that requires approval must be submitted alone"
                    )
            if refusals:
                logger.warning(
                    "Gateway refused %s for %d of %d tool call(s) — batch not executed: %s",
                    action,
                    len(refusals),
                    len(tool_calls),
                    refusals,
                )
                return {
                    "messages": _answer_all(
                        tool_calls,
                        {
                            k: f"Governance refused this action: {v}"
                            for k, v in refusals.items()
                        },
                        "Governance refused this action: another tool call in the same batch was refused",
                    ),
                    "governance_status": GOVERNANCE_DENIED,
                    "governance_envelope": None,
                    "routing_verdict_cache": None,
                }

            if deferred_ids:
                (deferred_id,) = deferred_ids.values()
                logger.info(
                    "Gateway requires approval for %s — batch parked as deferred_id=%s",
                    action,
                    deferred_id,
                )
                return {
                    "messages": [
                        ToolMessage(
                            content=_awaiting_approval_message(call),
                            tool_call_id=call.get("id"),
                            name=call.get("name"),
                        )
                        for call in tool_calls
                    ],
                    "governance_status": GOVERNANCE_REQUIRE_APPROVAL,
                    "governance_envelope": None,
                    "deferred_id": deferred_id,
                    "routing_verdict_cache": None,
                }

            # Execute exactly what was validated: no model-supplied deferred_id.
            update, outcomes = _split_outcomes(
                await func(_with_deferred_id(state, None)), tool_calls
            )
            denied = _refused_batch(update, tool_calls, outcomes)
            if denied is not None:
                return denied
            return {
                **update,
                "governance_status": GOVERNANCE_ALLOWED,
                "governance_envelope": verdicts[-1] if verdicts else None,
                "routing_verdict_cache": None,
            }

        return wrapper

    return decorator
