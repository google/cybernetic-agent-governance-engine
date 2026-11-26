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

"""LangGraph node factories (``langgraph>=1.0.0``) for CAGE governance.

Provides three composable node factories built over ``CageClient.preview()`` and
``CageClient.execute_tool()`` using ``langgraph.types.Command`` and
``langgraph.types.interrupt``:

1. ``governed_node`` — single-action preview/commit mediation with explicit
   ``principal_extractor`` and ``action_extractor`` (zero fabricated
   ``"unknown"`` principals or silent ``{}`` fallbacks).
2. ``approval_park_node`` — HITL park/resume node that requires a checkpointed
   ``deferred_id`` in state before calling ``interrupt()``, validates reviewer
   resume payloads, and routes via ``Command(goto=...)``.
3. ``governed_tool_node`` — ``1..N`` batch ``AIMessage.tool_calls`` governance
   node with deterministic ``derive_plan_step_key()`` idempotency keys,
   model-supplied ``deferred_id`` stripping, single-use approval redemption
   with retryable vs. terminal ``ApprovalRedemptionRefusal`` branching, and
   guaranteed ``ToolMessage(tool_call_id=...)`` pairing on every exit.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from langchain_core.messages import ToolMessage
from langgraph.config import get_config
from langgraph.types import Command, interrupt

from .core import CageClient
from .exceptions import (
    CageGatewayError,
    CommitOutcomeDecodeError,
    GatewayUnavailableError,
    RoutingSealVerificationError,
)
from .idempotency import (
    derive_idempotency_key,
    derive_plan_step_key,
    extract_plan_step_bindings,
)
from .outcomes import (
    INDETERMINATE_STATUSES,
    REFUSAL_DESCRIPTIONS,
    CommitOutcome,
    CommitStatus,
    GovernanceDecision,
    IndeterminateProvenance,
    PreviewResult,
)

logger = logging.getLogger("CageClient.langgraph")

_UNTRUSTED_APPROVAL_KEYS: frozenset[str] = frozenset({"deferred_id", "approval_token"})
_IDEMPOTENCY_PARAM_KEYS: frozenset[str] = frozenset(
    {"idempotency_key", "transaction_id"}
)


def _non_blank_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _require_callable(fn: Any, *, name: str) -> Callable[..., Any]:
    if not callable(fn):
        raise TypeError(f"{name} is required and must be callable")
    return fn


def _safe_extract_principal(
    principal_extractor: Callable[[Mapping[str, Any]], str],
    state: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    try:
        raw = principal_extractor(state)
    except Exception as exc:
        return (
            None,
            f"principal_extractor failed fail-closed ({type(exc).__name__}): {exc}",
        )
    if not isinstance(raw, str) or not raw.strip():
        return (
            None,
            "missing or empty governance principal; refusing to fabricate a default",
        )
    return raw.strip(), None


def _safe_extract_action(
    action_extractor: Callable[[Mapping[str, Any]], tuple[str, Mapping[str, Any]]],
    state: Mapping[str, Any],
) -> tuple[str | None, dict[str, Any] | None, str | None]:
    try:
        extracted = action_extractor(state)
    except Exception as exc:
        return (
            None,
            None,
            f"action_extractor failed fail-closed ({type(exc).__name__}): {exc}",
        )
    if not isinstance(extracted, tuple) or len(extracted) != 2:
        return None, None, "action_extractor must return (action, params)"
    action, params = extracted
    if not isinstance(action, str) or not action.strip():
        return None, None, "missing or empty action name; refusing to dispatch"
    if not isinstance(params, Mapping):
        return (
            None,
            None,
            "missing or non-mapping action parameters; refusing to fabricate {}",
        )
    clean_params = {
        k: v for k, v in params.items() if k not in _UNTRUSTED_APPROVAL_KEYS
    }
    return action.strip(), clean_params, None


def _cleared_hitl_update(
    *,
    deferred_id_key: str,
    approval_decision_key: str,
    deferred_step_ids_key: str = "deferred_step_ids",
) -> dict[str, Any]:
    return {
        deferred_id_key: None,
        deferred_step_ids_key: None,
        approval_decision_key: None,
        "approval_required": False,
    }


def _approved_token_from_state(
    state: Mapping[str, Any],
    *,
    deferred_id_key: str,
    approval_decision_key: str,
) -> str | None:
    decision = state.get(approval_decision_key)
    deferred_id = _non_blank_str(state.get(deferred_id_key))
    if (
        deferred_id is not None
        and isinstance(decision, Mapping)
        and decision.get("approved") is True
    ):
        return deferred_id
    return None


def _thread_id_from_langgraph() -> str | None:
    try:
        cfg = get_config()
    except RuntimeError:
        return None
    thread_id = (cfg.get("configurable") or {}).get("thread_id")
    return _non_blank_str(str(thread_id)) if thread_id is not None else None


def _route_commit_outcome(
    outcome: CommitOutcome,
    *,
    submitted_approval_token: str | None,
    on_allow: str,
    on_approval_required: str | None,
    on_defer: str | None,
    on_deny: str,
    on_indeterminate: str | None,
    commit_outcome_key: str,
    deferred_id_key: str,
    approval_decision_key: str,
) -> Command[Any]:
    serialized_outcome = outcome.to_dict()
    if outcome.is_completed:
        return Command(
            goto=on_allow,
            update={
                "governance_status": GovernanceDecision.ALLOWED.value,
                commit_outcome_key: serialized_outcome,
                "redemption_refusal": None,
                "may_have_executed": outcome.status is CommitStatus.EXECUTED,
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    approval_decision_key=approval_decision_key,
                ),
            },
        )

    if outcome.awaits_same_ticket:
        ticket_id = outcome.deferred_id or submitted_approval_token
        target = on_approval_required or on_defer or on_deny
        return Command(
            goto=target,
            update={
                "governance_status": "REQUIRE_APPROVAL"
                if ticket_id
                else GovernanceDecision.DENIED.value,
                commit_outcome_key: serialized_outcome,
                deferred_id_key: ticket_id,
                approval_decision_key: None,
                "approval_required": bool(ticket_id),
                "redemption_refusal": (
                    outcome.redemption_refusal.value
                    if outcome.redemption_refusal is not None
                    else None
                ),
            },
        )

    if outcome.status is CommitStatus.DEFERRED:
        if outcome.deferred_id and on_approval_required is not None:
            return Command(
                goto=on_approval_required,
                update={
                    "governance_status": "REQUIRE_APPROVAL",
                    commit_outcome_key: serialized_outcome,
                    deferred_id_key: outcome.deferred_id,
                    approval_decision_key: None,
                    "approval_required": True,
                    "redemption_refusal": None,
                },
            )
        return Command(
            goto=on_defer or on_deny,
            update={
                "governance_status": GovernanceDecision.DEFERRED.value,
                commit_outcome_key: serialized_outcome,
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    approval_decision_key=approval_decision_key,
                ),
                "redemption_refusal": None,
            },
        )

    if outcome.is_indeterminate:
        return Command(
            goto=on_indeterminate or on_deny,
            update={
                "governance_status": CommitStatus.INDETERMINATE.value,
                commit_outcome_key: serialized_outcome,
                "may_have_executed": True,
                "redemption_refusal": None,
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    approval_decision_key=approval_decision_key,
                ),
            },
        )

    return Command(
        goto=on_deny,
        update={
            "governance_status": GovernanceDecision.DENIED.value,
            commit_outcome_key: serialized_outcome,
            "redemption_refusal": (
                outcome.redemption_refusal.value
                if outcome.redemption_refusal is not None
                else None
            ),
            **_cleared_hitl_update(
                deferred_id_key=deferred_id_key,
                approval_decision_key=approval_decision_key,
            ),
        },
    )


def governed_node(
    *,
    client: CageClient,
    principal_extractor: Callable[[Mapping[str, Any]], str],
    action_extractor: Callable[[Mapping[str, Any]], tuple[str, Mapping[str, Any]]],
    tool_name_extractor: Callable[[Mapping[str, Any]], str] | None = None,
    idempotency_key_extractor: Callable[[Mapping[str, Any]], str] | None = None,
    approval_token_extractor: Callable[[Mapping[str, Any]], str | None] | None = None,
    on_allow: str,
    on_narrow: str | None = None,
    on_approval_required: str | None = None,
    on_defer: str | None = None,
    on_deny: str,
    on_unavailable: str | None = None,
    on_indeterminate: str | None = None,
    preview_before_execute: bool = True,
    require_commit_outcome: bool = True,
    verify_signature: bool | None = None,
    commit_outcome_key: str = "commit_outcome",
    deferred_id_key: str = "deferred_id",
    approval_decision_key: str = "approval_decision",
) -> Callable[[Mapping[str, Any]], Awaitable[Command[Any]]]:
    """Create a LangGraph node governing one action via preview and/or ``/tools/execute``.

    Validates ``principal_extractor`` and ``action_extractor`` before any
    gateway I/O and returns ``langgraph.types.Command`` so ``deferred_id`` is
    checkpointed before ``approval_park_node`` calls ``interrupt()``.
    """
    if not isinstance(client, CageClient):
        raise TypeError("client must be a CageClient instance")
    _require_callable(principal_extractor, name="principal_extractor")
    _require_callable(action_extractor, name="action_extractor")
    if tool_name_extractor is not None:
        _require_callable(tool_name_extractor, name="tool_name_extractor")
    if idempotency_key_extractor is not None:
        _require_callable(idempotency_key_extractor, name="idempotency_key_extractor")
    if approval_token_extractor is not None:
        _require_callable(approval_token_extractor, name="approval_token_extractor")

    async def _node(state: Mapping[str, Any]) -> Command[Any]:
        principal, principal_err = _safe_extract_principal(principal_extractor, state)
        if principal_err is not None or principal is None:
            return Command(
                goto=on_deny,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": principal_err,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        action_name, clean_params, action_err = _safe_extract_action(
            action_extractor, state
        )
        if action_err is not None or action_name is None or clean_params is None:
            return Command(
                goto=on_deny,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": action_err,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        approval_token: str | None = None
        if approval_token_extractor is not None:
            raw_tok = approval_token_extractor(state)
            approval_token = _non_blank_str(raw_tok)
        else:
            approval_token = _approved_token_from_state(
                state,
                deferred_id_key=deferred_id_key,
                approval_decision_key=approval_decision_key,
            )

        exec_params = dict(clean_params)

        if preview_before_execute and approval_token is None:
            preview_res: PreviewResult = await client.preview(
                action=action_name,
                parameters=clean_params,
                agent_id=principal,
            )
            if preview_res.decision is GovernanceDecision.UNAVAILABLE:
                return Command(
                    goto=on_unavailable or on_deny,
                    update={
                        "governance_status": GovernanceDecision.UNAVAILABLE.value,
                        "error": preview_res.error,
                    },
                )
            if preview_res.decision is GovernanceDecision.DENIED:
                return Command(
                    goto=on_deny,
                    update={
                        "governance_status": GovernanceDecision.DENIED.value,
                        "last_violation": {
                            "reason_code": preview_res.reason_code,
                            "audit_id": preview_res.audit_id,
                            "violations": list(preview_res.violations),
                            "recoverable": preview_res.recoverable,
                        },
                        **_cleared_hitl_update(
                            deferred_id_key=deferred_id_key,
                            approval_decision_key=approval_decision_key,
                        ),
                    },
                )
            if preview_res.decision is GovernanceDecision.DEFERRED:
                serialized_defer_exp = (
                    preview_res.defer_expires_at.isoformat()
                    if preview_res.defer_expires_at is not None
                    else None
                )
                if preview_res.requires_approval and preview_res.deferred_id:
                    return Command(
                        goto=on_approval_required or on_defer or on_deny,
                        update={
                            "governance_status": "REQUIRE_APPROVAL",
                            deferred_id_key: preview_res.deferred_id,
                            "defer_reason": preview_res.defer_reason,
                            "defer_expires_at": serialized_defer_exp,
                            "approval_required": True,
                        },
                    )
                return Command(
                    goto=on_defer or on_deny,
                    update={
                        "governance_status": GovernanceDecision.DEFERRED.value,
                        deferred_id_key: preview_res.deferred_id,
                        "defer_reason": preview_res.defer_reason,
                        "defer_expires_at": serialized_defer_exp,
                        "approval_required": False,
                    },
                )
            if preview_res.decision is GovernanceDecision.NARROWED:
                serialized_env = (
                    preview_res.envelope.model_dump(mode="json")
                    if preview_res.envelope is not None
                    else None
                )
                if tool_name_extractor is None or on_narrow is not None:
                    return Command(
                        goto=on_narrow or on_allow,
                        update={
                            "governance_status": GovernanceDecision.NARROWED.value,
                            "narrowed_params": (
                                dict(preview_res.narrowed_params)
                                if isinstance(preview_res.narrowed_params, Mapping)
                                else preview_res.narrowed_params
                            ),
                            "governance_envelope": serialized_env,
                        },
                    )
                if isinstance(preview_res.narrowed_params, Mapping):
                    exec_params.update(preview_res.narrowed_params)

            if tool_name_extractor is None:
                serialized_env = (
                    preview_res.envelope.model_dump(mode="json")
                    if preview_res.envelope is not None
                    else None
                )
                return Command(
                    goto=on_allow,
                    update={
                        "governance_status": GovernanceDecision.ALLOWED.value,
                        "governance_envelope": serialized_env,
                    },
                )

        if tool_name_extractor is None:
            return Command(
                goto=on_deny,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": "governed_node cannot execute without tool_name_extractor",
                },
            )

        raw_tool_name = tool_name_extractor(state)
        tool_name = _non_blank_str(raw_tool_name)
        if tool_name is None:
            return Command(
                goto=on_deny,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": "tool_name_extractor returned empty tool_name",
                },
            )

        idem_key = (
            _non_blank_str(idempotency_key_extractor(state))
            if idempotency_key_extractor is not None
            else None
        )
        try:
            outcome = await client.execute_tool(
                tool_name,
                exec_params,
                idempotency_key=idem_key,
                approval_token=approval_token,
                verify_signature=verify_signature,
                require_commit_outcome=require_commit_outcome,
                headers={"x-cage-principal": principal},
            )
        except GatewayUnavailableError as exc:
            return Command(
                goto=on_unavailable or on_deny,
                update={
                    "governance_status": GovernanceDecision.UNAVAILABLE.value,
                    "error": str(exc),
                },
            )
        except (CommitOutcomeDecodeError, RoutingSealVerificationError) as exc:
            inferred = CommitOutcome(
                status=CommitStatus.INDETERMINATE,
                message=(
                    f"CommitOutcome verification failed after dispatch ({exc}); "
                    "do not retry until reconciled."
                ),
                tool_name=tool_name,
                idempotency_key=idem_key,
                provenance=IndeterminateProvenance.CLIENT_INFERRED,
                verified=False,
                may_have_executed=True,
            )
            return Command(
                goto=on_indeterminate or on_deny,
                update={
                    "governance_status": CommitStatus.INDETERMINATE.value,
                    commit_outcome_key: inferred.to_dict(),
                    "may_have_executed": True,
                    "error": str(exc),
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )
        except CageGatewayError as exc:
            return Command(
                goto=on_deny,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": str(exc),
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        return _route_commit_outcome(
            outcome,
            submitted_approval_token=approval_token,
            on_allow=on_allow,
            on_approval_required=on_approval_required,
            on_defer=on_defer,
            on_deny=on_deny,
            on_indeterminate=on_indeterminate,
            commit_outcome_key=commit_outcome_key,
            deferred_id_key=deferred_id_key,
            approval_decision_key=approval_decision_key,
        )

    return _node


def approval_park_node(
    *,
    approved_target: str,
    rejected_target: str,
    deferred_id_key: str = "deferred_id",
    deferred_step_ids_key: str = "deferred_step_ids",
    approval_decision_key: str = "approval_decision",
    payload_builder: Callable[[Mapping[str, Any], str, list[str]], Mapping[str, Any]]
    | None = None,
    require_rationale: bool = True,
) -> Callable[[Mapping[str, Any]], Command[Any]]:
    """Create a LangGraph HITL suspension node backed by ``langgraph.types.interrupt()``.

    Requires a previously checkpointed ``deferred_id`` (or ``deferred_step_ids``)
    in state and fails closed to ``rejected_target`` if none is present or if the
    resume payload lacks valid approval metadata.
    """
    if payload_builder is not None:
        _require_callable(payload_builder, name="payload_builder")

    def _node(state: Mapping[str, Any]) -> Command[Any]:
        step_ids = [
            str(d).strip()
            for d in (state.get(deferred_step_ids_key) or [])
            if isinstance(d, str) and d.strip()
        ]
        deferred_id = _non_blank_str(state.get(deferred_id_key))
        deferred_ids = step_ids or ([deferred_id] if deferred_id is not None else [])
        primary_ticket = deferred_id or (deferred_ids[0] if deferred_ids else None)

        if primary_ticket is None:
            return Command(
                goto=rejected_target,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "approval_required": False,
                    "error": "approval_park_node requires a checkpointed deferred_id in state",
                },
            )

        payload: dict[str, Any] = {
            "reason": "approval_required",
            "deferred_id": primary_ticket,
            "deferred_ids": deferred_ids,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if payload_builder is not None:
            payload.update(dict(payload_builder(state, primary_ticket, deferred_ids)))

        resumed = interrupt(payload)
        if not isinstance(resumed, Mapping) or not isinstance(
            resumed.get("approved"), bool
        ):
            return Command(
                goto=rejected_target,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": "Invalid approval resume payload: boolean 'approved' required",
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        deferred_step_ids_key=deferred_step_ids_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        approved = resumed["approved"]
        reviewer = _non_blank_str(resumed.get("reviewer"))
        rationale = _non_blank_str(resumed.get("rationale"))
        if require_rationale and (reviewer is None or rationale is None):
            return Command(
                goto=rejected_target,
                update={
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": "Approval resume payload requires non-empty 'reviewer' and 'rationale'",
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        deferred_step_ids_key=deferred_step_ids_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        decision_record = {
            **dict(resumed),
            "approved": approved,
            "reviewer": reviewer or "",
            "rationale": rationale or "",
        }
        if approved:
            return Command(
                goto=approved_target,
                update={
                    approval_decision_key: decision_record,
                    "approval_required": False,
                },
            )

        return Command(
            goto=rejected_target,
            update={
                "governance_status": GovernanceDecision.DENIED.value,
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    deferred_step_ids_key=deferred_step_ids_key,
                    approval_decision_key=approval_decision_key,
                ),
            },
        )

    return _node


def _make_tool_message(*, content: str, tool_call_id: str, name: str) -> ToolMessage:
    kwargs: dict[str, Any] = {
        "content": content,
        "tool_call_id": tool_call_id,
        "name": name,
    }
    if tool_call_id:
        kwargs["id"] = f"cage-tool:{tool_call_id}"
    return ToolMessage(**kwargs)


def _paired_tool_messages(
    calls: Sequence[Mapping[str, Any]],
    per_call_text: Mapping[str, str],
    default_text: str,
) -> list[ToolMessage]:
    return [
        _make_tool_message(
            content=per_call_text.get(str(call.get("id") or ""), default_text),
            tool_call_id=str(call.get("id") or ""),
            name=str(call.get("name") or ""),
        )
        for call in calls
    ]


def _find_target_tool_calls(
    messages: Sequence[Any],
    *,
    allow_trailing_tool_messages: bool,
) -> tuple[Any, list[Any]]:
    if not messages:
        return None, []
    last_msg = messages[-1]
    direct_calls = list(getattr(last_msg, "tool_calls", None) or [])
    if direct_calls:
        return last_msg, direct_calls
    if not allow_trailing_tool_messages:
        return None, []
    trailing_call_ids: set[str] = set()
    idx = len(messages) - 1
    while idx >= 0 and isinstance(messages[idx], ToolMessage):
        tcid = _non_blank_str(getattr(messages[idx], "tool_call_id", None))
        if tcid is not None:
            trailing_call_ids.add(tcid)
        idx -= 1
    if idx < 0:
        return None, []
    candidate = messages[idx]
    candidate_calls = list(getattr(candidate, "tool_calls", None) or [])
    if not candidate_calls:
        return None, []
    candidate_ids = {
        str(c.get("id") or "") for c in candidate_calls if isinstance(c, Mapping)
    }
    if candidate_ids and candidate_ids.issubset(trailing_call_ids):
        return candidate, candidate_calls
    return None, []


def _humanize_refusal(outcome: CommitOutcome) -> str:
    if outcome.redemption_refusal is not None:
        desc = REFUSAL_DESCRIPTIONS.get(
            outcome.redemption_refusal, outcome.redemption_refusal.value
        )
        return f"Nothing was executed: {desc}."
    return (
        f"Nothing was executed: {outcome.message or 'gateway refused the tool call'}."
    )


def _format_commit_outcome_message(outcome: CommitOutcome) -> str:
    if outcome.status in INDETERMINATE_STATUSES:
        return (
            "The outcome of this tool call could not be confirmed. "
            "Do not submit it again until it has been reconciled."
        )
    if outcome.status is CommitStatus.DEFERRED:
        if outcome.approval_retained:
            return (
                "Nothing was executed. The gateway deferred this tool call; "
                "its approval is retained and nothing was spent."
            )
        return "Nothing was executed. The gateway deferred this tool call."
    if outcome.awaits_same_ticket:
        return (
            "Nothing was executed. This action is still awaiting reviewer approval "
            "at the compliance bridge; resume after approval is recorded."
        )
    if outcome.status is CommitStatus.REFUSED:
        return _humanize_refusal(outcome)
    return outcome.output if outcome.output is not None else outcome.message


def _execute_error_halt(
    exc: CageGatewayError,
    *,
    cid: str,
    tname: str,
    idem_key: str | None,
    on_deny: str,
    on_unavailable: str | None,
    on_indeterminate: str | None,
    deferred_id_key: str,
    approval_decision_key: str,
) -> tuple[ToolMessage, dict[str, Any] | None, str, str, dict[str, Any]]:
    if isinstance(exc, GatewayUnavailableError):
        return (
            _make_tool_message(
                content=f"Governance unavailable: {exc}",
                tool_call_id=cid,
                name=tname,
            ),
            None,
            GovernanceDecision.UNAVAILABLE.value,
            on_unavailable or on_deny,
            {"error": str(exc)},
        )
    if isinstance(exc, (CommitOutcomeDecodeError, RoutingSealVerificationError)):
        inferred = CommitOutcome(
            status=CommitStatus.INDETERMINATE,
            message=(
                "The outcome of this tool call could not be verified. "
                "Do not submit it again until it has been reconciled."
            ),
            tool_name=tname,
            idempotency_key=idem_key,
            provenance=IndeterminateProvenance.CLIENT_INFERRED,
            verified=False,
            may_have_executed=True,
        )
        return (
            _make_tool_message(
                content=_format_commit_outcome_message(inferred),
                tool_call_id=cid,
                name=tname,
            ),
            inferred.to_dict(),
            CommitStatus.INDETERMINATE.value,
            on_indeterminate or on_deny,
            {
                "may_have_executed": True,
                "error": str(exc),
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    approval_decision_key=approval_decision_key,
                ),
            },
        )
    return (
        _make_tool_message(
            content=f"Governance refused tool call: {exc}",
            tool_call_id=cid,
            name=tname,
        ),
        None,
        GovernanceDecision.DENIED.value,
        on_deny,
        {
            "error": str(exc),
            **_cleared_hitl_update(
                deferred_id_key=deferred_id_key,
                approval_decision_key=approval_decision_key,
            ),
        },
    )


def governed_tool_node(
    *,
    client: CageClient,
    action: str | Callable[[str, Mapping[str, Any], Mapping[str, Any]], str],
    principal_extractor: Callable[[Mapping[str, Any]], str],
    committing_tools: frozenset[str] | set[str] | None = None,
    plan_extractor: Callable[[Mapping[str, Any]], Any] | None = None,
    step_extractor: Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]]
    | None = None,
    step_canonical_extractor: Callable[[Any], tuple[str, ...]] | None = None,
    on_complete: str,
    on_approval_required: str | None = None,
    on_defer: str | None = None,
    on_deny: str,
    on_unavailable: str | None = None,
    on_indeterminate: str | None = None,
    approvable: bool = True,
    preview_before_execute: bool = True,
    verify_signature: bool | None = None,
    messages_key: str = "messages",
    deferred_id_key: str = "deferred_id",
    approval_decision_key: str = "approval_decision",
    commit_outcomes_key: str = "commit_outcomes",
) -> Callable[[Mapping[str, Any]], Awaitable[Command[Any]]]:
    """Create a LangGraph batch node mediating ``1..N`` ``AIMessage.tool_calls``.

    Guarantees:
      - Zero fabricated default principals or ``{}`` args: missing principal or
        malformed calls fail closed before gateway I/O.
      - Every model-supplied ``deferred_id`` / ``approval_token`` is stripped;
        only an approved state token is forwarded to ``/tools/execute``.
      - Deterministic per-step idempotency keys via ``derive_plan_step_key()``
        and ``derive_idempotency_key()`` for committing calls.
      - Every tool call ID in ``AIMessage.tool_calls`` receives a paired
        ``ToolMessage(tool_call_id=...)`` on every exit (completed, refused,
        deferred, unavailable, or indeterminate), preserving message history
        without ever leaking ``deferred_id`` into prompt text.
    """
    if not isinstance(client, CageClient):
        raise TypeError("client must be a CageClient instance")
    if isinstance(action, str):
        if not action.strip():
            raise ValueError("action must be a non-empty string or callable")
    elif not callable(action):
        raise TypeError("action must be a non-empty string or callable")
    _require_callable(principal_extractor, name="principal_extractor")
    if plan_extractor is not None:
        _require_callable(plan_extractor, name="plan_extractor")

    commit_set = frozenset(committing_tools) if committing_tools is not None else None

    def _is_committing(tool_name: str) -> bool:
        if commit_set is None:
            return True
        return tool_name in commit_set

    def _action_for(
        tool_name: str, args: Mapping[str, Any], state: Mapping[str, Any]
    ) -> str:
        if callable(action):
            resolved = action(tool_name, args, state)
            if not isinstance(resolved, str) or not resolved.strip():
                raise ValueError("action callable returned empty governance action")
            return resolved.strip()
        return action.strip()

    async def _node(state: Mapping[str, Any]) -> Command[Any]:
        messages = list(state.get(messages_key) or [])
        if not messages:
            return Command(goto=on_complete, update={messages_key: []})

        approved_token = (
            _approved_token_from_state(
                state,
                deferred_id_key=deferred_id_key,
                approval_decision_key=approval_decision_key,
            )
            if approvable
            else None
        )
        last_msg, raw_calls = _find_target_tool_calls(
            messages, allow_trailing_tool_messages=approved_token is not None
        )
        if not raw_calls:
            return Command(goto=on_complete, update={messages_key: []})

        calls: list[dict[str, Any]] = [dict(c) for c in raw_calls]

        principal, principal_err = _safe_extract_principal(principal_extractor, state)
        if principal_err is not None or principal is None:
            return Command(
                goto=on_deny,
                update={
                    messages_key: _paired_tool_messages(
                        calls, {}, f"Governance refused tool call: {principal_err}"
                    ),
                    "governance_status": GovernanceDecision.DENIED.value,
                    "error": principal_err,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        # Validate every tool call shape before any gateway call and strip model deferred_id.
        cleaned_calls: list[tuple[dict[str, Any], str, dict[str, Any], str | None]] = []
        invalid_msgs: dict[str, str] = {}
        thread_id = _thread_id_from_langgraph()
        message_id = _non_blank_str(getattr(last_msg, "id", None))
        plan_raw = plan_extractor(state) if plan_extractor is not None else None
        plan_digest, plan_steps = (
            extract_plan_step_bindings(plan_raw, step_extractor=step_extractor)
            if plan_raw is not None
            else (None, [])
        )
        used_steps: set[int] = set()
        step_counts: dict[str, int] = {}

        for call in calls:
            cid = str(call.get("id") or "")
            tname = _non_blank_str(call.get("name"))
            raw_args = call.get("args")
            if tname is None or not isinstance(raw_args, Mapping):
                invalid_msgs[cid] = (
                    "Governance refused tool call: missing tool name or mapping args."
                )
                cleaned_calls.append((call, tname or "", {}, None))
                continue
            clean_args = {
                k: v for k, v in raw_args.items() if k not in _UNTRUSTED_APPROVAL_KEYS
            }
            idem_key: str | None = None
            if _is_committing(tname):
                occ = step_counts.get(tname, 0)
                step_counts[tname] = occ + 1
                step_key = derive_plan_step_key(
                    clean_args,
                    plan_digest=plan_digest,
                    plan_steps=plan_steps,
                    used_step_indices=used_steps,
                    occurrence=occ,
                    canonical_extractor=step_canonical_extractor,
                )
                idem_key = derive_idempotency_key(
                    step_key, thread_id=thread_id, message_id=message_id
                )
            cleaned_calls.append((call, tname, clean_args, idem_key))

        if invalid_msgs:
            return Command(
                goto=on_deny,
                update={
                    messages_key: _paired_tool_messages(
                        calls,
                        invalid_msgs,
                        "Governance refused this batch: another tool call in the batch was invalid.",
                    ),
                    "governance_status": GovernanceDecision.DENIED.value,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        if approved_token is not None and len(cleaned_calls) > 1:
            return Command(
                goto=on_deny,
                update={
                    messages_key: _paired_tool_messages(
                        calls,
                        {},
                        "Governance refused this action: an approval covers exactly one tool call.",
                    ),
                    "governance_status": GovernanceDecision.DENIED.value,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                },
            )

        # Preview phase (skipped only when redeeming an approved ticket for a single call).
        exec_args_list: list[dict[str, Any]] = [
            dict(args) for _, _, args, _ in cleaned_calls
        ]
        if preview_before_execute and approved_token is None:
            preview_refusals: dict[str, str] = {}
            preview_unavailable: dict[str, str] = {}
            approval_tickets: dict[str, str] = {}
            terminal_defers: dict[str, str] = {}

            for idx, (call, tname, clean_args, _idem) in enumerate(cleaned_calls):
                cid = str(call.get("id") or "")
                try:
                    gov_action = _action_for(tname, clean_args, state)
                except ValueError as exc:
                    preview_refusals[cid] = str(exc)
                    continue
                preview_params = {
                    k: v
                    for k, v in clean_args.items()
                    if k not in _IDEMPOTENCY_PARAM_KEYS
                }
                preview_params["tool_name"] = tname
                preview_params.setdefault("action", gov_action)

                prev_res = await client.preview(
                    action=gov_action,
                    parameters=preview_params,
                    agent_id=principal,
                )
                if prev_res.decision is GovernanceDecision.ALLOWED:
                    continue
                if prev_res.decision is GovernanceDecision.NARROWED:
                    if isinstance(prev_res.narrowed_params, Mapping):
                        exec_args_list[idx].update(prev_res.narrowed_params)
                    continue
                if prev_res.decision is GovernanceDecision.UNAVAILABLE:
                    preview_unavailable[cid] = (
                        f"Governance unavailable: {prev_res.error or 'gateway error'}"
                    )
                    continue
                if prev_res.decision is GovernanceDecision.DEFERRED:
                    if (
                        prev_res.requires_approval
                        and approvable
                        and prev_res.deferred_id
                    ):
                        approval_tickets[cid] = prev_res.deferred_id
                    elif prev_res.requires_approval and not approvable:
                        preview_refusals[cid] = (
                            "Governance refused this action: approval is required on a non-approvable path."
                        )
                    else:
                        terminal_defers[cid] = (
                            "Nothing was executed: gateway deferred this request "
                            f"({prev_res.defer_reason or 'hold'})."
                        )
                    continue
                preview_refusals[cid] = (
                    f"Governance refused this action ({prev_res.reason_code or 'DENIED'})."
                )

            if approval_tickets and len(cleaned_calls) > 1:
                for cid in approval_tickets:
                    preview_refusals.setdefault(
                        cid,
                        "Governance refused this action: a call requiring approval must be submitted alone.",
                    )
                approval_tickets.clear()

            if preview_refusals or preview_unavailable or terminal_defers:
                per_call = {
                    **preview_unavailable,
                    **terminal_defers,
                    **preview_refusals,
                }
                only_unavailable = (
                    bool(preview_unavailable)
                    and not preview_refusals
                    and not terminal_defers
                )
                only_defer = (
                    bool(terminal_defers)
                    and not preview_refusals
                    and not preview_unavailable
                )
                if only_unavailable:
                    target = on_unavailable or on_deny
                    status = GovernanceDecision.UNAVAILABLE.value
                    fallback = "Governance unavailable for another tool call in the same batch."
                elif only_defer:
                    target = on_defer or on_deny
                    status = GovernanceDecision.DEFERRED.value
                    fallback = "Nothing was executed: another tool call in the same batch was deferred."
                else:
                    target = on_deny
                    status = GovernanceDecision.DENIED.value
                    fallback = "Governance refused this batch: another tool call in the batch was refused."
                return Command(
                    goto=target,
                    update={
                        messages_key: _paired_tool_messages(calls, per_call, fallback),
                        "governance_status": status,
                        **_cleared_hitl_update(
                            deferred_id_key=deferred_id_key,
                            approval_decision_key=approval_decision_key,
                        ),
                    },
                )

            if approval_tickets:
                (ticket_id,) = approval_tickets.values()
                waiting_msgs = _paired_tool_messages(
                    calls,
                    {},
                    "Nothing was executed. This action requires reviewer approval "
                    "at the compliance bridge; it is in your pending approvals.",
                )
                return Command(
                    goto=on_approval_required or on_defer or on_deny,
                    update={
                        messages_key: waiting_msgs,
                        "governance_status": "REQUIRE_APPROVAL",
                        deferred_id_key: ticket_id,
                        "approval_required": True,
                    },
                )

        # Execution phase across 1..N calls on POST /tools/execute.
        tool_messages: list[ToolMessage] = []
        outcomes_by_id: dict[str, dict[str, Any]] = {}
        halted_idx: int | None = None
        halt_status = GovernanceDecision.ALLOWED.value
        halt_target = on_complete
        halt_extra: dict[str, Any] = {}

        for idx, (call, tname, _clean_args, idem_key) in enumerate(cleaned_calls):
            cid = str(call.get("id") or "")
            exec_args = exec_args_list[idx]
            try:
                outcome = await client.execute_tool(
                    tname,
                    exec_args,
                    idempotency_key=idem_key,
                    approval_token=approved_token,
                    verify_signature=verify_signature,
                    require_commit_outcome=_is_committing(tname),
                    headers={"x-cage-principal": principal},
                )
            except CageGatewayError as exc:
                halted_idx = idx
                tmsg, inferred_dict, halt_status, halt_target, halt_extra = (
                    _execute_error_halt(
                        exc,
                        cid=cid,
                        tname=tname,
                        idem_key=idem_key,
                        on_deny=on_deny,
                        on_unavailable=on_unavailable,
                        on_indeterminate=on_indeterminate,
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    )
                )
                tool_messages.append(tmsg)
                if inferred_dict is not None:
                    outcomes_by_id[cid] = inferred_dict
                break

            outcomes_by_id[cid] = outcome.to_dict()
            tool_messages.append(
                _make_tool_message(
                    content=_format_commit_outcome_message(outcome),
                    tool_call_id=cid,
                    name=tname,
                )
            )
            if outcome.is_completed:
                continue

            halted_idx = idx
            if outcome.awaits_same_ticket and approvable:
                retained_ticket_id = outcome.deferred_id or approved_token
                halt_status = (
                    "REQUIRE_APPROVAL"
                    if retained_ticket_id
                    else GovernanceDecision.DENIED.value
                )
                halt_target = (
                    on_approval_required or on_defer or on_deny
                    if retained_ticket_id
                    else on_deny
                )
                halt_extra = {
                    deferred_id_key: retained_ticket_id,
                    approval_decision_key: None,
                    "approval_required": bool(retained_ticket_id),
                    "redemption_refusal": (
                        outcome.redemption_refusal.value
                        if outcome.redemption_refusal is not None
                        else None
                    ),
                }
            elif (
                outcome.status is CommitStatus.DEFERRED
                and outcome.deferred_id
                and approvable
            ):
                halt_status = "REQUIRE_APPROVAL"
                halt_target = on_approval_required or on_defer or on_deny
                halt_extra = {
                    deferred_id_key: outcome.deferred_id,
                    approval_decision_key: None,
                    "approval_required": True,
                }
            elif outcome.is_indeterminate:
                halt_status = CommitStatus.INDETERMINATE.value
                halt_target = on_indeterminate or on_deny
                halt_extra = {
                    "may_have_executed": True,
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                }
            else:
                halt_status = GovernanceDecision.DENIED.value
                halt_target = on_deny
                halt_extra = {
                    "redemption_refusal": (
                        outcome.redemption_refusal.value
                        if outcome.redemption_refusal is not None
                        else None
                    ),
                    **_cleared_hitl_update(
                        deferred_id_key=deferred_id_key,
                        approval_decision_key=approval_decision_key,
                    ),
                }
            break

        if halted_idx is not None:
            for call, tname, _args, _idem in cleaned_calls[halted_idx + 1 :]:
                cid = str(call.get("id") or "")
                tool_messages.append(
                    _make_tool_message(
                        content=(
                            "Tool call skipped because an earlier call in the same "
                            "governed batch did not complete."
                        ),
                        tool_call_id=cid,
                        name=tname,
                    )
                )
            return Command(
                goto=halt_target,
                update={
                    messages_key: tool_messages,
                    commit_outcomes_key: outcomes_by_id,
                    "governance_status": halt_status,
                    **halt_extra,
                },
            )

        return Command(
            goto=on_complete,
            update={
                messages_key: tool_messages,
                commit_outcomes_key: outcomes_by_id,
                "governance_status": GovernanceDecision.ALLOWED.value,
                "redemption_refusal": None,
                **_cleared_hitl_update(
                    deferred_id_key=deferred_id_key,
                    approval_decision_key=approval_decision_key,
                ),
            },
        )

    return _node
