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

"""DA-M1..DA-M9: the mutation set for the POAM-2026-232 unknown-actuation invariants.

A trade whose broker call may have gone out must never be recorded, answered
or reported as if nothing ran. Each mutant below breaks that at one of the
places that decide it, and each must be killed by its scenario:

* DA-M1 (unsafe): ``execute_trade_action`` frees the ledger key on an
  infrastructure error by exception type alone, so a dispatched trade can be
  claimed and actuated again.
* DA-M2 (unsafe): ``_govern_and_actuate`` flips to UNKNOWN only once
  ``dispatch_actuation`` returns, so a cancellation mid-dispatch releases the
  reservations and records BLOCKED.
* DA-M3 (unsafe): the guard reports a None or INDETERMINATE outcome as
  ``UNAVAILABLE``, the status that means nothing was sent.
* DA-M4 (unsafe): the guard drops None from its may-have-executed branch and
  crashes on it.
* DA-M5 (unsafe): DA-M4 without the crash: after a possible fill, the guard
  tells the model nothing was executed and to submit a new request.
* DA-M6 (unsafe): ``/tools/execute`` answers ``ActuationIndeterminateError``
  with the infrastructure 503, which carries no ``may_have_executed``.
* DA-M7 (unsafe): ``/tools/execute`` forwards a structured INDETERMINATE
  outcome without ``may_have_executed``.
* DA-M8 (safe direction): ``/tools/execute`` answers
  ``GovernanceInfrastructureError`` as indeterminate instead of 503.
* DA-M9 (safe direction): the guard reports a gateway outage before dispatch
  as ``DENIED`` instead of ``UNAVAILABLE``.

DA-M1 and DA-M5 survived the full fast suite until the dedicated tests in
``tests/cage_finance/test_trade_idempotency.py`` and
``tests/test_gateway_tool_guard.py`` were added; the other seven were already
killed there. This file keeps the kill rate a standing property, so the next
change to these functions is measured against all nine.

How a mutant runs: the function's own source (``inspect.getsource``, minus
its decorators) is edited at anchors that must each occur exactly once in it,
compiled, and executed in the live module's namespace, so the mutant's
globals are the module's and dotted-path patches still reach it. The module
attribute is swapped for the mutant for one test. Nothing is written to disk
and nothing is re-imported (``tool_provider`` registers its actuator at
import time), so scenarios call through module attributes. A scenario that
raises under the mutant counts as a difference; under the original it fails
the test.

When a refactor moves an anchor, retarget it to the same behaviour change.
Never drop a mutant to make the set pass.
"""

from __future__ import annotations
import __future__

import asyncio
import contextlib
import importlib
import inspect
import json
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from mcp.types import CallToolResult, TextContent
from starlette.requests import Request

from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.execution_idempotency import SHARED_CALLER, ExecutionLedger
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.seams.actuation import (
    ActuationIndeterminateError,
    ActuationOutcome,
    ActuationReceipt,
)
from src.gateway.server import governance_middleware, workload_identity
from src.governed_financial_advisor.graph.governance.tool_guard import COMMIT_OUTCOMES
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [
    pytest.mark.unit,
    pytest.mark.local,
    pytest.mark.usefixtures("connected_evidence_sink"),
]

_TOOL_PROVIDER = "src.cage_finance.tools.tool_provider"
_TOOL_GUARD = "src.governed_financial_advisor.graph.governance.tool_guard"
_TOOL_SERVER = "src.gateway.server.mcp_tool_server"

Edit = tuple[str, str]
Scenario = Callable[[], Awaitable[object]]


def _compile_mutant(module: ModuleType, name: str, edits: tuple[Edit, ...]) -> Any:
    """``module.name`` recompiled from its own source with ``edits`` applied.

    Decorators are dropped: the mutant replaces the module attribute, not a
    registration made at import time.
    """
    func = getattr(module, name)
    lines, first_line = inspect.getsourcelines(func)
    start = next(
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith(("def ", "async def "))
    )
    source = "".join(lines[start:])
    for old, new in edits:
        found = source.count(old)
        assert found == 1, f"{name}: anchor found {found} times, expected 1: {old!r}"
        source = source.replace(old, new)
    # Padded so that a traceback through the mutant names the original lines.
    code = compile(
        "\n" * (first_line + start - 1) + source,
        inspect.getsourcefile(func) or f"<mutant {name}>",
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    namespace: dict[str, Any] = {}
    # The module's own source, edited at the fixed anchors above.
    exec(code, module.__dict__, namespace)
    return namespace[name]


# ----------------------------------------------- execute_trade_action (M1, M2)

_TXN = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:cage:tests:da-mutation-set"))
_TRADE: dict[str, Any] = {
    "symbol": "AAPL",
    "amount": 10.0,
    "currency": "USD",
    "confidence": 0.99,
    "transaction_id": _TXN,
}


def _ledgered_governor() -> Any:
    """A governor stand-in whose execution ledger is real, over fakeredis."""
    governor = trade_governor()
    governor.components.execution_ledger = ExecutionLedger(
        fakeredis.aioredis.FakeRedis()
    )
    return governor


@contextmanager
def _trade_pipeline(actuate: AsyncMock) -> Iterator[None]:
    """Seal-issuing governance, a no-op seal check and a scripted broker."""
    with (
        patch(
            f"{_TOOL_PROVIDER}.enforce_governance",
            AsyncMock(side_effect=sealed_governance("seal-da")),
        ),
        patch(
            "src.gateway.governance.routing_seal.verify_and_consume_seal",
            new_callable=AsyncMock,
        ),
        patch(f"{_TOOL_PROVIDER}._broker_actuator.actuate", actuate),
        patch("src.gateway.infrastructure.redis_client.redis_client", None),
        patch(f"{_TOOL_PROVIDER}.record_refusal", new_callable=AsyncMock),
    ):
        yield


async def _ledger_status(governor: Any) -> object:
    """What a resubmission of ``_TXN`` would find in the ledger now."""
    reply = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    return getattr(reply, "status", "claimable")


async def _resubmit_after_post_dispatch_infra_error() -> object:
    """DA-M1: the broker accepts, settling fails on infrastructure, then a resubmit."""
    tool_provider = importlib.import_module(_TOOL_PROVIDER)
    governor = _ledgered_governor()
    actuate = AsyncMock(
        return_value=ActuationReceipt(
            accepted=True,
            receipt_id="r-da",
            session_uuid="s-da",
            raw_receipt={"execution_result": "EXECUTED"},
            outcome=ActuationOutcome.ACCEPTED,
        )
    )
    # Nothing after dispatch raises an infrastructure error today; the settle
    # step stands in for the first one that does.
    infra = GovernanceInfrastructureError(
        "settlement store unreachable after dispatch",
        dependency="settlement_store",
        failure_code="SETTLEMENT_STORE_UNAVAILABLE",
        error_code="settlement_store_unavailable",
    )
    with _trade_pipeline(actuate):
        with (
            patch.object(tool_provider, "_settle", AsyncMock(side_effect=infra)),
            contextlib.suppress(
                GovernanceInfrastructureError, ActuationIndeterminateError
            ),
        ):
            await tool_provider.execute_trade_action(**_TRADE, governor=governor)
        # The same transaction_id, with a healthy settle.
        await tool_provider.execute_trade_action(**_TRADE, governor=governor)
    return actuate.await_count, await _ledger_status(governor)


async def _cancel_mid_dispatch() -> object:
    """DA-M2: the broker call is cancelled while it is in flight."""
    tool_provider = importlib.import_module(_TOOL_PROVIDER)
    governor = _ledgered_governor()

    async def _cancelled(_clearance: Any) -> ActuationReceipt:
        raise asyncio.CancelledError

    with (
        _trade_pipeline(AsyncMock(side_effect=_cancelled)),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await tool_provider.execute_trade_action(**_TRADE, governor=governor)
    return governor.settle.await_args.kwargs["executed"], await _ledger_status(governor)


# ------------------------------------------------- gateway_tool_guard (M3-M5, M9)

_ALLOW_PREVIEW = (
    {"verdict": "ALLOW", "violations": [], "latency_ms": 1.0},
    None,
    False,
)
_UNREACHABLE_PREVIEW = (None, "ConnectError: gateway unreachable", True)


class _ReportingNode:
    """A tool executor that ran the batch and reports ``outcome`` for every call."""

    def __init__(self, outcome: CommitOutcome | None) -> None:
        self.outcome = outcome
        self.calls = 0

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        calls = state["messages"][-1].tool_calls
        return {
            "messages": [
                ToolMessage(content="tool ran", tool_call_id=c["id"], name=c["name"])
                for c in calls
            ],
            COMMIT_OUTCOMES: {str(c["id"]): self.outcome for c in calls},
        }


async def _guarded(node: _ReportingNode, preview: tuple[Any, ...]) -> dict[str, Any]:
    """Run one trade call through ``tool_guard.gateway_tool_guard`` as resolved now."""
    tool_guard = importlib.import_module(_TOOL_GUARD)
    call = {
        "name": "execute_trade_action",
        "args": {"symbol": "AAPL", "amount": 100.0, "currency": "USD"},
        "id": "t1",
    }
    state = {"messages": [AIMessage(content="", tool_calls=[call])]}
    with patch.object(
        tool_guard, "_authorize_action_classified", AsyncMock(return_value=preview)
    ):
        guarded = tool_guard.gateway_tool_guard("execute_trade", approvable=True)
        return await guarded(node)(state)


async def _guard_reply(outcome: CommitOutcome | None) -> object:
    out = await _guarded(_ReportingNode(outcome), _ALLOW_PREVIEW)
    replies = tuple(m.content for m in out["messages"] if m.tool_call_id == "t1")
    return out["governance_status"], replies


async def _guard_after_indeterminate() -> object:
    """DA-M3: the executor ran and reports an INDETERMINATE outcome."""
    return await _guard_reply(
        CommitOutcome(CommitStatus.INDETERMINATE, "broker reply lost after send")
    )


async def _guard_after_no_outcome() -> object:
    """DA-M4, DA-M5: the executor ran and decoded no outcome (None)."""
    return await _guard_reply(None)


async def _guard_on_unreachable_gateway() -> object:
    """DA-M9: validate-action is unreachable, so the executor never runs."""
    node = _ReportingNode(None)
    out = await _guarded(node, _UNREACHABLE_PREVIEW)
    return out["governance_status"], node.calls


# ------------------------------------------------ /tools/execute (M6, M7, M8)

_TRUSTED_CALLER = (
    "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
)


async def _tools_execute(
    tool: Callable[..., Awaitable[Any]],
) -> tuple[int, dict[str, Any]]:
    """``POST /tools/execute`` of ``tool`` by the trusted advisor, as (status, body).

    Calls ``mcp_tool_server.execute_tool_endpoint`` as resolved now, so a
    mutant swapped in for it is the one that answers.
    """
    tool_server = importlib.import_module(_TOOL_SERVER)
    policy = workload_identity.IdentityPolicy(
        trusted=frozenset({_TRUSTED_CALLER}), canary=frozenset()
    )
    tools = [SimpleNamespace(name="da_probe_tool", fn=tool)]
    with (
        patch.object(
            workload_identity, "extract_client_identity", return_value=_TRUSTED_CALLER
        ),
        patch.object(workload_identity, "load_identity_policy", return_value=policy),
        patch.object(
            tool_server, "refuse_if_quarantined", AsyncMock(return_value=None)
        ),
        patch.object(tool_server, "_check_rate_limit", AsyncMock(return_value=True)),
        patch.object(
            governance_middleware,
            "sanitize_mcp_tool_response",
            AsyncMock(return_value=None),
        ),
        patch.object(tool_server, "mark_request_refused"),
        patch.object(tool_server.mcp._tool_manager, "list_tools", return_value=tools),
    ):
        result = await tool_server.execute_tool_endpoint(
            tool_server.ToolExecutionRequest(tool_name="da_probe_tool", params={}),
            Request({"type": "http", "method": "POST", "path": "/tools/execute"}),
        )
    if isinstance(result, dict):  # FastAPI serves a returned dict as HTTP 200
        return 200, result
    return result.status_code, json.loads(result.body)


async def _endpoint_on_indeterminate_error() -> object:
    """DA-M6: the tool raises ``ActuationIndeterminateError``."""

    async def tool(**_kw: Any) -> Any:
        raise ActuationIndeterminateError(
            "broker reply lost after send", action="execute_trade"
        )

    status, body = await _tools_execute(tool)
    return (
        status,
        body.get("may_have_executed"),
        (body.get("outcome") or {}).get("status"),
    )


async def _endpoint_on_structured_indeterminate() -> object:
    """DA-M7: the tool answers with a structured INDETERMINATE outcome."""

    async def tool(**_kw: Any) -> CallToolResult:
        return CallToolResult(
            content=[TextContent(type="text", text="broker reply lost after send")],
            structuredContent=CommitOutcome(
                CommitStatus.INDETERMINATE, "broker reply lost after send"
            ).to_wire(),
            isError=True,
        )

    status, body = await _tools_execute(tool)
    return status, body.get("may_have_executed"), body.get("actuation_outcome")


async def _endpoint_on_infrastructure_error() -> object:
    """DA-M8: the tool raises ``GovernanceInfrastructureError`` before dispatch."""

    async def tool(**_kw: Any) -> Any:
        raise GovernanceInfrastructureError(
            "execution ledger unreachable",
            dependency="execution_ledger",
            failure_code="EXECUTION_LEDGER_UNAVAILABLE",
            error_code="execution_ledger_unavailable",
        )

    status, body = await _tools_execute(tool)
    return status, body.get("error"), body.get("may_have_executed")


# ---------------------------------------------------------------- mutants

MUTANTS: list[tuple[str, str, str, tuple[Edit, ...], Scenario]] = [
    (
        "DA-M1 unsafe: ledger key freed on an infrastructure error by type alone",
        _TOOL_PROVIDER,
        "execute_trade_action",
        (("                and attempt.status is ExecutionStatus.BLOCKED\n", ""),),
        _resubmit_after_post_dispatch_infra_error,
    ),
    (
        "DA-M2 unsafe: UNKNOWN flip moved after dispatch_actuation",
        _TOOL_PROVIDER,
        "_govern_and_actuate",
        (
            (
                "        attempt.status = ExecutionStatus.UNKNOWN\n"
                "        executed = True\n"
                "        receipt = await dispatch_actuation(actuator, clearance)\n",
                "        receipt = await dispatch_actuation(actuator, clearance)\n"
                "        attempt.status = ExecutionStatus.UNKNOWN\n"
                "        executed = True\n",
            ),
        ),
        _cancel_mid_dispatch,
    ),
    (
        "DA-M3 unsafe: guard reports a None/INDETERMINATE outcome as UNAVAILABLE",
        _TOOL_GUARD,
        "_refused_batch",
        (
            (
                '        "governance_status": GOVERNANCE_DENIED,\n'
                "        **_cleared_guard_hitl_state(),\n"
                '        "redemption_refusal": refusal.value'
                " if refusal is not None else None,\n",
                '        "governance_status": (\n'
                "            GOVERNANCE_UNAVAILABLE\n"
                "            if all(o is None or o.status in INDETERMINATE_STATUSES"
                " for o in unfinished.values())\n"
                "            else GOVERNANCE_DENIED\n"
                "        ),\n"
                "        **_cleared_guard_hitl_state(),\n"
                '        "redemption_refusal": refusal.value'
                " if refusal is not None else None,\n",
            ),
        ),
        _guard_after_indeterminate,
    ),
    (
        "DA-M4 unsafe: guard drops None from its may-have-executed branch (crash)",
        _TOOL_GUARD,
        "_terminal_message",
        (
            (
                "    if outcome is None or outcome.status in INDETERMINATE_STATUSES:\n",
                "    if outcome is not None and outcome.status"
                " in INDETERMINATE_STATUSES:\n",
            ),
        ),
        _guard_after_no_outcome,
    ),
    (
        "DA-M5 unsafe: guard tells a None outcome to submit a new request",
        _TOOL_GUARD,
        "_terminal_message",
        (
            (
                "    if outcome is None or outcome.status in INDETERMINATE_STATUSES:\n",
                "    if outcome is not None and outcome.status"
                " in INDETERMINATE_STATUSES:\n",
            ),
            (
                "    if outcome.status is CommitStatus.DEFERRED:\n"
                '        reason = "the gateway deferred it and holds no approval for it"\n',
                "    if outcome is not None and outcome.status is CommitStatus.DEFERRED:\n"
                '        reason = "the gateway deferred it and holds no approval for it"\n',
            ),
            (
                "    elif outcome.redemption_refusal is not None:\n",
                "    elif outcome is not None and outcome.redemption_refusal is not None:\n",
            ),
        ),
        _guard_after_no_outcome,
    ),
    (
        "DA-M6 unsafe: /tools/execute answers ActuationIndeterminateError with 503",
        _TOOL_SERVER,
        "execute_tool_endpoint",
        (
            (
                "    infra_error_types = _valid_exc_types(\n"
                "        GovernanceInfrastructureError,\n",
                "    infra_error_types = _valid_exc_types(\n"
                "        GovernanceInfrastructureError,\n"
                "        ActuationIndeterminateError,\n",
            ),
        ),
        _endpoint_on_indeterminate_error,
    ),
    (
        "DA-M7 unsafe: structured INDETERMINATE forwarded without may_have_executed",
        _TOOL_SERVER,
        "execute_tool_endpoint",
        (
            (
                '                response["actuation_outcome"] = "UNKNOWN"\n'
                '                response["may_have_executed"] = True\n',
                "                pass\n",
            ),
        ),
        _endpoint_on_structured_indeterminate,
    ),
    (
        "DA-M8 safe: /tools/execute answers infrastructure errors as indeterminate",
        _TOOL_SERVER,
        "execute_tool_endpoint",
        (
            (
                "    infra_error_types = _valid_exc_types(\n"
                "        GovernanceInfrastructureError,\n",
                "    infra_error_types = _valid_exc_types(\n",
            ),
            (
                "    actuation_indeterminate_types = _valid_exc_types(\n"
                "        ActuationIndeterminateError,\n",
                "    actuation_indeterminate_types = _valid_exc_types(\n"
                "        ActuationIndeterminateError,\n"
                "        GovernanceInfrastructureError,\n",
            ),
        ),
        _endpoint_on_infrastructure_error,
    ),
    (
        "DA-M9 safe: guard reports a gateway outage before dispatch as DENIED",
        _TOOL_GUARD,
        "gateway_tool_guard",
        (
            (
                "                        GOVERNANCE_UNAVAILABLE\n"
                "                        if only_unavailable\n",
                "                        GOVERNANCE_DENIED\n"
                "                        if only_unavailable\n",
            ),
        ),
        _guard_on_unreachable_gateway,
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mid", "module_name", "func_name", "edits", "scenario"),
    MUTANTS,
    ids=[m[0].split()[0] for m in MUTANTS],
)
async def test_mutant_is_killed(
    monkeypatch: pytest.MonkeyPatch,
    mid: str,
    module_name: str,
    func_name: str,
    edits: tuple[Edit, ...],
    scenario: Scenario,
) -> None:
    module = importlib.import_module(module_name)
    original = await scenario()
    monkeypatch.setattr(module, func_name, _compile_mutant(module, func_name, edits))
    try:
        mutant: object = await scenario()
    except NameError:
        raise  # an edit naming something the module lacks is broken, not killed
    except Exception as exc:  # a crash differs from the original too (DA-M4)
        mutant = f"raised {type(exc).__name__}"
    assert original != mutant, f"{mid} survived: {original!r}"


def test_mutation_set_is_da_m1_to_da_m9() -> None:
    # A mutant whose anchor moved is retargeted, never dropped.
    assert [m[0].split()[0] for m in MUTANTS] == [f"DA-M{i}" for i in range(1, 10)]
