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

"""DA-M1..DA-M16: mutation set for POAM-2026-232 / POAM-2026-252 attempt-state invariants.

A governed action whose actuator call may have gone out must never be recorded,
answered, or reported as if nothing ran. Every reader (the execution ledger,
domain settlement, the finance MCP tool result, and ``/tools/execute``) reads
one kernel-owned ``ActuationAttempt`` record written solely by
``dispatch_actuation()``. Each mutant below breaks one invariant in that chain,
and each must be killed both here and by a dedicated test in the normal suite:

* DA-M1 (unsafe): ``execute_trade_action`` asks ``ledger.release_unexecuted``
  to free the ledger key on an infrastructure error by exception type alone,
  ignoring ``not attempt.dispatched``.
* DA-M2 (unsafe): ``dispatch_actuation`` marks the kernel ``ActuationAttempt``
  only after awaiting ``actuator.actuate``, so mid-dispatch cancellation leaves
  the record ``BLOCKED`` and releases reservations.
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
* DA-M8 (safe direction): ``/tools/execute`` answers pre-dispatch
  ``GovernanceInfrastructureError`` as indeterminate instead of 503.
* DA-M9 (safe direction): the guard reports a gateway outage before dispatch
  as ``DENIED`` instead of ``UNAVAILABLE``.
* DA-M10 (unsafe): ``execute_tool_endpoint`` ignores the kernel attempt record
  on escaping post-dispatch exceptions and falls back to exception-type mapping.
* DA-M11 (unsafe): ``ExecutionLedger.release_unexecuted`` ignores the kernel
  attempt record (``attempt.dispatched``) and deletes a dispatched claim.
* DA-M12 (unsafe): the finance MCP tool wrapper (``_execute_trade_tool``)
  ignores the kernel attempt record on escaping post-dispatch exceptions.
* DA-M13 (unsafe): ``mark_dispatch`` (called by ``dispatch_actuation``) drops
  its fail-closed scope guard and proceeds when no ``actuation_attempt_scope``
  is open.
* DA-M14 (unsafe): ``ActuationAttempt`` monotonicity is dropped in
  ``settle_dispatch`` so a later ``REJECTED`` receipt overwrites an earlier
  ``EXECUTED`` or ``UNKNOWN`` dispatch in the same scope.
* DA-M15 (unsafe): ``close_actuation_attempt`` fails to merge a nested
  ``actuation_attempt_scope`` into its enclosing parent scope on exit.
* DA-M16 (unsafe): healthcare ``administer_dose_action`` ignores the kernel
  attempt record for settlement and response on an ``UNKNOWN`` receipt.

How a mutant runs: the target callable's own source (``inspect.getsource``,
dedented and minus its decorators) is edited at anchors that must each occur
exactly once in it, compiled, and executed in the live module's namespace, so
the mutant's globals are the module's and dotted-path patches still reach it.
The module or class attribute is swapped for the mutant for one test. Nothing
is written to disk and nothing is re-imported, so scenarios call through live
module attributes. A scenario that raises under the mutant counts as a
difference; under the original it fails the test.

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
import textwrap
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from mcp.types import CallToolResult, TextContent
from starlette.requests import Request

from src.cage_healthcare.tools.dose_order import DoseOrder
from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ActuationAttemptScopeError,
    Claim,
    ExecutionLedger,
    ExecutionStatus,
    actuation_attempt_scope,
)
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.seams.actuation import (
    ActuationIndeterminateError,
    ActuationOutcome,
    ActuationReceipt,
    ExecutionClearance,
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
_HEALTHCARE_PROVIDER = "src.cage_healthcare.tools.tool_provider"
_TOOL_GUARD = "src.governed_financial_advisor.graph.governance.tool_guard"
_CAGE_LANGGRAPH = "cage_client.langgraph"
_TOOL_SERVER = "src.gateway.server.mcp_tool_server"
_EXECUTION_ACTUATOR = "src.gateway.governance.execution_actuator"
_IDEMPOTENCY = "src.gateway.governance.execution_idempotency"

Edit = tuple[str, str]
Scenario = Callable[[], Awaitable[object]]


def _resolve_target(module: ModuleType, name: str) -> tuple[Any, str, Any]:
    """Return ``(owner, attr_name, callable_obj)`` for ``name`` or ``Class.method``."""
    if "." in name:
        cls_name, attr_name = name.split(".", 1)
        owner = getattr(module, cls_name)
        return owner, attr_name, getattr(owner, attr_name)
    return module, name, getattr(module, name)


def _compile_mutant(module: ModuleType, name: str, edits: tuple[Edit, ...]) -> Any:
    """``module.name`` (or ``Class.method``) recompiled from its own source with ``edits``.

    Decorators are dropped: the mutant replaces the module or class attribute,
    not a registration made at import time.
    """
    _owner, attr_name, func = _resolve_target(module, name)
    lines, first_line = inspect.getsourcelines(func)
    start = next(
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith(("def ", "async def "))
    )
    source = textwrap.dedent("".join(lines[start:]))
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
    return namespace[attr_name]


# --------------------------------- shared probe clearance / receipt helpers


def _probe_clearance(thread_id: str = "t-da-probe") -> ExecutionClearance:
    return ExecutionClearance(
        thread_id=thread_id,
        decision="ALLOW",
        decision_path="DIRECT",
        action="execute_trade",
        target="AAPL",
        operator_urn="urn:op:da",
        issued_at=0,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        required_quorum=0,
    )


def _probe_receipt(outcome: ActuationOutcome) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=outcome is ActuationOutcome.ACCEPTED,
        receipt_id="r-da" if outcome is ActuationOutcome.ACCEPTED else None,
        session_uuid="s-da" if outcome is ActuationOutcome.ACCEPTED else None,
        raw_receipt={"execution_result": "EXECUTED"}
        if outcome is ActuationOutcome.ACCEPTED
        else None,
        findings=[]
        if outcome is ActuationOutcome.ACCEPTED
        else [{"code": f"PROBE_{outcome.value}"}],
        outcome=outcome,
    )


def _probe_actuator(outcome: ActuationOutcome) -> Any:
    return SimpleNamespace(
        actuator_id="da_probe_actuator",
        actuate=AsyncMock(return_value=_probe_receipt(outcome)),
    )


# ------------------------------------ execute_trade_action / dispatch (M1, M2, M12)

_TXN = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:cage:tests:da-mutation-set"))
_TRADE: dict[str, Any] = {
    "symbol": "AAPL",
    "amount": 10.0,
    "currency": "USD",
    "confidence": 0.99,
    "idempotency_key": _TXN,
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
        patch.object(governance_middleware, "record_refusal", new_callable=AsyncMock),
    ):
        yield


async def _ledger_status(governor: Any) -> object:
    """What a resubmission of ``_TXN`` would find in the ledger now."""
    reply = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    return getattr(reply, "status", "claimable")


async def _resubmit_after_post_dispatch_infra_error() -> object:
    """DA-M1: post-dispatch infra error must not ask the ledger to release the key."""
    tool_provider = importlib.import_module(_TOOL_PROVIDER)
    governor = _ledgered_governor()
    ledger = governor.components.execution_ledger
    release = AsyncMock(wraps=ledger.release_unexecuted)
    actuate = AsyncMock(return_value=_probe_receipt(ActuationOutcome.ACCEPTED))
    infra = GovernanceInfrastructureError(
        "settlement store unreachable after dispatch",
        dependency="settlement_store",
        failure_code="SETTLEMENT_STORE_UNAVAILABLE",
        error_code="settlement_store_unavailable",
    )
    with patch.object(ledger, "release_unexecuted", release), _trade_pipeline(actuate):
        with (
            patch.object(tool_provider, "_settle", AsyncMock(side_effect=infra)),
            contextlib.suppress(
                GovernanceInfrastructureError, ActuationIndeterminateError
            ),
        ):
            await tool_provider.execute_trade_action(**_TRADE, governor=governor)
        await tool_provider.execute_trade_action(**_TRADE, governor=governor)
    return release.await_count, actuate.await_count, await _ledger_status(governor)


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


async def _finance_mcp_tool_on_post_dispatch_infra_error() -> object:
    """DA-M12: registered finance MCP tool wrapper answers post-dispatch error from record."""
    tool_provider = importlib.import_module(_TOOL_PROVIDER)
    governor = _ledgered_governor()
    registered: dict[str, Callable[..., Any]] = {}

    class _CaptureServer:
        def tool(self, name: str | None = None, **_kw: Any) -> Any:
            def _decorator(fn: Any) -> Any:
                registered[name or fn.__name__] = fn
                return fn

            return _decorator

    tool_provider.FinancialToolProvider().register_tools(_CaptureServer(), governor)
    tool = registered["execute_trade_action"]
    infra = GovernanceInfrastructureError(
        "settlement store unreachable after dispatch",
        dependency="settlement_store",
        failure_code="SETTLEMENT_STORE_UNAVAILABLE",
        error_code="settlement_store_unavailable",
    )
    actuate = AsyncMock(return_value=_probe_receipt(ActuationOutcome.UNKNOWN))
    with (
        _trade_pipeline(actuate),
        patch.object(tool_provider, "_settle", AsyncMock(side_effect=infra)),
    ):
        result = await tool(**_TRADE)
    return result.isError, (result.structuredContent or {}).get("status")


# ------------------------------------------------- governed_tool_node & advisor_tool_message (M3-M5, M9)


async def _guarded_via_sdk(
    *,
    outcome_status: str | None = "INDETERMINATE",
    unreachable: bool = False,
) -> tuple[str, tuple[str, ...], int]:
    """Run one trade call through live ``cage_client.langgraph.governed_tool_node``."""
    import httpx
    from cage_client import CageClient

    from tests.fixtures.signed_gateway import SignedGatewayStub

    langgraph_mod = importlib.import_module(_CAGE_LANGGRAPH)
    tool_guard = importlib.import_module(_TOOL_GUARD)
    stub = SignedGatewayStub()
    execute_calls = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal execute_calls
        if unreachable and request.url.path == "/governance/validate-action":
            raise httpx.ConnectError("gateway unreachable", request=request)
        if request.url.path == "/governance/validate-action":
            return httpx.Response(
                200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
            )
        execute_calls += 1
        if outcome_status is None:
            return httpx.Response(200, json={"status": "ERROR", "error": "no outcome"})
        return httpx.Response(
            200,
            json={
                "status": "ERROR",
                "actuation_outcome": "UNKNOWN",
                "may_have_executed": True,
                "outcome": {
                    "status": outcome_status,
                    "message": "broker reply lost after send",
                },
            },
        )

    call = {
        "name": "execute_trade_action",
        "args": {"symbol": "AAPL", "amount": 100.0, "currency": "USD"},
        "id": "t1",
    }
    state = {"messages": [AIMessage(content="", tool_calls=[call])]}
    async with CageClient(
        "http://gateway.test",
        http_transport=httpx.MockTransport(stub.transport_handler(_handler)),
    ) as client:
        node = langgraph_mod.governed_tool_node(
            client=client,
            action="execute_trade",
            mode="execute",
            committing_tools={"execute_trade_action"},
            principal_extractor=lambda _s: "advisor-sa",
            message_formatter=lambda c, e, o: tool_guard.advisor_tool_message(c, e, o),
            on_complete="executor",
            on_approval_required="approval",
            on_defer="__end__",
            on_deny="__end__",
            on_unavailable="__end__",
            on_indeterminate="__end__",
            approvable=True,
        )
        cmd = await node(state)
    out = dict(cmd.update or {})
    replies = tuple(m.content for m in out["messages"] if m.tool_call_id == "t1")
    return str(out["governance_status"]), replies, execute_calls


async def _guard_after_indeterminate() -> object:
    """DA-M3: /tools/execute reports an INDETERMINATE outcome."""
    status, replies, _ = await _guarded_via_sdk(outcome_status="INDETERMINATE")
    return status, replies


async def _guard_after_no_outcome() -> object:
    """DA-M4, DA-M5: advisor_tool_message formats an indeterminate/missing CommitOutcome."""
    tool_guard = importlib.import_module(_TOOL_GUARD)
    call = {
        "name": "execute_trade_action",
        "args": {"symbol": "AAPL", "amount": 100.0, "currency": "USD"},
        "id": "t1",
    }
    msg = tool_guard.advisor_tool_message(call, "terminal_outcome", None)
    status, replies, _ = await _guarded_via_sdk(outcome_status=None)
    return status, (msg,), replies


async def _guard_on_unreachable_gateway() -> object:
    """DA-M9: validate-action is unreachable, so /tools/execute never runs."""
    status, _replies, calls = await _guarded_via_sdk(unreachable=True)
    return status, calls


# -------------------------------------------- /tools/execute (M6, M7, M8, M10)

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


async def _endpoint_on_post_dispatch_infra_error() -> object:
    """DA-M10: an infrastructure error escaping after dispatch answers from the record."""
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)

    async def tool(**_kw: Any) -> Any:
        clr = _probe_clearance()
        await ExecutionLedger(None).claim(clr.action, SHARED_CALLER, clr.thread_id)
        await exec_actuator.dispatch_actuation(
            _probe_actuator(ActuationOutcome.UNKNOWN), clr
        )
        raise GovernanceInfrastructureError(
            "settlement store unreachable after dispatch",
            dependency="settlement_store",
            failure_code="SETTLEMENT_STORE_UNAVAILABLE",
            error_code="settlement_store_unavailable",
        )

    with patch.object(
        exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da10")
    ):
        status, body = await _tools_execute(tool)
    return (
        status,
        body.get("may_have_executed"),
        (body.get("outcome") or {}).get("status"),
    )


# --------------------------- kernel attempt record & healthcare (M11, M13-M16)


async def _ledger_release_after_dispatch() -> object:
    """DA-M11: ``ExecutionLedger.release_unexecuted`` refuses after dispatch."""
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    clr = _probe_clearance("k-da-m11")
    with (
        patch.object(
            exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da11")
        ),
        actuation_attempt_scope(),
    ):
        claim = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
        assert isinstance(claim, Claim)
        await exec_actuator.dispatch_actuation(
            _probe_actuator(ActuationOutcome.UNKNOWN), clr
        )
        released = await ledger.release_unexecuted(claim)
    again = await ledger.claim("execute_trade", SHARED_CALLER, "k-da-m11")
    return released, getattr(again, "status", "claimable")


async def _dispatch_without_open_scope() -> object:
    """DA-M13: ``dispatch_actuation`` refuses before awaiting ``actuate`` outside a scope."""
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)
    actuator = _probe_actuator(ActuationOutcome.ACCEPTED)
    with patch.object(
        exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da13")
    ):
        try:
            await exec_actuator.dispatch_actuation(actuator, _probe_clearance())
        except ActuationAttemptScopeError as exc:
            return type(exc).__name__, actuator.actuate.await_count
    return "dispatched", actuator.actuate.await_count


async def _later_rejected_in_same_scope() -> object:
    """DA-M14: a later REJECTED receipt in the same scope never hides EXECUTED."""
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)
    with (
        patch.object(
            exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da14")
        ),
        actuation_attempt_scope() as attempt,
    ):
        ledger = ExecutionLedger(None)
        c1, c2 = _probe_clearance("t-da-14a"), _probe_clearance("t-da-14b")
        await ledger.claim(c1.action, SHARED_CALLER, c1.thread_id)
        await exec_actuator.dispatch_actuation(
            _probe_actuator(ActuationOutcome.ACCEPTED), c1
        )
        await ledger.claim(c2.action, SHARED_CALLER, c2.thread_id)
        await exec_actuator.dispatch_actuation(
            _probe_actuator(ActuationOutcome.REJECTED), c2
        )
        return attempt.status, attempt.may_have_executed


async def _nested_scope_merge_on_exit() -> object:
    """DA-M15: exiting a nested scope folds its dispatch into the enclosing scope."""
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)
    with (
        patch.object(
            exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da15")
        ),
        actuation_attempt_scope() as outer,
    ):
        clr = _probe_clearance("t-da-15")
        with actuation_attempt_scope():
            await ExecutionLedger(None).claim(clr.action, SHARED_CALLER, clr.thread_id)
            await exec_actuator.dispatch_actuation(
                _probe_actuator(ActuationOutcome.UNKNOWN), clr
            )
        return outer.dispatched, outer.status, outer.may_have_executed


async def _healthcare_on_unknown_dispatch() -> object:
    """DA-M16: healthcare dose action settles and answers from the kernel attempt record."""
    clinical_tools = importlib.import_module(_HEALTHCARE_PROVIDER)
    exec_actuator = importlib.import_module(_EXECUTION_ACTUATOR)
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    governor.components.execution_ledger = ExecutionLedger(None)
    dose = {
        "patient_id": "P-101",
        "medication": "vancomycin",
        "dose_mg": 2.0,
        "idempotency_key": "9f5e3d2c-1b0a-4f9e-8d7c-6b5a4f3e2d1c",
    }
    evaluated = {**DoseOrder(**dose).model_dump(), "confidence": 0.99}
    actuator = _probe_actuator(ActuationOutcome.UNKNOWN)
    with (
        patch.object(
            exec_actuator, "ingest_actuation_receipt", AsyncMock(return_value="m-da16")
        ),
        patch.object(
            clinical_tools,
            "enforce_governance",
            AsyncMock(
                return_value=SealedAction("administer_dose", "seal-da16", evaluated)
            ),
        ),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
        patch.object(clinical_tools._gm, "record_refusal", new_callable=AsyncMock),
    ):
        result = await clinical_tools.administer_dose_action(**dose, governor=governor)
    return result.status, governor.settle.await_args.kwargs["executed"]


# ---------------------------------------------------------------- mutants

MUTANTS: list[tuple[str, str, str, tuple[Edit, ...], Scenario]] = [
    (
        "DA-M1 unsafe: ledger key release called on an infrastructure error by type alone",
        _IDEMPOTENCY,
        "_settle_claim_on_error",
        (("        and not attempt.dispatched\n", ""),),
        _resubmit_after_post_dispatch_infra_error,
    ),
    (
        "DA-M2 unsafe: kernel attempt record marked only after actuator.actuate",
        _EXECUTION_ACTUATOR,
        "dispatch_actuation",
        (
            (
                "    attempt = _idempotency.mark_dispatch(\n"
                "        action=clearance.action,\n"
                "        idempotency_key=clearance.thread_id,\n"
                "    )\n",
                "",
            ),
            (
                "    await ingest_actuation_receipt("
                "clearance, receipt, actuator_id=actuator.actuator_id)\n",
                "    attempt = _idempotency.mark_dispatch(\n"
                "        action=clearance.action,\n"
                "        idempotency_key=clearance.thread_id,\n"
                "    )\n"
                "    await ingest_actuation_receipt("
                "clearance, receipt, actuator_id=actuator.actuator_id)\n",
            ),
        ),
        _cancel_mid_dispatch,
    ),
    (
        "DA-M3 unsafe: governed_tool_node reports an INDETERMINATE outcome as UNAVAILABLE",
        _CAGE_LANGGRAPH,
        "governed_tool_node",
        (
            (
                "                halt_status = CommitStatus.INDETERMINATE.value\n",
                "                halt_status = GovernanceDecision.UNAVAILABLE.value\n",
            ),
        ),
        _guard_after_indeterminate,
    ),
    (
        "DA-M4 unsafe: advisor_tool_message drops None from its may-have-executed branch (crash)",
        _TOOL_GUARD,
        "advisor_tool_message",
        (
            (
                "        if outcome is None or outcome.status in INDETERMINATE_STATUSES:\n",
                "        if outcome is not None and outcome.status"
                " in INDETERMINATE_STATUSES:\n",
            ),
        ),
        _guard_after_no_outcome,
    ),
    (
        "DA-M5 unsafe: advisor_tool_message tells a None outcome to submit a new request",
        _TOOL_GUARD,
        "advisor_tool_message",
        (
            (
                "        if outcome is None or outcome.status in INDETERMINATE_STATUSES:\n",
                "        if outcome is not None and outcome.status"
                " in INDETERMINATE_STATUSES:\n",
            ),
            (
                "        if outcome.status is CommitStatus.DEFERRED:\n"
                '            reason = "the gateway deferred it and holds no approval for it"\n',
                "        if outcome is not None and outcome.status is CommitStatus.DEFERRED:\n"
                '            reason = "the gateway deferred it and holds no approval for it"\n',
            ),
            (
                "        elif outcome.redemption_refusal is not None:\n",
                "        elif outcome is not None and outcome.redemption_refusal is not None:\n",
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
        "DA-M9 safe: governed_tool_node reports a gateway outage before dispatch as DENIED",
        _CAGE_LANGGRAPH,
        "governed_tool_node",
        (
            (
                "                    target = on_unavailable or on_deny\n"
                "                    status = GovernanceDecision.UNAVAILABLE.value\n",
                "                    target = on_unavailable or on_deny\n"
                "                    status = GovernanceDecision.DENIED.value\n",
            ),
        ),
        _guard_on_unreachable_gateway,
    ),
    (
        "DA-M10 unsafe: execute_tool_endpoint ignores kernel attempt record on escaping error",
        _TOOL_SERVER,
        "execute_tool_endpoint",
        (
            (
                "    except exceptions_after_dispatch() as exc:\n",
                "    except () as exc:\n",
            ),
        ),
        _endpoint_on_post_dispatch_infra_error,
    ),
    (
        "DA-M11 unsafe: ExecutionLedger.release_unexecuted ignores kernel attempt record",
        _IDEMPOTENCY,
        "ExecutionLedger.release_unexecuted",
        (("    if attempt is not None and attempt.dispatched:\n", "    if False:\n"),),
        _ledger_release_after_dispatch,
    ),
    (
        "DA-M12 unsafe: finance MCP tool wrapper ignores kernel attempt record on escaping error",
        _TOOL_PROVIDER,
        "FinancialToolProvider.register_tools",
        (
            (
                "                if after_dispatch is not None:\n",
                "                if False:\n",
            ),
        ),
        _finance_mcp_tool_on_post_dispatch_infra_error,
    ),
    (
        "DA-M13 unsafe: dispatch_actuation proceeds when no actuation_attempt_scope is open",
        _IDEMPOTENCY,
        "mark_dispatch",
        (
            (
                "    if attempt is None:\n"
                "        raise ActuationAttemptScopeError(\n"
                '            "dispatch_actuation() was called outside actuation_attempt_scope(); "\n'
                '            "nothing could read what the dispatch did, so it was not sent"\n'
                "        )\n",
                "    if attempt is None:\n"
                "        attempt = ActuationAttempt()\n"
                "        attempt._dispatched = True\n"
                "        attempt._in_flight += 1\n"
                "        return attempt\n",
            ),
        ),
        _dispatch_without_open_scope,
    ),
    (
        "DA-M14 unsafe: ActuationAttempt monotonicity dropped so later REJECTED overwrites",
        _IDEMPOTENCY,
        "settle_dispatch",
        (
            (
                "        attempt._settled = _dominant(attempt._settled, status)\n",
                "        attempt._settled = status\n",
            ),
        ),
        _later_rejected_in_same_scope,
    ),
    (
        "DA-M15 unsafe: nested actuation_attempt_scope fails to merge into parent scope on exit",
        _IDEMPOTENCY,
        "close_actuation_attempt",
        (("        enclosing._absorb(closed)\n", "        pass\n"),),
        _nested_scope_merge_on_exit,
    ),
    (
        "DA-M16 unsafe: healthcare settlement and response ignore kernel attempt record",
        _HEALTHCARE_PROVIDER,
        "administer_dose_action",
        (
            (
                "            if attempt.status is _ei.ExecutionStatus.UNKNOWN:\n",
                "            if False:\n",
            ),
            (
                "            if attempt.status is _ei.ExecutionStatus.BLOCKED:\n",
                "            if not rec.accepted:\n",
            ),
            (
                "            await governor.settle(seal, executed=attempt.may_have_executed)\n",
                "            await governor.settle("
                "seal, executed=bool(locals().get('rec') and rec.accepted))\n",
            ),
        ),
        _healthcare_on_unknown_dispatch,
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
    owner, attr_name, _orig = _resolve_target(module, func_name)
    original = await scenario()
    monkeypatch.setattr(owner, attr_name, _compile_mutant(module, func_name, edits))
    try:
        mutant: object = await scenario()
    except NameError:
        raise  # an edit naming something the module lacks is broken, not killed
    except Exception as exc:  # a crash differs from the original too (DA-M4, DA-M12)
        mutant = f"raised {type(exc).__name__}"
    assert original != mutant, f"{mid} survived: {original!r}"


def test_mutation_set_is_da_m1_to_da_m16() -> None:
    # A mutant whose anchor moved is retargeted, never dropped.
    assert [m[0].split()[0] for m in MUTANTS] == [f"DA-M{i}" for i in range(1, 17)]
