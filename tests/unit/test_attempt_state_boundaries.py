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

"""Every reader of the kernel attempt record answers from it (POAM-2026-252).

Latent hardening: nothing on ``main`` raised an infrastructure-typed error
after dispatch when this was written. The tests inject one (a failing
settlement) and check each reader on its own, so that no layer's check is
masked by another's:

* the finance tool never asks the ledger to release a key once its trade was
  dispatched (a spy on ``release_unexecuted``; the kernel's own refusal is
  pinned in ``test_actuation_attempt_record.py``);
* the finance tool result (the MCP path) answers from the record;
* ``/tools/execute`` answers from the record for a tool that converts
  nothing, so the endpoint's check is exercised without the finance wrapper;
* every domain dispatch path runs inside an attempt scope on both the
  ``/tools/execute`` and MCP paths.
"""

from __future__ import annotations

import ast
import asyncio
import json
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
from mcp.server.fastmcp import FastMCP

from src.cage_finance.tools import tool_provider as finance_tools
from src.cage_finance.tools.tool_provider import (
    FinancialToolProvider,
    execute_trade_action,
)
from src.cage_healthcare.tools import tool_provider as clinical_tools
from src.cage_healthcare.tools.dose_order import DoseOrder
from src.cage_healthcare.tools.tool_provider import ClinicalToolProvider
from src.cage_physical_ai.tools.tool_provider import PhysicalAIToolProvider
from src.gateway.governance import execution_actuator as exec_act
from src.gateway.governance.commit_outcome import CommitStatus
from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
from src.gateway.governance.execution_actuator import dispatch_actuation
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    Claim,
    Duplicate,
    ExecutionLedger,
    ExecutionStatus,
    current_actuation_attempt,
)
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuationRejectedError,
    ExecutionClearance,
)
from src.gateway.server import governance_middleware as gm
from src.gateway.server import mcp_tool_server as mts
from src.gateway.server import workload_identity as wid
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ACCEPTED = ActuationOutcome.ACCEPTED
_REJECTED = ActuationOutcome.REJECTED
_UNKNOWN = ActuationOutcome.UNKNOWN
_TXN = "7d3c1f0a-9b2e-4c5d-8e6f-0a1b2c3d4e5f"
_TRADE: dict[str, Any] = {
    "symbol": "AAPL",
    "amount": 10.0,
    "currency": "USD",
    "confidence": 0.99,
    "transaction_id": _TXN,
}
_DOSE: dict[str, Any] = {
    "patient_id": "P-101",
    "medication": "vancomycin",
    "dose_mg": 2.0,
}
_CALLER = (
    "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
)


def _receipt(outcome: ActuationOutcome) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=outcome is _ACCEPTED,
        receipt_id="r-252" if outcome is _ACCEPTED else None,
        session_uuid=None,
        raw_receipt=None,
        findings=[] if outcome is _ACCEPTED else [{"code": f"BROKER_{outcome.value}"}],
        outcome=outcome,
    )


def _clearance() -> ExecutionClearance:
    return ExecutionClearance(
        thread_id="t-boundary",
        decision="ALLOW",
        decision_path="DIRECT",
        action="governed_action",
        target="target-1",
        operator_urn="urn:op",
        issued_at=0,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        required_quorum=0,
    )


def _infra(dependency: str = "post_dispatch_store") -> GovernanceInfrastructureError:
    return GovernanceInfrastructureError(
        "infrastructure error raised after dispatch",
        dependency=dependency,
        failure_code="POST_DISPATCH_UNAVAILABLE",
        error_code="post_dispatch_unavailable",
    )


class _ScopeObserver:
    """An actuator that notes the attempt record it is called under."""

    actuator_id = "scope_observer"

    def __init__(self, outcome: ActuationOutcome = _ACCEPTED) -> None:
        self.outcome = outcome
        self.seen: list[tuple[bool, ExecutionStatus] | None] = []

    async def actuate(self, _clearance: ExecutionClearance) -> ActuationReceipt:
        attempt = current_actuation_attempt()
        self.seen.append(
            None if attempt is None else (attempt.dispatched, attempt.status)
        )
        return _receipt(self.outcome)


@pytest.fixture(autouse=True)
def _ingest(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    stub = AsyncMock(return_value="msg-252")
    monkeypatch.setattr(exec_act, "ingest_actuation_receipt", stub)
    return stub


@pytest.fixture
def governor() -> MagicMock:
    gov = trade_governor()
    gov.components.execution_ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    return gov


@contextmanager
def _trade_pipeline(
    actuate: AsyncMock, *, settle_error: BaseException | None = None
) -> Iterator[None]:
    """Seal-issuing governance, a no-op seal check and a scripted broker.

    ``settle_error`` is raised by the settlement that runs after dispatch,
    standing in for the first post-dispatch step that raises.
    """
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                finance_tools,
                "enforce_governance",
                AsyncMock(side_effect=sealed_governance("seal-252")),
            )
        )
        stack.enter_context(
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                new_callable=AsyncMock,
            )
        )
        stack.enter_context(
            patch.object(finance_tools._broker_actuator, "actuate", actuate)
        )
        stack.enter_context(
            patch("src.gateway.infrastructure.redis_client.redis_client", None)
        )
        stack.enter_context(
            patch.object(finance_tools, "record_refusal", new_callable=AsyncMock)
        )
        if settle_error is not None:
            stack.enter_context(
                patch.object(
                    finance_tools, "_settle", AsyncMock(side_effect=settle_error)
                )
            )
        yield


def _registered(provider: Any, governor: Any, name: str) -> Callable[..., Any]:
    registered: dict[str, Callable[..., Any]] = {}

    class _Server:
        def tool(self, name: str | None = None, **_kw: Any) -> Any:
            def _decorator(fn: Any) -> Any:
                registered[name or fn.__name__] = fn
                return fn

            return _decorator

    provider.register_tools(_Server(), governor)
    return registered[name]


@contextmanager
def _endpoint(tools: dict[str, Callable[..., Any]]) -> Iterator[MagicMock]:
    """Admit the caller and offer ``tools`` on /tools/execute; yield the refusal spy."""
    listed = [SimpleNamespace(name=name, fn=fn) for name, fn in tools.items()]
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(wid, "extract_client_identity", return_value=_CALLER)
        )
        stack.enter_context(
            patch.object(
                wid,
                "load_identity_policy",
                return_value=SimpleNamespace(trusted=frozenset({_CALLER})),
            )
        )
        stack.enter_context(
            patch.object(mts, "refuse_if_quarantined", AsyncMock(return_value=None))
        )
        stack.enter_context(
            patch.object(mts, "_check_rate_limit", AsyncMock(return_value=True))
        )
        stack.enter_context(
            patch.object(gm, "sanitize_mcp_tool_response", AsyncMock(return_value=None))
        )
        stack.enter_context(
            patch.object(mts.mcp._tool_manager, "list_tools", return_value=listed)
        )
        yield stack.enter_context(patch.object(mts, "mark_request_refused"))


async def _post(tool: str, params: dict[str, Any] | None = None) -> tuple[int, dict]:
    response = await mts.execute_tool_endpoint(
        mts.ToolExecutionRequest(tool_name=tool, params=dict(params or {})),
        MagicMock(scope={}, headers={}),
    )
    if isinstance(response, dict):
        return 200, response
    return response.status_code, json.loads(response.body)


def _dispatch_then_raise(
    outcome: ActuationOutcome, error: Callable[[], BaseException]
) -> Callable[..., Any]:
    """A tool that converts nothing: it dispatches, then lets an error escape."""

    async def _tool(**_kwargs: Any) -> Any:
        await dispatch_actuation(_ScopeObserver(outcome), _clearance())
        raise error()

    return _tool


# ── The finance tool: settlement, ledger and result read the record ────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "recorded"),
    [(_UNKNOWN, ExecutionStatus.UNKNOWN), (_ACCEPTED, ExecutionStatus.EXECUTED)],
)
async def test_the_trade_tool_never_asks_to_release_a_dispatched_key(
    governor: MagicMock, outcome: ActuationOutcome, recorded: ExecutionStatus
) -> None:
    ledger = governor.components.execution_ledger
    release = AsyncMock(wraps=ledger.release_unexecuted)
    with (
        patch.object(ledger, "release_unexecuted", release),
        _trade_pipeline(
            AsyncMock(return_value=_receipt(outcome)), settle_error=_infra()
        ),
        pytest.raises(GovernanceInfrastructureError),
    ):
        await execute_trade_action(**_TRADE, governor=governor)
    release.assert_not_awaited()
    duplicate = await ledger.claim("execute_trade", SHARED_CALLER, _TXN)
    assert isinstance(duplicate, Duplicate)
    assert duplicate.status is recorded


@pytest.mark.asyncio
async def test_the_trade_tool_releases_the_key_on_an_outage_before_dispatch(
    governor: MagicMock,
) -> None:
    ledger = governor.components.execution_ledger
    release = AsyncMock(wraps=ledger.release_unexecuted)
    actuate = AsyncMock(return_value=_receipt(_ACCEPTED))
    with (
        patch.object(ledger, "release_unexecuted", release),
        _trade_pipeline(actuate),
        patch.object(
            finance_tools,
            "enforce_governance",
            AsyncMock(side_effect=_infra("policy_engine")),
        ),
        pytest.raises(GovernanceInfrastructureError),
    ):
        await execute_trade_action(**_TRADE, governor=governor)
    release.assert_awaited_once()
    actuate.assert_not_awaited()
    assert isinstance(await ledger.claim("execute_trade", SHARED_CALLER, _TXN), Claim)


@pytest.mark.asyncio
async def test_a_post_dispatch_outage_never_frees_an_executed_key(
    governor: MagicMock,
) -> None:
    actuate = AsyncMock(return_value=_receipt(_ACCEPTED))
    with (
        _trade_pipeline(actuate, settle_error=_infra()),
        pytest.raises(GovernanceInfrastructureError),
    ):
        await execute_trade_action(**_TRADE, governor=governor)
    with _trade_pipeline(actuate):
        replay = await execute_trade_action(**_TRADE, governor=governor)
    assert replay.status is CommitStatus.EXECUTED
    assert actuate.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status", "is_error", "resubmitted"),
    [
        (_UNKNOWN, "INDETERMINATE", True, "UNSETTLED_DUPLICATE"),
        (_ACCEPTED, "EXECUTED", False, "EXECUTED"),
    ],
)
async def test_the_trade_tool_result_answers_a_post_dispatch_error_from_the_record(
    governor: MagicMock,
    outcome: ActuationOutcome,
    status: str,
    is_error: bool,
    resubmitted: str,
) -> None:
    tool = _registered(FinancialToolProvider(), governor, "execute_trade_action")
    actuate = AsyncMock(return_value=_receipt(outcome))
    with _trade_pipeline(actuate, settle_error=_infra()):
        result = await tool(**_TRADE)
    assert result.isError is is_error
    assert result.structuredContent["status"] == status
    with _trade_pipeline(actuate):
        again = await tool(**_TRADE)
    assert again.structuredContent["status"] == resubmitted
    assert actuate.await_count == 1


@pytest.mark.asyncio
async def test_after_a_rejected_receipt_a_later_outage_keeps_its_type(
    governor: MagicMock,
) -> None:
    tool = _registered(FinancialToolProvider(), governor, "execute_trade_action")
    with (
        _trade_pipeline(
            AsyncMock(return_value=_receipt(_REJECTED)), settle_error=_infra()
        ),
        pytest.raises(GovernanceInfrastructureError),
    ):
        await tool(**_TRADE)
    duplicate = await governor.components.execution_ledger.claim(
        "execute_trade", SHARED_CALLER, _TXN
    )
    assert isinstance(duplicate, Duplicate)
    assert duplicate.status is ExecutionStatus.BLOCKED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status"),
    [(_UNKNOWN, "INDETERMINATE"), (_ACCEPTED, "EXECUTED")],
)
async def test_tools_execute_never_answers_a_dispatched_trade_with_503(
    governor: MagicMock,
    outcome: ActuationOutcome,
    status: str,
) -> None:
    tool = _registered(FinancialToolProvider(), governor, "execute_trade_action")
    with (
        _trade_pipeline(
            AsyncMock(return_value=_receipt(outcome)), settle_error=_infra()
        ),
        _endpoint({"execute_trade_action": tool}) as refused,
    ):
        code, body = await _post("execute_trade_action", _TRADE)
    assert code == 200
    assert body["outcome"]["status"] == status
    assert body["may_have_executed"] is True
    refused.assert_not_called()


# ── /tools/execute reads the record itself (no converting wrapper) ─────────


_ERRORS: list[Any] = [
    pytest.param(_infra, id="infrastructure"),
    pytest.param(lambda: EvidenceChainUnavailableError("evidence down"), id="evidence"),
    pytest.param(lambda: RuntimeError("unexpected"), id="unexpected"),
    pytest.param(lambda: PermissionError("refused late"), id="permission"),
    pytest.param(
        lambda: SymbolicGovernorViolation("late violation", action="governed_action"),
        id="governor",
    ),
]


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governed tool error after dispatch answered as",
)
@pytest.mark.parametrize("error", _ERRORS)
@pytest.mark.parametrize(
    ("outcome", "status", "actuation_outcome"),
    [(_UNKNOWN, "INDETERMINATE", "UNKNOWN"), (_ACCEPTED, "EXECUTED", "ACCEPTED")],
)
async def test_tools_execute_answers_any_post_dispatch_error_from_the_record(
    error: Callable[[], BaseException],
    outcome: ActuationOutcome,
    status: str,
    actuation_outcome: str,
) -> None:
    with _endpoint({"tool": _dispatch_then_raise(outcome, error)}) as refused:
        code, body = await _post("tool")
    assert code == 200
    assert body["status"] == "ERROR"
    assert body["error_type"] == type(error()).__name__
    assert body["may_have_executed"] is True
    assert body["actuation_outcome"] == actuation_outcome
    assert body["outcome"]["status"] == status
    refused.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governed tool error after dispatch answered as",
)
async def test_tools_execute_reads_the_record_a_sync_tool_dispatched_under() -> None:
    def _sync_tool(**_kwargs: Any) -> Any:
        asyncio.run(dispatch_actuation(_ScopeObserver(_UNKNOWN), _clearance()))
        raise _infra()

    with _endpoint({"sync_tool": _sync_tool}) as refused:
        code, body = await _post("sync_tool")
    assert code == 200
    assert body["outcome"]["status"] == "INDETERMINATE"
    assert body["may_have_executed"] is True
    refused.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governance infrastructure unavailable during /tools/execute",
)
async def test_tools_execute_keeps_the_type_mapping_before_dispatch() -> None:
    async def _fails(**_kwargs: Any) -> Any:
        raise _infra()

    with _endpoint({"fails": _fails}) as refused:
        code, body = await _post("fails")
    assert code == 503
    assert "may_have_executed" not in body
    refused.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governance infrastructure unavailable during /tools/execute",
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governed tool execution rejected by actuator",
)
async def test_tools_execute_keeps_the_type_mapping_after_a_rejected_receipt() -> None:
    def _rejected() -> BaseException:
        return ActuationRejectedError("Actuation rejected: BROKER_REJECTED")

    tools = {
        "outage": _dispatch_then_raise(_REJECTED, _infra),
        "rejected": _dispatch_then_raise(_REJECTED, _rejected),
    }
    with _endpoint(tools) as refused:
        outage_code, outage = await _post("outage")
        rejected_code, rejected = await _post("rejected")
    assert outage_code == 503
    assert "may_have_executed" not in outage
    assert rejected_code == 200
    assert rejected["actuation_outcome"] == "REJECTED"
    assert rejected["may_have_executed"] is False
    refused.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.covers(
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governed tool error after dispatch answered as",
    "src.gateway.server.mcp_tool_server:execute_tool_endpoint#Governance infrastructure unavailable during /tools/execute",
)
async def test_each_request_gets_a_fresh_record() -> None:
    async def _fails(**_kwargs: Any) -> Any:
        raise _infra()

    tools = {"dispatches": _dispatch_then_raise(_UNKNOWN, _infra), "fails": _fails}
    with _endpoint(tools):
        first_code, _first = await _post("dispatches")
        second_code, _second = await _post("fails")
    assert (first_code, second_code) == (200, 503)
    assert current_actuation_attempt() is None


# ── Every domain dispatch path runs inside an attempt scope ─────────────────


@pytest.mark.asyncio
async def test_finance_dispatches_inside_a_scope_on_tools_execute(
    governor: MagicMock,
) -> None:
    observer = _ScopeObserver()
    tool = _registered(FinancialToolProvider(), governor, "execute_trade_action")
    with (
        _trade_pipeline(AsyncMock(side_effect=observer.actuate)),
        _endpoint({"execute_trade_action": tool}) as refused,
    ):
        code, body = await _post("execute_trade_action", _TRADE)
    assert observer.seen == [(True, ExecutionStatus.UNKNOWN)]
    assert code == 200
    assert body["outcome"]["status"] == "EXECUTED"
    assert body["may_have_executed"] is True
    refused.assert_not_called()


@pytest.mark.asyncio
async def test_finance_dispatches_inside_a_scope_on_the_mcp_path(
    governor: MagicMock,
) -> None:
    observer = _ScopeObserver()
    server = FastMCP("attempt-scope-coverage")
    FinancialToolProvider().register_tools(server, governor)
    with _trade_pipeline(AsyncMock(side_effect=observer.actuate)):
        await server.call_tool("execute_trade_action", dict(_TRADE))
    assert observer.seen == [(True, ExecutionStatus.UNKNOWN)]


@contextmanager
def _clinical_pipeline(actuator: Any) -> Iterator[MagicMock]:
    """Seal-issuing governance, a no-op seal check and ``actuator`` for doses."""
    governor = MagicMock(settle=AsyncMock(return_value=[]))
    evaluated = {**DoseOrder(**_DOSE).model_dump(), "confidence": 0.99}
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                clinical_tools,
                "enforce_governance",
                AsyncMock(
                    return_value=SealedAction("administer_dose", "seal-252", evaluated)
                ),
            )
        )
        stack.enter_context(
            patch.object(
                clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
            )
        )
        stack.enter_context(
            patch.object(
                clinical_tools,
                "get_actuator_registry",
                return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
            )
        )
        stack.enter_context(
            patch.object(clinical_tools._gm, "record_refusal", new_callable=AsyncMock)
        )
        yield governor


@pytest.mark.asyncio
async def test_healthcare_dispatches_inside_a_scope_on_tools_execute() -> None:
    observer = _ScopeObserver()
    with _clinical_pipeline(observer) as governor:
        tool = _registered(ClinicalToolProvider(), governor, "administer_dose")
        with _endpoint({"administer_dose": tool}) as refused:
            code, body = await _post("administer_dose", _DOSE)
    assert observer.seen == [(True, ExecutionStatus.UNKNOWN)]
    assert code == 200
    assert body["status"] == "SUCCESS"
    governor.settle.assert_awaited_once_with("seal-252", executed=True)
    refused.assert_not_called()


@pytest.mark.asyncio
async def test_healthcare_dispatches_inside_a_scope_on_the_mcp_path() -> None:
    observer = _ScopeObserver()
    with _clinical_pipeline(observer) as governor:
        server = FastMCP("attempt-scope-coverage")
        ClinicalToolProvider().register_tools(server, governor)
        await server.call_tool("administer_dose", dict(_DOSE))
    assert observer.seen == [(True, ExecutionStatus.UNKNOWN)]
    governor.settle.assert_awaited_once_with("seal-252", executed=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status", "executed"),
    [
        (_ACCEPTED, "GOVERNED", True),
        (_UNKNOWN, "INDETERMINATE", True),
        (_REJECTED, "BLOCKED", False),
    ],
)
async def test_healthcare_answers_and_settles_from_the_record(
    outcome: ActuationOutcome, status: str, executed: bool
) -> None:
    with _clinical_pipeline(_ScopeObserver(outcome)) as governor:
        result = await clinical_tools.administer_dose_action(**_DOSE, governor=governor)
    assert result["status"] == status
    governor.settle.assert_awaited_once_with("seal-252", executed=executed)


def test_physical_ai_registers_no_tool_that_could_dispatch() -> None:
    server = FastMCP("attempt-scope-coverage")
    PhysicalAIToolProvider().register_tools(server, MagicMock())
    assert server._tool_manager.list_tools() == []


def _calls_dispatch(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            if name == "dispatch_actuation":
                return True
    return False


def _opens_scope(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call):
                    func = call.func
                    name = (
                        func.attr
                        if isinstance(func, ast.Attribute)
                        else getattr(func, "id", "")
                    )
                    if name == "actuation_attempt_scope":
                        return True
    return False


def test_every_module_that_dispatches_opens_a_scope_and_is_covered_above() -> None:
    """New dispatch paths must open a scope and get per-path coverage here."""
    src = Path(__file__).resolve().parents[2] / "src"
    kernel = src / "gateway" / "governance" / "execution_actuator.py"
    dispatching: set[str] = set()
    for path in sorted(src.rglob("*.py")):
        if path == kernel:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _calls_dispatch(tree):
            assert _opens_scope(tree), f"{path} dispatches without an attempt scope"
            dispatching.add(path.relative_to(src).as_posix())
    assert dispatching == {
        "cage_finance/tools/tool_provider.py",
        "cage_healthcare/tools/tool_provider.py",
    }
