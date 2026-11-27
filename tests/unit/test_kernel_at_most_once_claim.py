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

"""Kernel-owned at-most-once ``ExecutionLedger`` claim enforcement (POAM-2026-254).

Verifies all four POAM-2026-254 closure criteria:
  (a) Direct ``dispatch_actuation()`` without a live kernel claim fails closed
      with ``UnclaimedActuationError`` before ``actuate()`` is awaited and
      leaves ``attempt.dispatched == False``.
  (b) Single-consumption guard: a second ``dispatch_actuation()`` inside the
      same scope without a fresh ``ExecutionLedger.claim()`` fails closed.
  (c) Action or ``clearance.thread_id != claimed_idempotency_key`` mismatch
      fails closed; released or finalized claims cannot be dispatched;
      ``ActuationAttempt`` exposes no public setter accepting a ``Claim``.
  (d) Healthcare ``administer_dose`` retries after ``ACCEPTED`` (P1) and after
      ``UNKNOWN`` (P3) on both ``/tools/execute`` and MCP never call
      ``ClinicalDoseActuator.actuate()`` a second time, plus ``BLOCKED`` replay,
      verified HITL ``deferred_id`` takeover, pre-dispatch outage key release,
      and enforcing-posture ``ExecutionLedgerUnavailable`` (``503``).
  (e) ``dry_run=True`` leaves ``attempt._claim is None`` and fails closed if
      dispatch is attempted.
  (f) Layer 1 ``is_valid_idempotency_key`` accepts canonical UUIDv4/v5 and
      refuses malformed or non-string values.
  (g) Dedicated live mutation checks (``KC-M1``..``KC-M5``) with inverted
      pass/fail verification kill removing the pre-``actuate()`` claim guard,
      the single-consumption guard, the ``(action, idempotency_key)`` binding
      guard, and the pre-``_dispatched`` ordering in ``dispatch_actuation()`` /
      ``mark_dispatch()``.
"""

from __future__ import annotations
import __future__

import ast
import importlib
import inspect
import json
import textwrap
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from src.cage_finance.tools import tool_provider as finance_tools
from src.cage_healthcare.ground_truth import SimulatedSerumAssayProvider
from src.cage_healthcare.tools import tool_provider as clinical_tools
from src.cage_healthcare.tools.dose_order import DoseOrder
from src.cage_healthcare.tools.tool_provider import (
    ClinicalDoseActuator,
    ClinicalToolProvider,
    administer_dose_action,
)
from src.gateway.governance import execution_actuator as exec_act
from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.execution_actuator import dispatch_actuation
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ActuationAttempt,
    ActuationAttemptScopeError,
    Claim,
    Duplicate,
    ExecutionLedger,
    ExecutionStatus,
    UnclaimedActuationError,
    UnsettledDuplicate,
    actuation_attempt_scope,
    execution_claim_scope,
    is_valid_idempotency_key,
)
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.routing_seal import generate_seal
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ExecutionClearance,
)
from src.gateway.server import governance_middleware as gm
from src.gateway.server import mcp_tool_server as mts
from src.gateway.server import workload_identity as wid
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CALLER = (
    "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
)
_KEY_1 = "11111111-1111-4111-8111-111111111111"
_KEY_2 = "22222222-2222-4222-8222-222222222222"


def _clearance(
    *,
    action: str = "governed_action",
    thread_id: str = _KEY_1,
) -> ExecutionClearance:
    return ExecutionClearance(
        thread_id=thread_id,
        decision="ALLOW",
        decision_path="DIRECT",
        action=action,
        target="target-1",
        operator_urn="urn:op:test",
        issued_at=0,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=thread_id,
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        required_quorum=0,
    )


def _receipt(outcome: ActuationOutcome) -> ActuationReceipt:
    return ActuationReceipt(
        accepted=outcome is ActuationOutcome.ACCEPTED,
        receipt_id="r-254" if outcome is ActuationOutcome.ACCEPTED else None,
        session_uuid=None,
        raw_receipt=None,
        findings=[]
        if outcome is ActuationOutcome.ACCEPTED
        else [{"code": outcome.value}],
        outcome=outcome,
    )


def _actuator(outcome: ActuationOutcome = ActuationOutcome.ACCEPTED) -> Any:
    return SimpleNamespace(
        actuator_id="claim_test_actuator",
        actuate=AsyncMock(return_value=_receipt(outcome)),
    )


@pytest.fixture(autouse=True)
def _hmac_seals(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.gateway.governance.jwks as jwks_mod
    import src.gateway.governance.kms_signer as ks

    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=None))
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)


@pytest.fixture
def ingest_stub(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    stub = AsyncMock(return_value="msg-254")
    monkeypatch.setattr(exec_act, "ingest_actuation_receipt", stub)
    return stub


@contextmanager
def _endpoint(tools: dict[str, Callable[..., Any]]) -> Iterator[MagicMock]:
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


async def _post(tool: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    response = await mts.execute_tool_endpoint(
        mts.ToolExecutionRequest(tool_name=tool, params=dict(params)),
        MagicMock(scope={}, headers={}),
    )
    if isinstance(response, dict):
        return 200, response
    return response.status_code, json.loads(response.body)


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


# ── (a)-(c) Kernel dispatch_actuation() claim gate & unforgeability ──────────


@pytest.mark.asyncio
async def test_dispatch_without_claim_fails_closed_before_actuate(
    ingest_stub: AsyncMock,
) -> None:
    """(a) Direct dispatch_actuation() without a kernel claim fails closed."""
    actuator = _actuator()
    with actuation_attempt_scope() as attempt:
        with pytest.raises(UnclaimedActuationError) as exc_info:
            await dispatch_actuation(actuator, _clearance())
        assert isinstance(exc_info.value, ActuationAttemptScopeError)
        assert attempt.dispatched is False
        assert attempt.may_have_executed is False
        assert attempt.status is ExecutionStatus.BLOCKED
    actuator.actuate.assert_not_awaited()
    ingest_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_second_dispatch_in_same_scope_fails_closed(
    ingest_stub: AsyncMock,
) -> None:
    """(b) Single-consumption guard: one claim admits at most one dispatch."""
    actuator = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    clr = _clearance()
    with actuation_attempt_scope() as attempt:
        claim = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
        assert isinstance(claim, Claim)
        first = await dispatch_actuation(actuator, clr)
        assert first.outcome is ActuationOutcome.ACCEPTED
        assert attempt.dispatched is True
        with pytest.raises(UnclaimedActuationError, match="already consumed"):
            await dispatch_actuation(actuator, clr)
    assert actuator.actuate.await_count == 1
    assert ingest_stub.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dispatch_action", "dispatch_thread"),
    [
        ("other_action", _KEY_1),
        ("governed_action", _KEY_2),
        ("other_action", _KEY_2),
    ],
    ids=["action-mismatch", "thread-id-mismatch", "both-mismatch"],
)
async def test_action_or_thread_id_mismatch_fails_closed(
    ingest_stub: AsyncMock, dispatch_action: str, dispatch_thread: str
) -> None:
    """(c) Bound claim must match both clearance.action and clearance.thread_id."""
    actuator = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    with actuation_attempt_scope() as attempt:
        claim = await ledger.claim("governed_action", SHARED_CALLER, _KEY_1)
        assert isinstance(claim, Claim)
        with pytest.raises(UnclaimedActuationError, match="bound claim is for"):
            await dispatch_actuation(
                actuator, _clearance(action=dispatch_action, thread_id=dispatch_thread)
            )
        assert attempt.dispatched is False
        assert attempt.status is ExecutionStatus.BLOCKED
    actuator.actuate.assert_not_awaited()
    ingest_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_released_claim_and_duplicate_result_never_authorize_dispatch(
    ingest_stub: AsyncMock,
) -> None:
    """Releasing a claim clears it; a Duplicate return never binds a claim."""
    actuator = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    clr = _clearance()

    with actuation_attempt_scope() as attempt:
        claim = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
        assert isinstance(claim, Claim)
        assert await ledger.release_unexecuted(claim) is True
        with pytest.raises(UnclaimedActuationError):
            await dispatch_actuation(actuator, clr)
        assert attempt.dispatched is False

    # First attempt holds the key in-flight outside this scope; second gets Duplicate.
    first_claim = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
    assert isinstance(first_claim, Claim)
    with actuation_attempt_scope() as attempt:
        dup = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
        assert isinstance(dup, Duplicate)
        with pytest.raises(UnclaimedActuationError):
            await dispatch_actuation(actuator, clr)
        assert attempt.dispatched is False
    actuator.actuate.assert_not_awaited()


def test_actuation_attempt_has_no_public_claim_setter() -> None:
    """Claim binding is private to ExecutionLedger.claim(); no public setter exists."""
    public_methods = [
        name
        for name in dir(ActuationAttempt)
        if not name.startswith("_") and callable(getattr(ActuationAttempt, name))
    ]
    assert public_methods == []
    attempt = ActuationAttempt()
    with pytest.raises(AttributeError):
        attempt.claim = Claim("k", "t")  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        attempt.set_claim(Claim("k", "t"))  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_nested_scope_claim_is_not_inherited_by_outer_scope(
    ingest_stub: AsyncMock,
) -> None:
    """Closing an inner scope folds dispatch state, never transferring the claim."""
    actuator = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    clr = _clearance()
    with actuation_attempt_scope() as outer:
        with actuation_attempt_scope():
            claim = await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
            assert isinstance(claim, Claim)
        with pytest.raises(UnclaimedActuationError):
            await dispatch_actuation(actuator, clr)
        assert outer.dispatched is False
    actuator.actuate.assert_not_awaited()


# ── (e) dry_run=True leaves _claim=None and fails closed on dispatch ─────────


@pytest.mark.asyncio
async def test_dry_run_leaves_claim_none_and_fails_closed_if_dispatched(
    ingest_stub: AsyncMock,
) -> None:
    """(e) dry_run=True claims nothing and refuses any accidental dispatch."""
    gov = trade_governor()
    gov.components.execution_ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    actuator = _actuator()
    clr = _clearance(action="execute_trade", thread_id=_KEY_1)

    async with execution_claim_scope(
        gov,
        action="execute_trade",
        idempotency_key=_KEY_1,
        params={"idempotency_key": _KEY_1},
        dry_run=True,
    ) as scope:
        assert scope.attempt._claim is None
        with pytest.raises(UnclaimedActuationError):
            await dispatch_actuation(actuator, clr)
        assert scope.attempt.dispatched is False
    actuator.actuate.assert_not_awaited()


# ── (f) Layer 1 is_valid_idempotency_key unit checks ─────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        str(uuid.uuid4()),
        str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:cage:tests:254")),
        str(uuid.uuid4()).upper(),
    ],
    ids=["uuid4", "uuid5", "uuid4-upper"],
)
def test_is_valid_idempotency_key_accepts_uuid4_and_uuid5(value: str) -> None:
    assert is_valid_idempotency_key(value) is True


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "not-a-uuid",
        str(uuid.uuid1()),
        str(uuid.uuid3(uuid.NAMESPACE_URL, "x")),
        uuid.uuid4().hex,
        f"{uuid.uuid4()}\n",
        uuid.uuid4(),
        12345,
        False,
    ],
    ids=[
        "none",
        "empty",
        "garbage",
        "uuid1",
        "uuid3",
        "hex-no-dashes",
        "trailing-newline",
        "uuid-object",
        "int",
        "bool",
    ],
)
def test_is_valid_idempotency_key_rejects_invalid_values(value: object) -> None:
    assert is_valid_idempotency_key(value) is False


def test_dose_order_requires_valid_idempotency_key() -> None:
    with pytest.raises(ValidationError):
        DoseOrder(patient_id="PT-1", medication="amoxicillin", dose_mg=250.0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="UUID v4 or v5"):
        DoseOrder(
            patient_id="PT-1",
            medication="amoxicillin",
            dose_mg=250.0,
            idempotency_key="not-a-uuid",
        )
    order = DoseOrder(
        patient_id="PT-1",
        medication="amoxicillin",
        dose_mg=250.0,
        idempotency_key=_KEY_1,
    )
    assert order.idempotency_key == _KEY_1


# ── (d) Healthcare P1 / P3 reproductions & full lifecycle (/tools/execute + MCP)


def _clinical_governor(
    redis: fakeredis.aioredis.FakeRedis | None = None,
) -> MagicMock:
    gov = MagicMock()
    gov.settle = AsyncMock(return_value=[])
    gov.components = SimpleNamespace(execution_ledger=ExecutionLedger(redis))
    return gov


async def _seal_clinical(
    _gov: Any, action: str, params: dict[str, Any]
) -> SealedAction:
    seal = await generate_seal(action, params, record_hash="e" * 64)
    return SealedAction(action, seal, dict(params))


@pytest.mark.asyncio
async def test_healthcare_p1_retry_after_accepted_never_double_doses(
    ingest_stub: AsyncMock,
) -> None:
    """(d) P1 reproduction on /tools/execute + MCP: second call replays without actuating."""
    assay = SimulatedSerumAssayProvider()
    actuator = ClinicalDoseActuator(ledger=assay)
    actuate_spy = AsyncMock(wraps=actuator.actuate)
    actuator.actuate = actuate_spy  # type: ignore[method-assign]
    gov = _clinical_governor(fakeredis.aioredis.FakeRedis())
    enforce = AsyncMock(side_effect=_seal_clinical)
    refusals = AsyncMock(return_value="ph-dup-p1")
    dose_req = {
        "patient_id": "PT-0042",
        "medication": "amoxicillin",
        "dose_mg": 2.5,
        "idempotency_key": _KEY_1.upper(),
        "confidence": 0.99,
    }

    with (
        patch.object(clinical_tools, "enforce_governance", enforce),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
        patch.object(gm, "record_refusal", refusals),
    ):
        tool = _registered(ClinicalToolProvider(), gov, "administer_dose")
        with _endpoint({"administer_dose": tool}):
            code1, body1 = await _post("administer_dose", dose_req)
            # Retry with lowercase key (must collide on the exact same ledger key)
            code2, body2 = await _post(
                "administer_dose", {**dose_req, "idempotency_key": _KEY_1}
            )
        # Third retry over FastMCP surface also replays without actuating.
        mcp_server = FastMCP("p1-mcp")
        ClinicalToolProvider().register_tools(mcp_server, gov)
        mcp_res = await mcp_server.call_tool(
            "administer_dose", {**dose_req, "idempotency_key": _KEY_1}
        )

    assert (code1, code2) == (200, 200)
    assert body1["status"] == "SUCCESS"
    assert body1["outcome"]["status"] == "EXECUTED"
    assert body1["may_have_executed"] is True
    assert body2["status"] == "SUCCESS"
    assert body2["outcome"]["status"] == "EXECUTED"
    assert body2["may_have_executed"] is True
    assert body2["output"] == body1["output"]
    assert (
        CommitOutcome.from_wire(mcp_res.structuredContent).status
        is CommitStatus.EXECUTED
    )
    assert actuate_spy.await_count == 1
    assert enforce.await_count == 1
    assert gov.settle.await_count == 1
    assert gov.settle.await_args.kwargs["executed"] is True
    # Serum assay advanced exactly once: 15.0 -> 12.5 (never 10.0).
    assert assay.fetch_snapshot_sync().scalar == pytest.approx(12.5)
    # Both replays recorded AC-3 duplicate refusals.
    assert refusals.await_count == 2
    assert refusals.await_args.kwargs["oscal_control_ref"] == "AC-3"


@pytest.mark.asyncio
async def test_healthcare_p3_retry_after_unknown_blocks_via_unsettled_duplicate(
    ingest_stub: AsyncMock,
) -> None:
    """(d) P3 reproduction: UNKNOWN assay timeout locks out retries on /tools/execute and MCP."""
    assay = SimulatedSerumAssayProvider()
    calls = 0

    class _TimeoutAfterDebit:
        def record_debit(self, amount: float, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            assay.record_debit(amount, **kwargs)
            raise RuntimeError("assay journal ack timeout after write")

    actuator = ClinicalDoseActuator(ledger=_TimeoutAfterDebit())
    actuate_spy = AsyncMock(wraps=actuator.actuate)
    actuator.actuate = actuate_spy  # type: ignore[method-assign]
    gov = _clinical_governor(fakeredis.aioredis.FakeRedis())
    enforce = AsyncMock(side_effect=_seal_clinical)
    dose_req = {
        "patient_id": "PT-0042",
        "medication": "amoxicillin",
        "dose_mg": 2.5,
        "idempotency_key": _KEY_1,
        "confidence": 0.99,
    }

    with (
        patch.object(clinical_tools, "enforce_governance", enforce),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
    ):
        tool = _registered(ClinicalToolProvider(), gov, "administer_dose")
        with _endpoint({"administer_dose": tool}) as refused_metric:
            code1, body1 = await _post("administer_dose", dose_req)
            code2, body2 = await _post("administer_dose", dose_req)
            # Even passing a deferred_id cannot reclaim an UNKNOWN key.
            code3, body3 = await _post(
                "administer_dose", {**dose_req, "deferred_id": "defer-1"}
            )
        # Direct/MCP call also raises UnsettledDuplicate.
        with pytest.raises(UnsettledDuplicate, match="^UNKNOWN:"):
            await administer_dose_action(**dose_req, governor=gov)

    assert code1 == 200
    assert body1["status"] == "ERROR"
    assert body1["may_have_executed"] is True
    assert body1["actuation_outcome"] == "UNKNOWN"
    assert body1["outcome"]["status"] == "INDETERMINATE"
    assert (
        CommitOutcome.from_wire(body1["outcome"]).status is CommitStatus.INDETERMINATE
    )
    assert (code2, code3) == (200, 200)
    assert body2["status"] == "ERROR"
    assert body2["may_have_executed"] is True
    assert body2["actuation_outcome"] == "UNKNOWN"
    assert body2["outcome"]["status"] == "UNSETTLED_DUPLICATE"
    assert body3["outcome"]["status"] == "UNSETTLED_DUPLICATE"
    refused_metric.assert_not_called()
    assert actuate_spy.await_count == 1
    assert calls == 1
    assert assay.fetch_snapshot_sync().scalar == pytest.approx(12.5)
    assert gov.settle.await_count == 1
    assert gov.settle.await_args.kwargs["executed"] is True


@pytest.mark.asyncio
async def test_healthcare_blocked_replay_and_deferred_approval_takeover(
    ingest_stub: AsyncMock,
) -> None:
    """BLOCKED key replays without re-governing; verified deferred_id reclaims and executes once."""
    assay = SimulatedSerumAssayProvider()
    actuator = ClinicalDoseActuator(ledger=assay)
    actuate_spy = AsyncMock(wraps=actuator.actuate)
    actuator.actuate = actuate_spy  # type: ignore[method-assign]
    gov = _clinical_governor(fakeredis.aioredis.FakeRedis())
    enforce_deny = AsyncMock(side_effect=PermissionError("Governance Blocked: HITL"))

    async def _approve(
        _g: Any, act: str, p: dict[str, Any], **_kw: Any
    ) -> SealedAction:
        return await _seal_clinical(_g, act, p)

    enforce_approved = AsyncMock(side_effect=_approve)
    refusals = AsyncMock(return_value="ph-blocked")
    dose = {
        "patient_id": "PT-0042",
        "medication": "amoxicillin",
        "dose_mg": 2.5,
        "idempotency_key": _KEY_1,
    }

    with (
        patch.object(clinical_tools, "enforce_governance", enforce_deny),
        patch.object(gm, "enforce_approved_governance", enforce_approved),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
        patch.object(gm, "record_refusal", refusals),
    ):
        first = await administer_dose_action(**dose, governor=gov)
        replayed = await administer_dose_action(**dose, governor=gov)
        approved = await administer_dose_action(
            **dose, deferred_id="defer-hc-1", governor=gov
        )
        after_exec = await administer_dose_action(
            **dose, deferred_id="defer-hc-2", governor=gov
        )

    assert first.status is CommitStatus.REFUSED
    assert replayed.status is CommitStatus.REFUSED
    assert replayed.message == first.message
    assert approved.status is CommitStatus.EXECUTED
    assert after_exec.status is CommitStatus.EXECUTED
    assert after_exec.message == approved.message
    assert enforce_deny.await_count == 1
    assert enforce_approved.await_count == 1
    assert actuate_spy.await_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("connected_evidence_sink")
@pytest.mark.covers(
    'src.gateway.governance.execution_idempotency:execution_claim_scope#infra_dependency="execution_ledger"',
    "src.gateway.governance.execution_idempotency:_settle_claim_on_error#await ledger.release_unexecuted(claim)",
    "src.gateway.governance.execution_idempotency:ExecutionLedger.claim#no Redis is configured for the execution ledger",
)
async def test_healthcare_invalid_key_pre_dispatch_outage_release_and_ledger_outage(
    monkeypatch: pytest.MonkeyPatch, ingest_stub: AsyncMock
) -> None:
    """Invalid key refuses (AC-3); pre-dispatch outage releases key; ledger outage -> 503."""
    gov = _clinical_governor(fakeredis.aioredis.FakeRedis())
    refusals = AsyncMock(return_value="ph-invalid")
    enforce = AsyncMock(side_effect=_seal_clinical)
    actuator = ClinicalDoseActuator(ledger=SimulatedSerumAssayProvider())

    with (
        patch.object(clinical_tools, "enforce_governance", enforce),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
        patch.object(gm, "record_refusal", refusals),
    ):
        bad = await administer_dose_action(
            "PT-1", "amoxicillin", 2.0, "not-a-uuid", governor=gov
        )
    assert bad.status is CommitStatus.REFUSED
    assert "invalid idempotency_key" in bad.message
    enforce.assert_not_awaited()
    refusals.assert_awaited_once()

    # Pre-dispatch infrastructure outage propagates (503) and releases key so retry succeeds.
    infra = GovernanceInfrastructureError(
        "OPA unreachable",
        dependency="opa",
        failure_code="OPA_UNAVAILABLE",
        error_code="policy_engine_unavailable",
    )
    with (
        patch.object(
            clinical_tools, "enforce_governance", AsyncMock(side_effect=infra)
        ),
        patch.object(gm, "record_refusal", AsyncMock()),
        pytest.raises(GovernanceInfrastructureError) as exc_info,
    ):
        await administer_dose_action("PT-1", "amoxicillin", 2.0, _KEY_2, governor=gov)
    assert exc_info.value.failure_code == "OPA_UNAVAILABLE"

    with (
        patch.object(clinical_tools, "enforce_governance", enforce),
        patch.object(
            clinical_tools, "verify_and_consume_seal", AsyncMock(return_value=None)
        ),
        patch.object(
            clinical_tools,
            "get_actuator_registry",
            return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
        ),
    ):
        recovered = await administer_dose_action(
            "PT-1", "amoxicillin", 2.0, _KEY_2, governor=gov
        )
    assert recovered.status is CommitStatus.EXECUTED

    # Enforcing posture without Redis -> ExecutionLedgerUnavailable -> 503 on /tools/execute.
    monkeypatch.setenv("CAGE_ENV", "production")
    enforcing_gov = _clinical_governor(None)
    tool = _registered(ClinicalToolProvider(), enforcing_gov, "administer_dose")
    with _endpoint({"administer_dose": tool}):
        code, body = await _post(
            "administer_dose",
            {
                "patient_id": "PT-1",
                "medication": "amoxicillin",
                "dose_mg": 2.0,
                "idempotency_key": _KEY_1,
            },
        )
    assert code == 503
    assert body["error"] == "execution_ledger_unavailable"
    assert body["failure_code"] == "EXECUTION_LEDGER_UNAVAILABLE"


def test_domain_tools_hold_zero_private_execution_ledger_orchestration() -> None:
    """Closure Criterion 2: neither finance nor healthcare calls ExecutionLedger directly."""
    repo_root = Path(__file__).resolve().parents[2]
    forbidden_attrs = {
        "claim",
        "record_outcome",
        "release_unexecuted",
        "execution_ledger",
    }
    for rel in (
        "src/cage_finance/tools/tool_provider.py",
        "src/cage_healthcare/tools/tool_provider.py",
    ):
        tree = ast.parse((repo_root / rel).read_text(encoding="utf-8"), filename=rel)
        found = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in forbidden_attrs
        }
        assert not found, f"{rel} still holds private ledger orchestration: {found}"


def test_legacy_finance_id_validator_and_private_duplicate_handler_removed() -> None:
    """Clean break: legacy domain-scoped validator and duplicate handler are removed."""
    import src.cage_finance.models.trade_order as trade_order_mod

    legacy_validator = "is_valid_" + "transaction_id"
    assert not hasattr(trade_order_mod, legacy_validator)
    assert not hasattr(finance_tools, "_refuse_duplicate")


# ── (g) Dedicated mutation checks with inverted pass/fail verification ───────

Edit = tuple[str, str]
Probe = Callable[[], Awaitable[bool]]


def _compile_mutant(module: ModuleType, name: str, edits: tuple[Edit, ...]) -> Any:
    func = getattr(module, name)
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
    code = compile(
        "\n" * (first_line + start - 1) + source,
        inspect.getsourcefile(func) or f"<mutant {name}>",
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    namespace: dict[str, Any] = {}
    exec(code, module.__dict__, namespace)  # noqa: S102
    return namespace[name]


async def _probe_unclaimed_dispatch_refused() -> bool:
    """Invariant: unclaimed dispatch_actuation() raises UnclaimedActuationError, never actuates, leaves dispatched=False."""
    act = _actuator()
    with (
        patch.object(exec_act, "ingest_actuation_receipt", AsyncMock(return_value="m")),
        actuation_attempt_scope() as attempt,
    ):
        try:
            await exec_act.dispatch_actuation(act, _clearance())
        except UnclaimedActuationError:
            return act.actuate.await_count == 0 and attempt.dispatched is False
    return False


async def _probe_double_dispatch_refused() -> bool:
    """Invariant: second dispatch_actuation() on one claim fails closed before actuate()."""
    act = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    clr = _clearance()
    with (
        patch.object(exec_act, "ingest_actuation_receipt", AsyncMock(return_value="m")),
        actuation_attempt_scope(),
    ):
        await ledger.claim(clr.action, SHARED_CALLER, clr.thread_id)
        await exec_act.dispatch_actuation(act, clr)
        try:
            await exec_act.dispatch_actuation(act, clr)
        except UnclaimedActuationError:
            return act.actuate.await_count == 1
    return False


async def _probe_mismatched_key_refused() -> bool:
    """Invariant: clearance with wrong action or thread_id is refused before actuate()."""
    act = _actuator()
    ledger = ExecutionLedger(fakeredis.aioredis.FakeRedis())
    with (
        patch.object(exec_act, "ingest_actuation_receipt", AsyncMock(return_value="m")),
        actuation_attempt_scope() as attempt,
    ):
        await ledger.claim("governed_action", SHARED_CALLER, _KEY_1)
        try:
            await exec_act.dispatch_actuation(
                act, _clearance(action="governed_action", thread_id=_KEY_2)
            )
        except UnclaimedActuationError:
            return act.actuate.await_count == 0 and attempt.dispatched is False
    return False


_CLAIM_MUTANTS: list[tuple[str, str, str, tuple[Edit, ...], Probe]] = [
    (
        "KC-M1: remove absent-claim guard in mark_dispatch",
        "src.gateway.governance.execution_idempotency",
        "mark_dispatch",
        (
            (
                "    if not isinstance(attempt._claim, Claim):\n",
                "    if False:\n",
            ),
            (
                "    if (\n"
                "        attempt._claimed_action != action\n"
                "        or attempt._claimed_idempotency_key != idempotency_key\n"
                "    ):\n",
                "    if False:\n",
            ),
        ),
        _probe_unclaimed_dispatch_refused,
    ),
    (
        "KC-M2: remove single-consumption guard in mark_dispatch",
        "src.gateway.governance.execution_idempotency",
        "mark_dispatch",
        (
            (
                "    if attempt._claim_consumed:\n",
                "    if False:\n",
            ),
        ),
        _probe_double_dispatch_refused,
    ),
    (
        "KC-M3: remove (action, idempotency_key) binding check in mark_dispatch",
        "src.gateway.governance.execution_idempotency",
        "mark_dispatch",
        (
            (
                "    if (\n"
                "        attempt._claimed_action != action\n"
                "        or attempt._claimed_idempotency_key != idempotency_key\n"
                "    ):\n",
                "    if False:\n",
            ),
        ),
        _probe_mismatched_key_refused,
    ),
    (
        "KC-M4: flip attempt._dispatched = True before verifying claim",
        "src.gateway.governance.execution_idempotency",
        "mark_dispatch",
        (
            (
                "    if not isinstance(attempt._claim, Claim):\n",
                "    attempt._dispatched = True\n"
                "    if not isinstance(attempt._claim, Claim):\n",
            ),
        ),
        _probe_unclaimed_dispatch_refused,
    ),
    (
        "KC-M5: move mark_dispatch after actuator.actuate in dispatch_actuation",
        "src.gateway.governance.execution_actuator",
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
        _probe_unclaimed_dispatch_refused,
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mid", "module_name", "func_name", "edits", "probe"),
    _CLAIM_MUTANTS,
    ids=[m[0].split(":")[0] for m in _CLAIM_MUTANTS],
)
async def test_kernel_claim_mutant_is_killed_with_inverted_verification(
    monkeypatch: pytest.MonkeyPatch,
    mid: str,
    module_name: str,
    func_name: str,
    edits: tuple[Edit, ...],
    probe: Probe,
) -> None:
    """Inverted pass/fail verification: original MUST pass probe (True); mutant MUST fail (False)."""
    module = importlib.import_module(module_name)
    assert await probe() is True, f"{mid}: invariant probe failed on unmutated code"
    monkeypatch.setattr(module, func_name, _compile_mutant(module, func_name, edits))
    assert await probe() is False, f"{mid} survived!"


def test_claim_mutation_set_covers_kc_m1_to_kc_m5() -> None:
    assert [m[0].split(":")[0] for m in _CLAIM_MUTANTS] == [
        f"KC-M{i}" for i in range(1, 6)
    ]
