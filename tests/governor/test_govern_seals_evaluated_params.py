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

"""Committing runs seal, evidence and return the params their stages evaluated.

A committing run binds the action's server inputs (for example the trader's
role, or a live quote age) into a snapshot of the caller's params exactly
once. The defect covered here: committing runs sealed and evidenced the
caller's pre-binding params instead of the params the stages evaluated.
These tests pin the contract that replaced it:

* ``govern()`` and ``revalidate_post_hitl()`` return a ``SealedAction`` whose
  ``params`` are the evaluated params. The seal commits to them and verifies
  against them, never against the caller's dict.
* Refusal receipts, deferral snapshots, the approval's coverage check and its
  spend name the evaluated params (the snapshot only when binding failed).
* A post-approval redemption binds once, inside the committing run; its
  pre-check reads token state only.
* The finance trade tool verifies and actuates exactly the sealed params, so
  a measurement that changes between lookups cannot split them.
* The dry-run verdict carries the audit hash of the evaluated params for the
  envelope's ``subject.evaluated_action_hash``.
* Every fail-closed path the change added refuses without sealing or spending.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import ANY, AsyncMock, MagicMock

import fakeredis
import fakeredis.aioredis
import pytest

import src.gateway.governance.routing_seal as rs
from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_CONFIDENCE_NORM_ID,
    TradeConfidenceTier,
)
from src.cage_finance.tools import tool_provider as tool_provider_module
from src.cage_finance.tools.tool_provider import (
    _approval_covers_trade,
    execute_trade_action,
)
from src.gateway.governance import defer_queue as defer_queue_module
from src.gateway.governance.commit_outcome import (
    ApprovalRedemptionRefusal,
    CommitStatus,
)
from src.gateway.governance.contracts import (
    NormBinding,
    ReadOnlyTier,
    ServerInputUnavailableError,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import DeferQueue, Redemption
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.governance_envelope import (
    GovernanceEnvelopeBuilder,
    envelope_action_hash,
)
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor import verdicts as verdicts_module
from src.gateway.governance.governor.approval import PostHitlApproval
from src.gateway.governance.governor.errors import (
    GovernanceDeferred,
    GovernanceError,
    GovernanceInfrastructureError,
)
from src.gateway.governance.governor.governor import (
    APPROVAL_NOT_REDEEMABLE,
    SymbolicGovernor,
)
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.stages.opa import OpaStage
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.refusal_projection import (
    REFUSAL_ENVELOPE_EXCLUDED_KEYS,
    compute_refusal_params_hash,
)
from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    compute_action_hash,
    verify_seal,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
)
from src.gateway.governance.warrant import WarrantCache
from src.gateway.server import governance_middleware as gm
from tests.fixtures.approval import SpendCounter, granted_approval
from tests.fixtures.governor import (
    WARRANT_TEST_GOVERNING_VERSION,
    WARRANT_TEST_NOW,
    StaticWarrantSource,
    allow_opa,
    issue_test_warrant,
    make_governor,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

ACTION = "execute_trade"
#: The value the caller claims for the server-owned ``trader_role``.
SPOOFED_ROLE = "admin"
#: The value the server binds for the verified caller.
BOUND_ROLE = "junior"
DEFER_ID = "defer-approved-1"


def _caller_params(**overrides: Any) -> dict[str, Any]:
    """The caller's request; it claims a ``trader_role`` the server owns."""
    return {
        "symbol": "AAPL",
        "amount": 100.0,
        "currency": "USD",
        "side": "buy",
        "confidence": 0.99,
        "trader_role": SPOOFED_ROLE,
        **overrides,
    }


def _evaluated(params: Mapping[str, Any], role: str = BOUND_ROLE) -> dict[str, Any]:
    """``params`` as the stages evaluate them: ``trader_role`` bound server-side."""
    return {**params, "trader_role": role}


def _approved() -> dict[str, Any]:
    """The params a reviewer approved: the request as evaluated at approval time."""
    return _evaluated(_caller_params())


def _stripped(params: Mapping[str, Any]) -> dict[str, Any]:
    """``params`` as ``build_refusal_receipt`` scopes them for ``params_hash``."""
    return {k: v for k, v in params.items() if k not in REFUSAL_ENVELOPE_EXCLUDED_KEYS}


def _refusal_hash(params: Mapping[str, Any]) -> str:
    return compute_refusal_params_hash(ACTION, _stripped(params))


def _carries(value: Any, needle: str) -> bool:
    """True iff ``needle`` is a string leaf anywhere inside ``value``."""
    if isinstance(value, str):
        return value == needle
    if isinstance(value, Mapping):
        return any(_carries(v, needle) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_carries(v, needle) for v in value)
    return False


class _RoleResolver:
    """A domain ``ServerInputResolver``: the trader's role is bound server-side."""

    owned_keys: frozenset[str] = frozenset({"trader_role"})

    def __init__(self, role: str = BOUND_ROLE) -> None:
        self.role = role
        self.calls: list[dict[str, Any]] = []

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append(dict(params))
        return {"trader_role": self.role}


class _UnavailableResolver(_RoleResolver):
    """The trader directory is unreachable: no evaluated params can exist."""

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls.append(dict(params))
        raise ServerInputUnavailableError(
            "trader directory unreachable",
            dependency="trader_directory",
            failure_code="TRADER_DIRECTORY_UNAVAILABLE",
            error_code="trader_directory_unavailable",
        )


class _DriftingTelemetry:
    """A trade resolver whose measurement differs on every lookup (a quote age)."""

    owned_keys: frozenset[str] = frozenset({"latency_ms", "trader_role"})

    def __init__(self) -> None:
        self.calls = 0

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        return {"latency_ms": 10.0 + self.calls, "trader_role": BOUND_ROLE}


class _RecordingTier(ReadOnlyTier):
    """A read-only tier claiming ``ACTION`` that records the params it evaluated.

    ``refuse`` makes it report one HARD finding; ``revalidated`` makes the
    post-approval (POST_HITL) run re-run it.
    """

    def __init__(self, *, refuse: bool = False, revalidated: bool = False) -> None:
        self._refuse = refuse
        self._revalidated = revalidated
        self.seen: list[dict[str, Any]] = []

    @property
    def tier_name(self) -> str:
        return "recording_tier"

    @property
    def order(self) -> int:
        return 0

    @property
    def revalidated_after_approval(self) -> bool:
        return self._revalidated

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == ACTION

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.seen.append(copy.deepcopy(params))
        if not self._refuse:
            return []
        return [
            Violation(
                tier=self.tier_name,
                code="RECORDING_TIER_REFUSAL",
                message="the recording tier refuses this request",
                kind=ViolationKind.HARD,
            )
        ]


def _governor(resolver: Any, tier: _RecordingTier) -> SymbolicGovernor:
    """A governor whose only stage is ``tier``; ``resolver`` binds ``ACTION``."""
    return make_governor(
        core_stages=order_stages([tier]), server_inputs={ACTION: resolver}
    )


def _warrant_ineligible_governor(resolver: Any) -> SymbolicGovernor:
    """A committing run that defers: the trade-confidence norm's warrant is revoked."""
    binding = NormBinding(
        norm_id=TRADE_CONFIDENCE_NORM_ID,
        value=0.97,
        requires_warrant=True,
        actions=frozenset({ACTION}),
        governing_version=WARRANT_TEST_GOVERNING_VERSION,
    )
    revoked = issue_test_warrant(status="REVOKED", revocation_ref="REV-TEST")
    cache = WarrantCache(
        StaticWarrantSource({TRADE_CONFIDENCE_NORM_ID: revoked}),
        monotonic=lambda: 0.0,
        wall_clock=lambda: WARRANT_TEST_NOW,
    )
    warrant = WarrantStage(
        [binding], cache, jurisdiction="EU_ECB", clock=lambda: WARRANT_TEST_NOW
    )
    opa = allow_opa()
    return make_governor(
        opa=opa,
        core_stages=(OpaStage(opa), warrant),
        domain_tiers=(TradeConfidenceTier(binding),),
        server_inputs={ACTION: resolver},
    )


class _ApprovalQueue:
    """``DeferQueue`` stand-in holding one quorum-approved ``HITL_REQUIRED`` token.

    ``check_redemption`` checks token state only (no ``covers`` parameter);
    ``consume_redemption`` applies ``covers`` to the approved params and spends
    the token at most once, like the queue's compare-and-swap. Each answers a
    ``Redemption`` naming the typed refusal whenever no token is returned.
    ``stale_state_check`` lets a replay slip past the state check, as a
    concurrent redemption can. ``probe`` is sampled at every state check.
    """

    def __init__(
        self,
        approved: Mapping[str, Any],
        *,
        probe: Callable[[], Any] | None = None,
    ) -> None:
        self.token = SimpleNamespace(
            defer_id=DEFER_ID,
            opa_input_snapshot={"action": ACTION, "params": copy.deepcopy(approved)},
            barrier_preview=None,
            thread_id="thread-approval",
            hitl_holds=frozenset(),
        )
        self.probe = probe
        self.probes: list[Any] = []
        self.state_checks: list[tuple[str, str]] = []
        self.consume_calls: list[bool] = []
        self.consuming = False
        self.consumed = False
        self.stale_state_check = False

    def _approved_params(self) -> dict[str, Any]:
        return copy.deepcopy(self.token.opa_input_snapshot["params"])

    def _state_refusal(
        self, defer_id: str, action: str, *, honor_stale: bool
    ) -> ApprovalRedemptionRefusal | None:
        if defer_id != DEFER_ID:
            return ApprovalRedemptionRefusal.UNKNOWN_OR_EXPIRED
        if action != ACTION:
            return ApprovalRedemptionRefusal.ACTION_MISMATCH
        if self.consumed and not (honor_stale and self.stale_state_check):
            return ApprovalRedemptionRefusal.CONSUMED
        return None

    async def check_redemption(
        self,
        defer_id: str,
        *,
        action: str,
    ) -> Redemption:
        self.state_checks.append((defer_id, action))
        if self.probe is not None:
            self.probes.append(self.probe())
        refusal = self._state_refusal(defer_id, action, honor_stale=True)
        if refusal is not None:
            return Redemption(None, refusal)
        return Redemption(self.token, None)

    async def consume_redemption(
        self,
        defer_id: str,
        *,
        action: str,
        covers: Callable[[dict[str, Any]], bool],
    ) -> Redemption:
        self.consuming = True
        try:
            covered = bool(covers(self._approved_params()))
        finally:
            self.consuming = False
        self.consume_calls.append(covered)
        refusal = self._state_refusal(defer_id, action, honor_stale=False)
        if refusal is None and not covered:
            refusal = ApprovalRedemptionRefusal.PARAMS_NOT_COVERED
        if refusal is not None:
            return Redemption(None, refusal)
        self.consumed = True
        return Redemption(self.token, None)


def _serve(monkeypatch: pytest.MonkeyPatch, queue: _ApprovalQueue) -> AsyncMock:
    """Make ``queue`` the gateway's DeferQueue; capture middleware refusal receipts."""

    @asynccontextmanager
    async def _open() -> AsyncIterator[_ApprovalQueue]:
        yield queue

    monkeypatch.setattr(defer_queue_module, "open_defer_queue", _open)
    emitted = AsyncMock(return_value=None)
    monkeypatch.setattr(gm, "_emit_refusal_receipt", emitted)
    return emitted


def _record_spends(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record the evaluated params each gateway-built approval's ``spend`` gets."""
    spent: list[dict[str, Any]] = []
    build = gm.PostHitlApproval

    def _recording(**fields: Any) -> PostHitlApproval:
        inner = fields["spend"]

        async def _spend(evaluated: Mapping[str, Any]) -> bool:
            spent.append(copy.deepcopy(dict(evaluated)))
            return bool(await inner(evaluated))

        return build(**{**fields, "spend": _spend})

    monkeypatch.setattr(gm, "PostHitlApproval", _recording)
    return spent


async def _redeem(
    governor: SymbolicGovernor,
    params: dict[str, Any] | None = None,
    *,
    covers: Callable[[dict[str, Any], dict[str, Any]], bool] = _approval_covers_trade,
) -> SealedAction:
    """The post-approval committing run, as the trade tool starts it."""
    return await gm.enforce_approved_governance(
        governor,
        ACTION,
        _caller_params() if params is None else params,
        deferred_id=DEFER_ID,
        approval_covers=covers,
    )


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture
def seal_mock(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stand in for seal minting; records the params every seal would commit to."""
    mock = AsyncMock(return_value="sealed")
    monkeypatch.setattr(sealing_module, "issue_seal", mock)
    return mock


@pytest.fixture
def refusals(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Capture refusal receipts instead of hash-chaining them."""
    mock = AsyncMock()
    monkeypatch.setattr(verdicts_module, "publish_refusal", mock)
    return mock


@pytest.fixture
def infra_blocks(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Capture INFRASTRUCTURE_BLOCK records instead of hash-chaining them."""
    mock = AsyncMock()
    monkeypatch.setattr(verdicts_module, "publish_infrastructure_block", mock)
    return mock


@pytest.fixture
def parked(monkeypatch: pytest.MonkeyPatch) -> DeferQueue:
    """Route deferral parking to an in-memory queue."""
    queue = DeferQueue(fakeredis.aioredis.FakeRedis(decode_responses=True))

    @asynccontextmanager
    async def _open() -> AsyncIterator[DeferQueue]:
        yield queue

    monkeypatch.setattr(defer_queue_module, "open_defer_queue", _open)
    return queue


@pytest.fixture
async def real_seals(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[SimpleNamespace]:
    """Real HMAC seals over a hash-chained evidence sink and seal index (fakeredis)."""
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_EVIDENCE_BINDING", raising=False)

    sink = EvidenceStreamSink(
        redis_url="redis://localhost:6379", stream_key="cage:test:evaluated-params"
    )
    sink._redis = fakeredis.aioredis.FakeRedis(
        server=fakeredis.FakeServer(), decode_responses=True
    )
    sink._running = True
    index = fakeredis.aioredis.FakeRedis(server=fakeredis.FakeServer())

    async def _resolve(_client: Any) -> Any:
        return index

    monkeypatch.setattr(rs.es, "is_evidence_chain_blocking", lambda: True)
    monkeypatch.setattr(rs.es, "get_evidence_sink", lambda: sink)
    monkeypatch.setattr(rs, "_resolve_redis", _resolve)
    try:
        yield SimpleNamespace(sink=sink, index=index)
    finally:
        await sink.stop()


# -- govern(): the seal, the stages and the result share one binding ---------


async def test_govern_seals_the_server_bound_params_not_the_callers(
    seal_mock: AsyncMock,
) -> None:
    resolver = _RoleResolver()
    tier = _RecordingTier()
    raw = _caller_params()
    expected = _evaluated(raw)

    sealed = await _governor(resolver, tier).govern(ACTION, raw)

    seal_mock.assert_awaited_once_with(
        ACTION, expected, path="govern", reliance=(), decision_context=ANY
    )
    assert isinstance(sealed, SealedAction)
    assert (sealed.action, sealed.seal) == (ACTION, "sealed")
    assert sealed.params == expected
    assert sealed.params["trader_role"] == BOUND_ROLE
    assert tier.seen == [expected]
    # The resolver is asked without the caller's value, which reaches nothing.
    assert resolver.calls == [{k: v for k, v in raw.items() if k != "trader_role"}]
    assert not _carries(
        (seal_mock.await_args.args, seal_mock.await_args.kwargs), SPOOFED_ROLE
    )
    assert not _carries(sealed.params, SPOOFED_ROLE)
    assert not _carries(tier.seen, SPOOFED_ROLE)
    assert raw["trader_role"] == SPOOFED_ROLE  # the caller's dict is untouched


async def test_real_seal_verifies_against_evaluated_params_only(
    real_seals: SimpleNamespace,
) -> None:
    raw = _caller_params()

    governed = await _governor(_RoleResolver(), _RecordingTier()).govern(ACTION, raw)

    assert governed.params == _evaluated(raw)
    assert verify_seal(governed.seal, ACTION, governed.params) is True
    with pytest.raises(SymbolicGovernorViolation):
        verify_seal(governed.seal, ACTION, raw)
    # The single-use consume refuses the caller's params without burning the
    # nonce, then admits the evaluated params.
    with pytest.raises(SymbolicGovernorViolation):
        await rs.verify_and_consume_seal(
            governed.seal, ACTION, raw, redis_client=real_seals.index
        )
    assert await rs.verify_and_consume_seal(
        governed.seal, ACTION, governed.params, redis_client=real_seals.index
    )


async def test_govern_refusal_receipt_hashes_the_evaluated_params(
    seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    tier = _RecordingTier(refuse=True)
    raw = _caller_params(transaction_id=str(uuid.uuid4()))
    expected = _evaluated(raw)

    with pytest.raises(GovernanceError) as exc_info:
        await _governor(_RoleResolver(), tier).govern(ACTION, raw)

    assert type(exc_info.value) is GovernanceError
    receipt = exc_info.value.receipt
    assert receipt is not None
    refusals.assert_awaited_once_with(receipt)
    assert receipt.params_hash == _refusal_hash(expected)
    assert receipt.params_hash != _refusal_hash(raw)
    assert receipt.attempted_params == _stripped(expected)
    assert not _carries(receipt.attempted_params, SPOOFED_ROLE)
    assert tier.seen == [expected]
    seal_mock.assert_not_awaited()


async def test_govern_deferral_parks_the_evaluated_params(
    parked: DeferQueue,
    seal_mock: AsyncMock,
    refusals: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deferrals = AsyncMock()
    monkeypatch.setattr(verdicts_module, "publish_deferral", deferrals)
    raw = _caller_params()
    expected = _evaluated(raw)

    with pytest.raises(GovernanceDeferred) as exc_info:
        await _warrant_ineligible_governor(_RoleResolver()).govern(ACTION, raw)

    token = await parked.get(exc_info.value.deferred_id)
    assert token is not None
    assert token.opa_input_snapshot["params"] == expected
    assert token.opa_input_snapshot["metadata"]["params"] == expected
    assert not _carries(token.opa_input_snapshot, SPOOFED_ROLE)
    deferrals.assert_awaited_once()
    (published,) = deferrals.await_args.args
    assert published.opa_input_snapshot["params"] == expected
    seal_mock.assert_not_awaited()
    refusals.assert_not_awaited()


# -- revalidate_post_hitl(): coverage, spend and seal name the same params ---


async def test_revalidate_post_hitl_seals_and_spends_the_evaluated_params(
    seal_mock: AsyncMock,
) -> None:
    resolver = _RoleResolver()
    tier = _RecordingTier(revalidated=True)
    counter = SpendCounter()
    raw = _caller_params()
    expected = _evaluated(raw)

    sealed = await _governor(resolver, tier).revalidate_post_hitl(
        ACTION, raw, approval=granted_approval(counter=counter)
    )

    seal_mock.assert_awaited_once_with(
        ACTION,
        expected,
        path="revalidate_post_hitl",
        reliance=(),
        decision_context=ANY,
    )
    assert isinstance(sealed, SealedAction)
    assert sealed.params == expected
    assert sealed.params["trader_role"] == BOUND_ROLE
    # Covered before any stage ran, and spent, against exactly what was sealed.
    assert counter.covered == [sealed.params]
    assert counter.params == [sealed.params]
    assert counter.results == [True]
    assert tier.seen == [sealed.params]
    assert len(resolver.calls) == 1
    assert not _carries(seal_mock.await_args.args, SPOOFED_ROLE)


# -- The finance trade tool verifies and actuates the sealed params ----------


async def test_trade_with_drifting_telemetry_seals_verifies_and_actuates_one_param_set(
    real_seals: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A measurement that differs between lookups cannot split the params sealed
    from the params verified and actuated: the kernel looks it up once."""
    telemetry = _DriftingTelemetry()
    governor = make_governor(
        core_stages=order_stages([_RecordingTier()]),
        server_inputs={ACTION: telemetry},
    )
    sealed: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    mint = sealing_module.issue_seal
    consume = rs.verify_and_consume_seal

    async def _issue(action: str, params: dict[str, Any], **kwargs: Any) -> str:
        sealed.append(copy.deepcopy(params))
        return await mint(action, params, **kwargs)

    async def _verify(
        seal: str, action: str, params: dict[str, Any], **kwargs: Any
    ) -> bool:
        verified.append(copy.deepcopy(params))
        return await consume(seal, action, params, **kwargs)

    actuate = AsyncMock(
        return_value=ActuationReceipt(
            accepted=True,
            receipt_id="receipt-1",
            session_uuid=None,
            raw_receipt={"status": "executed"},
            outcome=ActuationOutcome.ACCEPTED,
        )
    )
    # The actuator is stubbed, not dispatch_actuation(): the kernel dispatch
    # path writes the attempt record the trade tool reads (POAM-2026-252).
    registry = MagicMock()
    registry.get_actuator.return_value = MagicMock(
        actuator_id="test_broker", actuate=actuate
    )
    monkeypatch.setattr(sealing_module, "issue_seal", _issue)
    monkeypatch.setattr(rs, "verify_and_consume_seal", _verify)
    monkeypatch.setattr(tool_provider_module, "get_actuator_registry", lambda: registry)
    # The NARROW receipt lookup finds nothing for an ALLOW seal.
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.redis_client", real_seals.index
    )

    for trade in (1, 2):
        outcome = await execute_trade_action(
            "AAPL",
            100.0,
            "USD",
            confidence=0.99,
            transaction_id=str(uuid.uuid4()),
            governor=governor,
        )

        assert outcome.status is CommitStatus.EXECUTED, outcome
        assert outcome.message.startswith("EXECUTED"), outcome
        assert telemetry.calls == trade  # one lookup per trade, in the committing run
        clearance = actuate.await_args.args[0]
        assert sealed[-1] == verified[-1] == clearance.params
        assert clearance.params["latency_ms"] == 10.0 + trade
        assert clearance.params["trader_role"] == BOUND_ROLE
    assert len(sealed) == len(verified) == actuate.await_count == 2


# -- The envelope's audit binding of the evaluated params --------------------


async def test_validate_action_evaluated_action_hash_binds_the_bound_params() -> None:
    raw = _caller_params()
    bound = _evaluated(raw)

    result = await _governor(_RoleResolver(), _RecordingTier()).validate_action(
        ACTION, raw
    )

    assert result["verdict"] == GovernanceDecision.ALLOW
    evaluated_hash = result["evaluated_action_hash"]
    assert evaluated_hash == envelope_action_hash(ACTION, bound)
    assert evaluated_hash == f"sha256:{compute_action_hash(ACTION, bound)}"
    assert evaluated_hash != envelope_action_hash(ACTION, raw)

    payload = {
        k: v
        for k, v in result.items()
        if k not in ("external_attestations", "evaluated_action_hash")
    }
    envelope = GovernanceEnvelopeBuilder().build_unsigned(
        ACTION, raw, payload, evaluated_action_hash=evaluated_hash
    )

    assert envelope.subject.evaluated_action_hash == evaluated_hash
    assert envelope.subject.action_hash == envelope_action_hash(ACTION, raw)
    subject = envelope.to_dict(include_signature=False)["subject"]
    assert subject["evaluated_action_hash"] == evaluated_hash
    assert subject["action_hash"] == envelope_action_hash(ACTION, raw)


# -- enforce_approved_governance(): one binding per redemption ---------------


async def test_redemption_binds_server_inputs_once_inside_the_committing_run(
    monkeypatch: pytest.MonkeyPatch, seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    resolver = _RoleResolver()
    tier = _RecordingTier(revalidated=True)
    queue = _ApprovalQueue(_approved(), probe=lambda: len(resolver.calls))
    _serve(monkeypatch, queue)
    binds: list[str] = []
    bind = governor_module.bind_server_inputs

    async def _bind(
        resolvers: Mapping[str, Any], action: str, params: Mapping[str, Any]
    ) -> dict[str, Any]:
        binds.append(action)
        return await bind(resolvers, action, params)

    monkeypatch.setattr(governor_module, "bind_server_inputs", _bind)

    sealed = await _redeem(_governor(resolver, tier))

    # The pre-check reads token state only: no covers, nothing bound yet.
    assert queue.state_checks == [(DEFER_ID, ACTION)]
    assert queue.probes == [0]
    # The committing run binds once; the stages and the seal share the result.
    assert binds == [ACTION]
    assert len(resolver.calls) == 1
    assert sealed.params == _evaluated(_caller_params())
    assert tier.seen == [sealed.params]
    assert queue.consume_calls == [True]
    assert queue.consumed
    refusals.assert_not_awaited()


async def test_redemption_covers_and_spends_exactly_the_sealed_params(
    monkeypatch: pytest.MonkeyPatch, seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    queue = _ApprovalQueue(_approved())
    _serve(monkeypatch, queue)
    spent = _record_spends(monkeypatch)
    matched: list[tuple[bool, dict[str, Any]]] = []

    def _matcher(approved: dict[str, Any], requested: dict[str, Any]) -> bool:
        matched.append((queue.consuming, copy.deepcopy(requested)))
        return _approval_covers_trade(approved, requested)

    sealed = await _redeem(
        _governor(_RoleResolver(), _RecordingTier(revalidated=True)),
        covers=_matcher,
    )

    # Covered before any stage ran, and again inside the compare-and-swap.
    assert matched == [(False, sealed.params), (True, sealed.params)]
    assert spent == [sealed.params]
    seal_mock.assert_awaited_once_with(
        ACTION,
        sealed.params,
        path="revalidate_post_hitl",
        reliance=(),
        decision_context=ANY,
    )
    assert not _carries(matched, SPOOFED_ROLE)
    assert queue.consumed
    refusals.assert_not_awaited()


async def test_redemption_refuses_a_changed_identity_input_without_spending(
    monkeypatch: pytest.MonkeyPatch, seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    """Approved for a junior trader; the verified caller now binds as senior."""
    resolver = _RoleResolver(role="senior")
    tier = _RecordingTier(revalidated=True)
    queue = _ApprovalQueue(_approved())  # approved trader_role: junior
    emitted = _serve(monkeypatch, queue)
    claimed = _caller_params(trader_role=BOUND_ROLE)  # claims the approved role

    with pytest.raises(
        (GovernanceError, PermissionError), match=APPROVAL_NOT_REDEEMABLE
    ):
        await _redeem(_governor(resolver, tier), claimed)

    assert queue.consume_calls == []
    assert not queue.consumed  # the approval stays unspent
    seal_mock.assert_not_awaited()
    assert tier.seen == []  # refused before any stage ran
    assert len(resolver.calls) == 1
    refusals.assert_awaited_once()
    (receipt,) = refusals.await_args.args
    assert receipt.attempted_params == _stripped(_evaluated(claimed, role="senior"))
    emitted.assert_awaited_once()


async def test_replayed_redemption_seals_nothing_and_is_refused(
    monkeypatch: pytest.MonkeyPatch, seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    resolver = _RoleResolver()
    queue = _ApprovalQueue(_approved())
    _serve(monkeypatch, queue)
    governor = _governor(resolver, _RecordingTier(revalidated=True))

    first = await _redeem(governor)

    assert first.params == _evaluated(_caller_params())
    assert queue.consume_calls == [True]
    seal_mock.assert_awaited_once()

    # A replay of the spent approval is refused by the state check: nothing runs.
    with pytest.raises(gm.ApprovalRedemptionRefused, match="not redeemable") as replay:
        await _redeem(governor)
    assert replay.value.refusal is ApprovalRedemptionRefusal.CONSUMED
    assert len(resolver.calls) == 1
    assert queue.consume_calls == [True]

    # A replay that raced past the state check loses the compare-and-swap.
    queue.stale_state_check = True
    with pytest.raises(
        gm.ApprovalRedemptionRefused, match=APPROVAL_NOT_REDEEMABLE
    ) as raced:
        await _redeem(governor)
    assert raced.value.refusal is ApprovalRedemptionRefusal.CONSUMED
    assert queue.consume_calls == [True, True]  # covered, but already spent
    seal_mock.assert_awaited_once()  # neither replay sealed anything


# -- Fail-closed paths -------------------------------------------------------


async def test_govern_unbindable_inputs_block_naming_the_snapshot(
    seal_mock: AsyncMock, infra_blocks: AsyncMock
) -> None:
    tier = _RecordingTier()
    raw = _caller_params()

    with pytest.raises(GovernanceInfrastructureError) as exc_info:
        await _governor(_UnavailableResolver(), tier).govern(ACTION, raw)

    assert exc_info.value.dependency == "trader_directory"
    assert exc_info.value.failure_code == "TRADER_DIRECTORY_UNAVAILABLE"
    infra_blocks.assert_awaited_once()
    block = infra_blocks.await_args.kwargs
    assert block["action"] == ACTION
    # No evaluated params exist: the record names the snapshot of the request.
    assert block["params"] == raw
    assert block["params"] is not raw
    assert block["dependency"] == "trader_directory"
    seal_mock.assert_not_awaited()
    assert tier.seen == []


async def test_govern_blocks_even_if_the_infrastructure_handler_returns(
    monkeypatch: pytest.MonkeyPatch, seal_mock: AsyncMock
) -> None:
    handler = AsyncMock(return_value=None)
    monkeypatch.setattr(governor_module, "handle_infrastructure_block", handler)
    tier = _RecordingTier()
    raw = _caller_params()

    with pytest.raises(
        GovernanceInfrastructureError, match="returned without raising"
    ) as exc_info:
        await _governor(_UnavailableResolver(), tier).govern(ACTION, raw)

    assert exc_info.value.dependency == "trader_directory"
    assert exc_info.value.failure_code == "TRADER_DIRECTORY_UNAVAILABLE"
    assert exc_info.value.error_code == "trader_directory_unavailable"
    handler.assert_awaited_once()
    action, named, violations, tier_failures, meta = handler.await_args.args
    assert (action, named, tier_failures) == (ACTION, raw, [])
    assert [v.code for v in violations] == ["TRADER_DIRECTORY_UNAVAILABLE"]
    assert meta == {"infra_error_code": "trader_directory_unavailable"}
    seal_mock.assert_not_awaited()
    assert tier.seen == []


async def test_post_hitl_raising_coverage_check_refuses_without_spending(
    seal_mock: AsyncMock, refusals: AsyncMock
) -> None:
    def _raising(evaluated: Mapping[str, Any]) -> bool:
        raise RuntimeError("coverage matcher failed")

    tier = _RecordingTier(revalidated=True)
    counter = SpendCounter()
    raw = _caller_params()

    with pytest.raises(GovernanceError, match=APPROVAL_NOT_REDEEMABLE) as exc_info:
        await _governor(_RoleResolver(), tier).revalidate_post_hitl(
            ACTION, raw, approval=granted_approval(counter=counter, covers=_raising)
        )

    assert type(exc_info.value) is GovernanceError
    assert counter.calls == 0
    assert not counter.spent
    assert counter.covered == [_evaluated(raw)]  # asked about the evaluated params
    assert tier.seen == []
    seal_mock.assert_not_awaited()
    refusals.assert_awaited_once()
    (receipt,) = refusals.await_args.args
    assert receipt.attempted_params == _stripped(_evaluated(raw))


async def test_post_hitl_unbindable_inputs_block_without_spending(
    seal_mock: AsyncMock, infra_blocks: AsyncMock, refusals: AsyncMock
) -> None:
    tier = _RecordingTier(revalidated=True)
    counter = SpendCounter()
    raw = _caller_params()

    with pytest.raises(GovernanceInfrastructureError):
        await _governor(_UnavailableResolver(), tier).revalidate_post_hitl(
            ACTION, raw, approval=granted_approval(counter=counter)
        )

    assert counter.calls == 0
    assert counter.covered == []
    assert not counter.spent
    assert tier.seen == []
    seal_mock.assert_not_awaited()
    refusals.assert_not_awaited()
    infra_blocks.assert_awaited_once()
    assert infra_blocks.await_args.kwargs["params"] == raw


async def test_revalidate_post_hitl_rejects_the_removed_rebind_inputs_keyword(
    seal_mock: AsyncMock,
) -> None:
    resolver = _RoleResolver()
    counter = SpendCounter()
    governor = _governor(resolver, _RecordingTier(revalidated=True))

    with pytest.raises(TypeError, match="rebind_inputs"):
        await governor.revalidate_post_hitl(  # type: ignore[call-arg]
            ACTION,
            _caller_params(),
            approval=granted_approval(counter=counter),
            rebind_inputs=True,
        )

    assert resolver.calls == []
    assert counter.calls == 0
    seal_mock.assert_not_awaited()
