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

"""A post-approval warrant deferral does not spend the approval (POAM-2026-104).

The committing run decides first and spends second
(``src/gateway/governance/governor/approval.py``):

* ALLOW spends the approval atomically inside the ReservationScope, before
  the seal is minted; a run that cannot spend it seals nothing.
* DEFER (only ``RELIANCE_INELIGIBLE`` findings) spends nothing.
* DENY spends it, then refuses (unchanged behaviour).

Queue level: ``DeferQueue.redeemable_approval`` checks without spending and
``consume_approval`` spends exactly once, also under concurrency.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_CONFIDENCE_NORM_ID,
    TradeConfidenceTier,
)
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    NormBinding,
    Violation,
    ViolationKind,
)
from src.gateway.governance.defer_queue import (
    _KEY_PREFIX,
    ApprovalRecord,
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.gateway.governance.governor import governor as governor_module
from src.gateway.governance.governor.approval import PostHitlApproval
from src.gateway.governance.governor.assembly import kernel_stages
from src.gateway.governance.governor.errors import GovernanceDeferred, GovernanceError
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.warrant import WarrantCache
from tests.fixtures.approval import SpendCounter, granted_approval
from tests.fixtures.governor import (
    WARRANT_TEST_GOVERNING_VERSION,
    WARRANT_TEST_NOW,
    StaticWarrantSource,
    allow_opa,
    clean_stpa,
    issue_test_warrant,
    make_governor,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ACTION = "execute_trade"
_TRADE = {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}
_BINDING = NormBinding(
    norm_id=TRADE_CONFIDENCE_NORM_ID,
    value=0.97,
    requires_warrant=True,
    actions=frozenset({_ACTION}),
    governing_version=WARRANT_TEST_GOVERNING_VERSION,
)
_MINT = "src.gateway.governance.routing_seal.generate_seal_with_evidence"
_SINK = "src.gateway.governance.evidence.stream.get_evidence_sink"
_REFUSAL = "src.gateway.governance.governor.verdicts.publish_refusal"


class _Barrier(MutatingTier):
    """A claiming phase-2 tier: commits (or refuses HARD), records rollbacks."""

    tier_name = "recording_barrier"
    order = 9

    def __init__(self, *, refuse: bool = False) -> None:
        self.refuse = refuse
        self.commits: list[str] = []
        self.rollbacks: list[str] = []

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == _ACTION

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        if self.refuse:
            return [
                Violation(
                    tier=self.tier_name,
                    code="BARRIER_VIOLATED",
                    message="would breach the cap",
                    kind=ViolationKind.HARD,
                )
            ], None
        self.commits.append(action)
        return [], CommitReceipt(tier=self.tier_name, magnitude=1.0, token="debit-1")

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.rollbacks.append(action)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        return None


def _governor(
    source: StaticWarrantSource, *, opa: Any = None, barrier: _Barrier | None = None
) -> tuple[Any, _Barrier]:
    opa = opa or allow_opa()
    stpa = clean_stpa()
    barrier = barrier or _Barrier()
    stage = WarrantStage(
        [_BINDING],
        WarrantCache(source),
        jurisdiction="EU_ECB",
        clock=lambda: WARRANT_TEST_NOW,
    )
    governor = make_governor(
        opa=opa,
        stpa_validator=stpa,
        core_stages=(*kernel_stages(opa, stpa), stage),
        domain_tiers=(TradeConfidenceTier(_BINDING), barrier),
    )
    return governor, barrier


def _revoked() -> StaticWarrantSource:
    return StaticWarrantSource(
        {
            TRADE_CONFIDENCE_NORM_ID: issue_test_warrant(
                status="REVOKED", revocation_ref="REV-AFTER-APPROVAL"
            )
        }
    )


def _sink() -> MagicMock:
    sink = MagicMock()
    sink.ingest = AsyncMock()
    return sink


# ── Governor: decide first, spend second ─────────────────────────────────────


async def test_allow_spends_once_before_the_seal_is_minted() -> None:
    governor, barrier = _governor(StaticWarrantSource.eligible())
    counter = SpendCounter()
    spent_at_mint: list[bool] = []

    async def _mint(*_a: Any, **_k: Any) -> str:
        spent_at_mint.append(counter.spent)
        return "seal-ok"

    with patch(_MINT, side_effect=_mint):
        seal = await governor.revalidate_post_hitl(
            _ACTION, dict(_TRADE), approval=granted_approval("PASS", counter=counter)
        )
    assert seal == "seal-ok"
    assert counter.results == [True]
    assert spent_at_mint == [True]  # spent before the seal existed
    assert barrier.commits == [_ACTION]
    assert barrier.rollbacks == []


async def test_warrant_ineligible_defers_without_spending_or_committing() -> None:
    governor, barrier = _governor(_revoked())
    counter = SpendCounter()
    sink = _sink()
    with patch(_MINT) as mint, patch(_SINK, return_value=sink), patch(_REFUSAL) as ref:
        with pytest.raises(GovernanceDeferred) as deferred:
            await governor.revalidate_post_hitl(
                _ACTION,
                dict(_TRADE),
                approval=granted_approval(
                    "PASS", approval_id="appr-1", counter=counter, thread_id="t-1"
                ),
            )
    assert counter.calls == 0  # the approval stays redeemable
    mint.assert_not_called()
    ref.assert_not_called()  # a deferral, not a refusal
    assert barrier.commits == []
    exc = deferred.value
    assert isinstance(exc, GovernanceError)  # callers that only stop still stop
    assert exc.deferred_id == "appr-1"
    assert exc.defer_reason == DeferReason.WARRANT_INELIGIBLE.value
    assert "RELIANCE_INELIGIBLE_REVOKED" in str(exc)
    (reliance,) = exc.reliance
    assert reliance["reliance_status"] == "INELIGIBLE_REVOKED"
    # Primary evidence: the failed attempt is hash-chained, naming the approval.
    (event,) = [
        c.args[0]
        for c in sink.ingest.await_args_list
        if c.args[0].get("type") == "GOVERNANCE_DEFERRAL"
    ]
    assert event["type"] == "GOVERNANCE_DEFERRAL"
    assert event["controlId"] == "CTRL_AGT_001"
    assert event["defer_id"] == "appr-1"
    assert event["thread_id"] == "t-1"
    assert event["profile"] == "POST_HITL"
    assert event["approval_retained"] is True
    assert event["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    assert event["reliance"] == [reliance]
    assert len(event["params_hash"]) == 64
    assert all(isinstance(v, dict) for v in event["violations"])


async def test_deferral_evidence_failure_is_counted_and_still_defers() -> None:
    governor, _ = _governor(_revoked())
    sink = _sink()
    sink.ingest.side_effect = RuntimeError("sink down")
    metrics = MagicMock()
    with (
        patch(_SINK, return_value=sink),
        patch(
            "src.gateway.governance.governor.verdicts.governor_metrics",
            return_value=metrics,
        ),
    ):
        with pytest.raises(GovernanceDeferred):
            await governor.revalidate_post_hitl(
                _ACTION, dict(_TRADE), approval=granted_approval("PASS")
            )
    metrics.evidence_publish_failure.assert_called_once_with("deferral")


async def test_a_spent_approval_seals_nothing_and_rolls_the_commit_back() -> None:
    governor, barrier = _governor(StaticWarrantSource.eligible())
    counter = SpendCounter(spent=True)  # already consumed elsewhere
    with patch(_MINT) as mint, patch(_REFUSAL) as refusal:
        with pytest.raises(GovernanceError, match="APPROVAL_NOT_REDEEMABLE") as exc:
            await governor.revalidate_post_hitl(
                _ACTION,
                dict(_TRADE),
                approval=granted_approval("PASS", counter=counter),
            )
    assert not isinstance(exc.value, GovernanceDeferred)
    mint.assert_not_called()
    assert counter.results == [False]
    assert barrier.commits == [_ACTION]
    assert barrier.rollbacks == [_ACTION]  # the clean run's reservation is released
    refusal.assert_awaited_once()  # the refused redemption is evidenced


async def test_hard_refusal_spends_the_approval() -> None:
    """DENY behaves as before: the approval is burned and the run refused."""
    opa = MagicMock()
    opa.evaluate_policy = AsyncMock(return_value="DENY")
    governor, barrier = _governor(_revoked(), opa=opa)
    counter = SpendCounter()
    with patch(_MINT) as mint, patch(_REFUSAL):
        with pytest.raises(GovernanceError) as exc:
            await governor.revalidate_post_hitl(
                _ACTION,
                dict(_TRADE),
                approval=granted_approval("PASS", counter=counter),
            )
    assert not isinstance(exc.value, GovernanceDeferred)
    assert counter.results == [True]
    mint.assert_not_called()
    assert barrier.commits == []


async def test_barrier_drift_spends_the_approval() -> None:
    governor, _ = _governor(
        StaticWarrantSource.eligible(), barrier=_Barrier(refuse=True)
    )
    counter = SpendCounter()
    with patch(_MINT) as mint, patch(_REFUSAL):
        with pytest.raises(GovernanceError, match="APPROVAL_CONTEXT_DRIFT"):
            await governor.revalidate_post_hitl(
                _ACTION,
                dict(_TRADE),
                approval=granted_approval("PASS", counter=counter),
            )
    assert counter.results == [True]
    mint.assert_not_called()


async def test_unrecognised_snapshot_spends_and_refuses_before_running() -> None:
    source = StaticWarrantSource.eligible()
    governor, barrier = _governor(source)
    counter = SpendCounter()
    with patch(_REFUSAL):
        with pytest.raises(GovernanceError, match="APPROVAL_CONTEXT_DRIFT"):
            await governor.revalidate_post_hitl(
                _ACTION,
                dict(_TRADE),
                approval=granted_approval("MAYBE", counter=counter),
            )
    assert counter.results == [True]
    assert source.calls == []
    assert barrier.commits == []


async def test_concurrent_redemptions_of_one_approval_seal_once() -> None:
    governor, barrier = _governor(StaticWarrantSource.eligible())
    counter = SpendCounter()  # one shared approval, like one queue token
    with patch(_MINT, return_value="seal-ok"), patch(_REFUSAL):
        results = await asyncio.gather(
            *(
                governor.revalidate_post_hitl(
                    _ACTION,
                    dict(_TRADE),
                    approval=granted_approval("PASS", counter=counter),
                )
                for _ in range(5)
            ),
            return_exceptions=True,
        )
    assert results.count("seal-ok") == 1, results
    refused = [r for r in results if isinstance(r, GovernanceError)]
    assert len(refused) == 4
    assert all("APPROVAL_NOT_REDEEMABLE" in str(r) for r in refused)
    assert counter.results.count(True) == 1
    assert len(barrier.commits) - len(barrier.rollbacks) == 1  # one reservation kept


async def test_spend_that_raises_seals_nothing() -> None:
    governor, barrier = _governor(StaticWarrantSource.eligible())

    async def _boom() -> bool:
        raise ConnectionError("queue down")

    approval = PostHitlApproval(approval_id="a", barrier_preview="PASS", spend=_boom)
    with patch(_MINT) as mint:
        with pytest.raises(ConnectionError):
            await governor.revalidate_post_hitl(
                _ACTION, dict(_TRADE), approval=approval
            )
    mint.assert_not_called()
    assert barrier.rollbacks == barrier.commits == [_ACTION]


def test_revalidate_post_hitl_requires_an_approval() -> None:
    """No post-approval run without an approval to spend (no default)."""
    import inspect

    sig = inspect.signature(governor_module.SymbolicGovernor.revalidate_post_hitl)
    assert sig.parameters["approval"].default is inspect.Parameter.empty
    assert "approved_barrier_preview" not in sig.parameters


# ── Queue: check without spending, spend exactly once ────────────────────────


@pytest.fixture
def queue() -> DeferQueue:
    return DeferQueue(fakeredis.aioredis.FakeRedis(decode_responses=True))


def _approval_record(who: str) -> ApprovalRecord:
    return ApprovalRecord(
        approver_urn=f"urn:operator:{who}",
        approved_at_utc="2026-10-07T12:00:00Z",
        auth_method="OIDC",
        auth_principal_hash=f"hash-{who}",
    )


async def _approved(queue: DeferQueue) -> str:
    token = DeferToken(
        thread_id="thread-spend",
        defer_reason=DeferReason.HITL_REQUIRED,
        ttl_seconds=300,
        opa_input_snapshot={"action": _ACTION, "params": {"amount": 10.0}},
    )
    await queue.park(token)
    await queue.approve(token.defer_id, _approval_record("alice"))
    await queue.approve(token.defer_id, _approval_record("bob"))
    return token.defer_id


async def _status(queue: DeferQueue, defer_id: str) -> str | None:
    return await queue._redis.hget(f"{_KEY_PREFIX}{defer_id}", "status")


def _covers(approved: dict[str, Any]) -> bool:
    return True


async def test_redeemable_approval_checks_without_spending(queue: DeferQueue) -> None:
    defer_id = await _approved(queue)
    for _ in range(3):
        token = await queue.redeemable_approval(
            defer_id, action=_ACTION, covers=_covers
        )
        assert token is not None and token.defer_id == defer_id
    assert await _status(queue, defer_id) == "RESOLVED"


async def test_consume_spends_once_then_nothing_is_redeemable(
    queue: DeferQueue,
) -> None:
    defer_id = await _approved(queue)
    assert await queue.consume_approval(defer_id, action=_ACTION, covers=_covers)
    assert await _status(queue, defer_id) == "CONSUMED"
    assert (
        await queue.consume_approval(defer_id, action=_ACTION, covers=_covers) is None
    )
    assert (
        await queue.redeemable_approval(defer_id, action=_ACTION, covers=_covers)
        is None
    )


async def test_concurrent_consumes_yield_one_token(queue: DeferQueue) -> None:
    defer_id = await _approved(queue)
    results = await asyncio.gather(
        *(
            queue.consume_approval(defer_id, action=_ACTION, covers=_covers)
            for _ in range(10)
        )
    )
    assert sum(r is not None for r in results) == 1
    assert await _status(queue, defer_id) == "CONSUMED"


async def test_consume_rechecks_and_a_mismatch_does_not_burn(
    queue: DeferQueue,
) -> None:
    defer_id = await _approved(queue)
    assert (
        await queue.consume_approval(defer_id, action=_ACTION, covers=lambda _p: False)
        is None
    )
    assert (
        await queue.consume_approval(defer_id, action="other_action", covers=_covers)
        is None
    )
    assert await _status(queue, defer_id) == "RESOLVED"  # still redeemable


async def test_an_expired_approval_is_neither_redeemable_nor_spendable(
    queue: DeferQueue,
) -> None:
    defer_id = await _approved(queue)
    await queue._redis.expire(f"{_KEY_PREFIX}{defer_id}", 0)
    assert (
        await queue.redeemable_approval(defer_id, action=_ACTION, covers=_covers)
        is None
    )
    assert (
        await queue.consume_approval(defer_id, action=_ACTION, covers=_covers) is None
    )


async def test_unapproved_token_is_not_redeemable(queue: DeferQueue) -> None:
    token = DeferToken(
        thread_id="thread-spend",
        defer_reason=DeferReason.HITL_REQUIRED,
        ttl_seconds=300,
        opa_input_snapshot={"action": _ACTION, "params": {"amount": 10.0}},
    )
    await queue.park(token)
    await queue.approve(token.defer_id, _approval_record("alice"))  # 1 of 2
    assert (
        await queue.redeemable_approval(token.defer_id, action=_ACTION, covers=_covers)
        is None
    )


# ── The plain committing run: a warrant failure is a DEFER, never a DENY ─────


@pytest.fixture
def parked(monkeypatch: pytest.MonkeyPatch) -> DeferQueue:
    """Route handle_defer's parking to an in-memory queue."""
    from contextlib import asynccontextmanager

    from src.gateway.governance import defer_queue as defer_queue_mod

    queue = DeferQueue(fakeredis.aioredis.FakeRedis(decode_responses=True))

    @asynccontextmanager
    async def _open():  # type: ignore[no-untyped-def]
        yield queue

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _open)
    return queue


async def test_govern_defers_on_an_ineligible_warrant_and_parks_it(
    parked: DeferQueue,
) -> None:
    governor, barrier = _governor(_revoked())
    sink = _sink()
    with patch(_MINT) as mint, patch(_SINK, return_value=sink), patch(_REFUSAL) as ref:
        with pytest.raises(GovernanceDeferred) as deferred:
            await governor.govern(_ACTION, dict(_TRADE))
    mint.assert_not_called()
    ref.assert_not_called()  # no refusal receipt for a warrant failure
    assert barrier.commits == []
    exc = deferred.value
    assert exc.defer_reason == DeferReason.WARRANT_INELIGIBLE.value
    assert "RELIANCE_INELIGIBLE_REVOKED" in str(exc)
    token = await parked.get(exc.deferred_id)
    assert token is not None
    assert token.defer_reason is DeferReason.WARRANT_INELIGIBLE
    assert token.opa_input_snapshot["reliance"] == exc.reliance
    (event,) = [
        c.args[0]
        for c in sink.ingest.await_args_list
        if c.args[0].get("type") == "GOVERNANCE_DEFERRAL"
    ]
    assert event["defer_id"] == exc.deferred_id
    assert event["reliance"] == exc.reliance


async def test_govern_hard_finding_outranks_the_warrant_and_denies(
    parked: DeferQueue,
) -> None:
    """Precedence: an independent HARD finding still denies under a revoked
    warrant (the warrant rule only removes reliance on its own norm)."""
    governor, _ = _governor(_revoked())
    with patch(_MINT) as mint, patch(_REFUSAL) as refusal:
        with pytest.raises(GovernanceError) as exc:
            await governor.govern(
                _ACTION, {"confidence": "0.99", "amount": 100.0, "symbol": "AAPL"}
            )
    assert not isinstance(exc.value, GovernanceDeferred)
    mint.assert_not_called()
    refusal.assert_awaited_once()
    (receipt,) = refusal.await_args.args
    assert receipt.violated_rule  # a real refusal receipt, not a deferral
