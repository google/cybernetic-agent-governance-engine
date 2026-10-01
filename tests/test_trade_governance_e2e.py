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

"""Trade governance end to end, hermetically: the scenario matrix (plan §0.4).

One gateway process, built from real parts wherever a safety property is
observed:

* the real kernel stages (FTRA over the finance registry, the finance STPA
  rules, OPA stage, confidence gate), classifier and verdict handlers;
* the real ``/governance/validate-action`` endpoint behind the real
  ``WorkloadIdentityMiddleware``, driven over ASGI;
* the real ``execute_trade_action`` committing run: seal minting and
  single-use burn, ``DeferQueue`` parking / quorum approval / consumption;
* real ``FiscalLimitGuard`` and ``ControlBarrierFunction`` state in fakeredis.

Doubles stand in only where no safety property is observed here: an RBAC
policy client that mirrors ``src/cage_finance/opa/trade_governance.rego``
(the rego itself is covered by the OPA suite), a causal gatekeeper that
refuses ``risk_score > 0.9``, and a recording broker actuator. Seals are the
dev-posture HMAC; KMS/``kid`` verification lives in the live suite
(``tests/e2e/test_gke_trade_flow.py``).

Scenarios that later phases turn green are strict xfails, so the day they
start passing the suite fails until the marker is removed.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount

from src.cage_finance.invariants import CashBarrier, finance_cost_resolver
from src.cage_finance.narrowers import AmountNarrower
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.stpa import UCA_RULES
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier
from src.gateway.governance import defer_queue as defer_queue_mod
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import ApprovalRecord, DeferQueue
from src.gateway.governance.evidence import stream as evidence_stream
from src.gateway.governance.governance_envelope import unwrap_governance_envelope
from src.gateway.governance.governor import governor as governor_mod
from src.gateway.governance.governor.governor import GovernanceError, SymbolicGovernor
from src.gateway.governance.narrower import NarrowerRegistry
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.seams.actuation import ActuationReceipt
from src.gateway.governance.stpa_validator import STPAValidator
from src.gateway.server import governance_middleware
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.workload_identity import (
    CLIENT_IDENTITY_HEADER,
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

ADVISOR = "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
DAILY_CAP_USD = 500_000.0
OPENING_CASH = 1_000_000.0
_CASH_KEY = "safety:current_cash"


# ---------------------------------------------------------------------------
# Doubles (no safety property is observed through these)
# ---------------------------------------------------------------------------


class RegoMirrorPolicy:
    """Mirrors trade_governance.rego's RBAC ladder; records every evaluation."""

    _LIMITS = {"junior": (5_000.0, 10_000.0), "senior": (500_000.0, 1_000_000.0)}

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def evaluate_policy(self, payload: dict[str, Any]) -> str:
        self.calls.append(payload)
        limits = self._LIMITS.get(str(payload.get("trader_role")))
        if limits is None:
            return "DENY"
        allow_max, review_max = limits
        amount = float(payload.get("amount", 0.0))
        if amount <= allow_max:
            return "ALLOW"
        if amount <= review_max:
            return "MANUAL_REVIEW"
        return "DENY"


class RiskGatekeeper:
    """Causal gatekeeper double: predicted risk above 0.9 is unsafe."""

    def causal_safety_check(self, params: dict[str, Any], *_: Any) -> bool:
        return float(params.get("risk_score", 0.0)) <= 0.9


class DoseLimitEngine:
    """Barrier engine for dose_barrier: at most 500 mg per administration."""

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        return "SAFE" if float(payload.get("dose_mg", 0)) <= 500 else "UNSAFE: dose > 500 mg"

    async def atomic_verify_and_commit(
        self, action_name: str, payload: dict[str, Any]
    ) -> tuple[bool, str, float]:
        dose = float(payload.get("dose_mg", 0))
        return (True, "COMMITTED", dose) if dose <= 500 else (False, "UNSAFE: dose > 500 mg", 0.0)

    async def rollback_state(self, magnitude: float, governance_signature: str | None = None) -> None:
        return None


# ---------------------------------------------------------------------------
# The gateway under test
# ---------------------------------------------------------------------------


@dataclass
class Gateway:
    governor: SymbolicGovernor
    policy: RegoMirrorPolicy
    fiscal: FiscalLimitGuard
    fiscal_tier: FiscalTierPlugin
    cbf: ControlBarrierFunction
    cbf_redis: Any
    defer_redis: Any
    seal_redis: Any
    actuate: AsyncMock
    refusals: AsyncMock
    http: httpx.AsyncClient

    async def validate(self, params: dict[str, Any], *, action: str = "execute_trade", headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.post(
            "/governance/validate-action",
            json={"action": action, "params": params},
            headers={CLIENT_IDENTITY_HEADER: ADVISOR} if headers is None else headers,
        )

    async def cash(self) -> float:
        return float(await self.cbf_redis.get(_CASH_KEY))

    async def parked_tokens(self) -> list[str]:
        return [k for k in await self.defer_redis.keys("DEFER:*") if k != "DEFER:expiry_index"]

    async def approve(self, deferred_id: str, *approvers: str) -> None:
        queue = DeferQueue(self.defer_redis)
        for urn in approvers:
            await queue.approve(
                deferred_id,
                ApprovalRecord(
                    approver_urn=urn,
                    approved_at_utc=datetime.now(timezone.utc).isoformat(),
                    auth_method="OIDC",
                    auth_principal_hash=hashlib.sha256(urn.encode()).hexdigest(),
                ),
            )

    async def execute(self, params: dict[str, Any], deferred_id: str | None = None) -> str:
        return await execute_trade_action(
            params["symbol"],
            params["amount"],
            params["currency"],
            params["confidence"],
            None,
            params["trader_id"],
            params["trader_role"],
            False,
            deferred_id,
            governor=self.governor,
            safety_filter=self.cbf,
        )


def trade(amount: float, role: str = "senior", **extra: Any) -> dict[str, Any]:
    return {
        "symbol": "AAPL",
        "amount": amount,
        "currency": "USD",
        "confidence": 0.98,
        "trader_id": "trader-7",
        "trader_role": role,
        "latency_ms": 10.0,
        "drawdown": 0.0,
        **extra,
    }


def _classifier(*, narrow: bool = False) -> ClassificationEngine:
    return ClassificationEngine(
        narrower_registry=NarrowerRegistry(narrowers=[AmountNarrower()]),
        confidence_threshold=0.95,
        defer_enabled=True,
        narrow_enabled=narrow,
        pause_enabled=False,
    )


@pytest.fixture
async def gw(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Gateway]:
    # Dev posture: HMAC seals (KMS JWS + kid verification is the live suite's job).
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    cbf_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    fiscal_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    defer_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    seal_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    await cbf_redis.set(_CASH_KEY, str(OPENING_CASH))

    raw_cbf_client = MagicMock()
    raw_cbf_client.get_raw_client.return_value = cbf_redis
    monkeypatch.setattr("src.gateway.governance.safety.cbf_engine.redis_client", raw_cbf_client)
    # No reconciler runs here: the verified-state store is empty, not unreachable.
    monkeypatch.setattr(
        "src.gateway.governance.safety.cbf_engine.sync_redis_client",
        fakeredis.FakeRedis(decode_responses=True),
    )
    monkeypatch.setattr("src.gateway.infrastructure.redis_client.redis_client", seal_redis)

    @asynccontextmanager
    async def _queue() -> AsyncIterator[DeferQueue]:
        yield DeferQueue(defer_redis)

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _queue)

    # A real hash-chained evidence sink: no seal is issued without an evidence commit.
    evidence_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    sink = evidence_stream.EvidenceStreamSink()
    with monkeypatch.context() as m:
        m.setattr("src.gateway.infrastructure.redis_client.build_async_redis", lambda *a, **k: evidence_redis)
        m.setattr("redis.asyncio.from_url", lambda *a, **k: evidence_redis)
        await sink.start()
    monkeypatch.setattr(evidence_stream, "_evidence_sink", sink)

    cbf = ControlBarrierFunction(
        invariant=CashBarrier(), cost_resolver=finance_cost_resolver, skip_epoch_seed=True
    )
    cbf.threshold_value = 0.0
    cbf.gamma = 1.0
    fiscal = FiscalLimitGuard(fiscal_redis, daily_cap_usd=DAILY_CAP_USD)
    fiscal_tier = FiscalTierPlugin(fiscal)
    policy = RegoMirrorPolicy()
    governor = make_governor(
        opa=policy,
        stpa_validator=STPAValidator(rules=UCA_RULES),
        classifier=_classifier(),
        domain_tiers=(
            CBFTierPlugin(cbf),
            fiscal_tier,
            CausalTierPlugin(RiskGatekeeper()),
            DoseBarrierTier(DoseLimitEngine()),
        ),
        safety_filter=cbf,
    )
    governance_app.state.governor = governor

    actuate = AsyncMock(
        side_effect=lambda clearance: ActuationReceipt(
            accepted=True,
            receipt_id=f"r-{uuid.uuid4().hex[:8]}",
            session_uuid=None,
            raw_receipt={"status": "executed"},
        )
    )
    monkeypatch.setattr(
        "src.cage_finance.actuators.broker_actuator.BrokerActuator.actuate", actuate
    )
    refusals = AsyncMock()
    monkeypatch.setattr(governance_middleware, "_emit_refusal_receipt", refusals)

    root = WorkloadIdentityMiddleware(
        Starlette(routes=[Mount("/governance", app=governance_app)]),
        IdentityPolicy(trusted=frozenset({ADVISOR})),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root), base_url="http://gateway"
    ) as http:
        yield Gateway(
            governor=governor,
            policy=policy,
            fiscal=fiscal,
            fiscal_tier=fiscal_tier,
            cbf=cbf,
            cbf_redis=cbf_redis,
            defer_redis=defer_redis,
            seal_redis=seal_redis,
            actuate=actuate,
            refusals=refusals,
            http=http,
        )
    governance_app.state.governor = None
    await sink.stop()


def _body(resp: httpx.Response) -> dict[str, Any]:
    """The decision payload, whether flat or wrapped in a v3.0 signed envelope."""
    return unwrap_governance_envelope(resp.json())


async def _require_approval(gw: Gateway, params: dict[str, Any]) -> str:
    resp = await gw.validate(params)
    assert resp.status_code == 200, resp.text
    body = _body(resp)
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert "seal" not in body
    assert body["deferred_id"]
    return str(body["deferred_id"])


async def _assert_nothing_committed(gw: Gateway) -> None:
    assert await gw.fiscal.current_spend_usd() == 0.0
    assert await gw.cash() == OPENING_CASH
    assert await gw.seal_redis.dbsize() == 0  # no seal nonce minted or burned
    gw.actuate.assert_not_awaited()


# ---------------------------------------------------------------------------
# S0 — ingress is deny-by-default on workload identity
# ---------------------------------------------------------------------------


async def test_s0_no_workload_identity_is_refused_before_any_evaluation(gw: Gateway) -> None:
    resp = await gw.validate(trade(500.0), headers={})
    assert resp.status_code == 403
    assert gw.policy.calls == []
    assert await gw.parked_tokens() == []
    await _assert_nothing_committed(gw)


# ---------------------------------------------------------------------------
# S1 / S2 / S3 — approval is gateway state, consumed exactly once
# ---------------------------------------------------------------------------


async def test_s1_require_approval_parks_a_token_and_commits_nothing(gw: Gateway) -> None:
    deferred_id = await _require_approval(gw, trade(20_000.0))
    assert await gw.parked_tokens() == [f"DEFER:{deferred_id}"]
    await _assert_nothing_committed(gw)


async def test_s2_approved_token_executes_once_with_one_commit(gw: Gateway) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")

    result = await gw.execute(params, deferred_id)

    assert result.startswith("EXECUTED: AAPL x 20000.0"), result
    assert await gw.fiscal.current_spend_usd() == 20_000.0
    assert await gw.cash() == OPENING_CASH - 20_000.0
    gw.actuate.assert_awaited_once()
    assert await gw.defer_redis.hget(f"DEFER:{deferred_id}", "status") == "CONSUMED"


async def _replay_concurrently(gw: Gateway) -> list[str]:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")
    return list(await asyncio.gather(gw.execute(params, deferred_id), gw.execute(params, deferred_id)))


def _assert_single_execution(results: list[str], spend: float) -> None:
    assert sorted(r.split(":")[0] for r in results) == ["BLOCKED", "EXECUTED"], results
    assert spend == 20_000.0


async def test_s3_concurrent_replay_executes_exactly_once(gw: Gateway) -> None:
    results = await _replay_concurrently(gw)
    _assert_single_execution(results, await gw.fiscal.current_spend_usd())
    gw.actuate.assert_awaited_once()


@pytest.mark.parametrize(
    ("approvers", "why"),
    [((), "no approvals"), (("urn:op:alice",), "below quorum")],
)
async def test_s2_unapproved_token_is_blocked(gw: Gateway, approvers: tuple[str, ...], why: str) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, *approvers)

    result = await gw.execute(params, deferred_id)

    assert result.startswith("BLOCKED"), (why, result)
    await _assert_nothing_committed(gw)
    gw.refusals.assert_awaited()


@pytest.mark.parametrize(
    "change",
    [{"amount": 20_000.01}, {"symbol": "MSFT"}, {"trader_role": "junior"}, {"trader_id": "someone-else"}],
    ids=["amount-grows", "other-symbol", "other-role", "other-trader"],
)
async def test_s2_approval_does_not_cover_other_params_and_is_not_burned(gw: Gateway, change: dict[str, Any]) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")

    assert (await gw.execute({**params, **change}, deferred_id)).startswith("BLOCKED")
    await _assert_nothing_committed(gw)
    # A mismatched request does not burn the approval; the approved trade still runs.
    assert (await gw.execute(params, deferred_id)).startswith("EXECUTED")


async def test_s2_approval_may_shrink_the_trade(gw: Gateway) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")

    assert (await gw.execute({**params, "amount": 15_000.0}, deferred_id)).startswith("EXECUTED")
    assert await gw.fiscal.current_spend_usd() == 15_000.0


async def test_s2_unknown_deferred_id_is_blocked(gw: Gateway) -> None:
    assert (await gw.execute(trade(20_000.0), str(uuid.uuid4()))).startswith("BLOCKED")
    await _assert_nothing_committed(gw)


async def test_s2_unreachable_defer_queue_blocks(gw: Gateway, monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def _down() -> AsyncIterator[DeferQueue]:
        raise ConnectionError("redis db=1 unreachable")
        yield  # pragma: no cover

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _down)
    assert (await gw.execute(trade(20_000.0), str(uuid.uuid4()))).startswith("BLOCKED")
    await _assert_nothing_committed(gw)


# ---------------------------------------------------------------------------
# S4 / S6 / S7 / S9 — refusals
# ---------------------------------------------------------------------------


async def _assert_denied(gw: Gateway, resp: httpx.Response, code: str) -> None:
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["verdict"] == "DENIED"
    assert any(code in str(v) for v in body["violations"]), body["violations"]
    assert await gw.parked_tokens() == []
    gw.refusals.assert_awaited_once()
    await _assert_nothing_committed(gw)


async def test_s4_rbac_denial_parks_nothing_and_emits_a_refusal(gw: Gateway) -> None:
    await _assert_denied(gw, await gw.validate(trade(50_000.0, role="junior")), "CTRL_OPA_005")


async def test_s6_fiscal_drift_after_approval_blocks_in_the_committing_run(gw: Gateway) -> None:
    params = trade(15_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=490_000.0)

    result = await gw.execute(params, deferred_id)

    assert result.startswith("BLOCKED"), result
    assert await gw.fiscal.current_spend_usd() == 490_000.0
    assert await gw.cash() == OPENING_CASH
    gw.actuate.assert_not_awaited()


async def test_s7_unsafe_control_action_is_denied(gw: Gateway) -> None:
    # The finance STPA rules act on structured params (UCA-9: compliance check
    # bypassed); free-text prompt screening belongs to the NeMo rails.
    await _assert_denied(gw, await gw.validate(trade(500.0, compliance_checked=False)), "STPA_UCA_UCA_9")


async def test_s9_causal_refusal_is_denied(gw: Gateway) -> None:
    await _assert_denied(gw, await gw.validate(trade(500.0, risk_score=0.95)), "CAUSAL_CHECK_FAILED")


# ---------------------------------------------------------------------------
# S12 — unregistered actions never auto-clear
# ---------------------------------------------------------------------------


async def _unregistered(gw: Gateway) -> httpx.Response:
    return await gw.validate(trade(10.0, confidence=0.99), action="rebalance_portfolio_unregistered")


def _assert_not_auto_cleared(resp: httpx.Response) -> None:
    assert resp.status_code in (200, 403), resp.text
    assert _body(resp).get("verdict") != GovernanceDecision.ALLOW


async def test_s12_unregistered_action_never_auto_clears(gw: Gateway) -> None:
    _assert_not_auto_cleared(await _unregistered(gw))


# ---------------------------------------------------------------------------
# Later phases (strict xfail: they must fail today, and fail the suite when fixed)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="Phase 1: FTRA sends every execute_trade to HITL")
async def test_s1a_small_trade_allowed_then_committed_exactly_once(gw: Gateway) -> None:
    params = trade(500.0, role="junior")
    body = _body(await gw.validate(params))
    assert body["verdict"] == GovernanceDecision.ALLOW
    assert "seal" not in body
    await _assert_nothing_committed(gw)

    assert (await gw.execute(params)).startswith("EXECUTED")
    assert await gw.fiscal.current_spend_usd() == 500.0


@pytest.mark.xfail(strict=True, reason="Phase 1: FTRA emits HITL for every execute_trade")
async def test_s1b_opa_manual_review_alone_requires_approval(gw: Gateway) -> None:
    resp = await gw.validate(trade(7_500.0, role="junior"))
    body = _body(resp)
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["classification_reason"] == "opa_manual_review"
    assert [v for v in body["violations"] if "FTRA" in str(v)] == []


@pytest.mark.xfail(strict=True, reason="Phase 1: FTRA provenance codes (FTRA_REGISTERED_IRREVERSIBLE)")
async def test_s1_require_approval_names_ftra_provenance(gw: Gateway) -> None:
    body = _body(await gw.validate(trade(20_000.0)))
    assert any("FTRA_REGISTERED_IRREVERSIBLE" in str(v) for v in body["violations"])


@pytest.mark.xfail(strict=True, reason="Phase 1: FTRA provenance codes (FTRA_UNREGISTERED_ACTION)")
async def test_s12_unregistered_action_names_its_provenance(gw: Gateway) -> None:
    body = _body(await _unregistered(gw))
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert any("FTRA_UNREGISTERED_ACTION" in str(v) for v in body["violations"])


@pytest.mark.xfail(strict=True, reason="Phase 1: CBF claims execute_trade_bounded by cost")
async def test_s13_bounded_trade_is_claimed_by_the_cash_barrier(gw: Gateway) -> None:
    await gw.cbf_redis.set(_CASH_KEY, "1000.0")
    resp = await gw.validate(trade(3_000.0), action="execute_trade_bounded")
    assert any("cbf" in str(v).lower() for v in _body(resp).get("violations", []))


@pytest.mark.xfail(strict=True, reason="Phase 1: POST_HITL runs every phase-2 tier (dose_barrier)")
async def test_s11_post_hitl_reruns_the_dose_barrier(gw: Gateway) -> None:
    params = {"dose_mg": 600, "trader_role": "senior", "amount": 0.0}
    with pytest.raises(GovernanceError) as refused:
        await gw.governor.revalidate_post_hitl("administer_medication", params)
    assert any("DOSE_BARRIER_VIOLATED" in v for v in refused.value.violations)


@pytest.mark.xfail(strict=True, reason="Phase 2: phase-2 barriers previewed before HITL")
async def test_s11_preview_surfaces_the_dose_barrier(gw: Gateway) -> None:
    resp = await gw.validate({"dose_mg": 600, "confidence": 0.99}, action="administer_medication")
    assert any("DOSE_BARRIER_VIOLATED" in str(v) for v in _body(resp).get("violations", []))


@pytest.mark.xfail(strict=True, reason="Phase 2: phase-2 barriers previewed before HITL")
async def test_s5_fiscal_breach_surfaces_before_human_review(gw: Gateway) -> None:
    resp = await gw.validate(trade(600_000.0))
    assert resp.status_code == 403
    assert any("FISCAL_LIMIT_EXCEEDED" in str(v) for v in _body(resp).get("violations", []))


@pytest.mark.xfail(strict=True, reason="Phase 2: sealed NARROW re-run in the committing path")
async def test_s10_autonomous_trade_is_narrowed_to_the_remaining_cap(gw: Gateway) -> None:
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)
    result = await gw.execute(trade(4_000.0))
    assert result.startswith("EXECUTED: AAPL x 3000.0"), result


# ---------------------------------------------------------------------------
# §0.5 mutation self-checks: each breaks one mechanism and observes a scenario fail
# ---------------------------------------------------------------------------


async def test_mutation_flipped_seal_byte_is_refused(gw: Gateway) -> None:
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        generate_seal_with_evidence,
        verify_and_consume_seal,
    )

    params = {"symbol": "AAPL", "amount": 1.0}
    seal = await generate_seal_with_evidence("execute_trade", params)
    i = len(seal) // 2
    tampered = seal[:i] + ("A" if seal[i] != "A" else "B") + seal[i + 1 :]
    with pytest.raises(SymbolicGovernorViolation):
        await verify_and_consume_seal(tampered, "execute_trade", params)


async def test_mutation_ftra_without_violations_lets_unregistered_actions_clear(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.gateway.governance.ftra import models as ftra_models

    real = ftra_models.FtraBoundaryResult.from_classification

    def _no_violations(*args: Any, **kwargs: Any) -> Any:
        from dataclasses import replace

        return replace(real(*args, **kwargs), violations=(), requires_hitl=False)

    monkeypatch.setattr(ftra_models.FtraBoundaryResult, "from_classification", staticmethod(_no_violations))
    with pytest.raises(AssertionError):
        _assert_not_auto_cleared(await _unregistered(gw))


async def test_mutation_committing_under_pending_approval_is_caught(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = governor_mod.run_pipeline

    async def _commits_anyway(stages: Any, ctx: Any, **kwargs: Any) -> Any:
        result = await real(stages, ctx, **kwargs)
        await gw.fiscal_tier.commit(ctx.action, dict(ctx.params))
        return result

    monkeypatch.setattr(governor_mod, "run_pipeline", _commits_anyway)
    await _require_approval(gw, trade(20_000.0))
    with pytest.raises(AssertionError):
        await _assert_nothing_committed(gw)


async def test_mutation_without_the_consumption_cas_replay_executes_twice(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _always(self: DeferQueue, *args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(DeferQueue, "atomic_resolve", _always)
    results = await _replay_concurrently(gw)
    with pytest.raises(AssertionError):
        _assert_single_execution(results, await gw.fiscal.current_spend_usd())
