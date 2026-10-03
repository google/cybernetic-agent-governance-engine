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
import json
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
from src.gateway.governance.causal.gatekeeper import CausalDecision
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.consensus import extract_field_magnitude
from src.gateway.governance.contracts import NarrowingResult
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import ApprovalRecord, DeferQueue
from src.gateway.governance.evidence import stream as evidence_stream
from src.gateway.governance.governance_envelope import unwrap_governance_envelope
from src.gateway.governance.governor import governor as governor_mod
from src.gateway.governance.governor import pipeline as pipeline_mod
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

    def evaluate(self, params: dict[str, Any], *_: Any, **__: Any) -> CausalDecision:
        safe = float(params.get("risk_score", 0.0)) <= 0.9
        return CausalDecision(safe, "world_model_trusted" if safe else "risk_boundary")

    def causal_safety_check(self, params: dict[str, Any], *_: Any, **__: Any) -> bool:
        return self.evaluate(params).safe


class DoseLimitEngine:
    """Barrier engine for dose_barrier: at most 500 mg per administration."""

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        return "SAFE" if float(payload.get("dose_mg", 0)) <= 500 else "UNSAFE: dose > 500 mg"

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
        *,
        debit_id: str | None = None,
    ) -> tuple[bool, str, float]:
        dose = float(payload.get("dose_mg", 0))
        return (True, "COMMITTED", dose) if dose <= 500 else (False, "UNSAFE: dose > 500 mg", 0.0)

    async def rollback_state(
        self,
        magnitude: float,
        governance_signature: str | None = None,
        *,
        debit_id: str | None = None,
    ) -> None:
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
            params.get("latency_ms"),
            params.get("drawdown"),
            governor=self.governor,
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


def _classifier(*, narrow: bool = False, narrowers: list[Any] | None = None) -> ClassificationEngine:
    return ClassificationEngine(
        narrower_registry=NarrowerRegistry(narrowers=narrowers or [AmountNarrower()]),
        confidence_threshold=0.95,
        defer_enabled=True,
        narrow_enabled=narrow,
    )


def _build_governor(
    policy: RegoMirrorPolicy,
    cbf: ControlBarrierFunction,
    fiscal_tier: FiscalTierPlugin,
    classifier: ClassificationEngine,
) -> SymbolicGovernor:
    return make_governor(
        opa=policy,
        stpa_validator=STPAValidator(rules=UCA_RULES),
        classifier=classifier,
        domain_tiers=(
            CBFTierPlugin(cbf),
            fiscal_tier,
            CausalTierPlugin(RiskGatekeeper()),
            DoseBarrierTier(DoseLimitEngine()),
        ),
        safety_filter=cbf,
        magnitude_extractor=extract_field_magnitude("amount"),
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
    governor = _build_governor(policy, cbf, fiscal_tier, _classifier())
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


# ---------------------------------------------------------------------------
# D-H — an approval is bound to the barrier snapshot the human saw
# ---------------------------------------------------------------------------


async def test_s6_barrier_drift_after_approval_is_refused_as_context_drift(gw: Gateway) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)  # barrier preview: PASS
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")
    await gw.cbf_redis.set(_CASH_KEY, "5000.0")  # the cash barrier now refuses 20k

    result = await gw.execute(params, deferred_id)

    assert result.startswith("BLOCKED"), result
    assert "APPROVAL_CONTEXT_DRIFT" in result, result
    assert await gw.cash() == 5000.0
    assert await gw.fiscal.current_spend_usd() == 0.0  # fiscal commit rolled back
    assert await gw.seal_redis.dbsize() == 0  # no seal minted
    gw.actuate.assert_not_awaited()
    gw.refusals.assert_awaited()


async def test_approval_given_against_a_failing_preview_may_run_once_it_passes(gw: Gateway) -> None:
    # FAIL → PASS is not drift: the human approved knowing the barrier would
    # breach (e.g. accepting a narrow hint) and the committing run re-checks.
    params = trade(600_000.0)
    resp = await gw.validate(params)
    body = _body(resp)
    assert body["classification_meta"]["barrier_preview"] == "FAIL"
    await gw.approve(str(body["deferred_id"]), "urn:op:alice", "urn:op:bob")

    result = await gw.execute({**params, "amount": 15_000.0}, str(body["deferred_id"]))

    assert result.startswith("EXECUTED"), result
    assert await gw.fiscal.current_spend_usd() == 15_000.0


async def test_approve_stamps_the_token_snapshot_over_a_client_supplied_binding(gw: Gateway) -> None:
    deferred_id = await _require_approval(gw, trade(20_000.0))
    queue = DeferQueue(gw.defer_redis)
    await queue.approve(
        deferred_id,
        ApprovalRecord(
            approver_urn="urn:op:mallory",
            approved_at_utc=datetime.now(timezone.utc).isoformat(),
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"urn:op:mallory").hexdigest(),
            approved_barrier_preview="FAIL",  # forged: the server decides this
        ),
    )

    token = await queue.get(deferred_id)

    assert token is not None
    assert [a.approved_barrier_preview for a in token.approvals] == ["PASS"]


async def test_consume_refuses_an_approval_bound_to_another_snapshot(gw: Gateway) -> None:
    params = trade(20_000.0)
    deferred_id = await _require_approval(gw, params)
    await gw.approve(deferred_id, "urn:op:alice", "urn:op:bob")
    key = f"DEFER:{deferred_id}"
    stored = json.loads(await gw.defer_redis.hget(key, "token"))
    stored["approvals"][0]["approved_barrier_preview"] = "FAIL"
    await gw.defer_redis.hset(key, "token", json.dumps(stored))

    result = await gw.execute(params, deferred_id)

    assert result.startswith("BLOCKED"), result
    await _assert_nothing_committed(gw)
    assert await gw.defer_redis.hget(key, "status") == "RESOLVED"  # not consumed


@pytest.mark.parametrize("snapshot", ["MAYBE", "", 7])
async def test_unparseable_approved_snapshot_is_refused_before_any_commit(gw: Gateway, snapshot: Any) -> None:
    with pytest.raises(GovernanceError) as refused:
        await gw.governor.revalidate_post_hitl(
            "execute_trade", trade(500.0), approved_barrier_preview=snapshot
        )
    assert "APPROVAL_CONTEXT_DRIFT" in str(refused.value)
    await _assert_nothing_committed(gw)


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
# Phase 1: conditional FTRA, provenance codes, claim-by-cost, structural POST_HITL
# ---------------------------------------------------------------------------


async def test_s1a_small_trade_allowed_then_committed_exactly_once(gw: Gateway) -> None:
    params = trade(500.0, role="junior")
    body = _body(await gw.validate(params))
    assert body["verdict"] == GovernanceDecision.ALLOW
    assert "seal" not in body
    await _assert_nothing_committed(gw)

    assert (await gw.execute(params)).startswith("EXECUTED")
    assert await gw.fiscal.current_spend_usd() == 500.0


async def test_s1b_opa_manual_review_alone_requires_approval(gw: Gateway) -> None:
    resp = await gw.validate(trade(7_500.0, role="junior"))
    body = _body(resp)
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["classification_reason"] == "opa_manual_review"
    assert [v for v in body["violations"] if "FTRA" in str(v)] == []


async def test_s1_require_approval_names_ftra_provenance(gw: Gateway) -> None:
    body = _body(await gw.validate(trade(20_000.0)))
    assert any("FTRA_REGISTERED_IRREVERSIBLE" in str(v) for v in body["violations"])


async def test_s12_unregistered_action_names_its_provenance(gw: Gateway) -> None:
    body = _body(await _unregistered(gw))
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert any("FTRA_UNREGISTERED_ACTION" in str(v) for v in body["violations"])


async def test_s13_bounded_trade_is_claimed_by_the_cash_barrier(gw: Gateway) -> None:
    await gw.cbf_redis.set(_CASH_KEY, "1000.0")
    resp = await gw.validate(trade(3_000.0), action="execute_trade_bounded")
    assert any("cbf" in str(v).lower() for v in _body(resp).get("violations", []))


async def test_s11_post_hitl_reruns_the_dose_barrier(gw: Gateway) -> None:
    params = {"dose_mg": 600, "trader_role": "senior", "amount": 0.0}
    with pytest.raises(GovernanceError) as refused:
        await gw.governor.revalidate_post_hitl("administer_medication", params, approved_barrier_preview=None)
    assert any("DOSE_BARRIER_VIOLATED" in v for v in refused.value.violations)


# ---------------------------------------------------------------------------
# Phase 2: phase-2 barriers previewed (never committed) before human approval
# ---------------------------------------------------------------------------


async def test_s1_clean_barrier_preview_is_recorded_for_the_reviewer(gw: Gateway) -> None:
    body = _body(await gw.validate(trade(20_000.0)))
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["classification_meta"]["barrier_preview"] == "PASS"
    assert body["classification_meta"]["barrier_preview_violations"] == []
    token = await DeferQueue(gw.defer_redis).get(body["deferred_id"])
    assert token is not None and token.opa_input_snapshot["barrier_preview"] == "PASS"
    await _assert_nothing_committed(gw)


async def test_s11_preview_surfaces_the_dose_barrier(gw: Gateway) -> None:
    # FTRA: unregistered here → HITL; OPA allows the senior role. The HARD
    # dose-barrier preview then denies before any token is parked.
    params = {"dose_mg": 600, "confidence": 0.99, "trader_role": "senior", "amount": 0.0}
    resp = await gw.validate(params, action="administer_medication")
    assert resp.status_code == 403, resp.text
    assert any("DOSE_BARRIER_VIOLATED" in str(v) for v in resp.json()["violations"])
    assert await gw.parked_tokens() == []
    await _assert_nothing_committed(gw)


async def test_s5_fiscal_breach_surfaces_before_human_review(gw: Gateway) -> None:
    # OPA MANUAL_REVIEW + FTRA out of envelope: approval is pending, so the
    # fiscal barrier is previewed. Its breach is NARROWABLE, not HARD (D-A):
    # the request still goes to a human, who is told it would breach the cap.
    resp = await gw.validate(trade(600_000.0))
    assert resp.status_code == 200, resp.text
    body = _body(resp)
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["deferred_id"]
    assert any("FISCAL_LIMIT_EXCEEDED" in str(v) for v in body["violations"])
    meta = body["classification_meta"]
    assert meta["barrier_preview"] == "FAIL"
    assert [v["code"] for v in meta["barrier_preview_violations"]] == ["FISCAL_LIMIT_EXCEEDED"]
    await _assert_nothing_committed(gw)


async def test_s10_autonomous_trade_is_narrowed_to_the_remaining_cap(gw: Gateway) -> None:
    gw.governor = _build_governor(gw.policy, gw.cbf, gw.fiscal_tier, _classifier(narrow=True))
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)
    result = await gw.execute(trade(4_000.0))
    assert result.startswith("EXECUTED: AAPL x 3000.0"), result
    assert await gw.fiscal.current_spend_usd() == DAILY_CAP_USD
    assert await _receipts(gw) == []  # the narrow receipt was fetched and burned


# ---------------------------------------------------------------------------
# Committing-path NARROW (govern): re-run sealed on clamped params + receipt.
# A fixed-clamp stub narrower lets these tests propose params that do or do
# not fit, independently of the bound the fiscal tier reports.
# ---------------------------------------------------------------------------


class HeadroomNarrower:
    """Clamps a fiscal breach to a fixed amount the test knows fits (or not)."""

    def __init__(self, clamp_to: float) -> None:
        self.clamp_to = clamp_to

    def can_narrow(self, violation: Any, action: str, params: dict[str, Any]) -> bool:
        return violation.code == "FISCAL_LIMIT_EXCEEDED" and float(params["amount"]) > self.clamp_to

    def narrow(self, violation: Any, action: str, params: dict[str, Any]) -> NarrowingResult:
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": self.clamp_to},
            constraints_applied=[f"amount <= {self.clamp_to}"],
            narrowing_reason="clamped to the remaining daily cap",
        )


def _narrowing(gw: Gateway, clamp_to: float) -> None:
    gw.governor = _build_governor(
        gw.policy, gw.cbf, gw.fiscal_tier, _classifier(narrow=True, narrowers=[HeadroomNarrower(clamp_to)])
    )


async def _receipts(gw: Gateway) -> list[Any]:
    return await gw.seal_redis.keys("narrow:receipt:*")


async def test_committing_run_seals_and_executes_the_narrowed_trade(gw: Gateway) -> None:
    _narrowing(gw, 3_000.0)
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)

    result = await gw.execute(trade(4_000.0))

    assert result.startswith("EXECUTED: AAPL x 3000.0"), result
    assert await gw.fiscal.current_spend_usd() == DAILY_CAP_USD
    assert await gw.cash() == OPENING_CASH - 3_000.0
    assert gw.actuate.await_args.args[0].params["amount"] == 3_000.0
    assert await _receipts(gw) == []  # fetched and burned


async def test_narrowed_params_that_still_breach_are_denied_and_commit_nothing(gw: Gateway) -> None:
    _narrowing(gw, 3_500.0)  # still over the $3,000 headroom: the re-run refuses
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)

    assert (await gw.execute(trade(4_000.0))).startswith("BLOCKED")
    assert await gw.fiscal.current_spend_usd() == 497_000.0
    assert await gw.cash() == OPENING_CASH
    assert await _receipts(gw) == []
    gw.actuate.assert_not_awaited()


async def test_undeliverable_narrow_receipt_rolls_the_commits_back(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    _narrowing(gw, 3_000.0)
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)

    async def _down(*_: Any, **__: Any) -> None:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(gw.seal_redis, "setex", _down)
    assert (await gw.execute(trade(4_000.0))).startswith("BLOCKED")
    assert await gw.fiscal.current_spend_usd() == 497_000.0
    assert await gw.cash() == OPENING_CASH
    gw.actuate.assert_not_awaited()


async def test_committing_run_without_narrowing_enabled_denies(gw: Gateway) -> None:
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)
    assert (await gw.execute(trade(4_000.0))).startswith("BLOCKED")
    assert await gw.fiscal.current_spend_usd() == 497_000.0
    assert await _receipts(gw) == []


# ---------------------------------------------------------------------------
# Phase 3: tiers report how much they would admit (Violation.bound)
# ---------------------------------------------------------------------------


async def test_s10_validate_offers_the_remaining_cap_as_a_narrow_candidate(gw: Gateway) -> None:
    gw.governor = _build_governor(gw.policy, gw.cbf, gw.fiscal_tier, _classifier(narrow=True))
    governance_app.state.governor = gw.governor
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=497_000.0)

    body = _body(await gw.validate(trade(4_000.0)))

    assert body["verdict"] == GovernanceDecision.NARROW
    assert body["narrowed_params"]["amount"] == 3_000.0
    assert [v["bound"] for v in body["violations"]] == [3_000.0]
    assert await gw.fiscal.current_spend_usd() == 497_000.0  # nothing reserved
    gw.actuate.assert_not_awaited()


def _hinting(gw: Gateway, narrowers: list[Any] | None = None) -> None:
    gw.governor = _build_governor(
        gw.policy, gw.cbf, gw.fiscal_tier, _classifier(narrow=True, narrowers=narrowers)
    )
    governance_app.state.governor = gw.governor


async def test_require_approval_carries_a_reverified_narrow_hint(gw: Gateway) -> None:
    # FTRA out of envelope (HITL) + fiscal preview over the cap (NARROWABLE,
    # bound = $10,000 headroom): the reviewer is offered the trade that fits.
    _hinting(gw)
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=490_000.0)
    params = trade(20_000.0)

    body = _body(await gw.validate(params))

    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["narrowed_params"] == {**params, "amount": 10_000.0}
    meta = body["classification_meta"]
    assert [v["bound"] for v in meta["barrier_preview_violations"]] == [10_000.0]
    token = await DeferQueue(gw.defer_redis).get(body["deferred_id"])
    assert token is not None
    assert token.opa_input_snapshot["narrow_hint"]["narrowed_params"]["amount"] == 10_000.0
    assert await gw.fiscal.current_spend_usd() == 490_000.0

    # Approving the hinted (shrunk) trade executes it in the committing run.
    await gw.approve(body["deferred_id"], "urn:op:alice", "urn:op:bob")
    result = await gw.execute(body["narrowed_params"], body["deferred_id"])
    assert result.startswith("EXECUTED: AAPL x 10000.0"), result
    assert await gw.fiscal.current_spend_usd() == DAILY_CAP_USD


async def test_require_approval_drops_a_hint_that_still_breaches(gw: Gateway) -> None:
    _hinting(gw, narrowers=[HeadroomNarrower(15_000.0)])  # over the $10,000 headroom
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=490_000.0)

    body = _body(await gw.validate(trade(20_000.0)))

    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["narrowed_params"] is None
    assert "narrow_hint" not in body["classification_meta"]
    token = await DeferQueue(gw.defer_redis).get(body["deferred_id"])
    assert token is not None and token.opa_input_snapshot["narrow_hint"] is None


async def test_require_approval_offers_no_hint_when_narrowing_is_disabled(gw: Gateway) -> None:
    await gw.fiscal.reserve(agent_id="other-desk", amount_usd=490_000.0)
    body = _body(await gw.validate(trade(20_000.0)))
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    assert body["narrowed_params"] is None


# ---------------------------------------------------------------------------
# §0.5 mutation self-checks: each breaks one mechanism and observes a scenario fail
# ---------------------------------------------------------------------------


async def test_mutation_without_the_fiscal_bound_s10_is_not_narrowed_to_the_cap(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _unknown(self: FiscalLimitGuard) -> None:
        return None

    monkeypatch.setattr(FiscalLimitGuard, "headroom_usd", _unknown)
    with pytest.raises(AssertionError):
        await test_s10_autonomous_trade_is_narrowed_to_the_remaining_cap(gw)


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


async def test_mutation_skipping_the_pending_approval_preview_hides_the_breach(
    gw: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _no_preview(*_: Any, **__: Any) -> tuple[list[Any], list[Any]]:
        return [], []

    monkeypatch.setattr(pipeline_mod, "_preview_mutating", _no_preview)
    with pytest.raises(AssertionError):
        await test_s5_fiscal_breach_surfaces_before_human_review(gw)
