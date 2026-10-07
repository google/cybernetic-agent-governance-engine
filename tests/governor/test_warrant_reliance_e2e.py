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

"""Warrant reliance, end to end (VEIP Phase 2, PR 6).

The governor is built by the composition root (``bootstrap_governor``: the
real finance plugin, the active region's thresholds and jurisdiction, the
``CAGE_WARRANT_SOURCE`` adapter). Requests enter through the gateway ASGI app
(``POST /governance/validate-action`` behind workload identity) and the trade
tool (``execute_trade_action``: commit, seal, verify-and-consume, actuate).
Evidence lands in a real hash-chained ``EvidenceStreamSink``; deferrals park
in a real ``DeferQueue``. Everything below the HTTP surface is CAGE code.

What this does **not** exercise: the partner wire. Provider 05 (VEIP) has no
live endpoint, so the warrant source is the seeded
``Provider05WarrantSource`` holding the VEIP v0.1 vectors verbatim
(``tests/integrations/provider_05/test_provider_05_veip_vectors.py``). This is
not the Over-the-Wire conformance test AGENTS.md requires of Tier 1 adapters;
that test cannot exist until VEIP publishes a sandbox endpoint.

Doubles (no reliance property is observed through them): OPA returns a fixed
verdict, the EU FRIA provider admits, the broker actuator records the
clearance, and Redis is fakeredis. Clocks are injected through
``assemble_governor(warrant_clock=...)`` and advanced by hand; nothing sleeps.

Matrix (``veip_phase2_recommendation.md`` §6):

* A — EU_ECB, VEC-001, confidence ≥ 0.97: ALLOW; the seal's evidence record
  carries the ELIGIBLE reliance record and verifies; the envelope carries an
  UNVERIFIED ``WARRANT`` attestation; the trade executes once.
* B/C — EU_ECB, VEC-002…006, MISSING, STALE: DEFER ``WARRANT_INELIGIBLE``,
  reliance in the token and the deferral evidence, never DENY, nothing
  sealed or actuated.
* No masking — HARD finding plus warrant failure: DENY, reliance in the
  refusal receipt.
* POST_HITL — warrant revoked after approval: refused, no seal.
* EU / APAC floors live; US unchanged; assembly refuses an ungateable EU
  governor.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount

import src.gateway.governance.routing_seal as rs
from src.cage_finance.tiers.trade_confidence_tier import TRADE_CONFIDENCE_NORM_ID
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance import constants
from src.gateway.governance import defer_queue as defer_queue_mod
from src.gateway.governance.contracts import PluginContribution
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import ApprovalRecord, DeferQueue, DeferReason
from src.gateway.governance.evidence import stream as evidence_stream
from src.gateway.governance.evidence.stream import verify_record
from src.gateway.governance.governance_envelope import unwrap_governance_envelope
from src.gateway.governance.governor.assembly import GovernorAssemblyError
from src.gateway.governance.governor.bootstrap import bootstrap_governor
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jurisdiction import eu_ai_act
from src.gateway.governance.seams.actuation import ActuationReceipt
from src.gateway.governance.seams.normative import ValidationResult
from src.gateway.governance.warrant import Warrant, WarrantClock
from src.gateway.governance.warrant.source_factory import (
    WARRANT_SOURCE_ENV,
    warrant_source_from_env,
)
from src.gateway.server import governance_middleware
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.workload_identity import (
    CLIENT_IDENTITY_HEADER,
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)
from src.integrations.provider_05 import Provider05WarrantSource
from tests.integrations.provider_05.test_provider_05_veip_vectors import (
    SHARED_WARRANT,
    VEIP_ACTIVE_DIGEST,
    VEIP_REVOKED_DIGEST,
    VEIP_TAMPERED_DIGEST,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

ADVISOR = (
    "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
#: The VEIP v0.1 shared ``evaluation_timestamp``.
VEIP_NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
_CASH_KEY = "safety:current_cash"
_OPENING_CASH = 1_000_000.0

#: VEC-002: the shared warrant, revoked (VEIP-published digest).
VEC_002_REVOKED: dict[str, Any] = {
    **SHARED_WARRANT,
    "status": "REVOKED",
    "revocation_ref": "Emergency Risk Notice #912",
    "digest": VEIP_REVOKED_DIGEST,
}
#: VEC-006: the shared warrant with its declared digest's last nibble flipped.
VEC_006_TAMPERED: dict[str, Any] = {**SHARED_WARRANT, "digest": VEIP_TAMPERED_DIGEST}


def _vec(fields: dict[str, Any]) -> Warrant:
    """A vector warrant exactly as VEIP published it (declared digest kept)."""
    return Warrant(**fields)


# ── Doubles ──────────────────────────────────────────────────────────────────


class _Clock:
    """Monotonic and wall clocks advanced together, by hand."""

    def __init__(self, wall: datetime = VEIP_NOW) -> None:
        self.mono = 1_000.0
        self.wall = wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += timedelta(seconds=seconds)

    def warrant_clock(self) -> WarrantClock:
        return WarrantClock(monotonic=lambda: self.mono, wall_clock=lambda: self.wall)


class _Opa:
    """OPA double: a fixed verdict for every request; records each input."""

    def __init__(self, verdict: str = "ALLOW") -> None:
        self.verdict = verdict
        self.calls: list[dict[str, Any]] = []

    async def evaluate_policy(self, payload: dict[str, Any]) -> str:
        self.calls.append(payload)
        return self.verdict


class _AdmittingFria:
    """EU FRIA normative provider double: every assessment is admitted."""

    async def fetch_baseline(self, region: str) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(admitted=True)

    async def submit_evidence(self, receipt: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError


def _eu_jurisdiction() -> Any:
    # FRIA freshness is judged on the FRIA tier's own (process) clock.
    assessed = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    return eu_ai_act.contribution(
        provider=_AdmittingFria(),  # type: ignore[arg-type]
        assessment_lookup=lambda action: {"assessed_at": assessed},
    )


# ── The stack under test ─────────────────────────────────────────────────────


@dataclasses.dataclass
class Stack:
    governor: SymbolicGovernor
    source: Provider05WarrantSource
    clock: _Clock
    opa: _Opa
    http: httpx.AsyncClient
    actuate: AsyncMock
    refusals: AsyncMock
    defer_redis: Any
    seal_redis: Any
    evidence_redis: Any
    stream_key: str

    async def validate(
        self, params: dict[str, Any], *, action: str = "execute_trade"
    ) -> httpx.Response:
        return await self.http.post(
            "/governance/validate-action",
            json={"action": action, "params": params},
            headers={CLIENT_IDENTITY_HEADER: ADVISOR},
        )

    async def execute(
        self, params: dict[str, Any], deferred_id: str | None = None
    ) -> str:
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
            params["side"],
            governor=self.governor,
        )

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

    async def chain(self) -> list[tuple[dict[str, Any], str]]:
        """Every evidence record with its predecessor hash; the chain verifies."""
        entries = [f for _id, f in await self.evidence_redis.xrange(self.stream_key)]
        out, prev = [], ""
        for fields in entries:
            assert verify_record(fields, prev_hash=prev).valid
            out.append((fields, prev))
            prev = fields["record_hash"]
        return out

    async def records(self, event_type: str) -> list[dict[str, Any]]:
        return [f for f, _ in await self.chain() if f["event_type"] == event_type]

    async def assert_nothing_actuated(self) -> None:
        self.actuate.assert_not_awaited()
        assert await self.records("GOVERNANCE_DECISION") == []  # no seal minted
        assert await self.seal_redis.dbsize() == 0  # no seal nonce burned


def trade(confidence: float = 0.98, **extra: Any) -> dict[str, Any]:
    return {
        "symbol": "AAPL",
        "amount": 500.0,
        "currency": "USD",
        "confidence": confidence,
        "trader_id": "trader-7",
        "trader_role": "junior",
        "side": "buy",
        **extra,
    }


def _body(resp: httpx.Response) -> dict[str, Any]:
    return unwrap_governance_envelope(resp.json())


def _payload(fields: dict[str, Any]) -> dict[str, Any]:
    return json.loads(fields["payload_json"])


StackFactory = Callable[..., Awaitable[Stack]]


@pytest.fixture
async def build(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[StackFactory]:
    """Build a gateway around ``bootstrap_governor`` for the pinned region."""
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")  # HMAC seals (dev)
    monkeypatch.setenv("CAGE_DOMAIN", "finance")
    monkeypatch.setenv(WARRANT_SOURCE_ENV, "provider_05")
    monkeypatch.delenv("CAGE_DEFER_ENABLED", raising=False)
    monkeypatch.setattr(constants, "_OVERLAY_DIRS", list(constants._OVERLAY_DIRS))

    cbf_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    fiscal_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    defer_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    seal_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    evidence_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await cbf_redis.set(_CASH_KEY, str(_OPENING_CASH))

    raw_cbf = MagicMock()
    raw_cbf.get_raw_client.return_value = cbf_redis
    monkeypatch.setattr(
        "src.gateway.governance.safety.cbf_engine.redis_client", raw_cbf
    )
    monkeypatch.setattr(
        "src.gateway.governance.safety.cbf_engine.sync_redis_client",
        fakeredis.FakeRedis(decode_responses=True),
    )
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.redis_client", seal_redis
    )
    # The causal tier caches its world-model verdict in (sync) Redis.
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.sync_redis_client",
        fakeredis.FakeRedis(decode_responses=True),
    )

    @asynccontextmanager
    async def _queue() -> AsyncIterator[DeferQueue]:
        yield DeferQueue(defer_redis)

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _queue)

    sink = evidence_stream.EvidenceStreamSink()
    with monkeypatch.context() as m:
        m.setattr(
            "src.gateway.infrastructure.redis_client.build_async_redis",
            lambda *a, **k: evidence_redis,
        )
        m.setattr("redis.asyncio.from_url", lambda *a, **k: evidence_redis)
        await sink.start()
    monkeypatch.setattr(evidence_stream, "_evidence_sink", sink)

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
    governance_middleware._validate_action_rate_buckets.clear()

    clients: list[httpx.AsyncClient] = []

    async def _build(
        *,
        seed: Warrant | None = None,
        opa_verdict: str = "ALLOW",
        clock: _Clock | None = None,
        region: str = "EU_ECB",
    ) -> Stack:
        # The adapter CAGE_WARRANT_SOURCE names, seeded with the VEIP vector.
        source = warrant_source_from_env()
        assert isinstance(source, Provider05WarrantSource)
        if seed is not None:
            source.seed(seed)
        clock = clock or _Clock()
        opa = _Opa(opa_verdict)
        with monkeypatch.context() as m:
            # FiscalLimitGuard.from_env() connects to REDIS_URL at assembly.
            m.setattr("redis.asyncio.from_url", lambda *a, **k: fiscal_redis)
            governor = bootstrap_governor(
                opa=opa,
                warrant_source=source,
                warrant_clock=clock.warrant_clock(),
                **({"jurisdiction": _eu_jurisdiction()} if region == "EU_ECB" else {}),
            )
        governance_app.state.governor = governor
        root = WorkloadIdentityMiddleware(
            Starlette(routes=[Mount("/governance", app=governance_app)]),
            IdentityPolicy(trusted=frozenset({ADVISOR})),
        )
        http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=root), base_url="http://gateway"
        )
        clients.append(http)
        return Stack(
            governor=governor,
            source=source,
            clock=clock,
            opa=opa,
            http=http,
            actuate=actuate,
            refusals=refusals,
            defer_redis=defer_redis,
            seal_redis=seal_redis,
            evidence_redis=evidence_redis,
            stream_key=sink._stream_key,
        )

    yield _build
    for http in clients:
        await http.aclose()
    governance_app.state.governor = None
    await sink.stop()


# ── Composition root ─────────────────────────────────────────────────────────


@pytest.mark.eu_ecb
async def test_bootstrap_wires_the_configured_source_behind_the_60s_cache(
    build: StackFactory,
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))
    (stage,) = [s for s in stack.governor.stages if isinstance(s, WarrantStage)]
    assert stage.source_name == "provider_05_warrant"
    assert stage.cache.max_age_seconds == 60.0
    (binding,) = stage.bindings
    assert binding.norm_id == TRADE_CONFIDENCE_NORM_ID
    assert binding.value == 0.97
    assert binding.governing_version == "cage-policy-2.1.0"


@pytest.mark.eu_ecb
def test_bootstrap_alone_resolves_provider_05_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No override: bootstrap_governor reads CAGE_WARRANT_SOURCE itself."""
    monkeypatch.setenv(WARRANT_SOURCE_ENV, "provider_05")
    monkeypatch.setattr(constants, "_OVERLAY_DIRS", list(constants._OVERLAY_DIRS))
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: MagicMock())
    governor = bootstrap_governor(opa=_Opa(), jurisdiction=_eu_jurisdiction())
    (stage,) = [s for s in governor.stages if isinstance(s, WarrantStage)]
    assert stage.source_name == "provider_05_warrant"


@pytest.mark.eu_ecb
@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({WARRANT_SOURCE_ENV: ""}, "warrant"),
        ({"CAGE_DEFER_ENABLED": "false"}, "(?i)defer"),
    ],
    ids=["no_source", "defer_disabled"],
)
def test_bootstrap_refuses_an_eu_governor_that_cannot_gate_its_warranted_norm(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], match: str
) -> None:
    monkeypatch.setenv(WARRANT_SOURCE_ENV, "provider_05")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(constants, "_OVERLAY_DIRS", list(constants._OVERLAY_DIRS))
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: MagicMock())
    with pytest.raises(GovernorAssemblyError, match=match):
        bootstrap_governor(opa=_Opa(), jurisdiction=_eu_jurisdiction())


def test_plugins_have_no_slot_to_supply_a_warrant() -> None:
    """Warrants enter only through the composition root's WarrantSource."""
    fields = {f.name for f in dataclasses.fields(PluginContribution)}
    assert not any("warrant" in name or "reliance" in name for name in fields)


# ── A: eligible warrant → ALLOW, sealed reliance, executed once ─────────────


@pytest.mark.eu_ecb
async def test_a_active_vec_001_allows_seals_the_reliance_and_executes_once(
    build: StackFactory,
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))

    # Preview through the gateway: ALLOW in a signed envelope that attests
    # the warrant, UNVERIFIED (issuer signatures are VEIP v0.2).
    resp = await stack.validate(trade(0.98))
    assert resp.status_code == 200, resp.text
    envelope = resp.json()
    body = unwrap_governance_envelope(envelope)
    assert body["verdict"] == GovernanceDecision.ALLOW
    (attestation,) = envelope["external_attestations"]
    assert attestation["type"] == "WARRANT"
    assert attestation["status"] == "UNVERIFIED"
    assert attestation["provider_name"] == "provider_05_warrant"
    assert attestation["warrant_digest"] == VEIP_ACTIVE_DIGEST
    assert attestation["reliance_status"] == "ELIGIBLE"
    assert await stack.records("GOVERNANCE_DECISION") == []  # previews never seal

    # Commit through the trade tool: one seal, consumed, one actuation.
    result = await stack.execute(trade(0.98))
    assert result.startswith("EXECUTED: AAPL x 500.0"), result
    stack.actuate.assert_awaited_once()
    clearance = stack.actuate.await_args.args[0]

    # The seal commits to an evidence record carrying the ELIGIBLE reliance.
    ((decision, prev),) = [
        (f, prev)
        for f, prev in await stack.chain()
        if f["event_type"] == "GOVERNANCE_DECISION"
    ]
    (reliance,) = _payload(decision)["reliance"]
    assert reliance["reliance_status"] == "ELIGIBLE"
    assert reliance["warrant_id"] == "warrant-veip-2026-001"
    assert reliance["warrant_digest"] == VEIP_ACTIVE_DIGEST
    assert reliance["warrant_status"] == "ACTIVE"
    assert reliance["governing_version"] == "cage-policy-2.1.0"
    assert reliance["provider_name"] == "provider_05_warrant"
    assert reliance["verification_status"] == "UNVERIFIED"
    assert reliance["evaluated_at"] == VEIP_NOW.isoformat()
    assert rs.verify_seal_against_evidence(
        clearance.routing_seal,
        "execute_trade",
        clearance.params,
        decision,
        prev_hash=prev,
    )

    # Single use: the consumed seal cannot authorise a second actuation.
    with pytest.raises(rs.SymbolicGovernorViolation):
        await rs.verify_and_consume_seal(
            clearance.routing_seal, "execute_trade", clearance.params
        )


@pytest.mark.eu_ecb
async def test_a_reliance_is_fetched_once_per_window_across_preview_and_commit(
    build: StackFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))
    fetches: list[str] = []
    fetch = stack.source.fetch

    async def _counting(norm_id: str) -> Warrant | None:
        fetches.append(norm_id)
        return await fetch(norm_id)

    monkeypatch.setattr(stack.source, "fetch", _counting)
    assert _body(await stack.validate(trade()))["verdict"] == GovernanceDecision.ALLOW
    stack.clock.advance(59.0)
    assert (await stack.execute(trade())).startswith("EXECUTED")
    assert fetches == [TRADE_CONFIDENCE_NORM_ID]


# ── EU floor: 0.97 is enforced, by the confidence semantics ─────────────────


@pytest.mark.eu_ecb
async def test_eu_floor_live_below_097_is_not_allowed_despite_an_eligible_warrant(
    build: StackFactory,
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))
    body = _body(await stack.validate(trade(0.96)))

    assert body["verdict"] != GovernanceDecision.ALLOW
    assert any("TRADE_CONFIDENCE_BELOW_FLOOR" in str(v) for v in body["violations"])
    assert body.get("defer_reason") != DeferReason.WARRANT_INELIGIBLE.value
    (reliance,) = body["reliance"]
    assert reliance["reliance_status"] == "ELIGIBLE"  # the warrant is not the issue
    assert (await stack.execute(trade(0.96))).startswith("BLOCKED")
    await stack.assert_nothing_actuated()


# ── B/C: every ineligible standing → DEFER, never DENY, nothing actuated ────


_INELIGIBLE = [
    pytest.param(_vec(VEC_002_REVOKED), {}, "INELIGIBLE_REVOKED", id="VEC-002-REVOKED"),
    pytest.param(
        _vec(SHARED_WARRANT),
        {"wall": datetime(2027, 1, 15, tzinfo=timezone.utc)},
        "INELIGIBLE_EXPIRED",
        id="VEC-003-EXPIRED",
    ),
    # VEC-004 moves the request out of the warrant's scope (the action
    # dimension, pinned at the verifier by the vector suite). End to end the
    # request stays an EU_ECB execute_trade, so the warrant moves instead: an
    # issuer warrant scoped to another jurisdiction.
    pytest.param(
        Warrant.issue(
            **{
                **SHARED_WARRANT,
                "scope": {**SHARED_WARRANT["scope"], "jurisdictions": ["APAC_MAS"]},
            }
        ),
        {},
        "INELIGIBLE_OUT_OF_SCOPE",
        id="VEC-004-OUT-OF-SCOPE",
    ),
    # VEC-005: the warrant was issued under another policy version than the
    # one the EU binding governs under (cage-policy-2.1.0).
    pytest.param(
        Warrant.issue(**{**SHARED_WARRANT, "governing_version": "cage-policy-9.9.9"}),
        {},
        "INELIGIBLE_VERSION_MISMATCH",
        id="VEC-005-VERSION-MISMATCH",
    ),
    pytest.param(
        _vec(VEC_006_TAMPERED), {}, "INELIGIBLE_UNRESOLVED", id="VEC-006-TAMPERED"
    ),
    pytest.param(None, {}, "INELIGIBLE_MISSING", id="MISSING"),
]


@pytest.mark.eu_ecb
@pytest.mark.parametrize(("seed", "clock_kw", "status"), _INELIGIBLE)
async def test_bc_ineligible_warrant_defers_with_reliance_and_actuates_nothing(
    build: StackFactory,
    seed: Warrant | None,
    clock_kw: dict[str, Any],
    status: str,
) -> None:
    stack = await build(seed=seed, clock=_Clock(**clock_kw))

    resp = await stack.validate(trade(0.98))
    assert resp.status_code == 200, resp.text
    body = _body(resp)
    assert body["verdict"] == GovernanceDecision.DEFER  # never DENY
    assert body["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    assert "seal" not in body
    assert any(f"RELIANCE_{status}" in str(v) for v in body["violations"])
    (reliance,) = body["reliance"]
    assert reliance["reliance_status"] == status
    assert reliance["verification_status"] == "UNVERIFIED"
    assert reliance["provider_name"] == "provider_05_warrant"
    if seed is not None:
        assert reliance["warrant_digest"] == seed.digest

    # Refusals are primary evidence: the parked token and the hash-chained
    # deferral event both carry the same reliance record.
    token = await DeferQueue(stack.defer_redis).get(body["defer_token"])
    assert token is not None
    assert token.defer_reason is DeferReason.WARRANT_INELIGIBLE
    assert token.opa_input_snapshot["reliance"] == [reliance]
    (deferral,) = await stack.records("GOVERNANCE_DEFERRAL")
    assert _payload(deferral)["reliance"] == [reliance]
    assert await stack.records("GOVERNANCE_REFUSAL") == []

    assert (await stack.execute(trade(0.98))).startswith("BLOCKED")  # commit too
    await stack.assert_nothing_actuated()


@pytest.mark.eu_ecb
async def test_c_stale_state_past_60s_with_a_failing_source_defers(
    build: StackFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))
    assert _body(await stack.validate(trade()))["verdict"] == GovernanceDecision.ALLOW

    async def _down(norm_id: str) -> Warrant | None:
        raise ConnectionError("VEIP warrant endpoint unreachable")

    monkeypatch.setattr(stack.source, "fetch", _down)
    stack.clock.advance(59.0)  # inside the window: the cached state still holds
    assert _body(await stack.validate(trade()))["verdict"] == GovernanceDecision.ALLOW
    stack.clock.advance(2.0)  # 61 s since receipt; the re-fetch fails

    body = _body(await stack.validate(trade()))
    assert body["verdict"] == GovernanceDecision.DEFER
    assert body["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    (reliance,) = body["reliance"]
    assert reliance["reliance_status"] == "INELIGIBLE_STALE"
    assert reliance["age_seconds"] == "61.000"
    assert reliance["max_age_seconds"] == "60.000"
    assert reliance["warrant_digest"] == VEIP_ACTIVE_DIGEST  # what went stale
    assert (await stack.execute(trade())).startswith("BLOCKED")
    await stack.assert_nothing_actuated()


# ── No masking: an independent HARD finding still DENIES ────────────────────


@pytest.mark.eu_ecb
async def test_hard_domain_violation_with_a_revoked_warrant_denies_with_reliance(
    build: StackFactory,
) -> None:
    """A malformed bounded trade (HARD in the bounding tier) under VEC-002."""
    stack = await build(seed=_vec(VEC_002_REVOKED))

    resp = await stack.validate(trade(), action="execute_trade_bounded")
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["verdict"] == "DENIED"  # not DEFER: the warrant masks nothing
    assert any("INVALID_REQUEST_PARAMS" in v for v in body["violations"])
    assert any("RELIANCE_INELIGIBLE_REVOKED" in v for v in body["violations"])
    (reliance,) = body["refusal_receipt"]["reliance"]
    assert reliance["reliance_status"] == "INELIGIBLE_REVOKED"
    assert reliance["warrant_digest"] == VEIP_REVOKED_DIGEST
    stack.refusals.assert_awaited_once()
    assert list(stack.refusals.await_args.kwargs["receipt"].reliance) == [reliance]
    (refusal,) = await stack.records("GOVERNANCE_REFUSAL")
    receipt = _payload(refusal)["receipt"]
    assert receipt["reliance"] == [reliance]
    assert receipt["proof_hash"] == body["proof_hash"]  # reliance is inside it
    assert await stack.records("GOVERNANCE_DEFERRAL") == []
    await stack.assert_nothing_actuated()


@pytest.mark.eu_ecb
async def test_kernel_hard_refusal_denies_before_the_warrant_is_consulted(
    build: StackFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPA DENY under VEC-002: DENY, never DEFER.

    The pipeline stops at the first HARD finding, and OPA runs before the
    warrant stage, so nothing was relied on and the receipt carries no
    reliance record (it never claims a warrant check that did not run).
    """
    stack = await build(seed=_vec(VEC_002_REVOKED), opa_verdict="DENY")
    fetches = await _never_fetched(stack, monkeypatch)

    resp = await stack.validate(trade())
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["verdict"] == "DENIED"
    assert body["refusal_receipt"].get("reliance", []) == []
    assert fetches == []
    assert await stack.records("GOVERNANCE_DEFERRAL") == []
    assert (await stack.execute(trade())).startswith("BLOCKED")
    await stack.assert_nothing_actuated()


# ── POST_HITL: a warrant revoked while the human decided ────────────────────


async def _approved_floor_breach(stack: Stack) -> str:
    """0.96 < 0.97 under an eligible warrant: a human approves the trade."""
    body = _body(await stack.validate(trade(0.96)))
    assert body["verdict"] == GovernanceDecision.REQUIRE_APPROVAL, body
    await stack.approve(body["deferred_id"], "urn:op:alice", "urn:op:bob")
    return str(body["deferred_id"])


@pytest.mark.eu_ecb
async def test_post_hitl_approval_executes_while_the_warrant_holds(
    build: StackFactory,
) -> None:
    """Control for the revocation case: the same approval, warrant unchanged."""
    stack = await build(seed=_vec(SHARED_WARRANT))
    deferred_id = await _approved_floor_breach(stack)
    stack.clock.advance(120.0)  # re-fetched after the window: still ACTIVE
    result = await stack.execute(trade(0.96), deferred_id)
    assert result.startswith("EXECUTED"), result
    stack.actuate.assert_awaited_once()


@pytest.mark.eu_ecb
async def test_post_hitl_revocation_after_approval_is_refused_without_a_seal(
    build: StackFactory,
) -> None:
    stack = await build(seed=_vec(SHARED_WARRANT))
    deferred_id = await _approved_floor_breach(stack)

    stack.source.seed(_vec(VEC_002_REVOKED))  # the issuer revokes ...
    stack.clock.advance(60.001)  # ... and the cached ACTIVE state expires

    result = await stack.execute(trade(0.96), deferred_id)
    assert result.startswith("BLOCKED"), result
    assert "RELIANCE_INELIGIBLE_REVOKED" in result
    await stack.assert_nothing_actuated()
    refusal = (await stack.records("GOVERNANCE_REFUSAL"))[-1]
    (reliance,) = _payload(refusal)["receipt"]["reliance"]
    assert reliance["reliance_status"] == "INELIGIBLE_REVOKED"
    assert reliance["warrant_digest"] == VEIP_REVOKED_DIGEST
    # The approval was spent: it cannot be replayed once the warrant returns.
    stack.source.seed(_vec(SHARED_WARRANT))
    stack.clock.advance(60.001)
    assert (await stack.execute(trade(0.96), deferred_id)).startswith("BLOCKED")
    await stack.assert_nothing_actuated()


# ── Unwarranted regions: floors live, warrant never consulted ───────────────


async def _never_fetched(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    fetches: list[str] = []

    async def _record(norm_id: str) -> Warrant | None:
        fetches.append(norm_id)
        return None

    monkeypatch.setattr(stack.source, "fetch", _record)
    return fetches


@pytest.mark.apac_mas
async def test_apac_floor_live_below_096_without_consulting_a_warrant(
    build: StackFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = await build(region="APAC_MAS")
    fetches = await _never_fetched(stack, monkeypatch)
    assert not any(isinstance(s, WarrantStage) for s in stack.governor.stages)

    body = _body(await stack.validate(trade(0.955)))
    assert body["verdict"] != GovernanceDecision.ALLOW
    assert any("TRADE_CONFIDENCE_BELOW_FLOOR" in str(v) for v in body["violations"])
    assert "reliance" not in body

    allowed = _body(await stack.validate(trade(0.965)))
    assert allowed["verdict"] == GovernanceDecision.ALLOW
    assert allowed.get("external_attestations") in (None, [])
    assert fetches == []


@pytest.mark.us_fed
async def test_us_fed_unchanged_095_clears_and_executes_without_a_warrant(
    build: StackFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = await build(region="US_FED")
    fetches = await _never_fetched(stack, monkeypatch)
    assert not any(isinstance(s, WarrantStage) for s in stack.governor.stages)

    body = _body(await stack.validate(trade(0.95)))
    assert body["verdict"] == GovernanceDecision.ALLOW
    assert "reliance" not in body
    assert (await stack.execute(trade(0.95))).startswith("EXECUTED")
    (decision,) = await stack.records("GOVERNANCE_DECISION")
    assert "reliance" not in _payload(decision)
    assert fetches == []
