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

"""Warrant reliance evidence binding (VEIP Phase 2, PR 4).

Invariants under test:

* ``SEAL_COMMITS_TO_RELIANCE`` — an ALLOW / NARROW seal's evidence record
  carries one reliance record per warranted norm the decision relied on, and
  the seal commits to it through ``record_hash``: changing any reliance field
  breaks seal verification, even when the record is re-hashed.
* ``REFUSALS_ARE_PRIMARY_EVIDENCE`` — a DEFER for ``WARRANT_INELIGIBLE``
  carries the same reliance record (``INELIGIBLE_*``) in its ``DeferToken``
  and in a hash-chained ``GOVERNANCE_DEFERRAL`` event; a DENY with a
  co-occurring warrant failure carries it inside the receipt's ``proof_hash``.
* ``ATTESTATION_UNVERIFIED`` — the envelope's ``WARRANT`` attestation and
  every reliance record are ``UNVERIFIED`` (issuer signatures are v0.2).
* ``UNWARRANTED_REGIONS_UNCHANGED`` — with no warranted norm (US_FED,
  APAC_MAS) no reliance record exists and the seal's evidence record is
  exactly what it was before.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import fakeredis
import fakeredis.aioredis
import pytest

import src.gateway.governance.routing_seal as rs
from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_CONFIDENCE_NORM_ID,
    TradeConfidenceTier,
)
from src.gateway.governance import defer_queue as defer_queue_module
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    NormBinding,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import DeferQueue, DeferReason
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.evidence.stream import EvidenceStreamSink, verify_record
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor import sealing as sealing_module
from src.gateway.governance.governor.assembly import DecisionFlags, assemble_governor
from src.gateway.governance.governor.errors import GovernanceDeferred, GovernanceError
from src.gateway.governance.governor.pipeline import (
    Profile,
    StageContext,
    resolve_claims,
)
from src.gateway.governance.governor.stages.opa import OpaStage
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.jurisdiction import resolve_jurisdiction
from src.gateway.governance.narrower import NarrowerRegistry, NarrowingResult
from src.gateway.governance.warrant import (
    RELIANCE_VERIFICATION_STATUS,
    RelianceRecord,
    RelianceStatus,
    StandingVerificationResult,
    WarrantCache,
)
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
_STREAM = "cage:test:warrant-evidence"
_RELIANCE_KEYS = {
    "norm_id",
    "warrant_id",
    "warrant_digest",
    "warrant_status",
    "reliance_status",
    "reason",
    "required_governing_version",
    "warrant_governing_version",
    "issuing_authority",
    "authority_basis",
    "revocation_ref",
    "residual_risk_ref",
    "attested_at",
    "observed_at",
    "age_seconds",
    "max_age_seconds",
    "provider_name",
    "verification_status",
}
#: The seal evidence record's fields before reliance binding existed.
_LEGACY_DECISION_KEYS = {
    "type",
    "controlId",
    "action",
    "params_hash",
    "timestamp_utc",
    "seal_ttl_s",
}

_BINDING = NormBinding(
    norm_id=TRADE_CONFIDENCE_NORM_ID,
    value=0.97,
    requires_warrant=True,
    actions=frozenset({"execute_trade", "execute_trade_bounded"}),
    governing_version=WARRANT_TEST_GOVERNING_VERSION,
)
_UNWARRANTED = NormBinding(
    norm_id=TRADE_CONFIDENCE_NORM_ID,
    value=0.95,
    requires_warrant=False,
    actions=frozenset({"execute_trade", "execute_trade_bounded"}),
)


def _trade(**overrides: Any) -> dict[str, Any]:
    return {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL", **overrides}


def _stage(
    source: StaticWarrantSource,
    jurisdiction: str = "EU_ECB",
    monotonic: Callable[[], float] = lambda: 0.0,
) -> WarrantStage:
    cache = WarrantCache(
        source, monotonic=monotonic, wall_clock=lambda: WARRANT_TEST_NOW
    )
    return WarrantStage(
        [_BINDING], cache, jurisdiction=jurisdiction, clock=lambda: WARRANT_TEST_NOW
    )


def _governor(
    source: StaticWarrantSource,
    *extra_tiers: Any,
    monotonic: Callable[[], float] = lambda: 0.0,
    **kwargs: Any,
) -> Any:
    """OPA + warrant gate + the warranted trade-confidence tier (no FTRA HITL)."""
    opa = allow_opa()
    return make_governor(
        opa=opa,
        core_stages=(OpaStage(opa), _stage(source, monotonic=monotonic)),
        domain_tiers=(TradeConfidenceTier(_BINDING), *extra_tiers),
        **kwargs,
    )


def _source_with(**overrides: Any) -> StaticWarrantSource:
    return StaticWarrantSource(
        {TRADE_CONFIDENCE_NORM_ID: issue_test_warrant(**overrides)}
    )


# ── Fixtures: a real hash-chained evidence stream and seal index ────────────


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Real ``EvidenceStreamSink`` and seal index over fakeredis; HMAC seals."""
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_EVIDENCE_BINDING", raising=False)

    stream_redis = fakeredis.aioredis.FakeRedis(
        server=fakeredis.FakeServer(), decode_responses=True
    )
    sink = EvidenceStreamSink(redis_url="redis://localhost:6379", stream_key=_STREAM)
    sink._redis = stream_redis
    index = fakeredis.aioredis.FakeRedis(server=fakeredis.FakeServer())
    queue_redis = fakeredis.aioredis.FakeRedis(
        server=fakeredis.FakeServer(), decode_responses=True
    )

    async def _resolve(_client: Any) -> Any:
        return index

    @asynccontextmanager
    async def _open_queue() -> AsyncIterator[DeferQueue]:
        yield DeferQueue(queue_redis)

    monkeypatch.setattr(rs.es, "is_evidence_chain_blocking", lambda: True)
    monkeypatch.setattr(rs.es, "get_evidence_sink", lambda: sink)
    monkeypatch.setattr(rs, "_resolve_redis", _resolve)
    monkeypatch.setattr(defer_queue_module, "open_defer_queue", _open_queue)

    async def records(event_type: str | None = None) -> list[dict[str, Any]]:
        entries = [fields for _id, fields in await stream_redis.xrange(_STREAM)]
        prev = ""
        for fields in entries:  # the whole chain verifies, in order
            assert verify_record(fields, prev_hash=prev).valid
            prev = fields["record_hash"]
        return [
            f for f in entries if event_type is None or f["event_type"] == event_type
        ]

    return SimpleNamespace(
        sink=sink,
        index=index,
        queue=DeferQueue(queue_redis),
        records=records,
    )


def _payload(fields: dict[str, Any]) -> dict[str, Any]:
    return json.loads(fields["payload_json"])


def _with_payload(fields: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    return {**fields, "payload_json": jcs_canonicalize_plan(payload).decode("utf-8")}


def _record_hash_of(seal: str) -> str:
    return seal.split(".")[2]  # v2 HMAC seal: expire.slug.record_hash.sig


# ── RelianceRecord ───────────────────────────────────────────────────────────


def _record(warrant: Any = None, **standing: Any) -> RelianceRecord:
    fields: dict[str, Any] = {
        "eligible": False,
        "reliance_status": RelianceStatus.INELIGIBLE_MISSING,
        "reason": "Warrant is missing",
        "attested_at": WARRANT_TEST_NOW.isoformat(),
        **standing,
    }
    if warrant is not None:
        fields.setdefault("warrant", warrant)
        fields.setdefault("warrant_id", warrant.warrant_id)
        fields.setdefault("warrant_digest", warrant.digest)
    return RelianceRecord(
        norm_id=TRADE_CONFIDENCE_NORM_ID,
        required_governing_version=WARRANT_TEST_GOVERNING_VERSION,
        provider_name="static_test_source",
        standing=StandingVerificationResult(**fields),
    )


def test_missing_warrant_record_is_complete_and_unattested() -> None:
    record = _record()
    evidence = record.to_dict()
    assert set(evidence) == _RELIANCE_KEYS
    assert evidence["warrant_id"] == evidence["warrant_digest"] == ""
    assert evidence["warrant_status"] == ""
    assert evidence["reliance_status"] == "INELIGIBLE_MISSING"
    assert evidence["verification_status"] == "UNVERIFIED"
    assert record.attestation() is None


def test_record_is_always_unverified_and_cannot_be_upgraded() -> None:
    warrant = issue_test_warrant()
    record = _record(
        warrant, eligible=True, reliance_status=RelianceStatus.ELIGIBLE, reason="ok"
    )
    assert RELIANCE_VERIFICATION_STATUS == "UNVERIFIED"
    assert record.verification_status == "UNVERIFIED"
    with pytest.raises(AttributeError):
        record.verification_status = "VERIFIED"  # type: ignore[misc]
    attestation = record.attestation()
    assert attestation is not None
    assert attestation.status == "UNVERIFIED"
    assert attestation.attestation_type == "WARRANT"
    assert attestation.provider_name == "static_test_source"
    assert attestation.metadata["warrant_digest"] == warrant.digest
    assert attestation.metadata["reliance_status"] == "ELIGIBLE"


@pytest.mark.parametrize(
    "field", ["norm_id", "required_governing_version", "provider_name"], ids=str
)
def test_record_refuses_empty_identity(field: str) -> None:
    kwargs: dict[str, Any] = {
        "norm_id": "n",
        "required_governing_version": "v",
        "provider_name": "p",
        "standing": _record().standing,
        field: "",
    }
    with pytest.raises(ValueError):
        RelianceRecord(**kwargs)


async def test_stage_reports_a_record_for_every_governing_norm() -> None:
    eligible = await _stage(StaticWarrantSource.eligible()).run(
        StageContext(action=_ACTION, params=_trade(), profile=Profile.FULL)
    )
    assert eligible.violations == ()
    (record,) = eligible.reliance
    assert record.eligible and record.reliance_status is RelianceStatus.ELIGIBLE

    ungoverned = await _stage(StaticWarrantSource.eligible()).run(
        StageContext(action="get_market_data", params={}, profile=Profile.FULL)
    )
    assert ungoverned.reliance == () and ungoverned.violations == ()


# ── ALLOW: the seal commits to the reliance record ───────────────────────────


async def test_allow_seal_evidence_carries_the_eligible_reliance_record(
    chain: SimpleNamespace,
) -> None:
    warrant = issue_test_warrant()
    governor = _governor(StaticWarrantSource({warrant.norm_id: warrant}))
    params = _trade()

    seal = await governor.govern(_ACTION, params)

    (decision,) = await chain.records("GOVERNANCE_DECISION")
    assert decision["record_hash"] == _record_hash_of(seal)
    (reliance,) = _payload(decision)["reliance"]
    assert reliance == {
        "norm_id": TRADE_CONFIDENCE_NORM_ID,
        "warrant_id": warrant.warrant_id,
        "warrant_digest": warrant.digest,
        "warrant_status": "ACTIVE",
        "reliance_status": "ELIGIBLE",
        "reason": reliance["reason"],
        "required_governing_version": WARRANT_TEST_GOVERNING_VERSION,
        "warrant_governing_version": warrant.governing_version,
        "issuing_authority": warrant.issuing_authority,
        "authority_basis": warrant.authority_basis,
        "revocation_ref": "",
        "residual_risk_ref": "",
        "attested_at": WARRANT_TEST_NOW.isoformat(),
        "observed_at": WARRANT_TEST_NOW.isoformat(),
        "age_seconds": "0.000",
        "max_age_seconds": "60.000",
        "provider_name": "static_test_source",
        "verification_status": "UNVERIFIED",
    }
    assert rs.verify_seal_against_evidence(
        seal, _ACTION, params, decision, prev_hash=""
    )
    assert await rs.verify_and_consume_seal(
        seal, _ACTION, params, redis_client=chain.index
    )


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("reliance_status", "INELIGIBLE_REVOKED"),
        ("warrant_digest", "0" * 64),
        ("warrant_id", "WARRANT-FORGED"),
        ("verification_status", "VERIFIED"),
        ("provider_name", "other_source"),
    ],
)
async def test_tampered_reliance_record_breaks_seal_verification(
    chain: SimpleNamespace, field: str, forged: str
) -> None:
    governor = _governor(StaticWarrantSource.eligible())
    params = _trade()
    seal = await governor.govern(_ACTION, params)
    (decision,) = await chain.records("GOVERNANCE_DECISION")

    payload = _payload(decision)
    payload["reliance"][0][field] = forged
    tampered = _with_payload(decision, payload)

    # The record no longer matches its own hash ...
    assert not verify_record(tampered, prev_hash="").valid
    with pytest.raises(rs.SymbolicGovernorViolation, match="does not verify"):
        rs.verify_seal_against_evidence(seal, _ACTION, params, tampered, prev_hash="")

    # ... and re-hashing it to look intact no longer matches the seal.
    rehashed = {
        **tampered,
        "record_hash": verify_record(tampered, prev_hash="").computed_hash,
    }
    assert verify_record(rehashed, prev_hash="").valid
    with pytest.raises(rs.SymbolicGovernorViolation):
        rs.verify_seal_against_evidence(seal, _ACTION, params, rehashed, prev_hash="")


async def test_dropping_the_reliance_record_breaks_seal_verification(
    chain: SimpleNamespace,
) -> None:
    governor = _governor(StaticWarrantSource.eligible())
    params = _trade()
    seal = await governor.govern(_ACTION, params)
    (decision,) = await chain.records("GOVERNANCE_DECISION")

    payload = _payload(decision)
    del payload["reliance"]
    stripped = _with_payload(decision, payload)
    stripped["record_hash"] = verify_record(stripped, prev_hash="").computed_hash
    with pytest.raises(rs.SymbolicGovernorViolation):
        rs.verify_seal_against_evidence(seal, _ACTION, params, stripped, prev_hash="")


async def test_generate_seal_refuses_non_json_reliance_before_committing(
    chain: SimpleNamespace,
) -> None:
    with pytest.raises(rs.SealCanonicalizationError):
        await rs.generate_seal_with_evidence(
            _ACTION, _trade(), reliance=[{"attested_at": WARRANT_TEST_NOW}]
        )
    assert await chain.records() == []


# ── NARROW: the narrowed run's reliance is sealed ────────────────────────────


class _AmountCap(MutatingTier):
    """Phase-2 barrier: NARROWABLE above ``limit``."""

    tier_name = "amount_cap"
    order = 9

    def __init__(self, limit: float) -> None:
        self.limit = limit

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == _ACTION

    def _refusal(self, params: dict[str, Any]) -> list[Violation]:
        if float(params["amount"]) <= self.limit:
            return []
        return [
            Violation(
                tier=self.tier_name,
                code="AMOUNT_CAP",
                message="amount above cap",
                kind=ViolationKind.NARROWABLE,
            )
        ]

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return self._refusal(params)

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        refused = self._refusal(params)
        if refused:
            return refused, None
        return [], CommitReceipt(tier=self.tier_name, magnitude=float(params["amount"]))

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        return None

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        return None


class _Clamp:
    def can_narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> bool:
        return violation.kind == ViolationKind.NARROWABLE

    def narrow(
        self, violation: Violation, action: str, params: dict[str, Any]
    ) -> NarrowingResult:
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={**params, "amount": 50.0},
            constraints_applied=["amount clamped to 50"],
            narrowing_reason="amount above cap",
        )


async def test_narrow_seal_carries_the_narrowed_runs_reliance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sealed: list[dict[str, Any]] = []

    async def _issue_seal(
        action: str, params: dict[str, Any], *, path: str, reliance: Any
    ) -> str:
        sealed.append({"path": path, "params": params, "reliance": reliance})
        return "sealed-narrow"

    monkeypatch.setattr(sealing_module, "issue_seal", _issue_seal)
    monkeypatch.setattr(
        "src.gateway.infrastructure.redis_client.redis_client",
        fakeredis.aioredis.FakeRedis(decode_responses=True),
    )
    source = StaticWarrantSource.eligible()
    engine = ClassificationEngine(NarrowerRegistry([_Clamp()]), narrow_enabled=True)
    governor = _governor(source, _AmountCap(limit=50.0), classifier=engine)

    assert await governor.govern(_ACTION, _trade(amount=500.0)) == "sealed-narrow"

    (seal,) = sealed
    assert seal["path"] == "govern_narrow"
    assert seal["params"]["amount"] == 50.0
    (record,) = seal["reliance"]
    assert record.reliance_status is RelianceStatus.ELIGIBLE
    # The narrowed re-run re-checks reliance through the cache; the warrant
    # is still inside the freshness window, so it is not fetched again.
    assert source.calls == [TRADE_CONFIDENCE_NORM_ID]


# ── Envelope attestation ─────────────────────────────────────────────────────


async def test_allow_response_attests_the_warrant_unverified(
    chain: SimpleNamespace,
) -> None:
    warrant = issue_test_warrant()
    governor = _governor(StaticWarrantSource({warrant.norm_id: warrant}))
    result = await governor.validate_action(_ACTION, _trade())

    assert result["verdict"] == GovernanceDecision.ALLOW
    (attestation,) = result["external_attestations"]
    assert attestation.attestation_type == "WARRANT"
    assert attestation.status == "UNVERIFIED"
    assert attestation.receipt_id == warrant.warrant_id
    assert attestation.metadata["warrant_digest"] == warrant.digest
    (reliance,) = result["reliance"]
    assert reliance["reliance_status"] == "ELIGIBLE"

    envelope = await GovernanceEnvelopeBuilder().build(
        action=_ACTION,
        params=_trade(),
        governance_result={"verdict": "ALLOW"},
        external_attestations=result["external_attestations"],
    )
    (signed,) = envelope.to_dict(include_signature=True)["external_attestations"]
    assert signed["type"] == "WARRANT"
    assert signed["status"] == "UNVERIFIED"
    assert signed["provider_name"] == "static_test_source"


# ── DEFER: refusals are primary evidence ─────────────────────────────────────


@pytest.mark.parametrize(
    ("source_factory", "status"),
    [
        (
            lambda: _source_with(status="REVOKED", revocation_ref="REV-1"),
            RelianceStatus.INELIGIBLE_REVOKED,
        ),
        (lambda: StaticWarrantSource(), RelianceStatus.INELIGIBLE_MISSING),
        (
            lambda: _source_with(
                scope={
                    "actions": ["execute_trade"],
                    "actors": ["*"],
                    "systems": ["*"],
                    "jurisdictions": ["US_FED"],
                }
            ),
            RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
        ),
    ],
    ids=["revoked", "missing", "out_of_scope"],
)
async def test_defer_carries_the_ineligible_reliance_record(
    chain: SimpleNamespace, source_factory: Any, status: RelianceStatus
) -> None:
    governor = _governor(source_factory())
    result = await governor.validate_action(_ACTION, _trade())

    assert result["verdict"] == GovernanceDecision.DEFER
    assert result["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    assert "external_attestations" not in result  # not an admissible verdict
    (reliance,) = result["reliance"]
    assert set(reliance) == _RELIANCE_KEYS
    assert reliance["reliance_status"] == status.value
    assert reliance["verification_status"] == "UNVERIFIED"

    # The parked token carries the same record ...
    token = await chain.queue.get(result["defer_token"])
    assert token is not None
    assert token.defer_reason is DeferReason.WARRANT_INELIGIBLE
    assert token.opa_input_snapshot["reliance"] == [reliance]

    # ... and so does the hash-chained deferral evidence, with no seal minted.
    assert await chain.records("GOVERNANCE_DECISION") == []
    (deferral,) = await chain.records("GOVERNANCE_DEFERRAL")
    event = _payload(deferral)
    assert event["defer_id"] == result["defer_token"]
    assert event["defer_reason"] == "WARRANT_INELIGIBLE"
    assert event["persisted"] is True
    assert event["reliance"] == [reliance]


async def test_deferral_evidence_is_published_even_when_parking_fails(
    chain: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    @asynccontextmanager
    async def _unreachable() -> AsyncIterator[DeferQueue]:
        raise ConnectionError("queue down")
        yield  # pragma: no cover

    monkeypatch.setattr(defer_queue_module, "open_defer_queue", _unreachable)
    governor = _governor(StaticWarrantSource())
    result = await governor.validate_action(_ACTION, _trade())

    assert result["verdict"] == GovernanceDecision.DEFER
    (deferral,) = await chain.records("GOVERNANCE_DEFERRAL")
    event = _payload(deferral)
    assert event["persisted"] is False
    assert event["reliance"][0]["reliance_status"] == "INELIGIBLE_MISSING"


async def test_reliance_reaches_the_approval_token_too(chain: SimpleNamespace) -> None:
    """An eligible warrant under a HITL finding: the approval token records it."""
    opa = allow_opa()
    governor = make_governor(
        opa=opa,
        stpa_validator=clean_stpa(),
        core_stages=(*_ftra_and_opa(opa), _stage(StaticWarrantSource.eligible())),
        domain_tiers=(TradeConfidenceTier(_BINDING),),
    )
    result = await governor.validate_action(_ACTION, _trade())

    assert result["verdict"] == GovernanceDecision.REQUIRE_APPROVAL
    (reliance,) = result["reliance"]
    assert reliance["reliance_status"] == "ELIGIBLE"
    token = await chain.queue.get(result["deferred_id"])
    assert token is not None
    assert token.opa_input_snapshot["reliance"] == [reliance]
    (deferral,) = await chain.records("GOVERNANCE_DEFERRAL")
    assert _payload(deferral)["reliance"] == [reliance]


def _ftra_and_opa(opa: Any) -> tuple[Any, ...]:
    from src.gateway.governance.governor.assembly import kernel_stages

    return kernel_stages(opa, clean_stpa())


# ── DENY with a co-occurring warrant failure ─────────────────────────────────


async def test_deny_receipt_carries_the_co_occurring_reliance_record(
    chain: SimpleNamespace,
) -> None:
    """A malformed score is HARD in the tier; the warrant failure rides along."""
    governor = _governor(StaticWarrantSource())
    with pytest.raises(GovernanceError) as exc_info:
        await governor.validate_action(_ACTION, _trade(confidence="0.99"))

    receipt = exc_info.value.receipt
    assert receipt is not None
    (reliance,) = receipt.reliance
    assert reliance["reliance_status"] == "INELIGIBLE_MISSING"

    # The record is inside proof_hash: changing it changes the proof.
    from dataclasses import replace

    forged = replace(
        receipt,
        proof_hash="",
        reliance=({**reliance, "reliance_status": "ELIGIBLE"},),
    )
    assert forged.proof_hash != receipt.proof_hash

    (refusal,) = await chain.records("GOVERNANCE_REFUSAL")
    assert _payload(refusal)["receipt"]["reliance"] == [reliance]


async def test_receipt_without_reliance_hashes_as_before() -> None:
    from src.gateway.governance.contracts import RefusalReceipt

    fields: dict[str, Any] = {
        "thread_id": "t",
        "action": "a",
        "violated_tier": "x",
        "violated_rule": "r",
        "timestamp": 1.0,
    }
    assert (
        RefusalReceipt(**fields).proof_hash
        == RefusalReceipt(**fields, reliance=()).proof_hash
    )


async def test_post_hitl_revocation_defers_with_the_revoked_reliance(
    chain: SimpleNamespace,
) -> None:
    """A warrant revoked after approval defers (POAM-2026-104): the deferral
    evidence carries the revoked reliance and names the retained approval."""
    source = _source_with(status="REVOKED", revocation_ref="REV-AFTER-APPROVAL")
    # With a phase-2 barrier claiming the action too (finance's cbf/fiscal).
    governor = _governor(source, _AmountCap(limit=1_000.0))
    counter = SpendCounter()
    with pytest.raises(GovernanceDeferred) as exc_info:
        await governor.revalidate_post_hitl(
            _ACTION,
            _trade(),
            approval=granted_approval(approval_id="appr-7", counter=counter),
        )
    assert counter.calls == 0  # the approval stays redeemable
    (reliance,) = exc_info.value.reliance
    assert reliance["reliance_status"] == "INELIGIBLE_REVOKED"
    assert await chain.records("GOVERNANCE_DECISION") == []
    assert await chain.records("GOVERNANCE_REFUSAL") == []
    (deferral,) = await chain.records("GOVERNANCE_DEFERRAL")
    event = _payload(deferral)
    assert event["defer_id"] == "appr-7"
    assert event["approval_retained"] is True
    assert event["reliance"] == [reliance]


async def test_post_hitl_revocation_is_caught_when_only_read_only_tiers_claim(
    chain: SimpleNamespace,
) -> None:
    """Regression: governedness must not depend on the profile.

    Only the read-only TradeConfidenceTier claims the action.  POST_HITL drops
    read-only domain tiers from the run, and run_pipeline used to decide
    "governed" *after* that filter — so it saw an ungoverned action, skipped
    the warrant stage and minted a seal over a warrant revoked while the
    request waited for a human.
    """
    source = StaticWarrantSource.eligible()
    now = [0.0]
    # No phase-2 tier claims execute_trade.
    governor = _governor(source, monotonic=lambda: now[0])

    approved = await governor.validate_action(_ACTION, _trade())
    assert approved["verdict"] == GovernanceDecision.ALLOW
    assert approved["reliance"][0]["reliance_status"] == "ELIGIBLE"

    source.put(issue_test_warrant(status="REVOKED", revocation_ref="REV-WHILE-WAITING"))
    now[0] += 60.001  # the human took longer than the freshness window
    with pytest.raises(GovernanceDeferred) as exc_info:
        await governor.revalidate_post_hitl(
            _ACTION, _trade(), approval=granted_approval()
        )

    assert "RELIANCE_INELIGIBLE_REVOKED" in str(exc_info.value)
    (reliance,) = exc_info.value.reliance
    assert reliance["reliance_status"] == "INELIGIBLE_REVOKED"
    assert await chain.records("GOVERNANCE_DECISION") == []  # no seal
    (deferral,) = await chain.records("GOVERNANCE_DEFERRAL")
    assert _payload(deferral)["reliance"] == [reliance]


async def test_pipeline_and_post_hitl_gate_agree_on_governedness() -> None:
    """run_pipeline and revalidate_post_hitl ask one function: resolve_claims."""
    governor = _governor(StaticWarrantSource.eligible())
    ctx = StageContext(action=_ACTION, params=_trade(), profile=Profile.POST_HITL)

    claims = resolve_claims(governor.stages, ctx)
    assert claims.governed
    assert [s.name for s in claims.claimed] == ["trade_confidence"]
    assert governor._is_governed_action(_ACTION, _trade())

    other = StageContext(action="read_quote", params={}, profile=Profile.POST_HITL)
    assert not resolve_claims(governor.stages, other).governed
    assert not governor._is_governed_action("read_quote", {})


# ── Best-effort evidence is never silent ─────────────────────────────────────


def _publish_failures(kind: str) -> float:
    from prometheus_client import REGISTRY

    value = REGISTRY.get_sample_value(
        "cage_governance_evidence_publish_failures_total", {"kind": kind}
    )
    return value or 0.0


async def test_deferral_proceeds_and_is_counted_when_the_sink_fails(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _down(event: Any) -> None:
        raise ConnectionError("evidence stream down")

    monkeypatch.setattr(chain.sink, "ingest", _down)
    before = _publish_failures("deferral")
    governor = _governor(StaticWarrantSource())

    with caplog.at_level("ERROR"):
        result = await governor.validate_action(_ACTION, _trade())

    # The deferral still proceeds: token parked with its reliance record ...
    assert result["verdict"] == GovernanceDecision.DEFER
    token = await chain.queue.get(result["defer_token"])
    assert token is not None
    assert token.opa_input_snapshot["reliance"] == result["reliance"]
    # ... and the lost evidence write is loud: ERROR log plus counter.
    assert _publish_failures("deferral") == before + 1
    assert any(
        r.levelname == "ERROR" and "deferral evidence" in r.getMessage()
        for r in caplog.records
    )


async def test_refusal_is_counted_when_the_sink_fails(
    chain: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _down(event: Any) -> None:
        raise ConnectionError("evidence stream down")

    monkeypatch.setattr(chain.sink, "ingest", _down)
    before = _publish_failures("refusal")
    governor = _governor(StaticWarrantSource())

    with caplog.at_level("ERROR"), pytest.raises(GovernanceError):
        await governor.validate_action(_ACTION, _trade(confidence="0.99"))

    assert _publish_failures("refusal") == before + 1
    assert any(
        r.levelname == "ERROR" and "refusal receipt" in r.getMessage()
        for r in caplog.records
    )


# ── Unwarranted regions: nothing changes ─────────────────────────────────────


async def test_unwarranted_seal_evidence_is_unchanged(chain: SimpleNamespace) -> None:
    opa = allow_opa()
    governor = make_governor(
        opa=opa,
        core_stages=(OpaStage(opa),),
        domain_tiers=(TradeConfidenceTier(_UNWARRANTED),),
    )
    params = _trade()
    seal = await governor.govern(_ACTION, params)

    (decision,) = await chain.records("GOVERNANCE_DECISION")
    assert set(_payload(decision)) == _LEGACY_DECISION_KEYS
    assert rs.verify_seal_against_evidence(
        seal, _ACTION, params, decision, prev_hash=""
    )
    result = await governor.validate_action(_ACTION, params)
    assert result["verdict"] == GovernanceDecision.ALLOW
    assert "reliance" not in result and "external_attestations" not in result


@pytest.mark.parametrize("region", ["US_FED", "APAC_MAS"])
async def test_unwarranted_regions_produce_no_reliance_record(
    chain: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, region: str
) -> None:
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region=region),
    )
    governor = assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=True, narrow=False),
        jurisdiction=resolve_jurisdiction(region),
    )
    assert not any(isinstance(s, WarrantStage) for s in governor.stages)

    # Without a world-model cache the causal gate refuses (fail closed); the
    # refusal is the decision under test and must carry no reliance record.
    with pytest.raises(GovernanceError) as exc_info:
        await governor.validate_action(_ACTION, _trade())
    assert exc_info.value.receipt.reliance == ()
    for record in await chain.records():
        assert "reliance" not in _payload(record)
