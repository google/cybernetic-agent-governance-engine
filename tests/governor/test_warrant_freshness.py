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

"""The Warrant Contract v0.1 60 s freshness window (VEIP Phase 2, PR 5).

Invariants under test:

* ``FRESH_SERVED`` — a warrant received at most ``max_age_seconds`` ago is
  served from the cache without a fetch (inclusive boundary).
* ``EXPIRED_REFETCHED`` — one tick past the window, the cache re-fetches, and a
  re-fetched revocation is refused on that very request.
* ``STALE_NEVER_ELIGIBLE`` — a re-fetch that raises or times out never extends
  the old state: ``INELIGIBLE_STALE`` -> ``RELIANCE_INELIGIBLE`` -> DEFER, even
  when the last state was ACTIVE.
* ``SINGLE_FLIGHT`` — concurrent requests for one norm share one fetch.
* ``POST_HITL_FRESHNESS`` — post-approval revalidation reads through the same
  window.
* ``WINDOW_BOUNDED`` — config above 60 s (the contract) or <= 0 is refused.
* ``FRESHNESS_IS_EVIDENCE`` — ``observed_at`` / ``age_seconds`` /
  ``max_age_seconds`` are in every reliance record.

The clocks are injected and advanced by hand; nothing sleeps.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_finance.tiers.trade_confidence_tier import (
    TRADE_CONFIDENCE_NORM_ID,
    TradeConfidenceTier,
)
from src.gateway.governance.contracts import NormBinding, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.defer_queue import DeferReason
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    assemble_governor,
    kernel_stages,
)
from src.gateway.governance.governor.errors import (
    GovernanceDeferred,
    GovernanceError,
)
from src.gateway.governance.governor.pipeline import Profile, StageContext
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jurisdiction import eu_ai_act
from src.gateway.governance.schemas import thresholds as thresholds_module
from src.gateway.governance.schemas.thresholds import (
    WARRANT_CONTRACT_MAX_AGE_SECONDS,
    WarrantThresholds,
)
from src.gateway.governance.warrant import (
    CONTRACT_MAX_AGE_SECONDS,
    RelianceStatus,
    Warrant,
    WarrantCache,
    WarrantFreshness,
)
from tests.fixtures.approval import SpendCounter, granted_approval
from tests.fixtures.governor import (
    WARRANT_TEST_GOVERNING_VERSION,
    WARRANT_TEST_NOW,
    allow_opa,
    clean_stpa,
    issue_test_warrant,
    make_governor,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = pathlib.Path(__file__).resolve().parents[2]
_NORM = TRADE_CONFIDENCE_NORM_ID
_TRADE = {"confidence": 0.99, "amount": 100.0, "symbol": "AAPL"}
_BINDING = NormBinding(
    norm_id=_NORM,
    value=0.97,
    requires_warrant=True,
    actions=frozenset({"execute_trade", "execute_trade_bounded"}),
    governing_version=WARRANT_TEST_GOVERNING_VERSION,
)


# ── Test doubles ─────────────────────────────────────────────────────────────


class _Clock:
    """Monotonic and wall clocks advanced together, by hand."""

    def __init__(self) -> None:
        self.mono = 5_000.0
        self.wall = WARRANT_TEST_NOW

    def monotonic(self) -> float:
        return self.mono

    def wall_clock(self) -> datetime:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += timedelta(seconds=seconds)


class _ScriptedSource:
    """A :class:`WarrantSource` whose next answers are set by the test.

    ``mode``: ``"ok"`` serves ``warrant``; ``"missing"`` returns ``None``;
    ``"error"`` raises; ``"hang"`` blocks until cancelled. ``gate``, when
    set, holds every fetch until the test releases it (single-flight).
    """

    provider_name = "scripted_test_source"

    def __init__(self, warrant: Warrant | None = None) -> None:
        self.warrant = warrant if warrant is not None else issue_test_warrant()
        self.mode = "ok"
        self.gate: asyncio.Event | None = None
        self.calls = 0

    async def fetch(self, norm_id: str) -> Warrant | None:
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.mode == "error":
            raise ConnectionError("issuer unreachable")
        if self.mode == "hang":
            await asyncio.Event().wait()
        if self.mode == "missing":
            return None
        return self.warrant


def _cache(source: _ScriptedSource, clock: _Clock, **kwargs: Any) -> WarrantCache:
    kwargs.setdefault("fetch_timeout_seconds", 0.05)
    return WarrantCache(
        source, monotonic=clock.monotonic, wall_clock=clock.wall_clock, **kwargs
    )


def _stage(cache: WarrantCache) -> WarrantStage:
    return WarrantStage(
        [_BINDING], cache, jurisdiction="EU_ECB", clock=lambda: WARRANT_TEST_NOW
    )


async def _run(stage: WarrantStage) -> Any:
    return await stage.run(
        StageContext(action="execute_trade", params=dict(_TRADE), profile=Profile.FULL)
    )


# ── The window ───────────────────────────────────────────────────────────────


async def test_fresh_hit_is_served_without_a_fetch() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock)

    first = await cache.observe(_NORM)
    clock.advance(30.0)
    second = await cache.observe(_NORM)

    assert source.calls == 1
    assert first.freshness is second.freshness is WarrantFreshness.FRESH
    assert second.warrant is first.warrant
    assert second.age_seconds == pytest.approx(30.0)
    assert second.observed_at == first.observed_at == WARRANT_TEST_NOW


async def test_exactly_sixty_seconds_is_still_fresh() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock)
    await cache.observe(_NORM)

    clock.advance(60.0)
    observation = await cache.observe(_NORM)

    assert source.calls == 1
    assert observation.fresh
    assert observation.age_seconds == pytest.approx(60.0)


async def test_one_millisecond_past_the_window_refetches() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock)
    await cache.observe(_NORM)

    clock.advance(60.001)
    observation = await cache.observe(_NORM)

    assert source.calls == 2
    assert observation.fresh
    assert observation.age_seconds == 0.0
    assert observation.observed_at == WARRANT_TEST_NOW + timedelta(seconds=60.001)


async def test_observed_at_is_cage_receipt_time_not_issuer_time() -> None:
    """The warrant's own validity fields never stand in for receipt time."""
    source, clock = _ScriptedSource(), _Clock()
    clock.wall = WARRANT_TEST_NOW + timedelta(hours=3)
    observation = await _cache(source, clock).observe(_NORM)
    assert observation.observed_at == WARRANT_TEST_NOW + timedelta(hours=3)
    assert observation.warrant is not None
    assert observation.observed_at.isoformat() not in (
        observation.warrant.valid_from,
        observation.warrant.valid_until,
    )


async def test_a_clock_reading_before_receipt_never_yields_negative_age() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock)
    await cache.observe(_NORM)
    clock.mono -= 5.0
    observation = await cache.observe(_NORM)
    assert observation.age_seconds == 0.0
    assert source.calls == 1


async def test_missing_is_never_cached() -> None:
    """A newly issued warrant is seen on the next request, not 60 s later."""
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock)
    source.mode = "missing"
    first = await cache.observe(_NORM)
    assert first.fresh and first.warrant is None
    assert first.observed_at == WARRANT_TEST_NOW

    source.mode = "ok"
    second = await cache.observe(_NORM)
    assert source.calls == 2
    assert second.warrant is source.warrant


async def test_missing_on_refetch_drops_the_cached_warrant() -> None:
    source, clock = _ScriptedSource(), _Clock()
    stage = _stage(_cache(source, clock))
    await _run(stage)
    clock.advance(60.001)
    source.mode = "missing"
    (violation,) = (await _run(stage)).violations
    assert violation.code == "RELIANCE_INELIGIBLE_MISSING"
    source.mode = "error"
    # Nothing is cached any more, so a failure now is UNRESOLVED, not STALE.
    (violation,) = (await _run(stage)).violations
    assert violation.code == "RELIANCE_INELIGIBLE_UNRESOLVED"


# ── Revocation and stale state ───────────────────────────────────────────────


async def test_revocation_on_refetch_takes_effect_immediately() -> None:
    source, clock = _ScriptedSource(), _Clock()
    stage = _stage(_cache(source, clock))
    assert (await _run(stage)).violations == ()

    source.warrant = issue_test_warrant(status="REVOKED", revocation_ref="REV-9")
    clock.advance(60.001)
    output = await _run(stage)

    (violation,) = output.violations
    assert violation.kind is ViolationKind.RELIANCE_INELIGIBLE
    assert violation.code == "RELIANCE_INELIGIBLE_REVOKED"
    (record,) = output.reliance
    assert record.to_dict()["warrant_status"] == "REVOKED"
    assert record.to_dict()["age_seconds"] == "0.000"


async def test_cached_revocation_is_not_forgotten_inside_the_window() -> None:
    source, clock = (
        _ScriptedSource(issue_test_warrant(status="REVOKED", revocation_ref="REV-1")),
        _Clock(),
    )
    stage = _stage(_cache(source, clock))
    await _run(stage)
    source.warrant = issue_test_warrant()
    clock.advance(59.0)
    (violation,) = (await _run(stage)).violations
    assert violation.code == "RELIANCE_INELIGIBLE_REVOKED"
    assert source.calls == 1


@pytest.mark.parametrize(
    ("mode", "error_text"),
    [("error", "ConnectionError: issuer unreachable"), ("hang", "did not answer")],
)
async def test_failed_refetch_is_stale_and_never_eligible(
    mode: str, error_text: str
) -> None:
    """The last state was ACTIVE and intact; past the window it is STALE."""
    source, clock = _ScriptedSource(), _Clock()
    stage = _stage(_cache(source, clock))
    assert (await _run(stage)).violations == ()

    clock.advance(60.001)
    source.mode = mode
    output = await _run(stage)

    (violation,) = output.violations
    assert violation.kind is ViolationKind.RELIANCE_INELIGIBLE
    assert violation.code == "RELIANCE_INELIGIBLE_STALE"
    assert error_text in violation.message
    (record,) = output.reliance
    assert not record.eligible
    assert record.reliance_status is RelianceStatus.INELIGIBLE_STALE
    evidence = record.to_dict()
    # The stale state is evidence of what went stale, with its true age.
    assert evidence["warrant_id"] == source.warrant.warrant_id
    assert evidence["warrant_digest"] == source.warrant.digest
    assert evidence["observed_at"] == WARRANT_TEST_NOW.isoformat()
    assert evidence["age_seconds"] == "60.001"
    assert evidence["max_age_seconds"] == "60.000"
    assert evidence["verification_status"] == "UNVERIFIED"


async def test_stale_state_keeps_ageing_and_recovers_on_a_good_fetch() -> None:
    source, clock = _ScriptedSource(), _Clock()
    stage = _stage(_cache(source, clock))
    await _run(stage)
    source.mode = "error"
    clock.advance(61.0)
    await _run(stage)
    clock.advance(30.0)
    (record,) = (await _run(stage)).reliance
    assert record.reliance_status is RelianceStatus.INELIGIBLE_STALE
    assert record.to_dict()["age_seconds"] == "91.000"
    assert source.calls == 3  # every request past the window retries

    source.mode = "ok"
    output = await _run(stage)
    assert output.violations == ()
    assert output.reliance[0].to_dict()["age_seconds"] == "0.000"


async def test_first_fetch_failure_is_unresolved_not_stale() -> None:
    source, clock = _ScriptedSource(), _Clock()
    source.mode = "error"
    output = await _run(_stage(_cache(source, clock)))
    (violation,) = output.violations
    assert violation.code == "RELIANCE_INELIGIBLE_UNRESOLVED"
    evidence = output.reliance[0].to_dict()
    assert evidence["observed_at"] == evidence["age_seconds"] == ""
    assert evidence["warrant_id"] == ""


# ── Single flight ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("expired_entry", [False, True])
async def test_concurrent_requests_share_one_fetch(expired_entry: bool) -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock, fetch_timeout_seconds=5.0)
    if expired_entry:
        await cache.observe(_NORM)
        clock.advance(60.001)
    calls_before = source.calls
    source.gate = asyncio.Event()

    waiters = [asyncio.create_task(cache.observe(_NORM)) for _ in range(25)]
    await asyncio.sleep(0)  # let every waiter reach the in-flight fetch
    source.gate.set()
    observations = await asyncio.gather(*waiters)

    assert source.calls - calls_before == 1
    assert {o.freshness for o in observations} == {WarrantFreshness.FRESH}
    assert all(o.warrant is source.warrant for o in observations)


async def test_single_flight_failure_is_shared_and_not_cached() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock, fetch_timeout_seconds=5.0)
    source.mode, source.gate = "error", asyncio.Event()
    waiters = [asyncio.create_task(cache.observe(_NORM)) for _ in range(5)]
    await asyncio.sleep(0)
    source.gate.set()
    observations = await asyncio.gather(*waiters)
    assert source.calls == 1
    assert {o.freshness for o in observations} == {WarrantFreshness.UNRESOLVED}
    source.mode, source.gate = "ok", None
    assert (await cache.observe(_NORM)).fresh
    assert source.calls == 2


async def test_a_cancelled_waiter_does_not_cancel_the_shared_fetch() -> None:
    source, clock = _ScriptedSource(), _Clock()
    cache = _cache(source, clock, fetch_timeout_seconds=5.0)
    source.gate = asyncio.Event()
    doomed = asyncio.create_task(cache.observe(_NORM))
    survivor = asyncio.create_task(cache.observe(_NORM))
    await asyncio.sleep(0)
    doomed.cancel()
    await asyncio.sleep(0)
    source.gate.set()
    assert (await survivor).fresh
    assert doomed.cancelled()
    assert source.calls == 1


# ── Governor: DEFER and POST_HITL ────────────────────────────────────────────


def _governor(cache: WarrantCache) -> Any:
    opa, stpa = allow_opa(), clean_stpa()
    return make_governor(
        opa=opa,
        stpa_validator=stpa,
        core_stages=(*kernel_stages(opa, stpa), _stage(cache)),
        domain_tiers=(TradeConfidenceTier(_BINDING),),
    )


async def test_stale_warrant_defers_the_governor_not_denies() -> None:
    source, clock = _ScriptedSource(), _Clock()
    governor = _governor(_cache(source, clock))
    first = await governor.validate_action("execute_trade", dict(_TRADE))
    assert first["verdict"] == GovernanceDecision.REQUIRE_APPROVAL  # FTRA HITL only

    clock.advance(60.001)
    source.mode = "error"
    result = await governor.validate_action("execute_trade", dict(_TRADE))
    assert result["verdict"] == GovernanceDecision.DEFER
    assert result["defer_reason"] == DeferReason.WARRANT_INELIGIBLE.value
    assert "RELIANCE_INELIGIBLE_STALE" in {v.code for v in result["violations"]}


async def test_post_hitl_inside_the_window_relies_on_the_cached_warrant() -> None:
    source, clock = _ScriptedSource(), _Clock()
    governor = _governor(_cache(source, clock))
    await governor.validate_action("execute_trade", dict(_TRADE))
    clock.advance(45.0)
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        return_value="seal-ok",
    ):
        seal = await governor.revalidate_post_hitl(
            "execute_trade", dict(_TRADE), approval=granted_approval("PASS")
        )
    assert seal == "seal-ok"
    assert source.calls == 1


@pytest.mark.parametrize("mode", ["error", "hang"])
async def test_post_hitl_with_an_expired_cache_refetches_and_defers_stale(
    mode: str,
) -> None:
    source, clock = _ScriptedSource(), _Clock()
    governor = _governor(_cache(source, clock))
    await governor.validate_action("execute_trade", dict(_TRADE))
    clock.advance(60.001)
    source.mode = mode
    counter = SpendCounter()
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence"
    ) as mint:
        with pytest.raises(GovernanceDeferred, match="RELIANCE_INELIGIBLE_STALE"):
            await governor.revalidate_post_hitl(
                "execute_trade",
                dict(_TRADE),
                approval=granted_approval("PASS", counter=counter),
            )
    assert source.calls == 2  # the expired state was re-fetched
    assert counter.calls == 0  # the approval is retained, not burned
    mint.assert_not_called()


async def test_post_hitl_with_an_expired_cache_seals_on_a_good_refetch() -> None:
    source, clock = _ScriptedSource(), _Clock()
    governor = _governor(_cache(source, clock))
    await governor.validate_action("execute_trade", dict(_TRADE))
    clock.advance(120.0)
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        return_value="seal-ok",
    ):
        seal = await governor.revalidate_post_hitl(
            "execute_trade", dict(_TRADE), approval=granted_approval("PASS")
        )
    assert seal == "seal-ok"
    assert source.calls == 2


# ── Configuration bounds ─────────────────────────────────────────────────────


def test_the_schema_bound_is_the_contract_bound() -> None:
    assert WARRANT_CONTRACT_MAX_AGE_SECONDS == CONTRACT_MAX_AGE_SECONDS == 60.0
    defaults = WarrantThresholds()
    assert defaults.max_age_seconds == 60.0
    assert 0 < defaults.fetch_timeout_seconds < defaults.max_age_seconds


def test_shipped_config_holds_the_contract_window() -> None:
    raw = json.loads((_REPO / "config/governance_thresholds.json").read_text())
    window = WarrantThresholds.model_validate(
        {k: v for k, v in raw["warrant"].items() if not k.startswith("_")}
    )
    assert window.max_age_seconds == 60.0


@pytest.mark.parametrize(
    "fields",
    [
        {"max_age_seconds": 60.001},
        {"max_age_seconds": 61},
        {"max_age_seconds": 3600},
        {"max_age_seconds": 0},
        {"max_age_seconds": -1},
        {"max_age_seconds": float("nan")},
        {"max_age_seconds": float("inf")},
        {"fetch_timeout_seconds": 0},
        {"fetch_timeout_seconds": -0.5},
        {"fetch_timeout_seconds": float("nan")},
        {"max_age_seconds": 5, "fetch_timeout_seconds": 5},
        {"max_age_seconds": 5, "fetch_timeout_seconds": 10},
    ],
)
def test_out_of_bounds_window_is_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        WarrantThresholds(**fields)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_age_seconds": 60.001},
        {"max_age_seconds": 0},
        {"max_age_seconds": -1},
        {"max_age_seconds": float("inf")},
        {"max_age_seconds": True},
        {"fetch_timeout_seconds": 0},
        {"max_age_seconds": 1, "fetch_timeout_seconds": 1},
    ],
)
def test_cache_refuses_an_out_of_bounds_window(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        WarrantCache(_ScriptedSource(), **kwargs)


def _write_config(tmp_path: pathlib.Path, warrant: dict[str, Any]) -> str:
    raw = json.loads((_REPO / "config/governance_thresholds.json").read_text())
    raw["warrant"] = warrant
    path = tmp_path / "governance_thresholds.json"
    path.write_text(json.dumps(raw))
    return str(path)


@pytest.mark.parametrize("max_age", [0, -5, 61, 300])
def test_loader_aborts_on_an_out_of_bounds_config(
    tmp_path: pathlib.Path, max_age: float
) -> None:
    path = _write_config(tmp_path, {"max_age_seconds": max_age})
    with pytest.raises(SystemExit):
        thresholds_module.load_and_validate_thresholds.__wrapped__(
            path, region="US_FED"
        )


@pytest.mark.parametrize("value", ["61", "0", "-1"])
def test_loader_aborts_on_an_out_of_bounds_env_override(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    path = _write_config(tmp_path, {"max_age_seconds": 60})
    monkeypatch.setenv("WARRANT_MAX_AGE_SECONDS", value)
    with pytest.raises(SystemExit):
        thresholds_module.load_and_validate_thresholds.__wrapped__(
            path, region="US_FED"
        )


def test_env_override_tightens_the_window(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, {"max_age_seconds": 60})
    monkeypatch.setenv("WARRANT_MAX_AGE_SECONDS", "20")
    monkeypatch.setenv("WARRANT_FETCH_TIMEOUT_SECONDS", "1.5")
    loaded = thresholds_module.load_and_validate_thresholds.__wrapped__(
        path, region="US_FED"
    )
    assert loaded.warrant.max_age_seconds == 20.0
    assert loaded.warrant.fetch_timeout_seconds == 1.5


# ── Composition root ─────────────────────────────────────────────────────────


class _AdmittingProvider:
    async def fetch_baseline(self, region: str) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    async def validate_fria(self, payload: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def submit_evidence(self, receipt: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError


def test_assembly_wraps_the_source_in_the_configured_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eu = thresholds_module.load_and_validate_thresholds(region="EU_ECB")
    tightened = eu.model_copy(
        update={
            "warrant": WarrantThresholds(max_age_seconds=15, fetch_timeout_seconds=1)
        }
    )
    monkeypatch.setattr(thresholds_module, "THRESHOLDS", tightened)
    source = _ScriptedSource()
    governor = assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=True, narrow=False),
        jurisdiction=eu_ai_act.contribution(provider=_AdmittingProvider()),  # type: ignore[arg-type]
        warrant_source=source,
    )
    (stage,) = [s for s in governor.stages if isinstance(s, WarrantStage)]
    assert isinstance(stage.cache, WarrantCache)
    assert stage.cache.max_age_seconds == 15.0
    assert stage.cache.fetch_timeout_seconds == 1.0
    assert stage.source_name == "scripted_test_source"


# ── Evidence ─────────────────────────────────────────────────────────────────


async def test_every_reliance_record_carries_freshness() -> None:
    source, clock = _ScriptedSource(), _Clock()
    stage = _stage(_cache(source, clock))
    await _run(stage)
    clock.advance(12.3456)
    (record,) = (await _run(stage)).reliance
    evidence = record.to_dict()
    assert evidence["observed_at"] == WARRANT_TEST_NOW.isoformat()
    assert evidence["age_seconds"] == "12.346"
    assert evidence["max_age_seconds"] == "60.000"
    assert record.observed_at == WARRANT_TEST_NOW.isoformat()
    assert record.age_seconds == pytest.approx(12.3456)
    assert all(isinstance(v, str) for v in evidence.values())


@pytest.mark.parametrize(
    "fields",
    [
        {"age_seconds": -1.0},
        {"age_seconds": float("nan")},
        {"max_age_seconds": float("inf")},
        {"age_seconds": True},
    ],
)
def test_reliance_record_refuses_malformed_freshness(fields: dict[str, Any]) -> None:
    from src.gateway.governance.warrant import (
        RelianceRecord,
        StandingVerificationResult,
    )

    standing = StandingVerificationResult(
        eligible=False,
        reliance_status=RelianceStatus.INELIGIBLE_MISSING,
        reason="missing",
        evaluated_at=WARRANT_TEST_NOW.isoformat(),
    )
    with pytest.raises(ValueError):
        RelianceRecord(
            norm_id=_NORM,
            governing_version=WARRANT_TEST_GOVERNING_VERSION,
            provider_name="p",
            standing=standing,
            **fields,
        )
