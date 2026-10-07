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

"""Phase 6 (D-L): FRIA is a jurisdiction obligation, wired only under EU_ECB.

Invariants under test (plan §6):

* ``FRIA_ONLY_UNDER_EU_ECB`` — no other region's governor has a ``fria`` tier,
  and the kernel governor package names neither the region nor the tier.
* ``EU_ECB_NEVER_RUNS_UNASSESSED`` — every degraded path of the ``fria`` tier
  (stale/missing artefact, provider down, timeout, error, refusal) blocks, and
  an enforcing EU posture refuses to start on the stub provider.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from src.cage_finance.plugin import FinanceCagePlugin
from src.gateway.governance import defer_queue as defer_queue_mod
from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import ViolationKind
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor import posture as posture_mod
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorComponents,
    assemble_governor,
)
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.posture import (
    PostureViolation,
    assert_production_posture,
)
from src.gateway.governance.governor.stages.domain_tiers import DomainTierStage
from src.gateway.governance.jurisdiction import (
    JURISDICTIONS,
    JurisdictionContribution,
    eu_ai_act,
    resolve_jurisdiction,
)
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import (
    CODE_HOLD,
    CODE_REJECTED,
    CODE_STALE,
    CODE_UNAVAILABLE,
    SYSTEM_WIDE_ASSESSMENT,
    FriaTier,
)
from src.gateway.governance.normative_provider import StubNormativeProvider
from src.gateway.governance.seams.normative import ValidationResult
from tests.fixtures.governor import (
    StaticWarrantSource,
    allow_opa,
    clean_stpa,
    default_classifier,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = pathlib.Path(__file__).resolve().parents[2]
_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
_FRESH = {"assessed_at": (_NOW - timedelta(days=30)).isoformat()}


class _FakeProvider:
    """Records calls; answers with ``result``, raises ``exc``, or sleeps past the timeout."""

    def __init__(
        self,
        result: ValidationResult | None = None,
        *,
        exc: Exception | None = None,
        hang: bool = False,
    ) -> None:
        self.result = result if result is not None else ValidationResult(admitted=True)
        self.exc = exc
        self.hang = hang
        self.calls: list[dict[str, Any]] = []

    async def fetch_baseline(self, region: str) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        self.calls.append(payload)
        if self.hang:
            await asyncio.sleep(10)
        if self.exc is not None:
            raise self.exc
        return self.result

    async def submit_evidence(
        self, receipt: dict[str, Any]
    ) -> Any:  # pragma: no cover - unused
        raise NotImplementedError


def _lookup(artefacts: Mapping[str, Mapping[str, Any]]) -> Any:
    return lambda action: artefacts.get(action)


def _tier(
    provider: _FakeProvider,
    artefacts: Mapping[str, Mapping[str, Any]] | None = None,
    **kwargs: Any,
) -> FriaTier:
    return FriaTier(
        provider,  # type: ignore[arg-type]
        region="EU_ECB",
        assessment_lookup=_lookup(
            {"execute_trade": _FRESH} if artefacts is None else artefacts
        ),
        reassessment_interval_days=kwargs.pop("interval", 365),
        gate_timeout_seconds=kwargs.pop("timeout", 0.05),
        clock=lambda: _NOW,
        **kwargs,
    )


def _assemble(
    *, jurisdiction: JurisdictionContribution | None = None, warranted: bool = False
) -> SymbolicGovernor:
    """``warranted`` wires what an EU_ECB governor needs for its warranted
    trade-confidence norm: DEFER enabled and a warrant source."""
    return assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=warranted, narrow=False),
        jurisdiction=jurisdiction,
        warrant_source=StaticWarrantSource.eligible() if warranted else None,
    )


def _use_region_thresholds(monkeypatch: pytest.MonkeyPatch, region: str) -> None:
    """Load ``region``'s effective thresholds; assembly refuses a region mismatch."""
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region=region),
    )


def _domain_stage_names(governor: SymbolicGovernor) -> list[str]:
    return [s.name for s in governor.stages if isinstance(s, DomainTierStage)]


# --- FRIA_ONLY_UNDER_EU_ECB ---------------------------------------------------


def test_jurisdiction_table_covers_exactly_the_three_regions() -> None:
    assert set(JURISDICTIONS) == {"US_FED", "APAC_MAS", "EU_ECB"}


@pytest.mark.parametrize("region", ["US_FED", "APAC_MAS"])
def test_non_eu_regions_contribute_no_tiers_or_requirements(region: str) -> None:
    contribution = resolve_jurisdiction(region)
    assert contribution.region == region
    assert contribution.tiers == ()
    assert contribution.runtime_requirements == ()


@pytest.mark.parametrize("region", ["US_FED", "APAC_MAS"])
def test_non_eu_governor_has_no_fria_tier(
    monkeypatch: pytest.MonkeyPatch, region: str
) -> None:
    _use_region_thresholds(monkeypatch, region)
    governor = _assemble(jurisdiction=resolve_jurisdiction(region))
    assert "fria" not in governor.registered_tier_names()
    assert "fria" not in _domain_stage_names(governor)


def test_default_test_region_resolves_without_fria() -> None:
    """The hermetic default (LOCAL → US_FED fallback) assembles no fria tier."""
    ControlRegistry.reconfigure("LOCAL")
    governor = _assemble()
    assert governor.components.jurisdiction is not None
    assert governor.components.jurisdiction.region == "US_FED"
    assert "fria" not in governor.registered_tier_names()


def test_eu_governor_runs_fria_once_in_phase_one_after_causal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_region_thresholds(monkeypatch, "EU_ECB")
    governor = _assemble(
        jurisdiction=eu_ai_act.contribution(provider=_FakeProvider()),  # type: ignore[arg-type]
        warranted=True,
    )
    names = _domain_stage_names(governor)
    assert names.count("fria") == 1
    assert names == [
        "trade_confidence",
        "bounding",
        "consensus",
        "causal",
        "fria",
        "cbf",
        "fiscal",
    ]
    fria = next(
        s
        for s in governor.stages
        if isinstance(s, DomainTierStage) and s.name == "fria"
    )
    assert fria.mutating is False
    # The domain view stays domain-only; the jurisdiction tier is separate.
    assert "fria" not in [t.tier_name for t in governor.domain_tiers]


def test_reconfigure_reports_the_region_it_loaded() -> None:
    """Regression: reconfigure() used to reset active_region to the default."""
    ControlRegistry.reconfigure("EU_ECB")  # restored by the conftest fixture
    assert ControlRegistry().active_region == "EU_ECB"
    assert (
        ControlRegistry().get_mapping_safe(GovernanceControl.FRIA_ASSESSMENT)
        is not None
    )


def test_eu_region_resolves_to_fria_through_control_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ControlRegistry.reconfigure("EU_ECB")  # restored by the conftest fixture
    _use_region_thresholds(monkeypatch, "EU_ECB")
    governor = _assemble(warranted=True)
    assert governor.components.jurisdiction is not None
    assert governor.components.jurisdiction.region == "EU_ECB"
    assert _domain_stage_names(governor).count("fria") == 1


def test_unknown_region_is_refused() -> None:
    with pytest.raises(ValueError, match="no jurisdiction entry"):
        resolve_jurisdiction("XX_NOWHERE")


def test_jurisdiction_tiers_must_be_read_only() -> None:
    from src.gateway.governance.contracts import CommitReceipt, MutatingTier, Violation

    class _Barrier(MutatingTier):
        tier_name = "barrier"
        order = 1

        def claims_action(self, action: str, params: dict[str, Any]) -> bool:
            return True

        async def evaluate(
            self, action: str, params: dict[str, Any]
        ) -> list[Violation]:
            return []

        async def commit(
            self, action: str, params: dict[str, Any]
        ) -> tuple[list[Violation], CommitReceipt | None]:
            return [], None

        async def rollback(
            self, action: str, params: dict[str, Any], receipt: CommitReceipt
        ) -> None:
            pass

        async def confirm(
            self, action: str, params: dict[str, Any], receipt: CommitReceipt
        ) -> None:
            pass

    with pytest.raises(TypeError, match="must be read-only"):
        JurisdictionContribution(region="EU_ECB", tiers=(_Barrier(),))


def test_jurisdiction_tiers_must_be_governance_tiers() -> None:
    class _DuckTyped:
        tier_name = "barrier"
        phase = 1
        order = 1

    with pytest.raises(TypeError, match="not a ReadOnlyTier"):
        JurisdictionContribution(region="EU_ECB", tiers=(_DuckTyped(),))  # type: ignore[arg-type]


def test_fria_tier_name_collision_with_a_domain_tier_is_rejected() -> None:
    from src.gateway.governance.contracts import ReadOnlyTier, Violation

    class _DomainFria(ReadOnlyTier):
        tier_name = "fria"
        order = 1

        def claims_action(self, action: str, params: dict[str, Any]) -> bool:
            return False

        async def evaluate(
            self, action: str, params: dict[str, Any]
        ) -> list[Violation]:
            return []

    components = GovernorComponents(
        opa=allow_opa(),
        core_stages=(),
        classifier=default_classifier(),
        domain_tiers=(_DomainFria(),),
        jurisdiction=eu_ai_act.contribution(provider=_FakeProvider()),  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="duplicate tier registration"):
        SymbolicGovernor(components)


def test_governor_package_names_no_region_and_no_fria() -> None:
    """Static scan: the kernel governor is jurisdiction-neutral."""
    offenders = [
        f"{path.relative_to(_REPO)}:{n}"
        for path in sorted((_REPO / "src/gateway/governance/governor").rglob("*.py"))
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if re.search(r"EU_ECB|fria", line, re.IGNORECASE)
    ]
    assert offenders == []


def test_universal_kernel_prose_does_not_mention_fria() -> None:
    """Outside the jurisdiction package (and the normative seam), FRIA is not a kernel concept."""
    root = _REPO / "src/gateway/governance"
    allowed = (root / "jurisdiction", root / "seams")
    allowed_names = {
        "normative_provider.py",
        "normative_provider_daemon.py",
        "constants.py",
    }
    offenders = [
        f"{path.relative_to(_REPO)}:{n}"
        for path in sorted(root.rglob("*.py"))
        if not any(path.is_relative_to(a) for a in allowed)
        and path.name not in allowed_names
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if re.search(r"fria", line, re.IGNORECASE)
    ]
    assert offenders == []


# --- FriaTier: EU_ECB_NEVER_RUNS_UNASSESSED -----------------------------------


@pytest.mark.asyncio
async def test_admitted_assessment_passes_and_always_consults_the_provider() -> None:
    provider = _FakeProvider(ValidationResult(admitted=True))
    tier = _tier(provider)
    # A confident model does not skip the provider: there is no fast path.
    assert (
        await tier.evaluate("execute_trade", {"confidence": 0.99, "thread_id": "t-1"})
        == []
    )
    assert len(provider.calls) == 1
    payload = provider.calls[0]
    assert payload["action"] == "execute_trade"
    assert payload["region"] == "EU_ECB"
    assert payload["control_id"] == "CTRL_FRIA_006"
    assert payload["thread_id"] == "t-1"


@pytest.mark.asyncio
async def test_human_review_finding_is_a_hitl_hold() -> None:
    provider = _FakeProvider(
        ValidationResult(
            admitted=False,
            findings=[{"needs_human_review": True, "message": "Annex III"}],
        )
    )
    [violation] = await _tier(provider).evaluate("execute_trade", {})
    assert (violation.code, violation.kind) == (CODE_HOLD, ViolationKind.HITL)
    assert violation.message.startswith("[CTRL_FRIA_006]")
    assert "Annex III" in violation.message


@pytest.mark.asyncio
async def test_refusal_without_review_is_hard() -> None:
    provider = _FakeProvider(
        ValidationResult(admitted=False, findings=[{"rule": "art27"}])
    )
    [violation] = await _tier(provider).evaluate("execute_trade", {})
    assert (violation.code, violation.kind) == (CODE_REJECTED, ViolationKind.HARD)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        _FakeProvider(hang=True),
        _FakeProvider(exc=ConnectionError("provider down")),
        _FakeProvider(ValidationResult(admitted=True, error="upstream 503")),
    ],
    ids=["timeout", "raises", "error_field"],
)
async def test_unavailable_provider_fails_closed(provider: _FakeProvider) -> None:
    [violation] = await _tier(provider).evaluate("execute_trade", {})
    assert (violation.code, violation.kind) == (CODE_UNAVAILABLE, ViolationKind.HARD)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("artefacts", "reason"),
    [
        ({}, "no FRIA artefact"),
        (
            {
                "execute_trade": {
                    "assessed_at": (_NOW - timedelta(days=366)).isoformat()
                }
            },
            "older than",
        ),
        (
            {"execute_trade": {"assessed_at": (_NOW + timedelta(days=1)).isoformat()}},
            "future",
        ),
        ({"execute_trade": {"assessed_at": "2026-09-01T00:00:00"}}, "no timezone"),
        ({"execute_trade": {"assessed_at": "last spring"}}, "not ISO-8601"),
        ({"execute_trade": {"assessor": "dpo"}}, "not ISO-8601"),
    ],
    ids=["missing", "stale", "future", "naive", "garbage", "no_timestamp"],
)
async def test_unassessed_action_is_refused_without_calling_the_provider(
    artefacts: dict[str, Any], reason: str
) -> None:
    provider = _FakeProvider()
    [violation] = await _tier(provider, artefacts).evaluate("execute_trade", {})
    assert (violation.code, violation.kind) == (CODE_STALE, ViolationKind.HARD)
    assert reason in violation.message
    assert provider.calls == []


@pytest.mark.asyncio
async def test_failing_artefact_lookup_is_stale() -> None:
    def _boom(action: str) -> None:
        raise OSError("baseline unreadable")

    provider = _FakeProvider()
    tier = FriaTier(
        provider,  # type: ignore[arg-type]
        region="EU_ECB",
        assessment_lookup=_boom,
        reassessment_interval_days=365,
        gate_timeout_seconds=1,
        clock=lambda: _NOW,
    )
    [violation] = await tier.evaluate("execute_trade", {})
    assert violation.code == CODE_STALE
    assert provider.calls == []


@pytest.mark.asyncio
async def test_system_wide_artefact_covers_unlisted_actions() -> None:
    provider = _FakeProvider()
    tier = _tier(provider, {SYSTEM_WIDE_ASSESSMENT: _FRESH})
    assert await tier.evaluate("rebalance_portfolio", {}) == []
    assert len(provider.calls) == 1


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan"), True, "365"])
def test_invalid_reassessment_interval_is_refused(bad: Any) -> None:
    with pytest.raises(ValueError, match="reassessment_interval_days"):
        _tier(_FakeProvider(), interval=bad)


def test_invalid_gate_timeout_is_refused() -> None:
    with pytest.raises(ValueError, match="gate_timeout_seconds"):
        _tier(_FakeProvider(), timeout=0)


def test_default_tier_claims_every_action_and_a_classifier_narrows() -> None:
    assert _tier(_FakeProvider()).claims_action("anything", {}) is True
    narrowed = _tier(
        _FakeProvider(), claims=lambda action, params: action == "execute_trade"
    )
    assert narrowed.claims_action("execute_trade", {}) is True
    assert narrowed.claims_action("get_quote", {}) is False


def test_reassessment_interval_comes_from_the_eu_thresholds_baseline(
    tmp_path: pathlib.Path,
) -> None:
    assert eu_ai_act.load_reassessment_interval_days() == 365
    missing = tmp_path / "EU_ECB_BASELINE.json"
    missing.write_text('{"fria": {}}')
    with pytest.raises(RuntimeError, match="fria_reassessment_interval_days"):
        eu_ai_act.load_reassessment_interval_days(missing)


def test_invalid_gate_timeout_env_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(eu_ai_act.GATE_TIMEOUT_ENV, "soon")
    with pytest.raises(RuntimeError, match="not a number"):
        eu_ai_act.gate_timeout_seconds()


def test_registry_lookup_finds_nothing_outside_eu() -> None:
    ControlRegistry.reconfigure("US_FED")
    assert ControlRegistry().active_region != "EU_ECB"
    assert eu_ai_act.registry_assessment_lookup("execute_trade") is None


def test_reference_eu_baseline_carries_no_fabricated_assessment() -> None:
    """The committed baseline has no artefact: a stub-backed EU run refuses every claimed action."""
    ControlRegistry.reconfigure("EU_ECB")
    assert eu_ai_act.registry_assessment_lookup("execute_trade") is None
    assert eu_ai_act.registry_assessment_lookup(SYSTEM_WIDE_ASSESSMENT) is None


# --- Governor-level verdicts ----------------------------------------------------


def _fria_only_governor(provider: _FakeProvider) -> SymbolicGovernor:
    return SymbolicGovernor(
        GovernorComponents(
            opa=allow_opa(),
            core_stages=(),
            classifier=default_classifier(),
            posture=DeploymentPosture.TEST,
            jurisdiction=JurisdictionContribution(
                region="EU_ECB", tiers=(_tier(provider, timeout=0.05),)
            ),
        )
    )


@pytest.fixture
def defer_redis(monkeypatch: pytest.MonkeyPatch) -> Any:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis(decode_responses=True)

    @asynccontextmanager
    async def _queue() -> AsyncIterator[defer_queue_mod.DeferQueue]:
        yield defer_queue_mod.DeferQueue(redis)

    monkeypatch.setattr(defer_queue_mod, "open_defer_queue", _queue)
    return redis


@pytest.mark.asyncio
async def test_fria_hold_parks_an_approval_token(defer_redis: Any) -> None:
    provider = _FakeProvider(
        ValidationResult(admitted=False, findings=[{"needs_human_review": True}])
    )
    result = await _fria_only_governor(provider).validate_action(
        "execute_trade", {"amount": 10}
    )
    assert result["verdict"] == "REQUIRE_APPROVAL"
    assert result["deferred_id"]
    async with defer_queue_mod.open_defer_queue() as queue:
        token = await queue.get(result["deferred_id"])
    assert token is not None


@pytest.mark.asyncio
async def test_fria_provider_timeout_denies_with_a_receipt(defer_redis: Any) -> None:
    with pytest.raises(GovernanceError) as exc:
        await _fria_only_governor(_FakeProvider(hang=True)).validate_action(
            "execute_trade", {"amount": 10}
        )
    assert exc.value.receipt is not None
    assert "CTRL_FRIA_006" in str(exc.value)


@pytest.mark.asyncio
async def test_admitted_fria_allows(defer_redis: Any) -> None:
    result = await _fria_only_governor(_FakeProvider()).validate_action(
        "execute_trade", {"amount": 10}
    )
    assert result["verdict"] == "ALLOW"


# --- Posture: an enforcing EU posture refuses the stub --------------------------


@pytest.fixture
def healthy(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Every non-jurisdiction probe healthy (mirrors test_startup_posture)."""

    class _Signer:
        is_kms_active = True

        def validate_ready(self) -> None:
            return None

    class _Verifier:
        trust_anchor_kids = ("projects/p/cryptoKeys/reconciler/cryptoKeyVersions/1",)

    class _Redis:
        def ping_ready(self) -> None:
            return None

    monkeypatch.setattr(posture_mod, "_signer", lambda: _Signer())
    monkeypatch.setattr(posture_mod, "_redis", lambda: _Redis())
    monkeypatch.setattr(posture_mod, "_reconciler_verifier", lambda: _Verifier())
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "ledger")
    monkeypatch.setenv(
        "KMS_GOVERNANCE_KEY",
        "projects/p/locations/l/keyRings/r/cryptoKeys/cage-gateway-seal-signer",
    )
    monkeypatch.setenv(
        "RECONCILER_KMS_KEY",
        "projects/p/locations/l/keyRings/r/cryptoKeys/cage-reconciler-snapshot-signer",
    )
    monkeypatch.setattr(
        "src.gateway.governance.routing_seal._USING_DEFAULT_SALT", False
    )
    return monkeypatch


def _eu_components(provider: Any, posture: DeploymentPosture) -> GovernorComponents:
    return GovernorComponents(
        opa=allow_opa(),
        core_stages=(),
        classifier=default_classifier(),
        posture=posture,
        jurisdiction=eu_ai_act.contribution(provider=provider),
    )


def test_enforcing_eu_posture_refuses_the_stub_provider(
    healthy: pytest.MonkeyPatch,
) -> None:
    components = _eu_components(StubNormativeProvider(), DeploymentPosture.PRODUCTION)
    with pytest.raises(
        PostureViolation, match="jurisdiction_requirements.*fria_normative_provider"
    ):
        assert_production_posture(DeploymentPosture.PRODUCTION, components=components)


def test_enforcing_eu_posture_accepts_a_real_provider(
    healthy: pytest.MonkeyPatch,
) -> None:
    components = _eu_components(_FakeProvider(), DeploymentPosture.PRODUCTION)
    assert_production_posture(DeploymentPosture.PRODUCTION, components=components)


def test_permissive_eu_posture_logs_but_starts_on_the_stub(
    healthy: pytest.MonkeyPatch,
) -> None:
    components = _eu_components(StubNormativeProvider(), DeploymentPosture.DEV)
    assert_production_posture(DeploymentPosture.DEV, components=components)


def test_non_eu_posture_has_no_jurisdiction_requirement(
    healthy: pytest.MonkeyPatch,
) -> None:
    components = GovernorComponents(
        opa=allow_opa(),
        core_stages=(),
        classifier=default_classifier(),
        posture=DeploymentPosture.PRODUCTION,
        jurisdiction=resolve_jurisdiction("US_FED"),
    )
    assert_production_posture(DeploymentPosture.PRODUCTION, components=components)
