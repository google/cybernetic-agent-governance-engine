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

"""End-to-end enforcement tests for declared consequence magnitudes (POAM-2026-155).

Covers:
1. Pre-flight (``FriaTier.evaluate``), mint (``mint_consequence_token_finding``),
   and consume (``ConsequenceGateway.evaluate``) across every refusal reason
   (zero, negative, boolean, non-numeric, non-finite, sub-minor-unit dust,
   unsafe IEEE-754 integer, absent path, top-level-only magnitude, undeclared
   action) at both length-1 (``params.amount``) and nested
   (``params.payment.amount``) paths.
2. Consume refusal leaves the single-use authority record marker unconsumed in
   ``ConsequenceAuthorityStore``.
3. ``FriaTier`` pre-flight refusal never calls ``provider.validate_fria``.
4. ``assemble_governor`` validation of ``PluginContribution.consequence_magnitudes``
   and ``JurisdictionContribution.consequence_magnitudes``.
5. Per-plugin blast-radius verification for ``finance``, ``healthcare``, and
   ``physical_ai``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import fakeredis.aioredis
import pytest
from opentelemetry.sdk.trace import TracerProvider

from src.cage_finance import (
    CONSEQUENCE_MAGNITUDES as FINANCE_MAGNITUDES,
)
from src.cage_finance import (
    REGISTERED_ACTIONS as FINANCE_ACTIONS,
)
from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_healthcare.constants import (
    CONSEQUENCE_MAGNITUDES as HEALTHCARE_MAGNITUDES,
)
from src.cage_healthcare.constants import (
    REGISTERED_ACTIONS as HEALTHCARE_ACTIONS,
)
from src.cage_healthcare.plugin import HealthcareCagePlugin
from src.cage_physical_ai.constants import PHYSICAL_AI_GOVERNED_ACTIONS
from src.cage_physical_ai.plugin import PhysicalAICagePlugin
from src.cage_physical_ai.tiers.kinematic_barrier_tier import _CLAIMED_PHYSICAL_ACTIONS
from src.cage_physical_ai.tiers.physical_consensus_tier import (
    HIGH_STAKES_PHYSICAL_ACTIONS,
)
from src.gateway.governance.consequence_authority_store import ConsequenceAuthorityStore
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_magnitude import (
    MAX_SAFE_MINOR_UNITS,
    ConsequenceMagnitudes,
    MagnitudeReason,
)
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.consequence_token_service import (
    FINDING_CODE_CONSEQUENCE_TOKEN,
    FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
    mint_consequence_token_finding,
)
from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.contracts import (
    ConsequenceMagnitude,
    MagnitudePath,
    PluginContribution,
    ViolationKind,
)
from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.assembly import (
    DecisionFlags,
    GovernorAssemblyError,
    assemble_governor,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.jurisdiction import (
    JurisdictionContribution,
    eu_ai_act,
    resolve_jurisdiction,
)
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import (
    CODE_MAGNITUDE,
    CODE_STALE,
    SYSTEM_WIDE_ASSESSMENT,
    FriaTier,
)
from src.gateway.governance.normative_provider import get_normative_provider
from src.gateway.governance.plugin_loader import domain_config_of
from src.gateway.governance.seams.normative import ValidationResult
from src.gateway.infrastructure.redis_replication import ReplicationPolicy
from src.integrations.provider_01.provider import FlowSignalNormativeProvider
from src.integrations.provider_08.adapter import Provider08NormativeProvider
from tests.fixtures.governor import allow_opa, clean_stpa
from tests.test_consequence_gateway import _make_mock_signer_with_keypair

pytestmark = [pytest.mark.unit, pytest.mark.local]

_TRACER = TracerProvider().get_tracer(__name__)


@pytest.fixture(autouse=True)
def _active_otel_span() -> Iterator[None]:
    """FriaTier builds its payload only under an active trace span."""
    with _TRACER.start_as_current_span("test"):
        yield


_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
_FRESH = {"assessed_at": (_NOW - timedelta(days=10)).isoformat()}

_POLICY = ConsequenceMagnitudes(
    (
        ConsequenceMagnitude(
            "flat_transfer",
            (MagnitudePath(("amount",), minor_unit_digits=2),),
        ),
        ConsequenceMagnitude(
            "nested_transfer",
            (MagnitudePath(("payment", "amount"), minor_unit_digits=2),),
        ),
        ConsequenceMagnitude(
            "whole_units",
            (MagnitudePath(("count",), minor_unit_digits=0),),
        ),
        ConsequenceMagnitude(
            "multi_leg",
            (
                MagnitudePath(("principal",), minor_unit_digits=2),
                MagnitudePath(("fee", "amount"), minor_unit_digits=2),
            ),
        ),
        ConsequenceMagnitude("read_quote", ()),
    )
)


class _RecordingProvider:
    """NormativeProvider test double recording every ``validate_fria`` call."""

    def __init__(self, result: ValidationResult | None = None) -> None:
        self.result = result if result is not None else ValidationResult(admitted=True)
        self.calls: list[dict[str, Any]] = []

    async def fetch_baseline(self, region: str) -> Any:  # pragma: no cover
        raise NotImplementedError

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        self.calls.append(payload)
        return self.result

    async def submit_evidence(self, receipt: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError


def _make_fria_tier(
    provider: _RecordingProvider,
    magnitudes: ConsequenceMagnitudes | None = _POLICY,
    *,
    fresh: bool = True,
) -> FriaTier:
    artefacts = (
        {SYSTEM_WIDE_ASSESSMENT: _FRESH}
        if fresh
        else {
            SYSTEM_WIDE_ASSESSMENT: {
                "assessed_at": (_NOW - timedelta(days=400)).isoformat()
            }
        }
    )
    return FriaTier(
        provider,  # type: ignore[arg-type]
        region="EU_ECB",
        assessment_lookup=lambda action: artefacts.get(action),
        reassessment_interval_days=365,
        gate_timeout_seconds=1.0,
        clock=lambda: _NOW,
        consequence_magnitudes=magnitudes,
    )


@pytest.fixture
def signer():
    signer_obj, _ = _make_mock_signer_with_keypair("ec_p256")
    return signer_obj


@pytest.fixture
async def store() -> ConsequenceAuthorityStore:
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return ConsequenceAuthorityStore(
        redis_client=redis_client,
        replication=ReplicationPolicy.standalone(),
        ttl_seconds=90,
    )


@pytest.fixture
def gateway(store: ConsequenceAuthorityStore, signer) -> ConsequenceGateway:
    return ConsequenceGateway(store=store, signer=signer, magnitudes=_POLICY)


def _wrap_params(action: str, path: tuple[str, ...], value: Any) -> dict[str, Any]:
    if len(path) == 1:
        return {"action": action, "params": {path[0]: value}}
    return {"action": action, "params": {path[0]: {path[1]: value}}}


# ---------------------------------------------------------------------------
# 1. Invalid values refused across all three boundaries (flat & nested paths)
# ---------------------------------------------------------------------------

_INVALID_VALUES_AND_DETAILS: list[tuple[str, Any, str]] = [
    ("int_zero", 0, "is not positive"),
    ("float_zero", 0.0, "is not positive"),
    ("neg_zero", -0.0, "is not positive"),
    ("neg_int", -1, "is not positive"),
    ("neg_float", -0.01, "is not positive"),
    ("bool_true", True, "is a boolean, not a number"),
    ("bool_false", False, "is a boolean, not a number"),
    ("str_num", "10.00", "not a number"),
    ("none_val", None, "not a number"),
    ("list_val", [10], "not a number"),
    ("dict_val", {"v": 10}, "not a number"),
    ("nan", float("nan"), "is not a finite number"),
    ("pos_inf", float("inf"), "is not a finite number"),
    ("neg_inf", float("-inf"), "is not a finite number"),
    ("dust_sub_cent", 0.001, "is not a whole number of minor units"),
    ("dust_half_cent", 10.005, "is not a whole number of minor units"),
    (
        "scaled_overflow_int",
        MAX_SAFE_MINOR_UNITS,
        "exceeds 9007199254740991 minor units",
    ),
    ("scaled_overflow_float", float(2**53), "exceeds 9007199254740991 minor units"),
    (
        "scaled_overflow_90T",
        90_071_992_547_410.0,
        "exceeds 9007199254740991 minor units",
    ),
]


@pytest.mark.parametrize(
    ("action", "path"),
    [
        ("flat_transfer", ("amount",)),
        ("nested_transfer", ("payment", "amount")),
    ],
    ids=["flat_path", "nested_path"],
)
@pytest.mark.parametrize(
    ("_case_id", "bad_value", "expected_detail"),
    _INVALID_VALUES_AND_DETAILS,
    ids=[c[0] for c in _INVALID_VALUES_AND_DETAILS],
)
@pytest.mark.asyncio
async def test_invalid_magnitude_refused_at_preflight_mint_and_consume(
    action: str,
    path: tuple[str, ...],
    _case_id: str,
    bad_value: Any,
    expected_detail: str,
    signer,
    store: ConsequenceAuthorityStore,
    gateway: ConsequenceGateway,
) -> None:
    payload = _wrap_params(action, path, bad_value)
    dotted_path = ".".join(("params", *path))

    # (a) FriaTier pre-flight refuses before calling provider.validate_fria
    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, _POLICY)
    violations = await tier.evaluate(action, payload["params"])
    assert len(violations) == 1
    assert violations[0].code == CODE_MAGNITUDE
    assert violations[0].kind == ViolationKind.HARD
    assert MagnitudeReason.INVALID.value in violations[0].message
    assert dotted_path in violations[0].message
    assert expected_detail in violations[0].message
    assert provider.calls == []

    # (b) ConsequenceToken mint service refuses fail-closed without calling KMS
    mock_signer = MagicMock()
    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=mock_signer,
    ):
        finding = await mint_consequence_token_finding(
            actor_id="actor-1",
            thread_id="thread-1",
            authority_record_id="rec-1",
            action_payload=payload,
            magnitudes=_POLICY,
        )
    assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
    assert finding["severity"] == "blocked"
    if expected_detail == "is not a finite number":
        assert "non-finite number" in finding["message"]
    else:
        assert finding.get("reason_code") == MagnitudeReason.INVALID.value
        assert expected_detail in finding["message"]
    mock_signer.sign_raw.assert_not_called()

    # (c) ConsequenceGateway.evaluate refuses at Step 5 without consuming the receipt
    # Note: NaN/Inf cannot be JCS-canonicalized into a valid token digest; for those,
    # Step 3 rejects with ACTION_BINDING_MISMATCH before Step 5, still without consuming.
    rec_id = f"rec-{action}-{_case_id}"
    if expected_detail == "is not a finite number":
        forged_token = await ConsequenceToken.mint(
            sub="actor-1",
            tid="thread-1",
            rec=rec_id,
            act="0" * 64,
            ver="v1",
            ttl_seconds=60,
            signer=signer,
        )
        eval_res = await gateway.evaluate(forged_token, payload)
        assert eval_res.decision == ConsequenceDecision.BLOCK
        assert eval_res.reason_code == "ACTION_BINDING_MISMATCH"
        assert await store.get_binding(rec_id) is None
    else:
        digest = hashlib.sha256(jcs_canonicalize_plan(payload)).hexdigest()
        token = await ConsequenceToken.mint(
            sub="actor-1",
            tid="thread-1",
            rec=rec_id,
            act=digest,
            ver="v1",
            ttl_seconds=60,
            signer=signer,
        )
        eval_res = await gateway.evaluate(token, payload)
        assert eval_res.decision == ConsequenceDecision.BLOCK
        assert eval_res.reason_code == MagnitudeReason.INVALID.value
        assert expected_detail in eval_res.detail
        assert await store.get_binding(rec_id) is None


# ---------------------------------------------------------------------------
# 2. Structural & policy refusals: top-level-only, absent path, undeclared
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_top_level_only_magnitude_refused_as_absent_at_all_boundaries(
    signer,
    store: ConsequenceAuthorityStore,
    gateway: ConsequenceGateway,
) -> None:
    """A magnitude placed at the top level instead of under params is refused."""
    payload = {"action": "flat_transfer", "amount": 10.0, "params": {}}

    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, _POLICY)
    [violation] = await tier.evaluate("flat_transfer", payload["params"])
    assert violation.code == CODE_MAGNITUDE
    assert MagnitudeReason.ABSENT.value in violation.message
    assert provider.calls == []

    finding = await mint_consequence_token_finding(
        actor_id="actor-1",
        thread_id="thread-1",
        authority_record_id="rec-top",
        action_payload=payload,
        magnitudes=_POLICY,
    )
    assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
    assert finding["reason_code"] == MagnitudeReason.ABSENT.value

    digest = hashlib.sha256(jcs_canonicalize_plan(payload)).hexdigest()
    token = await ConsequenceToken.mint(
        sub="actor-1",
        tid="thread-1",
        rec="rec-top",
        act=digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )
    eval_res = await gateway.evaluate(token, payload)
    assert eval_res.decision == ConsequenceDecision.BLOCK
    assert eval_res.reason_code == MagnitudeReason.ABSENT.value
    assert await store.get_binding("rec-top") is None


@pytest.mark.asyncio
async def test_undeclared_action_and_none_policy_refused_at_all_boundaries(
    signer,
    store: ConsequenceAuthorityStore,
    gateway: ConsequenceGateway,
) -> None:
    """An undeclared action (or None policy) fails closed with MAGNITUDE_UNDECLARED."""
    payload = {"action": "undeclared_op", "params": {"amount": 100.0}}

    for policy in (_POLICY, None, ConsequenceMagnitudes()):
        provider = _RecordingProvider()
        tier = _make_fria_tier(provider, policy)
        [violation] = await tier.evaluate("undeclared_op", payload["params"])
        assert violation.code == CODE_MAGNITUDE
        assert MagnitudeReason.UNDECLARED.value in violation.message
        assert provider.calls == []

        finding = await mint_consequence_token_finding(
            actor_id="actor-1",
            thread_id="thread-1",
            authority_record_id="rec-undeclared",
            action_payload=payload,
            magnitudes=policy,
        )
        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["reason_code"] == MagnitudeReason.UNDECLARED.value

    digest = hashlib.sha256(jcs_canonicalize_plan(payload)).hexdigest()
    token = await ConsequenceToken.mint(
        sub="actor-1",
        tid="thread-1",
        rec="rec-undeclared",
        act=digest,
        ver="v1",
        ttl_seconds=60,
        signer=signer,
    )
    eval_res = await gateway.evaluate(token, payload)
    assert eval_res.decision == ConsequenceDecision.BLOCK
    assert eval_res.reason_code == MagnitudeReason.UNDECLARED.value
    assert await store.get_binding("rec-undeclared") is None


@pytest.mark.asyncio
async def test_stale_artefact_still_checked_before_preflight_magnitude() -> None:
    """Staleness check runs before pre-flight magnitude check in FriaTier."""
    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, _POLICY, fresh=False)
    [violation] = await tier.evaluate("flat_transfer", {"amount": -10.0})
    assert violation.code == CODE_STALE
    assert provider.calls == []


# ---------------------------------------------------------------------------
# 3. Valid magnitudes and explicitly magnitude-free actions pass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("flat_transfer", {"amount": 0.01}),
        ("flat_transfer", {"amount": 250_000.50}),
        ("flat_transfer", {"amount": 90_071_992_547_409.0}),
        ("nested_transfer", {"payment": {"amount": 42.75}}),
        ("whole_units", {"count": 1}),
        ("whole_units", {"count": MAX_SAFE_MINOR_UNITS}),
        ("multi_leg", {"principal": 100.0, "fee": {"amount": 0.25}}),
        ("read_quote", {}),
        ("read_quote", {"symbol": "AAPL", "amount": 0}),
    ],
)
@pytest.mark.asyncio
async def test_valid_and_magnitude_free_actions_admitted_across_all_boundaries(
    action: str,
    params: dict[str, Any],
    signer,
    store: ConsequenceAuthorityStore,
    gateway: ConsequenceGateway,
) -> None:
    payload = {"action": action, "params": params}

    # (a) FriaTier pre-flight admits and calls provider.validate_fria
    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, _POLICY)
    assert await tier.evaluate(action, params) == []
    assert len(provider.calls) == 1

    # (b) ConsequenceToken mint service mints a valid token
    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=signer,
    ):
        finding = await mint_consequence_token_finding(
            actor_id="actor-1",
            thread_id="thread-1",
            authority_record_id=f"rec-ok-{action}-{hash(str(params))}",
            action_payload=payload,
            authority_state_version="v1",
            ttl_seconds=60,
            magnitudes=_POLICY,
        )
    assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN
    token = finding["token"]

    # (c) ConsequenceGateway.evaluate consumes the token once and returns EXECUTE
    eval_res = await gateway.evaluate(token, payload)
    assert eval_res.decision == ConsequenceDecision.EXECUTE
    assert eval_res.reason_code == "OK"
    assert await store.get_binding(finding["authority_record_id"]) is not None


@pytest.mark.asyncio
async def test_consume_refusal_leaves_receipt_unconsumed_for_valid_retry(
    signer,
    store: ConsequenceAuthorityStore,
) -> None:
    """When ConsequenceGateway refuses a bad magnitude at Step 5, the receipt is not burned."""
    permissive_mint_policy = ConsequenceMagnitudes(
        (ConsequenceMagnitude("flat_transfer", ()),)
    )
    strict_consume_gateway = ConsequenceGateway(
        store=store, signer=signer, magnitudes=_POLICY
    )
    bad_payload = {"action": "flat_transfer", "params": {"amount": -5.0}}

    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=signer,
    ):
        finding = await mint_consequence_token_finding(
            actor_id="actor-1",
            thread_id="thread-1",
            authority_record_id="rec-unburned",
            action_payload=bad_payload,
            magnitudes=permissive_mint_policy,
        )
    assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN

    eval_bad = await strict_consume_gateway.evaluate(finding["token"], bad_payload)
    assert eval_bad.decision == ConsequenceDecision.BLOCK
    assert eval_bad.reason_code == MagnitudeReason.INVALID.value
    assert "is not positive" in eval_bad.detail
    assert await store.get_binding("rec-unburned") is None


# ---------------------------------------------------------------------------
# 4. Assembly & Jurisdiction consistency enforcement
# ---------------------------------------------------------------------------


class _StubPlugin:
    api_version = "2.0"
    domain_config = None

    def __init__(
        self,
        name: str,
        *,
        registered_actions: tuple[str, ...] = (),
        consequence_magnitudes: tuple[ConsequenceMagnitude, ...] = (),
    ) -> None:
        self.name = name
        self._registered = registered_actions
        self._magnitudes = consequence_magnitudes

    def contribute(self) -> PluginContribution:
        return PluginContribution(
            domain=self.name,
            registered_actions=self._registered,
            consequence_magnitudes=self._magnitudes,
        )


def test_assemble_governor_rejects_unregistered_consequence_magnitude_action() -> None:
    plugin = _StubPlugin(
        "probe",
        registered_actions=("known_action",),
        consequence_magnitudes=(ConsequenceMagnitude("ghost_action", ()),),
    )
    with pytest.raises(
        GovernorAssemblyError,
        match="declares a consequence magnitude for 'ghost_action', which it does not register",
    ):
        assemble_governor(
            [plugin],
            posture=DeploymentPosture.TEST,
            opa=allow_opa(),
            stpa_validator=clean_stpa(),
            flags=DecisionFlags(defer=False, narrow=False),
            jurisdiction=resolve_jurisdiction("US_FED"),
        )


def test_assemble_governor_rejects_duplicate_consequence_magnitude_across_plugins() -> (
    None
):
    p1 = _StubPlugin(
        "p1",
        registered_actions=("shared_action",),
        consequence_magnitudes=(ConsequenceMagnitude("shared_action", ()),),
    )
    p2 = _StubPlugin(
        "p2",
        registered_actions=("shared_action",),
        consequence_magnitudes=(ConsequenceMagnitude("shared_action", ()),),
    )
    with pytest.raises(
        GovernorAssemblyError,
        match="duplicate consequence magnitude: 'shared_action' is contributed twice",
    ):
        assemble_governor(
            [p1, p2],
            posture=DeploymentPosture.TEST,
            opa=allow_opa(),
            stpa_validator=clean_stpa(),
            flags=DecisionFlags(defer=False, narrow=False),
            jurisdiction=resolve_jurisdiction("US_FED"),
        )


def test_assemble_governor_rejects_foreign_jurisdiction_magnitude_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region="EU_ECB"),
    )
    foreign_policy = ConsequenceMagnitudes((ConsequenceMagnitude("execute_trade", ()),))
    foreign_jurisdiction = eu_ai_act.contribution(
        provider=_RecordingProvider(),  # type: ignore[arg-type]
        consequence_magnitudes=foreign_policy,
    )
    with pytest.raises(
        GovernorAssemblyError,
        match="jurisdiction 'EU_ECB' checks a consequence-magnitude policy the domain contributions did not declare",
    ):
        assemble_governor(
            [FinanceCagePlugin()],
            posture=DeploymentPosture.TEST,
            opa=allow_opa(),
            stpa_validator=clean_stpa(),
            flags=DecisionFlags(defer=True, narrow=False),
            jurisdiction=foreign_jurisdiction,
        )


def test_assemble_governor_rejects_tier_with_foreign_magnitude_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance.schemas import thresholds as thresholds_module

    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region="EU_ECB"),
    )
    finance_policy = ConsequenceMagnitudes(FINANCE_MAGNITUDES)
    foreign_tier = _make_fria_tier(
        _RecordingProvider(),
        ConsequenceMagnitudes((ConsequenceMagnitude("execute_trade", ()),)),
    )
    bad_jurisdiction = JurisdictionContribution(
        region="EU_ECB",
        tiers=(foreign_tier,),
        consequence_magnitudes=finance_policy,
    )
    with pytest.raises(
        GovernorAssemblyError,
        match="jurisdiction 'EU_ECB' tier 'fria' checks a consequence-magnitude policy the domain contributions did not declare",
    ):
        assemble_governor(
            [FinanceCagePlugin()],
            posture=DeploymentPosture.TEST,
            opa=allow_opa(),
            stpa_validator=clean_stpa(),
            flags=DecisionFlags(defer=True, narrow=False),
            jurisdiction=bad_jurisdiction,
        )


def test_normative_provider_factory_threads_consequence_magnitudes() -> None:
    p01 = get_normative_provider("provider_01", consequence_magnitudes=_POLICY)
    assert isinstance(p01, FlowSignalNormativeProvider)
    assert p01._consequence_magnitudes == _POLICY

    p08 = get_normative_provider("provider_08", consequence_magnitudes=_POLICY)
    assert isinstance(p08, Provider08NormativeProvider)
    assert p08._consequence_magnitudes == _POLICY


# ---------------------------------------------------------------------------
# 5. Per-plugin blast-radius verification (finance, healthcare, physical_ai)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finance_plugin_consequence_magnitudes_eu_posture(
    monkeypatch: pytest.MonkeyPatch,
    signer,
) -> None:
    """FinanceCagePlugin declares all 6 registered actions; loses declarations -> fails."""
    from src.gateway.governance.schemas import thresholds as thresholds_module
    from tests.fixtures.governor import StaticWarrantSource

    ControlRegistry.reconfigure("EU_ECB")
    monkeypatch.setattr(
        thresholds_module,
        "THRESHOLDS",
        thresholds_module.load_and_validate_thresholds(region="EU_ECB"),
    )
    governor = assemble_governor(
        [FinanceCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=True, narrow=False),
        warrant_source=StaticWarrantSource.eligible(),
    )
    policy = governor.components.consequence_magnitudes
    assert set(policy.actions) == set(FINANCE_ACTIONS)
    assert governor.components.jurisdiction is not None
    assert governor.components.jurisdiction.consequence_magnitudes == policy

    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, policy)

    amount_actions = ("execute_trade", "execute_trade_bounded")
    magnitude_free_actions = (
        "check_balance",
        "market_analysis",
        "check_market_status",
        "prompt_injection_check",
    )
    assert set(amount_actions) | set(magnitude_free_actions) == set(FINANCE_ACTIONS)

    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=signer,
    ):
        for action in amount_actions:
            # Valid whole-cent amount passes both pre-flight and mint
            assert await tier.evaluate(action, {"amount": 125.50}) == []
            ok_finding = await mint_consequence_token_finding(
                actor_id="trader-1",
                thread_id="thread-fin",
                authority_record_id=f"rec-{action}",
                action_payload={"action": action, "params": {"amount": 125.50}},
                magnitudes=policy,
            )
            assert ok_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN

            # Sub-cent dust, zero, negative, or missing amount is refused at both
            for bad_params in (
                {},
                {"amount": 0.0},
                {"amount": -10.0},
                {"amount": 10.005},
            ):
                [violation] = await tier.evaluate(action, bad_params)
                assert violation.code == CODE_MAGNITUDE
                bad_finding = await mint_consequence_token_finding(
                    actor_id="trader-1",
                    thread_id="thread-fin",
                    authority_record_id=f"rec-{action}-bad",
                    action_payload={"action": action, "params": bad_params},
                    magnitudes=policy,
                )
                assert bad_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED

        for action in magnitude_free_actions:
            assert await tier.evaluate(action, {}) == []
            ok_finding = await mint_consequence_token_finding(
                actor_id="trader-1",
                thread_id="thread-fin",
                authority_record_id=f"rec-{action}",
                action_payload={"action": action, "params": {}},
                magnitudes=policy,
            )
            assert ok_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN


@pytest.mark.asyncio
async def test_healthcare_plugin_consequence_magnitudes_eu_posture(
    signer,
) -> None:
    """HealthcareCagePlugin declares 5 dosing actions (nanogram precision) and leaves 2 undeclared."""
    governor = assemble_governor(
        [HealthcareCagePlugin()],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False),
        jurisdiction=resolve_jurisdiction("US_FED"),
    )
    policy = governor.components.consequence_magnitudes
    assert policy == ConsequenceMagnitudes(HEALTHCARE_MAGNITUDES)
    declared_dosing = {
        "administer_dose",
        "dose_order",
        "administer_medication",
        "prescribe_medication",
        "order_controlled_substance",
    }
    undeclared_clinical = {"adjust_dosage", "override_contraindication"}
    assert declared_dosing | undeclared_clinical == set(HEALTHCARE_ACTIONS)
    assert set(policy.actions) == declared_dosing

    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, policy)

    with patch(
        "src.gateway.governance.consequence_token_service.get_governance_signer",
        return_value=signer,
    ):
        for action in sorted(declared_dosing):
            # 0.00025 mg (0.25 micrograms, e.g. calcitriol) is 250 whole nanograms -> admitted
            assert await tier.evaluate(action, {"dose_mg": 0.00025}) == []
            ok_finding = await mint_consequence_token_finding(
                actor_id="clinician-1",
                thread_id="thread-hc",
                authority_record_id=f"rec-{action}",
                action_payload={"action": action, "params": {"dose_mg": 0.00025}},
                magnitudes=policy,
            )
            assert ok_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN

            # Sub-nanogram dust (1e-7 mg), zero, negative, or missing dose_mg -> refused
            for bad_params in (
                {},
                {"dose_mg": 0.0},
                {"dose_mg": -0.5},
                {"dose_mg": 1e-7},
            ):
                [violation] = await tier.evaluate(action, bad_params)
                assert violation.code == CODE_MAGNITUDE
                bad_finding = await mint_consequence_token_finding(
                    actor_id="clinician-1",
                    thread_id="thread-hc",
                    authority_record_id=f"rec-{action}-bad",
                    action_payload={"action": action, "params": bad_params},
                    magnitudes=policy,
                )
                assert bad_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED

        # Deliberately undeclared actions are refused MAGNITUDE_UNDECLARED at pre-flight and mint
        calls_before = len(provider.calls)
        for action in sorted(undeclared_clinical):
            [violation] = await tier.evaluate(action, {"dose_mg": 5.0})
            assert violation.code == CODE_MAGNITUDE
            assert MagnitudeReason.UNDECLARED.value in violation.message

            bad_finding = await mint_consequence_token_finding(
                actor_id="clinician-1",
                thread_id="thread-hc",
                authority_record_id=f"rec-{action}",
                action_payload={"action": action, "params": {"dose_mg": 5.0}},
                magnitudes=policy,
            )
            assert bad_finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
            assert bad_finding["reason_code"] == MagnitudeReason.UNDECLARED.value
        assert len(provider.calls) == calls_before


@pytest.mark.asyncio
async def test_physical_ai_plugin_refused_before_assembly_and_undeclared_at_consequence_boundary() -> (
    None
):
    """Pins both conditions for physical_ai:
    1. CAGE_DOMAIN=physical_ai is refused before assembly (POAM-2026-077: domain_config is None).
    2. Its contribution registers no actions and no consequence_magnitudes, so every
       action claimed by its tiers is refused MAGNITUDE_UNDECLARED at FriaTier pre-flight
       and at ConsequenceToken minting. If physical_ai ever becomes runnable, this test
       fails and forces explicit ConsequenceMagnitude declarations.
    """
    plugin = PhysicalAICagePlugin()
    with pytest.raises(RuntimeError, match="declares no DomainConfig"):
        domain_config_of(plugin)

    contribution = plugin.contribute()
    assert contribution.registered_actions == frozenset()
    assert contribution.consequence_magnitudes == ()

    governor = assemble_governor(
        [plugin],
        posture=DeploymentPosture.TEST,
        opa=allow_opa(),
        stpa_validator=clean_stpa(),
        flags=DecisionFlags(defer=False, narrow=False),
        jurisdiction=resolve_jurisdiction("US_FED"),
    )
    policy = governor.components.consequence_magnitudes
    assert policy.actions == frozenset()

    all_physical_actions = (
        PHYSICAL_AI_GOVERNED_ACTIONS
        | _CLAIMED_PHYSICAL_ACTIONS
        | HIGH_STAKES_PHYSICAL_ACTIONS
    )
    assert len(all_physical_actions) == 9

    provider = _RecordingProvider()
    tier = _make_fria_tier(provider, policy)

    for action in sorted(all_physical_actions):
        [violation] = await tier.evaluate(
            action, {"velocity_m_s": 0.5, "target_velocity_mm_s": 500.0}
        )
        assert violation.code == CODE_MAGNITUDE
        assert MagnitudeReason.UNDECLARED.value in violation.message

        finding = await mint_consequence_token_finding(
            actor_id="robot-controller-1",
            thread_id="thread-phys",
            authority_record_id=f"rec-{action}",
            action_payload={
                "action": action,
                "params": {"velocity_m_s": 0.5, "target_velocity_mm_s": 500.0},
            },
            magnitudes=policy,
        )
        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["reason_code"] == MagnitudeReason.UNDECLARED.value

    assert provider.calls == []
