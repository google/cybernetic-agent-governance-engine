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

"""Unit tests for RP-1 WORM refusal parameter projection (POAM-2026-225).

Verifies that:
1. A domain plugin declaring no ``evaluated_param_specs`` leaks nothing
   (``evaluated_params == {}``) while ``params_hash`` binds the exact refused
   request.
2. ``EvaluatedParamSpec`` enforces closed value shapes (``NUMBER``,
   ``BOOLEAN``, ``ENUM``, ``UPPER_ALPHA_CODE``) and rejects identifier,
   credential, and free-text parameter names at declaration and assembly time.
3. Extra caller/LLM-hallucinated keys and prose stuffed inside declared keys
   never appear in ``GOVERNANCE_REFUSAL`` or ``GOVERNANCE_REFUSAL_RECEIPT``
   WORM records, while ``RefusalReceipt.attempted_params`` stays available in
   memory for offline ``Profile.DRY_RUN`` evaluation.
4. ``FinanceCagePlugin`` and ``HealthcareCagePlugin`` (``DoseOrder`` with
   ``patient_id`` and clinical ``indication``) emit zero PII/free-text bytes
   into WORM refusal records and verify ``proof_hash`` after round-tripping
   from WORM.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.plugin import FINANCE_EVALUATED_PARAM_SPECS, FinanceCagePlugin
from src.cage_healthcare.plugin import (
    HEALTHCARE_EVALUATED_PARAM_SPECS,
    HealthcareCagePlugin,
)
from src.cage_physical_ai.plugin import PhysicalAICagePlugin
from src.gateway.governance.contracts import (
    EvaluatedParamSpec,
    GovernanceTierFailure,
    PluginContribution,
    RefusalReceipt,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.verdicts import (
    build_refusal_receipt,
    publish_refusal,
)
from src.gateway.governance.refusal_projection import (
    assert_worm_safe_evaluated_params,
    compute_refusal_params_hash,
    project_evaluated_params,
    validate_evaluated_param_name,
)
from src.gateway.server.governance_middleware import _emit_refusal_receipt

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_default_deny_when_domain_declares_nothing() -> None:
    """A domain that declares nothing emits evaluated_params == {} and no attempted_params in WORM."""
    physical_contrib = PhysicalAICagePlugin().contribute()
    assert dict(physical_contrib.evaluated_param_specs) == {}

    canary_prose = "CANARY_SECRET_PROMPT_JOHN_DOE_99881"
    receipt = build_refusal_receipt(
        "move_arm",
        {
            "velocity_m_s": 9.5,
            "rationale": canary_prose,
            "thread_id": "thread-1",
        },
        [
            Violation(
                tier="kinematic",
                code="VEL_CAP",
                message="Velocity exceeds cap",
                kind=ViolationKind.HARD,
            )
        ],
        [
            GovernanceTierFailure(
                tier="kinematic",
                control_id="VEL_CAP",
                rule_description="Velocity exceeds cap",
            )
        ],
        evaluated_param_specs=physical_contrib.evaluated_param_specs,
    )

    assert receipt.schema_version == "v5"
    assert receipt.evaluated_stages == ()
    assert receipt.skipped_stages == ()
    assert receipt.evaluated_params == {}
    assert len(receipt.params_hash) == 64
    # In-memory content tier retains raw attempted_params for offline DRY_RUN eval
    assert receipt.attempted_params["rationale"] == canary_prose

    worm = receipt.to_worm_dict()
    serialized = json.dumps(worm)
    assert "attempted_params" not in worm
    assert worm["evaluated_params"] == {}
    assert worm["evaluated_stages"] == []
    assert worm["skipped_stages"] == []
    assert worm["params_hash"] == receipt.params_hash
    assert canary_prose not in serialized


@pytest.mark.parametrize(
    "bad_name",
    [
        "patient_id",
        "trader_id",
        "user_id",
        "account_id",
        "initiator_urn",
        "indication",
        "rationale",
        "prompt",
        "query",
        "notes",
        "memo",
        "comment",
        "message",
        "description",
        "narrative",
        "api_key",
        "bearer_token",
        "client_secret",
    ],
)
def test_forbidden_identifier_and_prose_param_names_rejected_at_declaration(
    bad_name: str,
) -> None:
    """Identifier, credential, and free-text parameter names cannot be declared on PluginContribution."""
    with pytest.raises(ValueError, match="forbidden in 7-year WORM"):
        validate_evaluated_param_name(bad_name)

    with pytest.raises(ValueError, match="forbidden in 7-year WORM"):
        PluginContribution(
            domain="bad_domain",
            registered_actions=frozenset({"act"}),
            evaluated_param_specs={
                "act": {bad_name: EvaluatedParamSpec.upper_alpha_code(max_length=8)}
            },
        )


def test_closed_value_shapes_reject_prose_and_unregistered_actions() -> None:
    """Closed EvaluatedParamSpec constructors reject whitespace enums, long/digit codes, and unknown actions."""
    with pytest.raises(ValueError, match="non-whitespace ASCII token"):
        EvaluatedParamSpec.enum("oral", "take twice daily with food")

    with pytest.raises(ValueError, match="1..12"):
        EvaluatedParamSpec.upper_alpha_code(max_length=32)

    with pytest.raises(ValueError, match="which it does not register"):
        PluginContribution(
            domain="bad_domain",
            registered_actions=frozenset({"known_action"}),
            evaluated_param_specs={
                "unregistered_action": {"amount": EvaluatedParamSpec.number()}
            },
        )


@pytest.mark.asyncio
async def test_finance_refusal_strips_extra_and_stuffed_params_from_both_worm_sinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both publish_refusal (GOVERNANCE_REFUSAL) and _emit_refusal_receipt (GOVERNANCE_REFUSAL_RECEIPT) strip prose & stuffed fields."""
    finance_contrib = FinanceCagePlugin().contribute()
    assert finance_contrib.evaluated_param_specs == FINANCE_EVALUATED_PARAM_SPECS

    canary_rationale = "Client Alice Roe asked to liquidate retirement account 88219"
    canary_stuffed_symbol = "Buy AAPL for Alice Roe immediately"

    # Case 1: valid symbol + extra LLM-hallucinated free-text rationale
    params_extra = {
        "symbol": "AAPL",
        "amount": 250_000.0,
        "currency": "USD",
        "confidence": 0.42,
        "side": "buy",
        "trader_role": "junior",
        "trader_id": "trader-secret-id-99",
        "rationale": canary_rationale,
        "limit_price": 195.50,
    }
    receipt = build_refusal_receipt(
        "execute_trade",
        params_extra,
        [
            Violation(
                tier="OPA",
                code="RBAC_LIMIT",
                message="Junior role limit exceeded",
                kind=ViolationKind.HARD,
            )
        ],
        [
            GovernanceTierFailure(
                tier="OPA",
                control_id="AC-3",
                rule_description="Junior role limit exceeded",
            )
        ],
        evaluated_param_specs=finance_contrib.evaluated_param_specs,
    )

    assert receipt.evaluated_params == {
        "symbol": "AAPL",
        "amount": 250_000.0,
        "currency": "USD",
        "confidence": 0.42,
        "side": "buy",
        "trader_role": "junior",
    }
    assert receipt.params_hash == compute_refusal_params_hash(
        "execute_trade", params_extra
    )

    # Case 2: prose stuffed directly inside declared ``symbol`` and ``amount`` fields
    stuffed_projected = project_evaluated_params(
        finance_contrib.evaluated_param_specs,
        "execute_trade",
        {
            "symbol": canary_stuffed_symbol,
            "amount": "all savings",
            "currency": "USD",
            "confidence": float("nan"),
            "side": "liquidate everything",
        },
    )
    assert stuffed_projected == {"currency": "USD"}

    # Capture both WORM emission paths
    captured_events: list[dict[str, object]] = []

    async def _fake_commit(event: dict[str, object], **kwargs: object) -> MagicMock:
        captured_events.append(event)
        return MagicMock(evidence_id="1-0", hash="a" * 64, sequence=1)

    monkeypatch.setattr(
        "src.gateway.governance.evidence.stream.commit_decision_evidence",
        _fake_commit,
    )
    monkeypatch.setattr(
        "src.gateway.governance.evidence.stream.get_evidence_sink",
        lambda: MagicMock(),
    )
    mock_signer = MagicMock()
    mock_signer.sign_async = AsyncMock(return_value="kms-sig")
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware.get_governance_signer",
        lambda: mock_signer,
    )

    await publish_refusal(receipt)
    await _emit_refusal_receipt(
        action_id="execute_trade",
        refusal_reason="Junior role limit exceeded",
        oscal_control_ref="AC-3",
        params=params_extra,
        receipt=receipt,
    )

    assert len(captured_events) == 2
    gov_refusal, oscal_refusal = captured_events
    assert gov_refusal["type"] == "GOVERNANCE_REFUSAL"
    assert oscal_refusal["type"] == "GOVERNANCE_REFUSAL_RECEIPT"

    for ev in captured_events:
        wire_json = json.dumps(ev)
        assert canary_rationale not in wire_json
        assert "trader-secret-id-99" not in wire_json
        assert "attempted_params" not in wire_json

    # Round-trip proof_hash verification from WORM payload alone (zero attempted_params)
    worm_rec = dict(gov_refusal["receipt"])  # type: ignore[arg-type]
    rehydrated = RefusalReceipt.from_worm_dict(worm_rec)
    assert rehydrated.attempted_params == {}
    assert rehydrated.verify_proof_hash() is True


def test_healthcare_dose_order_excludes_patient_id_and_clinical_indication() -> None:
    """Healthcare DoseOrder refusal omits patient_id, medication free text, and clinical indication from WORM."""
    hc_contrib = HealthcareCagePlugin().contribute()
    assert hc_contrib.evaluated_param_specs == HEALTHCARE_EVALUATED_PARAM_SPECS

    dose_params = {
        "patient_id": "PT-774411-JANE-ROE",
        "medication": "warfarin sodium custom compounding note",
        "dose_mg": 25.0,
        "route": "oral",
        "indication": "Patient Jane Roe history of DVT; consult Dr. Smith",
        "confidence": 0.60,
    }
    receipt = build_refusal_receipt(
        "administer_dose",
        dose_params,
        [
            Violation(
                tier="dose_barrier",
                code="SERUM_LIMIT",
                message="Dose exceeds therapeutic ceiling",
                kind=ViolationKind.HARD,
            )
        ],
        [
            GovernanceTierFailure(
                tier="dose_barrier",
                control_id="SERUM_LIMIT",
                rule_description="Dose exceeds therapeutic ceiling",
            )
        ],
        evaluated_param_specs=hc_contrib.evaluated_param_specs,
    )

    worm = receipt.to_worm_dict()
    worm_json = json.dumps(worm)
    assert worm["evaluated_params"] == {
        "dose_mg": 25.0,
        "route": "oral",
        "confidence": 0.60,
    }
    assert "PT-774411-JANE-ROE" not in worm_json
    assert "Jane Roe" not in worm_json
    assert "warfarin" not in worm_json
    assert "attempted_params" not in worm


def test_worm_belt_and_suspenders_rejects_free_text_in_evaluated_params() -> None:
    """Direct RefusalReceipt construction with prose or forbidden keys in evaluated_params fails closed."""
    with pytest.raises(ValueError, match="violates WORM token shape"):
        assert_worm_safe_evaluated_params({"route": "take two tablets by mouth"})

    with pytest.raises(ValueError, match="violates WORM token shape"):
        RefusalReceipt(
            thread_id="t1",
            action="administer_dose",
            violated_tier="CBF",
            violated_rule="rule",
            evaluated_params={"route": "free text prose"},
        )


def test_v4_frozen_preimage_and_v5_stage_coverage_worm_roundtrip() -> None:
    """Historical v4 WORM records remain verifiable while v5 commits evaluated/skipped stages."""
    v4_receipt = RefusalReceipt(
        thread_id="thread-v4",
        action="execute_trade",
        violated_tier="CBF",
        violated_rule="Margin exceeded",
        timestamp=1700000000.0,
        schema_version="v4",
        params_hash="a" * 64,
        evaluated_params={"amount": 500.0},
        control_id="SC-4",
    )
    v4_worm = v4_receipt.to_worm_dict()
    assert "evaluated_stages" not in v4_worm
    assert "skipped_stages" not in v4_worm
    v4_rehydrated = RefusalReceipt.from_worm_dict(v4_worm)
    assert v4_rehydrated.schema_version == "v4"
    assert v4_rehydrated.verify_proof_hash() is True

    v5_receipt = build_refusal_receipt(
        "execute_trade",
        {"symbol": "AAPL", "amount": 500.0},
        [
            Violation(
                tier="cbf",
                code="CBF_MARGIN",
                message="Margin exceeded",
                kind=ViolationKind.HARD,
            )
        ],
        [
            GovernanceTierFailure(
                tier="cbf",
                control_id="CBF_MARGIN",
                rule_description="Margin exceeded",
            )
        ],
        evaluated_stages=(("ftra", "PASS"), ("cbf", "FAIL")),
        skipped_stages=("opa",),
    )
    assert v5_receipt.schema_version == "v5"
    assert v5_receipt.evaluated_stages == (("ftra", "PASS"), ("cbf", "FAIL"))
    assert v5_receipt.skipped_stages == ("opa",)
    v5_worm = v5_receipt.to_worm_dict()
    assert v5_worm["evaluated_stages"] == [["ftra", "PASS"], ["cbf", "FAIL"]]
    assert v5_worm["skipped_stages"] == ["opa"]
    assert RefusalReceipt.from_worm_dict(v5_worm).verify_proof_hash() is True

    tampered = dict(v5_worm)
    tampered["skipped_stages"] = []
    assert RefusalReceipt.from_worm_dict(tampered).verify_proof_hash() is False
