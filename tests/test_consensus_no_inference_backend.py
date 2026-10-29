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

"""Consensus under ``CAGE_INFERENCE_BACKEND=none``.

Below its threshold the gate skips, as it does with a backend, because no
model was ever consulted for those actions. At or above it the gate refuses
immediately with ``CONSENSUS_NO_INFERENCE_BACKEND``: a DENY the evidence chain
can tell apart from a REJECT on the merits, reached without a critic call.
Every domain tier records the kernel's code, so none can turn it into an
admit.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.gateway.governance.consensus import (
    CONSENSUS_NO_INFERENCE_BACKEND,
    NOTIONAL_THRESHOLD_ESCALATION,
    ConsensusGate,
    consensus_admits,
    consensus_violation_code,
)
from src.gateway.governance.contracts import CriticSpec, ViolationKind
from src.gateway.governance.feature_flags import CAGE_CONSENSUS_CRITICS_ENABLED_ENV
from src.gateway.governance.inference_backend import ENV_VAR

pytestmark = [pytest.mark.unit, pytest.mark.local]

_THRESHOLD = 10_000.0


@pytest.fixture
def backend_none(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "none")


@pytest.fixture
def critics_enabled_backend_none(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "none")
    monkeypatch.setenv(CAGE_CONSENSUS_CRITICS_ENABLED_ENV, "true")


def _gate() -> ConsensusGate:
    return ConsensusGate(
        critics=(CriticSpec(role="risk", prompt="Review {action}"),),
        threshold=_THRESHOLD,
        high_stakes_actions=frozenset({"HIGH_STAKES_ACTION"}),
    )


@pytest.mark.asyncio
async def test_below_threshold_still_skips_under_none(backend_none) -> None:
    result = await _gate().check_consensus("act", {}, magnitude=_THRESHOLD - 1)

    assert result["status"] == "SKIPPED"
    assert "reason_code" not in result


@pytest.mark.asyncio
async def test_default_critics_disabled_escalates_deterministically_under_none(
    backend_none, monkeypatch
) -> None:
    monkeypatch.delenv(CAGE_CONSENSUS_CRITICS_ENABLED_ENV, raising=False)
    result = await _gate().check_consensus("act", {}, magnitude=_THRESHOLD)

    assert result["status"] == "ESCALATE"
    assert result["decision"] == "ESCALATE"
    assert result["reason_code"] == NOTIONAL_THRESHOLD_ESCALATION
    assert result["votes"] == []


@pytest.mark.asyncio
async def test_at_threshold_denies_under_none_when_critics_enabled(
    critics_enabled_backend_none,
) -> None:
    result = await _gate().check_consensus("act", {}, magnitude=_THRESHOLD)

    assert result["status"] == "DENY"
    assert result["decision"] == "DENY"
    assert result["reason_code"] == CONSENSUS_NO_INFERENCE_BACKEND
    assert result["votes"] == []


@pytest.mark.asyncio
async def test_high_stakes_action_denies_under_none_when_critics_enabled(
    critics_enabled_backend_none,
) -> None:
    result = await _gate().check_consensus("HIGH_STAKES_ACTION", {}, magnitude=1.0)

    assert result["status"] == "DENY"
    assert result["reason_code"] == CONSENSUS_NO_INFERENCE_BACKEND


@pytest.mark.asyncio
async def test_no_critic_is_consulted_and_no_client_built_under_none(
    critics_enabled_backend_none,
) -> None:
    gate = _gate()
    assert gate._registry is None
    assert gate._default_client is None
    with patch.object(ConsensusGate, "_get_critic_vote", AsyncMock()) as vote:
        await gate.check_consensus("act", {}, magnitude=_THRESHOLD * 5)
    vote.assert_not_awaited()


def test_admit_mapping_refuses_reason_coded_and_non_status_results() -> None:
    assert consensus_admits({"status": "APPROVE"})
    assert consensus_admits({"status": "SKIPPED"})
    assert not consensus_admits({"status": "DENY"})
    assert not consensus_admits({"decision": "APPROVE"})
    assert not consensus_admits(
        {"status": "SKIPPED", "reason_code": CONSENSUS_NO_INFERENCE_BACKEND}
    )
    assert (
        consensus_violation_code(
            {"status": "DENY", "reason_code": CONSENSUS_NO_INFERENCE_BACKEND}, "X"
        )
        == CONSENSUS_NO_INFERENCE_BACKEND
    )
    assert (
        consensus_violation_code(
            {"status": "ESCALATE", "reason_code": NOTIONAL_THRESHOLD_ESCALATION}, "X"
        )
        == NOTIONAL_THRESHOLD_ESCALATION
    )
    assert consensus_violation_code({"status": "REJECT"}, "X") == "X"


# ---------------------------------------------------------------------------
# Domain tiers record NOTIONAL_THRESHOLD_ESCALATION (HITL) by default, and
# CONSENSUS_NO_INFERENCE_BACKEND (HARD) when critics are enabled without a backend
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_domain_tiers_record_notional_threshold_escalation_by_default(
    backend_none, monkeypatch
) -> None:
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
    from src.cage_healthcare.tiers.clinical_consensus_tier import (
        ClinicalConsensusTier,
    )
    from src.cage_physical_ai.tiers.physical_consensus_tier import (
        PhysicalSafetyConsensusTier,
    )

    monkeypatch.delenv(CAGE_CONSENSUS_CRITICS_ENABLED_ENV, raising=False)

    fin_v = await ConsensusTierPlugin().evaluate(
        "execute_trade", {"amount": 500_000.0, "symbol": "AAPL"}
    )
    hc_v = await ClinicalConsensusTier().evaluate(
        "prescribe_medication", {"dose_mg": 5_000.0}
    )
    phys_v = await PhysicalSafetyConsensusTier().evaluate(
        "move_arm", {"velocity_m_s": 50.0}
    )

    assert [(v.code, v.kind) for v in fin_v] == [
        (NOTIONAL_THRESHOLD_ESCALATION, ViolationKind.HITL)
    ]
    assert [(v.code, v.kind) for v in hc_v] == [
        (NOTIONAL_THRESHOLD_ESCALATION, ViolationKind.HITL)
    ]
    assert [(v.code, v.kind) for v in phys_v] == [
        (NOTIONAL_THRESHOLD_ESCALATION, ViolationKind.HITL)
    ]


@pytest.mark.asyncio
async def test_finance_tier_records_no_backend_code(
    critics_enabled_backend_none,
) -> None:
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

    violations = await ConsensusTierPlugin().evaluate(
        "execute_trade", {"amount": 500_000.0, "symbol": "AAPL"}
    )

    assert [(v.code, v.kind) for v in violations] == [
        (CONSENSUS_NO_INFERENCE_BACKEND, ViolationKind.HARD)
    ]


@pytest.mark.asyncio
async def test_healthcare_tier_records_no_backend_code(
    critics_enabled_backend_none,
) -> None:
    from src.cage_healthcare.tiers.clinical_consensus_tier import (
        ClinicalConsensusTier,
    )

    violations = await ClinicalConsensusTier().evaluate(
        "prescribe_medication", {"dose_mg": 5_000.0}
    )

    assert [(v.code, v.kind) for v in violations] == [
        (CONSENSUS_NO_INFERENCE_BACKEND, ViolationKind.HARD)
    ]


@pytest.mark.asyncio
async def test_physical_tier_records_no_backend_code(
    critics_enabled_backend_none,
) -> None:
    from src.cage_physical_ai.tiers.physical_consensus_tier import (
        PhysicalSafetyConsensusTier,
    )

    violations = await PhysicalSafetyConsensusTier().evaluate(
        "move_arm", {"velocity_m_s": 50.0}
    )

    assert [(v.code, v.kind) for v in violations] == [
        (CONSENSUS_NO_INFERENCE_BACKEND, ViolationKind.HARD)
    ]
