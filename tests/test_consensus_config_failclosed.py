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

"""Consensus config fail-closed and domain-injection tests.

Verifies that ConsensusGate:
- Fails closed (status="DENY", decision="DENY") when triggered with empty critics
- Supports the domain-injected (critics, threshold, magnitude_extractor, quorum, high_stakes_actions) contract
- Formats domain-supplied CriticSpec prompts without finance literals in the kernel
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.consensus import ConsensusGate
from src.gateway.governance.contracts import ConsensusContribution, CriticSpec

pytestmark = [pytest.mark.local, pytest.mark.unit]


class TestConsensusContextSignature:
    """Verify the (action, context, magnitude) signature and threshold extraction."""

    @pytest.mark.asyncio
    async def test_check_consensus_with_context_dict(self):
        """check_consensus accepts the context-based signature and skips below threshold."""
        gate = ConsensusGate(
            critics=(CriticSpec(role="Reviewer", prompt_template="{action_type}: {params}"),),
            threshold=1000.0,
            magnitude_extractor=lambda p: float(p.get("amount", 0.0)),
            registry=MagicMock(),
        )

        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 100.0, "symbol": "AAPL"},
            magnitude=100.0,
        )
        assert result["status"] == "SKIPPED"
        assert result["reason"] == "Below threshold"

    @pytest.mark.asyncio
    async def test_check_consensus_magnitude_overrides_extractor(self):
        """When magnitude is explicitly provided, it takes precedence over magnitude_extractor."""
        gate = ConsensusGate(
            critics=(CriticSpec(role="Reviewer", prompt_template="{action_type}: {params}"),),
            threshold=1000.0,
            magnitude_extractor=lambda p: float(p.get("amount", 0.0)),
            registry=MagicMock(),
        )

        result = await gate.check_consensus(
            "execute_trade",
            context={"amount": 50000.0, "symbol": "AAPL"},
            magnitude=100.0,
        )
        assert result["status"] == "SKIPPED"

    @pytest.mark.asyncio
    async def test_check_consensus_uses_magnitude_extractor_when_magnitude_omitted(self):
        """When magnitude is None, falls back to magnitude_extractor(params)."""
        gate = ConsensusGate(
            critics=(CriticSpec(role="Reviewer", prompt_template="{action_type}: {params}"),),
            threshold=1000.0,
            magnitude_extractor=lambda p: float(p.get("dose_mg", 0.0)),
            registry=MagicMock(),
        )

        result = await gate.check_consensus(
            "administer_dose",
            context={"dose_mg": 50.0, "medication": "warfarin"},
        )
        assert result["status"] == "SKIPPED"


class TestConsensusFailClosedOnEmptyCritics:
    """Verify ConsensusGate fails closed when triggered with no critics configured."""

    @pytest.mark.asyncio
    async def test_empty_critics_above_threshold_returns_deny(self):
        """When magnitude >= threshold and critics is empty, returns DENY."""
        gate = ConsensusGate(
            critics=(),
            threshold=100.0,
            magnitude_extractor=lambda p: float(p.get("value", 0.0)),
            registry=MagicMock(),
        )

        result = await gate.check_consensus(
            "some_action",
            context={"value": 500.0},
        )
        assert result["status"] == "DENY"
        assert result["decision"] == "DENY"
        assert result["reason"] == "no_critics_configured"

    @pytest.mark.asyncio
    async def test_empty_critics_on_high_stakes_action_returns_deny(self):
        """When action is in high_stakes_actions and critics is empty, returns DENY even below threshold."""
        gate = ConsensusGate(
            critics=(),
            threshold=10000.0,
            magnitude_extractor=lambda _p: 0.0,
            high_stakes_actions=frozenset({"override_contraindication"}),
            registry=MagicMock(),
        )

        result = await gate.check_consensus(
            "override_contraindication",
            context={"patient_id": "P1"},
        )
        assert result["status"] == "DENY"
        assert result["decision"] == "DENY"
        assert result["reason"] == "no_critics_configured"


class TestDomainInjectedCriticPrompts:
    """Verify domain-injected CriticSpec prompts are formatted for each domain."""

    @pytest.mark.asyncio
    async def test_healthcare_consensus_formats_clinical_prompts_without_finance_terms(self):
        """Healthcare ConsensusGate formats clinical critic prompts with zero finance vocabulary."""
        from src.cage_healthcare.tiers.clinical_consensus_tier import (
            build_healthcare_consensus_gate,
        )

        gate = build_healthcare_consensus_gate()
        assert len(gate.critics) == 3
        roles = {c.role for c in gate.critics}
        assert roles == {"Pharmacist Reviewer", "Attending Physician", "Clinical Ethics"}

        captured_prompts: list[str] = []

        async def _fake_generate(prompt: str, **kwargs):
            captured_prompts.append(prompt)
            return '{"decision": "APPROVE", "reason": "Clinically appropriate"}'

        gate._registry = MagicMock()
        gate._registry.get_client.return_value = None
        gate._registry.get_model.return_value = "gemini-2.5-flash"
        gate._default_client = MagicMock()
        gate._default_client.generate = AsyncMock(side_effect=_fake_generate)

        with patch("src.gateway.governance.consensus.engine.genai_span") as mock_span_ctx:
            mock_span = MagicMock()
            mock_span.__enter__.return_value = mock_span
            mock_span.__exit__.return_value = False
            mock_span_ctx.return_value = mock_span

            result = await gate.check_consensus(
                action_type="administer_medication",
                params={"medication": "heparin", "dose_mg": 250.0},
            )

        assert result["status"] == "APPROVE"
        assert len(captured_prompts) == 3
        for prompt in captured_prompts:
            assert "administer_medication" in prompt
            assert "heparin" in prompt
            assert "equity" not in prompt.lower()
            assert "Risk Manager" not in prompt

    @pytest.mark.asyncio
    async def test_from_contribution_wires_all_fields(self):
        """ConsensusGate.from_contribution preserves threshold and high_stakes_actions."""
        contrib = ConsensusContribution(
            critics=(CriticSpec(role="Safety Critic", prompt_template="{action_type}: {params}"),),
            threshold=42.0,
            magnitude_extractor=lambda p: float(p.get("speed", 0.0)),
            high_stakes_actions=frozenset({"disengage_e_stop"}),
        )
        gate = ConsensusGate.from_contribution(contrib, registry=MagicMock())
        assert gate.threshold == 42.0
        assert not hasattr(gate, "quorum")
        assert gate.high_stakes_actions == frozenset({"disengage_e_stop"})
        assert len(gate.critics) == 1


class TestKernelAndConsumerTiersFailClosed:
    """Verify check_consensus and all three domain consensus tiers fail closed on malformed inputs."""

    @pytest.mark.parametrize(
        "bad_value",
        ["not-a-number", float("nan"), float("inf"), float("-inf"), True, False, -1.0, None],
    )
    @pytest.mark.asyncio
    async def test_kernel_check_consensus_fails_closed_on_invalid_magnitude_across_domains(
        self, bad_value
    ):
        """Kernel check_consensus returns DENY (invalid_magnitude) for finance, healthcare, and physical AI."""
        from src.cage_finance.tiers.consensus_tier import build_finance_consensus_gate
        from src.cage_healthcare.tiers.clinical_consensus_tier import (
            build_healthcare_consensus_gate,
        )
        from src.cage_physical_ai.tiers.physical_consensus_tier import (
            build_physical_consensus_gate,
        )

        fin_gate = build_finance_consensus_gate(registry=MagicMock())
        hc_gate = build_healthcare_consensus_gate()
        hc_gate._registry = MagicMock()
        phys_gate = build_physical_consensus_gate()
        phys_gate._registry = MagicMock()

        fin_res = await fin_gate.check_consensus(
            "execute_trade", context={"amount": bad_value}
        )
        assert fin_res["status"] == "DENY"
        assert fin_res["reason"] == "invalid_magnitude"

        hc_res = await hc_gate.check_consensus(
            action_type="administer_dose", params={"dose_mg": bad_value}
        )
        assert hc_res["status"] == "DENY"
        assert hc_res["reason"] == "invalid_magnitude"

        phys_res = await phys_gate.check_consensus(
            action_type="dispatch_trajectory", params={"velocity_m_s": bad_value}
        )
        assert phys_res["status"] == "DENY"
        assert phys_res["reason"] == "invalid_magnitude"

    @pytest.mark.parametrize(
        "bad_amount",
        ["not-a-number", float("nan"), float("inf"), True, False, -5.0, None],
    )
    @pytest.mark.asyncio
    async def test_finance_tier_fails_closed_on_invalid_amount(self, bad_amount):
        """ConsensusTierPlugin returns ViolationKind.HARD on invalid/bool/NaN/negative amounts."""
        from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
        from src.gateway.governance.contracts import ViolationKind

        tier = ConsensusTierPlugin(consensus=MagicMock())
        violations = await tier.evaluate("execute_trade", {"amount": bad_amount})
        assert len(violations) == 1
        assert violations[0].kind == ViolationKind.HARD
        assert violations[0].code == "CONSENSUS_REJECTED"

    @pytest.mark.parametrize(
        "bad_result",
        [
            "not-a-dict",
            None,
            123,
            {"status": "FOO", "reason": "unknown status"},
            {"status": None, "reason": "null status"},
            {},
        ],
    )
    @pytest.mark.asyncio
    async def test_all_consumer_tiers_fail_closed_on_non_dict_or_unknown_status(
        self, bad_result
    ):
        """Finance, healthcare, and physical consensus tiers all emit ViolationKind.HARD on non-dict or unknown/None status."""
        from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
        from src.cage_healthcare.tiers.clinical_consensus_tier import (
            ClinicalConsensusTier,
        )
        from src.cage_physical_ai.tiers.physical_consensus_tier import (
            PhysicalSafetyConsensusTier,
        )
        from src.gateway.governance.contracts import ViolationKind

        mock_engine = MagicMock()
        mock_engine.check_consensus = AsyncMock(return_value=bad_result)

        fin_tier = ConsensusTierPlugin(consensus=mock_engine)
        fin_v = await fin_tier.evaluate("execute_trade", {"amount": 25000.0})
        assert len(fin_v) == 1
        assert fin_v[0].kind == ViolationKind.HARD

        hc_tier = ClinicalConsensusTier(consensus_engine=mock_engine)
        hc_v = await hc_tier.evaluate("administer_dose", {"dose_mg": 250.0})
        assert len(hc_v) == 1
        assert hc_v[0].kind == ViolationKind.HARD

        phys_tier = PhysicalSafetyConsensusTier(consensus_engine=mock_engine)
        phys_v = await phys_tier.evaluate(
            "dispatch_trajectory", {"velocity_m_s": 5.0}
        )
        assert len(phys_v) == 1
        assert phys_v[0].kind == ViolationKind.HARD
        assert phys_v[0].message.startswith("[CTRL_PHYS_004]")

    @pytest.mark.asyncio
    async def test_consumer_tiers_fail_closed_when_engine_is_none(self):
        """All three consumer tiers fail closed with ViolationKind.HARD if their engine attribute is None."""
        from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
        from src.cage_healthcare.tiers.clinical_consensus_tier import (
            ClinicalConsensusTier,
        )
        from src.cage_physical_ai.tiers.physical_consensus_tier import (
            PhysicalSafetyConsensusTier,
        )
        from src.gateway.governance.contracts import ViolationKind

        fin_tier = ConsensusTierPlugin(consensus=MagicMock())
        fin_tier.consensus = None
        fin_v = await fin_tier.evaluate("execute_trade", {"amount": 100.0})
        assert len(fin_v) == 1 and fin_v[0].kind == ViolationKind.HARD

        hc_tier = ClinicalConsensusTier(consensus_engine=MagicMock())
        hc_tier.consensus_engine = None
        hc_v = await hc_tier.evaluate("administer_dose", {"dose_mg": 10.0})
        assert len(hc_v) == 1 and hc_v[0].kind == ViolationKind.HARD

        phys_tier = PhysicalSafetyConsensusTier(consensus_engine=MagicMock())
        phys_tier.consensus_engine = None
        phys_v = await phys_tier.evaluate("dispatch_trajectory", {"velocity_m_s": 1.0})
        assert len(phys_v) == 1 and phys_v[0].kind == ViolationKind.HARD
        assert phys_v[0].message.startswith("[CTRL_PHYS_004]")

