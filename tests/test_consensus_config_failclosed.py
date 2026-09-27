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
        """ConsensusGate.from_contribution preserves threshold, quorum, and high_stakes_actions."""
        contrib = ConsensusContribution(
            critics=(CriticSpec(role="Safety Critic", prompt_template="{action_type}: {params}"),),
            threshold=42.0,
            magnitude_extractor=lambda p: float(p.get("speed", 0.0)),
            quorum=0.75,
            high_stakes_actions=frozenset({"disengage_e_stop"}),
        )
        gate = ConsensusGate.from_contribution(contrib, registry=MagicMock())
        assert gate.threshold == 42.0
        assert gate.quorum == 0.75
        assert gate.high_stakes_actions == frozenset({"disengage_e_stop"})
        assert len(gate.critics) == 1
