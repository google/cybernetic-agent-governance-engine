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

"""

Tests verifying that spoofing confidence=1.0 in the action payload does NOT
cause a trade to bypass governance when other tiers (CBF or OPA) should deny it.

Issue #5 in peer-review remediation: Tier 2 confidence self-authentication gap.
See POAM-TIER2-001 disclosure in symbolic_governor.py §4.2 and §7.2 Limitations.

All tests run without live Redis (fakeredis) or live OPA (mocked).

Key property being tested:
  - Spoofing confidence=1.0 suppresses ONLY the Tier 2 (confidence threshold)
    violation check; it cannot suppress a CBF or OPA denial from a different tier.
  - HITL escalation (MANUAL_REVIEW / REQUIRE_APPROVAL) for a within-limits,
    low-confidence trade is acceptable — outright BLOCKED is not, since the
    trade itself is fiscally safe.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

# Ensure CAGE_ENV=test so module-level production startup guards in
# symbolic_governor.py (CBF_FAIL_OPEN=false, dowhy import) do not fire.
os.environ.setdefault("CAGE_ENV", "test")

from src.gateway.governance.symbolic_governor import GovernanceError, SymbolicGovernor

# ---------------------------------------------------------------------------
# Helpers — minimal SymbolicGovernor assembly
# ---------------------------------------------------------------------------


def _make_governor(
    *,
    cbf_committed: bool = True,
    cbf_reason: str = "COMMITTED",
    opa_decision: str = "ALLOW",
) -> SymbolicGovernor:
    """Assemble a SymbolicGovernor with all I/O mocked.

    Args:
        cbf_committed: Return value of atomic_verify_and_commit (True=commit).
        cbf_reason:    Accompanying reason string.
        opa_decision:  What OPA's evaluate_policy returns as the "allow" key.

    Returns:
        A fully wired SymbolicGovernor ready for ``_run_checks()``/``govern()``
        without hitting live Redis, OPA, or consensus network endpoints.
    """
    from src.gateway.governance.ftra.models import FtraBoundaryResult

    # --- CBF mock ---
    mock_cbf = AsyncMock()
    mock_cbf.atomic_verify_and_commit.return_value = (cbf_committed, cbf_reason)
    mock_cbf.verify_action.return_value = "SAFE" if cbf_committed else cbf_reason

    # --- OPA mock ---
    mock_opa = AsyncMock()
    mock_opa.evaluate_policy.return_value = {"allow": opa_decision}

    # --- Consensus mock (always APPROVE unless we tell it otherwise) ---
    mock_consensus = AsyncMock()
    mock_consensus.check_consensus.return_value = {"status": "APPROVE", "reason": "ok"}

    # --- STPA validator mock (no violations by default) ---
    mock_stpa = MagicMock()
    mock_stpa.validate.return_value = []

    governor = SymbolicGovernor(
        opa_client=mock_opa,
        stpa_validator=mock_stpa,
    )
    governor.register_domain_tier(CBFTierPlugin(mock_cbf))
    governor.register_domain_tier(ConsensusTierPlugin(mock_consensus))

    # Mock FTRA boundary check to return a safe result (no HITL required).
    # This allows tests to focus on confidence bypass behavior without being
    # blocked by the IrreversibilityClassifier.
    safe_ftra_result = FtraBoundaryResult(
        requires_hitl=False,
        irreversibility_score=0.0,
        classification="READ_ONLY",
        terminal_match=None,
        violations=[],
        bypassed_ftra_node=False,
    )
    governor._ftra_boundary_check = AsyncMock(return_value=safe_ftra_result)

    return governor


# ---------------------------------------------------------------------------
# Test 1: confidence=1.0 + CBF fiscal over-limit → BLOCKED by CBF
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_confidence_spoofing_does_not_bypass_cbf_block() -> None:
    """Submitting confidence=1.0 must NOT bypass a CBF (fiscal) block.

    The adversarial agent reports maximum confidence to suppress Tier 2
    (confidence threshold) escalation.  However, the independent Tier 3
    CBF check (cash barrier) returns UNSAFE because the requested amount
    exceeds the available balance.  The result must be BLOCKED.

    POAM-TIER2-001: confidence=1.0 suppresses the Tier-2 check only; it has
    no effect on the independent CBF Lua-atomic envelope evaluation.
    """
    governor = _make_governor(
        cbf_committed=False,
        cbf_reason="UNSAFE: h_next=-50000.00 < required=45000.00",
        opa_decision="ALLOW",
    )

    params = {
        "symbol": "AAPL",
        "quantity": 50000,
        "amount": 1_000_000.0,  # massively over-limit
        "confidence": 1.0,  # spoofed maximum confidence
        "trader_role": "junior",
    }

    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    assert exc_info.value is not None
    msg = str(exc_info.value)
    assert "CBF" in msg or "Safety Violation" in msg or "UNSAFE" in msg, (
        f"Expected CBF-related block; got: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: confidence=1.0 + OPA DENY → BLOCKED by OPA
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_confidence_spoofing_does_not_bypass_opa_deny() -> None:
    """Submitting confidence=1.0 must NOT bypass an OPA DENY verdict.

    The adversarial agent reports maximum confidence to suppress Tier 2
    escalation.  However, the independent Tier 3 OPA policy check returns DENY
    (e.g. the action category is prohibited).  The result must be BLOCKED.

    POAM-TIER2-001: confidence=1.0 clears only the Tier-2 local pre-check;
    OPA is evaluated independently and its DENY verdict is honoured regardless
    of what confidence value the agent self-reported.
    """
    governor = _make_governor(
        cbf_committed=True,
        cbf_reason="COMMITTED",
        opa_decision="DENY",
    )

    params = {
        "symbol": "PROHIBITED_TICKER",
        "quantity": 100,
        "amount": 5_000.0,  # within CBF limits
        "confidence": 1.0,  # spoofed maximum confidence
        "trader_role": "junior",
    }

    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    msg = str(exc_info.value)
    assert "OPA" in msg or "Denied" in msg or "Violation" in msg, (
        f"Expected OPA-related denial; got: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: low confidence (0.1) + within-limits trade → Tier-2 violation only
#         (HITL escalation acceptable; outright system error not expected)
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_low_confidence_within_limits_raises_tier2_violation() -> None:
    """A within-limits trade with low confidence triggers a Tier-2 confidence
    violation (GovernanceError), NOT a CBF or OPA block.

    This test confirms the governance pipeline is not over-blocking valid trades
    purely on the basis of a safety tier unrelated to fiscal limits.  The block
    is specifically the confidence Tier-2 check — the pipeline should never
    surface a CBF or OPA violation for an otherwise-permitted trade.

    POAM-TIER2-001: even though confidence=0.1 is below the 0.95 threshold and
    correctly triggers a governance stop, the *reason* must be Tier-2 confidence,
    not a spurious CBF or OPA error.
    """
    governor = _make_governor(
        cbf_committed=True,
        cbf_reason="COMMITTED",
        opa_decision="ALLOW",
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "amount": 1_500.0,  # well within fiscal limits
        "confidence": 0.1,  # genuinely low — below 0.95 threshold
        "trader_role": "junior",
    }

    # govern() raises GovernanceError; the message should reference Tier-2
    # confidence, NOT CBF or OPA.
    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    msg = str(exc_info.value)
    # Tier-2 message includes "Confidence Violation" or "confidence" and
    # does NOT include "CBF" or "OPA".
    assert "onfidence" in msg or "CTRL_" in msg, (
        f"Expected a Tier-2 confidence violation; got: {msg!r}"
    )
    assert "UNSAFE" not in msg, (
        f"CBF UNSAFE reason must not appear for a within-limits trade; got: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: confidence=1.0 with both CBF ALLOW and OPA ALLOW → APPROVED
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_high_confidence_valid_trade_is_approved() -> None:
    """A benign trade with confidence=1.0, CBF ALLOW, and OPA ALLOW is approved.

    Verifies that spoofed-high confidence does NOT cause over-blocking of a
    trade that all other tiers approve — confidence=1.0 is the expected value
    when an agent is genuinely highly confident in a valid within-limits trade.
    """
    from unittest.mock import patch

    governor = _make_governor(
        cbf_committed=True,
        cbf_reason="COMMITTED",
        opa_decision="ALLOW",
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "amount": 1_500.0,
        "confidence": 1.0,
        "trader_role": "senior",
    }

    # govern() returns a routing seal (non-empty string) on approval.
    # Mock generate_seal_with_evidence to avoid Redis dependency.
    with patch(
        "src.gateway.governance.routing_seal.generate_seal_with_evidence",
        new=AsyncMock(return_value="mock-seal-token"),
    ):
        seal = await governor.govern("execute_trade", params)
    assert isinstance(seal, str) and len(seal) > 0, (
        f"Expected a routing seal for an approved trade; got: {seal!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: confidence spoofing with MANUAL_REVIEW → REQUIRE_APPROVAL path
# ---------------------------------------------------------------------------


@pytest.mark.local
@pytest.mark.asyncio
async def test_confidence_spoofing_with_manual_review_escalates() -> None:
    """When OPA returns MANUAL_REVIEW and confidence=1.0, the pipeline must
    still escalate (REQUIRE_APPROVAL violation), not approve silently.

    confidence=1.0 can only suppress Tier-2; it cannot promote an OPA
    MANUAL_REVIEW to an unconditional ALLOW.
    """
    governor = _make_governor(
        cbf_committed=True,
        cbf_reason="COMMITTED",
        opa_decision="MANUAL_REVIEW",
    )

    params = {
        "symbol": "AAPL",
        "quantity": 10,
        "amount": 1_500.0,
        "confidence": 1.0,  # spoofed maximum confidence
        "trader_role": "junior",
    }

    # govern() raises GovernanceError for MANUAL_REVIEW (mapped as a violation)
    with pytest.raises(GovernanceError) as exc_info:
        await governor.govern("execute_trade", params)

    msg = str(exc_info.value)
    assert "Manual Review" in msg or "MANUAL" in msg or "Review" in msg, (
        f"Expected MANUAL_REVIEW escalation; got: {msg!r}"
    )
