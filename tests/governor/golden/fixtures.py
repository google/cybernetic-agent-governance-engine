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
Deterministic test scenarios and governor harness builder for the golden corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)
from src.cage_finance.tiers.bounding_tier import BoundingContractTierPlugin
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin
from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.gateway.core.policy import OPAClient
from src.gateway.governance.classification_engine import ClassificationEngine
from src.gateway.governance.contracts import ConsensusProvider, SafetyFilter, Violation, ViolationKind
from src.gateway.governance.ftra.models import FtraBoundaryResult, TerminalClassification
from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator
from src.gateway.governance.narrower import Narrower, NarrowerRegistry, NarrowingResult
from src.gateway.governance.governor.governor import SymbolicGovernor


@dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    action: str
    params: dict[str, Any]
    applicable_entry_points: tuple[str, ...] = ("validate_action", "govern", "revalidate_post_hitl", "verify")

    # Mocks configuration
    ftra_classification: TerminalClassification = TerminalClassification.READ_ONLY
    ftra_semantic_breach: bool = False

    stpa_violations: list[str] = field(default_factory=list)

    opa_decision: str = "ALLOW"
    opa_raises: Exception | None = None

    cbf_allowed: bool = True
    cbf_reason: str = "SAFE"
    cbf_raises: Exception | None = None

    consensus_status: str = "APPROVE"
    consensus_reason: str = "Consensus approved"

    causal_safe: bool = True

    fiscal_rejected: bool = False
    fiscal_reason: str = "Fiscal check passed"

    bounding_results: list[ContractResult] = field(default_factory=list)

    # Feature flags
    defer_enabled: bool = True
    narrow_enabled: bool = False
    pause_enabled: bool = False
    register_narrower: bool = False


class GoldenDummyNarrower(Narrower):
    def can_narrow(self, violation: Any, action: str, params: dict[str, Any]) -> bool:
        return True

    def narrow(self, violation: Any, action: str, params: dict[str, Any]) -> NarrowingResult:
        clamped = dict(params)
        if "amount" in clamped and clamped["amount"] > 1000:
            clamped["amount"] = 1000.0
        return NarrowingResult(
            can_narrow=True,
            narrowed_params=clamped,
            constraints_applied=["amount clamped to 1000.0"],
            narrowing_reason="Golden dummy narrower clamp",
        )


def build_governor_for_scenario(scenario: Scenario) -> tuple[SymbolicGovernor, dict[str, Any]]:
    collaborators: dict[str, Any] = {}

    # 1. OPA Client
    mock_opa = MagicMock(spec=OPAClient)
    if scenario.opa_raises is not None:
        mock_opa.evaluate_policy = AsyncMock(side_effect=scenario.opa_raises)
    else:
        mock_opa.evaluate_policy = AsyncMock(return_value={"decision": scenario.opa_decision, "allow": scenario.opa_decision})
    collaborators["opa_client.evaluate_policy"] = mock_opa.evaluate_policy

    # 2. STPA Validator (SYNCHRONOUS!)
    mock_stpa = MagicMock(spec=GeneratedSTPAValidator)
    mock_stpa.validate = MagicMock(return_value=list(scenario.stpa_violations))
    collaborators["stpa_validator.validate"] = mock_stpa.validate

    # 3. Consensus Provider
    mock_consensus = MagicMock(spec=ConsensusProvider)
    mock_consensus.check_consensus = AsyncMock(
        return_value={"status": scenario.consensus_status, "reason": scenario.consensus_reason}
    )
    collaborators["consensus_engine.check_consensus"] = mock_consensus.check_consensus

    # 4. Narrower Registry & Classification Engine
    narrowers = [GoldenDummyNarrower()] if scenario.register_narrower else []
    narrower_registry = NarrowerRegistry(narrowers)
    classification_engine = ClassificationEngine(
        narrower_registry=narrower_registry,
        confidence_threshold=0.70,
        defer_enabled=scenario.defer_enabled,
        narrow_enabled=scenario.narrow_enabled,
        pause_enabled=scenario.pause_enabled,
    )

    # 5. Domain Tiers
    # CBF Backend
    mock_cbf_backend = MagicMock()
    if scenario.cbf_raises is not None:
        mock_cbf_backend.atomic_verify_and_commit = AsyncMock(side_effect=scenario.cbf_raises)
    else:
        mock_cbf_backend.atomic_verify_and_commit = AsyncMock(
            return_value=(scenario.cbf_allowed, scenario.cbf_reason)
        )
    mock_cbf_backend.rollback_state = AsyncMock()
    mock_cbf_backend.verify_action = AsyncMock(return_value=scenario.cbf_reason if not scenario.cbf_allowed else "SAFE")
    collaborators["cbf.atomic_verify_and_commit"] = mock_cbf_backend.atomic_verify_and_commit
    collaborators["cbf.rollback_state"] = mock_cbf_backend.rollback_state
    cbf_tier = CBFTierPlugin(mock_cbf_backend)

    # Fiscal Backend
    mock_fiscal_guard = MagicMock()
    fiscal_token = MagicMock()
    fiscal_token.rejected = scenario.fiscal_rejected
    fiscal_token.rejection_reason = scenario.fiscal_reason
    fiscal_token.reservation_id = "golden-fiscal-token-123"
    fiscal_token.tier = "fiscal"
    fiscal_token.code = "FISCAL_LIMIT_EXCEEDED"
    fiscal_token.governing_state = {}
    fiscal_token.protected_consequence = ""
    mock_fiscal_guard.reserve = AsyncMock(return_value=fiscal_token)
    mock_fiscal_guard.confirm = AsyncMock()
    mock_fiscal_guard.release = AsyncMock()
    collaborators["fiscal_guard.reserve"] = mock_fiscal_guard.reserve
    collaborators["fiscal_guard.confirm"] = mock_fiscal_guard.confirm
    collaborators["fiscal_guard.release"] = mock_fiscal_guard.release
    fiscal_tier = FiscalTierPlugin(mock_fiscal_guard)

    # Consensus Tier
    consensus_tier = ConsensusTierPlugin(mock_consensus)

    # Causal Tier
    mock_causal_fn = MagicMock(return_value=scenario.causal_safe)
    collaborators["causal.causal_safety_check"] = mock_causal_fn
    causal_tier = CausalTierPlugin()
    causal_tier.evaluate = AsyncMock(
        return_value=[] if scenario.causal_safe else [
            Violation(
                tier="causal",
                code="CAUSAL_CHECK_FAILED",
                message="World model untrustworthy",
                kind=ViolationKind.HARD,
            )
        ]
    )

    # Bounding Tier
    mock_bounding_registry = MagicMock()
    mock_bounding_registry.evaluate_all = MagicMock(
        return_value=(scenario.bounding_results, None)
    )
    collaborators["bounding_registry.evaluate_all"] = mock_bounding_registry.evaluate_all
    bounding_tier = BoundingContractTierPlugin(mock_bounding_registry)

    domain_tiers = (
        bounding_tier,
        cbf_tier,
        fiscal_tier,
        consensus_tier,
        causal_tier,
    )

    governor = SymbolicGovernor(
        opa_client=mock_opa,
        safety_filter=mock_cbf_backend,
        consensus_engine=mock_consensus,
        classification_engine=classification_engine,
        stpa_validator=mock_stpa,
        domain_tiers=domain_tiers,
    )

    # Mock FTRA boundary check to return deterministic result without loading registry
    if scenario.ftra_semantic_breach:
        ftra_res = FtraBoundaryResult(
            requires_hitl=True,
            irreversibility_score=1.0,
            classification=f"{scenario.ftra_classification.value}_SEMANTIC_BREACH",
            terminal_match=scenario.action,
            violations=[Violation(tier="ftra", code="FTRA_SEMANTIC_BREACH", message=f"FTRA Semantic Boundary Breach: Action '{scenario.action}' failed semantic validation.", kind=ViolationKind.HARD)],
            bypassed_ftra_node=False,
        )
    else:
        req_hitl = scenario.ftra_classification in (
            TerminalClassification.IRREVERSIBLE_TERMINAL,
            TerminalClassification.EXTERNALLY_REVERSIBLE,
        )
        ftra_res = FtraBoundaryResult(
            requires_hitl=req_hitl,
            irreversibility_score=1.0 if req_hitl else 0.0,
            classification=scenario.ftra_classification.value,
            terminal_match=scenario.action if req_hitl else None,
            violations=[Violation(tier="ftra", code="FTRA_IRREVERSIBLE", message=f"FTRA Boundary Check: Action '{scenario.action}' is classified as {scenario.ftra_classification.value}", kind=ViolationKind.HITL)] if req_hitl else [],
            bypassed_ftra_node=False,
        )
    mock_ftra_check = AsyncMock(return_value=ftra_res)
    from src.gateway.governance.governor.stages.ftra import FtraStage
    ftra_stage = next(s for s in governor.stages if isinstance(s, FtraStage))
    ftra_stage._ftra_boundary_check = mock_ftra_check
    collaborators["ftra_stage._ftra_boundary_check"] = mock_ftra_check

    return governor, collaborators


SCENARIOS: list[Scenario] = [
    # 1. Happy path: ALLOW across all entry points
    Scenario(
        id="01_happy_path_allow",
        description="Clean execution trade with high confidence",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
    ),

    # 2. STPA UCA-1 violation
    Scenario(
        id="02_stpa_uca1_violation",
        description="STPA validator reports UCA-1 hazardous trade condition",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="STPA_UCA_001", message="[STPA_UCA_001] Hazardous trade execution under severe market stress", kind=ViolationKind.HARD)],
    ),

    # 3. CBF Refusal: UNSAFE: position limit
    Scenario(
        id="03_cbf_refusal_unsafe",
        description="CBF barrier violated with UNSAFE position limit",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        cbf_allowed=False,
        cbf_reason="UNSAFE: position limit exceeded",
    ),

    # 4. CBF Refusal: RECONCILIATION_UNAVAILABLE
    Scenario(
        id="04_cbf_refusal_reconciliation_unavailable",
        description="CBF barrier violated because reconciliation provider is down",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        cbf_allowed=False,
        cbf_reason="RECONCILIATION_UNAVAILABLE: ledger sync timeout",
    ),

    # 5. CBF Refusal: Fence epoch regression
    Scenario(
        id="05_cbf_refusal_fence_epoch",
        description="CBF barrier violated with fence epoch regression",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        cbf_allowed=False,
        cbf_reason="Fence epoch regression: current 5 < seen 6",
    ),

    # 6. OPA DENY
    Scenario(
        id="06_opa_deny",
        description="OPA policy explicitly denies the action",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        opa_decision="DENY",
    ),

    # 7. OPA GOVERNANCE_VIOLATION
    Scenario(
        id="07_opa_governance_violation",
        description="OPA policy returns GOVERNANCE_VIOLATION",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        opa_decision="GOVERNANCE_VIOLATION",
    ),

    # 8. OPA Unknown Verdict
    Scenario(
        id="08_opa_unknown_verdict",
        description="OPA policy returns an unrecognized verdict string",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        opa_decision="UNKNOWN_ARBITRARY_VERDICT",
    ),

    # 9. OPA MANUAL_REVIEW (HITL requirement)
    Scenario(
        id="09_opa_manual_review",
        description="OPA policy returns MANUAL_REVIEW",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        opa_decision="MANUAL_REVIEW",
    ),

    # 10. OPA Exception
    Scenario(
        id="10_opa_exception",
        description="OPA client raises connection error",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        opa_raises=ConnectionError("OPA service unreachable"),
    ),

    # 11. Confidence below threshold (0.60 < 0.70)
    Scenario(
        id="11_confidence_below_threshold_defer",
        description="Confidence score 0.60 is in deferrable zone below 0.70",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.60},
        defer_enabled=True,
    ),

    # 12. Confidence between 0.70 and 0.95 (soft threshold override)
    Scenario(
        id="12_confidence_mid_range",
        description="Confidence score 0.85 is below agent minimum (0.95) but >= 0.70",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.85},
    ),

    # 13. Confidence NaN
    Scenario(
        id="13_confidence_nan",
        description="Confidence score is NaN",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": float("nan")},
    ),

    # 14. Confidence inf
    Scenario(
        id="14_confidence_inf",
        description="Confidence score is infinity",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": float("inf")},
    ),

    # 15. Confidence greater than 1.0
    Scenario(
        id="15_confidence_greater_than_one",
        description="Confidence score is 1.5 exceeding 1.0",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 1.5},
    ),

    # 16. Confidence negative
    Scenario(
        id="16_confidence_negative",
        description="Confidence score is negative",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": -0.1},
    ),

    # 17. Confidence non-numeric
    Scenario(
        id="17_confidence_non_numeric",
        description="Confidence score is string",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": "high"},
    ),

    # 18. Confidence missing
    Scenario(
        id="18_confidence_missing",
        description="Confidence score is None",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0},
    ),

    # 19. FTRA irreversible terminal
    Scenario(
        id="19_ftra_irreversible_terminal",
        description="FTRA boundary check classifies action as IRREVERSIBLE_TERMINAL",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        ftra_classification=TerminalClassification.IRREVERSIBLE_TERMINAL,
    ),

    # 20. FTRA externally reversible
    Scenario(
        id="20_ftra_externally_reversible",
        description="FTRA boundary check classifies action as EXTERNALLY_REVERSIBLE",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        ftra_classification=TerminalClassification.EXTERNALLY_REVERSIBLE,
    ),

    # 21. FTRA semantic breach
    Scenario(
        id="21_ftra_semantic_breach",
        description="FTRA boundary check detects semantic breach in action parameters",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        ftra_semantic_breach=True,
    ),

    # 22. Consensus REJECT
    Scenario(
        id="22_consensus_reject",
        description="Multi-agent consensus engine returns REJECT",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        consensus_status="REJECT",
        consensus_reason="Risk manager vetoed order",
    ),

    # 23. Consensus ERROR
    Scenario(
        id="23_consensus_error",
        description="Multi-agent consensus engine returns ERROR",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        consensus_status="ERROR",
        consensus_reason="Consensus evaluation timed out",
    ),

    # 24. Causal check failed
    Scenario(
        id="24_causal_check_failed",
        description="DoWhy causal gatekeeper refutation fails",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        causal_safe=False,
    ),

    # 25. Fiscal Limit Pre-Reservation Rejected (Phase 2)
    Scenario(
        id="25_fiscal_reservation_rejected",
        description="Fiscal guard daily limit exceeded",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 5000000.0, "confidence": 0.99},
        fiscal_rejected=True,
        fiscal_reason="Daily limit of $1M exceeded",
    ),

    # 26. Bounding contract HARD_BLOCK (execute_trade_bounded)
    Scenario(
        id="26_bounding_hard_block",
        description="Bounding tier contracts return HARD_BLOCK",
        action="execute_trade_bounded",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        bounding_results=[
            ContractResult(
                contract_id="B1",
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[{"reason": "Max notional exceeded"}],
            )
        ],
    ),

    # 27. Bounding contract HITL_ESCALATE (execute_trade_bounded)
    Scenario(
        id="27_bounding_hitl_escalate",
        description="Bounding tier contracts return HITL_ESCALATE",
        action="execute_trade_bounded",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        bounding_results=[
            ContractResult(
                contract_id="B6",
                admitted=False,
                severity=ContractSeverity.HITL_ESCALATE,
                findings=[{"reason": "High impact trade requires human approval"}],
            )
        ],
    ),

    # 28. Ungoverned action (no domain tier claims it)
    Scenario(
        id="28_ungoverned_action_allow",
        description="Action not claimed by any domain tier passes through if OPA allows",
        action="read_market_news",
        params={"query": "inflation", "confidence": 0.99},
        applicable_entry_points=("validate_action", "govern", "verify"),
    ),

    # 29. Ungoverned action OPA Deny
    Scenario(
        id="29_ungoverned_action_deny",
        description="Action not claimed by domain tiers but blocked by OPA",
        action="query_restricted_database",
        params={"db": "classified", "confidence": 0.99},
        opa_decision="DENY",
        applicable_entry_points=("validate_action", "govern", "verify"),
    ),

    # 30. DEFER decision path enabled
    Scenario(
        id="30_defer_path_enabled",
        description="Low confidence routes to DEFER when defer is enabled",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.50},
        defer_enabled=True,
    ),

    # 31. DEFER decision path disabled (falls back to DENY)
    Scenario(
        id="31_defer_path_disabled",
        description="Low confidence falls back to DENY when defer is disabled",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.50},
        defer_enabled=False,
    ),

    # 32. PAUSE path enabled (transient condition)
    Scenario(
        id="32_pause_path_enabled",
        description="Transient condition routes to PAUSE when enabled",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="rate limit exceeded on upstream venue", kind=ViolationKind.HARD)],
        pause_enabled=True,
    ),

    # 33. PAUSE path disabled (transient condition falls back to DENY)
    Scenario(
        id="33_pause_path_disabled",
        description="Transient condition falls back to DENY when PAUSE is disabled",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="rate limit exceeded on upstream venue", kind=ViolationKind.HARD)],
        pause_enabled=False,
    ),

    # 34. NARROW path enabled with registered narrower
    Scenario(
        id="34_narrow_path_resolved",
        description="Narrowable violation clamped by narrower plugin",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 25000.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="amount exceeds limit", kind=ViolationKind.HARD)],
        narrow_enabled=True,
        register_narrower=True,
    ),

    # 35. NARROW path enabled but no narrower available (falls back to DENY)
    Scenario(
        id="35_narrow_path_no_narrower",
        description="Narrowable violation without registered narrower falls back to DENY",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 25000.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="amount exceeds limit", kind=ViolationKind.HARD)],
        narrow_enabled=True,
        register_narrower=False,
    ),

    # 36. NARROW path disabled (falls back to DENY)
    Scenario(
        id="36_narrow_path_disabled",
        description="Narrowable violation with narrow disabled falls back to DENY",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 25000.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="amount exceeds limit", kind=ViolationKind.HARD)],
        narrow_enabled=False,
        register_narrower=True,
    ),

    # 37. Multiple violations: STPA and CBF
    Scenario(
        id="37_multiple_violations_stpa_and_cbf",
        description="Both STPA and CBF fail (Phase 1 fails so CBF commit is skipped)",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.99},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="[STPA_UCA_001] Hazardous trade", kind=ViolationKind.HARD)],
        cbf_allowed=False,
        cbf_reason="UNSAFE: position limit",
    ),

    # 38. Structural override (STPA violation contradicts high self-reported confidence)
    Scenario(
        id="38_structural_override_stpa_contradiction",
        description="High confidence (0.98) with STPA violation triggers structural override",
        action="execute_trade",
        params={"symbol": "AAPL", "amount": 100.0, "confidence": 0.98},
        stpa_violations=[Violation(tier="stpa", code="TEST_VIOLATION", message="STPA violation flagged", kind=ViolationKind.HARD)],
    ),

    # 39. Non-trade action with OPA ALLOW
    Scenario(
        id="39_non_trade_action_allow",
        description="Non-trade action (check_balance) allows without CBF/consensus evaluation",
        action="check_balance",
        params={"account_id": "ACC123", "confidence": 0.99},
        applicable_entry_points=("validate_action", "govern", "verify"),
    ),

    # 40. Non-trade action with OPA DENY
    Scenario(
        id="40_non_trade_action_deny",
        description="Non-trade action (transfer_funds) denied by OPA",
        action="transfer_funds",
        params={"account_id": "ACC123", "amount": 50.0, "confidence": 0.99},
        opa_decision="DENY",
        applicable_entry_points=("validate_action", "govern", "verify"),
    ),
]
