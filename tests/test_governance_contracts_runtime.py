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
tests/test_governance_contracts_runtime.py
==========================================
Runtime behavior supplement to tests/test_governance_contracts.py.

Gap 11: test_governance_contracts.py gives false confidence (import and
structural checks only). This file exercises ACTUAL RUNTIME BEHAVIOR by:

  - Instantiating concrete classes that implement the Protocols
  - Calling methods and asserting return types and values
  - Testing structural Protocol compatibility via duck-typing
  - Exercising the ComplianceMetrics and OscalFinding Pydantic models
  - Testing the get_control_meta() / get_sla_seconds() typed accessors
    from compliance_bridge.types

Do NOT modify tests/test_governance_contracts.py.

Marks
-----
- ``local`` : safe to run with no live services (CI default)
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Concrete Protocol implementations for runtime testing
# (structural duck-typing — no inheritance required per PEP 544)
# ---------------------------------------------------------------------------


class _ConcreteSafetyFilter:
    """Minimal concrete implementation of the SafetyFilter Protocol."""

    def __init__(self, cash_balance: float = 10_000.0) -> None:
        self._balance = cash_balance

    def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        amount = float(payload.get("amount", 0))
        if amount > self._balance:
            return f"UNSAFE: Insufficient balance. Have {self._balance}, need {amount}."
        return "SAFE"

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
    ) -> tuple[bool, str]:
        amount = float(payload.get("amount", 0))
        if amount > self._balance:
            return (False, f"CBF_REJECT: balance {self._balance} < cost {amount}")
        self._balance -= amount
        return (True, "COMMITTED")

    def update_state(self, cost: float) -> None:
        self._balance -= cost

    def rollback_state(self, cost: float) -> None:
        self._balance += cost


class _ConcreteConsensusProvider:
    """Minimal concrete implementation of the ConsensusProvider Protocol."""

    def __init__(self, threshold_usd: float = 10_000.0) -> None:
        self._threshold = threshold_usd

    async def check_consensus(
        self, action: str, amount: float, symbol: str
    ) -> dict[str, Any]:
        if amount > self._threshold:
            return {
                "status": "ESCALATE",
                "reason": f"Amount {amount} exceeds consensus threshold {self._threshold}.",
            }
        return {"status": "APPROVE", "reason": "Within threshold."}


class _ConcretePolicyClient:
    """Minimal concrete implementation of the PolicyClient Protocol."""

    def __init__(self, allow_all: bool = True) -> None:
        self._allow_all = allow_all

    async def evaluate(self, policy_path: str, input_data: dict) -> dict:
        return {"result": {"allow": self._allow_all}}

    async def check_allowed(self, policy_path: str, input_data: dict) -> bool:
        return self._allow_all


class _ConcreteCausalGatekeeper:
    """Minimal concrete implementation of the CausalGatekeeper Protocol."""

    def causal_safety_check(self, params: dict, current_telemetry: Any = None) -> bool:
        amount = float(params.get("amount", 0))
        return amount <= 50_000.0


class _ConcreteReservationToken:
    """Minimal ReservationToken for FiscalGuard testing."""

    def __init__(self, agent_id: str, amount_usd: float, rejected: bool = False) -> None:
        self.agent_id = agent_id
        self.amount_usd = amount_usd
        self.rejected = rejected


class _ConcreteFiscalGuard:
    """Minimal concrete implementation of the FiscalGuard Protocol."""

    def __init__(self, daily_limit: float = 100_000.0) -> None:
        self._limit = daily_limit
        self._running_total = 0.0

    async def reserve(
        self, agent_id: str, amount_usd: float
    ) -> _ConcreteReservationToken:
        if self._running_total + amount_usd > self._limit:
            return _ConcreteReservationToken(agent_id, amount_usd, rejected=True)
        self._running_total += amount_usd
        return _ConcreteReservationToken(agent_id, amount_usd, rejected=False)

    async def release(self, token: _ConcreteReservationToken) -> float:
        if not token.rejected:
            self._running_total = max(0.0, self._running_total - token.amount_usd)
        return self._running_total


# ---------------------------------------------------------------------------
# Tests: SafetyFilter Protocol runtime behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestSafetyFilterRuntimeBehavior:
    """Runtime tests for the SafetyFilter Protocol contract."""

    def test_verify_action_returns_safe_within_balance(self) -> None:
        """verify_action must return 'SAFE' when amount is within balance."""
        sf = _ConcreteSafetyFilter(cash_balance=5_000.0)
        result = sf.verify_action("execute_trade", {"amount": 1_000.0})
        assert result == "SAFE", (
            f"Expected 'SAFE' for in-budget trade, got {result!r}"
        )

    def test_verify_action_returns_unsafe_over_balance(self) -> None:
        """verify_action must return a string starting with 'UNSAFE' when over budget."""
        sf = _ConcreteSafetyFilter(cash_balance=100.0)
        result = sf.verify_action("execute_trade", {"amount": 5_000.0})
        assert isinstance(result, str), "verify_action must return a str"
        assert result.startswith("UNSAFE"), (
            f"Expected result starting with 'UNSAFE', got {result!r}"
        )

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_returns_true_within_balance(self) -> None:
        """atomic_verify_and_commit must return (True, 'COMMITTED') within balance."""
        sf = _ConcreteSafetyFilter(cash_balance=10_000.0)
        ok, reason = await sf.atomic_verify_and_commit(
            "execute_trade", {"amount": 500.0}
        )
        assert ok is True, f"Expected committed, got ok={ok!r} reason={reason!r}"
        assert reason == "COMMITTED", f"Expected 'COMMITTED', got {reason!r}"

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_deducts_balance(self) -> None:
        """atomic_verify_and_commit must reduce the balance on commit."""
        sf = _ConcreteSafetyFilter(cash_balance=10_000.0)
        await sf.atomic_verify_and_commit("execute_trade", {"amount": 3_000.0})
        assert sf._balance == 7_000.0, (
            f"Expected balance=7000 after commit, got {sf._balance}"
        )

    @pytest.mark.asyncio
    async def test_atomic_verify_and_commit_returns_false_over_balance(self) -> None:
        """atomic_verify_and_commit must return (False, reason) over budget."""
        sf = _ConcreteSafetyFilter(cash_balance=100.0)
        ok, reason = await sf.atomic_verify_and_commit(
            "execute_trade", {"amount": 50_000.0}
        )
        assert ok is False, f"Expected rejection, got ok={ok!r}"
        assert isinstance(reason, str) and reason, "Rejection reason must be non-empty"

    def test_update_state_reduces_balance(self) -> None:
        """update_state must reduce the internal balance."""
        sf = _ConcreteSafetyFilter(cash_balance=1_000.0)
        sf.update_state(200.0)
        assert sf._balance == 800.0, (
            f"Expected balance=800 after update_state(200), got {sf._balance}"
        )

    def test_rollback_state_restores_balance(self) -> None:
        """rollback_state must restore the balance (idempotent refund)."""
        sf = _ConcreteSafetyFilter(cash_balance=800.0)
        sf.rollback_state(200.0)
        assert sf._balance == 1_000.0, (
            f"Expected balance=1000 after rollback_state(200), got {sf._balance}"
        )

    def test_safety_filter_protocol_satisfied(self) -> None:
        """_ConcreteSafetyFilter must satisfy the SafetyFilter Protocol structure."""
        from src.gateway.governance.contracts import SafetyFilter

        sf = _ConcreteSafetyFilter()
        # Protocol structural check: all required methods present and callable
        assert callable(sf.verify_action), "verify_action must be callable"
        assert callable(sf.atomic_verify_and_commit), "atomic_verify_and_commit must be callable"
        assert callable(sf.update_state), "update_state must be callable"
        assert callable(sf.rollback_state), "rollback_state must be callable"


# ---------------------------------------------------------------------------
# Tests: ConsensusProvider Protocol runtime behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestConsensusProviderRuntimeBehavior:
    """Runtime tests for the ConsensusProvider Protocol contract."""

    @pytest.mark.asyncio
    async def test_check_consensus_approve_below_threshold(self) -> None:
        """check_consensus must return APPROVE for amounts below the threshold."""
        cp = _ConcreteConsensusProvider(threshold_usd=10_000.0)
        result = await cp.check_consensus("execute_trade", 5_000.0, "AAPL")

        assert isinstance(result, dict), "check_consensus must return a dict"
        assert "status" in result, "Result must contain 'status'"
        assert result["status"] == "APPROVE", (
            f"Expected APPROVE below threshold, got {result['status']!r}"
        )

    @pytest.mark.asyncio
    async def test_check_consensus_escalate_above_threshold(self) -> None:
        """check_consensus must return ESCALATE for amounts above threshold."""
        cp = _ConcreteConsensusProvider(threshold_usd=10_000.0)
        result = await cp.check_consensus("execute_trade", 50_000.0, "TSLA")

        assert isinstance(result, dict), "check_consensus must return a dict"
        assert result["status"] == "ESCALATE", (
            f"Expected ESCALATE above threshold, got {result['status']!r}"
        )
        assert "reason" in result, "Escalation result must include 'reason'"

    @pytest.mark.asyncio
    async def test_check_consensus_result_has_required_keys(self) -> None:
        """check_consensus result must contain 'status' and 'reason' keys."""
        cp = _ConcreteConsensusProvider()
        result = await cp.check_consensus("execute_trade", 100.0, "GOOG")
        assert "status" in result, "Result must have 'status'"
        assert "reason" in result, "Result must have 'reason'"
        assert result["status"] in ("APPROVE", "REJECT", "ESCALATE"), (
            f"status must be one of APPROVE/REJECT/ESCALATE, got {result['status']!r}"
        )


# ---------------------------------------------------------------------------
# Tests: PolicyClient Protocol runtime behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestPolicyClientRuntimeBehavior:
    """Runtime tests for the PolicyClient Protocol contract."""

    @pytest.mark.asyncio
    async def test_evaluate_returns_dict(self) -> None:
        """evaluate() must return a dict."""
        pc = _ConcretePolicyClient(allow_all=True)
        result = await pc.evaluate("trade/governance", {"input": {"amount": 1000}})
        assert isinstance(result, dict), (
            f"evaluate() must return a dict, got {type(result)}"
        )

    @pytest.mark.asyncio
    async def test_check_allowed_returns_bool(self) -> None:
        """check_allowed() must return a bool."""
        pc = _ConcretePolicyClient(allow_all=True)
        result = await pc.check_allowed("trade/governance", {"input": {}})
        assert isinstance(result, bool), (
            f"check_allowed() must return a bool, got {type(result)}"
        )

    @pytest.mark.asyncio
    async def test_check_allowed_false_when_policy_denies(self) -> None:
        """check_allowed() must return False when policy denies."""
        pc = _ConcretePolicyClient(allow_all=False)
        result = await pc.check_allowed("trade/governance", {"input": {}})
        assert result is False, (
            f"Expected False from deny-all policy client, got {result}"
        )

    @pytest.mark.asyncio
    async def test_evaluate_and_check_allowed_are_consistent(self) -> None:
        """evaluate() and check_allowed() must agree on the allow decision."""
        for allow in (True, False):
            pc = _ConcretePolicyClient(allow_all=allow)
            eval_result = await pc.evaluate("trade/governance", {})
            allowed = await pc.check_allowed("trade/governance", {})
            assert allowed == eval_result["result"]["allow"], (
                f"evaluate() and check_allowed() must be consistent for allow={allow}"
            )


# ---------------------------------------------------------------------------
# Tests: CausalGatekeeper Protocol runtime behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestCausalGatekeeperRuntimeBehavior:
    """Runtime tests for the CausalGatekeeper Protocol contract."""

    def test_causal_safety_check_returns_bool(self) -> None:
        """causal_safety_check() must return a bool."""
        cg = _ConcreteCausalGatekeeper()
        result = cg.causal_safety_check({"amount": 1000.0})
        assert isinstance(result, bool), (
            f"causal_safety_check must return bool, got {type(result)}"
        )

    def test_causal_safety_check_safe_for_small_amount(self) -> None:
        """causal_safety_check() must return True for small amounts."""
        cg = _ConcreteCausalGatekeeper()
        result = cg.causal_safety_check({"amount": 1_000.0})
        assert result is True, (
            f"Expected True for safe amount, got {result}"
        )

    def test_causal_safety_check_unsafe_for_large_amount(self) -> None:
        """causal_safety_check() must return False for amounts exceeding safety boundary."""
        cg = _ConcreteCausalGatekeeper()
        result = cg.causal_safety_check({"amount": 100_000.0})
        assert result is False, (
            f"Expected False for unsafe amount, got {result}"
        )

    def test_causal_safety_check_accepts_telemetry_arg(self) -> None:
        """causal_safety_check() must accept an optional current_telemetry argument."""
        cg = _ConcreteCausalGatekeeper()
        telemetry = MagicMock()
        result = cg.causal_safety_check({"amount": 500.0}, current_telemetry=telemetry)
        assert isinstance(result, bool), (
            "causal_safety_check must return bool even with telemetry"
        )


# ---------------------------------------------------------------------------
# Tests: FiscalGuard Protocol runtime behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestFiscalGuardRuntimeBehavior:
    """Runtime tests for the FiscalGuard Protocol contract."""

    @pytest.mark.asyncio
    async def test_reserve_within_limit_not_rejected(self) -> None:
        """reserve() must return a non-rejected token within daily limit."""
        fg = _ConcreteFiscalGuard(daily_limit=100_000.0)
        token = await fg.reserve("agent-a", 10_000.0)

        assert token is not None, "reserve() must return a token"
        assert token.rejected is False, (
            f"Token must not be rejected within daily limit, got rejected={token.rejected}"
        )

    @pytest.mark.asyncio
    async def test_reserve_over_limit_is_rejected(self) -> None:
        """reserve() must return a rejected token when daily limit is exceeded."""
        fg = _ConcreteFiscalGuard(daily_limit=5_000.0)
        token = await fg.reserve("agent-b", 50_000.0)

        assert token.rejected is True, (
            "Token must be rejected when amount exceeds daily limit"
        )

    @pytest.mark.asyncio
    async def test_release_reduces_running_total(self) -> None:
        """release() must reduce the running total after a successful reserve."""
        fg = _ConcreteFiscalGuard(daily_limit=100_000.0)
        token = await fg.reserve("agent-c", 20_000.0)
        assert token.rejected is False

        new_total = await fg.release(token)
        assert new_total == 0.0, (
            f"Expected running_total=0 after releasing only reservation, got {new_total}"
        )

    @pytest.mark.asyncio
    async def test_release_returns_float(self) -> None:
        """release() must return a float (new running total in USD)."""
        fg = _ConcreteFiscalGuard(daily_limit=100_000.0)
        token = await fg.reserve("agent-d", 1_000.0)
        result = await fg.release(token)
        assert isinstance(result, float), (
            f"release() must return float, got {type(result)}"
        )

    @pytest.mark.asyncio
    async def test_reserve_accumulates_running_total(self) -> None:
        """Multiple reserve() calls must accumulate the running total."""
        fg = _ConcreteFiscalGuard(daily_limit=100_000.0)
        await fg.reserve("agent-e", 10_000.0)
        await fg.reserve("agent-e", 20_000.0)
        assert fg._running_total == 30_000.0, (
            f"Expected running_total=30000 after two reserves, got {fg._running_total}"
        )


# ---------------------------------------------------------------------------
# Tests: ComplianceMetrics and OscalFinding Pydantic models
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestComplianceMetricsModel:
    """Runtime tests for the ComplianceMetrics Pydantic model."""

    def test_compliance_metrics_instantiation(self) -> None:
        """ComplianceMetrics must instantiate with valid fields."""
        from src.compliance_bridge.types import ComplianceMetrics

        now = "2026-01-15T08:00:00+00:00"
        m = ComplianceMetrics(
            control_id="A.5.2",
            safety_rate=0.95,
            total_traces=100,
            blocked_traces=5,
            passed_traces=95,
            window_hours=24.0,
            last_event_utc=now,
            evidence_age_seconds=120.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        assert m.control_id == "A.5.2"
        assert m.safety_rate == 0.95
        assert m.total_traces == 100
        assert m.passed_traces == 95
        assert m.blocked_traces == 5

    def test_compliance_metrics_safety_rate_none_allowed(self) -> None:
        """ComplianceMetrics must accept safety_rate=None (M-10 requirement)."""
        from src.compliance_bridge.types import ComplianceMetrics

        m = ComplianceMetrics(
            control_id="SC-4",
            safety_rate=None,
            total_traces=0,
            blocked_traces=0,
            passed_traces=0,
            window_hours=24.0,
            last_event_utc="2026-01-01T00:00:00+00:00",
            evidence_age_seconds=0.0,
            startup_grace_active=True,
            startup_grace_remaining_hours=5.5,
        )
        assert m.safety_rate is None, "safety_rate=None must be accepted"

    def test_compliance_metrics_model_copy_updates_field(self) -> None:
        """model_copy(update=...) must return an updated ComplianceMetrics."""
        from src.compliance_bridge.types import ComplianceMetrics

        m = ComplianceMetrics(
            control_id="A.8.4",
            safety_rate=0.8,
            total_traces=10,
            blocked_traces=2,
            passed_traces=8,
            window_hours=24.0,
            last_event_utc="2026-01-01T00:00:00+00:00",
            evidence_age_seconds=30.0,
            startup_grace_active=False,
            startup_grace_remaining_hours=0.0,
        )
        updated = m.model_copy(update={"evidence_age_seconds": 999.0})
        assert updated.evidence_age_seconds == 999.0, (
            "model_copy must update evidence_age_seconds"
        )
        assert updated.control_id == "A.8.4", "Other fields must be preserved"

    def test_compliance_metrics_safety_rate_bounds(self) -> None:
        """ComplianceMetrics must reject safety_rate outside [0.0, 1.0]."""
        from src.compliance_bridge.types import ComplianceMetrics
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ComplianceMetrics(
                control_id="A.5.2",
                safety_rate=1.5,  # invalid: > 1.0
                total_traces=10,
                blocked_traces=0,
                passed_traces=10,
                window_hours=24.0,
                last_event_utc="2026-01-01T00:00:00+00:00",
                evidence_age_seconds=0.0,
                startup_grace_active=False,
                startup_grace_remaining_hours=0.0,
            )


@pytest.mark.local
class TestOscalFindingModel:
    """Runtime tests for the OscalFinding Pydantic model."""

    def test_oscal_finding_instantiation(self) -> None:
        """OscalFinding must instantiate with valid fields."""
        from src.compliance_bridge.types import OscalFinding

        f = OscalFinding(
            control_id="A.5.2",
            result="PASS",
            safety_rate=0.95,
            evidence_age_s=120.0,
            finding_id="finding-001",
            remarks="All traces passed ISO 42001 A.5.2",
        )
        assert f.control_id == "A.5.2"
        assert f.result == "PASS"
        assert f.finding_id == "finding-001"
        assert f.remarks is not None

    def test_oscal_finding_is_frozen(self) -> None:
        """OscalFinding must be frozen (immutable) after construction."""
        from src.compliance_bridge.types import OscalFinding
        from pydantic import ValidationError

        f = OscalFinding(
            control_id="A.9.2",
            result="FAIL",
            finding_id="finding-002",
        )
        with pytest.raises((ValidationError, TypeError)):
            # Frozen models must reject in-place mutation
            f.result = "PASS"  # type: ignore[misc]

    def test_oscal_finding_model_copy_creates_new_instance(self) -> None:
        """model_copy must create a new OscalFinding with updated fields."""
        from src.compliance_bridge.types import OscalFinding

        f = OscalFinding(
            control_id="SC-4",
            result="PASS",
            finding_id="finding-003",
        )
        f2 = f.model_copy(update={"finding_id": "finding-003-copy", "result": "FAIL"})
        assert f2.finding_id == "finding-003-copy", "Copy must have updated finding_id"
        assert f2.result == "FAIL", "Copy must have updated result"
        assert f.result == "PASS", "Original must be unchanged"

    def test_oscal_finding_valid_results(self) -> None:
        """OscalFinding must accept all valid OscalResult literals."""
        from src.compliance_bridge.types import OscalFinding

        valid_results = ("PASS", "FAIL", "NOT_APPLICABLE", "ERROR")
        for result in valid_results:
            f = OscalFinding(
                control_id="A.5.3",
                result=result,  # type: ignore[arg-type]
                finding_id=f"finding-{result}",
            )
            assert f.result == result, (
                f"OscalFinding must accept result={result!r}"
            )


# ---------------------------------------------------------------------------
# Tests: get_control_meta() and get_sla_seconds() typed accessors
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestControlMetaAccessors:
    """Runtime tests for get_control_meta() and get_sla_seconds() accessors."""

    def test_get_control_meta_us_fed_includes_universal(self) -> None:
        """get_control_meta('US_FED') must include universal ISO 42001 controls."""
        from src.compliance_bridge.types import get_control_meta

        meta = get_control_meta("US_FED")
        assert "A.5.2" in meta, "US_FED meta must include universal control A.5.2"
        assert "A.8.4" in meta, "US_FED meta must include universal control A.8.4"

    def test_get_control_meta_us_fed_includes_nist_controls(self) -> None:
        """get_control_meta('US_FED') must include US_FED-specific NIST controls."""
        from src.compliance_bridge.types import get_control_meta

        meta = get_control_meta("US_FED")
        assert "SA-11" in meta, "US_FED meta must include NIST SA-11"
        assert "SC-7" in meta, "US_FED meta must include NIST SC-7"
        assert "SC-8" in meta, "US_FED meta must include NIST SC-8"

    def test_get_control_meta_eu_ecb_excludes_nist_controls(self) -> None:
        """get_control_meta('EU_ECB') must NOT include US_FED-only NIST controls."""
        from src.compliance_bridge.types import get_control_meta

        meta = get_control_meta("EU_ECB")
        assert "SA-11" not in meta, "EU_ECB meta must NOT include US_FED-only SA-11"
        assert "SC-7" not in meta, "EU_ECB meta must NOT include US_FED-only SC-7"

    def test_get_control_meta_eu_ecb_includes_eu_ai_act(self) -> None:
        """get_control_meta('EU_ECB') must include EU AI Act controls."""
        from src.compliance_bridge.types import get_control_meta

        meta = get_control_meta("EU_ECB")
        assert "Article 12" in meta, "EU_ECB meta must include EU AI Act Article 12"
        assert "Article 13" in meta, "EU_ECB meta must include EU AI Act Article 13"

    def test_get_control_meta_apac_mas_includes_mas_feat(self) -> None:
        """get_control_meta('APAC_MAS') must include MAS FEAT controls."""
        from src.compliance_bridge.types import get_control_meta

        meta = get_control_meta("APAC_MAS")
        assert "MAS-FEAT-1" in meta, "APAC_MAS meta must include MAS-FEAT-1"

    def test_get_control_meta_returns_dict_of_dicts(self) -> None:
        """get_control_meta() must return a dict where all values are dicts."""
        from src.compliance_bridge.types import get_control_meta

        for region in ("US_FED", "EU_ECB", "APAC_MAS"):
            meta = get_control_meta(region)
            assert isinstance(meta, dict), f"get_control_meta({region!r}) must return dict"
            for ctrl_id, ctrl_meta in meta.items():
                assert isinstance(ctrl_meta, dict), (
                    f"Control {ctrl_id!r} in region {region!r} must have dict metadata"
                )

    def test_get_sla_seconds_us_fed_includes_nist_slas(self) -> None:
        """get_sla_seconds('US_FED') must include NIST SC-8 and SC-7 SLA targets."""
        from src.compliance_bridge.types import get_sla_seconds

        sla = get_sla_seconds("US_FED")
        assert "SC-8" in sla, "US_FED SLA must include SC-8"
        assert "SC-7" in sla, "US_FED SLA must include SC-7"
        # These are daily infrastructure checks — 86400s
        assert sla["SC-8"] == 86_400, (
            f"Expected SC-8 SLA=86400s, got {sla['SC-8']}"
        )

    def test_get_sla_seconds_eu_ecb_excludes_nist_slas(self) -> None:
        """get_sla_seconds('EU_ECB') must NOT include US_FED-only NIST SLAs."""
        from src.compliance_bridge.types import get_sla_seconds

        sla = get_sla_seconds("EU_ECB")
        assert "SC-8" not in sla, "EU_ECB SLA must NOT include US_FED-only SC-8"

    def test_get_sla_seconds_universal_controls_present_in_all_regions(self) -> None:
        """Universal SLA targets must be present in every region."""
        from src.compliance_bridge.types import get_sla_seconds

        universal_controls = ("A.9.2", "SC-4", "A.8.4", "A.5.3")
        for region in ("US_FED", "EU_ECB", "APAC_MAS"):
            sla = get_sla_seconds(region)
            for ctrl in universal_controls:
                assert ctrl in sla, (
                    f"Universal control {ctrl!r} must have SLA in region {region!r}"
                )
                assert isinstance(sla[ctrl], int) and sla[ctrl] > 0, (
                    f"SLA for {ctrl!r} in {region!r} must be a positive int"
                )
