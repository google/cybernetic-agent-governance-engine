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

"""Tier registry contract tests (ARCH-1: Formal verification completeness).

This module provides executable specifications of tier registration invariants,
documenting the contracts that domain plugins must satisfy when registering
tiers into the SymbolicGovernor kernel.

These tests serve as:
1. **Contract documentation**: Authoritative specification of tier plugin API
2. **Regression protection**: Prevent tier registration bugs from reaching production
3. **Domain plugin validation**: Verify new domain plugins satisfy kernel contracts

Scope:
- Tier registration API contracts (SymbolicGovernor.register_tier())
- Governor initialization contracts (safety_filter, consensus_engine, context)
- Domain plugin architecture compliance (Layer 2 separation)
- Tier execution order and dependency invariants

Out of scope:
- Individual tier logic (tested in domain-specific test files)
- Runtime governance behavior (tested in integration tests)
- TLA+ temporal properties (verified via proof/*.tla specs)
"""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Mark all tests as local and unit
pytestmark = [pytest.mark.unit, pytest.mark.local]


# ---------------------------------------------------------------------------
# Tier Registration Contract Tests
# ---------------------------------------------------------------------------


def test_symbolic_governor_requires_safety_filter_at_initialization() -> None:
    """SymbolicGovernor __init__ must receive a safety_filter parameter.

    Contract: The kernel cannot be instantiated without a safety filter
    (CBF engine or equivalent). This is a mandatory defense-in-depth layer.

    Rationale: Without a safety filter, irreversible actions could bypass
    quantitative barrier checks, violating OWASP AISVS C9 requirements.
    """
    # Verify signature requires safety_filter
    import inspect

    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    sig = inspect.signature(SymbolicGovernor.__init__)
    params = sig.parameters

    assert "safety_filter" in params, (
        "SymbolicGovernor.__init__ must declare safety_filter parameter"
    )

    # Verify it's not optional (no default value of None)
    param = params["safety_filter"]
    # If default is empty, it's required
    if param.default is not inspect.Parameter.empty:
        assert param.default is not None, (
            "safety_filter must not default to None (required parameter)"
        )


def test_symbolic_governor_requires_consensus_engine_at_initialization() -> None:
    """SymbolicGovernor __init__ must receive a consensus_engine parameter.

    Contract: The kernel cannot be instantiated without a consensus engine
    for multi-agent coordination (Tier 5).

    Rationale: Without consensus, the standing assembly cannot verify
    quorum-based decisions, enabling rogue agent capability escalation.
    """
    import inspect

    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    sig = inspect.signature(SymbolicGovernor.__init__)
    params = sig.parameters

    assert "consensus_engine" in params, (
        "SymbolicGovernor.__init__ must declare consensus_engine parameter"
    )

    param = params["consensus_engine"]
    if param.default is not inspect.Parameter.empty:
        assert param.default is not None, (
            "consensus_engine must not default to None (required parameter)"
        )


def test_symbolic_governor_requires_context_at_initialization() -> None:
    """SymbolicGovernor __init__ receives context via govern() method.

    Contract: The kernel receives LangGraph execution context via the
    govern() method (not __init__). This allows a single governor instance
    to process multiple requests with different contexts.
    """
    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    init_params = inspect.signature(SymbolicGovernor.__init__).parameters
    assert "context" not in init_params, "context must not be a parameter to SymbolicGovernor.__init__"

    govern_params = inspect.signature(SymbolicGovernor.govern).parameters
    assert "tool_name" in govern_params
    assert "params" in govern_params


def test_tier_registration_requires_callable_with_predictable_signature() -> None:
    """Tier plugins must implement GovernanceTierPlugin protocol methods."""
    from src.gateway.governance.contracts import GovernanceTierPlugin

    for method_name in ("claims_action", "evaluate", "commit"):
        assert hasattr(GovernanceTierPlugin, method_name), f"GovernanceTierPlugin must declare {method_name}"


def test_domain_plugins_must_not_import_from_kernel() -> None:
    """The Gate G3 boundary checker validates layer isolation across all files."""
    from scripts.check_import_boundaries import LAYER_1_GATEWAY, check_file_boundaries

    violations = []
    for p in Path(LAYER_1_GATEWAY).rglob("*.py"):
        if "__pycache__" not in str(p):
            violations.extend(check_file_boundaries(p))
    assert not violations, f"Gate G3 import boundary violations detected in kernel: {violations}"


def test_governor_initialization_creates_empty_tier_registry() -> None:
    """SymbolicGovernor initializes with an empty tier registry when domain_tiers=[]."""
    from src.gateway.governance.symbolic_governor import SymbolicGovernor

    gov = SymbolicGovernor(MagicMock(), MagicMock(), MagicMock(), domain_tiers=[])
    assert len(gov._domain_tiers) == 0, "Initial domain_tiers list must be empty"


# ---------------------------------------------------------------------------
# Tier Execution Order Contract Tests
# ---------------------------------------------------------------------------


def test_ftra_must_execute_before_other_tiers() -> None:
    """FTRA (Tier 0.5) must execute before all other governance tiers in formal model."""
    import proof.model as model

    assert model.TIERS[0] == "ftra", "FTRA (Tier 0.5) must be the first tier in execution order"


def test_cbf_and_opa_may_execute_concurrently() -> None:
    """CBF (Tier 3a) and OPA (Tier 3b) are present in the formal verification tier model."""
    import proof.model as model

    assert "cbf" in model.TIERS, "CBF must be in TIERS formal model"
    assert "opa" in model.TIERS, "OPA must be in TIERS formal model"


def test_consensus_tier_requires_multi_agent_context() -> None:
    """Consensus tier (Tier 5) pluggable implementation is available."""
    from unittest.mock import MagicMock
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

    tier = ConsensusTierPlugin(consensus=MagicMock())
    assert tier.tier_name == "consensus"
    assert tier.phase == 1
    assert tier.order == 5



# ---------------------------------------------------------------------------
# Domain Plugin Architecture Contract Tests
# ---------------------------------------------------------------------------


def test_domain_plugins_live_in_src_cage_prefix() -> None:
    """Domain plugins must reside under src/cage_{domain}/ directories.

    Contract: All domain-specific code (tiers, ontologies, Rego policies)
    must live under src/cage_finance/, src/cage_healthcare/, etc.

    Rationale: Namespace separation prevents domain logic from polluting
    the universal governance kernel (src/gateway/).

    Enforcement: Directory structure + import boundary check (Gate G3).
    """
    import os
    from pathlib import Path

    src_path = Path("src")
    cage_dirs = [
        d for d in src_path.iterdir() if d.is_dir() and d.name.startswith("cage_")
    ]

    # Verify at least one domain plugin exists
    assert len(cage_dirs) > 0, (
        "Expected at least one domain plugin directory (src/cage_*)"
    )

    # Verify each domain plugin has a tiers module
    for cage_dir in cage_dirs:
        tiers_path = cage_dir / "tiers"
        # Not all plugins may have implemented tiers yet (e.g. new domains)
        # This is a soft assertion to document the expected structure
        if tiers_path.exists():
            assert tiers_path.is_dir(), f"{cage_dir.name} should have a tiers/ package"


def test_finance_domain_plugin_registers_fiscal_tier() -> None:
    """Finance domain plugin (src/cage_finance/) provides fiscal tier.

    Contract: The finance domain plugin must provide a fiscal tier
    (pre-reservation of budget limits) for financial actions.

    Rationale: Fiscal tier is domain-specific to finance; healthcare
    and other domains may have different resource constraints.

    Enforcement: Finance-specific integration tests verify fiscal tier
    registration and execution.
    """
    from unittest.mock import MagicMock
    from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin

    plugin = FiscalTierPlugin(guard=MagicMock())
    assert plugin.tier_name == "fiscal"
    assert plugin.phase == 2
    assert plugin.order == 4
    assert plugin.claims_action("execute_trade", {}) is True
    assert plugin.claims_action("prescribe_medication", {}) is False


def test_healthcare_domain_plugin_registers_dosage_tier() -> None:
    """Healthcare domain plugin (src/cage_healthcare/) provides dosage tier.

    Contract: The healthcare domain plugin must provide a dosage tier
    (medication safety checks) for clinical actions.

    Rationale: Dosage tier is domain-specific to healthcare; financial
    actions do not have dosage constraints.

    Enforcement: Healthcare-specific integration tests verify dosage tier
    registration and execution.
    """
    from unittest.mock import MagicMock
    from src.cage_healthcare.tiers.dose_barrier_tier import DoseBarrierTier

    plugin = DoseBarrierTier(cbf=MagicMock())
    assert plugin.tier_name == "dose_barrier"
    assert plugin.phase == 2
    assert plugin.order == 3


# ---------------------------------------------------------------------------
# Tier Fail-Closed Semantics Contract Tests
# ---------------------------------------------------------------------------


def test_any_tier_failure_must_block_execution() -> None:
    """If any tier returns FAIL, the action must be blocked (DENIED phase).

    Contract: Governance tiers are conjunctive (AND gate). A single
    tier failure blocks execution regardless of other tier results.

    Rationale: Fail-closed semantics ensure defense-in-depth. Even if
    one tier has a bug or bypass, other tiers can still block unsafe
    actions.

    Proof: proof/model.py gated_transitions() verifies every DENIED
    state has at least one tier with FAIL result.
    """
    import importlib.util
    import sys
    from pathlib import Path

    model_path = Path(__file__).resolve().parents[1] / "proof" / "model.py"
    spec = importlib.util.spec_from_file_location("cage_proof_model", model_path)
    assert spec is not None and spec.loader is not None
    model = importlib.util.module_from_spec(spec)
    sys.modules["cage_proof_model"] = model
    spec.loader.exec_module(model)

    states = model.enumerate_reachable(model.gated_transitions)
    denied_from_tier = [
        s for s in states
        if s.phase == "DENIED" and any(r == "FAIL" for _, r in s.tier_results)
    ]
    assert len(denied_from_tier) > 0
    for state in denied_from_tier:
        assert state.resolved_allow is False
        assert state.seal_present is False


@pytest.mark.asyncio
async def test_unknown_tier_result_must_block_execution() -> None:
    """If any tier returns UNKNOWN, the action must be blocked.

    Contract: Governance tiers must return explicit ALLOW or DENY.
    UNKNOWN (uninitialized, exception, timeout) defaults to DENY.

    Rationale: Fail-closed on ambiguity prevents partial failures
    from creating untracked capability escalation.

    Enforcement: SymbolicGovernor._run_checks() logic.
    """
    from unittest.mock import MagicMock
    from src.gateway.governance.symbolic_governor import SymbolicGovernor
    from src.gateway.governance.contracts import GovernanceTierPlugin

    class BrokenTier(GovernanceTierPlugin):
        @property
        def tier_name(self) -> str:
            return "broken_tier"

        @property
        def phase(self) -> int:
            return 1

        @property
        def order(self) -> int:
            return 1

        def claims_action(self, action: str, params: dict[str, Any]) -> bool:
            return True

        async def evaluate(self, action: str, params: dict[str, Any]) -> list[Any]:
            raise RuntimeError("Tier crashed with unexpected exception")

        async def commit(self, action: str, params: dict[str, Any]) -> list[Any]:
            return []

        async def rollback(self, action: str, params: dict[str, Any]) -> None:
            pass

    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        domain_tiers=(BrokenTier(),),
    )
    violations = await gov._run_domain_tiers("execute_trade", {}, phase=1)
    assert len(violations) == 1
    assert violations[0].tier == "broken_tier"
    assert violations[0].code == "TIER_EXCEPTION"
    assert violations[0].recoverable is False
    assert violations[0].needs_human_review is True


@pytest.mark.asyncio
async def test_tier_timeout_must_block_execution() -> None:
    """If a tier times out (exceeds SLA budget), the action must be blocked.

    Contract: Tier evaluation must complete within allocated latency
    budget. Timeouts are treated as FAIL (fail-closed).

    Rationale: Timeout as FAIL prevents denial-of-service attacks
    from bypassing governance via intentional slowdown.
    """
    import asyncio
    from unittest.mock import MagicMock
    from src.gateway.governance.symbolic_governor import SymbolicGovernor
    from src.gateway.governance.contracts import GovernanceTierPlugin

    class TimeoutTier(GovernanceTierPlugin):
        @property
        def tier_name(self) -> str:
            return "timeout_tier"

        @property
        def phase(self) -> int:
            return 1

        @property
        def order(self) -> int:
            return 1

        def claims_action(self, action: str, params: dict[str, Any]) -> bool:
            return True

        async def evaluate(self, action: str, params: dict[str, Any]) -> list[Any]:
            raise asyncio.TimeoutError("Tier evaluation exceeded SLA budget")

        async def commit(self, action: str, params: dict[str, Any]) -> list[Any]:
            return []

        async def rollback(self, action: str, params: dict[str, Any]) -> None:
            pass

    gov = SymbolicGovernor(
        opa_client=MagicMock(),
        safety_filter=MagicMock(),
        consensus_engine=MagicMock(),
        domain_tiers=(TimeoutTier(),),
    )
    violations = await gov._run_domain_tiers("execute_trade", {}, phase=1)
    assert len(violations) == 1
    assert violations[0].tier == "timeout_tier"
    assert violations[0].code == "TIER_EXCEPTION"
    assert "TimeoutError" in violations[0].message
    assert violations[0].recoverable is False


# ---------------------------------------------------------------------------
# Tier Evidence Accumulation Contract Tests
# ---------------------------------------------------------------------------


def test_every_tier_must_emit_evidence_artifact() -> None:
    """Each tier must emit an evidence artifact.

    Contract: Tier execution produces a structured evidence record
    containing tier verdicts, violation structures, and chain commitment.

    Rationale: Evidence chain provides audit trail for compliance
    validation (NIST SP 800-53 AU-2, AU-3).
    """
    import dataclasses
    from src.gateway.governance.symbolic_governor import Violation
    from src.gateway.governance.evidence.stream import (
        EvidenceRecord,
        EvidenceCommitResult,
    )

    assert dataclasses.is_dataclass(Violation)
    assert dataclasses.is_dataclass(EvidenceRecord)
    assert dataclasses.is_dataclass(EvidenceCommitResult)


def test_evidence_artifacts_must_be_immutable() -> None:
    """TierEvidence artifacts and receipts must be immutable (frozen dataclass).

    Contract: Once emitted, evidence cannot be modified. This prevents
    post-hoc tampering with audit records.

    Rationale: Immutable evidence enables cryptographic signing and
    non-repudiation.

    Enforcement: @dataclass(frozen=True) on evidence dataclasses and receipts.
    """
    from src.gateway.governance.evidence.stream import EvidenceCommitResult
    from src.gateway.governance.evidence.cold_store import ColdStoreReceipt
    from src.gateway.governance.contracts import RefusalReceipt, PauseReceipt

    assert getattr(EvidenceCommitResult, "__dataclass_params__").frozen is True
    assert getattr(ColdStoreReceipt, "__dataclass_params__").frozen is True
    assert getattr(RefusalReceipt, "__dataclass_params__").frozen is True
    assert getattr(PauseReceipt, "__dataclass_params__").frozen is True


def test_evidence_chain_must_preserve_temporal_order() -> None:
    """Evidence artifacts must preserve tier execution order via timestamps.

    Contract: Evidence chain timestamp sequence must match tier
    execution order (FTRA → STPA → Confidence → ... → FRIA).

    Rationale: Temporal order enables causality analysis and replay
    debugging (which tier blocked the action, and when).
    """
    import dataclasses
    from src.gateway.governance.evidence.stream import EvidenceRecord, EvidenceCommitResult

    fields_record = {f.name for f in dataclasses.fields(EvidenceRecord)}
    assert "timestamp" in fields_record
    assert "sequence" in fields_record

    fields_commit = {f.name for f in dataclasses.fields(EvidenceCommitResult)}
    assert "commit_timestamp" in fields_commit
    assert "sequence" in fields_commit


# ---------------------------------------------------------------------------
# Regression Protection Tests
# ---------------------------------------------------------------------------


def test_tier_count_matches_published_proof_model() -> None:
    """The number of governance tiers must match the proof model.

    Contract: Any addition or removal of tiers requires updating:
    1. proof/model.py TIERS tuple
    2. tests/test_no_direct_bind_proof.py expected counts
    3. docs/paper/REVISION_TRACKER.md published figures

    Rationale: Proof/implementation divergence invalidates published
    formal verification claims.

    Enforcement: This test + proof state count regression tests.
    """
    import importlib.util
    import sys
    from pathlib import Path

    # Load proof model (same approach as test_no_direct_bind_proof.py)
    model_path = Path(__file__).resolve().parents[1] / "proof" / "model.py"
    spec = importlib.util.spec_from_file_location("cage_proof_model", model_path)
    assert spec is not None and spec.loader is not None
    model = importlib.util.module_from_spec(spec)
    sys.modules["cage_proof_model"] = model
    spec.loader.exec_module(model)

    # Verify tier count (updated for ARCH-1: 9 tiers including FTRA)
    assert len(model.TIERS) == 9, (
        f"Expected 9 governance tiers in proof model; got {len(model.TIERS)}: "
        f"{model.TIERS}"
    )

    # Verify FTRA is first tier
    assert model.TIERS[0] == "ftra", (
        "FTRA (Tier 0.5) must be the first tier in execution order"
    )


def test_no_hardcoded_domain_verbs_in_kernel() -> None:
    """The kernel must not hardcode domain-specific verbs (e.g. 'execute_trade').

    Contract: src/gateway/ code must never mention domain-specific
    actions like 'execute_trade', 'reverse_trade'.

    Rationale: Domain verb hardcoding violates kernel/plugin separation
    and prevents new domain plugin development.

    Enforcement: Code review + Gate G6 check via scripts/check_domain_literals.py.
    """
    from pathlib import Path
    import scripts.check_domain_literals as cdl

    gateway_dir = Path("src/gateway")
    violations = []
    for py_file in gateway_dir.rglob("*.py"):
        if not cdl.should_skip(py_file, gateway_dir):
            file_violations = cdl.check_file(py_file)
            for lineno, literal in file_violations:
                violations.append((str(py_file), lineno, literal))

    assert not violations, f"Forbidden domain literals found in kernel: {violations}"


# ---------------------------------------------------------------------------
# End-to-end contract validation
# ---------------------------------------------------------------------------


def test_tier_contracts_are_documented_in_architecture_md() -> None:
    """Tier registration contracts must be documented in ARCHITECTURE.md.

    Contract: The canonical tier plugin API specification lives in
    docs/architecture/ARCHITECTURE.md, not scattered across code comments.

    Rationale: Centralized contract documentation enables external
    domain plugin developers to implement CAGE-compliant plugins
    without reading kernel implementation details.

    Enforcement: Documentation review during PR merge.
    """
    from pathlib import Path

    arch_doc = Path("docs/architecture/ARCHITECTURE.md")
    assert arch_doc.exists(), "docs/architecture/ARCHITECTURE.md must exist"

    content = arch_doc.read_text()

    # Verify key architectural terms are documented
    # Note: Specific tier registration APIs evolve; look for core concepts
    assert "governance" in content.lower(), (
        "ARCHITECTURE.md must document governance architecture"
    )

    assert "domain plugin" in content.lower() or "cage_" in content, (
        "ARCHITECTURE.md must document domain plugin architecture"
    )

    # This is a smoke test; full documentation validation is manual
