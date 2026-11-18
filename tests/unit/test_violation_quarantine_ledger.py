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

# Closure regression guard for: POAM-2026-233
"""Unit and negative mutation tests for scripts/check_violation_quarantine_ledger.py."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts import check_violation_quarantine_ledger as ledger_gate

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _minimal_synthetic_repo(tmp_path: Path) -> Path:
    """Create a fast synthetic repo tree mirroring the real seam + verdicts contracts."""
    repo = tmp_path / "repo"
    real_root = ledger_gate.DEFAULT_REPO_ROOT
    for rel in (
        "src/gateway/governance/seams/quarantine.py",
        "src/gateway/governance/evidence/stream.py",
        "src/gateway/governance/governor/verdicts.py",
        "src/gateway/governance/safety/barrier_tier.py",
        "src/cage_finance/tiers/cbf_tier.py",
        "src/cage_healthcare/tiers/dose_barrier_tier.py",
        "src/cage_physical_ai/tiers/kinematic_barrier_tier.py",
    ):
        dst = repo / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(real_root / rel, dst)
    return repo


def test_live_repo_violation_quarantine_ledger_passes() -> None:
    report = ledger_gate.discover_and_check_ledger()
    assert report.ok, f"Ledger errors: {report.errors}"
    assert len(report.discovered_codes) >= 90
    assert (
        ledger_gate.QUARANTINE_CODES & ledger_gate.EXPLICIT_NO_QUARANTINE_CODES
        == frozenset()
    )
    assert report.discovered_infra_codes & ledger_gate.QUARANTINE_CODES == frozenset()
    assert ledger_gate.main(["--verbose"]) == 0


def test_planted_unclassified_violation_in_kernel_fails_floor(tmp_path: Path) -> None:
    repo = _minimal_synthetic_repo(tmp_path)
    planted = repo / "src/gateway/governance/planted_stage.py"
    planted.write_text(
        "from src.gateway.governance.contracts import Violation, ViolationKind\n"
        "def emit():\n"
        "    return Violation(tier='x', code='UNCLASSIFIED_NEW_CODE', message='m', kind=ViolationKind.HARD)\n",
        encoding="utf-8",
    )
    report = ledger_gate.discover_and_check_ledger(
        repo,
        quarantine_codes=ledger_gate.QUARANTINE_CODES,
        non_quarantine_codes={
            "CBF_RECONCILIATION_UNAVAILABLE",
            "DOSE_BARRIER_UNCONFIGURED",
            "KINEMATIC_BARRIER_UNCONFIGURED",
        },
    )
    assert not report.ok
    assert any("UNCLASSIFIED_NEW_CODE" in err for err in report.errors)


def test_planted_unclassified_violation_in_integrations_fails_floor(
    tmp_path: Path,
) -> None:
    """Addendum 5: src/integrations/ (and all src/**/*.py) has zero blind spots."""
    repo = _minimal_synthetic_repo(tmp_path)
    planted = repo / "src/integrations/foo/adapter.py"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(
        "from src.gateway.governance.contracts import Violation, ViolationKind\n"
        "def bad():\n"
        "    return Violation(tier='adapter', code='UNCLASSIFIED_INTEGRATION_CODE', message='m', kind=ViolationKind.HARD)\n",
        encoding="utf-8",
    )
    report = ledger_gate.discover_and_check_ledger(
        repo,
        quarantine_codes=ledger_gate.QUARANTINE_CODES,
        non_quarantine_codes={
            "CBF_RECONCILIATION_UNAVAILABLE",
            "DOSE_BARRIER_UNCONFIGURED",
            "KINEMATIC_BARRIER_UNCONFIGURED",
        },
    )
    assert not report.ok
    assert "UNCLASSIFIED_INTEGRATION_CODE" in report.discovered_codes
    assert any("UNCLASSIFIED_INTEGRATION_CODE" in err for err in report.errors)


def test_code_in_both_quarantine_and_non_quarantine_fails_disjointness() -> None:
    report = ledger_gate.discover_and_check_ledger(
        quarantine_codes=ledger_gate.QUARANTINE_CODES | {"OPA_DENY"},
        non_quarantine_codes=ledger_gate.EXPLICIT_NO_QUARANTINE_CODES,
    )
    assert not report.ok
    assert any(
        "BOTH QUARANTINE_CODES and EXPLICIT_NO_QUARANTINE_CODES" in err
        and "OPA_DENY" in err
        for err in report.errors
    )


def test_stale_retired_code_fails_ceiling() -> None:
    report = ledger_gate.discover_and_check_ledger(
        quarantine_codes=ledger_gate.QUARANTINE_CODES,
        non_quarantine_codes=ledger_gate.EXPLICIT_NO_QUARANTINE_CODES
        | {"RETIRED_GHOST_CODE_2025"},
    )
    assert not report.ok
    assert any(
        "Stale code(s)" in err and "RETIRED_GHOST_CODE_2025" in err
        for err in report.errors
    )


def test_infrastructure_code_in_quarantine_codes_fails_isolation() -> None:
    report = ledger_gate.discover_and_check_ledger(
        quarantine_codes=ledger_gate.QUARANTINE_CODES | {"OPA_UNAVAILABLE"},
        non_quarantine_codes=ledger_gate.EXPLICIT_NO_QUARANTINE_CODES
        - {"OPA_UNAVAILABLE"},
    )
    assert not report.ok
    assert any(
        "ViolationKind.INFRASTRUCTURE" in err and "OPA_UNAVAILABLE" in err
        for err in report.errors
    )


def test_unresolvable_dynamic_code_expression_fails_closed(tmp_path: Path) -> None:
    repo = _minimal_synthetic_repo(tmp_path)
    planted = repo / "src/gateway/governance/dynamic_code.py"
    planted.write_text(
        "from src.gateway.governance.contracts import Violation, ViolationKind\n"
        "def foo() -> str:\n"
        "    return 'DYNAMIC'\n"
        "def bad():\n"
        "    return Violation(tier='x', code=foo(), message='m', kind=ViolationKind.HARD)\n",
        encoding="utf-8",
    )
    report = ledger_gate.discover_and_check_ledger(
        repo,
        quarantine_codes=ledger_gate.QUARANTINE_CODES,
        non_quarantine_codes={
            "CBF_RECONCILIATION_UNAVAILABLE",
            "DOSE_BARRIER_UNCONFIGURED",
            "KINEMATIC_BARRIER_UNCONFIGURED",
        },
    )
    assert not report.ok
    assert any("dynamic_code.py:5" in site for site in report.unresolved_sites)
    assert any("Unresolvable dynamic Violation code" in err for err in report.errors)
