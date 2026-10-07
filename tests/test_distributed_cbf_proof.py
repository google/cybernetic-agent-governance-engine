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

"""Pins the formal models: distributed CBF claims, TLC cfg parity, verdict lattice.

POAM-2026-090. The distributed CBF model's claims were previously asserted
only under ``__main__``; the cfg named constants the spec did not declare.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from proof import distributed_cbf_model as dcbf
from proof.model import (
    enumerate_reachable,
    enumerate_region,
    gated_transitions,
    narrow_valid,
    ungated_transitions,
    verdict_lattice_holds,
    verdict_of,
)
from src.gateway.governance.classification_engine import (
    ClassificationContext,
    ClassificationEngine,
)
from src.gateway.governance.contracts import NarrowingResult, Violation, ViolationKind
from src.gateway.governance.narrower import NarrowerRegistry

pytestmark = [pytest.mark.unit, pytest.mark.local]

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proof"


# ---------------------------------------------------------------------------
# Distributed CBF: pinned counts and claims
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "n"), sorted(dcbf.EXPECTED_STATE_COUNTS))
def test_state_counts_and_sp1_verdicts_are_pinned(name: str, n: int) -> None:
    result = dcbf.check(dcbf.config_for(name, n))
    got = (result.states, result.sp1_holds, result.sp2_holds)
    assert got == dcbf.EXPECTED_STATE_COUNTS[(name, n)]
    assert result.sp4_holds, "fence epoch decreased outside a stale failover"


def test_shipped_posture_survives_stale_failover() -> None:
    """Reconciled + WAIT N: no double spend and no over-credit for up to
    three processes, with restarts and one stale failover."""
    for n in (1, 2, 3):
        r = dcbf.check(dcbf.config_for("DistributedCBF", n))
        assert r.sp1_holds and r.sp2_holds


def test_without_sync_replication_fencing_does_not_prevent_double_spend() -> None:
    """Negative control: WAIT N is load-bearing. A second process whose
    last_seen epoch is at the regressed value spends the restored balance —
    no restart needed."""
    r = dcbf.check(dcbf.Config(2, sync_replication=False, allow_restart=False))
    assert not r.sp1_holds
    assert "stale_failover" in r.counterexample
    assert not any(step.startswith("agent_restart") for step in r.counterexample)
    failover = r.counterexample.index("stale_failover")
    assert any(step.startswith("commit") for step in r.counterexample[:failover])


def test_single_process_without_sync_last_seen_is_reseeded() -> None:
    """Even one process is not protected by _last_seen_epoch without WAIT N:
    a rollback after the failover assigns ``_last_seen_epoch = new_epoch``
    (the regressed epoch + 1), and so does a restart."""
    r = dcbf.check(dcbf.Config(1, sync_replication=False, allow_restart=False))
    assert not r.sp1_holds
    failover = r.counterexample.index("stale_failover")
    assert "rollback(a0)" in r.counterexample[failover:]
    r = dcbf.check(dcbf.Config(1, sync_replication=False, allow_restart=True))
    assert not r.sp1_holds
    assert "agent_restart(a0)" in r.counterexample


def test_sp1_does_not_rely_on_the_fence_cas() -> None:
    """The script checks the barrier on live primary state in both modes."""
    assert dcbf.check(dcbf.config_for("DistributedCBF_unfenced", 2)).sp1_holds


# ---------------------------------------------------------------------------
# TLC cfg parity (hermetic: no Java needed)
# ---------------------------------------------------------------------------


def _cfg_constants(path: Path) -> dict[str, str]:
    text = path.read_text()
    block = text.split("CONSTANTS", 1)[1].split("INVARIANTS", 1)[0]
    return dict(re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", block, re.MULTILINE))


def _spec_constants(path: Path) -> set[str]:
    block = path.read_text().split("\nCONSTANTS\n", 1)[1].split("\nVARIABLES", 1)[0]
    return set(re.findall(r"^\s{4}(\w+),?", block, re.MULTILINE))


def _spec_definitions(path: Path) -> set[str]:
    return set(re.findall(r"^(\w+)(?:\([^)]*\))? ==", path.read_text(), re.MULTILINE))


def _cfg_checked_names(path: Path) -> set[str]:
    names: set[str] = set()
    for section in ("INVARIANTS", "PROPERTIES"):
        if section in path.read_text():
            body = path.read_text().split(section, 1)[1]
            body = re.split(r"\n[A-Z_]+\s", "\n" + body.lstrip("\n"), maxsplit=1)[0]
            names |= set(re.findall(r"^\s+(\w+)\s*$", body, re.MULTILINE))
    return names


@pytest.mark.parametrize("name", sorted(dcbf.CONFIGS))
def test_cfg_matches_spec_and_python_config(name: str) -> None:
    spec = PROOF / "DistributedCBF.tla"
    cfg_path = PROOF / f"{name}.cfg"
    consts = _cfg_constants(cfg_path)
    assert set(consts) == _spec_constants(spec), "cfg and spec constants differ"
    assert _cfg_checked_names(cfg_path) <= _spec_definitions(spec)

    cfg = dcbf.CONFIGS[name]
    tla_bool = {"TRUE": True, "FALSE": False}
    assert (
        consts["AgentIDs"].strip("{}").replace(" ", "").count(",") + 1 == cfg.n_agents
    )
    assert int(consts["InitialPool"]) == dcbf.INITIAL_POOL
    assert int(consts["ReserveAmount"]) == dcbf.RESERVE_AMOUNT
    assert int(consts["MaxAgentReserve"]) == dcbf.MAX_AGENT_RESERVE
    assert int(consts["MaxFenceEpoch"]) == dcbf.MAX_FENCE_EPOCH
    assert int(consts["MaxStaleFailovers"]) == cfg.max_stale_failovers
    assert tla_bool[consts["SyncReplication"]] is cfg.sync_replication
    assert tla_bool[consts["Fenced"]] is cfg.fenced
    assert tla_bool[consts["AllowRestart"]] is cfg.allow_restart


@pytest.mark.skipif(not os.environ.get("TLA_TOOLS_JAR"), reason="TLA_TOOLS_JAR not set")
def test_tlc_reproduces_python_bfs() -> None:
    from scripts.verify_tla import main as verify_tla

    assert verify_tla() == 0


# ---------------------------------------------------------------------------
# proof/model.py: published counts, I-6, verdict lattice
# ---------------------------------------------------------------------------


def test_published_governance_model_counts() -> None:
    """proof/README.md and REVISION_TRACKER cite these numbers."""
    assert len(enumerate_reachable(gated_transitions)) == 38
    assert len(enumerate_reachable(ungated_transitions)) == 19
    assert len(enumerate_region("EU_ECB")) == 42


def test_i6_narrow_valid_holds_on_every_reachable_state() -> None:
    states = enumerate_reachable(gated_transitions)
    assert any(s.phase == "NARROW" for s in states)
    assert all(narrow_valid(s) for s in states)


def test_verdict_lattice_claims() -> None:
    assert verdict_lattice_holds()


class _AlwaysNarrows:
    def can_narrow(self, violation: Violation, action: str, params: dict) -> bool:
        return True

    def narrow(
        self, violation: Violation, action: str, params: dict
    ) -> NarrowingResult:
        return NarrowingResult(
            can_narrow=True,
            narrowed_params={"amount": 1},
            constraints_applied=["clamp"],
            narrowing_reason="parity",
        )


_KIND = {
    "HARD": ViolationKind.HARD,
    "HITL": ViolationKind.HITL,
    "DEFERRABLE": ViolationKind.DEFERRABLE,
    "NARROWABLE": ViolationKind.NARROWABLE,
    "RELIANCE_INELIGIBLE": ViolationKind.RELIANCE_INELIGIBLE,
}


def test_verdict_of_matches_classification_engine() -> None:
    """Every kind set x confidence x narrowing x manual review x defer flag."""
    from itertools import product

    from proof.model import _kind_sets

    for kinds in _kind_sets():
        if not kinds:
            continue
        for low, narrows, manual, defer in product((False, True), repeat=4):
            engine = ClassificationEngine(
                narrower_registry=NarrowerRegistry([_AlwaysNarrows()]),
                confidence_threshold=0.70,
                defer_enabled=defer,
                narrow_enabled=narrows,
            )
            ctx = ClassificationContext(
                violations=[
                    Violation(tier="t", code=f"C_{k}", message="m", kind=_KIND[k])
                    for k in sorted(kinds)
                ],
                confidence=0.5 if low else 0.9,
                opa_decision="MANUAL_REVIEW" if manual else None,
                policy_ambiguous=False,
                params={"amount": 10},
            )
            got = engine.classify(ctx, "act").decision.value
            want = verdict_of(
                kinds,
                low_confidence=low,
                narrows=narrows,
                manual_review=manual,
                defer_enabled=defer,
            )
            assert got == want, (kinds, low, narrows, manual, defer)
