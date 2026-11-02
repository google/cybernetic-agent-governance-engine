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

"""Pinned TLC results for the specs without a Python twin (POAM-2026-091).

``DistributedCBF*.cfg`` is pinned against its Python BFS
(``proof/distributed_cbf_model.py``). ``FtraBoundary`` and
``LangGraphHarness`` have no BFS twin, so their TLC results are pinned here:
the number of distinct states TLC reports under ``-continue`` and the exact
set of invariants it reports violated. TLC reports the first violated
invariant per state, in cfg order, so the negative-control cfgs list the
invariant they demonstrate first.

``DECLARED_CHECKS`` pins what every cfg, all eight, asks TLC to check. State
counts cannot catch a dropped INVARIANT or PROPERTY line: the reachable states
are the same, so the count still matches while one property fewer is checked.

``scripts/verify_tla.py`` compares a live TLC run with these pins;
``tests/test_tla_specs_proof.py`` checks cfg/spec parity without Java.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TlcPin:
    """What TLC must report for one cfg."""

    spec: str
    distinct_states: int
    violated: frozenset[str]
    negative_control: bool = False


TLC_PINS: dict[str, TlcPin] = {
    # FtraBoundary.tla — in-graph ftra_node vs controller FtraStage (R-03).
    "FtraBoundary": TlcPin("FtraBoundary", 8272, frozenset()),
    "FtraBoundary_nonetpol": TlcPin("FtraBoundary", 8756, frozenset()),
    "FtraBoundary_noboundary": TlcPin(
        "FtraBoundary",
        13792,
        frozenset(
            {
                "NoUnreviewedIrreversibleExecution",
                "ControllerBoundaryCoversInGraphBypass",
                "ControllerBoundaryUnconditional",
            }
        ),
        negative_control=True,
    ),
    # LangGraphHarness.tla — GFA thread over MaxTurns turns + DeferQueue.
    "LangGraphHarness": TlcPin("LangGraphHarness", 82652, frozenset()),
    "LangGraphHarness_unguarded": TlcPin(
        "LangGraphHarness",
        906,
        frozenset({"SingleUseDeferralTicket"}),
        negative_control=True,
    ),
}


@dataclass(frozen=True)
class CfgChecks:
    """The invariants and properties one cfg asks TLC to check."""

    invariants: frozenset[str]
    properties: frozenset[str] = frozenset()


_CBF_CHECKS = CfgChecks(
    frozenset({"TypeOK", "SP1_NoDoubleSpend", "SP2_NoOvercommit"}),
    frozenset({"SP4_FenceEpochMonotonic"}),
)
_FTRA_INVARIANTS = frozenset(
    {
        "TypeOK",
        "ControllerBoundaryCoversInGraphBypass",
        "ControllerBoundaryUnconditional",
        "NoUnreviewedIrreversibleExecution",
        "FailClosedOnUnknownAction",
        "RegistryUnavailableFailsClosed",
        "AutoClearOnlyInsideEnvelope",
        "NetworkPolicyEnforced",
        "ConsistentClassification",
        "HITLRequiredPropagates",
        "ParseErrorsPreventClear",
    }
)
_HARNESS_INVARIANTS = frozenset(
    {
        "TypeOK",
        "NoDirectBind",
        "SealGateIntegrity",
        "EvidenceChainIntegrity",
        "HITLTimeoutSafety",
        "OutputRailCoverage",
        "SingleUseDeferralTicket",
        "BudgetNeverExceededWithoutPause",
        "RefusedTurnNeverTrades",
        "FtraHoldNeverTradesThisTurn",
    }
)

DECLARED_CHECKS: dict[str, CfgChecks] = {
    "DistributedCBF": _CBF_CHECKS,
    "DistributedCBF_nosync": _CBF_CHECKS,
    "DistributedCBF_unfenced": _CBF_CHECKS,
    # Only the shipped cfg runs FairSpec, so only it checks liveness.
    "FtraBoundary": CfgChecks(_FTRA_INVARIANTS, frozenset({"EveryRequestTerminates"})),
    "FtraBoundary_nonetpol": CfgChecks(_FTRA_INVARIANTS),
    "FtraBoundary_noboundary": CfgChecks(_FTRA_INVARIANTS),
    "LangGraphHarness": CfgChecks(_HARNESS_INVARIANTS),
    "LangGraphHarness_unguarded": CfgChecks(_HARNESS_INVARIANTS),
}

_CFG_COMMENT = re.compile(r"\\\*[^\n]*|\(\*.*?\*\)", re.DOTALL)
_CFG_KEYWORDS = frozenset(
    {
        "CONSTANT",
        "CONSTANTS",
        "INIT",
        "NEXT",
        "SPECIFICATION",
        "INVARIANT",
        "INVARIANTS",
        "PROPERTY",
        "PROPERTIES",
        "SYMMETRY",
        "VIEW",
        "CONSTRAINT",
        "CONSTRAINTS",
        "ACTION_CONSTRAINT",
        "ACTION_CONSTRAINTS",
        "CHECK_DEADLOCK",
        "POSTCONDITION",
        "ALIAS",
    }
)


def declared_checks(cfg_text: str) -> CfgChecks:
    """Read the INVARIANT(S) and PROPERTY/PROPERTIES sections of a TLC cfg."""
    found: dict[str, set[str]] = {"INVARIANT": set(), "PROPERTY": set()}
    section = ""
    for token in re.findall(r"[A-Za-z_]\w*", _CFG_COMMENT.sub(" ", cfg_text)):
        if token in _CFG_KEYWORDS:
            section = {"INVARIANTS": "INVARIANT", "PROPERTIES": "PROPERTY"}.get(
                token, token
            )
        elif section in found:
            found[section].add(token)
    return CfgChecks(frozenset(found["INVARIANT"]), frozenset(found["PROPERTY"]))
