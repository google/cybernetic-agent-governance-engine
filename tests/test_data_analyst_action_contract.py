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

"""The data analyst's governed action must be one the finance domain registers.

Regression for the 2026-10-03 in-cluster benchmark
(``docs/paper/measurements/2026-10-03-57556228/PROVENANCE.md``). The data
analyst submitted its market-data tool calls as ``fetch_market_data``. No layer
registers that action. ``trade_governance.rego`` denied it (``CTRL_OPA_005``),
and FTRA would have classified it ``IRREVERSIBLE_TERMINAL`` (fail closed). Every
benign market-data question was refused as a result. The action is now
``market_analysis``, which every layer registers as read-only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from src.cage_finance import REGISTERED_ACTIONS
from src.gateway.governance import stpa_compiler
from src.gateway.governance.ftra.classifier import _load_registry_document
from src.governed_financial_advisor.graph.subgraphs.data_analyst_graph import (
    GOVERNED_ACTION,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]
_RUNTIME_REGISTRY = _REPO / "config" / "ftra" / "terminal_registry.json"
_GENERATED_REGISTRY = _REPO / "src" / "cage_finance" / "stpa" / "terminal_registry.json"
_FINANCE_STPA = _REPO / "src" / "cage_finance" / "config" / "stpa"
_TRADE_REGO = _REPO / "src" / "cage_finance" / "opa" / "trade_governance.rego"


def test_governed_action_is_market_analysis() -> None:
    assert GOVERNED_ACTION == "market_analysis"


def test_governed_action_is_on_the_finance_action_surface() -> None:
    assert GOVERNED_ACTION in REGISTERED_ACTIONS


def test_runtime_ftra_registry_classifies_it_read_only() -> None:
    # _load_registry_document verifies manifest_sha256, so this also proves
    # the registry was rehashed after the edit.
    registry = _load_registry_document(_RUNTIME_REGISTRY)
    assert registry.terminals[GOVERNED_ACTION] == "READ_ONLY"


def test_generated_ftra_registry_classifies_it_read_only() -> None:
    terminals = json.loads(_GENERATED_REGISTRY.read_text())["terminals"]
    assert terminals[GOVERNED_ACTION] == "READ_ONLY"


# ---------------------------------------------------------------------------
# OPA: evaluate the shipped policy against the input shape the OPA stage
# builds (``{**params, "action": action, "tool_input": params}``) for a
# data-analyst tool call. The tool call carries no trader_role or risk_profile.
# ---------------------------------------------------------------------------


def _opa_decision(action: str) -> Any:
    params = {"symbol": "AAPL", "tool_name": "check_market_status", "action": action}
    payload = {**params, "action": action, "tool_input": params}
    out = subprocess.run(  # noqa: S603 — fixed argv, local opa binary
        [
            str(shutil.which("opa")),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(_TRADE_REGO),
            "data.trade.governance.allow",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]


def _opa_runs() -> bool:
    """True when an ``opa`` binary is on PATH and actually executes."""
    opa = shutil.which("opa")
    if opa is None:
        return False
    try:
        subprocess.run(  # noqa: S603 — fixed argv, local opa binary
            [opa, "version"], capture_output=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


_needs_opa = pytest.mark.skipif(not _opa_runs(), reason="no runnable opa binary")


@_needs_opa
def test_opa_allows_the_governed_action() -> None:
    assert _opa_decision(GOVERNED_ACTION) == "ALLOW"


@_needs_opa
def test_opa_denies_the_unregistered_name_it_replaced() -> None:
    # Negative control: the old action name is still denied, so the ALLOW
    # above comes from the registered name and not from a permissive policy.
    assert _opa_decision("fetch_market_data") == "DENY"


# ---------------------------------------------------------------------------
# Compiler: a control action may declare its FTRA classification.
# ---------------------------------------------------------------------------


def _finance_structure() -> stpa_compiler.ControlStructureModel:
    return stpa_compiler.load_control_structures(sorted(_FINANCE_STPA.rglob("*.yaml")))


def test_control_action_classification_reaches_the_registry() -> None:
    terminals = json.loads(stpa_compiler.generate_terminal_registry(_finance_structure()))[
        "terminals"
    ]
    assert terminals["market_analysis"] == "READ_ONLY"


def test_uca_classification_wins_when_more_restrictive() -> None:
    cs = _finance_structure()
    actions = [
        {**ca, "terminal_classification": "READ_ONLY"} if ca.get("name") == "execute_trade" else ca
        for ca in cs.control_actions
    ]
    terminals = json.loads(
        stpa_compiler.generate_terminal_registry(cs.model_copy(update={"control_actions": actions}))
    )["terminals"]
    assert terminals["execute_trade"] == "IRREVERSIBLE_TERMINAL"


def test_invalid_control_action_classification_is_rejected() -> None:
    raw = _finance_structure().model_dump()
    raw["control_actions"][0]["terminal_classification"] = "MOSTLY_HARMLESS"
    with pytest.raises(ValueError, match="terminal_classification"):
        stpa_compiler.ControlStructureModel.model_validate(raw)
