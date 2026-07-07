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
Tests for src.gateway.governance.ontology — TradingKnowledgeGraph (UCA-7 semantic constraints).

Note: TradingKnowledgeGraph is a dataclass with ucas and constraints dicts.
It does not have a validate() method. Key methods:
  - get_rubric() → list[STAMP_UCA]
  - get_constraints_for_action(action_name) → list[Constraint]
  - add_uca(uca) / add_constraint(constraint)
  - ISO_CONTROL_MAP — class-level dict of control mappings
"""

import pytest

pytestmark = pytest.mark.unit


def test_trading_knowledge_graph_initializes():
    """TradingKnowledgeGraph should initialize without errors."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    assert graph is not None


def test_trading_knowledge_graph_ucas_populated():
    """TradingKnowledgeGraph should populate UCAs on init (UCA-1 through UCA-6 at minimum)."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    assert len(graph.ucas) >= 4
    assert "UCA-1" in graph.ucas
    assert "UCA-2" in graph.ucas
    assert "UCA-5" in graph.ucas
    assert "UCA-6" in graph.ucas


def test_trading_knowledge_graph_constraints_populated():
    """TradingKnowledgeGraph should populate safety constraints on init."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    assert len(graph.constraints) >= 2
    assert "SC-1" in graph.constraints
    assert "FIN-2" in graph.constraints


def test_get_rubric_returns_all_ucas():
    """get_rubric() should return a list containing all registered UCAs."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    rubric = graph.get_rubric()
    assert isinstance(rubric, list)
    assert len(rubric) == len(graph.ucas)
    uca_ids = {uca.id for uca in rubric}
    assert "UCA-1" in uca_ids
    assert "UCA-5" in uca_ids


def test_get_constraints_for_action_execute_trade():
    """get_constraints_for_action('execute_trade') should return FIN-2 constraint."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    constraints = graph.get_constraints_for_action("execute_trade")
    assert isinstance(constraints, list)
    constraint_ids = {c.id for c in constraints}
    assert "FIN-2" in constraint_ids


def test_get_constraints_for_action_write_db():
    """get_constraints_for_action('write_db') should return SC-1 constraint."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    constraints = graph.get_constraints_for_action("write_db")
    constraint_ids = {c.id for c in constraints}
    assert "SC-1" in constraint_ids


def test_get_constraints_for_action_unknown_action():
    """get_constraints_for_action() with an unknown action should return an empty list."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    result = graph.get_constraints_for_action("nonexistent_action")
    assert result == []


def test_iso_control_map_has_required_keys():
    """ISO_CONTROL_MAP must contain the four documented governance control categories."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    assert "SOCIAL_IMPACT" in TradingKnowledgeGraph.ISO_CONTROL_MAP
    assert "LOGGING_AUDIT" in TradingKnowledgeGraph.ISO_CONTROL_MAP
    assert "DATA_PRIVACY" in TradingKnowledgeGraph.ISO_CONTROL_MAP
    assert "FISCAL_CONTROLS" in TradingKnowledgeGraph.ISO_CONTROL_MAP


def test_add_uca_registers_new_uca():
    """add_uca() should register a new UCA in the graph."""
    from src.gateway.governance.ontology import STAMP_UCA, TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    new_uca = STAMP_UCA(
        id="UCA-99",
        category="Test Category",
        description="Test UCA",
        hazard_link="H-99",
        detection_pattern="test_pattern",
    )
    graph.add_uca(new_uca)
    assert "UCA-99" in graph.ucas
    assert graph.ucas["UCA-99"].description == "Test UCA"


def test_add_constraint_registers_new_constraint():
    """add_constraint() should register a new Constraint in the graph."""
    from src.gateway.governance.ontology import Constraint, TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    new_constraint = Constraint(
        id="TEST-1",
        description="Test constraint",
        logic="test_value == True",
        scope=["test_action"],
    )
    graph.add_constraint(new_constraint)
    assert "TEST-1" in graph.constraints
    constraints = graph.get_constraints_for_action("test_action")
    assert any(c.id == "TEST-1" for c in constraints)


def test_uca_1_governs_write_operations():
    """UCA-1 should be categorized as 'Unsafe Action' regarding DB writes."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    uca1 = graph.ucas["UCA-1"]
    assert uca1.category == "Unsafe Action"
    assert (
        "write" in uca1.detection_pattern.lower()
        or "approval_token" in uca1.detection_pattern.lower()
    )


def test_uca_2_governs_latency():
    """UCA-2 should be categorized as 'Wrong Timing' regarding latency."""
    from src.gateway.governance.ontology import TradingKnowledgeGraph

    graph = TradingKnowledgeGraph()
    uca2 = graph.ucas["UCA-2"]
    assert uca2.category == "Wrong Timing"
    assert "latency" in uca2.detection_pattern.lower()
