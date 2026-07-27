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
Forward-Looking Trajectory Reachability Analyzer (FTRA) — CAGE Tier 0.5.

This package implements the commencement-time worst-case reachability analysis
described in plans/COMMENCEMENT_TIME_REACHABILITY_ANALYZER.md.

Before the first LangGraph node fires, the FTRA:
  1. Builds a NetworkX DiGraph from the ExecutionPlan step list.
  2. Classifies each step's action against the compiled terminal registry
     (config/ftra/terminal_registry.json).
  3. Runs DFS reachability from step[0] to find all reachable
     IRREVERSIBLE_TERMINAL nodes.
  4. Returns a FTRAVerdict:
       CLEAR          — no irreversible terminal reachable
       HITL_REQUIRED  — irreversible terminal reachable, confidence >= 0.70
       BLOCKED        — irreversible terminal reachable, confidence < 0.70

Control ID: CTRL_FTRA_001
"""

from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
from src.gateway.governance.ftra.models import (
    FTRAVerdict,
    ReachabilityResult,
    TerminalClassification,
)
from src.gateway.governance.ftra.node_factory import create_ftra_node

__all__ = [
    "FTRAVerdict",
    "IrreversibilityClassifier",
    "PlanGraphAnalyzer",
    "ReachabilityResult",
    "TerminalClassification",
    "create_ftra_node",
]
