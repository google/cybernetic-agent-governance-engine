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
src.evaluator_agent — Audit Harness Package

This package provides POST-HOC audit and evaluation tooling for CAGE:
- EvaluatorAuditor: Scores completed agent trace logs against SC-1 and governance constraints
- AgentBeatsSimulator: Adversarial simulation harness (test/evaluation only)

This is DISTINCT from the real-time EvaluatorAgent in:
  src.governed_financial_advisor.agents.evaluator.agent

The real-time EvaluatorAgent runs DURING the LangGraph pipeline using live MCP tools.
The EvaluatorAuditor runs AFTER execution, scoring trace logs.

SC-1 enforcement: EvaluatorAuditor delegates to STPAValidator for SC-1 checks
to maintain a single source of truth for SC-1 logic.
"""
