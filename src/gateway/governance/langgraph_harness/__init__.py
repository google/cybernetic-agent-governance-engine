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
LangGraph Governance Harness — reusable node factories for any LangGraph agent.

Exports factory functions that produce async LangGraph node functions with
OPA policy enforcement, NeMo guardrail gating, OTel tracing, ISO 42001
stamping, and fail-closed exception handling baked in.

Usage::

    from src.gateway.governance.langgraph_harness import (
        create_opa_safety_node,
        create_opa_safety_router,
        create_nemo_guardrail_node,
        create_nemo_output_rail_node,
        OpaNodeConfig,
        NemoNodeConfig,
    )

    safety_node = create_opa_safety_node(OpaNodeConfig(
        policy_action_name="execute_trade",
        payload_extractor=my_extractor_fn,
    ))
"""

from src.gateway.governance.langgraph_harness.nemo_node_factory import (
    create_nemo_guardrail_node,
    create_nemo_output_rail_node,
)
from src.gateway.governance.langgraph_harness.opa_node_factory import (
    create_opa_safety_node,
    create_opa_safety_router,
)
from src.gateway.governance.langgraph_harness.types import (
    ConfidenceExtractor,
    FtraNodeConfig,
    MessageExtractor,
    NemoNodeConfig,
    OpaNodeConfig,
    PayloadExtractor,
    PlanExtractor,
    StateDict,
    ThreadIdExtractor,
    default_confidence_extractor,
    default_plan_extractor,
)

__all__ = [
    "ConfidenceExtractor",
    "FtraNodeConfig",
    "MessageExtractor",
    "NemoNodeConfig",
    "OpaNodeConfig",
    "PayloadExtractor",
    "PlanExtractor",
    "StateDict",
    "ThreadIdExtractor",
    "create_nemo_guardrail_node",
    "create_nemo_output_rail_node",
    "create_opa_safety_node",
    "create_opa_safety_router",
    "default_confidence_extractor",
    "default_plan_extractor",
]
