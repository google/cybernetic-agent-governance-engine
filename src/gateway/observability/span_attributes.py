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
span_attributes.py — Vendor-Decoupled Telemetry Attribute Constants

Centralizes all OpenTelemetry span attribute keys used throughout CAGE,
decoupling application code from Langfuse-specific attribute naming conventions.

Design Rationale (Wave 1, Task W1.4):
    - Eliminates ~250+ hardcoded "langfuse.*" string literals across codebase
    - Enables switching observability backends without code changes
    - Provides single source of truth for telemetry attribute naming
    - Type-safe constants prevent typos in attribute keys

Architecture Position:
    This module is imported by:
        - Gateway governance middleware
        - Symbolic governor
        - NeMo guardrails manager
        - LangGraph harness nodes
        - Compliance bridge
        - Governed advisor nodes

Migration Strategy (Wave 2):
    Replace all occurrences of:
        span.set_attribute("langfuse.observation.type", "span")
    With:
        span.set_attribute(SPAN_ATTR_OBSERVATION_TYPE, "span")

    This allows future backend swaps (e.g. Langfuse → Grafana Tempo) by changing
    only these constants, not 250+ call sites.

Categories:
    1. Observation Attributes (SPAN_ATTR_OBSERVATION_*)
    2. Trace Attributes (SPAN_ATTR_TRACE_*)
    3. Metadata Attributes (SPAN_ATTR_META_*)
    4. ISO 42001 Control Attributes (SPAN_ATTR_ISO_*)
    5. Governance Attributes (SPAN_ATTR_GOV_*)
    6. Model/Generation Attributes (SPAN_ATTR_MODEL_*)
    7. Guardrails Attributes (SPAN_ATTR_GUARDRAIL_*)

Note: These constants currently use Langfuse naming conventions because CAGE
      standardizes on Langfuse for sovereign compliance telemetry. When migrating
      to a different backend, update the constant values (not the call sites).
"""

# ---------------------------------------------------------------------------
# 1. Observation Attributes (Langfuse observation-level metadata)
# ---------------------------------------------------------------------------

# Core observation metadata
SPAN_ATTR_OBSERVATION_TYPE = "langfuse.observation.type"
"""Observation type: 'span', 'generation', 'event'"""

SPAN_ATTR_OBSERVATION_NAME = "langfuse.observation.name"
"""Human-readable observation name (e.g. 'governance_evaluation', 'opa_policy_check')"""

SPAN_ATTR_OBSERVATION_INPUT = "langfuse.observation.input"
"""Input payload for the observation (typically JSON string)"""

SPAN_ATTR_OBSERVATION_OUTPUT = "langfuse.observation.output"
"""Output payload for the observation (typically JSON string or verdict)"""

# Model-related observation metadata
SPAN_ATTR_OBSERVATION_MODEL_NAME = "langfuse.observation.model.name"
"""Model name/identifier (e.g. 'gemini-1.5-pro', 'llama-3-70b')"""

# Observation metadata namespace (searchable in Langfuse UI)
SPAN_ATTR_OBSERVATION_METADATA_PREFIX = "langfuse.observation.metadata."
"""Prefix for observation-level metadata (custom key-value pairs)"""

SPAN_ATTR_OBSERVATION_METADATA_STPA_HAZARD = "langfuse.observation.metadata.stpa_hazard"
"""STPA hazard identifier (e.g. 'UCA-1_SEMANTIC_BYPASS')"""

SPAN_ATTR_OBSERVATION_METADATA_ISO_CONTROL = "langfuse.observation.metadata.iso_control"
"""ISO 42001 control identifier (e.g. 'A.5.2', 'A.8.4')"""

SPAN_ATTR_OBSERVATION_METADATA_FALLBACK_REASON = (
    "langfuse.observation.metadata.fallback_reason"
)
"""Reason for fallback behavior (e.g. 'NeMo_config_parse_failed')"""

SPAN_ATTR_OBSERVATION_METADATA_GOVERNANCE_STATE = (
    "langfuse.observation.metadata.governance_state"
)
"""Governance state (e.g. 'CIRCUIT_OPEN_REJECTED', 'DEGRADED_FAIL_OPEN')"""

# ---------------------------------------------------------------------------
# 2. Trace Attributes (Langfuse trace-level metadata)
# ---------------------------------------------------------------------------

SPAN_ATTR_TRACE_TAGS = "langfuse.trace.tags"
"""Trace tags (JSON array of strings, e.g. '["iso-42001", "control:A.5.3"]')"""

SPAN_ATTR_TRACE_METADATA_PREFIX = "langfuse.trace.metadata."
"""Prefix for trace-level metadata (indexed/searchable in Langfuse)"""

# Trace metadata: ISO 42001 controls
SPAN_ATTR_TRACE_METADATA_ISO_CONTROL_ID = "langfuse.trace.metadata.iso.control_id"
"""ISO 42001 primary control ID (e.g. 'A.10.1', 'A.8.4')"""

SPAN_ATTR_TRACE_METADATA_ISO_CONTROL_ID_SECONDARY = (
    "langfuse.trace.metadata.iso.control_id_secondary"
)
"""ISO 42001 secondary control ID for multi-control compliance"""

SPAN_ATTR_TRACE_METADATA_ISO_REQUIREMENT = "langfuse.trace.metadata.iso.requirement"
"""ISO 42001 control requirement description"""

SPAN_ATTR_TRACE_METADATA_ISO_REQUIREMENT_SECONDARY = (
    "langfuse.trace.metadata.iso.requirement_secondary"
)
"""ISO 42001 secondary requirement description"""

# Trace metadata: Governance
SPAN_ATTR_TRACE_METADATA_GOVERNANCE_OPA_URL = (
    "langfuse.trace.metadata.governance.opa_url"
)
"""OPA policy server URL"""

SPAN_ATTR_TRACE_METADATA_GOVERNANCE_ACTION = "langfuse.trace.metadata.governance.action"
"""Governance action being evaluated (e.g. 'execute_trade', 'prescribe')"""

SPAN_ATTR_TRACE_METADATA_GOVERNANCE_POLICY_INPUT_SIZE = (
    "langfuse.trace.metadata.governance.policy_input_size"
)
"""Size of OPA policy input payload (bytes)"""

SPAN_ATTR_TRACE_METADATA_GOVERNANCE_DECISION = (
    "langfuse.trace.metadata.governance.decision"
)
"""Final governance decision (ALLOW, DENY, DEFER, etc)"""

SPAN_ATTR_TRACE_METADATA_GOVERNANCE_DENIAL_REASON = (
    "langfuse.trace.metadata.governance.denial_reason"
)
"""Reason for denial verdict"""

# Trace metadata: Guardrails
SPAN_ATTR_TRACE_METADATA_GUARDRAIL_ID = "langfuse.trace.metadata.guardrail.id"
"""Guardrail identifier (NeMo action name)"""

SPAN_ATTR_TRACE_METADATA_GUARDRAIL_ACTION = "langfuse.trace.metadata.guardrail.action"
"""Guardrail action name"""

SPAN_ATTR_TRACE_METADATA_GUARDRAIL_OUTCOME = (
    "langfuse.trace.metadata.guardrails.outcome"
)
"""Guardrail outcome (BLOCKED, APPROVED, etc)"""

SPAN_ATTR_TRACE_METADATA_GUARDRAIL_BLOCK_REASON = (
    "langfuse.trace.metadata.guardrail.block_reason"
)
"""Reason for guardrail block"""

SPAN_ATTR_TRACE_METADATA_GUARDRAILS_FRAMEWORK = (
    "langfuse.trace.metadata.guardrails.framework"
)
"""Guardrails framework name (e.g. 'nemo')"""

SPAN_ATTR_TRACE_METADATA_GUARDRAILS_INPUT_LENGTH = (
    "langfuse.trace.metadata.guardrails.input_length"
)
"""Input text length (characters)"""

SPAN_ATTR_TRACE_METADATA_GUARDRAILS_INTERVENED = (
    "langfuse.trace.metadata.guardrails.intervened"
)
"""Boolean: did guardrails intervene?"""

# Trace metadata: Risk
SPAN_ATTR_TRACE_METADATA_RISK_VERDICT = "langfuse.trace.metadata.risk.verdict"
"""Risk verdict (SAFE, UNSAFE, etc)"""

# Trace metadata: Consensus
SPAN_ATTR_TRACE_METADATA_CONSENSUS_DECISION = (
    "langfuse.trace.metadata.consensus.decision"
)
"""Consensus decision (APPROVE, REJECT, etc)"""

SPAN_ATTR_TRACE_METADATA_CONSENSUS_VOTES = "langfuse.trace.metadata.consensus.votes"
"""Consensus vote breakdown (JSON string)"""

# Trace metadata: Current node (LangGraph)
SPAN_ATTR_TRACE_METADATA_CURRENT_NODE = "langfuse.trace.metadata.current_node"
"""Current LangGraph node name"""

SPAN_ATTR_TRACE_METADATA_MCP_SERVER = "langfuse.trace.metadata.mcp_server"
"""MCP server identifier"""

# Trace metadata: Latency/Performance
SPAN_ATTR_TRACE_METADATA_LATENCY_CURRENCY_TAX = (
    "langfuse.trace.metadata.latency_currency_tax"
)
"""Governance overhead latency (milliseconds)"""

# Trace metadata: POAM
SPAN_ATTR_TRACE_METADATA_POAM_REF = "langfuse.trace.metadata.poam_ref"
"""POAM finding reference (e.g. 'AI600-005')"""

# ---------------------------------------------------------------------------
# 3. CAGE-Specific Attributes (non-Langfuse namespaced)
# ---------------------------------------------------------------------------

SPAN_ATTR_CAGE_GOVERNANCE = "cage.governance"
"""Boolean: is this span governance-related?"""

SPAN_ATTR_CAGE_VERDICT = "cage.verdict"
"""CAGE governance verdict (ALLOW, DENY, etc)"""

SPAN_ATTR_CAGE_SEAL_ISSUED = "cage.seal_issued"
"""Boolean: was a routing seal issued?"""

# Governance stages
SPAN_ATTR_GOVERNANCE_STAGE = "governance.stage"
"""Governance evaluation stage (e.g. 'ftra_boundary', 'tier2_corroboration')"""

SPAN_ATTR_GOVERNANCE_TOOL = "governance.tool"
"""Tool name being governed"""

SPAN_ATTR_GOVERNANCE_BLOCKED = "governance.blocked"
"""Boolean: was action blocked?"""

SPAN_ATTR_GOVERNANCE_REASON = "governance.reason"
"""Denial/approval reason"""

# ---------------------------------------------------------------------------
# 4. Gen AI Semantic Conventions (OpenTelemetry standard)
# ---------------------------------------------------------------------------

SPAN_ATTR_GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
"""Gen AI operation name (e.g. 'chat', 'tool_call', 'embedding')"""

SPAN_ATTR_GEN_AI_SYSTEM = "gen_ai.system"
"""Gen AI system identifier (e.g. 'financial-advisor-gateway', 'nemo-guardrails')"""

SPAN_ATTR_GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
"""Requested model name"""

# ---------------------------------------------------------------------------
# 5. HITL (Human-in-the-Loop) Attributes
# ---------------------------------------------------------------------------

SPAN_ATTR_HITL_REGULATORY_CITATION = "hitl.regulatory_citation"
"""Regulatory citation for HITL escalation"""

# ---------------------------------------------------------------------------
# 6. OPA Attributes
# ---------------------------------------------------------------------------

SPAN_ATTR_OPA_URL = "opa.url"
"""OPA server URL"""

SPAN_ATTR_OPA_POLICY_PATH = "opa.policy_path"
"""OPA policy path (e.g. 'trade_governance')"""

# ---------------------------------------------------------------------------
# 7. ISO 42001 Control Attributes (non-Langfuse namespaced)
# ---------------------------------------------------------------------------

SPAN_ATTR_ISO42001_CONTROL_ID = "iso42001.control_id"
"""ISO 42001 control identifier (alternative namespace)"""

# ---------------------------------------------------------------------------
# 8. Thread/Request Context Attributes
# ---------------------------------------------------------------------------

SPAN_ATTR_THREAD_ID = "thread.id"
"""Thread/conversation identifier"""

# ---------------------------------------------------------------------------
# 9. MCP (Model Context Protocol) Attributes
# ---------------------------------------------------------------------------

SPAN_ATTR_MCP_TOOL_RESULT_LENGTH = "mcp.tool.result_length"
"""MCP tool result length (characters)"""

# ---------------------------------------------------------------------------
# 10. AI Webhook Attributes (Langfuse score webhooks)
# ---------------------------------------------------------------------------

SPAN_ATTR_AI_WEBHOOK_LANGFUSE_SCORE_NAME = "ai.webhook.langfuse.score_name"
"""Langfuse score name from webhook"""

SPAN_ATTR_AI_WEBHOOK_LANGFUSE_SCORE_VALUE = "ai.webhook.langfuse.score_value"
"""Langfuse score value from webhook"""

SPAN_ATTR_AI_WEBHOOK_LANGFUSE_TRACE_ID = "ai.webhook.langfuse.trace_id"
"""Langfuse trace ID from webhook"""

SPAN_ATTR_AI_WEBHOOK_LANGFUSE_COOLDOWN_ACTIVE = "ai.webhook.langfuse.cooldown_active"
"""Boolean: is webhook cooldown active?"""

# ---------------------------------------------------------------------------
# Usage Examples (for documentation/testing)
# ---------------------------------------------------------------------------

# Example 1: Governance evaluation span
# with tracer.start_as_current_span("governance") as span:
#     span.set_attribute(SPAN_ATTR_OBSERVATION_TYPE, "span")
#     span.set_attribute(SPAN_ATTR_OBSERVATION_NAME, "governance_evaluation")
#     span.set_attribute(SPAN_ATTR_TRACE_METADATA_ISO_CONTROL_ID, "A.8.4")
#     span.set_attribute(SPAN_ATTR_CAGE_GOVERNANCE, True)

# Example 2: NeMo guardrails validation
# with tracer.start_as_current_span("nemo_input") as span:
#     span.set_attribute(SPAN_ATTR_OBSERVATION_TYPE, "span")
#     span.set_attribute(SPAN_ATTR_OBSERVATION_NAME, "nemo_input_verification")
#     span.set_attribute(SPAN_ATTR_TRACE_METADATA_GUARDRAILS_FRAMEWORK, "nemo")
#     span.set_attribute(
#         SPAN_ATTR_OBSERVATION_METADATA_STPA_HAZARD, "UCA-1_SEMANTIC_BYPASS"
#     )

# Example 3: OPA policy check
# with tracer.start_as_current_span("opa_check") as span:
#     span.set_attribute(SPAN_ATTR_OBSERVATION_TYPE, "span")
#     span.set_attribute(SPAN_ATTR_OBSERVATION_NAME, "opa_policy_check")
#     span.set_attribute(SPAN_ATTR_OPA_URL, "http://opa:8181")
#     span.set_attribute(SPAN_ATTR_TRACE_METADATA_GOVERNANCE_ACTION, "execute_trade")
