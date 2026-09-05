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

"""attributes.py — Centralized Telemetry Attribute Keys.

Declares type-safe constants for OpenTelemetry span attributes and trace/observation
metadata used across CAGE.

Architecture & Design Rationale (Wave 1, Task W1.6 / AW-6):
  - Vendor namespace decoupling: Declares the telemetry vendor prefix in exactly
    one place, driven by the ``CAGE_TELEMETRY_ATTR_NAMESPACE`` environment variable
    (default: "langfuse").
  - Zero hot-path overhead: Uses module-level ``Final[str]`` constants rather than
    dataclasses or function calls on static lookup paths.
  - Dynamic key helpers: Provides ``metadata(key)`` and ``observation_metadata(key)``
    for runtime-parameterized attribute naming.
  - Wire-format stability: When using default namespace ("langfuse"), all emitted
    attribute keys remain 100% byte-identical to historical string literals to
    preserve hash-chain and evidence audit trail verifiability (§0 invariant).
"""

from __future__ import annotations

import os
from typing import Final

# ---------------------------------------------------------------------------
# Namespace resolution
# ---------------------------------------------------------------------------

NAMESPACE: Final[str] = (
    os.environ.get("CAGE_TELEMETRY_ATTR_NAMESPACE", "langfuse").strip() or "langfuse"
)


def metadata(key: str) -> str:
    """Format a trace metadata key within the active telemetry namespace.

    Example:
        metadata("governance.action") -> "langfuse.trace.metadata.governance.action"
    """
    return f"{NAMESPACE}.trace.metadata.{key}"


def observation_metadata(key: str) -> str:
    """Format an observation metadata key within the active telemetry namespace.

    Example:
        observation_metadata("iso_control") -> "langfuse.observation.metadata.iso_control"
    """
    return f"{NAMESPACE}.observation.metadata.{key}"


# ---------------------------------------------------------------------------
# 1. Observation Attributes (Observation-level metadata)
# ---------------------------------------------------------------------------

OBSERVATION_TYPE: Final[str] = f"{NAMESPACE}.observation.type"
"""Observation type: 'span', 'generation', 'event'"""

OBSERVATION_NAME: Final[str] = f"{NAMESPACE}.observation.name"
"""Human-readable observation name (e.g. 'governance_evaluation', 'opa_policy_check')"""

OBSERVATION_INPUT: Final[str] = f"{NAMESPACE}.observation.input"
"""Input payload for the observation (typically JSON string or message text)"""

OBSERVATION_OUTPUT: Final[str] = f"{NAMESPACE}.observation.output"
"""Output payload for the observation (typically JSON string, verdict, or completion)"""

OBSERVATION_MODEL_NAME: Final[str] = f"{NAMESPACE}.observation.model.name"
"""Model name/identifier (e.g. 'gemini-1.5-pro', 'llama-3-70b')"""

OBSERVATION_METADATA_PREFIX: Final[str] = f"{NAMESPACE}.observation.metadata."
"""Prefix for observation-level metadata"""

OBSERVATION_METADATA_STPA_HAZARD: Final[str] = (
    f"{NAMESPACE}.observation.metadata.stpa_hazard"
)
"""STPA hazard identifier (e.g. 'UCA-1_SEMANTIC_BYPASS')"""

OBSERVATION_METADATA_ISO_CONTROL: Final[str] = (
    f"{NAMESPACE}.observation.metadata.iso_control"
)
"""ISO 42001 control identifier (e.g. 'A.5.2', 'A.8.4')"""

OBSERVATION_METADATA_FALLBACK_REASON: Final[str] = (
    f"{NAMESPACE}.observation.metadata.fallback_reason"
)
"""Reason for fallback behavior (e.g. 'NeMo_config_parse_failed')"""

OBSERVATION_METADATA_GOVERNANCE_STATE: Final[str] = (
    f"{NAMESPACE}.observation.metadata.governance_state"
)
"""Governance state (e.g. 'CIRCUIT_OPEN_REJECTED', 'DEGRADED_FAIL_OPEN')"""


# ---------------------------------------------------------------------------
# 2. Trace & Session Attributes
# ---------------------------------------------------------------------------

SESSION_ID: Final[str] = f"{NAMESPACE}.session.id"
"""Session identifier for grouping interactions"""

TRACE_TAGS: Final[str] = f"{NAMESPACE}.trace.tags"
"""Trace tags (JSON array of strings, e.g. '[\"iso-42001\", \"control:A.5.3\"]')"""

TRACE_METADATA_PREFIX: Final[str] = f"{NAMESPACE}.trace.metadata."
"""Prefix for trace-level metadata"""


# ---------------------------------------------------------------------------
# 3. ISO 42001 Compliance Control Attributes
# ---------------------------------------------------------------------------

TRACE_METADATA_ISO_CONTROL_ID: Final[str] = f"{NAMESPACE}.trace.metadata.iso.control_id"
"""ISO 42001 primary control ID (e.g. 'A.10.1', 'A.8.4')"""

TRACE_METADATA_ISO_CONTROL_ID_SECONDARY: Final[str] = (
    f"{NAMESPACE}.trace.metadata.iso.control_id_secondary"
)
"""ISO 42001 secondary control ID for multi-control compliance"""

TRACE_METADATA_ISO_REQUIREMENT: Final[str] = (
    f"{NAMESPACE}.trace.metadata.iso.requirement"
)
"""ISO 42001 control requirement description"""

TRACE_METADATA_ISO_REQUIREMENT_SECONDARY: Final[str] = (
    f"{NAMESPACE}.trace.metadata.iso.requirement_secondary"
)
"""ISO 42001 secondary requirement description"""


# ---------------------------------------------------------------------------
# 4. Governance & Policy Attributes
# ---------------------------------------------------------------------------

TRACE_METADATA_GOVERNANCE_OPA_URL: Final[str] = (
    f"{NAMESPACE}.trace.metadata.governance.opa_url"
)
"""OPA policy server URL"""

TRACE_METADATA_GOVERNANCE_ACTION: Final[str] = (
    f"{NAMESPACE}.trace.metadata.governance.action"
)
"""Governance action being evaluated (e.g. 'execute_trade', 'prescribe')"""

TRACE_METADATA_GOVERNANCE_POLICY_INPUT_SIZE: Final[str] = (
    f"{NAMESPACE}.trace.metadata.governance.policy_input_size"
)
"""Size of OPA policy input payload (bytes)"""

TRACE_METADATA_GOVERNANCE_DECISION: Final[str] = (
    f"{NAMESPACE}.trace.metadata.governance.decision"
)
"""Final governance decision (ALLOW, DENY, DEFER, etc.)"""

TRACE_METADATA_GOVERNANCE_DENIAL_REASON: Final[str] = (
    f"{NAMESPACE}.trace.metadata.governance.denial_reason"
)
"""Reason for denial verdict"""

TRACE_METADATA_RISK_VERDICT: Final[str] = f"{NAMESPACE}.trace.metadata.risk.verdict"
"""Risk verdict (SAFE, UNSAFE, etc.)"""

TRACE_METADATA_CONSENSUS_DECISION: Final[str] = (
    f"{NAMESPACE}.trace.metadata.consensus.decision"
)
"""Consensus decision (APPROVE, REJECT, etc.)"""

TRACE_METADATA_CONSENSUS_VOTES: Final[str] = (
    f"{NAMESPACE}.trace.metadata.consensus.votes"
)
"""Consensus vote breakdown (JSON string)"""

TRACE_METADATA_CURRENT_NODE: Final[str] = f"{NAMESPACE}.trace.metadata.current_node"
"""Current LangGraph node name"""

TRACE_METADATA_MCP_SERVER: Final[str] = f"{NAMESPACE}.trace.metadata.mcp_server"
"""MCP server identifier"""

TRACE_METADATA_LATENCY_CURRENCY_TAX: Final[str] = (
    f"{NAMESPACE}.trace.metadata.latency_currency_tax"
)
"""Governance overhead latency (milliseconds)"""

TRACE_METADATA_POAM_REF: Final[str] = f"{NAMESPACE}.trace.metadata.poam_ref"
"""POAM finding reference (e.g. 'AI600-005')"""


# ---------------------------------------------------------------------------
# 5. Guardrails Metadata Attributes
# ---------------------------------------------------------------------------

TRACE_METADATA_GUARDRAIL_ID: Final[str] = f"{NAMESPACE}.trace.metadata.guardrail.id"
"""Guardrail identifier (NeMo action name)"""

TRACE_METADATA_GUARDRAIL_ACTION: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrail.action"
)
"""Guardrail action name"""

TRACE_METADATA_GUARDRAIL_OUTCOME: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrail.outcome"
)
"""Guardrail outcome (BLOCKED, APPROVED, etc.)"""

TRACE_METADATA_GUARDRAIL_BLOCK_REASON: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrail.block_reason"
)
"""Reason for guardrail block"""

TRACE_METADATA_GUARDRAILS_OUTCOME: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrails.outcome"
)
"""Guardrail outcome plural form (BLOCKED, APPROVED, etc.)"""

TRACE_METADATA_GUARDRAILS_FRAMEWORK: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrails.framework"
)
"""Guardrails framework name (e.g. 'nemo')"""

TRACE_METADATA_GUARDRAILS_INPUT_LENGTH: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrails.input_length"
)
"""Input text length (characters)"""

TRACE_METADATA_GUARDRAILS_INTERVENED: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrails.intervened"
)
"""Boolean: did guardrails intervene?"""

TRACE_METADATA_GUARDRAILS_INTERVENTION: Final[str] = (
    f"{NAMESPACE}.trace.metadata.guardrails.intervention"
)
"""Guardrails intervention type (e.g. 'fallback')"""


# ---------------------------------------------------------------------------
# 6. Webhook Attributes
# ---------------------------------------------------------------------------

WEBHOOK_THRESHOLD_BREACH: Final[str] = f"{NAMESPACE}.webhook.threshold_breach"
"""Webhook threshold breach event name"""

AI_WEBHOOK_SCORE_NAME: Final[str] = f"ai.webhook.{NAMESPACE}.score_name"
"""Webhook score name"""

AI_WEBHOOK_SCORE_VALUE: Final[str] = f"ai.webhook.{NAMESPACE}.score_value"
"""Webhook score value"""

AI_WEBHOOK_TRACE_ID: Final[str] = f"ai.webhook.{NAMESPACE}.trace_id"
"""Webhook trace ID"""

AI_WEBHOOK_COOLDOWN_ACTIVE: Final[str] = f"ai.webhook.{NAMESPACE}.cooldown_active"
"""Boolean: is webhook cooldown active?"""

AI_WEBHOOK_COOLDOWN_SECONDS_REMAINING: Final[str] = (
    f"ai.webhook.{NAMESPACE}.cooldown_seconds_remaining"
)
"""Remaining seconds in webhook cooldown"""


# ---------------------------------------------------------------------------
# 7. CAGE-Specific Attributes (Non-vendor namespaced)
# ---------------------------------------------------------------------------

SPAN_ATTR_CAGE_GOVERNANCE: Final[str] = "cage.governance"
"""Boolean: is this span governance-related?"""

SPAN_ATTR_CAGE_VERDICT: Final[str] = "cage.verdict"
"""CAGE governance verdict (ALLOW, DENY, etc.)"""

SPAN_ATTR_CAGE_SEAL_ISSUED: Final[str] = "cage.seal_issued"
"""Boolean: was a routing seal issued?"""

SPAN_ATTR_GOVERNANCE_STAGE: Final[str] = "governance.stage"
"""Governance evaluation stage (e.g. 'ftra_boundary', 'tier2_corroboration')"""

SPAN_ATTR_GOVERNANCE_TOOL: Final[str] = "governance.tool"
"""Tool name being governed"""

SPAN_ATTR_GOVERNANCE_BLOCKED: Final[str] = "governance.blocked"
"""Boolean: was action blocked?"""

SPAN_ATTR_GOVERNANCE_REASON: Final[str] = "governance.reason"
"""Denial/approval reason"""


# ---------------------------------------------------------------------------
# 8. Gen AI Semantic Conventions (OpenTelemetry standard)
# ---------------------------------------------------------------------------

SPAN_ATTR_GEN_AI_OPERATION_NAME: Final[str] = "gen_ai.operation.name"
"""Gen AI operation name (e.g. 'chat', 'tool_call', 'embedding')"""

SPAN_ATTR_GEN_AI_SYSTEM: Final[str] = "gen_ai.system"
"""Gen AI system identifier (e.g. 'financial-advisor-gateway', 'nemo-guardrails')"""

SPAN_ATTR_GEN_AI_REQUEST_MODEL: Final[str] = "gen_ai.request.model"
"""Requested model name"""


# ---------------------------------------------------------------------------
# 9. HITL, OPA, ISO 42001, Thread, and MCP Attributes
# ---------------------------------------------------------------------------

SPAN_ATTR_HITL_REGULATORY_CITATION: Final[str] = "hitl.regulatory_citation"
"""Regulatory citation for HITL escalation"""

SPAN_ATTR_OPA_URL: Final[str] = "opa.url"
"""OPA server URL"""

SPAN_ATTR_OPA_POLICY_PATH: Final[str] = "opa.policy_path"
"""OPA policy path (e.g. 'trade_governance')"""

SPAN_ATTR_ISO42001_CONTROL_ID: Final[str] = "iso42001.control_id"
"""ISO 42001 control identifier (alternative namespace)"""

SPAN_ATTR_THREAD_ID: Final[str] = "thread.id"
"""Thread/conversation identifier"""

SPAN_ATTR_MCP_TOOL_RESULT_LENGTH: Final[str] = "mcp.tool.result_length"
"""MCP tool result length (characters)"""
