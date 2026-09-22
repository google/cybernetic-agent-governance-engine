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

# Agent Catalog OPA Policy — Work Stream F (Phase B) + A2A Authorization
# =========================================================================
# Enforces per-agent tool authorization using caller identity from OIDC JWT
# or mTLS SPIFFE ID (injected by the OIDC middleware or AgentGatewayAdapter).
#
# **Phase 2: Agent-to-Agent (A2A) Authorization with SPIFFE Namespace Prefix Matching**
# When a parent agent invokes a subagent, the parent's SPIFFE ID is evaluated
# against the subagent's `authorized_parent_prefixes` using prefix matching.
# This enables hierarchical trust delegation without enumerating every parent SPIFFE ID.
#
# Example:
#   Parent SPIFFE ID: spiffe://cluster.local/ns/agents/sa/orchestrator
#   Subagent authorized_parent_prefixes: ["spiffe://cluster.local/ns/agents/"]
#   → Authorization succeeds (prefix match)
#
# This policy is evaluated as part of the existing OPA policy bundle.
# No changes to the OPA client or evaluation pipeline are required.
#
# Input schema (additive — existing policies unaffected):
#   input.caller_identity.sub  — OIDC sub claim or SPIFFE ID
#   input.tool_name            — tool name from the JSON-RPC body
#   input.subagent_id          — (optional) target subagent SPIFFE ID for A2A calls
#
# Data document: config/agent_catalog.json (loaded as data.agent_catalog_data)
#
# Compliance: AC-3 (Access Enforcement), IA-2 (Identification and Authentication), IA-3 (Device Identification)
# Change category: Cat-M (Major) — breaking change, removes anonymous fallback

package agent_catalog

import future.keywords.in

# ---------------------------------------------------------------------------
# allow — true if caller is in the approved catalog AND tool is permitted
# ---------------------------------------------------------------------------

# Allow if: caller is in approved_agents AND tool is in caller's allowed_tools
allow {
    agent := approved_agents[input.caller_identity.sub]
    input.tool_name in agent.allowed_tools
}

# Allow A2A invocation if parent SPIFFE ID matches subagent's authorized prefix
allow {
    input.subagent_id
    subagent := approved_agents[input.subagent_id]
    parent_spiffe := input.caller_identity.sub
    _parent_authorized_for_subagent(parent_spiffe, subagent)
}

# ---------------------------------------------------------------------------
# violation — set of human-readable denial reasons
# ---------------------------------------------------------------------------

# Deny with reason if caller is not in approved_agents
violation[msg] {
    not approved_agents[input.caller_identity.sub]
    msg := sprintf(
        "caller '%v' is not in the approved agent catalog",
        [input.caller_identity.sub],
    )
}

# Deny with reason if tool is not in caller's allowed_tools
violation[msg] {
    agent := approved_agents[input.caller_identity.sub]
    not input.tool_name in agent.allowed_tools
    not input.subagent_id  # not an A2A call
    msg := sprintf(
        "caller '%v' is not authorized to call tool '%v'",
        [input.caller_identity.sub, input.tool_name],
    )
}

# Deny A2A invocation if parent SPIFFE ID does not match any authorized prefix
violation[msg] {
    input.subagent_id
    subagent := approved_agents[input.subagent_id]
    parent_spiffe := input.caller_identity.sub
    not _parent_authorized_for_subagent(parent_spiffe, subagent)
    msg := sprintf(
        "parent agent '%v' is not authorized to invoke subagent '%v' (no matching SPIFFE prefix)",
        [parent_spiffe, input.subagent_id],
    )
}

# ---------------------------------------------------------------------------
# Helper rules
# ---------------------------------------------------------------------------

# _parent_authorized_for_subagent: true if parent SPIFFE ID matches any authorized prefix
_parent_authorized_for_subagent(parent_spiffe, subagent) {
    # Get authorized_parent_prefixes from subagent (default to empty array if not present)
    authorized_prefixes := object.get(subagent, "authorized_parent_prefixes", [])
    
    # Check if parent_spiffe starts with any of the authorized prefixes
    some prefix in authorized_prefixes
    startswith(parent_spiffe, prefix)
}

# ---------------------------------------------------------------------------
# approved_agents — loaded from config/agent_catalog.json
# ---------------------------------------------------------------------------

# Data loaded from config/agent_catalog.json via OPA data document.
# The catalog is loaded at OPA startup and reloaded on bundle update.
# It is never modified directly in production — changes go through PR + CI.
approved_agents := data.agent_catalog_data.agents

# ---------------------------------------------------------------------------
# caller_sub_present — guard for missing caller_identity
# ---------------------------------------------------------------------------

# BREAKING CHANGE: Removed anonymous fallback.
# All requests MUST provide a verified SPIFFE URI via mTLS client certificate.
# Unauthenticated requests will fail closed with 401/403.
#
# If caller_identity.sub is empty, the request is denied (no allow rule matches).
caller_sub_present {
    input.caller_identity.sub != ""
}
