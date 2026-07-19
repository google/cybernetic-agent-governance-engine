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

# Agent Catalog OPA Policy — Work Stream F (Phase B)
# ====================================================
# Enforces per-agent tool authorization using caller identity from OIDC JWT
# or mTLS SPIFFE ID (injected by the OIDC middleware or AgentGatewayAdapter).
#
# This policy is evaluated as part of the existing OPA policy bundle.
# No changes to the OPA client or evaluation pipeline are required.
#
# Input schema (additive — existing policies unaffected):
#   input.caller_identity.sub  — OIDC sub claim or SPIFFE ID
#   input.tool_name            — tool name from the JSON-RPC body
#
# Data document: config/agent_catalog.json (loaded as data.agent_catalog_data)
#
# Compliance: AC-3 (Access Enforcement)
# Change category: Cat-N (Normal) — new OPA policy, no new infrastructure

package agent_catalog

import future.keywords.in

# ---------------------------------------------------------------------------
# allow — true if caller is in the approved catalog AND tool is permitted
# ---------------------------------------------------------------------------

# Allow if: caller is in approved_agents AND tool is in caller's allowed_tools
allow if {
    agent := approved_agents[input.caller_identity.sub]
    input.tool_name in agent.allowed_tools
}

# ---------------------------------------------------------------------------
# violation — set of human-readable denial reasons
# ---------------------------------------------------------------------------

# Deny with reason if caller is not in approved_agents
violation contains msg if {
    not approved_agents[input.caller_identity.sub]
    msg := sprintf(
        "caller '%v' is not in the approved agent catalog",
        [input.caller_identity.sub],
    )
}

# Deny with reason if tool is not in caller's allowed_tools
violation contains msg if {
    agent := approved_agents[input.caller_identity.sub]
    not input.tool_name in agent.allowed_tools
    msg := sprintf(
        "caller '%v' is not authorized to call tool '%v'",
        [input.caller_identity.sub, input.tool_name],
    )
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

# If caller_identity is absent (OIDC middleware not configured), the catalog
# policy is a no-op — existing deployments without OIDC are unaffected.
# When OIDC is configured, caller_identity.sub is always present.
caller_sub_present if {
    input.caller_identity.sub != ""
}

# Override allow to false when caller_identity is absent and catalog is non-empty
# (defense-in-depth: if catalog has entries, require identity)
allow if {
    not caller_sub_present
    count(approved_agents) == 0
}
