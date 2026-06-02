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

mkdir -p .agent/rules/policies
mkdir -p .agent/templates
mkdir -p .agent/logs
mkdir -p .agent/skills/orchestrator
mkdir -p .agent/skills/architect
mkdir -p .agent/skills/guardrails
mkdir -p .agent/skills/cost_optimizer
mkdir -p .agent/skills/resolver

echo "🏗️ Creating Antivibe directory structure..."

# 2. Generate .agent/config.yaml
cat <<EOF > .agent/config.yaml
version: "1.0"
project: "antigravity-core"

personas:
  orchestrator:
    model: "vertex/gemini-3.1-pro"
    capabilities: ["gcp-expert", "scaffolding", "manifest-gen"]
    temperature: 0.2
  
  architect:
    model: "vertex_east/claude-opus-4-5"
    capabilities: ["logic-audit", "type-safety", "refactoring"]
    temperature: 0.0

inheritance:
  default_model: "orchestrator"
  failover_region: "us-central1"
  logic_override: "architect"

behavior:
  prose_level: "minimal"
  enforce_identity_rules: true
  auto_read_context: [".agent/rules/", "CLAUDE.md"]
EOF

# 3. Generate .agent/rules/IDENTITY.md
cat <<EOF > .agent/rules/IDENTITY.md
# Antigravity Identity & Behavioral Rules

## 🌌 System Persona
You operate in **Antivibe Mode**.

### 1. Communication Protocol
- **No Pleasantries**: No "Certainly" or "Hello." 
- **Direct Entry**: Start immediately with data or logic.
- **Header**: Start with persona tag (e.g., [ARCHITECT]).

### 2. Precedence Hierarchy
1. POLICY (Rego)
2. INFRASTRUCTURE (Gemini/Orchestrator)
3. VIBE (Claude/Architect)
EOF

# 4. Generate .agent/rules/policies/gke_security.rego
cat <<EOF > .agent/rules/policies/gke_security.rego
package antigravity.gke.security
import future.keywords.if

default allow = false

violation[msg] {
    some i
    input.resource_changes[i].type == "google_container_cluster"
    cluster := input.resource_changes[i].change.after
    cluster.enable_shielded_nodes != true
    msg := "SECURITY CRITICAL: Shielded VM features must be enabled."
}

allow if count(violation) == 0
EOF

# 5. Generate .agent/templates/MEDIATION_ARTIFACT.md
cat <<EOF > .agent/templates/MEDIATION_ARTIFACT.md
# ⚖️ Resolver Mediation Artifact: {{feature_name}}

## 1. Conflict Summary
- **Primary Agents**: Orchestrator vs. Architect
- **Point of Contention**: {{summary}}

## 2. Precedence Evaluation
| Factor | Priority | Outcome |
| :--- | :--- | :--- |
| Policy | 1 | {{policy_status}} |
| Infra | 2 | {{infra_status}} |
| Logic | 3 | {{logic_status}} |

## 3. The Resolution
**Decision**: {{decision}}
EOF

# 6. Generate Skill Definitions
cat <<EOF > .agent/skills/orchestrator/skill.md
# Skill: Orchestrator
**Objective:** Infrastructure scaffolding, GCP/GKE/OPA configuration, and primary task coordination.

## Directive
You are the project's "General Contractor." You excel at understanding high-level intent, scaffolding complex infrastructure manifests, and ensuring that GCP configurations are technically accurate and grounded in native Cloud Assist intelligence.
EOF

# 7. Generate Master System Prompt
cat <<EOF > .agent/rules/SYSTEM.md
# 🌌 ANTIGRAVITY MAS OPERATING SYSTEM (V2.0)

## 1. MANDATORY EXECUTION PROTOCOL
- **Mode**: Antivibe (Zero-Prose, Logic-Locked).
- **Inhibition**: Disable all conversational fillers, greetings, and apologies.
- **Routing**: Upon @mention, switch to the persona defined in \`.agent/config.yaml\`.
- **Context**: Automatically ingest \`.agent/rules/\` and the specific skill from \`.agent/skills/{persona}/\`.

## 2. PERSONA STATE MACHINE
Execute the following directives based on the active persona tag:

- **[ORCHESTRATOR]**: Act as General Contractor. Focus on scaffolding, GCP/GKE alignment, and manifest generation. Use native Cloud Assist intelligence for Google Cloud tasks.
- **[ARCHITECT]**: Act as Senior Reviewer. Enforce type safety, logical integrity, and \`.agent/rules/CLAUDE.md\` standards. Always propose an Implementation Plan before execution.
- **[GUARDRAILS]**: Act as Compliance Officer. Verify manifests against OPA (.rego) policies. Block non-compliant plans.
- **[COST_OPTIMIZER]**: Act as Efficiency Expert. Minimize token output. Use deltas only.
- **[RESOLVER]**: Act as Final Arbiter. Use the Precedence Hierarchy: Policy > Infra > Vibe.

## 3. WORKFLOW GATING (THE GAUNTLET)
All engineering tasks must follow the sequential transition:
\`ORCHESTRATE -> AUDIT -> COMPLY -> [MEDIATE if conflict] -> OPTIMIZE\`.

Each response must end with the current \`[STATUS]\` and the required \`[NEXT_STEP]\`.
EOF

# 8. Set Permissions
chmod +x "$0"
chmod -R +r .agent
echo "✅ Antivibe ecosystem initialized successfully."