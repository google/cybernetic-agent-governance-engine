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
provider_06 — Agent Integrity Integration Adapter
=================================================

Integrates CAGE with Simran Pabla's Agent Integrity verification system
(https://github.com/SimranPabla/agent-integrity).

Agent Integrity provides deterministic verification of agent-authored
responses with a tri-state verdict model:

  - PASS    → Response may be released (maps to admitted=True)
  - BLOCKED → Response must not be released (maps to admitted=False)
  - REVIEW  → Human review required (maps to DEFER with EXTERNAL_VALIDATION)

This adapter follows the "Sidecar CLI" deployment pattern from the Agent
Integrity ARCHITECTURE.md: call the CLI as a subprocess and exchange JSON
over stdin/stdout to preserve the single implementation of verification rules.

Environment variables
---------------------
  CAGE_AGENT_INTEGRITY_ENDPOINT — Mock endpoint URL for spike testing
  CAGE_AGENT_INTEGRITY_PROJECT_ROOT — Path to trusted project root (optional)
  CAGE_AGENT_INTEGRITY_TIMEOUT — Per-request timeout in seconds (default: 10)

Status
------
**SPIKE** — Bounded to adapter + mock endpoint per Simran's guidance.
"""

from src.integrations.provider_06.adapter import (
    IntegrityFinding,
    IntegrityResult,
    IntegrityStatus,
    Provider06AgentIntegrityAdapter,
)

__all__ = [
    "IntegrityFinding",
    "IntegrityResult",
    "IntegrityStatus",
    "Provider06AgentIntegrityAdapter",
]
