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

"""Deterministic OpenAI-compatible inference stub (Layer 3, POAM-2026-191).

Used exclusively in opt-in E2E conformance suites and non-production staging
verification (``enable_e2e_advisor = true`` / ``CAGE_INFERENCE_BACKEND=stub``)
to exercise the governed advisor -> gateway inference proxy -> MCP governance
loop without GPU hardware.

Scenario dispatch is strictly decoupled from raw request digests (``F-36``):
volatile ``timestamp_utc`` strings, trace IDs, and message IDs are stripped
before extracting canonical scenario markers and declared ``tools``.
"""

from __future__ import annotations

from src.integrations.inference_stub.scenarios import (
    ResolvedScenario,
    StubTurnDecision,
    normalize_intent_text,
    resolve_chat_completion,
    resolve_scenario,
)
from src.integrations.inference_stub.server import create_stub_app

__all__ = [
    "ResolvedScenario",
    "StubTurnDecision",
    "create_stub_app",
    "normalize_intent_text",
    "resolve_chat_completion",
    "resolve_scenario",
]
