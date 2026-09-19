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
provider_08 — Verdict Runtime Evidence Normative Provider (Layer 3)
====================================================================

Synchronous ``NormativeProvider`` adapter for Verdict Systems, an external
runtime-evidence layer that holds sealed governance records outside the
system that produced them and anchors each record commitment to the Sigstore
Rekor transparency log.

Public Exports:
- ``Provider08NormativeProvider`` — the adapter (``from_env()`` for config)
- Pydantic v2 wire models for the three Verdict endpoints
"""

from .adapter import (
    FINDING_CODE_ANCHOR_DEFERRED,
    FINDING_CODE_ENDPOINT_ERROR,
    FINDING_CODE_EXTERNAL_HOLD,
    FINDING_CODE_PARSE_ERROR,
    FINDING_CODE_REFUSE,
    Provider08NormativeProvider,
)
from .schema import (
    VerdictBaselineResponse,
    VerdictEvidenceSealResponse,
    VerdictFinding,
    VerdictFriaResponse,
)

__all__ = [
    "FINDING_CODE_ANCHOR_DEFERRED",
    "FINDING_CODE_ENDPOINT_ERROR",
    "FINDING_CODE_EXTERNAL_HOLD",
    "FINDING_CODE_PARSE_ERROR",
    "FINDING_CODE_REFUSE",
    "Provider08NormativeProvider",
    "VerdictBaselineResponse",
    "VerdictEvidenceSealResponse",
    "VerdictFinding",
    "VerdictFriaResponse",
]
