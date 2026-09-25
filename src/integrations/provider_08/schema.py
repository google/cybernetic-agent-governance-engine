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
provider_08 Wire Protocol Schema Models (Verdict Runtime Evidence Provider)

Strict Pydantic v2 models for the three Verdict endpoints behind the
``NormativeProvider`` seam. Unknown decisions fail validation, which the
adapter maps to a fail-closed ``PARSE_ERROR`` finding.

See: docs/partners/provider_08/VERDICT_PARTNER_SPECIFICATION.md
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class VerdictFinding(BaseModel):
    """One structural finding from the Verdict FRIA gate (OSCAL vocabulary)."""

    model_config = ConfigDict(extra="ignore")

    code: str
    status: Literal["pass", "fail", "not_applicable", "error"]
    severity: Literal["info", "review", "blocked"]
    message: str
    control_id: str | None = None
    reference: str | None = None


class VerdictFriaResponse(BaseModel):
    """``POST /validate/fria`` response."""

    model_config = ConfigDict(extra="ignore")

    decision: Literal["ALLOW", "REFUSE", "ESCALATE"]
    admitted: bool
    message: str = ""
    findings: list[VerdictFinding] = Field(default_factory=list)
    region: str
    authority_record_id: str
    authority_state_version: str
    validation_hash: str
    validated_at: str
    hold_ttl_seconds: int | None = None
    provider: str = "verdict.systems"


class VerdictBaselineResponse(BaseModel):
    """``GET /legal-baseline/{region}`` response."""

    model_config = ConfigDict(extra="ignore")

    region: str
    profile: dict[str, Any]
    profile_sha256: str
    authority_state_version: str = ""
    schema_version: str = ""
    issued_at: str = ""
    provider: str = "verdict.systems"


class VerdictEvidenceSealResponse(BaseModel):
    """``GET|POST /evidence-chain/{thread_id}`` response."""

    model_config = ConfigDict(extra="ignore")

    thread_id: str
    evidence_hash: str
    seal_hash: str
    seal_status: str
    timestamp: float
    sealed_at: str = ""
    evidence_record_id: str = ""
    payload_hash: str = ""
    transparency_anchor: dict[str, Any] | None = None
    verify_url: str | None = None
    provider: str = "verdict.systems"
