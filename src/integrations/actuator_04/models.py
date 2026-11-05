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

"""Wire data transfer models and validation schemas for actuator_04 seams."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.gateway.governance.seams.digests import require_sha256_hex
from src.integrations.actuator_04.constants import (
    ALLOWED_OCSF_CLASS_UIDS,
    MAX_OCSF_METADATA_BYTES,
)


@dataclass(frozen=True)
class HostQuarantineReceiptPayload:
    """Parsed substrate response payload from POST /v1/cage/quarantine."""

    status: str
    quarantined: bool
    enforcement_plane: str
    rule_id: str
    quarantined_at: str
    envelope_digest: str
    kid: str
    signature: str
    target_pid: int | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HostQuarantineReleaseReceiptPayload:
    """Parsed substrate response payload from POST /v1/cage/release."""

    status: str
    released: bool
    enforcement_plane: str
    epoch_before: int
    epoch_after: int
    released_at: str
    envelope_digest: str
    kid: str
    signature: str
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HostAttestationPayload:
    """Parsed substrate response payload from GET /v1/cage/attest."""

    attestation_type: str
    ring0_posture: str
    tpm_pcr_quote: str
    pcr_values: dict[str, str]
    timestamp_utc: str
    kid: str
    signature: str
    epoch_map: dict[str, int] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConformalValidationResponsePayload:
    """Parsed response payload from POST /v1/cage/conformal/validate."""

    admitted: bool
    nonconformity_score: float
    p_value: float
    alpha: float
    voter_consensus: str
    findings: list[dict[str, Any]]
    sealed_at: float
    kid: str
    signature: str
    raw_response: dict[str, Any] = field(default_factory=dict)


class OcsfEventModel(BaseModel):
    """Pydantic validator for incoming signed OCSF telemetry events."""

    model_config = ConfigDict(hide_input_in_errors=True)

    class_uid: int
    category_uid: int = Field(default=1, ge=0)
    severity_id: int = Field(default=1, ge=0, le=6)
    activity_id: int = Field(default=1, ge=0)
    action: str = Field(default="observed", min_length=1, max_length=64)
    disposition: str = Field(default="Allowed", min_length=1, max_length=64)
    sandbox_id: str = Field(min_length=1, max_length=128)
    thread_id: str = Field(min_length=1, max_length=128)
    governance_decision_digest: str
    agent_svid: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    kid: str | None = None
    signature: str | None = None

    @field_validator("class_uid")
    @classmethod
    def _v_class_uid(cls, v: int) -> int:
        if v not in ALLOWED_OCSF_CLASS_UIDS:
            raise ValueError(
                f"Unsupported OCSF class_uid={v}; expected one of {sorted(ALLOWED_OCSF_CLASS_UIDS)}"
            )
        return v

    @field_validator("governance_decision_digest")
    @classmethod
    def _v_decision_digest(cls, v: str) -> str:
        return require_sha256_hex(v, field="governance_decision_digest")

    @field_validator("metadata")
    @classmethod
    def _v_metadata_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json

        serialized = json.dumps(v, default=str).encode("utf-8")
        if len(serialized) > MAX_OCSF_METADATA_BYTES:
            raise ValueError(
                f"OCSF metadata is {len(serialized)} bytes; limit {MAX_OCSF_METADATA_BYTES}"
            )
        return v
