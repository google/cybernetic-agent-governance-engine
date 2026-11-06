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

"""CAGE Gateway Client SDK Envelope Types.

Defines the read-only, immutable Pydantic models that clients receive from the
governance gateway. ``CageClient`` cryptographically verifies ``GovernanceEnvelope``
responses by default against an out-of-band ``kid`` trust anchor (``JwksKeyResolver``
or pinned ``public_keys``), enforces ``expires_at`` freshness, and binds
``subject.action`` + ``subject.action_hash`` to the submitted request.

Note that channel TLS/mTLS (``transport.py``) protects only the point-to-point
transport hop and does NOT substitute for end-to-end ``GovernanceEnvelope.signature``
verification.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GovernanceEnvelope(BaseModel):
    """Read-only client view of a cryptographically signed governance decision envelope.

    Strictly immutable (``frozen=True``, ``extra="forbid"``).

    Security & Verification Scope:
        1. By default, ``CageClient`` verifies ``GovernanceEnvelope.signature``
           over RFC 8785 JCS canonical bytes against an out-of-band ``kid`` trust
           anchor (JWKS or pinned ``public_keys``), checks ``expires_at`` freshness,
           and validates ``subject.action`` + ``subject.action_hash`` request
           binding before returning ``ALLOW`` or dispatching ``NARROW`` / ``DENY`` /
           ``DEFER`` verdicts.
        2. Channel TLS/mTLS in ``transport.py`` protects only the point-to-point
           transport channel and does NOT substitute for end-to-end
           ``GovernanceEnvelope.signature`` verification.
    """

    envelope_version: str = Field(
        ..., pattern=r"^3\.\d+$", description="Envelope schema version (e.g., '3.0')"
    )
    envelope_type: str = Field(
        default="cage_governance_decision",
        description="Fixed type identifier for governance decision envelopes",
    )
    envelope_id: str | None = Field(
        default=None,
        description="Unique identifier for the governance envelope",
    )
    issued_at: datetime = Field(
        ..., description="UTC datetime when the envelope was issued"
    )
    expires_at: datetime = Field(
        ...,
        description="UTC datetime when the envelope expires (verified for freshness by CageClient)",
    )
    issuer: dict[str, str] = Field(
        ...,
        description="Gateway instance metadata (service, instance_id, region)",
    )
    subject: dict[str, str] = Field(
        ...,
        description="Governed action metadata (action, action_hash, record_hash, agent_id)",
    )
    governance_context: dict[str, Any] = Field(
        ...,
        description="Governance metadata (policy_version, tiers_passed, etc.)",
    )
    payload: dict[str, Any] = Field(
        ..., description="Decision payload (structure depends on decision type)"
    )
    external_attestations: list[dict[str, Any]] | None = Field(
        default=None,
        description="Optional external normative/attestation records",
    )
    signature: dict[str, str] | None = Field(
        default=None,
        description="Cryptographic signature (algorithm, kid, value) verified out-of-band by CageClient",
    )

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class ExecutionGrant(BaseModel):
    """Direct dispatch execution grant (JWT-style token)."""

    grant_version: str = Field(
        default="1.0", description="Execution grant schema version"
    )
    iss: str = Field(..., description="Issuer (gateway instance identifier)")
    sub: str = Field(..., description="Subject (authorized agent identifier)")
    aud: str = Field(..., description="Audience (target actuator/service)")
    exp: int = Field(..., description="Expiration time (Unix timestamp)")
    iat: int = Field(..., description="Issued-at time (Unix timestamp)")
    nonce: str = Field(..., description="Unique nonce (replay attack prevention)")
    action_hash: str = Field(
        ..., description="SHA256 hash of action parameters (integrity check)"
    )
    record_hash: str = Field(
        ..., description="SHA256 hash of audit record (governance trail link)"
    )
    signature: str = Field(..., description="Base64-encoded cryptographic signature")

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
