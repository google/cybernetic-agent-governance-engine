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
CAGE Gateway Client SDK Envelope Types.

This module defines the read-only, immutable Pydantic models representing
decision envelope payloads returned by the governance gateway. Note that
``CageClient`` performs Pydantic schema validation only — it does NOT verify
``signature`` against a gateway trust anchor and does NOT enforce ``expires_at``
temporal freshness client-side.

Clients parse these envelopes but NEVER construct or modify them. All envelopes
are frozen (immutable) to prevent accidental in-memory mutation after parsing.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GovernanceEnvelope(BaseModel):
    """
    Read-only client schema view of a governance decision envelope.

    This model parses the decision payload, audit metadata, ``expires_at``, and
    ``signature`` fields returned by the gateway for a proposed action.

    Security & Verification Scope (IMPORTANT):
        1. ``CageClient`` currently performs Pydantic schema validation and
           fail-closed HTTP status and payload verdict mediation
           (``200``/``403``/``422``/``202``/``409``/``5xx``) only —
           **it does NOT verify ``GovernanceEnvelope.signature`` against a
           gateway trust anchor and does NOT check ``GovernanceEnvelope.expires_at``
           freshness client-side**. Both ``signature`` and ``expires_at`` are
           parsed as **untrusted** fields unless verified separately against an
           independently resolved out-of-band ``kid`` trust anchor.
        2. **TLS/mTLS in ``transport.py`` protects only the point-to-point
           transport channel and does NOT substitute for end-to-end envelope
           signature verification.** The envelope carries a ``signature`` field
           specifically so trust does not rest solely on transport or proxy
           configuration; callers requiring cryptographic non-repudiation or
           replay/freshness enforcement must verify the signature and
           ``expires_at`` independently.

    The envelope is strictly immutable (``frozen=True``). Clients parse envelopes
    received from the gateway but NEVER construct or modify them. Any attempt
    to modify an envelope after creation will raise a ``ValidationError``.
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
        description=(
            "UTC datetime when the envelope expires "
            "(parsed as schema data; not checked for freshness by CageClient)"
        ),
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
        description=(
            "Signature metadata (algorithm, value, kid); "
            "unverified unless checked separately against a gateway trust anchor"
        ),
    )

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class ExecutionGrant(BaseModel):
    """
    Read-only Pydantic schema model for a JWT-style execution grant payload.

    Security Note:
        ``packages/cage-client/`` currently provides schema parsing only for
        ``ExecutionGrant`` — it does NOT verify ``signature`` against a gateway
        trust anchor, does NOT check ``exp`` temporal freshness, and does NOT
        consume ``nonce`` client-side. Downstream actuators or callers MUST
        cryptographically verify the grant against an out-of-band trust anchor
        and enforce expiration/single-use semantics before executing any action.

    Like ``GovernanceEnvelope``, this model is strictly immutable (``frozen=True``).
    """

    grant_version: str = Field(
        default="1.0", description="Execution grant schema version"
    )
    iss: str = Field(..., description="Issuer (gateway instance identifier)")
    sub: str = Field(..., description="Subject (authorized agent identifier)")
    aud: str = Field(..., description="Audience (target actuator/service)")
    exp: int = Field(
        ...,
        description="Expiration time (Unix timestamp; unverified client-side)",
    )
    iat: int = Field(..., description="Issued-at time (Unix timestamp)")
    nonce: str = Field(..., description="Unique nonce claim")
    action_hash: str = Field(
        ..., description="SHA256 hash of action parameters (integrity claim)"
    )
    record_hash: str = Field(
        ..., description="SHA256 hash of audit record (governance trail link)"
    )
    signature: str = Field(
        ...,
        description="Base64-encoded signature string (unverified client-side)",
    )

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
