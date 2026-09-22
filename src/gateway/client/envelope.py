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

This module defines the read-only, immutable envelope structures that clients
receive from the governance gateway. These envelopes represent cryptographically
signed governance decisions and execution grants.

Clients parse these envelopes but NEVER construct or modify them. All envelopes
are frozen (immutable) to prevent accidental or malicious tampering.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GovernanceEnvelope(BaseModel):
    """
    Read-only client view of a governance decision envelope.

    This envelope represents the gateway's final governance decision for a
    proposed action. It includes the decision payload, audit context, and a
    cryptographic signature that the client MUST verify before trusting the
    decision.

    The envelope is strictly immutable (frozen=True). Clients parse envelopes
    received from the gateway but NEVER construct or modify them. Any attempt
    to modify an envelope after creation will raise a ValidationError.

    Attributes:
        envelope_version: Semantic version of the envelope schema (e.g., "3.0").
            Must match the regex pattern "^3\\.d+$" to ensure compatibility.
        envelope_type: Fixed string "cage_governance_decision" identifying the
            envelope as a governance decision (vs. other future envelope types).
        issued_at: UTC datetime when the envelope was issued by the gateway.
        expires_at: UTC datetime when the envelope expires and is no longer valid.
        issuer: Dictionary identifying the gateway instance that issued the envelope:
            - 'service': Service name (e.g., "cage-gateway")
            - 'instance_id': Unique instance identifier
            - 'region': Deployment region (e.g., "us-central1")
        subject: Dictionary identifying the action being governed:
            - 'action': Action name (e.g., "execute_trade")
            - 'action_hash': SHA256 hash of the action parameters
            - 'record_hash': SHA256 hash of the audit record
            - 'agent_id': Identifier of the agent requesting the action
        governance_context: Dictionary containing governance metadata:
            - 'policy_version': Version of the policy that was evaluated
            - 'tiers_passed': List of governance tiers that approved the action
        payload: The actual decision payload, structure depends on decision type:
            - For ALLOW: {'decision': 'ALLOW', 'execution_token': '...'}
            - For DENY: {'decision': 'DENY', 'reason_code': '...', 'details': {...}}
            - For DEFER: {'decision': 'DEFER', 'ticket_id': '...', 'reason': '...'}
        signature: Cryptographic signature dictionary:
            - 'algorithm': Signature algorithm (e.g., "RS256")
            - 'value': Base64-encoded signature
            - 'kid': Key identifier for the signing key
    """

    envelope_version: str = Field(
        ..., pattern=r"^3\.\d+$", description="Envelope schema version (e.g., '3.0')"
    )
    envelope_type: str = Field(
        default="cage_governance_decision",
        description="Fixed type identifier for governance decision envelopes",
    )
    issued_at: datetime = Field(
        ..., description="UTC datetime when the envelope was issued"
    )
    expires_at: datetime = Field(
        ..., description="UTC datetime when the envelope expires"
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
    signature: dict[str, str] = Field(
        ...,
        description="Cryptographic signature (algorithm, value, kid)",
    )

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class ExecutionGrant(BaseModel):
    """
    Phase 3 direct dispatch execution grant (JWT-style token).

    This envelope represents a cryptographically signed grant that authorizes
    direct execution of a governed action without further gateway involvement.
    It is used in Phase 3 of the client SDK to enable offline, low-latency
    execution after governance approval.

    The grant is structured as a JWT-like token with standard claims (iss, sub,
    aud, exp, iat) plus CAGE-specific claims for action integrity verification.

    Like GovernanceEnvelope, this model is strictly immutable (frozen=True).
    Clients parse grants received from the gateway but NEVER construct them.

    Attributes:
        grant_version: Version of the grant schema (default: "1.0").
        iss: Issuer claim - identifies the gateway that issued the grant.
        sub: Subject claim - identifies the agent authorized to execute.
        aud: Audience claim - identifies the target actuator/service.
        exp: Expiration time (Unix timestamp) - grant is invalid after this time.
        iat: Issued-at time (Unix timestamp) - when the grant was created.
        nonce: Unique nonce to prevent replay attacks.
        action_hash: SHA256 hash of the action parameters, used to verify that
            the action hasn't been modified since governance approval.
        record_hash: SHA256 hash of the audit record linking the grant to the
            governance decision trail.
        signature: Base64-encoded cryptographic signature over all claims.
    """

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
