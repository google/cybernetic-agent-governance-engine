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
CAGE Gateway Client SDK Exception Hierarchy.

Defines structured exception types raised by the CAGE Client SDK when mediating
governance responses and verifying cryptographic ``GovernanceEnvelope`` integrity.
"""

from datetime import datetime
from typing import Any


class CageGatewayError(Exception):
    """Base exception for all CAGE Gateway client errors."""


class PolicyViolationException(CageGatewayError):
    """Raised when a proposed action violates governance policy or is narrowed."""

    def __init__(
        self,
        reason_code: str,
        violation_details: dict[str, Any],
        audit_id: str,
        recoverable: bool = True,
    ) -> None:
        self.reason_code = reason_code
        self.violation_details = violation_details
        self.audit_id = audit_id
        self.recoverable = recoverable
        super().__init__(
            f"Policy violation ({reason_code}): {violation_details.get('policy_rule', 'unknown')} "
            f"[audit_id={audit_id}, recoverable={recoverable}]"
        )


class DeferralPending(CageGatewayError):
    """Raised when an action requires human-in-the-loop approval and is deferred."""

    def __init__(
        self,
        ticket_id: str,
        defer_reason: str,
        expires_at: datetime,
        ttl_seconds: int = 14400,
    ) -> None:
        self.ticket_id = ticket_id
        self.defer_reason = defer_reason
        self.expires_at = expires_at
        self.ttl_seconds = ttl_seconds
        super().__init__(
            f"Action deferred: {defer_reason} [ticket_id={ticket_id}, "
            f"expires_at={expires_at.isoformat()}]"
        )


class RoutingSealVerificationError(CageGatewayError):
    """
    Raised when ``GovernanceEnvelope`` cryptographic or freshness verification fails.

    Raised fail-closed by ``CageClient`` and ``JwksKeyResolver`` whenever:
      - ``GovernanceEnvelope.signature`` is missing, malformed, contains embedded
        key material, uses a forbidden/mismatched algorithm, or fails cryptographic
        verification against the out-of-band ``kid`` trust anchor;
      - ``kid`` cannot be resolved from pinned ``public_keys`` or
        ``/governance/.well-known/jwks.json`` (including JWKS staleness eviction or
        HTTP ``304`` rejection);
      - ``issued_at`` / ``expires_at`` are naive, non-monotonic, or expired beyond
        ``clock_skew_seconds``; or
      - ``subject.action`` or ``subject.action_hash`` fails to match the submitted
        request action and parameters.
    """
