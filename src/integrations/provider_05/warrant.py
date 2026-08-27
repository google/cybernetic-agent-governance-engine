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
warrant.py — CAGE x Provider 05 Warrant Contract v0.1 Data Model & Standing Verifier.
======================================================================================

Implements the frozen CAGE x Provider 05 Warrant Contract v0.1 specification:
  - 11-field Warrant schema with RFC 8785 (JCS) canonical cryptographic binding.
  - Standing verification: integrity, currency, scope, version, and status.
  - Failure semantics: failure removes eligibility for reliance (fallback or DEFER).
  - Governance envelope binding: binds warrant_id, digest, reliance_status, and reason.

Governing Rule:
  A warrant failure removes CAGE's right to rely on that norm. It does not
  itself become an institutional ALLOW or DENY.

Precision:
  CAGE verifies the supplied warrant object is authentic, current, applicable,
  and eligible for reliance; it does not establish the underlying institutional truth.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.integrations.provider_05.warrant")


class WarrantStatus(str, Enum):
    """Lifecycle status of a Provider 05 institutional warrant."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class RelianceStatus(str, Enum):
    """Reliance eligibility outcome from CAGE standing verification."""

    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE_MISSING = "INELIGIBLE_MISSING"
    INELIGIBLE_EXPIRED = "INELIGIBLE_EXPIRED"
    INELIGIBLE_REVOKED = "INELIGIBLE_REVOKED"
    INELIGIBLE_OUT_OF_SCOPE = "INELIGIBLE_OUT_OF_SCOPE"
    INELIGIBLE_VERSION_MISMATCH = "INELIGIBLE_VERSION_MISMATCH"
    INELIGIBLE_UNRESOLVED = "INELIGIBLE_UNRESOLVED"


@dataclass
class WarrantScope:
    """Applicability scope where warrant reliance is valid."""

    actions: list[str] = field(default_factory=lambda: ["*"])
    actors: list[str] = field(default_factory=lambda: ["*"])
    systems: list[str] = field(default_factory=lambda: ["*"])
    jurisdictions: list[str] = field(default_factory=lambda: ["*"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": sorted(self.actions),
            "actors": sorted(self.actors),
            "systems": sorted(self.systems),
            "jurisdictions": sorted(self.jurisdictions),
        }

    def contains(
        self,
        action: str | None = None,
        actor: str | None = None,
        system: str | None = None,
        jurisdiction: str | None = None,
    ) -> bool:
        """Check whether given execution attributes fall within this scope."""
        if action and "*" not in self.actions and action not in self.actions:
            return False
        if actor and "*" not in self.actors and actor not in self.actors:
            return False
        if system and "*" not in self.systems and system not in self.systems:
            return False
        if (
            jurisdiction
            and "*" not in self.jurisdictions
            and jurisdiction not in self.jurisdictions
        ):
            return False
        return True


@dataclass
class Warrant:
    """11-field frozen Provider 05 Warrant contract representation (v0.1)."""

    warrant_id: str
    norm_id: str
    issuing_authority: str
    authority_basis: str
    scope: WarrantScope | dict[str, Any]
    valid_from: str  # ISO 8601 UTC
    valid_until: str  # ISO 8601 UTC
    governing_version: str
    status: WarrantStatus | str
    revocation_ref: str | None = None
    residual_risk_ref: str | None = None
    digest: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.status, str):
            self.status = WarrantStatus(self.status.upper())
        if isinstance(self.scope, dict) and not isinstance(self.scope, WarrantScope):
            self.scope = WarrantScope(
                actions=self.scope.get("actions", ["*"]),
                actors=self.scope.get("actors", ["*"]),
                systems=self.scope.get("systems", ["*"]),
                jurisdictions=self.scope.get("jurisdictions", ["*"]),
            )
        if not self.digest:
            self.digest = self.compute_digest()

    def to_canonical_dict(self) -> dict[str, Any]:
        """Produce the dictionary of fields 1-11 for JCS canonicalization."""
        scope_dict = (
            self.scope.to_dict() if isinstance(self.scope, WarrantScope) else self.scope
        )
        return {
            "warrant_id": self.warrant_id,
            "norm_id": self.norm_id,
            "issuing_authority": self.issuing_authority,
            "authority_basis": self.authority_basis,
            "scope": scope_dict,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "governing_version": self.governing_version,
            "status": (
                self.status.value
                if isinstance(self.status, WarrantStatus)
                else str(self.status)
            ),
            "revocation_ref": self.revocation_ref,
            "residual_risk_ref": self.residual_risk_ref,
        }

    def to_canonical_bytes(self) -> bytes:
        """Produce RFC 8785 JCS canonical bytes for cryptographic signing/digest."""
        return jcs_canonicalize_plan(self.to_canonical_dict())

    def compute_digest(self) -> str:
        """Compute SHA-256 hex digest over JCS canonical bytes."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Full representation including digest."""
        d = self.to_canonical_dict()
        d["digest"] = self.digest or self.compute_digest()
        return d


@dataclass
class StandingVerificationResult:
    """Result of CAGE verifying a warrant's standing."""

    eligible: bool
    reliance_status: RelianceStatus
    reason: str
    warrant: Warrant | None = None
    warrant_id: str = ""
    warrant_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reliance_status": self.reliance_status.value,
            "reason": self.reason,
            "warrant_id": self.warrant_id,
            "warrant_digest": self.warrant_digest,
        }


class WarrantStandingVerifier:
    """CAGE verifier for checking standing and reliance eligibility of warrants.

    Performs 5-point validation:
      1. Cryptographic Integrity: recomputed JCS digest matches warrant.digest.
      2. Status Check: status is ACTIVE (not REVOKED or SUSPENDED).
      3. Currency Check: current time falls strictly within [valid_from, valid_until].
      4. Version Check: governing_version matches context or expected runtime baseline.
      5. Scope Check: action/actor/system/jurisdiction fall within warrant.scope.
    """

    @classmethod
    def verify_standing(
        cls,
        warrant: Warrant | None,
        context: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> StandingVerificationResult:
        """Evaluate standing and return reliance eligibility."""
        context = context or {}

        # 1. Missing check
        if warrant is None:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_MISSING,
                reason="Warrant is missing; cannot ground reliance on norm",
            )

        w_id = warrant.warrant_id
        w_digest = warrant.digest

        # 2. Cryptographic integrity check
        computed_digest = warrant.compute_digest()
        if warrant.digest and warrant.digest != computed_digest:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=f"Cryptographic digest mismatch: declared {warrant.digest[:16]}... vs computed {computed_digest[:16]}...",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        # 3. Status check
        if warrant.status == WarrantStatus.REVOKED:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_REVOKED,
                reason=f"Warrant revoked: {warrant.revocation_ref or 'revocation basis recorded'}",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        if warrant.status == WarrantStatus.SUSPENDED:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=f"Warrant suspended: {warrant.revocation_ref or 'suspension active'}",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        if warrant.status != WarrantStatus.ACTIVE:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=f"Warrant has unrecognised status: {warrant.status}",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        # 4. Currency / Temporal check
        current_time = now or datetime.now(timezone.utc)
        try:
            from_dt = datetime.fromisoformat(warrant.valid_from.replace("Z", "+00:00"))
            until_dt = datetime.fromisoformat(
                warrant.valid_until.replace("Z", "+00:00")
            )
            if current_time < from_dt or current_time > until_dt:
                return StandingVerificationResult(
                    eligible=False,
                    reliance_status=RelianceStatus.INELIGIBLE_EXPIRED,
                    reason=f"Warrant temporal window invalid: current {current_time.isoformat()} outside [{warrant.valid_from}, {warrant.valid_until}]",
                    warrant=warrant,
                    warrant_id=w_id,
                    warrant_digest=w_digest,
                )
        except Exception as dt_exc:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_UNRESOLVED,
                reason=f"Invalid ISO 8601 temporal format: {dt_exc}",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        # 5. Version check
        expected_version = context.get("governing_version") or context.get(
            "policy_version"
        )
        if expected_version and warrant.governing_version != expected_version:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
                reason=f"Governing version mismatch: expected {expected_version} vs warrant {warrant.governing_version}",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        # 6. Scope check
        scope_obj = (
            warrant.scope
            if isinstance(warrant.scope, WarrantScope)
            else WarrantScope(
                actions=warrant.scope.get("actions", ["*"]),
                actors=warrant.scope.get("actors", ["*"]),
                systems=warrant.scope.get("systems", ["*"]),
                jurisdictions=warrant.scope.get("jurisdictions", ["*"]),
            )
        )
        if not scope_obj.contains(
            action=context.get("action"),
            actor=context.get("actor") or context.get("operator_urn"),
            system=context.get("system"),
            jurisdiction=context.get("jurisdiction")
            or context.get("deployment_region"),
        ):
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
                reason=f"Context ({context}) is outside warrant scope ({scope_obj.to_dict()})",
                warrant=warrant,
                warrant_id=w_id,
                warrant_digest=w_digest,
            )

        # All checks pass
        return StandingVerificationResult(
            eligible=True,
            reliance_status=RelianceStatus.ELIGIBLE,
            reason="Warrant standing verified and active; norm eligible for reliance",
            warrant=warrant,
            warrant_id=w_id,
            warrant_digest=w_digest,
        )


def bind_warrant_to_attestation(
    warrant: Warrant, standing: StandingVerificationResult
) -> ExternalAttestation:
    """Create an ExternalAttestation binding the warrant into a GovernanceEnvelope."""
    status_str = (
        AttestationStatus.VERIFIED.value
        if standing.eligible
        else AttestationStatus.DENIED.value
    )
    return ExternalAttestation(
        attestation_type="WARRANT",
        status=status_str,
        receipt_id=warrant.warrant_id,
        attested_at=warrant.valid_from,
        metadata={
            "warrant_id": warrant.warrant_id,
            "warrant_digest": warrant.digest,
            "norm_id": warrant.norm_id,
            "reliance_status": standing.reliance_status.value,
            "reason": standing.reason,
            "issuing_authority": warrant.issuing_authority,
            "authority_basis": warrant.authority_basis,
        },
    )
