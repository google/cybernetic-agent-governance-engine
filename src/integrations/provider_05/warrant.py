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

Fail-closed invariants (v0.1):
  - CAGE never computes a warrant's declared digest on the issuer's behalf. A
    warrant without a declared digest is UNRESOLVED; only ``Warrant.issue()``
    (the issuer-side helper used by fixtures and seeded stores) computes one.
  - A scope must declare all four dimensions (actions, actors, systems,
    jurisdictions). CAGE never infers a missing dimension as ``"*"``.
  - The evaluation context must carry ``action``, ``jurisdiction`` and
    ``governing_version``; absence is UNRESOLVED, never "in scope".
  - ``Warrant`` and ``WarrantScope`` are immutable, so state cannot change
    between verification and evidence binding.

Known v0.1 limitation:
  The digest proves the warrant is internally consistent, not who issued it.
  Issuer signature verification against a ``kid``-resolved trust anchor is a
  v0.2 item, so warrant attestations are emitted as ``UNVERIFIED``.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.integrations.provider_05.warrant")

SCOPE_DIMENSIONS: tuple[str, ...] = ("actions", "actors", "systems", "jurisdictions")
REQUIRED_CONTEXT_KEYS: tuple[str, ...] = ("action", "jurisdiction", "governing_version")


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


@dataclass(frozen=True)
class WarrantScope:
    """Applicability scope where warrant reliance is valid.

    All four dimensions are required. ``"*"`` must be declared explicitly by
    the issuer; it is never assumed.
    """

    actions: tuple[str, ...]
    actors: tuple[str, ...]
    systems: tuple[str, ...]
    jurisdictions: tuple[str, ...]

    def __post_init__(self) -> None:
        for dim in SCOPE_DIMENSIONS:
            object.__setattr__(self, dim, tuple(getattr(self, dim)))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> WarrantScope | None:
        """Build a scope from its wire form, or ``None`` if malformed."""
        if not all(isinstance(raw.get(dim), list | tuple) for dim in SCOPE_DIMENSIONS):
            return None
        return cls(**{dim: raw[dim] for dim in SCOPE_DIMENSIONS})

    def to_dict(self) -> dict[str, Any]:
        return {dim: sorted(getattr(self, dim)) for dim in SCOPE_DIMENSIONS}

    def contains(
        self,
        action: str,
        jurisdiction: str,
        actor: str | None = None,
        system: str | None = None,
    ) -> bool:
        """Check whether given execution attributes fall within this scope.

        ``action`` and ``jurisdiction`` are mandatory. ``actor`` and ``system``
        are checked only when the context supplies them; the v0.1 vectors do
        not carry them (open question for v0.2).
        """

        def _admits(values: tuple[str, ...], item: str | None) -> bool:
            return item is None or "*" in values or item in values

        return (
            _admits(self.actions, action)
            and _admits(self.jurisdictions, jurisdiction)
            and _admits(self.actors, actor)
            and _admits(self.systems, system)
        )


@dataclass(frozen=True)
class Warrant:
    """11-field frozen Provider 05 Warrant contract representation (v0.1).

    ``scope`` holds a ``WarrantScope`` when well-formed, or the raw dict when
    a dimension is missing; the verifier treats the latter as UNRESOLVED.
    ``digest`` is the issuer-declared value and is never back-filled.
    """

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
        if isinstance(self.status, str) and not isinstance(self.status, WarrantStatus):
            try:
                object.__setattr__(self, "status", WarrantStatus(self.status.upper()))
            except ValueError:
                pass  # Unrecognised status: kept verbatim, verifier yields UNRESOLVED.
        if isinstance(self.scope, dict):
            parsed = WarrantScope.from_dict(self.scope)
            if parsed is not None:
                object.__setattr__(self, "scope", parsed)

    @classmethod
    def issue(cls, **fields: Any) -> Warrant:
        """Issuer-side constructor: build a warrant and declare its digest.

        Intended for the seeded store and test fixtures, which stand in for
        the VEIP issuer. CAGE's verification path never calls this.
        """
        fields.pop("digest", None)
        draft = cls(**fields)
        return cls(**{**fields, "digest": draft.compute_digest()})

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
        """Full representation including the declared digest."""
        return {**self.to_canonical_dict(), "digest": self.digest}


@dataclass(frozen=True)
class StandingVerificationResult:
    """Result of CAGE verifying a warrant's standing."""

    eligible: bool
    reliance_status: RelianceStatus
    reason: str
    evaluated_at: str
    warrant: Warrant | None = None
    warrant_id: str = ""
    warrant_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reliance_status": self.reliance_status.value,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at,
            "warrant_id": self.warrant_id,
            "warrant_digest": self.warrant_digest,
        }


class WarrantStandingVerifier:
    """CAGE verifier for checking standing and reliance eligibility of warrants.

    Check order (first failure wins):
      0. Presence: a warrant was supplied (else MISSING).
      1. Context: action, jurisdiction and governing_version are supplied.
      2. Integrity: a digest is declared and equals the recomputed JCS digest.
      3. Status: ACTIVE (REVOKED -> REVOKED; SUSPENDED/unknown -> UNRESOLVED).
      4. Currency: evaluation time within [valid_from, valid_until].
      5. Version: governing_version equals the runtime governing version.
      6. Scope: well-formed four-dimension scope admits the context.
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
        current_time = now or datetime.now(timezone.utc)
        evaluated_at = current_time.isoformat()

        if warrant is None:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_MISSING,
                reason="Warrant is missing; cannot ground reliance on norm",
                evaluated_at=evaluated_at,
            )

        def _ineligible(
            status: RelianceStatus, reason: str
        ) -> StandingVerificationResult:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=status,
                reason=reason,
                evaluated_at=evaluated_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id,
                warrant_digest=warrant.digest,
            )

        # 1. Context completeness
        missing_keys = [k for k in REQUIRED_CONTEXT_KEYS if not context.get(k)]
        if missing_keys:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Evaluation context missing required keys: {missing_keys}",
            )

        # 2. Cryptographic integrity
        if not warrant.digest:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                "Warrant carries no declared digest; integrity cannot be established",
            )
        computed_digest = warrant.compute_digest()
        if warrant.digest != computed_digest:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Cryptographic digest mismatch: declared {warrant.digest[:16]}... "
                f"vs computed {computed_digest[:16]}...",
            )

        # 3. Status
        if warrant.status == WarrantStatus.REVOKED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_REVOKED,
                f"Warrant revoked: {warrant.revocation_ref or 'revocation basis recorded'}",
            )
        if warrant.status == WarrantStatus.SUSPENDED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant suspended: {warrant.revocation_ref or 'suspension active'}",
            )
        if warrant.status != WarrantStatus.ACTIVE:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant has unrecognised status: {warrant.status}",
            )

        # 4. Currency
        try:
            from_dt = datetime.fromisoformat(warrant.valid_from.replace("Z", "+00:00"))
            until_dt = datetime.fromisoformat(
                warrant.valid_until.replace("Z", "+00:00")
            )
            out_of_window = current_time < from_dt or current_time > until_dt
        except (TypeError, ValueError) as dt_exc:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Invalid temporal comparison: {dt_exc}",
            )
        if out_of_window:
            return _ineligible(
                RelianceStatus.INELIGIBLE_EXPIRED,
                f"Warrant temporal window invalid: current {evaluated_at} outside "
                f"[{warrant.valid_from}, {warrant.valid_until}]",
            )

        # 5. Version
        expected_version = context["governing_version"]
        if warrant.governing_version != expected_version:
            return _ineligible(
                RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
                f"Governing version mismatch: expected {expected_version} "
                f"vs warrant {warrant.governing_version}",
            )

        # 6. Scope
        if not isinstance(warrant.scope, WarrantScope):
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant scope malformed; all of {list(SCOPE_DIMENSIONS)} are required",
            )
        if not warrant.scope.contains(
            action=context["action"],
            jurisdiction=context["jurisdiction"],
            actor=context.get("actor"),
            system=context.get("system"),
        ):
            return _ineligible(
                RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
                f"Context ({context}) is outside warrant scope ({warrant.scope.to_dict()})",
            )

        return StandingVerificationResult(
            eligible=True,
            reliance_status=RelianceStatus.ELIGIBLE,
            reason="Warrant standing verified and active; norm eligible for reliance",
            evaluated_at=evaluated_at,
            warrant=warrant,
            warrant_id=warrant.warrant_id,
            warrant_digest=warrant.digest,
        )


def bind_warrant_to_attestation(
    warrant: Warrant, standing: StandingVerificationResult
) -> ExternalAttestation:
    """Create an ExternalAttestation binding the warrant into a GovernanceEnvelope.

    The attestation status is always ``UNVERIFIED``: the digest proves internal
    consistency, not issuer identity (signature verification is v0.2). Reliance
    eligibility is carried in ``metadata["reliance_status"]``; an ineligible
    warrant is never expressed as ``DENIED``, which would read as an
    institutional verdict and contradict the governing rule.
    """
    if (
        standing.warrant_id != warrant.warrant_id
        or standing.warrant_digest != warrant.digest
    ):
        raise ValueError(
            "Standing result does not belong to this warrant; refusing to bind evidence"
        )
    return ExternalAttestation(
        attestation_type="WARRANT",
        status=AttestationStatus.UNVERIFIED.value,
        receipt_id=warrant.warrant_id,
        attested_at=standing.evaluated_at,
        provider_name="provider_05_warrant",
        metadata={
            "warrant_id": warrant.warrant_id,
            "warrant_digest": warrant.digest,
            "norm_id": warrant.norm_id,
            "governing_version": warrant.governing_version,
            "reliance_status": standing.reliance_status.value,
            "reason": standing.reason,
            "issuing_authority": warrant.issuing_authority,
            "authority_basis": warrant.authority_basis,
            "revocation_ref": warrant.revocation_ref,
            "residual_risk_ref": warrant.residual_risk_ref,
        },
    )
