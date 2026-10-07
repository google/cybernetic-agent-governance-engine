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
Warrant Contract v0.1 data model (vendor-neutral kernel types).

Implements the frozen Warrant Contract v0.1 schema:
  - 11-field ``Warrant`` with RFC 8785 (JCS) canonical cryptographic binding.
  - Four-dimension ``WarrantScope`` (actions, actors, systems, jurisdictions).
  - ``WarrantStatus`` (issuer lifecycle) and ``RelianceStatus`` (CAGE's
    reliance eligibility outcome), plus ``StandingVerificationResult``.

Fail-closed invariants (v0.1):
  - CAGE never computes a warrant's declared digest on the issuer's behalf. A
    warrant without a declared digest is UNRESOLVED; only ``Warrant.issue()``
    (the issuer-side helper used by fixtures and seeded sources) computes one.
  - A scope must declare all four dimensions. CAGE never infers a missing
    dimension as ``"*"``.
  - ``Warrant`` and ``WarrantScope`` are immutable, so state cannot change
    between verification and evidence binding.

Known v0.1 limitation:
  The digest proves the warrant is internally consistent, not who issued it.
  Issuer signature verification against a ``kid``-resolved trust anchor is a
  v0.2 item.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

SCOPE_DIMENSIONS: tuple[str, ...] = ("actions", "actors", "systems", "jurisdictions")
REQUIRED_CONTEXT_KEYS: tuple[str, ...] = ("action", "jurisdiction", "governing_version")


class WarrantStatus(str, Enum):
    """Issuer-declared lifecycle status of an institutional warrant."""

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
    #: The cached warrant state outlived the freshness window and the
    #: re-fetch failed (``warrant.cache.WarrantCache``).
    INELIGIBLE_STALE = "INELIGIBLE_STALE"


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
    """11-field frozen Warrant contract representation (v0.1).

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

        Intended for seeded warrant sources and test fixtures, which stand in
        for the external issuer. CAGE's verification path never calls this.
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
    """Result of CAGE verifying a warrant's standing.

    ``attested_at`` (ISO 8601 UTC) is when CAGE evaluated standing; it is the
    Warrant Contract v0.1 ``attested_at`` evidence field and is always set,
    including when no warrant was supplied.
    """

    eligible: bool
    reliance_status: RelianceStatus
    reason: str
    attested_at: str
    warrant: Warrant | None = None
    warrant_id: str = ""
    warrant_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reliance_status": self.reliance_status.value,
            "reason": self.reason,
            "attested_at": self.attested_at,
            "warrant_id": self.warrant_id,
            "warrant_digest": self.warrant_digest,
        }
