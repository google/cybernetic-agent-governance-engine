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
Warrant Contract v0.1 & v0.2 data model (vendor-neutral kernel types).

Implements the frozen Warrant Contract v0.1 and v0.2 schemas:
  - v0.1: 11-field ``Warrant`` with RFC 8785 (JCS) canonical digest.
  - v0.2: 20-field ``Warrant`` adding ``schema_version``, ``environment``,
    ``norm_parameters``, ``state_as_of``, ``issued_at``, ``alg``, ``kid``, and
    Ed25519 ``signature`` verified against a ``kid``-resolved
    :class:`~src.gateway.governance.warrant.trust_anchor.VerifiedKeyManifest`.
  - Four-dimension ``WarrantScope`` (actions, actors, systems, jurisdictions).
  - ``WarrantStatus`` (issuer lifecycle) and ``RelianceStatus`` (CAGE's
    reliance eligibility outcome), plus ``StandingVerificationResult``.

Fail-closed invariants:
  - CAGE never computes a warrant's declared digest on the issuer's behalf. A
    warrant without a declared digest is UNRESOLVED; only ``Warrant.issue()``
    (the issuer-side helper used by fixtures and seeded sources) computes one.
  - A scope must declare all four dimensions. CAGE never infers a missing
    dimension as ``"*"``.
  - ``Warrant`` and ``WarrantScope`` are immutable, so state cannot change
    between verification and evidence binding.
  - ``StandingVerificationResult.verification_status`` is ``VERIFIED`` only
    after cryptographic verification of a signed v0.2 warrant against a
    verified key manifest; unsigned or unverified warrants are ``UNVERIFIED``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

SCOPE_DIMENSIONS: tuple[str, ...] = ("actions", "actors", "systems", "jurisdictions")
REQUIRED_CONTEXT_KEYS: tuple[str, ...] = ("action", "jurisdiction", "governing_version")
WARRANT_SCHEMA_VERSION_V02: str = "veip-warrant/0.2"


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
    INELIGIBLE_SUSPENDED = "INELIGIBLE_SUSPENDED"
    INELIGIBLE_OUT_OF_SCOPE = "INELIGIBLE_OUT_OF_SCOPE"
    INELIGIBLE_VERSION_MISMATCH = "INELIGIBLE_VERSION_MISMATCH"
    INELIGIBLE_AUTHENTICITY = "INELIGIBLE_AUTHENTICITY"
    INELIGIBLE_UNRESOLVED = "INELIGIBLE_UNRESOLVED"
    #: The cached warrant state outlived the freshness window and the
    #: re-fetch failed, or the issuer's ``state_as_of`` is older than the
    #: freshness window.
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
        are checked when the context supplies them.
        """

        def _admits(values: tuple[str, ...], item: str | None) -> bool:
            return item is None or "*" in values or item in values

        return (
            _admits(self.actions, action)
            and _admits(self.jurisdictions, jurisdiction)
            and _admits(self.actors, actor)
            and _admits(self.systems, system)
        )


def _freeze_mapping(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(
        {k: _freeze_mapping(v) if isinstance(v, Mapping) else v for k, v in raw.items()}
    )


def _thaw_mapping(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: _thaw_mapping(v) if isinstance(v, Mapping) else v for k, v in raw.items()
    }


@dataclass(frozen=True)
class Warrant:
    """Frozen Warrant contract representation (v0.1 and v0.2).

    ``scope`` holds a ``WarrantScope`` when well-formed, or the raw dict when
    a dimension is missing; the verifier treats the latter as UNRESOLVED.
    ``digest`` and ``signature`` are the issuer-declared values and are never
    back-filled.
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
    # Warrant Contract v0.2 fields (empty/None on v0.1 warrants)
    schema_version: str = ""
    environment: str = ""
    norm_parameters: Mapping[str, Any] | None = None
    state_as_of: str = ""
    issued_at: str = ""
    alg: str = ""
    kid: str = ""
    signature: str = ""

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
        if isinstance(self.norm_parameters, Mapping) and not isinstance(
            self.norm_parameters, MappingProxyType
        ):
            object.__setattr__(
                self, "norm_parameters", _freeze_mapping(self.norm_parameters)
            )

    @property
    def is_v02(self) -> bool:
        """Return whether this warrant carries v0.2 envelope/authenticity fields."""
        return bool(
            self.schema_version
            or self.environment
            or self.norm_parameters is not None
            or self.state_as_of
            or self.issued_at
            or self.alg
            or self.kid
            or self.signature
        )

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
        """Produce the canonical dictionary of content fields for JCS hashing."""
        scope_dict = (
            self.scope.to_dict() if isinstance(self.scope, WarrantScope) else self.scope
        )
        status_str = (
            self.status.value
            if isinstance(self.status, WarrantStatus)
            else str(self.status)
        )
        if self.is_v02:
            norm_params = (
                _thaw_mapping(self.norm_parameters)
                if isinstance(self.norm_parameters, Mapping)
                else self.norm_parameters
            )
            return {
                "schema_version": self.schema_version,
                "environment": self.environment,
                "warrant_id": self.warrant_id,
                "norm_id": self.norm_id,
                "issuing_authority": self.issuing_authority,
                "authority_basis": self.authority_basis,
                "scope": scope_dict,
                "norm_parameters": norm_params,
                "valid_from": self.valid_from,
                "valid_until": self.valid_until,
                "governing_version": self.governing_version,
                "status": status_str,
                "revocation_ref": (
                    "" if self.revocation_ref is None else self.revocation_ref
                ),
                "residual_risk_ref": (
                    "" if self.residual_risk_ref is None else self.residual_risk_ref
                ),
                "state_as_of": self.state_as_of,
                "issued_at": self.issued_at,
                "alg": self.alg,
                "kid": self.kid,
            }
        return {
            "warrant_id": self.warrant_id,
            "norm_id": self.norm_id,
            "issuing_authority": self.issuing_authority,
            "authority_basis": self.authority_basis,
            "scope": scope_dict,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "governing_version": self.governing_version,
            "status": status_str,
            "revocation_ref": self.revocation_ref,
            "residual_risk_ref": self.residual_risk_ref,
        }

    def to_canonical_bytes(self) -> bytes:
        """Produce RFC 8785 JCS canonical bytes for digest computation."""
        return jcs_canonicalize_plan(self.to_canonical_dict())

    def to_signed_bytes(self) -> bytes:
        """Produce RFC 8785 JCS canonical bytes for v0.2 signature verification.

        Under Warrant Contract v0.2, the Ed25519 signature covers the JCS
        canonical representation of all warrant fields including ``digest``
        and excluding ``signature``.
        """
        return jcs_canonicalize_plan(
            {**self.to_canonical_dict(), "digest": self.digest}
        )

    def compute_digest(self) -> str:
        """Compute SHA-256 hex digest over JCS canonical bytes."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Full representation including declared digest (and signature in v0.2)."""
        base = {**self.to_canonical_dict(), "digest": self.digest}
        if self.is_v02:
            base["signature"] = self.signature
        return base


@dataclass(frozen=True)
class StandingVerificationResult:
    """Result of CAGE verifying a warrant's standing.

    ``attested_at`` (ISO 8601 UTC) is when CAGE evaluated standing; it is the
    Warrant Contract ``attested_at`` evidence field and is always set,
    including when no warrant was supplied. ``verification_status`` is
    ``VERIFIED`` only when a v0.2 warrant's Ed25519 signature has been
    cryptographically verified against a ``kid``-resolved key manifest.
    """

    eligible: bool
    reliance_status: RelianceStatus
    reason: str
    attested_at: str
    warrant: Warrant | None = None
    warrant_id: str = ""
    warrant_digest: str = ""
    verification_status: str = "UNVERIFIED"

    def __post_init__(self) -> None:
        if self.verification_status not in ("UNVERIFIED", "VERIFIED"):
            raise ValueError(
                f"Invalid StandingVerificationResult.verification_status: "
                f"{self.verification_status!r}"
            )
        if self.verification_status == "VERIFIED" and (
            self.warrant is None
            or not self.warrant.is_v02
            or not self.warrant.signature
            or not self.warrant.kid
        ):
            raise ValueError(
                "StandingVerificationResult cannot claim VERIFIED status without "
                "a signed v0.2 warrant"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reliance_status": self.reliance_status.value,
            "reason": self.reason,
            "attested_at": self.attested_at,
            "warrant_id": self.warrant_id,
            "warrant_digest": self.warrant_digest,
        }
