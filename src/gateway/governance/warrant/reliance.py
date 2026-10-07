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

"""Reliance records: what one decision relied on, as evidence.

The kernel ``WarrantStage`` produces one :class:`RelianceRecord` for every
warranted norm that governs the requested action, eligible or not. The record
travels with the governance result and is written, with the same fields
whatever the verdict, into the artefact that decision produces:

* ALLOW / NARROW seal: the evidence record the routing seal commits to
  (``record_hash``), so the seal proves which warrant grounded execution;
* DEFER / REQUIRE_APPROVAL: the parked ``DeferToken`` and its
  ``GOVERNANCE_DEFERRAL`` evidence event;
* DENY: the ``RefusalReceipt`` (inside its ``proof_hash``).

Refusals are primary evidence: an ineligible record is as complete as an
eligible one.

One source of truth: :meth:`RelianceRecord.to_dict` is the evidence form, and
the envelope's ``WARRANT`` attestation (:meth:`RelianceRecord.attestation`)
carries exactly that dict as its metadata. The hash-chained record and the
signed envelope therefore cannot disagree about what was relied on.

Warrant Contract v0.1 evidence fields (``WARRANT_CONTRACT_EVIDENCE_FIELDS``
maps each contract name to its key here):

=====================  ==============================  =========================
Contract field         Evidence key                    Meaning
=====================  ==============================  =========================
``warrant_id``         ``warrant_id``                  issuer's warrant id
``norm_id``            ``norm_id``                     the governed norm
``digest``             ``warrant_digest``              issuer-declared digest
``reliance_status``    ``reliance_status``             CAGE's eligibility outcome
``governing_version``  ``warrant_governing_version``   version the warrant declares
``residual_risk_ref``  ``residual_risk_ref``           opaque issuer reference
``attested_at``        ``attested_at``                 when CAGE evaluated standing
=====================  ==============================  =========================

``governing_version`` is split in two so it is never ambiguous:
``required_governing_version`` is the version the deployment's ``NormBinding``
requires (what the warrant was checked against), and
``warrant_governing_version`` the version the warrant declares. They differ
exactly when the outcome is ``INELIGIBLE_VERSION_MISMATCH`` (or when no warrant
was received, in which case the warrant side is empty).

Absent values: every warrant-declared field (``warrant_id``,
``warrant_digest``, ``warrant_status``, ``warrant_governing_version``,
``issuing_authority``, ``authority_basis``, ``revocation_ref``,
``residual_risk_ref``) is the empty string ``""`` when no warrant was received
(``INELIGIBLE_MISSING``, or the source failed before answering), and the two
optional warrant fields (``revocation_ref``, ``residual_risk_ref``) are also
``""`` when the warrant declares none. ``warrant_id == ""`` is the marker for
"no warrant". The evidence form is strings-only, so it is always
JCS-canonicalisable. ``attested_at`` is never empty: standing is always
evaluated, even when the outcome is that there was nothing to evaluate.

``residual_risk_ref`` is opaque to CAGE: it is recorded verbatim and never
resolved or interpreted (Warrant Contract v0.1, partner Q5).

Freshness: ``observed_at`` is when CAGE received the warrant state (its own
receipt time, not an issuer-declared time) and ``age_seconds`` how old that
state was when the decision relied on it; ``max_age_seconds`` is the
freshness window it was held to (``warrant.cache.WarrantCache``).

``verification_status`` is always ``UNVERIFIED``. The declared digest proves
the warrant is internally consistent, not who issued it; issuer signatures
against a ``kid``-resolved trust anchor are a Warrant Contract v0.2 item.
Until then no record can claim more, so the field cannot be set. The envelope
attestation status is ``UNVERIFIED`` for the same reason; an ineligible
warrant is never expressed as ``DENIED``, which would read as an institutional
verdict rather than a reliance outcome.

The emitting source is the ``WarrantSource.provider_name`` the stage was
assembled with; the kernel never names a vendor.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from src.gateway.governance.seams.attestation import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.warrant.model import (
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantStatus,
)

#: The only verification status a v0.1 reliance record can carry.
RELIANCE_VERIFICATION_STATUS: str = AttestationStatus.UNVERIFIED.value

#: ``ExternalAttestation.attestation_type`` of the envelope warrant entry.
WARRANT_ATTESTATION_TYPE: str = "WARRANT"

#: Warrant Contract v0.1 evidence field name -> ``RelianceRecord.to_dict`` key.
WARRANT_CONTRACT_EVIDENCE_FIELDS: Mapping[str, str] = MappingProxyType(
    {
        "warrant_id": "warrant_id",
        "norm_id": "norm_id",
        "digest": "warrant_digest",
        "reliance_status": "reliance_status",
        "governing_version": "warrant_governing_version",
        "residual_risk_ref": "residual_risk_ref",
        "attested_at": "attested_at",
    }
)


@dataclass(frozen=True)
class RelianceRecord:
    """One warranted norm's reliance outcome for one governance decision.

    The stored fields are what only the decision knows (the norm, the
    version the binding requires, the source, the standing and its
    freshness); everything the warrant declares is read from
    ``standing.warrant`` so it cannot be restated inconsistently.

    ``observed_at`` (ISO 8601 UTC) and ``age_seconds`` describe CAGE's receipt
    of the warrant state the standing was computed from; both are empty when
    nothing was received (the source failed before answering).
    """

    norm_id: str
    required_governing_version: str
    provider_name: str
    standing: StandingVerificationResult
    observed_at: str = ""
    age_seconds: float | None = None
    max_age_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("norm_id", "required_governing_version", "provider_name"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"RelianceRecord.{name} must be a non-empty string")
        if not isinstance(self.standing, StandingVerificationResult):
            raise TypeError(
                "RelianceRecord.standing must be a StandingVerificationResult"
            )
        warrant = self.standing.warrant
        expected = ("", "") if warrant is None else (warrant.warrant_id, warrant.digest)
        if (self.standing.warrant_id, self.standing.warrant_digest) != expected:
            raise ValueError(
                "RelianceRecord.standing does not belong to its warrant; "
                "refusing to bind evidence"
            )
        if not isinstance(self.standing.attested_at, str) or not (
            self.standing.attested_at
        ):
            raise ValueError("RelianceRecord.standing.attested_at must be set")
        if not isinstance(self.observed_at, str):
            raise TypeError("RelianceRecord.observed_at must be an ISO 8601 string")
        for name in ("age_seconds", "max_age_seconds"):
            seconds = getattr(self, name)
            if seconds is not None and (
                isinstance(seconds, bool)
                or not isinstance(seconds, int | float)
                or not math.isfinite(seconds)
                or seconds < 0
            ):
                raise ValueError(
                    f"RelianceRecord.{name} must be None or a finite number >= 0"
                )

    # ── decision outcome ────────────────────────────────────────────────────

    @property
    def eligible(self) -> bool:
        return self.standing.eligible

    @property
    def reliance_status(self) -> RelianceStatus:
        return self.standing.reliance_status

    @property
    def reason(self) -> str:
        return self.standing.reason

    @property
    def attested_at(self) -> str:
        """When CAGE evaluated standing (ISO 8601 UTC); never empty."""
        return self.standing.attested_at

    @property
    def verification_status(self) -> str:
        """Always ``UNVERIFIED`` until issuer signatures exist (v0.2)."""
        return RELIANCE_VERIFICATION_STATUS

    # ── warrant-declared (``""`` when no warrant was received) ──────────────

    @property
    def warrant(self) -> Warrant | None:
        return self.standing.warrant

    @property
    def warrant_id(self) -> str:
        return self.standing.warrant_id

    @property
    def warrant_digest(self) -> str:
        """The issuer-declared digest, never one CAGE computed."""
        return self.standing.warrant_digest

    @property
    def warrant_status(self) -> str:
        warrant = self.warrant
        if warrant is None:
            return ""
        if isinstance(warrant.status, WarrantStatus):
            return warrant.status.value
        return str(warrant.status)

    @property
    def warrant_governing_version(self) -> str:
        return _declared(self.warrant, "governing_version")

    @property
    def issuing_authority(self) -> str:
        return _declared(self.warrant, "issuing_authority")

    @property
    def authority_basis(self) -> str:
        return _declared(self.warrant, "authority_basis")

    @property
    def revocation_ref(self) -> str:
        return _declared(self.warrant, "revocation_ref")

    @property
    def residual_risk_ref(self) -> str:
        """Opaque issuer reference, recorded verbatim, never resolved."""
        return _declared(self.warrant, "residual_risk_ref")

    # ── evidence forms ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """The JSON evidence form (strings only, so JCS-canonicalisable).

        ``age_seconds`` and ``max_age_seconds`` are decimal strings with
        millisecond precision (``""`` when unknown). See the module docstring
        for the Warrant Contract field mapping and the empty-value rules.
        """
        return {
            "norm_id": self.norm_id,
            "warrant_id": self.warrant_id,
            "warrant_digest": self.warrant_digest,
            "warrant_status": self.warrant_status,
            "reliance_status": self.reliance_status.value,
            "reason": self.reason,
            "required_governing_version": self.required_governing_version,
            "warrant_governing_version": self.warrant_governing_version,
            "issuing_authority": self.issuing_authority,
            "authority_basis": self.authority_basis,
            "revocation_ref": self.revocation_ref,
            "residual_risk_ref": self.residual_risk_ref,
            "attested_at": self.attested_at,
            "observed_at": self.observed_at,
            "age_seconds": _seconds(self.age_seconds),
            "max_age_seconds": _seconds(self.max_age_seconds),
            "provider_name": self.provider_name,
            "verification_status": self.verification_status,
        }

    def attestation(self) -> ExternalAttestation | None:
        """The envelope ``WARRANT`` attestation, or ``None`` with no warrant.

        Its metadata is exactly :meth:`to_dict`, so the signed envelope and
        the hash-chained evidence carry the same fields and values. Always
        ``UNVERIFIED`` (see the module docstring).
        """
        if self.warrant is None:
            return None
        return ExternalAttestation(
            attestation_type=WARRANT_ATTESTATION_TYPE,
            status=RELIANCE_VERIFICATION_STATUS,
            receipt_id=self.warrant_id,
            attested_at=self.attested_at,
            provider_name=self.provider_name,
            metadata=self.to_dict(),
        )


def _declared(warrant: Warrant | None, name: str) -> str:
    """A warrant-declared string field, ``""`` when absent or undeclared."""
    if warrant is None:
        return ""
    value = getattr(warrant, name)
    return "" if value is None else str(value)


def _seconds(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}"


def reliance_evidence(records: Iterable[RelianceRecord]) -> list[dict[str, Any]]:
    """The evidence form of ``records``, in decision order."""
    return [record.to_dict() for record in records]


def reliance_attestations(
    records: Iterable[RelianceRecord],
) -> list[ExternalAttestation]:
    """One ``WARRANT`` attestation per record that carries a warrant."""
    return [a for a in (record.attestation() for record in records) if a is not None]


__all__ = [
    "RELIANCE_VERIFICATION_STATUS",
    "WARRANT_ATTESTATION_TYPE",
    "WARRANT_CONTRACT_EVIDENCE_FIELDS",
    "RelianceRecord",
    "reliance_attestations",
    "reliance_evidence",
]
