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

``verification_status`` is always ``UNVERIFIED``. The declared digest proves
the warrant is internally consistent, not who issued it; issuer signatures
against a ``kid``-resolved trust anchor are a Warrant Contract v0.2 item.
Until then no record can claim more, so the field cannot be set.

The emitting source is the ``WarrantSource.provider_name`` the stage was
assembled with; the kernel never names a vendor.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.seams.attestation import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.warrant.evidence import bind_warrant_to_attestation
from src.gateway.governance.warrant.model import (
    RelianceStatus,
    StandingVerificationResult,
    WarrantStatus,
)

#: The only verification status a v0.1 reliance record can carry.
RELIANCE_VERIFICATION_STATUS: str = AttestationStatus.UNVERIFIED.value


@dataclass(frozen=True)
class RelianceRecord:
    """One warranted norm's reliance outcome for one governance decision.

    ``governing_version`` is the version the deployment's binding requires
    (what the warrant was checked against), not the version the warrant
    declares; a mismatch shows up as ``INELIGIBLE_VERSION_MISMATCH``.
    """

    norm_id: str
    governing_version: str
    provider_name: str
    standing: StandingVerificationResult

    def __post_init__(self) -> None:
        for name in ("norm_id", "governing_version", "provider_name"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"RelianceRecord.{name} must be a non-empty string")
        if not isinstance(self.standing, StandingVerificationResult):
            raise TypeError(
                "RelianceRecord.standing must be a StandingVerificationResult"
            )

    @property
    def eligible(self) -> bool:
        return self.standing.eligible

    @property
    def reliance_status(self) -> RelianceStatus:
        return self.standing.reliance_status

    @property
    def verification_status(self) -> str:
        """Always ``UNVERIFIED`` until issuer signatures exist (v0.2)."""
        return RELIANCE_VERIFICATION_STATUS

    def to_dict(self) -> dict[str, Any]:
        """The JSON evidence form (strings only, so JCS-canonicalisable).

        ``warrant_id``, ``warrant_digest`` and ``warrant_status`` are ``""``
        when no warrant was supplied (``INELIGIBLE_MISSING``) or the source
        failed before returning one. ``warrant_digest`` is the issuer-declared
        digest, never one CAGE computed.
        """
        warrant = self.standing.warrant
        if warrant is None:
            warrant_status = ""
        elif isinstance(warrant.status, WarrantStatus):
            warrant_status = warrant.status.value
        else:
            warrant_status = str(warrant.status)
        return {
            "norm_id": self.norm_id,
            "warrant_id": self.standing.warrant_id,
            "warrant_digest": self.standing.warrant_digest,
            "warrant_status": warrant_status,
            "reliance_status": self.standing.reliance_status.value,
            "reason": self.standing.reason,
            "governing_version": self.governing_version,
            "evaluated_at": self.standing.evaluated_at,
            "provider_name": self.provider_name,
            "verification_status": self.verification_status,
        }

    def attestation(self) -> ExternalAttestation | None:
        """The envelope ``WARRANT`` attestation, or ``None`` with no warrant.

        Always ``UNVERIFIED`` (see :func:`bind_warrant_to_attestation`).
        """
        warrant = self.standing.warrant
        if warrant is None:
            return None
        return bind_warrant_to_attestation(
            warrant, self.standing, provider_name=self.provider_name
        )


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
    "RelianceRecord",
    "reliance_attestations",
    "reliance_evidence",
]
