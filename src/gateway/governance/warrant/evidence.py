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
Warrant evidence binding into the GovernanceEnvelope.

Binds ``warrant_id``, digest, ``reliance_status`` and reason into an
``ExternalAttestation``. The emitting source is named by the caller (the
``WarrantSource.provider_name`` of the source that supplied the warrant), so
the kernel never hard-codes a vendor identity.
"""

from __future__ import annotations

from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.warrant.model import StandingVerificationResult, Warrant


def bind_warrant_to_attestation(
    warrant: Warrant,
    standing: StandingVerificationResult,
    *,
    provider_name: str,
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
        provider_name=provider_name,
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
