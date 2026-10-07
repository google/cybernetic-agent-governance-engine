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

"""Warrant Contract v0.1 evidence fields of the kernel ``RelianceRecord``.

For every VEIP v0.1 vector (VEC-001..006) and the MISSING contract state, the
reliance record CAGE writes into hash-chained evidence must carry the seven
contract evidence fields (``warrant_id``, ``norm_id``, ``digest``,
``reliance_status``, ``governing_version``, ``residual_risk_ref``,
``attested_at``) with the vector's values, plus the version the binding
required, kept apart from the version the warrant declares.

The envelope ``WARRANT`` attestation is derived from the same record, so its
metadata must equal the record's evidence form exactly.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Any

import pytest

from src.gateway.governance.warrant import (
    WARRANT_CONTRACT_EVIDENCE_FIELDS,
    RelianceRecord,
    RelianceStatus,
    Warrant,
    WarrantStandingVerifier,
)
from tests.integrations.provider_05.test_provider_05_veip_vectors import (
    SHARED_CONTEXT,
    SHARED_WARRANT,
    VEIP_ACTIVE_DIGEST,
    VEIP_TAMPERED_DIGEST,
    VEIP_V01_VECTORS,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

_PROVIDER = "provider_05_warrant"
_RESIDUAL_RISK_REF = "RRR-2026-08-01-A1"
_WARRANT_GOVERNING_VERSION = "cage-policy-2.1.0"
#: Every key a warrant supplies; all ``""`` when no warrant was received.
_WARRANT_DECLARED_KEYS = (
    "warrant_id",
    "warrant_digest",
    "warrant_status",
    "warrant_governing_version",
    "issuing_authority",
    "authority_basis",
    "revocation_ref",
    "residual_risk_ref",
)


def _record(
    warrant: dict[str, Any] | None, context: dict[str, Any]
) -> tuple[RelianceRecord, datetime]:
    ctx = dict(context)
    now = datetime.fromisoformat(ctx.pop("evaluation_timestamp").replace("Z", "+00:00"))
    standing = WarrantStandingVerifier.verify_standing(
        Warrant(**warrant) if warrant is not None else None, context=ctx, now=now
    )
    record = RelianceRecord(
        norm_id=SHARED_WARRANT["norm_id"],
        required_governing_version=ctx["governing_version"],
        provider_name=_PROVIDER,
        standing=standing,
    )
    return record, now


def test_contract_field_mapping_names_the_seven_v01_evidence_fields() -> None:
    assert dict(WARRANT_CONTRACT_EVIDENCE_FIELDS) == {
        "warrant_id": "warrant_id",
        "norm_id": "norm_id",
        "digest": "warrant_digest",
        "reliance_status": "reliance_status",
        "governing_version": "warrant_governing_version",
        "residual_risk_ref": "residual_risk_ref",
        "attested_at": "attested_at",
    }


@pytest.mark.parametrize(("warrant", "context", "expected"), VEIP_V01_VECTORS)
def test_vector_record_carries_every_contract_field(
    warrant: dict[str, Any], context: dict[str, Any], expected: RelianceStatus
) -> None:
    record, now = _record(warrant, context)
    evidence = record.to_dict()

    contract = {
        name: evidence[key] for name, key in WARRANT_CONTRACT_EVIDENCE_FIELDS.items()
    }
    assert contract == {
        "warrant_id": "warrant-veip-2026-001",
        "norm_id": "confidence.min_trade_confidence",
        "digest": warrant["digest"],
        "reliance_status": expected.value,
        "governing_version": _WARRANT_GOVERNING_VERSION,
        "residual_risk_ref": _RESIDUAL_RISK_REF,
        "attested_at": now.isoformat(),
    }
    assert evidence["required_governing_version"] == context["governing_version"]
    assert evidence["issuing_authority"] == SHARED_WARRANT["issuing_authority"]
    assert evidence["authority_basis"] == SHARED_WARRANT["authority_basis"]
    assert evidence["revocation_ref"] == (warrant["revocation_ref"] or "")
    assert evidence["warrant_status"] == warrant["status"]
    assert evidence["provider_name"] == _PROVIDER
    assert evidence["verification_status"] == "UNVERIFIED"
    assert all(isinstance(value, str) for value in evidence.values())

    # The record's attributes are the evidence form's source, field for field.
    assert record.residual_risk_ref == _RESIDUAL_RISK_REF
    assert record.attested_at == now.isoformat()
    assert record.issuing_authority == SHARED_WARRANT["issuing_authority"]


@pytest.mark.parametrize(("warrant", "context", "expected"), VEIP_V01_VECTORS)
def test_vector_attestation_is_derived_from_the_record(
    warrant: dict[str, Any], context: dict[str, Any], expected: RelianceStatus
) -> None:
    record, now = _record(warrant, context)
    attestation = record.attestation()
    assert attestation is not None
    assert attestation.metadata == record.to_dict()
    assert attestation.attested_at == record.attested_at == now.isoformat()
    assert attestation.receipt_id == record.warrant_id
    assert attestation.provider_name == _PROVIDER
    assert attestation.status == "UNVERIFIED"


def test_vec_005_keeps_required_and_declared_versions_apart() -> None:
    (vec_005,) = [v for v in VEIP_V01_VECTORS if v.id == "VEC-005-VERSION-MISMATCH"]
    warrant, context, _ = vec_005.values
    record, _ = _record(warrant, context)
    assert record.reliance_status is RelianceStatus.INELIGIBLE_VERSION_MISMATCH
    assert record.required_governing_version == "cage-policy-9.9.9"
    assert record.warrant_governing_version == _WARRANT_GOVERNING_VERSION


def test_vec_006_reason_shows_distinguishable_full_digests() -> None:
    record, _ = _record(
        {**SHARED_WARRANT, "digest": VEIP_TAMPERED_DIGEST}, SHARED_CONTEXT
    )
    assert record.reliance_status is RelianceStatus.INELIGIBLE_UNRESOLVED
    assert VEIP_TAMPERED_DIGEST != VEIP_ACTIVE_DIGEST
    assert record.reason == (
        f"Cryptographic digest mismatch: declared {VEIP_TAMPERED_DIGEST} "
        f"vs computed {VEIP_ACTIVE_DIGEST}"
    )


def test_missing_record_is_explicitly_empty_on_the_warrant_side() -> None:
    record, now = _record(None, SHARED_CONTEXT)
    evidence = record.to_dict()
    assert evidence["reliance_status"] == "INELIGIBLE_MISSING"
    assert {key: evidence[key] for key in _WARRANT_DECLARED_KEYS} == dict.fromkeys(
        _WARRANT_DECLARED_KEYS, ""
    )
    assert evidence["norm_id"] == "confidence.min_trade_confidence"
    assert evidence["required_governing_version"] == _WARRANT_GOVERNING_VERSION
    assert evidence["attested_at"] == now.isoformat()  # standing is still evaluated
    assert set(WARRANT_CONTRACT_EVIDENCE_FIELDS.values()) <= set(evidence)
    assert record.attestation() is None


def test_undeclared_residual_risk_ref_is_empty_not_none() -> None:
    record, _ = _record(
        {
            **SHARED_WARRANT,
            "residual_risk_ref": None,
            "digest": Warrant.issue(
                **{**SHARED_WARRANT, "residual_risk_ref": None}
            ).digest,
        },
        SHARED_CONTEXT,
    )
    assert record.reliance_status is RelianceStatus.ELIGIBLE
    assert record.to_dict()["residual_risk_ref"] == ""


def test_record_is_frozen_and_its_contract_fields_are_read_only() -> None:
    record, _ = _record(SHARED_WARRANT, SHARED_CONTEXT)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.required_governing_version = "other"  # type: ignore[misc]
    for name in ("residual_risk_ref", "attested_at", "issuing_authority"):
        with pytest.raises(AttributeError):
            setattr(record, name, "forged")
