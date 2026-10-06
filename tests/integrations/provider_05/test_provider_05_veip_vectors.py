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
VEIP v0.1 six-vector interoperability suite.

Runs the VEIP-supplied vectors (CAGE_VEIP_v0.1_6_Test_Vectors, Aug 2026) through
the kernel ``WarrantStandingVerifier``. The declared digests are the values
VEIP published, pinned as literals: a change to canonicalization, field
spelling or scope shape on either side breaks interop and fails here.

Also pins the fail-closed regressions found when probing the verifier beyond
the six vectors (empty digest, incomplete context, malformed scope, mutation).
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Any

import pytest

from src.gateway.governance.warrant import (
    RelianceStatus,
    Warrant,
    WarrantStandingVerifier,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

# --- VEIP-published constants ------------------------------------------------

VEIP_ACTIVE_DIGEST = "b30bcf69de25d8b3e4e4f159d9c364df6488470f2035cfadf0e611cfa2e11fce"
VEIP_REVOKED_DIGEST = "fa18a43aaa7b5e452e98e19bc293ddd978a7d11a00713d95e0d358f133b3059a"
VEIP_TAMPERED_DIGEST = (
    "b30bcf69de25d8b3e4e4f159d9c364df6488470f2035cfadf0e611cfa2e11fc0"
)

SHARED_WARRANT: dict[str, Any] = {
    "warrant_id": "warrant-veip-2026-001",
    "norm_id": "confidence.min_trade_confidence",
    "issuing_authority": "Risk Oversight Committee (EU_ECB)",
    "authority_basis": "EU AI Act Art. 9 Risk Management Instrument #442",
    "scope": {
        "actions": ["execute_trade"],
        "actors": ["*"],
        "systems": ["cage-gateway"],
        "jurisdictions": ["EU_ECB"],
    },
    "valid_from": "2026-08-01T00:00:00Z",
    "valid_until": "2026-12-31T23:59:59Z",
    "governing_version": "cage-policy-2.1.0",
    "status": "ACTIVE",
    "revocation_ref": None,
    "residual_risk_ref": "RRR-2026-08-01-A1",
    "digest": VEIP_ACTIVE_DIGEST,
}

SHARED_CONTEXT: dict[str, Any] = {
    "action": "execute_trade",
    "jurisdiction": "EU_ECB",
    "governing_version": "cage-policy-2.1.0",
    "evaluation_timestamp": "2026-08-22T12:00:00Z",
    "model_confidence": 0.98,
}


def _vector(
    vector_id: str,
    expected: RelianceStatus,
    warrant_delta: dict[str, Any] | None = None,
    context_delta: dict[str, Any] | None = None,
) -> Any:
    return pytest.param(
        {**SHARED_WARRANT, **(warrant_delta or {})},
        {**SHARED_CONTEXT, **(context_delta or {})},
        expected,
        id=vector_id,
    )


VEIP_V01_VECTORS = [
    _vector("VEC-001-ACTIVE", RelianceStatus.ELIGIBLE),
    _vector(
        "VEC-002-REVOKED",
        RelianceStatus.INELIGIBLE_REVOKED,
        warrant_delta={
            "status": "REVOKED",
            "revocation_ref": "Emergency Risk Notice #912",
            "digest": VEIP_REVOKED_DIGEST,
        },
    ),
    _vector(
        "VEC-003-EXPIRED",
        RelianceStatus.INELIGIBLE_EXPIRED,
        context_delta={"evaluation_timestamp": "2027-01-15T00:00:00Z"},
    ),
    _vector(
        "VEC-004-OUT-OF-SCOPE",
        RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
        context_delta={"action": "unauthorized_wire_action"},
    ),
    _vector(
        "VEC-005-VERSION-MISMATCH",
        RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
        context_delta={"governing_version": "cage-policy-9.9.9"},
    ),
    _vector(
        "VEC-006-TAMPERED-DIGEST",
        RelianceStatus.INELIGIBLE_UNRESOLVED,
        warrant_delta={"digest": VEIP_TAMPERED_DIGEST},
    ),
]


def _evaluate(warrant: dict[str, Any] | None, context: dict[str, Any]):
    ctx = dict(context)
    now = datetime.fromisoformat(
        ctx.pop("evaluation_timestamp", "2026-08-22T12:00:00Z").replace("Z", "+00:00")
    )
    w = Warrant(**warrant) if warrant is not None else None
    return WarrantStandingVerifier.verify_standing(w, context=ctx, now=now)


# --- Interop: the six VEIP vectors -------------------------------------------


@pytest.mark.parametrize(("warrant", "context", "expected"), VEIP_V01_VECTORS)
def test_veip_v01_vector(
    warrant: dict[str, Any], context: dict[str, Any], expected: RelianceStatus
) -> None:
    result = _evaluate(warrant, context)
    assert result.reliance_status == expected, result.reason
    assert result.eligible is (expected == RelianceStatus.ELIGIBLE)
    assert result.warrant_digest == warrant["digest"]


@pytest.mark.parametrize(
    ("delta", "published"),
    [
        pytest.param({}, VEIP_ACTIVE_DIGEST, id="ACTIVE"),
        pytest.param(
            {"status": "REVOKED", "revocation_ref": "Emergency Risk Notice #912"},
            VEIP_REVOKED_DIGEST,
            id="REVOKED",
        ),
    ],
)
def test_canonical_digest_reproduces_veip_published_value(
    delta: dict[str, Any], published: str
) -> None:
    """CAGE's RFC 8785 bytes must hash to exactly what VEIP published."""
    fields = {**SHARED_WARRANT, **delta, "digest": ""}
    assert Warrant(**fields).compute_digest() == published


def test_missing_warrant_is_ineligible() -> None:
    """Contract state MISSING (no VEIP vector): no warrant, no reliance."""
    result = _evaluate(None, SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_MISSING
    assert result.eligible is False


# --- Fail-closed regressions -------------------------------------------------


@pytest.mark.parametrize(
    "warrant_delta",
    [
        pytest.param({"digest": ""}, id="empty-digest"),
        pytest.param(
            {"digest": "", "issuing_authority": "Self-issued by domain plugin"},
            id="self-issued-no-digest",
        ),
        pytest.param(
            {"issuing_authority": "Self-issued by domain plugin"}, id="field-tampered"
        ),
    ],
)
def test_integrity_cannot_be_back_filled(warrant_delta: dict[str, Any]) -> None:
    result = _evaluate({**SHARED_WARRANT, **warrant_delta}, SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


@pytest.mark.parametrize("missing_key", ["action", "jurisdiction", "governing_version"])
def test_incomplete_context_is_unresolved_not_in_scope(missing_key: str) -> None:
    context = {k: v for k, v in SHARED_CONTEXT.items() if k != missing_key}
    result = _evaluate(SHARED_WARRANT, context)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED
    assert missing_key in result.reason


def test_empty_context_is_unresolved() -> None:
    result = _evaluate(SHARED_WARRANT, {"evaluation_timestamp": "2026-08-22T12:00:00Z"})
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


@pytest.mark.parametrize("dropped", ["actions", "actors", "systems", "jurisdictions"])
def test_scope_dimension_is_never_inferred(dropped: str) -> None:
    """Q4: CAGE must not infer jurisdictional (or any) coverage."""
    scope = {k: v for k, v in SHARED_WARRANT["scope"].items() if k != dropped}
    issued = Warrant.issue(**{**SHARED_WARRANT, "scope": scope})
    result = WarrantStandingVerifier.verify_standing(
        issued,
        context={
            k: v for k, v in SHARED_CONTEXT.items() if k != "evaluation_timestamp"
        },
        now=datetime(2026, 8, 22, 12, tzinfo=timezone.utc),
    )
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED
    assert "scope malformed" in result.reason


def test_other_jurisdiction_is_out_of_scope() -> None:
    result = _evaluate(SHARED_WARRANT, {**SHARED_CONTEXT, "jurisdiction": "US_FED"})
    assert result.reliance_status == RelianceStatus.INELIGIBLE_OUT_OF_SCOPE


def test_unknown_status_is_unresolved() -> None:
    issued = Warrant.issue(**{**SHARED_WARRANT, "status": "SUPERSEDED"})
    result = _evaluate(issued.to_dict(), SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


def test_naive_evaluation_time_is_unresolved() -> None:
    w = Warrant(**SHARED_WARRANT)
    ctx = {k: v for k, v in SHARED_CONTEXT.items() if k != "evaluation_timestamp"}
    result = WarrantStandingVerifier.verify_standing(
        w, ctx, now=datetime(2026, 8, 22, 12)
    )
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("2026-08-01T00:00:00Z", RelianceStatus.ELIGIBLE),
        ("2026-12-31T23:59:59Z", RelianceStatus.ELIGIBLE),
        ("2026-07-31T23:59:59Z", RelianceStatus.INELIGIBLE_EXPIRED),
        ("2027-01-01T00:00:00Z", RelianceStatus.INELIGIBLE_EXPIRED),
    ],
)
def test_validity_window_is_inclusive(timestamp: str, expected: RelianceStatus) -> None:
    result = _evaluate(
        SHARED_WARRANT, {**SHARED_CONTEXT, "evaluation_timestamp": timestamp}
    )
    assert result.reliance_status == expected


def test_warrant_is_immutable_after_verification() -> None:
    w = Warrant(**SHARED_WARRANT)
    with pytest.raises(dataclasses.FrozenInstanceError):
        w.status = "REVOKED"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        w.scope.jurisdictions = ("*",)  # type: ignore[misc, union-attr]
