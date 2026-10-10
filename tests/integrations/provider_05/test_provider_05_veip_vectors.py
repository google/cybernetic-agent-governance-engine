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


# --- VEIP v0.2 Eight-Scenario Conformance Suite ------------------------------

import json  # noqa: E402
from pathlib import Path  # noqa: E402

from src.gateway.governance.warrant import (  # noqa: E402
    KeyManifestVerificationError,
    RelianceRecord,
    StandingVerificationResult,
    VerifiedKeyManifest,
    WarrantCache,
    WarrantTrustAnchor,
)
from src.integrations.provider_05 import (  # noqa: E402
    VEIP_SANDBOX_ROOT_FINGERPRINT,
    VEIP_SANDBOX_ROOT_KID,
    VEIP_SANDBOX_ROOT_PUBLIC_KEY_B64,
    VEIP_SANDBOX_TRUST_ANCHOR,
    Provider05WarrantSource,
)

_V02_DIR = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "partners"
    / "provider_05"
    / "veip_v02"
)
VEIP_V02_KEY_MANIFEST: dict[str, Any] = json.loads(
    (_V02_DIR / "key_manifest.json").read_text(encoding="utf-8")
)
VEIP_V02_WARRANTS: dict[str, dict[str, Any]] = json.loads(
    (_V02_DIR / "warrants_v02_vectors.json").read_text(encoding="utf-8")
)
VEIP_V02_EVAL_TIME = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)
VEIP_V02_CONTEXT: dict[str, Any] = {
    "action": "execute_trade",
    "jurisdiction": "EU_ECB",
    "governing_version": "cage-policy-2.1.0",
    "norm_value": 0.97,
    "actor": "agent:governed_financial_advisor",
    "system": "cage-gateway",
}

VEIP_V02_SCENARIOS = [
    pytest.param(
        "ACTIVE",
        RelianceStatus.ELIGIBLE,
        "VERIFIED",
        "eligible for reliance",
        id="V02-ACTIVE",
    ),
    pytest.param(
        "REVOKED",
        RelianceStatus.INELIGIBLE_REVOKED,
        "VERIFIED",
        "Emergency Risk Notice #912",
        id="V02-REVOKED",
    ),
    pytest.param(
        "SUSPENDED",
        RelianceStatus.INELIGIBLE_UNRESOLVED,
        "VERIFIED",
        "Temporary Suspension #S-17",
        id="V02-SUSPENDED",
    ),
    pytest.param(
        "EXPIRED",
        RelianceStatus.INELIGIBLE_EXPIRED,
        "VERIFIED",
        "temporal window invalid",
        id="V02-EXPIRED",
    ),
    pytest.param(
        "STALE_STATE",
        RelianceStatus.INELIGIBLE_STALE,
        "VERIFIED",
        "state_as_of stale",
        id="V02-STALE_STATE",
    ),
    pytest.param(
        "TAMPERED_SIGNATURE",
        RelianceStatus.INELIGIBLE_UNRESOLVED,
        "UNVERIFIED",
        "SIGNATURE_INVALID",
        id="V02-TAMPERED_SIGNATURE",
    ),
    pytest.param(
        "UNKNOWN_KID",
        RelianceStatus.INELIGIBLE_UNRESOLVED,
        "UNVERIFIED",
        "UNKNOWN_KID",
        id="V02-UNKNOWN_KID",
    ),
    pytest.param(
        "MISSING",
        RelianceStatus.INELIGIBLE_MISSING,
        "UNVERIFIED",
        "Warrant is missing",
        id="V02-MISSING",
    ),
]


def test_veip_v02_key_manifest_verifies_against_out_of_band_root_anchor() -> None:
    assert VEIP_SANDBOX_TRUST_ANCHOR.fingerprint == VEIP_SANDBOX_ROOT_FINGERPRINT
    manifest = VerifiedKeyManifest.verify(
        VEIP_V02_KEY_MANIFEST,
        VEIP_SANDBOX_TRUST_ANCHOR,
        now=VEIP_V02_EVAL_TIME,
    )
    assert manifest.manifest_id == "veip-sandbox-manifest-2026-10-07"
    assert (
        manifest.manifest_digest
        == "fa6c4e0c1d03a6f760792738c2de00fc6f6c2d4fea7455098981986a91744b6d"
    )
    entry = manifest.resolve_key("veip-sandbox-issuer-2026-10")
    assert entry is not None
    assert entry.is_active_at(VEIP_V02_EVAL_TIME)


@pytest.mark.parametrize(
    ("scenario", "expected_status", "expected_verified", "reason_substring"),
    VEIP_V02_SCENARIOS,
)
def test_veip_v02_scenario_vector(
    scenario: str,
    expected_status: RelianceStatus,
    expected_verified: str,
    reason_substring: str,
) -> None:
    manifest = VerifiedKeyManifest.verify(
        VEIP_V02_KEY_MANIFEST,
        VEIP_SANDBOX_TRUST_ANCHOR,
        now=VEIP_V02_EVAL_TIME,
    )
    raw_warrant = VEIP_V02_WARRANTS.get(scenario)
    warrant = Warrant(**raw_warrant) if raw_warrant is not None else None
    result = WarrantStandingVerifier.verify_standing(
        warrant,
        context=VEIP_V02_CONTEXT,
        now=VEIP_V02_EVAL_TIME,
        key_manifest=manifest,
        max_age_seconds=60.0,
    )
    assert result.reliance_status is expected_status, result.reason
    assert result.eligible is (expected_status is RelianceStatus.ELIGIBLE)
    assert result.verification_status == expected_verified
    assert reason_substring in result.reason

    record = RelianceRecord(
        norm_id="confidence.min_trade_confidence",
        required_governing_version="cage-policy-2.1.0",
        provider_name="provider_05_warrant",
        standing=result,
    )
    assert record.verification_status == expected_verified
    assert record.to_dict()["verification_status"] == expected_verified
    att = record.attestation()
    if warrant is None:
        assert att is None
    else:
        assert att is not None
        assert att.status == expected_verified


def test_veip_v02_trust_anchor_type_system_invariants() -> None:
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        WarrantTrustAnchor(
            root_kid=VEIP_SANDBOX_ROOT_KID,
            public_key_b64=VEIP_SANDBOX_ROOT_PUBLIC_KEY_B64,
            expected_fingerprint="sha256:" + "0" * 64,
        )

    with pytest.raises(TypeError, match="cannot be instantiated directly"):
        VerifiedKeyManifest(
            schema_version="veip-key-manifest/0.2",
            environment="SANDBOX",
            manifest_id="m",
            issuer="Veraxis",
            generated_at="2026-10-07T14:00:00Z",
            valid_until="2026-11-07T14:00:00Z",
            root_kid=VEIP_SANDBOX_ROOT_KID,
            manifest_digest="0" * 64,
            signature="sig",
            keys={},
            anchor_fingerprint=VEIP_SANDBOX_ROOT_FINGERPRINT,
        )

    w_v02 = Warrant(**VEIP_V02_WARRANTS["ACTIVE"])
    with pytest.raises(TypeError, match="must be a VerifiedKeyManifest"):
        WarrantStandingVerifier.verify_standing(
            w_v02,
            context=VEIP_V02_CONTEXT,
            now=VEIP_V02_EVAL_TIME,
            key_manifest=VEIP_V02_KEY_MANIFEST,  # type: ignore[arg-type]
        )

    # v0.2 warrant without a key manifest fails closed as UNVERIFIED
    no_manifest = WarrantStandingVerifier.verify_standing(
        w_v02, context=VEIP_V02_CONTEXT, now=VEIP_V02_EVAL_TIME
    )
    assert no_manifest.reliance_status is RelianceStatus.INELIGIBLE_UNRESOLVED
    assert no_manifest.verification_status == "UNVERIFIED"

    # Downgrade protection: unsigned v0.1 warrant rejected when key_manifest is active
    manifest = VerifiedKeyManifest.verify(
        VEIP_V02_KEY_MANIFEST,
        VEIP_SANDBOX_TRUST_ANCHOR,
        now=VEIP_V02_EVAL_TIME,
    )
    downgraded = WarrantStandingVerifier.verify_standing(
        Warrant(**SHARED_WARRANT),
        context=VEIP_V02_CONTEXT,
        now=VEIP_V02_EVAL_TIME,
        key_manifest=manifest,
    )
    assert downgraded.reliance_status is RelianceStatus.INELIGIBLE_UNRESOLVED
    assert downgraded.verification_status == "UNVERIFIED"
    assert "Unsigned v0.1 warrant rejected" in downgraded.reason

    # Tampered key manifest signature is rejected at verification
    tampered_manifest = {
        **VEIP_V02_KEY_MANIFEST,
        "signature": "A" + VEIP_V02_KEY_MANIFEST["signature"][1:],
    }
    with pytest.raises(KeyManifestVerificationError, match="signature verification"):
        VerifiedKeyManifest.verify(
            tampered_manifest,
            VEIP_SANDBOX_TRUST_ANCHOR,
            now=VEIP_V02_EVAL_TIME,
        )

    # StandingVerificationResult refuses forged VERIFIED status on unsigned warrant
    with pytest.raises(ValueError, match="cannot claim VERIFIED"):
        StandingVerificationResult(
            eligible=True,
            reliance_status=RelianceStatus.ELIGIBLE,
            reason="forged",
            attested_at=VEIP_V02_EVAL_TIME.isoformat(),
            warrant=Warrant(**SHARED_WARRANT),
            warrant_id="warrant-veip-2026-001",
            warrant_digest=VEIP_ACTIVE_DIGEST,
            verification_status="VERIFIED",
        )


@pytest.mark.asyncio
async def test_veip_v02_cache_resolves_and_caches_verified_key_manifest() -> None:
    source = Provider05WarrantSource()
    source.seed_key_manifest(VEIP_V02_KEY_MANIFEST)
    source.seed(Warrant(**VEIP_V02_WARRANTS["ACTIVE"]))
    cache = WarrantCache(source, wall_clock=lambda: VEIP_V02_EVAL_TIME)
    obs = await cache.observe("confidence.min_trade_confidence")
    assert obs.fresh
    assert obs.warrant is not None and obs.warrant.is_v02
    assert isinstance(obs.key_manifest, VerifiedKeyManifest)
    assert obs.manifest_error == ""
