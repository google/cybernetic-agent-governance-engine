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
VEIP v0.3 Pre-Implementation Review Package & 29-Row Vector Conformance Suite.

Verifies:
  1. SHA-256 integrity of the deposited review package in
     ``docs/partners/provider_05/veip_v03/MANIFEST.sha256``.
  2. JSON Schema compliance of ``RiskAcceptanceRecord.to_v03_dict()``,
     ``AdmissibilityGrant.to_v03_dict()``, and
     ``SubstrateAttestation.to_v03_dict()`` against the three v0.3 proposed
     schemas.
  3. All 29 expected-outcome rows in ``EXPECTED_OUTCOME_VECTORS.csv``:
     - 5 WARRANT rows (VERSION_MISMATCH, OUT_OF_SCOPE, UNRESOLVED,
       POST_HITL_STEP_1, POST_HITL_STEP_2_RETAINED)
     - 8 BLUEPRINT rows (VALID, WRONG_PURPOSE, WRONG_KID, EXPIRED, STALE,
       OUT_OF_SCOPE, BAD_SIGNATURE, MISSING)
     - 8 KEY rows (VALID, WRONG_PURPOSE, WRONG_KID, EXPIRED, STALE,
       OUT_OF_SCOPE, BAD_SIGNATURE, MISSING)
     - 8 PHYSICS rows (VALID, WRONG_PURPOSE, WRONG_KID, EXPIRED, STALE,
       OUT_OF_SCOPE, BAD_SIGNATURE, MISSING)
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.gateway.governance.governance_envelope import AttestationStatus
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.warrant import (
    MANIFEST_SCHEMA_VERSION_V03,
    RelianceStatus,
    VerifiedKeyManifest,
    Warrant,
    WarrantScope,
    WarrantStandingVerifier,
    WarrantStatus,
    WarrantTrustAnchor,
)
from src.integrations.provider_05 import (
    BLUEPRINT_SCHEMA_VERSION_V03,
    KEY_SCHEMA_VERSION_V03,
    PHYSICS_SCHEMA_VERSION_V03,
    AdmissibilityGrant,
    Provider05BlueprintProvider,
    Provider05Client,
    Provider05KeyProvider,
    Provider05PhysicsProvider,
    RiskAcceptanceRecord,
    SubstrateAttestation,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VEIP_V03_DIR = _REPO_ROOT / "docs" / "partners" / "provider_05" / "veip_v03"
_PINNED_NOW = datetime(2026, 10, 19, 12, 0, 15, tzinfo=timezone.utc)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _raw_pub_b64u(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64u(raw)


@pytest.fixture(scope="module")
def v03_pki() -> dict[str, Any]:
    """Generate deterministic Ed25519 root and purpose-separated issuer keys for v0.3."""
    root_priv = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
    warrant_priv = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
    blueprint_priv = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
    key_priv = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)
    physics_priv = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)

    root_raw = root_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    root_fp = f"sha256:{hashlib.sha256(root_raw).hexdigest()}"
    trust_anchor = WarrantTrustAnchor(
        root_kid="veip-sandbox-manifest-root-2026-10",
        public_key_b64=_b64u(root_raw),
        expected_fingerprint=root_fp,
    )

    unsigned_manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION_V03,
        "environment": "SANDBOX",
        "manifest_id": "veip-manifest-v03-2026-10-19",
        "issuer": "urn:veraxis:veip:sandbox",
        "generated_at": "2026-10-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "root_kid": "veip-sandbox-manifest-root-2026-10",
        "keys": [
            {
                "kid": "veip-v03-warrant-2026-10",
                "alg": "Ed25519",
                "public_key_b64u": _raw_pub_b64u(warrant_priv),
                "status": "ACTIVE",
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "purpose": "WARRANT",
            },
            {
                "kid": "veip-v03-blueprint-2026-10",
                "alg": "Ed25519",
                "public_key_b64u": _raw_pub_b64u(blueprint_priv),
                "status": "ACTIVE",
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "purpose": "BLUEPRINT",
            },
            {
                "kid": "veip-v03-key-2026-10",
                "alg": "Ed25519",
                "public_key_b64u": _raw_pub_b64u(key_priv),
                "status": "ACTIVE",
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "purpose": "KEY",
            },
            {
                "kid": "veip-v03-physics-2026-10",
                "alg": "Ed25519",
                "public_key_b64u": _raw_pub_b64u(physics_priv),
                "status": "ACTIVE",
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "purpose": "PHYSICS",
            },
        ],
    }
    manifest_digest = hashlib.sha256(
        jcs_canonicalize_plan(unsigned_manifest)
    ).hexdigest()
    signed_manifest_body = {**unsigned_manifest, "manifest_digest": manifest_digest}
    manifest_sig = _b64u(root_priv.sign(jcs_canonicalize_plan(signed_manifest_body)))
    raw_manifest = {**signed_manifest_body, "signature": manifest_sig}
    verified_manifest = VerifiedKeyManifest.verify(
        raw_manifest, trust_anchor, now=_PINNED_NOW
    )

    return {
        "trust_anchor": trust_anchor,
        "verified_manifest": verified_manifest,
        "warrant_priv": warrant_priv,
        "blueprint_priv": blueprint_priv,
        "key_priv": key_priv,
        "physics_priv": physics_priv,
    }


def _default_scope() -> dict[str, list[str]]:
    return {
        "actions": ["treasury_transfer", "execute_treasury_transfer"],
        "actors": ["spiffe://cage.local/treasury-agent"],
        "systems": ["gke-node-us-central1-01"],
        "jurisdictions": ["US_FED"],
    }


def _sign_v03_record(record: Any, priv: Ed25519PrivateKey) -> Any:
    record.digest = record.compute_digest()
    record.signature = _b64u(priv.sign(record.to_signed_bytes()))
    return record


def _make_signed_warrant(
    priv: Ed25519PrivateKey,
    *,
    kid: str = "veip-v03-warrant-2026-10",
    governing_version: str = "2026.10.v1",
) -> Warrant:
    unsigned = Warrant(
        warrant_id="veip-warrant-v03-001",
        norm_id="FINRA.4511.RECORD_RETENTION",
        issuing_authority="urn:veraxis:veip:sandbox",
        authority_basis="Board Resolution 2026-Q4",
        governing_version=governing_version,
        status=WarrantStatus.ACTIVE,
        scope=WarrantScope.from_dict(_default_scope()),
        valid_from="2026-10-19T00:00:00Z",
        valid_until="2026-10-20T00:00:00Z",
        schema_version="veip-warrant/0.2",
        environment="SANDBOX",
        issued_at="2026-10-19T12:00:00Z",
        state_as_of="2026-10-19T12:00:00Z",
        norm_parameters={"RECORD_RETENTION": {"value": 10000}},
        alg="Ed25519",
        kid=kid,
    )
    digest = unsigned.compute_digest()
    with_digest = Warrant(**{**unsigned.to_dict(), "digest": digest})
    sig = _b64u(priv.sign(with_digest.to_signed_bytes()))
    return Warrant(**{**with_digest.to_dict(), "signature": sig})


def test_deposited_veip_v03_package_manifest_sha256() -> None:
    """Verify every file in docs/partners/provider_05/veip_v03/ matches MANIFEST.sha256."""
    manifest_path = _VEIP_V03_DIR / "MANIFEST.sha256"
    assert manifest_path.is_file()
    entries = [
        line.strip().split()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(entries) == 7
    for expected_sha, filename in entries:
        file_path = _VEIP_V03_DIR / filename
        assert file_path.is_file(), f"Missing {filename}"
        actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
        assert actual_sha == expected_sha, f"SHA-256 mismatch for {filename}"


def test_veip_v03_proposed_json_schemas_validate_models(
    v03_pki: dict[str, Any],
) -> None:
    """Verify RiskAcceptanceRecord, AdmissibilityGrant, and SubstrateAttestation match v0.3 JSON Schemas."""
    bp_schema = json.loads(
        (
            _VEIP_V03_DIR / "BLUEPRINT_RiskAcceptanceRecord_PROPOSED_SCHEMA.json"
        ).read_text(encoding="utf-8")
    )
    key_schema = json.loads(
        (_VEIP_V03_DIR / "KEY_AdmissibilityGrant_PROPOSED_SCHEMA.json").read_text(
            encoding="utf-8"
        )
    )
    phys_schema = json.loads(
        (_VEIP_V03_DIR / "PHYSICS_SubstrateAttestation_PROPOSED_SCHEMA.json").read_text(
            encoding="utf-8"
        )
    )

    bp = _sign_v03_record(
        RiskAcceptanceRecord(
            schema_version=BLUEPRINT_SCHEMA_VERSION_V03,
            environment="SANDBOX",
            artifact_id="veip-bp-001",
            issuer="urn:veraxis:veip:sandbox",
            subject_ref="THR-FIN-006",
            scope=_default_scope(),
            issued_at="2026-10-19T12:00:00Z",
            valid_from="2026-10-19T00:00:00Z",
            valid_until="2026-10-20T00:00:00Z",
            state_as_of="2026-10-19T12:00:00Z",
            alg="Ed25519",
            kid="veip-v03-blueprint-2026-10",
            risk_id="THR-FIN-006",
            accepted_by="Jane Doe, CISO / AO",
            risk_limit="10000.0",
        ),
        v03_pki["blueprint_priv"],
    )
    jsonschema.validate(instance=bp.to_v03_dict(), schema=bp_schema)

    grant = _sign_v03_record(
        AdmissibilityGrant(
            schema_version=KEY_SCHEMA_VERSION_V03,
            environment="SANDBOX",
            artifact_id="veip-key-001",
            issuer="urn:veraxis:veip:sandbox",
            subject_ref="spiffe://cage.local/treasury-agent",
            scope=_default_scope(),
            issued_at="2026-10-19T12:00:00Z",
            valid_from="2026-10-19T00:00:00Z",
            valid_until="2026-10-20T00:00:00Z",
            state_as_of="2026-10-19T12:00:00Z",
            alg="Ed25519",
            kid="veip-v03-key-2026-10",
            grant_id="grant-4412",
            authority_basis_ref="sha256:a1b2c3d4",
            permitted_action="treasury_transfer",
        ),
        v03_pki["key_priv"],
    )
    jsonschema.validate(instance=grant.to_v03_dict(), schema=key_schema)

    phys = _sign_v03_record(
        SubstrateAttestation(
            schema_version=PHYSICS_SCHEMA_VERSION_V03,
            environment="SANDBOX",
            artifact_id="veip-phys-001",
            issuer="urn:veraxis:veip:sandbox",
            subject_ref="gke-node-us-central1-01",
            scope=_default_scope(),
            issued_at="2026-10-19T12:00:00Z",
            valid_from="2026-10-19T00:00:00Z",
            valid_until="2026-10-20T00:00:00Z",
            state_as_of="2026-10-19T12:00:00Z",
            alg="Ed25519",
            kid="veip-v03-physics-2026-10",
            substrate_id="gke-node-us-central1-01",
            attestation_result="PASS",
            measurement_ref="pcr0:99aa",
        ),
        v03_pki["physics_priv"],
    )
    jsonschema.validate(instance=phys.to_v03_dict(), schema=phys_schema)


@pytest.mark.asyncio
async def test_all_29_expected_outcome_vectors_csv(
    v03_pki: dict[str, Any],
) -> None:
    """Execute all 29 rows from EXPECTED_OUTCOME_VECTORS.csv and assert exact status parity."""
    csv_path = _VEIP_V03_DIR / "EXPECTED_OUTCOME_VECTORS.csv"
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 29

    manifest: VerifiedKeyManifest = v03_pki["verified_manifest"]
    base_ctx = {
        "action": "treasury_transfer",
        "jurisdiction": "US_FED",
        "actor": "spiffe://cage.local/treasury-agent",
        "system": "gke-node-us-central1-01",
        "governing_version": "2026.10.v1",
        "norm_value": 10000,
        "now": _PINNED_NOW,
    }

    for row in rows:
        vec_id = row["id"]
        ev_class = row["evidence_class"]
        expected_status = row["expected_status"]

        if ev_class == "WARRANT":
            warrant = _make_signed_warrant(v03_pki["warrant_priv"])
            ctx = dict(base_ctx)
            if vec_id == "VERSION_MISMATCH":
                ctx["governing_version"] = "2025.01.legacy"
            elif vec_id == "OUT_OF_SCOPE":
                ctx["jurisdiction"] = "APAC_SG"
            elif vec_id == "UNRESOLVED":
                ctx.pop("jurisdiction")
            elif vec_id in ("POST_HITL_STEP_1", "POST_HITL_STEP_2_RETAINED"):
                # Both initial HITL release check and retained re-verification
                # evaluate the current warrant against the same identity & scope
                pass

            res = WarrantStandingVerifier.verify_standing(
                warrant,
                ctx,
                now=_PINNED_NOW,
                key_manifest=manifest,
            )
            assert res.reliance_status.value == expected_status, (
                f"Vector {vec_id}: expected {expected_status}, got {res.reliance_status.value}"
            )
            gateway_outcome = "ALLOW" if res.eligible else "DEFER"
            assert gateway_outcome == row["expected_gateway"]
            continue

        # Build v0.3 BLUEPRINT, KEY, or PHYSICS test case
        client = Provider05Client(key_manifest=manifest)
        ctx = dict(base_ctx)
        suffix = vec_id.split("_", 1)[1]

        kid_map = {
            "BLUEPRINT": ("veip-v03-blueprint-2026-10", v03_pki["blueprint_priv"]),
            "KEY": ("veip-v03-key-2026-10", v03_pki["key_priv"]),
            "PHYSICS": ("veip-v03-physics-2026-10", v03_pki["physics_priv"]),
        }
        wrong_purpose_map = {
            "BLUEPRINT": ("veip-v03-key-2026-10", v03_pki["key_priv"]),
            "KEY": ("veip-v03-physics-2026-10", v03_pki["physics_priv"]),
            "PHYSICS": ("veip-v03-blueprint-2026-10", v03_pki["blueprint_priv"]),
        }

        kid, priv = kid_map[ev_class]
        valid_from = "2026-10-19T00:00:00Z"
        valid_until = "2026-10-20T00:00:00Z"
        state_as_of = "2026-10-19T12:00:00Z"

        if suffix == "WRONG_PURPOSE":
            kid, priv = wrong_purpose_map[ev_class]
        elif suffix == "WRONG_KID":
            kid = "veip-v03-unknown-kid-9999"
        elif suffix == "EXPIRED":
            valid_from = "2026-10-18T00:00:00Z"
            valid_until = "2026-10-19T11:00:00Z"
        elif suffix == "STALE":
            state_as_of = "2026-10-19T11:55:00Z"  # 315s old > 60s max
        elif suffix == "OUT_OF_SCOPE":
            ctx["jurisdiction"] = "EU_DORA"

        if suffix != "MISSING":
            if ev_class == "BLUEPRINT":
                rec = _sign_v03_record(
                    RiskAcceptanceRecord(
                        schema_version=BLUEPRINT_SCHEMA_VERSION_V03,
                        environment="SANDBOX",
                        artifact_id=f"bp-{vec_id.lower()}",
                        issuer="urn:veraxis:veip:sandbox",
                        subject_ref="THR-FIN-006",
                        scope=_default_scope(),
                        issued_at="2026-10-19T12:00:00Z",
                        valid_from=valid_from,
                        valid_until=valid_until,
                        state_as_of=state_as_of,
                        alg="Ed25519",
                        kid=kid,
                        risk_id="THR-FIN-006",
                        accepted_by="Jane Doe, CISO / AO",
                        risk_limit="10000.0",
                    ),
                    priv,
                )
                if suffix == "BAD_SIGNATURE":
                    rec.signature = _b64u(b"\x00" * 64)
                client.seed_risk_acceptance(rec)
            elif ev_class == "KEY":
                grant = _sign_v03_record(
                    AdmissibilityGrant(
                        schema_version=KEY_SCHEMA_VERSION_V03,
                        environment="SANDBOX",
                        artifact_id=f"key-{vec_id.lower()}",
                        issuer="urn:veraxis:veip:sandbox",
                        subject_ref="spiffe://cage.local/treasury-agent",
                        scope=_default_scope(),
                        issued_at="2026-10-19T12:00:00Z",
                        valid_from=valid_from,
                        valid_until=valid_until,
                        state_as_of=state_as_of,
                        alg="Ed25519",
                        kid=kid,
                        grant_id="grant-001",
                        authority_basis_ref="sha256:a1b2c3d4",
                        permitted_action="treasury_transfer",
                    ),
                    priv,
                )
                if suffix == "BAD_SIGNATURE":
                    grant.signature = _b64u(b"\x00" * 64)
                client.seed_admissibility_grant(grant)
            elif ev_class == "PHYSICS":
                att = _sign_v03_record(
                    SubstrateAttestation(
                        schema_version=PHYSICS_SCHEMA_VERSION_V03,
                        environment="SANDBOX",
                        artifact_id=f"phys-{vec_id.lower()}",
                        issuer="urn:veraxis:veip:sandbox",
                        subject_ref="gke-node-us-central1-01",
                        scope=_default_scope(),
                        issued_at="2026-10-19T12:00:00Z",
                        valid_from=valid_from,
                        valid_until=valid_until,
                        state_as_of=state_as_of,
                        alg="Ed25519",
                        kid=kid,
                        substrate_id="gke-node-us-central1-01",
                        attestation_result="PASS",
                        measurement_ref="pcr0:99aa",
                    ),
                    priv,
                )
                if suffix == "BAD_SIGNATURE":
                    att.signature = _b64u(b"\x00" * 64)
                client.seed_substrate_attestation(att)

        provider: Any
        if ev_class == "BLUEPRINT":
            provider = Provider05BlueprintProvider(client=client)
        elif ev_class == "KEY":
            provider = Provider05KeyProvider(client=client)
        else:
            provider = Provider05PhysicsProvider(client=client)

        attestations = await provider.fetch_attestations(ctx)
        assert len(attestations) == 1
        entry = attestations[0]
        assert entry.metadata["veip_v03_status"] == expected_status, (
            f"Vector {vec_id}: expected {expected_status}, got {entry.metadata}"
        )
        assert entry.metadata["reason_code"] == suffix, (
            f"Vector {vec_id}: expected reason_code {suffix}, got {entry.metadata['reason_code']}"
        )
        if expected_status == "ACCEPT":
            assert entry.status == AttestationStatus.VERIFIED.value
        else:
            assert entry.status in (
                AttestationStatus.DENIED.value,
                AttestationStatus.STALE.value,
            )
