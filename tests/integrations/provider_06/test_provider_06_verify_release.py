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

"""Phase 2 tests for Provider06AgentIntegrityAdapter POST /v1/verify-release & FileJWKSClient.

Validates:
- FileJWKSClient detached Ed25519 authority signature verification over
  CageReceiptTrustManifestV1, monotonic anti-rollback persistence, and per-key
  revocation/expiry enforcement.
- Length-prefixed HMAC-SHA256 request authentication headers.
- POST /v1/verify-release exact-byte release verification for PASS outcomes.
- Signed refusal preservation for REVIEW, BLOCKED, and RELEASE_REFUSED outcomes.
- Fail-closed handling of phase-safe non-200 TechnicalErrorResponse payloads.
- SidecarHealthCheck.check_readiness_detail() 503 reason & Retry-After parsing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.integrations.provider_06.adapter import (
    FINDING_CODE_ENDPOINT_ERROR,
    FINDING_CODE_RELEASE_REFUSED,
    FINDING_CODE_RELEASED_BYTES_MISMATCH,
    FINDING_CODE_REVIEW_PENDING,
    PROTOCOL_VERSION,
    SIDECAR_PROTOCOL_VERSION,
    VERIFY_RELEASE_PATH,
    Provider06AgentIntegrityAdapter,
    VerifyReleaseStatus,
    compute_sidecar_auth_headers,
    encode_sidecar_auth_input,
    extract_integrity_status,
    is_review_pending,
)
from src.integrations.provider_06.jwks_client import (
    CAGE_MANIFEST_EXTENSION_URI,
    MANIFEST_SIGNATURE_DOMAIN,
    FileJWKSClient,
)
from src.integrations.provider_06.lifecycle import SidecarHealthCheck

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_signed_trust_manifest(
    *,
    authority_sk: Ed25519PrivateKey,
    receipt_sk: Ed25519PrivateKey,
    kid: str = "cage-receipt-ed25519-2026-04",
    authority_kid: str = "cage-manifest-authority-2026-04",
    generation: int = 1,
    issued_at: str | None = None,
    valid_until: str | None = None,
    revoked_at: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    issued_str = issued_at or _iso_utc(now - timedelta(minutes=5))
    valid_str = valid_until or _iso_utc(now + timedelta(hours=2))

    pub_bytes = receipt_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk: dict[str, Any] = {
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": kid,
        "kty": "OKP",
        "use": "sig",
        "x": _b64url_encode(pub_bytes),
    }
    key_meta: dict[str, Any] = {
        "kid": kid,
        "notAfter": valid_str,
        "notBefore": issued_str,
        "revokedAt": revoked_at,
    }

    ext_unsigned: dict[str, Any] = {
        "authorityKeyId": authority_kid,
        "generation": generation,
        "issuedAt": issued_str,
        "keyMetadata": [key_meta],
        "receiptProfile": {
            "audience": "cage-gateway",
            "engineVersion": "2.0.0-alpha.1",
            "issuer": "agent-integrity-sidecar",
            "maximumFutureSkewSeconds": 60,
            "maximumReceiptLifetimeSeconds": 3600,
            "purpose": "verified-release-receipt",
        },
        "signatureAlgorithm": "Ed25519",
        "validUntil": valid_str,
        "version": "1",
    }
    unsigned_manifest: dict[str, Any] = {
        "keys": [jwk],
        CAGE_MANIFEST_EXTENSION_URI: ext_unsigned,
    }
    manifest_digest = hashlib.sha256(
        jcs_canonicalize_plan(unsigned_manifest)
    ).hexdigest()
    sig_input = MANIFEST_SIGNATURE_DOMAIN + bytes.fromhex(manifest_digest)
    sig_b64u = _b64url_encode(authority_sk.sign(sig_input))

    ext_signed = dict(ext_unsigned)
    ext_signed["manifestDigest"] = manifest_digest
    ext_signed["signature"] = sig_b64u
    return {
        "keys": [jwk],
        CAGE_MANIFEST_EXTENSION_URI: ext_signed,
    }


def _build_v2_signed_receipt(
    *,
    receipt_sk: Ed25519PrivateKey,
    envelope: dict[str, Any],
    verification: dict[str, Any],
    kid: str = "cage-receipt-ed25519-2026-04",
) -> dict[str, Any]:
    now = datetime.now(UTC)
    created_at = _iso_utc(now)
    expires_at = _iso_utc(now + timedelta(minutes=10))
    envelope_digest = hashlib.sha256(jcs_canonicalize_plan(envelope)).hexdigest()
    policy_digest = (
        hashlib.sha256(jcs_canonicalize_plan(envelope["policy"])).hexdigest()
        if isinstance(envelope.get("policy"), dict)
        else "b" * 64
    )

    body: dict[str, Any] = {
        "receiptVersion": "2-alpha",
        "receiptId": "rcpt-test-0001",
        "issuer": "agent-integrity-sidecar",
        "audience": "cage-gateway",
        "purpose": "verified-release-receipt",
        "engineVersion": "2.0.0-alpha.1",
        "createdAt": created_at,
        "expiresAt": expires_at,
        "envelopeDigest": envelope_digest,
        "policyDigest": policy_digest,
        "verification": verification,
    }
    signing_payload = jcs_canonicalize_plan(
        {
            "protected": {"algorithm": "Ed25519", "keyId": kid},
            "body": body,
        }
    )
    sig_b64 = base64.b64encode(receipt_sk.sign(signing_payload)).decode("ascii")
    signed_without_digest = dict(body)
    signed_without_digest["signature"] = {
        "algorithm": "Ed25519",
        "keyId": kid,
        "value": sig_b64,
    }
    receipt_digest = hashlib.sha256(
        jcs_canonicalize_plan(signed_without_digest)
    ).hexdigest()
    full_receipt = dict(signed_without_digest)
    full_receipt["receiptDigest"] = receipt_digest
    return full_receipt


@pytest.mark.asyncio
async def test_file_jwks_client_verifies_signed_manifest_and_persists_generation(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    state_path = tmp_path / "manifest_state.json"

    manifest_gen2 = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
        generation=2,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest_gen2))

    client = FileJWKSClient(
        manifest_url=manifest_path,
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        manifest_state_path=state_path,
    )
    pub = await client.get_key("cage-receipt-ed25519-2026-04")
    assert pub is not None
    assert client.manifest_extension is not None
    assert client.manifest_extension.generation == 2
    assert state_path.exists()

    # Rollback to generation 1 must fail closed even on a fresh client instance
    manifest_gen1 = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
        generation=1,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest_gen1))

    restarted_client = FileJWKSClient(
        manifest_url=manifest_path,
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        manifest_state_path=state_path,
    )
    with pytest.raises(ValueError, match="generation rollback"):
        await restarted_client.get_key("cage-receipt-ed25519-2026-04")


@pytest.mark.asyncio
async def test_file_jwks_client_rejects_revoked_key(tmp_path: Path) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    now = datetime.now(UTC)
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
        issued_at=_iso_utc(now - timedelta(minutes=10)),
        valid_until=_iso_utc(now + timedelta(hours=1)),
        revoked_at=_iso_utc(now - timedelta(minutes=1)),
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    client = FileJWKSClient(
        manifest_url=manifest_path,
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
    )
    pub = await client.get_key("cage-receipt-ed25519-2026-04")
    assert pub is None


@pytest.mark.parametrize("client_id", ["cage-gateway", "cagé-gateway"])
def test_sidecar_hmac_auth_headers_encoding(client_id: str) -> None:
    body = b'{"envelope":{},"serviceProtocolVersion":"1"}'
    body_digest = hashlib.sha256(body).hexdigest()
    secret = b"super-secret-32-byte-hmac-key-01"
    fields = [
        "POST",
        "/v1/verify-release",
        "1",
        client_id,
        "hmac-k1",
        "1776600000000",
        "nonce-12345678",
        body_digest,
    ]
    # Independent oracle: fixed field order, UTF-8 byte lengths, unsigned u32BE.
    expected_frame = b"agent-integrity-sidecar-auth-v1" + b"".join(
        len(value.encode("utf-8")).to_bytes(4, "big") + value.encode("utf-8")
        for value in fields
    )
    expected_mac = (
        base64.urlsafe_b64encode(
            hmac.new(secret, expected_frame, hashlib.sha256).digest()
        )
        .decode("ascii")
        .rstrip("=")
    )
    assert encode_sidecar_auth_input(fields) == expected_frame
    headers = compute_sidecar_auth_headers(
        method="POST",
        path=VERIFY_RELEASE_PATH,
        service_protocol_version=SIDECAR_PROTOCOL_VERSION,
        client_id=client_id,
        key_id="hmac-k1",
        timestamp_ms=1776600000000,
        nonce="nonce-12345678",
        body_digest=body_digest,
        secret=secret,
    )
    assert headers == {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Agent-Integrity-Client": client_id,
        "X-Agent-Integrity-Key-Id": "hmac-k1",
        "X-Agent-Integrity-Timestamp": "1776600000000",
        "X-Agent-Integrity-Nonce": "nonce-12345678",
        "X-Agent-Integrity-Signature": expected_mac,
    }


@pytest.mark.asyncio
async def test_verify_release_pass_verifies_signed_receipt_and_exact_bytes(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    candidate_text = '{"answer":"verified exact bytes"}'
    candidate_bytes = candidate_text.encode("utf-8")
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
    envelope = {
        "envelopeId": "env-test-0001",
        "response": {"content": candidate_text},
    }
    verification = {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "PASS",
        "findings": [],
    }
    signed_receipt = _build_v2_signed_receipt(
        receipt_sk=receipt_sk,
        envelope=envelope,
        verification=verification,
    )
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == VERIFY_RELEASE_PATH
        seen_headers.update(dict(request.headers))
        req_body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
                "requestId": req_body["requestId"],
                "status": "PASS",
                "verification": verification,
                "receipt": signed_receipt,
                "releasedResponse": {
                    "encoding": "base64",
                    "bytes": base64.b64encode(candidate_bytes).decode("ascii"),
                    "sha256": candidate_sha,
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        key_manifest_url=str(manifest_path),
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        transport=httpx.MockTransport(handler),
        client_id="cage-gateway",
        hmac_key_id="hmac-k1",
        hmac_secret=b"super-secret-32-byte-hmac-key-01",
        use_verify_release=True,
    )

    outcome = await adapter.verify_release(envelope=envelope)
    assert outcome.admitted is True
    assert outcome.status == VerifyReleaseStatus.PASS
    assert outcome.receipt_verified is True
    assert outcome.released_response is not None
    assert outcome.released_response.decoded_bytes == candidate_bytes
    assert outcome.released_response.text == candidate_text
    assert outcome.released_response.sha256 == candidate_sha
    assert "x-agent-integrity-signature" in seen_headers

    # Also verify validate_fria dispatches to verify_release
    vr = await adapter.validate_fria(envelope)
    assert vr.admitted is True
    assert vr.error is None


@pytest.mark.asyncio
async def test_verify_release_fails_closed_on_tampered_released_bytes(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    envelope = {
        "envelopeId": "env-test-0001",
        "response": {"content": "expected safe output"},
    }
    verification = {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "PASS",
        "findings": [],
    }
    signed_receipt = _build_v2_signed_receipt(
        receipt_sk=receipt_sk,
        envelope=envelope,
        verification=verification,
    )
    tampered_bytes = b"tampered output bytes"

    def handler(request: httpx.Request) -> httpx.Response:
        req_body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
                "requestId": req_body["requestId"],
                "status": "PASS",
                "verification": verification,
                "receipt": signed_receipt,
                "releasedResponse": {
                    "encoding": "base64",
                    "bytes": base64.b64encode(tampered_bytes).decode("ascii"),
                    "sha256": hashlib.sha256(tampered_bytes).hexdigest(),
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        key_manifest_url=str(manifest_path),
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        transport=httpx.MockTransport(handler),
        use_verify_release=True,
    )

    outcome = await adapter.verify_release(envelope=envelope)
    assert outcome.admitted is False
    assert outcome.released_response is None
    assert any(
        f["code"] == FINDING_CODE_RELEASED_BYTES_MISMATCH for f in outcome.findings
    )


@pytest.mark.asyncio
async def test_verify_release_preserves_signed_refusal_on_release_refused(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    envelope = {
        "envelopeId": "env-test-0001",
        "response": {"content": "candidate text"},
    }
    prospective_pass_verification = {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "PASS",
        "findings": [],
    }
    prospective_pass_receipt = _build_v2_signed_receipt(
        receipt_sk=receipt_sk,
        envelope=envelope,
        verification=prospective_pass_verification,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        req_body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
                "requestId": req_body["requestId"],
                "status": "RELEASE_REFUSED",
                "verification": prospective_pass_verification,
                "receipt": prospective_pass_receipt,
                "release": {
                    "status": "REVIEW",
                    "code": "RECEIPT_RECHECK_REFUSED",
                    "retryable": False,
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        key_manifest_url=str(manifest_path),
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        transport=httpx.MockTransport(handler),
        use_verify_release=True,
    )

    outcome = await adapter.verify_release(envelope=envelope)
    assert outcome.admitted is False
    assert outcome.status == VerifyReleaseStatus.RELEASE_REFUSED
    assert outcome.receipt_verified is True
    assert outcome.released_response is None
    assert outcome.release_refusal is not None
    assert outcome.release_refusal.code == "RECEIPT_RECHECK_REFUSED"
    assert outcome.release_refusal.status == "REVIEW"
    assert outcome.receipt is not None
    assert outcome.receipt["verification"]["status"] == "PASS"

    vr = outcome.to_validation_result()
    assert vr.admitted is False
    assert is_review_pending(vr.findings) is True
    assert any(f["code"] == FINDING_CODE_RELEASE_REFUSED for f in vr.findings)
    assert any(f["code"] == FINDING_CODE_REVIEW_PENDING for f in vr.findings)
    assert extract_integrity_status(vr.findings) == "REVIEW"


@pytest.mark.asyncio
async def test_verify_release_fails_closed_on_technical_error_response(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    def handler(request: httpx.Request) -> httpx.Response:
        req_body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            503,
            json={
                "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
                "requestId": req_body["requestId"],
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "retryable": True,
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        key_manifest_url=str(manifest_path),
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        transport=httpx.MockTransport(handler),
        use_verify_release=True,
    )

    outcome = await adapter.verify_release(envelope={"envelopeId": "env-test-0001"})
    assert outcome.admitted is False
    assert outcome.status is None
    assert outcome.http_status == 503
    assert outcome.error_code == "SERVICE_UNAVAILABLE"
    assert outcome.retryable is True
    assert outcome.released_response is None
    assert any(f["code"] == FINDING_CODE_ENDPOINT_ERROR for f in outcome.findings)


@pytest.mark.asyncio
async def test_check_readiness_detail_parses_503_reasons_and_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            headers={"Retry-After": "5"},
            json={
                "ready": False,
                "reasons": ["RECOVERY_REQUIRED", "KEYS"],
            },
        )

    probe = SidecarHealthCheck(
        "http://sidecar.local",
        transport=httpx.MockTransport(handler),
    )
    detail = await probe.check_readiness_detail()
    assert detail.ready is False
    assert detail.status_code == 503
    assert detail.reasons == ("RECOVERY_REQUIRED", "KEYS")
    assert detail.retry_after == 5


@pytest.mark.asyncio
async def test_verify_release_wrong_receipt_key_denies_after_wire_repair(
    tmp_path: Path,
) -> None:
    authority_sk = Ed25519PrivateKey.generate()
    receipt_sk = Ed25519PrivateKey.generate()
    authority_pub_b64u = _b64url_encode(
        authority_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    manifest_path = tmp_path / "jwks.json"
    manifest = _build_signed_trust_manifest(
        authority_sk=authority_sk,
        receipt_sk=receipt_sk,
    )
    manifest_path.write_bytes(jcs_canonicalize_plan(manifest))

    candidate_text = '{"answer":"verified exact bytes"}'
    candidate_bytes = candidate_text.encode("utf-8")
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
    envelope = {
        "envelopeId": "env-test-0001",
        "response": {"content": candidate_text},
    }
    verification = {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "PASS",
        "findings": [],
    }
    signed_receipt = _build_v2_signed_receipt(
        receipt_sk=Ed25519PrivateKey.generate(),
        envelope=envelope,
        verification=verification,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == VERIFY_RELEASE_PATH
        req_body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "serviceProtocolVersion": SIDECAR_PROTOCOL_VERSION,
                "requestId": req_body["requestId"],
                "status": "PASS",
                "verification": verification,
                "receipt": signed_receipt,
                "releasedResponse": {
                    "encoding": "base64",
                    "bytes": base64.b64encode(candidate_bytes).decode("ascii"),
                    "sha256": candidate_sha,
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        key_manifest_url=str(manifest_path),
        authority_keys={"cage-manifest-authority-2026-04": authority_pub_b64u},
        transport=httpx.MockTransport(handler),
        client_id="cage-gateway",
        hmac_key_id="hmac-k1",
        hmac_secret=b"super-secret-32-byte-hmac-key-01",
        use_verify_release=True,
    )

    outcome = await adapter.verify_release(envelope=envelope)
    assert outcome.admitted is False
    assert outcome.receipt_verified is False
    assert outcome.released_response is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload", [[], {"serviceProtocolVersion": "1"}, b"{invalid-json"]
)
async def test_verify_release_malformed_response_denies_after_wire_repair(
    payload: Any,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Content-Type"] == "application/json"
        assert "x-agent-integrity-signature" in request.headers
        if isinstance(payload, bytes):
            return httpx.Response(200, content=payload)
        return httpx.Response(200, json=payload)

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        transport=httpx.MockTransport(handler),
        hmac_secret=b"test-only-hmac-secret-length-32!!",
        use_verify_release=True,
    )
    outcome = await adapter.verify_release({"response": {"content": "test"}})
    assert outcome.admitted is False
    assert outcome.receipt_verified is False
    assert outcome.released_response is None


@pytest.mark.asyncio
async def test_verify_release_unsigned_adapter_branch_denies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["Accept"] == "application/json"
        assert not any(
            name.startswith("x-agent-integrity-") for name in request.headers
        )
        return httpx.Response(
            401,
            json={
                "serviceProtocolVersion": "1",
                "error": {
                    "code": "AUTHENTICATION_FAILED",
                    "retryable": False,
                },
            },
        )

    adapter = Provider06AgentIntegrityAdapter(
        endpoint="http://sidecar.local",
        transport=httpx.MockTransport(handler),
        use_verify_release=True,
    )
    outcome = await adapter.verify_release({"response": {"content": "test"}})
    assert outcome.http_status == 401
    assert outcome.error_code == "AUTHENTICATION_FAILED"
    assert outcome.admitted is False
    assert outcome.receipt_verified is False
    assert outcome.released_response is None
