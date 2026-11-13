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
Standalone unit and cryptographic verification test suite for cage-client SDK subpackage.
"""

from __future__ import annotations

import asyncio
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import tomllib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
    utils,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

# Add standalone subpackage src directory to path for testing
subpackage_root = Path(__file__).parent.parent
subpackage_src = subpackage_root / "src"
if str(subpackage_src) not in sys.path:
    sys.path.insert(0, str(subpackage_src))

import cage_client
from cage_client import (
    CageClient,
    CageGatewayError,
    DeferralPending,
    GovernanceEnvelope,
    JwksKeyResolver,
    PolicyViolationException,
    RoutingSealVerificationError,
    cage_guard,
    compute_expected_action_hash,
    enforce_verification_posture,
    generate_w3c_traceparent,
)
from cage_client._jcs import canonicalize
from cage_client.transport import create_mtls_transport


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ec_keypair(
    kid: str = "ec-key-01",
    curve: ec.EllipticCurve = ec.SECP256R1(),
    crv_name: str = "P-256",
    alg: str = "ES256",
) -> tuple[ec.EllipticCurvePrivateKey, bytes, dict[str, Any]]:
    priv = ec.generate_private_key(curve)
    pub = priv.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    coord_len = (curve.key_size + 7) // 8
    nums = pub.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": crv_name,
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "x": _b64u(nums.x.to_bytes(coord_len, "big")),
        "y": _b64u(nums.y.to_bytes(coord_len, "big")),
    }
    return priv, pem, jwk


def _make_ed25519_keypair(
    kid: str = "ed-key-01",
) -> tuple[ed25519.Ed25519PrivateKey, bytes, dict[str, Any]]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": _b64u(raw),
    }
    return priv, pem, jwk


def _make_rsa_keypair(
    kid: str = "rsa-key-01",
    alg: str = "RS256",
) -> tuple[rsa.RSAPrivateKey, bytes, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    nums = pub.public_numbers()
    n_len = (nums.n.bit_length() + 7) // 8
    e_len = (nums.e.bit_length() + 7) // 8
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": _b64u(nums.n.to_bytes(n_len, "big")),
        "e": _b64u(nums.e.to_bytes(e_len, "big")),
    }
    return priv, pem, jwk


def _sign_envelope_dict(
    unsigned_env: dict[str, Any],
    *,
    priv_key: Any,
    kid: str,
    algorithm: str,
    ec_p1363: bool = False,
) -> dict[str, Any]:
    env_copy = {k: v for k, v in unsigned_env.items() if k != "signature"}
    canon = canonicalize(env_copy)
    if isinstance(priv_key, ec.EllipticCurvePrivateKey):
        hash_alg = {
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }.get(algorithm.upper(), hashes.SHA256())
        der_sig = priv_key.sign(canon, ec.ECDSA(hash_alg))
        if ec_p1363:
            r, s = utils.decode_dss_signature(der_sig)
            coord_len = (priv_key.curve.key_size + 7) // 8
            sig_bytes = r.to_bytes(coord_len, "big") + s.to_bytes(coord_len, "big")
        else:
            sig_bytes = der_sig
    elif isinstance(priv_key, ed25519.Ed25519PrivateKey):
        sig_bytes = priv_key.sign(canon)
    elif isinstance(priv_key, rsa.RSAPrivateKey):
        if algorithm.upper().startswith("PS"):
            sig_bytes = priv_key.sign(
                canon,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            sig_bytes = priv_key.sign(canon, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise TypeError(f"Unsupported key: {type(priv_key)}")

    signed = dict(env_copy)
    signed["signature"] = {
        "algorithm": algorithm,
        "kid": kid,
        "value": _b64u(sig_bytes),
    }
    return signed


def _build_unsigned_envelope(
    *,
    action: str = "query_resource",
    parameters: dict[str, Any] | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    **payload_overrides: Any,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    iat = issued_at or (now - timedelta(seconds=5))
    exp = expires_at or (now + timedelta(minutes=5))
    params = parameters if parameters is not None else {"limit": 10}
    payload: dict[str, Any] = {"verdict": "ALLOW"}
    payload.update(payload_overrides)
    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-standalone-001",
        "issued_at": iat.isoformat(),
        "expires_at": exp.isoformat(),
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-001",
            "region": "us-central1",
        },
        "subject": {
            "action": action,
            "action_hash": compute_expected_action_hash(action, params),
            "agent_id": "agent-01",
        },
        "governance_context": {
            "policy_version": "1.0",
            "tiers_passed": ["stpa", "opa"],
        },
        "payload": payload,
        "external_attestations": [{"provider": "provider_01", "status": "VERIFIED"}],
    }


def _sample_top_level_envelope(**payload_overrides: Any) -> dict[str, Any]:
    """Return a synthetic v3.0 top-level GovernanceEnvelope dictionary for schema tests."""
    payload: dict[str, Any] = {"verdict": "ALLOW"}
    payload.update(payload_overrides)
    return {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-standalone-001",
        "issued_at": "2026-09-18T20:00:00+00:00",
        "expires_at": "2026-09-18T20:05:00+00:00",
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-001",
            "region": "us-central1",
        },
        "subject": {
            "action": "query_resource",
            "action_hash": "hash-abc",
            "agent_id": "agent-01",
        },
        "governance_context": {
            "policy_version": "1.0",
            "tiers_passed": ["stpa", "opa"],
        },
        "payload": payload,
        "external_attestations": [{"provider": "provider_01", "status": "VERIFIED"}],
        "signature": {
            "algorithm": "ES256",
            "value": "base64url-sig",
            "kid": "cage-kms-key-01",
        },
    }


async def _run_with_mock_handler(
    handler: Any,
    *,
    action: str = "query_resource",
    parameters: dict[str, Any] | None = None,
    agent_id: str = "agent-01",
    verify_signature: bool = False,
    verify_expiration: bool = False,
    verify_subject: bool = False,
    **client_kwargs: Any,
) -> GovernanceEnvelope:
    """Execute CageClient.validate_action against an in-memory httpx.MockTransport."""
    client = CageClient(
        gateway_url="https://cage-standalone.example.test",
        verify_signature=verify_signature,
        verify_expiration=verify_expiration,
        verify_subject=verify_subject,
        **client_kwargs,
    )
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://cage-standalone.example.test",
    )
    try:
        return await client.validate_action(
            action=action,
            parameters=parameters or {"limit": 10},
            agent_id=agent_id,
        )
    finally:
        await client.aclose()


def test_standalone_exports() -> None:
    """Verify all top-level symbols export correctly."""
    assert cage_client.__version__ == "0.3.0"
    assert cage_client.CageClient is CageClient
    assert cage_client.GovernanceEnvelope is GovernanceEnvelope
    assert cage_client.JwksKeyResolver is JwksKeyResolver
    assert cage_client.JwksCache is JwksKeyResolver
    assert cage_client.cage_guard is cage_guard
    assert cage_client.enforce_verification_posture is enforce_verification_posture
    assert issubclass(PolicyViolationException, CageGatewayError)
    assert issubclass(DeferralPending, CageGatewayError)
    assert issubclass(RoutingSealVerificationError, CageGatewayError)
    assert "verify_routing_seal" not in cage_client.__all__


def test_routing_seal_secret_rejected() -> None:
    """Verify CageClient v0.3.0 rejects removed routing_seal_secret parameter."""
    with pytest.raises(TypeError):
        CageClient(
            gateway_url="https://cage-gateway.example.com",
            routing_seal_secret="legacy-secret",  # type: ignore[call-arg]
        )


def test_w3c_traceparent_format() -> None:
    """Verify generated W3C traceparent matches specification."""
    tp = generate_w3c_traceparent()
    parts = tp.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32  # 16 bytes hex
    assert len(parts[2]) == 16  # 8 bytes hex
    assert parts[3] == "01"


def test_pyproject_declares_cryptography_and_docs_describe_envelope_verification() -> (
    None
):
    """Verify cage-client declares cryptography>=41.0.0 and documents fail-closed verification."""
    pyproject_data = tomllib.loads(
        (subpackage_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert pyproject_data["project"]["version"] == "0.3.0"
    runtime_deps = pyproject_data["project"]["dependencies"]
    assert any(dep.startswith("cryptography>=41.0.0") for dep in runtime_deps), (
        f"cryptography>=41.0.0 must be declared in pyproject.toml: {runtime_deps}"
    )

    envelope_doc = GovernanceEnvelope.__doc__ or ""
    assert "RFC 8785" in envelope_doc
    assert "GovernanceEnvelope.signature" in envelope_doc
    assert "expires_at" in envelope_doc
    assert "does NOT substitute" in envelope_doc

    validate_doc = CageClient.validate_action.__doc__ or ""
    assert "JwksKeyResolver" in validate_doc
    assert "does NOT substitute" in validate_doc

    allow_doc = CageClient._handle_allow_response.__doc__ or ""
    assert "RoutingSealVerificationError" in allow_doc
    assert "does NOT substitute" in allow_doc

    readme_text = (subpackage_root / "README.md").read_text(encoding="utf-8")
    assert "JwksKeyResolver" in readme_text
    assert "does NOT substitute for end-to-end" in readme_text


def test_partial_mtls_cert_or_key_fails_closed() -> None:
    """Half-configured mTLS (cert without key or key without cert) raises ValueError (#533)."""
    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path="/nonexistent/cert.pem", key_path=None)

    with pytest.raises(
        ValueError, match="cert_path and key_path must be provided together"
    ):
        create_mtls_transport(cert_path=None, key_path="/nonexistent/key.pem")


def test_standalone_top_level_allow_and_extra_fields_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dev/test opt-out parses unsigned envelope; extra schema keys fail closed."""
    monkeypatch.setenv("CAGE_ENV", "test")
    env_dict = _sample_top_level_envelope()
    del env_dict["signature"]

    envelope = asyncio.run(
        _run_with_mock_handler(lambda req: httpx.Response(200, json=env_dict))
    )
    assert envelope.envelope_id == "env-standalone-001"
    assert envelope.signature is None
    assert envelope.external_attestations == [
        {"provider": "provider_01", "status": "VERIFIED"}
    ]

    extra_env = _sample_top_level_envelope()
    extra_env["unexpected_top_level_field"] = "forbidden"
    with pytest.raises(CageGatewayError, match="Failed to parse governance envelope"):
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=extra_env))
        )


def test_standalone_http_200_verdicts_mediated_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200 NARROW, DENY, REQUIRE_APPROVAL, DEFER, and unknown verdicts mediate fail-closed (#484)."""
    monkeypatch.setenv("CAGE_ENV", "test")
    narrow_env = _sample_top_level_envelope(
        verdict="NARROW",
        narrowed_params={"limit": 5},
        violations=[
            {
                "tier": "cbf",
                "code": "CBF_CLAMP",
                "message": "clamped",
                "kind": "narrowable",
            }
        ],
    )
    with pytest.raises(PolicyViolationException) as narrow_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=narrow_env))
        )
    assert narrow_exc.value.reason_code == "NARROWED"
    assert narrow_exc.value.recoverable is True
    assert narrow_exc.value.violation_details["narrowed_params"] == {"limit": 5}

    deny_env = _sample_top_level_envelope(
        verdict="DENY",
        violations=[
            {
                "tier": "cbf",
                "code": "CBF_HARD_STOP",
                "message": "blocked",
                "kind": "hard",
            }
        ],
    )
    with pytest.raises(PolicyViolationException) as deny_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=deny_env))
        )
    assert deny_exc.value.reason_code == "CBF_HARD_STOP"
    assert deny_exc.value.audit_id == "env-standalone-001"

    hitl_env = _sample_top_level_envelope(
        verdict="REQUIRE_APPROVAL",
        deferred_id="hitl-parked-001",
        classification_reason="hitl_violation",
    )
    with pytest.raises(DeferralPending) as hitl_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=hitl_env))
        )
    assert hitl_exc.value.ticket_id == "hitl-parked-001"
    assert hitl_exc.value.defer_reason == "hitl_violation"

    unpersisted_hitl_env = _sample_top_level_envelope(
        verdict="REQUIRE_APPROVAL",
        deferred_id=None,
        classification_reason="hitl_violation",
    )
    with pytest.raises(CageGatewayError, match="DEFER envelope missing required"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=unpersisted_hitl_env)
            )
        )

    defer_env = _sample_top_level_envelope(
        verdict="DEFER",
        defer_token="defer-tok-002",
        defer_reason="CONFIDENCE_BELOW_THRESHOLD",
        retry_after_seconds=300,
    )
    with pytest.raises(DeferralPending) as defer_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=defer_env))
        )
    assert defer_exc.value.ticket_id == "defer-tok-002"
    assert defer_exc.value.defer_reason == "CONFIDENCE_BELOW_THRESHOLD"
    assert defer_exc.value.ttl_seconds == 300

    unknown_env = _sample_top_level_envelope(verdict="ESCALATE")
    with pytest.raises(CageGatewayError, match="unrecognised verdict"):
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(200, json=unknown_env))
        )


def test_standalone_v2_refusal_403_and_v1_external_hold_202(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canonical gateway 403 refusal (proof_hash) and 202 EXTERNAL_HOLD (defer_id) wire formats."""
    monkeypatch.setenv("CAGE_ENV", "test")
    refusal_403 = {
        "schema_version": "2.0.0",
        "verdict": "DENIED",
        "violations": ["[CBF_LIMIT_BREACH] Threshold exceeded"],
        "proof_hash": "a" * 64,
        "refusal_receipt": {
            "violated_tier": "cbf",
            "violated_rule": "[CBF_LIMIT_BREACH] Threshold exceeded",
            "proof_hash": "a" * 64,
        },
    }
    with pytest.raises(PolicyViolationException) as refusal_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(403, json=refusal_403))
        )
    assert refusal_exc.value.audit_id == "a" * 64
    assert refusal_exc.value.reason_code == "CBF_LIMIT_BREACH"
    assert (
        refusal_exc.value.violation_details["refusal_receipt"]["proof_hash"] == "a" * 64
    )

    hold_202 = {
        "schema_version": "1.0.0",
        "defer_id": "ext-hold-777",
        "status": "pending_review",
        "poll_url": "/v1/defer/ext-hold-777",
        "verdict": "DEFER",
        "defer_reason": "EXTERNAL_HOLD",
        "ttl_seconds": 300,
    }
    with pytest.raises(DeferralPending) as hold_exc:
        asyncio.run(
            _run_with_mock_handler(lambda req: httpx.Response(202, json=hold_202))
        )
    assert hold_exc.value.ticket_id == "ext-hold-777"
    assert hold_exc.value.defer_reason == "EXTERNAL_HOLD"
    assert hold_exc.value.ttl_seconds == 300


def test_standalone_default_jwks_and_pinned_public_keys_verify_es256_and_eddsa() -> (
    None
):
    """Default CageClient verifies ES256 (DER + P1363) and EdDSA via JWKS and public_keys."""
    ec_priv, ec_pem, ec_jwk = _make_ec_keypair(kid="ec-01")
    ed_priv, _ed_pem, ed_jwk = _make_ed25519_keypair(kid="ed-01")
    jwks_doc = {"keys": [ec_jwk, ed_jwk]}
    params = {"limit": 10, "neg_zero": -0.0}

    for priv, kid, alg, p1363 in [
        (ec_priv, "ec-01", "ES256", False),
        (ec_priv, "ec-01", "ES256", True),
        (ed_priv, "ed-01", "EdDSA", False),
    ]:
        signed_env = _sign_envelope_dict(
            _build_unsigned_envelope(parameters=params),
            priv_key=priv,
            kid=kid,
            algorithm=alg,
            ec_p1363=p1363,
        )

        def handler(
            req: httpx.Request, env: dict[str, Any] = signed_env
        ) -> httpx.Response:
            if req.url.path == "/governance/.well-known/jwks.json":
                return httpx.Response(200, json=jwks_doc)
            return httpx.Response(200, json=env)

        verified = asyncio.run(
            _run_with_mock_handler(
                handler,
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
            )
        )
        assert verified.signature is not None
        assert verified.signature["kid"] == kid

    # Also verify pinned public_keys (PEM str, PEM bytes, and PublicKey object) without JWKS hit
    ec_signed = _sign_envelope_dict(
        _build_unsigned_envelope(parameters=params),
        priv_key=ec_priv,
        kid="ec-01",
        algorithm="ES256",
    )
    pinned_verified = asyncio.run(
        _run_with_mock_handler(
            lambda req: (
                httpx.Response(200, json=ec_signed)
                if req.url.path.endswith("/validate-action")
                else httpx.Response(500)
            ),
            parameters=params,
            verify_signature=True,
            verify_expiration=True,
            verify_subject=True,
            public_keys={
                "ec-01": ec_pem.decode("utf-8"),
                "ed-01": ed_priv.public_key(),
            },
        )
    )
    assert pinned_verified.envelope_id == "env-standalone-001"


def test_standalone_validly_signed_foreign_algorithms_are_refused() -> None:
    """Correct ES384/ES512/RS256/PS256 signatures are refused: pinned, via JWKS, or mixed in."""
    params = {"limit": 10}
    p384_priv, p384_pem, p384_jwk = _make_ec_keypair(
        kid="p384-01", curve=ec.SECP384R1(), crv_name="P-384", alg="ES384"
    )
    p521_priv, p521_pem, p521_jwk = _make_ec_keypair(
        kid="p521-01", curve=ec.SECP521R1(), crv_name="P-521", alg="ES512"
    )
    rsa_priv, rsa_pem, rsa_jwk = _make_rsa_keypair(kid="rsa-01", alg="RS256")

    def serve(doc: dict[str, Any], env: dict[str, Any]) -> Any:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/governance/.well-known/jwks.json":
                return httpx.Response(200, json=doc)
            return httpx.Response(200, json=env)

        return handler

    cases: list[tuple[Any, bytes, dict[str, Any], str, str]] = [
        (p384_priv, p384_pem, p384_jwk, "p384-01", "ES384"),
        (p521_priv, p521_pem, p521_jwk, "p521-01", "ES512"),
        (rsa_priv, rsa_pem, rsa_jwk, "rsa-01", "RS256"),
        (rsa_priv, rsa_pem, {**rsa_jwk, "alg": "PS256"}, "rsa-01", "PS256"),
    ]
    for priv, pem, jwk, kid, alg in cases:
        signed = _sign_envelope_dict(
            _build_unsigned_envelope(parameters=params),
            priv_key=priv,
            kid=kid,
            algorithm=alg,
        )

        # Pinned: the key itself is refused when the client is built.
        with pytest.raises(RoutingSealVerificationError, match="not accepted"):
            CageClient(
                gateway_url="https://cage-standalone.example.test",
                public_keys={kid: pem},
            )

        # Via JWKS: the key set is refused, so the envelope never verifies.
        with pytest.raises(RoutingSealVerificationError, match="not accepted"):
            asyncio.run(
                _run_with_mock_handler(
                    serve({"keys": [jwk]}, signed),
                    parameters=params,
                    verify_signature=True,
                    verify_expiration=True,
                    verify_subject=True,
                )
            )

    # One foreign key refuses the whole JWKS, even for an envelope signed by an
    # accepted key: the client never works from a partially usable key set.
    ec_priv, _, ec_jwk = _make_ec_keypair(kid="ec-01")
    accepted = _sign_envelope_dict(
        _build_unsigned_envelope(parameters=params),
        priv_key=ec_priv,
        kid="ec-01",
        algorithm="ES256",
    )
    with pytest.raises(RoutingSealVerificationError, match="not accepted"):
        asyncio.run(
            _run_with_mock_handler(
                serve({"keys": [ec_jwk, rsa_jwk]}, accepted),
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
            )
        )


def test_standalone_tampered_embedded_alg_confusion_expiry_and_replay_fail_closed() -> (
    None
):
    """Tampering, embedded keys, alg confusion, expiry, and replay all raise RoutingSealVerificationError."""
    ec_priv, ec_pem, _ = _make_ec_keypair(kid="ec-01")
    params = {"limit": 10}

    # 1. Tampered verdict (DENY -> ALLOW) or tampered narrowed_params BEFORE verdict dispatch
    signed_deny = _sign_envelope_dict(
        _build_unsigned_envelope(parameters=params, verdict="DENY"),
        priv_key=ec_priv,
        kid="ec-01",
        algorithm="ES256",
    )
    signed_deny["payload"] = {"verdict": "ALLOW"}
    with pytest.raises(RoutingSealVerificationError, match="verification failed"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=signed_deny),
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
                public_keys={"ec-01": ec_pem},
            )
        )

    # 2. Embedded public key inside signature or top-level envelope -> RoutingSealVerificationError
    rogue_priv, rogue_pem, rogue_jwk = _make_ec_keypair(kid="rogue-01")
    embedded_sig_env = _sign_envelope_dict(
        _build_unsigned_envelope(parameters=params),
        priv_key=rogue_priv,
        kid="rogue-01",
        algorithm="ES256",
    )
    embedded_sig_env["signature"]["public_key"] = rogue_pem.decode("utf-8")
    with pytest.raises(
        RoutingSealVerificationError, match="unexpected or embedded-key"
    ):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=embedded_sig_env),
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
                public_keys={"ec-01": ec_pem},
            )
        )

    embedded_top_env = _sign_envelope_dict(
        _build_unsigned_envelope(parameters=params),
        priv_key=rogue_priv,
        kid="rogue-01",
        algorithm="ES256",
    )
    embedded_top_env["jwk"] = rogue_jwk
    with pytest.raises(RoutingSealVerificationError, match="embedded key material"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=embedded_top_env),
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
                public_keys={"ec-01": ec_pem},
            )
        )

    # 3. Relabelled valid ES256 signature: every label but ES256 is refused
    for bad_alg in (
        "ES384",
        "ES512",
        "RS256",
        "PS256",
        "EdDSA",
        "none",
        "HS256",
        "es256",
        "ECDSA_P256_SHA256",
    ):
        confused_env = _sign_envelope_dict(
            _build_unsigned_envelope(parameters=params),
            priv_key=ec_priv,
            kid="ec-01",
            algorithm="ES256",
        )
        confused_env["signature"]["algorithm"] = bad_alg
        with pytest.raises(RoutingSealVerificationError):
            asyncio.run(
                _run_with_mock_handler(
                    lambda req, env=confused_env: httpx.Response(200, json=env),
                    parameters=params,
                    verify_signature=True,
                    verify_expiration=True,
                    verify_subject=True,
                    public_keys={"ec-01": ec_pem},
                )
            )

    # 4. Expired envelope beyond clock_skew_seconds fails; within clock_skew_seconds passes
    now = datetime.now(timezone.utc)
    expired_env = _sign_envelope_dict(
        _build_unsigned_envelope(
            parameters=params,
            issued_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(seconds=10),
        ),
        priv_key=ec_priv,
        kid="ec-01",
        algorithm="ES256",
    )
    with pytest.raises(RoutingSealVerificationError, match="expired"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=expired_env),
                parameters=params,
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
                clock_skew_seconds=5.0,
                public_keys={"ec-01": ec_pem},
            )
        )
    skew_ok = asyncio.run(
        _run_with_mock_handler(
            lambda req: httpx.Response(200, json=expired_env),
            parameters=params,
            verify_signature=True,
            verify_expiration=True,
            verify_subject=True,
            clock_skew_seconds=30.0,
            public_keys={"ec-01": ec_pem},
        )
    )
    assert skew_ok.envelope_id == "env-standalone-001"

    # 5. Replay / parameter substitution: valid signature for limit=10 replayed for limit=9999
    valid_limit_10 = _sign_envelope_dict(
        _build_unsigned_envelope(parameters={"limit": 10}),
        priv_key=ec_priv,
        kid="ec-01",
        algorithm="ES256",
    )
    with pytest.raises(RoutingSealVerificationError, match="action_hash"):
        asyncio.run(
            _run_with_mock_handler(
                lambda req: httpx.Response(200, json=valid_limit_10),
                parameters={"limit": 9999},
                verify_signature=True,
                verify_expiration=True,
                verify_subject=True,
                public_keys={"ec-01": ec_pem},
            )
        )


def test_standalone_jwks_ttl_staleness_304_rotation_and_flood_cooldown() -> None:
    """JWKS resolver enforces TTL, max_jwks_staleness_s eviction, 304 rejection, rotation, and flood cooldown."""
    priv_v1, _, jwk_v1 = _make_ec_keypair(kid="kid-v1")
    priv_v2, _, jwk_v2 = _make_ec_keypair(kid="kid-v2")
    now_mono = [1000.0]
    jwks_state: dict[str, Any] = {"status": 200, "body": {"keys": [jwk_v1]}, "hits": 0}
    params = {"limit": 10}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            assert "if-none-match" not in {k.lower() for k in req.headers.keys()}
            jwks_state["hits"] += 1
            return httpx.Response(jwks_state["status"], json=jwks_state["body"])
        return httpx.Response(200, json=jwks_state["envelope"])

    async def _scenario() -> None:
        client = CageClient(
            gateway_url="https://cage-standalone.example.test",
            jwks_ttl_s=60.0,
            max_jwks_staleness_s=300.0,
            jwks_min_refresh_interval_s=10.0,
            jwks_clock=lambda: now_mono[0],
        )
        await client._client.aclose()
        client._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="https://cage-standalone.example.test",
        )
        try:
            # 1. Cold cache warms kid-v1
            jwks_state["envelope"] = _sign_envelope_dict(
                _build_unsigned_envelope(parameters=params),
                priv_key=priv_v1,
                kid="kid-v1",
                algorithm="ES256",
            )
            await client.validate_action("query_resource", params, "agent-01")
            assert jwks_state["hits"] == 1

            # 2. Stale TTL (>60s) with 503 < max_staleness_s (300s) serves warm kid-v1
            now_mono[0] = 1100.0
            jwks_state["status"] = 503
            await client.validate_action("query_resource", params, "agent-01")
            assert jwks_state["hits"] == 2

            # 3. Past max_staleness_s (>=300s since t=1000) with 503 evicts & fails closed
            now_mono[0] = 1305.0
            with pytest.raises(RoutingSealVerificationError, match="no fresh cached"):
                await client.validate_action("query_resource", params, "agent-01")
            assert jwks_state["hits"] == 3

            # 4. HTTP 304 is explicitly rejected fail-closed
            jwks_state["status"] = 304
            with pytest.raises(RoutingSealVerificationError, match="304"):
                await client.validate_action("query_resource", params, "agent-01")

            # 5. Rotation to kid-v2 atomically evicts kid-v1
            jwks_state["status"] = 200
            jwks_state["body"] = {"keys": [jwk_v2]}
            jwks_state["envelope"] = _sign_envelope_dict(
                _build_unsigned_envelope(parameters=params),
                priv_key=priv_v2,
                kid="kid-v2",
                algorithm="ES256",
            )
            await client.validate_action("query_resource", params, "agent-01")
            hits_after_v2 = jwks_state["hits"]

            # Forged unknown-kid burst within jwks_min_refresh_interval_s=10s hits JWKS at most ONCE!
            now_mono[0] = 1306.0
            for idx in range(5):
                forged = dict(jwks_state["envelope"])
                forged["signature"] = {
                    "algorithm": "ES256",
                    "kid": f"forged-kid-{idx}",
                    "value": forged["signature"]["value"],
                }
                jwks_state["envelope"] = forged
                with pytest.raises(RoutingSealVerificationError, match="unknown kid"):
                    await client.validate_action("query_resource", params, "agent-01")
            assert jwks_state["hits"] == hits_after_v2 + 1
        finally:
            await client.aclose()

    asyncio.run(_scenario())


@pytest.mark.parametrize(
    "enforcing_env",
    ["staging", "prod", "production", "ci", "uat", "canary", "custom-env"],
)
@pytest.mark.parametrize(
    "opt_out_kwargs",
    [
        {"verify_signature": False},
        {"verify_expiration": False},
        {"verify_subject": False},
    ],
)
def test_standalone_enforcing_posture_forbids_verification_opt_out(
    monkeypatch: pytest.MonkeyPatch,
    enforcing_env: str,
    opt_out_kwargs: dict[str, bool],
) -> None:
    """Any non-dev/test CAGE_ENV rejects verification opt-out at CageClient init."""
    monkeypatch.setenv("CAGE_ENV", enforcing_env)
    with pytest.raises(ValueError, match="forbidden in enforcing posture"):
        CageClient(
            gateway_url="https://cage-standalone.example.test",
            **opt_out_kwargs,
        )
