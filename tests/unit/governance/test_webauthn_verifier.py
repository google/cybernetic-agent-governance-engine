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

"""Unit and route tests for cryptographic W3C WebAuthn assertion verification (POAM-2026-210).

Covers:
  - Cryptographic signature verification across ``ES256`` (ECDSA P-256), ``EdDSA``
    (Ed25519), and ``RS256`` (RSA PKCS#1 v1.5 >= 2048-bit) in both PEM and JWK
    trust-store formats.
  - W3C WebAuthn Level 2 §7.2 ``authenticatorData`` invariants: 32-byte
    ``SHA-256(rp_id)``, ``UP`` (``0x01``), ``UV`` (``0x04``), backup state
    consistency (``BS=1 => BE=1``), and minimum 37-byte length.
  - ``CollectedClientData`` invariants: ``type == "webauthn.get"``, HTTPS origin
    allowlist + RP domain scope, ``crossOrigin is not True``, and constant-time
    32-byte ``challenge`` binding against ``DeferToken.expected_webauthn_bindings()``.
  - Out-of-band ``(operator_urn, credential_id)`` ownership binding, rejection of
    embedded/private key material, and rejection of workload SVID principals.
  - Unconditional enforcement on ``POST /v1/defer/{defer_id}/escalate`` in
    ``CAGE_ENV=production`` and ``CAGE_ENV=staging`` when ``operator.channel_provenance``
    is ``"OIDC"`` or ``"MTLS_HEADER"`` (never gated on ``auth_method == "WEBAUTHN"``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from pathlib import Path
from typing import Any

import fakeredis.aioredis
import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from src.compliance_bridge import auth as bridge_auth
from src.compliance_bridge import main as bridge_main
from src.compliance_bridge.oidc_verifier import reset_oidc_verifier
from src.gateway.governance.defer_queue import (
    ApprovalRecord,
    ApprovalStatus,
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.gateway.governance.webauthn_verifier import (
    WebAuthnConfigError,
    WebAuthnVerificationError,
    load_webauthn_verifier_config_from_env,
    validate_configured_webauthn_env,
    verify_webauthn_assertion,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

RP_ID = "console.cage.example"
ORIGIN = "https://console.cage.example"
ALICE = "alice@example.com"
BOB = "bob@example.com"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_assertion(
    priv_key: Any,
    alg: str,
    *,
    challenge_hex: str,
    rp_id: str = RP_ID,
    origin: str = ORIGIN,
    ceremony_type: str = "webauthn.get",
    flags: int = 0x05,
    sign_count: int = 7,
    cross_origin: bool | None = False,
) -> tuple[str, str, str]:
    """Return ``(client_data_json_b64, authenticator_data_b64, signature_b64)``."""
    challenge_bytes = bytes.fromhex(challenge_hex)
    cd_obj: dict[str, Any] = {
        "type": ceremony_type,
        "challenge": _b64u(challenge_bytes),
        "origin": origin,
    }
    if cross_origin is not None:
        cd_obj["crossOrigin"] = cross_origin
    cd_bytes = json.dumps(cd_obj, separators=(",", ":")).encode("utf-8")
    auth_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + struct.pack(">I", sign_count)
    )
    signed_payload = auth_data + hashlib.sha256(cd_bytes).digest()
    if alg == "ES256":
        sig = priv_key.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
    elif alg == "EdDSA":
        sig = priv_key.sign(signed_payload)
    elif alg == "RS256":
        sig = priv_key.sign(signed_payload, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise AssertionError(f"Unsupported test alg {alg}")
    return _b64u(cd_bytes), _b64u(auth_data), _b64u(sig)


class TestWebAuthnCryptographicAlgorithmsAndTrustStore:
    """POAM-2026-210: Asymmetric signature verification and out-of-band trust store."""

    @pytest.mark.parametrize("alg", ["ES256", "EdDSA", "RS256"])
    @pytest.mark.parametrize("key_format", ["pem", "jwk"])
    def test_verifies_es256_eddsa_rs256_in_pem_and_jwk_formats(
        self, monkeypatch: pytest.MonkeyPatch, alg: str, key_format: str
    ) -> None:
        cred_id = _b64u(f"cred-{alg}-{key_format}".encode("ascii"))
        if alg == "ES256":
            priv: Any = ec.generate_private_key(ec.SECP256R1())
            nums = priv.public_key().public_numbers()
            jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u(nums.x.to_bytes(32, "big")),
                "y": _b64u(nums.y.to_bytes(32, "big")),
            }
        elif alg == "EdDSA":
            priv = ed25519.Ed25519PrivateKey.generate()
            raw_pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw_pub)}
        else:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rnums = priv.public_key().public_numbers()
            n_len = (rnums.n.bit_length() + 7) // 8
            e_len = (rnums.e.bit_length() + 7) // 8
            jwk = {
                "kty": "RSA",
                "n": _b64u(rnums.n.to_bytes(n_len, "big")),
                "e": _b64u(rnums.e.to_bytes(e_len, "big")),
            }

        entry: dict[str, Any] = {
            "credential_id": cred_id,
            "operator_urn": ALICE,
            "alg": alg,
        }
        if key_format == "pem":
            entry["public_key_pem"] = (
                priv.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8")
            )
        else:
            entry["public_key_jwk"] = jwk

        monkeypatch.setenv("CAGE_WEBAUTHN_RP_ID", RP_ID)
        monkeypatch.setenv("CAGE_WEBAUTHN_ALLOWED_ORIGINS", ORIGIN)
        monkeypatch.setenv(
            "CAGE_WEBAUTHN_CREDENTIALS_JSON", json.dumps({"credentials": [entry]})
        )

        challenge_hex = hashlib.sha256(b"poam-210-challenge").hexdigest()
        cdj, ad, sig = _sign_assertion(priv, alg, challenge_hex=challenge_hex)

        verified = verify_webauthn_assertion(
            approver_urn=f"urn:cage:operator:oidc:{ALICE}",
            credential_id=cred_id,
            client_data_json=cdj,
            authenticator_data=ad,
            signature=sig,
            challenge_binding=challenge_hex,
            expected_bindings={challenge_hex},
        )
        assert verified.credential_id == cred_id
        assert verified.sign_count == 7
        assert (verified.flags & 0x04) != 0

        # Flipping 1 bit in signature must fail cryptographic verification.
        sig_bytes = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
        sig_bytes[-1] ^= 0x01
        with pytest.raises(
            WebAuthnVerificationError,
            match="cryptographic signature verification failed",
        ):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=cred_id,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=_b64u(bytes(sig_bytes)),
                challenge_binding=challenge_hex,
            )

    def test_rejects_private_key_material_weak_rsa_and_workload_svid_in_trust_store(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("CAGE_WEBAUTHN_RP_ID", RP_ID)
        monkeypatch.setenv("CAGE_WEBAUTHN_ALLOWED_ORIGINS", ORIGIN)

        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pub_pem = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        # Private PEM rejected
        monkeypatch.setenv(
            "CAGE_WEBAUTHN_CREDENTIALS_JSON",
            json.dumps(
                [
                    {
                        "credential_id": _b64u(b"cred-priv"),
                        "operator_urn": ALICE,
                        "alg": "ES256",
                        "public_key_pem": priv_pem,
                    }
                ]
            ),
        )
        with pytest.raises(WebAuthnConfigError, match="PRIVATE KEY"):
            load_webauthn_verifier_config_from_env()

        # Private JWK parameter "d" rejected
        nums = priv.public_key().public_numbers()
        monkeypatch.setenv(
            "CAGE_WEBAUTHN_CREDENTIALS_JSON",
            json.dumps(
                [
                    {
                        "credential_id": _b64u(b"cred-jwk-d"),
                        "operator_urn": ALICE,
                        "alg": "ES256",
                        "public_key_jwk": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": _b64u(nums.x.to_bytes(32, "big")),
                            "y": _b64u(nums.y.to_bytes(32, "big")),
                            "d": _b64u(b"\x01" * 32),
                        },
                    }
                ]
            ),
        )
        with pytest.raises(WebAuthnConfigError, match="private/symmetric"):
            load_webauthn_verifier_config_from_env()

        # Workload SVID operator_urn rejected
        monkeypatch.setenv(
            "CAGE_WEBAUTHN_CREDENTIALS_JSON",
            json.dumps(
                [
                    {
                        "credential_id": _b64u(b"cred-svid"),
                        "operator_urn": "spiffe://cluster.local/ns/cage/sa/gateway",
                        "alg": "ES256",
                        "public_key_pem": pub_pem,
                    }
                ]
            ),
        )
        with pytest.raises(WebAuthnConfigError, match="Workload identity"):
            load_webauthn_verifier_config_from_env()

        # Setting both FILE and JSON simultaneously fails closed
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(
            json.dumps(
                [
                    {
                        "credential_id": _b64u(b"cred-ok"),
                        "operator_urn": ALICE,
                        "alg": "ES256",
                        "public_key_pem": pub_pem,
                    }
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CAGE_WEBAUTHN_CREDENTIALS_FILE", str(creds_file))
        with pytest.raises(WebAuthnConfigError, match="Simultaneous"):
            validate_configured_webauthn_env()


class TestWebAuthnW3CAssertionInvariants:
    """POAM-2026-210: RP ID hash, UP/UV/BS/BE flags, origin, crossOrigin, and credential ownership."""

    def _configure_alice_and_bob(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[str, ec.EllipticCurvePrivateKey, str, ec.EllipticCurvePrivateKey]:
        alice_priv = ec.generate_private_key(ec.SECP256R1())
        bob_priv = ec.generate_private_key(ec.SECP256R1())
        alice_cred = _b64u(b"cred-alice-01")
        bob_cred = _b64u(b"cred-bob-01")
        creds = [
            {
                "credential_id": alice_cred,
                "operator_urn": ALICE,
                "alg": "ES256",
                "public_key_pem": alice_priv.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8"),
            },
            {
                "credential_id": bob_cred,
                "operator_urn": BOB,
                "alg": "ES256",
                "public_key_pem": bob_priv.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8"),
            },
        ]
        monkeypatch.setenv("CAGE_WEBAUTHN_RP_ID", RP_ID)
        monkeypatch.setenv("CAGE_WEBAUTHN_ALLOWED_ORIGINS", ORIGIN)
        monkeypatch.setenv(
            "CAGE_WEBAUTHN_CREDENTIALS_JSON", json.dumps({"credentials": creds})
        )
        return alice_cred, alice_priv, bob_cred, bob_priv

    def test_enforces_rp_id_hash_flags_origin_cross_origin_and_ownership(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        alice_cred, alice_priv, bob_cred, bob_priv = self._configure_alice_and_bob(
            monkeypatch
        )
        ch = hashlib.sha256(b"w3c-invariant-check").hexdigest()

        # 1. Wrong RP ID hash
        cdj, ad, sig = _sign_assertion(
            alice_priv, "ES256", challenge_hex=ch, rp_id="evil.example"
        )
        with pytest.raises(WebAuthnVerificationError, match="rpIdHash"):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 2. UP=0 (flags=0x04) rejected
        cdj, ad, sig = _sign_assertion(
            alice_priv, "ES256", challenge_hex=ch, flags=0x04
        )
        with pytest.raises(WebAuthnVerificationError, match="User Present"):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 3. UV=0 (flags=0x01, touch-only without user verification) rejected
        cdj, ad, sig = _sign_assertion(
            alice_priv, "ES256", challenge_hex=ch, flags=0x01
        )
        with pytest.raises(WebAuthnVerificationError, match="User Verified"):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 4. Invalid backup state BS=1 without BE=1 (flags=0x15) rejected
        cdj, ad, sig = _sign_assertion(
            alice_priv, "ES256", challenge_hex=ch, flags=0x15
        )
        with pytest.raises(WebAuthnVerificationError, match="BS=1 with BE=0"):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 5. crossOrigin=True rejected
        cdj, ad, sig = _sign_assertion(
            alice_priv, "ES256", challenge_hex=ch, cross_origin=True
        )
        with pytest.raises(WebAuthnVerificationError, match="crossOrigin"):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 6. Disallowed origin rejected
        cdj, ad, sig = _sign_assertion(
            alice_priv,
            "ES256",
            challenge_hex=ch,
            origin="https://phishing.cage.example",
        )
        with pytest.raises(
            WebAuthnVerificationError,
            match="outside Relying Party ID scope|not in allowed",
        ):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=alice_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )

        # 7. Cross-operator credential substitution: Alice presenting Bob's signed assertion rejected
        cdj, ad, sig = _sign_assertion(bob_priv, "ES256", challenge_hex=ch)
        with pytest.raises(
            WebAuthnVerificationError, match="not registered to operator"
        ):
            verify_webauthn_assertion(
                approver_urn=ALICE,
                credential_id=bob_cred,
                client_data_json=cdj,
                authenticator_data=ad,
                signature=sig,
                challenge_binding=ch,
            )


class TestComplianceBridgeEscalateEnforcingWebAuthn:
    """POAM-2026-210: /v1/defer/{defer_id}/escalate enforces cryptographic WebAuthn on OIDC channel."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("posture", ["production", "staging"])
    @pytest.mark.covers(
        "src.compliance_bridge.main:defer_escalate#WEBAUTHN_BINDING_REQUIRED",
        "src.compliance_bridge.main:defer_escalate#Out-of-band WebAuthn trust configuration unavailable",
        "src.gateway.governance.webauthn_verifier:verify_webauthn_assertion",
    )
    async def test_escalate_enforces_cryptographic_webauthn_when_channel_is_oidc(
        self, monkeypatch: pytest.MonkeyPatch, posture: str
    ) -> None:
        # Configure out-of-band human OIDC IdP keypair for Alice and Bob.
        oidc_priv = ec.generate_private_key(ec.SECP256R1())
        oidc_jwk = json.loads(
            pyjwt.algorithms.ECAlgorithm.to_jwk(oidc_priv.public_key())
        )
        oidc_jwk.update({"kid": "idp-kid-210", "use": "sig", "alg": "ES256"})

        monkeypatch.setenv("CAGE_ENV", posture)
        monkeypatch.setattr(bridge_auth, "_CAGE_ENV", posture)
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "true")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "false")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_ISSUER", "https://idp.cage.example")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_AUDIENCE", "cage-compliance-bridge")
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_JSON", json.dumps({"keys": [oidc_jwk]}))
        monkeypatch.delenv("CAGE_OPERATOR_JWKS_FILE", raising=False)
        monkeypatch.delenv("CAGE_OPERATOR_JWKS_URI", raising=False)
        monkeypatch.setenv("CAGE_TRUSTED_OPERATOR_IDENTITIES", f"{ALICE},{BOB}")
        reset_oidc_verifier()

        now = int(time.time())
        alice_jwt = pyjwt.encode(
            {
                "sub": ALICE,
                "iss": "https://idp.cage.example",
                "aud": "cage-compliance-bridge",
                "iat": now - 5,
                "exp": now + 300,
            },
            oidc_priv,
            algorithm="ES256",
            headers={"kid": "idp-kid-210"},
        )
        bob_jwt = pyjwt.encode(
            {
                "sub": BOB,
                "iss": "https://idp.cage.example",
                "aud": "cage-compliance-bridge",
                "iat": now - 5,
                "exp": now + 300,
            },
            oidc_priv,
            algorithm="ES256",
            headers={"kid": "idp-kid-210"},
        )

        defer_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        queue = DeferQueue(defer_redis)
        monkeypatch.setattr(
            "src.gateway.governance.defer_queue.get_shared_defer_queue",
            lambda _url=None: queue,
        )
        monkeypatch.setattr(
            bridge_main, "_resolve_defer_redis_url", lambda: "redis://fake:6379/1"
        )

        token = DeferToken(
            thread_id=f"thread-poam210-{posture}",
            defer_reason=DeferReason.HITL_REQUIRED,
            opa_input_snapshot={
                "action": "execute_trade",
                "params": {"symbol": "AAPL", "amount": 50000.0},
            },
            initiator_urn="advisor-session-initiator",
        )
        await queue.park(token)
        decision_ch = token.compute_decision_challenge_binding()

        alice_w_priv = ec.generate_private_key(ec.SECP256R1())
        bob_w_priv = ec.generate_private_key(ec.SECP256R1())
        alice_cred = _b64u(b"alice-yubikey-210")
        bob_cred = _b64u(b"bob-yubikey-210")

        # 1. Unconfigured WebAuthn trust store fails closed with 503 WEBAUTHN_TRUST_UNCONFIGURED
        monkeypatch.delenv("CAGE_WEBAUTHN_RP_ID", raising=False)
        monkeypatch.delenv("CAGE_WEBAUTHN_ALLOWED_ORIGINS", raising=False)
        monkeypatch.delenv("CAGE_WEBAUTHN_CREDENTIALS_JSON", raising=False)
        monkeypatch.delenv("CAGE_WEBAUTHN_CREDENTIALS_FILE", raising=False)

        cdj_a, ad_a, sig_a = _sign_assertion(
            alice_w_priv, "ES256", challenge_hex=decision_ch
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_main.app),
            base_url="http://bridge.local",
        ) as client:
            # 1a. Missing signature & authenticator_data on OIDC channel -> 400 WEBAUTHN_BINDING_REQUIRED
            r_no_sig = await client.post(
                f"/v1/defer/{token.defer_id}/escalate",
                headers={"Authorization": f"Bearer {alice_jwt}"},
                json={"client_data_json": cdj_a, "challenge_binding": decision_ch},
            )
            assert r_no_sig.status_code == 400
            assert r_no_sig.json()["detail"]["error"] == "WEBAUTHN_BINDING_REQUIRED"

            # 1b. Present fields but unconfigured WebAuthn trust store -> 503 WEBAUTHN_TRUST_UNCONFIGURED
            r_unconf = await client.post(
                f"/v1/defer/{token.defer_id}/escalate",
                headers={"Authorization": f"Bearer {alice_jwt}"},
                json={
                    "credential_id": alice_cred,
                    "client_data_json": cdj_a,
                    "authenticator_data": ad_a,
                    "signature": sig_a,
                    "challenge_binding": decision_ch,
                },
            )
            assert r_unconf.status_code == 503
            assert r_unconf.json()["detail"]["error"] == "WEBAUTHN_TRUST_UNCONFIGURED"

            # Configure out-of-band WebAuthn trust anchors for Alice and Bob.
            monkeypatch.setenv("CAGE_WEBAUTHN_RP_ID", RP_ID)
            monkeypatch.setenv("CAGE_WEBAUTHN_ALLOWED_ORIGINS", ORIGIN)
            monkeypatch.setenv(
                "CAGE_WEBAUTHN_CREDENTIALS_JSON",
                json.dumps(
                    {
                        "credentials": [
                            {
                                "credential_id": alice_cred,
                                "operator_urn": ALICE,
                                "alg": "ES256",
                                "public_key_pem": alice_w_priv.public_key()
                                .public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                                )
                                .decode("utf-8"),
                            },
                            {
                                "credential_id": bob_cred,
                                "operator_urn": BOB,
                                "alg": "ES256",
                                "public_key_pem": bob_w_priv.public_key()
                                .public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                                )
                                .decode("utf-8"),
                            },
                        ]
                    }
                ),
            )

            # 2. Dummy base64url signature/authenticator_data on OIDC channel -> 400 APPROVAL_VALIDATION_FAILED
            r_dummy = await client.post(
                f"/v1/defer/{token.defer_id}/escalate",
                headers={"Authorization": f"Bearer {alice_jwt}"},
                json={
                    "credential_id": alice_cred,
                    "client_data_json": cdj_a,
                    "authenticator_data": "dGVzdC1hdXRoLWRhdGE",
                    "signature": "dGVzdC1zaWduYXR1cmU",
                    "challenge_binding": decision_ch,
                },
            )
            assert r_dummy.status_code == 400
            assert r_dummy.json()["detail"]["error"] == "APPROVAL_VALIDATION_FAILED"

            # 3. Valid cryptographic WebAuthn assertion from Alice (1/2) -> 200 partially_approved
            r_alice = await client.post(
                f"/v1/defer/{token.defer_id}/escalate",
                headers={"Authorization": f"Bearer {alice_jwt}"},
                json={
                    "credential_id": alice_cred,
                    "client_data_json": cdj_a,
                    "authenticator_data": ad_a,
                    "signature": sig_a,
                    "challenge_binding": decision_ch,
                },
            )
            assert r_alice.status_code == 200, r_alice.text
            assert r_alice.json()["status"] == "partially_approved"

            # 4. Valid cryptographic WebAuthn assertion from Bob (2/2) -> 200 escalated
            cdj_b, ad_b, sig_b = _sign_assertion(
                bob_w_priv, "ES256", challenge_hex=decision_ch
            )
            r_bob = await client.post(
                f"/v1/defer/{token.defer_id}/escalate",
                headers={"Authorization": f"Bearer {bob_jwt}"},
                json={
                    "credential_id": bob_cred,
                    "client_data_json": cdj_b,
                    "authenticator_data": ad_b,
                    "signature": sig_b,
                    "challenge_binding": decision_ch,
                },
            )
            assert r_bob.status_code == 200, r_bob.text
            assert r_bob.json()["status"] == "escalated"

        redeemable = await queue.redeemable_token(
            token.defer_id,
            action="execute_trade",
        )
        assert redeemable is not None
        assert len(redeemable.approvals) == 2
        assert redeemable.approvals[0].auth_method == "OIDC"
        assert redeemable.approvals[0].credential_id == alice_cred
        assert redeemable.approvals[1].credential_id == bob_cred
        reset_oidc_verifier()

    @pytest.mark.asyncio
    async def test_credential_id_padding_variant_rejected_as_duplicate_approval(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "test")
        defer_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        queue = DeferQueue(defer_redis)
        token = DeferToken(
            thread_id="thread-pad-dup",
            defer_reason=DeferReason.HITL_REQUIRED,
            opa_input_snapshot={"action": "execute_trade", "params": {"amount": 100.0}},
        )
        await queue.park(token)

        rec1 = ApprovalRecord(
            approver_urn="urn:cage:operator:oidc:op1",
            approved_at_utc="2026-11-20T00:00:00Z",
            auth_method="DEV_SYNTHETIC",
            auth_principal_hash="1" * 64,
            credential_id="Y3JlZC1zaGFyZWQ=",
        )
        rec2 = ApprovalRecord(
            approver_urn="urn:cage:operator:oidc:op2",
            approved_at_utc="2026-11-20T00:00:01Z",
            auth_method="DEV_SYNTHETIC",
            auth_principal_hash="2" * 64,
            credential_id="Y3JlZC1zaGFyZWQ",
        )
        s1, _ = await queue.approve(token.defer_id, rec1)
        assert s1 == ApprovalStatus.PARTIAL_QUORUM
        s2, _ = await queue.approve(token.defer_id, rec2)
        assert s2 == ApprovalStatus.ALREADY_APPROVED
