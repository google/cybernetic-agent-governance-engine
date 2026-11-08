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

"""Unit tests for out-of-band ``kid``-resolved OIDC verification and SPIFFE broker binding."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from starlette.requests import Request

from src.compliance_bridge.auth import require_operator_identity
from src.compliance_bridge.oidc_verifier import (
    DEFAULT_OPERATOR_OIDC_AUDIENCE,
    OidcVerifier,
    parse_jwks_payload,
    reset_oidc_verifier,
    validate_jwks_uri,
)
from src.gateway.governance.seams.credential_broker import (
    CredentialAccessDenied,
    TriIdentityCredentialBinding,
    validate_tri_identity_binding,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ISSUER = "https://idp.example.org"
_AUDIENCE = DEFAULT_OPERATOR_OIDC_AUDIENCE


def _ed25519_jwk(
    kid: str = "op-ed-1",
) -> tuple[ed25519.Ed25519PrivateKey, dict[str, Any]]:
    priv = ed25519.Ed25519PrivateKey.generate()
    jwk_dict = json.loads(pyjwt.algorithms.OKPAlgorithm.to_jwk(priv.public_key()))
    jwk_dict["kid"] = kid
    return priv, jwk_dict


def _es256_jwk(
    kid: str = "op-ec-1",
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, Any]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk_dict = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(priv.public_key()))
    jwk_dict["kid"] = kid
    return priv, jwk_dict


def _rs256_jwk(kid: str = "op-rsa-1") -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk_dict["kid"] = kid
    return priv, jwk_dict


def _mint(
    priv: Any,
    *,
    alg: str,
    kid: str | None = "op-ed-1",
    sub: str = "operator:alice@example.org",
    iss: str = _ISSUER,
    aud: str = _AUDIENCE,
    exp_offset: int = 300,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    headers: dict[str, Any] = {}
    if kid is not None:
        headers["kid"] = kid
    if extra_headers:
        headers.update(extra_headers)
    payload = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "iat": now,
        "exp": now + exp_offset,
    }
    return pyjwt.encode(payload, priv, algorithm=alg, headers=headers)


class TestValidateJwksUri:
    """Strict scheme & host checks for out-of-band JWKS URIs."""

    def test_accepts_https_uri(self) -> None:
        uri = "https://idp.example.org/.well-known/jwks.json"
        assert validate_jwks_uri(uri) == uri

    @pytest.mark.parametrize(
        "bad_uri",
        [
            "",
            "file:///etc/passwd",
            "ftp://idp.example.org/jwks.json",
            "http://idp.example.org/jwks.json",
            "https://user:secret@idp.example.org/jwks.json",
        ],
    )
    def test_rejects_unsafe_or_credentialed_uris(
        self, bad_uri: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.setenv("CAGE_ALLOW_INSECURE_LOOPBACK_JWKS", "true")
        with pytest.raises(ValueError):
            validate_jwks_uri(bad_uri)

    def test_http_loopback_requires_non_enforcing_and_explicit_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        uri = "http://127.0.0.1:8089/jwks.json"
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.delenv("CAGE_ALLOW_INSECURE_LOOPBACK_JWKS", raising=False)
        with pytest.raises(ValueError, match="https://"):
            validate_jwks_uri(uri)

        monkeypatch.setenv("CAGE_ALLOW_INSECURE_LOOPBACK_JWKS", "true")
        assert validate_jwks_uri(uri) == uri

        monkeypatch.setenv("CAGE_ENV", "staging")
        with pytest.raises(ValueError, match="https://"):
            validate_jwks_uri(uri)


class TestParseJwksPayload:
    """Rejects symmetric or private key material in JWKS payloads."""

    def test_rejects_symmetric_and_private_jwk_entries(self) -> None:
        priv, pub_jwk = _ed25519_jwk("good-kid")
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        payload = json.dumps(
            {
                "keys": [
                    pub_jwk,
                    {"kid": "oct-kid", "kty": "oct", "k": "c2VjcmV0"},
                    {**pub_jwk, "kid": "priv-jwk", "d": "cHJpdmF0ZQ"},
                    {"kid": "priv-pem", "pem": priv_pem},
                ]
            }
        )
        parsed = parse_jwks_payload(payload)
        assert list(parsed.keys()) == ["good-kid"]


class TestOidcVerifier:
    """Out-of-band kid resolution, algorithm allowlist, and claim checks."""

    @pytest.mark.asyncio
    async def test_verifies_eddsa_es256_and_rs256_tokens(self) -> None:
        ed_priv, ed_jwk = _ed25519_jwk("kid-ed")
        ec_priv, ec_jwk = _es256_jwk("kid-ec")
        rsa_priv, rsa_jwk = _rs256_jwk("kid-rsa")
        jwks = parse_jwks_payload(json.dumps({"keys": [ed_jwk, ec_jwk, rsa_jwk]}))
        verifier = OidcVerifier(issuer=_ISSUER, audience=_AUDIENCE, jwks_cache=jwks)

        for priv, alg, kid in [
            (ed_priv, "EdDSA", "kid-ed"),
            (ec_priv, "ES256", "kid-ec"),
            (rsa_priv, "RS256", "kid-rsa"),
        ]:
            tok = _mint(priv, alg=alg, kid=kid)
            ok, claims, err = await verifier.verify_token(tok)
            assert ok is True, err
            assert claims["sub"] == "operator:alice@example.org"
            assert claims["_verified_kid"] == kid

    @pytest.mark.asyncio
    @pytest.mark.parametrize("embedded_hdr", ["jwk", "jku", "x5c", "x5u"])
    async def test_rejects_embedded_key_headers(self, embedded_hdr: str) -> None:
        ed_priv, ed_jwk = _ed25519_jwk("kid-ed")
        jwks = parse_jwks_payload(json.dumps({"keys": [ed_jwk]}))
        verifier = OidcVerifier(issuer=_ISSUER, audience=_AUDIENCE, jwks_cache=jwks)

        tok = _mint(
            ed_priv,
            alg="EdDSA",
            kid="kid-ed",
            extra_headers={embedded_hdr: "https://attacker.example/jwks.json"},
        )
        ok, claims, err = await verifier.verify_token(tok)
        assert ok is False
        assert claims == {}
        assert "embedded key header" in err

    @pytest.mark.asyncio
    async def test_fails_closed_on_unknown_kid_expired_or_wrong_claims(self) -> None:
        ed_priv, ed_jwk = _ed25519_jwk("known-kid")
        jwks = parse_jwks_payload(json.dumps({"keys": [ed_jwk]}))
        verifier = OidcVerifier(issuer=_ISSUER, audience=_AUDIENCE, jwks_cache=jwks)

        for tok in [
            _mint(ed_priv, alg="EdDSA", kid="unknown-kid"),
            _mint(ed_priv, alg="EdDSA", kid=None),
            _mint(ed_priv, alg="EdDSA", kid="known-kid", exp_offset=-30),
            _mint(
                ed_priv, alg="EdDSA", kid="known-kid", iss="https://wrong.example.org"
            ),
            _mint(ed_priv, alg="EdDSA", kid="known-kid", aud="wrong-audience"),
            _mint(ed_priv, alg="EdDSA", kid="known-kid", sub="   "),
        ]:
            ok, claims, _ = await verifier.verify_token(tok)
            assert ok is False
            assert claims == {}

    @pytest.mark.asyncio
    async def test_fetches_remote_https_jwks_via_transport(self) -> None:
        ed_priv, ed_jwk = _ed25519_jwk("remote-kid")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            assert str(request.url) == "https://idp.example.org/.well-known/jwks.json"
            return httpx.Response(200, json={"keys": [ed_jwk]})

        verifier = OidcVerifier(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            jwks_uri="https://idp.example.org/.well-known/jwks.json",
            http_transport=httpx.MockTransport(handler),
        )
        tok = _mint(ed_priv, alg="EdDSA", kid="remote-kid")
        ok1, claims1, _ = await verifier.verify_token(tok)
        ok2, claims2, _ = await verifier.verify_token(tok)
        assert ok1 is True and ok2 is True
        assert claims1["sub"] == claims2["sub"] == "operator:alice@example.org"
        assert calls == 1

    @pytest.mark.asyncio
    async def test_compliance_bridge_auth_extracts_verified_oidc_operator(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reset_oidc_verifier()
        ed_priv, ed_jwk = _ed25519_jwk("bridge-kid")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "true")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_ISSUER", _ISSUER)
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_AUDIENCE", _AUDIENCE)
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_JSON", json.dumps({"keys": [ed_jwk]}))
        monkeypatch.setenv(
            "CAGE_TRUSTED_OPERATOR_IDENTITIES", "operator:alice@example.org"
        )

        tok = _mint(
            ed_priv, alg="EdDSA", kid="bridge-kid", sub="operator:alice@example.org"
        )
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/defer/def-1/escalate",
            "client": ("10.24.1.7", 50000),
            "headers": [(b"authorization", f"Bearer {tok}".encode())],
        }
        principal = await require_operator_identity(Request(scope))
        assert principal.operator_urn == "operator:alice@example.org"
        assert principal.channel_provenance == "OIDC"
        reset_oidc_verifier()


class TestCredentialBrokerSpiffeOnly:
    """Ensure retired GEAP principal:// URIs are rejected at the Layer 1 broker seam."""

    def test_rejects_retired_geap_principal_uri_and_accepts_spiffe(self) -> None:
        with pytest.raises(CredentialAccessDenied):
            validate_tri_identity_binding(
                TriIdentityCredentialBinding(
                    user_id="user:alice",
                    agent_svid="principal://agents.global.org-123/advisor",
                    tool_name="market_data",
                    routing_seal="seal-token",
                    user_verified=True,
                )
            )

        validate_tri_identity_binding(
            TriIdentityCredentialBinding(
                user_id="user:alice",
                agent_svid="spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
                tool_name="market_data",
                routing_seal="seal-token",
                user_verified=True,
            )
        )
