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

"""End-user principal binding: verified OIDC identity vs. asserted principal (issues #516, #520).

Covers the wire and authentication contracts in
``src/governed_financial_advisor/models/principal.py`` and
``src/governed_financial_advisor/infrastructure/auth.py``:

* A request carrying a verified OIDC JWT (resolved out-of-band by ``kid``)
  propagates that authenticated principal end-to-end (``user_context``,
  ``principal_verified_context=True``, ``x-cage-principal``,
  ``x-cage-principal-verified="true"``, ``x-geap-user-id``, and span
  attributes ``enduser.id`` + ``cage.principal.verified=True``).
* A request whose body ``user_id`` disagrees with the verified OIDC claim is
  refused with HTTP 403 before graph execution.
* A request without a verified OIDC identity is refused (HTTP 401) in
  enforcing postures or when ``CAGE_USER_OIDC_ISSUER`` /
  ``CAGE_REQUIRE_VERIFIED_PRINCIPAL`` is configured (unless
  ``CAGE_ALLOW_ASSERTED_PRINCIPAL=true``), and is explicitly marked unverified
  (``cage.principal.verified=False``, ``x-cage-principal-verified="false"``)
  in permissive postures (``dev`` / ``test`` / ``ci``).
* ``x-cage-principal`` and ``x-geap-user-id`` are sanitized and truncated by
  one helper that matches the gateway's ``sanitize_principal``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from pydantic import ValidationError

from src.gateway.observability.attributes import (
    SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED,
    SPAN_ATTR_ENDUSER_ID,
)
from src.gateway.server.rate_limit import sanitize_principal as gateway_sanitize
from src.governed_financial_advisor.infrastructure.auth import (
    PrincipalIdentity,
    requires_verified_principal,
    verify_user_oidc_token,
)
from src.governed_financial_advisor.infrastructure.gateway_client import (
    GatewayClient,
)
from src.governed_financial_advisor.models.principal import (
    PRINCIPAL_MAX_LEN,
    PRINCIPAL_PATTERN,
    principal_header_value,
)
from src.governed_financial_advisor.models.query import QueryRequest
from src.governed_financial_advisor.utils.context import (
    principal_verified_context,
    user_context,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_API_KEY = "test-advisor-api-key"
_AUTH = {"Authorization": f"Bearer {_API_KEY}"}

_OIDC_ISSUER = "https://idp.example.com"
_OIDC_AUDIENCE = "cage-advisor"
_OIDC_KID = "user-oidc-key-01"

#: Values QueryRequest accepts that reach the gateway byte-for-byte.
_PASS_THROUGH_PRINCIPALS = (
    "investor-42",
    "user:alice@example.com",
    "spiffe://cluster.local/ns/default/sa/advisor",
    "A.b_c:d@e/f-g",
    "p" * PRINCIPAL_MAX_LEN,
)

#: (value, reason) pairs QueryRequest must reject.
_INVALID_PRINCIPALS = (
    ("", "empty"),
    ("alice smith", "space"),
    ("alice\n", "trailing newline"),
    ("alice\r\nx-injected: 1", "header injection"),
    ("alice;drop", "semicolon"),
    ("ユーザー", "non-ASCII"),
    ("p" * (PRINCIPAL_MAX_LEN + 1), "65 characters"),
)

#: Hostile or malformed inputs for the header sanitizer parity check.
_SANITIZER_CORPUS = (
    "investor-42",
    "user:alice@example.com",
    "  padded  ",
    "bad\nheader\x00value!",
    "alice\r\nx-injected: 1",
    "ユーザー-7",
    "a b c",
    "__edge__",
    "x" * 100,
    "a" * 63 + "!" + "b",
    "_" * 70 + "z",
    "!!!",
    "   ",
    "",
    "anonymous",
)


# ---------------------------------------------------------------------------
# QueryRequest model
# ---------------------------------------------------------------------------


class TestQueryRequestPrincipal:
    """QueryRequest.user_id is required and matches the gateway principal charset."""

    def test_missing_user_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            QueryRequest(prompt="Tell me about ETFs")
        errors = exc_info.value.errors()
        assert [e["loc"] for e in errors] == [("user_id",)]
        assert errors[0]["type"] == "missing"

    @pytest.mark.parametrize(
        ("user_id", "reason"),
        _INVALID_PRINCIPALS,
        ids=[r for _, r in _INVALID_PRINCIPALS],
    )
    def test_invalid_user_id_is_rejected(self, user_id: str, reason: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            QueryRequest(prompt="Tell me about ETFs", user_id=user_id)
        assert [e["loc"] for e in exc_info.value.errors()] == [("user_id",)], reason

    def test_non_string_user_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            QueryRequest(prompt="Tell me about ETFs", user_id=42)  # type: ignore[arg-type]

    @pytest.mark.parametrize("user_id", _PASS_THROUGH_PRINCIPALS)
    def test_accepted_user_id_reaches_gateway_unchanged(self, user_id: str) -> None:
        request = QueryRequest(prompt="Tell me about ETFs", user_id=user_id)
        assert request.user_id == user_id
        assert principal_header_value(user_id) == user_id
        assert gateway_sanitize(user_id) == user_id

    def test_edge_underscores_are_normalized_like_the_gateway(self) -> None:
        """The charset admits ``_``; the gateway strips it from the edges, and so does the header."""
        request = QueryRequest(prompt="Tell me about ETFs", user_id="_alice_")
        assert principal_header_value(request.user_id) == "alice"
        assert gateway_sanitize(request.user_id) == "alice"

    def test_pattern_matches_the_gateway_charset(self) -> None:
        charset = "".join(chr(c) for c in range(32, 127))
        allowed = {ch for ch in charset if re.fullmatch(PRINCIPAL_PATTERN, ch)}
        survives_gateway = {
            ch for ch in charset if gateway_sanitize(f"a{ch}a") == f"a{ch}a"
        }
        assert allowed == survives_gateway


# ---------------------------------------------------------------------------
# POST /agent/query validation (HTTP)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def advisor_server() -> Any:
    """Import the advisor app with its import-time telemetry hooks stubbed."""
    with (
        patch("src.integrations.nemo.manager.load_rails", return_value=MagicMock()),
        patch("src.gateway.infrastructure.telemetry_client.configure_telemetry"),
        patch(
            "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
        ),
    ):
        import src.governed_financial_advisor.server as srv
    return srv


class _CapturingGraph:
    """Graph stand-in that records the principal the gateway client would send."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def ainvoke(
        self, inputs: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "inputs": inputs,
                "config": config,
                "user_context": user_context.get(),
                "principal_verified": principal_verified_context.get(),
                "headers": GatewayClient()._build_headers(),
            }
        )
        return {"messages": [SimpleNamespace(content="Diversify across index funds.")]}


@pytest.fixture
def stub_cache() -> Iterator[MagicMock]:
    cache = MagicMock()
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock(return_value=None)
    with patch(
        "src.governed_financial_advisor.infrastructure.query_cache.get_query_cache",
        AsyncMock(return_value=cache),
    ):
        yield cache


@pytest.fixture
def query_client(
    advisor_server: Any, stub_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> tuple[TestClient, _CapturingGraph]:
    monkeypatch.setenv("CAGE_API_KEY", _API_KEY)
    monkeypatch.delenv("CAGE_ADVISOR_RUNTIME", raising=False)
    monkeypatch.delenv("CAGE_USER_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("CAGE_USER_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("CAGE_USER_OIDC_JWKS_JSON", raising=False)
    monkeypatch.delenv("CAGE_USER_OIDC_TRUST_ANCHORS_FILE", raising=False)
    monkeypatch.delenv("CAGE_REQUIRE_VERIFIED_PRINCIPAL", raising=False)
    monkeypatch.delenv("CAGE_ALLOW_ASSERTED_PRINCIPAL", raising=False)
    graph = _CapturingGraph()
    monkeypatch.setattr(advisor_server.app.state, "graph", graph, raising=False)
    return TestClient(advisor_server.app, raise_server_exceptions=True), graph


@pytest.fixture
def ed25519_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return priv, pub_pem


def _mint_user_jwt(
    priv: Any,
    *,
    sub: str = "user:alice@example.com",
    kid: str = _OIDC_KID,
    iss: str = _OIDC_ISSUER,
    aud: str = _OIDC_AUDIENCE,
    exp_offset: int = 300,
    alg: str = "EdDSA",
    extra_headers: dict[str, Any] | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": int(time.time()) + exp_offset,
    }
    if extra_claims:
        payload.update(extra_claims)
    headers: dict[str, Any] = {"kid": kid}
    if extra_headers:
        headers.update(extra_headers)
    return pyjwt.encode(payload, priv, algorithm=alg, headers=headers)


class TestAgentQueryRejectsBadPrincipal:
    """POST /agent/query fails closed with 422 before any graph execution."""

    def test_missing_user_id_returns_422(
        self, query_client: tuple[TestClient, _CapturingGraph]
    ) -> None:
        client, graph = query_client
        resp = client.post("/agent/query", json={"prompt": "Hello"}, headers=_AUTH)
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert [d["loc"] for d in detail] == [["body", "user_id"]]
        assert detail[0]["type"] == "missing"
        assert graph.calls == []

    @pytest.mark.parametrize(
        ("user_id", "reason"),
        _INVALID_PRINCIPALS,
        ids=[r for _, r in _INVALID_PRINCIPALS],
    )
    def test_invalid_user_id_returns_422(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        user_id: str,
        reason: str,
    ) -> None:
        client, graph = query_client
        resp = client.post(
            "/agent/query", json={"prompt": "Hello", "user_id": user_id}, headers=_AUTH
        )
        assert resp.status_code == 422, reason
        assert [d["loc"] for d in resp.json()["detail"]] == [["body", "user_id"]]
        assert graph.calls == []

    def test_valid_user_id_reaches_graph_and_gateway_header(
        self, query_client: tuple[TestClient, _CapturingGraph]
    ) -> None:
        client, graph = query_client
        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers=_AUTH,
        )
        assert resp.status_code == 200
        assert resp.json()["response"] == "Diversify across index funds."
        assert len(graph.calls) == 1
        call = graph.calls[0]
        assert call["inputs"]["user_id"] == "user:alice@example.com"
        assert call["user_context"] == "user:alice@example.com"
        assert call["principal_verified"] is False
        assert call["headers"]["x-cage-principal"] == "user:alice@example.com"
        assert call["headers"]["x-cage-principal-verified"] == "false"


# ---------------------------------------------------------------------------
# Verified end-user OIDC identity binding (issue #520)
# ---------------------------------------------------------------------------


class TestAuthenticatedPrincipalBinding:
    """Verified OIDC identity carries the principal end-to-end, marked verified."""

    def test_verified_bearer_oidc_carries_principal_end_to_end(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")

        token = _mint_user_jwt(priv, sub="user:alice@example.com")
        resp = client.post(
            "/agent/query",
            json={"prompt": "Rebalance my portfolio", "user_id": "user:alice@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert len(graph.calls) == 1
        call = graph.calls[0]
        assert call["inputs"]["user_id"] == "user:alice@example.com"
        assert call["user_context"] == "user:alice@example.com"
        assert call["principal_verified"] is True
        assert call["headers"]["x-cage-principal"] == "user:alice@example.com"
        assert call["headers"]["x-cage-principal-verified"] == "true"
        assert call["headers"]["x-geap-user-id"] == "user:alice@example.com"

    def test_verified_user_token_header_with_api_key_omitting_body_user_id(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """X-CAGE-User-Token + Bearer CAGE_API_KEY binds verified principal even without body user_id."""
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        anchors_file = tmp_path / "user_oidc_anchors.json"
        anchors_file.write_text(
            json.dumps({"keys": [{"kid": _OIDC_KID, "pem": pub_pem}]}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv("CAGE_USER_OIDC_TRUST_ANCHORS_FILE", str(anchors_file))

        token = _mint_user_jwt(priv, sub="investor-42")
        resp = client.post(
            "/agent/query",
            json={"prompt": "Show my allocation", "user_id": "investor-42"},
            headers={**_AUTH, "X-CAGE-User-Token": token},
        )
        assert resp.status_code == 200
        assert len(graph.calls) == 1
        call = graph.calls[0]
        assert call["inputs"]["user_id"] == "investor-42"
        assert call["user_context"] == "investor-42"
        assert call["principal_verified"] is True
        assert call["headers"]["x-cage-principal"] == "investor-42"
        assert call["headers"]["x-cage-principal-verified"] == "true"

    def test_rs256_jwk_trust_anchor_verifies_principal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Out-of-band RSA JWK entry in CAGE_USER_OIDC_JWKS_JSON verifies RS256 user tokens."""
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk_dict = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(rsa_priv.public_key()))
        jwk_dict["kid"] = "rsa-key-01"
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({"keys": [jwk_dict]})
        )

        token = _mint_user_jwt(
            rsa_priv,
            sub="user:rsa-investor@example.com",
            kid="rsa-key-01",
            alg="RS256",
        )
        principal = verify_user_oidc_token(token)
        assert principal == PrincipalIdentity(
            user_id="user:rsa-investor@example.com",
            verified=True,
            issuer=_OIDC_ISSUER,
            kid="rsa-key-01",
        )

    def test_mismatched_body_user_id_and_verified_token_returns_403(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Caller cannot assert user:mallory when authenticated as user:alice."""
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )

        token = _mint_user_jwt(priv, sub="user:alice@example.com")
        resp = client.post(
            "/agent/query",
            json={
                "prompt": "Transfer funds",
                "user_id": "user:mallory@example.com",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "does not match authenticated principal" in resp.json()["detail"]
        assert graph.calls == []

    def test_unknown_kid_fails_closed_with_401(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )

        token = _mint_user_jwt(priv, kid="unknown-kid")
        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert graph.calls == []

    @pytest.mark.parametrize("embedded_field", ["jwk", "jku", "x5c", "x5u"])
    def test_embedded_key_headers_are_rejected_with_401(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
        embedded_field: str,
    ) -> None:
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )

        token = _mint_user_jwt(
            priv, extra_headers={embedded_field: "https://attacker.example/jwks.json"}
        )
        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert graph.calls == []

    def test_expired_or_wrong_issuer_token_rejected_with_401(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, graph = query_client
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )

        expired = _mint_user_jwt(priv, exp_offset=-60)
        resp_exp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp_exp.status_code == 401

        wrong_iss = _mint_user_jwt(priv, iss="https://rogue-idp.example.com")
        resp_iss = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers={"Authorization": f"Bearer {wrong_iss}"},
        )
        assert resp_iss.status_code == 401
        assert graph.calls == []

    def test_unverified_request_refused_when_oidc_configured_or_enforcing(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without a verified user token, API-key-only requests fail closed when required."""
        client, graph = query_client
        _, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )

        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers=_AUTH,
        )
        assert resp.status_code == 401
        assert "Verified end-user principal required" in resp.json()["detail"]
        assert graph.calls == []

    def test_unverified_request_refused_in_production_posture(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, graph = query_client
        monkeypatch.setenv("CAGE_ENV", "production")
        assert requires_verified_principal() is True

        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers=_AUTH,
        )
        assert resp.status_code == 401
        assert graph.calls == []

    def test_allow_asserted_principal_override_permits_unverified_in_dev(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client, graph = query_client
        _, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )
        monkeypatch.setenv("CAGE_ALLOW_ASSERTED_PRINCIPAL", "true")

        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers=_AUTH,
        )
        assert resp.status_code == 200
        assert len(graph.calls) == 1
        assert graph.calls[0]["principal_verified"] is False
        assert graph.calls[0]["headers"]["x-cage-principal-verified"] == "false"


class TestQuerySpanMarksPrincipalVerification:
    """The /agent/query span records enduser.id and cage.principal.verified."""

    async def test_span_records_enduser_and_unverified_flag(
        self, advisor_server: Any, stub_cache: MagicMock
    ) -> None:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer(__name__)
        graph = _CapturingGraph()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(graph=graph)),
            headers={},
        )

        with tracer.start_as_current_span("POST /agent/query"):
            result = await advisor_server.query_agent(
                QueryRequest(prompt="Hello", user_id="investor-42"),
                request,
                _auth="test",
            )

        assert result["response"] == "Diversify across index funds."
        (span,) = exporter.get_finished_spans()
        assert span.attributes[SPAN_ATTR_ENDUSER_ID] == "investor-42"
        assert span.attributes[SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED] is False
        assert SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED == "cage.principal.verified"
        assert SPAN_ATTR_ENDUSER_ID == "enduser.id"

    async def test_span_records_verified_true_when_principal_authenticated(
        self,
        advisor_server: Any,
        stub_cache: MagicMock,
        ed25519_keypair: tuple[Ed25519PrivateKey, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        priv, pub_pem = ed25519_keypair
        monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _OIDC_ISSUER)
        monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _OIDC_AUDIENCE)
        monkeypatch.setenv(
            "CAGE_USER_OIDC_JWKS_JSON", json.dumps({_OIDC_KID: pub_pem})
        )
        token = _mint_user_jwt(priv, sub="user:alice@example.com")

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer(__name__)
        graph = _CapturingGraph()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(graph=graph)),
            headers={"authorization": f"Bearer {token}"},
        )

        with tracer.start_as_current_span("POST /agent/query"):
            result = await advisor_server.query_agent(
                QueryRequest(prompt="Hello", user_id="user:alice@example.com"),
                request,
                _auth=PrincipalIdentity(
                    user_id="user:alice@example.com",
                    verified=True,
                    issuer=_OIDC_ISSUER,
                    kid=_OIDC_KID,
                ),
            )

        assert result["response"] == "Diversify across index funds."
        (span,) = exporter.get_finished_spans()
        assert span.attributes[SPAN_ATTR_ENDUSER_ID] == "user:alice@example.com"
        assert span.attributes[SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED] is True


# ---------------------------------------------------------------------------
# Outbound gateway headers
# ---------------------------------------------------------------------------


def _headers_for(principal: str, *, verified: bool = False) -> dict[str, str]:
    token = user_context.set(principal)
    v_token = principal_verified_context.set(verified)
    try:
        return GatewayClient()._build_headers()
    finally:
        principal_verified_context.reset(v_token)
        user_context.reset(token)


class TestPrincipalHeaders:
    """x-cage-principal and x-geap-user-id share one sanitizer and cap."""

    def test_both_headers_are_sanitized_and_truncated_identically(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        hostile = "bad\nheader\x00value!" + "x" * 100
        headers = _headers_for(hostile, verified=True)

        expected = gateway_sanitize(hostile)
        assert headers["x-cage-principal"] == expected
        assert headers["x-cage-principal-verified"] == "true"
        assert headers["x-geap-user-id"] == expected
        assert len(expected) == PRINCIPAL_MAX_LEN
        assert re.fullmatch(PRINCIPAL_PATTERN, expected)
        assert expected.startswith("bad_header_value_x")

    def test_long_principal_is_capped_at_64_in_both_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        headers = _headers_for("u" * 100)
        assert headers["x-cage-principal"] == "u" * PRINCIPAL_MAX_LEN
        assert headers["x-cage-principal-verified"] == "false"
        assert headers["x-geap-user-id"] == "u" * PRINCIPAL_MAX_LEN

    @pytest.mark.parametrize("unusable", ["!!!", "   ", "", "\n\x00"])
    def test_unusable_principal_sends_neither_header(
        self, monkeypatch: pytest.MonkeyPatch, unusable: str
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        headers = _headers_for(unusable)
        assert "x-cage-principal" not in headers
        assert "x-cage-principal-verified" not in headers
        assert "x-geap-user-id" not in headers

    def test_geap_user_header_only_on_geap_runtime(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CAGE_ADVISOR_RUNTIME", raising=False)
        headers = _headers_for("investor-42", verified=True)
        assert headers["x-cage-principal"] == "investor-42"
        assert headers["x-cage-principal-verified"] == "true"
        assert "x-geap-user-id" not in headers

    @pytest.mark.parametrize("raw", _SANITIZER_CORPUS)
    def test_helper_matches_gateway_sanitizer(self, raw: str) -> None:
        advisor_value = principal_header_value(raw)
        gateway_value = gateway_sanitize(raw)
        if advisor_value is None:
            assert gateway_value == "anonymous"
        else:
            assert advisor_value == gateway_value
