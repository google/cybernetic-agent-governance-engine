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

"""Tests for OIDC JWT validation middleware — Phase B Work Stream E.

Tests the OIDCValidationMiddleware and validate_oidc_token() function
added to src/gateway/server/governance_middleware.py.
"""

from __future__ import annotations

import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_jwt_parts(header: dict, payload: dict, signature: str = "fakesig") -> str:
    """Build a fake JWT string (not cryptographically valid)."""
    import base64

    def _b64(d: dict) -> str:
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.{signature}"


# ---------------------------------------------------------------------------
# _decode_jwt_header tests
# ---------------------------------------------------------------------------


class TestDecodeJwtHeader:
    """Tests for the JWT header decoder."""

    def test_valid_header_decoded(self):
        from src.gateway.server.governance_middleware import _decode_jwt_header

        token = _make_jwt_parts({"alg": "RS256", "kid": "key1"}, {"sub": "user"})
        header = _decode_jwt_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "key1"

    def test_malformed_token_raises(self):
        from src.gateway.server.governance_middleware import _decode_jwt_header

        with pytest.raises(ValueError, match="3 segments"):
            _decode_jwt_header("only.two")

    def test_invalid_base64_raises(self):
        from src.gateway.server.governance_middleware import _decode_jwt_header

        with pytest.raises(ValueError):
            _decode_jwt_header("!!!.payload.sig")


# ---------------------------------------------------------------------------
# validate_oidc_token tests
# ---------------------------------------------------------------------------


class TestValidateOidcToken:
    """Tests for validate_oidc_token() — requires PyJWT mock."""

    @pytest.mark.asyncio
    async def test_pyjwt_not_installed_returns_empty(self):
        """If PyJWT is not installed, validation is skipped and empty dict returned."""
        import builtins

        real_import = builtins.__import__

        def _mock_import(name, *args, **kwargs):
            if name == "jwt":
                raise ImportError("No module named 'jwt'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_mock_import):
            from src.gateway.server.governance_middleware import validate_oidc_token

            result = await validate_oidc_token("any.token.here")
        assert result == {}

    @pytest.mark.asyncio
    async def test_malformed_jwt_raises_401(self):
        """Malformed JWT header → HTTP 401."""
        from src.gateway.server.governance_middleware import validate_oidc_token

        with pytest.raises(HTTPException) as exc_info:
            await validate_oidc_token("not.a.valid.jwt.at.all.extra")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_jwks_fetch_failure_raises_401(self):
        """JWKS endpoint unreachable → HTTP 401."""
        import src.gateway.server.governance_middleware as gm

        token = _make_jwt_parts({"alg": "RS256", "kid": "k1"}, {"sub": "user"})

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with patch.object(
                gm,
                "_fetch_jwks",
                side_effect=RuntimeError("connection refused"),
            ):
                with pytest.raises(HTTPException) as exc_info:
                    await gm.validate_oidc_token(token)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_no_matching_key_raises_401(self):
        """No matching JWKS key for kid → HTTP 401 (no fallback to 'default')."""
        import src.gateway.server.governance_middleware as gm

        token = _make_jwt_parts({"alg": "RS256", "kid": "unknown-kid"}, {"sub": "user"})
        fake_default = {"kty": "RSA", "kid": "default", "n": "fake", "e": "AQAB"}

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with patch.object(
                gm, "_fetch_jwks", return_value={"default": fake_default}
            ):
                with pytest.raises(HTTPException) as exc_info:
                    await gm.validate_oidc_token(token)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_kid_or_embedded_jwk_raises_401(self):
        """Missing kid or embedded jwk header → HTTP 401."""
        import src.gateway.server.governance_middleware as gm

        token_no_kid = _make_jwt_parts({"alg": "RS256"}, {"sub": "user"})
        token_with_jwk = _make_jwt_parts(
            {"alg": "RS256", "kid": "k1", "jwk": {"kty": "RSA"}}, {"sub": "user"}
        )

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with pytest.raises(HTTPException) as exc_info1:
                await gm.validate_oidc_token(token_no_kid)
            assert exc_info1.value.status_code == 401

            with pytest.raises(HTTPException) as exc_info2:
                await gm.validate_oidc_token(token_with_jwk)
            assert exc_info2.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_jwt_raises_401(self):
        """Expired JWT → HTTP 401."""
        import src.gateway.server.governance_middleware as gm

        token = _make_jwt_parts(
            {"alg": "RS256", "kid": "k1"}, {"sub": "user", "exp": 1}
        )
        fake_key_data = {"kty": "RSA", "kid": "k1", "n": "fake", "e": "AQAB"}

        mock_jwt = MagicMock()
        mock_jwt.ExpiredSignatureError = Exception
        mock_jwt.InvalidTokenError = Exception
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.side_effect = mock_jwt.ExpiredSignatureError("expired")

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with patch.object(
                gm,
                "_fetch_jwks",
                return_value={"k1": fake_key_data, "_fetched_at": time.monotonic()},
            ):
                with patch.dict("sys.modules", {"jwt": mock_jwt}):
                    with pytest.raises(HTTPException) as exc_info:
                        await gm.validate_oidc_token(token)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_jwt_returns_caller_identity(self):
        """Valid JWT → caller_identity dict with sub, iss, scope."""
        import src.gateway.server.governance_middleware as gm

        token = _make_jwt_parts({"alg": "RS256", "kid": "k1"}, {"sub": "user123"})
        fake_key_data = {"kty": "RSA", "kid": "k1", "n": "fake", "e": "AQAB"}
        fake_claims = {
            "sub": "user123",
            "iss": "https://issuer.example.com",
            "scope": "read write",
        }

        mock_jwt = MagicMock()
        mock_jwt.ExpiredSignatureError = type("ExpiredSignatureError", (Exception,), {})
        mock_jwt.InvalidTokenError = type("InvalidTokenError", (Exception,), {})
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = fake_claims

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with patch.object(
                gm,
                "_fetch_jwks",
                return_value={"k1": fake_key_data, "_fetched_at": time.monotonic()},
            ):
                with patch.dict("sys.modules", {"jwt": mock_jwt}):
                    result = await gm.validate_oidc_token(token)

        assert result["sub"] == "user123"
        assert result["iss"] == "https://issuer.example.com"
        assert result["scope"] == "read write"


# ---------------------------------------------------------------------------
# OIDCValidationMiddleware behaviour tests
# ---------------------------------------------------------------------------


class TestOIDCValidationMiddleware:
    """Tests for the ASGI middleware wrapper."""

    @pytest.mark.asyncio
    async def test_no_jwks_uri_passes_through(self):
        """If CAGE_OIDC_JWKS_URI is not set, all requests pass through unchanged."""
        import src.gateway.server.governance_middleware as gm

        call_count = 0

        async def _app(scope, receive, send):
            nonlocal call_count
            call_count += 1

        middleware = gm.OIDCValidationMiddleware(_app)

        with patch.object(gm, "_OIDC_JWKS_URI", None):
            scope = {"type": "http", "headers": []}
            await middleware(scope, None, None)

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self):
        """Non-HTTP scopes (websocket, lifespan) pass through unchanged."""
        import src.gateway.server.governance_middleware as gm

        call_count = 0

        async def _app(scope, receive, send):
            nonlocal call_count
            call_count += 1

        middleware = gm.OIDCValidationMiddleware(_app)
        scope = {"type": "lifespan"}
        await middleware(scope, None, None)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_no_authorization_header_passes_through(self):
        """Missing Authorization header → pass through unchanged (backward compat)."""
        import src.gateway.server.governance_middleware as gm

        call_count = 0

        async def _app(scope, receive, send):
            nonlocal call_count
            call_count += 1

        middleware = gm.OIDCValidationMiddleware(_app)

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/governance/validate-action",
                "query_string": b"",
                "headers": [],  # no Authorization header
            }
            await middleware(scope, MagicMock(), MagicMock())

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self):
        """Invalid JWT → 401 response, app not called."""
        import src.gateway.server.governance_middleware as gm

        call_count = 0

        async def _app(scope, receive, send):
            nonlocal call_count
            call_count += 1

        middleware = gm.OIDCValidationMiddleware(_app)

        responses_sent = []

        async def _send(message):
            responses_sent.append(message)

        with patch.object(gm, "_OIDC_JWKS_URI", "https://example.com/jwks"):
            with patch.object(
                gm,
                "validate_oidc_token",
                side_effect=HTTPException(
                    status_code=401,
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                    detail={"error": "invalid_token"},
                ),
            ):
                scope = {
                    "type": "http",
                    "method": "POST",
                    "path": "/governance/validate-action",
                    "query_string": b"",
                    "headers": [
                        (b"authorization", b"Bearer bad.token.here"),
                    ],
                }
                await middleware(scope, MagicMock(), _send)

        # App should NOT have been called
        assert call_count == 0
        # A response should have been sent
        assert len(responses_sent) > 0
        status_msg = next(
            m for m in responses_sent if m.get("type") == "http.response.start"
        )
        assert status_msg["status"] == 401

    @pytest.mark.asyncio
    async def test_fetch_jwks_rejects_invalid_url_scheme(self):
        """_fetch_jwks raises RuntimeError when _OIDC_JWKS_URI uses a non-http(s) scheme."""
        import src.gateway.server.governance_middleware as gm

        with (
            patch.object(gm, "_OIDC_JWKS_URI", "file:///etc/passwd"),
            patch.object(gm, "_jwks_cache", {}),
        ):
            with pytest.raises(RuntimeError, match="unsupported URL scheme"):
                await gm._fetch_jwks()

    def test_recursive_non_finite_float_rejected_in_requests(self):
        """ValidateActionRequest and ToolExecutionRequest reject nested NaN/Infinity floats."""
        from pydantic import ValidationError

        from src.gateway.server.governance_middleware import ValidateActionRequest
        from src.gateway.server.mcp_tool_server import ToolExecutionRequest

        with pytest.raises(ValidationError, match="non-finite float"):
            ValidateActionRequest(
                action="transfer",
                params={"nested": {"items": [1.0, float("nan")]}},
            )

        with pytest.raises(ValidationError, match="non-finite float"):
            ToolExecutionRequest(
                tool_name="transfer",
                params={"nested": {"limit": float("inf")}},
            )


pytestmark = [pytest.mark.unit, pytest.mark.local]
