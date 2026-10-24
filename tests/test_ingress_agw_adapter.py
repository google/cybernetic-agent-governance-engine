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
Unit tests for src/gateway/governance/ingress/agw_adapter.py.

Tests AgwRequest, AgwAdapterResult dataclasses, AgwAdapter methods,
and the get_agw_adapter() singleton factory — all without live OIDC/network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwRequestDataclass:
    """Tests for the AgwRequest dataclass."""

    def test_required_fields_only(self):
        """AgwRequest can be constructed with only required fields."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(
            agent_id="agent-001",
            tool_name="execute_trade",
            parameters={"symbol": "AAPL", "amount": 100},
        )

        assert req.agent_id == "agent-001"
        assert req.tool_name == "execute_trade"
        assert req.parameters == {"symbol": "AAPL", "amount": 100}
        assert req.oidc_token == ""
        assert req.trace_id == ""

    def test_optional_fields_defaults(self):
        """oidc_token and trace_id default to empty strings; metadata defaults to {}."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(agent_id="a", tool_name="t", parameters={})

        assert req.oidc_token == ""
        assert req.trace_id == ""
        assert req.metadata == {}

    def test_full_construction(self):
        """AgwRequest accepts all fields."""
        from src.gateway.governance.ingress.agw_adapter import AgwRequest

        req = AgwRequest(
            agent_id="agent-xyz",
            tool_name="check_market_status",
            parameters={"symbol": "TSLA"},
            oidc_token="eyJ...",
            trace_id="trace-abc",
            metadata={"region": "us-fed"},
        )

        assert req.oidc_token == "eyJ..."
        assert req.trace_id == "trace-abc"
        assert req.metadata["region"] == "us-fed"


@pytest.mark.local
class TestAgwAdapterResultDataclass:
    """Tests for the AgwAdapterResult dataclass."""

    def test_required_fields(self):
        """AgwAdapterResult captures success/agent_id/tool_name/parameters."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapterResult

        result = AgwAdapterResult(
            success=True,
            agent_id="agent-001",
            tool_name="execute_trade",
            parameters={"amount": 500},
        )

        assert result.success is True
        assert result.agent_id == "agent-001"
        assert result.tool_name == "execute_trade"
        assert result.identity_verified is False
        assert result.error == ""

    def test_error_field_populated(self):
        """AgwAdapterResult can carry an error message."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapterResult

        result = AgwAdapterResult(
            success=False,
            agent_id="unknown",
            tool_name="",
            parameters={},
            error="OIDC validation failed",
        )

        assert result.success is False
        assert "OIDC" in result.error


# ---------------------------------------------------------------------------
# AgwAdapter.translate_request tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterTranslateRequest:
    """Tests for AgwAdapter.translate_request()."""

    @pytest.mark.asyncio
    async def test_translate_well_formed_request(self):
        """translate_request extracts agent_id, tool name and parameters correctly."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "advisor-001",
            "tool": {
                "name": "get_market_sentiment",
                "parameters": {"symbol": "NVDA"},
            },
            "auth": {"token": "tok-123"},
            "trace_id": "trace-xyz",
            "metadata": {"env": "prod"},
        }

        req = await adapter.translate_request(raw)

        assert req.agent_id == "advisor-001"
        assert req.tool_name == "get_market_sentiment"
        assert req.parameters == {"symbol": "NVDA"}
        assert req.oidc_token == "tok-123"
        assert req.trace_id == "trace-xyz"
        assert req.metadata["env"] == "prod"

    @pytest.mark.asyncio
    async def test_translate_missing_fields_use_defaults(self):
        """translate_request gracefully handles missing optional keys."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {}  # completely empty

        req = await adapter.translate_request(raw)

        assert req.agent_id == "unknown"
        assert req.tool_name == ""
        assert req.parameters == {}
        assert req.oidc_token == ""
        assert req.trace_id == ""

    @pytest.mark.asyncio
    async def test_translate_nested_tool_dict(self):
        """tool.name and tool.parameters are extracted from the nested dict."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "a",
            "tool": {"name": "verify_content_safety", "parameters": {"text": "hello"}},
        }
        req = await adapter.translate_request(raw)

        assert req.tool_name == "verify_content_safety"
        assert req.parameters["text"] == "hello"


# ---------------------------------------------------------------------------
# AgwAdapter.validate_oidc_token tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterValidateOidcToken:
    """Tests for AgwAdapter.validate_oidc_token()."""

    @pytest.mark.asyncio
    async def test_no_issuer_returns_false(self):
        """Returns (False, {}) when AGW_OIDC_ISSUER is not configured."""
        with patch("src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER", ""):
            from src.gateway.governance.ingress.agw_adapter import AgwAdapter

            adapter = AgwAdapter()
            is_valid, claims = await adapter.validate_oidc_token("any-token")

        assert is_valid is False
        assert claims == {}

    @pytest.mark.asyncio
    async def test_with_issuer_stub_returns_false(self):
        """Current stub implementation returns fail-closed (False, {}) even with issuer set."""
        with patch(
            "src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER",
            "https://issuer.example.com",
        ):
            from src.gateway.governance.ingress.agw_adapter import AgwAdapter

            adapter = AgwAdapter()
            is_valid, claims = await adapter.validate_oidc_token("eyJ...")

        assert is_valid is False
        assert isinstance(claims, dict)


# ---------------------------------------------------------------------------
# AgwAdapter.process tests
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestAgwAdapterProcess:
    """Tests for AgwAdapter.process()."""

    @pytest.mark.asyncio
    async def test_process_returns_adapter_result(self):
        """process() returns an AgwAdapterResult with fail-closed semantics.

        Issue #2 remediation: success is now coupled to identity_verified.
        When OIDC validation fails (identity_verified=False), success is also False.
        """
        from src.gateway.governance.ingress.agw_adapter import (
            AgwAdapter,
            AgwAdapterResult,
        )

        adapter = AgwAdapter()
        raw = {
            "agent_id": "agent-abc",
            "tool": {"name": "check_market_status", "parameters": {"symbol": "AAPL"}},
            "auth": {"token": ""},
        }
        result = await adapter.process(raw)

        assert isinstance(result, AgwAdapterResult)
        # Issue #2: success is now False when OIDC validation fails (fail-closed)
        assert result.success is False
        assert result.agent_id == "agent-abc"
        assert result.tool_name == "check_market_status"
        assert result.identity_verified is False  # OIDC stub returns False
        assert "OIDC token validation failed" in result.error

    @pytest.mark.asyncio
    async def test_process_propagates_parameters(self):
        """process() passes through the parameters dict correctly."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "agent_id": "a",
            "tool": {"name": "t", "parameters": {"key": "val", "num": 42}},
        }
        result = await adapter.process(raw)

        assert result.parameters["key"] == "val"
        assert result.parameters["num"] == 42


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------


@pytest.mark.local
class TestGetAgwAdapter:
    """Tests for get_agw_adapter() lazy singleton."""

    def test_returns_agw_adapter_instance(self):
        """get_agw_adapter() returns an AgwAdapter."""
        import src.gateway.governance.ingress.agw_adapter as mod

        mod._agw_adapter = None  # reset singleton

        from src.gateway.governance.ingress.agw_adapter import (
            AgwAdapter,
            get_agw_adapter,
        )

        result = get_agw_adapter()

        assert isinstance(result, AgwAdapter)

    def test_returns_same_instance_on_second_call(self):
        """get_agw_adapter() is a singleton — same object on repeated calls."""
        import src.gateway.governance.ingress.agw_adapter as mod

        mod._agw_adapter = None  # reset

        from src.gateway.governance.ingress.agw_adapter import get_agw_adapter

        a1 = get_agw_adapter()
        a2 = get_agw_adapter()

        assert a1 is a2


# ---------------------------------------------------------------------------
# Phase 3 (Modules M1 & M2): MCP JSON-RPC 2.0, Tri-Identity & REQUEST_AUTHZ
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
class TestGeapMcpJsonRpcAndTriIdentity:
    """Tests for Phase 3 Modules M1 & M2 in AgwAdapter and CredentialBroker."""

    @pytest.mark.asyncio
    async def test_translate_mcp_jsonrpc_tools_call_frame(self):
        """translate_request parses MCP JSON-RPC 2.0 tools/call envelope."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        adapter = AgwAdapter()
        raw = {
            "jsonrpc": "2.0",
            "id": "req-42",
            "method": "tools/call",
            "params": {
                "name": "transfer_funds",
                "arguments": {"amount": 2500, "currency": "USD"},
            },
            "headers": {
                "Authorization": "Bearer eyJ.test.token",
                "x-geap-delegated-oauth-token": "ya29.delegated-oauth-token",
            },
            "trace_id": "trace-mcp-001",
        }
        req = await adapter.translate_request(raw)

        assert req.tool_name == "transfer_funds"
        assert req.parameters == {"amount": 2500, "currency": "USD"}
        assert req.oidc_token == "eyJ.test.token"
        assert req.trace_id == "trace-mcp-001"

    @pytest.mark.asyncio
    async def test_validate_oidc_token_kid_resolved_eddsa_and_rejects_embedded_jwk(
        self,
    ):
        """validate_oidc_token resolves public key by kid and rejects embedded jwk."""
        import time

        import jwt as pyjwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        priv = Ed25519PrivateKey.generate()
        pub_pem = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        issuer = "https://accounts.google.com"
        adapter = AgwAdapter(jwks_cache={"geap-key-01": pub_pem})
        now = int(time.time())

        valid_token = pyjwt.encode(
            {
                "iss": issuer,
                "sub": "principal://agents.global.org-12345/agent/advisor",
                "aud": "cage-gateway",
                "exp": now + 300,
                "act_sub": "user:alice@example.com",
                "scope": "https://www.googleapis.com/auth/cloud-platform read:ledger",
            },
            priv,
            algorithm="EdDSA",
            headers={"kid": "geap-key-01"},
        )

        with patch(
            "src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER", issuer
        ):
            ok, claims = await adapter.validate_oidc_token(valid_token)
            assert ok is True
            assert claims["sub"] == "principal://agents.global.org-12345/agent/advisor"
            assert claims["_verified_kid"] == "geap-key-01"

            tri = adapter.extract_tri_identity(
                {"auth": {"delegated_token": "ya29.secret-token"}},
                claims,
            )
            assert tri.user_id == "user:alice@example.com"
            assert (
                tri.agent_principal
                == "principal://agents.global.org-12345/agent/advisor"
            )
            assert tri.is_valid_agent_principal is True
            assert tri.oauth_scopes == (
                "https://www.googleapis.com/auth/cloud-platform",
                "read:ledger",
            )
            assert len(tri.delegated_token_sha256) == 64
            assert len(tri.compute_binding_digest()) == 64

            # Unknown kid must fail closed
            unknown_kid_token = pyjwt.encode(
                {
                    "iss": issuer,
                    "sub": "principal://agents.global.org-12345/agent/advisor",
                    "aud": "cage-gateway",
                    "exp": now + 300,
                },
                priv,
                algorithm="EdDSA",
                headers={"kid": "unknown-kid"},
            )
            ok_unknown, _ = await adapter.validate_oidc_token(unknown_kid_token)
            assert ok_unknown is False

            # Embedded JWK header must fail closed
            embedded_jwk_token = pyjwt.encode(
                {
                    "iss": issuer,
                    "sub": "principal://agents.global.org-12345/agent/advisor",
                    "aud": "cage-gateway",
                    "exp": now + 300,
                },
                priv,
                algorithm="EdDSA",
                headers={"kid": "geap-key-01", "jwk": {"kty": "OKP"}},
            )
            ok_embedded, _ = await adapter.validate_oidc_token(embedded_jwk_token)
            assert ok_embedded is False

    @pytest.mark.asyncio
    async def test_evaluate_request_authz_allow_and_deny(self):
        """evaluate_request_authz returns 200 + seal on ALLOW and 403 on DENY/DEFER."""
        import time

        import jwt as pyjwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        priv = Ed25519PrivateKey.generate()
        pub_pem = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        issuer = "https://accounts.google.com"
        token = pyjwt.encode(
            {
                "iss": issuer,
                "sub": "spiffe://geap.cloud.google.com/ns/prod/sa/agent-1",
                "aud": "cage-gateway",
                "exp": int(time.time()) + 300,
                "act_sub": "user:bob@example.com",
                "scope": "mcp:tools",
            },
            priv,
            algorithm="EdDSA",
            headers={"kid": "kid-1"},
        )

        adapter = AgwAdapter(jwks_cache={"kid-1": pub_pem})
        raw_mcp = {
            "jsonrpc": "2.0",
            "id": "rpc-1",
            "method": "tools/call",
            "params": {
                "name": "rebalance_portfolio",
                "arguments": {"portfolio_id": "pf-100"},
            },
            "headers": {"Authorization": f"Bearer {token}"},
        }

        mock_gov_allow = AsyncMock()
        mock_gov_allow.validate_action.return_value = {
            "allowed": True,
            "decision": "ALLOW",
        }

        with (
            patch("src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER", issuer),
            patch(
                "src.gateway.governance.ingress.agw_adapter.generate_seal",
                return_value="seal.jwt.token",
            ),
        ):
            decision = await adapter.evaluate_request_authz(
                raw_mcp, governor=mock_gov_allow
            )
            assert decision.allowed is True
            assert decision.http_status == 200
            assert decision.decision == "ALLOW"
            assert decision.headers_to_inject["X-CAGE-Routing-Seal"] == "seal.jwt.token"
            assert "X-CAGE-Tri-Identity-Digest" in decision.headers_to_inject

            # Now test DENY -> 403 fail-closed
            mock_gov_deny = AsyncMock()
            mock_gov_deny.validate_action.return_value = {
                "allowed": False,
                "decision": "DENY",
                "reason": "CBF barrier violated",
            }
            deny_decision = await adapter.evaluate_request_authz(
                raw_mcp, governor=mock_gov_deny
            )
            assert deny_decision.allowed is False
            assert deny_decision.http_status == 403
            assert deny_decision.decision == "DENY"
            assert "X-CAGE-Routing-Seal" not in deny_decision.headers_to_inject

    async def test_validate_tri_identity_binding_enforces_pre_credentials_seal(self):
        """validate_tri_identity_binding verifies seal + ID-1/ID-2 before ID-3 release."""
        from src.gateway.governance.routing_seal import generate_seal
        from src.gateway.governance.seams.credential_broker import (
            CredentialAccessDenied,
            TriIdentityCredentialBinding,
            validate_tri_identity_binding,
        )

        params = {"account": "acc-1"}
        seal = await generate_seal("update_record", params, record_hash=None)

        binding = TriIdentityCredentialBinding(
            user_id="user:alice@example.com",
            agent_svid="principal://agents.global.org-12345/agent/advisor",
            tool_name="update_record",
            routing_seal=seal,
            oauth_scopes=("scope:write",),
        )
        validate_tri_identity_binding(binding)

        bad_binding = TriIdentityCredentialBinding(
            user_id="user:alice@example.com",
            agent_svid="principal://agents.global.org-12345/agent/advisor",
            tool_name="update_record",
            routing_seal="",
            oauth_scopes=("scope:write",),
        )
        with pytest.raises(CredentialAccessDenied):
            validate_tri_identity_binding(bad_binding)


# ---------------------------------------------------------------------------
# ID-1 provenance: GeapTriIdentityContext.user_verified (issue #516)
# ---------------------------------------------------------------------------

_GEAP_ISSUER = "https://accounts.google.com"
_GEAP_AGENT = "principal://agents.global.org-12345/agent/advisor"
_GEAP_KID = "geap-key-01"


def _geap_token(priv, kid: str = _GEAP_KID, **claims) -> str:
    import time

    import jwt as pyjwt

    payload = {
        "iss": _GEAP_ISSUER,
        "sub": _GEAP_AGENT,
        "aud": "cage-gateway",
        "exp": int(time.time()) + 300,
        **claims,
    }
    return pyjwt.encode(payload, priv, algorithm="EdDSA", headers={"kid": kid})


def _tools_call(token: str, **headers: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "rpc-516",
        "method": "tools/call",
        "params": {
            "name": "rebalance_portfolio",
            "arguments": {"portfolio_id": "pf-516"},
        },
        "headers": {"Authorization": f"Bearer {token}", **headers},
    }


@pytest.fixture
def geap_adapter():
    """AgwAdapter trusting one out-of-band Ed25519 key, plus its private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.gateway.governance.ingress.agw_adapter import AgwAdapter

    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    with patch(
        "src.gateway.governance.ingress.agw_adapter.AGW_OIDC_ISSUER", _GEAP_ISSUER
    ):
        yield AgwAdapter(jwks_cache={_GEAP_KID: pub_pem}), priv


@pytest.mark.unit
@pytest.mark.local
class TestTriIdentityUserVerified:
    """ID-1 is ``user_verified`` only when it comes from verified OIDC claims."""

    @pytest.mark.parametrize("claim", ["act_sub", "user_sub"])
    async def test_verified_user_claim_sets_user_verified(self, geap_adapter, claim):
        adapter, priv = geap_adapter
        ok, claims = await adapter.validate_oidc_token(
            _geap_token(priv, **{claim: "user:alice@example.com"})
        )
        assert ok is True

        tri = adapter.extract_tri_identity(
            {"headers": {"x-geap-user-id": "user:mallory@example.com"}}, claims
        )

        assert tri.user_id == "user:alice@example.com"
        assert tri.user_verified is True
        assert tri.to_envelope_claims()["id1_user_verified"] is True

    async def test_verified_token_without_user_claim_leaves_id1_asserted(
        self, geap_adapter
    ):
        adapter, priv = geap_adapter
        ok, claims = await adapter.validate_oidc_token(_geap_token(priv))
        assert ok is True

        tri = adapter.extract_tri_identity(
            {
                "tri_identity": {"user_id": "user:asserted"},
                "headers": {"x-geap-user-id": "user:header"},
            },
            claims,
        )

        assert tri.user_id == "user:asserted"
        assert tri.kid == _GEAP_KID
        assert tri.user_verified is False
        assert tri.to_envelope_claims()["id1_user_verified"] is False

    def test_header_only_id1_is_unverified(self):
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        tri = AgwAdapter().extract_tri_identity(
            {"headers": {"x-geap-user-id": "user:header"}}
        )

        assert tri.user_id == "user:header"
        assert tri.user_verified is False
        assert tri.to_envelope_claims()["id1_user_verified"] is False

    def test_claims_without_verification_stamp_are_unverified(self):
        """Claims that validate_oidc_token did not stamp never mark ID-1 verified."""
        from src.gateway.governance.ingress.agw_adapter import AgwAdapter

        tri = AgwAdapter().extract_tri_identity(
            {}, {"act_sub": "user:alice@example.com", "sub": _GEAP_AGENT}
        )

        assert tri.user_id == "user:alice@example.com"
        assert tri.user_verified is False

    def test_context_defaults_to_unverified_and_digest_ignores_flag(self):
        from src.gateway.governance.ingress.agw_adapter import GeapTriIdentityContext

        asserted = GeapTriIdentityContext(
            user_id="user:alice", agent_principal=_GEAP_AGENT
        )
        verified = GeapTriIdentityContext(
            user_id="user:alice", agent_principal=_GEAP_AGENT, user_verified=True
        )

        assert asserted.user_verified is False
        assert asserted.compute_binding_digest() == verified.compute_binding_digest()

    async def test_request_authz_passes_verified_id1_to_governor(self, geap_adapter):
        adapter, priv = geap_adapter
        token = _geap_token(priv, act_sub="user:alice@example.com")
        governor = AsyncMock()
        governor.validate_action.return_value = {"allowed": True, "decision": "ALLOW"}

        with patch(
            "src.gateway.governance.ingress.agw_adapter.generate_seal",
            return_value="seal.jwt.token",
        ):
            decision = await adapter.evaluate_request_authz(
                _tools_call(token, **{"x-geap-user-id": "user:mallory@example.com"}),
                governor=governor,
            )

        assert decision.allowed is True
        assert decision.tri_identity.user_id == "user:alice@example.com"
        assert decision.tri_identity.user_verified is True
        governed_params = governor.validate_action.call_args.args[1]
        assert governed_params["_tri_identity"]["id1_user"] == "user:alice@example.com"
        assert governed_params["_tri_identity"]["id1_user_verified"] is True

    async def test_request_authz_unverified_token_fails_closed_with_asserted_id1(
        self, geap_adapter
    ):
        adapter, priv = geap_adapter
        token = _geap_token(priv, kid="unknown-kid", act_sub="user:alice@example.com")
        governor = AsyncMock()

        decision = await adapter.evaluate_request_authz(
            _tools_call(token, **{"x-geap-user-id": "user:mallory@example.com"}),
            governor=governor,
        )

        assert decision.allowed is False
        assert decision.http_status == 403
        assert decision.decision == "UNAUTHENTICATED"
        assert decision.headers_to_inject == {}
        assert decision.tri_identity.user_id == "user:mallory@example.com"
        assert decision.tri_identity.user_verified is False
        governor.validate_action.assert_not_called()
