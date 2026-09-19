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
test_provider_07_adapter.py — Provider 07 (InferTheta) Adapter Tests
====================================================================

Comprehensive test suite for the Bayesian Causal Suitability Oracle adapter.

Tests cover:
- Protocol compliance (NormativeProvider 3-endpoint seam)
- JWKS-based Ed25519 key resolution and caching
- JCS signature verification over inference responses
- Tri-state decision mapping (ALLOW/REFUSE/ESCALATE → admitted bool)
- Token mint verification (authority_record_id required for ALLOW)
- Fail-closed semantics on HTTP errors, timeouts, signature failures, unknown kid
- Environment variable configuration via from_env()
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_07 import (
    InferThetaInferenceRequest,
    InferThetaInferenceResponse,
    NormativeProviderError,
    Provider07JwksClient,
    Provider07NormativeProvider,
    verify_inference_signature,
)

# Hermetic: tests provider_07 adapter with mocks, no live services
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate ephemeral Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def jwks_payload(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
) -> dict[str, Any]:
    """Generate mock JWKS payload with valid Ed25519 public key."""
    _, public_key = ed25519_keypair

    # Serialize public key to base64url (32 bytes for Ed25519)
    public_bytes = public_key.public_bytes_raw()
    x_b64 = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key-001",
                "x": x_b64,
            }
        ]
    }


@pytest.fixture
def mock_jwks_client(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
) -> Provider07JwksClient:
    """Create a mock JWKS client that returns the test public key."""
    _, public_key = ed25519_keypair

    client = MagicMock(spec=Provider07JwksClient)

    async def mock_get_key(kid: str) -> Ed25519PublicKey | None:
        if kid == "test-key-001":
            return public_key
        return None

    client.get_key = mock_get_key
    return client


def sign_response(
    payload: dict[str, Any],
    private_key: Ed25519PrivateKey,
    kid: str = "test-key-001",
) -> dict[str, Any]:
    """Generate a canonically signed InferTheta response payload."""
    # Add kid first (will be part of signed content)
    payload_with_kid = {**payload, "kid": kid}

    # Create canonical copy omitting signature field
    canonical_payload = {k: v for k, v in payload_with_kid.items() if k != "signature"}

    # Canonicalize via JCS
    canonical_bytes = jcs_canonicalize_plan(canonical_payload)

    # Sign with Ed25519
    signature_bytes = private_key.sign(canonical_bytes)
    signature_b64 = (
        base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    )

    # Return payload with kid and signature
    return {
        **payload_with_kid,
        "signature": signature_b64,
    }


@pytest.fixture
def valid_request_payload() -> dict[str, Any]:
    """Create a complete valid InferThetaInferenceRequest payload."""
    return {
        "scenario_id": "test-scenario-123",
        "action": "rebalance_portfolio",
        "target": "urn:portfolio:client-456",
        "actor_id": "urn:agent:advisor-789",
        "portfolio_vector": {"bonds": 0.6, "stocks": 0.4},
        "proposed_trade": {
            "asset": "VANGUARD_TOTAL_BOND_INDEX",
            "side": "BUY",
            "amount": 10000.0,
            "currency": "USD",
        },
        "client_profile": {
            "risk_tolerance": "CONSERVATIVE",
            "investment_horizon_years": 10,
            "liquidity_need": "MEDIUM",
        },
        "market_volatility_index": 0.15,
        "context": {},
    }


@pytest.fixture
def adapter(mock_jwks_client: Provider07JwksClient) -> Provider07NormativeProvider:
    """Create adapter instance with mock JWKS client."""
    return Provider07NormativeProvider(
        endpoint="http://localhost:8087",
        api_key="test-api-key",
        timeout_seconds=5.0,
        jwks_client=mock_jwks_client,
    )


def _mock_http_response(json_data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Create a mock httpx response."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx

        mock.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=MagicMock(status_code=status_code),
        )
    mock.status_code = status_code
    return mock


# ---------------------------------------------------------------------------
# Protocol Compliance Tests
# ---------------------------------------------------------------------------


class TestProtocolCompliance:
    """Tests for NormativeProvider protocol compliance."""

    @pytest.mark.asyncio
    async def test_fetch_baseline_success(
        self,
        adapter: Provider07NormativeProvider,
    ) -> None:
        """fetch_baseline returns NormativeBaseline with regional rules."""
        mock_response = _mock_http_response(
            {
                "region": "us-east-1",
                "rules": [
                    {
                        "rule_id": "SEC_REG_BI_2019",
                        "description": "SEC Regulation Best Interest",
                        "threshold": 0.85,
                    }
                ],
                "baseline_hash": "sha256-abc123",
                "issued_at": 1234567890,
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("us-east-1")

        assert isinstance(result, NormativeBaseline)
        assert result.region == "us-east-1"
        assert result.is_valid
        assert "rules" in result.profile
        assert len(result.profile["rules"]) == 1
        assert result.profile["rules"][0]["rule_id"] == "SEC_REG_BI_2019"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_fetch_baseline_http_error(
        self,
        adapter: Provider07NormativeProvider,
    ) -> None:
        """fetch_baseline fails closed on HTTP error."""
        mock_response = _mock_http_response({}, status_code=500)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("us-east-1")

        assert isinstance(result, NormativeBaseline)
        assert not result.is_valid
        assert result.error is not None
        assert "HTTP error" in result.error


# ---------------------------------------------------------------------------
# Tri-State Decision Mapping Tests
# ---------------------------------------------------------------------------


class TestTriStateDecisionMapping:
    """Tests for ALLOW/REFUSE/ESCALATE → admitted bool mapping."""

    @pytest.mark.asyncio
    async def test_validate_fria_allow_success(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """ALLOW with valid signature and authority_record_id → admitted=True."""
        private_key, _ = ed25519_keypair

        # Create unsigned response payload
        unsigned_payload = {
            "decision": "ALLOW",
            "confidence_score": 0.96,
            "posterior_risk_score": 0.08,
            "marginal_probabilities": {"drawdown_gt_15pct": 0.05},
            "utility_rankings": [],
            "authority_record_id": "auth-token-12345",
            "findings": [],
        }

        # Sign the response
        signed_response = sign_response(unsigned_payload, private_key)
        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            request_payload = {
                "scenario_id": "test-123",
                "action": "rebalance_portfolio",
                "target": "urn:portfolio:client-456",
                "actor_id": "urn:agent:advisor-789",
                "portfolio_vector": {"bonds": 0.6, "stocks": 0.4},
                "proposed_trade": {
                    "asset": "VANGUARD_TOTAL_BOND_INDEX",
                    "side": "BUY",
                    "amount": 10000.0,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "CONSERVATIVE",
                    "investment_horizon_years": 10,
                    "liquidity_need": "MEDIUM",
                },
                "market_volatility_index": 0.15,
            }

            result = await adapter.validate_fria(request_payload)

        assert isinstance(result, ValidationResult)
        assert result.admitted is True
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_ALLOW"
        assert result.findings[0]["authority_record_id"] == "auth-token-12345"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_validate_fria_allow_missing_authority_record_id(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """ALLOW without authority_record_id fails closed → admitted=False."""
        private_key, _ = ed25519_keypair

        unsigned_payload = {
            "decision": "ALLOW",
            "confidence_score": 0.96,
            "posterior_risk_score": 0.08,
            "marginal_probabilities": {},
            "utility_rankings": [],
            "authority_record_id": None,  # Missing token mint proof!
            "findings": [],
        }

        signed_response = sign_response(unsigned_payload, private_key)
        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "TOKEN_MINT_FAILED"

    @pytest.mark.asyncio
    async def test_validate_fria_refuse(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """REFUSE decision → admitted=False with INFERTHETA_UNSUITABLE."""
        private_key, _ = ed25519_keypair

        unsigned_payload = {
            "decision": "REFUSE",
            "confidence_score": 0.92,
            "posterior_risk_score": 0.78,
            "marginal_probabilities": {"drawdown_gt_15pct": 0.82},
            "utility_rankings": [],
            "authority_record_id": None,
            "findings": [],
        }

        signed_response = sign_response(unsigned_payload, private_key)
        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_UNSUITABLE"
        assert result.findings[0]["posterior_risk_score"] == 0.78

    @pytest.mark.asyncio
    async def test_validate_fria_escalate(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """ESCALATE decision → admitted=False, needs_human_review=True."""
        private_key, _ = ed25519_keypair

        unsigned_payload = {
            "decision": "ESCALATE",
            "confidence_score": 0.68,
            "posterior_risk_score": 0.55,
            "marginal_probabilities": {"regulatory_ambiguity": 0.91},
            "utility_rankings": [],
            "authority_record_id": None,
            "findings": [],
        }

        signed_response = sign_response(unsigned_payload, private_key)
        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_ESCALATE"
        assert result.findings[0]["needs_human_review"] is True
        assert result.findings[0]["posterior_risk_score"] == 0.55


# ---------------------------------------------------------------------------
# Signature Verification Tests
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    """Tests for Ed25519 JCS signature verification."""

    @pytest.mark.asyncio
    async def test_validate_fria_unknown_kid(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """Unknown kid not in JWKS → admitted=False, INFERTHETA_UNKNOWN_KEY."""
        private_key, _ = ed25519_keypair

        unsigned_payload = {
            "decision": "ALLOW",
            "confidence_score": 0.96,
            "posterior_risk_score": 0.08,
            "marginal_probabilities": {},
            "utility_rankings": [],
            "authority_record_id": "should-not-matter",
            "findings": [],
        }

        # Sign with unknown kid
        signed_response = sign_response(
            unsigned_payload, private_key, kid="unknown-key-999"
        )
        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_UNKNOWN_KEY"

    @pytest.mark.asyncio
    async def test_validate_fria_invalid_signature(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """Signature verification failure → admitted=False, INFERTHETA_SIGNATURE_INVALID."""
        private_key, _ = ed25519_keypair

        unsigned_payload = {
            "decision": "ALLOW",
            "confidence_score": 0.96,
            "posterior_risk_score": 0.08,
            "marginal_probabilities": {},
            "utility_rankings": [],
            "authority_record_id": "auth-token-123",
            "findings": [],
        }

        signed_response = sign_response(unsigned_payload, private_key)

        # Corrupt the signature
        signed_response["signature"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        mock_response = _mock_http_response(signed_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# Fail-Closed Error Handling Tests
# ---------------------------------------------------------------------------


class TestFailClosedSemantics:
    """Tests for fail-closed behavior on HTTP errors and timeouts."""

    @pytest.mark.asyncio
    async def test_validate_fria_http_500_fail_closed(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
    ) -> None:
        """HTTP 500 server error → admitted=False, PROVIDER_07_HTTP_ERROR."""
        mock_response = _mock_http_response({}, status_code=500)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "PROVIDER_07_HTTP_ERROR"

    @pytest.mark.asyncio
    async def test_validate_fria_timeout_fail_closed(
        self,
        adapter: Provider07NormativeProvider,
        valid_request_payload: dict[str, Any],
    ) -> None:
        """Request timeout → admitted=False."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = httpx.TimeoutException("Timeout")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(valid_request_payload)

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "PROVIDER_07_HTTP_ERROR"


# ---------------------------------------------------------------------------
# Evidence Submission Tests
# ---------------------------------------------------------------------------


class TestEvidenceSubmission:
    """Tests for submit_evidence() audit trail submission."""

    @pytest.mark.asyncio
    async def test_submit_evidence_success(
        self,
        adapter: Provider07NormativeProvider,
    ) -> None:
        """submit_evidence returns EvidenceSeal with seal_hash."""
        mock_response = _mock_http_response(
            {
                "thread_id": "thread-123",
                "seal_hash": "sha256-seal-abc",
                "timestamp": 1234567890.5,
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-123", "evidence-hash-xyz")

        assert isinstance(result, EvidenceSeal)
        assert result.thread_id == "thread-123"
        assert result.seal_hash == "sha256-seal-abc"
        assert result.error is None


# ---------------------------------------------------------------------------
# Environment Variable Configuration Tests
# ---------------------------------------------------------------------------


class TestEnvironmentConfiguration:
    """Tests for from_env() constructor."""

    def test_from_env_instantiation(self) -> None:
        """from_env() reads PROVIDER_07_* environment variables."""
        env_vars = {
            "PROVIDER_07_ENDPOINT": "http://infertheta.example.com",
            "PROVIDER_07_API_KEY": "test-key-abc",
            "PROVIDER_07_JWKS_URL": "http://infertheta.example.com/.well-known/jwks.json",
            "PROVIDER_07_TIMEOUT_SECONDS": "10.0",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            adapter = Provider07NormativeProvider.from_env()

        assert adapter._endpoint == "http://infertheta.example.com"
        assert adapter._api_key == "test-key-abc"
        assert adapter._timeout_seconds == 10.0

    def test_from_env_default_endpoint(self) -> None:
        """from_env() uses default endpoint when PROVIDER_07_ENDPOINT is not set."""
        with patch.dict(os.environ, {}, clear=True):
            adapter = Provider07NormativeProvider.from_env()
            assert adapter._endpoint == "http://localhost:8087"


# ---------------------------------------------------------------------------
# JWKS Client Tests
# ---------------------------------------------------------------------------


class TestJwksClient:
    """Tests for Provider07JwksClient key resolution."""

    def test_jwks_url_scheme_validation(self) -> None:
        """JWKS client rejects non-http/https URLs (Bandit B310 compliance)."""
        with pytest.raises(ValueError, match="Invalid JWKS URL scheme"):
            Provider07JwksClient(jwks_url="ftp://invalid.example.com/jwks.json")

    @pytest.mark.asyncio
    async def test_jwks_client_key_resolution(
        self,
        jwks_payload: dict[str, Any],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """JWKS client resolves Ed25519 keys from manifest."""
        _, public_key = ed25519_keypair

        mock_response = MagicMock()
        mock_response.json.return_value = jwks_payload
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            client = Provider07JwksClient(
                jwks_url="http://localhost:8087/.well-known/jwks.json"
            )
            resolved_key = await client.get_key("test-key-001")

        assert resolved_key is not None
        assert isinstance(resolved_key, Ed25519PublicKey)
        # Verify it's the same key by comparing serialized bytes
        assert resolved_key.public_bytes_raw() == public_key.public_bytes_raw()

    @pytest.mark.asyncio
    async def test_jwks_client_unknown_kid_returns_none(
        self,
        jwks_payload: dict[str, Any],
    ) -> None:
        """JWKS client returns None for unknown kid (caller must fail closed)."""
        mock_response = MagicMock()
        mock_response.json.return_value = jwks_payload
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            client = Provider07JwksClient(
                jwks_url="http://localhost:8087/.well-known/jwks.json"
            )
            resolved_key = await client.get_key("unknown-key-999")

        assert resolved_key is None


# ---------------------------------------------------------------------------
# Signature Verification Function Tests
# ---------------------------------------------------------------------------


def test_verify_inference_signature_success(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
) -> None:
    """verify_inference_signature returns True for valid signature."""
    private_key, public_key = ed25519_keypair

    payload = {
        "decision": "ALLOW",
        "confidence_score": 0.95,
        "posterior_risk_score": 0.10,
    }

    signed_payload = sign_response(payload, private_key)

    result = verify_inference_signature(
        payload=signed_payload,
        public_key=public_key,
        signature_b64=signed_payload["signature"],
    )

    assert result is True


def test_verify_inference_signature_invalid(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
) -> None:
    """verify_inference_signature returns False for invalid signature."""
    _, public_key = ed25519_keypair

    payload = {
        "decision": "ALLOW",
        "signature": "INVALID_SIGNATURE_BASE64",
    }

    result = verify_inference_signature(
        payload=payload,
        public_key=public_key,
        signature_b64="INVALID_SIGNATURE_BASE64",
    )

    assert result is False


# ---------------------------------------------------------------------------
# Partner Contract Alignment Vectors (InferTheta Step 1 Review Package)
# ---------------------------------------------------------------------------


@pytest.fixture
def partner_contract_vectors() -> list[dict[str, Any]]:
    """Test vectors provided by InferTheta partner for Step 1 field-name lock."""
    return [
        {
            "id": "allow",
            "narrative": "Moderate client, balanced mix, small bond buy, low VIX.",
            "request": {
                "scenario_id": "11111111-1111-4111-8111-111111111111",
                "action": "rebalance_portfolio",
                "target": "urn:account:client-allow:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.4,
                    "INTL_EQUITY": 0.1,
                    "FIXED_INCOME": 0.4,
                    "CASH": 0.1,
                },
                "proposed_trade": {
                    "asset": "VANGUARD_TOTAL_BOND_INDEX",
                    "side": "BUY",
                    "amount": 25000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "MODERATE",
                    "investment_horizon_years": 12,
                    "liquidity_need": "LOW",
                },
                "market_volatility_index": 0.12,
                "context": {
                    "session_id": "advise-allow",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
            "response": {
                "decision": "ALLOW",
                "confidence_score": 0.918,
                "posterior_risk_score": 0.082,
                "marginal_probabilities": {
                    "drawdown_gt_15pct": 0.08,
                    "volatility_spike": 0.12,
                    "liquidity_stress": 0.03,
                },
                "utility_rankings": [
                    {"action": "rebalance_to_proposed", "expected_utility": 0.87},
                    {"action": "defer_to_human", "expected_utility": 0.65},
                    {"action": "reject_trade", "expected_utility": 0.42},
                ],
                "authority_record_id": "infertheta-step1-allow-unsigned",
                "kid": "infertheta-staging-ed25519-step1",
                "signature": "unsigned-placeholder",
                "findings": [
                    {
                        "rule_id": "FINRA-2111-CUSTOMER-SPECIFIC",
                        "status": "COMPLIANT",
                        "evidence": "Moderate profile, bond buy, low volatility. Best EU is rebalance_to_proposed.",
                    },
                    {
                        "rule_id": "SEC-REGBI-BEST-INTEREST",
                        "status": "COMPLIANT",
                        "evidence": "posterior_risk_score 0.082 = 0.5*0.08 + 0.3*0.12 + 0.2*0.03, below the 0.20 ALLOW band.",
                    },
                ],
            },
        },
        {
            "id": "refuse",
            "narrative": "Conservative client, already >70% equity, large equity buy, high VIX.",
            "request": {
                "scenario_id": "22222222-2222-4222-8222-222222222222",
                "action": "execute_trade",
                "target": "urn:account:client-refuse:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.7,
                    "INTL_EQUITY": 0.15,
                    "FIXED_INCOME": 0.1,
                    "CASH": 0.05,
                },
                "proposed_trade": {
                    "asset": "VANGUARD_TOTAL_STOCK_MARKET",
                    "side": "BUY",
                    "amount": 150000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "CONSERVATIVE",
                    "investment_horizon_years": 3,
                    "liquidity_need": "HIGH",
                },
                "market_volatility_index": 0.42,
                "context": {
                    "session_id": "advise-refuse",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
            "response": {
                "decision": "REFUSE",
                "confidence_score": 0.535,
                "posterior_risk_score": 0.465,
                "marginal_probabilities": {
                    "drawdown_gt_15pct": 0.55,
                    "volatility_spike": 0.4,
                    "liquidity_stress": 0.35,
                },
                "utility_rankings": [
                    {"action": "reject_trade", "expected_utility": 0.88},
                    {"action": "defer_to_human", "expected_utility": 0.51},
                    {"action": "rebalance_to_proposed", "expected_utility": 0.22},
                ],
                "authority_record_id": None,
                "kid": "infertheta-staging-ed25519-step1",
                "signature": "unsigned-placeholder",
                "findings": [
                    {
                        "rule_id": "FINRA-2111-CUSTOMER-SPECIFIC",
                        "status": "BREACH",
                        "evidence": "CONSERVATIVE client, HIGH liquidity need, large EQUITY buy with short horizon.",
                    },
                    {
                        "rule_id": "SEC-REGBI-BEST-INTEREST",
                        "status": "BREACH",
                        "evidence": "posterior_risk_score 0.465 = 0.5*0.55 + 0.3*0.40 + 0.2*0.35, at or above 0.40 REFUSE band.",
                    },
                ],
            },
        },
        {
            "id": "escalate",
            "narrative": "Moderate client, modest equity buy, mid VIX.",
            "request": {
                "scenario_id": "33333333-3333-4333-8333-333333333333",
                "action": "execute_trade",
                "target": "urn:account:client-escalate:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.5,
                    "INTL_EQUITY": 0.15,
                    "FIXED_INCOME": 0.25,
                    "CASH": 0.1,
                },
                "proposed_trade": {
                    "asset": "SPDR_S_AND_P_500",
                    "side": "BUY",
                    "amount": 40000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "MODERATE",
                    "investment_horizon_years": 8,
                    "liquidity_need": "MEDIUM",
                },
                "market_volatility_index": 0.28,
                "context": {
                    "session_id": "advise-escalate",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
            "response": {
                "decision": "ESCALATE",
                "confidence_score": 0.745,
                "posterior_risk_score": 0.255,
                "marginal_probabilities": {
                    "drawdown_gt_15pct": 0.28,
                    "volatility_spike": 0.25,
                    "liquidity_stress": 0.2,
                },
                "utility_rankings": [
                    {"action": "defer_to_human", "expected_utility": 0.72},
                    {"action": "rebalance_to_proposed", "expected_utility": 0.58},
                    {"action": "reject_trade", "expected_utility": 0.41},
                ],
                "authority_record_id": None,
                "kid": "infertheta-staging-ed25519-step1",
                "signature": "unsigned-placeholder",
                "findings": [
                    {
                        "rule_id": "FINRA-2111-CUSTOMER-SPECIFIC",
                        "status": "REVIEW",
                        "evidence": "posterior_risk_score 0.255 sits in [0.20, 0.40). Best EU is defer_to_human.",
                    },
                    {
                        "rule_id": "SEC-REGBI-BEST-INTEREST",
                        "status": "REVIEW",
                        "evidence": "Human judgment, not autonomous execution.",
                    },
                ],
            },
        },
    ]


class TestInferThetaPartnerContractVectors:
    """Test suite validating partner InferTheta contract vectors against adapter."""

    def test_partner_vectors_schema_validation(
        self,
        partner_contract_vectors: list[dict[str, Any]],
    ) -> None:
        """All partner test vectors parse strictly into CAGE Pydantic models."""
        for vector in partner_contract_vectors:
            req = InferThetaInferenceRequest(**vector["request"])
            assert req.action in ("rebalance_portfolio", "execute_trade")
            assert req.proposed_trade.currency == "USD"

            resp = InferThetaInferenceResponse(**vector["response"])
            assert resp.decision in ("ALLOW", "REFUSE", "ESCALATE")
            assert 0.0 <= resp.confidence_score <= 1.0
            assert 0.0 <= resp.posterior_risk_score <= 1.0

    @pytest.mark.asyncio
    async def test_partner_vector_allow_flow(
        self,
        adapter: Provider07NormativeProvider,
        partner_contract_vectors: list[dict[str, Any]],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """Partner ALLOW vector passes verification and admits action."""
        private_key, _ = ed25519_keypair
        allow_vector = next(v for v in partner_contract_vectors if v["id"] == "allow")

        signed_resp = sign_response(allow_vector["response"], private_key)
        mock_response = _mock_http_response(signed_resp)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(allow_vector["request"])

        assert isinstance(result, ValidationResult)
        assert result.admitted is True
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_ALLOW"
        assert (
            result.findings[0]["authority_record_id"]
            == "infertheta-step1-allow-unsigned"
        )
        assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.082)

    @pytest.mark.asyncio
    async def test_partner_vector_refuse_flow(
        self,
        adapter: Provider07NormativeProvider,
        partner_contract_vectors: list[dict[str, Any]],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """Partner REFUSE vector fails closed as unsuitable."""
        private_key, _ = ed25519_keypair
        refuse_vector = next(v for v in partner_contract_vectors if v["id"] == "refuse")

        signed_resp = sign_response(refuse_vector["response"], private_key)
        mock_response = _mock_http_response(signed_resp)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(refuse_vector["request"])

        assert isinstance(result, ValidationResult)
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_UNSUITABLE"
        assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.465)

    @pytest.mark.asyncio
    async def test_partner_vector_escalate_flow(
        self,
        adapter: Provider07NormativeProvider,
        partner_contract_vectors: list[dict[str, Any]],
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey],
    ) -> None:
        """Partner ESCALATE vector blocks autonomous action and sets needs_human_review."""
        private_key, _ = ed25519_keypair
        escalate_vector = next(
            v for v in partner_contract_vectors if v["id"] == "escalate"
        )

        signed_resp = sign_response(escalate_vector["response"], private_key)
        mock_response = _mock_http_response(signed_resp)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(escalate_vector["request"])

        assert isinstance(result, ValidationResult)
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "INFERTHETA_ESCALATE"
        assert result.findings[0]["needs_human_review"] is True
        assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.255)

    @pytest.mark.asyncio
    async def test_partner_vectors_unsigned_fail_closed(
        self,
        adapter: Provider07NormativeProvider,
        partner_contract_vectors: list[dict[str, Any]],
    ) -> None:
        """Unsigned Step 1 partner payloads fail closed under live adapter execution."""
        allow_vector = next(v for v in partner_contract_vectors if v["id"] == "allow")
        raw_unsigned_response = allow_vector["response"]
        mock_response = _mock_http_response(raw_unsigned_response)

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(allow_vector["request"])

        # Fails closed because signature/kid cannot be verified
        assert isinstance(result, ValidationResult)
        assert result.admitted is False
        assert result.findings[0]["code"] in (
            "INFERTHETA_UNKNOWN_KEY",
            "INFERTHETA_SIGNATURE_INVALID",
        )

