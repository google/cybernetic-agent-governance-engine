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
test_provider_01.py — Provider 01 Adapter Tests
===============================================

Tests for the Provider 01 NormativeProvider adapter including:
- Protocol compliance (correct method signatures and return types)
- HTTP error handling (HTTPStatusError, RequestError)
- Rich findings generation on failure
- Fail-closed behavior
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.provider_01.provider import Provider01NormativeProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> Provider01NormativeProvider:
    """Create an adapter with a mock endpoint."""
    return Provider01NormativeProvider(
        endpoint="http://localhost:8080",
        api_key="test-api-key",
        timeout=5.0,
    )


@pytest.fixture
def adapter_no_endpoint() -> Provider01NormativeProvider:
    """Create an adapter without an endpoint configured."""
    return Provider01NormativeProvider(
        endpoint="",
        api_key="",
        timeout=5.0,
    )


def _mock_response(json_data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Create a mock httpx response."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    mock.headers = {"ETag": "test-etag-123"}
    mock.status_code = status_code
    return mock


# ---------------------------------------------------------------------------
# Protocol Compliance Tests
# ---------------------------------------------------------------------------


class TestProtocolCompliance:
    """Tests for NormativeProvider protocol compliance."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_fetch_baseline_returns_normative_baseline(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """fetch_baseline returns NormativeBaseline dataclass."""
        mock_response = _mock_response(
            {
                "profile": {"controls": ["AC-1", "AC-2"]},
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("US_FED")

        from src.gateway.governance.normative_provider import NormativeBaseline

        assert isinstance(result, NormativeBaseline)
        assert result.region == "US_FED"
        assert result.profile == {"controls": ["AC-1", "AC-2"]}
        assert result.etag == "test-etag-123"
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_validate_fria_returns_validation_result(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """validate_fria returns ValidationResult dataclass."""
        mock_response = _mock_response(
            {
                "decision": "REFUSE",
                "findings": [],
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        from src.gateway.governance.normative_provider import ValidationResult

        assert isinstance(result, ValidationResult)
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "FLOWSIGNAL_REFUSE"
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_returns_evidence_seal(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """submit_evidence returns EvidenceSeal dataclass."""
        mock_response = _mock_response(
            {
                "seal_hash": "sha256-abc123",
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-123", "evidence-hash")

        from src.gateway.governance.normative_provider import EvidenceSeal

        assert isinstance(result, EvidenceSeal)
        assert result.thread_id == "thread-123"
        assert result.seal_hash == "sha256-abc123"
        assert result.error is None


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for HTTP error handling and fail-closed behavior."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_status_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """HTTPStatusError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 503
            mock_response.text = "Service Unavailable"
            client_instance.post.side_effect = httpx.HTTPStatusError(
                message="Service Error",
                request=MagicMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert result.error == "HTTP 503"
        # Verify rich findings are present
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["severity"] == "blocked"
        assert "503" in result.findings[0]["message"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_request_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """RequestError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = httpx.ConnectError("Connection refused")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert "Connection refused" in (result.error or "")
        # Verify rich findings are present
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["severity"] == "blocked"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_status_error_on_fetch_baseline_returns_error(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """HTTPStatusError on fetch_baseline returns NormativeBaseline with error."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = "Not Found"
            client_instance.get.side_effect = httpx.HTTPStatusError(
                message="Not Found",
                request=MagicMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("UNKNOWN_REGION")

        assert result.region == "UNKNOWN_REGION"
        assert result.profile == {}
        assert "HTTP 404" in (result.error or "")

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_request_error_on_submit_evidence_returns_error(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """RequestError on submit_evidence returns EvidenceSeal with error."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.side_effect = httpx.TimeoutException("Timeout")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-123", "evidence-hash")

        assert result.thread_id == "thread-123"
        assert result.seal_hash == ""
        assert "Timeout" in (result.error or "")


# ---------------------------------------------------------------------------
# Factory Registration Tests
# ---------------------------------------------------------------------------


class TestFactoryRegistration:
    """Tests for provider_01 registration in the factory."""

    def test_provider_01_is_registered(self) -> None:
        """provider_01 is listed in available providers."""
        from src.gateway.governance.normative_provider import get_normative_provider

        # Attempting to get an unknown provider should list provider_01
        try:
            get_normative_provider("nonexistent_provider")
        except ValueError as exc:
            assert "provider_01" in str(exc)

    @pytest.mark.local
    def test_provider_01_instantiates(self) -> None:
        """provider_01 can be instantiated via factory."""
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider("provider_01")
        assert isinstance(provider, Provider01NormativeProvider)


# ---------------------------------------------------------------------------
# Phase 2 ST-4: ConsequenceToken Minting Tests
# ---------------------------------------------------------------------------


class TestConsequenceTokenMinting:
    """Tests for ConsequenceToken minting on FlowSignal ALLOW (Phase 2 ST-4)."""

    def _make_mock_signer_with_keypair(self):
        """Create a mock signer with a real EC P-256 keypair for authentic sign/verify."""
        from unittest.mock import MagicMock

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        from src.gateway.governance.kms_signer import (
            GCPKMSProvider,
            KMSGovernanceSigner,
        )

        # Generate real keypair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Mock KMS client
        mock_client = MagicMock()
        key_name = "projects/test/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"

        # Mock get_crypto_key_version for algorithm detection
        mock_version = MagicMock()
        mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
        mock_client.get_crypto_key_version.return_value = mock_version

        # Create provider (auto-detects sha256 from mocked algorithm)
        provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)

        # Create signer
        signer = KMSGovernanceSigner(
            kms_client=mock_client,
            key_version_name=key_name,
            public_key_pem=public_pem,
            provider=provider,
        )

        # Mock sign_raw to use the real private key
        def mock_sign_raw(message: bytes) -> bytes:
            import hashlib

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

            digest = hashlib.sha256(message).digest()
            hash_alg = hashes.SHA256()
            return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hash_alg)))

        # Patch the provider's sign_digest method
        provider.sign_digest = MagicMock(side_effect=lambda d: mock_sign_raw(b"dummy"))

        # Actually we need to mock sign_raw on the signer level
        signer.sign_raw = MagicMock(side_effect=mock_sign_raw)

        return signer

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_allow_mints_consequence_token(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """FlowSignal ALLOW mints a ConsequenceToken and attaches it as a finding."""
        from unittest.mock import patch

        import httpx

        action_payload = {
            "actor_id": "user-12345",
            "thread_id": "thread-abc",
            "action": "trade",
            "amount": 50000,
        }

        flowsignal_response = {
            "decision": "ALLOW",
            "authority_record_id": "auth-record-xyz",
            "authority_state_version": "v1.2.3",
            "message": "Transaction approved",
        }

        mock_response = _mock_response(flowsignal_response)

        # Mock the signer
        mock_signer = self._make_mock_signer_with_keypair()

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        # Assertions
        assert result.admitted is True, "ALLOW should admit the transaction"
        assert len(result.findings) == 1, (
            "ALLOW should produce exactly one finding (CONSEQUENCE_TOKEN)"
        )

        finding = result.findings[0]
        assert finding["code"] == "CONSEQUENCE_TOKEN"
        assert finding["severity"] == "info"
        assert "token" in finding, "Finding must contain the JWS token"
        assert finding["authority_record_id"] == "auth-record-xyz"

        # Verify the token is a well-formed JWS (3 base64url segments)
        token = finding["token"]
        assert isinstance(token, str)
        assert token.count(".") == 2, "JWS must have 3 segments"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_minted_token_round_trips_verification(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """The minted ConsequenceToken can be verified and claims match inputs."""
        from unittest.mock import patch

        import httpx

        from src.gateway.governance.consequence_token import ConsequenceToken

        action_payload = {
            "actor_id": "user-99999",
            "thread_id": "thread-xyz",
            "action": "transfer",
            "destination": "account-456",
        }

        flowsignal_response = {
            "decision": "ALLOW",
            "authority_record_id": "auth-rec-12345",
            "authority_state_version": "v2.0.0",
        }

        mock_response = _mock_response(flowsignal_response)
        mock_signer = self._make_mock_signer_with_keypair()

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        token = result.findings[0]["token"]

        # Verify the token
        claims = ConsequenceToken.verify(token, signer=mock_signer)

        # Assertions: claims match the expected inputs
        assert claims.sub == "user-99999", "sub claim must match actor_id"
        assert claims.tid == "thread-xyz", "tid claim must match thread_id"
        assert claims.rec == "auth-rec-12345", (
            "rec claim must match authority_record_id"
        )
        assert claims.ver == "v2.0.0", "ver claim must match authority_state_version"
        assert claims.jti == claims.rec, "jti must equal rec"

        # Verify action digest matches
        import hashlib

        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        expected_digest = hashlib.sha256(
            jcs_canonicalize_plan(action_payload)
        ).hexdigest()
        assert claims.act == expected_digest, (
            "act claim must match JCS digest of action_payload"
        )

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_minted_token_integrates_with_consequence_gateway(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """Cross-module integration: minted token produces EXECUTE from ConsequenceGateway."""
        pytest.importorskip("fakeredis", reason="fakeredis required")
        from unittest.mock import patch

        import fakeredis.aioredis
        import httpx

        from src.gateway.governance.consequence_authority_store import (
            ConsequenceAuthorityStore,
        )
        from src.gateway.governance.consequence_gateway import (
            ConsequenceDecision,
            ConsequenceGateway,
        )

        action_payload = {
            "actor_id": "user-integration",
            "thread_id": "thread-integration",
            "action": "high_value_trade",
            "value": 100000,
        }

        flowsignal_response = {
            "decision": "ALLOW",
            "authority_record_id": "auth-integration-test",
            "authority_state_version": "v1.0",
        }

        mock_response = _mock_response(flowsignal_response)
        mock_signer = self._make_mock_signer_with_keypair()

        # Mint the token via provider_01
        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        token = result.findings[0]["token"]

        # Consume the token via ConsequenceGateway (with fakeredis)
        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        store = ConsequenceAuthorityStore(fake_redis, ttl_seconds=90)
        gateway = ConsequenceGateway(store=store, signer=mock_signer)

        evaluation = await gateway.evaluate(token, action_payload)

        # Assertions: gateway accepts the token
        assert evaluation.decision == ConsequenceDecision.EXECUTE, (
            "Token should produce EXECUTE"
        )
        assert evaluation.reason_code == "OK"

        # Replay should fail (single-use enforcement)
        replay_evaluation = await gateway.evaluate(token, action_payload)
        assert replay_evaluation.decision == ConsequenceDecision.BLOCK
        assert replay_evaluation.reason_code == "ALREADY_CONSUMED"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_mint_failure_fails_closed(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """If ConsequenceToken minting fails, validate_fria returns admitted=False."""
        from unittest.mock import MagicMock, patch

        import httpx

        action_payload = {
            "actor_id": "user-fail",
            "thread_id": "thread-fail",
            "action": "test",
        }

        flowsignal_response = {
            "decision": "ALLOW",
            "authority_record_id": "auth-fail",
        }

        mock_response = _mock_response(flowsignal_response)

        # Mock signer to raise (simulate KMS failure)
        mock_signer = MagicMock()
        mock_signer.sign_raw.side_effect = RuntimeError("KMS unavailable")

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        # Assertions: fail-closed
        assert result.admitted is False, (
            "Mint failure must fail-closed (admitted=False)"
        )
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"
        assert result.findings[0]["severity"] == "blocked"
        assert "ConsequenceToken minting failed" in result.findings[0]["message"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_refuse_does_not_mint_token(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """FlowSignal REFUSE does not mint a token."""
        from unittest.mock import patch

        import httpx

        action_payload = {"actor_id": "user-refuse", "thread_id": "thread-refuse"}

        flowsignal_response = {
            "decision": "REFUSE",
            "message": "Transaction blocked",
        }

        mock_response = _mock_response(flowsignal_response)
        mock_signer = MagicMock()

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        # Assertions: no token minted, mint not called
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "FLOWSIGNAL_REFUSE"
        assert "token" not in result.findings[0]
        mock_signer.sign_raw.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_escalate_does_not_mint_token(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """FlowSignal ESCALATE does not mint a token."""
        from unittest.mock import patch

        import httpx

        action_payload = {"actor_id": "user-escalate", "thread_id": "thread-escalate"}

        flowsignal_response = {
            "decision": "ESCALATE",
            "message": "Requires human review",
        }

        mock_response = _mock_response(flowsignal_response)
        mock_signer = MagicMock()

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        # Assertions: no token minted
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "FLOWSIGNAL_HOLD"
        assert "token" not in result.findings[0]
        mock_signer.sign_raw.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_flowsignal_allow_without_authority_record_fails_closed(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """FlowSignal ALLOW without authority_record_id fails closed (Phase 2 ST-4).

        When the response includes decision=ALLOW but omits authority_record_id,
        ConsequenceToken minting fails and the entire validation fails closed
        with admitted=False and CONSEQUENCE_TOKEN_MINT_FAILED finding.
        """
        from unittest.mock import patch

        import httpx

        action_payload = {"actor_id": "user-legacy", "thread_id": "thread-legacy"}

        # FlowSignal response with decision but missing authority_record_id
        response = {
            "decision": "ALLOW",
            "findings": [],
        }

        mock_response = _mock_response(response)
        mock_signer = MagicMock()

        with (
            patch("httpx.AsyncClient") as MockClient,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer",
                return_value=mock_signer,
            ),
        ):
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(action_payload)

        # Assertions: minting failed, fail-closed
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"
        assert "authority_record_id missing" in result.findings[0]["message"]
        mock_signer.sign_raw.assert_not_called()
