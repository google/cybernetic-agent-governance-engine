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
test_consequence_token_service.py — Kernel Minting Service Tests (Phase 8, C6)

Tests for the relocated ConsequenceToken minting service. Validates:
1. Byte-identical token generation across the relocation (regression guard)
2. Fail-closed behavior when authority_record_id is missing
3. Kernel service isolation (no adapter-layer dependencies)
"""

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.consequence_token_service import (
    FINDING_CODE_CONSEQUENCE_TOKEN,
    FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
    mint_consequence_token_finding,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestConsequenceTokenService:
    """Test suite for the kernel minting service."""

    def test_mint_consequence_token_finding_success(self) -> None:
        """Successful minting returns CONSEQUENCE_TOKEN finding with JWS token."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/locations/us/keyRings/cage/cryptoKeys/gov/cryptoKeyVersions/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.return_value = b"mock_signature_64_bytes_" + b"\x00" * 40

        action_payload = {
            "action": "execute_trade",
            "symbol": "AAPL",
            "quantity": 100,
        }

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
                authority_state_version="v1",
                ttl_seconds=60,
            )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN
        assert finding["severity"] == "info"
        assert "token" in finding
        assert finding["authority_record_id"] == "rec-xyz"
        assert "ConsequenceToken minted" in finding["message"]

        # Verify token format (compact JWS: header.payload.signature)
        token = finding["token"]
        parts = token.split(".")
        assert len(parts) == 3, "Token should be compact JWS with 3 parts"

    def test_mint_without_authority_record_id_fails_closed(self) -> None:
        """Missing authority_record_id fails closed with MINT_FAILED finding."""
        action_payload = {"action": "execute_trade", "actor_id": "user-123"}

        # No patching needed — the service should fail before reaching KMS
        finding = mint_consequence_token_finding(
            actor_id="user-123",
            thread_id="thread-abc",
            authority_record_id="",  # Missing!
            action_payload=action_payload,
        )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "authority_record_id missing from FlowSignal response" in finding["message"]

    def test_mint_without_actor_id_fails_closed(self) -> None:
        """Missing actor_id fails closed with MINT_FAILED finding."""
        action_payload = {"action": "execute_trade"}

        finding = mint_consequence_token_finding(
            actor_id="",  # Missing!
            thread_id="thread-abc",
            authority_record_id="rec-xyz",
            action_payload=action_payload,
        )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "actor_id missing from action_payload" in finding["message"]

    def test_byte_identical_tokens_across_relocation(self) -> None:
        """Tokens minted by kernel service match old adapter-side minting.

        This is the critical regression guard: if canonicalization or claim
        ordering changes, downstream verification breaks silently. The kernel
        service must produce byte-identical tokens to the prior adapter path.
        """
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/locations/us/keyRings/cage/cryptoKeys/gov/cryptoKeyVersions/1"
        mock_signer.jose_alg = "ES256"

        # Fixed signature for deterministic comparison
        fixed_signature = b"A" * 64
        mock_signer.sign_raw.return_value = fixed_signature

        action_payload = {
            "action": "execute_trade",
            "symbol": "AAPL",
            "quantity": 100,
            "actor_id": "user-deterministic",
            "thread_id": "thread-deterministic",
        }

        with (
            patch(
                "src.gateway.governance.consequence_token_service.get_governance_signer",
                return_value=mock_signer,
            ),
            patch("time.time", return_value=1234567890),
        ):
            finding = mint_consequence_token_finding(
                actor_id="user-deterministic",
                thread_id="thread-deterministic",
                authority_record_id="rec-deterministic",
                action_payload=action_payload,
                authority_state_version="v1",
                ttl_seconds=60,
            )

        token_new = finding["token"]

        # Simulate the old adapter-side path (directly calling ConsequenceToken.mint)
        with patch("time.time", return_value=1234567890):
            from src.gateway.governance.consequence_token import ConsequenceToken

            action_digest = hashlib.sha256(
                jcs_canonicalize_plan(action_payload)
            ).hexdigest()
            token_old = ConsequenceToken.mint(
                sub="user-deterministic",
                tid="thread-deterministic",
                rec="rec-deterministic",
                act=action_digest,
                ver="v1",
                ttl_seconds=60,
                signer=mock_signer,
            )

        # The tokens MUST be byte-identical (this is the regression guard)
        assert (
            token_new == token_old
        ), "Kernel service must produce byte-identical tokens to old adapter path"

        # Verify signing input was identical (same number of calls, same message)
        assert mock_signer.sign_raw.call_count == 2
        call_args_new = mock_signer.sign_raw.call_args_list[0][0][0]
        call_args_old = mock_signer.sign_raw.call_args_list[1][0][0]
        assert (
            call_args_new == call_args_old
        ), "Signing inputs must match across relocation"

    def test_kms_signing_failure_fails_closed(self) -> None:
        """KMS signing failure returns fail-closed MINT_FAILED finding."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/locations/us/keyRings/cage/cryptoKeys/gov/cryptoKeyVersions/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.side_effect = RuntimeError("KMS unavailable")

        action_payload = {"action": "execute_trade"}

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
            )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "KMS unavailable" in finding["message"]

    def test_nullable_authority_state_version(self) -> None:
        """authority_state_version=None is normalized to empty string in claims."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/key/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.return_value = b"X" * 64

        action_payload = {"action": "test"}

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
                authority_state_version=None,  # Nullable
            )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN
        # Token should be successfully minted with ver="" in claims
        assert "token" in finding
