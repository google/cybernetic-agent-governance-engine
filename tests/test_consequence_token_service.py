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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.gateway.governance.consequence_magnitude import ConsequenceMagnitudes
from src.gateway.governance.consequence_token_service import (
    FINDING_CODE_CONSEQUENCE_TOKEN,
    FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED,
    mint_consequence_token_finding,
)
from src.gateway.governance.contracts import ConsequenceMagnitude, MagnitudePath
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

pytestmark = [pytest.mark.unit, pytest.mark.local]

_MAGNITUDES = ConsequenceMagnitudes(
    (
        ConsequenceMagnitude("execute_trade", (MagnitudePath(("quantity",), 0),)),
        ConsequenceMagnitude("test", ()),
    )
)


class TestConsequenceTokenService:
    """Test suite for the kernel minting service."""

    async def test_mint_consequence_token_finding_success(self) -> None:
        """Successful minting returns CONSEQUENCE_TOKEN finding with JWS token."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/locations/us/keyRings/cage/cryptoKeys/gov/cryptoKeyVersions/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.return_value = b"mock_signature_64_bytes_" + b"\x00" * 40
        mock_signer.sign_raw_async = AsyncMock(
            side_effect=lambda msg: mock_signer.sign_raw(msg)
        )

        action_payload = {
            "action": "execute_trade",
            "params": {"symbol": "AAPL", "quantity": 100},
        }

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = await mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
                authority_state_version="v1",
                ttl_seconds=60,
                magnitudes=_MAGNITUDES,
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

    async def test_mint_without_authority_record_id_fails_closed(self) -> None:
        """Missing authority_record_id fails closed with MINT_FAILED finding."""
        action_payload = {"action": "execute_trade", "actor_id": "user-123"}

        # No patching needed — the service should fail before reaching KMS
        finding = await mint_consequence_token_finding(
            actor_id="user-123",
            thread_id="thread-abc",
            authority_record_id="",  # Missing!
            action_payload=action_payload,
            magnitudes=_MAGNITUDES,
        )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert (
            "authority_record_id missing from normative provider response"
            in finding["message"]
        )

    async def test_mint_without_actor_id_fails_closed(self) -> None:
        """Missing actor_id fails closed with MINT_FAILED finding."""
        action_payload = {"action": "execute_trade"}

        finding = await mint_consequence_token_finding(
            actor_id="",  # Missing!
            thread_id="thread-abc",
            authority_record_id="rec-xyz",
            action_payload=action_payload,
            magnitudes=_MAGNITUDES,
        )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "actor_id missing from action_payload" in finding["message"]

    async def test_byte_identical_tokens_across_relocation(self) -> None:
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
        mock_signer.sign_raw_async = AsyncMock(
            side_effect=lambda msg: mock_signer.sign_raw(msg)
        )

        action_payload = {
            "action": "execute_trade",
            "params": {"symbol": "AAPL", "quantity": 100},
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
            finding = await mint_consequence_token_finding(
                actor_id="user-deterministic",
                thread_id="thread-deterministic",
                authority_record_id="rec-deterministic",
                action_payload=action_payload,
                authority_state_version="v1",
                ttl_seconds=60,
                magnitudes=_MAGNITUDES,
            )

        token_new = finding["token"]

        # Simulate the old adapter-side path (directly calling ConsequenceToken.mint)
        with patch("time.time", return_value=1234567890):
            from src.gateway.governance.consequence_token import ConsequenceToken

            action_digest = hashlib.sha256(
                jcs_canonicalize_plan(action_payload)
            ).hexdigest()
            token_old = await ConsequenceToken.mint(
                sub="user-deterministic",
                tid="thread-deterministic",
                rec="rec-deterministic",
                act=action_digest,
                ver="v1",
                ttl_seconds=60,
                signer=mock_signer,
            )

        # The tokens MUST be byte-identical (this is the regression guard)
        assert token_new == token_old, (
            "Kernel service must produce byte-identical tokens to old adapter path"
        )

        # Verify signing input was identical (same number of calls, same message)
        assert mock_signer.sign_raw.call_count == 2
        call_args_new = mock_signer.sign_raw.call_args_list[0][0][0]
        call_args_old = mock_signer.sign_raw.call_args_list[1][0][0]
        assert call_args_new == call_args_old, (
            "Signing inputs must match across relocation"
        )

    async def test_kms_signing_failure_fails_closed(self) -> None:
        """KMS signing failure returns fail-closed MINT_FAILED finding."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/locations/us/keyRings/cage/cryptoKeys/gov/cryptoKeyVersions/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.side_effect = RuntimeError("KMS unavailable")
        mock_signer.sign_raw_async = AsyncMock(
            side_effect=lambda msg: mock_signer.sign_raw(msg)
        )

        action_payload = {"action": "execute_trade", "params": {"quantity": 100}}

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = await mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
                magnitudes=_MAGNITUDES,
            )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "KMS unavailable" in finding["message"]

    async def test_nullable_authority_state_version(self) -> None:
        """authority_state_version=None is normalized to empty string in claims."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.key_id = "projects/test/key/1"
        mock_signer.jose_alg = "ES256"
        mock_signer.sign_raw.return_value = b"X" * 64
        mock_signer.sign_raw_async = AsyncMock(
            side_effect=lambda msg: mock_signer.sign_raw(msg)
        )

        action_payload = {"action": "test"}

        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=mock_signer,
        ):
            finding = await mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload=action_payload,
                authority_state_version=None,  # Nullable
                magnitudes=_MAGNITUDES,
            )

        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN
        # Token should be successfully minted with ver="" in claims
        assert "token" in finding

    @pytest.mark.parametrize(
        "unsafe_int", [9007199254740992, 9007199254740993, -(2**53)]
    )
    async def test_unsafe_json_integer_rejected_fail_closed(
        self, unsafe_int: int
    ) -> None:
        """Issue #406: Integers outside IEEE-754 safe range [-(2^53-1), 2^53-1] fail closed before JCS."""
        finding = await mint_consequence_token_finding(
            actor_id="user-123",
            thread_id="thread-abc",
            authority_record_id="rec-xyz",
            action_payload={"action": "transfer", "amount_minor_units": unsafe_int},
            magnitudes=_MAGNITUDES,
        )
        assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
        assert finding["severity"] == "blocked"
        assert "integer outside" in finding["message"]

    @pytest.mark.parametrize(
        "bad_receipt_exp",
        [True, False, 0, -100, "1763150600", 1763150600.5, 1000, 999],
    )
    async def test_invalid_or_non_future_receipt_expires_at_fails_closed(
        self, bad_receipt_exp: object
    ) -> None:
        """POAM-2026-156 item 2: boolean, non-int, <= 0, or <= iat receipt_expires_at fails closed."""
        from src.gateway.governance.consequence_token import (
            ConsequenceToken,
            ConsequenceTokenMalformedError,
        )
        from src.gateway.governance.kms_signer import (
            KMSGovernanceSigner,
            SoftwareEd25519Provider,
        )

        signer = KMSGovernanceSigner(
            provider=SoftwareEd25519Provider(key_id="cts-rec-exp-guard")
        )
        with (
            patch(
                "src.gateway.governance.consequence_token_service.get_governance_signer",
                return_value=signer,
            ),
            patch(
                "src.gateway.governance.consequence_token.time.time",
                return_value=1000,
            ),
        ):
            with pytest.raises(ConsequenceTokenMalformedError):
                await ConsequenceToken.mint(
                    sub="user-123",
                    tid="thread-abc",
                    rec="rec-xyz",
                    act="a" * 64,
                    receipt_expires_at=bad_receipt_exp,  # type: ignore[arg-type]
                    signer=signer,
                )

            finding = await mint_consequence_token_finding(
                actor_id="user-123",
                thread_id="thread-abc",
                authority_record_id="rec-xyz",
                action_payload={"action": "test"},
                magnitudes=_MAGNITUDES,
                receipt_expires_at=bad_receipt_exp,  # type: ignore[arg-type]
            )
            assert finding["code"] == FINDING_CODE_CONSEQUENCE_TOKEN_MINT_FAILED
            assert finding["severity"] == "blocked"

    async def test_verify_enforces_rec_exp_type_iat_bound_and_expiry(self) -> None:
        """ConsequenceToken.verify rejects malformed rec_exp and expired rec_exp even before token exp."""
        import base64
        import json

        from src.gateway.governance.consequence_token import (
            ConsequenceToken,
            ConsequenceTokenError,
            ConsequenceTokenMalformedError,
        )
        from src.gateway.governance.kms_signer import (
            KMSGovernanceSigner,
            SoftwareEd25519Provider,
        )

        signer = KMSGovernanceSigner(
            provider=SoftwareEd25519Provider(key_id="cts-verify-rec-exp")
        )
        with patch(
            "src.gateway.governance.consequence_token.time.time",
            return_value=1000,
        ):
            valid_token = await ConsequenceToken.mint(
                sub="user-123",
                tid="thread-abc",
                rec="rec-short-receipt",
                act="b" * 64,
                ttl_seconds=60,
                receipt_expires_at=1020,
                signer=signer,
            )
            claims = ConsequenceToken.verify(valid_token, signer=signer)
            assert claims.rec_exp == 1020

        # At t=1025: token exp=1060 is NOT expired, but rec_exp=1020 IS expired -> rejected!
        with patch(
            "src.gateway.governance.consequence_token.time.time",
            return_value=1025,
        ):
            with pytest.raises(
                ConsequenceTokenError, match="Authority receipt expired"
            ):
                ConsequenceToken.verify(valid_token, signer=signer)

        # Signed malformed rec_exp claims (bool, str, <=0, <=iat, None) raise ConsequenceTokenMalformedError
        header_b64 = valid_token.split(".")[0]
        for bad_claim in (True, False, "1050", 0, -5, None, 1000, 995):
            payload = {
                "sub": "user-123",
                "tid": "thread-abc",
                "rec": "rec-malformed",
                "act": "b" * 64,
                "ver": "",
                "iat": 1000,
                "exp": 1060,
                "jti": "rec-malformed",
                "rec_exp": bad_claim,
            }
            payload_b64 = (
                base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode())
                .rstrip(b"=")
                .decode("ascii")
            )
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            sig = await signer.sign_raw_async(signing_input)
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
            crafted = f"{header_b64}.{payload_b64}.{sig_b64}"
            with patch(
                "src.gateway.governance.consequence_token.time.time",
                return_value=1005,
            ):
                with pytest.raises(ConsequenceTokenMalformedError, match="rec_exp"):
                    ConsequenceToken.verify(crafted, signer=signer)
