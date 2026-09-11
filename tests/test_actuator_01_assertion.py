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
Tests for actuator_01 assertion builder.

Validates the 120-byte assertion layout, domain-tag isolation from quorum
signatures, base64url encoding, and pre-flight validation.
"""

import hashlib
import struct
from unittest.mock import MagicMock

import pytest

from src.integrations.actuator_01.assertion import (
    ACTUATOR_01_DOMAIN_TAG_ASSERTION,
    ASSERTION_TOTAL_BYTES,
    AssertionBuildError,
    build_assertion,
    decode_assertion,
)
from src.integrations.actuator_01.signatures import ACTUATOR_01_DOMAIN_TAG_QUORUM

# Hermetic: tests 120-byte assertion encoding/decoding and validation in-memory.
pytestmark = [pytest.mark.unit, pytest.mark.local]

# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_signer():
    """KMS signer mock that returns a 64-byte deterministic signature."""
    signer = MagicMock()
    signer.is_kms_active = True
    # Return a deterministic 64-byte signature based on the input.
    signer.sign_raw.side_effect = lambda msg: hashlib.sha512(msg).digest()[:64]
    return signer


@pytest.fixture()
def valid_digest_hex():
    return hashlib.sha256(b"test envelope bytes").hexdigest()


@pytest.fixture()
def valid_nonce_hex():
    return "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"


@pytest.fixture()
def valid_issued_at():
    return 1725724800  # 2024-09-07T16:00:00Z


# ── Test: Assertion Layout ────────────────────────────────────────────────


class TestAssertionLayout:
    """Verify the 120-byte assertion has the correct binary layout."""

    def test_assertion_is_exactly_120_bytes(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        raw_total = (
            len(decoded["digest"])
            + len(decoded["nonce"])
            + 8  # timestamp
            + len(decoded["signature"])
        )
        assert raw_total == ASSERTION_TOTAL_BYTES

    def test_digest_field_is_32_bytes(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert len(decoded["digest"]) == 32
        assert decoded["digest"] == bytes.fromhex(valid_digest_hex)

    def test_nonce_field_is_16_bytes(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert len(decoded["nonce"]) == 16
        assert decoded["nonce"] == bytes.fromhex(valid_nonce_hex)

    def test_timestamp_is_big_endian_uint64(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert decoded["timestamp"] == valid_issued_at

    def test_signature_is_64_bytes(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert len(decoded["signature"]) == 64

    def test_signable_payload_is_56_bytes(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert len(decoded["signable_payload"]) == 56


# ── Test: Domain Tag Isolation ────────────────────────────────────────────


class TestDomainTagIsolation:
    """Assertion and quorum signatures use different domain tags."""

    def test_assertion_domain_tag_differs_from_quorum(self):
        assert ACTUATOR_01_DOMAIN_TAG_ASSERTION != ACTUATOR_01_DOMAIN_TAG_QUORUM

    def test_assertion_domain_tag_exact_value(self):
        assert ACTUATOR_01_DOMAIN_TAG_ASSERTION == b"ARCHYTAN_ASSERTION_V1:"

    def test_signer_receives_assertion_domain_tag(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        build_assertion(valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer)
        call_args = mock_signer.sign_raw.call_args[0][0]
        assert call_args.startswith(ACTUATOR_01_DOMAIN_TAG_ASSERTION)

    def test_signer_does_not_receive_quorum_tag(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        build_assertion(valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer)
        call_args = mock_signer.sign_raw.call_args[0][0]
        assert not call_args.startswith(ACTUATOR_01_DOMAIN_TAG_QUORUM)


# ── Test: Base64url Encoding ─────────────────────────────────────────────


class TestBase64UrlEncoding:
    """Verify base64url encoding with no padding."""

    def test_no_padding_characters(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        assert "=" not in b64

    def test_no_standard_base64_characters(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        """base64url uses - and _ instead of + and /."""
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        assert "+" not in b64
        assert "/" not in b64

    def test_roundtrip_decode(
        self, mock_signer, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        b64 = build_assertion(
            valid_digest_hex, valid_nonce_hex, valid_issued_at, mock_signer
        )
        decoded = decode_assertion(b64)
        assert decoded["digest"] == bytes.fromhex(valid_digest_hex)
        assert decoded["nonce"] == bytes.fromhex(valid_nonce_hex)
        assert decoded["timestamp"] == valid_issued_at


# ── Test: Validation ─────────────────────────────────────────────────────


class TestAssertionValidation:
    """Pre-flight validation of assertion inputs."""

    def test_rejects_short_digest(self, mock_signer, valid_nonce_hex, valid_issued_at):
        with pytest.raises(AssertionBuildError, match="64 hex chars"):
            build_assertion("abcd", valid_nonce_hex, valid_issued_at, mock_signer)

    def test_rejects_invalid_hex_digest(
        self, mock_signer, valid_nonce_hex, valid_issued_at
    ):
        bad_hex = "z" * 64
        with pytest.raises(AssertionBuildError, match="not valid hex"):
            build_assertion(bad_hex, valid_nonce_hex, valid_issued_at, mock_signer)

    def test_rejects_short_nonce(self, mock_signer, valid_digest_hex, valid_issued_at):
        with pytest.raises(AssertionBuildError, match="32 hex chars"):
            build_assertion(valid_digest_hex, "abcd", valid_issued_at, mock_signer)

    def test_rejects_negative_timestamp(
        self, mock_signer, valid_digest_hex, valid_nonce_hex
    ):
        with pytest.raises(AssertionBuildError, match="positive Unix timestamp"):
            build_assertion(valid_digest_hex, valid_nonce_hex, -1, mock_signer)

    def test_rejects_zero_timestamp(
        self, mock_signer, valid_digest_hex, valid_nonce_hex
    ):
        with pytest.raises(AssertionBuildError, match="positive Unix timestamp"):
            build_assertion(valid_digest_hex, valid_nonce_hex, 0, mock_signer)

    def test_rejects_inactive_kms(
        self, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        signer = MagicMock()
        signer.is_kms_active = False
        with pytest.raises(RuntimeError, match="KMS is not active"):
            build_assertion(valid_digest_hex, valid_nonce_hex, valid_issued_at, signer)

    def test_rejects_wrong_signature_length(
        self, valid_digest_hex, valid_nonce_hex, valid_issued_at
    ):
        signer = MagicMock()
        signer.is_kms_active = True
        signer.sign_raw.return_value = b"\x00" * 48  # Wrong length
        with pytest.raises(AssertionBuildError, match="48 bytes, expected 64"):
            build_assertion(valid_digest_hex, valid_nonce_hex, valid_issued_at, signer)


# ── Test: Decode ──────────────────────────────────────────────────────────


class TestDecodeAssertion:
    """Verify decode_assertion error handling."""

    def test_rejects_wrong_length(self):
        import base64

        raw = b"\x00" * 100  # Not 120
        b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        with pytest.raises(AssertionBuildError, match="100 bytes, expected 120"):
            decode_assertion(b64)

    def test_rejects_invalid_base64(self):
        with pytest.raises(AssertionBuildError, match="Invalid base64url"):
            decode_assertion("!!!not-base64!!!")
