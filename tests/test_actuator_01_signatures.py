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
test_actuator_01_signatures.py — Ed25519 Signature Construction Tests

Tests for the quorum signature construction per Phase 2, Stream C.
"""

import hashlib

import pytest

from src.gateway.governance.kms_signer import KMSGovernanceSigner
from src.integrations.actuator_01.signatures import (
    ACTUATOR_01_DOMAIN_TAG_QUORUM,
    sign_for_quorum,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestQuorumSignatures:
    """Test quorum signature construction."""

    def test_sign_for_quorum_produces_lowercase_hex(self, monkeypatch):
        """Quorum signatures are lowercase hex (wire contract requirement)."""
        # Mock signer with test key
        mock_signature = b"a" * 64  # 64-byte Ed25519 signature

        class MockSigner:
            is_kms_active = True

            def sign_raw(self, message: bytes) -> bytes:
                return mock_signature

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        sig_hex = sign_for_quorum(signer, canonical_bytes)

        # Should be lowercase hex
        assert sig_hex == mock_signature.hex().lower()
        assert sig_hex == sig_hex.lower()  # No uppercase letters
        assert len(sig_hex) == 128  # 64 bytes = 128 hex chars

    def test_sign_for_quorum_uses_domain_tag(self, monkeypatch):
        """Quorum signatures use ACTUATOR_01_DOMAIN_TAG_QUORUM to prevent replay."""
        signed_message = None

        class MockSigner:
            is_kms_active = True

            def sign_raw(self, message: bytes) -> bytes:
                nonlocal signed_message
                signed_message = message
                return b"x" * 64

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        sign_for_quorum(signer, canonical_bytes)

        # Verify the signed message starts with domain tag
        assert signed_message is not None
        assert signed_message.startswith(ACTUATOR_01_DOMAIN_TAG_QUORUM)

        # Verify the digest is appended after the tag
        body_digest = hashlib.sha256(canonical_bytes).digest()
        expected_message = ACTUATOR_01_DOMAIN_TAG_QUORUM + body_digest
        assert signed_message == expected_message

    def test_sign_for_quorum_fails_when_kms_inactive(self):
        """sign_for_quorum raises RuntimeError if KMS is not active."""

        class MockSigner:
            is_kms_active = False

        signer = MockSigner()
        canonical_bytes = b'{"action":"test"}'

        with pytest.raises(RuntimeError, match="KMS is not active"):
            sign_for_quorum(signer, canonical_bytes)

    def test_domain_tag_isolation(self):
        """ACTUATOR_01_DOMAIN_TAG_QUORUM is distinct and prevents cross-context replay."""
        tag = ACTUATOR_01_DOMAIN_TAG_QUORUM

        # Verify it's the expected value
        assert tag == b"ACTUATOR_01_QUORUM_V1:"

        # Verify it's bytes (not string)
        assert isinstance(tag, bytes)
