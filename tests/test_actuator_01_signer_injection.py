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
test_actuator_01_signer_injection.py — Signer Abstraction Injection Tests (Phase 7, C5)

Tests that actuator_01 adapters accept an injected RawMessageSigner protocol
conforming to the narrowest sufficient abstraction, eliminating the
service-locator anti-pattern (no get_governance_signer() calls).
"""

from unittest.mock import MagicMock

import pytest

from src.integrations.actuator_01.adapter import Actuator01Adapter
from src.integrations.actuator_01.assertion import build_assertion
from src.integrations.actuator_01.client import ActuatorHttpClient
from src.integrations.actuator_01.signatures import sign_for_quorum

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestActuatorSignerInjection:
    """Test suite for RawMessageSigner dependency injection in actuator_01."""

    def test_signatures_accepts_protocol_conforming_double(self) -> None:
        """sign_for_quorum accepts a test double implementing RawMessageSigner."""
        # Create a minimal test double (duck-typed protocol conformance)
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.sign_raw.return_value = b"A" * 64  # Ed25519 signature length

        canonical_bytes = b'{"action":"execute_trade","nonce":"abc123"}'

        # This should succeed without requiring concrete KMSGovernanceSigner
        signature_hex = sign_for_quorum(mock_signer, canonical_bytes)

        assert isinstance(signature_hex, str)
        assert len(signature_hex) == 128  # 64 bytes = 128 hex chars
        mock_signer.sign_raw.assert_called_once()

    def test_assertion_builder_accepts_protocol_conforming_double(self) -> None:
        """build_assertion accepts a test double implementing RawMessageSigner."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True
        mock_signer.sign_raw.return_value = b"B" * 64

        envelope_digest_hex = "a" * 64  # Valid SHA-256 hex
        nonce_hex = "b" * 32  # Valid 16-byte nonce
        issued_at = 1234567890

        assertion_b64 = build_assertion(
            envelope_digest_hex=envelope_digest_hex,
            nonce_hex=nonce_hex,
            issued_at=issued_at,
            signer=mock_signer,
        )

        assert isinstance(assertion_b64, str)
        # 120 bytes base64url-encoded (no padding) = 160 chars
        assert len(assertion_b64) == 160
        mock_signer.sign_raw.assert_called_once()

    def test_adapter_accepts_injected_signer_without_kernel_global(self) -> None:
        """Actuator01Adapter can be constructed with an injected signer.

        This is the direct proof that the service-locator pattern is gone:
        the adapter accepts a signer at construction and does not call
        get_governance_signer() to reach into kernel globals.
        """
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MagicMock()
        mock_signer.is_kms_active = True

        # Should succeed without patching get_governance_signer
        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,
        )

        assert adapter is not None
        assert adapter.actuator_id == "actuator_01"
        assert adapter._signer is mock_signer

    def test_adapter_per_operator_signer_resolution(self) -> None:
        """Adapter supports per-operator signer resolution via callback."""
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_default_signer = MagicMock()
        mock_default_signer.is_kms_active = True

        # Per-operator resolver (different signer per operator URN)
        operator_signers = {
            "urn:operator:alice": MagicMock(is_kms_active=True),
            "urn:operator:bob": MagicMock(is_kms_active=True),
        }

        def resolve_signer(urn: str):  # type: ignore[no-untyped-def]
            return operator_signers.get(urn, mock_default_signer)

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_default_signer,
            signer_resolver=resolve_signer,
        )

        # Verify resolver is wired correctly
        assert adapter._resolve_signer("urn:operator:alice") is operator_signers["urn:operator:alice"]
        assert adapter._resolve_signer("urn:operator:bob") is operator_signers["urn:operator:bob"]
        assert adapter._resolve_signer("urn:operator:charlie") is mock_default_signer

    def test_kms_inactive_signer_fails_closed(self) -> None:
        """sign_for_quorum fails closed when signer.is_kms_active=False."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = False  # Not active

        canonical_bytes = b'{"action":"test"}'

        with pytest.raises(RuntimeError, match="KMS is not active"):
            sign_for_quorum(mock_signer, canonical_bytes)

    def test_assertion_kms_inactive_fails_closed(self) -> None:
        """build_assertion fails closed when signer.is_kms_active=False."""
        mock_signer = MagicMock()
        mock_signer.is_kms_active = False

        with pytest.raises(RuntimeError, match="KMS is not active"):
            build_assertion(
                envelope_digest_hex="a" * 64,
                nonce_hex="b" * 32,
                issued_at=1234567890,
                signer=mock_signer,
            )
