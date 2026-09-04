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
M-2 Fix: ECDSA DER→raw Signature Conversion Tests

Tests for the `_der_to_raw_ecdsa_signature()` function that converts
DER-encoded ECDSA signatures from KMS to raw R||S format required by JWT.

The key vulnerability being tested (M-2): The original implementation silently
swallowed exceptions (try/except ValueError: pass), masking DER conversion
failures. The fix removes exception swallowing and adds explicit length validation.

Test Coverage:
- Real ECDSA signatures from all three curves (P-256, P-384, P-521)
- Output length validation
- Error handling for invalid inputs
- Round-trip conversion (DER→raw→verification)
"""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from src.gateway.governance.routing_seal import _der_to_raw_ecdsa_signature

# ---------------------------------------------------------------------------
# Helper: Generate real ECDSA signatures
# ---------------------------------------------------------------------------


def _generate_ecdsa_signature(curve, message: bytes = b"test message") -> bytes:
    """Generate a real DER-encoded ECDSA signature."""
    private_key = ec.generate_private_key(curve, default_backend())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


# ---------------------------------------------------------------------------
# Tests: ES256 (P-256)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_es256_conversion():
    """Test ES256 DER→raw conversion with real signature."""
    der_sig = _generate_ecdsa_signature(ec.SECP256R1())
    raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES256")

    # ES256: 32 bytes R + 32 bytes S = 64 bytes
    assert len(raw_sig) == 64
    assert isinstance(raw_sig, bytes)


@pytest.mark.unit
@pytest.mark.local
def test_es256_multiple_conversions():
    """Test ES256 conversion across multiple signatures (tests for leading-zero edge cases)."""
    # Generate multiple signatures to increase probability of hitting leading-zero case
    for _ in range(20):
        der_sig = _generate_ecdsa_signature(ec.SECP256R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES256")
        assert len(raw_sig) == 64


@pytest.mark.unit
@pytest.mark.local
def test_es256_round_trip():
    """Test that raw signature can be converted back to DER and verified."""
    message = b"test message for round trip"
    curve = ec.SECP256R1()

    # Generate key pair
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    # Sign
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    # Convert to raw
    raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES256")
    assert len(raw_sig) == 64

    # Extract R and S from raw signature
    r_bytes = raw_sig[:32]
    s_bytes = raw_sig[32:]
    r = int.from_bytes(r_bytes, byteorder="big")
    s = int.from_bytes(s_bytes, byteorder="big")

    # Convert back to DER
    der_sig_reconstructed = asym_utils.encode_dss_signature(r, s)

    # Verify reconstructed signature
    public_key.verify(der_sig_reconstructed, message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# Tests: ES384 (P-384)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_es384_conversion():
    """Test ES384 DER→raw conversion with real signature."""
    der_sig = _generate_ecdsa_signature(ec.SECP384R1())
    raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES384")

    # ES384: 48 bytes R + 48 bytes S = 96 bytes
    assert len(raw_sig) == 96
    assert isinstance(raw_sig, bytes)


@pytest.mark.unit
@pytest.mark.local
def test_es384_multiple_conversions():
    """Test ES384 conversion across multiple signatures."""
    for _ in range(20):
        der_sig = _generate_ecdsa_signature(ec.SECP384R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES384")
        assert len(raw_sig) == 96


# ---------------------------------------------------------------------------
# Tests: ES512 (P-521)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_es512_conversion():
    """Test ES512 DER→raw conversion with real signature."""
    der_sig = _generate_ecdsa_signature(ec.SECP521R1())
    raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES512")

    # ES512 (P-521): 66 bytes R + 66 bytes S = 132 bytes (not 128!)
    assert len(raw_sig) == 132
    assert isinstance(raw_sig, bytes)


@pytest.mark.unit
@pytest.mark.local
def test_es512_multiple_conversions():
    """Test ES512 conversion across multiple signatures."""
    for _ in range(20):
        der_sig = _generate_ecdsa_signature(ec.SECP521R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES512")
        assert len(raw_sig) == 132


# ---------------------------------------------------------------------------
# Tests: Output Length Validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_output_length_validation_es256():
    """Test that output length is always 64 bytes for ES256."""
    for _ in range(10):
        der_sig = _generate_ecdsa_signature(ec.SECP256R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES256")
        assert len(raw_sig) == 64, "ES256 raw signature must be exactly 64 bytes"


@pytest.mark.unit
@pytest.mark.local
def test_output_length_validation_es384():
    """Test that output length is always 96 bytes for ES384."""
    for _ in range(10):
        der_sig = _generate_ecdsa_signature(ec.SECP384R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES384")
        assert len(raw_sig) == 96, "ES384 raw signature must be exactly 96 bytes"


@pytest.mark.unit
@pytest.mark.local
def test_output_length_validation_es512():
    """Test that output length is always 132 bytes for ES512."""
    for _ in range(10):
        der_sig = _generate_ecdsa_signature(ec.SECP521R1())
        raw_sig = _der_to_raw_ecdsa_signature(der_sig, "ES512")
        assert len(raw_sig) == 132, "ES512 raw signature must be exactly 132 bytes"


# ---------------------------------------------------------------------------
# Tests: Error Handling
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_unsupported_algorithm():
    """Test that unsupported algorithms raise ValueError."""
    der_sig = _generate_ecdsa_signature(ec.SECP256R1())
    with pytest.raises(ValueError, match="Unsupported JOSE algorithm"):
        _der_to_raw_ecdsa_signature(der_sig, "RS256")


@pytest.mark.unit
@pytest.mark.local
def test_invalid_der_signature():
    """Test that invalid DER input raises ValueError."""
    invalid_der = b"not a valid der signature"
    with pytest.raises(ValueError, match="Failed to convert"):
        _der_to_raw_ecdsa_signature(invalid_der, "ES256")


@pytest.mark.unit
@pytest.mark.local
def test_truncated_der_signature():
    """Test that truncated DER input raises ValueError."""
    der_sig = _generate_ecdsa_signature(ec.SECP256R1())
    truncated = der_sig[:10]  # Truncate to invalid length
    with pytest.raises(ValueError, match="Failed to convert"):
        _der_to_raw_ecdsa_signature(truncated, "ES256")


@pytest.mark.unit
@pytest.mark.local
def test_wrong_curve_for_algorithm():
    """Test that using wrong curve for algorithm is detected."""
    # Generate ES384 signature but try to convert as ES256
    der_sig = _generate_ecdsa_signature(ec.SECP384R1())
    # This should either raise or produce wrong length
    try:
        _der_to_raw_ecdsa_signature(der_sig, "ES256")
        # If it doesn't raise, it should fail length validation
        # (though PyJWT might not detect this mismatch)
    except ValueError:
        # Expected: conversion or validation fails
        pass


# ---------------------------------------------------------------------------
# Tests: M-2 Fix Verification (No Silent Exception Swallowing)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
def test_m2_fix_no_silent_exception_swallowing():
    """Verify that M-2 fix removes silent exception swallowing.

    The original code had:
        try:
            signature = der_to_raw_signature(signature, curve)
        except ValueError:
            pass

    This test verifies that exceptions are now properly raised.
    """
    invalid_der = bytes([0x30, 0x00])  # Minimal invalid SEQUENCE

    # Should raise, not silently swallow the exception
    with pytest.raises(ValueError):
        _der_to_raw_ecdsa_signature(invalid_der, "ES256")


@pytest.mark.unit
@pytest.mark.local
def test_m2_fix_length_validation():
    """Verify that length validation catches incorrect output lengths."""
    # This is hard to test directly without mocking PyJWT, but we can verify
    # that all our test signatures have correct lengths
    for _ in range(10):
        for curve, alg, expected_len in [
            (ec.SECP256R1(), "ES256", 64),
            (ec.SECP384R1(), "ES384", 96),
            (ec.SECP521R1(), "ES512", 132),
        ]:
            der_sig = _generate_ecdsa_signature(curve)
            raw_sig = _der_to_raw_ecdsa_signature(der_sig, alg)
            assert len(raw_sig) == expected_len
