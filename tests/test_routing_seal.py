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
Unit tests — Routing Seal (gateway issuance + GFA verification mirror).

**v2 Seal Format (B2 Enhancement):**
The seal format now includes 4 components:
    ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``

This cryptographically binds the seal to a specific evidence record in the
compliance evidence stream. See B2 implementation for details.

Covers:
- Happy path: generate → verify succeeds (v2 format with record_hash)
- Evidence binding: seal is cryptographically bound to record_hash
- Expired seal: verify raises SymbolicGovernorViolation
- Tampered sig: verify raises SymbolicGovernorViolation
- Action mismatch: verify raises SymbolicGovernorViolation
- Malformed seal: verify raises SymbolicGovernorViolation
- Record hash mismatch: verify raises SymbolicGovernorViolation
- Canonical payload determinism: dict ordering doesn't affect HMAC
- GFA mirror: uses same HMAC key; verify_seal produces same result as gateway

CRIT-1 fix note: verify_seal() (both gateway and GFA versions) now raises
``SymbolicGovernorViolation`` on any verification failure instead of returning
``False``. This prevents callers from silently ignoring a failed seal check.
"""

import datetime
import os
import time

import pytest
from freezegun import freeze_time

# Set GOVERNANCE_SALT before importing modules under test
os.environ.setdefault("GOVERNANCE_SALT", "TEST_SALT_UNIT_32_CHARACTERS_OK!")


@pytest.fixture(autouse=True)
def disable_seal_strict_mode(monkeypatch):
    """Disable strict mode for all tests in this module.

    Strict mode rejects HMAC seals in production environments.
    Tests use HMAC seals for unit testing, so we disable strict mode.
    """
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")


from src.gateway.governance.routing_seal import (
    extract_record_hash,
    generate_seal,
)
from src.governed_financial_advisor.utils.routing_seal import (
    SymbolicGovernorViolation,
)
from src.governed_financial_advisor.utils.routing_seal import (
    extract_record_hash as gfa_extract_record_hash,
)
from src.governed_financial_advisor.utils.routing_seal import (
    verify_seal as gfa_verify_seal,
)

PARAMS = {
    "symbol": "AAPL",
    "amount": 10000.0,
    "currency": "USD",
    "confidence": 0.85,
    "trader_role": "junior",
}

# Test record hash for evidence binding tests
TEST_RECORD_HASH = "abc123def456789012345678901234567890abcdef1234567890abcdef12345678"


class TestRoutingSeal:
    """Gateway issuance + GFA verification."""

    def test_happy_path(self):
        """A freshly generated seal must verify successfully."""
        seal = generate_seal("execute_trade", PARAMS)
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True

    def test_v2_seal_format_has_four_parts(self):
        """v2 seals must have 4 dot-separated components."""
        seal = generate_seal("execute_trade", PARAMS)
        parts = seal.split(".")
        assert len(parts) == 4, f"Expected 4 parts, got {len(parts)}: {seal}"
        expire_hex, action_slug, record_hash, hmac_sig = parts
        # Verify structure
        assert len(expire_hex) > 0
        assert action_slug == "execute-trade"
        assert len(record_hash) > 0  # sentinel or actual hash
        assert len(hmac_sig) == 64  # SHA-256 hex

    def test_seal_with_record_hash(self):
        """Seal generated with record_hash must include it in wire format."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        parts = seal.split(".")
        assert len(parts) == 4
        assert parts[2] == TEST_RECORD_HASH
        # Verify it validates
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True

    def test_seal_without_record_hash_uses_sentinel(self):
        """Seal generated without record_hash uses sentinel value."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=None)
        record_hash = extract_record_hash(seal)
        assert record_hash == "no-evidence-binding"
        # Verify it validates
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True

    def test_expired_seal(self):
        """A seal generated with ttl=0 should be expired immediately."""
        now = time.time()
        seal = generate_seal("execute_trade", PARAMS, ttl_s=0)
        # Advance frozen time 2 s past seal creation so expiry is definitive
        frozen_dt = datetime.datetime.fromtimestamp(now + 2, tz=datetime.timezone.utc)
        with freeze_time(frozen_dt):
            with pytest.raises(SymbolicGovernorViolation):
                gfa_verify_seal(seal, "execute_trade", PARAMS)

    def test_tampered_signature(self):
        """Mutating the HMAC signature component must fail verification."""
        seal = generate_seal("execute_trade", PARAMS)
        parts = seal.split(".")
        # v2 format: sig is at index 3 (4th part)
        parts[3] = parts[3][:-1] + ("a" if parts[3][-1] != "a" else "b")
        tampered = ".".join(parts)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(tampered, "execute_trade", PARAMS)

    def test_tampered_record_hash(self):
        """Mutating the record_hash component must fail HMAC verification."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        parts = seal.split(".")
        # v2 format: record_hash is at index 2 (3rd part)
        parts[2] = "tampered" + parts[2][8:]
        tampered = ".".join(parts)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(tampered, "execute_trade", PARAMS)

    def test_action_mismatch(self):
        """Verifying with a different action name must fail."""
        seal = generate_seal("execute_trade", PARAMS)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(seal, "cancel_trade", PARAMS)

    def test_param_mismatch(self):
        """Verifying with modified params must fail (HMAC covers payload)."""
        seal = generate_seal("execute_trade", PARAMS)
        bad_params = {**PARAMS, "amount": 99999.0}
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(seal, "execute_trade", bad_params)

    def test_malformed_seal_too_few_parts(self):
        """A seal missing a dot segment must raise SymbolicGovernorViolation (v2 expects 4)."""
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal("abc.def", "execute_trade", PARAMS)
        # Also test 3 parts (old v1 format)
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal("abc.def.ghi", "execute_trade", PARAMS)

    def test_malformed_seal_empty(self):
        """An empty seal string must raise SymbolicGovernorViolation."""
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal("", "execute_trade", PARAMS)

    def test_canonical_payload_dict_order_invariant(self):
        """Dict ordering must not affect seal validity (JSON sort_keys=True)."""
        params_a = {"symbol": "AAPL", "amount": 1000.0, "currency": "USD"}
        params_b = {"currency": "USD", "amount": 1000.0, "symbol": "AAPL"}
        seal = generate_seal("execute_trade", params_a)
        assert gfa_verify_seal(seal, "execute_trade", params_b) is True

    def test_action_slug_normalisation(self):
        """Action names with underscores are normalised to dashes in slug."""
        params_a = {"symbol": "AAPL", "amount": 1000.0, "currency": "USD"}
        seal = generate_seal("execute_trade", params_a)
        # Action slug is 'execute-trade' internally — verify must still pass
        assert gfa_verify_seal(seal, "execute_trade", params_a) is True


class TestRecordHashBinding:
    """B2: Tests for HMAC seal binding to evidence record hash."""

    def test_extract_record_hash_returns_correct_value(self):
        """extract_record_hash() returns the record_hash from a v2 seal."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        assert extract_record_hash(seal) == TEST_RECORD_HASH
        assert gfa_extract_record_hash(seal) == TEST_RECORD_HASH

    def test_extract_record_hash_sentinel_value(self):
        """extract_record_hash() returns sentinel for seals without evidence binding."""
        seal = generate_seal("execute_trade", PARAMS)  # No record_hash
        assert extract_record_hash(seal) == "no-evidence-binding"

    def test_extract_record_hash_malformed_seal(self):
        """extract_record_hash() returns None for malformed seals."""
        assert extract_record_hash("abc.def") is None
        assert extract_record_hash("abc.def.ghi") is None  # v1 format
        assert extract_record_hash("") is None

    def test_expected_record_hash_match_succeeds(self):
        """Verification succeeds when expected_record_hash matches seal's record_hash."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        # Explicit match check
        assert (
            gfa_verify_seal(
                seal, "execute_trade", PARAMS, expected_record_hash=TEST_RECORD_HASH
            )
            is True
        )

    def test_expected_record_hash_mismatch_fails(self):
        """Verification fails when expected_record_hash doesn't match seal's record_hash."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        wrong_hash = "wrong" + TEST_RECORD_HASH[5:]
        with pytest.raises(SymbolicGovernorViolation) as exc_info:
            gfa_verify_seal(
                seal, "execute_trade", PARAMS, expected_record_hash=wrong_hash
            )
        assert "record_hash mismatch" in str(exc_info.value)

    def test_expected_record_hash_none_skips_check(self):
        """When expected_record_hash=None, no record_hash validation is performed."""
        seal = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        # Should pass without checking record_hash
        assert (
            gfa_verify_seal(seal, "execute_trade", PARAMS, expected_record_hash=None)
            is True
        )

    def test_seal_with_different_record_hashes_are_distinct(self):
        """Seals with different record_hashes produce different HMACs."""
        hash_a = "a" * 64
        hash_b = "b" * 64
        seal_a = generate_seal("execute_trade", PARAMS, record_hash=hash_a)
        seal_b = generate_seal("execute_trade", PARAMS, record_hash=hash_b)
        # Seals should be different
        assert seal_a != seal_b
        # Both should verify
        assert gfa_verify_seal(seal_a, "execute_trade", PARAMS) is True
        assert gfa_verify_seal(seal_b, "execute_trade", PARAMS) is True
        # But cross-verification with expected_record_hash should fail
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(
                seal_a, "execute_trade", PARAMS, expected_record_hash=hash_b
            )

    def test_record_hash_included_in_hmac_input(self):
        """Changing record_hash changes the HMAC even with same action/params."""
        seal_without = generate_seal("execute_trade", PARAMS, record_hash=None)
        seal_with = generate_seal("execute_trade", PARAMS, record_hash=TEST_RECORD_HASH)
        # Extract HMACs (4th component)
        hmac_without = seal_without.split(".")[3]
        hmac_with = seal_with.split(".")[3]
        # HMACs must differ
        assert hmac_without != hmac_with


class TestRoutingSealGatewayMirrorParity:
    """Ensure both modules produce identical HMAC under the same GOVERNANCE_SALT."""

    def test_gfa_verify_accepts_gateway_seal(self):
        """The GFA's verify_seal must accept seals issued by the gateway module."""
        for action in (
            "execute_trade",
            "evaluate_policy",
            "trigger_safety_intervention",
        ):
            seal = generate_seal(action, PARAMS)
            assert gfa_verify_seal(seal, action, PARAMS) is True, (
                f"GFA verify_seal rejected a valid gateway seal for action='{action}'"
            )

    def test_correct_seal_required_before_actuation(self):
        """Simulates the defense-in-depth check in tools/api.py."""
        seal = generate_seal("execute_trade", PARAMS)
        # Correct: verify passes → actuation allowed
        assert gfa_verify_seal(seal, "execute_trade", PARAMS) is True
        # Tampered seal: verify raises → actuation blocked
        tampered = seal[:-4] + "XXXX"
        with pytest.raises(SymbolicGovernorViolation):
            gfa_verify_seal(tampered, "execute_trade", PARAMS)


pytestmark = [pytest.mark.unit, pytest.mark.local]
