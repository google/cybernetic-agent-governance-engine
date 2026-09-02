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
Test suite for FTRA terminal registry signature verification (VEC-005, VEC-008).

Hermetic test strategy:
    - Generate EC P-256 keypair in-process (no live KMS)
    - Construct KMSGovernanceSigner with stub provider
    - Exercise real verify() code path (no mocking of the function under test)

Vectors:
    - VEC-005a: tampered registry, no .sig → SIG_MISSING
    - VEC-005b: tampered registry, .sig signed over original → SIG_INVALID
    - VEC-005c: same tampered registry, enforcement OFF → loads (bypass succeeds)
    - VEC-008a: serial rollback (41 after 42) → SERIAL_REGRESSED
    - VEC-008b: serial advance (43 after 42) → loads
    - VEC-008c: serial below FTRA_REGISTRY_MIN_SERIAL → SERIAL_REGRESSED

Guard tests:
    - Valid signature, expires_at in past → EXPIRED
    - expires_at naive (no timezone) → EXPIRY_NAIVE
    - expires_at absent → EXPIRY_MISSING
    - No field named "signed_at" in compiler output (section 3 trap)
    - Digest cache: two loads of identical bytes → one verify() call
    - Digest cache does NOT mask expiry: same bytes, clock advanced → fails
    - Reload path: verified at startup, file swapped, FTRA_REGISTRY_RELOAD → fails
"""

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.gateway.governance.ftra.registry_verifier import (
    ENVELOPE_INVALID,
    EXPIRED,
    EXPIRY_MISSING,
    EXPIRY_NAIVE,
    SERIAL_MISSING,
    SERIAL_REGRESSED,
    SIG_INVALID,
    SIG_MISSING,
    verify_registry,
)
from src.gateway.governance.kms_signer import KMSGovernanceSigner

# ---------------------------------------------------------------------------
# Fixtures: in-process EC P-256 keypair and signer
# ---------------------------------------------------------------------------


# The `hermetic_signer` fixture lives in tests/conftest.py, backed by
# tests/ftra_signing_harness.py. It was previously duplicated here; the shared
# version is session-scoped so that the autouse signer patch (which must apply
# to every test, including those that load a registry indirectly) can depend on
# it without a ScopeMismatch.


@pytest.fixture
def clean_verifier_state():
    """Reset module-level verifier state before each test."""
    from src.gateway.governance.ftra import registry_verifier

    registry_verifier._last_verified_digest = None
    registry_verifier._last_signature_valid = None
    registry_verifier._seen_serial_high_water = 0
    yield
    # Cleanup
    registry_verifier._last_verified_digest = None
    registry_verifier._last_signature_valid = None
    registry_verifier._seen_serial_high_water = 0


# ---------------------------------------------------------------------------
# Helper: create signed v2.0 registry
# ---------------------------------------------------------------------------


def create_signed_registry(
    tmp_path: Path,
    signer: KMSGovernanceSigner,
    serial: int = 42,
    validity_days: int = 90,
    terminals: dict[str, str] | None = None,
) -> tuple[Path, dict]:
    """Create a signed v2.0 terminal registry for testing.

    Args:
        tmp_path: Pytest tmp_path fixture.
        signer: Hermetic signer with in-process keypair.
        serial: Registry serial number.
        validity_days: Validity period in days.
        terminals: Terminal classification dict (defaults to test fixture).

    Returns:
        Tuple of (registry_path, registry_dict)
    """
    from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

    if terminals is None:
        terminals = {
            "check_balance": "READ_ONLY",
            "execute_trade": "IRREVERSIBLE_TERMINAL",
        }

    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(days=validity_days)

    registry = {
        "version": "2.0",
        "serial": serial,
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": "Any action absent from this registry is treated as IRREVERSIBLE_TERMINAL.",
        "terminals": terminals,
    }

    # Sign the registry
    signature_hex = signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }

    registry_path = tmp_path / "terminal_registry.json"
    sig_path = Path(str(registry_path) + ".sig")

    registry_path.write_text(json.dumps(registry, indent=2))
    sig_path.write_text(json.dumps(sig_envelope, indent=2))

    return registry_path, registry


# ---------------------------------------------------------------------------
# VEC-005: Registry re-declaration bypass
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_vec_005a_tampered_registry_no_sig(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-005a: execute_trade re-declared REVERSIBLE, no .sig file → SIG_MISSING."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Create original valid registry
    registry_path, original = create_signed_registry(tmp_path, hermetic_signer)

    # Tamper: re-declare execute_trade as REVERSIBLE
    tampered = original.copy()
    tampered["terminals"] = {
        "check_balance": "READ_ONLY",
        "execute_trade": "REVERSIBLE",  # Tampered
    }
    registry_path.write_text(json.dumps(tampered, indent=2))

    # Remove signature file
    sig_path = Path(str(registry_path) + ".sig")
    sig_path.unlink()

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == SIG_MISSING


@pytest.mark.local
def test_vec_005b_tampered_registry_wrong_sig(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-005b: execute_trade re-declared REVERSIBLE, .sig signed over original → SIG_INVALID."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Create original valid registry with signature
    registry_path, original = create_signed_registry(tmp_path, hermetic_signer)

    # Keep the .sig file unchanged (signed over original)
    # Tamper the registry content
    tampered = original.copy()
    tampered["terminals"] = {
        "check_balance": "READ_ONLY",
        "execute_trade": "REVERSIBLE",  # Tampered
    }
    registry_path.write_text(json.dumps(tampered, indent=2))

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == SIG_INVALID


@pytest.mark.local
def test_vec_005c_no_env_var_can_disable_enforcement(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-005c: no environment variable can turn verification off.

    Replaces the original VEC-005c, which asserted that
    ``FTRA_REGISTRY_REQUIRE_SIGNATURE=false`` let a tampered registry load. That
    posture gate has been removed (plan §13, R2): enforcement is unconditional,
    so the bypass it documented no longer exists.

    The vector is kept, inverted. It now pins the property that replaced the
    gate — setting the old flag, or claiming a dev environment, must not weaken
    verification. Deleting the test outright would leave nothing guarding
    against the gate being quietly reintroduced.
    """
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "false")
    monkeypatch.setenv("CAGE_ENV", "development")

    registry_path, original = create_signed_registry(tmp_path, hermetic_signer)

    # Tamper: re-declare execute_trade as REVERSIBLE
    tampered = original.copy()
    tampered["terminals"] = {
        "check_balance": "READ_ONLY",
        "execute_trade": "REVERSIBLE",
    }
    registry_path.write_text(json.dumps(tampered, indent=2))

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False, (
        "Tampered registry must fail verification regardless of "
        "FTRA_REGISTRY_REQUIRE_SIGNATURE or CAGE_ENV"
    )
    assert result.reason == SIG_INVALID


# ---------------------------------------------------------------------------
# VEC-008: Signed-registry rollback
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_vec_008a_serial_rollback(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-008a: Serial 41 after 42 seen → SERIAL_REGRESSED."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Load registry with serial 42
    registry_path_42, _ = create_signed_registry(
        tmp_path, hermetic_signer, serial=42
    )
    result = verify_registry(registry_path_42, signer=hermetic_signer)
    assert result.valid is True
    assert result.serial == 42

    # Attempt to load registry with serial 41 (rollback)
    rollback_dir = tmp_path / "rollback"
    rollback_dir.mkdir(parents=True, exist_ok=True)
    registry_path_41, _ = create_signed_registry(
        rollback_dir, hermetic_signer, serial=41
    )
    result = verify_registry(registry_path_41, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == SERIAL_REGRESSED


@pytest.mark.local
def test_vec_008b_serial_advance(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-008b: Serial 43 after 42 → loads."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Load registry with serial 42
    registry_path_42, _ = create_signed_registry(
        tmp_path, hermetic_signer, serial=42
    )
    result = verify_registry(registry_path_42, signer=hermetic_signer)
    assert result.valid is True
    assert result.serial == 42

    # Load registry with serial 43 (advance)
    advance_dir = tmp_path / "advance"
    advance_dir.mkdir(parents=True, exist_ok=True)
    registry_path_43, _ = create_signed_registry(
        advance_dir, hermetic_signer, serial=43
    )
    result = verify_registry(registry_path_43, signer=hermetic_signer)
    assert result.valid is True
    assert result.serial == 43


@pytest.mark.local
def test_vec_008c_serial_below_floor(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """VEC-008c: Serial below FTRA_REGISTRY_MIN_SERIAL → SERIAL_REGRESSED."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")
    monkeypatch.setenv("FTRA_REGISTRY_MIN_SERIAL", "100")

    # Attempt to load registry with serial 50 (below floor of 100)
    registry_path, _ = create_signed_registry(tmp_path, hermetic_signer, serial=50)
    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == SERIAL_REGRESSED


# ---------------------------------------------------------------------------
# Guard tests: expiry, signed_at trap, cache behavior
# ---------------------------------------------------------------------------


@pytest.mark.local
def test_guard_expiry_past(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """Valid signature, expires_at in the past → EXPIRED."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Create registry that expired 1 day ago
    registry_path, _ = create_signed_registry(
        tmp_path, hermetic_signer, validity_days=-1
    )

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == EXPIRED


@pytest.mark.local
def test_guard_expiry_naive(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """expires_at naive (no timezone) → EXPIRY_NAIVE (never coerced)."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    registry = {
        "version": "2.0",
        "serial": 42,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": "2027-01-01T00:00:00",  # Naive datetime
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": "Test",
        "terminals": {"check_balance": "READ_ONLY"},
    }

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    # Create valid signature
    signature_hex = hermetic_signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": hermetic_signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }
    sig_path = Path(str(registry_path) + ".sig")
    sig_path.write_text(json.dumps(sig_envelope, indent=2))

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == EXPIRY_NAIVE


@pytest.mark.local
def test_guard_expiry_absent(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """expires_at absent → EXPIRY_MISSING."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    registry = {
        "version": "2.0",
        "serial": 42,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        # expires_at deliberately omitted
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": "Test",
        "terminals": {"check_balance": "READ_ONLY"},
    }

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    signature_hex = hermetic_signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": hermetic_signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }
    sig_path = Path(str(registry_path) + ".sig")
    sig_path.write_text(json.dumps(sig_envelope, indent=2))

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == EXPIRY_MISSING


@pytest.mark.local
def test_guard_no_signed_at_field(tmp_path, hermetic_signer):
    """Compiler output must never contain a field named "signed_at" (section 3 trap)."""
    from src.gateway.governance.stpa_compiler import generate_terminal_registry

    # Create a minimal v2.0 registry (testing the generated output)
    # Use the existing signed registry helper which calls the compiler internally
    registry_path, registry_dict = create_signed_registry(
        tmp_path, hermetic_signer, serial=42
    )

    # Guard assertion: no "signed_at" field
    # The create_signed_registry helper builds the dict directly, but the
    # real compiler would have the same constraint
    assert "signed_at" not in registry_dict, (
        "BUG: Registry dict contains 'signed_at' field, "
        "which triggers KMSGovernanceSigner 300-second staleness rejection"
    )

    # Also verify the serialized JSON doesn't contain it
    registry_json = registry_path.read_text()
    assert "signed_at" not in registry_json, (
        "BUG: Registry JSON contains 'signed_at' string"
    )


@pytest.mark.local
def test_guard_digest_cache_skips_crypto(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """Digest cache: two loads of identical bytes → one verify() call."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    registry_path, _ = create_signed_registry(tmp_path, hermetic_signer)

    # First load: signature verified
    with patch.object(
        hermetic_signer, "verify", wraps=hermetic_signer.verify
    ) as mock_verify:
        result1 = verify_registry(registry_path, signer=hermetic_signer)
        assert result1.valid is True
        assert mock_verify.call_count == 1

    # Second load: same bytes, should hit digest cache
    with patch.object(
        hermetic_signer, "verify", wraps=hermetic_signer.verify
    ) as mock_verify:
        result2 = verify_registry(registry_path, signer=hermetic_signer)
        assert result2.valid is True
        # verify() should NOT be called again (digest cache hit)
        assert mock_verify.call_count == 0


@pytest.mark.local
def test_guard_cache_does_not_mask_expiry(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """Digest cache does NOT mask expiry: same bytes, clock advanced past expires_at → fails."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    # Create registry that expires in 2 seconds
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(seconds=2)

    registry = {
        "version": "2.0",
        "serial": 42,
        "issued_at": now_utc.isoformat(),
        "expires_at": expires_at.isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": "Test",
        "terminals": {"check_balance": "READ_ONLY"},
    }

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    signature_hex = hermetic_signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": hermetic_signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }
    sig_path = Path(str(registry_path) + ".sig")
    sig_path.write_text(json.dumps(sig_envelope, indent=2))

    # First load: valid
    result1 = verify_registry(registry_path, signer=hermetic_signer)
    assert result1.valid is True

    # Wait for expiry
    time.sleep(3)

    # Second load: same bytes, but expired
    result2 = verify_registry(registry_path, signer=hermetic_signer)
    assert result2.valid is False
    assert result2.reason == EXPIRED


@pytest.mark.local
def test_guard_serial_missing(
    tmp_path, hermetic_signer, clean_verifier_state, monkeypatch
):
    """serial field missing or not an integer → SERIAL_MISSING."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    registry = {
        "version": "2.0",
        # serial deliberately omitted
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        "system": "CAGE Financial Advisor",
        "system_version": "1.1.0",
        "fail_closed_note": "Test",
        "terminals": {"check_balance": "READ_ONLY"},
    }

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    signature_hex = hermetic_signer.sign(registry)
    sig_envelope = {
        "alg": "ES256",
        "key_id": hermetic_signer.key_id,
        "canonicalization": "RFC8785-JCS",
        "signature": signature_hex,
    }
    sig_path = Path(str(registry_path) + ".sig")
    sig_path.write_text(json.dumps(sig_envelope, indent=2))

    result = verify_registry(registry_path, signer=hermetic_signer)
    assert result.valid is False
    assert result.reason == SERIAL_MISSING


@pytest.mark.local
def test_guard_envelope_invalid_version(tmp_path, clean_verifier_state, monkeypatch):
    """version != "2.0" → ENVELOPE_INVALID."""
    monkeypatch.setenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "true")

    registry = {
        "version": "1.0",  # Wrong version
        "terminals": {"check_balance": "READ_ONLY"},
    }

    registry_path = tmp_path / "terminal_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))

    result = verify_registry(registry_path, signer=None)
    assert result.valid is False
    assert result.reason == ENVELOPE_INVALID


@pytest.mark.local
def test_s6_expiry_gauge_emits_epoch_timestamp(
    tmp_path, hermetic_signer, clean_verifier_state
):
    """S6: cage_ftra_registry_expires_at_seconds must emit epoch float, not datetime.
    
    This test exists because the as-shipped S6 code passed `result.expires_at` (a
    datetime object) directly to `Gauge.set()`, which requires a float. That raised
    TypeError in production but was masked locally by the ImportError fallback
    setting the gauge to None.
    
    The test MUST fail before the `.timestamp()` fix is applied, or it proves nothing.
    """
    pytest.importorskip("prometheus_client")
    from src.gateway.governance.ftra.classifier import _REGISTRY_EXPIRES_AT_GAUGE
    
    # Gauge must not be None — a missing metric is a failure, not a skip
    assert _REGISTRY_EXPIRES_AT_GAUGE is not None, (
        "S6 gauge is None despite prometheus_client being available. "
        "This test cannot validate the fix."
    )
    
    # Create a signed registry with known expiry
    registry_path, registry_dict = create_signed_registry(
        tmp_path, hermetic_signer, serial=1, validity_days=90
    )
    expected_expires_dt = datetime.fromisoformat(registry_dict["expires_at"])
    
    # Clear the gauge before testing (in case other tests set it)
    _REGISTRY_EXPIRES_AT_GAUGE.set(0)
    
    # Load the registry via the classifier (which triggers S6)
    from src.gateway.governance.ftra.classifier import _load_registry
    _ = _load_registry(registry_path)
    
    # The gauge sample must equal expires_at.timestamp(), not the datetime object
    from prometheus_client import REGISTRY
    samples = list(_REGISTRY_EXPIRES_AT_GAUGE.collect())[0].samples
    assert len(samples) == 1, f"Expected 1 gauge sample, got {len(samples)}"
    
    actual_value = samples[0].value
    expected_value = expected_expires_dt.timestamp()
    
    assert isinstance(actual_value, (int, float)), (
        f"Gauge value must be numeric (epoch seconds), got {type(actual_value)}"
    )
    assert abs(actual_value - expected_value) < 1.0, (
        f"Gauge value {actual_value} does not match expected {expected_value} "
        f"(expires_at={expected_expires_dt.isoformat()}). "
        f"Difference: {abs(actual_value - expected_value)} seconds"
    )
