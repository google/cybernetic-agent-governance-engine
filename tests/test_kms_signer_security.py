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
Security tests for KMSGovernanceSigner (src/gateway/governance/kms_signer.py).

Covers:
  - signing_algorithm property (HMAC fallback vs KMS mode)
  - sign() OTel span attributes in both modes
  - _hmac_sign() CRITICAL log emission in degraded state
  - assert_kms_active_in_production() environment-gated enforcement
  - from_env() fallback paths (no key set, ImportError)
"""

import json
import os
from unittest.mock import MagicMock, patch, call

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_signer(kms_client=None, key_version_name="", legacy_salt="test-salt"):
    """Construct a KMSGovernanceSigner directly without touching env vars."""
    from src.gateway.governance.kms_signer import KMSGovernanceSigner
    return KMSGovernanceSigner(
        kms_client=kms_client,
        key_version_name=key_version_name,
        public_key_pem=b"",
        legacy_salt=legacy_salt,
    )


# ---------------------------------------------------------------------------
# signing_algorithm property
# ---------------------------------------------------------------------------

def test_signing_algorithm_hmac_when_kms_inactive():
    """signing_algorithm returns 'HMAC_SHA256_FALLBACK' when _kms_active is False."""
    signer = _make_signer(kms_client=None, key_version_name="")
    assert signer.signing_algorithm == "HMAC_SHA256_FALLBACK"


def test_signing_algorithm_kms_when_kms_active():
    """signing_algorithm returns 'KMS_ASYMMETRIC' when kms_client and key_version_name are set."""
    mock_client = MagicMock()
    signer = _make_signer(kms_client=mock_client, key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
    assert signer.signing_algorithm == "KMS_ASYMMETRIC"


def test_is_kms_active_false_without_client():
    """is_kms_active is False when no kms_client is provided."""
    signer = _make_signer(kms_client=None)
    assert signer.is_kms_active is False


def test_is_kms_active_false_without_key_version():
    """is_kms_active is False when kms_client is set but key_version_name is empty."""
    mock_client = MagicMock()
    signer = _make_signer(kms_client=mock_client, key_version_name="")
    assert signer.is_kms_active is False


def test_is_kms_active_true_with_client_and_key():
    """is_kms_active is True when both kms_client and key_version_name are provided."""
    mock_client = MagicMock()
    signer = _make_signer(
        kms_client=mock_client,
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
    assert signer.is_kms_active is True


# ---------------------------------------------------------------------------
# sign() OTel span attributes
# ---------------------------------------------------------------------------

def test_sign_sets_span_attribute_algorithm_hmac():
    """sign() sets cage.signing.algorithm='HMAC_SHA256_FALLBACK' on the OTel span in HMAC mode."""
    signer = _make_signer(kms_client=None, key_version_name="", legacy_salt="test-salt")

    mock_span = MagicMock()
    mock_ctx_manager = MagicMock()
    mock_ctx_manager.__enter__ = MagicMock(return_value=mock_span)
    mock_ctx_manager.__exit__ = MagicMock(return_value=False)

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer:
        mock_tracer.start_as_current_span.return_value = mock_ctx_manager
        signer.sign({"action": "test"})

    mock_span.set_attribute.assert_any_call("cage.signing.algorithm", "HMAC_SHA256_FALLBACK")


def test_sign_sets_span_attribute_kms_active_false_in_hmac_mode():
    """sign() sets cage.signing.kms_active=False on the OTel span in HMAC mode."""
    signer = _make_signer(kms_client=None, key_version_name="", legacy_salt="test-salt")

    mock_span = MagicMock()
    mock_ctx_manager = MagicMock()
    mock_ctx_manager.__enter__ = MagicMock(return_value=mock_span)
    mock_ctx_manager.__exit__ = MagicMock(return_value=False)

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer:
        mock_tracer.start_as_current_span.return_value = mock_ctx_manager
        signer.sign({"action": "test"})

    mock_span.set_attribute.assert_any_call("cage.signing.kms_active", False)


def test_sign_sets_span_attribute_algorithm_kms():
    """sign() sets cage.signing.algorithm='KMS_ASYMMETRIC' on the OTel span in KMS mode."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    # Mock the KMS response
    mock_response = MagicMock()
    mock_response.signature = b"\xde\xad\xbe\xef" * 8
    mock_kms_client.asymmetric_sign.return_value = mock_response

    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    mock_span = MagicMock()
    mock_ctx_manager = MagicMock()
    mock_ctx_manager.__enter__ = MagicMock(return_value=mock_span)
    mock_ctx_manager.__exit__ = MagicMock(return_value=False)

    # Mock the KMS service types import inside _kms_sign
    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(return_value=MagicMock())
    mock_kms_service.Digest = MagicMock(return_value=MagicMock())

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        mock_tracer.start_as_current_span.return_value = mock_ctx_manager
        signer.sign({"action": "test"})

    mock_span.set_attribute.assert_any_call("cage.signing.algorithm", "KMS_ASYMMETRIC")


def test_sign_sets_span_attribute_kms_active_true_in_kms_mode():
    """sign() sets cage.signing.kms_active=True on the OTel span in KMS mode."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    mock_response = MagicMock()
    mock_response.signature = b"\xde\xad\xbe\xef" * 8
    mock_kms_client.asymmetric_sign.return_value = mock_response

    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    mock_span = MagicMock()
    mock_ctx_manager = MagicMock()
    mock_ctx_manager.__enter__ = MagicMock(return_value=mock_span)
    mock_ctx_manager.__exit__ = MagicMock(return_value=False)

    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(return_value=MagicMock())
    mock_kms_service.Digest = MagicMock(return_value=MagicMock())

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        mock_tracer.start_as_current_span.return_value = mock_ctx_manager
        signer.sign({"action": "test"})

    mock_span.set_attribute.assert_any_call("cage.signing.kms_active", True)


# ---------------------------------------------------------------------------
# _hmac_sign() CRITICAL log in degraded state
# ---------------------------------------------------------------------------

def test_hmac_sign_emits_critical_log_when_kms_active():
    """_hmac_sign() emits logger.critical() with KMS_SIGNING_FALLBACK event when _kms_active=True (degraded state)."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name, legacy_salt="test-salt")

    # Confirm _kms_active is True
    assert signer._kms_active is True

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger:
        signer._hmac_sign(plan_bytes)

    # Verify critical was called
    assert mock_logger.critical.called, "logger.critical() was not called in degraded state"

    # Extract the JSON payload from the critical call
    critical_call_args = mock_logger.critical.call_args
    critical_message = critical_call_args[0][0]
    payload = json.loads(critical_message)

    assert payload["event"] == "KMS_SIGNING_FALLBACK"


def test_hmac_sign_critical_log_contains_severity_critical():
    """_hmac_sign() CRITICAL log payload contains 'severity': 'CRITICAL'."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name, legacy_salt="test-salt")

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger:
        signer._hmac_sign(plan_bytes)

    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["severity"] == "CRITICAL"


def test_hmac_sign_critical_log_contains_hmac_signing_path():
    """_hmac_sign() CRITICAL log payload contains 'signing_path': 'HMAC_SHA256_FALLBACK'."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name, legacy_salt="test-salt")

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger:
        signer._hmac_sign(plan_bytes)

    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["signing_path"] == "HMAC_SHA256_FALLBACK"


def test_hmac_sign_no_critical_log_when_kms_inactive():
    """_hmac_sign() does NOT emit logger.critical() when _kms_active=False (normal dev fallback)."""
    signer = _make_signer(kms_client=None, key_version_name="", legacy_salt="test-salt")

    assert signer._kms_active is False

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger:
        signer._hmac_sign(plan_bytes)

    mock_logger.critical.assert_not_called()


def test_hmac_sign_returns_valid_hex_digest():
    """_hmac_sign() returns a non-empty hex string when legacy_salt is set."""
    signer = _make_signer(kms_client=None, key_version_name="", legacy_salt="test-salt")
    plan_bytes = b'{"action":"test"}'
    result = signer._hmac_sign(plan_bytes)
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 hex digest is 64 chars


# ---------------------------------------------------------------------------
# assert_kms_active_in_production()
# ---------------------------------------------------------------------------

def test_assert_kms_active_does_not_raise_in_development():
    """assert_kms_active_in_production() does NOT raise when CAGE_ENV=development, even if KMS is inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    with patch.dict(os.environ, {"CAGE_ENV": "development"}, clear=False), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        # Should not raise
        assert_kms_active_in_production()


def test_assert_kms_active_does_not_raise_in_test_env():
    """assert_kms_active_in_production() does NOT raise when CAGE_ENV=test, even if KMS is inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    with patch.dict(os.environ, {"CAGE_ENV": "test"}, clear=False), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        assert_kms_active_in_production()


def test_assert_kms_active_does_not_raise_in_ci_env():
    """assert_kms_active_in_production() does NOT raise when CAGE_ENV=ci, even if KMS is inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    with patch.dict(os.environ, {"CAGE_ENV": "ci"}, clear=False), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        assert_kms_active_in_production()


def test_assert_kms_active_raises_in_production_when_kms_inactive():
    """assert_kms_active_in_production() raises RuntimeError when CAGE_ENV=production and KMS is inactive."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    env_overrides = {"CAGE_ENV": "production"}
    # Remove ENVIRONMENT to avoid it overriding CAGE_ENV logic
    env_without_environment = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
    env_without_environment.update(env_overrides)

    with patch.dict(os.environ, env_without_environment, clear=True), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        with pytest.raises(RuntimeError, match="HMAC fallback mode"):
            assert_kms_active_in_production()


def test_assert_kms_active_does_not_raise_in_production_when_kms_active():
    """assert_kms_active_in_production() does NOT raise when CAGE_ENV=production and KMS IS active."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = True

    env_overrides = {"CAGE_ENV": "production"}
    env_without_environment = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
    env_without_environment.update(env_overrides)

    with patch.dict(os.environ, env_without_environment, clear=True), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        # Should not raise
        assert_kms_active_in_production()


def test_assert_kms_active_raises_uses_environment_fallback():
    """assert_kms_active_in_production() uses ENVIRONMENT var when CAGE_ENV is not set."""
    mock_signer = MagicMock()
    mock_signer.is_kms_active = False

    # Clear CAGE_ENV, set ENVIRONMENT=production
    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["ENVIRONMENT"] = "production"

    with patch.dict(os.environ, env, clear=True), \
         patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=mock_signer):
        from src.gateway.governance.kms_signer import assert_kms_active_in_production
        with pytest.raises(RuntimeError):
            assert_kms_active_in_production()


# ---------------------------------------------------------------------------
# from_env() fallback paths
# ---------------------------------------------------------------------------

def test_from_env_hmac_fallback_when_no_kms_key_set():
    """from_env() produces a signer with is_kms_active=False when KMS_GOVERNANCE_KEY is not set."""
    env = {k: v for k, v in os.environ.items() if k not in ("KMS_GOVERNANCE_KEY",)}
    env["GOVERNANCE_SALT"] = "test-salt-for-from-env"

    with patch.dict(os.environ, env, clear=True):
        # Reload the module-level constants by patching them directly
        with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""), \
             patch("src.gateway.governance.kms_signer._LEGACY_SALT", "test-salt-for-from-env"):
            from src.gateway.governance.kms_signer import KMSGovernanceSigner
            signer = KMSGovernanceSigner.from_env()

    assert signer.is_kms_active is False
    assert signer.signing_algorithm == "HMAC_SHA256_FALLBACK"


def test_from_env_hmac_fallback_when_google_cloud_kms_not_installed():
    """from_env() falls back to HMAC when KMS_GOVERNANCE_KEY is set but google-cloud-kms raises ImportError."""
    with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION",
               "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"), \
         patch("src.gateway.governance.kms_signer._LEGACY_SALT", "test-salt"), \
         patch("builtins.__import__", side_effect=_import_error_for_google_cloud_kms):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        signer = KMSGovernanceSigner.from_env()

    assert signer.is_kms_active is False
    assert signer.signing_algorithm == "HMAC_SHA256_FALLBACK"


def _import_error_for_google_cloud_kms(name, *args, **kwargs):
    """Side-effect function: raises ImportError only for google.cloud.kms imports."""
    if "google" in name or "google.cloud" in name:
        raise ImportError(f"No module named '{name}'")
    return original_import(name, *args, **kwargs)


# Store the real __import__ before patching
import builtins
original_import = builtins.__import__


def test_from_env_signing_algorithm_hmac_when_no_key():
    """from_env() signer has signing_algorithm='HMAC_SHA256_FALLBACK' when KMS_GOVERNANCE_KEY is absent."""
    with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""), \
         patch("src.gateway.governance.kms_signer._LEGACY_SALT", "test-salt"):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        signer = KMSGovernanceSigner.from_env()

    assert signer.signing_algorithm == "HMAC_SHA256_FALLBACK"


# ---------------------------------------------------------------------------
# _kms_sign() CRITICAL log on runtime KMS failure
# ---------------------------------------------------------------------------

def test_kms_sign_emits_critical_log_on_failure():
    """_kms_sign() emits logger.critical() with KMS_SIGNING_FALLBACK event when KMS call fails at runtime."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name, legacy_salt="test-salt")

    # Make the KMS service types import succeed but the actual sign call fail
    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(side_effect=RuntimeError("KMS unavailable"))
    mock_kms_service.Digest = MagicMock()

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        result = signer._kms_sign(plan_bytes)

    # Should fall back to HMAC and emit critical
    assert mock_logger.critical.called
    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["event"] == "KMS_SIGNING_FALLBACK"
    # Result should be the HMAC fallback (non-empty hex string)
    assert isinstance(result, str)
    assert len(result) == 64
