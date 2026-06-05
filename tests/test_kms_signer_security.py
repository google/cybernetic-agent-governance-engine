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

def _make_signer(kms_client=None, key_version_name=""):
    """Construct a KMSGovernanceSigner directly without touching env vars."""
    from src.gateway.governance.kms_signer import KMSGovernanceSigner
    return KMSGovernanceSigner(
        kms_client=kms_client,
        key_version_name=key_version_name,
        public_key_pem=b"",
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

def test_sign_raises_runtime_error_when_kms_inactive():
    """sign() raises RuntimeError when KMS is not active (no HMAC fallback)."""
    signer = _make_signer(kms_client=None, key_version_name="")
    with pytest.raises(RuntimeError, match="KMS is not active"):
        signer.sign({"action": "test"})


def test_sign_algorithm_property_hmac_fallback_label_when_kms_inactive():
    """signing_algorithm returns 'HMAC_SHA256_FALLBACK' label when KMS inactive (property still exists for audit tagging)."""
    signer = _make_signer(kms_client=None, key_version_name="")
    assert signer.signing_algorithm == "HMAC_SHA256_FALLBACK"


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

    # Mock the KMS service types import inside _kms_sign (must mock all parent packages)
    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(return_value=MagicMock())
    mock_kms_service.Digest = MagicMock(return_value=MagicMock())
    kms_modules = {
        "google": MagicMock(), "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(), "google.cloud.kms_v1.types": MagicMock(),
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer, \
         patch.dict("sys.modules", kms_modules):
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
    kms_modules = {
        "google": MagicMock(), "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(), "google.cloud.kms_v1.types": MagicMock(),
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with patch("src.gateway.governance.kms_signer._tracer") as mock_tracer, \
         patch.dict("sys.modules", kms_modules):
        mock_tracer.start_as_current_span.return_value = mock_ctx_manager
        signer.sign({"action": "test"})

    mock_span.set_attribute.assert_any_call("cage.signing.kms_active", True)


# ---------------------------------------------------------------------------
# _kms_sign() failure behaviour (no HMAC fallback)
# ---------------------------------------------------------------------------

def test_kms_sign_emits_critical_log_and_raises_on_failure():
    """_kms_sign() emits logger.critical() with KMS_SIGNING_FAILED event and raises RuntimeError when KMS call fails."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    # Confirm _kms_active is True
    assert signer._kms_active is True

    plan_bytes = b'{"action":"test"}'

    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(side_effect=RuntimeError("KMS unavailable"))
    mock_kms_service.Digest = MagicMock()

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        with pytest.raises(RuntimeError, match="KMS asymmetricSign failed"):
            signer._kms_sign(plan_bytes)

    # Verify critical was called with KMS_SIGNING_FAILED event
    assert mock_logger.critical.called, "logger.critical() was not called on KMS failure"
    critical_call_args = mock_logger.critical.call_args
    critical_message = critical_call_args[0][0]
    payload = json.loads(critical_message)
    assert payload["event"] == "KMS_SIGNING_FAILED"


def test_kms_sign_critical_log_contains_severity_critical():
    """_kms_sign() CRITICAL log payload contains 'severity': 'CRITICAL'."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    plan_bytes = b'{"action":"test"}'

    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(side_effect=RuntimeError("KMS unavailable"))
    mock_kms_service.Digest = MagicMock()

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        with pytest.raises(RuntimeError):
            signer._kms_sign(plan_bytes)

    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["severity"] == "CRITICAL"


def test_kms_sign_critical_log_contains_audit_note():
    """_kms_sign() CRITICAL log payload contains 'audit_note' indicating no fallback."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    plan_bytes = b'{"action":"test"}'

    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(side_effect=RuntimeError("KMS unavailable"))
    mock_kms_service.Digest = MagicMock()

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        with pytest.raises(RuntimeError):
            signer._kms_sign(plan_bytes)

    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert "audit_note" in payload


def test_sign_raises_when_kms_inactive_no_fallback():
    """sign() raises RuntimeError when _kms_active=False — no HMAC fallback exists."""
    signer = _make_signer(kms_client=None, key_version_name="")
    assert signer._kms_active is False
    with pytest.raises(RuntimeError, match="KMS is not active"):
        signer.sign({"action": "test"})


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
# from_env() error paths (no HMAC fallback — raises RuntimeError)
# ---------------------------------------------------------------------------

def test_from_env_raises_when_no_kms_key_set():
    """from_env() raises RuntimeError when KMS_GOVERNANCE_KEY is not set (no HMAC fallback)."""
    with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        with pytest.raises(RuntimeError, match="KMS_GOVERNANCE_KEY is not set"):
            KMSGovernanceSigner.from_env()


def test_from_env_raises_when_google_cloud_kms_not_installed():
    """from_env() raises RuntimeError when KMS_GOVERNANCE_KEY is set but google-cloud-kms raises ImportError."""
    import builtins
    original_import = builtins.__import__

    def _import_error_for_google_cloud_kms(name, *args, **kwargs):
        if "google.cloud" in name or name == "google":
            raise ImportError(f"No module named '{name}'")
        return original_import(name, *args, **kwargs)

    with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION",
               "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"), \
         patch("builtins.__import__", side_effect=_import_error_for_google_cloud_kms):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        with pytest.raises(RuntimeError, match="google-cloud-kms is not installed"):
            KMSGovernanceSigner.from_env()


def test_from_env_signing_algorithm_raises_when_no_key():
    """from_env() raises RuntimeError (not returns HMAC signer) when KMS_GOVERNANCE_KEY is absent."""
    with patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        with pytest.raises(RuntimeError, match="KMS_GOVERNANCE_KEY is not set"):
            KMSGovernanceSigner.from_env()


# ---------------------------------------------------------------------------
# _kms_sign() CRITICAL log on runtime KMS failure — raises RuntimeError (no fallback)
# ---------------------------------------------------------------------------

def test_kms_sign_emits_critical_log_and_raises_on_runtime_failure():
    """_kms_sign() emits logger.critical() with KMS_SIGNING_FAILED event and raises RuntimeError when KMS call fails."""
    mock_kms_client = MagicMock()
    key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    signer = _make_signer(kms_client=mock_kms_client, key_version_name=key_name)

    # Make the KMS service types import succeed but the actual sign call fail
    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(side_effect=RuntimeError("KMS unavailable"))
    mock_kms_service.Digest = MagicMock()

    plan_bytes = b'{"action":"test"}'

    with patch("src.gateway.governance.kms_signer.logger") as mock_logger, \
         patch.dict("sys.modules", {"google.cloud.kms_v1.types.service": mock_kms_service}):
        with pytest.raises(RuntimeError, match="KMS asymmetricSign failed"):
            signer._kms_sign(plan_bytes)

    # Should emit critical with KMS_SIGNING_FAILED (not FALLBACK — there is no fallback)
    assert mock_logger.critical.called
    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["event"] == "KMS_SIGNING_FAILED"
