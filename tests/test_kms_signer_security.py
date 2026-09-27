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
  - startup posture ``kms_signing_mode`` check (governor/posture.py) against a
    real signer: HMAC fallback refused under enforcing postures, logged under
    DEV/TEST/CI
  - from_env() fallback paths (no key set, ImportError)
"""

import json
import os
from unittest.mock import MagicMock, patch

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
    signer = _make_signer(
        kms_client=mock_client,
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
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
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": MagicMock(),
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with (
        patch("src.gateway.governance.kms_signer._tracer") as mock_tracer,
        patch.dict("sys.modules", kms_modules),
    ):
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
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": MagicMock(),
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with (
        patch("src.gateway.governance.kms_signer._tracer") as mock_tracer,
        patch.dict("sys.modules", kms_modules),
    ):
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
    mock_kms_service.AsymmetricSignRequest = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )
    mock_kms_service.Digest = MagicMock()
    # `from google.cloud.kms_v1.types import service` resolves via attribute lookup
    # on sys.modules["google.cloud.kms_v1.types"], NOT via sys.modules key lookup.
    # The types mock must expose .service = mock_kms_service so the import binds
    # to our mock rather than to an auto-generated MagicMock attribute.
    mock_kms_types = MagicMock()
    mock_kms_types.service = mock_kms_service
    kms_modules = {
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": mock_kms_types,
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with (
        patch("src.gateway.governance.kms_signer.logger") as mock_logger,
        patch.dict("sys.modules", kms_modules),
    ):
        with pytest.raises(RuntimeError, match="KMS asymmetricSign failed"):
            signer._kms_sign(plan_bytes)

    # Verify critical was called with KMS_SIGNING_FAILED event
    assert mock_logger.critical.called, (
        "logger.critical() was not called on KMS failure"
    )
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
    mock_kms_service.AsymmetricSignRequest = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )
    mock_kms_service.Digest = MagicMock()
    mock_kms_types = MagicMock()
    mock_kms_types.service = mock_kms_service
    kms_modules = {
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": mock_kms_types,
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with (
        patch("src.gateway.governance.kms_signer.logger") as mock_logger,
        patch.dict("sys.modules", kms_modules),
    ):
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
    mock_kms_service.AsymmetricSignRequest = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )
    mock_kms_service.Digest = MagicMock()
    mock_kms_types = MagicMock()
    mock_kms_types.service = mock_kms_service
    kms_modules = {
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": mock_kms_types,
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    with (
        patch("src.gateway.governance.kms_signer.logger") as mock_logger,
        patch.dict("sys.modules", kms_modules),
    ):
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
# Startup posture: kms_signing_mode (K3) against a real KMSGovernanceSigner
# ---------------------------------------------------------------------------

_KEY_NAME = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"


class _HealthyRedis:
    def ping_ready(self) -> None:
        return None


@pytest.fixture()
def posture_probes(monkeypatch):
    """Every startup probe except the signer healthy; tests choose the signer."""
    from src.gateway.governance.governor import posture as posture_mod

    class _Verifier:
        trust_anchor_kids = ("reconciler-kid",)

    monkeypatch.setattr(posture_mod, "_redis", lambda: _HealthyRedis())
    monkeypatch.setattr(posture_mod, "_reconciler_verifier", lambda: _Verifier())
    monkeypatch.setenv("RECONCILER_KMS_KEY", "projects/p/locations/l/keyRings/r/cryptoKeys/reconciler")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "ledger")
    monkeypatch.setattr("src.gateway.governance.routing_seal._USING_DEFAULT_SALT", False)

    def use_signer(signer):
        monkeypatch.setattr(posture_mod, "_signer", lambda: signer)

    return use_signer


def _components(posture):
    from tests.fixtures.governor import make_governor

    return make_governor(posture=posture).components


@pytest.mark.parametrize("posture_name", ["DEV", "TEST", "CI"])
def test_hmac_fallback_signer_is_permitted_but_logged_in_permissive_posture(
    posture_probes, caplog, posture_name
):
    """An HMAC-fallback signer does not abort DEV/TEST/CI startup; it logs CRITICAL."""
    import logging

    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.posture import assert_production_posture

    posture = DeploymentPosture[posture_name]
    signer = _make_signer(kms_client=None, key_version_name="")
    assert signer.is_kms_active is False
    posture_probes(signer)

    with caplog.at_level(logging.CRITICAL):
        assert_production_posture(posture, components=_components(posture))

    checks = [
        json.loads(r.getMessage())["check"]
        for r in caplog.records
        if r.levelno == logging.CRITICAL and "CAGE_POSTURE_CHECK_FAILED" in r.getMessage()
    ]
    assert checks == ["kms_signing_mode"]


@pytest.mark.parametrize("posture_name", ["PRODUCTION", "STAGING", "LOCAL"])
def test_hmac_fallback_signer_refuses_enforcing_posture(posture_probes, posture_name):
    """An HMAC-fallback signer aborts startup under every enforcing posture."""
    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.posture import (
        PostureViolation,
        assert_production_posture,
    )

    posture = DeploymentPosture[posture_name]
    posture_probes(_make_signer(kms_client=None, key_version_name=""))

    with pytest.raises(PostureViolation, match="kms_signing_mode: governance signer is in HMAC fallback mode"):
        assert_production_posture(posture, components=_components(posture))


def test_kms_active_signer_passes_kms_signing_mode_check(posture_probes):
    """A KMS-backed signer satisfies the kms_signing_mode check in production."""
    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor import posture as posture_mod

    signer = _make_signer(kms_client=MagicMock(), key_version_name=_KEY_NAME)
    assert signer.is_kms_active is True
    posture_probes(signer)

    kms_signing_mode = dict(posture_mod.CHECKS)["kms_signing_mode"]
    kms_signing_mode(_components(DeploymentPosture.PRODUCTION))  # must not raise


def test_hmac_fallback_refused_when_posture_comes_from_environment_fallback(posture_probes):
    """With CAGE_ENV unset, ENVIRONMENT=production resolves an enforcing posture
    and the HMAC-fallback signer is refused."""
    from src.gateway.governance.env_posture import (
        DeploymentPosture,
        is_enforcing,
        resolve_posture,
    )
    from src.gateway.governance.governor.posture import (
        PostureViolation,
        assert_production_posture,
    )

    posture_probes(_make_signer(kms_client=None, key_version_name=""))
    env = {k: v for k, v in os.environ.items() if k not in ("CAGE_ENV", "ENVIRONMENT")}
    env["ENVIRONMENT"] = "production"

    with patch.dict(os.environ, env, clear=True):
        posture = resolve_posture()
        assert posture is DeploymentPosture.PRODUCTION
        assert is_enforcing(posture)
        with pytest.raises(PostureViolation, match="kms_signing_mode"):
            assert_production_posture(posture, components=_components(posture))


# ---------------------------------------------------------------------------
# from_env() error paths (no HMAC fallback — raises RuntimeError)
# ---------------------------------------------------------------------------


def test_from_env_raises_when_no_kms_key_set():
    """from_env() raises RuntimeError when KMS_GOVERNANCE_KEY is not set (no HMAC fallback)."""
    with (
        patch.dict(os.environ, {"CAGE_ENV": "production", "ENVIRONMENT": "production"}),
        patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""),
    ):
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

    with (
        patch.dict(os.environ, {"CAGE_ENV": "production", "ENVIRONMENT": "production"}),
        patch(
            "src.gateway.governance.kms_signer._KMS_KEY_VERSION",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ),
        patch("builtins.__import__", side_effect=_import_error_for_google_cloud_kms),
    ):
        from src.gateway.governance.kms_signer import KMSGovernanceSigner

        with pytest.raises(RuntimeError, match="google-cloud-kms is not installed"):
            KMSGovernanceSigner.from_env()


def test_from_env_signing_algorithm_raises_when_no_key():
    """from_env() raises RuntimeError (not returns HMAC signer) when KMS_GOVERNANCE_KEY is absent."""
    with (
        patch.dict(os.environ, {"CAGE_ENV": "production", "ENVIRONMENT": "production"}),
        patch("src.gateway.governance.kms_signer._KMS_KEY_VERSION", ""),
    ):
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

    # Make the KMS service types import succeed but the actual sign call fail.
    # `from google.cloud.kms_v1.types import service` resolves .service via attribute
    # access on sys.modules["google.cloud.kms_v1.types"], so mock_kms_types.service
    # must equal mock_kms_service for the side_effect to be applied.
    mock_kms_service = MagicMock()
    mock_kms_service.AsymmetricSignRequest = MagicMock(
        side_effect=RuntimeError("KMS unavailable")
    )
    mock_kms_service.Digest = MagicMock()
    mock_kms_types = MagicMock()
    mock_kms_types.service = mock_kms_service
    kms_modules = {
        "google": MagicMock(),
        "google.cloud": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.kms_v1.types": mock_kms_types,
        "google.cloud.kms_v1.types.service": mock_kms_service,
    }

    plan_bytes = b'{"action":"test"}'

    with (
        patch("src.gateway.governance.kms_signer.logger") as mock_logger,
        patch.dict("sys.modules", kms_modules),
    ):
        with pytest.raises(RuntimeError, match="KMS asymmetricSign failed"):
            signer._kms_sign(plan_bytes)

    # Should emit critical with KMS_SIGNING_FAILED (not FALLBACK — there is no fallback)
    assert mock_logger.critical.called
    critical_call_args = mock_logger.critical.call_args
    payload = json.loads(critical_call_args[0][0])
    assert payload["event"] == "KMS_SIGNING_FAILED"
