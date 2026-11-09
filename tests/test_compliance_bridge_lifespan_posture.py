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
# Closure regression guard for: POAM-018

"""POAM-018: the compliance bridge refuses to start without Langfuse credentials.

Every lifespan test runs the real FastAPI startup (``with TestClient(app)``),
not a lifespan-skipping client, so a regression that drops
``validate_langfuse_credentials()`` from ``lifespan`` fails here. Posture is
resolved per call, so a module first imported under ``CAGE_ENV=test`` (as every
hermetic run does) still fails closed when the service starts under an
enforcing posture.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import src.compliance_bridge.main as bridge_main
from src.compliance_bridge.audit_workflow import (
    LANGFUSE_CREDENTIAL_ENV_VARS,
    validate_langfuse_credentials,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_ENFORCING_POSTURES = ("staging", "production", "local", "unknown-posture")
_PERMISSIVE_POSTURES = ("dev", "test", "ci")


def _configured_env(posture: str | None) -> dict[str, str]:
    env = {var: f"synthetic-{var.lower()}" for var in LANGFUSE_CREDENTIAL_ENV_VARS}
    if posture is not None:
        env["CAGE_ENV"] = posture
    return env


# ---------------------------------------------------------------------------
# Guard semantics (pure: explicit env mapping, no process state)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("posture", [*_ENFORCING_POSTURES, None])
@pytest.mark.parametrize("missing_var", LANGFUSE_CREDENTIAL_ENV_VARS)
def test_guard_raises_naming_each_missing_credential_under_enforcing_posture(
    posture: str | None, missing_var: str
) -> None:
    env = _configured_env(posture)
    env[missing_var] = ""  # empty counts as missing
    with pytest.raises(RuntimeError, match=rf"\[POAM-018\].*{missing_var}"):
        validate_langfuse_credentials(env)


@pytest.mark.parametrize("posture", _PERMISSIVE_POSTURES)
def test_guard_only_warns_under_permissive_posture(
    posture: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        validate_langfuse_credentials({"CAGE_ENV": posture})
    assert any(
        "[POAM-018]" in rec.getMessage()
        and all(var in rec.getMessage() for var in LANGFUSE_CREDENTIAL_ENV_VARS)
        for rec in caplog.records
    )


@pytest.mark.parametrize("posture", _ENFORCING_POSTURES)
def test_guard_passes_when_all_credentials_configured(posture: str) -> None:
    validate_langfuse_credentials(_configured_env(posture))


def test_guard_is_not_run_at_import_time() -> None:
    """Startup, not import, is the enforcement point: no module-level call remains."""
    import ast
    import inspect

    import src.compliance_bridge.audit_workflow as audit_workflow

    tree = ast.parse(inspect.getsource(audit_workflow))
    module_level_calls = [
        node.value.func.id
        for node in tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    ]
    assert "validate_langfuse_credentials" not in module_level_calls


# ---------------------------------------------------------------------------
# Real lifespan startup
# ---------------------------------------------------------------------------


@contextmanager
def _stubbed_startup_dependencies() -> Iterator[MagicMock]:
    """Stub custody clients, CMEK probe, SLA loop and Langfuse I/O.

    The custodian factory is a ``MagicMock`` so tests can assert the
    POAM-018 pre-flight ran before any custody client was constructed.
    """
    custodian = MagicMock()
    custodian.run_forever = AsyncMock(return_value=None)
    custodian.aclose = AsyncMock(return_value=None)
    verifier = MagicMock()
    verifier.run_forever = AsyncMock(return_value=None)
    custodian_factory = MagicMock(return_value=custodian)
    with (
        patch.object(bridge_main, "_app_langfuse", None),
        patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()),
        patch(
            "src.compliance_bridge.evidence_custodian.EvidenceCustodian.from_env",
            new=custodian_factory,
        ),
        patch(
            "src.compliance_bridge.evidence_verifier.CustodyVerifier.from_env",
            return_value=verifier,
        ),
        patch(
            "src.compliance_bridge.main.validate_cmek_configuration",
            return_value={
                "cmek_enabled": False,
                "key_name": None,
                "bucket_verified": False,
                "warnings": [],
            },
        ),
        patch(
            "src.compliance_bridge.main.run_sla_monitor",
            new=AsyncMock(return_value=None),
        ),
    ):
        yield custodian_factory


def _set_startup_env(
    monkeypatch: pytest.MonkeyPatch, posture: str | None, *, credentials: bool
) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    if posture is None:
        monkeypatch.delenv("CAGE_ENV", raising=False)
    else:
        monkeypatch.setenv("CAGE_ENV", posture)
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
    monkeypatch.setenv("KMS_BATCH_ENABLED", "false")
    monkeypatch.setenv(
        "CAGE_TRUSTED_OPERATOR_IDENTITIES", "operator:auditor@example.org"
    )
    for var in LANGFUSE_CREDENTIAL_ENV_VARS:
        if credentials:
            monkeypatch.setenv(var, f"synthetic-{var.lower()}")
        else:
            monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("posture", ["staging", "production", "local", None])
@pytest.mark.parametrize("missing_var", LANGFUSE_CREDENTIAL_ENV_VARS)
def test_lifespan_refuses_startup_before_custody_when_credential_missing(
    posture: str | None, missing_var: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_startup_env(monkeypatch, posture, credentials=True)
    monkeypatch.delenv(missing_var, raising=False)

    with _stubbed_startup_dependencies() as custodian_factory:
        with pytest.raises(RuntimeError, match=rf"\[POAM-018\].*{missing_var}"):
            with TestClient(bridge_main.app):
                pass
        custodian_factory.assert_not_called()


def test_lifespan_starts_in_staging_with_credentials_and_health_reports_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_startup_env(monkeypatch, "staging", credentials=True)

    with _stubbed_startup_dependencies() as custodian_factory:
        with TestClient(bridge_main.app) as client:
            custodian_factory.assert_called()
            body = client.get("/health").json()

    assert body["langfuse_compliance_configured"] is True
    assert body["langfuse_app_configured"] is True
    assert body["environment"] == "staging"


def test_lifespan_starts_in_dev_without_credentials_and_health_reports_absence(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _set_startup_env(monkeypatch, "dev", credentials=False)
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")

    with (
        _stubbed_startup_dependencies(),
        caplog.at_level(logging.WARNING),
        TestClient(bridge_main.app) as client,
    ):
        body = client.get("/health").json()

    assert body["langfuse_compliance_configured"] is False
    assert body["langfuse_app_configured"] is False
    assert any("[POAM-018]" in rec.getMessage() for rec in caplog.records)
