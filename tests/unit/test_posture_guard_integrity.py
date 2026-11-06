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

"""Unit, AST, and runtime behavioral tests for posture guard integrity (F-112)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI

from scripts.check_posture_guard_integrity import (
    main as check_posture_main,
)
from scripts.check_posture_guard_integrity import (
    scan_source,
    scan_tree,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "src"


# ---------------------------------------------------------------------------
# 1. Repository-wide gate pass
# ---------------------------------------------------------------------------


def test_repo_src_has_zero_posture_guard_violations() -> None:
    """All files under src/ must pass Rule A and Rule B with zero waivers."""
    violations = scan_tree(_SRC_ROOT)
    assert violations == [], (
        "Posture guard integrity violations detected:\n"
        + "\n".join(f"  {v.format_line_span()}: {v.detail}" for v in violations)
    )


def test_cli_main_exits_zero_on_repo() -> None:
    """CLI entrypoint returns exit code 0 with --verbose against src/."""
    rc = check_posture_main(["--root", str(_SRC_ROOT), "--verbose"])
    assert rc == 0


def test_cli_main_fails_closed_on_missing_root(tmp_path: Path) -> None:
    """CLI entrypoint returns exit code 1 when the scan root does not exist."""
    rc = check_posture_main(["--root", str(tmp_path / "does_not_exist")])
    assert rc == 1


# ---------------------------------------------------------------------------
# 2. Synthetic AST fixtures — Rule A (Query #3: Swallowed posture-gated raise)
# ---------------------------------------------------------------------------


def test_rule_a_flags_swallowed_posture_gated_function() -> None:
    """Broad except without re-raise around a posture-gated function is flagged."""
    code = """
import os

def build_signer():
    if os.environ.get("CAGE_ENV", "production") != "dev":
        raise RuntimeError("missing KMS key")
    return object()

def startup():
    try:
        return build_signer()
    except Exception:
        return None
"""
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule A" in violations[0].rule
    assert "build_signer()" in violations[0].target


def test_rule_a_flags_transitive_from_env_and_singleton_getter() -> None:
    """ClassName.from_env and _get_* wrappers calling posture-gated targets are flagged when swallowed."""
    code = """
def is_enforcing():
    return True

class InnerSigner:
    @classmethod
    def from_env(cls):
        if is_enforcing():
            raise RuntimeError("KMS required")
        return cls()

class OuterLogger:
    @classmethod
    def from_env(cls):
        return cls(InnerSigner.from_env())

def _get_outer_logger():
    return OuterLogger.from_env()

def bad_boot_class():
    try:
        OuterLogger.from_env()
    except RuntimeError:
        pass

def bad_boot_singleton():
    try:
        _get_outer_logger()
    except:
        pass
"""
    violations = scan_source(code)
    assert len(violations) == 2
    targets = {v.target for v in violations}
    assert targets == {"OuterLogger.from_env()", "_get_outer_logger()"}


def test_rule_a_flags_partial_return_before_reraise() -> None:
    """An except handler with a conditional early return before raise is still flagged."""
    code = """
def build_guard():
    if is_enforcing():
        raise RuntimeError("refused")

def boot(ignore: bool):
    try:
        build_guard()
    except Exception:
        if ignore:
            return
        raise
"""
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule A" in violations[0].rule


def test_rule_a_allows_unconditional_reraise_and_enforcing_reraise() -> None:
    """Handlers that re-raise unconditionally or re-raise when is_enforcing() holds are allowed."""
    code = """
class ConfigError(Exception):
    pass

def build_signer():
    if is_enforcing(resolve_posture()):
        raise RuntimeError("missing key")
    return None

def custodian_from_env():
    try:
        return build_signer()
    except RuntimeError as exc:
        raise ConfigError(str(exc)) from exc

def logger_from_env():
    try:
        return build_signer()
    except Exception:
        if is_enforcing(resolve_posture()):
            raise
        return None
"""
    assert scan_source(code) == []


def test_rule_a_allows_import_error_only_fallback() -> None:
    """Optional-dependency fallbacks catching strictly ImportError / ModuleNotFoundError are allowed."""
    code = """
def build_optional_adapter():
    if is_enforcing():
        raise RuntimeError("missing key")
    return object()

def load_optional():
    try:
        return build_optional_adapter()
    except (ImportError, ModuleNotFoundError):
        return None
"""
    assert scan_source(code) == []


# ---------------------------------------------------------------------------
# 3. Synthetic AST fixtures — Rule B (Query #4: Caller-narrowed posture guard)
# ---------------------------------------------------------------------------


def test_rule_b_flags_prod_only_caller_narrowing() -> None:
    """Wrapping a broad enforcing guard inside `if env == "prod":` is flagged."""
    code = """
import os

class Signer:
    def assert_kms_active_in_production(self):
        env = os.environ.get("CAGE_ENV", "production").lower()
        if env in ("development", "test", "dev", "ci"):
            return
        raise RuntimeError("HMAC fallback active")

def boot(signer: Signer, env: str):
    if env == "prod":
        signer.assert_kms_active_in_production()
"""
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule B" in violations[0].rule
    assert "assert_kms_active_in_production()" in violations[0].target
    assert violations[0].line_number == 12
    assert violations[0].end_line_number == 13


def test_rule_b_flags_enum_production_only_and_negated_else_narrowing() -> None:
    """Rule B catches DeploymentPosture.PRODUCTION-only conditions and != 'prod' else branches."""
    code = """
def assert_posture_ready():
    if is_enforcing():
        raise RuntimeError("not ready")

def boot_enum(posture):
    if posture == DeploymentPosture.PRODUCTION:
        assert_posture_ready()

def boot_else(env: str):
    if env != "prod":
        pass
    else:
        assert_posture_ready()
"""
    violations = scan_source(code)
    assert len(violations) == 2
    assert all("Rule B" in v.rule for v in violations)


def test_rule_b_allows_unconditional_and_is_enforcing_calls() -> None:
    """Unconditional guard calls and `if is_enforcing():` calls are allowed."""
    code = """
def assert_posture_ready():
    if is_enforcing():
        raise RuntimeError("not ready")

def boot_unconditional():
    assert_posture_ready()

def boot_enforcing():
    if is_enforcing():
        assert_posture_ready()

def boot_full_enforcing_set(env: str):
    if env in ("prod", "production", "staging"):
        assert_posture_ready()
"""
    assert scan_source(code) == []


def test_cross_module_scan_tree_flags_violations_and_returns_nonzero(
    tmp_path: Path,
) -> None:
    """scan_tree and CLI main detect Rule A and Rule B across separate module files."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "guards.py").write_text(
        "def assert_ready():\n"
        "    if is_enforcing():\n"
        "        raise RuntimeError('fail')\n",
        encoding="utf-8",
    )
    (pkg / "caller.py").write_text(
        "from pkg.guards import assert_ready\n"
        "def boot(env: str):\n"
        "    try:\n"
        "        assert_ready()\n"
        "    except Exception:\n"
        "        pass\n"
        "    if env == 'prod':\n"
        "        assert_ready()\n",
        encoding="utf-8",
    )
    violations = scan_tree(tmp_path)
    assert len(violations) == 2
    assert check_posture_main(["--root", str(tmp_path)]) == 1


# ---------------------------------------------------------------------------
# 4. Runtime behavioral tests — F-112 remediations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cage_env", ["staging", "prod", "production"])
@pytest.mark.asyncio
async def test_async_batch_signer_start_propagates_failure_without_leaking_worker(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """AsyncBatchSigner.start() fails closed in staging/prod without spawning _worker_task."""
    from src.compliance_bridge.kms_batch_signer import AsyncBatchSigner

    monkeypatch.setenv("CAGE_ENV", cage_env)
    monkeypatch.delenv("EVIDENCE_KMS_KEY", raising=False)
    monkeypatch.delenv("KMS_PROVIDER", raising=False)
    monkeypatch.delenv("CAGE_KMS_PROVIDER", raising=False)

    signer = AsyncBatchSigner(flush_interval_ms=50, max_batch_size=4)
    with pytest.raises(RuntimeError, match="EVIDENCE_KMS_KEY is not set"):
        await signer.start()

    assert signer._worker_task is None
    assert signer.is_running is False


@pytest.mark.parametrize("cage_env", ["staging", "prod", "production"])
def test_assert_kms_active_in_production_enforces_staging_and_prod(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """AsyncBatchSigner.assert_kms_active_in_production() raises across all enforcing postures."""
    from src.compliance_bridge.kms_batch_signer import AsyncBatchSigner

    monkeypatch.setenv("CAGE_ENV", cage_env)
    signer = AsyncBatchSigner()
    with pytest.raises(RuntimeError, match="HMAC fallback mode"):
        signer.assert_kms_active_in_production()


@pytest.mark.parametrize("cage_env", ["dev", "test", "ci"])
def test_assert_kms_active_in_production_relaxes_in_permissive_postures(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """AsyncBatchSigner.assert_kms_active_in_production() allows permissive dev/test/ci postures."""
    from src.compliance_bridge.kms_batch_signer import AsyncBatchSigner

    monkeypatch.setenv("CAGE_ENV", cage_env)
    signer = AsyncBatchSigner()
    signer.assert_kms_active_in_production()


@pytest.mark.parametrize("cage_env", ["staging", "production", "prod"])
@pytest.mark.asyncio
async def test_compliance_bridge_lifespan_invokes_kms_guard_in_all_enforcing_postures(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """compliance_bridge lifespan calls assert_kms_active_in_production() in staging, production, and prod."""
    from src.compliance_bridge import main as cb_main
    from src.compliance_bridge.kms_batch_signer import AsyncBatchSigner

    monkeypatch.setenv("CAGE_ENV", cage_env)
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")

    custodian = MagicMock()
    custodian.run_forever = AsyncMock(return_value=None)
    custodian.aclose = AsyncMock(return_value=None)
    verifier = MagicMock()
    verifier.run_forever = AsyncMock(return_value=None)

    # Pre-seed an HMAC-fallback signer on AsyncBatchSigner so start() succeeds
    # and assert_kms_active_in_production() is the guard that refuses startup.
    fallback_batch_signer = AsyncBatchSigner(flush_interval_ms=500, max_batch_size=4)
    fallback_batch_signer._signer = MagicMock(is_kms_active=False)

    test_app = FastAPI()
    try:
        with (
            patch(
                "src.compliance_bridge.evidence_custodian.EvidenceCustodian.from_env",
                return_value=custodian,
            ),
            patch(
                "src.compliance_bridge.evidence_verifier.CustodyVerifier.from_env",
                return_value=verifier,
            ),
            patch.object(
                cb_main,
                "validate_cmek_configuration",
                return_value={
                    "cmek_enabled": True,
                    "key_name": "projects/<PROJECT_ID>/locations/us-central1/keyRings/r/cryptoKeys/k",
                    "bucket_verified": True,
                    "warnings": [],
                },
            ),
            patch.object(cb_main, "_get_app_langfuse", return_value=MagicMock()),
            patch(
                "src.gateway.governance.schemas.thresholds.get_kms_batch_enabled",
                return_value=True,
            ),
            patch(
                "src.compliance_bridge.kms_batch_signer.get_batch_signer",
                return_value=fallback_batch_signer,
            ),
        ):
            with pytest.raises(RuntimeError, match="HMAC fallback mode"):
                async with cb_main.lifespan(test_app):
                    pass
    finally:
        await fallback_batch_signer.stop()


@pytest.mark.parametrize("cage_env", ["staging", "production", "prod"])
@pytest.mark.asyncio
async def test_hybrid_server_lifespan_propagates_uca_logger_failure_in_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    cage_env: str,
) -> None:
    """_gateway_lifespan propagates UCALogger.from_env() failure in enforcing postures instead of warning."""
    import src.gateway.governance.evidence.stream as stream_mod
    import src.gateway.governance.uca_logger as uca_mod
    from tests.test_hybrid_server import _make_hybrid_stubs

    monkeypatch.setenv("CAGE_ENV", cage_env)
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")
    monkeypatch.setenv(
        "CAGE_TRUSTED_CLIENT_IDENTITIES",
        "advisor.cage.serviceaccount.identity.linkerd.cluster.local",
    )
    monkeypatch.setattr(uca_mod, "_uca_logger", None)
    monkeypatch.setattr(stream_mod, "start_evidence_sink", AsyncMock(return_value=None))

    stubs = _make_hybrid_stubs()
    # Exercise the real uca_logger module with a failing KMSGovernanceSigner.from_env().
    stubs.pop("src.gateway.governance.uca_logger", None)
    stubs[
        "src.gateway.governance.kms_signer"
    ].KMSGovernanceSigner.from_env.side_effect = RuntimeError(
        "KMS_GOVERNANCE_KEY is not set"
    )

    sys.modules.pop("src.gateway.server.hybrid_server", None)
    caplog.set_level(logging.WARNING)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        test_app = FastAPI()
        served = False
        with pytest.raises(RuntimeError, match="KMS_GOVERNANCE_KEY is not set"):
            async with _gateway_lifespan(test_app):
                served = True

    assert served is False
    assert not any("non-blocking" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_hybrid_server_lifespan_prewarms_uca_singleton_in_dev_without_dead_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In dev posture, _gateway_lifespan pre-warms _get_uca_logger() and avoids dead app.state fields."""
    import src.gateway.governance.uca_logger as uca_mod
    from tests.test_hybrid_server import _make_hybrid_stubs

    monkeypatch.setenv("CAGE_ENV", "dev")
    monkeypatch.setenv("RECONCILIATION_PROVIDER", "stub")
    monkeypatch.setenv("CAGE_NORMATIVE_PROVIDER", "static")
    monkeypatch.setenv(
        "CAGE_TRUSTED_CLIENT_IDENTITIES",
        "advisor.cage.serviceaccount.identity.linkerd.cluster.local",
    )
    monkeypatch.setattr(uca_mod, "_uca_logger", None)

    stubs = _make_hybrid_stubs()
    stubs.pop("src.gateway.governance.uca_logger", None)
    stubs[
        "src.gateway.governance.kms_signer"
    ].KMSGovernanceSigner.from_env.side_effect = RuntimeError("no KMS in local dev")

    sys.modules.pop("src.gateway.server.hybrid_server", None)

    with patch.dict("sys.modules", stubs):
        from src.gateway.server.hybrid_server import _gateway_lifespan

        test_app = FastAPI()
        async with _gateway_lifespan(test_app):
            assert uca_mod._uca_logger is not None
            assert uca_mod._uca_logger._test_mode is True
            assert hasattr(test_app.state, "defer_queue")
            assert not hasattr(test_app.state, "token_quota_proxy")
            assert not hasattr(test_app.state, "uca_logger")


# ---------------------------------------------------------------------------
# 5. Compliance bridge CORS posture resolution (_resolve_cors_origins)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cage_env", ["prod", "production", "staging"])
def test_resolve_cors_origins_empty_in_enforcing_postures_when_unset(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """_resolve_cors_origins() returns [] across prod, production, and staging when ALLOWED_ORIGINS is unset."""
    from src.compliance_bridge.main import _resolve_cors_origins

    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("CAGE_ENV", cage_env)

    assert _resolve_cors_origins() == []


def test_resolve_cors_origins_returns_localhost_defaults_in_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_resolve_cors_origins() returns the 4 localhost dev origins when CAGE_ENV=dev and ALLOWED_ORIGINS is unset."""
    from src.compliance_bridge.main import _resolve_cors_origins

    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("CAGE_ENV", "dev")

    assert _resolve_cors_origins() == [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]


@pytest.mark.parametrize("cage_env", ["prod", "staging", "dev"])
def test_resolve_cors_origins_honors_explicit_allowed_origins(
    monkeypatch: pytest.MonkeyPatch,
    cage_env: str,
) -> None:
    """Explicit ALLOWED_ORIGINS is honored and stripped without empty entries in every posture."""
    from src.compliance_bridge.main import _resolve_cors_origins

    monkeypatch.setenv("CAGE_ENV", cage_env)
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        " https://console.example.com , https://audit.example.com , ",
    )

    assert _resolve_cors_origins() == [
        "https://console.example.com",
        "https://audit.example.com",
    ]


# ---------------------------------------------------------------------------
# 6. Non-vacuous corpus recognition floor
# ---------------------------------------------------------------------------


def test_empty_directory_fails_corpus_floor(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An empty --root directory recognizes 0 Python files and must fail closed."""
    empty_dir = tmp_path / "empty_src"
    empty_dir.mkdir()
    rc = check_posture_main(["--root", str(empty_dir)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "POSTURE GUARD CORPUS FLOOR FAILURE" in captured.out
    assert "scanned Python files 0 < minimum expected 1" in captured.out


def test_zero_recognized_guards_fails_when_minimum_corpus_required(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A corpus with Python files but 0 recognized guards fails when floor > 0."""
    blind_dir = tmp_path / "blind_src"
    blind_dir.mkdir()
    (blind_dir / "plain.py").write_text(
        "def add(x: int, y: int) -> int:\n    return x + y\n", encoding="utf-8"
    )

    rc = check_posture_main(
        [
            "--root",
            str(blind_dir),
            "--min-raising-targets",
            "1",
            "--min-broad-guards",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "recognized posture-raising targets 0 < minimum expected 1" in captured.out
    assert "recognized broad enforcing guards 0 < minimum expected 1" in captured.out
