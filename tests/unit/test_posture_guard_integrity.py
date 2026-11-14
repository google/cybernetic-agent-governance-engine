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
    scan_tree_with_stats,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "src"


# ---------------------------------------------------------------------------
# 1. Repository-wide gate pass
# ---------------------------------------------------------------------------


def test_repo_src_has_zero_posture_guard_violations() -> None:
    """All files under src/ must pass Rule A, Rule B, and Rule C with non-vacuous middleware recognition."""
    violations, file_count, raising_count, broad_count, middleware_count = (
        scan_tree_with_stats(_SRC_ROOT)
    )
    assert violations == [], (
        "Posture guard integrity violations detected:\n"
        + "\n".join(f"  {v.format_line_span()}: {v.detail}" for v in violations)
    )
    assert file_count >= 100
    assert raising_count >= 10
    assert broad_count >= 5
    from scripts.check_posture_guard_integrity import MIN_EXPECTED_MIDDLEWARE_HANDLERS

    assert middleware_count >= MIN_EXPECTED_MIDDLEWARE_HANDLERS


def test_cli_main_exits_zero_on_repo() -> None:
    """CLI entrypoint returns exit code 0 with --verbose against src/."""
    rc = check_posture_main(["--verbose"])
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
    from src.compliance_bridge.audit_workflow import LANGFUSE_CREDENTIAL_ENV_VARS
    from src.compliance_bridge.kms_batch_signer import AsyncBatchSigner

    monkeypatch.setenv("CAGE_ENV", cage_env)
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "true")
    for var in LANGFUSE_CREDENTIAL_ENV_VARS:
        monkeypatch.setenv(var, f"synthetic-{var.lower()}")

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
            "--min-middleware-handlers",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "recognized posture-raising targets 0 < minimum expected 1" in captured.out
    assert "recognized broad enforcing guards 0 < minimum expected 1" in captured.out
    assert "recognized middleware handlers 0 < minimum expected 1" in captured.out


# ---------------------------------------------------------------------------
# 7. Synthetic AST fixtures — Rule B early-return & De Morgan negation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("guard_clause", "expected_kind"),
    [
        ('if env != "prod":\n        return', "early-exit guard"),
        ('if env not in ("prod", "production"):\n        return', "early-exit guard"),
        ('if not (env == "prod"):\n        return', "early-exit guard"),
        (
            "if posture != DeploymentPosture.PRODUCTION:\n        return",
            "early-exit guard",
        ),
        ('if env == "staging":\n        return', "early-exit guard"),
        ('if env in ("dev", "staging"):\n        return', "early-exit guard"),
        (
            'if env == "prod":\n        marker = 1\n    else:\n        return',
            "early-exit guard",
        ),
        ('if env != "prod" and flag:\n        return', "early-exit guard"),
        ('if env != "prod" or flag:\n        return', "early-exit guard"),
    ],
)
def test_rule_b_flags_early_return_and_negated_posture_narrowing(
    guard_clause: str,
    expected_kind: str,
) -> None:
    """Preceding non-raising early returns that skip staging narrow downstream guards to prod-only."""
    code = f"""
def assert_posture_ready():
    if is_enforcing():
        raise RuntimeError("not ready")

def boot(env: str, posture=None, flag: bool = True):
    {guard_clause}
    assert_posture_ready()
"""
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule B" in violations[0].rule
    assert expected_kind in violations[0].detail
    assert "assert_posture_ready()" in violations[0].target
    assert violations[0].line_number < violations[0].end_line_number


def test_rule_b_flags_loop_continue_and_ternary_narrowing() -> None:
    """`continue` guard clauses in loops and inline ternary expressions are flagged."""
    code = """
def assert_posture_ready():
    if is_enforcing():
        raise RuntimeError("not ready")

def boot_loop(envs: list[str]):
    for env in envs:
        if env != "prod":
            continue
        assert_posture_ready()

def boot_ternary(env: str):
    return assert_posture_ready() if env == "prod" else None
"""
    violations = scan_source(code)
    assert len(violations) == 2
    assert all("Rule B" in v.rule for v in violations)


def test_rule_b_allows_enforcing_early_returns_and_fail_closed_raises() -> None:
    """Early returns that retain staging or fail closed via raise are allowed."""
    code = """
def assert_posture_ready():
    if is_enforcing():
        raise RuntimeError("not ready")

def ok_not_enforcing():
    if not is_enforcing():
        return
    assert_posture_ready()

def ok_permissive_only(env: str):
    if env in ("dev", "test", "ci"):
        return
    assert_posture_ready()

def ok_de_morgan_admits_staging(env: str):
    if env != "prod" and env != "staging":
        return
    assert_posture_ready()

def ok_notin_enforcing_set(env: str):
    if env not in ("prod", "production", "staging"):
        return
    assert_posture_ready()

def ok_disjunction_admits_staging(env: str):
    if env == "prod" or env == "staging":
        assert_posture_ready()

def ok_fail_closed_raise(env: str):
    if env != "prod":
        raise RuntimeError("prod required")
    assert_posture_ready()
"""
    assert scan_source(code) == []


# ---------------------------------------------------------------------------
# 8. Synthetic AST fixtures — Rule C middleware bound-gated guard fallthrough
# ---------------------------------------------------------------------------

_MCP_QUARANTINE_MIDDLEWARE_HEADER = """
import collections
import json

_MAX_MCP_INSPECT_BYTES = 65536

async def check_and_refuse_quarantined_workload(scope, *, explicit_thread_id=None):
    return None

class McpQuarantineMiddleware:
    def __init__(self, inner_app):
        self.app = inner_app

    @staticmethod
    async def _send_json(send, status_code: int, payload: dict) -> None:
        await send({"type": "http.response.start", "status": status_code, "headers": []})
        await send({"type": "http.response.body", "body": json.dumps(payload).encode()})
"""


def test_rule_c_flags_asgi_middleware_size_cap_fallthrough_to_replay() -> None:
    """ASGI middleware skipping check_* above _MAX_MCP_INSPECT_BYTES and replaying to self.app is flagged."""
    code = (
        _MCP_QUARANTINE_MIDDLEWARE_HEADER
        + """
    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        buffered = collections.deque()
        raw_chunks = []
        total_bytes = 0
        complete = False
        while total_bytes <= _MAX_MCP_INSPECT_BYTES:
            msg = await receive()
            buffered.append(msg)
            chunk = msg.get("body", b"")
            if chunk:
                raw_chunks.append(chunk)
                total_bytes += len(chunk)
            if not msg.get("more_body", False):
                complete = True
                break

        if complete and raw_chunks and total_bytes <= _MAX_MCP_INSPECT_BYTES:
            refusal = await check_and_refuse_quarantined_workload(
                scope, explicit_thread_id="t-1"
            )
            if refusal is not None:
                await self._send_json(send, refusal[0], refusal[1])
                return

        async def _replay():
            return buffered.popleft() if buffered else await receive()

        await self.app(scope, _replay, send)
"""
    )
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule C" in violations[0].rule
    assert "check_and_refuse_quarantined_workload()" in violations[0].target
    assert "threshold condition" in violations[0].detail


def test_rule_c_flags_bounded_while_loop_evasion_without_413_rejection() -> None:
    """Removing `<=` from the `if` while keeping a bounded `while` loop without 413 rejection is still flagged."""
    code = (
        _MCP_QUARANTINE_MIDDLEWARE_HEADER
        + """
    async def __call__(self, scope, receive, send) -> None:
        buffered = collections.deque()
        raw_chunks = []
        total_bytes = 0
        complete = False
        while total_bytes <= _MAX_MCP_INSPECT_BYTES:
            msg = await receive()
            buffered.append(msg)
            chunk = msg.get("body", b"")
            if chunk:
                raw_chunks.append(chunk)
                total_bytes += len(chunk)
            if not msg.get("more_body", False):
                complete = True
                break

        if complete and raw_chunks:
            refusal = await check_and_refuse_quarantined_workload(
                scope, explicit_thread_id="t-1"
            )
            if refusal is not None:
                await self._send_json(send, refusal[0], refusal[1])
                return

        await self.app(scope, receive, send)
"""
    )
    violations = scan_source(code)
    assert len(violations) == 1
    assert "Rule C" in violations[0].rule
    assert "bounded while-loop" in violations[0].detail


def test_rule_c_flags_http_middleware_early_dispatch_on_size_threshold() -> None:
    """BaseHTTPMiddleware.dispatch and @app.middleware bypassing guards via early call_next on size > MAX are flagged."""
    code = """
class PayloadGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if int(request.headers.get("content-length", "0")) > 65536:
            return await call_next(request)
        verify_request_signature(request)
        return await call_next(request)

@app.middleware("http")
async def inline_guard_mw(request, call_next):
    if len(request.scope.get("raw_path", b"")) <= 256:
        enforce_path_policy(request)
    return await call_next(request)
"""
    violations = scan_source(code)
    assert len(violations) == 2
    assert all("Rule C" in v.rule for v in violations)
    assert {v.target for v in violations} == {
        "verify_request_signature()",
        "enforce_path_policy()",
    }


@pytest.mark.parametrize(
    "remediated_body",
    [
        # Variant 1: 413 early return inside unbounded while loop
        """
    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        buffered = collections.deque()
        raw_chunks = []
        total_bytes = 0
        complete = False
        while True:
            msg = await receive()
            buffered.append(msg)
            chunk = msg.get("body", b"")
            if chunk:
                raw_chunks.append(chunk)
                total_bytes += len(chunk)
                if total_bytes > _MAX_MCP_INSPECT_BYTES:
                    await self._send_json(send, 413, {"error": "payload_too_large"})
                    return
            if not msg.get("more_body", False):
                complete = True
                break

        if complete and raw_chunks:
            refusal = await check_and_refuse_quarantined_workload(scope, explicit_thread_id="t-1")
            if refusal is not None:
                await self._send_json(send, refusal[0], refusal[1])
                return

        await self.app(scope, receive, send)
""",
        # Variant 2: Post-loop explicit `if total_bytes > _MAX_MCP_INSPECT_BYTES: return 413`
        """
    async def __call__(self, scope, receive, send) -> None:
        raw_chunks = []
        total_bytes = 0
        complete = False
        while total_bytes <= _MAX_MCP_INSPECT_BYTES:
            msg = await receive()
            chunk = msg.get("body", b"")
            if chunk:
                raw_chunks.append(chunk)
                total_bytes += len(chunk)
            if not msg.get("more_body", False):
                complete = True
                break
        if total_bytes > _MAX_MCP_INSPECT_BYTES:
            await self._send_json(send, 413, {"error": "payload_too_large"})
            return
        if complete and raw_chunks and total_bytes <= _MAX_MCP_INSPECT_BYTES:
            refusal = await check_and_refuse_quarantined_workload(scope, explicit_thread_id="t-1")
            if refusal is not None:
                await self._send_json(send, refusal[0], refusal[1])
                return
        await self.app(scope, receive, send)
""",
        # Variant 3: Else-branch returning 413 on threshold `if`
        """
    async def __call__(self, scope, receive, send) -> None:
        raw_chunks = [b"{}"]
        total_bytes = 2
        if total_bytes <= _MAX_MCP_INSPECT_BYTES:
            refusal = await check_and_refuse_quarantined_workload(scope, explicit_thread_id="t-1")
            if refusal is not None:
                await self._send_json(send, refusal[0], refusal[1])
                return
        else:
            await self._send_json(send, 413, {"error": "payload_too_large"})
            return
        await self.app(scope, receive, send)
""",
    ],
)
def test_rule_c_allows_fail_closed_413_remediations(remediated_body: str) -> None:
    """Failing closed with 413 (without calling self.app) when exceeding _MAX_MCP_INSPECT_BYTES passes Rule C."""
    assert scan_source(_MCP_QUARANTINE_MIDDLEWARE_HEADER + remediated_body) == []
