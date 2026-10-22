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

"""Unit and AST guard tests for the async governance signer seam (B2)."""

from __future__ import annotations

import ast
import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from src.gateway.governance import kms_signer as ks
from src.gateway.governance import routing_seal as rs
from src.gateway.governance.kms_signer import (
    BaseKMSProvider,
    BatchGovernanceSigner,
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.integrations.gcp.kms_provider import GCPKMSProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "src"

_FORBIDDEN_SYNC_SIGN_ATTRS = frozenset(
    {
        "sign",
        "sign_raw",
        "sign_jws",
        "sign_precomputed_digest",
        "sign_decision",
        "sign_batch",
    }
)


def _iter_production_python_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(_SRC_ROOT.rglob("*.py")):
        if "tests" in path.parts:
            continue
        files.append(path)
    return files


class _AsyncSignCallVisitor(ast.NodeVisitor):
    """Find sync signer method calls inside ``async def`` and unawaited ``generate_seal`` calls."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.sync_sign_violations: list[str] = []
        self.unawaited_seal_violations: list[str] = []
        self._in_async_fn: list[str] = []
        self._awaited_calls: set[int] = set()

    def visit_Await(self, node: ast.Await) -> Any:
        if isinstance(node.value, ast.Call):
            self._awaited_calls.add(id(node.value))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._in_async_fn.append(node.name)
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._in_async_fn.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        # Nested sync functions inside an async function (e.g. _invoke closure
        # passed to run_in_executor) do not execute on the event loop directly.
        saved = self._in_async_fn
        self._in_async_fn = []
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._in_async_fn = saved

    def visit_Call(self, node: ast.Call) -> Any:
        # 1. Check for sync .sign*() inside async def
        if self._in_async_fn and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in _FORBIDDEN_SYNC_SIGN_ATTRS:
                fn_name = self._in_async_fn[-1]
                self.sync_sign_violations.append(
                    f"{self.rel_path}:{node.lineno} async def {fn_name}() calls .{attr}()"
                )

        # 2. Check for any generate_seal(...) call that is not directly awaited
        is_generate_seal = (
            isinstance(node.func, ast.Name) and node.func.id == "generate_seal"
        ) or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "generate_seal"
        )
        if is_generate_seal and id(node) not in self._awaited_calls:
            self.unawaited_seal_violations.append(
                f"{self.rel_path}:{node.lineno} calls generate_seal() without await"
            )

        self.generic_visit(node)


def test_ast_no_sync_signing_in_async_and_all_generate_seal_awaited() -> None:
    """No async def in src/ calls sync .sign*() and every generate_seal() call is awaited."""
    sync_violations: list[str] = []
    seal_violations: list[str] = []

    for py_file in _iter_production_python_files():
        rel = str(py_file.relative_to(_REPO_ROOT))
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=rel)
        visitor = _AsyncSignCallVisitor(rel)
        visitor.visit(tree)
        sync_violations.extend(visitor.sync_sign_violations)
        seal_violations.extend(visitor.unawaited_seal_violations)

    assert not sync_violations, (
        "Found synchronous signer calls inside async functions in src/:\n"
        + "\n".join(sync_violations)
    )
    assert not seal_violations, (
        "Found unawaited generate_seal() calls in src/:\n" + "\n".join(seal_violations)
    )


class _RecordingProvider(BaseKMSProvider):
    """Provider double that records thread names, concurrency, and optional delay."""

    def __init__(self, delay_s: float = 0.0) -> None:
        self._inner = SoftwareEd25519Provider()
        self.delay_s = delay_s
        self.thread_names: list[str] = []
        self.thread_ids: list[int] = []
        self._lock = threading.Lock()
        self.in_flight = 0
        self.max_in_flight = 0

    @property
    def provider_name(self) -> str:
        return "HERMETIC_ED25519"

    @property
    def expects_raw_message(self) -> bool:
        return True

    @property
    def jose_alg(self) -> str:
        return "EdDSA"

    def _record_enter(self) -> None:
        t = threading.current_thread()
        with self._lock:
            self.thread_names.append(t.name)
            self.thread_ids.append(t.ident or -1)
            self.in_flight += 1
            if self.in_flight > self.max_in_flight:
                self.max_in_flight = self.in_flight

    def _record_exit(self) -> None:
        with self._lock:
            self.in_flight -= 1

    def sign_digest(self, digest: bytes) -> bytes:
        self._record_enter()
        try:
            if self.delay_s > 0:
                time.sleep(self.delay_s)
            return self._inner.sign_digest(digest)
        finally:
            self._record_exit()

    def sign_raw(self, message: bytes) -> bytes:
        self._record_enter()
        try:
            if self.delay_s > 0:
                time.sleep(self.delay_s)
            return self._inner.sign_raw(message)
        finally:
            self._record_exit()

    def get_public_key_pem(self) -> bytes:
        return self._inner.get_public_key_pem()


async def test_sign_async_executes_on_cage_kms_worker_thread() -> None:
    """Async signing dispatches blocking provider work off the event-loop thread."""
    provider = _RecordingProvider()
    signer = KMSGovernanceSigner(
        provider=provider,
        key_version_name="test-key-v1",
        public_key_pem=provider.get_public_key_pem(),
    )
    loop_thread_id = threading.get_ident()

    sig_hex = await signer.sign_async({"action": "execute_trade", "amount": 10})
    raw_sig = await signer.sign_raw_async(b"canonical-payload")
    jws_sig = await signer.sign_jws_async(b"jws-payload")

    assert isinstance(sig_hex, str) and len(sig_hex) > 0
    assert raw_sig
    assert isinstance(jws_sig, bytes) and len(jws_sig) > 0
    assert len(provider.thread_ids) == 3
    assert all(tid != loop_thread_id for tid in provider.thread_ids)
    assert all(name.startswith("cage-kms") for name in provider.thread_names)


async def test_kms_concurrency_semaphore_bounds_in_flight_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CAGE_KMS_MAX_CONCURRENCY caps concurrent in-flight provider signing calls."""
    monkeypatch.setenv("CAGE_KMS_MAX_CONCURRENCY", "2")
    ks._KMS_SEMAPHORES.clear()

    provider = _RecordingProvider(delay_s=0.06)
    signer = KMSGovernanceSigner(
        provider=provider,
        key_version_name="test-key-v1",
        public_key_pem=provider.get_public_key_pem(),
    )

    results = await asyncio.gather(
        *[signer.sign_raw_async(f"msg-{i}".encode()) for i in range(6)]
    )
    assert len(results) == 6
    assert provider.max_in_flight == 2


async def test_kms_sign_timeout_fails_closed_without_issuing_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CAGE_KMS_SIGN_TIMEOUT_SECONDS aborts hung KMS calls and mints no routing seal."""
    monkeypatch.setenv("CAGE_KMS_SIGN_TIMEOUT_SECONDS", "0.05")
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")

    provider = _RecordingProvider(delay_s=0.30)
    signer = KMSGovernanceSigner(
        provider=provider,
        key_version_name="test-key-v1",
        public_key_pem=provider.get_public_key_pem(),
    )
    monkeypatch.setattr(ks, "_signer", signer)

    with pytest.raises(TimeoutError):
        await rs.generate_seal(
            "execute_trade",
            {"symbol": "ACME", "amount": 100},
            record_hash="a" * 64,
        )


async def test_sync_sign_on_running_event_loop_raises_in_dev_and_logs_in_prod(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Calling sync .sign*() on a running event loop raises in dev/test and logs ERROR in prod."""
    provider = _RecordingProvider()
    signer = KMSGovernanceSigner(
        provider=provider,
        key_version_name="test-key-v1",
        public_key_pem=provider.get_public_key_pem(),
    )
    batch_signer = BatchGovernanceSigner(signer=signer)

    # Non-enforcing posture (development) -> raises RuntimeError
    monkeypatch.setenv("CAGE_ENV", "development")
    with pytest.raises(RuntimeError, match="sign_async"):
        signer.sign({"action": "read"})
    with pytest.raises(RuntimeError, match="sign_raw_async"):
        signer.sign_raw(b"msg")
    with pytest.raises(RuntimeError, match="sign_jws_async"):
        signer.sign_jws(b"msg")
    with pytest.raises(RuntimeError, match="sign_precomputed_digest_async"):
        signer.sign_precomputed_digest(b"0" * 32)
    with pytest.raises(RuntimeError, match="sign_decision_async"):
        signer.sign_decision({"action": "read", "decision": "ALLOW"})
    with pytest.raises(RuntimeError, match="sign_batch_async"):
        batch_signer.sign_batch([{"action": "read"}])

    # Enforcing posture (production) -> logs ERROR and does not raise from the loop guard
    monkeypatch.setenv("CAGE_ENV", "production")
    with caplog.at_level(logging.ERROR, logger="Gateway.Governance.KMSSigner"):
        ks._guard_no_running_loop("sign")
    assert any(
        "Synchronous sign() called from an active asyncio event loop" in rec.message
        for rec in caplog.records
    )


def test_gcp_kms_provider_forwards_configured_rpc_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GCPKMSProvider honours CAGE_KMS_RPC_TIMEOUT_SECONDS on asymmetric_sign."""
    monkeypatch.setenv("CAGE_KMS_RPC_TIMEOUT_SECONDS", "3.25")
    captured_kwargs: dict[str, Any] = {}

    class _ClientDouble:
        def get_crypto_key_version(self, *, name: str) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(
                algorithm=SimpleNamespace(name="EC_SIGN_P256_SHA256")
            )

        def asymmetric_sign(self, *, request: Any, timeout: float = 0.0) -> Any:
            from types import SimpleNamespace

            captured_kwargs["timeout"] = timeout
            return SimpleNamespace(signature=b"der-sig")

    provider = GCPKMSProvider(
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        kms_client=_ClientDouble(),
    )
    sig = provider.sign_digest(b"0" * 32)
    assert sig == b"der-sig"
    assert captured_kwargs["timeout"] == 3.25
