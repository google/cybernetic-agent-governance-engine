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

"""Unit tests for scripts/check_daemon_lifespans.py (AST Query #1)."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from scripts.check_daemon_lifespans import (
    audit_daemon_lifespans,
    classify_daemon_class,
    main,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _parse_first_class(source: str) -> ast.ClassDef:
    tree = ast.parse(textwrap.dedent(source))
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            return node
    raise AssertionError("No ClassDef found in snippet")


def _write_module(root: Path, rel_path: str, source: str) -> Path:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    return target


class TestClassifyDaemonClass:
    """Tests for structural daemon/background-loop AST classification."""

    def test_async_start_spawning_task_is_classified_as_daemon(self) -> None:
        cls_node = _parse_first_class(
            """
            class JwksSyncDaemon:
                def __init__(self) -> None:
                    self._sync_task = None
                    self._running = False

                async def start(self) -> None:
                    self._running = True
                    self._sync_task = asyncio.create_task(self._jwk_sync_loop())

                async def stop(self) -> None:
                    self._running = False

                async def _jwk_sync_loop(self) -> None:
                    while self._running:
                        await asyncio.sleep(60)
            """
        )
        is_daemon, entries = classify_daemon_class(cls_node)
        assert is_daemon is True
        assert entries == ("start",)

    def test_thread_spawning_start_is_classified_as_daemon(self) -> None:
        cls_node = _parse_first_class(
            """
            class RegistryPoller:
                def start(self) -> None:
                    self._thread = threading.Thread(target=self._poll, daemon=True)
                    self._thread.start()

                def stop(self) -> None:
                    self._running = False
            """
        )
        is_daemon, entries = classify_daemon_class(cls_node)
        assert is_daemon is True
        assert entries == ("start",)

    def test_run_forever_and_run_loop_with_wait_loops_are_daemons(self) -> None:
        forever_cls = _parse_first_class(
            """
            class CustodianLoop:
                async def run_forever(self) -> None:
                    while not self._stopping:
                        await asyncio.sleep(5.0)
            """
        )
        loop_cls = _parse_first_class(
            """
            class ReconcilerLoop:
                async def run_loop(self, stop_event) -> None:
                    while not stop_event.is_set():
                        await asyncio.wait_for(stop_event.wait(), timeout=1.0)
            """
        )
        assert classify_daemon_class(forever_cls) == (True, ("run_forever",))
        assert classify_daemon_class(loop_cls) == (True, ("run_loop",))

    def test_non_daemon_span_protocol_and_abstract_base_are_ignored(self) -> None:
        span_cls = _parse_first_class(
            """
            class TelemetrySpan:
                def start(self) -> float:
                    self._started_at = time.monotonic()
                    return self._started_at

                def stop(self) -> float:
                    return time.monotonic() - self._started_at
            """
        )
        proto_cls = _parse_first_class(
            """
            class LifecycleProtocol(Protocol):
                async def run_forever(self) -> None:
                    while True:
                        await asyncio.sleep(1.0)
            """
        )
        abc_cls = _parse_first_class(
            """
            class BaseWorker(ABC):
                @abstractmethod
                async def start(self) -> None:
                    raise NotImplementedError
            """
        )
        empty_forever_cls = _parse_first_class(
            """
            class OneShotRunner:
                def run_forever(self) -> int:
                    return 42
            """
        )
        assert classify_daemon_class(span_cls) == (False, ())
        assert classify_daemon_class(proto_cls) == (False, ())
        assert classify_daemon_class(abc_cls) == (False, ())
        assert classify_daemon_class(empty_forever_cls) == (False, ())


class TestAuditDaemonLifespans:
    """Tests for cross-module lifespan reachability and start-site resolution."""

    def test_wired_daemons_across_lifespan_main_factory_and_plugin_pass(
        self, tmp_path: Path
    ) -> None:
        src_dir = tmp_path / "src"
        _write_module(
            src_dir,
            "service/daemons.py",
            """
            import asyncio

            class BatchSignerDaemon:
                async def start(self) -> None:
                    self._task = asyncio.create_task(self._flush_loop())

                async def _flush_loop(self) -> None:
                    while True:
                        await asyncio.sleep(1.0)

            class VerifierDaemon:
                async def run_forever(self) -> None:
                    while True:
                        await asyncio.sleep(5.0)

            class ReconcileDaemon:
                async def run_loop(self) -> None:
                    while True:
                        await asyncio.sleep(10.0)

            class StreamSinkDaemon:
                async def start(self) -> None:
                    self._task = asyncio.create_task(self._drain_loop())

                async def _drain_loop(self) -> None:
                    while True:
                        await asyncio.sleep(1.0)

            _sink: StreamSinkDaemon | None = None

            def get_stream_sink() -> StreamSinkDaemon:
                global _sink
                if _sink is None:
                    _sink = StreamSinkDaemon()
                return _sink

            async def start_stream_sink() -> None:
                sink = get_stream_sink()
                await sink.start()
            """,
        )
        _write_module(
            src_dir,
            "service/plugin.py",
            """
            import asyncio

            class WorldRefresher:
                async def run_forever(self) -> None:
                    while True:
                        await asyncio.sleep(30.0)

            class DomainTier:
                def __init__(self) -> None:
                    self._refresher = WorldRefresher()

                @property
                def refresher(self) -> WorldRefresher:
                    return self._refresher

            class DomainPlugin:
                def contribute(self) -> object:
                    tier = DomainTier()
                    return tier.refresher.run_forever
            """,
        )
        _write_module(
            src_dir,
            "pkg/__init__.py",
            """
            from .worker import start_relative_worker

            async def startup() -> None:
                await start_relative_worker()
            """,
        )
        _write_module(
            src_dir,
            "pkg/worker.py",
            """
            import asyncio

            class RelativeWorkerDaemon:
                async def start(self) -> None:
                    self._task = asyncio.create_task(self._work_loop())

                async def _work_loop(self) -> None:
                    while True:
                        await asyncio.sleep(2.0)

            async def start_relative_worker() -> None:
                worker = RelativeWorkerDaemon()
                await worker.start()
            """,
        )
        _write_module(
            src_dir,
            "service/app.py",
            """
            import asyncio
            from contextlib import asynccontextmanager
            from src.service.daemons import (
                BatchSignerDaemon,
                ReconcileDaemon,
                VerifierDaemon,
                start_stream_sink,
            )

            @asynccontextmanager
            async def lifespan(app: object):
                signer = BatchSignerDaemon()
                await signer.start()
                await start_stream_sink()
                verifier = VerifierDaemon()
                task = asyncio.create_task(verifier.run_forever())
                yield
                task.cancel()

            async def _cli_runner() -> None:
                reconciler = ReconcileDaemon()
                await reconciler.run_loop()

            if __name__ == "__main__":
                asyncio.run(_cli_runner())
            """,
        )

        result = audit_daemon_lifespans(src_dir, repo_root=tmp_path)
        assert result.unstarted == ()
        assert {d.name for d in result.daemons} == {
            "BatchSignerDaemon",
            "ReconcileDaemon",
            "RelativeWorkerDaemon",
            "StreamSinkDaemon",
            "VerifierDaemon",
            "WorldRefresher",
        }
        assert main(["--src-dir", str(src_dir), "--verbose"]) == 0

    def test_unstarted_daemon_is_flagged_even_with_name_collision_and_dead_helper(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src_dir = tmp_path / "src"
        _write_module(
            src_dir,
            "adapters/orphan.py",
            """
            import asyncio
            from typing import TYPE_CHECKING

            if TYPE_CHECKING:
                class TypeCheckingOnlyDaemon:
                    async def start(self) -> None:
                        self._task = asyncio.create_task(self._loop())

            class OrphanJwksDaemon:
                def __init__(self) -> None:
                    self._sync_task = None
                    self._running = False

                async def start(self) -> None:
                    self._running = True
                    self._sync_task = asyncio.create_task(self._jwk_sync_loop())

                async def on_startup(self) -> None:
                    # Self-call inside the daemon class itself must NOT count as external wiring
                    await self.start()

                async def stop(self) -> None:
                    self._running = False

                async def _jwk_sync_loop(self) -> None:
                    while self._running:
                        await asyncio.sleep(60.0)

            async def dead_uncalled_helper() -> None:
                # Never called from any lifespan, contribute, or __main__ root
                daemon = OrphanJwksDaemon()
                await daemon.start()
            """,
        )
        _write_module(
            src_dir,
            "server/main.py",
            """
            import asyncio

            class LiveHeartbeatDaemon:
                async def start(self) -> None:
                    self._task = asyncio.create_task(self._beat_loop())

                async def _beat_loop(self) -> None:
                    while True:
                        await asyncio.sleep(5.0)

            class RequestTimerSpan:
                def start(self) -> None:
                    self.t0 = 1.0

                def stop(self) -> None:
                    self.t1 = 2.0

            async def lifespan(app: object) -> None:
                # Calling start() on LiveHeartbeatDaemon and RequestTimerSpan must NOT
                # mask OrphanJwksDaemon.start() being uncalled.
                span = RequestTimerSpan()
                span.start()
                live = LiveHeartbeatDaemon()
                await live.start()
            """,
        )

        result = audit_daemon_lifespans(src_dir, repo_root=tmp_path)
        assert {d.name for d in result.daemons} == {
            "LiveHeartbeatDaemon",
            "OrphanJwksDaemon",
        }
        assert [d.name for d in result.unstarted] == ["OrphanJwksDaemon"]
        assert result.wired_locations["LiveHeartbeatDaemon"] != ()
        assert result.wired_locations["OrphanJwksDaemon"] == ()

        exit_code = main(["--src-dir", str(src_dir), "--verbose"])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "[UNSTARTED] OrphanJwksDaemon" in captured.out
        assert "Daemon lifespan check FAILED" in captured.out

    def test_missing_src_dir_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = tmp_path / "does_not_exist"
        exit_code = main(["--src-dir", str(missing)])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "src directory not found" in captured.err

    def test_repository_src_wires_all_live_daemons_and_excludes_provider_02(
        self,
    ) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        result = audit_daemon_lifespans(repo_root / "src", repo_root=repo_root)
        discovered_names = {d.name for d in result.daemons}

        # F-110: Provider02AttestationProvider no longer carries dead daemon methods
        assert "Provider02AttestationProvider" not in discovered_names

        expected_wired = {
            "AgentRegistryDaemon",
            "AsyncBatchSigner",
            "CustodyVerifier",
            "EvidenceCustodian",
            "EvidenceStreamSink",
            "GroundTruthReconciler",
            "PromptRegistry",
            "WorldModelRefresher",
        }
        assert expected_wired.issubset(discovered_names)
        for daemon_name in expected_wired:
            assert result.wired_locations[daemon_name], (
                f"Expected live daemon {daemon_name} to resolve at least one start site"
            )

    def test_zero_recognized_daemons_or_empty_corpus_fails_closed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        empty_dir = tmp_path / "empty_src"
        empty_dir.mkdir()
        assert main(["--src-dir", str(empty_dir)]) == 1
        captured = capsys.readouterr()
        assert "vacuous/blind corpus floor not met" in captured.err
        assert "scanned Python files 0 < minimum expected 1" in captured.err

        plain_dir = tmp_path / "plain_src"
        _write_module(
            plain_dir,
            "service/plain.py",
            """
            class PlainHelper:
                def compute(self) -> int:
                    return 42
            """,
        )
        assert main(["--src-dir", str(plain_dir)]) == 1
        captured = capsys.readouterr()
        assert "recognized daemon classes 0 < minimum expected 1" in captured.err
