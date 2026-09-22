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

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

BASE_COMMIT = "94e9d717be22bafcf6307efd9434fdb04754ac6a"
REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures/project"
ARTIFACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "artifacts/provider_06_agent_integrity_conformance_result.json"
)
PROSE_PATH = REPO_ROOT / "docs/partners/provider_06/CONFORMANCE_RESULT.md"
AGENT_INTEGRITY_ROOT = REPO_ROOT / "third_party/agent-integrity"
CLI_PATH = AGENT_INTEGRITY_ROOT / "packages/cli/dist/cli.js"
PROTECTED_PATHS = (
    "src/integrations/provider_06/adapter.py",
    "src/integrations/provider_06/mock_endpoint.py",
    "third_party/agent-integrity/schemas/integrity-envelope.schema.json",
    "third_party/agent-integrity/schemas/integrity-receipt.schema.json",
)

_MAX_OUTPUT_BYTES = 128 * 1024
_BUILD_TIMEOUT_SECONDS = 180
_VERIFY_TIMEOUT_SECONDS = 30
_GENERATOR_VERSION = 1
_BUILD_LOCK_PATH = (
    Path(tempfile.gettempdir()) / "cage-provider-06-agent-integrity-build.lock"
)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class VerificationResult:
    returncode: int
    stdout: dict[str, object]
    stderr: str


@dataclass(frozen=True)
class FixtureProject:
    project_root: Path
    policy_path: Path
    trusted_config_path: Path


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"required executable is unavailable: {name}")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str, cwd: Path = REPO_ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


@contextlib.contextmanager
def cross_process_lock(lock_path: Path, *, timeout_seconds: float) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"timed out waiting for build lock: {lock_path}")
                time.sleep(0.05)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def run_bounded_process(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    output_cap_bytes: int = _MAX_OUTPUT_BYTES,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> ProcessResult:
    process = subprocess.Popen(
        list(args),
        cwd=cwd,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    assert process.stdout is not None and process.stderr is not None
    if input_bytes is not None:
        assert process.stdin is not None
        process.stdin.write(input_bytes)
        process.stdin.close()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    failure: RuntimeError | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = RuntimeError(
                    f"process timed out after {timeout_seconds} seconds"
                )
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = selector.select(0)
                if not events:
                    break
            for key, _ in events:
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bucket = captured[key.data]
                bucket.extend(chunk)
                if len(bucket) > output_cap_bytes:
                    failure = RuntimeError(
                        f"Agent Integrity {key.data} exceeds {output_cap_bytes} bytes"
                    )
                    break
            if failure is not None:
                break
    finally:
        selector.close()
        if failure is not None or process.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    if failure is not None:
        raise failure
    return ProcessResult(
        process.returncode, bytes(captured["stdout"]), bytes(captured["stderr"])
    )


def _bounded_text(value: bytes, label: str) -> str:
    if len(value) > _MAX_OUTPUT_BYTES:
        raise RuntimeError(f"Agent Integrity {label} exceeds {_MAX_OUTPUT_BYTES} bytes")
    return value.decode("utf-8", errors="replace")


def _parse_one_object(raw: str) -> dict[str, object]:
    stripped = raw.lstrip()
    value, end = json.JSONDecoder().raw_decode(stripped)
    if stripped[end:].strip():
        raise RuntimeError("Agent Integrity stdout contains trailing content")
    if not isinstance(value, dict):
        raise RuntimeError("Agent Integrity stdout must contain one JSON object")
    return value


def ensure_agent_integrity_cli() -> None:
    with cross_process_lock(_BUILD_LOCK_PATH, timeout_seconds=_BUILD_TIMEOUT_SECONDS):
        node = _executable("node")
        npm = _executable("npm")
        version = (
            run_bounded_process(
                [node, "--version"], cwd=AGENT_INTEGRITY_ROOT, timeout_seconds=10
            )
            .stdout.decode("ascii")
            .strip()
        )
        try:
            major = int(version.removeprefix("v").split(".", maxsplit=1)[0])
        except (ValueError, IndexError) as error:
            raise RuntimeError(f"unrecognized Node.js version: {version}") from error
        if major < 22:
            raise RuntimeError(f"Node.js 22 or newer is required, found {version}")
        for args in ([npm, "ci", "--ignore-scripts"], [npm, "run", "build"]):
            completed = run_bounded_process(
                args,
                cwd=AGENT_INTEGRITY_ROOT,
                timeout_seconds=_BUILD_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                stderr = _bounded_text(completed.stderr, "build stderr")[-4000:]
                raise RuntimeError(f"Agent Integrity locked build failed: {stderr}")
        if not CLI_PATH.is_file():
            raise RuntimeError(
                "Agent Integrity CLI build did not produce packages/cli/dist/cli.js"
            )


def copy_fixture_project(tmp_path: Path) -> FixtureProject:
    project_root = tmp_path / "project"
    shutil.copytree(FIXTURE_ROOT, project_root)
    trusted_config_path = project_root / "integrity/trusted-config.json"
    config = json.loads(trusted_config_path.read_text(encoding="utf-8"))
    if config.get("projectRoot") != "__PROJECT_ROOT__":
        raise RuntimeError(
            "committed trusted config must contain the project-root placeholder"
        )
    config["projectRoot"] = str(project_root.resolve())
    trusted_config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return FixtureProject(
        project_root=project_root,
        policy_path=project_root / "integrity/policy.yaml",
        trusted_config_path=trusted_config_path,
    )


def run_agent_integrity_verify(
    fixture: FixtureProject,
    request: dict[str, object],
) -> VerificationResult:
    ensure_agent_integrity_cli()
    completed = run_bounded_process(
        [
            _executable("node"),
            str(CLI_PATH),
            "verify",
            "--trusted-policy",
            str(fixture.policy_path),
            "--trusted-config",
            str(fixture.trusted_config_path),
        ],
        input_bytes=json.dumps(
            request, separators=(",", ":"), ensure_ascii=False
        ).encode(),
        cwd=AGENT_INTEGRITY_ROOT,
        timeout_seconds=_VERIFY_TIMEOUT_SECONDS,
    )
    stdout = _bounded_text(completed.stdout, "stdout")
    stderr = _bounded_text(completed.stderr, "stderr")
    try:
        parsed = _parse_one_object(stdout)
    except (json.JSONDecodeError, RuntimeError) as error:
        raise RuntimeError(
            f"Agent Integrity returned invalid JSON: {error}; stderr={stderr[-2000:]}"
        ) from error
    return VerificationResult(completed.returncode, parsed, stderr[-4000:])


def _request(project: Path, name: str) -> dict[str, object]:
    return json.loads((project / name).read_text(encoding="utf-8"))


def _finding_codes(result: VerificationResult) -> list[str]:
    findings = result.stdout.get("findings", [])
    return [
        item["code"]
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    ]


def _observe(
    name: str, request_name: str, root: Path, mutation: str | None = None
) -> dict[str, object]:
    fixture = copy_fixture_project(root / name)
    request = _request(fixture.project_root, request_name)
    if mutation == "response":
        response = request["envelope"]["response"]  # type: ignore[index]
        response["content"] = f"{response['content']} Mutated."  # type: ignore[index]
    elif mutation == "source":
        (fixture.project_root / "docs/source.md").write_text(
            "mutated source bytes\n", encoding="utf-8"
        )
    elif mutation == "missing":
        (fixture.project_root / "docs/source.md").unlink()
    elif mutation == "config":
        config = json.loads(fixture.trusted_config_path.read_text(encoding="utf-8"))
        config["allowedRoots"] = ["not-docs"]
        fixture.trusted_config_path.write_text(json.dumps(config), encoding="utf-8")
    result = run_agent_integrity_verify(fixture, request)
    return {
        "exitCode": result.returncode,
        "status": result.stdout.get("status"),
        "findingCodes": _finding_codes(result),
    }


def generate_conformance_artifact(output_path: Path | None = None) -> dict[str, object]:
    ensure_agent_integrity_cli()
    expectations = (
        ("valid_fixture", "request-pass.json", None, 0, "PASS"),
        ("ambiguous_support", "request-review.json", None, 2, "REVIEW"),
        ("blocked_decision", "request-blocked.json", None, 3, "BLOCKED"),
        ("response_mutation", "request-pass.json", "response", 3, "BLOCKED"),
        ("source_mutation", "request-pass.json", "source", 3, "BLOCKED"),
        ("missing_source", "request-pass.json", "missing", 3, "BLOCKED"),
        ("invalid_trusted_config", "request-pass.json", "config", 3, "BLOCKED"),
    )
    with tempfile.TemporaryDirectory(prefix="provider-06-conformance-") as temp:
        root = Path(temp)
        scenarios = []
        for name, fixture_name, mutation, exit_code, status in expectations:
            actual = _observe(name, fixture_name, root, mutation)
            expected = {"exitCode": exit_code, "status": status}
            scenarios.append(
                {
                    "name": name,
                    "fixture": fixture_name
                    if mutation is None
                    else f"{fixture_name} with copied {mutation} mutation",
                    "expected": expected,
                    "actual": actual,
                    "passed": actual["exitCode"] == exit_code
                    and actual["status"] == status,
                }
            )
    agent_tree = _git("rev-parse", "HEAD:third_party/agent-integrity")
    protected = {path: _sha256(REPO_ROOT / path) for path in PROTECTED_PATHS}
    artifact: dict[str, object] = {
        "schemaVersion": 2,
        "experiment": "provider-06-agent-integrity-verification-conformance",
        "verdict": "PASS" if all(item["passed"] for item in scenarios) else "FAIL",
        "requiredScenariosPassed": sum(bool(item["passed"]) for item in scenarios),
        "requiredScenariosTotal": len(scenarios),
        "scenarios": scenarios,
        "protectedFiles": protected,
        "provenance": {
            "generatorVersion": _GENERATOR_VERSION,
            "cageBase": BASE_COMMIT,
            "cageEvidenceBinding": "fixed-base-plus-protected-file-sha256",
            "agentIntegrityTree": agent_tree,
            "agentIntegrityPackageLockSha256": _sha256(
                AGENT_INTEGRITY_ROOT / "package-lock.json"
            ),
            "agentIntegrityCliBuildSha256": _sha256(CLI_PATH),
        },
        "buildPolicy": {
            "installCommand": "npm ci --ignore-scripts",
            "buildCommand": "npm run build",
            "networkRequiredForCleanInstall": True,
            "lifecycleScriptsDisabled": True,
        },
    }
    if output_path is not None:
        output_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return artifact
