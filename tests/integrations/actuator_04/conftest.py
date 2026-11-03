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

"""Pytest fixtures and process supervisor for actuator_04 live loopback tests.

Spawns real compiled killswitch-server child processes over OS loopback TCP sockets.
Adheres strictly to the Zero-Mock Over-The-Wire Conformance Mandate in CAGE AGENTS.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any, AsyncGenerator, Generator

from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]


def get_free_port() -> int:
    """Acquire an ephemeral port safely from the OS TCP stack."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])


def resolve_killswitch_binary() -> Path:
    """Locate the compiled release binary for killswitch."""
    candidates = [
        Path(r"D:\harfile\killswitch\target\release\killswitch.exe"),
        Path(r"D:\harfile\killswitch\killswitch.exe"),
        Path(r"D:\harfile\killswitch\target\debug\killswitch.exe"),
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    raise FileNotFoundError(
        "Could not find compiled killswitch.exe binary. Run `cargo build --release --workspace` first!"
    )


def wait_for_health(base_url: str, timeout: float = 15.0) -> bool:
    """Poll the substrate readiness endpoint (GET /.well-known/jwks.json)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with httpx.Client(timeout=0.5) as client:
                resp = client.get(f"{base_url}/.well-known/jwks.json")
                if resp.status_code == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


class InMemoryEd25519Signer:
    """In-memory Ed25519 RawMessageSigner implementation for live over-the-wire tests."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._pub_raw = self._private_key.public_key().public_bytes_raw()
        self.key_id: str = hashlib.sha256(self._pub_raw).hexdigest()

    @property
    def is_kms_active(self) -> bool:
        return True

    @property
    def public_key_bytes(self) -> bytes:
        return self._pub_raw

    def sign_raw(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    async def sign_raw_async(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def to_jwk(self) -> dict[str, Any]:
        x_b64 = base64.urlsafe_b64encode(self._pub_raw).decode("ascii").rstrip("=")
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.key_id,
            "x": x_b64,
            "use": "sig",
            "alg": "EdDSA",
        }


@pytest.fixture(scope="module")
def killswitch_server_harness(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Spawn a real killswitch-server child process on an ephemeral loopback port."""
    tmp_path = tmp_path_factory.mktemp("ks_single")
    port = get_free_port()
    binary_path = resolve_killswitch_binary()

    # Create CAGE test signer and JWKS key manifest
    signer = InMemoryEd25519Signer()
    jwks_json = json.dumps({"keys": [signer.to_jwk()]})

    state_dir = tmp_path / "state"
    db_dir = tmp_path / "db"
    state_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["KILLSWITCH_PORT"] = str(port)
    env["KILLSWITCH_HOST"] = "127.0.0.1"
    env["KILLSWITCH_STATE_DIR"] = str(state_dir)
    env["KILLSWITCH_DATABASE_DIR"] = str(db_dir)
    env["CAGE_TRUSTED_JWKS_JSON"] = jwks_json
    env["KILLSWITCH_MASTER_TOKEN"] = "test_master_token_live_wire_00000000000000"
    env["KILLSWITCH_SELF_DIAGNOSTIC"] = "1"
    env["KILLSWITCH_NO_AUTO_ELEVATE"] = "1"
    env["KILLSWITCH_NO_BROWSER"] = "1"
    env["CARGO"] = "1"
    env["RUST_TEST_THREADS"] = "1"

    log_path = tmp_path / "server.log"
    log_file = open(log_path, "wb")

    cmd = [
        str(binary_path),
        "--daemon",
        "-H", "127.0.0.1",
        "-p", str(port),
        "--db-dir", str(db_dir),
    ]

    proc = subprocess.Popen(
        cmd,
        cwd=str(tmp_path),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    base_url = f"http://127.0.0.1:{port}"
    healthy = wait_for_health(base_url, timeout=15.0)

    if not healthy:
        proc.kill()
        log_file.close()
        logs = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        raise TimeoutError(f"Server at {base_url} failed readiness probe within 15s. Logs:\n{logs}")

    harness = {
        "proc": proc,
        "port": port,
        "base_url": base_url,
        "signer": signer,
        "kid": signer.key_id,
        "state_dir": state_dir,
        "db_dir": db_dir,
        "tmp_path": tmp_path,
        "log_path": log_path,
        "binary_path": binary_path,
    }

    yield harness

    # Teardown
    try:
        proc.terminate()
        proc.wait(timeout=3.0)
    except Exception:
        proc.kill()
    finally:
        log_file.close()


@pytest.fixture(scope="module")
def killswitch_cluster_harness(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Spawn 3 independent live killswitch-server child processes for cluster testing."""
    tmp_path = tmp_path_factory.mktemp("ks_cluster")
    binary_path = resolve_killswitch_binary()
    ports = [get_free_port(), get_free_port(), get_free_port()]

    # Ensure unique ports
    while len(set(ports)) < 3:
        ports = [get_free_port(), get_free_port(), get_free_port()]

    signer = InMemoryEd25519Signer()
    jwks_json = json.dumps({"keys": [signer.to_jwk()]})

    procs = []
    log_files = []
    nodes = {}

    for idx, port in enumerate(ports):
        node_id = f"node-{idx + 1}"
        node_dir = tmp_path / node_id
        state_dir = node_dir / "state"
        db_dir = node_dir / "db"
        state_dir.mkdir(parents=True, exist_ok=True)
        db_dir.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env["KILLSWITCH_PORT"] = str(port)
        env["KILLSWITCH_HOST"] = "127.0.0.1"
        env["KILLSWITCH_STATE_DIR"] = str(state_dir)
        env["KILLSWITCH_DATABASE_DIR"] = str(db_dir)
        env["CAGE_TRUSTED_JWKS_JSON"] = jwks_json
        env["KILLSWITCH_MASTER_TOKEN"] = f"test_cluster_token_node_{idx}_00000000000"
        env["KILLSWITCH_SELF_DIAGNOSTIC"] = "1"
        env["KILLSWITCH_NO_AUTO_ELEVATE"] = "1"
        env["KILLSWITCH_NO_BROWSER"] = "1"
        env["CARGO"] = "1"
        env["RUST_TEST_THREADS"] = "1"

        log_path = node_dir / "server.log"
        log_file = open(log_path, "wb")
        log_files.append(log_file)

        cmd = [
            str(binary_path),
            "--daemon",
            "-H", "127.0.0.1",
            "-p", str(port),
            "--db-dir", str(db_dir),
        ]

        proc = subprocess.Popen(
            cmd,
            cwd=str(node_dir),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        procs.append(proc)
        nodes[node_id] = f"http://127.0.0.1:{port}"

    # Wait for all nodes to become healthy
    for node_id, url in nodes.items():
        if not wait_for_health(url, timeout=15.0):
            for p in procs:
                p.kill()
            for lf in log_files:
                lf.close()
            raise TimeoutError(f"Cluster node {node_id} at {url} failed readiness probe.")

    cluster = {
        "ports": ports,
        "nodes": nodes,
        "signer": signer,
        "kid": signer.key_id,
        "procs": procs,
        "tmp_path": tmp_path,
    }

    yield cluster

    # Teardown all cluster nodes
    for proc in procs:
        try:
            proc.terminate()
            proc.wait(timeout=3.0)
        except Exception:
            proc.kill()

    for lf in log_files:
        try:
            lf.close()
        except Exception:
            pass
