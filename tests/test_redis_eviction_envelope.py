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
tests/test_redis_eviction_envelope.py — Redis noeviction invariant verification
================================================================================

Validates that the Redis evidence state store (db=1) enforces the
noeviction memory policy required by the Adaptive Gating Engine.

When a transaction's consensus score falls into the ambiguity band
(0.70 ≤ Score < 0.95), the deferred transaction token is parked in db=1.
If the cluster hits the maxmemory ceiling, Redis MUST fail-closed and
refuse new writes — never silently evict frozen execution states.

This test requires a live Redis instance (port-forwarded or local).
Run with:  pytest tests/test_redis_eviction_envelope.py --run-integration

Related:
  - deployment/k8s/redis-config.yaml (ConfigMap with noeviction policy)
  - deployment/k8s/redis-statefulset.yaml (Guaranteed QoS deployment)
  - src/compliance_bridge/evidence_stream.py (db=1 consumer)
"""

from __future__ import annotations

import json
import os

import pytest
import redis

# ---------------------------------------------------------------------------
# Redis topology notes
# ---------------------------------------------------------------------------
# GKE Managed Memorystore for Valkey:
#   - Does not support CONFIG GET / CONFIG SET when disabled or restricted
#   - Does not allow FLUSHDB / FLUSHALL rename tricks (standard Redis commands)
#   - Enforces persistence and replication at the managed-service level
#
# GKE self-managed Redis StatefulSet (redis-config.yaml):
#   - Supports all CONFIG GET assertions and command renames.

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Test 1: noeviction policy invariant
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_noeviction_invariant():
    """Redis MUST be configured with noeviction in every environment.

    Governance state must never be silently evicted; at the memory ceiling
    Redis refuses writes and the gateway fails closed.

    On managed Redis instances where CONFIG GET is not supported, the
    eviction policy is enforced at the infrastructure tier and this
    assertion is skipped.
    """
    client = _get_redis_client(db=1)
    expected_policy = "noeviction"

    try:
        max_memory_policy = client.config_get("maxmemory-policy")["maxmemory-policy"]
    except redis.exceptions.ResponseError as exc:
        pytest.skip(
            f"Redis CONFIG GET not supported on this instance (Managed Memorystore?): {exc}"
        )

    assert max_memory_policy == expected_policy, (
        f"CRITICAL: Redis db=1 maxmemory-policy is '{max_memory_policy}', "
        f"expected '{expected_policy}'."
    )


# ---------------------------------------------------------------------------
# Test 2: maxmemory ceiling is set
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_maxmemory_configured():
    """Redis MUST have a maxmemory ceiling to prevent unbounded growth.

    On Managed Memorystore where CONFIG GET is not supported, the
    memory ceiling is enforced at the managed-service tier and this
    assertion is skipped.
    """
    client = _get_redis_client(db=1)
    env = (os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT") or "dev").lower()
    expected_mb = (
        1024 * 1024 * 1024 if env in ("prod", "production") else 256 * 1024 * 1024
    )

    try:
        maxmemory = int(client.config_get("maxmemory")["maxmemory"])
    except redis.exceptions.ResponseError as exc:
        pytest.skip(
            f"Redis CONFIG GET not supported on this instance (Managed Memorystore?): {exc}"
        )

    assert maxmemory > 0, (
        "CRITICAL: Redis maxmemory is 0 (unlimited). The container will "
        "grow unbounded and trigger a kubelet OOM-kill."
    )

    assert maxmemory == expected_mb, (
        f"WARNING: Redis maxmemory is {maxmemory}, "
        f"expected {expected_mb} for {env} environment."
    )


# ---------------------------------------------------------------------------
# Test 3: db=1 write/read round-trip
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_db1_deferral_payload_roundtrip():
    """Deferred gating tokens can be written and read from db=1.

    Validates the exact payload shape used by evidence_stream.py
    and the Adaptive Gating Engine's DEFER path.
    """
    client = _get_redis_client(db=1)

    deferral_payload = {
        "action_token": "tok_verify_envelope_test",
        "consensus_score": 0.84,
        "status": "DEFERRED",
        "reason": "EXTERNAL_VALIDATION",
        "thread_id": "test-thread-eviction-envelope",
    }

    key = "cage:defer:tok_verify_envelope_test"
    try:
        # Write
        client.set(key, json.dumps(deferral_payload))

        # Read back
        stored = json.loads(client.get(key))
        assert stored["status"] == "DEFERRED"
        assert stored["consensus_score"] == 0.84
        assert stored["reason"] == "EXTERNAL_VALIDATION"
    finally:
        # Always clean up test keys
        client.delete(key)


# ---------------------------------------------------------------------------
# Test 4: dangerous commands are disabled
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.gke
def test_redis_dangerous_commands_disabled():
    """FLUSHDB and FLUSHALL MUST be disabled to prevent accidental data loss.

    The redis.conf renames these commands to empty strings, making them
    unavailable at runtime.

    GKE Managed Memorystore does not disable FLUSHDB at the command level —
    data-loss prevention is enforced via IAM roles on the Memorystore instance.
    This assertion only applies to the self-managed GKE StatefulSet where
    redis-config.yaml renames the command.
    """
    client = _get_redis_client(db=1)
    if getattr(client, "is_managed_memorystore", False):
        pytest.skip(
            "Managed Memorystore does not rename FLUSHDB — data-loss prevention "
            "is enforced via Memorystore IAM roles, not command renaming."
        )

    # FLUSHDB should raise an error (command renamed to "")
    with pytest.raises(redis.exceptions.ResponseError):
        client.flushdb()


# ---------------------------------------------------------------------------
# Test 5: AOF persistence enabled
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_aof_persistence_enabled():
    """AOF persistence MUST be enabled for write durability.

    Without AOF, a pod restart loses all deferred gating tokens.

    On Managed Memorystore, persistence and replication are enforced at the
    managed-service tier. This assertion is skipped on Managed Memorystore.
    """
    client = _get_redis_client(db=1)
    if getattr(client, "is_managed_memorystore", False):
        pytest.skip(
            "Managed Memorystore for Valkey enforces persistence and replication "
            "(WAIT 1 100) at the managed service tier rather than local AOF."
        )

    try:
        appendonly = client.config_get("appendonly")["appendonly"]
    except redis.exceptions.ResponseError as exc:
        pytest.skip(
            f"Redis CONFIG GET not supported on this instance (Managed Memorystore?): {exc}"
        )

    assert appendonly == "yes", (
        f"CRITICAL: Redis appendonly is '{appendonly}', expected 'yes'. "
        f"Deferred gating tokens will be lost on pod restart."
    )


# ---------------------------------------------------------------------------
# Test 6: db=0 and db=1 namespace isolation
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_db_namespace_isolation():
    """Keys written to db=1 are NOT visible in db=0.

    Validates that the LangGraph checkpoint namespace (db=0) and the
    evidence state store (db=1) are properly isolated.
    """
    db0 = _get_redis_client(db=0)
    db1 = _get_redis_client(db=1)

    test_key = "cage:isolation_test:eviction_envelope"
    try:
        db1.set(test_key, "db1_value")

        # db=0 should NOT see the key
        assert db0.get(test_key) is None, (
            "CRITICAL: db=0 can see keys from db=1. Namespace isolation broken."
        )

        # db=1 should see the key
        assert db1.get(test_key) == b"db1_value"
    finally:
        db1.delete(test_key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _GkeMemorystoreProxyClient:
    """Executes Redis operations against GKE Managed Memorystore PSC via deploy/gateway."""

    is_managed_memorystore = True

    def __init__(self, db: int = 1, namespace: str = "governance-stack") -> None:
        self._db = db
        self._namespace = namespace

    def _exec(self, op: str, *args: str) -> object:
        import subprocess

        payload = json.dumps({"db": self._db, "op": op, "args": list(args)})
        script = (
            "import asyncio, json, os, sys\n"
            "from src.gateway.infrastructure.redis_client import build_async_redis\n"
            "req = json.loads(sys.stdin.read())\n"
            "async def run():\n"
            "    h = os.environ['REDIS_HOST']\n"
            "    p = os.environ.get('REDIS_PORT', '6379')\n"
            "    r = build_async_redis(f'redis://{h}:{p}', db=req['db'])\n"
            "    try:\n"
            "        op = req['op']\n"
            "        a = req['args']\n"
            "        if op == 'config_get':\n"
            "            res = await r.config_get(a[0])\n"
            "        elif op == 'set':\n"
            "            res = await r.set(a[0], a[1])\n"
            "        elif op == 'get':\n"
            "            res = await r.get(a[0])\n"
            "        elif op == 'delete':\n"
            "            res = await r.delete(*a)\n"
            "        elif op == 'flushdb':\n"
            "            res = await r.flushdb()\n"
            "        print(json.dumps({'ok': True, 'res': res}))\n"
            "    except Exception as e:\n"
            "        print(json.dumps({'ok': False, 'err': str(e), 'type': type(e).__name__}))\n"
            "    finally:\n"
            "        await r.aclose()\n"
            "asyncio.run(run())\n"
        )
        proc = subprocess.run(
            [
                "kubectl",
                "exec",
                "-i",
                "-n",
                self._namespace,
                "deploy/gateway",
                "-c",
                "gateway",
                "--",
                "python3",
                "-c",
                script,
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise redis.exceptions.ConnectionError(
                proc.stderr.strip() or "kubectl exec gateway redis proxy failed"
            )
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        if not out.get("ok"):
            raise redis.exceptions.ResponseError(out.get("err", "Redis error"))
        return out.get("res")

    def config_get(self, pattern: str) -> dict[str, str]:
        res = self._exec("config_get", pattern)
        return res if isinstance(res, dict) else {}

    def set(self, key: str, value: str) -> object:
        return self._exec("set", key, value)

    def get(self, key: str) -> bytes | None:
        res = self._exec("get", key)
        if res is None:
            return None
        return res.encode("utf-8") if isinstance(res, str) else res

    def delete(self, *keys: str) -> object:
        return self._exec("delete", *keys)

    def flushdb(self) -> object:
        return self._exec("flushdb")


def _get_redis_client(db: int = 1) -> redis.Redis:
    """Build a Redis client for the specified DB.

    Connection parameters are sourced from the environment,
    matching the existing conftest.py conventions. Falls back to the
    in-cluster GKE Memorystore PSC proxy when localhost:6379 is not forwarded.
    """
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))
    redis_password = os.environ.get("REDIS_PASSWORD", "")

    client = redis.Redis(
        host=redis_host,
        port=redis_port,
        db=db,
        password=redis_password,
        socket_timeout=2,
        socket_connect_timeout=2,
        decode_responses=False,
    )
    try:
        client.ping()
        return client
    except redis.exceptions.ConnectionError:
        return _GkeMemorystoreProxyClient(db=db)  # type: ignore[return-value]
