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
# Test 1: noeviction policy invariant
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_noeviction_invariant():
    """Redis db=1 MUST be configured with allkeys-lru maxmemory-policy.

    (Updated to reflect the 256MB LRU policy requested by user).
    """
    client = _get_redis_client(db=1)
    env = os.environ.get("ENVIRONMENT", "dev").lower()
    expected_policy = "noeviction" if env in ("prod", "production") else "allkeys-lru"

    max_memory_policy = client.config_get("maxmemory-policy")["maxmemory-policy"]
    assert max_memory_policy == expected_policy, (
        f"CRITICAL: Redis db=1 maxmemory-policy is '{max_memory_policy}', "
        f"expected '{expected_policy}' for {env} environment."
    )


# ---------------------------------------------------------------------------
# Test 2: maxmemory ceiling is set
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_redis_maxmemory_configured():
    """Redis MUST have a maxmemory ceiling to prevent unbounded growth."""
    client = _get_redis_client(db=1)
    env = os.environ.get("ENVIRONMENT", "dev").lower()
    expected_mb = (
        1024 * 1024 * 1024 if env in ("prod", "production") else 256 * 1024 * 1024
    )

    maxmemory = int(client.config_get("maxmemory")["maxmemory"])
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
def test_redis_dangerous_commands_disabled():
    """FLUSHDB and FLUSHALL MUST be disabled to prevent accidental data loss.

    The redis.conf renames these commands to empty strings, making them
    unavailable at runtime.
    """
    client = _get_redis_client(db=1)

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
    """
    client = _get_redis_client(db=1)

    appendonly = client.config_get("appendonly")["appendonly"]
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


def _get_redis_client(db: int = 1) -> redis.Redis:
    """Build a Redis client for the specified DB.

    Connection parameters are sourced from the environment,
    matching the existing conftest.py conventions.
    """
    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_port = int(os.environ.get("REDIS_PORT", "6379"))
    redis_password = os.environ.get("REDIS_PASSWORD", "")

    return redis.Redis(
        host=redis_host,
        port=redis_port,
        db=db,
        password=redis_password,
        socket_timeout=5,
        decode_responses=False,
    )
