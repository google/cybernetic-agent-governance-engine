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
F4 remediation test: Redis-backed fiscal reservation tokens.

Before fix: tokens stored in self._tokens = {} (in-memory dict)
  - Lost on restart
  - Not shared across replicas (cross-pod rollback silently no-ops)
  - Never evicted (unbounded growth)

After fix: tokens stored in Redis with TTL
  - Survive restart
  - Shared across replicas
  - Auto-expire after reservation_ttl
  - Missing token logs ERROR and fails closed
"""

import logging
import uuid

import pytest

from src.cage_finance.tiers.fiscal_tier import FiscalTierPlugin
from src.gateway.governance.safety.resource_guard import FiscalLimitGuard


@pytest.fixture
async def fiscal_tier_pair(cleanup_redis_client):
    """Two FiscalTierPlugin instances sharing the same Redis (simulates two pods)."""
    redis_client = cleanup_redis_client
    guard = FiscalLimitGuard(
        redis_client=redis_client,
        daily_cap_usd=100_000.0,
        reservation_ttl=300,
    )
    tier_a = FiscalTierPlugin(guard)
    tier_b = FiscalTierPlugin(guard)
    
    # Verify they share the same Redis client (cross-instance requirement)
    assert tier_a._redis is tier_b._redis
    
    return tier_a, tier_b


class TestFiscalTierRedisTokenStorage:
    """F4 fix: tokens are stored in Redis instead of in-memory dict."""

    @pytest.mark.asyncio
    async def test_cross_instance_rollback_succeeds(
        self, fiscal_tier_pair
    ):
        """Rollback on instance B succeeds for a token committed by instance A.

        F4 failure mode before fix: instance A stores token in self._tokens = {},
        instance B cannot see it, rollback silently no-ops.
        """
        tier_a, tier_b = fiscal_tier_pair
        transaction_id = str(uuid.uuid4())
        
        # Instance A commits a reservation
        params = {
            "amount": 1000.0,
            "agent_id": "agent_cross_test",
            "transaction_id": transaction_id,
        }
        violations = await tier_a.commit("execute_trade", params)
        assert violations == [], "Commit should succeed"
        
        # Instance B rolls back the same transaction
        # Before F4 fix: this would silently no-op (no token in B's _tokens dict)
        # After F4 fix: B retrieves the token from Redis and releases it
        await tier_b.rollback("execute_trade", params)
        
        # Verify the token was released: check that the fiscal counter decreased
        current_spend = await tier_a.guard.current_spend_usd()
        assert current_spend == 0.0, (
            f"Cross-instance rollback should release the reservation (got {current_spend})"
        )

    @pytest.mark.asyncio
    async def test_missing_token_logs_error_and_returns(
        self, fiscal_tier_pair, caplog
    ):
        """Rollback with no stored token logs ERROR and returns (fail-closed).

        F4 fix: missing token is logged loudly, never silently ignored.
        """
        tier_a, _tier_b = fiscal_tier_pair
        transaction_id = str(uuid.uuid4())
        
        # Attempt rollback for a transaction that was never committed
        params = {"transaction_id": transaction_id}
        
        with caplog.at_level(logging.ERROR):
            await tier_a.rollback("execute_trade", params)
        
        # Assert ERROR was logged
        assert any(
            "no reservation token found" in record.message.lower()
            and transaction_id in record.message
            for record in caplog.records
        ), "Missing token must log ERROR with transaction_id"
        
        # Verify rollback did not raise (fail-closed, not fail-open)
        # The method returns None; we're asserting it didn't raise an exception

    @pytest.mark.asyncio
    async def test_token_has_ttl_in_redis(self, fiscal_tier_pair, cleanup_redis_client):
        redis_client = cleanup_redis_client
        """Stored tokens have a TTL to prevent unbounded growth.

        F4 fix: tokens expire after reservation_ttl (default 300s).
        """
        tier_a, _tier_b = fiscal_tier_pair
        transaction_id = str(uuid.uuid4())
        
        params = {
            "amount": 500.0,
            "agent_id": "agent_ttl_test",
            "transaction_id": transaction_id,
        }
        await tier_a.commit("execute_trade", params)
        
        # Check the token key has a TTL
        key = f"fiscal:token:{transaction_id}"
        
        # Detect async vs sync client
        client_module = type(redis_client).__module__
        if "asyncio" in client_module or "aioredis" in client_module:
            ttl = await redis_client.ttl(key)
        else:
            import asyncio
            loop = asyncio.get_running_loop()
            ttl = await loop.run_in_executor(None, redis_client.ttl, key)
        
        assert ttl > 0, f"Token key {key} must have a TTL (got {ttl})"
        assert ttl <= 300, f"TTL should be <= reservation_ttl (got {ttl})"

    @pytest.mark.asyncio
    async def test_token_survives_tier_instance_restart(
        self, fiscal_tier_pair, cleanup_redis_client
    ):
        redis_client = cleanup_redis_client
        """Token persists in Redis when the tier instance is replaced (simulates restart).

        F4 failure mode before fix: tier restart loses all self._tokens entries.
        """
        tier_a, _tier_b = fiscal_tier_pair
        transaction_id = str(uuid.uuid4())
        
        params = {
            "amount": 2000.0,
            "agent_id": "agent_restart_test",
            "transaction_id": transaction_id,
        }
        await tier_a.commit("execute_trade", params)
        
        # Simulate restart: create a new FiscalTierPlugin instance
        guard_new = FiscalLimitGuard(
            redis_client=redis_client,
            daily_cap_usd=100_000.0,
            reservation_ttl=300,
        )
        tier_new = FiscalTierPlugin(guard_new)
        
        # The new instance should be able to retrieve the token and rollback
        await tier_new.rollback("execute_trade", params)
        
        # Verify the rollback succeeded
        current_spend = await tier_new.guard.current_spend_usd()
        assert current_spend == 0.0, (
            "Token should survive tier restart and be rollbackable"
        )
