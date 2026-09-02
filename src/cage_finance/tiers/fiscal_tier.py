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

import json
import logging
import uuid
from typing import Any

from src.cage_finance.tiers import _TRADE_ACTIONS
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation
from src.gateway.governance.safety.resource_guard import FiscalLimitGuard

logger = logging.getLogger(__name__)


class FiscalTierPlugin(GovernanceTierPlugin):
    """Fiscal guard tier (phase 2, order 4)."""

    def __init__(self, guard: FiscalLimitGuard):
        self.guard = guard
        # F4 fix: tokens now stored in Redis (shared across replicas) instead of
        # in-memory dict (lost on restart, not shared across pods).
        # The Redis client is reused from FiscalLimitGuard to avoid a second connection.
        self._redis = guard._redis
        self._reservation_ttl = guard._reservation_ttl

    @property
    def tier_name(self) -> str:
        return "fiscal"

    @property
    def phase(self) -> int:
        return 2

    @property
    def order(self) -> int:
        return 4

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in _TRADE_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        # Phase 2 tiers only implement commit and rollback.
        return []

    def _token_key(self, transaction_id: str) -> str:
        """Redis key for a reservation token."""
        return f"fiscal:token:{transaction_id}"

    async def _store_token(self, transaction_id: str, token: Any) -> None:
        """Store reservation token in Redis with TTL."""
        key = self._token_key(transaction_id)
        # Serialize token to JSON (ReservationToken is a dataclass)
        import dataclasses
        token_dict = dataclasses.asdict(token)
        value = json.dumps(token_dict)
        
        try:
            # Use the same async/sync detection logic as FiscalLimitGuard
            if hasattr(self._redis, "set") and hasattr(self._redis.set, "__call__"):
                # Check if it's async by trying to detect asyncio client
                client_module = type(self._redis).__module__
                if "asyncio" in client_module or "aioredis" in client_module:
                    await self._redis.set(key, value, ex=self._reservation_ttl)
                else:
                    # Sync client — run in executor
                    import asyncio
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(
                        None, lambda: self._redis.set(key, value, ex=self._reservation_ttl)
                    )
        except Exception as exc:
            logger.error(
                "FiscalTierPlugin: failed to store token %s in Redis: %s — "
                "rollback will fail if this transaction is aborted.",
                transaction_id,
                exc,
            )

    async def _retrieve_token(self, transaction_id: str) -> Any | None:
        """Retrieve reservation token from Redis."""
        from src.gateway.governance.safety.resource_guard import ReservationToken
        
        key = self._token_key(transaction_id)
        
        try:
            # Detect async vs sync client
            client_module = type(self._redis).__module__
            if "asyncio" in client_module or "aioredis" in client_module:
                value = await self._redis.get(key)
            else:
                import asyncio
                loop = asyncio.get_running_loop()
                value = await loop.run_in_executor(None, self._redis.get, key)
            
            if value is None:
                return None
            
            # Deserialize from JSON
            token_dict = json.loads(value)
            return ReservationToken(**token_dict)
        except Exception as exc:
            logger.error(
                "FiscalTierPlugin: failed to retrieve token %s from Redis: %s",
                transaction_id,
                exc,
            )
            return None

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        amount = float(params.get("amount", 0.0))
        agent_id = params.get("agent_id") or params.get("trader_id") or "anonymous"
        transaction_id = params.get("transaction_id", str(uuid.uuid4()))

        token = await self.guard.reserve(agent_id=agent_id, amount_usd=amount)
        if token.rejected:
            return [
                Violation(
                    tier=self.tier_name,
                    code="FISCAL_LIMIT_EXCEEDED",
                    message=f"Daily fiscal limit exceeded for {agent_id}",
                    recoverable=True,
                )
            ]

        # F4 fix: store token in Redis instead of in-memory dict
        await self._store_token(transaction_id, token)
        
        # F3: confirm() is called at governance-approval time (commit phase), not
        # post-execution. The tier lifecycle has no post-execution hook, so this
        # represents "governance approved" rather than "trade executed". If the
        # system crashes between approval and execution, the reservation remains
        # counted (conservative fiscal limit enforcement).
        await self.guard.confirm(token)
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        transaction_id = params.get("transaction_id")
        
        # F4 fix: retrieve token from Redis instead of in-memory dict
        token = await self._retrieve_token(transaction_id)
        
        if token is None:
            # F4 fix: log loudly when rollback finds no token — silence is dangerous
            logger.error(
                "FiscalTierPlugin.rollback: no reservation token found for "
                "transaction_id=%s — rollback cannot release fiscal capacity. "
                "This may indicate a storage failure, cross-pod rollback before "
                "token replication, or a missing commit.",
                transaction_id,
            )
            return
        
        await self.guard.release(token)
