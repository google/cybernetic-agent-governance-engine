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
fiscal_limit_guard.py — Atomic Pre-Reservation of OPA Fiscal Limits

Solves the multi-agent "race to the rail" collision problem:

  Without this guard:
    Agent A reads remaining_limit = $200k → OPA: ALLOW → executes $200k
    Agent B reads remaining_limit = $200k → OPA: ALLOW → executes $200k
    Result: $400k spent against a $200k limit.

  With this guard:
    Agent A calls reserve($200k) → Redis ATOMIC: OK, remaining = $0
    Agent B calls reserve($200k) → Redis ATOMIC: REJECTED (would exceed cap)
    OPA only sees post-reservation balances — it is never the source of truth
    for concurrency control, only for policy semantics.

Architecture:
  1. Pre-OPA: Agent calls reserve_limit(agent_id, amount, window) atomically.
     Uses a Redis WATCH/MULTI/EXEC optimistic lock so check + increment are
     a single atomic pipeline — no interleaving possible.
     Returns a ReservationToken with a TTL.

  2. OPA evaluation runs against the post-reservation state (OPA's job is
     policy semantics, not concurrency control).

  3. On trade execution success: the Saga COMPLETED entry implicitly confirms
     the spend. The reservation is permanent until the daily window expires.

  4. On trade failure / Saga rollback: the Saga compensating node calls
     release(token) to atomically decrement the counter.

  5. Stale reservation expiry: if an agent crashes between reserve() and
     the API call (the ghost-state scenario), the window TTL ensures the
     reserved capacity is automatically reclaimed by Redis.

Redis key schema:
  fiscal:daily_limit:{window_key}  → current reserved spend (int, cents)

Atomicity:
  Uses Redis optimistic locking via WATCH/MULTI/EXEC pipeline.
  On concurrent write conflict the pipeline is retried up to _MAX_RETRIES
  times with exponential backoff before failing closed.

Usage:
  guard = FiscalLimitGuard.from_env()
  token = guard.reserve(agent_id="trading-agent", amount_usd=50_000.0)
  if token.rejected:
      raise GovernanceLimitError("Daily limit pre-reservation rejected")
  try:
      # ... call OPA, execute trade ...
      guard.confirm(token)
  except Exception:
      guard.release(token)  # Saga rollback path
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_MAX_RETRIES = 5      # WATCH/MULTI/EXEC retry limit on concurrent write conflict
_RETRY_BASE_MS = 5    # Base backoff in ms (exponential with jitter)


@dataclass
class ReservationToken:
    """Returned by FiscalLimitGuard.reserve().

    Attributes:
        reservation_id:    UUID — used to identify and release this reservation.
        agent_id:          The agent that made the reservation.
        amount_usd:        The USD amount reserved.
        amount_cents:      amount_usd * 100 as int (stored in Redis).
        window_key:        The Redis daily-window key (e.g. '2026-05-19').
        cap_usd:           The hard ceiling this reservation was checked against.
        running_total_usd: Post-reservation total across all agents in this window.
        rejected:          True if the reservation was denied (cap would be exceeded).
        reserved_at:       Unix timestamp of reservation.
        ttl_seconds:       Remaining TTL — reservation auto-releases after this.
    """

    reservation_id: str
    agent_id: str
    amount_usd: float
    amount_cents: int
    window_key: str
    cap_usd: float
    running_total_usd: float = 0.0
    rejected: bool = False
    reserved_at: float = field(default_factory=time.time)
    ttl_seconds: int = 300


class GovernanceLimitError(Exception):
    """Raised when a fiscal limit pre-reservation is rejected."""


class FiscalLimitGuard:
    """Atomic pre-reservation guard for OPA fiscal limits.

    Prevents multi-agent "race to the rail" by atomically reserving a slice
    of the daily fiscal limit in Redis *before* OPA evaluation.

    Each agent-thread must call reserve() → [OPA + API call] → confirm() or
    release().  If the agent crashes between reserve() and confirm(), the window
    TTL automatically reclaims the reservation.

    Atomicity is implemented via Redis WATCH/MULTI/EXEC optimistic locking —
    fully supported by both production Redis and fakeredis.aioredis in tests.

    Args:
        redis_client:     A ``redis.asyncio.Redis`` instance (async).
        daily_cap_usd:    Hard ceiling for all agents combined (default $500k).
        reservation_ttl:  Seconds before a stale reservation auto-expires (default 300s).
        window_seconds:   Window duration in seconds for the rolling counter (default 86400).
    """

    def __init__(
        self,
        redis_client: object,
        daily_cap_usd: float = 500_000.0,
        reservation_ttl: int = 300,
        window_seconds: int = 86_400,
    ) -> None:
        self._redis = redis_client
        self._daily_cap_usd = daily_cap_usd
        self._reservation_ttl = reservation_ttl
        self._window_seconds = window_seconds

    @classmethod
    def from_env(
        cls,
        daily_cap_usd: Optional[float] = None,
        reservation_ttl: int = 300,
    ) -> "FiscalLimitGuard":
        """Construct from REDIS_URL environment variable."""
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "redis-py is required for FiscalLimitGuard. "
                "Install with: pip install redis"
            ) from exc

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        cap = daily_cap_usd or float(
            os.environ.get("FISCAL_DAILY_CAP_USD", "500000")
        )
        client = aioredis.from_url(redis_url, decode_responses=True)
        return cls(client, daily_cap_usd=cap, reservation_ttl=reservation_ttl)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _window_key(self) -> str:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        return f"fiscal:daily_limit:{day}"

    def _is_async_client(self) -> bool:
        """Return True if the Redis client is an async (redis.asyncio) client."""
        # redis.asyncio clients have a coroutine-based execute_command; the sync
        # client's pipeline() returns a Pipeline whose watch() is a plain method.
        # The most reliable detection is checking the module path of the client.
        client_module = type(self._redis).__module__
        return "asyncio" in client_module

    def _sync_atomic_increment(self, key: str, amount_cents: int, cap_cents: int) -> int:
        """Sync WATCH/MULTI/EXEC increment — used when client is redis.Redis (sync)."""
        for attempt in range(_MAX_RETRIES):
            try:
                pipe = self._redis.pipeline(True)  # type: ignore[attr-defined]
                pipe.watch(key)
                current = int(pipe.get(key) or 0)
                if (current + amount_cents) > cap_cents:
                    pipe.reset()
                    return -1
                pipe.multi()
                pipe.incrby(key, amount_cents)
                pipe.expire(key, self._window_seconds)
                results = pipe.execute()
                return int(results[0])
            except Exception as exc:
                err_name = type(exc).__name__
                if "WatchError" in err_name and attempt < _MAX_RETRIES - 1:
                    backoff = (_RETRY_BASE_MS * (2 ** attempt) + random.randint(0, 5)) / 1000.0
                    import time as _time
                    _time.sleep(backoff)
                    continue
                logger.error(
                    "_atomic_increment: error on attempt %d key=%s err=%s",
                    attempt, key, exc,
                )
                return -2
        return -2

    def _sync_atomic_decrement(self, key: str, amount_cents: int) -> int:
        """Sync WATCH/MULTI/EXEC decrement — used when client is redis.Redis (sync)."""
        for attempt in range(_MAX_RETRIES):
            try:
                pipe = self._redis.pipeline(True)  # type: ignore[attr-defined]
                pipe.watch(key)
                current = int(pipe.get(key) or 0)
                new_val = max(0, current - amount_cents)
                pipe.multi()
                pipe.set(key, new_val)
                pipe.expire(key, self._window_seconds)
                pipe.execute()
                return new_val
            except Exception as exc:
                err_name = type(exc).__name__
                if "WatchError" in err_name and attempt < _MAX_RETRIES - 1:
                    backoff = (_RETRY_BASE_MS * (2 ** attempt) + random.randint(0, 5)) / 1000.0
                    import time as _time
                    _time.sleep(backoff)
                    continue
                logger.error(
                    "_atomic_decrement: error on attempt %d key=%s err=%s",
                    attempt, key, exc,
                )
                return -1
        return -1

    async def _atomic_increment(
        self, key: str, amount_cents: int, cap_cents: int
    ) -> int:
        """Atomically increment the spend counter if it stays within cap.

        Supports both sync (redis.Redis) and async (redis.asyncio.Redis) clients.
        When a sync client is detected the pipeline runs in a thread executor so
        the async caller is not blocked.

        Returns:
            New total (int, in cents) on success.
            -1 if cap would be exceeded.
            -2 if all retries failed due to contention (treated as fail-closed).
        """
        if not self._is_async_client():
            # Sync client — run blocking pipeline in a thread executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_atomic_increment, key, amount_cents, cap_cents
            )

        # Async client path (redis.asyncio)
        for attempt in range(_MAX_RETRIES):
            try:
                pipe = self._redis.pipeline(True)  # type: ignore[attr-defined]
                await pipe.watch(key)
                current = int(await pipe.get(key) or 0)
                if (current + amount_cents) > cap_cents:
                    await pipe.reset()
                    return -1
                pipe.multi()
                pipe.incrby(key, amount_cents)
                pipe.expire(key, self._window_seconds)
                results = await pipe.execute()
                return int(results[0])
            except Exception as exc:
                # WatchError or connection error — retry with backoff
                err_name = type(exc).__name__
                if "WatchError" in err_name and attempt < _MAX_RETRIES - 1:
                    backoff = (_RETRY_BASE_MS * (2 ** attempt) + random.randint(0, 5)) / 1000.0
                    await asyncio.sleep(backoff)
                    continue
                logger.error(
                    "_atomic_increment: error on attempt %d key=%s err=%s",
                    attempt, key, exc,
                )
                return -2  # fail-closed signal
        return -2

    async def _atomic_decrement(
        self, key: str, amount_cents: int
    ) -> int:
        """Atomically decrement the spend counter, flooring at 0.

        Supports both sync (redis.Redis) and async (redis.asyncio.Redis) clients.
        Returns new total in cents, or -1 on error.
        """
        if not self._is_async_client():
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._sync_atomic_decrement, key, amount_cents
            )

        # Async client path (redis.asyncio)
        for attempt in range(_MAX_RETRIES):
            try:
                pipe = self._redis.pipeline(True)  # type: ignore[attr-defined]
                await pipe.watch(key)
                current = int(await pipe.get(key) or 0)
                new_val = max(0, current - amount_cents)
                pipe.multi()
                pipe.set(key, new_val)
                pipe.expire(key, self._window_seconds)
                await pipe.execute()
                return new_val
            except Exception as exc:
                err_name = type(exc).__name__
                if "WatchError" in err_name and attempt < _MAX_RETRIES - 1:
                    backoff = (_RETRY_BASE_MS * (2 ** attempt) + random.randint(0, 5)) / 1000.0
                    await asyncio.sleep(backoff)
                    continue
                logger.error(
                    "_atomic_decrement: error on attempt %d key=%s err=%s",
                    attempt, key, exc,
                )
                return -1
        return -1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def reserve(
        self,
        agent_id: str,
        amount_usd: float,
    ) -> ReservationToken:
        """Atomically reserve a slice of the daily fiscal limit.

        Safe to call from multiple concurrent agent threads or processes.

        Args:
            agent_id:   Logical name of the requesting agent.
            amount_usd: USD amount to reserve (must be > 0).

        Returns:
            ReservationToken — always returns; check ``token.rejected``.
        """
        if amount_usd <= 0:
            raise ValueError(f"reserve: amount_usd must be > 0, got {amount_usd}")

        amount_cents = int(round(amount_usd * 100))
        cap_cents = int(round(self._daily_cap_usd * 100))
        window_key = self._window_key()
        reservation_id = str(uuid.uuid4())

        try:
            result = await self._atomic_increment(window_key, amount_cents, cap_cents)
        except Exception as exc:
            logger.error(
                "FiscalLimitGuard.reserve: unexpected error agent=%s err=%s — failing closed.",
                agent_id, exc,
            )
            result = -2


        # -1 = cap exceeded, -2 = Redis error (fail-closed)
        rejected = result < 0
        running_total_usd = (result / 100.0) if result >= 0 else self._daily_cap_usd

        token = ReservationToken(
            reservation_id=reservation_id,
            agent_id=agent_id,
            amount_usd=amount_usd,
            amount_cents=amount_cents,
            window_key=window_key,
            cap_usd=self._daily_cap_usd,
            running_total_usd=running_total_usd,
            rejected=rejected,
            ttl_seconds=self._reservation_ttl,
        )

        if rejected:
            logger.warning(
                "FiscalLimitGuard: REJECTED agent=%s amount=%.2f cap=%.2f result=%d",
                agent_id, amount_usd, self._daily_cap_usd, result,
            )
        else:
            logger.info(
                "FiscalLimitGuard: RESERVED agent=%s amount=%.2f "
                "running_total=%.2f/%.2f id=%s",
                agent_id, amount_usd, running_total_usd,
                self._daily_cap_usd, reservation_id,
            )
        return token

    async def release(self, token: ReservationToken) -> float:
        """Release a reservation — called by the Saga compensating node on rollback.

        Safe to call multiple times (idempotent via floor-at-zero).

        Returns the new running total in USD after release.
        """
        if token.rejected:
            return 0.0

        result = await self._atomic_decrement(token.window_key, token.amount_cents)
        new_total_usd = max(0.0, result / 100.0) if result >= 0 else 0.0
        logger.info(
            "FiscalLimitGuard: RELEASED agent=%s amount=%.2f "
            "new_total=%.2f id=%s",
            token.agent_id, token.amount_usd, new_total_usd, token.reservation_id,
        )
        return new_total_usd

    def confirm(self, token: ReservationToken) -> None:
        """Confirm that a reservation became a real spend (trade executed).

        Currently a semantic hook — the counter already reflects the spend.
        """
        if token.rejected:
            return
        logger.info(
            "FiscalLimitGuard: CONFIRMED spend agent=%s amount=%.2f id=%s",
            token.agent_id, token.amount_usd, token.reservation_id,
        )

    async def current_spend_usd(self) -> float:
        """Return the current reserved + confirmed spend for today's window."""
        try:
            key = self._window_key()
            if self._is_async_client():
                raw = await self._redis.get(key)  # type: ignore[attr-defined]
            else:
                loop = asyncio.get_event_loop()
                raw = await loop.run_in_executor(None, self._redis.get, key)  # type: ignore[attr-defined]
            return int(raw) / 100.0 if raw else 0.0
        except Exception as exc:
            logger.error("FiscalLimitGuard.current_spend_usd: Redis error: %s", exc)
            return 0.0

    async def remaining_usd(self) -> float:
        """Return remaining headroom in today's window."""
        return max(0.0, self._daily_cap_usd - await self.current_spend_usd())
