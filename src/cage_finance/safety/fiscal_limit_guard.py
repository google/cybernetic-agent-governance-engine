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

"""fiscal_limit_guard.py — Atomic Pre-Reservation of the Daily Fiscal Cap

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

Lifecycle of a reservation (ADR-009):

  1. ``reserve()`` — during the governor's committing run (the fiscal tier's
     ``commit()``).  Check-and-increment of the window counter and the entry
     in the pending set happen in one Lua script, so they are atomic.
  2. ``confirm(token)`` — after the sealed trade has executed
     (``SymbolicGovernor.settle(seal, executed=True)``).  The reservation
     leaves the pending set and counts for the rest of the window.
  3. ``release(token)`` — the trade did not execute, or the committing run
     was refused after this tier committed.  The reservation leaves the
     pending set and the counter is decremented.
  4. Expiry — a reservation still pending ``reservation_ttl`` seconds after
     ``reserve()`` was never settled (the process died between seal and
     actuation, or nothing actuated the seal).  ``reclaim_expired()`` moves
     it to the reclaimed set and decrements the counter.  It runs lazily at
     the start of ``reserve()``.  The read-only previews (``would_accept()``,
     ``headroom_usd()``) never write: they subtract expired reservations
     from the counter they read, so they agree with what ``reserve()`` will
     see after its reclaim.
     A ``confirm()`` that arrives after its reservation was reclaimed puts
     the amount back (uncapped, because the trade already happened) and
     logs a warning.

Each transition is exactly-once: a member leaves the pending set in only one
of confirm, release or reclaim, so a double settle or a settle racing the
reclaimer cannot count or refund the same reservation twice.

Redis key schema:
  fiscal:daily_limit:{YYYY-MM-DD}  → reserved + confirmed spend (int, cents)
  fiscal:pending                   → ZSET of open reservations, score = expiry epoch
  fiscal:reclaimed                 → ZSET of reclaimed reservations, score = reclaim epoch
"""

from __future__ import annotations

import asyncio
import functools
import logging
import math
import os
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_LAST_FISCAL_STORE_ERROR: ContextVar[str | None] = ContextVar(
    "_LAST_FISCAL_STORE_ERROR", default=None
)

PENDING_KEY = "fiscal:pending"
RECLAIMED_KEY = "fiscal:reclaimed"
_RECLAIM_BATCH = 100

_LUA_RESERVE = """
local amount = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current + amount > tonumber(ARGV[2]) then
  return -1
end
local total = redis.call('INCRBY', KEYS[1], amount)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
redis.call('ZADD', KEYS[2], ARGV[5], ARGV[4])
return total
"""

_LUA_RELEASE = """
if redis.call('ZREM', KEYS[2], ARGV[1]) == 0 then
  redis.call('ZREM', KEYS[3], ARGV[1])
  return -1
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
local total = redis.call('DECRBY', KEYS[1], tonumber(ARGV[2]))
if total < 0 then
  redis.call('SET', KEYS[1], 0, 'KEEPTTL')
  total = 0
end
return total
"""

_LUA_CONFIRM = """
if redis.call('ZREM', KEYS[2], ARGV[1]) == 1 then
  return 1
end
if redis.call('ZREM', KEYS[3], ARGV[1]) == 1 then
  if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('INCRBY', KEYS[1], tonumber(ARGV[2]))
  end
  return 2
end
return 0
"""

_LUA_RECLAIM = """
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, tonumber(ARGV[2]))
local reclaimed = 0
for _, member in ipairs(expired) do
  redis.call('ZREM', KEYS[1], member)
  redis.call('ZADD', KEYS[2], ARGV[1], member)
  local cents, window = string.match(member, '^[^|]+|(%d+)|(.+)$')
  if cents and redis.call('EXISTS', window) == 1 then
    local total = redis.call('DECRBY', window, tonumber(cents))
    if total < 0 then
      redis.call('SET', window, 0, 'KEEPTTL')
    end
  end
  reclaimed = reclaimed + 1
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[3])
return reclaimed
"""


@dataclass(frozen=True)
class ReservationToken:
    """Atomic fiscal limit reservation receipt."""

    reservation_id: str
    agent_id: str
    amount_usd: float
    amount_cents: int
    window_key: str
    cap_usd: float
    running_total_usd: float
    rejected: bool
    reserved_at: float
    ttl_seconds: int
    store_unavailable: bool = False
    store_error: str | None = None

    @property
    def member(self) -> str:
        """This reservation's entry in the pending / reclaimed sets."""
        return f"{self.reservation_id}|{self.amount_cents}|{self.window_key}"


class GovernanceLimitError(Exception):
    """Raised when a fiscal limit pre-reservation is rejected."""


class FiscalLimitGuard:
    """Atomic pre-reservation guard for the daily fiscal cap."""

    def __init__(
        self,
        redis_client: object,
        daily_cap_usd: float = 500_000.0,
        reservation_ttl: int = 300,
        window_seconds: int = 86_400,
    ) -> None:
        if (
            isinstance(daily_cap_usd, bool)
            or not isinstance(daily_cap_usd, (int, float))
            or not math.isfinite(daily_cap_usd)
            or daily_cap_usd <= 0.0
        ):
            raise ValueError(
                f"daily_cap_usd must be a finite positive number, got {daily_cap_usd!r}"
            )
        if (
            isinstance(reservation_ttl, bool)
            or not isinstance(reservation_ttl, int)
            or reservation_ttl <= 0
        ):
            raise ValueError("reservation_ttl must be positive")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")
        self._redis = redis_client
        self._daily_cap_usd = float(daily_cap_usd)
        self._reservation_ttl = reservation_ttl
        self._window_seconds = window_seconds

    @classmethod
    def from_env(
        cls,
        daily_cap_usd: float | None = None,
        reservation_ttl: int = 300,
    ) -> FiscalLimitGuard:
        """Construct from REDIS_URL environment variable using the pooled TLS/IAM builder."""
        from src.gateway.infrastructure.redis_client import build_async_redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        cap = (
            float(os.environ.get("FISCAL_DAILY_CAP_USD", "500000"))
            if daily_cap_usd is None
            else daily_cap_usd
        )
        client = build_async_redis(redis_url, socket_timeout=3.0)
        return cls(client, daily_cap_usd=cap, reservation_ttl=reservation_ttl)

    def _window_key(self) -> str:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        return f"fiscal:daily_limit:{day}"

    def _is_async_client(self) -> bool:
        """Return True if the Redis client is an async (redis.asyncio) client."""
        client_module = type(self._redis).__module__
        return "asyncio" in client_module or "aioredis" in client_module

    async def _eval(self, script: str, keys: list[str], args: list[object]) -> int:
        """Run a Lua script atomically on either client kind; return its integer result."""
        call = functools.partial(self._redis.eval, script, len(keys), *keys, *args)  # type: ignore[attr-defined]
        if self._is_async_client():
            result = await call()
        else:
            result = await asyncio.get_running_loop().run_in_executor(None, call)
        return int(result)

    async def _reclaim_quietly(self) -> None:
        """Reclaim expired reservations; a failure only leaves them counted (conservative)."""
        try:
            await self.reclaim_expired()
        except Exception as exc:
            logger.warning(
                "FiscalLimitGuard: reclaim failed; expired reservations stay counted: %s",
                exc,
            )

    async def reclaim_expired(self, now: float | None = None) -> int:
        """Release every reservation still pending past its TTL; return how many."""
        now = time.time() if now is None else now
        reclaimed = await self._eval(
            _LUA_RECLAIM,
            [PENDING_KEY, RECLAIMED_KEY],
            [now, _RECLAIM_BATCH, now - self._window_seconds],
        )
        if reclaimed:
            logger.warning(
                "FiscalLimitGuard: RECLAIMED %d unsettled reservation(s) past their %ds TTL",
                reclaimed,
                self._reservation_ttl,
            )
        return reclaimed

    async def reserve(
        self,
        agent_id: str,
        amount_usd: float | None = None,
        amount_minor: int | None = None,
    ) -> ReservationToken:
        """Atomically reserve a slice of the daily fiscal limit (fails closed)."""
        if amount_usd is None and amount_minor is None:
            raise ValueError("Must provide either amount_usd or amount_minor")

        if amount_usd is not None:
            if (
                isinstance(amount_usd, bool)
                or not isinstance(amount_usd, (int, float))
                or not math.isfinite(amount_usd)
            ):
                raise ValueError(
                    f"reserve: amount_usd must be a finite positive number, got {amount_usd!r}"
                )
            if amount_usd <= 0:
                raise ValueError(f"reserve: amount_usd must be > 0, got {amount_usd}")

        if amount_minor is not None:
            if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
                raise ValueError(
                    f"reserve: amount_minor must be an integer (not bool), got {type(amount_minor)}"
                )
            if amount_minor <= 0:
                raise ValueError(
                    f"reserve: amount_minor must be > 0, got {amount_minor}"
                )
            if amount_usd is not None and int(round(amount_usd * 100)) != amount_minor:
                raise ValueError(
                    f"reserve: conflicting amounts amount_usd={amount_usd!r} vs amount_minor={amount_minor!r}"
                )
            amount_cents = amount_minor
            resolved_usd = (
                float(amount_usd) if amount_usd is not None else amount_minor / 100.0
            )
        else:
            assert amount_usd is not None
            amount_cents = int(round(amount_usd * 100))
            if amount_cents <= 0:
                raise ValueError(
                    f"reserve: amount_usd must round to at least 1 cent (> 0), got {amount_usd!r}"
                )
            resolved_usd = float(amount_usd)

        cap_cents = int(round(self._daily_cap_usd * 100))
        window_key = self._window_key()
        reservation_id = str(uuid.uuid4())
        member = f"{reservation_id}|{amount_cents}|{window_key}"

        await self._reclaim_quietly()
        store_unavailable = False
        store_error: str | None = None
        try:
            result = await self._eval(
                _LUA_RESERVE,
                [window_key, PENDING_KEY],
                [
                    amount_cents,
                    cap_cents,
                    self._window_seconds,
                    member,
                    time.time() + self._reservation_ttl,
                ],
            )
        except Exception as exc:
            logger.error(
                "FiscalLimitGuard.reserve: Redis error agent=%s err=%s — failing closed.",
                agent_id,
                exc,
            )
            result = -2
            store_unavailable = True
            store_error = f"{type(exc).__name__}: {exc}"

        rejected = result < 0
        running_total_usd = (result / 100.0) if result >= 0 else self._daily_cap_usd

        token = ReservationToken(
            reservation_id=reservation_id,
            agent_id=agent_id,
            amount_usd=resolved_usd,
            amount_cents=amount_cents,
            reserved_at=datetime.now(timezone.utc).timestamp(),
            window_key=window_key,
            cap_usd=self._daily_cap_usd,
            running_total_usd=running_total_usd,
            rejected=rejected,
            ttl_seconds=self._reservation_ttl,
            store_unavailable=store_unavailable,
            store_error=store_error,
        )

        if rejected:
            logger.warning(
                "FiscalLimitGuard: REJECTED agent=%s amount=%.2f cap=%.2f result=%d",
                agent_id,
                resolved_usd,
                self._daily_cap_usd,
                result,
            )
        else:
            logger.info(
                "FiscalLimitGuard: RESERVED agent=%s amount=%.2f "
                "running_total=%.2f/%.2f id=%s ttl=%ds",
                agent_id,
                resolved_usd,
                running_total_usd,
                self._daily_cap_usd,
                reservation_id,
                self._reservation_ttl,
            )
        return token

    async def release(self, token: ReservationToken) -> float:
        """Release a pending reservation: the trade did not execute."""
        if token.rejected:
            return 0.0
        result = await self._eval(
            _LUA_RELEASE,
            [token.window_key, PENDING_KEY, RECLAIMED_KEY],
            [token.member, token.amount_cents],
        )
        if result < 0:
            logger.info(
                "FiscalLimitGuard: release no-op (already settled or reclaimed) id=%s",
                token.reservation_id,
            )
            return 0.0
        logger.info(
            "FiscalLimitGuard: RELEASED agent=%s amount=%.2f new_total=%.2f id=%s",
            token.agent_id,
            token.amount_usd,
            result / 100.0,
            token.reservation_id,
        )
        return result / 100.0

    async def confirm(self, token: ReservationToken) -> None:
        """Make a reservation permanent: the trade executed."""
        if token.rejected:
            return
        outcome = await self._eval(
            _LUA_CONFIRM,
            [token.window_key, PENDING_KEY, RECLAIMED_KEY],
            [token.member, token.amount_cents],
        )
        if outcome == 2:
            logger.warning(
                "FiscalLimitGuard: CONFIRMED after TTL reclaim; re-counted agent=%s "
                "amount=%.2f id=%s",
                token.agent_id,
                token.amount_usd,
                token.reservation_id,
            )
        elif outcome == 1:
            logger.info(
                "FiscalLimitGuard: CONFIRMED spend agent=%s amount=%.2f id=%s",
                token.agent_id,
                token.amount_usd,
                token.reservation_id,
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

    async def _call(self, method: str, *args: object) -> Any:
        """Run one Redis command on either client kind."""
        fn = getattr(self._redis, method)
        if self._is_async_client():
            return await fn(*args)
        return await asyncio.get_running_loop().run_in_executor(
            None, functools.partial(fn, *args)
        )

    @staticmethod
    def last_store_error() -> str | None:
        """Task-local Redis store error recorded by the most recent window read."""
        return _LAST_FISCAL_STORE_ERROR.get()

    async def _read_window_cents(self) -> int | None:
        """Today's spend in cents as ``reserve()`` would see it, or ``None`` if unreadable."""
        _LAST_FISCAL_STORE_ERROR.set(None)
        try:
            key = self._window_key()
            raw = await self._call("get", key)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            _LAST_FISCAL_STORE_ERROR.set(err)
            logger.error(
                "FiscalLimitGuard: window read failed — failing closed: %s", exc
            )
            return None
        try:
            current = int(raw) if raw else 0
            if current == 0:
                return 0
            try:
                expired = await self._call(
                    "zrangebyscore", PENDING_KEY, "-inf", time.time()
                )
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                _LAST_FISCAL_STORE_ERROR.set(err)
                logger.error(
                    "FiscalLimitGuard: pending-set read failed — failing closed: %s",
                    exc,
                )
                return None
            for member in expired or ():
                text = member.decode() if isinstance(member, bytes) else str(member)
                _, cents, window = text.split("|", 2)
                if window == key:
                    current -= int(cents)
            return max(0, current)
        except Exception as exc:
            logger.error(
                "FiscalLimitGuard: malformed window state — failing closed: %s", exc
            )
            return None

    async def check_acceptability(self, amount_usd: float) -> tuple[bool, str | None]:
        """Return ``(accepted, store_error)`` distinguishing Redis outages from cap breaches."""
        _LAST_FISCAL_STORE_ERROR.set(None)
        accepted = await self.would_accept(amount_usd=amount_usd)
        if accepted:
            return True, None
        return False, _LAST_FISCAL_STORE_ERROR.get()

    async def would_accept(self, amount_usd: float) -> bool:
        """Read-only: would ``reserve(amount_usd=...)`` be accepted right now?"""
        _LAST_FISCAL_STORE_ERROR.set(None)
        if (
            isinstance(amount_usd, bool)
            or not isinstance(amount_usd, (int, float))
            or not math.isfinite(amount_usd)
            or amount_usd <= 0
        ):
            return False
        amount_cents = int(round(amount_usd * 100))
        if amount_cents <= 0:
            return False
        current_cents = await self._read_window_cents()
        if current_cents is None:
            return False
        cap_cents = int(round(self._daily_cap_usd * 100))
        return current_cents + amount_cents <= cap_cents

    async def headroom_usd(self) -> float | None:
        """Read-only: the largest amount ``reserve()`` would accept right now."""
        current_cents = await self._read_window_cents()
        if current_cents is None:
            return None
        cap_cents = int(round(self._daily_cap_usd * 100))
        return max(0, cap_cents - current_cents) / 100.0

    async def remaining_usd(self) -> float:
        """Return remaining headroom in today's window."""
        return max(0.0, self._daily_cap_usd - await self.current_spend_usd())
