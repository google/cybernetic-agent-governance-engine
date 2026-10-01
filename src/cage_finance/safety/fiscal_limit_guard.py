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

Known gap: a crash *after* the trade but *before* ``confirm()`` lets the
reservation expire, so that spend is under-counted for the rest of the
window.  Closing it needs the actuation receipt to drive the confirm; see
ADR-009.

Redis key schema:
  fiscal:daily_limit:{YYYY-MM-DD}  → reserved + confirmed spend (int, cents)
  fiscal:pending                   → ZSET of open reservations, score = expiry epoch
  fiscal:reclaimed                 → ZSET of reclaimed reservations, score = reclaim epoch

  A member is ``"{reservation_id}|{amount_cents}|{window_key}"``.  The
  reclaim script derives the window key from the member, so these keys must
  live on one Redis node (standalone or a single cluster hash slot).

Safety invariants:
  * Requested amounts are strictly positive and finite.
  * ``reserve()`` fails closed: any Redis error yields a rejected token.
  * The counter never goes below zero, and a release, reclaim or confirm
    never recreates an expired window.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import math
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

PENDING_KEY = "fiscal:pending"
RECLAIMED_KEY = "fiscal:reclaimed"
_RECLAIM_BATCH = 100  # reservations reclaimed per call; the rest wait for the next call

# KEYS: window, pending.  ARGV: amount_cents, cap_cents, window_seconds, member, expires_at.
# Returns the new window total in cents, or -1 if the cap would be exceeded.
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

# KEYS: window, pending, reclaimed.  ARGV: member, amount_cents.
# Returns the new window total in cents, or -1 if the reservation was not
# pending (already confirmed, released or reclaimed).
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

# KEYS: window, pending, reclaimed.  ARGV: member, amount_cents.
# Returns 1 (confirmed), 2 (was reclaimed: amount counted again), 0 (no-op).
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

# KEYS: pending, reclaimed.  ARGV: now, batch, reclaimed_cutoff.
# Returns the number of reservations reclaimed.
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
    """Atomic fiscal limit reservation receipt.

    Returned by FiscalLimitGuard.reserve() to attest that a slice of the daily
    fiscal limit has been atomically reserved in Redis. The token must be
    passed to confirm() or release() to finalize or cancel the reservation;
    otherwise it expires after ``ttl_seconds``.
    """

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

    @property
    def member(self) -> str:
        """This reservation's entry in the pending / reclaimed sets."""
        return f"{self.reservation_id}|{self.amount_cents}|{self.window_key}"


class GovernanceLimitError(Exception):
    """Raised when a fiscal limit pre-reservation is rejected."""


class FiscalLimitGuard:
    """Atomic pre-reservation guard for the daily fiscal cap.

    Prevents multi-agent "race to the rail" by atomically reserving a slice
    of the daily fiscal limit in Redis *before* the trade.  See the module
    docstring for the reserve → confirm | release | expire lifecycle.

    Works with both ``redis.asyncio.Redis`` and synchronous ``redis.Redis``
    clients (the latter is driven from the default executor).

    Args:
        redis_client:     A Redis client (async or sync).
        daily_cap_usd:    Hard ceiling for all agents combined (default $500k).
        reservation_ttl:  Seconds an unsettled reservation stays counted (default 300s).
        window_seconds:   Lifetime of a window counter key (default 86400).
    """

    def __init__(
        self,
        redis_client: object,
        daily_cap_usd: float = 500_000.0,
        reservation_ttl: int = 300,
        window_seconds: int = 86_400,
    ) -> None:
        if reservation_ttl <= 0:
            raise ValueError("reservation_ttl must be positive")
        self._redis = redis_client
        self._daily_cap_usd = daily_cap_usd
        self._reservation_ttl = reservation_ttl
        self._window_seconds = window_seconds

    @classmethod
    def from_env(
        cls,
        daily_cap_usd: float | None = None,
        reservation_ttl: int = 300,
    ) -> FiscalLimitGuard:
        """Construct from REDIS_URL environment variable."""
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "redis-py is required for FiscalLimitGuard. "
                "Install with: pip install redis"
            ) from exc

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        cap = daily_cap_usd or float(os.environ.get("FISCAL_DAILY_CAP_USD", "500000"))
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def reclaim_expired(self, now: float | None = None) -> int:
        """Release every reservation still pending past its TTL; return how many.

        These reservations were never settled: the process stopped between
        seal and actuation, or a sealed run was never actuated.  Raises on a
        Redis error.
        """
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

        if amount_minor is not None:
            if not isinstance(amount_minor, int):
                raise ValueError(
                    f"reserve: amount_minor must be an integer, got {type(amount_minor)}"
                )
            if amount_minor <= 0:
                raise ValueError(
                    f"reserve: amount_minor must be > 0, got {amount_minor}"
                )
            amount_cents = amount_minor
            if amount_usd is None:
                amount_usd = amount_minor / 100.0
        else:
            if not isinstance(amount_usd, (int, float)) or not math.isfinite(
                amount_usd
            ):  # type: ignore[arg-type]
                raise ValueError(
                    f"reserve: amount_usd must be a finite positive number, got {amount_usd!r}"
                )
            if amount_usd <= 0:  # type: ignore[operator]
                raise ValueError(f"reserve: amount_usd must be > 0, got {amount_usd}")
            amount_cents = int(round(amount_usd * 100))  # type: ignore[operator]
        cap_cents = int(round(self._daily_cap_usd * 100))
        window_key = self._window_key()
        reservation_id = str(uuid.uuid4())
        member = f"{reservation_id}|{amount_cents}|{window_key}"

        await self._reclaim_quietly()
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

        rejected = result < 0
        running_total_usd = (result / 100.0) if result >= 0 else self._daily_cap_usd

        token = ReservationToken(
            reservation_id=reservation_id,
            agent_id=agent_id,
            amount_usd=amount_usd,
            amount_cents=amount_cents,
            reserved_at=datetime.now(timezone.utc).timestamp(),
            window_key=window_key,
            cap_usd=self._daily_cap_usd,
            running_total_usd=running_total_usd,
            rejected=rejected,
            ttl_seconds=self._reservation_ttl,
        )

        if rejected:
            logger.warning(
                "FiscalLimitGuard: REJECTED agent=%s amount=%.2f cap=%.2f result=%d",
                agent_id,
                amount_usd,
                self._daily_cap_usd,
                result,
            )
        else:
            logger.info(
                "FiscalLimitGuard: RESERVED agent=%s amount=%.2f "
                "running_total=%.2f/%.2f id=%s ttl=%ds",
                agent_id,
                amount_usd,
                running_total_usd,
                self._daily_cap_usd,
                reservation_id,
                self._reservation_ttl,
            )
        return token

    async def release(self, token: ReservationToken) -> float:
        """Release a pending reservation: the trade did not execute.

        Returns the new window total in USD (``0.0`` when there was nothing
        to release).  Idempotent: a reservation already confirmed, released
        or reclaimed is left alone.  Raises on a Redis error; the
        reservation then stays pending and is reclaimed after its TTL.
        """
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
        """Make a reservation permanent: the trade executed.

        Idempotent.  If the reservation already expired and was reclaimed,
        its amount is counted again (uncapped: the money is spent) and a
        warning is logged.  Raises on a Redis error; the reservation then
        expires, under-counting this spend.
        """
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

    async def _call(self, method: str, *args: object) -> object:
        """Run one Redis command on either client kind."""
        fn = getattr(self._redis, method)
        if self._is_async_client():
            return await fn(*args)
        return await asyncio.get_running_loop().run_in_executor(None, functools.partial(fn, *args))

    async def _read_window_cents(self) -> int | None:
        """Today's spend in cents as ``reserve()`` would see it, or ``None`` if unreadable.

        Read-only.  Reserved + confirmed spend, minus reservations of this
        window that are past their TTL but not yet reclaimed: ``reserve()``
        reclaims those before it checks the cap, so a preview that counted
        them would refuse what the commit then admits.
        """
        try:
            key = self._window_key()
            raw = await self._call("get", key)
            current = int(raw) if raw else 0
            if current == 0:
                return 0
            expired = await self._call("zrangebyscore", PENDING_KEY, "-inf", time.time())
            for member in expired or ():
                text = member.decode() if isinstance(member, bytes) else str(member)
                _, cents, window = text.split("|", 2)
                if window == key:
                    current -= int(cents)
            return max(0, current)
        except Exception as exc:
            logger.error(
                "FiscalLimitGuard: window read failed — failing closed: %s", exc
            )
            return None

    async def would_accept(self, amount_usd: float) -> bool:
        """Read-only: would ``reserve(amount_usd=...)`` be accepted right now?"""
        if (
            not isinstance(amount_usd, (int, float))
            or not math.isfinite(amount_usd)
            or amount_usd <= 0
        ):
            return False
        current_cents = await self._read_window_cents()
        if current_cents is None:
            return False
        amount_cents = int(round(amount_usd * 100))
        cap_cents = int(round(self._daily_cap_usd * 100))
        return current_cents + amount_cents <= cap_cents

    async def headroom_usd(self) -> float | None:
        """Read-only: the largest amount ``reserve()`` would accept right now.

        ``None`` when the window cannot be read. Unlike :meth:`remaining_usd`
        this never reports the full cap on a Redis error, so it is safe to
        hand to a narrower as a bound. The value is a snapshot: a concurrent
        reservation can shrink it, which the committing re-run then catches.
        """
        current_cents = await self._read_window_cents()
        if current_cents is None:
            return None
        cap_cents = int(round(self._daily_cap_usd * 100))
        return max(0, cap_cents - current_cents) / 100.0

    async def remaining_usd(self) -> float:
        """Return remaining headroom in today's window."""
        return max(0.0, self._daily_cap_usd - await self.current_spend_usd())
