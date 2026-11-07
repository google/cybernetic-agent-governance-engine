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
token_quota_proxy.py — Stateful Per-Session Token Quota Circuit Breaker
========================================================================
Implements ISO 42001 Annex A.4 (Resource Management).

Enforces hard per-session token and step-count quotas on every call to
external foundational models.  Backed by Redis atomic Lua counters, it
blocks execution and forces safe rollback when:

  - ``sequence_step_count > step_quota_max`` (default: 12), OR
  - ``accumulated_tokens > token_quota_max`` (default: 100,000)

Security posture: FAIL-CLOSED.
  - Redis unavailable → request BLOCKED (QuotaExceededError raised).
  - This mirrors the fail-closed security posture of domain resource guards.

Atomicity:
  All counter mutations use a single Redis Lua script via EVALSHA.
  This eliminates the parallel-branch over-allocation race that bare
  INCRBY + Python check would create.

Two-phase commit:
  1. check_and_increment() reserves max_tokens before the vLLM call.
  2. reconcile_actual_tokens() corrects over-allocation after vLLM responds.

Rollback:
  rollback_step() decrements counters when NeMo/OPA/vLLM fails after
  quota was reserved.

Redis key schema:
  quota:session:{agent_uuid}:steps   — INCR / DECR, TTL=session_ttl
  quota:session:{agent_uuid}:tokens  — INCRBY / DECRBY, TTL=session_ttl
  quota:session:{agent_uuid}:meta    — HSET metadata, TTL=session_ttl

Usage::

    proxy = TokenQuotaProxy.from_env()
    result = await proxy.check_and_increment(agent_id="agent-uuid", token_delta=1024)
    if not result.allowed:
        raise QuotaExceededError(...)
    try:
        # ... call vLLM ...
        await proxy.reconcile_actual_tokens(agent_id, reserved=1024, actual=876)
    except Exception:
        await proxy.rollback_step(agent_id, reserved_tokens=1024)
        raise
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("Gateway.Governance.TokenQuotaProxy")

# ---------------------------------------------------------------------------
# Lua scripts — loaded via SCRIPT LOAD at proxy init; called via EVALSHA.
# Using Lua ensures check + increment is a single atomic Redis operation.
# ---------------------------------------------------------------------------

# H-10: All quota mutations use atomic Lua scripts via EVALSHA.
# This eliminates the GET-then-SET race condition where concurrent requests
# could each read the same counter value below the limit and all proceed,
# collectively exceeding the quota.  A single Lua script executes atomically
# on the Redis server — no other command can interleave between the check
# and the increment.

# check_and_increment: atomically increment step and token counters.
# Returns {allowed, steps, tokens, reason, quota_status} as a 5-element list.
_LUA_CHECK_AND_INCREMENT = """
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- ARGV[1] = step_quota_max, ARGV[2] = token_quota_max
-- ARGV[3] = token_delta, ARGV[4] = ttl_seconds
-- ARGV[5] = soft_cap_tokens (optional)
-- ARGV[6] = burst_max_tokens (optional)
-- ARGV[7] = allow_burst (0 or 1, optional)
local steps  = redis.call('INCR', KEYS[1])
local tokens = redis.call('INCRBY', KEYS[2], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])

local step_max = tonumber(ARGV[1])
local token_max = tonumber(ARGV[2])
local delta = tonumber(ARGV[3])
local soft_cap = (ARGV[5] and ARGV[5] ~= '') and tonumber(ARGV[5]) or token_max
local burst_max = (ARGV[6] and ARGV[6] ~= '') and tonumber(ARGV[6]) or token_max
local allow_burst = (ARGV[7] and ARGV[7] ~= '') and tonumber(ARGV[7]) or 0

if steps > step_max then
    redis.call('DECR', KEYS[1])
    redis.call('DECRBY', KEYS[2], delta)
    return {0, steps - 1, tokens - delta, 'step_count', 'EXHAUSTED'}
end

if tokens > token_max then
    if allow_burst == 1 and tokens <= burst_max then
        return {1, steps, tokens, '', 'BURST_ACTIVE'}
    else
        redis.call('DECR', KEYS[1])
        redis.call('DECRBY', KEYS[2], delta)
        return {0, steps - 1, tokens - delta, 'token_count', 'EXHAUSTED'}
    end
end

if tokens >= soft_cap then
    return {1, steps, tokens, '', 'SOFT_CAP_REACHED'}
end

return {1, steps, tokens, '', 'NORMAL'}
"""

# rollback: atomically decrement both counters after a downstream failure.
_LUA_ROLLBACK = """
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- ARGV[1] = reserved_tokens
redis.call('DECR', KEYS[1])
redis.call('DECRBY', KEYS[2], ARGV[1])
return 1
"""

# reconcile: adjust token counter by (actual - reserved) after vLLM responds.
_LUA_RECONCILE = """
-- KEYS[1] = tokens_key
-- ARGV[1] = reserved_tokens, ARGV[2] = actual_tokens_used
local delta = tonumber(ARGV[2]) - tonumber(ARGV[1])
if delta ~= 0 then
    redis.call('INCRBY', KEYS[1], delta)
end
return 1
"""


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class QuotaExceededError(Exception):
    """Raised when a session exceeds its token or step-count quota.

    Attributes:
        agent_id:      The agent UUID session that was blocked.
        reason:        Human-readable reason: "step_count" or "token_count".
        current_value: The counter value that triggered the block.
        quota_max:     The configured hard limit.
        session_key:   The Redis key prefix for this session.
    """

    def __init__(
        self,
        agent_id: str,
        reason: str,
        current_value: int,
        quota_max: int,
        session_key: str,
    ) -> None:
        self.agent_id = agent_id
        self.reason = reason
        self.current_value = current_value
        self.quota_max = quota_max
        self.session_key = session_key
        super().__init__(
            f"Quota exceeded for agent '{agent_id}': "
            f"{reason}={current_value} > max={quota_max} "
            f"(session_key={session_key})"
        )


@dataclass
class QuotaCheckResult:
    """Result of a check_and_increment call.

    Attributes:
        allowed:            True if the request is within quota or allowed under burst.
        agent_id:           The agent UUID that was checked.
        step_count:         Current step count after this call.
        accumulated_tokens: Current token count after this call.
        step_quota_max:     Configured step hard limit.
        token_quota_max:    Configured token hard limit.
        block_reason:       "step_count", "token_count", or "" if allowed.
        session_ttl:        TTL in seconds for this session's Redis keys.
        quota_status:       "NORMAL", "SOFT_CAP_REACHED", "BURST_ACTIVE", or "EXHAUSTED".
        tokens_remaining:   Estimated tokens remaining in base or burst quota.
        burst_available:    True if burst allowance has not been exhausted.
    """

    allowed: bool
    agent_id: str
    step_count: int
    accumulated_tokens: int
    step_quota_max: int
    token_quota_max: int
    block_reason: str | None
    session_ttl: int
    quota_status: str = "NORMAL"
    tokens_remaining: int = 0
    burst_available: bool = True


# ---------------------------------------------------------------------------
# TokenQuotaProxy
# ---------------------------------------------------------------------------


class TokenQuotaProxy:
    """Stateful inline circuit breaker enforcing per-session token quotas.

    Uses an atomic Redis Lua reservation pattern operating
    on token counts and step counts, with task-aware elastic bursting (RFC #652).

    Args:
        redis_client:           An async Redis client (redis.asyncio.Redis or
                                fakeredis.aioredis for tests).
        step_quota_max:         Hard limit on sequence steps per session (default 12).
        token_quota_max:        Hard limit on accumulated tokens per session (default 100k).
        session_ttl:            TTL in seconds for session Redis keys (default 3600).
        soft_cap_ratio:         Threshold ratio triggering soft-cap warning (default 0.85).
        burst_allowance_ratio:  Allowed elastic overdraft ratio to finish in-flight tasks (default 0.15).
        safe_landing_reserve:   Reserved tokens for handover manifest generation (default 1500).
    """

    def __init__(
        self,
        redis_client: Any,
        step_quota_max: int = 12,
        token_quota_max: int = 100_000,
        session_ttl: int = 3600,
        soft_cap_ratio: float = 0.85,
        burst_allowance_ratio: float = 0.15,
        safe_landing_reserve: int = 1500,
    ) -> None:
        self._redis = redis_client
        self._step_quota_max = step_quota_max
        self._token_quota_max = token_quota_max
        self._session_ttl = session_ttl
        self._soft_cap_ratio = soft_cap_ratio
        self._burst_allowance_ratio = burst_allowance_ratio
        self._safe_landing_reserve = safe_landing_reserve
        # SHA hashes loaded at init time via _load_scripts()
        self._sha_check: str | None = None
        self._sha_rollback: str | None = None
        self._sha_reconcile: str | None = None

    @property
    def step_quota_max(self) -> int:
        return self._step_quota_max

    @property
    def token_quota_max(self) -> int:
        return self._token_quota_max

    @property
    def session_ttl(self) -> int:
        return self._session_ttl

    @property
    def soft_cap_ratio(self) -> float:
        return self._soft_cap_ratio

    @property
    def burst_allowance_ratio(self) -> float:
        return self._burst_allowance_ratio

    @property
    def safe_landing_reserve(self) -> int:
        return self._safe_landing_reserve

    @property
    def soft_cap_tokens(self) -> int:
        return int(self._token_quota_max * self._soft_cap_ratio)

    @property
    def burst_max_tokens(self) -> int:
        return int(self._token_quota_max * (1.0 + self._burst_allowance_ratio))

    @classmethod
    def from_env(cls, redis_client: Any | None = None) -> TokenQuotaProxy:
        """Construct from environment variables.

        Environment variables:
            REDIS_URL                   — Redis connection URL (default: redis://localhost:6379)
            STEP_QUOTA_MAX              — Hard step limit per session (default: 12)
            TOKEN_QUOTA_MAX             — Hard token limit per session (default: 100000)
            SESSION_TTL_SECONDS         — Session TTL in seconds (default: 3600)
            TOKEN_QUOTA_SOFT_CAP_RATIO  — Soft-cap ratio (default: 0.85)
            TOKEN_QUOTA_BURST_RATIO     — Burst overdraft ratio (default: 0.15)
            TOKEN_QUOTA_SAFE_RESERVE    — Safe-landing reserve tokens (default: 1500)

        Raises:
            RuntimeError: If redis-py is not installed.
        """
        if redis_client is None:
            from src.gateway.infrastructure.redis_client import build_async_redis

            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
            client = build_async_redis(redis_url, socket_timeout=3.0)
        else:
            client = redis_client

        step_max = int(
            os.environ.get("CAGE_STEP_QUOTA_MAX")
            or os.environ.get("STEP_QUOTA_MAX", "12")
        )
        token_max = int(
            os.environ.get("CAGE_TOKEN_QUOTA_MAX")
            or os.environ.get("TOKEN_QUOTA_MAX", "100000")
        )
        ttl = int(
            os.environ.get("CAGE_SESSION_TTL_SECONDS")
            or os.environ.get("SESSION_TTL_SECONDS", "3600")
        )
        soft_cap_ratio = float(
            os.environ.get("CAGE_QUOTA_SOFT_CAP_RATIO")
            or os.environ.get("TOKEN_QUOTA_SOFT_CAP_RATIO", "0.85")
        )
        burst_ratio = float(
            os.environ.get("CAGE_QUOTA_BURST_ALLOWANCE_RATIO")
            or os.environ.get("TOKEN_QUOTA_BURST_RATIO", "0.15")
        )
        safe_reserve = int(
            os.environ.get("CAGE_QUOTA_SAFE_LANDING_RESERVE")
            or os.environ.get("TOKEN_QUOTA_SAFE_RESERVE", "1500")
        )

        return cls(
            redis_client=client,
            step_quota_max=step_max,
            token_quota_max=token_max,
            session_ttl=ttl,
            soft_cap_ratio=soft_cap_ratio,
            burst_allowance_ratio=burst_ratio,
            safe_landing_reserve=safe_reserve,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _session_key(self, agent_id: str, suffix: str) -> str:
        """Build a namespaced Redis key for a session counter."""
        return f"quota:session:{agent_id}:{suffix}"

    async def _load_scripts(self) -> None:
        """Load Lua scripts into Redis and cache their SHA hashes.

        Called lazily on first use.  Safe to call multiple times — Redis
        SCRIPT LOAD is idempotent (same script always produces the same SHA).
        """
        if self._sha_check is not None:
            return
        try:
            self._sha_check = await self._redis.script_load(_LUA_CHECK_AND_INCREMENT)
            self._sha_rollback = await self._redis.script_load(_LUA_ROLLBACK)
            self._sha_reconcile = await self._redis.script_load(_LUA_RECONCILE)
            logger.info(
                "TokenQuotaProxy: Lua scripts loaded "
                "(check=%s..., rollback=%s..., reconcile=%s...)",
                self._sha_check[:8],
                self._sha_rollback[:8],
                self._sha_reconcile[:8],
            )
        except Exception as exc:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.error(
                "TokenQuotaProxy: failed to load Lua scripts: %s — "
                "all requests will be BLOCKED (fail-closed).",
                exc,
            )
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_and_increment(
        self,
        agent_id: str,
        token_delta: int = 0,
        allow_burst: bool = False,
    ) -> QuotaCheckResult:
        """Atomically check quota and increment counters if within limits or burst ceiling.

        This is the primary enforcement point.  Call this before any vLLM
        or NeMo call.  If the result is not allowed, return 429 immediately.

        Fail-CLOSED: any Redis error raises QuotaExceededError so the
        request is blocked rather than allowed through.

        Args:
            agent_id:    The agent UUID identifying this session.
            token_delta: The number of tokens to reserve (from max_tokens
                         in the request body).  Use 0 if unknown.
            allow_burst: If True, permits elastic overdraft up to the burst
                         allowance ceiling to finalize an active task (RFC #652).

        Returns:
            QuotaCheckResult with allowed=True if within quota or burst allowance.

        Raises:
            QuotaExceededError: If quota is exceeded OR Redis is unavailable.
        """
        try:
            await self._load_scripts()
        except Exception as exc:
            # Fail-CLOSED: script load failure → block the request
            raise QuotaExceededError(
                agent_id=agent_id,
                reason="redis_unavailable",
                current_value=0,
                quota_max=self._step_quota_max,
                session_key=self._session_key(agent_id, "steps"),
            ) from exc

        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        soft_cap_tokens = int(self._token_quota_max * self._soft_cap_ratio)
        burst_max_tokens = int(
            self._token_quota_max * (1.0 + self._burst_allowance_ratio)
        )

        try:
            result = await self._redis.evalsha(
                self._sha_check,
                2,  # numkeys
                steps_key,
                tokens_key,
                str(self._step_quota_max),
                str(self._token_quota_max),
                str(max(0, token_delta)),
                str(self._session_ttl),
                str(soft_cap_tokens),
                str(burst_max_tokens),
                "1" if allow_burst else "0",
            )
        except Exception as exc:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.error(
                "TokenQuotaProxy.check_and_increment: Redis error agent=%s err=%s "
                "— failing CLOSED.",
                agent_id,
                exc,
            )
            raise QuotaExceededError(
                agent_id=agent_id,
                reason="redis_unavailable",
                current_value=0,
                quota_max=self._step_quota_max,
                session_key=steps_key,
            ) from exc

        # Lua returns: {allowed(0/1), steps, tokens, reason_str, quota_status}
        allowed_flag = int(result[0])
        steps = int(result[1])
        tokens = int(result[2])
        reason = str(result[3]) if result[3] else None
        quota_status = str(result[4]) if len(result) > 4 and result[4] else "NORMAL"

        burst_max = int(self._token_quota_max * (1.0 + self._burst_allowance_ratio))
        burst_available = tokens < burst_max

        if quota_status == "BURST_ACTIVE":
            tokens_remaining = max(0, burst_max - tokens)
        else:
            tokens_remaining = max(0, self._token_quota_max - tokens)

        quota_result = QuotaCheckResult(
            allowed=allowed_flag == 1,
            agent_id=agent_id,
            step_count=steps,
            accumulated_tokens=tokens,
            step_quota_max=self._step_quota_max,
            token_quota_max=self._token_quota_max,
            block_reason=reason,
            session_ttl=self._session_ttl,
            quota_status=quota_status,
            tokens_remaining=tokens_remaining,
            burst_available=burst_available,
        )

        if quota_result.allowed:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.info(
                "TokenQuotaProxy: ALLOWED agent=%s status=%s steps=%d/%d tokens=%d/%d",
                agent_id,
                quota_status,
                steps,
                self._step_quota_max,
                tokens,
                self._token_quota_max,
            )
        else:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy: BLOCKED agent=%s reason=%s steps=%d/%d tokens=%d/%d",
                agent_id,
                reason,
                steps,
                self._step_quota_max,
                tokens,
                self._token_quota_max,
            )

        return quota_result

    async def request_completion_overdraft(
        self,
        agent_id: str,
        estimated_delta: int,
    ) -> QuotaCheckResult:
        """Explicitly request atomic completion overdraft to finalize an in-flight task."""
        return await self.check_and_increment(
            agent_id=agent_id,
            token_delta=estimated_delta,
            allow_burst=True,
        )

    async def get_session_quota(self, agent_id: str) -> dict[str, Any]:
        """Inspect current quota counters and burst availability for an agent session."""
        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        steps_raw = await self._redis.get(steps_key)
        tokens_raw = await self._redis.get(tokens_key)
        steps = int(steps_raw) if steps_raw else 0
        tokens = int(tokens_raw) if tokens_raw else 0
        burst_max = int(self._token_quota_max * (1.0 + self._burst_allowance_ratio))
        soft_cap = int(self._token_quota_max * self._soft_cap_ratio)

        status = "NORMAL"
        if tokens > self._token_quota_max:
            status = "BURST_ACTIVE" if tokens <= burst_max else "EXHAUSTED"
        elif tokens >= soft_cap:
            status = "SOFT_CAP_REACHED"
        if steps > self._step_quota_max:
            status = "EXHAUSTED"

        return {
            "agent_id": agent_id,
            "step_count": steps,
            "accumulated_tokens": tokens,
            "quota_max_steps": self._step_quota_max,
            "quota_max_tokens": self._token_quota_max,
            "soft_cap_tokens": soft_cap,
            "burst_max_tokens": burst_max,
            "quota_status": status,
            "tokens_remaining": max(0, self._token_quota_max - tokens),
            "burst_tokens_remaining": max(0, burst_max - tokens),
            "burst_available": tokens < burst_max,
        }

    async def reconcile_actual_tokens(
        self,
        agent_id: str,
        reserved_tokens: int,
        actual_tokens_used: int,
    ) -> None:
        """Correct token over-allocation after vLLM responds.

        Call this after a successful vLLM response to adjust the token
        counter from the reserved amount to the actual tokens used.

        Args:
            agent_id:          The agent UUID for this session.
            reserved_tokens:   The token_delta passed to check_and_increment.
            actual_tokens_used: The actual tokens consumed (from vLLM response).
        """
        if reserved_tokens == actual_tokens_used:
            return  # No adjustment needed

        tokens_key = self._session_key(agent_id, "tokens")
        try:
            await self._load_scripts()
            await self._redis.evalsha(
                self._sha_reconcile,
                1,  # numkeys
                tokens_key,
                str(reserved_tokens),
                str(actual_tokens_used),
            )
            delta = actual_tokens_used - reserved_tokens
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.debug(
                "TokenQuotaProxy.reconcile: agent=%s reserved=%d actual=%d delta=%+d",
                agent_id,
                reserved_tokens,
                actual_tokens_used,
                delta,
            )
        except Exception as exc:
            # Non-fatal: log and continue.  The block is already enforced.
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy.reconcile: Redis error agent=%s err=%s "
                "— token counter may be slightly over-reserved.",
                agent_id,
                exc,
            )

    async def rollback_step(
        self,
        agent_id: str,
        reserved_tokens: int,
    ) -> None:
        """Atomically decrement counters after a downstream failure.

        Call this in the except block when NeMo/OPA/vLLM raises after
        check_and_increment() already reserved quota.

        Args:
            agent_id:        The agent UUID for this session.
            reserved_tokens: The token_delta that was reserved.
        """
        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        try:
            await self._load_scripts()
            await self._redis.evalsha(
                self._sha_rollback,
                2,  # numkeys
                steps_key,
                tokens_key,
                str(reserved_tokens),
            )
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.info(
                "TokenQuotaProxy.rollback: agent=%s reserved_tokens=%d rolled back",
                agent_id,
                reserved_tokens,
            )
        except Exception as exc:
            # Non-fatal: log and continue.  The downstream failure is already
            # propagating; a rollback failure is a secondary concern.
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy.rollback: Redis error agent=%s err=%s "
                "— step counter may be slightly over-counted.",
                agent_id,
                exc,
            )

    async def reset_session(self, agent_id: str) -> None:
        """Delete all Redis keys for a session (admin / test use only).

        Args:
            agent_id: The agent UUID whose session to reset.
        """
        keys = [
            self._session_key(agent_id, "steps"),
            self._session_key(agent_id, "tokens"),
            self._session_key(agent_id, "meta"),
        ]
        try:
            await self._redis.delete(*keys)
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.info(
                "TokenQuotaProxy.reset_session: agent=%s keys deleted", agent_id
            )
        except Exception as exc:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy.reset_session: Redis error agent=%s err=%s",
                agent_id,
                exc,
            )

    async def get_session_state(self, agent_id: str) -> dict:
        """Return the current session counters for an agent.

        Args:
            agent_id: The agent UUID to inspect.

        Returns:
            Dict with keys: steps, tokens, step_quota_max, token_quota_max,
            session_ttl, agent_id.
        """
        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        try:
            steps_raw, tokens_raw = await self._redis.mget(steps_key, tokens_key)
            return {
                "agent_id": agent_id,
                "steps": int(steps_raw or 0),
                "tokens": int(tokens_raw or 0),
                "step_quota_max": self._step_quota_max,
                "token_quota_max": self._token_quota_max,
                "session_ttl": self._session_ttl,
            }
        except Exception as exc:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy.get_session_state: Redis error agent=%s err=%s",
                agent_id,
                exc,
            )
            return {
                "agent_id": agent_id,
                "steps": 0,
                "tokens": 0,
                "step_quota_max": self._step_quota_max,
                "token_quota_max": self._token_quota_max,
                "session_ttl": self._session_ttl,
                "error": str(exc),
            }


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_token_quota_proxy: TokenQuotaProxy | None = None


def _get_token_quota_proxy() -> TokenQuotaProxy:
    """Return the module-level TokenQuotaProxy singleton.

    Lazily initialised on first call.  Thread-safe because Python's GIL
    guarantees atomic reference assignment for simple object creation.
    """
    global _token_quota_proxy
    if _token_quota_proxy is None:
        _token_quota_proxy = TokenQuotaProxy.from_env()
    return _token_quota_proxy
