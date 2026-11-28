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
# Supports single-scope (KEYS[1..2]) or dual-scope session + workload ceiling
# (KEYS[1..4]) in a single atomic Lua execution so neither counter stays
# incremented when either limit is exceeded.
# Returns {allowed, steps, tokens, reason} as a 4-element list.
_LUA_CHECK_AND_INCREMENT = """
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- Optional: KEYS[3] = workload_steps_key, KEYS[4] = workload_tokens_key
-- ARGV[1] = step_quota_max, ARGV[2] = token_quota_max
-- ARGV[3] = token_delta, ARGV[4] = ttl_seconds
-- Optional: ARGV[5] = workload_step_quota_max, ARGV[6] = workload_token_quota_max
local delta  = tonumber(ARGV[3])
local steps  = redis.call('INCR', KEYS[1])
local tokens = redis.call('INCRBY', KEYS[2], delta)
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])
if steps > tonumber(ARGV[1]) then
    redis.call('DECR', KEYS[1])
    redis.call('DECRBY', KEYS[2], delta)
    return {0, steps - 1, tokens - delta, 'step_count'}
end
if tokens > tonumber(ARGV[2]) then
    redis.call('DECR', KEYS[1])
    redis.call('DECRBY', KEYS[2], delta)
    return {0, steps - 1, tokens - delta, 'token_count'}
end
if #KEYS >= 4 then
    local w_steps  = redis.call('INCR', KEYS[3])
    local w_tokens = redis.call('INCRBY', KEYS[4], delta)
    redis.call('EXPIRE', KEYS[3], ARGV[4])
    redis.call('EXPIRE', KEYS[4], ARGV[4])
    if w_steps > tonumber(ARGV[5]) then
        redis.call('DECR', KEYS[1])
        redis.call('DECRBY', KEYS[2], delta)
        redis.call('DECR', KEYS[3])
        redis.call('DECRBY', KEYS[4], delta)
        return {0, w_steps - 1, w_tokens - delta, 'workload_step_count'}
    end
    if w_tokens > tonumber(ARGV[6]) then
        redis.call('DECR', KEYS[1])
        redis.call('DECRBY', KEYS[2], delta)
        redis.call('DECR', KEYS[3])
        redis.call('DECRBY', KEYS[4], delta)
        return {0, w_steps - 1, w_tokens - delta, 'workload_token_count'}
    end
end
return {1, steps, tokens, ''}
"""

# rollback: atomically decrement session (and optional workload) counters after a downstream failure.
_LUA_ROLLBACK = """
-- KEYS[1] = steps_key, KEYS[2] = tokens_key
-- Optional: KEYS[3] = workload_steps_key, KEYS[4] = workload_tokens_key
-- ARGV[1] = reserved_tokens
local s = redis.call('DECR', KEYS[1])
if s <= 0 then
    redis.call('DEL', KEYS[1])
end
local t = redis.call('DECRBY', KEYS[2], ARGV[1])
if t <= 0 then
    redis.call('DEL', KEYS[2])
end
if #KEYS >= 4 then
    local ws = redis.call('DECR', KEYS[3])
    if ws <= 0 then
        redis.call('DEL', KEYS[3])
    end
    local wt = redis.call('DECRBY', KEYS[4], ARGV[1])
    if wt <= 0 then
        redis.call('DEL', KEYS[4])
    end
end
return 1
"""

# reconcile: adjust token counter(s) by (actual - reserved) after vLLM responds.
_LUA_RECONCILE = """
-- KEYS[1] = tokens_key [, KEYS[2] = workload_tokens_key]
-- ARGV[1] = reserved_tokens, ARGV[2] = actual_tokens_used
local delta = tonumber(ARGV[2]) - tonumber(ARGV[1])
if delta ~= 0 then
    if redis.call('EXISTS', KEYS[1]) == 1 then
        local t = redis.call('INCRBY', KEYS[1], delta)
        if t < 0 then
            local ttl = redis.call('TTL', KEYS[1])
            redis.call('SET', KEYS[1], 0)
            if ttl > 0 then
                redis.call('EXPIRE', KEYS[1], ttl)
            end
        end
    end
    if #KEYS >= 2 and redis.call('EXISTS', KEYS[2]) == 1 then
        local wt = redis.call('INCRBY', KEYS[2], delta)
        if wt < 0 then
            local wttl = redis.call('TTL', KEYS[2])
            redis.call('SET', KEYS[2], 0)
            if wttl > 0 then
                redis.call('EXPIRE', KEYS[2], wttl)
            end
        end
    end
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
        allowed:            True if the request is within quota.
        agent_id:           The agent UUID that was checked.
        step_count:         Current step count after this call.
        accumulated_tokens: Current token count after this call.
        step_quota_max:     Configured step hard limit.
        token_quota_max:    Configured token hard limit.
        block_reason:       "step_count", "token_count", or "" if allowed.
        session_ttl:        TTL in seconds for this session's Redis keys.
    """

    allowed: bool
    agent_id: str
    step_count: int
    accumulated_tokens: int
    step_quota_max: int
    token_quota_max: int
    block_reason: str | None
    session_ttl: int

    @property
    def tokens_remaining(self) -> int:
        """Non-negative remaining token budget for this session."""
        return max(0, self.token_quota_max - self.accumulated_tokens)


# ---------------------------------------------------------------------------
# TokenQuotaProxy
# ---------------------------------------------------------------------------


class TokenQuotaProxy:
    """Stateful inline circuit breaker enforcing per-session token quotas.

    Uses an atomic Redis Lua reservation pattern operating
    on token counts and step counts.

    Args:
        redis_client:    An async Redis client (redis.asyncio.Redis or
                         fakeredis.aioredis for tests).
        step_quota_max:  Hard limit on sequence steps per session (default 12).
        token_quota_max: Hard limit on accumulated tokens per session (default 100k).
        session_ttl:     TTL in seconds for session Redis keys (default 3600).
    """

    def __init__(
        self,
        redis_client: Any,
        step_quota_max: int = 12,
        token_quota_max: int = 100_000,
        session_ttl: int = 3600,
        workload_step_quota_max: int | None = None,
        workload_token_quota_max: int | None = None,
    ) -> None:
        self._redis = redis_client
        self._step_quota_max = step_quota_max
        self._token_quota_max = token_quota_max
        self._session_ttl = session_ttl
        self._workload_step_quota_max = (
            workload_step_quota_max
            if workload_step_quota_max is not None
            else max(step_quota_max * 100, 1200)
        )
        self._workload_token_quota_max = (
            workload_token_quota_max
            if workload_token_quota_max is not None
            else max(token_quota_max * 100, 10_000_000)
        )
        # SHA hashes loaded at init time via _load_scripts()
        self._sha_check: str | None = None
        self._sha_rollback: str | None = None
        self._sha_reconcile: str | None = None

    @classmethod
    def from_env(cls) -> TokenQuotaProxy:
        """Construct from environment variables.

        Environment variables:
            REDIS_URL                — Redis connection URL (default: redis://localhost:6379)
            STEP_QUOTA_MAX           — Hard step limit per session (default: 12)
            TOKEN_QUOTA_MAX          — Hard token limit per session (default: 100000)
            SESSION_TTL_SECONDS      — Session TTL in seconds (default: 3600)
            WORKLOAD_STEP_QUOTA_MAX  — Optional pod-wide workload step ceiling
            WORKLOAD_TOKEN_QUOTA_MAX — Optional pod-wide workload token ceiling

        Raises:
            RuntimeError: If redis-py is not installed.
        """
        from src.gateway.infrastructure.redis_client import build_async_redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        step_max = int(os.environ.get("STEP_QUOTA_MAX", "12"))
        token_max = int(os.environ.get("TOKEN_QUOTA_MAX", "100000"))
        ttl = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))
        raw_w_step = os.environ.get("WORKLOAD_STEP_QUOTA_MAX")
        raw_w_token = os.environ.get("WORKLOAD_TOKEN_QUOTA_MAX")
        workload_step_max = (
            int(raw_w_step) if raw_w_step and raw_w_step.strip() else None
        )
        workload_token_max = (
            int(raw_w_token) if raw_w_token and raw_w_token.strip() else None
        )

        client = build_async_redis(redis_url, socket_timeout=3.0)
        return cls(
            redis_client=client,
            step_quota_max=step_max,
            token_quota_max=token_max,
            session_ttl=ttl,
            workload_step_quota_max=workload_step_max,
            workload_token_quota_max=workload_token_max,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _session_key(self, agent_id: str, suffix: str) -> str:
        """Build a namespaced Redis key for a session counter."""
        return f"quota:session:{agent_id}:{suffix}"

    def _workload_key(self, workload_id: str, suffix: str) -> str:
        """Build a namespaced Redis key for a pod-wide workload ceiling counter."""
        return f"quota:workload:{workload_id}:{suffix}"

    @staticmethod
    def _validate_non_negative_int(value: Any, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be a non-bool integer, got {value!r}")
        if value < 0:
            raise ValueError(f"{name} must be non-negative, got {value!r}")
        return int(value)

    async def _evalsha_with_reload(
        self,
        which: str,
        script: str,
        numkeys: int,
        *keys_and_args: str,
    ) -> Any:
        """Execute cached Lua SHA with automatic NOSCRIPT reload recovery (KG-28)."""
        await self._load_scripts()
        sha_attr = f"_sha_{which}"
        sha = getattr(self, sha_attr)
        try:
            return await self._redis.evalsha(sha, numkeys, *keys_and_args)
        except Exception as exc:
            if "NOSCRIPT" not in str(exc).upper():
                raise
            logger.warning(
                "Quota proxy: NOSCRIPT on %s Lua script — reloading scripts and retrying.",
                which,
            )
            self._sha_check = None
            self._sha_rollback = None
            self._sha_reconcile = None
            await self._load_scripts()
            refreshed_sha = getattr(self, sha_attr)
            return await self._redis.evalsha(refreshed_sha, numkeys, *keys_and_args)

    async def _load_scripts(self) -> None:
        """Load Lua scripts into Redis and cache their SHA hashes.

        Called lazily on first use.  Safe to call multiple times — Redis
        SCRIPT LOAD is idempotent (same script always produces the same SHA).
        """
        if (
            self._sha_check is not None
            and self._sha_rollback is not None
            and self._sha_reconcile is not None
        ):
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
        *,
        workload_id: str | None = None,
    ) -> QuotaCheckResult:
        """Atomically check quota and increment counters if within limits.

        This is the primary enforcement point.  Call this before any vLLM
        or NeMo call.  If the result is not allowed, return 429 immediately.

        Fail-CLOSED: any Redis error raises QuotaExceededError so the
        request is blocked rather than allowed through.

        Args:
            agent_id:    The session scope key (or agent UUID when unscoped).
            token_delta: The number of tokens to reserve.  Use 0 if unknown.
            workload_id: Optional pod-wide Linkerd SVID when ``agent_id`` is
                         session-scoped; enforces the pod-wide workload safety
                         ceiling atomically in the same Lua hop.

        Returns:
            QuotaCheckResult with allowed=True if within quota.

        Raises:
            QuotaExceededError: If token_delta is invalid OR Redis is unavailable.
        """
        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        enforce_workload = bool(workload_id and workload_id != agent_id)
        reported_agent_id = (
            workload_id if (enforce_workload and workload_id is not None) else agent_id
        )
        try:
            validated_delta = self._validate_non_negative_int(
                token_delta, "token_delta"
            )
        except ValueError as exc:
            raise QuotaExceededError(
                agent_id=reported_agent_id,
                reason="invalid_token_delta",
                current_value=0,
                quota_max=self._token_quota_max,
                session_key=tokens_key,
            ) from exc

        try:
            if enforce_workload and workload_id is not None:
                w_steps_key = self._workload_key(workload_id, "steps")
                w_tokens_key = self._workload_key(workload_id, "tokens")
                result = await self._evalsha_with_reload(
                    "check",
                    _LUA_CHECK_AND_INCREMENT,
                    4,
                    steps_key,
                    tokens_key,
                    w_steps_key,
                    w_tokens_key,
                    str(self._step_quota_max),
                    str(self._token_quota_max),
                    str(validated_delta),
                    str(self._session_ttl),
                    str(self._workload_step_quota_max),
                    str(self._workload_token_quota_max),
                )
            else:
                result = await self._evalsha_with_reload(
                    "check",
                    _LUA_CHECK_AND_INCREMENT,
                    2,  # numkeys
                    steps_key,
                    tokens_key,
                    str(self._step_quota_max),
                    str(self._token_quota_max),
                    str(validated_delta),
                    str(self._session_ttl),
                )
        except Exception as exc:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.error(
                "TokenQuotaProxy.check_and_increment: Redis error agent=%s err=%s "
                "— failing CLOSED.",
                reported_agent_id,
                exc,
            )
            raise QuotaExceededError(
                agent_id=reported_agent_id,
                reason="redis_unavailable",
                current_value=0,
                quota_max=self._step_quota_max,
                session_key=steps_key,
            ) from exc

        # Lua returns: {allowed(0/1), steps, tokens, reason_str}
        allowed_flag = int(result[0])
        steps = int(result[1])
        tokens = int(result[2])
        reason = str(result[3]) if result[3] else None

        is_workload_block = reason in ("workload_step_count", "workload_token_count")
        effective_step_max = (
            self._workload_step_quota_max if is_workload_block else self._step_quota_max
        )
        effective_token_max = (
            self._workload_token_quota_max
            if is_workload_block
            else self._token_quota_max
        )

        quota_result = QuotaCheckResult(
            allowed=allowed_flag == 1,
            agent_id=reported_agent_id,
            step_count=steps,
            accumulated_tokens=tokens,
            step_quota_max=effective_step_max,
            token_quota_max=effective_token_max,
            block_reason=reason,
            session_ttl=self._session_ttl,
        )

        if quota_result.allowed:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.info(
                "TokenQuotaProxy: ALLOWED agent=%s steps=%d/%d tokens=%d/%d",
                reported_agent_id,
                steps,
                effective_step_max,
                tokens,
                effective_token_max,
            )
        else:
            # 'token' = LLM usage-token counts; logs agent id/counters/error only.
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning(
                "TokenQuotaProxy: BLOCKED agent=%s reason=%s steps=%d/%d tokens=%d/%d",
                reported_agent_id,
                reason,
                steps,
                effective_step_max,
                tokens,
                effective_token_max,
            )

        return quota_result

    async def reconcile_actual_tokens(
        self,
        agent_id: str,
        reserved_tokens: int,
        actual_tokens_used: int,
        *,
        workload_id: str | None = None,
    ) -> None:
        """Correct token over-allocation after vLLM responds.

        Call this after a successful vLLM response to adjust the token
        counter from the reserved amount to the actual tokens used.

        Args:
            agent_id:           The session scope key (or agent UUID).
            reserved_tokens:    The token_delta passed to check_and_increment.
            actual_tokens_used: The actual tokens consumed (from vLLM response).
            workload_id:        Optional pod-wide Linkerd SVID when session-scoped.
        """
        reserved_valid = self._validate_non_negative_int(
            reserved_tokens, "reserved_tokens"
        )
        actual_valid = self._validate_non_negative_int(
            actual_tokens_used, "actual_tokens_used"
        )
        if reserved_valid == actual_valid:
            return  # No adjustment needed

        tokens_key = self._session_key(agent_id, "tokens")
        enforce_workload = bool(workload_id and workload_id != agent_id)
        try:
            if enforce_workload and workload_id is not None:
                w_tokens_key = self._workload_key(workload_id, "tokens")
                await self._evalsha_with_reload(
                    "reconcile",
                    _LUA_RECONCILE,
                    2,
                    tokens_key,
                    w_tokens_key,
                    str(reserved_valid),
                    str(actual_valid),
                )
            else:
                await self._evalsha_with_reload(
                    "reconcile",
                    _LUA_RECONCILE,
                    1,  # numkeys
                    tokens_key,
                    str(reserved_valid),
                    str(actual_valid),
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
        *,
        workload_id: str | None = None,
    ) -> None:
        """Atomically decrement counters after a downstream failure.

        Call this in the except block when NeMo/OPA/vLLM raises after
        check_and_increment() already reserved quota.

        Args:
            agent_id:        The session scope key (or agent UUID).
            reserved_tokens: The token_delta that was reserved.
            workload_id:     Optional pod-wide Linkerd SVID when session-scoped.
        """
        reserved_valid = self._validate_non_negative_int(
            reserved_tokens, "reserved_tokens"
        )
        steps_key = self._session_key(agent_id, "steps")
        tokens_key = self._session_key(agent_id, "tokens")
        enforce_workload = bool(workload_id and workload_id != agent_id)
        try:
            if enforce_workload and workload_id is not None:
                w_steps_key = self._workload_key(workload_id, "steps")
                w_tokens_key = self._workload_key(workload_id, "tokens")
                await self._evalsha_with_reload(
                    "rollback",
                    _LUA_ROLLBACK,
                    4,
                    steps_key,
                    tokens_key,
                    w_steps_key,
                    w_tokens_key,
                    str(reserved_valid),
                )
            else:
                await self._evalsha_with_reload(
                    "rollback",
                    _LUA_ROLLBACK,
                    2,  # numkeys
                    steps_key,
                    tokens_key,
                    str(reserved_valid),
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

import threading

_token_quota_proxy: TokenQuotaProxy | None = None
_token_quota_proxy_lock = threading.Lock()


def _get_token_quota_proxy() -> TokenQuotaProxy:
    """Return the module-level TokenQuotaProxy singleton (thread-safe lazy init)."""
    global _token_quota_proxy
    if _token_quota_proxy is None:
        with _token_quota_proxy_lock:
            if _token_quota_proxy is None:
                _token_quota_proxy = TokenQuotaProxy.from_env()
    return _token_quota_proxy
