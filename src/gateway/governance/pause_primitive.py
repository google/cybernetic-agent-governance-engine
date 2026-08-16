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
pause_primitive.py — PAUSE State Machine Primitive (CAGE v0.1.4)

The PAUSE primitive allows resumable suspension of action execution. Unlike
DEFER (which queues for human review or automated data-hydration), PAUSE
suspends execution waiting for an external signal to resume — useful for:

  - Rate limiting (soft, will clear with time)
  - Circuit breaker open (external dependency unavailable)
  - Coordination wait (cross-agent synchronization)
  - Resource temporarily unavailable

Architecture:
  CAGE's decision vocabulary is extended to six states by adding PAUSE alongside
  ALLOW, DENY, DEFER, NARROW, and REQUIRE_APPROVAL. PAUSE activates when a
  transient external condition prevents immediate execution but will likely
  resolve without human intervention or context enrichment.

  The PauseToken is stored in Redis database index ``db=1`` with prefix ``PAUSE:``
  and a configurable TTL (default: 1 hour). When the TTL expires, the pause
  auto-denies — the client must retry the original request.

  Data structures:
    Redis Hash   PAUSE:{pause_token}     — full PauseState JSON
    Redis ZSet   PAUSE:expiry_index      — member=pause_token, score=expiry_unix_ts

  Paused requests are resolved by:
    (a) Explicit resume via POST /v1/pause/{pause_token}/resume
    (b) Automatic expiry (TTL exceeded → state transitions to EXPIRED)

Resume semantics:
  - Resume is idempotent: calling resume on an already-resumed token returns
    success without side effects.
  - Resume accepts optional context data that can modify the resumed request.
  - Expired tokens cannot be resumed; the client must retry the original request.

HTTP Response:
  - HTTP 503 Service Unavailable with Retry-After header
  - Body includes pause_token, resume_endpoint, expires_at, and estimated_wait_seconds

Feature flag: CAGE_PAUSE_ENABLED (default: false — opt-in).
When disabled, PAUSE candidates fall back to DENY.

ISO 42001 mapping: A.8.4 (AI System Operation Controls) — formal pause is an
operation control that prevents unsafe execution under transient conditions.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis key prefixes — isolated in db=1 (noeviction)
# ---------------------------------------------------------------------------

_KEY_PREFIX = "PAUSE:"
_EXPIRY_ZSET = "PAUSE:expiry_index"
_DEFAULT_TTL = 3600  # 1-hour park window before auto-deny

# ---------------------------------------------------------------------------
# Feature flag: CAGE_PAUSE_ENABLED
# ---------------------------------------------------------------------------

CAGE_PAUSE_ENABLED: bool = os.getenv("CAGE_PAUSE_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# PauseReason — why the execution was paused
# ---------------------------------------------------------------------------


class PauseReason(str, Enum):
    """Enumeration of root causes for a PAUSE decision.

    Maps to OTel span attributes for telemetry and alerting.
    """

    RATE_LIMITED = "RATE_LIMITED"
    """Request rate exceeded soft threshold; will clear with time."""

    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    """External dependency circuit breaker is open; awaiting recovery."""

    COORDINATION_WAIT = "COORDINATION_WAIT"
    """Waiting for cross-agent coordination signal."""

    RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE"
    """Transient resource unavailability (e.g., quota exhausted, service degraded)."""

    MANUAL_GATE = "MANUAL_GATE"
    """Explicit pause requested by operator or policy; awaiting manual resume."""


# ---------------------------------------------------------------------------
# PauseStatus — lifecycle status of a paused request
# ---------------------------------------------------------------------------


class PauseStatus(str, Enum):
    """Lifecycle status of a paused request."""

    PAUSED = "PAUSED"
    """Request is actively paused, awaiting resume signal."""

    RESUMED = "RESUMED"
    """Request has been resumed via the resume endpoint."""

    EXPIRED = "EXPIRED"
    """Pause TTL exceeded; request auto-denied."""


# ---------------------------------------------------------------------------
# PauseState — the paused execution context
# ---------------------------------------------------------------------------


class PauseState(BaseModel):
    """Immutable snapshot of an execution context paused in the PAUSE queue.

    Fields:
        pause_token         — stable UUID v4 assigned at pause time.
        request_id          — original request ID (for correlation).
        thread_id           — LangGraph thread (checkpoint) ID if applicable.
        pause_reason        — root cause from PauseReason enum.
        original_request    — sanitized copy of the original request payload.
        paused_at_utc       — ISO-8601 UTC timestamp when the request was paused.
        expires_at_utc      — ISO-8601 UTC timestamp when the pause expires.
        ttl_seconds         — how long before the pause expires (auto-deny).
        status              — current lifecycle status (PAUSED/RESUMED/EXPIRED).
        resumed_at_utc      — ISO-8601 UTC when resumed, or None.
        resume_context      — optional context data provided at resume time.
        estimated_wait_secs — optional hint for client polling interval.
    """

    pause_token: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = Field(default="")
    thread_id: str = Field(default="")
    pause_reason: PauseReason = Field(default=PauseReason.RATE_LIMITED)
    original_request: dict[str, Any] = Field(default_factory=dict)
    paused_at_utc: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    expires_at_utc: str = Field(default="")
    ttl_seconds: int = Field(default=_DEFAULT_TTL)
    status: PauseStatus = Field(default=PauseStatus.PAUSED)
    resumed_at_utc: str | None = None
    resume_context: dict[str, Any] | None = None
    estimated_wait_secs: int | None = None

    def model_post_init(self, __context: Any) -> None:
        """Set expires_at_utc based on paused_at_utc + ttl_seconds if not set."""
        if not self.expires_at_utc:
            paused_at = datetime.fromisoformat(self.paused_at_utc)
            expires_at = datetime.fromtimestamp(
                paused_at.timestamp() + self.ttl_seconds, tz=timezone.utc
            )
            self.expires_at_utc = expires_at.isoformat()


# ---------------------------------------------------------------------------
# ResumeResult — outcome of a resume_request() call
# ---------------------------------------------------------------------------


class ResumeResult(str, Enum):
    """Outcome of a resume_request() call."""

    RESUMED = "RESUMED"
    """Request was successfully resumed (first resume call)."""

    ALREADY_RESUMED = "ALREADY_RESUMED"
    """Request was already resumed (idempotent success)."""

    EXPIRED = "EXPIRED"
    """Pause TTL exceeded; cannot resume (must retry original request)."""

    NOT_FOUND = "NOT_FOUND"
    """No pause token found with the given ID."""


# ---------------------------------------------------------------------------
# PauseManager — Redis-backed pause token registry
# ---------------------------------------------------------------------------


class PauseManager:
    """Redis-backed PAUSE token manager with TTL-scored expiry.

    Mandatory deployment configuration:
        Redis database: ``db=1`` (isolated from LangGraph checkpointer at db=0)
        maxmemory-policy: ``noeviction`` (fail-safe — block on OOM rather than
                                          silently dropping paused requests)

    Args:
        redis_client: An aioredis or redis-py async client connected to ``db=1``.
                      Callers are responsible for connection lifecycle.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    # ------------------------------------------------------------------
    # pause_request — pause an action and store state in Redis
    # ------------------------------------------------------------------

    async def pause_request(
        self,
        request_id: str,
        reason: str | PauseReason,
        ttl_seconds: int = _DEFAULT_TTL,
        original_request: dict[str, Any] | None = None,
        thread_id: str = "",
        estimated_wait_secs: int | None = None,
    ) -> str:
        """Pause a request and store its state in Redis.

        Args:
            request_id:          Unique identifier for the original request.
            reason:              Pause reason string or PauseReason enum.
            ttl_seconds:         Time-to-live in seconds (default: 3600 = 1 hour).
            original_request:    Optional copy of the original request payload.
            thread_id:           Optional LangGraph thread ID for correlation.
            estimated_wait_secs: Optional hint for client polling interval.

        Returns:
            The pause_token (UUID v4) for resuming this request.

        Raises:
            Exception: If Redis write fails (fail-closed behavior).
        """
        # Normalize reason to enum value string
        if isinstance(reason, PauseReason):
            reason_str = reason.value
        else:
            reason_str = reason

        # Create pause state
        state = PauseState(
            request_id=request_id,
            thread_id=thread_id,
            pause_reason=PauseReason(reason_str) if reason_str in [r.value for r in PauseReason] else PauseReason.RATE_LIMITED,
            original_request=original_request or {},
            ttl_seconds=ttl_seconds,
            estimated_wait_secs=estimated_wait_secs,
        )

        key = f"{_KEY_PREFIX}{state.pause_token}"
        expiry_ts = time.time() + ttl_seconds
        state_json = state.model_dump_json()

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.hset(key, mapping={"state": state_json, "status": "PAUSED"})
                pipe.expire(key, ttl_seconds)
                pipe.zadd(_EXPIRY_ZSET, {state.pause_token: expiry_ts})
                await pipe.execute()
        except Exception as exc:
            logger.error(
                "[pause_primitive] pause_request() failed for request_id=%s: %s",
                request_id,
                exc,
            )
            raise

        logger.info(
            "[pause_primitive] Paused request request_id=%s pause_token=%s reason=%s "
            "ttl=%ds expires_at=%s",
            request_id,
            state.pause_token,
            reason_str,
            ttl_seconds,
            state.expires_at_utc,
        )

        return state.pause_token

    # ------------------------------------------------------------------
    # resume_request — resume a paused request
    # ------------------------------------------------------------------

    async def resume_request(
        self,
        pause_token: str,
        resume_context: dict[str, Any] | None = None,
    ) -> ResumeResult:
        """Resume a paused request.

        Resume is idempotent: calling resume on an already-resumed token
        returns ALREADY_RESUMED without side effects.

        Args:
            pause_token:    The pause_token returned by pause_request().
            resume_context: Optional context data to attach to the resumed request.

        Returns:
            ResumeResult indicating the outcome.
        """
        key = f"{_KEY_PREFIX}{pause_token}"
        raw = await self._redis.hget(key, "state")
        if raw is None:
            logger.warning(
                "[pause_primitive] resume_request() called for unknown pause_token=%s",
                pause_token,
            )
            return ResumeResult.NOT_FOUND

        state = PauseState.model_validate_json(raw)

        # Check if already resumed (idempotent success)
        if state.status == PauseStatus.RESUMED:
            logger.info(
                "[pause_primitive] resume_request() idempotent: pause_token=%s already resumed",
                pause_token,
            )
            return ResumeResult.ALREADY_RESUMED

        # Check if expired
        expires_at = datetime.fromisoformat(state.expires_at_utc)
        now = datetime.now(tz=timezone.utc)
        if now > expires_at:
            # Mark as expired in Redis
            state.status = PauseStatus.EXPIRED
            try:
                async with self._redis.pipeline(transaction=True) as pipe:
                    pipe.hset(key, mapping={"state": state.model_dump_json(), "status": "EXPIRED"})
                    pipe.zrem(_EXPIRY_ZSET, pause_token)
                    await pipe.execute()
            except Exception as exc:
                logger.warning(
                    "[pause_primitive] Failed to update expired state for pause_token=%s: %s",
                    pause_token,
                    exc,
                )
            logger.warning(
                "[pause_primitive] resume_request() failed: pause_token=%s expired at %s",
                pause_token,
                state.expires_at_utc,
            )
            return ResumeResult.EXPIRED

        # Resume the request
        state.status = PauseStatus.RESUMED
        state.resumed_at_utc = datetime.now(tz=timezone.utc).isoformat()
        state.resume_context = resume_context

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.hset(
                    key,
                    mapping={
                        "state": state.model_dump_json(),
                        "status": "RESUMED",
                        **({"resume_context": json.dumps(resume_context)} if resume_context else {}),
                    },
                )
                pipe.zrem(_EXPIRY_ZSET, pause_token)
                await pipe.execute()
        except Exception as exc:
            logger.error(
                "[pause_primitive] resume_request() Redis write failed for pause_token=%s: %s",
                pause_token,
                exc,
            )
            raise

        logger.info(
            "[pause_primitive] Resumed request pause_token=%s request_id=%s resumed_at=%s",
            pause_token,
            state.request_id,
            state.resumed_at_utc,
        )

        return ResumeResult.RESUMED

    # ------------------------------------------------------------------
    # get_pause_state — fetch a single pause state by token
    # ------------------------------------------------------------------

    async def get_pause_state(self, pause_token: str) -> PauseState | None:
        """Fetch a single pause state by pause_token.

        Returns None if not found (expired and evicted, or never created).

        Args:
            pause_token: The pause_token to look up.

        Returns:
            PauseState if found, None otherwise.
        """
        key = f"{_KEY_PREFIX}{pause_token}"
        raw = await self._redis.hget(key, "state")
        if raw is None:
            return None
        return PauseState.model_validate_json(raw)

    # ------------------------------------------------------------------
    # expire_pause — explicitly expire a pause token
    # ------------------------------------------------------------------

    async def expire_pause(self, pause_token: str) -> None:
        """Explicitly expire a pause token (e.g., on error or timeout).

        This transitions the pause state to EXPIRED and removes it from
        the expiry index. The key remains in Redis until its TTL expires
        for audit purposes.

        Args:
            pause_token: The pause_token to expire.
        """
        key = f"{_KEY_PREFIX}{pause_token}"
        raw = await self._redis.hget(key, "state")
        if raw is None:
            logger.debug(
                "[pause_primitive] expire_pause() called for unknown pause_token=%s",
                pause_token,
            )
            return

        state = PauseState.model_validate_json(raw)
        state.status = PauseStatus.EXPIRED

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.hset(key, mapping={"state": state.model_dump_json(), "status": "EXPIRED"})
                pipe.zrem(_EXPIRY_ZSET, pause_token)
                await pipe.execute()
        except Exception as exc:
            logger.warning(
                "[pause_primitive] expire_pause() failed for pause_token=%s: %s",
                pause_token,
                exc,
            )

        logger.info(
            "[pause_primitive] Expired pause_token=%s request_id=%s",
            pause_token,
            state.request_id,
        )

    # ------------------------------------------------------------------
    # list_active_pauses — return all active (non-expired, non-resumed) pauses
    # ------------------------------------------------------------------

    async def list_active_pauses(self, limit: int = 100) -> list[PauseState]:
        """Return active (PAUSED status) tokens, ordered by expiry deadline.

        Args:
            limit: Maximum number of tokens to return.

        Returns:
            List of PauseState objects, soonest-expiring first.
        """
        now = time.time()
        members = await self._redis.zrangebyscore(
            _EXPIRY_ZSET, now, "+inf", start=0, num=limit
        )

        states: list[PauseState] = []
        for pause_token in members:
            key = f"{_KEY_PREFIX}{pause_token}"
            raw = await self._redis.hget(key, "state")
            if raw:
                state = PauseState.model_validate_json(raw)
                if state.status == PauseStatus.PAUSED:
                    states.append(state)

        return states

    # ------------------------------------------------------------------
    # expire_stale — sweep and expire pauses past their TTL
    # ------------------------------------------------------------------

    async def expire_stale(self) -> int:
        """Sweep the expiry index for pauses past their TTL and mark them EXPIRED.

        Called periodically by a background task or cron job.

        Returns:
            Count of pauses that were expired.
        """
        now = time.time()
        members = await self._redis.zrangebyscore(_EXPIRY_ZSET, "-inf", now)

        count = 0
        for pause_token in members:
            await self.expire_pause(pause_token)
            count += 1

        if count:
            logger.info("[pause_primitive] expire_stale() expired %d pause(s).", count)
        return count

    # ------------------------------------------------------------------
    # get_active_pause_count — get count of active pauses (for gauge metric)
    # ------------------------------------------------------------------

    async def get_active_pause_count(self) -> int:
        """Return the count of active (non-expired) pauses.

        Used for the Prometheus gauge `cage_governance_active_pauses`.

        Returns:
            Count of active pauses.
        """
        now = time.time()
        # Count members in the zset with expiry > now
        return await self._redis.zcount(_EXPIRY_ZSET, now, "+inf")


# ---------------------------------------------------------------------------
# Module-level helper for building resume endpoint URL
# ---------------------------------------------------------------------------


def build_resume_endpoint(pause_token: str) -> str:
    """Build the resume endpoint URL for a pause token.

    Args:
        pause_token: The pause_token UUID.

    Returns:
        URL path for POST /v1/pause/{pause_token}/resume.
    """
    return f"/v1/pause/{pause_token}/resume"
