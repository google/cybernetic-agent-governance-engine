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
defer_queue.py — DEFER State Machine Primitive (CAGE v0.1.0)

AARM Conformance: Satisfies the "Deferral Service" mandate from the CSA AARM
specification — a formal state for situational ambiguity or data starvation that
avoids forcing a brittle binary allow/deny choice.

Architecture:
  CAGE's Layer 3 tri-state decision (ALLOW | DENY | MANUAL_REVIEW) is extended to
  four states by adding DEFER. DEFER activates when OPA would return MANUAL_REVIEW
  but the accompanying confidence score is below the "Confidence-Starvation Boundary"
  threshold (default: 0.70 — see UCA-7 in ontology.py).

  Confidence-Starvation Boundary (approved architectural decision, CAGE v0.1.0):
    ≥ 0.95  →  ALLOW/DENY (Autonomous Clearance via system_authz.rego)
    0.70–0.95 → MANUAL_REVIEW (human operator sign-off required)
    < 0.70  →  DEFER (context fundamentally corrupted or missing critical state;
                        forcing human review at this confidence creates operational
                        fatigue — route to automated data-hydration loop instead)

  The DeferToken is parked in Redis database index ``db=1`` with a ``noeviction``
  maxmemory policy (separate from the LangGraph checkpointer at db=0) to prevent
  eviction interference during high-throughput scaling events.

  Data structures:
    Redis Hash   DEFER:{defer_id}        — full DeferToken JSON
    Redis ZSet   DEFER:expiry_index      — member=defer_id, score=expiry_unix_ts

  Pending tokens are resolved by:
    (a) Human-in-the-loop step-up via POST /v1/defer/{id}/escalate
    (b) Automated data injection sweep via POST /v1/defer/{id}/inject

ISO 42001 mapping: A.8.4 (AI System Operation Controls) — formal pause is an
operation control that prevents unsafe execution under ambiguous context.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.gateway.infrastructure.redis_client import TransactionAbortedError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis key prefixes — isolated in db=1 (noeviction)
# ---------------------------------------------------------------------------

_KEY_PREFIX = "DEFER:"
_EXPIRY_ZSET = "DEFER:expiry_index"
_DEFAULT_TTL = 3600 * 4  # 4-hour park window before stale escalation

# ---------------------------------------------------------------------------
# DeferReason — why the execution graph was halted
# ---------------------------------------------------------------------------


class DeferReason(str, Enum):
    """Enumeration of root causes for a DEFER decision.

    Maps to AARM threat vector annotations on OTel spans.
    """

    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    """OPA input snapshot is missing required fields for a deterministic decision."""

    AMBIGUOUS_SEMANTIC_DISTANCE = "AMBIGUOUS_SEMANTIC_DISTANCE"
    """vLLM sidecar semantic similarity score is within the ambiguity band (0.40–0.60)."""

    DATA_STARVATION = "DATA_STARVATION"
    """Langfuse telemetry evidence window is empty or below minimum sample threshold."""

    CONFIDENCE_BELOW_THRESHOLD = "CONFIDENCE_BELOW_THRESHOLD"
    """model confidence_score < DEFER_CONFIDENCE_THRESHOLD (default 0.70)."""

    EXTERNAL_VALIDATION = "EXTERNAL_VALIDATION"
    """Consensus score in ambiguous zone (0.70–0.95); awaiting external FRIA gate."""


# ---------------------------------------------------------------------------
# DeferToken — the parked execution context
# ---------------------------------------------------------------------------


class DeferToken(BaseModel):
    """Immutable snapshot of an execution context parked in the DEFER queue.

    Fields:
        defer_id            — stable UUID v4 assigned at park time.
        thread_id           — LangGraph thread (checkpoint) ID for the paused graph.
        defer_reason        — root cause from DeferReason enum.
        opa_input_snapshot  — sanitised copy of the OPA input dict at decision time
                              (PII fields stripped; fiscal amounts preserved).
        semantic_distance   — vLLM cosine distance score [0, 1] at decision time,
                              or None if the sidecar was unavailable.
        confidence_score    — model self-reported confidence [0, 1].
        deferred_at_utc     — ISO-8601 UTC timestamp when the token was parked.
        ttl_seconds         — how long before the token is considered stale and
                              auto-escalated to MANUAL_REVIEW.
        resolved_at_utc     — ISO-8601 UTC when the token was resolved, or None.
        resolution          — "ESCALATED" | "INJECTED" | "EXPIRED" | None.
        aarm_vector         — AARM threat vector tag for OTel span annotation.
    """

    defer_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    thread_id: str
    defer_reason: DeferReason
    opa_input_snapshot: dict[str, Any] = Field(default_factory=dict)
    semantic_distance: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    deferred_at_utc: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    ttl_seconds: int = Field(default=_DEFAULT_TTL)
    resolved_at_utc: str | None = None
    resolution: str | None = None
    aarm_vector: str = "AARM-V7"  # Context Window Overflow


# ---------------------------------------------------------------------------
# DeferQueue — Redis-backed token registry
# ---------------------------------------------------------------------------


class DeferQueue:
    """Redis-backed DEFER token queue with TTL-scored expiry.

    Mandatory deployment configuration:
        Redis database: ``db=1`` (isolated from LangGraph checkpointer at db=0)
        maxmemory-policy: ``noeviction``  (fail-safe — block on OOM rather than
                                           silently dropping execution contexts)

    Args:
        redis_client: An aioredis or redis-py async client connected to ``db=1``.
                      Callers are responsible for connection lifecycle.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    # ------------------------------------------------------------------
    # park — add a deferred token to the queue
    # ------------------------------------------------------------------

    async def park(self, token: DeferToken) -> str:
        """Park a DeferToken in Redis.

        Args:
            token: The fully constructed DeferToken.

        Returns:
            The ``defer_id`` of the parked token.

        Raises:
            TransactionAbortedError: The Redis WATCH/MULTI/EXEC transaction was
                aborted because a concurrent writer modified a watched key.  The
                caller should treat this as a retriable condition.
        """
        key = f"{_KEY_PREFIX}{token.defer_id}"
        expiry_ts = time.time() + token.ttl_seconds
        token_json = token.model_dump_json()

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.hset(key, mapping={"token": token_json, "status": "PARKED"})
                pipe.expire(key, token.ttl_seconds)
                pipe.zadd(_EXPIRY_ZSET, {token.defer_id: expiry_ts})
                await pipe.execute()
        except TransactionAbortedError:
            logger.warning(
                "[defer_queue] park() transaction aborted for defer_id=%s thread_id=%s — "
                "returning DeferResult.ABORTED",
                token.defer_id,
                token.thread_id,
            )
            raise

        logger.info(
            "[defer_queue] Parked token defer_id=%s thread_id=%s reason=%s "
            "confidence=%.3f ttl=%ds",
            token.defer_id,
            token.thread_id,
            token.defer_reason.value,
            token.confidence_score or -1.0,
            token.ttl_seconds,
        )
        return token.defer_id

    # ------------------------------------------------------------------
    # resolve — mark a parked token as resolved
    # ------------------------------------------------------------------

    async def resolve(
        self,
        defer_id: str,
        resolution: str,  # "ESCALATED" | "INJECTED" | "EXPIRED"
        injection_data: dict | None = None,
    ) -> DeferToken | None:
        """Resolve a parked DeferToken.

        Args:
            defer_id:       The token's defer_id.
            resolution:     Resolution type string.
            injection_data: Optional data payload for INJECTED resolutions.

        Returns:
            The updated DeferToken, or None if the token was not found.
        """
        key = f"{_KEY_PREFIX}{defer_id}"
        raw = await self._redis.hget(key, "token")
        if raw is None:
            logger.warning(
                "[defer_queue] resolve() called for unknown defer_id=%s", defer_id
            )
            return None

        token = DeferToken.model_validate_json(raw)
        token.resolved_at_utc = datetime.now(tz=timezone.utc).isoformat()
        token.resolution = resolution

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.hset(
                    key,
                    mapping={
                        "token": token.model_dump_json(),
                        "status": "RESOLVED",
                        **(
                            {"injection_data": json.dumps(injection_data)}
                            if injection_data
                            else {}
                        ),
                    },
                )
                pipe.zrem(_EXPIRY_ZSET, defer_id)
                await pipe.execute()
        except TransactionAbortedError:
            logger.warning(
                "[defer_queue] resolve() transaction aborted for defer_id=%s resolution=%s — "
                "returning DeferResult.ABORTED",
                defer_id,
                resolution,
            )
            raise

        logger.info(
            "[defer_queue] Resolved defer_id=%s resolution=%s thread_id=%s",
            defer_id,
            resolution,
            token.thread_id,
        )
        return token

    # ------------------------------------------------------------------
    # get — fetch a single token by ID
    # ------------------------------------------------------------------

    async def get(self, defer_id: str) -> DeferToken | None:
        """Fetch a single token by defer_id.

        Returns None if not found (expired or never parked).
        """
        key = f"{_KEY_PREFIX}{defer_id}"
        raw = await self._redis.hget(key, "token")
        if raw is None:
            return None
        return DeferToken.model_validate_json(raw)

    # ------------------------------------------------------------------
    # list_pending — return all unresolved tokens
    # ------------------------------------------------------------------

    async def list_pending(
        self,
        limit: int = 100,
        include_expired: bool = False,
    ) -> list[DeferToken]:
        """Return pending (PARKED) tokens, ordered by expiry deadline (soonest first).

        Args:
            limit:           Maximum number of tokens to return.
            include_expired: If True, include tokens past their TTL deadline.

        Returns:
            List of DeferToken objects, soonest-expiring first.
        """
        now = time.time()
        max_ts = "+inf" if include_expired else now
        members = await self._redis.zrangebyscore(
            _EXPIRY_ZSET, "-inf", max_ts, start=0, num=limit
        )

        tokens: list[DeferToken] = []
        for defer_id in members:
            key = f"{_KEY_PREFIX}{defer_id}"
            raw = await self._redis.hget(key, "token")
            if raw:
                tokens.append(DeferToken.model_validate_json(raw))

        return tokens

    # ------------------------------------------------------------------
    # expire_stale — sweep and escalate tokens past their TTL
    # ------------------------------------------------------------------

    async def expire_stale(self) -> int:
        """Sweep the expiry index for tokens past their TTL and mark them EXPIRED.

        Called periodically by the SLA monitor background task.

        Returns:
            Count of tokens that were expired and escalated.
        """
        now = time.time()
        members = await self._redis.zrangebyscore(_EXPIRY_ZSET, "-inf", now)

        count = 0
        for defer_id in members:
            resolved = await self.resolve(defer_id, "EXPIRED")
            if resolved:
                count += 1
                logger.warning(
                    "[defer_queue] Token expired and auto-escalated: defer_id=%s thread_id=%s",
                    defer_id,
                    resolved.thread_id,
                )

        if count:
            logger.info("[defer_queue] expire_stale() swept %d stale token(s).", count)
        return count


# ---------------------------------------------------------------------------
# DEFER_CONFIDENCE_THRESHOLD — module-level constant
# ---------------------------------------------------------------------------

#: The "Confidence-Starvation Boundary" (CAGE v0.1.0 architectural decision).
#: Execution context with confidence below this threshold routes to DEFER rather
#: than MANUAL_REVIEW, preventing operational fatigue from fundamentally incomplete
#: context windows. See UCA-7 in src/gateway/governance/ontology.py.
DEFER_CONFIDENCE_THRESHOLD: float = 0.70


# ---------------------------------------------------------------------------
# replay_evaluate — Phase 3 of the confidence-score replay flow
# ---------------------------------------------------------------------------


class ReplayResult(str, Enum):
    """Outcome of a replay_evaluate() call.

    ADMITTED:  The enriched context raised effective confidence above
               DEFER_CONFIDENCE_THRESHOLD; the token has been resolved
               with resolution="INJECTED" and removed from the DEFER queue.
    PARKED:    Effective confidence is still below the threshold; the token
               remains in Redis db=1 awaiting further hydration or escalation.
    NOT_FOUND: No token with the given defer_id exists in the queue.
    """

    ADMITTED = "ADMITTED"
    PARKED = "PARKED"
    NOT_FOUND = "NOT_FOUND"


async def replay_evaluate(
    queue: DeferQueue,
    defer_id: str,
    enriched_context: dict[str, Any],
) -> ReplayResult:
    """Phase 3 — Re-evaluate a parked token against the confidence threshold.

    This is the canonical re-evaluation entry point for the three-phase
    confidence-score replay flow (CAGE v0.1.0):

      Phase 1 — PARK:    Token with confidence < DEFER_CONFIDENCE_THRESHOLD
                         is parked in Redis db=1 via DeferQueue.park().
      Phase 2 — HYDRATE: Out-of-band context enrichment raises effective
                         confidence (caller responsibility).
      Phase 3 — REPLAY:  This function.  Reads the effective confidence from
                         ``enriched_context["confidence_score"]`` and compares
                         it against DEFER_CONFIDENCE_THRESHOLD (0.70).

    Decision logic:
      - If ``enriched_context["confidence_score"] >= DEFER_CONFIDENCE_THRESHOLD``:
          Calls ``queue.resolve(defer_id, "INJECTED", injection_data=enriched_context)``
          to remove the token from the DEFER queue and returns ``ReplayResult.ADMITTED``.
      - If the effective confidence is still below the threshold:
          The token remains PARKED; returns ``ReplayResult.PARKED``.
      - If the token is not found (expired or never parked):
          Returns ``ReplayResult.NOT_FOUND``.

    Args:
        queue:            A ``DeferQueue`` instance connected to Redis db=1.
        defer_id:         The ``defer_id`` of the parked token to re-evaluate.
        enriched_context: Dict produced by the hydration step.  Must contain
                          ``"confidence_score"`` (float in [0, 1]).  Any
                          additional fields are stored as injection_data on
                          the resolved token for audit purposes.

    Returns:
        A ``ReplayResult`` enum member indicating the outcome.

    ISO 42001 mapping: A.8.4 (AI System Operation Controls) — changed-condition
    replay is a formal re-entry point that prevents indefinite parking of tokens
    whose context has been enriched by automated data-hydration loops.
    """
    token = await queue.get(defer_id)
    if token is None:
        logger.warning(
            "[replay_evaluate] Token not found for defer_id=%s — returning NOT_FOUND.",
            defer_id,
        )
        return ReplayResult.NOT_FOUND

    effective_confidence: float = float(
        enriched_context.get("confidence_score", token.confidence_score or 0.0)
    )

    if effective_confidence >= DEFER_CONFIDENCE_THRESHOLD:
        await queue.resolve(defer_id, "INJECTED", injection_data=enriched_context)
        logger.info(
            "[replay_evaluate] Token ADMITTED: defer_id=%s effective_confidence=%.3f "
            "threshold=%.2f",
            defer_id,
            effective_confidence,
            DEFER_CONFIDENCE_THRESHOLD,
        )
        return ReplayResult.ADMITTED

    logger.info(
        "[replay_evaluate] Token remains PARKED: defer_id=%s effective_confidence=%.3f "
        "threshold=%.2f",
        defer_id,
        effective_confidence,
        DEFER_CONFIDENCE_THRESHOLD,
    )
    return ReplayResult.PARKED
