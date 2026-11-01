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
consequence_authority_store.py — Single use of consequence authority records

ConsequenceGateway executes an action only after consume_once() wins for the
ConsequenceToken's ``rec`` claim. Adapters set ``rec`` to the provider's
per-determination receipt id (provider_01: the partner's authority receipt),
never to a field that may name a mandate. Each determination is therefore
consumed once, and two determinations under one mandate don't collide.

Mechanism: plain ``SET NX EX`` followed by ``WAIT``. No Lua runs on the normal
path. The one script is the compare-and-set below, and it runs only for a
marker recovered from a lost reply.

  - Marker: ``SET <key> <binding>:<op id> NX EX <ttl>``. The write that wins is
    the one consumption. The binding hash, SHA-256 over (thread_id, actor_id,
    action_digest, state_version), lets the gateway tell a replay (same
    binding) from a substitution (different binding).
  - Retry-safe: the per-attempt op id lets a SET that redis-py re-sends after
    a lost reply recognise its own write instead of reading it as a replay
    (redis_single_use).
  - Replica-acknowledged: when the replication policy waits for replicas
    (``CAGE_REDIS_WAIT_REPLICAS`` > 0), the winning write is followed by
    ``WAIT``, sent once on the socket that carried it (redis_replication).
    A marker recovered from a lost reply was written on an earlier socket.
    It is re-asserted on the current socket first, by a compare-and-set
    script that writes only if the marker is still this attempt's.
  - Strict replication (``CAGE_STRICT_REPLICATION``): a short or failed
    acknowledgement raises ConsumptionNotReplicatedError. Nothing executes and
    the marker stays, so the record stays consumed. It is never deleted to
    allow a retry. A lenient policy logs the shortfall, counts it, and
    proceeds, as CBF commits do.
  - Fail-closed: Redis errors propagate. consume_once() never answers True or
    False on a Redis failure.

Key schema:
  flowsignal:token:<rec>  →  "<SHA-256 binding hash>:<op id>"   (TTL 90 s)

The 90 s TTL is 1.5 times the ConsequenceToken's 60 s lifetime, so a token
always expires before its marker. That suffices while ``rec`` names one
determination. Retaining the marker for a record's whole validity needs the
partner's receipt-validity rules (POAM-2026-156 item 2, POAM-2026-113).

Usage:
  store = ConsequenceAuthorityStore.from_env()
  binding = ConsequenceAuthorityStore.binding_hash(
      thread_id=claims.tid,
      actor_id=claims.sub,
      action_digest=claims.act,
      state_version=claims.ver,
  )
  first_use = await store.consume_once(claims.rec, binding)
  if not first_use:
      # REPLAY if get_binding(claims.rec) == binding, else SUBSTITUTION.
      ...
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import time
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.infrastructure.redis_replication import (
    ReplicationPolicy,
    acknowledged_replicas,
    pinned_connection,
    write_socket,
)
from src.gateway.infrastructure.redis_single_use import (
    NxOutcome,
    new_op_id,
    set_nx_outcome,
    set_nx_retry_safe,
)

logger = logging.getLogger(__name__)

_KEY_PREFIX = "flowsignal:token:"

#: Re-write the marker on the current socket only while it is still ours.
#: The SET advances this connection's replication offset, so the WAIT that
#: follows counts it.
_REASSERT_IF_OURS_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
  return 1
end
return 0
"""

_UNACKNOWLEDGED_COUNTER: Any = None
_WAIT_LATENCY_HISTOGRAM: Any = None

try:
    from prometheus_client import REGISTRY, Counter, Histogram

    def _get_or_create_metric(
        metric_cls: Any, name: str, *args: Any, **kwargs: Any
    ) -> Any:
        try:
            return metric_cls(name, *args, **kwargs)
        except ValueError:
            collector = REGISTRY._names_to_collectors.get(name)
            if collector is not None:
                return collector
            raise

    _UNACKNOWLEDGED_COUNTER = _get_or_create_metric(
        Counter,
        "cage_consequence_consumption_unacknowledged_total",
        "Single-use consumption markers whose replica acknowledgement (WAIT) "
        "fell short or failed, by outcome (refused under strict replication, "
        "proceeded otherwise)",
        ["outcome"],
    )
    _WAIT_LATENCY_HISTOGRAM = _get_or_create_metric(
        Histogram,
        "cage_consequence_wait_latency_seconds",
        "Latency of the WAIT that acknowledges a single-use consumption marker",
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
except ImportError:
    pass


class ConsumptionNotReplicatedError(RuntimeError):
    """A consumption marker was written but not acknowledged by enough replicas.

    Raised only under strict replication. The marker is left in place, so the
    record stays consumed, and the caller must not execute.
    """

    def __init__(self, authority_record_id: str, detail: str) -> None:
        super().__init__(
            f"consumption of {authority_record_id!r} is not replica-acknowledged: "
            f"{detail}"
        )
        self.authority_record_id = authority_record_id
        self.detail = detail


class ConsequenceAuthorityStore:
    """Single-use consumption of consequence authority records (see module docstring).

    Args:
        redis_client: ``redis.asyncio.Redis`` instance (async). When the policy
            waits for replicas, each consumption pins a single-connection
            client from its pool.
        replication: The deployment's replica-acknowledgement policy
            (``ReplicationPolicy.from_env()`` in :meth:`from_env`). Required:
            a store that skipped ``WAIT`` by default would not be durable.
        ttl_seconds: How long a marker is retained (default 90 s).

    Raises:
        ValueError: The policy waits for replicas with a timeout of 0 ms or
            less (``WAIT n 0`` blocks until the socket times out).
    """

    def __init__(
        self,
        redis_client: object,
        *,
        replication: ReplicationPolicy,
        ttl_seconds: int = 90,
    ) -> None:
        if replication.waits and replication.timeout_ms <= 0:
            raise ValueError(
                "ConsequenceAuthorityStore: a WAIT timeout must be positive, got "
                f"{replication.timeout_ms} ms"
            )
        self._redis = redis_client
        self._replication = replication
        self._ttl_seconds = ttl_seconds

    @classmethod
    def from_env(cls) -> ConsequenceAuthorityStore:
        """Construct from the environment.

        Reads ``REDIS_URL``, ``FLOWSIGNAL_CONSUMPTION_TTL_SECONDS`` and the
        replication policy (``CAGE_REDIS_WAIT_REPLICAS``,
        ``CAGE_REDIS_WAIT_TIMEOUT_MS``, ``CAGE_STRICT_REPLICATION``; see
        ``ReplicationPolicy.from_env()``).
        """
        from src.gateway.infrastructure.redis_client import build_async_redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        ttl_seconds = int(os.environ.get("FLOWSIGNAL_CONSUMPTION_TTL_SECONDS", "90"))
        client = build_async_redis(redis_url, socket_timeout=3.0)
        return cls(
            client, replication=ReplicationPolicy.from_env(), ttl_seconds=ttl_seconds
        )

    @staticmethod
    def binding_hash(
        thread_id: str,
        actor_id: str,
        action_digest: str,
        state_version: str | None,
    ) -> str:
        """Return SHA-256 hex digest of the JCS-canonicalized binding tuple.

        Args:
            thread_id: Conversation/request thread identifier.
            actor_id: Actor making the request (agent ID, user ID).
            action_digest: Hash of the action being authorized.
            state_version: The provider's authority state version (or None).

        Returns:
            SHA-256 hex digest (64 hex chars).
        """
        # Normalize None → "" for consistent hashing
        normalized_version = state_version if state_version is not None else ""
        canonical = jcs_canonicalize_plan(
            [thread_id, actor_id, action_digest, normalized_version]
        )
        return hashlib.sha256(canonical).hexdigest()

    async def consume_once(self, authority_record_id: str, binding: str) -> bool:
        """Consume the record once. True only for the consumption that wins.

        Args:
            authority_record_id: The token's ``rec`` claim: the provider's
                per-determination receipt id.
            binding: SHA-256 binding hash (from binding_hash()).

        Returns:
            True if this call wrote the marker (including a re-send after a
            lost reply) and, when the policy waits for replicas, the write was
            acknowledged or the policy is lenient. False if another
            consumption holds the marker.

        Raises:
            ConsumptionNotReplicatedError: Strict replication, and the marker
                was not acknowledged by enough replicas. The marker stays.
            Exception: Redis connection/timeout errors. Never silently returns
                True/False on Redis failure; callers must fail closed.
        """
        key = f"{_KEY_PREFIX}{authority_record_id}"
        # The binding plus a per-attempt op id: a SET re-sent after a lost
        # reply finds this exact marker and still counts as this consumption.
        marker = f"{binding}:{new_op_id()}"

        try:
            if self._replication.waits:
                won = await self._consume_acknowledged(authority_record_id, key, marker)
            else:
                won = await set_nx_retry_safe(
                    self._redis, key, marker, ex=self._ttl_seconds
                )
        except ConsumptionNotReplicatedError:
            raise
        except Exception as exc:
            # Fail-closed: propagate Redis errors to caller
            logger.error(
                "ConsequenceAuthorityStore.consume_once: Redis error for "
                "authority_record_id=%s: %s — failing closed.",
                authority_record_id,
                exc,
            )
            raise

        if won:
            logger.info(
                "ConsequenceAuthorityStore: CONSUMED authority_record_id=%s binding=%s ttl=%ds",
                authority_record_id,
                binding[:16] + "...",  # Log first 16 chars of hash for audit
                self._ttl_seconds,
            )
        else:
            logger.warning(
                "ConsequenceAuthorityStore: ALREADY_CONSUMED authority_record_id=%s "
                "(replay or substitution attempt)",
                authority_record_id,
            )
        return won

    async def _consume_acknowledged(
        self, authority_record_id: str, key: str, marker: str
    ) -> bool:
        """Write the marker and WAIT for it, both on one pinned socket."""
        pinned, should_close = await pinned_connection(self._redis)
        try:
            outcome = await set_nx_outcome(pinned, key, marker, ex=self._ttl_seconds)
            if outcome is NxOutcome.HELD:
                return False
            if outcome is NxOutcome.RESENT and not await self._reassert(
                pinned, key, marker
            ):
                # The marker expired or another consumption replaced it after
                # the lost reply. This attempt no longer holds the record.
                return False
            # The socket that carried the write, captured before anything else
            # can reach the connection.
            socket = write_socket(pinned)
            await self._acknowledge(pinned, socket, authority_record_id)
            return True
        finally:
            if should_close:
                await pinned.aclose()

    async def _reassert(self, pinned: Any, key: str, marker: str) -> bool:
        """Re-write ``marker`` on the pinned socket if it is still ours."""
        result = pinned.eval(_REASSERT_IF_OURS_LUA, 1, key, marker)
        if inspect.isawaitable(result):
            result = await result
        return bool(result == 1)

    async def _acknowledge(
        self, pinned: Any, socket: object | None, authority_record_id: str
    ) -> None:
        """WAIT for the configured replicas. A shortfall follows the policy."""
        policy = self._replication
        started = time.monotonic()
        try:
            acks = await acknowledged_replicas(
                pinned, socket, policy.replicas, policy.timeout_ms
            )
        except Exception as exc:
            self._observe_wait(started)
            self._unacknowledged(
                authority_record_id, f"WAIT failed ({type(exc).__name__}: {exc})"
            )
            return
        self._observe_wait(started)
        if acks < policy.replicas:
            self._unacknowledged(
                authority_record_id,
                f"{acks} of {policy.replicas} replicas acknowledged within "
                f"{policy.timeout_ms} ms",
            )

    @staticmethod
    def _observe_wait(started: float) -> None:
        if _WAIT_LATENCY_HISTOGRAM is not None:
            _WAIT_LATENCY_HISTOGRAM.observe(time.monotonic() - started)

    def _unacknowledged(self, authority_record_id: str, detail: str) -> None:
        """Refuse under strict replication, else log, count and proceed."""
        strict = self._replication.strict
        if _UNACKNOWLEDGED_COUNTER is not None:
            _UNACKNOWLEDGED_COUNTER.labels(
                outcome="refused" if strict else "proceeded"
            ).inc()
        if strict:
            logger.error(
                "ConsequenceAuthorityStore: CONSUMPTION_NOT_REPLICATED "
                "authority_record_id=%s: %s — refusing; the marker stays.",
                authority_record_id,
                detail,
            )
            raise ConsumptionNotReplicatedError(authority_record_id, detail)
        logger.warning(
            json.dumps(
                {
                    "event": "CONSUMPTION_WAIT_SHORTFALL",
                    "severity": "WARNING",
                    "authority_record_id": authority_record_id,
                    "detail": detail,
                    "strict_replication": False,
                }
            )
        )

    async def get_binding(self, authority_record_id: str) -> str | None:
        """Return the stored binding value for audit/diagnostic use.

        Enables distinguishing BINDING_MISMATCH (substitution) vs ALREADY_CONSUMED
        (replay) in logs and findings.

        Args:
            authority_record_id: Unique identifier for the consequence authority decision.

        Returns:
            SHA-256 binding hash if present, else None.
        """
        key = f"{_KEY_PREFIX}{authority_record_id}"

        try:
            value = await self._redis.get(key)  # type: ignore[attr-defined]
            if value is None:
                return None
            if isinstance(value, bytes):
                value = value.decode()
            # Strip the per-attempt op id that consume_once() appends.
            return value.rsplit(":", 1)[0]
        except Exception as exc:
            logger.error(
                "ConsequenceAuthorityStore.get_binding: Redis error for "
                "authority_record_id=%s: %s",
                authority_record_id,
                exc,
            )
            # For diagnostic/audit use — return None on error (don't propagate)
            return None
