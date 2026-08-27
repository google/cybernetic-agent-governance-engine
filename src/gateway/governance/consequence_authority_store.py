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
consequence_authority_store.py — Redis-Lua Consumption Store for FlowSignal Tokens

Phase 1 (P0) primitive for atomic single-use consumption of consequence authority tokens.
This is the storage/consumption layer only — token minting, JCS/KMS signing, and wire
protocol integration with FlowSignal are implemented in Phase 2.

Architecture:
  - Atomic single-use marker: uses Redis SET NX EX for lock-free single-key atomicity.
  - Binding hash (not sentinel): stores SHA-256(thread_id:actor_id:action_digest:state_version)
    to enable audit trail distinguishing REPLAY vs SUBSTITUTION attacks.
  - TTL: 90s (1.5x the 60s JWS TTL mentioned in the FlowSignal integration plan, per
    R4 safety margin).
  - Fail-closed: Redis connection/timeout errors propagate as exceptions; never silently
    return True/False on Redis failure.

Key schema:
  flowsignal:token:<authority_record_id>  → SHA-256 binding hash (TTL: 90s)

Usage (Phase 2 integration point):
  store = ConsequenceAuthorityStore.from_env()
  binding = ConsequenceAuthorityStore.binding_hash(
      thread_id=ctx.thread_id,
      actor_id=ctx.actor_id,
      action_digest=action_hash,
      state_version=authority_response.version,
  )

  first_use = await store.consume_once(authority_record_id="fs-token-uuid", binding=binding)
  if not first_use:
      # Either REPLAY (same binding) or SUBSTITUTION (different binding)
      stored = await store.get_binding(authority_record_id="fs-token-uuid")
      if stored == binding:
          raise ConsequenceReplayError("Token already consumed")
      else:
          raise ConsequenceSubstitutionError("Binding mismatch — substitution attack")
"""

from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)


class ConsequenceAuthorityStore:
    """Atomic single-use consumption store for FlowSignal consequence authority tokens.

    Provides fail-closed, atomic single-use enforcement with binding-value integrity.
    Uses Redis SET NX EX for lock-free single-key atomicity (no WATCH/MULTI/EXEC overhead).

    Args:
        redis_client: redis.asyncio.Redis instance (async).
        ttl_seconds: How long to retain consumption markers (default 90s).
    """

    def __init__(self, redis_client: object, ttl_seconds: int = 90) -> None:
        self._redis = redis_client
        self._ttl_seconds = ttl_seconds

    @classmethod
    def from_env(cls) -> ConsequenceAuthorityStore:
        """Construct from REDIS_URL and FLOWSIGNAL_CONSUMPTION_TTL_SECONDS env vars.

        Returns:
            ConsequenceAuthorityStore instance with async Redis client.
        """
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "redis-py is required for ConsequenceAuthorityStore. "
                "Install with: pip install redis"
            ) from exc

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        ttl_seconds = int(os.environ.get("FLOWSIGNAL_CONSUMPTION_TTL_SECONDS", "90"))
        client = aioredis.from_url(redis_url, decode_responses=True)
        return cls(client, ttl_seconds=ttl_seconds)

    @staticmethod
    def binding_hash(
        thread_id: str,
        actor_id: str,
        action_digest: str,
        state_version: str | None,
    ) -> str:
        """Return SHA-256 hex digest of the binding tuple.

        Args:
            thread_id: Conversation/request thread identifier.
            actor_id: Actor making the request (agent ID, user ID).
            action_digest: Hash of the action being authorized.
            state_version: FlowSignal authority state version (or None).

        Returns:
            SHA-256 hex digest (64 hex chars).
        """
        # Normalize None → "" for consistent hashing
        normalized_version = state_version if state_version is not None else ""
        payload = f"{thread_id}:{actor_id}:{action_digest}:{normalized_version}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def consume_once(self, authority_record_id: str, binding: str) -> bool:
        """Atomically consume the authority token for the given record ID.

        Uses Redis SET NX EX for lock-free atomicity. If the key already exists
        (consumed by another request), this returns False.

        Args:
            authority_record_id: Unique identifier for the consequence authority
                decision (e.g., UUID from FlowSignal response).
            binding: SHA-256 binding hash (from binding_hash()).

        Returns:
            True if this call won the race (first consumption, key was set).
            False if already consumed/contended (key already exists).

        Raises:
            Exception on Redis connection/timeout errors. Never silently returns
            True/False on Redis failure — callers must apply fail-closed policy.
        """
        key = f"flowsignal:token:{authority_record_id}"

        # SET key value NX EX ttl_seconds
        # Returns True if key was set (first consumption), False if key exists.
        try:
            result = await self._redis.set(  # type: ignore[attr-defined]
                key,
                binding,
                nx=True,  # Only set if key does NOT exist
                ex=self._ttl_seconds,  # Expiry in seconds
            )

            success = bool(result)

            if success:
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

            return success

        except Exception as exc:
            # Fail-closed: propagate Redis errors to caller
            logger.error(
                "ConsequenceAuthorityStore.consume_once: Redis error for "
                "authority_record_id=%s: %s — failing closed.",
                authority_record_id,
                exc,
            )
            raise

    async def get_binding(self, authority_record_id: str) -> str | None:
        """Return the stored binding value for audit/diagnostic use.

        Enables distinguishing BINDING_MISMATCH (substitution) vs ALREADY_CONSUMED
        (replay) in logs and findings.

        Args:
            authority_record_id: Unique identifier for the consequence authority decision.

        Returns:
            SHA-256 binding hash if present, else None.
        """
        key = f"flowsignal:token:{authority_record_id}"

        try:
            value = await self._redis.get(key)  # type: ignore[attr-defined]
            return value if value is not None else None
        except Exception as exc:
            logger.error(
                "ConsequenceAuthorityStore.get_binding: Redis error for "
                "authority_record_id=%s: %s",
                authority_record_id,
                exc,
            )
            # For diagnostic/audit use — return None on error (don't propagate)
            return None
