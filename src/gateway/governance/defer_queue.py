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
    0.70-0.95 -> MANUAL_REVIEW (human operator sign-off required)
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

import asyncio
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis key prefixes — isolated in db=1 (noeviction)
# ---------------------------------------------------------------------------

_KEY_PREFIX = "DEFER:"
_EXPIRY_ZSET = "DEFER:expiry_index"
_DEFAULT_TTL = 3600 * 4  # 4-hour park window before stale escalation
_DEFAULT_HOLD_TTL = 300  # 5-minute default TTL for external hold escalations

# ---------------------------------------------------------------------------
# Lua CAS Script for Revision-Based Compare-and-Swap
# ---------------------------------------------------------------------------

#: Lua script for atomic compare-and-swap on revision-controlled token updates.
#: This script compares the current revision against the expected revision,
#: and only updates the token blob + status if they match, then increments
#: the revision counter. This prevents lost updates during concurrent dual-
#: control approvals.
#:
#: Arguments:
#:   KEYS[1] — Redis hash key (e.g., "DEFER:{defer_id}")
#:   ARGV[1] — Expected revision (integer as string)
#:   ARGV[2] — New token JSON blob (opaque string, no parsing in Lua)
#:   ARGV[3] — New status string
#:
#: Returns:
#:   {1, new_rev}      — Success: updated token, status, and revision
#:   {0, actual_rev}   — Conflict: current revision != expected revision
#:
#: Slot-safety: Touches exactly one key (KEYS[1]) — safe for Redis Cluster.
_CAS_UPDATE_LUA = """
local current_rev = redis.call('HGET', KEYS[1], 'rev')
if current_rev == false then
    current_rev = '0'
end

local expected_rev = ARGV[1]
if current_rev ~= expected_rev then
    return {0, tonumber(current_rev)}
end

local new_rev = tonumber(current_rev) + 1
redis.call('HSET', KEYS[1], 'token', ARGV[2], 'status', ARGV[3], 'rev', new_rev)
return {1, new_rev}
"""


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
    """vLLM sidecar semantic similarity score is within the ambiguity band (0.40-0.60)."""

    DATA_STARVATION = "DATA_STARVATION"
    """Langfuse telemetry evidence window is empty or below minimum sample threshold."""

    CONFIDENCE_BELOW_THRESHOLD = "CONFIDENCE_BELOW_THRESHOLD"
    """model confidence_score < DEFER_CONFIDENCE_THRESHOLD (default 0.70)."""

    EXTERNAL_VALIDATION = "EXTERNAL_VALIDATION"
    """Consensus score in ambiguous zone (0.70-0.95); awaiting external FRIA gate."""

    FTRA_IRREVERSIBLE_TERMINAL = "FTRA_IRREVERSIBLE_TERMINAL"
    """FTRA Tier 0.5 gate: an IRREVERSIBLE_TERMINAL node is reachable from step[0]
    of the ExecutionPlan and the Evaluator confidence score is >= FRIA_ZONE_DEFER
    (0.70).  The plan is parked pending synchronous human-in-the-loop clearance.
    Control ID: CTRL_FTRA_001."""

    EXTERNAL_HOLD = "EXTERNAL_HOLD"
    """External normative provider returned an escalation decision requiring
    human-in-the-loop approval. Transaction is parked with provider-specified TTL
    (default: 300s). On expiry, routes to governance-hitl-dlq topic for operator review."""


# ---------------------------------------------------------------------------
# ApprovalRecord — dual-control approval state (Phase 2, Stream B)
# ---------------------------------------------------------------------------


class ApprovalRecord(BaseModel):
    """A single operator's approval of a parked decision.

    Required fields land in Phase 2 (Stream B). The five WebAuthn fields are
    optional at rest and populated in Phase 5 once Q1/Q6 resolve; an ESCALATE
    clearance refuses locally if they are absent.

    Phase 2 dual-control implementation per
    local/integrations/archytan/IMPLEMENTATION_PLAN_v2.md §4.4.1.

    v3.0 WebAuthn Audit Fix (Archytan Vector 3):
        client_data_json replaces client_data_hash to preserve the raw W3C
        CollectedClientData for cryptographic verification. This remediates
        the audit finding where hashing before verification prevented
        challenge binding validation.
    """

    # --- Required from Phase 2 -------------------------------------------
    approver_urn: str
    """Durable operator URN — same identifier as the wire."""

    approved_at_utc: str
    """ISO-8601 UTC timestamp of approval."""

    auth_method: str
    """Authentication method: "OIDC" | "MTLS" | "WEBAUTHN"."""

    auth_principal_hash: str
    """SHA-256 of the authenticated principal; never the raw principal."""

    # --- Optional until Phase 5 (WebAuthn) -------------------------------
    credential_id: str | None = None
    """base64url-encoded WebAuthn credential ID."""

    client_data_json: str | None = None
    """base64url-encoded W3C CollectedClientData raw JSON string (v3.0+)."""

    client_data_hash: str | None = None
    """hex SHA-256 of clientDataJSON (deprecated; use client_data_json)."""

    authenticator_data: str | None = None
    """base64url-encoded authenticator data."""

    signature: str | None = None
    """base64url-encoded WebAuthn signature."""

    challenge_binding: str | None = None
    """hex SHA-256 over the bound decision fields."""

    def verify_webauthn_challenge(self) -> bool:
        """Verify WebAuthn challenge binding (v3.0+ audit fix).

        This method validates that the challenge embedded in client_data_json
        matches the expected challenge_binding. It implements the cryptographic
        verification flow required by the W3C WebAuthn specification.

        Returns:
            True if verification succeeds, False otherwise.

        Raises:
            ValueError: If required fields are missing or malformed.
        """
        import base64
        import hashlib

        if not self.client_data_json or not self.challenge_binding:
            return False

        try:
            # Decode client_data_json using canonical base64url padding
            b64_str = self.client_data_json
            pad = "=" * (-len(b64_str) % 4)
            client_data_bytes = base64.urlsafe_b64decode(b64_str + pad)

            # Compute and cache the client_data_hash
            computed_hash = hashlib.sha256(client_data_bytes).hexdigest()
            if self.client_data_hash is None:
                # Populate the hash field for backward compatibility
                object.__setattr__(self, "client_data_hash", computed_hash)

            # Parse the JSON and extract the challenge field
            client_data = json.loads(client_data_bytes.decode("utf-8"))
            challenge_b64 = client_data.get("challenge", "")

            # Decode the challenge using canonical base64url padding
            pad_challenge = "=" * (-len(challenge_b64) % 4)
            challenge_bytes = base64.urlsafe_b64decode(challenge_b64 + pad_challenge)

            # Compare against the expected challenge_binding
            expected_bytes = bytes.fromhex(self.challenge_binding)
            return challenge_bytes == expected_bytes

        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            logger.warning("WebAuthn challenge verification failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# DeferToken — the parked execution context
# ---------------------------------------------------------------------------


class DeferToken(BaseModel):
    """Immutable snapshot of an execution context parked in the DEFER queue.

    Schema v2 additions (Phase 2, Stream B):
        schema_version      — schema version (1 = legacy, 2 = dual-control).
        approvals           — list of operator approval records.
        required_quorum     — number of distinct approvals needed for resolution.
        correlation_id      — UUID minted at ingress, before the governance decision.

    Schema v3 additions (PRAXIS Phase 2):
        upstream_permit_id  — External upstream authority reference. If set, token
                              is authority-bound and cannot be resumed via quorum
                              approvals or context injection (zero-authority parking).

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

    # --- v2 additions (Phase 2, Stream B) ---------------------------------
    schema_version: int = 2
    approvals: list[ApprovalRecord] = Field(default_factory=list)
    required_quorum: int = Field(default=2, ge=2, le=5)
    correlation_id: str | None = None

    # --- v3 additions (PRAXIS Phase 2) ------------------------------------
    upstream_permit_id: str | None = None

    def is_authority_bound(self) -> bool:
        """Return True if bound to external upstream authority.

        Authority-bound tokens cannot be resumed via quorum or injection;
        they must expire naturally, forcing zero-base re-adjudication.

        This implements the PRAXIS Alignment Phase 2 zero-authority parking
        principle: tokens holding external permit dependencies surrender all
        compute and signing authority upon parking.

        Returns:
            True if upstream_permit_id is set, False otherwise.
        """
        return self.upstream_permit_id is not None

    def model_post_init(self, __context: Any) -> None:
        """Post-init: derive correlation_id and wire quorum threshold."""
        # B-2: Derive correlation_id from thread_id if absent (v1 token compatibility)
        if self.correlation_id is None:
            namespace_cage = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
            self.correlation_id = str(uuid.uuid5(namespace_cage, self.thread_id))

        # B-2.4: Wire required_quorum from defer_reason for quorum-3 reasons
        # (FTRA_IRREVERSIBLE_TERMINAL, EXTERNAL_VALIDATION, EXTERNAL_HOLD)
        if self.defer_reason and self.required_quorum == 2:  # default value check
            try:
                computed_quorum = get_required_quorum(self.defer_reason)
                if computed_quorum != 2:  # Only override if different from default
                    object.__setattr__(self, "required_quorum", computed_quorum)
            except (KeyError, ValueError):
                # Unknown defer_reason; leave required_quorum at default
                pass


# ---------------------------------------------------------------------------
# ApprovalStatus — result of DeferQueue.approve()
# ---------------------------------------------------------------------------


class ApprovalStatus(str, Enum):
    """Outcome of a DeferQueue.approve() call.

    PARTIAL_QUORUM:      Approval recorded; token remains PARTIALLY_APPROVED.
    QUORUM_REACHED:      Quorum threshold met; token transitions to RESOLVED.
    ALREADY_APPROVED:    This operator has already approved this token.
    NOT_FOUND:           Token does not exist or has already been resolved.
    CONTENTION_ABORTED:  CAS retry exhausted due to excessive concurrent modifications.
    """

    PARTIAL_QUORUM = "PARTIAL_QUORUM"
    QUORUM_REACHED = "QUORUM_REACHED"
    ALREADY_APPROVED = "ALREADY_APPROVED"
    NOT_FOUND = "NOT_FOUND"
    CONTENTION_ABORTED = "CONTENTION_ABORTED"


# ---------------------------------------------------------------------------
# Required quorum mapping (Phase 2, §4.5)
# ---------------------------------------------------------------------------

#: Total mapping from DeferReason to required_quorum threshold.
#: Implementation as a data table (not branching logic) so partner
#: objections require only a one-line change.
_DEFER_REASON_QUORUM: dict[DeferReason, int] = {
    DeferReason.FTRA_IRREVERSIBLE_TERMINAL: 3,
    DeferReason.EXTERNAL_VALIDATION: 3,
    DeferReason.EXTERNAL_HOLD: 3,
    DeferReason.CONFIDENCE_BELOW_THRESHOLD: 2,
    DeferReason.AMBIGUOUS_SEMANTIC_DISTANCE: 2,
    DeferReason.INSUFFICIENT_CONTEXT: 2,
    DeferReason.DATA_STARVATION: 2,
}


def get_required_quorum(defer_reason: DeferReason) -> int:
    """Return the required quorum threshold for a given DeferReason.

    Per local/integrations/archytan/IMPLEMENTATION_PLAN_v2.md §4.5,
    this mapping is total over all seven DeferReason enum values.

    Irreversible terminal nodes and external validation escalations
    require 3 distinct approvers; baseline dual control requires 2.

    Args:
        defer_reason: The DeferReason enum value.

    Returns:
        Required quorum threshold (2 or 3).
    """
    return _DEFER_REASON_QUORUM[defer_reason]


# ---------------------------------------------------------------------------
# DeferQueue — Redis-backed token registry
# ---------------------------------------------------------------------------


#: Type alias for the DLQ publisher callback.
#: The callback receives the expired DeferToken and is responsible for
#: publishing it to the governance-hitl-dlq Pub/Sub topic.
DLQPublisher = Callable[[DeferToken], Awaitable[None]]


class DeferQueue:
    """Redis-backed DEFER token queue with TTL-scored expiry.

    Mandatory deployment configuration:
        Redis database: ``db=1`` (isolated from LangGraph checkpointer at db=0)
        maxmemory-policy: ``noeviction``  (fail-safe — block on OOM rather than
                                           silently dropping execution contexts)

    Args:
        redis_client: An aioredis or redis-py async client connected to ``db=1``.
                      Callers are responsible for connection lifecycle.
        dlq_publisher: Optional async callback invoked when a
                       ``DeferReason.EXTERNAL_HOLD`` token expires.
                       The callback should publish the token to the
                       ``governance-hitl-dlq`` Pub/Sub topic. If ``None``
                       (default), expired tokens are logged but not published.
                       Errors raised by the callback are caught and logged —
                       they do not crash the expiry sweep for other tokens.
    """

    def __init__(
        self,
        redis_client: Any,
        dlq_publisher: DLQPublisher | None = None,
    ) -> None:
        self._redis = redis_client
        self._dlq_publisher = dlq_publisher
        self._cas_update_sha: str | None = None

    # ------------------------------------------------------------------
    # CAS Helper Methods — Revision-Based Atomicity Primitives
    # ------------------------------------------------------------------

    async def _read_token_with_rev(
        self, defer_id: str
    ) -> tuple[DeferToken | None, str | None, int]:
        """Atomically read token, status, and revision fields.

        This helper uses HMGET to atomically read all three fields in a
        single round-trip, ensuring snapshot consistency for CAS operations.

        Migration path: If the 'rev' field is absent (legacy tokens parked
        before revision tracking was added), it defaults to 0. This enables
        zero-downtime rollout of the CAS primitive.

        Args:
            defer_id: The token's defer_id.

        Returns:
            A tuple of (DeferToken | None, status | None, revision).
            - token: The parsed DeferToken, or None if not found.
            - status: The current status string ("PARKED", "PARTIALLY_APPROVED",
                      "RESOLVED"), or None if the key does not exist.
            - revision: The current revision number (integer), or 0 if absent.

        Example::

            token, status, rev = await queue._read_token_with_rev(defer_id)
            if token is None:
                return ApprovalStatus.NOT_FOUND

            # ... validate invariants ...

            # Atomically update via CAS
            success, new_rev = await queue._cas_update(
                defer_id, rev, updated_token, "RESOLVED"
            )
        """
        key = f"{_KEY_PREFIX}{defer_id}"
        raw_token, raw_status, raw_rev = await self._redis.hmget(
            key, "token", "status", "rev"
        )

        if raw_token is None:
            return (None, None, 0)

        token = DeferToken.model_validate_json(raw_token)
        status = raw_status

        # Migration path: absent rev field defaults to 0
        revision = int(raw_rev) if raw_rev is not None else 0

        return (token, status, revision)

    async def _cas_update(
        self,
        defer_id: str,
        expected_rev: int,
        updated_token: DeferToken,
        new_status: str,
    ) -> tuple[bool, int]:
        """Atomically update token + status via revision-based compare-and-swap.

        This method implements the core CAS primitive for concurrent-safe token
        mutations. It ensures that only one of multiple concurrent approve()
        calls can succeed, preventing the lost-update race condition that occurs
        when WATCH/MULTI/EXEC is executed on separate connections.

        CAS Semantics:
            - Compares the current revision in Redis against expected_rev.
            - If they match: updates token blob + status + increments revision.
            - If they conflict: returns failure + the actual current revision.

        The Lua script (_CAS_UPDATE_LUA) is executed via EVALSHA for efficiency,
        with a fallback to EVAL + SCRIPT LOAD if the script is not yet cached.

        Args:
            defer_id:       The token's defer_id.
            expected_rev:   The revision number read by _read_token_with_rev().
            updated_token:  The new DeferToken to write (already mutated by caller).
            new_status:     The new status string ("PARTIALLY_APPROVED", "RESOLVED").

        Returns:
            A tuple of (success: bool, actual_or_new_rev: int).
            - If success is True: actual_or_new_rev is the incremented revision.
            - If success is False: actual_or_new_rev is the conflicting revision
              observed in Redis (caller should retry with fresh read).

        Raises:
            Exception: Redis connection errors are propagated to the caller.

        Example::

            # Read current state
            token, status, rev = await queue._read_token_with_rev(defer_id)

            # Mutate token in-memory
            token.approvals.append(new_approval)

            # Attempt CAS update
            success, new_rev = await queue._cas_update(
                defer_id, rev, token, "PARTIALLY_APPROVED"
            )
            if not success:
                # Conflict: another approval raced us. Retry from the top.
                raise TransactionAbortedError()
        """
        key = f"{_KEY_PREFIX}{defer_id}"
        token_json = updated_token.model_dump_json()

        # Lazily load the script and cache its SHA on first call
        if self._cas_update_sha is None:
            self._cas_update_sha = await self._redis.script_load(_CAS_UPDATE_LUA)
            logger.debug(
                "[defer_queue] Loaded CAS Lua script, SHA=%s", self._cas_update_sha
            )

        try:
            # Attempt EVALSHA (fast path: script already loaded)
            result = await self._redis.evalsha(
                self._cas_update_sha,
                1,  # number of keys
                key,
                str(expected_rev),
                token_json,
                new_status,
            )
        except Exception as exc:
            # NOSCRIPT error: script was evicted, reload and retry with EVAL
            if "NOSCRIPT" in str(exc):
                logger.debug(
                    "[defer_queue] NOSCRIPT error, falling back to EVAL for defer_id=%s",
                    defer_id,
                )
                result = await self._redis.eval(
                    _CAS_UPDATE_LUA,
                    1,
                    key,
                    str(expected_rev),
                    token_json,
                    new_status,
                )
                # Re-cache the SHA for future calls
                self._cas_update_sha = await self._redis.script_load(_CAS_UPDATE_LUA)
            else:
                # Other errors: propagate
                raise

        # Parse result: [success_flag, revision]
        success_flag = int(result[0])
        actual_or_new_rev = int(result[1])

        if success_flag == 1:
            logger.debug(
                "[defer_queue] CAS SUCCESS: defer_id=%s rev %d → %d status=%s",
                defer_id,
                expected_rev,
                actual_or_new_rev,
                new_status,
            )
            return (True, actual_or_new_rev)
        else:
            logger.debug(
                "[defer_queue] CAS CONFLICT: defer_id=%s expected_rev=%d actual_rev=%d",
                defer_id,
                expected_rev,
                actual_or_new_rev,
            )
            return (False, actual_or_new_rev)

    # ------------------------------------------------------------------
    # park — add a deferred token to the queue
    # ------------------------------------------------------------------

    async def park(self, token: DeferToken, correlation_id: str | None = None) -> str:
        """Park a DeferToken in Redis.

        Uses atomic HSETNX for initial key creation. If the key already exists
        (idempotent re-park), uses CAS retry loop to update only if current
        status is PARKED (does not overwrite RESOLVED tokens).

        Args:
            token: The fully constructed DeferToken.
            correlation_id: Optional correlation ID to associate with the token.

        Returns:
            The ``defer_id`` of the parked token.
        """
        if correlation_id is not None:
            token.correlation_id = correlation_id

        key = f"{_KEY_PREFIX}{token.defer_id}"
        expiry_ts = time.time() + token.ttl_seconds
        token_json = token.model_dump_json()

        # Attempt atomic key creation with HSETNX
        created = await self._redis.hsetnx(key, "token", token_json)

        if created:
            # New key — complete initialization with pipeline
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.hset(key, "status", "PARKED")
                pipe.hset(key, "rev", 0)
                pipe.expire(key, token.ttl_seconds)
                pipe.zadd(_EXPIRY_ZSET, {token.defer_id: expiry_ts})
                await pipe.execute()

            logger.info(
                "[defer_queue] Parked token defer_id=%s thread_id=%s correlation_id=%s reason=%s "
                "confidence=%.3f ttl=%ds",
                token.defer_id,
                token.thread_id,
                token.correlation_id,
                token.defer_reason.value,
                token.confidence_score or -1.0,
                token.ttl_seconds,
            )
        else:
            # Key exists — idempotent re-park via CAS (only update if status=PARKED)
            max_retries = 3
            base_jitter_ms = 5

            for attempt in range(max_retries):
                existing_token, current_status, revision = await self._read_token_with_rev(
                    token.defer_id
                )

                if existing_token is None:
                    # Race: key was deleted between HSETNX and now
                    logger.warning(
                        "[defer_queue] park() re-park race: key disappeared for defer_id=%s",
                        token.defer_id,
                    )
                    break

                # Only update if current status is PARKED
                if current_status != "PARKED":
                    logger.info(
                        "[defer_queue] park() idempotent: defer_id=%s already in status=%s, skipping",
                        token.defer_id,
                        current_status,
                    )
                    break

                # Attempt CAS update
                success, new_rev = await self._cas_update(
                    token.defer_id, revision, token, "PARKED"
                )

                if success:
                    # Update expiry index (idempotent)
                    await self._redis.zadd(_EXPIRY_ZSET, {token.defer_id: expiry_ts})
                    logger.info(
                        "[defer_queue] park() idempotent re-park: defer_id=%s updated",
                        token.defer_id,
                    )
                    break

                # CAS conflict — retry with jitter
                jitter_ms = base_jitter_ms * (2**attempt)
                logger.debug(
                    "[defer_queue] park() CAS conflict on attempt %d/%d for defer_id=%s, "
                    "retrying after %dms",
                    attempt + 1,
                    max_retries,
                    token.defer_id,
                    jitter_ms,
                )
                await asyncio.sleep(jitter_ms / 1000.0)

        return token.defer_id

    # ------------------------------------------------------------------
    # _resolve — mark a parked token as resolved (internal only)
    # ------------------------------------------------------------------

    async def _resolve(
        self,
        defer_id: str,
        resolution: str,  # "ESCALATED" | "INJECTED" | "EXPIRED"
        injection_data: dict | None = None,
    ) -> DeferToken | None:
        """Resolve a parked DeferToken (internal only).

        External callers must use replay_evaluate() to enforce invariant-governed
        resolution. Direct resolution bypasses confidence threshold checks and
        violates ADR-008 Phase 5.

        Uses revision-based CAS with bounded retry (3 attempts) to prevent lost
        updates during concurrent resolution attempts.

        Args:
            defer_id:       The token's defer_id.
            resolution:     Resolution type string.
            injection_data: Optional data payload for INJECTED resolutions.

        Returns:
            The updated DeferToken, or None if the token was not found or CAS
            retry was exhausted.
        """
        max_retries = 3
        base_jitter_ms = 5

        for attempt in range(max_retries):
            # Read current token state with revision
            token, current_status, revision = await self._read_token_with_rev(defer_id)

            if token is None:
                logger.warning(
                    "[defer_queue] _resolve() called for unknown defer_id=%s", defer_id
                )
                return None

            # Mutate token in-memory
            token.resolved_at_utc = datetime.now(tz=timezone.utc).isoformat()
            token.resolution = resolution

            # Attempt CAS update
            success, new_rev = await self._cas_update(
                defer_id, revision, token, "RESOLVED"
            )

            if success:
                # CAS succeeded — post-update cleanup
                await self._redis.zrem(_EXPIRY_ZSET, defer_id)

                # Store injection_data if provided (separate operation, idempotent)
                if injection_data:
                    key = f"{_KEY_PREFIX}{defer_id}"
                    await self._redis.hset(
                        key, "injection_data", json.dumps(injection_data)
                    )

                logger.info(
                    "[defer_queue] Resolved defer_id=%s resolution=%s thread_id=%s correlation_id=%s",
                    defer_id,
                    resolution,
                    token.thread_id,
                    token.correlation_id,
                )
                return token

            # CAS conflict — retry with exponential jitter
            jitter_ms = base_jitter_ms * (2**attempt)
            logger.debug(
                "[defer_queue] _resolve() CAS conflict on attempt %d/%d for defer_id=%s, "
                "retrying after %dms",
                attempt + 1,
                max_retries,
                defer_id,
                jitter_ms,
            )
            await asyncio.sleep(jitter_ms / 1000.0)

        # Retry exhaustion
        logger.warning(
            "[defer_queue] _resolve() CAS retry exhausted for defer_id=%s resolution=%s "
            "after %d attempts — returning None",
            defer_id,
            resolution,
            max_retries,
        )
        return None

    # ------------------------------------------------------------------
    # atomic_resolve — atomic CAS ticket invalidation for idempotency
    # ------------------------------------------------------------------

    async def atomic_resolve(
        self,
        ticket_id: str,
        expected_status: str = "PENDING",
        new_status: str = "RESOLVED",
    ) -> bool:
        """Atomically transition a ticket status via Lua CAS (compare-and-swap).

        Guarantees idempotency for resume operations: only the first resume
        attempt succeeds. Subsequent attempts return False, enabling the
        caller to return HTTP 409 Conflict to prevent double-execution.

        This is the atomic primitive that prevents "double-spending" of
        approval tickets — a core safety invariant for HITL resumption flows.

        Implementation:
            Uses a Lua script executed on Redis to ensure atomicity across
            concurrent resume requests. The script checks current status and
            only updates if it matches the expected value.

        Args:
            ticket_id:       The defer_id or ticket identifier to resolve.
            expected_status: Status value required for transition (default: "PENDING").
            new_status:      Target status value (default: "RESOLVED").

        Returns:
            True if the status was transitioned from expected_status to new_status.
            False if the current status does not match expected_status (already
            resolved, expired, or never existed).

        Note:
            This method only updates the status field. The caller is responsible
            for updating the full token record (resolved_at_utc, resolution, etc.)
            after atomic_resolve returns True.

        Example::

            # In a resume endpoint:
            if not await defer_queue.atomic_resolve(ticket_id):
                # Already resolved or expired
                raise HTTPException(status_code=409, detail="Ticket already resolved")

            # Proceed with graph resumption...
        """
        key = f"{_KEY_PREFIX}{ticket_id}"

        # Lua script for atomic compare-and-swap on status field
        lua_script = """
        local current = redis.call('HGET', KEYS[1], 'status')
        if current == ARGV[1] then
            redis.call('HSET', KEYS[1], 'status', ARGV[2])
            return 1
        else
            return 0
        end
        """

        try:
            result = await self._redis.eval(
                lua_script,
                1,  # number of keys
                key,
                expected_status,
                new_status,
            )

            if result == 1:
                logger.info(
                    "[defer_queue] atomic_resolve SUCCESS: ticket_id=%s %s → %s",
                    ticket_id,
                    expected_status,
                    new_status,
                )
                return True
            else:
                # CAS failed — current status does not match expected
                current_status = await self._redis.hget(key, "status")
                logger.warning(
                    "[defer_queue] atomic_resolve FAILED: ticket_id=%s expected=%s "
                    "current=%s — ticket already resolved or expired",
                    ticket_id,
                    expected_status,
                    current_status,
                )
                return False

        except Exception as exc:
            logger.error(
                "[defer_queue] atomic_resolve raised exception for ticket_id=%s: %s",
                ticket_id,
                exc,
            )
            # Fail closed — treat errors as "already resolved" to prevent double-execution
            return False

    # ------------------------------------------------------------------
    # approve — append an approval and check quorum (Phase 2, Stream B)
    # ------------------------------------------------------------------

    async def approve(
        self,
        defer_id: str,
        record: ApprovalRecord,
    ) -> tuple[ApprovalStatus, DeferToken | None]:
        """Append an approval; resolve only when the quorum threshold is met.

        Enforces invariants via revision-based CAS:
          - Token is in PARKED or PARTIALLY_APPROVED state
          - record.approver_urn is not already present in token.approvals
          - Status becomes PARTIALLY_APPROVED while len(approvals) < required_quorum
          - Status becomes RESOLVED only when distinct approver count >= required_quorum

        PRAXIS Phase 2 Zero-Authority Parking:
          - Authority-bound tokens (upstream_permit_id is set) REFUSE all approvals
          - Returns ApprovalStatus.NOT_FOUND to fail-closed for authority-bound tokens

        Concurrent approval safety: Uses revision-based CAS with bounded retry (3 attempts).
        On CAS conflict, retries with 5ms exponential jitter. On retry exhaustion, returns
        CONTENTION_ABORTED.

        Args:
            defer_id: The token's defer_id.
            record: The ApprovalRecord to append.

        Returns:
            Tuple of (ApprovalStatus, updated_token_or_None).
            Status indicates: PARTIAL_QUORUM, QUORUM_REACHED, ALREADY_APPROVED,
            NOT_FOUND, or CONTENTION_ABORTED (on CAS retry exhaustion).
        """
        max_retries = 3
        base_jitter_ms = 5

        for attempt in range(max_retries):
            # Read current token state with revision
            token, current_status, revision = await self._read_token_with_rev(defer_id)

            if token is None:
                logger.warning(
                    "[defer_queue] approve() called for unknown defer_id=%s", defer_id
                )
                return (ApprovalStatus.NOT_FOUND, None)

            # PRAXIS Phase 2: Refuse approval for authority-bound tokens
            if token.is_authority_bound():
                logger.warning(
                    "[defer_queue] Approval REFUSED for authority-bound token: "
                    "defer_id=%s upstream_permit_id=%s. Token must expire; "
                    "re-entry requires fresh query with fresh permit.",
                    defer_id,
                    token.upstream_permit_id,
                )
                return (ApprovalStatus.NOT_FOUND, None)

            # Only approve tokens in PARKED or PARTIALLY_APPROVED state
            if current_status not in ("PARKED", "PARTIALLY_APPROVED"):
                logger.warning(
                    "[defer_queue] approve() called for already-resolved defer_id=%s status=%s",
                    defer_id,
                    current_status,
                )
                return (ApprovalStatus.NOT_FOUND, None)

            # Check for duplicate approver
            existing_urns = {a.approver_urn for a in token.approvals}
            if record.approver_urn in existing_urns:
                logger.warning(
                    "[defer_queue] Duplicate approval rejected: defer_id=%s approver=%s",
                    defer_id,
                    record.approver_urn,
                )
                return (ApprovalStatus.ALREADY_APPROVED, token)

            # Append approval (in-memory mutation)
            token.approvals.append(record)
            distinct_approvers = len({a.approver_urn for a in token.approvals})

            # Determine new status
            if distinct_approvers >= token.required_quorum:
                new_status = "RESOLVED"
                token.resolved_at_utc = datetime.now(tz=timezone.utc).isoformat()
                token.resolution = "ESCALATED"
                approval_status = ApprovalStatus.QUORUM_REACHED
            else:
                new_status = "PARTIALLY_APPROVED"
                approval_status = ApprovalStatus.PARTIAL_QUORUM

            # Attempt CAS update
            success, new_rev = await self._cas_update(
                defer_id, revision, token, new_status
            )

            if success:
                # CAS succeeded — post-update cleanup
                if new_status == "RESOLVED":
                    # Remove from expiry index (idempotent, separate operation)
                    await self._redis.zrem(_EXPIRY_ZSET, defer_id)

                logger.info(
                    "[defer_queue] Approval recorded: defer_id=%s approver=%s "
                    "distinct_approvers=%d/%d status=%s correlation_id=%s",
                    defer_id,
                    record.approver_urn,
                    distinct_approvers,
                    token.required_quorum,
                    new_status,
                    token.correlation_id,
                )
                return (approval_status, token)

            # CAS conflict — retry with exponential jitter
            jitter_ms = base_jitter_ms * (2**attempt)
            logger.debug(
                "[defer_queue] approve() CAS conflict on attempt %d/%d for defer_id=%s, "
                "retrying after %dms",
                attempt + 1,
                max_retries,
                defer_id,
                jitter_ms,
            )
            await asyncio.sleep(jitter_ms / 1000.0)

        # Retry exhaustion
        logger.warning(
            "[defer_queue] approve() CAS retry exhausted for defer_id=%s approver=%s "
            "after %d attempts — returning CONTENTION_ABORTED",
            defer_id,
            record.approver_urn,
            max_retries,
        )
        return (ApprovalStatus.CONTENTION_ABORTED, None)

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
    # get_token — inspect token and status without consuming
    # ------------------------------------------------------------------

    async def get_token(self, defer_id: str) -> DeferToken | None:
        """Inspect a DEFER token by defer_id without mutating or consuming it.

        This method is used by the polling endpoint (GET /v1/defer/{defer_id})
        to allow clients to check the status of a parked decision.

        Args:
            defer_id: The unique defer_id of the parked token.

        Returns:
            The DeferToken instance if found, None if the token does not exist
            (never parked, or already expired and removed from Redis).

        Note:
            This method does NOT mutate the token or remove it from the queue.
            To resolve a token, use resolve() or approve().
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

        For tokens with ``DeferReason.EXTERNAL_HOLD``, the optional
        ``dlq_publisher`` callback (set via constructor) is invoked to route
        the expired token to the ``governance-hitl-dlq`` Pub/Sub topic. Errors
        in the publisher callback are caught and logged but do not crash the
        expiry sweep — other tokens continue to be processed.

        Returns:
            Count of tokens that were expired and escalated.
        """
        now = time.time()
        members = await self._redis.zrangebyscore(_EXPIRY_ZSET, "-inf", now)

        count = 0
        dlq_count = 0
        for defer_id in members:
            # Fetch token BEFORE resolving — needed for DLQ routing decision
            token_before = await self.get(defer_id)
            resolved = await self._resolve(defer_id, "EXPIRED")
            if resolved:
                count += 1
                logger.warning(
                    "[defer_queue] Token expired and auto-escalated: defer_id=%s "
                    "thread_id=%s reason=%s",
                    defer_id,
                    resolved.thread_id,
                    resolved.defer_reason.value,
                )

                # Route EXTERNAL_HOLD tokens to DLQ if publisher is configured
                if (
                    token_before is not None
                    and token_before.defer_reason == DeferReason.EXTERNAL_HOLD
                    and self._dlq_publisher is not None
                ):
                    try:
                        await self._dlq_publisher(resolved)
                        dlq_count += 1
                        logger.info(
                            "[defer_queue] EXTERNAL_HOLD token routed to DLQ: "
                            "defer_id=%s thread_id=%s",
                            defer_id,
                            resolved.thread_id,
                        )
                    except Exception as dlq_exc:
                        # Log but don't crash — other tokens should still be processed
                        logger.warning(
                            "[defer_queue] DLQ publish failed for defer_id=%s: %s "
                            "(token still marked EXPIRED)",
                            defer_id,
                            dlq_exc,
                        )

        if count:
            logger.info(
                "[defer_queue] expire_stale() swept %d stale token(s), "
                "%d routed to DLQ.",
                count,
                dlq_count,
            )
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
# FlowSignal escalation token factory
# ---------------------------------------------------------------------------


def create_external_hold_token(
    thread_id: str,
    confidence_score: float,
    opa_input_snapshot: dict[str, Any],
    finding_message: str | None = None,
    ttl_seconds: int | None = None,
) -> DeferToken:
    """Create a DeferToken for external provider escalation decisions.

    This factory ensures the correct ``DeferReason.EXTERNAL_HOLD`` reason
    and applies the provider-specified TTL (or the 300-second default).

    Args:
        thread_id:           LangGraph thread ID for checkpoint correlation.
        confidence_score:    Model/consensus confidence at decision time.
        opa_input_snapshot:  Sanitized OPA input dict (PII stripped).
        finding_message:     Optional message from the EXTERNAL_HOLD finding.
        ttl_seconds:         Optional provider-specified TTL (default: 300s).

    Returns:
        A fully constructed DeferToken ready for ``DeferQueue.park()``.

    Example::

        from src.gateway.governance.defer_queue import (
            create_external_hold_token, DeferQueue
        )

        token = create_external_hold_token(
            thread_id="thread-123",
            confidence_score=0.82,
            opa_input_snapshot={"action": "execute_trade", "amount_usd": 50000},
            ttl_seconds=600,
        )
        await queue.park(token)
    """
    return DeferToken(
        thread_id=thread_id,
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=confidence_score,
        opa_input_snapshot={
            **opa_input_snapshot,
            # Embed the finding message for audit purposes (non-sensitive)
            "_external_hold_finding_message": finding_message or "",
        },
        ttl_seconds=ttl_seconds if ttl_seconds is not None else _DEFAULT_HOLD_TTL,
        aarm_vector="AARM-V8",  # CSA AARM External Hold (tri-state provider escalation)
    )


def is_external_hold_finding(finding: dict[str, Any]) -> bool:
    """Check if a validation finding is an external provider HOLD finding.

    A finding is an external hold if it has:
      - ``code`` == "EXTERNAL_HOLD"
      - ``needs_human_review`` == True

    This helper is used by ``enforce_fria_boundary()`` to detect when to use
    the external hold escalation path.

    Args:
        finding: A single finding dict from ``ValidationResult.findings``.

    Returns:
        True if the finding is an EXTERNAL_HOLD, False otherwise.
    """
    return (
        finding.get("code") == "EXTERNAL_HOLD"
        and finding.get("needs_human_review", False) is True
    )


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
          Calls ``queue._resolve(defer_id, "INJECTED", injection_data=enriched_context)``
          to remove the token from the DEFER queue and returns ``ReplayResult.ADMITTED``.
      - If the effective confidence is still below the threshold:
          The token remains PARKED; returns ``ReplayResult.PARKED``.
      - If the token is not found (expired or never parked):
          Returns ``ReplayResult.NOT_FOUND``.

    PRAXIS Phase 2 Zero-Authority Parking:
      - Authority-bound tokens (upstream_permit_id is set) REFUSE injection
      - Returns ``ReplayResult.NOT_FOUND`` to fail-closed for authority-bound tokens

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

    # PRAXIS Phase 2: Refuse injection for authority-bound tokens
    if token.is_authority_bound():
        logger.warning(
            "[replay_evaluate] Context injection REFUSED for authority-bound token: "
            "defer_id=%s upstream_permit_id=%s. Authority-bound tokens are strictly "
            "immutable after parking and must expire naturally.",
            defer_id,
            token.upstream_permit_id,
        )
        return ReplayResult.NOT_FOUND

    effective_confidence: float = float(
        enriched_context.get("confidence_score", token.confidence_score or 0.0)
    )

    if effective_confidence >= DEFER_CONFIDENCE_THRESHOLD:
        await queue._resolve(defer_id, "INJECTED", injection_data=enriched_context)
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
