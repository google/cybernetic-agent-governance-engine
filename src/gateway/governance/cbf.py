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
Stateful Redis-backed financial invariant enforcer.

Implements a discrete-time Control Barrier Function (CBF) that uses Redis
for state persistence so that stateless Cloud Run instances share a
consistent cash-balance view.

Phase 1 fix: imports now resolve against the canonical gateway-internal
infrastructure package (``src.gateway.infrastructure.*``) instead of the
cross-package ``src.governed_financial_advisor.*`` path.

Phase 4.1 fix: ``update_state()`` and ``rollback_state()`` use Redis
WATCH / MULTI / EXEC optimistic locking to prevent race conditions under
concurrent trade execution in the stateless Cloud Run environment.
"""

import asyncio
import json
import logging
import math

# ---------------------------------------------------------------------------
# Canonical gateway-internal imports (Phase 1.1)
# ---------------------------------------------------------------------------
import os
import time
from typing import Any

from src.gateway.governance.constants import ControlRegistry, GovernanceControl

# ---------------------------------------------------------------------------
# Threshold singleton (Phase 2.3)
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import THRESHOLDS
from src.gateway.infrastructure.redis_client import redis_client
from src.gateway.infrastructure.telemetry import get_tracer

logger = logging.getLogger("SafetyLayer")

# ---------------------------------------------------------------------------
# Environment detection (module-level so tests can patch it)
# ---------------------------------------------------------------------------
_cage_env_cbf = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _cage_env_cbf not in ("development", "test", "dev", "ci")

# ---------------------------------------------------------------------------
# Feature flag: Replay defense (R-04 mitigation, §2.10)
# ---------------------------------------------------------------------------
# Stage 1 (read-side): When enabled, CBF enforces sequence validation.
_REPLAY_DEFENSE_ENABLED: bool = os.environ.get(
    "CAGE_RECONCILIATION_REPLAY_DEFENSE", "false"
).lower() in ("true", "1", "yes")

# Redis key for tracking last accepted sequence (never TTL'd)
_REDIS_KEY_SEQUENCE_LAST_ACCEPTED = "reconciliation:sequence:last_accepted"

# ---------------------------------------------------------------------------
# Feature flag: Fence epoch validation (R-05 mitigation, §2.6)
# ---------------------------------------------------------------------------
# When enabled, CBF validates fence epoch hasn't regressed after failover.
# This detects stale reads from replicas that haven't caught up to primary.
# DEFAULT CHANGED (peer review Fix A2): Enabled by default to provide failover
# protection out-of-box. Operators can disable with CAGE_REDIS_SYNCHRONOUS_REPLICATION=false.
# Cross-region impact: US_FED, EU_ECB, APAC_MAS all benefit from failover safety.
_FENCE_EPOCH_ENABLED: bool = os.environ.get(
    "CAGE_REDIS_SYNCHRONOUS_REPLICATION", "true"
).lower() in ("true", "1", "yes")

# Redis key for fence epoch counter (never TTL'd)
_REDIS_KEY_FENCE_EPOCH = "safety:fence_epoch"

# ---------------------------------------------------------------------------
# Feature flag: WAIT command replication (Phase 4.3)
# ---------------------------------------------------------------------------
# When CAGE_REDIS_WAIT_REPLICAS > 0, CBF will call Redis WAIT after fence
# epoch increment to ensure the epoch is replicated before returning.
# https://redis.io/commands/wait/
# DEFAULT CHANGED (peer review Fix A1): Enabled by default (1 replica) to ensure
# durability before returning success to caller. Set CAGE_REDIS_WAIT_REPLICAS=0 to disable.
# Cross-region impact: US_FED, EU_ECB, APAC_MAS all benefit from replication guarantee.
_WAIT_REPLICAS: int = int(os.environ.get("CAGE_REDIS_WAIT_REPLICAS", "1"))
_WAIT_TIMEOUT_MS: int = int(os.environ.get("CAGE_REDIS_WAIT_TIMEOUT_MS", "1000"))

# Sentinel awareness (Phase 4.3 stretch goal)
# When set, connection should be Sentinel-aware for automatic failover handling.
_REDIS_SENTINEL_MASTER_NAME: str | None = os.environ.get("REDIS_SENTINEL_MASTER_NAME")

# ---------------------------------------------------------------------------
# Prometheus telemetry for replay defense (§2.10) and WAIT replication (§4.3)
# ---------------------------------------------------------------------------
try:
    from prometheus_client import Counter, Gauge, Histogram

    _REPLAY_REJECTED_COUNTER = Counter(
        "cage_reconciliation_replay_rejected_total",
        "Number of reconciliation payloads rejected due to non-advancing sequence (R-04 replay defense)",
        ["source"],
    )
    # R-05 fence epoch telemetry
    _EPOCH_REGRESSION_COUNTER = Counter(
        "cage_cbf_epoch_regression_detected_total",
        "Number of CBF reads rejected due to fence epoch regression (R-05 double-spend defense)",
    )
    _CURRENT_FENCE_EPOCH_GAUGE = Gauge(
        "cage_cbf_current_fence_epoch",
        "Current value of the CBF fence epoch counter",
    )
    # Phase 4.3: WAIT command telemetry
    _WAIT_LATENCY_HISTOGRAM = Histogram(
        "cage_cbf_wait_latency_seconds",
        "Latency of Redis WAIT command for replication synchronization (Phase 4.3)",
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
    _WAIT_TIMEOUT_COUNTER = Counter(
        "cage_cbf_wait_timeout_total",
        "Number of Redis WAIT commands that timed out before reaching replica count (Phase 4.3)",
    )
except ImportError:
    _REPLAY_REJECTED_COUNTER = None  # type: ignore[assignment]
    _EPOCH_REGRESSION_COUNTER = None  # type: ignore[assignment]
    _CURRENT_FENCE_EPOCH_GAUGE = None  # type: ignore[assignment]
    _WAIT_LATENCY_HISTOGRAM = None  # type: ignore[assignment]
    _WAIT_TIMEOUT_COUNTER = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# ControlBarrierFunction
# ---------------------------------------------------------------------------


class ControlBarrierFunction:
    """Discrete-time Control Barrier Function (CBF).

    Uses Redis for state persistence so that stateless Cloud Run instances
    share a consistent cash-balance view.

    Phase 4.1: ``update_state()`` and ``rollback_state()`` wrap all
    read-modify-write operations in a Redis WATCH / MULTI / EXEC optimistic-
    locking pipeline.  If another process mutates the key between the WATCH
    and the EXEC, the transaction is aborted and retried up to
    ``_MAX_RETRIES`` times before raising ``RuntimeError``.
    """

    _MAX_RETRIES: int = 5

    LUA_ATOMIC_CBF: str = """
-- KEYS[1]: safety:current_cash
-- KEYS[2]: audit:state_ledger
-- KEYS[3]: safety:fence_epoch (R-05)
-- ARGV[1]: cost (float string)
-- ARGV[2]: min_cash_balance (float string)
-- ARGV[3]: gamma (float string)
-- ARGV[4]: governance_signature (string, may be empty)
-- Returns: array {status_code, message, new_balance_str, new_epoch}
--   status_code 1 = COMMITTED, 0 = UNSAFE (envelope violation)
local raw = redis.call('GET', KEYS[1])
local current = raw and tonumber(raw) or 100000.0
local cost = tonumber(ARGV[1]) or 0.0
local min_cash = tonumber(ARGV[2])
local gamma = tonumber(ARGV[3])
local sig = ARGV[4]

local next_cash = current - cost
local h_t = current - min_cash
local h_next = next_cash - min_cash
local required_h_next = (1.0 - gamma) * h_t

-- Read current epoch for return (even on UNSAFE)
local current_epoch_raw = redis.call('GET', KEYS[3])
local current_epoch = current_epoch_raw and tonumber(current_epoch_raw) or 0

if h_next < required_h_next or h_next < 0 then
    return {0, "UNSAFE: h_next=" .. tostring(h_next) .. " < required=" .. tostring(required_h_next), tostring(current), current_epoch}
end

redis.call('SET', KEYS[1], tostring(next_cash))
-- R-05: Increment fence epoch on every mutating write
local new_epoch = redis.call('INCR', KEYS[3])
if sig ~= "" then
    redis.call('RPUSH', KEYS[2], sig .. ":" .. tostring(next_cash))
end
return {1, "COMMITTED", tostring(next_cash), new_epoch}
"""

    def __init__(self):  # type: ignore[no-untyped-def]
        # Thresholds from singleton — no inline literals.
        self.min_cash_balance: float = THRESHOLDS.cbf.min_cash_balance
        self.gamma: float = THRESHOLDS.cbf.gamma
        self.redis_key: str = "safety:current_cash"
        self.tracer = get_tracer("src.gateway.governance.safety")
        self._lua_sha: str | None = None
        # Reviewer note H53: local intra-window debits subtracted from snapshot to prevent double-spend within TTL window.
        self._local_debits: float = 0.0
        # R-05 fence epoch: track last seen epoch to detect regression after failover
        self._last_seen_epoch: int = 0

    async def setup(self) -> None:
        """Bootstrap Redis state if the key is absent (first run)."""
        if redis_client is None:
            logger.error("Redis client unavailable — cannot bootstrap CBF state.")
            return
        if await redis_client.get(self.redis_key) is None:
            await redis_client.set(self.redis_key, "100000.0")
        # Initialize fence epoch if absent (R-05)
        client = redis_client.get_raw_client()
        epoch_raw = await client.get(_REDIS_KEY_FENCE_EPOCH)
        if epoch_raw is None:
            await client.set(_REDIS_KEY_FENCE_EPOCH, "0")
            logger.info("R-05: Initialized fence epoch to 0")

    async def _get_current_cash(self) -> float:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        return await redis_client.get_float(self.redis_key, 100000.0)

    # ------------------------------------------------------------------
    # R-05 Fence Epoch: Double-spend detection across Redis failover
    # ------------------------------------------------------------------

    async def _increment_fence_epoch(self, pipeline: Any) -> int:
        """Increment the fence epoch atomically within the pipeline.

        §2.6 R-05 mitigation: The fence epoch is a monotonically increasing
        counter that increments on every CBF-mutating write. After a Redis
        failover, if a replica hasn't replicated the latest epoch, reads
        from that replica will return a regressed epoch, which we detect
        and reject (fail-closed).

        Args:
            pipeline: Redis pipeline object to queue the INCR command.

        Returns:
            The new epoch value after increment.

        Note:
            The INCR command is atomic and creates the key with value 1 if
            it doesn't exist. The epoch is never TTL'd.
        """
        # Queue INCR in the pipeline — returns new value after increment
        pipeline.incr(_REDIS_KEY_FENCE_EPOCH)
        # The actual value is returned when pipeline.execute() is called
        # Caller must extract from execute() results
        return 0  # Placeholder; actual value comes from pipeline results

    async def _get_fence_epoch(self) -> int:
        """Read the current fence epoch from Redis.

        Returns:
            The current epoch value, or 0 if the key doesn't exist.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        client = redis_client.get_raw_client()
        raw = await client.get(_REDIS_KEY_FENCE_EPOCH)
        if raw is None:
            return 0
        return int(raw)

    async def _check_fence_epoch(self, current_epoch: int) -> tuple[bool, str]:
        """Validate that current fence epoch hasn't regressed.

        §2.6 R-05 mitigation: After a Redis primary-to-replica failover,
        the replica may not have replicated the latest fence epoch. If the
        epoch we read is less than the last epoch we saw, we've likely
        switched to a stale replica. This is a double-spend vulnerability.

        Args:
            current_epoch: The epoch value just read from Redis.

        Returns:
            (True, "OK") if epoch is valid (>= last seen).
            (False, reason) if epoch has regressed (< last seen).

        Side effects:
            - On regression: logs CRITICAL, increments Prometheus counter
            - On valid: updates _last_seen_epoch, updates Prometheus gauge
        """
        if current_epoch < self._last_seen_epoch:
            reason = (
                f"epoch={current_epoch} < last_seen={self._last_seen_epoch} "
                "(possible failover to stale replica)"
            )
            logger.critical(
                json.dumps(
                    {
                        "event": "CBF_EPOCH_REGRESSION_DETECTED",
                        "severity": "CRITICAL",
                        "current_epoch": current_epoch,
                        "last_seen_epoch": self._last_seen_epoch,
                        "audit_note": (
                            "R-05: Fence epoch regression detected. This indicates "
                            "a possible failover to a Redis replica that hasn't "
                            "replicated the latest writes. Rejecting read to prevent "
                            "double-spend vulnerability. Fail-closed."
                        ),
                    }
                )
            )
            if _EPOCH_REGRESSION_COUNTER is not None:
                _EPOCH_REGRESSION_COUNTER.inc()
            return (False, reason)

        # Epoch is valid — update tracking state
        self._last_seen_epoch = current_epoch
        if _CURRENT_FENCE_EPOCH_GAUGE is not None:
            _CURRENT_FENCE_EPOCH_GAUGE.set(current_epoch)

        return (True, "OK")

    # ------------------------------------------------------------------
    # Phase 4.3: WAIT command for synchronous replication
    # ------------------------------------------------------------------

    async def _sync_to_replicas(
        self,
        num_replicas: int | None = None,
        timeout_ms: int | None = None,
    ) -> bool:
        """Block until fence epoch is replicated to at least num_replicas.

        Phase 4.3: Uses Redis WAIT command to ensure the fence epoch increment
        (and any preceding writes) is replicated to the specified number of
        replicas before returning. This provides stronger durability guarantees
        for deployments using Redis replication.

        See: https://redis.io/commands/wait/

        Args:
            num_replicas: Number of replicas to wait for. Defaults to
                          CAGE_REDIS_WAIT_REPLICAS env var (default 0 = disabled).
            timeout_ms: Timeout in milliseconds to wait for replication.
                        Defaults to CAGE_REDIS_WAIT_TIMEOUT_MS env var (default 1000).

        Returns:
            True if replication confirmed to num_replicas within timeout.
            False if timeout elapsed before replication confirmed.
            True (no-op) if num_replicas == 0 (WAIT disabled).

        Note:
            - WAIT returns the number of replicas that acknowledged the write.
            - A return value < num_replicas means some replicas are lagging.
            - Timeout is not an error condition for WAIT; it simply means we
              waited the full duration without reaching the replica count.
        """
        # Use provided values or fall back to module-level config
        replicas = num_replicas if num_replicas is not None else _WAIT_REPLICAS
        timeout = timeout_ms if timeout_ms is not None else _WAIT_TIMEOUT_MS

        # No-op if WAIT is disabled (replicas=0 is the default)
        if replicas <= 0:
            return True

        if redis_client is None:
            logger.warning("Redis client unavailable — cannot execute WAIT command.")
            return False

        client = redis_client.get_raw_client()
        start_time = time.time()

        try:
            # WAIT numreplicas timeout
            # Returns: number of replicas that acknowledged the write
            acks: int = await client.execute_command("WAIT", replicas, timeout)

            elapsed = time.time() - start_time

            # Record latency in Prometheus histogram
            if _WAIT_LATENCY_HISTOGRAM is not None:
                _WAIT_LATENCY_HISTOGRAM.observe(elapsed)

            if acks >= replicas:
                logger.debug(
                    "Phase 4.3: WAIT confirmed replication to %d/%d replicas in %.3fs",
                    acks,
                    replicas,
                    elapsed,
                )
                return True
            else:
                # Timeout elapsed before reaching replica count
                logger.warning(
                    json.dumps(
                        {
                            "event": "CBF_WAIT_TIMEOUT",
                            "severity": "WARNING",
                            "requested_replicas": replicas,
                            "acknowledged_replicas": acks,
                            "timeout_ms": timeout,
                            "elapsed_seconds": round(elapsed, 3),
                            "audit_note": (
                                "Phase 4.3: Redis WAIT timed out before reaching "
                                f"requested replica count. {acks}/{replicas} replicas "
                                "acknowledged. Proceeding with degraded replication."
                            ),
                        }
                    )
                )
                if _WAIT_TIMEOUT_COUNTER is not None:
                    _WAIT_TIMEOUT_COUNTER.inc()
                return False

        except Exception as exc:
            elapsed = time.time() - start_time
            logger.error(
                "Phase 4.3: WAIT command failed after %.3fs: %s",
                elapsed,
                exc,
            )
            # Record the latency even on error
            if _WAIT_LATENCY_HISTOGRAM is not None:
                _WAIT_LATENCY_HISTOGRAM.observe(elapsed)
            return False

    async def _validate_sequence(
        self, incoming_sequence: int, source: str, sync_redis: Any
    ) -> tuple[bool, str]:
        """Validate incoming sequence is strictly greater than last accepted.

        §2.10 R-04 Replay defense: monotonic sequence number validation.
        Prevents replay of stale balance data by rejecting payloads with
        non-advancing sequence numbers.

        Args:
            incoming_sequence: The sequence number in the incoming payload.
            source: Provider source name (for logging).
            sync_redis: Synchronous Redis client for reading/writing sequence.

        Returns:
            (True, "OK") if sequence is advancing.
            (False, reason) if sequence is non-advancing (replay detected).
        """
        try:
            # Read last accepted sequence
            last_accepted_raw = await asyncio.to_thread(
                sync_redis.get,
                _REDIS_KEY_SEQUENCE_LAST_ACCEPTED,  # type: ignore[attr-defined]
            )
            last_accepted = int(last_accepted_raw) if last_accepted_raw else 0

            if incoming_sequence <= last_accepted:
                reason = (
                    f"sequence={incoming_sequence} <= last_accepted={last_accepted}"
                )
                return (False, reason)

            # Update last_accepted atomically
            await asyncio.to_thread(
                sync_redis.set,
                _REDIS_KEY_SEQUENCE_LAST_ACCEPTED,
                str(incoming_sequence),  # type: ignore[attr-defined]
            )
            logger.debug(
                "[R-04] Sequence validated: incoming=%d > last_accepted=%d, updated",
                incoming_sequence,
                last_accepted,
            )
            return (True, "OK")

        except Exception as exc:
            # On error, fail-open to allow balance through (conservative)
            # but log a warning so the issue is visible
            logger.warning(
                "[R-04] Sequence validation error: %s — allowing payload (fail-open)",
                exc,
            )
            return (True, f"validation error (fail-open): {exc}")

    async def _read_cbf_state_atomic(self) -> dict[str, float | str]:
        """Read the CBF cash balance, preferring externally reconciled ground truth.

        Priority order (POAM-023):
          1. ``reconciliation:verified_balance`` — written by the isolated
             reconciliation-worker daemon, KMS-signed, TTL-gated.  When present
             and signature-valid, this is the authoritative balance.
          2. ``safety:current_cash`` — self-reported by the execution system.
             Used only when the reconciled balance is absent or invalid.
             A CRITICAL audit log is emitted so the fallback is always visible
             in Langfuse and SIEM.

        Returns:
            dict with keys:
                ``current_cash`` (float)  — the balance to use in the CBF formula
                ``source``       (str)    — ``"reconciled"`` | ``"reconciled_unsigned"``
                                           | ``"self_reported"``
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")

        # ── Attempt 1: externally reconciled balance (POAM-023) ──────────────
        try:
            # LOW-6 fix: removed inline `import asyncio as _asyncio` — asyncio is
            # already imported at module level.
            from src.compliance_bridge.reconciliation_worker import (
                read_verified_balance,
            )

            # read_verified_balance is synchronous (redis-py sync client).
            # Use sync_redis_client (blocking redis.Redis) — NOT redis_client._get()
            # which returns an aioredis.Redis (async) client whose .get() returns a
            # coroutine instead of a value, causing the JSON parse to fail with:
            #   "the JSON object must be str, bytes or bytearray, not coroutine"
            # (CBF_USING_SELF_REPORTED_BALANCE log sentinel — POAM-023 async bug).
            from src.gateway.infrastructure.redis_client import sync_redis_client

            verified = await asyncio.to_thread(read_verified_balance, sync_redis_client)

            if verified is not None and verified.is_valid:
                if verified.signature:
                    # Verify KMS signature before trusting the balance.
                    try:
                        from src.gateway.governance.kms_signer import (
                            get_governance_signer,
                        )

                        signer = get_governance_signer()
                        payload_dict = {
                            "source": verified.source,
                            "balance_usd": verified.balance_usd,
                            "verified_at": verified.verified_at,
                            "sequence": verified.sequence,  # §2.10: in signed payload
                        }
                        sig_valid = signer.verify(payload_dict, verified.signature)
                        if sig_valid:
                            # ── §2.10 R-04 Replay defense: sequence validation ────
                            if _REPLAY_DEFENSE_ENABLED and verified.sequence > 0:
                                (
                                    sequence_valid,
                                    seq_reason,
                                ) = await self._validate_sequence(
                                    verified.sequence,
                                    verified.source,
                                    sync_redis_client,
                                )
                                if not sequence_valid:
                                    # Replay detected — fall through to self-reported
                                    logger.critical(
                                        json.dumps(
                                            {
                                                "event": "CBF_RECONCILED_BALANCE_SEQUENCE_REPLAY_DETECTED",
                                                "severity": "CRITICAL",
                                                "source": verified.source,
                                                "balance_usd": verified.balance_usd,
                                                "sequence": verified.sequence,
                                                "reason": seq_reason,
                                                "audit_note": (
                                                    "R-04 Replay defense: monotonic sequence "
                                                    "validation FAILED. Payload sequence is "
                                                    "non-advancing. Falling back to self-reported "
                                                    "balance. Possible TTL reset attack or stale replay."
                                                ),
                                            }
                                        )
                                    )
                                    # Increment Prometheus counter for replay rejection
                                    if _REPLAY_REJECTED_COUNTER is not None:
                                        _REPLAY_REJECTED_COUNTER.labels(
                                            source=verified.source
                                        ).inc()
                                    # Fall through to self-reported balance below
                                else:
                                    # Sequence valid — update last_accepted and proceed
                                    logger.info(
                                        "CBF: using externally reconciled balance=%.2f "
                                        "source=%s verified_at=%.0f sequence=%d (KMS signature valid, sequence advancing)",
                                        verified.balance_usd,
                                        verified.source,
                                        verified.verified_at,
                                        verified.sequence,
                                    )
                                    return {
                                        "current_cash": verified.balance_usd,
                                        "source": "reconciled",
                                        "sequence": verified.sequence,
                                    }
                            else:
                                # Replay defense disabled or sequence=0 (backward compat)
                                logger.info(
                                    "CBF: using externally reconciled balance=%.2f "
                                    "source=%s verified_at=%.0f (KMS signature valid)",
                                    verified.balance_usd,
                                    verified.source,
                                    verified.verified_at,
                                )
                                return {
                                    "current_cash": verified.balance_usd,
                                    "source": "reconciled",
                                }
                        else:
                            logger.critical(
                                json.dumps(
                                    {
                                        "event": "CBF_RECONCILED_BALANCE_SIGNATURE_INVALID",
                                        "severity": "CRITICAL",
                                        "source": verified.source,
                                        "balance_usd": verified.balance_usd,
                                        "audit_note": (
                                            "KMS signature on reconciled balance is INVALID. "
                                            "Falling back to self-reported balance. "
                                            "POAM-023: CBF ground truth unverified."
                                        ),
                                    }
                                )
                            )
                    except Exception as sig_exc:
                        logger.critical(
                            json.dumps(
                                {
                                    "event": "CBF_KMS_VERIFY_FAILED",
                                    "severity": "CRITICAL",
                                    "error": str(sig_exc),
                                    "audit_note": (
                                        "KMS signature verification raised an exception. "
                                        "Falling back to self-reported balance. "
                                        "POAM-023: CBF ground truth unverified."
                                    ),
                                }
                            )
                        )
                else:
                    # Unsigned reconciled balance — accept only in dev/test.
                    if _IS_PRODUCTION:
                        logger.critical(
                            json.dumps(
                                {
                                    "event": "CBF_RECONCILED_BALANCE_UNSIGNED_IN_PRODUCTION",
                                    "severity": "CRITICAL",
                                    "source": verified.source,
                                    "balance_usd": verified.balance_usd,
                                    "audit_note": (
                                        "Reconciled balance has no KMS signature in production. "
                                        "Falling back to self-reported balance. "
                                        "POAM-023: CBF ground truth unverified."
                                    ),
                                }
                            )
                        )
                    else:
                        logger.debug(
                            "CBF: using unsigned reconciled balance=%.2f source=%s "
                            "(dev/test mode — KMS signing not required)",
                            verified.balance_usd,
                            verified.source,
                        )
                        return {
                            "current_cash": verified.balance_usd,
                            "source": "reconciled_unsigned",
                        }
        except Exception as recon_exc:
            logger.warning(
                "CBF: reconciled balance read failed (%s) — falling back to "
                "self-reported balance.",
                recon_exc,
            )

        # ── Fallback: self-reported balance (POAM-023 open) ──────────────────
        logger.critical(
            json.dumps(
                {
                    "event": "CBF_USING_SELF_REPORTED_BALANCE",
                    "severity": "CRITICAL",
                    "redis_key": self.redis_key,
                    "audit_note": (
                        "No verified external balance available. "
                        "CBF is evaluating against self-reported safety:current_cash. "
                        "POAM-023 open: CBF ground truth is unverified. "
                        "Set RECONCILIATION_PROVIDER=plaid or =anchorage to close."
                    ),
                }
            )
        )
        # CRIT-4 fix: use public get_raw_client() instead of private _get().
        client = redis_client.get_raw_client()
        async with client.pipeline(transaction=False) as pipe:
            pipe.get(self.redis_key)
            pipe.get(_REDIS_KEY_FENCE_EPOCH)  # R-05: read epoch atomically
            results = await pipe.execute()
        raw_cash = results[0]
        raw_epoch = results[1]
        current_cash = float(raw_cash) if raw_cash is not None else 100000.0
        current_epoch = int(raw_epoch) if raw_epoch is not None else 0

        # ── §2.6 R-05 Fence epoch validation ──────────────────────────────────
        # When CAGE_REDIS_SYNCHRONOUS_REPLICATION is enabled, validate that
        # the fence epoch hasn't regressed (indicating failover to stale replica).
        if _FENCE_EPOCH_ENABLED:
            epoch_valid, epoch_reason = await self._check_fence_epoch(current_epoch)
            if not epoch_valid:
                # Epoch regression detected — fail-closed, return None balance
                # to force caller to reject the action.
                return {
                    "current_cash": None,  # type: ignore[dict-item]
                    "source": "epoch_regression",
                    "fence_epoch": current_epoch,
                    "epoch_reason": epoch_reason,
                }
        else:
            # Epoch tracking without validation (default mode)
            # Still update the gauge for observability
            self._last_seen_epoch = current_epoch
            if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                _CURRENT_FENCE_EPOCH_GAUGE.set(current_epoch)

        return {
            "current_cash": current_cash,
            "source": "self_reported",
            "fence_epoch": current_epoch,
        }

    def get_h(self, cash_balance: float) -> float:
        """Safety function h(x).  Safe when h(x) >= 0."""
        return cash_balance - self.min_cash_balance

    @staticmethod
    def _resolve_trade_cost(action_name: str, payload: dict[str, Any]) -> float:
        """Return the validated cash cost for *action_name*.

        Only ``execute_trade`` carries a cash cost; every other action is 0.
        A non-finite (NaN/inf) or negative ``amount`` is rejected here so it can
        never reach the barrier certificate or the Redis cash-state write. A
        negative cost makes ``next_cash = current - cost`` larger than the
        current balance, so the ``h_next >= (1-gamma)*h_t`` envelope check passes
        and the atomic commit inflates ``safety:current_cash``; a NaN cost makes
        every comparison false, so the barrier also passes and the balance is
        poisoned. This mirrors the finiteness/positive guard that
        ``FiscalLimitGuard.reserve`` already applies to reservations.
        """
        if action_name != "execute_trade":
            return 0.0
        cost = float(payload.get("amount", 0.0))
        if not math.isfinite(cost) or cost < 0:
            raise ValueError(
                f"invalid trade amount {payload.get('amount')!r} — "
                "must be a finite, non-negative number"
            )
        return cost

    # ------------------------------------------------------------------
    # verify_action
    # ------------------------------------------------------------------

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        """Verify an action is safe relative to shared Redis cash state.

        Uses ``_read_cbf_state_atomic()`` to snapshot all state keys in a single
        pipeline round-trip, preventing the race condition where interleaved writes
        between individual GETs cause the barrier certificate to be evaluated
        against an inconsistent state snapshot (H-07).
        """
        state = await self._read_cbf_state_atomic()
        balance_source: str = str(state.get("source", "unknown"))

        # R-05: Handle epoch regression (fail-closed)
        if state.get("current_cash") is None or balance_source == "epoch_regression":
            epoch_reason = state.get("epoch_reason", "unknown")
            fence_epoch = state.get("fence_epoch", 0)
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            result = (
                f"[{GovernanceControl.TRADITIONAL_MRM_VALIDATION.value}] "
                f"{_mrm_meta['primary_framework']} Violation: "
                f"R-05 Fence epoch regression detected (epoch={fence_epoch}). "
                f"Reason: {epoch_reason}. Fail-closed."
            )
            logger.warning("⛔ CBF check rejected: epoch regression — %s", epoch_reason)
            return result

        current_cash = float(state["current_cash"])
        fence_epoch = int(state.get("fence_epoch", 0))

        if self.tracer:
            with self.tracer.start_as_current_span("safety.cbf_check") as span:  # type: ignore[attr-defined]
                # R-05: Add fence epoch to span attributes
                span.set_attribute("cage.cbf.fence_epoch", fence_epoch)
                return await self._do_verify_action(
                    action_name, payload, current_cash, balance_source, span
                )
        else:
            return await self._do_verify_action(
                action_name, payload, current_cash, balance_source, None
            )

    async def _do_verify_action(
        self,
        action_name: str,
        payload: dict[str, Any],
        current_cash: float,
        balance_source: str,
        span: Any,
    ) -> str:
        if span:
            span.set_attribute("safety.cash.current", current_cash)
            # POAM-023: stamp the balance provenance so every CBF decision is
            # auditable — "reconciled" means KMS-signed external ground truth;
            # "self_reported" means the execution system wrote its own balance.
            span.set_attribute("safety.balance.source", balance_source)
            span.set_attribute(
                "safety.balance.reconciled", balance_source == "reconciled"
            )
            # CTRL_MRM_004: CBF is a traditional, deterministic quantitative formula
            # (h(x) = cash_balance - min_cash_balance with static decay g).
            # It falls under SR 26-2 Model Risk Management scope, not agentic ISO 42001.
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            span.set_attribute("governance.control_id", _mrm_meta["internal_id"])
            span.set_attribute("governance.framework", _mrm_meta["primary_framework"])
            span.set_attribute(
                "governance.legacy_citation", _mrm_meta["legacy_citation"]
            )
            span.set_attribute("governance.scope", _mrm_meta["scope"])

        try:
            cost = self._resolve_trade_cost(action_name, payload)
        except (TypeError, ValueError) as exc:
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            result = (
                f"[{GovernanceControl.TRADITIONAL_MRM_VALIDATION.value}] "
                f"{_mrm_meta['primary_framework']} Violation: {exc}"
            )
            logger.warning("⛔ CBF check rejected trade: %s", exc)
            if span:
                span.set_attribute("safety.result", result)
            return result

        # Reviewer note H53: local intra-window debits subtracted from snapshot to prevent double-spend within TTL window.
        effective_balance = current_cash - self._local_debits
        next_cash = effective_balance - cost
        h_t = self.get_h(effective_balance)
        h_next = self.get_h(next_cash)
        required_h_next = (1.0 - self.gamma) * h_t

        logger.info(
            "🛡️ CBF Check | Cash: %.2f (effective=%.2f) → %.2f",
            current_cash,
            effective_balance,
            next_cash,
        )

        result = "SAFE"
        if h_next < required_h_next or h_next < 0:
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            result = (
                f"[{GovernanceControl.TRADITIONAL_MRM_VALIDATION.value}] "
                f"{_mrm_meta['primary_framework']} Violation: "
                f"Safety Violation (RBC/CBF). "
                f"h(next)={h_next:.2f} < threshold={required_h_next:.2f}"
            )
            if h_next < 0 and span:
                span.set_attribute("safety.bankruptcy", True)
                span.set_attribute("safety.bankruptcy_deficit", abs(h_next))

        # H53: accumulate local debit when the trade is approved, so subsequent
        # intra-TTL calls see the already-committed debit against the snapshot.
        if result == "SAFE" and action_name == "execute_trade" and cost > 0:
            self._local_debits += cost

        # Drawdown check — read limit from threshold singleton
        if "drawdown_pct" in payload:
            limit = THRESHOLDS.drawdown.limit
            raw_drawdown = float(payload.get("drawdown_pct", 0.0))
            current_drawdown = raw_drawdown / 100.0
            if current_drawdown > limit:
                msg = f"UNSAFE: Drawdown Violation. {current_drawdown:.2%} > Limit {limit:.2%}"
                logger.warning("⛔ %s", msg)
                result = msg if result == "SAFE" else f"{result}; {msg}"

        if span:
            span.set_attribute("safety.cash.next", next_cash)
            span.set_attribute("safety.barrier.h_next", h_next)
            span.set_attribute("safety.result", result)

        return result

    # ------------------------------------------------------------------
    # _update_state_unsafe — WATCH/MULTI/EXEC atomic transaction (internal)
    # ------------------------------------------------------------------

    async def _update_state_unsafe(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        """Atomically deduct *cost* from the Redis cash balance.

        .. warning::
            **v3.0.0 Breaking Change:** Renamed from ``update_state()`` to
            ``_update_state_unsafe()`` to signal that this method does NOT
            re-verify the CBF safety condition before committing.

            External callers MUST use ``atomic_verify_and_commit()`` instead,
            which collapses the check and commit into a single atomic Redis
            Lua hop, eliminating the TOCTOU window (MED-5 finding).

            This method is retained for internal use by ``rollback_state()``
            where re-verification is not applicable.

        Uses WATCH / MULTI / EXEC optimistic locking.  Retries up to
        ``_MAX_RETRIES`` times if a concurrent writer modified the key.

        Args:
            cost:                 Amount to deduct from the cash balance.
            governance_signature: Optional KMS governance signature to persist
                                  in the ``audit:state_ledger`` RPUSH log.

        Raises:
            RuntimeError: If all retries are exhausted or Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot update CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                async with redis_client.pipeline() as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = float(raw) if raw is not None else 100000.0
                    new_balance = current - cost
                    pipe.multi()
                    pipe.set(self.redis_key, str(new_balance))
                    # R-05: Increment fence epoch on every mutating write
                    pipe.incr(_REDIS_KEY_FENCE_EPOCH)
                    if governance_signature:
                        ledger_entry = json.dumps(
                            {
                                "ts": time.time(),
                                "cost": cost,
                                "new_balance": new_balance,
                                "governance_signature": governance_signature,
                            }
                        )
                        pipe.rpush("audit:state_ledger", ledger_entry)
                    results = await pipe.execute()
                    # R-05: Extract new epoch from pipeline results (index depends on signature)
                    new_epoch = results[1] if results and len(results) > 1 else 0
                    self._last_seen_epoch = new_epoch
                    if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                        _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

                    # Phase 4.3: WAIT for replication if configured
                    wait_result = await self._sync_to_replicas()
                    wait_suffix = (
                        " (WAIT OK)" if _WAIT_REPLICAS > 0 and wait_result else ""
                    )
                    if _WAIT_REPLICAS > 0 and not wait_result:
                        wait_suffix = " (WAIT timeout)"

                    logger.info(
                        "✅ CBF state updated atomically: %.2f → %.2f (epoch=%d, attempt %d)%s",
                        current,
                        new_balance,
                        new_epoch,
                        attempt + 1,
                        wait_suffix,
                    )
                    return
            except Exception as exc:
                # WatchError or transient failure — retry
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF _update_state_unsafe failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    # ------------------------------------------------------------------
    # rollback_state — WATCH/MULTI/EXEC atomic transaction (Phase 4.1)
    # ------------------------------------------------------------------

    def reset_local_debits(self) -> None:
        """Reset the local intra-window debit accumulator to zero.

        Called by the reconciliation daemon on each successful snapshot refresh
        cycle so that the next CBF check starts from the fresh external balance
        rather than accumulating debits across TTL windows indefinitely.

        The daemon should call this immediately after writing a new
        ``reconciliation:verified_balance`` key so that ``verify_action()``
        picks up the refreshed snapshot on the next call.
        """
        self._local_debits = 0.0

    async def rollback_state(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        """Atomically restore *cost* to the Redis cash balance.

        Mirrors ``_update_state_unsafe`` but adds rather than deducts.  Call this
        when a trade was approved by the CBF but failed downstream (e.g.
        broker API error).

        Args:
            cost:                 Amount to restore to the cash balance.
            governance_signature: Optional KMS governance signature to persist
                                  in the ``audit:state_ledger`` RPUSH log.

        Raises:
            RuntimeError: If all retries are exhausted or Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot rollback CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                async with redis_client.pipeline() as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = float(raw) if raw is not None else 100000.0
                    restored = current + cost
                    pipe.multi()
                    pipe.set(self.redis_key, str(restored))
                    # R-05: Increment fence epoch on every mutating write (including rollback)
                    pipe.incr(_REDIS_KEY_FENCE_EPOCH)
                    if governance_signature:
                        ledger_entry = json.dumps(
                            {
                                "ts": time.time(),
                                "cost": cost,
                                "new_balance": restored,
                                "governance_signature": governance_signature,
                                "rollback": True,
                            }
                        )
                        pipe.rpush("audit:state_ledger", ledger_entry)
                    results = await pipe.execute()
                    # R-05: Extract new epoch from pipeline results
                    new_epoch = results[1] if results and len(results) > 1 else 0
                    self._last_seen_epoch = new_epoch
                    if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                        _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

                    # Phase 4.3: WAIT for replication if configured
                    wait_result = await self._sync_to_replicas()
                    wait_suffix = (
                        " (WAIT OK)" if _WAIT_REPLICAS > 0 and wait_result else ""
                    )
                    if _WAIT_REPLICAS > 0 and not wait_result:
                        wait_suffix = " (WAIT timeout)"

                    logger.info(
                        "🔄 CBF state rolled back atomically: %.2f → %.2f (epoch=%d, attempt %d)%s",
                        current,
                        restored,
                        new_epoch,
                        attempt + 1,
                        wait_suffix,
                    )
                    return
            except Exception as exc:
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "⚡ CBF WATCH conflict on rollback attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF rollback_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    # ------------------------------------------------------------------
    # atomic_verify_and_commit — Lua-atomic CBF check+commit (CAGE-SEC-002)
    # ------------------------------------------------------------------

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
    ) -> tuple[bool, str]:
        """Collapse CBF check and state commit into one atomic Redis Lua hop.

        Eliminates the TOCTOU window between ``verify_action()`` (read-only,
        governance check phase) and ``update_state()`` (write, MCP tool handler
        phase) by executing both as a single Lua script inside Redis.

        The Lua script replicates the exact CBF formula:
            h(S(t+1)) >= (1 - g) * h(S(t))   AND   h(S(t+1)) >= 0

        KMS signature verification (proof of compliance) must occur in Python
        before calling this method — Redis Lua has no cryptographic FFI.

        Args:
            action_name:          Name of the action being evaluated (e.g.
                                  ``"execute_trade"``).
            payload:              Action parameters dict; ``payload["amount"]``
                                  is used as the cost for ``execute_trade``.
            governance_signature: Optional KMS governance signature string.
                                  Persisted to ``audit:state_ledger`` on commit.

        Returns:
            ``(True, "COMMITTED")`` on success.
            ``(False, reason_string)`` when the CBF envelope is violated.

        Raises:
            RuntimeError: If Redis is unavailable.
        """
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot run atomic CBF.")

        try:
            cost = self._resolve_trade_cost(action_name, payload)
        except (TypeError, ValueError) as exc:
            reason = f"UNSAFE: {exc}"
            logger.warning("⛔ CBF atomic check rejected trade: %s", exc)
            return (False, reason)

        # R-05: Include fence epoch key for atomic increment in Lua script
        keys = ["safety:current_cash", "audit:state_ledger", _REDIS_KEY_FENCE_EPOCH]
        argv = [
            str(cost),
            str(self.min_cash_balance),
            str(self.gamma),
            governance_signature,
        ]

        # CRIT-4 fix: use public get_raw_client() instead of private _get().
        client = redis_client.get_raw_client()

        async def _run_evalsha() -> list:
            return await client.evalsha(self._lua_sha, len(keys), *keys, *argv)  # type: ignore[arg-type, misc]  # evalsha return type varies by redis-py version

        async def _load_and_run() -> list:
            self._lua_sha = await client.script_load(self.LUA_ATOMIC_CBF)
            return await _run_evalsha()

        if self.tracer:
            with self.tracer.start_as_current_span(  # type: ignore[attr-defined]
                "safety.cbf_atomic_check_commit"
            ) as span:
                span.set_attribute("safety.cash.cost", cost)
                _mrm_meta = ControlRegistry().get_mapping(
                    GovernanceControl.TRADITIONAL_MRM_VALIDATION
                )
                span.set_attribute("governance.control_id", _mrm_meta["internal_id"])
                span.set_attribute(
                    "governance.framework", _mrm_meta["primary_framework"]
                )
                span.set_attribute(
                    "governance.legacy_citation", _mrm_meta["legacy_citation"]
                )
                span.set_attribute("governance.scope", _mrm_meta["scope"])
                # Phase 4.3: Add WAIT replicas to span attributes
                span.set_attribute("cage.cbf.wait_replicas", _WAIT_REPLICAS)
                result_list = await self._evalsha_with_noscript_retry(
                    client, keys, argv, _run_evalsha, _load_and_run
                )
                committed, message = self._parse_lua_result(result_list, span)

                # Phase 4.3: WAIT for replication if configured and committed
                if committed and _WAIT_REPLICAS > 0:
                    wait_result = await self._sync_to_replicas()
                    span.set_attribute("cage.cbf.wait_success", wait_result)
                    if not wait_result:
                        # Log but don't fail — WAIT timeout is degraded, not failed
                        logger.warning(
                            "Phase 4.3: atomic_verify_and_commit completed but WAIT timed out"
                        )

                return (committed, message)
        else:
            result_list = await self._evalsha_with_noscript_retry(
                client, keys, argv, _run_evalsha, _load_and_run
            )
            committed, message = self._parse_lua_result(result_list, None)

            # Phase 4.3: WAIT for replication if configured and committed
            if committed and _WAIT_REPLICAS > 0:
                wait_result = await self._sync_to_replicas()
                if not wait_result:
                    logger.warning(
                        "Phase 4.3: atomic_verify_and_commit completed but WAIT timed out"
                    )

            return (committed, message)

    async def _evalsha_with_noscript_retry(
        self,
        client: Any,
        keys: list[str],
        argv: list[str],
        run_evalsha_fn: Any,
        load_and_run_fn: Any,
    ) -> list:
        """Load the Lua SHA on first call; retry once on NOSCRIPT error."""
        if self._lua_sha is None:
            self._lua_sha = await client.script_load(self.LUA_ATOMIC_CBF)

        try:
            return await run_evalsha_fn()
        except Exception as exc:
            if "NOSCRIPT" in str(exc):
                logger.warning("⚡ Lua SHA evicted from Redis — reloading script.")
                return await load_and_run_fn()
            raise

    def _parse_lua_result(
        self,
        result_list: list,
        span: Any,
    ) -> tuple[bool, str]:
        """Parse the Lua script return array into a Python (bool, str) tuple."""
        status_code = int(result_list[0])
        message = (
            result_list[1].decode()
            if isinstance(result_list[1], bytes)
            else str(result_list[1])
        )
        new_balance_str = (
            result_list[2].decode()
            if isinstance(result_list[2], bytes)
            else str(result_list[2])
        )
        # R-05: Extract epoch from Lua result (4th element)
        new_epoch = 0
        if len(result_list) > 3:
            epoch_raw = result_list[3]
            new_epoch = int(epoch_raw) if epoch_raw is not None else 0

        committed = status_code == 1
        if span:
            span.set_attribute("safety.result", "COMMITTED" if committed else "UNSAFE")
            span.set_attribute("safety.cash.next", float(new_balance_str))
            # R-05: Add fence epoch to span attributes
            span.set_attribute("cage.cbf.fence_epoch", new_epoch)

        # R-05: Update epoch tracking and telemetry
        if committed and new_epoch > 0:
            self._last_seen_epoch = new_epoch
            if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

        if committed:
            logger.info(
                "✅ CBF atomic check+commit: COMMITTED — new_balance=%s epoch=%d",
                new_balance_str,
                new_epoch,
            )
            return (True, "COMMITTED")
        else:
            logger.info(
                "⛔ CBF atomic check+commit: UNSAFE — %s (epoch=%d)", message, new_epoch
            )
            return (False, message)


# Global singleton
safety_filter = ControlBarrierFunction()
