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

"""Stateful Redis-backed invariant-parametric Control Barrier Function (CBF) engine.

Implements a discrete-time Control Barrier Function enforcing
h(S(t+1)) >= (1 - gamma) * h(S(t)) >= 0 for all t >= 0, gamma in (0, 1).
Parameterized by a domain-contributed ``InvariantModel`` and ``cost_resolver``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
import inspect
import json
import logging
import math
import os
import time
from typing import Any

from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import InvariantModel
from src.gateway.governance.schemas.thresholds import THRESHOLDS
from src.gateway.infrastructure.redis_client import redis_client, sync_redis_client
from src.gateway.infrastructure.telemetry import get_tracer

logger = logging.getLogger("SafetyLayer")

_cage_env_cbf = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _cage_env_cbf not in ("development", "test", "dev", "ci")

_CBF_STRICT_MODE: bool = os.environ.get(
    "CAGE_CBF_STRICT_MODE", "true" if _IS_PRODUCTION else "false"
).lower() in ("true", "1", "yes")

_REPLAY_DEFENSE_ENABLED: bool = os.environ.get(
    "CAGE_RECONCILIATION_REPLAY_DEFENSE", "false"
).lower() in ("true", "1", "yes")

_REDIS_KEY_SEQUENCE_LAST_ACCEPTED = "reconciliation:sequence:last_accepted"

_FENCE_EPOCH_ENABLED: bool = os.environ.get(
    "CAGE_REDIS_SYNCHRONOUS_REPLICATION", "true"
).lower() in ("true", "1", "yes")

_REDIS_KEY_FENCE_EPOCH = "safety:fence_epoch"
_REDIS_KEY_LOCAL_DEBITS = "cbf:local_debits"

_WAIT_REPLICAS: int = int(os.environ.get("CAGE_REDIS_WAIT_REPLICAS", "1"))
_WAIT_TIMEOUT_MS: int = int(os.environ.get("CAGE_REDIS_WAIT_TIMEOUT_MS", "1000"))

_STRICT_REPLICATION: bool = os.environ.get(
    "CAGE_STRICT_REPLICATION", "true" if _IS_PRODUCTION else "false"
).lower() in ("true", "1", "yes")

_REDIS_SENTINEL_MASTER_NAME: str | None = os.environ.get("REDIS_SENTINEL_MASTER_NAME")

_REPLAY_REJECTED_COUNTER: Any = None
_EPOCH_REGRESSION_COUNTER: Any = None
_CURRENT_FENCE_EPOCH_GAUGE: Any = None
_WAIT_LATENCY_HISTOGRAM: Any = None
_WAIT_TIMEOUT_COUNTER: Any = None
_STRICT_REPLICATION_ROLLBACK_COUNTER: Any = None

try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram

    def _get_or_create_metric(
        metric_cls: Any, name: str, *args: Any, **kwargs: Any
    ) -> Any:
        try:
            return metric_cls(name, *args, **kwargs)
        except (ValueError, Exception):
            collector = REGISTRY._names_to_collectors.get(name)
            if collector is not None:
                return collector
            raise

    _REPLAY_REJECTED_COUNTER = _get_or_create_metric(
        Counter,
        "cage_reconciliation_replay_rejected_total",
        "Number of reconciliation payloads rejected due to non-advancing sequence (R-04 replay defense)",
        ["source"],
    )
    _EPOCH_REGRESSION_COUNTER = _get_or_create_metric(
        Counter,
        "cage_cbf_epoch_regression_detected_total",
        "Number of CBF reads rejected due to fence epoch regression (R-05 double-spend defense)",
    )
    _CURRENT_FENCE_EPOCH_GAUGE = _get_or_create_metric(
        Gauge,
        "cage_cbf_current_fence_epoch",
        "Current value of the CBF fence epoch counter",
    )
    _WAIT_LATENCY_HISTOGRAM = _get_or_create_metric(
        Histogram,
        "cage_cbf_wait_latency_seconds",
        "Latency of Redis WAIT command for replication synchronization (Phase 4.3)",
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
    _WAIT_TIMEOUT_COUNTER = _get_or_create_metric(
        Counter,
        "cage_cbf_wait_timeout_total",
        "Number of Redis WAIT commands that timed out before reaching replica count (Phase 4.3)",
    )
    _STRICT_REPLICATION_ROLLBACK_COUNTER = _get_or_create_metric(
        Counter,
        "cage_cbf_strict_replication_rollback_total",
        "Number of CBF commits rolled back due to WAIT timeout in strict replication mode (P0 hardening)",
    )
except ImportError:
    pass


class GroundTruthUnavailableError(RuntimeError):
    """Raised when CBF cannot verify ground-truth state (fail-closed behavior)."""

    def __init__(self, message: str, cause: Exception | None = None):
        super().__init__(message)
        self.cause = cause


class CBFInitializationError(RuntimeError):
    """Raised when CBF cannot seed its initial fence epoch from Redis."""


async def _get_raw_redis(r: Any) -> Any:
    """Extract raw redis client from wrapper or mock."""
    if r is None:
        return None
    getter = getattr(r, "get_raw_client", None)
    if callable(getter):
        client = getter()
        if inspect.isawaitable(client):
            client = await client
        return client
    return r


class ControlBarrierFunction:
    """Discrete-time invariant-parametric Control Barrier Function (CBF)."""

    _MAX_RETRIES: int = 5

    LUA_ATOMIC_CBF: str = """
-- Parameterized affine barrier script.
-- Driven by InvariantModel: h(x) = state[state_key] - thresholds[threshold_key]
--
-- KEYS[1]: <InvariantModel.state_key> — barrier state variable
-- KEYS[2]: audit:state_ledger
-- KEYS[3]: safety:fence_epoch (R-05)
-- ARGV[1]: magnitude (float string) — deduction amount
-- ARGV[2]: threshold (float string) — <InvariantModel.threshold_key> resolved floor
-- ARGV[3]: gamma (float string) — <InvariantModel.gamma>
-- ARGV[4]: governance_signature (string, may be empty)
-- ARGV[5]: ground_truth_state (float string) -- KMS-verified state from Python
-- ARGV[6]: expected_fence (int string) -- Expected fence epoch for CAS validation
-- Returns: array {status_code, message, new_state_str, new_epoch}
--   status_code 1 = COMMITTED, 0 = UNSAFE (envelope violation)
local expected_fence = tonumber(ARGV[6])
local current_fence_raw = redis.call('GET', KEYS[3])
local current_fence = current_fence_raw and tonumber(current_fence_raw) or 0
if current_fence ~= expected_fence then
    return {0, "Fence epoch regression: expected " .. tostring(expected_fence) .. ", got " .. tostring(current_fence), "0", current_fence}
end

local current = tonumber(ARGV[5])
if not current then
    return {0, "Ground truth balance unavailable", "0", current_fence}
end
local cost = tonumber(ARGV[1]) or 0.0
local threshold = tonumber(ARGV[2])
local gamma = tonumber(ARGV[3])
local sig = ARGV[4]

local next_state = current - cost
local h_t = current - threshold
local h_next = next_state - threshold
local required_h_next = (1.0 - gamma) * h_t

if h_next < required_h_next or h_next < 0 then
    return {0, "UNSAFE: h_next=" .. tostring(h_next) .. " < required=" .. tostring(required_h_next), tostring(current), current_fence}
end

redis.call('SET', KEYS[1], tostring(next_state))
local new_epoch = redis.call('INCR', KEYS[3])
if sig ~= "" then
    redis.call('RPUSH', KEYS[2], sig .. ":" .. tostring(next_state))
end
return {1, "COMMITTED", tostring(next_state), new_epoch}
"""

    def __init__(
        self,
        invariant: InvariantModel | None = None,
        cost_resolver: Any = None,
        skip_epoch_seed: bool = False,
    ) -> None:
        if invariant is None:
            raise ValueError(
                "ControlBarrierFunction requires an explicit InvariantModel instance"
            )
        self._invariant = invariant
        self._cost_resolver = cost_resolver or self._default_cost_resolver
        self._gamma_override: float | None = None
        self._threshold_override: float | None = None

        # Validate threshold_key resolves at construction time
        _ = self._resolve_threshold()

        self.tracer: Any = get_tracer("src.gateway.governance.safety")
        self._lua_sha: str | None = None
        self._local_debits: float = 0.0
        self._last_seen_epoch: int = self._fetch_initial_fence_epoch_sync(
            skip_epoch_seed
        )
        self._last_verified_fence_epoch: int | None = None

    @property
    def invariant(self) -> InvariantModel:
        """Return the declarative InvariantModel enforced by this engine."""
        return self._invariant

    @property
    def threshold_key(self) -> str:
        """Threshold key derived from invariant model."""
        return self._invariant.threshold_key

    def _resolve_threshold(self) -> float:
        if self._threshold_override is not None:
            return self._threshold_override
        try:
            return float(THRESHOLDS.resolve(self._invariant.threshold_key))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"Unknown threshold_key {self._invariant.threshold_key!r} on InvariantModel"
            ) from exc

    @property
    def threshold_value(self) -> float:
        """Resolved numeric barrier floor for this invariant."""
        return self._resolve_threshold()

    @threshold_value.setter
    def threshold_value(self, value: float) -> None:
        self._threshold_override = float(value)

    def _initial_state_scalar(self) -> float:
        init_val = getattr(self._invariant, "initial_state", None)
        if isinstance(init_val, (int, float)) and math.isfinite(init_val):
            return float(init_val)
        return self._resolve_threshold() * 2.0

    @property
    def gamma(self) -> float:
        """CBF gamma derived from invariant model."""
        if self._gamma_override is not None:
            return self._gamma_override
        return self._invariant.gamma

    @gamma.setter
    def gamma(self, value: float) -> None:
        cage_env = os.getenv("CAGE_ENV", "dev").lower()
        if cage_env in ("production", "prod"):
            logger.warning(
                "gamma override in production is unsafe for concurrent requests; "
                "use static configuration (InvariantModel.gamma) instead"
            )
        self._gamma_override = value

    @property
    def redis_key(self) -> str:
        """State key derived from invariant model."""
        return self._invariant.state_key

    def evaluate_barrier(self, state_scalar: float) -> float:
        """Evaluate affine barrier function h(x) = state_scalar - threshold."""
        return float(state_scalar) - self._resolve_threshold()

    def verify_trajectory(
        self,
        trajectory: Sequence[Mapping[str, Any]],
        initial_state: float | None = None,
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Verify a multi-step action trajectory against this barrier.

        Derives the action name from ``step.get("action", "unknown")`` for each
        step and resolves cost via the domain ``cost_resolver``.
        """
        current_state = (
            float(initial_state)
            if initial_state is not None
            else self._initial_state_scalar()
        )
        records: list[dict[str, Any]] = []
        all_safe = True
        for idx, step in enumerate(trajectory):
            action_name = str(step.get("action", "unknown"))
            raw_params = step.get("params", step.get("payload", step))
            payload = dict(raw_params) if isinstance(raw_params, Mapping) else {}
            cost = self._resolve_action_cost(action_name, payload)
            h_t = self.evaluate_barrier(current_state)
            next_state = current_state - cost
            h_next = self.evaluate_barrier(next_state)
            required_h_next = (1.0 - self.gamma) * h_t
            step_safe = not (
                cost > 0 and (h_next < required_h_next or h_next < 0)
            )
            records.append(
                {
                    "step": idx,
                    "action": action_name,
                    "cost": cost,
                    "state_before": current_state,
                    "state_after": next_state if step_safe else current_state,
                    "h_t": h_t,
                    "h_next": h_next,
                    "required_h_next": required_h_next,
                    "safe": step_safe,
                }
            )
            if step_safe:
                current_state = next_state
            else:
                all_safe = False
                break
        return all_safe, records

    def _fetch_initial_fence_epoch_sync(self, skip_epoch_seed: bool) -> int:
        if skip_epoch_seed:
            logger.debug("B3a: Skipping epoch seed (skip_epoch_seed=True)")
            return 0

        if sync_redis_client is None:
            if _IS_PRODUCTION:
                raise CBFInitializationError(
                    "Cannot initialize CBF: sync Redis client unavailable. "
                    "Fence epoch cannot be seeded from external anchor. "
                    "Failing closed to prevent stale-read attack window."
                )
            logger.warning(
                "B3a: sync Redis client unavailable in dev/test mode — "
                "proceeding with epoch=0. Set CAGE_ENV=prod to enforce "
                "fail-closed behavior."
            )
            return 0

        try:
            epoch_raw = sync_redis_client.get(_REDIS_KEY_FENCE_EPOCH)
            if epoch_raw is None:
                sync_redis_client._get().set(_REDIS_KEY_FENCE_EPOCH, "0")
                logger.info(
                    "B3a: First-ever startup — initialized fence epoch to 0 in Redis"
                )
                return 0
            epoch = int(epoch_raw)
            logger.info("B3a: Seeded fence epoch from Redis: %d", epoch)
            if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                _CURRENT_FENCE_EPOCH_GAUGE.set(epoch)
            return epoch
        except Exception as exc:
            if _IS_PRODUCTION:
                raise CBFInitializationError(
                    f"Cannot initialize CBF: fence epoch unavailable from Redis. "
                    f"Error: {exc}. Failing closed to prevent stale-read attack window."
                ) from exc
            logger.warning(
                "B3a: Redis unavailable in dev/test mode — proceeding with "
                "epoch=0. Set CAGE_ENV=prod to enforce fail-closed behavior. "
                "Error: %s",
                exc,
            )
            return 0

    async def setup(self) -> None:
        """Bootstrap Redis state if the key is absent (first run)."""
        if redis_client is None:
            logger.error("Redis client unavailable — cannot bootstrap CBF state.")
            return
        if await redis_client.get(self.redis_key) is None:
            await redis_client.set(
                self.redis_key, str(self._initial_state_scalar())
            )
        client = await _get_raw_redis(redis_client)
        if client is not None:
            epoch_raw = await client.get(_REDIS_KEY_FENCE_EPOCH)
            if epoch_raw is None:
                await client.set(_REDIS_KEY_FENCE_EPOCH, "0")
                logger.info("R-05: Initialized fence epoch to 0")

    async def _get_current_cash(self) -> float:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        return await redis_client.get_float(
            self.redis_key, self._initial_state_scalar()
        )

    async def _increment_fence_epoch(self, pipeline: Any) -> int:
        pipeline.incr(_REDIS_KEY_FENCE_EPOCH)
        return 0

    async def _get_fence_epoch(self) -> int:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")
        client = await _get_raw_redis(redis_client)
        raw = await client.get(_REDIS_KEY_FENCE_EPOCH)
        if raw is None:
            return 0
        return int(raw)

    async def _check_fence_epoch(self, current_epoch: int) -> tuple[bool, str]:
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

        self._last_seen_epoch = current_epoch
        if _CURRENT_FENCE_EPOCH_GAUGE is not None:
            _CURRENT_FENCE_EPOCH_GAUGE.set(current_epoch)

        return (True, "OK")

    async def _sync_to_replicas(
        self,
        num_replicas: int | None = None,
        timeout_ms: int | None = None,
    ) -> bool:
        replicas = num_replicas if num_replicas is not None else _WAIT_REPLICAS
        timeout = timeout_ms if timeout_ms is not None else _WAIT_TIMEOUT_MS

        if replicas <= 0:
            return True

        if redis_client is None:
            logger.warning("Redis client unavailable — cannot execute WAIT command.")
            return False

        raw_client_getter = getattr(redis_client, "get_raw_client", None)
        if callable(raw_client_getter):
            client = raw_client_getter()
            if inspect.isawaitable(client):
                client = await client
        else:
            client = redis_client
        start_time = time.time()

        try:
            cmd = client.execute_command("WAIT", replicas, timeout)
            if inspect.isawaitable(cmd):
                acks = await cmd
            else:
                acks = int(cmd) if cmd is not None else 0

            elapsed = time.time() - start_time

            if _WAIT_LATENCY_HISTOGRAM is not None:
                _WAIT_LATENCY_HISTOGRAM.observe(elapsed)

            if acks >= replicas:
                return True

            logger.warning(
                json.dumps(
                    {
                        "event": "CBF_WAIT_TIMEOUT",
                        "severity": "WARNING",
                        "requested_replicas": replicas,
                        "acknowledged_replicas": acks,
                        "timeout_ms": timeout,
                        "elapsed_seconds": round(elapsed, 3),
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
            if _WAIT_LATENCY_HISTOGRAM is not None:
                _WAIT_LATENCY_HISTOGRAM.observe(elapsed)
            return False

    async def _validate_sequence(
        self, incoming_sequence: int, source: str, sync_redis: Any
    ) -> tuple[bool, str]:
        try:
            last_accepted_raw = await asyncio.to_thread(
                sync_redis.get,
                _REDIS_KEY_SEQUENCE_LAST_ACCEPTED,
            )
            last_accepted = int(last_accepted_raw) if last_accepted_raw else 0

            if incoming_sequence <= last_accepted:
                reason = (
                    f"sequence={incoming_sequence} <= last_accepted={last_accepted}"
                )
                return (False, reason)

            await asyncio.to_thread(
                sync_redis.set,
                _REDIS_KEY_SEQUENCE_LAST_ACCEPTED,
                str(incoming_sequence),
            )
            return (True, "OK")
        except Exception as exc:
            logger.warning(
                "[R-04] Sequence validation error: %s — allowing payload (fail-open)",
                exc,
            )
            return (True, f"validation error (fail-open): {exc}")

    async def _read_cbf_state_atomic(self) -> dict[str, Any]:
        """Read the CBF state scalar, preferring externally reconciled ground truth."""
        if redis_client is None:
            raise RuntimeError("Redis client unavailable.")

        try:
            from src.gateway.governance.reconciliation.daemon import (
                read_verified_snapshot,
            )

            verified = await asyncio.to_thread(
                read_verified_snapshot,
                sync_redis_client,
                self._invariant.invariant_id,
            )

            if verified is not None and verified.is_valid:
                scalar_val = float(verified.state_scalar)
                if verified.signature:
                    try:
                        from src.gateway.governance.kms_signer import (
                            get_governance_signer,
                        )

                        signer = get_governance_signer()
                        payload_dict = {
                            "source": verified.source,
                            "state_scalar": scalar_val,
                            "verified_at": verified.verified_at,
                            "sequence": verified.sequence,
                        }
                        sig_valid = signer.verify(payload_dict, verified.signature)
                        if sig_valid:
                            seq_num = getattr(verified, "sequence", 0)
                            if (
                                _REPLAY_DEFENSE_ENABLED
                                and isinstance(seq_num, int)
                                and seq_num > 0
                            ):
                                (
                                    sequence_valid,
                                    seq_reason,
                                ) = await self._validate_sequence(
                                    seq_num,
                                    verified.source,
                                    sync_redis_client,
                                )
                                if not sequence_valid:
                                    logger.critical(
                                        json.dumps(
                                            {
                                                "event": "CBF_RECONCILED_BALANCE_SEQUENCE_REPLAY_DETECTED",
                                                "severity": "CRITICAL",
                                                "source": verified.source,
                                                "state_scalar": scalar_val,
                                                "sequence": verified.sequence,
                                                "reason": seq_reason,
                                            }
                                        )
                                    )
                                    if _REPLAY_REJECTED_COUNTER is not None:
                                        _REPLAY_REJECTED_COUNTER.labels(
                                            source=verified.source
                                        ).inc()
                                else:
                                    fence_epoch = await self._get_fence_epoch()
                                    return {
                                        "state_scalar": scalar_val,
                                        "current_cash": scalar_val,
                                        "source": "reconciled",
                                        "sequence": verified.sequence,
                                        "fence_epoch": fence_epoch,
                                    }
                            else:
                                fence_epoch = await self._get_fence_epoch()
                                return {
                                    "state_scalar": scalar_val,
                                    "current_cash": scalar_val,
                                    "source": "reconciled",
                                    "sequence": verified.sequence,
                                    "fence_epoch": fence_epoch,
                                }
                        else:
                            logger.critical(
                                json.dumps(
                                    {
                                        "event": "CBF_RECONCILED_BALANCE_SIGNATURE_INVALID",
                                        "severity": "CRITICAL",
                                        "source": verified.source,
                                        "state_scalar": scalar_val,
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
                                    "strict_mode": _CBF_STRICT_MODE,
                                }
                            )
                        )
                        if _CBF_STRICT_MODE:
                            raise GroundTruthUnavailableError(
                                f"Cannot verify balance — transaction rejected. "
                                f"KMS verification failed: {type(sig_exc).__name__}",
                                cause=sig_exc,
                            ) from sig_exc
                else:
                    if _IS_PRODUCTION:
                        logger.critical(
                            json.dumps(
                                {
                                    "event": "CBF_RECONCILED_BALANCE_UNSIGNED_IN_PRODUCTION",
                                    "severity": "CRITICAL",
                                    "source": verified.source,
                                    "state_scalar": scalar_val,
                                }
                            )
                        )
                    else:
                        return {
                            "state_scalar": scalar_val,
                            "current_cash": scalar_val,
                            "source": "reconciled_unsigned",
                        }
        except GroundTruthUnavailableError:
            raise
        except Exception as recon_exc:
            if _CBF_STRICT_MODE:
                raise GroundTruthUnavailableError(
                    f"Cannot verify balance — transaction rejected. "
                    f"Reconciliation read failed: {type(recon_exc).__name__}",
                    cause=recon_exc,
                ) from recon_exc

        logger.warning(
            "[DIAG-FAILOPEN] cbf_using_self_reported_balance decision=allow_with_unverified_ground_truth "
            "redis_key=%s poam_ref=POAM-023 security_impact=HIGH",
            self.redis_key,
        )
        logger.critical(
            json.dumps(
                {
                    "event": "CBF_USING_SELF_REPORTED_BALANCE",
                    "severity": "CRITICAL",
                    "redis_key": self.redis_key,
                }
            )
        )
        client = await _get_raw_redis(redis_client)
        pipe_ctx = client.pipeline(transaction=False)
        if inspect.isawaitable(pipe_ctx):
            pipe_ctx = await pipe_ctx
        async with pipe_ctx as pipe:
            pipe.get(self.redis_key)
            pipe.get(_REDIS_KEY_FENCE_EPOCH)
            results = await pipe.execute()
            if inspect.isawaitable(results):
                results = await results
        raw_state = results[0]
        raw_epoch = results[1]
        current_state = (
            float(raw_state)
            if raw_state is not None
            else self._initial_state_scalar()
        )
        current_epoch = int(raw_epoch) if raw_epoch is not None else 0

        if _FENCE_EPOCH_ENABLED:
            epoch_valid, epoch_reason = await self._check_fence_epoch(current_epoch)
            if not epoch_valid:
                return {
                    "state_scalar": None,
                    "current_cash": None,
                    "source": "epoch_regression",
                    "fence_epoch": current_epoch,
                    "epoch_reason": epoch_reason,
                }
        else:
            self._last_seen_epoch = current_epoch
            if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                _CURRENT_FENCE_EPOCH_GAUGE.set(current_epoch)

        return {
            "state_scalar": current_state,
            "current_cash": current_state,
            "source": "self_reported",
            "fence_epoch": current_epoch,
        }

    async def _resolve_ground_truth_balance(self) -> tuple[float, dict[str, Any]]:
        state = await self._read_cbf_state_atomic()

        if (
            state.get("current_cash") is not None
            and state.get("source") == "reconciled"
        ):
            sequence = state.get("sequence", 0)
            return (
                float(state["current_cash"]),
                {
                    "source": "reconciliation",
                    "sequence": sequence,
                    "fence_epoch": state.get("fence_epoch", 0),
                    "strict_mode": _CBF_STRICT_MODE,
                    "reconciliation_age_ms": 0,
                },
            )
        if _CBF_STRICT_MODE and state.get("source") in (
            "epoch_regression",
            "self_reported",
        ):
            fallback_reason = (
                state.get("epoch_reason")
                if state.get("source") == "epoch_regression"
                else "reconciliation unavailable"
            )
            from src.gateway.governance.governor.governor import GovernanceError

            raise GovernanceError(
                f"CBF strict mode: {fallback_reason}",
                payload={"audit_code": "CBF_STRICT_RECONCILIATION_UNAVAILABLE"},
            )

        current_cash = state.get("current_cash")
        balance = (
            float(current_cash)
            if current_cash is not None
            else self._initial_state_scalar()
        )
        fence_epoch = int(state.get("fence_epoch", 0))

        return (
            balance,
            {
                "source": "self_reported",
                "fence_epoch": fence_epoch,
                "strict_mode": False,
                "reconciliation_age_ms": None,
            },
        )

    @staticmethod
    def _default_cost_resolver(action_name: str, payload: dict[str, Any]) -> float:
        return 0.0

    def _resolve_action_cost(self, action_name: str, payload: dict[str, Any]) -> float:
        cost = self._cost_resolver(action_name, payload)

        if not math.isfinite(cost) or cost < 0:
            raise ValueError(
                f"invalid action cost {cost!r} from resolver — must be a finite, non-negative number"
            )
        return cost

    async def verify_action(self, action_name: str, payload: dict[str, Any]) -> str:
        state = await self._read_cbf_state_atomic()
        balance_source: str = str(state.get("source", "unknown"))

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
            logger.warning("CBF check rejected: epoch regression — %s", epoch_reason)
            return result

        current_state = float(state["current_cash"])
        fence_epoch = int(state.get("fence_epoch", 0))

        if self.tracer:
            with self.tracer.start_as_current_span("safety.cbf_check") as span:
                span.set_attribute("cage.cbf.fence_epoch", fence_epoch)
                return await self._do_verify_action(
                    action_name, payload, current_state, balance_source, span
                )
        return await self._do_verify_action(
            action_name, payload, current_state, balance_source, None
        )

    async def _do_verify_action(
        self,
        action_name: str,
        payload: dict[str, Any],
        current_state: float,
        balance_source: str,
        span: Any,
    ) -> str:
        if span:
            span.set_attribute("safety.cash.current", current_state)
            span.set_attribute("safety.balance.source", balance_source)
            span.set_attribute(
                "safety.balance.reconciled", balance_source == "reconciled"
            )
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
            cost = self._resolve_action_cost(action_name, payload)
        except (TypeError, ValueError) as exc:
            _mrm_meta = ControlRegistry().get_mapping(
                GovernanceControl.TRADITIONAL_MRM_VALIDATION
            )
            result = (
                f"[{GovernanceControl.TRADITIONAL_MRM_VALIDATION.value}] "
                f"{_mrm_meta['primary_framework']} Violation: {exc}"
            )
            logger.warning("CBF check rejected action: %s", exc)
            if span:
                span.set_attribute("safety.result", result)
            return result

        effective_state = current_state - self._local_debits
        next_state = effective_state - cost
        h_t = self.evaluate_barrier(effective_state)
        h_next = self.evaluate_barrier(next_state)
        required_h_next = (1.0 - self.gamma) * h_t

        result = "SAFE"
        if cost > 0 and (h_next < required_h_next or h_next < 0):
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

        if result == "SAFE" and cost > 0:
            self._local_debits += cost

        if span:
            span.set_attribute("safety.cash.next", next_state)
            span.set_attribute("safety.barrier.h_next", h_next)
            span.set_attribute("safety.result", result)

        return result

    async def _update_state_unsafe(
        self, cost: float, governance_signature: str | None = None
    ) -> None:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot update CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                pipe_ctx = redis_client.pipeline()
                if inspect.isawaitable(pipe_ctx):
                    pipe_ctx = await pipe_ctx
                async with pipe_ctx as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = (
                        float(raw)
                        if raw is not None
                        else self._initial_state_scalar()
                    )
                    new_balance = current - cost
                    pipe.multi()
                    pipe.set(self.redis_key, str(new_balance))
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
                    new_epoch = results[1] if results and len(results) > 1 else 0
                    self._last_seen_epoch = new_epoch
                    if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                        _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

                    await self._sync_to_replicas()
                    return
            except Exception as exc:
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "CBF WATCH conflict on attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF _update_state_unsafe failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    def reset_local_debits(self) -> None:
        """Reset the local intra-window debit accumulator to zero."""
        self._local_debits = 0.0

    async def rollback_state(
        self, magnitude: float, governance_signature: str | None = None
    ) -> None:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot rollback CBF state.")

        for attempt in range(self._MAX_RETRIES):
            try:
                pipe_ctx = redis_client.pipeline()
                if inspect.isawaitable(pipe_ctx):
                    pipe_ctx = await pipe_ctx
                async with pipe_ctx as pipe:
                    await pipe.watch(self.redis_key)
                    raw = await pipe.get(self.redis_key)
                    current = (
                        float(raw)
                        if raw is not None
                        else self._initial_state_scalar()
                    )
                    restored = current + magnitude
                    pipe.multi()
                    pipe.set(self.redis_key, str(restored))
                    pipe.incr(_REDIS_KEY_FENCE_EPOCH)
                    if governance_signature:
                        ledger_entry = json.dumps(
                            {
                                "ts": time.time(),
                                "cost": magnitude,
                                "new_balance": restored,
                                "governance_signature": governance_signature,
                                "rollback": True,
                            }
                        )
                        pipe.rpush("audit:state_ledger", ledger_entry)
                    results = await pipe.execute()
                    new_epoch = results[1] if results and len(results) > 1 else 0
                    self._last_seen_epoch = new_epoch
                    if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                        _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

                    await self._sync_to_replicas()
                    return
            except Exception as exc:
                if "WatchError" in type(exc).__name__:
                    logger.warning(
                        "CBF WATCH conflict on rollback attempt %d/%d — retrying.",
                        attempt + 1,
                        self._MAX_RETRIES,
                    )
                    continue
                raise

        raise RuntimeError(
            f"CBF rollback_state failed after {self._MAX_RETRIES} retries due to concurrent writes."
        )

    async def atomic_verify_and_commit(
        self,
        action_name: str,
        payload: dict[str, Any],
        governance_signature: str = "",
    ) -> tuple[bool, str, float]:
        if redis_client is None:
            raise RuntimeError("Redis client unavailable — cannot run atomic CBF.")

        try:
            cost = self._resolve_action_cost(action_name, payload)
        except (TypeError, ValueError) as exc:
            reason = f"UNSAFE: {exc}"
            logger.warning("CBF atomic check rejected action: %s", exc)
            return (False, reason, 0.0)

        try:
            (
                ground_truth_balance,
                balance_metadata,
            ) = await self._resolve_ground_truth_balance()
        except Exception as exc:
            reason = f"RECONCILIATION_UNAVAILABLE: {exc}"
            logger.error("CBF atomic check rejected: %s", reason)
            return (False, reason, 0.0)

        local_debit_total = 0.0
        if balance_metadata["source"] == "reconciliation" and redis_client is not None:
            client = await _get_raw_redis(redis_client)
            if hasattr(client, "lrange"):
                local_debits_res = client.lrange(_REDIS_KEY_LOCAL_DEBITS, 0, -1)
                local_debits_raw = (
                    await local_debits_res
                    if inspect.isawaitable(local_debits_res)
                    else local_debits_res
                )
                if local_debits_raw:
                    for debit_entry in local_debits_raw:
                        if isinstance(debit_entry, (bytes, bytearray)):
                            debit_entry = debit_entry.decode("utf-8")
                        try:
                            debit_data = json.loads(debit_entry)
                            if debit_data.get(
                                "reconciliation_sequence"
                            ) == balance_metadata.get("sequence"):
                                local_debit_total += debit_data.get("amount", 0.0)
                        except Exception:
                            pass

        effective_balance = ground_truth_balance - local_debit_total

        current_fence_epoch = balance_metadata["fence_epoch"]
        if self._last_verified_fence_epoch is not None:
            if current_fence_epoch < self._last_verified_fence_epoch:
                logger.critical(
                    json.dumps(
                        {
                            "event": "FENCE_EPOCH_REGRESSION",
                            "severity": "CRITICAL",
                            "current_epoch": current_fence_epoch,
                            "last_verified_epoch": self._last_verified_fence_epoch,
                        }
                    )
                )
                return (
                    False,
                    f"Fence epoch regression: {current_fence_epoch} < {self._last_verified_fence_epoch}",
                    0.0,
                )

        keys = [self._invariant.state_key, "audit:state_ledger", _REDIS_KEY_FENCE_EPOCH]
        resolved_threshold = self._resolve_threshold()

        argv = [
            str(cost),
            str(resolved_threshold),
            str(self.gamma),
            governance_signature,
            str(effective_balance),
            str(current_fence_epoch),
        ]

        client = await _get_raw_redis(redis_client)

        async def _run_evalsha() -> list:
            res = client.evalsha(self._lua_sha, len(keys), *keys, *argv)
            return await res if inspect.isawaitable(res) else res

        async def _load_and_run() -> list:
            res = client.script_load(self.LUA_ATOMIC_CBF)
            self._lua_sha = await res if inspect.isawaitable(res) else res
            return await _run_evalsha()

        if self.tracer:
            with self.tracer.start_as_current_span(
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
                span.set_attribute("cage.cbf.wait_replicas", _WAIT_REPLICAS)
                result_list = await self._evalsha_with_noscript_retry(
                    client, keys, argv, _run_evalsha, _load_and_run
                )
                committed, message = self._parse_lua_result(result_list, span)

                if (
                    committed
                    and balance_metadata["source"] == "reconciliation"
                    and redis_client is not None
                ):
                    if hasattr(client, "rpush"):
                        debit_entry = json.dumps(
                            {
                                "amount": cost,
                                "reconciliation_sequence": balance_metadata.get(
                                    "sequence"
                                ),
                                "timestamp": time.time(),
                                "action_signature": governance_signature,
                            }
                        )
                        rpush_res = client.rpush(_REDIS_KEY_LOCAL_DEBITS, debit_entry)
                        if inspect.isawaitable(rpush_res):
                            await rpush_res
                        if hasattr(client, "ltrim"):
                            ltrim_res = client.ltrim(_REDIS_KEY_LOCAL_DEBITS, -1000, -1)
                            if inspect.isawaitable(ltrim_res):
                                await ltrim_res

                if committed and _WAIT_REPLICAS > 0:
                    wait_result = await self._sync_to_replicas()
                    span.set_attribute("cage.cbf.wait_success", wait_result)
                    span.set_attribute(
                        "cage.cbf.strict_replication", _STRICT_REPLICATION
                    )
                    if not wait_result:
                        if _STRICT_REPLICATION and _FENCE_EPOCH_ENABLED:
                            await self.rollback_state(cost)
                            span.set_attribute(
                                "cage.cbf.strict_replication_rollback", True
                            )
                            if _STRICT_REPLICATION_ROLLBACK_COUNTER is not None:
                                _STRICT_REPLICATION_ROLLBACK_COUNTER.inc()
                            return (
                                False,
                                "REPLICATION_UNCONFIRMED: Redis WAIT timed out on replicas. Failed closed.",
                                0.0,
                            )

                return (committed, message, cost if committed else 0.0)

        result_list = await self._evalsha_with_noscript_retry(
            client, keys, argv, _run_evalsha, _load_and_run
        )
        committed, message = self._parse_lua_result(result_list, None)

        if (
            committed
            and balance_metadata["source"] == "reconciliation"
            and redis_client is not None
        ):
            if hasattr(client, "rpush"):
                debit_entry = json.dumps(
                    {
                        "amount": cost,
                        "reconciliation_sequence": balance_metadata.get("sequence"),
                        "timestamp": time.time(),
                        "action_signature": governance_signature,
                    }
                )
                rpush_res = client.rpush(_REDIS_KEY_LOCAL_DEBITS, debit_entry)
                if inspect.isawaitable(rpush_res):
                    await rpush_res
                if hasattr(client, "ltrim"):
                    ltrim_res = client.ltrim(_REDIS_KEY_LOCAL_DEBITS, -1000, -1)
                    if inspect.isawaitable(ltrim_res):
                        await ltrim_res

        if committed and _WAIT_REPLICAS > 0:
            wait_result = await self._sync_to_replicas()
            if not wait_result:
                if _STRICT_REPLICATION and _FENCE_EPOCH_ENABLED:
                    await self.rollback_state(cost)
                    if _STRICT_REPLICATION_ROLLBACK_COUNTER is not None:
                        _STRICT_REPLICATION_ROLLBACK_COUNTER.inc()
                    return (
                        False,
                        "REPLICATION_UNCONFIRMED: Redis WAIT timed out on replicas. Failed closed.",
                        0.0,
                    )

        return (committed, message, cost if committed else 0.0)

    async def _evalsha_with_noscript_retry(
        self,
        client: Any,
        keys: list[str],
        argv: list[str],
        run_evalsha_fn: Any,
        load_and_run_fn: Any,
    ) -> list:
        if self._lua_sha is None:
            self._lua_sha = await client.script_load(self.LUA_ATOMIC_CBF)

        try:
            return await run_evalsha_fn()
        except Exception as exc:
            if "NOSCRIPT" in str(exc):
                logger.warning("Lua SHA evicted from Redis — reloading script.")
                return await load_and_run_fn()
            raise

    def _parse_lua_result(
        self,
        result_list: list,
        span: Any,
    ) -> tuple[bool, str]:
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
        new_epoch = 0
        if len(result_list) > 3:
            epoch_raw = result_list[3]
            new_epoch = int(epoch_raw) if epoch_raw is not None else 0

        committed = status_code == 1
        if span:
            span.set_attribute("safety.result", "COMMITTED" if committed else "UNSAFE")
            span.set_attribute("safety.cash.next", float(new_balance_str))
            span.set_attribute("cage.cbf.fence_epoch", new_epoch)

        if committed and new_epoch > 0:
            self._last_seen_epoch = new_epoch
            self._last_verified_fence_epoch = new_epoch
            if _CURRENT_FENCE_EPOCH_GAUGE is not None:
                _CURRENT_FENCE_EPOCH_GAUGE.set(new_epoch)

        if committed:
            return (True, "COMMITTED")
        return (False, message)
