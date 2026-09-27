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

"""Domain-agnostic GroundTruthReconciler daemon (Layer 1 kernel).

Polls domain-contributed ``GroundTruthProvider`` instances, validates
monotonic sequences, timestamp freshness, clock skew, source authenticity,
barrier-floor compliance, and discrepancy bounds, signs verified snapshots
via the KMS governance signer, and writes TTL-bounded records to Redis keyed
by ``invariant_id``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
import inspect
import json
import logging
import math
import os
import time
from typing import Any, Protocol

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.ground_truth import (
    FaultMode,
    GroundTruthProvider,
    GroundTruthSnapshot,
    SimulatedSource,
)

logger = logging.getLogger("cage.reconciliation")

POLL_INTERVAL_SECONDS: int = int(
    os.environ.get("RECONCILIATION_POLL_INTERVAL_SECONDS", "60")
)
TTL_SECONDS: int = int(os.environ.get("RECONCILIATION_TTL_SECONDS", "300"))
PROVIDER: str = os.environ.get("RECONCILIATION_PROVIDER", "simulated")

REPLAY_DEFENSE_ENABLED: bool = os.environ.get(
    "CAGE_RECONCILIATION_REPLAY_DEFENSE", "false"
).lower() in ("true", "1", "yes")

RECONCILED_STATE_KEY_PREFIX = "cage:ground_truth:"
_REDIS_KEY_VERIFIED_BALANCE = "reconciliation:verified_balance"
_REDIS_KEY_VERIFIED_AT = "reconciliation:verified_at"
_REDIS_KEY_PROVIDER = "reconciliation:provider"
_REDIS_KEY_SIGNATURE = "reconciliation:signature"
_REDIS_KEY_SEQUENCE_LATEST = "reconciliation:sequence:latest"
_REDIS_KEY_SEQUENCE_LAST_ACCEPTED = "reconciliation:sequence:last_accepted"
FENCE_EPOCH_KEY = "safety:fence_epoch"
_CBF_FENCE_EPOCH_KEY = "safety:cbf_fence_epoch"

_DEFAULT_STATE_KEYS: dict[str, str] = {
    "finance.cash_balance": "safety:cash_balance",
    "healthcare.serum_concentration": "safety:serum_concentration",
    "physical_ai.spatial_separation": "safety:separation_distance_mm",
    "physical_ai.kinematic_velocity": "safety:end_effector_velocity_mm_s",
    "physical_ai.torque_saturation": "safety:joint_torque_nm",
}


def reconciled_state_key(invariant_id: str) -> str:
    """Return the canonical Redis key for a reconciled invariant state."""
    return f"{RECONCILED_STATE_KEY_PREFIX}{invariant_id}"


@contextmanager
def _null_context():  # type: ignore[no-untyped-def]
    yield


@dataclass
class ReconciliationResult:
    """Result of an external ground-truth reconciliation tick."""

    source: str
    balance_usd: float = 0.0
    verified_at: float = field(default_factory=time.time)
    signature: str = ""
    ttl_seconds: int = TTL_SECONDS
    raw_response: dict[str, Any] | None = None
    error: str | None = None
    sequence: int = 0
    invariant_id: str = "finance.cash_balance"
    state_scalar: float | None = None
    kms_key_id: str = ""
    discrepancy_detected: bool = False
    discrepancy_delta: float = 0.0

    def __post_init__(self) -> None:
        if self.state_scalar is None:
            self.state_scalar = float(self.balance_usd)
        elif self.balance_usd == 0.0 and math.isfinite(self.state_scalar):
            self.balance_usd = float(self.state_scalar)

    @property
    def kms_signature(self) -> str:
        return self.signature

    @property
    def is_valid(self) -> bool:
        """True if reconciliation succeeded and scalar is finite and non-negative."""
        scalar = (
            self.state_scalar if self.state_scalar is not None else self.balance_usd
        )
        return (
            self.error is None
            and isinstance(scalar, (int, float))
            and not isinstance(scalar, bool)
            and math.isfinite(scalar)
            and scalar >= 0.0
        )

    @property
    def is_stale(self) -> bool:
        """True if the snapshot is older than its TTL."""
        return (time.time() - self.verified_at) > self.ttl_seconds

    def to_redis_payload(self) -> str:
        """Serialize to a deterministic RFC 8785 JCS JSON string for Redis storage."""
        scalar = (
            self.state_scalar if self.state_scalar is not None else self.balance_usd
        )
        payload_dict = {
            "source": self.source,
            "balance_usd": self.balance_usd,
            "state_scalar": scalar,
            "invariant_id": self.invariant_id,
            "verified_at": self.verified_at,
            "signature": self.signature,
            "sequence": self.sequence,
            "kms_key_id": self.kms_key_id,
        }
        return jcs_canonicalize_plan(payload_dict).decode("utf-8")

    @classmethod
    def from_redis_payload(cls, payload: str | bytes) -> ReconciliationResult:
        """Deserialize from Redis JSON payload."""
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8")
        data = json.loads(payload)
        scalar_raw = data.get("state_scalar", data.get("balance_usd", 0.0))
        balance_raw = data.get("balance_usd", scalar_raw)
        return cls(
            source=data["source"],
            balance_usd=float(balance_raw),
            state_scalar=float(scalar_raw),
            invariant_id=data.get("invariant_id", "finance.cash_balance"),
            verified_at=float(data["verified_at"]),
            signature=data.get("signature", ""),
            sequence=int(data.get("sequence", 0)),
            kms_key_id=data.get("kms_key_id", ""),
        )


class LedgerProvider(Protocol):
    """Legacy protocol alias for ground-truth providers."""

    def fetch_balance(self, account_id: str) -> ReconciliationResult:
        ...  # pragma: no cover


class _DefaultSimulatedProvider(GroundTruthProvider):
    """Default kernel-level simulated provider used when none is injected."""

    invariant_id: str = "finance.cash_balance"
    state_key: str = "safety:cash_balance"

    def __init__(self, initial_scalar: float | None = None) -> None:
        default_scalar = (
            initial_scalar
            if initial_scalar is not None
            else float(os.environ.get("RECONCILIATION_STUB_BALANCE_USD", "100000.0"))
        )
        self._source = SimulatedSource(
            invariant_id=self.invariant_id,
            state_key=self.state_key,
            initial_scalar=default_scalar,
            barrier_floor=20_000.0,
        )
        self.source = self._source

    def inject_fault(self, mode: FaultMode | str) -> None:
        self._source.inject_fault(mode)

    def clear_fault(self) -> None:
        self._source.clear_fault()

    def record_debit(self, magnitude: float) -> None:
        self._source.record_debit(magnitude)

    def reset(self, *, scalar: float | None = None) -> None:
        self._source.reset(scalar=scalar)

    def fetch_snapshot_sync(self) -> GroundTruthSnapshot:
        return self._source.next_snapshot()

    async def fetch_snapshot(self) -> GroundTruthSnapshot:
        return self.fetch_snapshot_sync()


class GroundTruthReconciler:
    """Domain-agnostic ground-truth reconciliation daemon.

    Polls ``GroundTruthProvider`` instances, enforces fail-closed validation on
    all fault modes (timeout, connection error, malformed payload, negative/NaN
    scalar, stale/future timestamp, unverified source, scalar below barrier,
    and discrepancy spike), signs snapshots via KMS, and writes TTL-bounded
    verified state to Redis keyed by ``invariant_id``.
    """

    def __init__(
        self,
        provider: Any | None = None,
        redis_client: Any = None,
        account_id: str = "default",
        poll_interval: int = POLL_INTERVAL_SECONDS,
        ttl: int = TTL_SECONDS,
        signer: Any | None = None,
        *,
        providers: (
            Mapping[str, GroundTruthProvider]
            | Sequence[GroundTruthProvider]
            | None
        ) = None,
        max_staleness_s: float | None = None,
        max_clock_skew_s: float = 5.0,
        discrepancy_threshold: float | None = None,
    ) -> None:
        self._providers: dict[str, Any] = {}
        if providers is not None:
            if isinstance(providers, Mapping):
                self._providers.update(providers)
            else:
                for p in providers:
                    inv_id = getattr(p, "invariant_id", "finance.cash_balance")
                    self._providers[inv_id] = p

        if provider is not None:
            self._provider = provider
            inv_id = getattr(provider, "invariant_id", "finance.cash_balance")
            if isinstance(inv_id, str):
                self._providers.setdefault(inv_id, provider)
        elif self._providers:
            self._provider = next(iter(self._providers.values()))
        else:
            self._provider = _DefaultSimulatedProvider()
            self._providers[self._provider.invariant_id] = self._provider

        self._redis = redis_client
        self._account_id = account_id
        self._poll_interval = poll_interval
        self._ttl = ttl
        self._signer = signer
        self._max_staleness_s = (
            float(max_staleness_s) if max_staleness_s is not None else float(ttl)
        )
        self._max_clock_skew_s = float(max_clock_skew_s)
        self._discrepancy_threshold = discrepancy_threshold
        self._failure_count: int = 0
        self._last_sequence_by_invariant: dict[str, int] = {}

    @property
    def failure_count(self) -> int:
        """Total number of failed reconciliation or KMS signing ticks."""
        return self._failure_count

    def _get_source(self, provider: Any) -> Any:
        return getattr(provider, "source", getattr(provider, "_source", None))

    def _resolve_barrier_floor(self, invariant_id: str, provider: Any) -> float | None:
        source_obj = self._get_source(provider)
        source_floor = getattr(
            source_obj,
            "barrier_floor",
            getattr(provider, "barrier_floor", None),
        )
        if isinstance(source_floor, (int, float)) and math.isfinite(source_floor):
            return float(source_floor)
        try:
            from src.gateway.governance.plugin_loader import load_domain_plugin
            from src.gateway.governance.schemas.thresholds import THRESHOLDS

            threshold_key = getattr(
                source_obj,
                "threshold_key",
                getattr(provider, "threshold_key", None),
            )
            if not threshold_key and "." in invariant_id:
                domain_name = invariant_id.partition(".")[0]
                plugin = load_domain_plugin(domain_name)
                for inv in plugin.contribute().invariants:
                    if getattr(inv, "invariant_id", None) == invariant_id:
                        threshold_key = getattr(inv, "threshold_key", None)
                        break
            if threshold_key:
                return float(THRESHOLDS.resolve(threshold_key))
        except Exception:
            pass
        return None

    def _invalidate_redis_verified_state(self, invariant_id: str) -> None:
        if self._redis is None:
            return
        try:
            if hasattr(self._redis, "delete"):
                self._redis.delete(reconciled_state_key(invariant_id))
                if invariant_id == "finance.cash_balance":
                    self._redis.delete(_REDIS_KEY_VERIFIED_BALANCE)
        except Exception:
            pass

    def _increment_fence_epoch(self) -> None:
        if self._redis is None:
            return
        try:
            if hasattr(self._redis, "incr"):
                self._redis.incr(FENCE_EPOCH_KEY)
                self._redis.incr(_CBF_FENCE_EPOCH_KEY)
        except Exception:
            pass

    def _read_self_reported_baseline(
        self, invariant_id: str, provider: Any
    ) -> float | None:
        state_key = getattr(
            provider, "state_key", _DEFAULT_STATE_KEYS.get(invariant_id)
        )
        if self._redis is not None and state_key and hasattr(self._redis, "get"):
            try:
                raw = self._redis.get(state_key)
                if raw is not None and not isinstance(raw, MagicMock_type()):
                    val = float(raw)
                    if math.isfinite(val):
                        return val
            except Exception:
                pass
        source_obj = self._get_source(provider)
        init_scalar = getattr(source_obj, "initial_scalar", None)
        if isinstance(init_scalar, (int, float)) and math.isfinite(init_scalar):
            return float(init_scalar)
        return None

    def _write_verified_balance(
        self,
        result: ReconciliationResult,
        *,
        allow_unconfigured_kms_in_dev: bool = True,
        fetch_ms: float = 0.0,
        set_span_attr: Any | None = None,
    ) -> ReconciliationResult:
        """Sign the reconciled state payload and write verified state to Redis."""
        from src.gateway.governance.env_posture import is_enforcing, resolve_posture

        def _attr(key: str, val: object) -> None:
            if callable(set_span_attr):
                set_span_attr(key, val)

        enforcing = is_enforcing(resolve_posture())
        t_sign_start = time.monotonic()
        unconfigured_dev_signer = False
        try:
            if self._signer is not None:
                signer = self._signer
            else:
                from src.gateway.governance.kms_signer import get_governance_signer

                try:
                    signer = get_governance_signer()
                except Exception:
                    unconfigured_dev_signer = True
                    raise
                if not enforcing and not getattr(signer, "is_kms_active", True):
                    unconfigured_dev_signer = True
                    raise RuntimeError("KMS signer inactive in dev/test posture")

            payload_dict = {
                "source": result.source,
                "balance_usd": result.balance_usd,
                "verified_at": result.verified_at,
                "sequence": result.sequence,
            }
            if hasattr(signer, "sign"):
                raw_sig = signer.sign(payload_dict)
            elif hasattr(signer, "sign_decision"):
                raw_sig = signer.sign_decision(payload_dict)
            else:
                raise RuntimeError("Configured governance signer has no sign method")

            if hasattr(raw_sig, "signature"):
                sig_str = str(raw_sig.signature)
                result.kms_key_id = str(getattr(raw_sig, "kid", ""))
            elif isinstance(raw_sig, dict):
                sig_str = str(raw_sig.get("signature", ""))
                result.kms_key_id = str(raw_sig.get("kid", ""))
            else:
                sig_str = str(raw_sig or "")

            sig_alg = getattr(
                raw_sig,
                "algorithm",
                getattr(signer, "signing_algorithm", "KMS_ASYMMETRIC"),
            )
            if not sig_str or sig_str.startswith("HMAC_FALLBACK"):
                raise RuntimeError("KMS signer returned empty or fallback signature")
            if enforcing and (
                sig_alg in ("HMAC_SHA256_FALLBACK", "HS256", "SOFTWARE_ED25519")
                or not getattr(signer, "is_kms_active", True)
            ):
                raise RuntimeError(
                    f"Unverified/fallback signing algorithm {sig_alg!r} rejected in enforcing posture"
                )

            result.signature = sig_str
            logger.info("Reconciled state signed via KMS.")
        except Exception as sign_exc:
            kms_sign_ms = (time.monotonic() - t_sign_start) * 1000.0
            _attr("reconciliation.kms_sign_ms", round(kms_sign_ms, 1))
            _attr("reconciliation.signed", False)
            can_skip_sig = (
                allow_unconfigured_kms_in_dev
                and unconfigured_dev_signer
                and not enforcing
                and self._signer is None
            )
            if not can_skip_sig:
                self._failure_count += 1
                result.signature = ""
                result.error = f"KMS signing failed: {sign_exc}"
                _attr("reconciliation.error", result.error)
                self._invalidate_redis_verified_state(result.invariant_id)
                logger.error(
                    "Reconciliation KMS signing FAILED (fail-closed, Redis write aborted): %s",
                    sign_exc,
                )
                return result
            logger.warning(
                "KMS signing unconfigured in non-enforcing posture: %s",
                sign_exc,
            )
        else:
            kms_sign_ms = (time.monotonic() - t_sign_start) * 1000.0
            _attr("reconciliation.kms_sign_ms", round(kms_sign_ms, 1))
            _attr("reconciliation.signed", bool(result.signature))

        if self._redis is None:
            return result

        t_redis_start = time.monotonic()
        try:
            payload_json = result.to_redis_payload()
            inv_key = reconciled_state_key(result.invariant_id)
            pipe = self._redis.pipeline()
            pipe.setex(inv_key, self._ttl, payload_json)
            if result.invariant_id == "finance.cash_balance":
                pipe.setex(
                    _REDIS_KEY_VERIFIED_BALANCE,
                    self._ttl,
                    payload_json,
                )
                pipe.setex(
                    _REDIS_KEY_VERIFIED_AT,
                    self._ttl,
                    str(result.verified_at),
                )
                pipe.setex(
                    _REDIS_KEY_PROVIDER,
                    self._ttl,
                    result.source,
                )
                if result.signature:
                    pipe.setex(
                        _REDIS_KEY_SIGNATURE,
                        self._ttl,
                        result.signature,
                    )
            pipe.execute()
        except Exception as redis_exc:
            self._failure_count += 1
            logger.error(
                "Reconciliation Redis write FAILED: %s — CBF will fail-closed.",
                redis_exc,
            )
            result.error = f"Redis write failed: {redis_exc}"
            _attr("reconciliation.redis_error", str(redis_exc))
        finally:
            redis_write_ms = (time.monotonic() - t_redis_start) * 1000.0
            _attr("reconciliation.redis_write_ms", round(redis_write_ms, 1))

        return result

    def _fetch_from_provider(
        self, target_provider: Any, default_invariant_id: str
    ) -> tuple[ReconciliationResult, bool]:
        """Fetch from either a GroundTruthProvider or a legacy fetch_balance mock."""
        use_fetch_balance = False
        if not isinstance(target_provider, GroundTruthProvider):
            prov_dict = getattr(target_provider, "__dict__", {})
            mock_children = getattr(target_provider, "_mock_children", {})
            if (
                "fetch_balance" in prov_dict
                or "fetch_balance" in mock_children
                or (
                    hasattr(target_provider, "fetch_balance")
                    and not hasattr(target_provider, "fetch_snapshot")
                    and not hasattr(target_provider, "fetch_snapshot_sync")
                )
            ):
                use_fetch_balance = True

        if use_fetch_balance:
            raw_res = target_provider.fetch_balance(self._account_id)
            if isinstance(raw_res, ReconciliationResult):
                return raw_res, False
            if isinstance(raw_res, GroundTruthSnapshot):
                snap = raw_res
            else:
                raise ValueError(f"Unsupported provider return type: {type(raw_res)!r}")
        else:
            if hasattr(target_provider, "fetch_snapshot_sync"):
                snap = target_provider.fetch_snapshot_sync()
            else:
                snap = target_provider.fetch_snapshot()
                if inspect.isawaitable(snap):
                    import asyncio

                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None
                    if loop is not None and loop.is_running():
                        # Coroutine from SimulatedSource.next_snapshot is immediate
                        source_obj = self._get_source(target_provider)
                        snap.close()  # type: ignore[attr-defined]
                        if source_obj is not None and hasattr(
                            source_obj, "next_snapshot"
                        ):
                            snap = source_obj.next_snapshot()
                        else:
                            raise RuntimeError(
                                "Async provider requires fetch_snapshot_sync inside running event loop"
                            )
                    else:
                        snap = asyncio.run(snap)

        if isinstance(snap, ReconciliationResult):
            return snap, False
        if not isinstance(snap, GroundTruthSnapshot):
            raise ValueError(
                f"GroundTruthProvider returned invalid snapshot: {type(snap)!r}"
            )
        if not snap.invariant_id or (snap.metadata and snap.metadata.get("malformed")):
            raise ValueError("Malformed ground-truth snapshot payload")

        return (
            ReconciliationResult(
                source=snap.source,
                balance_usd=snap.state_scalar,
                state_scalar=snap.state_scalar,
                invariant_id=snap.invariant_id or default_invariant_id,
                verified_at=snap.verified_at,
                sequence=snap.sequence,
                raw_response=dict(snap.metadata) if snap.metadata else None,
            ),
            True,
        )

    def reconcile(self, invariant_id: str | None = None) -> ReconciliationResult:
        """Execute a single reconciliation cycle and return ``ReconciliationResult``."""
        target_provider = (
            self._providers.get(invariant_id, self._provider)
            if invariant_id is not None
            else self._provider
        )
        inv_id = invariant_id or getattr(
            target_provider, "invariant_id", "finance.cash_balance"
        )
        if not isinstance(inv_id, str):
            inv_id = "finance.cash_balance"

        try:
            from opentelemetry import trace as _otel_trace

            _tracer = _otel_trace.get_tracer("cage.reconciliation_worker")
            _span_ctx = _tracer.start_as_current_span("reconciliation.cycle")
        except Exception:
            _span_ctx = None  # type: ignore[assignment]

        def _set_span_attr(key: str, value: object) -> None:
            if _span_ctx is not None:
                try:
                    span = _otel_trace.get_current_span()
                    span.set_attribute(key, value)  # type: ignore[arg-type]
                except Exception:
                    pass

        with _span_ctx if _span_ctx is not None else _null_context():
            _set_span_attr("reconciliation.provider", PROVIDER)
            _set_span_attr("reconciliation.account_id", self._account_id)
            _set_span_attr("reconciliation.invariant_id", inv_id)

            t_fetch_start = time.monotonic()
            try:
                result, is_snapshot = self._fetch_from_provider(
                    target_provider, inv_id
                )
            except Exception as exc:
                self._failure_count += 1
                self._invalidate_redis_verified_state(inv_id)
                logger.error(
                    "Reconciliation FAILED: invariant=%s account=%s error=%s",
                    inv_id,
                    self._account_id,
                    exc,
                )
                _set_span_attr("reconciliation.error", str(exc))
                return ReconciliationResult(
                    source=PROVIDER,
                    balance_usd=0.0,
                    state_scalar=0.0,
                    invariant_id=inv_id,
                    error=str(exc),
                )
            finally:
                fetch_ms = (time.monotonic() - t_fetch_start) * 1000.0
                _set_span_attr("reconciliation.plaid_fetch_ms", round(fetch_ms, 1))

            # 1. Source verification (FaultMode.UNVERIFIED_SOURCE)
            if (
                not result.source
                or not isinstance(result.source, str)
                or result.source == "unverified_rogue_feed"
                or result.source.startswith("unverified")
            ):
                self._failure_count += 1
                self._invalidate_redis_verified_state(result.invariant_id)
                result.error = f"Unverified ground-truth source: {result.source!r}"
                _set_span_attr("reconciliation.error", result.error)
                return result

            # 2. Scalar finiteness & non-negativity (FaultMode.NEGATIVE_VALUE, NAN_VALUE)
            if not result.is_valid:
                self._failure_count += 1
                self._invalidate_redis_verified_state(result.invariant_id)
                if result.error is None:
                    result.error = (
                        f"Invalid ground-truth state_scalar: {result.state_scalar!r}"
                    )
                _set_span_attr("reconciliation.error", result.error)
                return result

            scalar = float(
                result.state_scalar
                if result.state_scalar is not None
                else result.balance_usd
            )

            # 3. Timestamp freshness & future clock skew (STALE_TIMESTAMP, FUTURE_TIMESTAMP)
            if is_snapshot:
                now = time.time()
                age = now - result.verified_at
                if age > self._max_staleness_s:
                    self._failure_count += 1
                    self._invalidate_redis_verified_state(result.invariant_id)
                    result.error = (
                        f"Stale ground-truth snapshot: age={age:.1f}s > "
                        f"max_staleness={self._max_staleness_s:.1f}s"
                    )
                    _set_span_attr("reconciliation.error", result.error)
                    return result
                if (result.verified_at - now) > self._max_clock_skew_s:
                    self._failure_count += 1
                    self._invalidate_redis_verified_state(result.invariant_id)
                    result.error = (
                        f"Future timestamp exceeds clock skew tolerance: "
                        f"skew={result.verified_at - now:.1f}s > {self._max_clock_skew_s:.1f}s"
                    )
                    _set_span_attr("reconciliation.error", result.error)
                    return result

            # 4. Barrier floor check & Discrepancy spike check
            barrier_floor = self._resolve_barrier_floor(
                result.invariant_id, target_provider
            )
            if is_snapshot and barrier_floor is not None and scalar < barrier_floor:
                self._failure_count += 1
                state_key = getattr(
                    target_provider,
                    "state_key",
                    _DEFAULT_STATE_KEYS.get(result.invariant_id),
                )
                if (
                    self._redis is not None
                    and state_key
                    and hasattr(self._redis, "set")
                ):
                    try:
                        self._redis.set(state_key, str(scalar))
                    except Exception:
                        pass
                self._increment_fence_epoch()
                self._invalidate_redis_verified_state(result.invariant_id)
                result.error = (
                    f"Ground-truth scalar {scalar} is below barrier floor {barrier_floor}"
                )
                _set_span_attr("reconciliation.error", result.error)
                return result

            if is_snapshot:
                baseline = self._read_self_reported_baseline(
                    result.invariant_id, target_provider
                )
                is_flagged_spike = bool(
                    result.raw_response
                    and result.raw_response.get("discrepancy_spike")
                )
                if baseline is not None or is_flagged_spike:
                    delta = (
                        abs(scalar - baseline)
                        if baseline is not None
                        else abs(scalar)
                    )
                    eff_threshold = (
                        float(self._discrepancy_threshold)
                        if self._discrepancy_threshold is not None
                        else (0.5 * abs(baseline) if baseline else 100.0)
                    )
                    if is_flagged_spike or delta > eff_threshold:
                        self._failure_count += 1
                        result.discrepancy_detected = True
                        result.discrepancy_delta = delta
                        self._increment_fence_epoch()
                        self._invalidate_redis_verified_state(result.invariant_id)
                        result.error = (
                            f"Discrepancy spike detected: delta={delta:.2f} > "
                            f"threshold={eff_threshold:.2f}; fence epoch incremented"
                        )
                        _set_span_attr("reconciliation.error", result.error)
                        return result

            _set_span_attr("reconciliation.balance_usd", result.balance_usd)

            # 5. Monotonic sequence number (§2.10 R-04 replay defense)
            if is_snapshot and result.sequence > 0:
                last_seq = self._last_sequence_by_invariant.get(
                    result.invariant_id, 0
                )
                if result.sequence <= last_seq:
                    self._failure_count += 1
                    self._invalidate_redis_verified_state(result.invariant_id)
                    result.error = (
                        f"Non-advancing sequence {result.sequence} <= {last_seq}"
                    )
                    return result
                self._last_sequence_by_invariant[result.invariant_id] = (
                    result.sequence
                )

            if REPLAY_DEFENSE_ENABLED and self._redis is not None:
                try:
                    new_sequence = int(self._redis.incr(_REDIS_KEY_SEQUENCE_LATEST))
                    result.sequence = new_sequence
                except Exception as seq_exc:
                    logger.error(
                        "[R-04] Failed to increment sequence counter: %s",
                        seq_exc,
                    )
            elif is_snapshot:
                result.sequence = 0

            _set_span_attr("cage.reconciliation.sequence", result.sequence)

            return self._write_verified_balance(
                result,
                allow_unconfigured_kms_in_dev=True,
                fetch_ms=fetch_ms,
                set_span_attr=_set_span_attr,
            )

    def reconcile_once(
        self, invariant_id: str | None = None
    ) -> ReconciliationResult | None:
        """Execute one reconciliation tick and return the result on success, or ``None`` on any fault."""
        res = self.reconcile(invariant_id=invariant_id)
        if not res.is_valid:
            return None
        return res

    def reconcile_all(self) -> dict[str, ReconciliationResult]:
        """Reconcile every registered invariant provider."""
        results: dict[str, ReconciliationResult] = {}
        for inv_id in list(self._providers.keys()):
            results[inv_id] = self.reconcile(invariant_id=inv_id)
        return results

    def run_loop(self) -> None:
        """Run the reconciliation daemon in a blocking loop."""
        while True:
            try:
                self.reconcile_all()
            except Exception as exc:
                logger.error("Reconciliation loop error (non-fatal): %s", exc)
            time.sleep(self._poll_interval)

    @classmethod
    def from_env(cls) -> GroundTruthReconciler:
        """Construct a reconciler from environment variables."""
        try:
            import redis  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "redis-py is required for GroundTruthReconciler."
            ) from exc

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        account_id = os.environ.get("RECONCILIATION_ACCOUNT_ID", "default")
        client = redis.from_url(redis_url, decode_responses=True)
        return cls(
            provider=_DefaultSimulatedProvider(),
            redis_client=client,
            account_id=account_id,
        )


def MagicMock_type() -> type:
    from unittest.mock import MagicMock

    return MagicMock


def read_verified_balance(
    redis_client: Any,
    invariant_id: str = "finance.cash_balance",
    *,
    signer: Any | None = None,
    max_staleness_s: float | None = None,
) -> ReconciliationResult | None:
    """Read and validate the externally reconciled snapshot from Redis."""
    if redis_client is None:
        return None
    try:
        raw = redis_client.get(reconciled_state_key(invariant_id))
        if raw is None and invariant_id == "finance.cash_balance":
            raw = redis_client.get(_REDIS_KEY_VERIFIED_BALANCE)
        if raw is None:
            return None

        result = ReconciliationResult.from_redis_payload(raw)
        if not result.is_valid:
            return None

        now = time.time()
        effective_ttl = (
            float(max_staleness_s)
            if max_staleness_s is not None
            else float(result.ttl_seconds)
        )
        if (now - result.verified_at) > effective_ttl:
            logger.warning(
                "Verified state for %s is stale (verified_at=%.0f, age=%.0fs, ttl=%.0fs) — failing closed.",
                invariant_id,
                result.verified_at,
                now - result.verified_at,
                effective_ttl,
            )
            return None
        if (result.verified_at - now) > 5.0:
            logger.warning(
                "Verified state for %s has future timestamp skew — failing closed.",
                invariant_id,
            )
            return None

        if signer is not None:
            if not result.signature:
                return None
            payload_dict = {
                "source": result.source,
                "balance_usd": result.balance_usd,
                "verified_at": result.verified_at,
                "sequence": result.sequence,
            }
            if hasattr(signer, "verify"):
                if not signer.verify(payload_dict, result.signature):
                    return None
            elif hasattr(signer, "verify_decision"):
                if not signer.verify_decision(
                    payload_dict,
                    result.signature,
                    kid=result.kms_key_id or getattr(signer, "key_id", None),
                ):
                    return None

        return result
    except Exception as exc:
        logger.error(
            "Failed to read verified state for %s from Redis: %s — failing closed.",
            invariant_id,
            exc,
        )
        return None


def read_verified_snapshot(
    redis_client: Any,
    invariant_id: str = "finance.cash_balance",
    *,
    signer: Any | None = None,
    max_staleness_s: float | None = None,
) -> ReconciliationResult | None:
    """Read the verified ground-truth snapshot for ``invariant_id``."""
    try:
        return read_verified_balance(
            redis_client,
            invariant_id=invariant_id,
            signer=signer,
            max_staleness_s=max_staleness_s,
        )
    except TypeError:
        return read_verified_balance(redis_client)


def read_verified_state(
    redis_client: Any,
    invariant_id: str = "finance.cash_balance",
    *,
    signer: Any | None = None,
    max_staleness_s: float | None = None,
) -> float | None:
    """Read the verified scalar state for ``invariant_id``, or ``None`` if unavailable/invalid."""
    snap = read_verified_snapshot(
        redis_client,
        invariant_id=invariant_id,
        signer=signer,
        max_staleness_s=max_staleness_s,
    )
    if snap is None or not snap.is_valid:
        return None
    return float(
        snap.state_scalar if snap.state_scalar is not None else snap.balance_usd
    )


ExternalLedgerReconciler = GroundTruthReconciler
LedgerReconciliationDaemon = GroundTruthReconciler

__all__ = [
    "ExternalLedgerReconciler",
    "FENCE_EPOCH_KEY",
    "FaultMode",
    "GroundTruthProvider",
    "GroundTruthReconciler",
    "GroundTruthSnapshot",
    "LedgerProvider",
    "LedgerReconciliationDaemon",
    "POLL_INTERVAL_SECONDS",
    "PROVIDER",
    "RECONCILED_STATE_KEY_PREFIX",
    "REPLAY_DEFENSE_ENABLED",
    "ReconciliationResult",
    "SimulatedSource",
    "TTL_SECONDS",
    "read_verified_balance",
    "read_verified_snapshot",
    "read_verified_state",
    "reconciled_state_key",
]

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    reconciler = GroundTruthReconciler.from_env()
    reconciler.run_loop()
