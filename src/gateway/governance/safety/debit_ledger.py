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

"""Settlement-aware local-debit ledger shared by the CBF and the reconciler.

The Control Barrier Function debits state the instant it admits an action,
but the external ground-truth source (a custodian, a lab feed, a sensor
aggregator) only reflects that debit after a settlement delay. Between the
two, the reconciled scalar overstates the headroom. This module holds the
O(1) ledger that closes the gap (ADR-010):

* ``cbf:debits``          HASH   ``debit_id -> JSON{amount, submitted_at, ...}``
* ``cbf:debits:pending``  ZSET   score commit time, member ``debit_id`` —
  admitted but not yet confirmed as executed
* ``cbf:debits:by_time``  ZSET   score confirm time, member ``debit_id`` —
  confirmed (executed) debits, the only ones ``settle`` may prune
* ``cbf:debits:total``    STRING running sum of outstanding amounts (pending
  and confirmed)
* ``cbf:debits:rolled_back`` HASH ``debit_id -> rolled_back_at`` (tombstones
  that make rollback exactly idempotent; pruned by ``settle``)

The commit and rollback scripts that *write* the ledger live next to the
barrier in :mod:`src.gateway.governance.safety.cbf_engine` because they must
run in the same Lua hop as the fence CAS. A commit enters ``pending``;
``confirm`` (ADR-009, after the action executed) moves it to ``by_time``
stamped with the confirm time, which is at or after the custodian's own
receipt time. The *settle* script here runs only in the reconciliation
daemon, off the hot path, after a verified snapshot has been published. Only
``settle`` ever lowers the total, and only for *confirmed* debits stamped at
or before a cutoff derived from the snapshot's attested ``settled_through``
(or the configured lag fallback) minus a clock-skew margin. A pending debit
is never settled: if its confirm never arrives (the governor's settlement
hold expired), ``settle`` promotes it to ``by_time`` stamped with the
promotion time once it is older than ``reconciliation.pending_debit_max_age_seconds``.
Every race therefore errs toward *less* headroom, never more.
"""

from __future__ import annotations

import inspect
import logging
import math
import time
from typing import Any

logger = logging.getLogger("SafetyLayer.debit_ledger")

DEBITS_KEY = "cbf:debits"
DEBITS_BY_TIME_KEY = "cbf:debits:by_time"
DEBITS_PENDING_KEY = "cbf:debits:pending"
DEBITS_TOTAL_KEY = "cbf:debits:total"
DEBITS_ROLLED_BACK_KEY = "cbf:debits:rolled_back"

LUA_SETTLE_DEBITS: str = """
-- Settle confirmed debits stamped at or before ARGV[1] and re-derive the total.
-- KEYS[1]: cbf:debits (HASH)        KEYS[2]: cbf:debits:by_time (ZSET, confirmed)
-- KEYS[3]: cbf:debits:total         KEYS[4]: cbf:debits:rolled_back (HASH)
-- KEYS[5]: cbf:debits:pending (ZSET, unconfirmed)
-- ARGV[1]: cutoff (float string; inclusive)
-- ARGV[2]: orphan cutoff (float string, may be empty): pending debits committed
--          at or before it are promoted to KEYS[2] stamped ARGV[3]
-- ARGV[3]: promotion stamp (float string; now)
-- Returns: {settled, promoted}
local cutoff = tonumber(ARGV[1])
if not cutoff then
    return {0, 0}
end
-- A debit whose confirm never arrives may still have executed: promote it as
-- confirmed *now*. ``now`` is after every snapshot cutoff, so a promoted debit
-- is never settled in the pass that promotes it.
local promoted = 0
local orphan_cutoff = tonumber(ARGV[2] or "")
local stamp = tonumber(ARGV[3] or "")
if orphan_cutoff and stamp then
    local orphans = redis.call('ZRANGEBYSCORE', KEYS[5], '-inf', ARGV[2])
    for _, id in ipairs(orphans) do
        redis.call('ZREM', KEYS[5], id)
        redis.call('ZADD', KEYS[2], ARGV[3], id)
        promoted = promoted + 1
    end
end
local ids = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
for _, id in ipairs(ids) do
    redis.call('HDEL', KEYS[1], id)
    redis.call('ZREM', KEYS[2], id)
end
-- Recompute the running total from the surviving entries so INCRBYFLOAT
-- drift never accumulates across polls.
local total = 0.0
local remaining = redis.call('HVALS', KEYS[1])
for _, entry in ipairs(remaining) do
    local ok, data = pcall(cjson.decode, entry)
    if ok and data and tonumber(data.amount) then
        total = total + tonumber(data.amount)
    end
end
redis.call('SET', KEYS[3], tostring(total))
-- Tombstones older than the cutoff can no longer collide with a live debit.
local tombstones = redis.call('HGETALL', KEYS[4])
for i = 1, #tombstones, 2 do
    local ts = tonumber(tombstones[i + 1])
    if ts and ts <= cutoff then
        redis.call('HDEL', KEYS[4], tombstones[i])
    end
end
return {#ids, promoted}
"""

LUA_UNSETTLED_TOTAL: str = """
-- Read-only: sum of debits a snapshot with this cutoff cannot have absorbed:
-- every pending debit plus confirmed debits stamped strictly after ARGV[1].
-- KEYS[1]: cbf:debits (HASH)   KEYS[2]: cbf:debits:by_time (ZSET)
-- KEYS[3]: cbf:debits:pending (ZSET)
-- ARGV[1]: cutoff (float string; exclusive)
local cutoff = tonumber(ARGV[1])
if not cutoff then
    return "0"
end
local ids = redis.call('ZRANGEBYSCORE', KEYS[2], '(' .. ARGV[1], '+inf')
for _, id in ipairs(redis.call('ZRANGE', KEYS[3], 0, -1)) do
    table.insert(ids, id)
end
local total = 0.0
local batch = 500
for start = 1, #ids, batch do
    local stop = math.min(start + batch - 1, #ids)
    local entries = redis.call('HMGET', KEYS[1], unpack(ids, start, stop))
    for _, entry in ipairs(entries) do
        if entry then
            local ok, data = pcall(cjson.decode, entry)
            if ok and data and tonumber(data.amount) then
                total = total + tonumber(data.amount)
            end
        end
    end
end
return tostring(total)
"""

LUA_CONFIRM_DEBIT: str = """
-- Confirm an executed debit: move it from pending to by_time stamped ARGV[2].
-- KEYS[1]: cbf:debits (HASH)   KEYS[2]: cbf:debits:by_time (ZSET)
-- KEYS[3]: cbf:debits:pending (ZSET)
-- ARGV[1]: debit_id            ARGV[2]: confirm time (float string)
-- Returns: 1 if confirmed, 0 if the debit is not pending (already confirmed,
-- rolled back, promoted or never ledgered on this primary).
if not redis.call('ZSCORE', KEYS[3], ARGV[1]) then
    return 0
end
redis.call('ZREM', KEYS[3], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
local entry = redis.call('HGET', KEYS[1], ARGV[1])
if entry then
    local ok, data = pcall(cjson.decode, entry)
    if ok and type(data) == 'table' then
        data.confirmed_at = tonumber(ARGV[2])
        redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(data))
    end
end
return 1
"""


def settlement_cutoff(
    verified_at: float,
    settled_through: float | None,
    *,
    lag_seconds: float,
    skew_seconds: float,
) -> float:
    """Latest ``submitted_at`` a snapshot is trusted to have absorbed.

    A provider that attests ``settled_through`` is believed up to that
    instant (but never past the snapshot's own ``verified_at``); one that
    does not is assumed to lag by ``lag_seconds``. ``skew_seconds`` is then
    subtracted because ``submitted_at`` is stamped by the gateway's clock and
    ``settled_through`` by the provider's.
    """
    if settled_through is not None and math.isfinite(settled_through):
        base = min(float(settled_through), float(verified_at))
    else:
        base = float(verified_at) - float(lag_seconds)
    return base - float(skew_seconds)


def _unwrap_sync(client: Any) -> Any:
    raw = getattr(client, "_get", None)
    return raw() if callable(raw) else client


def _coerce_float(value: Any) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    if not isinstance(value, (int, float, str)):
        # Mocks and other non-replies never count as outstanding debits.
        return 0.0
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return parsed if math.isfinite(parsed) else 0.0


def _settle_argv(cutoff: float, orphan_before: float | None, now: float | None) -> list[str]:
    promote = orphan_before is not None and math.isfinite(orphan_before)
    stamp = now if now is not None else time.time()
    return [
        repr(float(cutoff)),
        repr(float(orphan_before)) if promote else "",
        repr(float(stamp)) if promote else "",
    ]


def _settled_count(res: Any, cutoff: float) -> int:
    if isinstance(res, (list, tuple)) and len(res) == 2:
        settled, promoted = int(res[0]), int(res[1])
    else:
        settled, promoted = (int(res) if res is not None else 0), 0
    if promoted:
        logger.warning(
            "Promoted %d unconfirmed debit(s) to confirmed (no confirm within the "
            "pending-debit max age); settled %d through %s",
            promoted,
            settled,
            cutoff,
        )
    return settled


def _settle_keys() -> list[str]:
    return [
        DEBITS_KEY,
        DEBITS_BY_TIME_KEY,
        DEBITS_TOTAL_KEY,
        DEBITS_ROLLED_BACK_KEY,
        DEBITS_PENDING_KEY,
    ]


def settle_debits_sync(
    client: Any,
    cutoff: float,
    *,
    orphan_before: float | None = None,
    now: float | None = None,
) -> int:
    """Prune confirmed debits stamped at or before ``cutoff``; return how many settled.

    With ``orphan_before``, pending debits committed at or before it are first
    promoted to confirmed, stamped ``now`` (default: the current time).
    """
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0
    raw_client = _unwrap_sync(client)
    keys = _settle_keys()
    try:
        res = raw_client.eval(
            LUA_SETTLE_DEBITS, len(keys), *keys, *_settle_argv(cutoff, orphan_before, now)
        )
        return _settled_count(res, cutoff)
    except Exception as exc:
        logger.warning("Failed to settle local debits through %s: %s", cutoff, exc)
        return 0


async def settle_debits(
    client: Any,
    cutoff: float,
    *,
    orphan_before: float | None = None,
    now: float | None = None,
) -> int:
    """Async variant of :func:`settle_debits_sync` for in-process callers."""
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0
    keys = _settle_keys()
    try:
        res = client.eval(
            LUA_SETTLE_DEBITS, len(keys), *keys, *_settle_argv(cutoff, orphan_before, now)
        )
        if inspect.isawaitable(res):
            res = await res
        return _settled_count(res, cutoff)
    except Exception as exc:
        logger.warning("Failed to settle local debits through %s: %s", cutoff, exc)
        return 0


async def confirm_debit(client: Any, debit_id: str, *, now: float | None = None) -> bool:
    """Mark ``debit_id`` executed: move it from pending to confirmed at ``now``.

    Returns ``False`` if the debit is not pending (already confirmed, rolled
    back, promoted, or never ledgered on this primary). Redis errors propagate:
    the governor reports a failed confirm as ``CONFIRM_FAILED``, and the entry
    stays pending, which only withholds headroom.
    """
    stamp = now if now is not None else time.time()
    res = client.eval(
        LUA_CONFIRM_DEBIT,
        3,
        DEBITS_KEY,
        DEBITS_BY_TIME_KEY,
        DEBITS_PENDING_KEY,
        debit_id,
        repr(float(stamp)),
    )
    if inspect.isawaitable(res):
        res = await res
    return bool(int(res or 0))


def unsettled_total_sync(client: Any, cutoff: float) -> float:
    """Pending debits plus confirmed ones stamped after ``cutoff`` (daemon-side read)."""
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0.0
    raw_client = _unwrap_sync(client)
    try:
        res = raw_client.eval(
            LUA_UNSETTLED_TOTAL,
            3,
            DEBITS_KEY,
            DEBITS_BY_TIME_KEY,
            DEBITS_PENDING_KEY,
            repr(float(cutoff)),
        )
        return _coerce_float(res)
    except Exception as exc:
        logger.warning("Failed to read unsettled debit total after %s: %s", cutoff, exc)
        return 0.0


def outstanding_debits_total_sync(client: Any) -> float:
    """Current value of ``cbf:debits:total`` (0.0 when absent)."""
    if client is None:
        return 0.0
    raw_client = _unwrap_sync(client)
    try:
        return _coerce_float(raw_client.get(DEBITS_TOTAL_KEY))
    except Exception as exc:
        logger.warning("Failed to read outstanding debit total: %s", exc)
        return 0.0


async def outstanding_debits_total(client: Any) -> float:
    """Async read of ``cbf:debits:total`` (0.0 when absent)."""
    if client is None:
        return 0.0
    try:
        res = client.get(DEBITS_TOTAL_KEY)
        if inspect.isawaitable(res):
            res = await res
        return _coerce_float(res)
    except Exception as exc:
        logger.warning("Failed to read outstanding debit total: %s", exc)
        return 0.0


__all__ = [
    "DEBITS_BY_TIME_KEY",
    "DEBITS_KEY",
    "DEBITS_PENDING_KEY",
    "DEBITS_ROLLED_BACK_KEY",
    "DEBITS_TOTAL_KEY",
    "LUA_CONFIRM_DEBIT",
    "LUA_SETTLE_DEBITS",
    "LUA_UNSETTLED_TOTAL",
    "confirm_debit",
    "outstanding_debits_total",
    "outstanding_debits_total_sync",
    "settle_debits",
    "settle_debits_sync",
    "settlement_cutoff",
    "unsettled_total_sync",
]
