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
* ``cbf:debits:by_time``  ZSET   score ``submitted_at``, member ``debit_id``
* ``cbf:debits:total``    STRING running sum of outstanding amounts
* ``cbf:debits:rolled_back`` HASH ``debit_id -> rolled_back_at`` (tombstones
  that make rollback exactly idempotent; pruned by ``settle``)

The commit and rollback scripts that *write* the ledger live next to the
barrier in :mod:`src.gateway.governance.safety.cbf_engine` because they must
run in the same Lua hop as the fence CAS. The *settle* script here runs only
in the reconciliation daemon, off the hot path, after a verified snapshot has
been published. Only ``settle`` ever lowers the total, and only for debits
submitted at or before a cutoff derived from the snapshot's attested
``settled_through`` (or the configured lag fallback) minus a clock-skew
margin. Every race therefore errs toward *less* headroom, never more.
"""

from __future__ import annotations

import inspect
import logging
import math
from typing import Any

logger = logging.getLogger("SafetyLayer.debit_ledger")

DEBITS_KEY = "cbf:debits"
DEBITS_BY_TIME_KEY = "cbf:debits:by_time"
DEBITS_TOTAL_KEY = "cbf:debits:total"
DEBITS_ROLLED_BACK_KEY = "cbf:debits:rolled_back"

LUA_SETTLE_DEBITS: str = """
-- Settle local debits submitted at or before ARGV[1] and re-derive the total.
-- KEYS[1]: cbf:debits (HASH)        KEYS[2]: cbf:debits:by_time (ZSET)
-- KEYS[3]: cbf:debits:total         KEYS[4]: cbf:debits:rolled_back (HASH)
-- ARGV[1]: cutoff (float string; inclusive)
-- Returns: number of debits settled.
local cutoff = tonumber(ARGV[1])
if not cutoff then
    return 0
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
return #ids
"""

LUA_UNSETTLED_TOTAL: str = """
-- Read-only: sum of debits submitted strictly after ARGV[1].
-- KEYS[1]: cbf:debits (HASH)   KEYS[2]: cbf:debits:by_time (ZSET)
-- ARGV[1]: cutoff (float string; exclusive)
local cutoff = tonumber(ARGV[1])
if not cutoff then
    return "0"
end
local ids = redis.call('ZRANGEBYSCORE', KEYS[2], '(' .. ARGV[1], '+inf')
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


def settle_debits_sync(client: Any, cutoff: float) -> int:
    """Prune debits submitted at or before ``cutoff``; return how many settled."""
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0
    raw_client = _unwrap_sync(client)
    try:
        res = raw_client.eval(
            LUA_SETTLE_DEBITS,
            4,
            DEBITS_KEY,
            DEBITS_BY_TIME_KEY,
            DEBITS_TOTAL_KEY,
            DEBITS_ROLLED_BACK_KEY,
            repr(float(cutoff)),
        )
        return int(res) if res is not None else 0
    except Exception as exc:
        logger.warning("Failed to settle local debits through %s: %s", cutoff, exc)
        return 0


async def settle_debits(client: Any, cutoff: float) -> int:
    """Async variant of :func:`settle_debits_sync` for in-process callers."""
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0
    try:
        res = client.eval(
            LUA_SETTLE_DEBITS,
            4,
            DEBITS_KEY,
            DEBITS_BY_TIME_KEY,
            DEBITS_TOTAL_KEY,
            DEBITS_ROLLED_BACK_KEY,
            repr(float(cutoff)),
        )
        if inspect.isawaitable(res):
            res = await res
        return int(res) if res is not None else 0
    except Exception as exc:
        logger.warning("Failed to settle local debits through %s: %s", cutoff, exc)
        return 0


def unsettled_total_sync(client: Any, cutoff: float) -> float:
    """Sum of debits submitted strictly after ``cutoff`` (daemon-side read)."""
    if client is None or cutoff is None or not math.isfinite(cutoff):
        return 0.0
    raw_client = _unwrap_sync(client)
    try:
        res = raw_client.eval(
            LUA_UNSETTLED_TOTAL,
            2,
            DEBITS_KEY,
            DEBITS_BY_TIME_KEY,
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
    "DEBITS_ROLLED_BACK_KEY",
    "DEBITS_TOTAL_KEY",
    "LUA_SETTLE_DEBITS",
    "LUA_UNSETTLED_TOTAL",
    "outstanding_debits_total",
    "outstanding_debits_total_sync",
    "settle_debits",
    "settle_debits_sync",
    "settlement_cutoff",
    "unsettled_total_sync",
]
