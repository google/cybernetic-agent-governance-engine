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

"""Shared, principal-keyed Redis GCRA rate limiter for the CAGE gateway (PR A4).

Replaces per-pod, per-IP sliding-window limiters that collapsed all in-mesh
callers behind Linkerd into a single peer IP bucket.

Each request atomically checks two Generic Cell Rate Algorithm (GCRA) buckets
via a single Redis Lua script (``register_script`` / ``EVALSHA``):

  1. ``rl:{route}:id:{l5d-client-id}`` — fleet budget for the calling workload;
  2. ``rl:{route}:p:{principal}``      — per end-user or session budget.

The ``x-cage-principal`` header is sanitized and length-capped (64 chars), and
is only trusted when the request has already been authenticated with a verified
Linkerd workload identity (``l5d-client-id``).

If Redis is unavailable or raises an error, the limiter falls back to an
in-process GCRA limiter keyed on the same ``(route, identity, principal)``
tuple and increments ``cage_rate_limit_backend_errors_total``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from cachetools import TTLCache
from fastapi import Request

from src.gateway.server.workload_identity import extract_client_identity

logger = logging.getLogger("Gateway.RateLimit")

PRINCIPAL_HEADER = "x-cage-principal"
_MAX_PRINCIPAL_LEN = 64
_SAFE_PRINCIPAL_RE = re.compile(r"[^a-zA-Z0-9._:@/-]+")

DEFAULT_PRINCIPAL_PER_MIN = 120
DEFAULT_IDENTITY_PER_MIN = 600
DEFAULT_WINDOW_SECONDS = 60.0

# ---------------------------------------------------------------------------
# Prometheus metrics (optional — degrades gracefully when absent)
# ---------------------------------------------------------------------------

_METRICS_AVAILABLE = False
rate_limit_backend_errors_total: Any = None
rate_limit_hits_total: Any = None
rate_limit_active_buckets: Any = None

try:
    from prometheus_client import REGISTRY, Counter, Gauge

    _METRICS_AVAILABLE = True

    def _get_or_create_counter(
        name: str, doc: str, labelnames: tuple[str, ...] = ()
    ) -> Any:
        try:
            return Counter(name, doc, labelnames)
        except ValueError:
            return REGISTRY._names_to_collectors.get(name)

    def _get_or_create_gauge(name: str, doc: str) -> Any:
        try:
            return Gauge(name, doc)
        except ValueError:
            return REGISTRY._names_to_collectors.get(name)

    rate_limit_backend_errors_total = _get_or_create_counter(
        "cage_rate_limit_backend_errors_total",
        "Total Redis backend errors during gateway rate-limit evaluation (fell back to local GCRA)",
        ("route",),
    )
    rate_limit_hits_total = _get_or_create_counter(
        "cage_rate_limit_hits_total",
        "Total gateway rate-limit rejections by route and bucket scope",
        ("route", "scope"),
    )
    rate_limit_active_buckets = _get_or_create_gauge(
        "mcp_rate_limit_active_buckets",
        "Current number of active fallback rate-limit tracking buckets",
    )
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Dual-bucket GCRA Lua script (atomic across identity + principal buckets)
# ---------------------------------------------------------------------------
# KEYS[1] = rl:{route}:id:{identity}
# KEYS[2] = rl:{route}:p:{principal}
# ARGV[1] = now_ms (if <= 0, uses Redis server TIME)
# ARGV[2] = id_emission_interval_ms   (window_ms / identity_limit)
# ARGV[3] = id_delay_tolerance_ms     (window_ms)
# ARGV[4] = p_emission_interval_ms    (window_ms / principal_limit)
# ARGV[5] = p_delay_tolerance_ms      (window_ms)
#
# Returns: {allowed (1|0), retry_after_ms (int), blocked_scope (''|'identity'|'principal')}
#
# Not idempotent, by design: if redis-py re-sends the script after a lost
# reply, an admitted request is charged twice (both TATs advance by 2T) and
# the re-send may answer 429 for a request the first run admitted. That only
# ever throttles more, never admits beyond the budget, so it is accepted
# rather than storing an operation id with every bucket.
LUA_GCRA_DUAL_BUCKET = """
local id_key = KEYS[1]
local p_key = KEYS[2]
local now_ms = tonumber(ARGV[1])
if not now_ms or now_ms <= 0 then
    local t = redis.call('TIME')
    now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local id_T = tonumber(ARGV[2])
local id_tau = tonumber(ARGV[3])
local p_T = tonumber(ARGV[4])
local p_tau = tonumber(ARGV[5])

local id_tat = tonumber(redis.call('GET', id_key) or '0')
local p_tat = tonumber(redis.call('GET', p_key) or '0')

local id_base = math.max(now_ms, id_tat)
local new_id_tat = id_base + id_T
local id_allow_at = id_base - (id_tau - id_T)
if now_ms + 1e-6 < id_allow_at then
    local retry_ms = math.ceil(id_allow_at - now_ms)
    return {0, retry_ms, 'identity'}
end

local p_base = math.max(now_ms, p_tat)
local new_p_tat = p_base + p_T
local p_allow_at = p_base - (p_tau - p_T)
if now_ms + 1e-6 < p_allow_at then
    local retry_ms = math.ceil(p_allow_at - now_ms)
    return {0, retry_ms, 'principal'}
end

local id_ttl = math.max(1000, math.ceil(new_id_tat - now_ms + id_T))
local p_ttl = math.max(1000, math.ceil(new_p_tat - now_ms + p_T))
redis.call('PSETEX', id_key, id_ttl, tostring(new_id_tat))
redis.call('PSETEX', p_key, p_ttl, tostring(new_p_tat))
return {1, 0, ''}
"""


@dataclass(frozen=True)
class RateLimitVerdict:
    """Outcome of a dual-bucket GCRA rate-limit evaluation."""

    allowed: bool
    retry_after_seconds: int = 0
    scope: str = ""
    identity: str = ""
    principal: str = ""


def sanitize_principal(raw: str | None) -> str:
    """Sanitize and length-cap an ``x-cage-principal`` header value."""
    if not raw or not isinstance(raw, str):
        return "anonymous"
    cleaned = _SAFE_PRINCIPAL_RE.sub("_", raw.strip())[:_MAX_PRINCIPAL_LEN].strip("_")
    return cleaned if cleaned else "anonymous"


def extract_rate_limit_keys(request: Request) -> tuple[str, str]:
    """Extract ``(identity, principal)`` from a request.

    ``x-cage-principal`` is trusted ONLY when the request carries a verified
    Linkerd workload identity (``l5d-client-id``) or when ``request.state``
    was explicitly marked trusted by ``WorkloadIdentityMiddleware``. Without a
    verified workload identity, ``x-cage-principal`` is ignored so an
    unauthenticated caller cannot spoof distinct principal buckets.
    """
    scope = getattr(request, "scope", None) or {}
    verified_identity: str | None = None
    try:
        verified_identity = extract_client_identity(scope)
    except Exception:
        verified_identity = None

    if verified_identity:
        raw_principal: str | None = None
        headers = getattr(request, "headers", None)
        if headers is not None and hasattr(headers, "get"):
            candidate = headers.get(PRINCIPAL_HEADER)
            if isinstance(candidate, str):
                raw_principal = candidate
        if raw_principal is None:
            for k, v in scope.get("headers", []):
                if k.lower() == PRINCIPAL_HEADER.encode("latin-1"):
                    raw_principal = v.decode("latin-1", errors="ignore")
                    break
        principal = sanitize_principal(raw_principal)
        return verified_identity, principal

    # Fallback when called in isolated unit tests without Linkerd headers:
    # do NOT trust x-cage-principal; collapse principal to the untrusted client host.
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) or "unauthenticated"
    safe_host = sanitize_principal(host)
    return f"untrusted:{safe_host}", f"untrusted:{safe_host}"


def resolve_rate_limits(
    *,
    principal_per_min: int | None = None,
    identity_per_min: int | None = None,
    window_seconds: float | None = None,
    legacy_max_calls: int | None = None,
    legacy_window_seconds: float | None = None,
) -> tuple[int, int, float]:
    """Resolve ``(principal_limit, identity_limit, window_seconds)`` from env or overrides."""
    if window_seconds is not None:
        win = float(window_seconds)
    elif legacy_window_seconds is not None:
        win = float(legacy_window_seconds)
    else:
        win = float(
            os.environ.get(
                "CAGE_RATE_LIMIT_WINDOW_SECONDS",
                os.environ.get(
                    "VALIDATE_ACTION_RATE_WINDOW",
                    os.environ.get(
                        "MCP_RATE_LIMIT_WINDOW_SECONDS", str(DEFAULT_WINDOW_SECONDS)
                    ),
                ),
            )
        )
    win = max(1.0, win)

    if principal_per_min is not None:
        p_limit = int(principal_per_min)
    elif legacy_max_calls is not None:
        p_limit = int(legacy_max_calls)
    else:
        p_limit = int(
            os.environ.get(
                "CAGE_RATE_LIMIT_PRINCIPAL_PER_MIN",
                os.environ.get(
                    "VALIDATE_ACTION_RATE_LIMIT",
                    os.environ.get(
                        "MCP_RATE_LIMIT_MAX_CALLS", str(DEFAULT_PRINCIPAL_PER_MIN)
                    ),
                ),
            )
        )
    p_limit = max(1, p_limit)

    if identity_per_min is not None:
        id_limit = int(identity_per_min)
    else:
        raw_id = os.environ.get("CAGE_RATE_LIMIT_IDENTITY_PER_MIN")
        if raw_id is not None:
            id_limit = int(raw_id)
        else:
            id_limit = max(DEFAULT_IDENTITY_PER_MIN, p_limit * 5)
    id_limit = max(p_limit, id_limit)

    return p_limit, id_limit, win


class SharedRateLimiter:
    """Dual-bucket GCRA rate limiter backed by Redis Lua (``EVALSHA``) with local fallback."""

    def __init__(
        self,
        redis_client: Any = None,
        *,
        principal_per_min: int | None = None,
        identity_per_min: int | None = None,
        window_seconds: float | None = None,
    ) -> None:
        self._redis: Any = redis_client
        self._script: Any = None
        self._script_redis_id: int | None = None
        self._principal_per_min = principal_per_min
        self._identity_per_min = identity_per_min
        self._window_seconds = window_seconds
        self._fallback_tat: TTLCache[str, float] = TTLCache(maxsize=10000, ttl=3600)
        self._fallback_lock = asyncio.Lock()

    def bind_redis(self, redis_client: Any) -> None:
        """Bind or replace the async Redis client (e.g. during FastAPI lifespan startup)."""
        self._redis = redis_client
        self._script = None
        self._script_redis_id = None

    def clear(self) -> None:
        """Clear in-process fallback buckets (for test isolation)."""
        self._fallback_tat.clear()

    def _get_script(self, redis_conn: Any) -> Any:
        if self._script is None or self._script_redis_id != id(redis_conn):
            reg_fn = getattr(redis_conn, "register_script", None)
            if callable(reg_fn):
                self._script = reg_fn(LUA_GCRA_DUAL_BUCKET)
                self._script_redis_id = id(redis_conn)
            else:
                self._script = None
        return self._script

    async def _eval_redis(
        self,
        redis_conn: Any,
        *,
        id_key: str,
        p_key: str,
        now_ms: int,
        id_T: float,
        id_tau: float,
        p_T: float,
        p_tau: float,
    ) -> list[Any]:
        script = self._get_script(redis_conn)
        args = [now_ms, id_T, id_tau, p_T, p_tau]
        if script is not None:
            res = script(keys=[id_key, p_key], args=args, client=redis_conn)
            if asyncio.iscoroutine(res) or hasattr(res, "__await__"):
                res = await res
            return list(res)
        res = await redis_conn.eval(LUA_GCRA_DUAL_BUCKET, 2, id_key, p_key, *args)
        return list(res)

    async def _check_fallback(
        self,
        *,
        route: str,
        id_key: str,
        p_key: str,
        identity: str,
        principal: str,
        id_T: float,
        id_tau: float,
        p_T: float,
        p_tau: float,
    ) -> RateLimitVerdict:
        now_ms = time.monotonic() * 1000.0
        async with self._fallback_lock:
            id_tat = float(self._fallback_tat.get(id_key, 0.0))
            p_tat = float(self._fallback_tat.get(p_key, 0.0))

            id_base = max(now_ms, id_tat)
            new_id_tat = id_base + id_T
            id_allow_at = id_base - (id_tau - id_T)
            if now_ms + 1e-6 < id_allow_at:
                retry_s = max(1, math.ceil((id_allow_at - now_ms) / 1000.0))
                if _METRICS_AVAILABLE and rate_limit_hits_total is not None:
                    rate_limit_hits_total.labels(route=route, scope="identity").inc()
                return RateLimitVerdict(
                    allowed=False,
                    retry_after_seconds=retry_s,
                    scope="identity",
                    identity=identity,
                    principal=principal,
                )

            p_base = max(now_ms, p_tat)
            new_p_tat = p_base + p_T
            p_allow_at = p_base - (p_tau - p_T)
            if now_ms + 1e-6 < p_allow_at:
                retry_s = max(1, math.ceil((p_allow_at - now_ms) / 1000.0))
                if _METRICS_AVAILABLE and rate_limit_hits_total is not None:
                    rate_limit_hits_total.labels(route=route, scope="principal").inc()
                return RateLimitVerdict(
                    allowed=False,
                    retry_after_seconds=retry_s,
                    scope="principal",
                    identity=identity,
                    principal=principal,
                )

            self._fallback_tat[id_key] = new_id_tat
            self._fallback_tat[p_key] = new_p_tat
            if _METRICS_AVAILABLE and rate_limit_active_buckets is not None:
                rate_limit_active_buckets.set(len(self._fallback_tat))
            return RateLimitVerdict(
                allowed=True,
                retry_after_seconds=0,
                scope="",
                identity=identity,
                principal=principal,
            )

    async def check(
        self,
        route: str,
        *,
        identity: str,
        principal: str,
        redis_override: Any = None,
        principal_per_min: int | None = None,
        identity_per_min: int | None = None,
        window_seconds: float | None = None,
        now_ms: int = 0,
    ) -> RateLimitVerdict:
        """Evaluate the dual-bucket GCRA rate limit for ``(route, identity, principal)``."""
        p_limit, id_limit, win_s = resolve_rate_limits(
            principal_per_min=principal_per_min or self._principal_per_min,
            identity_per_min=identity_per_min or self._identity_per_min,
            window_seconds=window_seconds or self._window_seconds,
        )
        win_ms = win_s * 1000.0
        id_T = win_ms / float(id_limit)
        id_tau = win_ms
        p_T = win_ms / float(p_limit)
        p_tau = win_ms

        id_key = f"rl:{route}:id:{identity}"
        p_key = f"rl:{route}:p:{principal}"

        redis_conn = redis_override if redis_override is not None else self._redis
        if redis_conn is not None:
            try:
                raw = await self._eval_redis(
                    redis_conn,
                    id_key=id_key,
                    p_key=p_key,
                    now_ms=now_ms,
                    id_T=id_T,
                    id_tau=id_tau,
                    p_T=p_T,
                    p_tau=p_tau,
                )
                allowed = bool(int(raw[0]))
                retry_ms = int(raw[1])
                scope_raw = raw[2]
                scope = (
                    scope_raw.decode("utf-8", errors="ignore")
                    if isinstance(scope_raw, bytes)
                    else str(scope_raw)
                )
                if not allowed:
                    retry_s = max(1, math.ceil(retry_ms / 1000.0))
                    if _METRICS_AVAILABLE and rate_limit_hits_total is not None:
                        rate_limit_hits_total.labels(
                            route=route, scope=scope or "principal"
                        ).inc()
                    return RateLimitVerdict(
                        allowed=False,
                        retry_after_seconds=retry_s,
                        scope=scope or "principal",
                        identity=identity,
                        principal=principal,
                    )
                return RateLimitVerdict(
                    allowed=True,
                    retry_after_seconds=0,
                    scope="",
                    identity=identity,
                    principal=principal,
                )
            except Exception as exc:
                logger.warning(
                    "⚠️ Rate-limit Redis backend error on route=%s (%s) — falling back to local GCRA",
                    route,
                    exc,
                )
                if _METRICS_AVAILABLE and rate_limit_backend_errors_total is not None:
                    rate_limit_backend_errors_total.labels(route=route).inc()

        return await self._check_fallback(
            route=route,
            id_key=id_key,
            p_key=p_key,
            identity=identity,
            principal=principal,
            id_T=id_T,
            id_tau=id_tau,
            p_T=p_T,
            p_tau=p_tau,
        )

    async def check_request(
        self,
        request: Request,
        route: str,
        *,
        principal_per_min: int | None = None,
        identity_per_min: int | None = None,
        window_seconds: float | None = None,
    ) -> RateLimitVerdict:
        """Extract ``(identity, principal)`` from ``request`` and evaluate the limiter."""
        identity, principal = extract_rate_limit_keys(request)
        app = getattr(request, "app", None)
        app_state = getattr(app, "state", None) if app is not None else None
        redis_override = getattr(app_state, "rate_limit_redis", None) or getattr(
            app_state, "redis", None
        )
        return await self.check(
            route,
            identity=identity,
            principal=principal,
            redis_override=redis_override,
            principal_per_min=principal_per_min,
            identity_per_min=identity_per_min,
            window_seconds=window_seconds,
        )


_default_limiter = SharedRateLimiter()


def get_shared_rate_limiter() -> SharedRateLimiter:
    """Return the process-wide shared rate limiter singleton."""
    return _default_limiter


def build_rate_limit_redis_from_env() -> Any:
    """Build an async Redis client for rate limiting via ``build_async_redis`` when configured."""
    from src.gateway.infrastructure.redis_client import build_async_redis

    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        host = os.environ.get("REDIS_HOST", "").strip()
        if not host:
            return None
        port = os.environ.get("REDIS_PORT", "6379").strip() or "6379"
        scheme = (
            "rediss"
            if os.environ.get("REDIS_TLS", "").lower() in ("true", "1", "yes")
            else "redis"
        )
        url = f"{scheme}://{host}:{port}"
    db = int(os.environ.get("REDIS_DB", "0"))
    return build_async_redis(url, db=db, socket_timeout=2.0)
