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
Shared Redis client for the gateway package.

This is the canonical Redis client for all gateway-internal modules
(safety.py, symbolic_governor, etc.).  It wraps redis.asyncio to provide
convenience helpers used by ControlBarrierFunction.

Environment variables:
    REDIS_HOST     — default "localhost"
    REDIS_PORT     — default 6379
    REDIS_DB       — default 0
    REDIS_PASSWORD — optional
    REDIS_TLS      — set to "true" to use rediss:// (TLS). Also auto-enabled
                     when REDIS_URL starts with "rediss://". In production
                     (GKE/Cloud Memorystore) always set REDIS_TLS=true.
                     ssl_cert_reqs=None is used to allow self-signed certs in dev.
"""

import asyncio
import json
import logging
import os
import ssl
from typing import Any

logger = logging.getLogger("Gateway.Infrastructure.Redis")


class TransactionAbortedError(Exception):
    """Raised when a Redis WATCH/MULTI/EXEC transaction is aborted due to a
    concurrent modification of a watched key (WatchError).

    Callers should treat this as a retriable condition: the watched key was
    modified by another writer between the WATCH and EXEC calls, so the
    transaction was rolled back atomically by Redis.  Any staging keys written
    *before* the MULTI block have been explicitly deleted by the client before
    this exception is raised, leaving Redis in a clean state.
    """


try:
    from urllib.parse import unquote as _unquote
    from urllib.parse import urlparse as _urlparse

    import redis
    import redis.asyncio as aioredis

    _REDIS_URL = os.environ.get("REDIS_URL", "")
    _REDIS_DB = int(os.environ.get("REDIS_DB", "0"))

    # ---------------------------------------------------------------------------
    # Phase 4.3: Sentinel-aware connection support (stretch goal)
    # ---------------------------------------------------------------------------
    # When REDIS_SENTINEL_MASTER_NAME is set, the client should use Redis
    # Sentinel for automatic failover handling instead of direct connections.
    #
    # TODO(phase-4.3): Implement Sentinel-aware connection factory.
    # Reference: https://redis-py.readthedocs.io/en/stable/sentinel.html
    #
    # Implementation outline:
    #   1. Parse REDIS_SENTINEL_HOSTS (comma-separated host:port pairs)
    #   2. Create redis.sentinel.Sentinel or redis.asyncio.sentinel.Sentinel
    #   3. Use sentinel.master_for(REDIS_SENTINEL_MASTER_NAME) for writes
    #   4. Optionally use sentinel.slave_for() for reads (read replicas)
    #
    # Example configuration:
    #   REDIS_SENTINEL_MASTER_NAME=mymaster
    #   REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
    #
    _REDIS_SENTINEL_MASTER_NAME: str | None = os.environ.get(
        "REDIS_SENTINEL_MASTER_NAME"
    )
    _REDIS_SENTINEL_HOSTS: str | None = os.environ.get("REDIS_SENTINEL_HOSTS")

    if _REDIS_SENTINEL_MASTER_NAME:
        logger.info(
            "🔧 Redis Sentinel mode configured (master=%s) — "
            "NOTE: Sentinel connection factory is a Phase 4.3 stub. "
            "Using direct connection until full Sentinel support is implemented.",
            _REDIS_SENTINEL_MASTER_NAME,
        )

    # Parse defaults from REDIS_URL if present, then allow REDIS_HOST/REDIS_PORT overrides
    if _REDIS_URL:
        _parsed_url = _urlparse(_REDIS_URL)
        _url_host: str = _parsed_url.hostname or "localhost"
        _url_port: int = _parsed_url.port or 6379
        # CRIT fix: REDIS_URL commonly carries the password as the URL
        # password component (redis://:<password>@host:port), but this
        # module previously only read a standalone REDIS_PASSWORD env var
        # and silently dropped any password embedded in REDIS_URL. In
        # deployments that only set REDIS_URL (not a separate
        # REDIS_PASSWORD), this caused every Redis command from this
        # client to be sent unauthenticated, surfacing as
        # "NOAUTH Authentication required." at call time — e.g. in the
        # CBF's read_verified_balance() path — even though a manual
        # redis.from_url(REDIS_URL) connection (which parses the password
        # correctly) succeeds.
        _url_password: str | None = (
            _unquote(_parsed_url.password) if _parsed_url.password else None
        )
    else:
        _url_host = "localhost"
        _url_port = 6379
        _url_password = None

    _REDIS_PASSWORD: str | None = os.environ.get("REDIS_PASSWORD") or _url_password

    _REDIS_HOST = os.environ.get("REDIS_HOST", _url_host)
    _raw_port = os.environ.get("REDIS_PORT", "")
    if _raw_port:
        try:
            _REDIS_PORT = int(_raw_port)
        except ValueError:
            _REDIS_PORT = _url_port
    else:
        _REDIS_PORT = _url_port

    # HIGH-04: TLS detection — enabled when REDIS_TLS=true OR REDIS_URL uses rediss://
    _REDIS_TLS: bool = os.environ.get("REDIS_TLS", "").lower() in (
        "true",
        "1",
        "yes",
    ) or _REDIS_URL.startswith("rediss://")
    if _REDIS_TLS:
        logger.info("🔒 Gateway Redis TLS enabled (rediss://)")

    # HIGH-1 fix: determine TLS cert verification mode based on environment.
    # The previous code used ssl.CERT_NONE unconditionally, making the TLS
    # connection vulnerable to MITM attacks even in production.
    _CAGE_ENV_REDIS: str = os.environ.get("CAGE_ENV", "prod").lower()
    if _REDIS_TLS:
        if _CAGE_ENV_REDIS in ("dev", "development", "test", "ci"):
            _REDIS_SSL_CERT_REQS = ssl.CERT_NONE
            _REDIS_CA_CERT_PATH: str | None = None
            logger.warning(
                "⚠️ Gateway Redis TLS: ssl_cert_reqs=NONE in %s mode. "
                "Set CAGE_ENV=prod to enforce certificate verification.",
                _CAGE_ENV_REDIS,
            )
        else:
            _REDIS_SSL_CERT_REQS = ssl.CERT_REQUIRED
            _REDIS_CA_CERT_PATH = os.environ.get(
                "REDIS_CA_CERT_PATH", "/etc/ssl/certs/ca-certificates.crt"
            )
            logger.info(
                "🔒 Gateway Redis TLS: ssl_cert_reqs=REQUIRED, ca_certs=%s",
                _REDIS_CA_CERT_PATH,
            )
    else:
        _REDIS_SSL_CERT_REQS = ssl.CERT_NONE
        _REDIS_CA_CERT_PATH = None

    class _AsyncRedisClient:
        """Thin async Redis wrapper matching the interface expected by safety.py."""

        def __init__(self):  # type: ignore[no-untyped-def]
            self._client: aioredis.Redis | None = None
            self._loop: asyncio.AbstractEventLoop | None = None
            self._lock: asyncio.Lock | None = None

        def _get_lock(self) -> asyncio.Lock:
            """Return (or lazily create) an asyncio.Lock bound to the current event loop.

            The lock must be created within an async context to be bound to the
            correct event loop.
            """
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None

            # Create a new lock if we don't have one or if the event loop changed
            if self._lock is None or (
                self._loop is not None and self._loop != current_loop
            ):
                self._lock = asyncio.Lock()
            return self._lock

        async def _get(self) -> aioredis.Redis:
            """Return (or lazily create) the Redis client.

            Thread-safe via double-check locking pattern with asyncio.Lock to prevent
            multiple concurrent async tasks from racing during initialization.
            """
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None

            # Fast path: client exists and is valid
            if (
                self._client is not None
                and (self._loop is None or self._loop == current_loop)
                and (self._loop is None or not self._loop.is_closed())
            ):
                return self._client

            # Slow path: need to create client, use lock to prevent races
            async with self._get_lock():
                # Double-check inside lock
                if (
                    self._client is None
                    or (self._loop is not None and self._loop != current_loop)
                    or (self._loop is not None and self._loop.is_closed())
                ):
                    self._loop = current_loop
                    self._client = aioredis.Redis(
                        host=_REDIS_HOST,
                        port=_REDIS_PORT,
                        db=_REDIS_DB,
                        password=_REDIS_PASSWORD,
                        decode_responses=True,
                        socket_connect_timeout=3.0,
                        socket_timeout=3.0,
                        ssl=_REDIS_TLS,
                        ssl_cert_reqs=_REDIS_SSL_CERT_REQS,
                        ssl_ca_certs=_REDIS_CA_CERT_PATH,
                    )
            return self._client

        async def get(self, key: str) -> str | None:
            client = await self._get()
            return await client.get(key)

        async def set(self, key: str, value: str) -> None:
            client = await self._get()
            await client.set(key, value)

        async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
            """Set *key* to *value* with an expiry of *ttl_seconds* seconds."""
            client = await self._get()
            await client.setex(key, ttl_seconds, value)

        async def delete(self, *keys: str) -> int:
            """Delete one or more keys."""
            client = await self._get()
            return await client.delete(*keys)

        async def get_float(self, key: str, default: float = 0.0) -> float:
            raw = await self.get(key)
            if raw is None:
                return default
            try:
                return float(raw)
            except (ValueError, TypeError):
                return default

        async def pipeline(self):  # type: ignore[no-untyped-def]
            """Return a raw redis.asyncio pipeline for WATCH/MULTI/EXEC."""
            client = await self._get()
            return client.pipeline()

        async def watch(self, *keys: str):  # type: ignore[no-untyped-def]
            """Return a pipeline in WATCH mode for optimistic locking."""
            client = await self._get()
            return client.pipeline()

        async def get_raw_client(self) -> aioredis.Redis:
            """Return the underlying aioredis.Redis client.

            Use this only when the raw client is required for operations not
            exposed by the wrapper (e.g. Lua EVALSHA in cbf.py).  Prefer the
            wrapper methods (get, set, setex, pipeline) for all other uses.

            CRIT-4 fix: replaces direct calls to the private _get() method from
            cbf.py, which broke encapsulation and bypassed the wrapper contract.
            """
            return await self._get()

        async def watched_transaction(
            self,
            watch_keys: list[str],
            staging_keys: list[str],
            build_pipeline_fn: Any,
        ) -> Any:
            """Execute a WATCH/MULTI/EXEC transaction with guaranteed cleanup on abort.

            Contract:
                1. WATCH is issued on *watch_keys* before any reads or staging writes.
                2. The caller-supplied *build_pipeline_fn* is invoked with the pipeline
                   object after WATCH but before MULTI.  It may write staging keys
                   (SET/HSET/LPUSH/etc.) outside the pipeline queue — those keys must
                   be listed in *staging_keys* so they can be cleaned up on abort.
                3. MULTI is called, the pipeline commands are queued, and EXEC is
                   issued atomically.
                4. If a concurrent writer modifies any watched key between step 1 and
                   step 3, Redis raises ``WatchError``.  This method catches it,
                   deletes every key listed in *staging_keys* (best-effort), emits a
                   structured WARNING log, and re-raises as ``TransactionAbortedError``.

            Cleanup guarantee:
                Any key in *staging_keys* that was written before MULTI is explicitly
                deleted via ``DEL`` before ``TransactionAbortedError`` is raised.  This
                prevents dirty staging state from leaking into subsequent reads.

            Args:
                watch_keys:        Keys to pass to WATCH.  The transaction aborts if
                                   any of these are modified by another client before
                                   EXEC.
                staging_keys:      Keys written outside the pipeline (before MULTI)
                                   that must be cleaned up on WatchError.
                build_pipeline_fn: Async callable ``(pipe) -> None`` invoked after
                                   WATCH.  It should issue any pre-MULTI writes and
                                   then queue pipeline commands.  The pipeline is
                                   already in buffered (MULTI) mode when EXEC is
                                   called by this method.

            Returns:
                The list of results returned by ``pipe.execute()``.

            Raises:
                TransactionAbortedError: A watched key was modified concurrently.
                                         All staging keys have been deleted.
            """
            client = await self._get()
            async with client.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(*watch_keys)
                    pipe.multi()
                    await build_pipeline_fn(pipe)
                    return await pipe.execute()
                except aioredis.WatchError:
                    # Best-effort cleanup of any staging keys written before MULTI.
                    if staging_keys:
                        try:
                            await client.delete(*staging_keys)
                        except Exception as del_exc:
                            logger.warning(
                                "watched_transaction: staging key cleanup failed: %s",
                                del_exc,
                            )
                    logger.warning(
                        json.dumps(
                            {
                                "event": "redis_watch_abort",
                                "keys_cleaned": staging_keys,
                                "reason": "WatchError",
                            }
                        )
                    )
                    raise TransactionAbortedError(
                        f"WATCH aborted: concurrent modification of {watch_keys}"
                    ) from None

        async def ping_ready(self) -> None:
            """Verify Redis is reachable by issuing a PING command.

            Call this at startup before marking the pod ready. Raises
            RuntimeError if the ping fails or times out — preventing silent
            failures on every CBF call when Redis is unreachable
            (see PERFORMANCE_REVIEW.md §3).

            Returns:
                None on success.

            Raises:
                RuntimeError: If the PING command fails or raises any exception.
            """
            try:
                client = await self._get()
                result = await client.ping()  # type: ignore[misc]  # redis-py ping() returns bool | Awaitable[bool] depending on connection type
                if not result:
                    raise RuntimeError(
                        f"Redis PING returned falsy response at "
                        f"{_REDIS_HOST}:{_REDIS_PORT}"
                    )
            except RuntimeError:
                raise
            except Exception as exc:
                raise RuntimeError(
                    f"Redis is not reachable at {_REDIS_HOST}:{_REDIS_PORT}: {exc}"
                ) from exc

        async def close(self) -> None:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    redis_client = _AsyncRedisClient()
    logger.info(
        "✅ Gateway Redis client initialised (%s:%s db=%s)",
        _REDIS_HOST,
        _REDIS_PORT,
        _REDIS_DB,
    )

    class _SyncRedisClient:
        """Thin synchronous Redis wrapper for use in thread-pool contexts.

        This client uses the standard (blocking) ``redis.Redis`` driver so it
        can be called safely from worker threads (e.g. functions dispatched via
        ``asyncio.to_thread``).  It shares the same connection parameters as
        the async ``_AsyncRedisClient`` above.
        """

        def __init__(self) -> None:
            self._client: redis.Redis | None = None  # type: ignore[type-arg]

        def _get(self) -> redis.Redis:  # type: ignore[type-arg]
            if self._client is None:
                self._client = redis.Redis(
                    host=_REDIS_HOST,
                    port=_REDIS_PORT,
                    db=_REDIS_DB,
                    password=_REDIS_PASSWORD,
                    decode_responses=True,
                    socket_connect_timeout=3.0,
                    socket_timeout=3.0,
                    ssl=_REDIS_TLS,
                    ssl_cert_reqs=_REDIS_SSL_CERT_REQS,  # type: ignore[arg-type]
                    ssl_ca_certs=_REDIS_CA_CERT_PATH,
                )
            return self._client

        def get(self, key: str) -> str | None:
            return self._get().get(key)  # type: ignore[return-value]

        def setex(self, key: str, ttl_seconds: int, value: str) -> None:
            """Set *key* to *value* with an expiry of *ttl_seconds* seconds."""
            self._get().setex(key, ttl_seconds, value)

        def ping_ready(self) -> None:
            """Verify Redis is reachable by issuing a synchronous PING command.

            Designed for module-import-time startup probes (which run in a
            synchronous context). Raises RuntimeError if the ping fails or
            times out — preventing silent CBF failures when Redis is
            unreachable (see PERFORMANCE_REVIEW.md §3).

            Returns:
                None on success.

            Raises:
                RuntimeError: If the PING command fails or raises any exception.
            """
            try:
                result = self._get().ping()
                if not result:
                    raise RuntimeError(
                        f"Redis PING returned falsy response at "
                        f"{_REDIS_HOST}:{_REDIS_PORT}"
                    )
            except RuntimeError:
                raise
            except Exception as exc:
                raise RuntimeError(
                    f"Redis is not reachable at {_REDIS_HOST}:{_REDIS_PORT}: {exc}"
                ) from exc

        def close(self) -> None:
            if self._client is not None:
                self._client.close()
                self._client = None

    sync_redis_client = _SyncRedisClient()
    logger.info(
        "✅ Gateway sync Redis client initialised (%s:%s db=%s)",
        _REDIS_HOST,
        _REDIS_PORT,
        _REDIS_DB,
    )

except ImportError:
    logger.warning(
        "⚠️ redis.asyncio not installed — gateway Redis client unavailable. "
        "Install with: pip install redis[asyncio]"
    )
    redis_client = None  # type: ignore[assignment]
    sync_redis_client = None  # type: ignore[assignment]


def get_redis_client() -> "_SyncRedisClient":  # type: ignore[name-defined]
    """Return the module-level synchronous Redis client singleton.

    Use this factory for startup readiness probes and any synchronous
    context (e.g. module-import-time assertions in symbolic_governor.py).
    The async ``redis_client`` singleton is preferred for all async paths.

    Raises:
        RuntimeError: If the redis package is not installed
            (``sync_redis_client`` is None).
    """
    if sync_redis_client is None:
        raise RuntimeError(
            "Redis client is not available — redis package not installed. "
            "Install with: pip install redis[asyncio]"
        )
    return sync_redis_client  # type: ignore[return-value]
