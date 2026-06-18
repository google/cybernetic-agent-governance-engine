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

import logging
import os

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver
from opentelemetry import trace

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level checkpointer type tracking (R-13)
# ---------------------------------------------------------------------------
# Exposed via get_checkpointer_type() for health checks and liveness probes.
_CHECKPOINTER_TYPE: str = "unknown"


def get_checkpointer_type() -> str:
    """Return the active checkpointer type: ``"redis"`` or ``"memory"``.

    Useful for Kubernetes liveness probes and health endpoints to detect
    silent MemorySaver fallback which causes HITL state loss on pod restart.
    """
    return _CHECKPOINTER_TYPE


def _set_memory_fallback_alerts(reason: str) -> MemorySaver:
    """Log an ERROR, emit OTel attributes, and set an env var when falling
    back to MemorySaver.  Returns a new MemorySaver instance.

    This function is called from every fallback path in get_checkpointer() so
    that the CRITICAL condition is never silently swallowed.
    """
    global _CHECKPOINTER_TYPE

    # 1. ERROR-level log (not just a warning) — visible in all log aggregators
    logger.error(
        "CRITICAL: Redis unavailable — using MemorySaver. "
        "HITL approval state will be lost on pod restart. "
        "Check REDIS_URL env var and Redis connectivity. Reason: %s",
        reason,
    )

    # 2. OTel span attributes so the condition is queryable in traces
    try:
        span = trace.get_current_span()
        if span and span.is_recording():
            span.set_attribute("checkpointer.type", "MemorySaver")
            span.set_attribute("checkpointer.state_loss_risk", True)
            span.add_event(
                "checkpointer.memory_fallback",
                {"reason": str(reason)},
            )
    except Exception:
        pass  # OTel must never break the happy path

    # 3. Environment variable for k8s liveness / health probes
    os.environ["CHECKPOINTER_TYPE"] = "memory"
    _CHECKPOINTER_TYPE = "memory"

    return MemorySaver()


def get_checkpointer(redis_url: str | None = None) -> BaseCheckpointSaver:
    """Return a Redis checkpointer if explicitly configured, otherwise fall
    back to MemorySaver with CRITICAL-level alerting (R-13).

    Supports Sentinel master discovery if Sentinel is available at port 26379.
    """
    global _CHECKPOINTER_TYPE

    # 1. Determine Redis URL & Host
    if redis_url is None:
        redis_url = os.environ.get("REDIS_URL")

    redis_host = os.environ.get("REDIS_HOST")
    if redis_url is None:
        if redis_host and redis_host.lower() not in ["", "none", "false"]:
            redis_port = os.environ.get("REDIS_PORT", "6379")
            redis_url = f"redis://{redis_host}:{redis_port}"

    # 2. If no URL, fall back to MemorySaver with alerting
    if not redis_url:
        return _set_memory_fallback_alerts(
            "No Redis configuration found (REDIS_URL/REDIS_HOST env vars not set)"
        )

    # Parse hostname for Sentinel check
    try:
        from urllib.parse import urlparse
        parsed = urlparse(redis_url)
        host = parsed.hostname or redis_host or ""
    except Exception:
        host = redis_host or ""

    # 3. Try Sentinel-based AsyncRedisSaver first
    if host and host.lower() not in ["", "none", "false"]:
        try:
            import socket
            from redis.asyncio.sentinel import Sentinel
            from langgraph.checkpoint.redis import AsyncRedisSaver

            # Probe Sentinel port 26379
            s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_sock.settimeout(1.0)
            result = s_sock.connect_ex((host, 26379))
            s_sock.close()

            if result == 0:
                logger.info("Sentinel detected at %s:26379. Resolving master 'mymaster' for checkpointer...", host)
                password = os.environ.get("REDIS_PASSWORD")
                if not password and redis_url:
                    try:
                        from urllib.parse import urlparse
                        parsed_url = urlparse(redis_url)
                        if parsed_url.password:
                            password = parsed_url.password
                    except Exception:
                        pass
                sentinel = Sentinel(
                    [(host, 26379)],
                    sentinel_kwargs={'password': password} if password else None,
                    socket_connect_timeout=2.0,
                    socket_timeout=5.0
                )
                redis_client = sentinel.master_for(
                    'mymaster',
                    password=password if password else None,
                    decode_responses=True
                )
                logger.info("Using Sentinel master client for AsyncRedisSaver.")
                os.environ["CHECKPOINTER_TYPE"] = "redis"
                _CHECKPOINTER_TYPE = "redis"
                return AsyncRedisSaver(redis_client=redis_client)
        except Exception as sentinel_exc:
            logger.warning("Sentinel check/resolution failed, falling back to standard Redis checkpointer: %s", sentinel_exc)

    # 4. Try to load standard Redis Saver
    try:
        from langgraph.checkpoint.redis import AsyncRedisSaver

        # R-13 capability probe: verify the connected Redis instance supports
        # RedisJSON (JSON.SET command).  AsyncRedisSaver requires RedisJSON at
        # runtime; plain Redis (e.g. Bitnami redis:latest) will reject JSON.SET
        # with "unknown command" causing every graph.ainvoke() to return HTTP 500.
        # We probe synchronously here (at startup) so the fallback fires before
        # any request is served, rather than on the first live request.
        try:
            import redis as _redis_sync
            _probe_client = _redis_sync.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            _probe_client.execute_command("JSON.SET", "__cage_probe__", "$", '{"ok":1}')
            _probe_client.delete("__cage_probe__")
            _probe_client.close()
            logger.info("RedisJSON capability probe passed — JSON.SET is supported.")
        except _redis_sync.exceptions.ResponseError as probe_exc:
            if "unknown command" in str(probe_exc).lower() or "json" in str(probe_exc).lower():
                return _set_memory_fallback_alerts(
                    f"Redis instance does not support RedisJSON (JSON.SET rejected): {probe_exc}. "
                    "Deploy Redis Stack (redis/redis-stack) to enable persistent checkpointing."
                )
            # Other ResponseError (e.g. WRONGTYPE) — not a capability gap, proceed
            logger.warning("RedisJSON probe returned unexpected ResponseError (proceeding): %s", probe_exc)
        except Exception as probe_exc:
            # Connection failure during probe — fall back
            return _set_memory_fallback_alerts(
                f"Redis connectivity probe failed: {probe_exc}"
            )

        logger.info("Using AsyncRedisSaver at %s", redis_url)
        os.environ["CHECKPOINTER_TYPE"] = "redis"
        _CHECKPOINTER_TYPE = "redis"
        return AsyncRedisSaver(redis_url)
    except ImportError as exc:
        return _set_memory_fallback_alerts(
            f"langgraph-checkpoint-redis not installed: {exc}"
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return _set_memory_fallback_alerts(
            f"Redis connection failed: {exc}"
        )
