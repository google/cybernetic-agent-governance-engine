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
import asyncio
from typing import Optional

from redis.asyncio import Redis, ConnectionPool
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from opentelemetry import trace
from src.governed_financial_advisor.utils.telemetry import get_tracer

logger = logging.getLogger("Infrastructure.Redis")

class AsyncRedisClient:
    """
    Strict Async Redis Client for LangGraph Checkpointing.
    Enforces explicitly typed state, connection timeouts, and failing-fast.
    """
    def __init__(self) -> None:
        redis_url = os.getenv("REDIS_URL")
        redis_host = os.getenv("REDIS_HOST")
        if not redis_url and not redis_host:
            logger.warning(
                "Neither REDIS_URL nor REDIS_HOST is set — Redis client will not be available. "
                "Sessions will not persist across pod restarts."
            )
        self.redis_url: str = redis_url or ""

        # Determine host: REDIS_URL takes precedence when set (its parsed hostname
        # is the authoritative value).  REDIS_HOST is only used as a fallback when
        # REDIS_URL is absent, which preserves backwards compatibility for
        # deployments that set only REDIS_HOST.
        if redis_url:
            # Parse host from e.g. "redis://myredis:1234" → "myredis"
            try:
                from urllib.parse import urlparse  # noqa: PLC0415
                parsed = urlparse(redis_url)
                self.redis_host: str = parsed.hostname or ""
            except Exception:
                self.redis_host = redis_host or ""
        elif redis_host:
            self.redis_host = redis_host
        else:
            self.redis_host = ""

        # Determine port: prefer parsing REDIS_PORT env (handles Kubernetes
        # "tcp://host:port" injection); fall back to REDIS_URL; last resort 6379.
        redis_port_env = os.getenv("REDIS_PORT", "")
        if redis_port_env:
            try:
                # Strip Kubernetes "tcp://host:port" prefix if present
                raw = redis_port_env.replace("tcp://", "").split(":")[-1]
                self.redis_port: int = int(raw)
            except ValueError:
                self.redis_port = 6379
        elif redis_url:
            try:
                from urllib.parse import urlparse  # noqa: PLC0415
                parsed = urlparse(redis_url)
                self.redis_port = parsed.port or 6379
            except Exception:
                self.redis_port = 6379
        else:
            self.redis_port = 6379

        self.pool: Optional[ConnectionPool] = None
        self.client: Optional[Redis] = None
        self.use_redis: bool = bool(self.redis_host) and self.redis_host.lower() not in ["", "none", "false"]
        self.tracer = get_tracer()

    async def connect(self) -> None:
        """Initializes the async connection pool with strict timeouts."""
        if not self.use_redis:
            logger.warning("REDIS_HOST disabled. Async client cannot initialized memory fallback in prod.")
            return

        # 1. Try Sentinel Connection
        try:
            import socket
            from redis.asyncio.sentinel import Sentinel

            # Probe Sentinel port 26379
            s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_sock.settimeout(1.0)
            result = s_sock.connect_ex((self.redis_host, 26379))
            s_sock.close()

            if result == 0:
                logger.info(f"Sentinel detected at {self.redis_host}:26379. Resolving master 'mymaster'...")
                password = os.getenv("REDIS_PASSWORD")
                if not password and self.redis_url:
                    try:
                        from urllib.parse import urlparse
                        parsed_url = urlparse(self.redis_url)
                        if parsed_url.password:
                            password = parsed_url.password
                    except Exception:
                        pass
                sentinel = Sentinel(
                    [(self.redis_host, 26379)],
                    sentinel_kwargs={'password': password} if password else None,
                    socket_connect_timeout=2.0,
                    socket_timeout=5.0
                )
                self.client = sentinel.master_for(
                    'mymaster',
                    password=password if password else None,
                    decode_responses=True
                )
                await self.client.ping()
                logger.info("✅ Async Redis Pool established via Sentinel master connection.")
                return
        except Exception as sentinel_exc:
            logger.warning(f"Sentinel initialization failed, falling back to standard Redis: {sentinel_exc}")

        # 2. Fallback to Standard Connection
        try:
            self.pool = ConnectionPool.from_url(
                self.redis_url,
                max_connections=100,
                socket_connect_timeout=2.0,
                socket_timeout=5.0,
                decode_responses=True
            )
            self.client = Redis(connection_pool=self.pool)
            await self.client.ping()
            logger.info(f"✅ Async Redis Pool established at {self.redis_url}")
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"❌ CRITICAL: Async Redis Connection Failed: {e}")
            self.client = None
            # Fail fast - do not fallback to memory in a distributed cluster
            raise e

    async def close(self) -> None:
        """Gracefully closes the connection pool."""
        if self.client:
            await self.client.aclose()
            logger.info("Closed Async Redis connections.")

    async def get(self, key: str) -> Optional[str]:
        """Async retrieval with OpenTelemetry tracking."""
        if not self.client:
            raise ConnectionError("AsyncRedisClient not connected.")
        
        with self.tracer.start_as_current_span("redis.get") as span:
            span.set_attribute("redis.key", key)
            try:
                return await self.client.get(key)
            except RedisError as e:
                span.record_exception(e)
                logger.error(f"Async Redis GET Error: {e}")
                raise

    async def get_float(self, key: str, default: float = 0.0) -> float:
        """Typed async payload retrieval."""
        val = await self.get(key)
        if val is None:
            return default
        try:
            return float(val)
        except ValueError:
            logger.warning(f"Type parsing error for {key}: Expected float, got {val}")
            return default

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        """Async state persistence."""
        if not self.client:
            raise ConnectionError("AsyncRedisClient not connected.")

        with self.tracer.start_as_current_span("redis.set") as span:
            span.set_attribute("redis.key", key)
            try:
                await self.client.set(key, value, ex=ttl)
            except RedisError as e:
                span.record_exception(e)
                logger.error(f"Async Redis SET Error: {e}")
                raise

    async def delete(self, key: str) -> None:
        """Async key deletion."""
        if not self.client:
            raise ConnectionError("AsyncRedisClient not connected.")

        with self.tracer.start_as_current_span("redis.delete") as span:
            span.set_attribute("redis.key", key)
            try:
                await self.client.delete(key)
            except RedisError as e:
                span.record_exception(e)
                logger.error(f"Async Redis DELETE Error: {e}")
                raise

# Alias for backwards-compatibility with tests that import RedisClient
RedisClient = AsyncRedisClient

# Global Instance Interface
redis_client = AsyncRedisClient()
