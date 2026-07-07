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
Intelligent Query Cache - Functionality-Preserving Performance Optimization

Caches ONLY deterministic educational/regulatory queries where the answer
doesn't change over time. Market data and personalized advice are NEVER cached.

Performance Impact:
  - Cache hit: <1s (vs 60-180s full execution)
  - Cache miss: 0ms overhead (full pipeline executes)
  - Hit rate: 20-30% expected (educational queries)

Quality Impact: ZERO
  - Cached responses = previous full governance pipeline execution
  - Same quality as uncached (memoization, not approximation)
"""

import hashlib
import json
import logging
import os
import re

logger = logging.getLogger(__name__)


class QueryCache:
    """Intelligent query cache that only caches safe, deterministic queries."""

    # Educational patterns: answers don't change, safe to cache
    CACHEABLE_PATTERNS = [
        # Educational queries
        r"what is (.*?)(diversification|sharpe|volatility|rebalancing|etf|bond)",
        r"explain (.*?)(portfolio|risk|return|allocation|ratio|concept)",
        r"define (.*?)(asset|stock|fund|market|trading|investment)",
        r"how does (.*?)(work|function|affect|impact)",
        # Regulatory/compliance queries
        r"what (are|regulations|rules|constraints) (apply|govern)",
        r"regulatory (requirements|constraints|guidelines)",
        r"compliance (rules|requirements|standards)",
    ]

    # Time-sensitive/personalized: NEVER cache
    NON_CACHEABLE_PATTERNS = [
        # Market data (changes constantly)
        r"analyze (AAPL|MSFT|GOOGL|TSLA|[A-Z]{1,5})",  # Ticker symbols
        r"current price",
        r"market performance",
        r"stock price",
        r"today",
        r"now",
        r"recent",
        r"latest",
        # User-specific (personalized)
        r"my portfolio",
        r"should I",
        r"recommend for me",
        r"I want to",
        r"help me",
        # Trading actions (must execute fresh)
        r"buy|sell|trade|execute|order",
    ]

    def __init__(self, redis_client=None):
        """Initialize with optional Redis backend. Falls back to dict if Redis unavailable."""
        self.redis = redis_client
        self.local_cache = {}  # Fallback for when Redis not available
        self.ttl = int(os.environ.get("QUERY_CACHE_TTL", "3600"))  # 1 hour default
        self.enabled = os.environ.get("ENABLE_QUERY_CACHE", "true").lower() == "true"

        if not self.enabled:
            logger.info("QueryCache: Caching disabled via ENABLE_QUERY_CACHE=false")

    def is_cacheable(self, query: str) -> bool:
        """Determine if a query is safe to cache based on content patterns."""
        if not self.enabled:
            return False

        query_lower = query.lower()

        # First check: Is it explicitly non-cacheable?
        for pattern in self.NON_CACHEABLE_PATTERNS:
            if re.search(pattern, query_lower, re.IGNORECASE):
                logger.debug("QueryCache: NON-CACHEABLE (matches: %s)", pattern)
                return False

        # Second check: Is it a cacheable pattern?
        for pattern in self.CACHEABLE_PATTERNS:
            if re.search(pattern, query_lower, re.IGNORECASE):
                logger.debug("QueryCache: CACHEABLE (matches: %s)", pattern)
                return True

        # Default: Don't cache ambiguous queries (conservative)
        logger.debug("QueryCache: NON-CACHEABLE (no pattern match)")
        return False

    def _get_cache_key(self, query: str, governance_context: dict | None = None) -> str:
        """Generate cache key from normalized query and governance context.

        # Governance context included in cache key to prevent stale decisions
        """
        # Normalize: lowercase, strip whitespace, remove extra spaces
        normalized = " ".join(query.lower().strip().split())
        # Use full 64-character SHA-256 hex digest (M-02: no truncation)
        query_hash = hashlib.sha256(normalized.encode()).hexdigest()
        if governance_context:
            ctx_json = json.dumps(governance_context, sort_keys=True)
            ctx_hash = hashlib.sha256(ctx_json.encode()).hexdigest()
            return f"query_cache:{query_hash}:{ctx_hash}"
        return f"query_cache:{query_hash}"

    async def get(
        self, query: str, governance_context: dict | None = None
    ) -> str | None:
        """Get cached response if available and query is cacheable."""
        if not self.is_cacheable(query):
            return None

        # Governance context included in cache key to prevent stale decisions
        cache_key = self._get_cache_key(query, governance_context)

        # Try Redis first
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    logger.info("QueryCache HIT (Redis): %s", query[:50])
                    return cached
            except Exception as e:
                logger.warning("QueryCache: Redis get failed: %s", e)

        # Fallback to local cache
        if cache_key in self.local_cache:
            logger.info("QueryCache HIT (local): %s", query[:50])
            return self.local_cache[cache_key]

        logger.debug("QueryCache MISS: %s", query[:50])
        return None

    async def set(
        self, query: str, response: str, governance_context: dict | None = None
    ):
        """Cache response if query is cacheable."""
        if not self.is_cacheable(query):
            return

        # Governance context included in cache key to prevent stale decisions
        cache_key = self._get_cache_key(query, governance_context)

        # Try Redis first
        if self.redis:
            try:
                await self.redis.setex(cache_key, self.ttl, response)
                logger.info(
                    "QueryCache SET (Redis): %s (TTL=%ds)", query[:50], self.ttl
                )
                return
            except Exception as e:
                logger.warning("QueryCache: Redis set failed: %s", e)

        # Fallback to local cache
        self.local_cache[cache_key] = response
        logger.info("QueryCache SET (local): %s", query[:50])

    async def clear(self):
        """Clear all cached queries."""
        if self.redis:
            try:
                # Delete all keys matching pattern
                cursor = 0
                while True:
                    cursor, keys = await self.redis.scan(cursor, match="query_cache:*")
                    if keys:
                        await self.redis.delete(*keys)
                    if cursor == 0:
                        break
                logger.info("QueryCache: Cleared Redis cache")
            except Exception as e:
                logger.warning("QueryCache: Redis clear failed: %s", e)

        self.local_cache.clear()
        logger.info("QueryCache: Cleared local cache")


# Singleton instance
_cache_instance: QueryCache | None = None


async def get_query_cache(redis_client=None) -> QueryCache:
    """Get or create the singleton query cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = QueryCache(redis_client)
        logger.info(
            "QueryCache initialized: enabled=%s, ttl=%ds, backend=%s",
            _cache_instance.enabled,
            _cache_instance.ttl,
            "Redis" if redis_client else "local",
        )
    return _cache_instance
