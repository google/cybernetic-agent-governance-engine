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

"""Single-use Redis writes that stay correct when the client re-sends them.

Pooled async clients from ``build_async_redis()``
(``src/gateway/infrastructure/redis_client.py``) retry ``ConnectionError``,
``TimeoutError`` and ``BusyLoadingError``. If the server executed a command
but the reply was lost, redis-py sends the same command again. A ``SET NX``
or a compare-and-set script then finds the state its own first send wrote and
reports a conflict: a consumed seal reads as a replay, a fresh DPoP ``jti`` as
reused, a quorum approval as a lost race.

The remedy is an operation id: a random value generated once per logical
attempt and stored in, or next to, the value the attempt writes. A re-send
carries the same id and recognises its own write. Every other writer,
including a genuine replay of the same request, carries a different id and
still gets today's conflict, so fail-closed behaviour is unchanged.
"""

from __future__ import annotations

import secrets
from typing import Any


def new_op_id() -> str:
    """Return a random id for one logical write attempt (128 bits, hex)."""
    return secrets.token_hex(16)


async def set_nx_retry_safe(redis: Any, key: str, value: str, *, ex: int) -> bool:
    """``SET key value NX EX ex``; True if this attempt holds ``key``.

    ``value`` must be unique to the attempt (embed :func:`new_op_id`). When
    the key already exists and holds exactly ``value``, it was written by an
    earlier send of this same command whose reply was lost, so the attempt
    still holds the key. Any other value is a conflict and returns False.

    Raises:
        Exception: Redis errors propagate, so callers keep failing closed.
    """
    if await redis.set(key, value, nx=True, ex=ex):
        return True
    stored = await redis.get(key)
    if isinstance(stored, bytes):
        stored = stored.decode()
    return stored == value
