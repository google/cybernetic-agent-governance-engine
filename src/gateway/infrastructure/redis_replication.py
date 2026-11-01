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

"""Replica acknowledgement (``WAIT``) for Redis writes.

Valkey and Redis replicate asynchronously, so "synchronous replication" is not
an available control. ``WAIT numreplicas timeout`` is: it blocks until that
many replicas have acknowledged the writes *of the connection that sends it*,
or until the timeout, and returns how many did. It doesn't make replication
synchronous.

Because ``WAIT`` counts only its own connection's writes, three rules keep its
answer meaningful:

* The write and its ``WAIT`` share one socket. A pooled client may send them on
  different connections, and a ``WAIT`` on a connection with no writes returns
  every connected replica at once. :func:`pinned_connection` provides a
  single-connection client.
* ``WAIT`` goes out exactly once. redis-py's retry (``build_async_redis()``
  retries connection errors and timeouts) reconnects and re-sends a failed
  command. A re-sent ``WAIT`` counts the new socket's writes, which are none,
  and that happens exactly when a failover drops connections.
* The ``WAIT`` uses the socket that carried the write. redis-py connects a
  closed connection silently when a command is sent, so
  :func:`acknowledged_replicas` compares the socket against the one
  :func:`write_socket` captured when the write completed, and talks to the
  connection directly rather than through the retrying client.

:class:`ReplicationPolicy` is the deployment's configuration. The CBF engine
(``safety/cbf_engine.py``) and the consequence authority store
(``consequence_authority_store.py``) both read it.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import Any

#: ``CAGE_ENV`` values whose replication is lenient unless configured otherwise.
_LENIENT_ENVS = ("development", "test", "dev", "ci")


@dataclass(frozen=True)
class ReplicationPolicy:
    """How many replicas must acknowledge a write, for how long to wait, and what a shortfall means.

    Attributes:
        replicas: Replicas that must acknowledge (``CAGE_REDIS_WAIT_REPLICAS``,
            default 1). Zero or less sends no ``WAIT``.
        timeout_ms: ``WAIT`` timeout in milliseconds
            (``CAGE_REDIS_WAIT_TIMEOUT_MS``, default 1000).
        strict: A shortfall refuses the operation (``CAGE_STRICT_REPLICATION``,
            default on unless ``CAGE_ENV`` is development, test, dev or ci).
            A lenient caller logs the shortfall, counts it and proceeds.
    """

    replicas: int
    timeout_ms: int
    strict: bool

    @classmethod
    def from_env(cls) -> ReplicationPolicy:
        """The deployment's policy, with the CBF engine's defaults."""
        cage_env = (
            os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
        ).lower()
        strict_default = "false" if cage_env in _LENIENT_ENVS else "true"
        return cls(
            replicas=int(os.environ.get("CAGE_REDIS_WAIT_REPLICAS", "1")),
            timeout_ms=int(os.environ.get("CAGE_REDIS_WAIT_TIMEOUT_MS", "1000")),
            strict=os.environ.get("CAGE_STRICT_REPLICATION", strict_default).lower()
            in ("true", "1", "yes"),
        )

    @classmethod
    def standalone(cls) -> ReplicationPolicy:
        """A Redis with no replicas: no ``WAIT`` is sent."""
        return cls(replicas=0, timeout_ms=0, strict=False)

    @property
    def waits(self) -> bool:
        """Whether a write is followed by ``WAIT``."""
        return self.replicas > 0


class ReplicaAckError(RuntimeError):
    """``WAIT`` could not run on the socket that carried the write, or it gave no count."""


async def pinned_connection(client: Any) -> tuple[Any, bool]:
    """Return a single-connection client over ``client``'s pool, and whether to close it.

    Commands sent through the returned client share one socket, so a write and
    the ``WAIT`` after it are counted together. ``client`` itself comes back,
    unpinned, when it is not a pooled ``redis.asyncio.Redis`` client or when
    it is already single-connection.

    Returns:
        ``(connection_client, should_close)``.
    """
    if client is None:
        return None, False
    if getattr(client, "single_connection_client", False) is True:
        return client, False
    from redis.asyncio import Redis as AsyncRedis

    if type(client) is not AsyncRedis:
        return client, False
    try:
        pinned = client.client()
        if inspect.isawaitable(pinned):
            pinned = await pinned
        return pinned, (pinned is not client and hasattr(pinned, "aclose"))
    except Exception:
        return client, False


def write_socket(client: Any) -> object | None:
    """Identify the live socket of a pinned client, or return None when it has none.

    redis-py's asyncio ``Connection`` replaces its stream writer on every
    (re)connect, so the writer object identifies one TCP connection. Take it
    right after the write completes and hand it to :func:`acknowledged_replicas`.
    """
    connection = getattr(client, "connection", None)
    if connection is None or not getattr(connection, "is_connected", False):
        return None
    return getattr(connection, "_writer", None)


async def acknowledged_replicas(
    client: Any, socket: object | None, replicas: int, timeout_ms: int
) -> int:
    """Send ``WAIT replicas timeout_ms`` once on ``socket`` and return the count.

    ``socket`` is :func:`write_socket` of ``client``, taken when the write
    completed. The command goes straight to the connection, outside redis-py's
    retry, and only while that same socket is live. On any other socket the
    ``WAIT`` would count nothing.

    Raises:
        ReplicaAckError: The write's socket is gone, or the reply is not a count.
        Exception: Connection and protocol errors from the ``WAIT`` itself.
    """
    if socket is None or write_socket(client) is not socket:
        raise ReplicaAckError(
            "the socket that carried the write is gone; a WAIT on another socket "
            "counts nothing"
        )
    connection = client.connection
    try:
        await connection.send_command("WAIT", replicas, timeout_ms, check_health=False)
        reply = await connection.read_response()
    except Exception:
        await connection.disconnect()
        raise
    if isinstance(reply, bool) or not isinstance(reply, int):
        raise ReplicaAckError(f"WAIT returned {reply!r}, not a replica count")
    return reply
