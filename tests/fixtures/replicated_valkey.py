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

"""A replicated Valkey on localhost, for hermetic tests of replica acknowledgement.

Real redis-py clients (``build_async_redis()``, with its pool and retry policy)
talk RESP2 over TCP to an in-process server. The server models what ``WAIT``
depends on:

* A primary and replicas with asynchronous replication. A write reaches a
  replica only when replication runs (on ``WAIT``, or :meth:`replicate`) and is
  not paused, so a test can widen the window between a write and its
  replication as far as it needs.
* Per-connection write offsets. ``WAIT`` counts only the writes of the
  connection that sends it, so a ``WAIT`` on a connection with no writes is
  "acknowledged" by every replica. That is why an unpinned or re-sent ``WAIT``
  proves nothing.
* Failover. :meth:`fail_over` promotes a replica with whatever it holds and
  drops every client connection.
* Fault injection. The server can lose a reply after executing the command,
  close a connection after replying, or fail a command.

Only the commands that the consequence authority store and redis-py's
connection handshake send are implemented.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.gateway.governance.consequence_authority_store import _REASSERT_IF_OURS_LUA
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction


@dataclass
class _Node:
    data: dict[str, str] = field(default_factory=dict)
    expiry: dict[str, float] = field(default_factory=dict)
    applied: int = 0

    def get(self, key: str) -> str | None:
        deadline = self.expiry.get(key)
        if deadline is not None and time.monotonic() >= deadline:
            self.data.pop(key, None)
            self.expiry.pop(key, None)
        return self.data.get(key)

    def put(self, key: str, value: str, deadline: float | None) -> None:
        self.data[key] = value
        if deadline is None:
            self.expiry.pop(key, None)
        else:
            self.expiry[key] = deadline


@dataclass
class _Client:
    id: int
    writer: asyncio.StreamWriter
    last_write: int = 0


class ReplicatedValkey:
    """An in-process primary with replicas, served over RESP2 on 127.0.0.1."""

    def __init__(self, replicas: int = 1) -> None:
        self.primary = _Node()
        self.replicas = [_Node() for _ in range(replicas)]
        self.replication_paused = False
        #: ``(connection id, command)`` for every command the server received.
        self.commands: list[tuple[int, str]] = []
        self._log: list[tuple[int, str, str, float | None]] = []
        self._offset = 0
        self._clients: dict[int, _Client] = {}
        self._ids = itertools.count(1)
        self._lose_reply: set[str] = set()
        self._close_after: set[str] = set()
        self._fail: dict[str, str] = {}
        self._scripts: dict[str, Callable[[_Client, list[str], list[str]], bytes]] = {
            _REASSERT_IF_OURS_LUA: self._reassert_if_ours,
            ControlBarrierFunction.LUA_ATOMIC_CBF: self._cbf_atomic_commit,
            ControlBarrierFunction.LUA_ROLLBACK_CBF: self._cbf_rollback,
        }
        self._scripts_by_sha: dict[
            str, Callable[[_Client, list[str], list[str]], bytes]
        ] = {
            hashlib.sha1(script.encode()).hexdigest(): fn
            for script, fn in self._scripts.items()
        }
        self._server: asyncio.AbstractServer | None = None
        self.port = 0

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> ReplicatedValkey:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        for client in list(self._clients.values()):
            client.writer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.port}"

    # -- inspection and fault injection -------------------------------------

    def value(self, key: str) -> str | None:
        """What the primary holds for ``key``."""
        return self.primary.get(key)

    def replica_value(self, key: str, index: int = 0) -> str | None:
        """What replica ``index`` holds for ``key``."""
        return self.replicas[index].get(key)

    def connections_running(self, command: str) -> list[int]:
        """Ids of the connections that sent ``command``, in order."""
        return [cid for cid, name in self.commands if name == command.upper()]

    def lose_next_reply(self, command: str) -> None:
        """Execute the next ``command``, then drop the connection before replying."""
        self._lose_reply.add(command.upper())

    def close_after_next(self, command: str) -> None:
        """Reply to the next ``command``, then close that connection."""
        self._close_after.add(command.upper())

    def fail_next(self, command: str, message: str) -> None:
        """Answer the next ``command`` with an error instead of executing it."""
        self._fail[command.upper()] = message

    def replicate(self) -> None:
        """Deliver every pending write to every replica, unless replication is paused."""
        if self.replication_paused:
            return
        for node in self.replicas:
            for offset, key, value, deadline in self._log:
                if offset > node.applied:
                    node.put(key, value, deadline)
                    node.applied = offset

    async def fail_over(self) -> None:
        """Promote the first replica with what it holds and drop every client connection.

        A fresh replica, synced from the promoted node, takes the old primary's
        place, so ``WAIT`` can be satisfied again afterwards.
        """
        promoted = self.replicas.pop(0)
        self.primary = _Node(data=dict(promoted.data), expiry=dict(promoted.expiry))
        self._log.clear()
        self._offset = 0
        self.replicas.append(
            _Node(data=dict(self.primary.data), expiry=dict(self.primary.expiry))
        )
        for client in list(self._clients.values()):
            client.writer.close()
        # Let the connection handlers observe the closed transports.
        await asyncio.sleep(0)

    # -- server --------------------------------------------------------------

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client = _Client(next(self._ids), writer)
        self._clients[client.id] = client
        try:
            while True:
                args = await _read_command(reader)
                if args is None:
                    break
                name = args[0].upper()
                self.commands.append((client.id, name))
                if name in self._fail:
                    reply = _error(self._fail.pop(name))
                else:
                    reply = self._execute(client, name, args[1:])
                if name in self._lose_reply:
                    self._lose_reply.discard(name)
                    break
                writer.write(reply)
                await writer.drain()
                if name in self._close_after:
                    self._close_after.discard(name)
                    break
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._clients.pop(client.id, None)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _execute(self, client: _Client, name: str, args: list[str]) -> bytes:
        if name == "PING":
            return b"+PONG\r\n"
        if name in ("CLIENT", "SELECT", "AUTH"):
            return b"+OK\r\n"
        if name == "GET":
            return _bulk(self.primary.get(args[0]))
        if name == "EXISTS":
            return _integer(sum(1 for key in args if self.primary.get(key) is not None))
        if name == "DEL":
            removed = sum(1 for k in args if self.primary.data.pop(k, None) is not None)
            return _integer(removed)
        if name == "SET":
            return self._set(client, args)
        if name == "SCRIPT" and args and args[0].upper() == "LOAD":
            sha = hashlib.sha1(args[1].encode()).hexdigest()
            if args[1] in self._scripts:
                self._scripts_by_sha[sha] = self._scripts[args[1]]
            return _bulk(sha)
        if name == "EVAL":
            script, numkeys = args[0], int(args[1])
            handler = self._scripts.get(script)
            if handler is None:
                return _error("ERR unknown script in test server")
            return handler(client, args[2 : 2 + numkeys], args[2 + numkeys :])
        if name == "EVALSHA":
            sha, numkeys = args[0], int(args[1])
            handler = self._scripts_by_sha.get(sha)
            if handler is None:
                return _error("NOSCRIPT No matching script. Please use EVAL.")
            return handler(client, args[2 : 2 + numkeys], args[2 + numkeys :])
        if name == "WAIT":
            self.replicate()
            acked = sum(
                1 for node in self.replicas if node.applied >= client.last_write
            )
            return _integer(acked)
        return _error(f"ERR unknown command '{name}'")

    def _set(self, client: _Client, args: list[str]) -> bytes:
        key, value, options = args[0], args[1], [a.upper() for a in args[2:]]
        exists = self.primary.get(key) is not None
        if ("NX" in options and exists) or ("XX" in options and not exists):
            return b"$-1\r\n"
        if "KEEPTTL" in options:
            deadline = self.primary.expiry.get(key)
        elif "EX" in options:
            deadline = time.monotonic() + int(args[2 + options.index("EX") + 1])
        else:
            deadline = None
        self._write(client, key, value, deadline)
        return b"+OK\r\n"

    def _reassert_if_ours(
        self, client: _Client, keys: list[str], argv: list[str]
    ) -> bytes:
        """The store's compare-and-set script, with Valkey's semantics."""
        key, marker = keys[0], argv[0]
        if self.primary.get(key) != marker:
            return _integer(0)
        self._write(client, key, marker, self.primary.expiry.get(key))
        return _integer(1)

    def _cbf_atomic_commit(
        self, client: _Client, keys: list[str], argv: list[str]
    ) -> bytes:
        """CBF LUA_ATOMIC_CBF commit step for WAIT socket/failover tests."""
        state_key, epoch_key, hwm_key = keys[0], keys[2], keys[4]
        cost = float(argv[0])
        current = float(self.primary.get(state_key) or argv[4])
        next_val = current - cost
        new_epoch = int(self.primary.get(epoch_key) or "0") + 1
        self._write(client, state_key, str(next_val), None)
        self._write(client, epoch_key, str(new_epoch), None)
        self._write(client, hwm_key, str(new_epoch), None)
        return _array(
            [
                _integer(1),
                _bulk("COMMITTED"),
                _bulk(str(next_val)),
                _integer(new_epoch),
                _bulk(str(current)),
            ]
        )

    def _cbf_rollback(self, client: _Client, keys: list[str], argv: list[str]) -> bytes:
        """CBF LUA_ROLLBACK_CBF rollback step for WAIT socket/failover tests."""
        state_key, epoch_key, hwm_key = keys[0], keys[2], keys[4]
        restore = float(argv[0])
        current = float(self.primary.get(state_key) or "0.0")
        restored = current + restore
        new_epoch = int(self.primary.get(epoch_key) or "0") + 1
        self._write(client, state_key, str(restored), None)
        self._write(client, epoch_key, str(new_epoch), None)
        self._write(client, hwm_key, str(new_epoch), None)
        return _array(
            [
                _integer(1),
                _bulk("ROLLED_BACK"),
                _bulk(str(restored)),
                _integer(new_epoch),
                _bulk(str(current)),
                _bulk(str(restore)),
            ]
        )

    def _write(
        self, client: _Client, key: str, value: str, deadline: float | None
    ) -> None:
        self._offset += 1
        self.primary.put(key, value, deadline)
        self._log.append((self._offset, key, value, deadline))
        client.last_write = self._offset


async def _read_command(reader: asyncio.StreamReader) -> list[str] | None:
    header = await reader.readline()
    if not header:
        return None
    if not header.startswith(b"*"):
        raise ConnectionError(f"inline commands are not supported: {header!r}")
    args: list[str] = []
    for _ in range(int(header[1:-2])):
        length = int((await reader.readline())[1:-2])
        args.append((await reader.readexactly(length + 2))[:-2].decode())
    return args


def _bulk(value: str | None) -> bytes:
    if value is None:
        return b"$-1\r\n"
    data = value.encode()
    return b"$%d\r\n%s\r\n" % (len(data), data)


def _integer(value: int) -> bytes:
    return b":%d\r\n" % value


def _array(items: list[bytes]) -> bytes:
    return (b"*%d\r\n" % len(items)) + b"".join(items)


def _error(message: str) -> bytes:
    return f"-{message}\r\n".encode()


def build_client(server: ReplicatedValkey) -> Any:
    """A production-shaped async client (``build_async_redis()``) for ``server``."""
    from src.gateway.infrastructure.redis_client import build_async_redis

    return build_async_redis(server.url, socket_timeout=3.0)
