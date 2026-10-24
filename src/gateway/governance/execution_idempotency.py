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

"""At-most-once execution of governed actions, keyed by an idempotency key.

A tool claims ``(action, caller_identity, idempotency_key)`` before it governs
the action, and records the outcome once it knows it. A resubmission of the
same key never reaches governance or actuation again: it gets back the
recorded outcome, or a refusal while the first attempt is still running.

Statuses, from the point of view of the side effect:

* ``IN_FLIGHT`` — claimed; the outcome is not recorded yet.
* ``EXECUTED`` — the action ran.
* ``BLOCKED`` — the action did not run (refused, rejected or deferred).
* ``UNKNOWN`` — the action may have run. The claim stays, so the key is not
  executed again while the outcome awaits reconciliation.

A key whose action may have run (``IN_FLIGHT``, ``EXECUTED``, ``UNKNOWN``) is
never claimed again. A ``BLOCKED`` key is answered with its recorded outcome
too, unless the claim passes ``reclaim_blocked``: a resubmission that brings
new authority the caller verifies before acting (an approval, say) takes the
key over and is decided afresh.

Records live in Redis under ``cage:exec:{action}:{caller_identity}:{key}``
for ``ttl_seconds``. ``SET NX EX`` claims a key with a per-attempt random
token; a Lua compare-and-set on that token records the outcome. A Redis
command whose reply is lost is resent with the same token, so a claim that
landed is recognised as this attempt's own.

Fail closed: a configured Redis that cannot be reached, or no Redis under an
enforcing posture, makes :meth:`ExecutionLedger.claim` raise
:class:`ExecutionLedgerUnavailable`. Only a non-enforcing posture without
Redis falls back to a process-local registry, as the quarantine actuator does.

Domain-agnostic kernel code (Layer 1): the caller names the action.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.gateway.governance.env_posture import is_enforcing, resolve_posture

logger = logging.getLogger(__name__)

KEY_PREFIX = "cage:exec"
#: ``caller_identity`` for a call path that cannot supply a verified caller
#: identity; every caller of the action then shares one key space.
SHARED_CALLER = "_shared"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60

# No ':' (the key separator), whitespace or glob characters in a key part.
_KEY_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}$")
_REDIS_ATTEMPTS = 2

# KEYS[1] = record key; ARGV = the BLOCKED record's token, new record, TTL.
# Returns 1 when the BLOCKED record was replaced, 0 when it changed or expired.
_RECLAIM_BLOCKED_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local record = cjson.decode(raw)
if record['token'] ~= ARGV[1] or record['status'] ~= 'BLOCKED' then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
return 1
"""

# KEYS[1] = record key; ARGV = token, status, outcome.
# Returns 1 when recorded, 0 when the record is gone, -1 when another
# attempt owns the key.
_RECORD_OUTCOME_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local record = cjson.decode(raw)
if record['token'] ~= ARGV[1] then return -1 end
record['status'] = ARGV[2]
record['outcome'] = ARGV[3]
redis.call('SET', KEYS[1], cjson.encode(record), 'KEEPTTL')
return 1
"""


class ExecutionStatus(str, Enum):
    """What an execution ledger record says about the side effect."""

    IN_FLIGHT = "IN_FLIGHT"
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class ExecutionLedgerUnavailable(RuntimeError):
    """The ledger cannot guarantee at-most-once execution; refuse the action."""


class UnsettledDuplicate(RuntimeError):
    """A resubmitted key whose first attempt has not settled; not executed again.

    A tool raises it for a :class:`Duplicate` that is ``IN_FLIGHT`` or
    ``UNKNOWN`` instead of returning a reply, so that no caller reads the
    duplicate's answer as a settled outcome.
    """


@dataclass(frozen=True)
class Claim:
    """This attempt owns the key and must record its outcome."""

    key: str
    token: str


@dataclass(frozen=True)
class Duplicate:
    """The key was claimed before. ``outcome`` is None while that attempt runs."""

    key: str
    status: ExecutionStatus
    outcome: str | None


@dataclass
class _LocalRecord:
    token: str
    status: ExecutionStatus
    outcome: str | None
    expires_at: float


def _decode_record(raw: Any) -> tuple[str | None, ExecutionStatus, str | None]:
    """Parse a stored record; an unreadable one reads as ``UNKNOWN`` (fail closed)."""
    try:
        text = raw.decode() if isinstance(raw, bytes) else str(raw)
        record = json.loads(text)
        status = ExecutionStatus(record["status"])
        token = record.get("token")
        outcome = record.get("outcome")
    except (ValueError, KeyError, TypeError, AttributeError):
        return None, ExecutionStatus.UNKNOWN, None
    return (
        token if isinstance(token, str) else None,
        status,
        outcome if isinstance(outcome, str) else None,
    )


class ExecutionLedger:
    """Claims idempotency keys and records outcomes for at-most-once execution.

    Built once per governor by :func:`~src.gateway.governance.governor.assembly.assemble_governor`
    and read as ``governor.components.execution_ledger``.

    Args:
        redis_client: An async Redis client, or the gateway's shared wrapper
            (its raw client is used for ``SET NX EX`` and ``EVAL``). ``None``
            when no Redis is configured.
        ttl_seconds: How long a key is remembered. Reconcile ``UNKNOWN``
            outcomes within this window.
    """

    def __init__(
        self, redis_client: Any | None, *, ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ExecutionLedger ttl_seconds must be positive")
        self._redis_client = redis_client
        self._ttl_seconds = ttl_seconds
        self._local: dict[str, _LocalRecord] = {}
        self._local_lock = threading.Lock()

    @staticmethod
    def key_for(action: str, caller_identity: str, idempotency_key: str) -> str:
        """The record key; refuses parts that could break out of their segment."""
        for name, part in (
            ("action", action),
            ("caller_identity", caller_identity),
            ("idempotency_key", idempotency_key),
        ):
            if not isinstance(part, str) or not _KEY_PART.fullmatch(part):
                raise ValueError(f"invalid execution ledger {name}: {part!r}")
        return f"{KEY_PREFIX}:{action}:{caller_identity}:{idempotency_key}"

    async def claim(
        self,
        action: str,
        caller_identity: str,
        idempotency_key: str,
        *,
        reclaim_blocked: bool = False,
    ) -> Claim | Duplicate:
        """Claim ``idempotency_key`` for one attempt at ``action``.

        Args:
            reclaim_blocked: Take over a key whose recorded attempt is
                ``BLOCKED`` (the action did not run) instead of answering with
                that attempt's outcome. Only for a resubmission that brings
                new authority, such as an approval, which the caller verifies
                before acting.

        Returns:
            :class:`Claim` when this attempt owns the key, otherwise a
            :class:`Duplicate` carrying the recorded status and outcome.

        Raises:
            ValueError: A key part is malformed.
            ExecutionLedgerUnavailable: At-most-once execution cannot be
                guaranteed (Redis unreachable, or absent under an enforcing
                posture).
        """
        key = self.key_for(action, caller_identity, idempotency_key)
        token = secrets.token_hex(16)
        redis = await self._raw_redis()
        if redis is None:
            if is_enforcing(resolve_posture()):
                raise ExecutionLedgerUnavailable(
                    "no Redis is configured for the execution ledger under an "
                    "enforcing posture"
                )
            return self._claim_local(key, token, reclaim_blocked=reclaim_blocked)

        record = json.dumps(
            {"token": token, "status": ExecutionStatus.IN_FLIGHT.value, "outcome": None}
        )
        last_exc: Exception | None = None
        for _ in range(_REDIS_ATTEMPTS):
            try:
                if await redis.set(key, record, nx=True, ex=self._ttl_seconds):
                    return Claim(key, token)
                raw = await redis.get(key)
                if raw is None:  # expired between SET NX and GET
                    continue
                owner, status, outcome = _decode_record(raw)
                if owner == token:  # an earlier write of this attempt landed
                    return Claim(key, token)
                if (
                    not reclaim_blocked
                    or status is not ExecutionStatus.BLOCKED
                    or owner is None
                ):
                    return Duplicate(key, status, outcome)
                reclaimed = await redis.eval(
                    _RECLAIM_BLOCKED_LUA, 1, key, owner, record, self._ttl_seconds
                )
                if int(reclaimed) == 1:
                    return Claim(key, token)
                # The record changed after the GET: read it again.
            except Exception as exc:  # a write may have landed: resend it
                last_exc = exc
        raise ExecutionLedgerUnavailable(
            f"execution ledger could not claim {key}"
            + (f": {last_exc}" if last_exc else ": the record kept changing")
        ) from last_exc

    async def record_outcome(
        self, claim: Claim, status: ExecutionStatus, outcome: str
    ) -> bool:
        """Store the final status and outcome text if ``claim`` still owns its key.

        Never raises for a storage failure: the outcome is already decided, so
        a failure is logged and the record stays ``IN_FLIGHT`` until it
        expires (duplicates are refused meanwhile).

        Returns:
            True when the outcome was recorded.
        """
        if status is ExecutionStatus.IN_FLIGHT:
            raise ValueError("record_outcome needs a final status")
        try:
            redis = await self._raw_redis()
        except ExecutionLedgerUnavailable as exc:
            logger.critical("execution ledger outcome for %s lost: %s", claim.key, exc)
            return False
        if redis is None:
            return self._record_local(claim, status, outcome)
        last_exc: Exception | None = None
        for _ in range(_REDIS_ATTEMPTS):
            try:
                result = await redis.eval(
                    _RECORD_OUTCOME_LUA,
                    1,
                    claim.key,
                    claim.token,
                    status.value,
                    outcome,
                )
            except Exception as exc:  # setting the same outcome again is harmless
                last_exc = exc
                continue
            if int(result) == 1:
                return True
            logger.critical(
                "execution ledger outcome %s for %s not recorded: the claim %s",
                status.value,
                claim.key,
                "expired" if int(result) == 0 else "is owned by another attempt",
            )
            return False
        logger.critical(
            "execution ledger outcome %s for %s not recorded: %s",
            status.value,
            claim.key,
            last_exc,
        )
        return False

    async def _raw_redis(self) -> Any | None:
        """The raw async client behind ``redis_client`` (None when unconfigured)."""
        client = self._redis_client
        if client is None:
            return None
        get_raw = getattr(client, "get_raw_client", None)
        if get_raw is None:
            return client
        try:
            return await get_raw()
        except Exception as exc:
            raise ExecutionLedgerUnavailable(
                f"execution ledger Redis client unavailable: {exc}"
            ) from exc

    def _claim_local(
        self, key: str, token: str, *, reclaim_blocked: bool
    ) -> Claim | Duplicate:
        now = time.monotonic()
        with self._local_lock:
            existing = self._local.get(key)
            if (
                existing is not None
                and existing.expires_at > now
                and not (reclaim_blocked and existing.status is ExecutionStatus.BLOCKED)
            ):
                return Duplicate(key, existing.status, existing.outcome)
            self._local[key] = _LocalRecord(
                token=token,
                status=ExecutionStatus.IN_FLIGHT,
                outcome=None,
                expires_at=now + self._ttl_seconds,
            )
        return Claim(key, token)

    def _record_local(
        self, claim: Claim, status: ExecutionStatus, outcome: str
    ) -> bool:
        with self._local_lock:
            record = self._local.get(claim.key)
            if (
                record is None
                or record.token != claim.token
                or record.expires_at <= time.monotonic()
            ):
                logger.critical(
                    "execution ledger outcome %s for %s not recorded: the claim "
                    "is gone",
                    status.value,
                    claim.key,
                )
                return False
            record.status = status
            record.outcome = outcome
        return True
