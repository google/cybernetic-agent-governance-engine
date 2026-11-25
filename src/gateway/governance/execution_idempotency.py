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

Attempt state (POAM-2026-252): whether the current attempt may have executed
is answered once, by the kernel. :func:`actuation_attempt_scope` opens an
:class:`ActuationAttempt` record for a committing run; ``dispatch_actuation()``
is its only writer (it marks the record before ``actuate()`` is awaited and
settles it from the receipt), and the domain tool's settlement and ledger
decision, :meth:`ExecutionLedger.release_unexecuted`, the domain tool result
and ``/tools/execute`` all read the same record instead of keeping copies.

Domain-agnostic kernel code (Layer 1): the caller names the action.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.env_posture import is_enforcing, resolve_posture

logger = logging.getLogger(__name__)

KEY_PREFIX = "cage:exec"
#: ``caller_identity`` for a call path that cannot supply a verified caller
#: identity; every caller of the action then shares one key space.
SHARED_CALLER = "_shared"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60

#: A committing action's idempotency key: a canonical UUID of version 4
#: (random) or 5 (name-based, e.g. derived from a tool call).
_IDEMPOTENCY_KEY_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def is_valid_idempotency_key(value: object) -> bool:
    """Whether ``value`` is an accepted idempotency key (UUIDv4 or UUIDv5)."""
    return isinstance(value, str) and bool(_IDEMPOTENCY_KEY_RE.fullmatch(value.lower()))


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

_RELEASE_UNEXECUTED_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if (not ok) or type(record) ~= 'table' then return -1 end
if record['token'] ~= ARGV[1] or record['status'] ~= 'IN_FLIGHT' then return -1 end
redis.call('DEL', KEYS[1])
return 1
"""

# KEYS[1] = record key; ARGV = target_status ('EXECUTED' or 'BLOCKED'), outcome.
# Transitions only when current status is 'UNKNOWN'.
_RESOLVE_UNKNOWN_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if (not ok) or type(record) ~= 'table' then return -1 end
if record['status'] ~= 'UNKNOWN' then return -1 end
record['status'] = ARGV[1]
record['outcome'] = ARGV[2]
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


# ── Attempt state: what the current committing run has dispatched ──────────

#: How settled statuses combine: a later ``REJECTED`` receipt never hides an
#: earlier dispatch that may have executed.
_ATTEMPT_RANK: dict[ExecutionStatus, int] = {
    ExecutionStatus.BLOCKED: 0,
    ExecutionStatus.EXECUTED: 1,
    ExecutionStatus.UNKNOWN: 2,
}


def _dominant(a: ExecutionStatus, b: ExecutionStatus) -> ExecutionStatus:
    return a if _ATTEMPT_RANK[a] >= _ATTEMPT_RANK[b] else b


class ActuationAttemptScopeError(RuntimeError):
    """``dispatch_actuation()`` was called with no attempt scope open.

    Raised before the actuator is awaited, so nothing was sent: outside a
    scope no caller could read what the dispatch did.
    """


class UnclaimedActuationError(ActuationAttemptScopeError):
    """``dispatch_actuation()`` was called without a live kernel ``ExecutionLedger`` claim.

    Raised synchronously before ``_dispatched`` flips and before the actuator
    is awaited, so nothing was sent. Covers absent claims, already-consumed
    claims (single-dispatch enforcement), and claims whose
    ``(action, idempotency_key)`` does not match
    ``(clearance.action, clearance.thread_id)``.
    """


class ActuationAttempt:
    """Whether the current committing run may have executed: the kernel's answer.

    Opened by :func:`actuation_attempt_scope`. ``status`` is ``BLOCKED`` until
    something is dispatched. Only ``dispatch_actuation()`` writes the dispatch
    state and only :meth:`ExecutionLedger.claim` attaches a live :class:`Claim`
    to the active record (no public setter accepts a ``Claim``).
    ``dispatch_actuation()`` verifies and consumes that claim synchronously
    before flipping ``_dispatched`` and before awaiting ``actuate()`` (the
    record reads ``UNKNOWN`` from then on), and settles it once the receipt is
    in the evidence stream (``ACCEPTED`` -> ``EXECUTED``, ``UNKNOWN`` ->
    ``UNKNOWN``, ``REJECTED`` -> ``BLOCKED``). A dispatch that ends without a
    settled receipt (an exception or a cancellation) leaves the record
    ``UNKNOWN``.

    The record only moves towards "may have executed": a ``REJECTED`` receipt
    is the only way back to ``BLOCKED``, and only while nothing else in the
    scope may have executed. ``dispatched`` never goes back to ``False``.
    """

    __slots__ = (
        "_claim",
        "_claim_consumed",
        "_claimed_action",
        "_claimed_idempotency_key",
        "_dispatched",
        "_in_flight",
        "_settled",
        "_unsettled",
    )

    def __init__(self) -> None:
        self._dispatched = False
        self._in_flight = 0
        self._settled = ExecutionStatus.BLOCKED
        self._unsettled = False
        self._claim: Claim | None = None
        self._claimed_action: str | None = None
        self._claimed_idempotency_key: str | None = None
        self._claim_consumed: bool = False

    @property
    def dispatched(self) -> bool:
        """Whether anything in this scope was handed to an actuator."""
        return self._dispatched

    @property
    def status(self) -> ExecutionStatus:
        """``BLOCKED``, ``EXECUTED`` or ``UNKNOWN``, as the ledger records it."""
        if self._in_flight or self._unsettled:
            return ExecutionStatus.UNKNOWN
        return self._settled

    @property
    def may_have_executed(self) -> bool:
        """False only while nothing was dispatched or every dispatch was rejected."""
        return self.status is not ExecutionStatus.BLOCKED

    def __repr__(self) -> str:
        return (
            f"ActuationAttempt(status={self.status.value}, "
            f"dispatched={self._dispatched})"
        )

    def _absorb(self, closed: ActuationAttempt) -> None:
        """Fold a closed nested scope into this one without losing a dispatch."""
        self._dispatched = self._dispatched or closed._dispatched
        # A dispatch still in flight when its scope closed never settles here.
        self._unsettled = self._unsettled or closed._unsettled or closed._in_flight > 0
        self._settled = _dominant(self._settled, closed._settled)


_current_attempt: ContextVar[ActuationAttempt | None] = ContextVar(
    "cage_actuation_attempt", default=None
)


def open_actuation_attempt() -> Token[ActuationAttempt | None]:
    """Open a fresh attempt record in the current context.

    For a request boundary that keeps a token (``/tools/execute``): close it
    with :func:`close_actuation_attempt` in a ``finally``. Everything else
    uses :func:`actuation_attempt_scope`.
    """
    return _current_attempt.set(ActuationAttempt())


def close_actuation_attempt(token: Token[ActuationAttempt | None]) -> None:
    """Close the record ``token`` opened and fold it into the enclosing one."""
    closed = _current_attempt.get()
    _current_attempt.reset(token)
    enclosing = _current_attempt.get()
    if enclosing is not None and closed is not None:
        enclosing._absorb(closed)


@contextmanager
def actuation_attempt_scope() -> Iterator[ActuationAttempt]:
    """Open a fresh attempt record for one committing run.

    Every dispatch inside the block is recorded here; ``dispatch_actuation()``
    refuses to run outside one. On exit, before an exception reaches an
    enclosing handler, the record is folded into the enclosing scope's, so a
    request boundary sees everything its tool dispatched. Context copies
    (``asyncio.to_thread``, task creation) share the record by reference, so
    a dispatch made under one is still recorded where the scope's owner
    reads it.
    """
    attempt = ActuationAttempt()
    token = _current_attempt.set(attempt)
    try:
        yield attempt
    finally:
        close_actuation_attempt(token)


def current_actuation_attempt() -> ActuationAttempt | None:
    """The record of the innermost open scope; ``None`` outside every scope."""
    return _current_attempt.get()


def exceptions_after_dispatch() -> tuple[type[Exception], ...]:
    """``(Exception,)`` once the current attempt may have executed, else ``()``.

    For an ``except`` clause, whose expression is evaluated only when an
    error reaches it: such a clause catches every error after dispatch and
    none before, so the attempt record, not the error's type, decides how an
    error escaping after dispatch is answered.
    """
    attempt = _current_attempt.get()
    if attempt is not None and attempt.may_have_executed:
        return (Exception,)
    return ()


def outcome_after_dispatch(message: str) -> CommitOutcome | None:
    """The committing outcome for an error that escaped once dispatch may have executed.

    Read from the current attempt record, whatever the error's type:
    ``EXECUTED`` when the receipt was accepted, ``INDETERMINATE`` while the
    outcome is unknown. ``None`` while nothing in the scope may have
    executed (or outside every scope): the caller keeps its own mapping.
    """
    attempt = _current_attempt.get()
    if attempt is None or not attempt.may_have_executed:
        return None
    if attempt.status is ExecutionStatus.EXECUTED:
        return CommitOutcome(CommitStatus.EXECUTED, message)
    return CommitOutcome(CommitStatus.INDETERMINATE, message)


def _bind_claim_to_attempt(claim: Claim, *, action: str, idempotency_key: str) -> Claim:
    """Attach a kernel-minted ``Claim`` onto the active attempt record (private).

    Called strictly from :meth:`ExecutionLedger.claim` on a successful claim;
    there is no public setter accepting a ``Claim`` instance (POAM-2026-254).
    """
    attempt = _current_attempt.get()
    if attempt is not None:
        attempt._claim = claim
        attempt._claimed_action = action
        attempt._claimed_idempotency_key = idempotency_key
        attempt._claim_consumed = False
    return claim


def mark_dispatch(*, action: str, idempotency_key: str) -> ActuationAttempt:
    """Verify the active kernel claim and mark a dispatch before anything is sent.

    Called only by ``dispatch_actuation()``, synchronously and before it
    awaits the actuator, so an unclaimed, spent, or mismatched dispatch is
    refused before ``_dispatched`` flips or any byte leaves, and a valid
    dispatch makes the record read ``UNKNOWN`` before any byte can leave.

    Raises:
        ActuationAttemptScopeError: No scope is open; nothing may be sent.
        UnclaimedActuationError: The active scope holds no live unspent kernel
            ``ExecutionLedger`` claim matching ``(action, idempotency_key)``.
    """
    attempt = _current_attempt.get()
    if attempt is None:
        raise ActuationAttemptScopeError(
            "dispatch_actuation() was called outside actuation_attempt_scope(); "
            "nothing could read what the dispatch did, so it was not sent"
        )
    if not isinstance(attempt._claim, Claim):
        raise UnclaimedActuationError(
            f"dispatch_actuation() for action={action!r} thread_id={idempotency_key!r} "
            "refused: no kernel ExecutionLedger claim is bound to the active attempt"
        )
    if attempt._claim_consumed:
        raise UnclaimedActuationError(
            f"dispatch_actuation() for action={action!r} thread_id={idempotency_key!r} "
            "refused: the bound ExecutionLedger claim was already consumed"
        )
    if (
        attempt._claimed_action != action
        or attempt._claimed_idempotency_key != idempotency_key
    ):
        raise UnclaimedActuationError(
            f"dispatch_actuation() for action={action!r} thread_id={idempotency_key!r} "
            f"refused: bound claim is for action={attempt._claimed_action!r} "
            f"idempotency_key={attempt._claimed_idempotency_key!r}"
        )
    attempt._claim_consumed = True
    attempt._dispatched = True
    attempt._in_flight += 1
    return attempt


def settle_dispatch(attempt: ActuationAttempt, status: ExecutionStatus | None) -> None:
    """Close one dispatch :func:`mark_dispatch` marked (``dispatch_actuation()`` only).

    ``status`` is what the recorded receipt says. ``None`` (the dispatch ended
    without one) or any status other than ``BLOCKED``, ``EXECUTED`` or
    ``UNKNOWN`` leaves the record ``UNKNOWN``.
    """
    attempt._in_flight = max(0, attempt._in_flight - 1)
    if status is not None and status in _ATTEMPT_RANK:
        attempt._settled = _dominant(attempt._settled, status)
    else:
        attempt._unsettled = True


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
            local_res = self._claim_local(key, token, reclaim_blocked=reclaim_blocked)
            if isinstance(local_res, Claim):
                return _bind_claim_to_attempt(
                    local_res, action=action, idempotency_key=idempotency_key
                )
            return local_res

        record = json.dumps(
            {"token": token, "status": ExecutionStatus.IN_FLIGHT.value, "outcome": None}
        )
        last_exc: Exception | None = None
        for _ in range(_REDIS_ATTEMPTS):
            try:
                if await redis.set(key, record, nx=True, ex=self._ttl_seconds):
                    return _bind_claim_to_attempt(
                        Claim(key, token),
                        action=action,
                        idempotency_key=idempotency_key,
                    )
                raw = await redis.get(key)
                if raw is None:  # expired between SET NX and GET
                    continue
                owner, status, outcome = _decode_record(raw)
                if owner == token:  # an earlier write of this attempt landed
                    return _bind_claim_to_attempt(
                        Claim(key, token),
                        action=action,
                        idempotency_key=idempotency_key,
                    )
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
                    return _bind_claim_to_attempt(
                        Claim(key, token),
                        action=action,
                        idempotency_key=idempotency_key,
                    )
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
            recorded = self._record_local(claim, status, outcome)
            if recorded:
                attempt = _current_attempt.get()
                if attempt is not None and attempt._claim == claim:
                    attempt._claim_consumed = True
            return recorded
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
                attempt = _current_attempt.get()
                if attempt is not None and attempt._claim == claim:
                    attempt._claim_consumed = True
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

    async def release_unexecuted(self, claim: Claim) -> bool:
        """Release ``claim`` if it is still ``IN_FLIGHT`` and owned by this attempt.

        Used strictly when governance blocks on infrastructure unavailability
        before actuation started, so retrying the same ``transaction_id`` after
        the dependency recovers does not collide with a stale ``BLOCKED`` or
        ``IN_FLIGHT`` record (F-03, POAM-2026-233).

        Never once the current attempt has dispatched (POAM-2026-252): the
        claim is kept, the attempt's own status is recorded in its place
        (``UNKNOWN`` while the outcome is in doubt, which unknown-actuation
        reconciliation can resolve; ``EXECUTED`` or ``BLOCKED`` once a receipt
        settled it), and ``False`` is returned.
        """
        attempt = _current_attempt.get()
        if attempt is not None and attempt.dispatched:
            status = attempt.status
            logger.critical(
                "execution ledger claim %s not released: the attempt was "
                "dispatched; recording %s instead",
                claim.key,
                status.value,
            )
            await self.record_outcome(
                claim,
                status,
                f"{status.value}: the claim was kept because the attempt had "
                "been dispatched",
            )
            return False
        try:
            redis = await self._raw_redis()
        except ExecutionLedgerUnavailable as exc:
            logger.warning(
                "execution ledger unexecuted claim %s could not be released: %s",
                claim.key,
                exc,
            )
            return False
        if redis is None:
            released = self._release_local(claim)
            if released and attempt is not None and attempt._claim == claim:
                attempt._claim = None
                attempt._claimed_action = None
                attempt._claimed_idempotency_key = None
                attempt._claim_consumed = False
            return released
        for _ in range(_REDIS_ATTEMPTS):
            try:
                result = await redis.eval(
                    _RELEASE_UNEXECUTED_LUA,
                    1,
                    claim.key,
                    claim.token,
                )
            except Exception as exc:
                logger.warning(
                    "execution ledger unexecuted claim %s release retry failed: %s",
                    claim.key,
                    exc,
                )
                continue
            released = int(result) == 1
            if released and attempt is not None and attempt._claim == claim:
                attempt._claim = None
                attempt._claimed_action = None
                attempt._claimed_idempotency_key = None
                attempt._claim_consumed = False
            return released
        return False

    async def resolve_unknown(
        self,
        action: str,
        caller_identity: str,
        idempotency_key: str,
        *,
        status: ExecutionStatus,
        outcome: str,
    ) -> bool:
        """Transition an ``UNKNOWN`` ledger record to ``EXECUTED`` or ``BLOCKED`` after reconciliation."""
        if status not in (ExecutionStatus.EXECUTED, ExecutionStatus.BLOCKED):
            raise ValueError(
                f"resolve_unknown requires EXECUTED or BLOCKED, got {status!r}"
            )
        key = self.key_for(action, caller_identity, idempotency_key)
        try:
            redis = await self._raw_redis()
        except ExecutionLedgerUnavailable as exc:
            logger.warning(
                "execution ledger unknown record %s could not be resolved: %s",
                key,
                exc,
            )
            return False
        if redis is None:
            return self._resolve_unknown_local(key, status, outcome)
        for _ in range(_REDIS_ATTEMPTS):
            try:
                result = await redis.eval(
                    _RESOLVE_UNKNOWN_LUA,
                    1,
                    key,
                    status.value,
                    outcome,
                )
            except Exception as exc:
                logger.warning(
                    "execution ledger unknown resolution retry failed for %s: %s",
                    key,
                    exc,
                )
                continue
            return int(result) == 1
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

    def _release_local(self, claim: Claim) -> bool:
        with self._local_lock:
            record = self._local.get(claim.key)
            if (
                record is None
                or record.token != claim.token
                or record.status is not ExecutionStatus.IN_FLIGHT
            ):
                return False
            del self._local[claim.key]
        return True

    def _resolve_unknown_local(
        self, key: str, status: ExecutionStatus, outcome: str
    ) -> bool:
        with self._local_lock:
            record = self._local.get(key)
            if record is None or record.status is not ExecutionStatus.UNKNOWN:
                return False
            record.status = status
            record.outcome = outcome
        return True


# ── Kernel-owned claim lifecycle scope (POAM-2026-254) ──────────────────────

#: Ledger statuses whose recorded reply settles a resubmission.
_SETTLED_REPLAY_STATUSES: frozenset[ExecutionStatus] = frozenset(
    {ExecutionStatus.EXECUTED, ExecutionStatus.BLOCKED}
)


class ExecutionClaimScope:
    """Return-type-agnostic handle yielded by :func:`execution_claim_scope`.

    Domain tools inspect ``invalid_key_reason`` and ``duplicate`` to format
    refusals or replays in their own return shape, record their outcome prose
    via :meth:`set_outcome_summary`, and never call ``ExecutionLedger``
    methods directly.
    """

    __slots__ = (
        "_outcome_summary",
        "_pre_dispatch_infra_failure",
        "attempt",
        "duplicate",
        "idempotency_key",
        "invalid_key_reason",
        "proof_hash",
    )

    def __init__(
        self,
        *,
        attempt: ActuationAttempt,
        idempotency_key: str | None = None,
        invalid_key_reason: str | None = None,
        duplicate: Duplicate | None = None,
        proof_hash: str = "",
    ) -> None:
        self.attempt: ActuationAttempt = attempt
        self.idempotency_key: str | None = idempotency_key
        self.invalid_key_reason: str | None = invalid_key_reason
        self.duplicate: Duplicate | None = duplicate
        self.proof_hash: str = proof_hash
        self._outcome_summary: str | None = None
        self._pre_dispatch_infra_failure: bool = False

    def set_outcome_summary(self, summary: str) -> None:
        """Store the settled outcome prose for ``ExecutionLedger.record_outcome()``."""
        self._outcome_summary = summary

    def mark_pre_dispatch_infra_failure(self) -> None:
        """Request key release on normal exit when a pre-dispatch outage was caught.

        Honored on exit ONLY while ``not self.attempt.dispatched``; once
        ``dispatch_actuation()`` has run, the claim is never released.
        """
        self._pre_dispatch_infra_failure = True


async def _settle_claim_on_error(
    ledger: ExecutionLedger,
    claim: Claim,
    attempt: ActuationAttempt,
    exc: BaseException,
) -> None:
    """Release an unexecuted claim on pre-dispatch outage; otherwise record ``attempt.status``."""
    from src.gateway.governance.evidence.stream import (
        EvidenceChainUnavailableError,
    )
    from src.gateway.governance.governor.errors import (
        GovernanceInfrastructureError,
    )

    # Only an outage before anything was dispatched frees the key;
    # once the action was handed to an actuator its status is kept.
    if (
        isinstance(
            exc,
            (GovernanceInfrastructureError, EvidenceChainUnavailableError),
        )
        and not attempt.dispatched
    ):
        await ledger.release_unexecuted(claim)
    else:
        await ledger.record_outcome(
            claim,
            attempt.status,
            f"{attempt.status.value}: {str(exc) or type(exc).__name__}",
        )


@asynccontextmanager
async def execution_claim_scope(
    governor: Any,
    *,
    action: str,
    idempotency_key: Any,
    params: dict[str, Any],
    dry_run: bool = False,
    reclaim_blocked: bool = False,
    caller_identity: str = SHARED_CALLER,
    key_field_name: str = "idempotency_key",
) -> AsyncIterator[ExecutionClaimScope]:
    """Own the Layer 1 at-most-once claim lifecycle for a committing action.

    Opens an :func:`actuation_attempt_scope`, validates ``idempotency_key`` via
    :func:`is_valid_idempotency_key`, acquires the kernel ``ExecutionLedger``
    claim (attaching it onto the active ``ActuationAttempt`` inside
    :meth:`ExecutionLedger.claim`), handles ledger outages (``503`` via
    ``handle_infrastructure_block``), settles or raises on duplicates, and on
    exit either releases the claim on a pre-dispatch infrastructure error or
    records ``attempt.status`` and the caller's summary.

    Decoupled from ``CommitOutcome`` so domain plugins with different return
    shapes share one kernel enforcement seam (POAM-2026-254).
    """
    from src.gateway.server import governance_middleware as _gm

    with actuation_attempt_scope() as attempt:
        if idempotency_key is None or idempotency_key == "":
            reason = (
                f"{key_field_name} is required (a UUIDv4 or UUIDv5 idempotency key)."
            )
            proof_hash = await _gm.record_refusal(
                action, reason, oscal_control_ref="AC-3", params=params
            )
            yield ExecutionClaimScope(
                attempt=attempt,
                invalid_key_reason=reason,
                proof_hash=proof_hash,
            )
            return

        if not is_valid_idempotency_key(idempotency_key):
            reason = (
                f"invalid {key_field_name} {str(idempotency_key)[:64]!r}; "
                "expected a UUIDv4 or UUIDv5."
            )
            proof_hash = await _gm.record_refusal(
                action, reason, oscal_control_ref="AC-3", params=params
            )
            yield ExecutionClaimScope(
                attempt=attempt,
                invalid_key_reason=reason,
                proof_hash=proof_hash,
            )
            return

        normalized_key = idempotency_key.lower()
        normalized_params = {**params, key_field_name: normalized_key}
        claim: Claim | None = None
        ledger: ExecutionLedger | None = None

        if not dry_run:
            try:
                components = getattr(governor, "components", None)
                candidate = getattr(components, "execution_ledger", None)
                if not isinstance(candidate, ExecutionLedger):
                    raise ExecutionLedgerUnavailable(
                        "governor.components.execution_ledger is not configured"
                    )
                ledger = candidate
                claimed = await ledger.claim(
                    action,
                    caller_identity,
                    normalized_key,
                    reclaim_blocked=reclaim_blocked,
                )
            except ExecutionLedgerUnavailable as exc:
                from src.gateway.governance.contracts import Violation, ViolationKind
                from src.gateway.governance.governor.errors import (
                    GovernanceInfrastructureError,
                )
                from src.gateway.governance.governor.verdicts import (
                    handle_infrastructure_block,
                )

                reason = (
                    "execution ledger unavailable, at-most-once execution cannot be "
                    f"guaranteed: {exc}"
                )
                logger.error(
                    "%s %s blocked on execution ledger outage: %s",
                    action,
                    normalized_key,
                    reason,
                )
                await handle_infrastructure_block(
                    action,
                    normalized_params,
                    [
                        Violation(
                            tier="execution_ledger",
                            code="EXECUTION_LEDGER_UNAVAILABLE",
                            message=reason,
                            kind=ViolationKind.INFRASTRUCTURE,
                            infra_dependency="execution_ledger",
                            infra_error_code="execution_ledger_unavailable",
                        )
                    ],
                    [],
                )
                raise GovernanceInfrastructureError(
                    f"handle_infrastructure_block returned without raising; blocking {action}",
                    dependency="execution_ledger",
                    failure_code="EXECUTION_LEDGER_UNAVAILABLE",
                    error_code="execution_ledger_unavailable",
                ) from exc

            if isinstance(claimed, Duplicate):
                dup_reason = (
                    f"duplicate submission of {key_field_name} {normalized_key} "
                    f"(first attempt {claimed.status.value})"
                )
                if (
                    claimed.outcome is not None
                    and claimed.status in _SETTLED_REPLAY_STATUSES
                ):
                    logger.warning("%s refused: %s", action, dup_reason)
                    proof_hash = await _gm.record_refusal(
                        action,
                        dup_reason,
                        oscal_control_ref="AC-3",
                        params=normalized_params,
                    )
                    yield ExecutionClaimScope(
                        attempt=attempt,
                        idempotency_key=normalized_key,
                        duplicate=claimed,
                        proof_hash=proof_hash,
                    )
                    return
                logger.warning("%s unsettled duplicate blocked: %s", action, dup_reason)
                state = {
                    ExecutionStatus.IN_FLIGHT: "has not finished",
                    ExecutionStatus.UNKNOWN: "has an unknown outcome, pending reconciliation",
                }.get(claimed.status, "left no recorded reply")
                first = f" First attempt: {claimed.outcome}" if claimed.outcome else ""
                raise UnsettledDuplicate(
                    f"{claimed.status.value}: {key_field_name} {normalized_key} was already "
                    f"submitted and its first attempt {state}; it is not executed again.{first}"
                )
            claim = claimed

        scope = ExecutionClaimScope(
            attempt=attempt,
            idempotency_key=normalized_key,
        )
        try:
            yield scope
        except BaseException as exc:
            if claim is not None and ledger is not None:
                await _settle_claim_on_error(ledger, claim, attempt, exc)
            raise
        if claim is not None and ledger is not None:
            if scope._pre_dispatch_infra_failure and not attempt.dispatched:
                await ledger.release_unexecuted(claim)
            else:
                summary = (
                    scope._outcome_summary
                    if scope._outcome_summary is not None
                    else attempt.status.value
                )
                await ledger.record_outcome(claim, attempt.status, summary)
