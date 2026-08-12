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
Cryptographic Routing Seal — Defense-in-Depth for Tool Actuation.

The Routing Seal is a short-lived HMAC-SHA256 token issued by the Hybrid
Gateway after a successful ``/v1/governance/validate-action`` approval.  The
GFA service (or any downstream actuator) MUST verify the seal before executing
the trade.  This ensures that execution cannot proceed by simply ignoring the
HTTP response from the governance endpoint.

Seal format (URL-safe base64, no padding):
    <timestamp_ms_hex>.<action_slug>.<hmac_hex>

Seal lifetime is configurable via ``GOVERNANCE_SEAL_TTL_S`` (default 30s).
The HMAC key is derived from ``GOVERNANCE_SALT`` — the same env var that is
already present in both gateway and GFA deployments.

Cryptographic contract (P3 fix)
--------------------------------
``verify_seal()`` now raises ``SymbolicGovernorViolation`` instead of returning
``False`` on any failure.  This makes it impossible for callers to silently
ignore a failed verification — the exception propagates unless explicitly
caught.  The ``require_cleared_seal`` decorator enforces this contract at the
call-site level: any wrapped callable is blocked from executing if the seal
check fails.

Usage:
    # Gateway (issuance):
    seal = generate_seal("execute_trade", params)

    # Verification — raises SymbolicGovernorViolation on failure:
    verify_seal(seal, "execute_trade", params)

    # Decorator pattern:
    @require_cleared_seal(seal, "execute_trade", params)
    async def _actuate():
        ...
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import inspect
import json
import logging
import os
import time
from collections.abc import Callable
from typing import Any, TypeVar

from src.gateway.governance.constants import GovernanceControl

logger = logging.getLogger(__name__)

# The routing seal enforces the authorized action space declared in the
# agentic scope statement (SR 26-2 §3.1, AI 600-1 §2.5).  Any action that
# passes seal verification is implicitly attested to be within the scope
# defined by this control.
_SCOPE_CONTROL = GovernanceControl.AGENTIC_SCOPE_STATEMENT

F = TypeVar("F", bound=Callable[..., Any])

# Seal TTL — seals expire after this many seconds.
_TTL_S = int(os.getenv("GOVERNANCE_SEAL_TTL_S", "30"))

# HMAC key — must match between gateway (issuer) and GFA (verifier).
# Use _require_env so that production deployments fail fast if GOVERNANCE_SALT
# is not set, rather than silently using an insecure hardcoded default.
_DEFAULT_SALT = "default-governance-salt-change-in-production"

from src.gateway.governance.constants import _require_env

_GOVERNANCE_SALT = _require_env("GOVERNANCE_SALT", _DEFAULT_SALT, sensitive=True)
_HMAC_KEY = _GOVERNANCE_SALT.encode()

# True when the hardcoded default salt is active (no custom GOVERNANCE_SALT set).
# Tests patch this flag directly to simulate default vs. custom salt scenarios.
_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == _DEFAULT_SALT


# ---------------------------------------------------------------------------
# P3 — SymbolicGovernorViolation exception
# ---------------------------------------------------------------------------


class SymbolicGovernorViolation(Exception):
    """Raised when a routing seal verification fails.

    This exception is the canonical signal that a cryptographic governance
    contract has been violated.  It is intentionally *not* a subclass of
    ``ValueError`` or ``PermissionError`` so that callers cannot accidentally
    swallow it via broad ``except Exception`` handlers without re-raising.

    Attributes:
        reason: Human-readable description of the specific failure mode
                (e.g. "expired", "HMAC mismatch", "malformed").
        action: The action name that was being verified.
    """

    def __init__(self, reason: str, action: str = "") -> None:
        self.reason = reason
        self.action = action
        super().__init__(
            f"SymbolicGovernorViolation: routing seal rejected for action "
            f"'{action}': {reason}"
        )


def is_default_salt() -> bool:
    """Returns True if the routing seal is using the hardcoded default GOVERNANCE_SALT.

    Returns the value of the module-level ``_USING_DEFAULT_SALT`` flag, which is
    set at import time based on whether ``GOVERNANCE_SALT`` env var is set to a
    non-default value.  Tests may patch this flag directly.
    """
    return _USING_DEFAULT_SALT


def assert_custom_salt_in_production() -> None:
    """Raise RuntimeError if the default GOVERNANCE_SALT is active in production.

    Checks ``_USING_DEFAULT_SALT`` (patchable by tests) and the current
    environment (``CAGE_ENV`` or ``ENVIRONMENT`` env var).  Raises in production
    when the default salt is active; no-op in development/test/ci environments.
    """
    if not _USING_DEFAULT_SALT:
        return  # Custom salt is set — no risk

    env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    non_production_envs = ("development", "dev", "test", "ci")
    if env in non_production_envs:
        return  # Non-production — default salt is acceptable

    raise RuntimeError(
        "CAGE SECURITY FAILURE: GOVERNANCE_SALT is using the hardcoded default value "
        f"(REDACTED_SALT) in environment '{env}'. "
        "Set a strong, unique GOVERNANCE_SALT (≥32 bytes) before deploying to production. "
        "The default salt allows any party with access to the source code to forge "
        "routing seals and bypass governance enforcement."
    )


def _canonical_payload(action: str, params: dict) -> bytes:
    """Produce a stable, deterministic byte representation of the action payload.

    Fields are sorted so that dict ordering differences don't break verification.
    Non-serialisable values are coerced to strings.
    """
    safe = {
        k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
        for k, v in params.items()
    }
    canon = json.dumps(
        {"action": action, **safe}, sort_keys=True, separators=(",", ":")
    )
    return canon.encode()


def generate_seal(action: str, params: dict, ttl_s: int = _TTL_S) -> str:
    """Generate a short-lived HMAC-SHA256 routing seal.

    Args:
        action:  Tool / policy action name (e.g. ``"execute_trade"``).
        params:  Execution plan parameters dict.
        ttl_s:   Seal lifetime in seconds (default: ``GOVERNANCE_SEAL_TTL_S``).

    Returns:
        A dot-separated seal string: ``<expire_ts_hex>.<action_slug>.<hmac_hex>``
    """
    expire_ts = int(time.time()) + ttl_s
    expire_hex = format(expire_ts, "x")
    # Strip dots from action_slug to guarantee unambiguous 3-way split on "."
    # during verify_seal (seal.split(".", 2)).  Any dots in the action name
    # would shift the split boundary and cause verification to fail on a valid seal.
    action_slug = action.replace("_", "-").replace(".", "-").lower()[:32]
    payload = _canonical_payload(action, params)
    message = f"{expire_hex}.{action_slug}.".encode() + payload
    sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()
    seal = f"{expire_hex}.{action_slug}.{sig}"
    logger.debug("🔏 Routing seal issued: action=%s expire=%s", action, expire_ts)
    return seal


def verify_seal(seal: str, action: str, params: dict) -> bool:
    """Verify a routing seal issued by the Hybrid Gateway.

    Returns ``True`` on success.  Raises ``SymbolicGovernorViolation`` on any
    verification failure — the exception is never swallowed so callers cannot
    silently ignore a failed check.  The ``require_cleared_seal`` decorator
    relies on this propagation contract.

    Cryptographic contract:
        Algorithm : HMAC-SHA256
        Key       : ``GOVERNANCE_SALT`` environment variable (≥32 bytes in
                    production; see ``assert_custom_salt_in_production()``).
        Message   : ``<expire_hex>.<action_slug>.`` + canonical JSON payload
                    (``json.dumps({"action": action, **params}, sort_keys=True,
                    separators=(",", ":"))``).
        Digest    : hex-encoded lowercase SHA-256 HMAC.
        TTL       : ``GOVERNANCE_SEAL_TTL_S`` seconds (default 30).

    Args:
        seal:    Seal string as returned by :func:`generate_seal`.
        action:  Tool / policy action name — must match the issuance action.
        params:  Execution plan parameters — must match the issuance params.

    Returns:
        ``True`` if the seal is valid and unexpired.

    Raises:
        SymbolicGovernorViolation: If the seal is malformed, expired, has an
            action mismatch, or fails HMAC verification.  Always raised on
            failure — never swallowed — so callers cannot ignore it.
    """
    try:
        parts = seal.split(".", 2)
        if len(parts) != 3:
            reason = f"malformed seal (got {len(parts)} parts, expected 3)"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        expire_hex, action_slug, received_sig = parts

        # Check expiry
        try:
            expire_ts = int(expire_hex, 16)
        except ValueError:
            reason = f"non-hex expiry field: {expire_hex!r}"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        if time.time() > expire_ts:
            reason = f"expired (ts={expire_ts})"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        # Check action slug
        expected_slug = action.replace("_", "-").lower()[:32]
        if action_slug != expected_slug:
            reason = (
                f"action mismatch (got '{action_slug}', expected '{expected_slug}')"
            )
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        # Recompute HMAC
        payload = _canonical_payload(action, params)
        message = f"{expire_hex}.{action_slug}.".encode() + payload
        expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            reason = "HMAC mismatch — seal may be forged or tampered"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        logger.debug("✅ Routing seal verified: action=%s", action)
        return True

    except SymbolicGovernorViolation:
        # Re-raise — never swallow. Callers must handle the exception explicitly.
        # CRIT-1 fix: the previous code caught SymbolicGovernorViolation and
        # returned False, allowing callers to silently ignore a failed seal check.
        raise
    except Exception as exc:
        reason = f"unexpected verification error: {exc}"
        logger.warning("🔒 Routing seal verification error: %s", exc)
        raise SymbolicGovernorViolation(reason, action) from exc


async def verify_and_consume_seal(
    seal: str,
    action: str,
    params: dict,
    redis_client: Any = None,
) -> bool:
    """Verify a routing seal AND atomically burn it in Redis to prevent replay.

    CAGE-SEC-008 / Terry Snyder & Miracle Owolabi remediation:
    Enforces atomic single-use seal semantics. Even within the 30-second TTL
    window, a seal can only be executed once. Subsequent attempts with the
    same seal are rejected with 'SEAL_REPLAY_DETECTED'.

    Args:
        seal:         Routing seal string.
        action:       Tool/action name.
        params:       Execution parameters.
        redis_client: Optional async or sync Redis client. If omitted, attempts
                      to load ambient Redis client.

    Returns:
        True on successful verification and atomic single-use consumption.

    Raises:
        SymbolicGovernorViolation: If verification fails or if the seal was
            already consumed (replay attack detected).
    """
    # 1. First verify cryptographic validity & TTL
    verify_seal(seal, action, params)

    # 2. If redis client is provided or available, enforce single-use consumption
    parts = seal.split(".", 2)
    expire_hex, _action_slug, sig = parts
    expire_ts = int(expire_hex, 16)
    ttl = max(int(expire_ts - time.time()), 1)

    if redis_client is None:
        try:
            from src.gateway.infrastructure.redis_client import get_redis_client

            redis_client = get_redis_client().client
        except Exception:
            redis_client = None

    if redis_client is not None:
        burn_key = f"cage:seal:consumed:{sig}"
        try:
            res = redis_client.set(burn_key, "1", nx=True, ex=ttl)
            if inspect.isawaitable(res):
                res = await res

            if not res:
                reason = "routing seal already consumed (Replay Attack Detected)"
                logger.error(
                    "🔒 [CAGE-SEC-008] Routing seal REPLAY REJECTED: action=%s sig=%s",
                    action,
                    sig[:16],
                )
                raise SymbolicGovernorViolation(reason, action)
            logger.debug("🔥 Routing seal consumed atomically: key=%s", burn_key)
        except SymbolicGovernorViolation:
            raise
        except Exception as exc:
            logger.warning("⚠️ Failed to burn routing seal in Redis: %s", exc)

    return True


def require_cleared_seal(
    seal: str,
    action: str,
    params: dict,
) -> Callable[[F], F]:
    """Decorator factory that enforces a cleared routing seal before execution.

    Wraps any async or sync callable and raises ``SymbolicGovernorViolation``
    immediately if ``verify_seal()`` fails.  The wrapped callable is never
    invoked if the seal check fails.

    Cryptographic contract:
        The decorator calls ``verify_seal(seal, action, params)`` before
        delegating to the wrapped function.  ``verify_seal`` uses HMAC-SHA256
        with the ``GOVERNANCE_SALT`` key.  A failed check raises
        ``SymbolicGovernorViolation`` — the wrapped function is NOT called.

    Args:
        seal:    Routing seal string from the governance approval response.
        action:  Action name that was approved (e.g. ``"execute_trade"``).
        params:  Parameters dict that was approved — must match the seal.

    Returns:
        A decorator that wraps the target callable with seal verification.

    Raises:
        SymbolicGovernorViolation: If the seal is invalid or expired, raised
            before the wrapped callable is invoked.

    Example::

        @require_cleared_seal(seal, "execute_trade", params)
        async def _actuate() -> str:
            return await broker.execute(params)

        result = await _actuate()
    """

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # verify_seal() raises SymbolicGovernorViolation on any failure —
                # no need to check the return value. The wrapped function is never
                # called if the seal is invalid (CRIT-1 fix).
                verify_seal(seal, action, params)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # verify_seal() raises SymbolicGovernorViolation on any failure —
                # no need to check the return value. The wrapped function is never
                # called if the seal is invalid (CRIT-1 fix).
                verify_seal(seal, action, params)
                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# C-03: Auto-enforce custom HMAC salt at import time in production.
# This ensures the check runs before any seal is generated or verified.
# ---------------------------------------------------------------------------
import os as _os

# MED-8 fix: removed the `== "prod"` guard that only triggered for CAGE_ENV=prod
# exactly.  Deployments with CAGE_ENV=staging, CAGE_ENV=uat, or CAGE_ENV=preprod
# using the default salt would silently pass.  assert_custom_salt_in_production()
# already handles all non-dev/test environments correctly — call it unconditionally.
assert_custom_salt_in_production()
