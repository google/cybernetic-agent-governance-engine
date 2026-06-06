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
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Seal TTL — seals expire after this many seconds.
_TTL_S = int(os.getenv("GOVERNANCE_SEAL_TTL_S", "30"))

# HMAC key — must match between gateway (issuer) and GFA (verifier).
_GOVERNANCE_SALT = os.getenv("GOVERNANCE_SALT", "REDACTED_SALT")
_HMAC_KEY = _GOVERNANCE_SALT.encode()

_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == "REDACTED_SALT"

if _USING_DEFAULT_SALT:
    logger.warning(
        "⚠️ [RoutingSeal] GOVERNANCE_SALT is not set — using the hardcoded default "
        "'REDACTED_SALT'. This key is publicly visible in the source "
        "repository. Set GOVERNANCE_SALT to a cryptographically random value "
        "(>=32 bytes) in all non-development environments. "
        "AUDIT: routing seals are forgeable by any party with repository access."
    )


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

    A True return value means routing seals are forgeable by any party with
    access to the source repository. This must be False in production.
    """
    return _USING_DEFAULT_SALT


def assert_custom_salt_in_production() -> None:
    """Raise RuntimeError if the default GOVERNANCE_SALT is active in production.

    Call during application startup.
    """
    env = (os.getenv("CAGE_ENV") or os.getenv("ENVIRONMENT", "production")).lower()
    if env in ("development", "test", "dev", "ci"):
        return
    if _USING_DEFAULT_SALT:
        raise RuntimeError(
            "CAGE STARTUP FAILURE: routing_seal.py is using the hardcoded default "
            "GOVERNANCE_SALT ('REDACTED_SALT'). This key is publicly "
            "visible in the source repository and must not be used in production. "
            "Set GOVERNANCE_SALT to a cryptographically random value of >=32 bytes."
        )


def _canonical_payload(action: str, params: dict) -> bytes:
    """Produce a stable, deterministic byte representation of the action payload.

    Fields are sorted so that dict ordering differences don't break verification.
    Non-serialisable values are coerced to strings.
    """
    safe = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
            for k, v in params.items()}
    canon = json.dumps({"action": action, **safe}, sort_keys=True, separators=(",", ":"))
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
    action_slug = action.replace("_", "-").lower()[:32]
    payload = _canonical_payload(action, params)
    message = f"{expire_hex}.{action_slug}.".encode() + payload
    sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()
    seal = f"{expire_hex}.{action_slug}.{sig}"
    logger.debug("🔏 Routing seal issued: action=%s expire=%s", action, expire_ts)
    return seal


def verify_seal(seal: str, action: str, params: dict) -> bool:
    """Verify a routing seal issued by the Hybrid Gateway.

    Returns ``True`` on success, ``False`` on any verification failure.
    Also raises ``SymbolicGovernorViolation`` on failure so that callers
    using the decorator pattern (``require_cleared_seal``) cannot silently
    ignore a failed verification.

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
        ``False`` if the seal is malformed, expired, has an action mismatch,
        or fails HMAC verification.

    Raises:
        SymbolicGovernorViolation: Same failure conditions as returning False —
            raised so that ``require_cleared_seal`` callers cannot ignore failures.
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
            reason = f"action mismatch (got '{action_slug}', expected '{expected_slug}')"
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
        return False
    except Exception as exc:  # noqa: BLE001
        reason = f"unexpected verification error: {exc}"
        logger.warning("🔒 Routing seal verification error: %s", exc)
        return False


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
                if not verify_seal(seal, action, params):
                    raise SymbolicGovernorViolation("seal verification failed", action)
                return await func(*args, **kwargs)
            return async_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                if not verify_seal(seal, action, params):
                    raise SymbolicGovernorViolation("seal verification failed", action)
                return func(*args, **kwargs)
            return sync_wrapper  # type: ignore[return-value]
    return decorator
