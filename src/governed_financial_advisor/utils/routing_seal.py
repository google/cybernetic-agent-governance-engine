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
Routing Seal — GFA-side verification mirror.

This module is a **read-only mirror** of the verification logic from
``src/gateway/governance/routing_seal.py``.  It exists so that the GFA
service can verify HMAC-SHA256 routing seals issued by the Hybrid Gateway
**without importing gateway source code** (which would couple the two
deployment images unnecessarily).

Seal format (v2 — includes evidence record hash binding):
    <timestamp_ms_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>

**BREAKING CHANGE (v2):** The seal format now includes a 4th component —
``record_hash_hex`` — which cryptographically binds the seal to the specific
evidence record committed to the compliance evidence stream. This ensures:

  1. The seal authenticates the governor's decision at issuance time
  2. The seal is cryptographically bound to a specific evidence record
  3. Any audit can cryptographically verify that the seal corresponds to
     a particular evidence record in the durable chain

The issuance logic (``generate_seal``) is intentionally omitted — only the
Hybrid Gateway may issue seals.  The GFA only verifies them.

Both pods share the ``GOVERNANCE_SALT`` environment variable, which is the
HMAC key.  Symmetric HMAC-SHA256 validation works flawlessly because both
sides use the same key and the same canonical payload serialisation.

HMAC input (v2):
    HMAC-SHA256(
        key=GOVERNANCE_SALT,
        message=expire_hex || "." || action_slug || "." || record_hash || "." || canonical_payload
    )

Usage:
    from src.governed_financial_advisor.utils.routing_seal import (
        verify_seal,
        SymbolicGovernorViolation,
    )

    # verify_seal() raises SymbolicGovernorViolation on failure (P3 fix).
    # Callers must use try/except — a return-value check is no longer possible.
    try:
        verify_seal(seal, "execute_trade", params)
    except SymbolicGovernorViolation as exc:
        raise PermissionError(f"Invalid or expired routing seal — trade blocked: {exc.reason}")
"""

# SYNC NOTE: This file must remain in sync with
# src/gateway/governance/routing_seal.py (the gateway-side issuer).
# Both files share the same GOVERNANCE_SALT, seal format, and TTL logic.
# If you change the seal format or default salt in one file, update the other.

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SymbolicGovernorViolation — mirrors src/gateway/governance/routing_seal.py
# ---------------------------------------------------------------------------


class SymbolicGovernorViolation(Exception):
    """Raised when a routing seal verification fails.

    GFA-side mirror of the gateway's ``SymbolicGovernorViolation``.  Defined
    here so that the GFA service does not need to import gateway source code.

    Attributes:
        reason: Human-readable description of the specific failure mode.
        action: The action name that was being verified.
    """

    def __init__(self, reason: str, action: str = "") -> None:
        self.reason = reason
        self.action = action
        super().__init__(
            f"SymbolicGovernorViolation: routing seal rejected for action "
            f"'{action}': {reason}"
        )


_GOVERNANCE_SALT = os.getenv("GOVERNANCE_SALT", "REDACTED_SALT")
_HMAC_KEY = _GOVERNANCE_SALT.encode()

_USING_DEFAULT_SALT: bool = _GOVERNANCE_SALT == "REDACTED_SALT"

# ---------------------------------------------------------------------------
# Environment detection (module-level so tests can patch it)
# ---------------------------------------------------------------------------
_cage_env_seal = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _cage_env_seal not in ("development", "test", "dev", "ci")

# ---------------------------------------------------------------------------
# Feature flag: Evidence binding enforcement (P0 security hardening)
# ---------------------------------------------------------------------------
# When CAGE_REQUIRE_EVIDENCE_BINDING=true (default in production), verify_seal()
# rejects seals with record_hash="no-evidence-binding" (or empty/none variants).
# This ensures all financial actions are cryptographically bound to evidence
# records in the compliance evidence stream.
# Cross-region impact: US_FED, EU_ECB, APAC_MAS all benefit from evidence binding.
_REQUIRE_EVIDENCE_BINDING: bool = os.environ.get(
    "CAGE_REQUIRE_EVIDENCE_BINDING", "true" if _IS_PRODUCTION else "false"
).lower() in ("true", "1", "yes")

if _USING_DEFAULT_SALT:
    logger.warning(
        "⚠️ [RoutingSeal] GOVERNANCE_SALT is not set — using the hardcoded default "
        "'REDACTED_SALT'. This key is publicly visible in the source "
        "repository. Set GOVERNANCE_SALT to a cryptographically random value "
        "(>=32 bytes) in all non-development environments. "
        "AUDIT: routing seals are forgeable by any party with repository access."
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
    env = (os.getenv("CAGE_ENV") or os.getenv("ENVIRONMENT", "production")).lower()  # type: ignore[union-attr]
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

    Must be byte-for-byte identical to the gateway's implementation so that
    HMAC verification succeeds across the service boundary.
    """
    safe = {
        k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
        for k, v in params.items()
    }
    canon = json.dumps(
        {"action": action, **safe}, sort_keys=True, separators=(",", ":")
    )
    return canon.encode()


def verify_seal(
    seal: str,
    action: str,
    params: dict,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal issued by the Hybrid Gateway (v2 format).

    **BREAKING CHANGE (v2):** The seal format now includes 4 components:
        ``<expire_ts_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>``

    Returns ``True`` on success.  Raises ``SymbolicGovernorViolation`` on any
    verification failure — the exception is never swallowed so callers cannot
    silently ignore a failed check.  This mirrors the CRIT-1 fix applied to
    ``src/gateway/governance/routing_seal.py``; both modules must stay in sync.

    Cryptographic contract (v2):
        Algorithm : HMAC-SHA256
        Key       : ``GOVERNANCE_SALT`` environment variable (≥32 bytes in
                    production; see ``assert_custom_salt_in_production()``).
        Message   : ``<expire_hex>.<action_slug>.<record_hash>.`` + canonical JSON payload
                    (``json.dumps({"action": action, **params}, sort_keys=True,
                    separators=(",", ":"))``).
        Digest    : hex-encoded lowercase SHA-256 HMAC.
        TTL       : ``GOVERNANCE_SEAL_TTL_S`` seconds (default 30).

    Args:
        seal:    Seal string from the Gateway's ``/governance/validate-action`` response.
        action:  Tool / policy action name — must match the issuance action.
        params:  Execution plan parameters — must match the issuance params.
        expected_record_hash:  Optional. If provided, verify that the seal's
                               embedded record_hash matches this value. Use
                               this to cryptographically verify seal ↔ evidence
                               correspondence.

    Returns:
        ``True`` if the seal is valid and unexpired.

    Raises:
        SymbolicGovernorViolation: If the seal is malformed, expired, has an
            action mismatch, record_hash mismatch, or fails HMAC verification.
            Always raised on failure — never swallowed — so callers cannot ignore it.
    """
    try:
        parts = seal.split(".", 3)
        if len(parts) != 4:
            reason = f"malformed seal (got {len(parts)} parts, expected 4 for v2 format)"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        expire_hex, action_slug, record_hash_hex, received_sig = parts

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

        # P0 hardening: Enforce evidence presence in production
        # When CAGE_REQUIRE_EVIDENCE_BINDING=true, seals without cryptographic
        # evidence binding are rejected. This ensures all financial actions are
        # bound to evidence records in the compliance evidence stream.
        _NO_EVIDENCE_SENTINELS = ("no-evidence-binding", "", "none")
        if _REQUIRE_EVIDENCE_BINDING and record_hash_hex.lower() in _NO_EVIDENCE_SENTINELS:
            reason = (
                "Evidence sufficiency violation: seal lacks a cryptographically bound "
                f"evidence record_hash (got '{record_hash_hex}'). "
                "Production requires CAGE_REQUIRE_EVIDENCE_BINDING=true."
            )
            logger.error(
                "⛔ [EVIDENCE_BINDING] Routing seal rejected: action=%s reason=%s",
                action,
                reason,
            )
            raise SymbolicGovernorViolation(reason, action)

        # B2: Optionally verify record_hash matches expected value
        if expected_record_hash is not None:
            if not hmac.compare_digest(record_hash_hex, expected_record_hash):
                reason = (
                    f"record_hash mismatch — seal not bound to expected evidence "
                    f"(got '{record_hash_hex[:16]}…', expected '{expected_record_hash[:16]}…')"
                )
                logger.warning("🔒 Routing seal rejected: %s", reason)
                raise SymbolicGovernorViolation(reason, action)

        # Recompute HMAC (v2 format includes record_hash in message)
        payload = _canonical_payload(action, params)
        message = f"{expire_hex}.{action_slug}.{record_hash_hex}.".encode() + payload
        expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            reason = "HMAC mismatch — seal may be forged or tampered"
            logger.warning("🔒 Routing seal rejected: %s", reason)
            raise SymbolicGovernorViolation(reason, action)

        logger.debug(
            "✅ Routing seal verified: action=%s record_hash=%s",
            action,
            record_hash_hex[:16] if len(record_hash_hex) > 16 else record_hash_hex,
        )
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


def extract_record_hash(seal: str) -> str | None:
    """Extract the record_hash component from a v2 seal.

    Useful for auditing and verification workflows that need to look up the
    evidence record corresponding to a seal.

    Args:
        seal: A v2 seal string.

    Returns:
        The record_hash_hex component, or None if the seal is malformed.
        Returns ``"no-evidence-binding"`` for seals generated without evidence.
    """
    parts = seal.split(".", 3)
    if len(parts) != 4:
        return None
    return parts[2]


async def verify_and_consume_seal(
    seal: str,
    action: str,
    params: dict,
    redis_client: Any = None,
    expected_record_hash: str | None = None,
) -> bool:
    """Verify a routing seal AND atomically burn it in Redis to prevent replay.

    CAGE-SEC-008 / Terry Snyder & Miracle Owolabi remediation:
    Enforces atomic single-use seal semantics. Even within the 30-second TTL
    window, a seal can only be executed once. Subsequent attempts with the
    same seal are rejected with 'SEAL_REPLAY_DETECTED'.

    Args:
        seal:         Routing seal string (v2 format).
        action:       Tool/action name.
        params:       Execution parameters.
        redis_client: Optional async or sync Redis client. If omitted, attempts
                      to load ambient GFA Redis client.
        expected_record_hash: Optional. If provided, verify that the seal's
                              embedded record_hash matches this value.

    Returns:
        True on successful verification and atomic single-use consumption.

    Raises:
        SymbolicGovernorViolation: If verification fails or if the seal was
            already consumed (replay attack detected).
    """
    import inspect

    # 1. First verify cryptographic validity & TTL (and optional record_hash)
    verify_seal(seal, action, params, expected_record_hash=expected_record_hash)

    # 2. If redis client is provided or available, enforce single-use consumption
    # v2 seal format: expire_hex.action_slug.record_hash.sig
    parts = seal.split(".", 3)
    expire_hex, _action_slug, _record_hash, sig = parts
    expire_ts = int(expire_hex, 16)
    ttl = max(int(expire_ts - time.time()), 1)

    if redis_client is None:
        try:
            from src.governed_financial_advisor.infrastructure.redis_client import (
                redis_client as _ambient_client,
            )

            redis_client = _ambient_client
        except Exception:
            redis_client = None

    if redis_client is None:
        raise SymbolicGovernorViolation("Redis unavailable: cannot enforce atomic single-use seal consumption", action)

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
            logger.error("⚠️ Failed to burn routing seal in Redis: %s", exc)
            raise SymbolicGovernorViolation("Redis unavailable or burn failed", action) from exc

    return True
