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

Usage:
    # Gateway (issuance):
    seal = generate_seal("execute_trade", params)

    # GFA (verification before actuation):
    if not verify_seal(seal, "execute_trade", params):
        raise GovernanceError("Invalid or expired routing seal")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

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

    Returns ``True`` if the seal is cryptographically valid and not expired.
    Returns ``False`` (never raises) on any invalid input so that callers can
    treat a ``False`` result as a hard governance block.

    Args:
        seal:    Seal string as returned by :func:`generate_seal`.
        action:  Tool / policy action name — must match the issuance action.
        params:  Execution plan parameters — must match the issuance params.
    """
    try:
        parts = seal.split(".", 2)
        if len(parts) != 3:
            logger.warning("🔒 Routing seal rejected: malformed (got %d parts)", len(parts))
            return False

        expire_hex, action_slug, received_sig = parts

        # Check expiry
        expire_ts = int(expire_hex, 16)
        if time.time() > expire_ts:
            logger.warning("🔒 Routing seal rejected: expired (ts=%s)", expire_ts)
            return False

        # Check action slug
        expected_slug = action.replace("_", "-").lower()[:32]
        if action_slug != expected_slug:
            logger.warning(
                "🔒 Routing seal rejected: action mismatch (got %s, expected %s)",
                action_slug, expected_slug,
            )
            return False

        # Recompute HMAC
        payload = _canonical_payload(action, params)
        message = f"{expire_hex}.{action_slug}.".encode() + payload
        expected_sig = hmac.new(_HMAC_KEY, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            logger.warning("🔒 Routing seal rejected: HMAC mismatch")
            return False

        logger.debug("✅ Routing seal verified: action=%s", action)
        return True

    except Exception as exc:  # noqa: BLE001
        logger.warning("🔒 Routing seal verification error: %s", exc)
        return False
