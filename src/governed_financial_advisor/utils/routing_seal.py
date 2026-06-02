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

The issuance logic (``generate_seal``) is intentionally omitted — only the
Hybrid Gateway may issue seals.  The GFA only verifies them.

Both pods share the ``GOVERNANCE_SALT`` environment variable, which is the
HMAC key.  Symmetric HMAC-SHA256 validation works flawlessly because both
sides use the same key and the same canonical payload serialisation.

Usage:
    from src.governed_financial_advisor.utils.routing_seal import verify_seal

    if not verify_seal(seal, "execute_trade", params):
        raise PermissionError("Invalid or expired routing seal — trade blocked")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

_GOVERNANCE_SALT = os.getenv("GOVERNANCE_SALT", "REDACTED_SALT")
_HMAC_KEY = _GOVERNANCE_SALT.encode()


def _canonical_payload(action: str, params: dict) -> bytes:
    """Produce a stable, deterministic byte representation of the action payload.

    Must be byte-for-byte identical to the gateway's implementation so that
    HMAC verification succeeds across the service boundary.
    """
    safe = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
            for k, v in params.items()}
    canon = json.dumps({"action": action, **safe}, sort_keys=True, separators=(",", ":"))
    return canon.encode()


def verify_seal(seal: str, action: str, params: dict) -> bool:
    """Verify a routing seal issued by the Hybrid Gateway.

    Returns ``True`` if the seal is cryptographically valid and not expired.
    Returns ``False`` (never raises) on any invalid input so that callers can
    treat a ``False`` result as a hard governance block.

    Args:
        seal:    Seal string from the Gateway's ``/governance/validate-action`` response.
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
