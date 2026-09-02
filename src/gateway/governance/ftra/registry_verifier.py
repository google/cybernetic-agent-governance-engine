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
FTRA Terminal Registry Signature Verification

This module closes **VEC-005** (registry re-declaration bypass) and **VEC-008**
(signed-registry rollback) by validating detached signatures and enforcing
monotonic serial numbers.

Verification order (cheap structural checks before crypto):
    1. Envelope shape — version == "2.0", terminals is dict, no "signed_at" field
    2. .sig file present and parseable
    3. expires_at present, timezone-aware, in the future
    4. Serial monotonicity (high-water mark + FTRA_REGISTRY_MIN_SERIAL floor)
    5. Signature verification (KMS-touching work last)

Posture gating:
    - FTRA_REGISTRY_REQUIRE_SIGNATURE env var controls enforcement
    - Defaults ON in production, OFF in dev/test/ci (derived from CAGE_ENV)
    - Precedent: cbf_engine.py line 426 for Redis epoch fail-closed behavior

Known limitations (documented in FTRA_COMPENSATING_CONTROLS.md):
    - Posture gate is not a defense against env-control attacks
    - In-memory high-water mark defeated by registry rollback + pod restart
      (mitigated by deployment-pinned FTRA_REGISTRY_MIN_SERIAL floor)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("Gateway.Governance.FTRA.RegistryVerifier")

# ---------------------------------------------------------------------------
# Module-level state for digest cache and serial monotonicity
# ---------------------------------------------------------------------------

_verification_lock = threading.RLock()
_last_verified_digest: str | None = None
_last_signature_valid: bool | None = None
_seen_serial_high_water: int = 0

# ---------------------------------------------------------------------------
# Failure codes (ten distinct codes per plan section 4)
# ---------------------------------------------------------------------------

SIG_MISSING = "SIG_MISSING"
SIG_MALFORMED = "SIG_MALFORMED"
SIG_INVALID = "SIG_INVALID"
EXPIRED = "EXPIRED"
EXPIRY_MISSING = "EXPIRY_MISSING"
EXPIRY_NAIVE = "EXPIRY_NAIVE"
SERIAL_REGRESSED = "SERIAL_REGRESSED"
SERIAL_MISSING = "SERIAL_MISSING"
ENVELOPE_INVALID = "ENVELOPE_INVALID"
PUBKEY_UNAVAILABLE = "PUBKEY_UNAVAILABLE"


# ---------------------------------------------------------------------------
# VerificationResult dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """Result of registry signature and envelope verification.

    Attributes:
        valid: True if all checks passed, False otherwise.
        reason: Machine-readable failure code (surfaced as OTel span attribute).
        serial: Registry serial number if present, None otherwise.
        expires_at: Registry expiration timestamp if present, None otherwise.
    """

    valid: bool
    reason: str
    serial: int | None
    expires_at: datetime | None


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------


def _get_enforcement_posture() -> bool:
    """Return True if signature enforcement is ON, False otherwise.

    Reads FTRA_REGISTRY_REQUIRE_SIGNATURE first. If unset, derives from
    CAGE_ENV: ON in production, OFF in dev/test/ci.

    Precedent: cbf_engine.py:426 for Redis epoch enforcement.
    """
    explicit = os.getenv("FTRA_REGISTRY_REQUIRE_SIGNATURE", "").lower()
    if explicit in ("true", "1", "yes"):
        return True
    if explicit in ("false", "0", "no"):
        return False

    # Derive from CAGE_ENV
    env = (os.getenv("CAGE_ENV") or os.getenv("ENVIRONMENT", "production")).lower()
    is_production = env not in ("development", "test", "dev", "ci")
    return is_production


def _get_serial_floor() -> int:
    """Return the deployment-pinned serial floor (FTRA_REGISTRY_MIN_SERIAL).

    Defaults to 0 if unset. Survives pod restart because it is set in the
    Deployment manifest, not held in memory.
    """
    floor_str = os.getenv("FTRA_REGISTRY_MIN_SERIAL", "0")
    try:
        return int(floor_str)
    except ValueError:
        logger.warning(
            "FTRA_REGISTRY_MIN_SERIAL='%s' is not an integer, using 0", floor_str
        )
        return 0


def _commit_serial_high_water(serial_value: int) -> None:
    """Advance the in-memory anti-rollback high-water mark.

    R3/D3: call this **only** after the registry's signature has been proven
    valid. Committing an unverified serial lets an attacker poison the mark with
    a forged high value — the forgery itself is rejected, but every subsequent
    legitimate registry is then refused ``SERIAL_REGRESSED`` for the lifetime of
    the process, turning a blocked attack into a self-inflicted denial of the
    governance control.

    Args:
        serial_value: Serial number from a fully verified registry.
    """
    global _seen_serial_high_water
    with _verification_lock:
        if serial_value > _seen_serial_high_water:
            _seen_serial_high_water = serial_value
            logger.info(
                "FTRA registry serial high-water mark updated: %d", serial_value
            )


def verify_registry(
    registry_path: Path,
    signer: Any | None = None,
) -> VerificationResult:
    """Verify a terminal registry envelope and detached signature.

    Ordered checks (cheap structural checks before KMS-touching work):
        1. Envelope shape (version, terminals dict, no "signed_at" trap)
        2. .sig file present and parseable
        3. expires_at present, timezone-aware, in the future
        4. Serial monotonicity (high-water mark + FTRA_REGISTRY_MIN_SERIAL floor)
        5. Signature verification (asymmetric crypto, cached by digest)

    Args:
        registry_path: Path to the terminal_registry.json file.
        signer: KMSGovernanceSigner instance with public_key_pem loaded.
                If None and enforcement is ON, returns PUBKEY_UNAVAILABLE.

    Returns:
        VerificationResult with valid=True on success, or valid=False with a
        distinct failure reason code.

    Raises:
        Never raises. All failures return VerificationResult(valid=False, reason=...).
    """
    enforcement_on = _get_enforcement_posture()

    # ---------------------------------------------------------------------------
    # Step 0: Load registry bytes and JSON
    # ---------------------------------------------------------------------------
    try:
        registry_bytes = registry_path.read_bytes()
        registry_dict: dict[str, Any] = json.loads(registry_bytes)
    except Exception as exc:
        logger.error(
            "FTRA registry verification: failed to load %s: %s", registry_path, exc
        )
        return VerificationResult(
            valid=False, reason=ENVELOPE_INVALID, serial=None, expires_at=None
        )

    # ---------------------------------------------------------------------------
    # Step 1: Envelope shape
    # ---------------------------------------------------------------------------
    version = registry_dict.get("version")
    terminals = registry_dict.get("terminals")
    if version != "2.0":
        logger.warning(
            "FTRA registry version is '%s', expected '2.0' — verification skipped",
            version,
        )
        return VerificationResult(
            valid=False, reason=ENVELOPE_INVALID, serial=None, expires_at=None
        )

    if not isinstance(terminals, dict):
        logger.error("FTRA registry 'terminals' is not a dict")
        return VerificationResult(
            valid=False, reason=ENVELOPE_INVALID, serial=None, expires_at=None
        )

    # Guard: no "signed_at" field (plan section 3 trap)
    if "signed_at" in registry_dict:
        logger.error(
            "FTRA registry contains 'signed_at' field — this would trigger "
            "KMSGovernanceSigner staleness rejection after 300 seconds. "
            "Use 'issued_at' and 'expires_at' instead."
        )
        return VerificationResult(
            valid=False, reason=ENVELOPE_INVALID, serial=None, expires_at=None
        )

    # ---------------------------------------------------------------------------
    # Step 2: .sig file present and parseable
    # ---------------------------------------------------------------------------
    sig_path = Path(str(registry_path) + ".sig")
    if enforcement_on and not sig_path.exists():
        logger.error(
            "FTRA registry signature file missing: %s (enforcement ON)", sig_path
        )
        return VerificationResult(
            valid=False, reason=SIG_MISSING, serial=None, expires_at=None
        )

    sig_dict: dict[str, Any] = {}
    signature_hex: str | None = None
    if sig_path.exists():
        try:
            sig_dict = json.loads(sig_path.read_text())
            signature_hex = sig_dict.get("signature")
            if not signature_hex:
                raise ValueError("signature field missing or empty")
        except Exception as exc:
            logger.error(
                "FTRA registry signature file malformed (%s): %s", sig_path, exc
            )
            return VerificationResult(
                valid=False, reason=SIG_MALFORMED, serial=None, expires_at=None
            )

    # ---------------------------------------------------------------------------
    # Step 3: expires_at present, timezone-aware, in the future
    # ---------------------------------------------------------------------------
    serial_value = registry_dict.get("serial")
    expires_at_str = registry_dict.get("expires_at")
    expires_at_dt: datetime | None = None

    if expires_at_str is None:
        logger.error("FTRA registry 'expires_at' field missing")
        return VerificationResult(
            valid=False,
            reason=EXPIRY_MISSING,
            serial=serial_value,
            expires_at=None,
        )

    try:
        expires_at_dt = datetime.fromisoformat(expires_at_str)
    except Exception as exc:
        logger.error(
            "FTRA registry 'expires_at' is not a valid ISO 8601 timestamp: %s", exc
        )
        return VerificationResult(
            valid=False,
            reason=EXPIRY_MISSING,
            serial=serial_value,
            expires_at=None,
        )

    # Reject naive datetimes (never coerce to UTC)
    if expires_at_dt.tzinfo is None:
        logger.error(
            "FTRA registry 'expires_at' is timezone-naive: %s", expires_at_str
        )
        return VerificationResult(
            valid=False, reason=EXPIRY_NAIVE, serial=serial_value, expires_at=None
        )

    # Check expiry (re-evaluated on every load, outside digest cache)
    now_utc = datetime.now(timezone.utc)
    if expires_at_dt <= now_utc:
        logger.error(
            "FTRA registry expired: expires_at=%s, now=%s",
            expires_at_dt.isoformat(),
            now_utc.isoformat(),
        )
        return VerificationResult(
            valid=False, reason=EXPIRED, serial=serial_value, expires_at=expires_at_dt
        )

    # ---------------------------------------------------------------------------
    # Step 4: Serial monotonicity
    # ---------------------------------------------------------------------------
    if serial_value is None or not isinstance(serial_value, int):
        logger.error("FTRA registry 'serial' field missing or not an integer")
        return VerificationResult(
            valid=False,
            reason=SERIAL_MISSING,
            serial=None,
            expires_at=expires_at_dt,
        )

    global _seen_serial_high_water
    serial_floor = _get_serial_floor()

    # R3/D3: reject a regression here, but do NOT commit the high-water mark yet.
    # Committing before the signature is checked lets an attacker poison the mark
    # with a forged `serial: 999999`; the forgery is rejected, but every later
    # legitimate registry is then refused SERIAL_REGRESSED for the pod's lifetime,
    # converting a blocked forgery into a self-inflicted denial of the control.
    # The commit happens after step 5 succeeds.
    with _verification_lock:
        effective_floor = max(serial_floor, _seen_serial_high_water)
        if serial_value < effective_floor:
            logger.error(
                "FTRA registry serial rollback detected: serial=%d, floor=%d "
                "(FTRA_REGISTRY_MIN_SERIAL=%d, in-memory high-water=%d)",
                serial_value,
                effective_floor,
                serial_floor,
                _seen_serial_high_water,
            )
            return VerificationResult(
                valid=False,
                reason=SERIAL_REGRESSED,
                serial=serial_value,
                expires_at=expires_at_dt,
            )

    # ---------------------------------------------------------------------------
    # Step 5: Signature verification (KMS-touching work last, cached by digest)
    # ---------------------------------------------------------------------------
    if not enforcement_on:
        logger.info(
            "FTRA registry signature enforcement OFF (posture gate) — skipping verification"
        )
        # R3/D3: no signature was checked on this path, so the serial is
        # unverified. Deliberately do NOT advance the high-water mark — doing so
        # would let an unverified serial poison the mark via the dev path.
        return VerificationResult(
            valid=True, reason="", serial=serial_value, expires_at=expires_at_dt
        )

    if signer is None:
        logger.error(
            "FTRA registry signature enforcement ON but no signer provided "
            "(public key unavailable)"
        )
        return VerificationResult(
            valid=False,
            reason=PUBKEY_UNAVAILABLE,
            serial=serial_value,
            expires_at=expires_at_dt,
        )

    # Digest cache: skip crypto if content unchanged
    digest = hashlib.sha256(registry_bytes).hexdigest()
    global _last_verified_digest, _last_signature_valid

    with _verification_lock:
        if digest == _last_verified_digest and _last_signature_valid is not None:
            if _last_signature_valid:
                logger.debug(
                    "FTRA registry signature cached (digest=%s...)", digest[:16]
                )
                # Signature previously verified for these exact bytes — safe to
                # commit the high-water mark (R3).
                _commit_serial_high_water(serial_value)
                return VerificationResult(
                    valid=True,
                    reason="",
                    serial=serial_value,
                    expires_at=expires_at_dt,
                )
            else:
                # Signature was invalid last time — re-verify anyway (transient KMS errors)
                pass

    # Perform signature verification
    try:
        # KMSGovernanceSigner.verify() expects a dict and canonicalizes internally
        sig_valid = signer.verify(registry_dict, signature_hex)

        with _verification_lock:
            _last_verified_digest = digest
            _last_signature_valid = sig_valid

        if not sig_valid:
            logger.error(
                "FTRA registry signature verification FAILED (serial=%d, key_id=%s)",
                serial_value,
                getattr(signer, "key_id", "unknown"),
            )
            return VerificationResult(
                valid=False,
                reason=SIG_INVALID,
                serial=serial_value,
                expires_at=expires_at_dt,
            )

        logger.info(
            "✅ FTRA registry signature verified: serial=%d, key_id=%s",
            serial_value,
            getattr(signer, "key_id", "unknown"),
        )
        # R3/D3: the signature is now proven valid — only here is it safe to
        # advance the anti-rollback high-water mark.
        _commit_serial_high_water(serial_value)
        return VerificationResult(
            valid=True, reason="", serial=serial_value, expires_at=expires_at_dt
        )

    except Exception as exc:
        logger.error(
            "FTRA registry signature verification raised exception: %s", exc
        )
        return VerificationResult(
            valid=False,
            reason=SIG_INVALID,
            serial=serial_value,
            expires_at=expires_at_dt,
        )
