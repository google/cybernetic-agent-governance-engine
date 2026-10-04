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
receipt_verifier.py — kid-resolved verification of actuator_01 receipts.

A partner response body MAY carry a detached Ed25519 signature::

    {
      "receipt_id": "...", "session_uuid": "...", "status": "...",
      "envelope_digest": "<sha256 hex of the canonical envelope CAGE sent>",
      "signature": {"alg": "EdDSA", "kid": "<key id>", "value": "<base64url>"}
    }

Signed message: ``RECEIPT_SIGNATURE_DOMAIN_TAG || JCS(body without "signature")``.

Verification rules (fail closed):

- The key is resolved ONLY by ``kid`` from an independently fetched manifest,
  never from the receipt itself. An unknown ``kid`` is ``INVALID``.
- The signed body must echo the ``envelope_digest`` CAGE submitted, binding the
  receipt to this exact clearance (a valid receipt for another order is
  ``INVALID``).
- A body with no signature, or one whose key manifest cannot be fetched or is
  not configured, is ``UNVERIFIED`` — receipt resolution is not verification.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.actuation import ReceiptVerification
from src.integrations.actuator_01.constants import RECEIPT_SIGNATURE_DOMAIN_TAG
from src.integrations.trust.key_manifest import Ed25519KeyResolver

logger = logging.getLogger(__name__)

_ED25519_SIGNATURE_BYTES = 64


@dataclass(frozen=True)
class ReceiptCheck:
    """Result of checking a partner receipt signature."""

    verification: ReceiptVerification
    finding: dict | None = None


def _finding(code: str, severity: str, detail: str) -> dict:
    return {"code": code, "severity": severity, "detail": detail}


def _invalid(code: str, detail: str) -> ReceiptCheck:
    logger.warning("[actuator_01/receipt] %s: %s", code, detail)
    return ReceiptCheck(ReceiptVerification.INVALID, _finding(code, "TERMINAL", detail))


async def verify_partner_receipt(
    body: dict[str, Any] | None,
    *,
    envelope_digest: str,
    key_resolver: Ed25519KeyResolver | None,
) -> ReceiptCheck:
    """Verify a partner response body's detached receipt signature.

    Never raises: every failure maps to ``INVALID`` or ``UNVERIFIED``.
    """
    if not isinstance(body, dict) or "signature" not in body:
        return ReceiptCheck(ReceiptVerification.UNVERIFIED)

    signature = body["signature"]
    if not isinstance(signature, dict):
        return _invalid("RECEIPT_SIGNATURE_MALFORMED", "signature is not an object")
    if signature.get("alg") != "EdDSA":
        return _invalid(
            "RECEIPT_SIGNATURE_MALFORMED",
            f"unsupported alg {signature.get('alg')!r} (EdDSA required)",
        )
    kid = signature.get("kid")
    value = signature.get("value")
    if not isinstance(kid, str) or not kid or not isinstance(value, str) or not value:
        return _invalid("RECEIPT_SIGNATURE_MALFORMED", "signature kid/value missing")

    if key_resolver is None:
        return ReceiptCheck(
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_TRUST_ANCHOR_UNCONFIGURED",
                "WARNING",
                f"signed receipt (kid={kid}) but no receipt key manifest configured",
            ),
        )

    try:
        public_key = await key_resolver.get_key(kid)
    except Exception as exc:
        logger.error("[actuator_01/receipt] key manifest unavailable: %s", exc)
        return ReceiptCheck(
            ReceiptVerification.UNVERIFIED,
            _finding(
                "RECEIPT_KEY_MANIFEST_UNAVAILABLE",
                "WARNING",
                f"could not resolve kid={kid}: {type(exc).__name__}",
            ),
        )
    if public_key is None:
        return _invalid("RECEIPT_UNKNOWN_KID", f"kid={kid} not in receipt key manifest")

    try:
        signature_bytes = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return _invalid("RECEIPT_SIGNATURE_MALFORMED", "signature value is not base64url")
    if len(signature_bytes) != _ED25519_SIGNATURE_BYTES:
        return _invalid(
            "RECEIPT_SIGNATURE_MALFORMED",
            f"Ed25519 signature must be 64 bytes, got {len(signature_bytes)}",
        )

    signed_body = {k: v for k, v in body.items() if k != "signature"}
    try:
        message = RECEIPT_SIGNATURE_DOMAIN_TAG + jcs_canonicalize_plan(signed_body)
        public_key.verify(signature_bytes, message)
    except InvalidSignature:
        return _invalid("RECEIPT_SIGNATURE_INVALID", f"signature does not verify (kid={kid})")
    except Exception as exc:
        return _invalid(
            "RECEIPT_SIGNATURE_MALFORMED", f"receipt not canonicalizable: {type(exc).__name__}"
        )

    if signed_body.get("envelope_digest") != envelope_digest:
        return _invalid(
            "RECEIPT_ENVELOPE_MISMATCH",
            "signed receipt is bound to a different envelope_digest",
        )

    logger.info("[actuator_01/receipt] receipt signature VERIFIED (kid=%s)", kid)
    return ReceiptCheck(ReceiptVerification.VERIFIED)
