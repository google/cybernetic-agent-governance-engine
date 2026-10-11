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
Ed25519 JCS Signature Verification for Agent Integrity Receipts.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) with Ed25519
cryptographic verification to ensure receipt integrity and non-repudiation.

Verification Flow:
1. Create canonical copy of receipt omitting "receiptDigest" and "signature"
2. Canonicalize receipt via RFC 8785 JCS (deterministic JSON serialization)
3. Compute SHA-256 digest and verify against receiptDigest
4. Decode base64 signature bytes
5. Verify Ed25519 signature over canonical bytes using resolved public key

Security Invariants:
- Signature and receiptDigest fields MUST be excluded from canonicalization
- JCS canonicalization prevents floating-point drift across languages
- Ed25519 signature verification is constant-time
- InvalidSignature exceptions are caught and mapped to False (fail-closed)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.provider_06.signature")

_CANONICAL_B64_64_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")


def verify_receipt_digest(
    receipt: dict[str, Any],
    *,
    strict_v2: bool = False,
) -> bool:
    """
    Verify receipt digest matches SHA-256 of canonicalized receipt payload.

    In upstream Agent Integrity v2-alpha (``build-receipt.ts`` / ``recheck-receipt.ts``),
    ``receiptDigest`` is computed over the signed receipt object (omitting only
    ``receiptDigest``). In Phase 1 spike fixtures, ``receiptDigest`` was computed
    over the unsigned body (omitting both ``receiptDigest`` and ``signature``).

    When ``strict_v2=True`` (used by ``POST /v1/verify-release``), only the
    upstream signed-receipt digest is accepted.
    """
    try:
        expected_digest = receipt.get("receiptDigest", "")
        if not isinstance(expected_digest, str) or not expected_digest:
            logger.warning("provider_06: Receipt missing receiptDigest field")
            return False

        # Upstream v2-alpha: SHA-256 over JCS of receipt omitting receiptDigest
        signed_copy = {k: v for k, v in receipt.items() if k != "receiptDigest"}
        signed_digest = hashlib.sha256(jcs_canonicalize_plan(signed_copy)).hexdigest()
        if signed_digest == expected_digest:
            logger.debug("provider_06: Receipt digest verification SUCCESS (v2 signed)")
            return True

        if strict_v2:
            logger.warning(
                "provider_06: Receipt digest mismatch (strict_v2): expected=%s computed=%s",
                expected_digest,
                signed_digest,
            )
            return False

        # Phase 1 spike fallback: SHA-256 over JCS omitting receiptDigest and signature
        unsigned_copy = {
            k: v for k, v in receipt.items() if k not in ("receiptDigest", "signature")
        }
        unsigned_digest = hashlib.sha256(
            jcs_canonicalize_plan(unsigned_copy)
        ).hexdigest()
        if unsigned_digest == expected_digest:
            logger.debug(
                "provider_06: Receipt digest verification SUCCESS (legacy unsigned)"
            )
            return True

        logger.warning(
            "provider_06: Receipt digest mismatch: expected=%s computed=%s",
            expected_digest,
            signed_digest,
        )
        return False

    except Exception as exc:
        logger.warning(
            "provider_06: Receipt digest verification FAILED — %s: %s",
            type(exc).__name__,
            exc,
        )
        return False


def verify_receipt_signature(
    receipt: dict[str, Any],
    public_key: Ed25519PublicKey,
    *,
    strict_v2: bool = False,
) -> bool:
    """
    Verify Ed25519 JCS signature over Agent Integrity receipt.

    In upstream Agent Integrity v2-alpha (``build-receipt.ts`` / ``recheck-receipt.ts``),
    the Ed25519 signature is canonical standard base64 (86 chars + ``==``) over
    ``jcs_canonicalize({"protected": {"algorithm": "Ed25519", "keyId": keyId}, "body": unsigned_body})``.
    When ``strict_v2=True``, only this upstream v2-alpha format is accepted.
    """
    try:
        signature_block = receipt.get("signature", {})
        if not isinstance(signature_block, dict):
            logger.warning("provider_06: Receipt missing signature block")
            return False

        if signature_block.get("algorithm") != "Ed25519":
            logger.warning("provider_06: Unsupported signature algorithm")
            return False

        key_id = signature_block.get("keyId", "")
        signature_value = signature_block.get("value", "")
        if (
            not isinstance(key_id, str)
            or not key_id
            or not isinstance(signature_value, str)
            or not signature_value
        ):
            logger.warning("provider_06: Receipt signature.keyId or value missing")
            return False

        unsigned_body = {
            k: v for k, v in receipt.items() if k not in ("receiptDigest", "signature")
        }

        if strict_v2:
            if not _CANONICAL_B64_64_RE.fullmatch(signature_value):
                logger.warning(
                    "provider_06: Non-canonical base64 signature in strict_v2 mode"
                )
                return False
            signature_bytes = base64.b64decode(signature_value, validate=True)
            if (
                len(signature_bytes) != 64
                or base64.b64encode(signature_bytes).decode("ascii") != signature_value
            ):
                logger.warning("provider_06: Invalid signature encoding in strict_v2")
                return False
            envelope_payload = jcs_canonicalize_plan(
                {
                    "protected": {"algorithm": "Ed25519", "keyId": key_id},
                    "body": unsigned_body,
                }
            )
            public_key.verify(signature_bytes, envelope_payload)
            logger.debug("provider_06: Signature verification SUCCESS (strict_v2)")
            return True

        # Try canonical base64 (v2-alpha) or base64url (Phase 1 spike)
        if _CANONICAL_B64_64_RE.fullmatch(signature_value):
            signature_bytes = base64.b64decode(signature_value)
        else:
            signature_bytes = base64.urlsafe_b64decode(signature_value + "==")

        if len(signature_bytes) != 64:
            logger.warning(
                "provider_06: Invalid signature length: expected=64 got=%d",
                len(signature_bytes),
            )
            return False

        # First check upstream v2-alpha protected+body signature payload
        v2_payload = jcs_canonicalize_plan(
            {
                "protected": {"algorithm": "Ed25519", "keyId": key_id},
                "body": unsigned_body,
            }
        )
        try:
            public_key.verify(signature_bytes, v2_payload)
            logger.debug("provider_06: Signature verification SUCCESS (v2)")
            return True
        except InvalidSignature:
            pass

        # Fallback to Phase 1 spike unsigned-body payload
        legacy_payload = jcs_canonicalize_plan(unsigned_body)
        public_key.verify(signature_bytes, legacy_payload)
        logger.debug("provider_06: Signature verification SUCCESS (legacy)")
        return True

    except InvalidSignature:
        logger.warning(
            "provider_06: Signature verification FAILED — InvalidSignature exception"
        )
        return False

    except Exception as exc:
        logger.warning(
            "provider_06: Signature verification FAILED — %s: %s",
            type(exc).__name__,
            exc,
        )
        return False
