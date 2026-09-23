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
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.provider_06.signature")


def verify_receipt_digest(receipt: dict[str, Any]) -> bool:
    """
    Verify receipt digest matches SHA-256 of canonicalized receipt payload.

    Creates a canonical copy of the receipt with "receiptDigest" and "signature"
    fields removed, canonicalizes it via RFC 8785 JCS, computes SHA-256, and
    compares against the receipt's receiptDigest field.

    Args:
        receipt: Agent Integrity receipt dict (AlphaIntegrityReceipt)

    Returns:
        True if digest matches, False otherwise (fail-closed on errors)

    Note:
        This function never raises exceptions. All errors are caught and
        mapped to False to ensure fail-closed behavior.
    """
    try:
        # Extract expected digest
        expected_digest = receipt.get("receiptDigest", "")
        if not expected_digest:
            logger.warning("provider_06: Receipt missing receiptDigest field")
            return False

        # Step 1: Create canonical copy omitting receiptDigest and signature
        canonical_receipt = {
            k: v
            for k, v in receipt.items()
            if k not in ("receiptDigest", "signature")
        }

        # Step 2: Canonicalize via RFC 8785 JCS
        canonical_bytes = jcs_canonicalize_plan(canonical_receipt)

        # Step 3: Compute SHA-256 digest
        computed_digest = hashlib.sha256(canonical_bytes).hexdigest()

        # Step 4: Compare digests
        if computed_digest != expected_digest:
            logger.warning(
                "provider_06: Receipt digest mismatch: expected=%s computed=%s",
                expected_digest,
                computed_digest,
            )
            return False

        logger.debug("provider_06: Receipt digest verification SUCCESS")
        return True

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
) -> bool:
    """
    Verify Ed25519 JCS signature over Agent Integrity receipt.

    Creates a canonical copy of the receipt with "receiptDigest" and "signature"
    fields removed, canonicalizes it via RFC 8785 JCS, and verifies the Ed25519
    signature.

    Args:
        receipt: Agent Integrity receipt dict (AlphaIntegrityReceipt)
        public_key: Ed25519 public key resolved from out-of-band JWKS

    Returns:
        True if signature is valid, False otherwise (fail-closed on errors)

    Note:
        This function never raises exceptions. All cryptographic failures
        (InvalidSignature, base64 decode errors, etc.) are caught and
        mapped to False to ensure fail-closed behavior.
    """
    try:
        # Extract signature block
        signature_block = receipt.get("signature", {})
        if not isinstance(signature_block, dict):
            logger.warning("provider_06: Receipt missing signature block")
            return False

        signature_value = signature_block.get("value", "")
        if not signature_value:
            logger.warning("provider_06: Receipt signature.value missing")
            return False

        # Step 1: Create canonical copy omitting receiptDigest and signature
        canonical_receipt = {
            k: v
            for k, v in receipt.items()
            if k not in ("receiptDigest", "signature")
        }

        # Step 2: Canonicalize via RFC 8785 JCS
        canonical_bytes = jcs_canonicalize_plan(canonical_receipt)

        # Step 3: Decode base64url signature bytes
        # Ed25519 signatures are 64 bytes. Add padding if needed.
        signature_bytes = base64.urlsafe_b64decode(signature_value + "==")

        if len(signature_bytes) != 64:
            logger.warning(
                "provider_06: Invalid signature length: expected=64 got=%d",
                len(signature_bytes),
            )
            return False

        # Step 4: Verify Ed25519 signature
        # This is constant-time and raises InvalidSignature on failure.
        public_key.verify(signature_bytes, canonical_bytes)

        logger.debug("provider_06: Signature verification SUCCESS")
        return True

    except InvalidSignature:
        # Cryptographic verification failed — signature does not match payload
        logger.warning(
            "provider_06: Signature verification FAILED — InvalidSignature exception"
        )
        return False

    except Exception as exc:
        # Catch-all for base64 decode errors, malformed payloads, etc.
        # Fail-closed: treat all errors as verification failure.
        logger.warning(
            "provider_06: Signature verification FAILED — %s: %s",
            type(exc).__name__,
            exc,
        )
        return False
