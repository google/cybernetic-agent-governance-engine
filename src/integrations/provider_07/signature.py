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
Ed25519 JCS Signature Verification for InferTheta Inference Responses.

Implements RFC 8785 JSON Canonicalization Scheme (JCS) with Ed25519
cryptographic verification to ensure inference response integrity and
non-repudiation.

Verification Flow:
1. Create canonical copy of payload omitting "signature" field
2. Canonicalize payload via RFC 8785 JCS (deterministic JSON serialization)
3. Decode urlsafe base64 signature bytes
4. Verify Ed25519 signature over canonical bytes using resolved public key

Security Invariants:
- Signature field MUST be excluded from canonicalization input
- JCS canonicalization prevents floating-point drift across languages
- Ed25519 signature verification is constant-time
- InvalidSignature exceptions are caught and mapped to False (fail-closed)
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("cage.provider_07.signature")


def verify_inference_signature(
    payload: dict[str, Any],
    public_key: Ed25519PublicKey,
    signature_b64: str,
) -> bool:
    """
    Verify Ed25519 JCS signature over inference response payload.

    Creates a canonical copy of the payload with the "signature" field removed,
    canonicalizes it via RFC 8785 JCS, and verifies the Ed25519 signature.

    Args:
        payload: Inference response payload (InferThetaInferenceResponse dict)
        public_key: Ed25519 public key resolved from out-of-band JWKS
        signature_b64: Base64url-encoded signature bytes from response.signature

    Returns:
        True if signature is valid, False otherwise (fail-closed on errors)

    Note:
        This function never raises exceptions. All cryptographic failures
        (InvalidSignature, base64 decode errors, etc.) are caught and
        mapped to False to ensure fail-closed behavior.
    """
    try:
        # Step 1: Create canonical copy omitting "signature" field
        # Trust Anchor Invariant: Never verify against embedded keys.
        # The signature field is excluded to prevent it from being part
        # of the signed content.
        canonical_payload = {k: v for k, v in payload.items() if k != "signature"}

        # Step 2: Canonicalize via RFC 8785 JCS
        # This produces deterministic byte representation, preventing
        # floating-point canonicalization drift between Python and other
        # languages (e.g., Go, Java in the InferTheta service).
        canonical_bytes = jcs_canonicalize_plan(canonical_payload)

        # Step 3: Decode base64url signature bytes
        # Ed25519 signatures are 64 bytes. Add padding if needed.
        signature_bytes = base64.urlsafe_b64decode(signature_b64 + "==")

        if len(signature_bytes) != 64:
            logger.warning(
                "provider_07: Invalid signature length: expected=64 got=%d",
                len(signature_bytes),
            )
            return False

        # Step 4: Verify Ed25519 signature
        # This is constant-time and raises InvalidSignature on failure.
        public_key.verify(signature_bytes, canonical_bytes)

        logger.debug("provider_07: Signature verification SUCCESS")
        return True

    except InvalidSignature:
        # Cryptographic verification failed — signature does not match payload
        logger.warning(
            "provider_07: Signature verification FAILED — InvalidSignature exception"
        )
        return False

    except Exception as exc:
        # Catch-all for base64 decode errors, malformed payloads, etc.
        # Fail-closed: treat all errors as verification failure.
        logger.warning(
            "provider_07: Signature verification FAILED — %s: %s",
            type(exc).__name__,
            exc,
        )
        return False
