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
raw_signer_protocol.py — Minimal Signer Protocol for Layer 3 Adapters

Defines the narrowest sufficient abstraction for vendor adapters that need
raw message signing without depending on the full concrete KMSGovernanceSigner.

This protocol supports dependency injection: adapters accept a RawMessageSigner
at construction, allowing test doubles and eliminating service-locator calls
to kernel globals.
"""

from __future__ import annotations

from typing import Protocol


class RawMessageSigner(Protocol):
    """Minimal protocol for KMS-backed raw message signing.

    Vendor adapters (actuator_01, etc.) depend on this protocol rather than
    the concrete KMSGovernanceSigner class, enabling:
    - Dependency injection (signer passed at construction)
    - Test doubles without patching kernel globals
    - Layer isolation (no concrete kernel types in Layer 3)

    This protocol captures only what actuator_01 actually uses:
    - is_kms_active: runtime check before signing
    - sign_raw: sign arbitrary bytes with KMS (Ed25519/ECDSA/RSA)
    """

    @property
    def is_kms_active(self) -> bool:
        """True if Cloud KMS signing is available (production mode)."""
        ...

    def sign_raw(self, message: bytes) -> bytes:
        """Sign raw bytes directly (for JWT/JWS signing or domain-tagged messages).

        Args:
            message: Raw bytes to sign.

        Returns:
            Raw signature bytes.

        Raises:
            RuntimeError: If KMS is not active or signing fails.
        """
        ...
