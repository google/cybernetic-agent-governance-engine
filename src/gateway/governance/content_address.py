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

"""Vendor-neutral content addressing primitives.

This module provides OCI-style content addressing (RFC 6920) for immutable
artifact identification. Content addresses are algorithm-prefixed digests
supporting both direct content hashes and keyed commitments.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar
from urllib.parse import quote, unquote


class ContentAddressKind(Enum):
    """Discriminates dereferenceable content addresses from keyed commitments."""

    DIGEST = "DIGEST"  # Dereferenceable content hash
    COMMITMENT = "COMMITMENT"  # Keyed HMAC, not dereferenceable


class MalformedContentAddress(ValueError):
    """Raised when parsing an invalid content address."""

    pass


@dataclass(frozen=True)
class ContentAddress:
    """An immutable content-addressed identifier.

    Supports both dereferenceable content hashes (DIGEST) and non-dereferenceable
    keyed commitments (COMMITMENT). The kind discriminator prevents misuse of
    commitments as resolvable addresses.

    Attributes:
        algorithm: Hash or commitment algorithm (e.g., "sha256", "hmac-sha256")
        hex_digest: Lowercase hexadecimal digest without prefix
        kind: DIGEST for dereferenceable hashes, COMMITMENT for keyed HMACs
    """

    algorithm: str
    hex_digest: str
    kind: ContentAddressKind

    # Single source of truth: algorithm → (expected_hex_length, kind)
    _ALGORITHM_SPECS: ClassVar[dict[str, tuple[int, ContentAddressKind]]] = {
        "sha256": (64, ContentAddressKind.DIGEST),
        "sha384": (96, ContentAddressKind.DIGEST),
        "sha512": (128, ContentAddressKind.DIGEST),
        "hmac-sha256": (64, ContentAddressKind.COMMITMENT),
    }

    # UUID pattern for rejection (RFC 4122)
    _UUID_PATTERN: ClassVar[re.Pattern] = re.compile(  # type: ignore[type-arg]
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    @classmethod
    def parse(cls, raw: str) -> "ContentAddress":
        """Parse a content address from canonical or URL-encoded form.

        Accepts:
        - Canonical: "sha256:<hex>"
        - URL-encoded: "sha256%3A<hex>"

        Hex input is normalized to lowercase.

        Args:
            raw: Content address string

        Returns:
            Parsed ContentAddress

        Raises:
            MalformedContentAddress: Invalid format, unknown algorithm,
                non-hex characters, wrong digest length, or UUID in digest position
        """
        # Decode URL encoding if present
        decoded = unquote(raw)

        # Split on colon separator
        if ":" not in decoded:
            raise MalformedContentAddress(
                f"Missing separator in content address: {raw}"
            )

        parts = decoded.split(":", 1)
        if len(parts) != 2:
            raise MalformedContentAddress(f"Invalid content address format: {raw}")

        algorithm, digest = parts
        algorithm = algorithm.lower()

        # Check for unknown algorithm
        if algorithm not in cls._ALGORITHM_SPECS:
            raise MalformedContentAddress(
                f"Unknown algorithm '{algorithm}'. "
                f"Supported: {', '.join(cls._ALGORITHM_SPECS.keys())}"
            )

        expected_length, kind = cls._ALGORITHM_SPECS[algorithm]

        # Reject UUID in digest position
        if cls._UUID_PATTERN.match(digest):
            raise MalformedContentAddress(f"UUID detected in digest position: {digest}")

        # Normalize to lowercase
        digest_lower = digest.lower()

        # Check for non-hex characters
        if not re.match(r"^[0-9a-f]+$", digest_lower):
            raise MalformedContentAddress(
                f"Non-hexadecimal characters in digest: {digest}"
            )

        # Check digest length
        if len(digest_lower) != expected_length:
            raise MalformedContentAddress(
                f"Invalid digest length for {algorithm}: "
                f"expected {expected_length} chars, got {len(digest_lower)}"
            )

        return cls(algorithm=algorithm, hex_digest=digest_lower, kind=kind)

    @property
    def canonical(self) -> str:
        """Return canonical form with colon separator: 'sha256:<hex>'."""
        return f"{self.algorithm}:{self.hex_digest}"

    @property
    def url_encoded(self) -> str:
        """Return URL-encoded form: 'sha256%3A<hex>'."""
        return f"{self.algorithm}{quote(':')}{self.hex_digest}"
