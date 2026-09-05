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
pii_scrubber.py — Mandatory PII Scrubbing Gate for Evidence Stream Ingest
==========================================================================

Sprint 2, Deliverable 2.6: PII scrubbing with ScrubbedPayload newtype.

Design Consideration §6.1: PII scrubbing must precede immutable append.
The ScrubbedPayload newtype ensures unscrubbed data has no code path to XADD.

Type-enforced scrubbing prevents raw user data from entering the cryptographically
sealed evidence chain. This is critical for:
  - GDPR Article 25 (data protection by design)
  - ISO 42001 A.6.3 (data minimization)
  - NIST SP 800-53 AC-23 (data mining protection)

The newtype pattern forces all call sites to explicitly invoke PIIScrubber.scrub()
before evidence stream ingestion, preventing accidental PII leakage into the
immutable audit trail.
"""

from __future__ import annotations

import re
from typing import Any, NewType

# NewType prevents unscrubbed data from reaching Evidence Stream
ScrubbedPayload = NewType("ScrubbedPayload", dict[str, Any])


class PIIScrubber:
    """
    Mandatory PII scrubbing gate before Evidence Stream ingest.

    Design Consideration §6.1: PII scrubbing must precede immutable append.
    The ScrubbedPayload newtype ensures unscrubbed data has no code path to XADD.

    Redaction patterns:
      - Email addresses → [EMAIL_REDACTED]
      - SSN (XXX-XX-XXXX) → [SSN_REDACTED]
      - Phone numbers → [PHONE_REDACTED]
      - Credit card numbers → [CC_REDACTED]

    Usage:
        >>> payload = {"user": "alice@example.com", "amount": 100.0}
        >>> scrubbed = PIIScrubber.scrub(payload)
        >>> sink.ingest_sync(scrubbed)  # Type enforced by ScrubbedPayload
    """

    # Patterns from src/gateway/governance/pii_sanitizer.py
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    # Match phone numbers: 555-123-4567, 555.123.4567, 5551234567, 555-1234
    PHONE_PATTERN = re.compile(r"\b\d{3}[-.]?\d{3,4}[-.]?\d{4}\b|\b\d{3}[-]\d{4}\b")
    CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")

    @staticmethod
    def scrub(payload: dict[str, Any]) -> ScrubbedPayload:
        """
        Scrub PII from payload.

        Returns ScrubbedPayload newtype that can be ingested to Evidence Stream.

        Args:
            payload: Unscrubbed event payload (governance decision, audit finding, etc.)

        Returns:
            ScrubbedPayload newtype with PII patterns replaced by redaction markers.
        """
        scrubbed = payload.copy()

        # Recursively scrub string values
        for key, value in scrubbed.items():
            if isinstance(value, str):
                scrubbed[key] = PIIScrubber._scrub_string(value)
            elif isinstance(value, dict):
                scrubbed[key] = PIIScrubber.scrub(value)
            elif isinstance(value, list):
                scrubbed[key] = [
                    PIIScrubber.scrub(item)
                    if isinstance(item, dict)
                    else PIIScrubber._scrub_string(item)
                    if isinstance(item, str)
                    else item
                    for item in value
                ]

        return ScrubbedPayload(scrubbed)

    @staticmethod
    def _scrub_string(text: str) -> str:
        """Replace PII patterns with redacted markers."""
        text = PIIScrubber.EMAIL_PATTERN.sub("[EMAIL_REDACTED]", text)
        text = PIIScrubber.SSN_PATTERN.sub("[SSN_REDACTED]", text)
        text = PIIScrubber.PHONE_PATTERN.sub("[PHONE_REDACTED]", text)
        text = PIIScrubber.CREDIT_CARD_PATTERN.sub("[CC_REDACTED]", text)
        return text
