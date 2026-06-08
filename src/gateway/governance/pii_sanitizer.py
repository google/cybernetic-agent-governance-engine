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
pii_sanitizer.py — Pre-Ledger PII Sanitization Pipeline
=========================================================
Implements ISO 42001 Annex A.6 (Data Lineage and PII Leak Mitigation).

Every UCA compliance record written to the WORM ledger passes through this
pipeline before serialization.  The sanitizer applies five regex patterns
sequentially to redact SSNs, credit card numbers, email addresses, phone
numbers, and API keys / Bearer tokens.

Design decisions
----------------
- Patterns are compiled once at module import time (no per-call overhead).
- All patterns use ``re.sub()`` — no stateful regex objects per call.
- False-positive resistance: SSN pattern excludes invalid ranges (000, 666,
  9xx) per IRS rules; CC pattern requires Luhn-compatible prefix ranges.
- The sanitizer is intentionally conservative: it may redact some non-PII
  strings that match the patterns (e.g. a 9-digit product code that looks
  like an SSN).  This is the correct trade-off for a WORM audit ledger.

Usage::

    from src.gateway.governance.pii_sanitizer import PIISanitizer

    sanitizer = PIISanitizer()
    clean = sanitizer.sanitize("Contact user@example.com or 123-45-6789")
    # → "Contact [REDACTED_EMAIL] or [REDACTED_SSN]"
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger("Gateway.Governance.PIISanitizer")

# ---------------------------------------------------------------------------
# Compiled PII patterns — ordered from most-specific to least-specific to
# avoid partial matches (e.g. SSN before phone, CC before generic numbers).
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SSN: 9 digits in NNN-NN-NNNN or NNNNNNNNN format.
    # Excludes invalid ranges: 000, 666, 9xx area codes.
    (
        re.compile(
            r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
        ),
        "[REDACTED_SSN]",
    ),
    # Credit card: Visa, MC, Amex, Discover, JCB, Diners.
    # Allows optional spaces or dashes between 4-digit groups (e.g. 4111-1111-1111-1111).
    # Pattern: leading prefix digits followed by remaining digits with optional separators.
    (
        re.compile(
            r"\b(?:"
            # Visa: 4 + 12 or 15 more digits (13 or 16 total), groups separated by [-\s]?
            r"4\d{3}(?:[-\s]?\d{4}){2,3}"
            # Mastercard: 51-55 + 14 more digits
            r"|5[1-5]\d{2}(?:[-\s]?\d{4}){3}"
            # Amex: 34 or 37 + 13 more digits (15 total, groups 4-6-5)
            r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"
            # Diners: 300-305 or 36x or 38x + 11 more digits (14 total)
            r"|3(?:0[0-5]|[68]\d)\d{11}"
            # Discover: 6011 or 65xx + 12 more digits (16 total)
            r"|6(?:011|5\d{2})(?:[-\s]?\d{4}){3}"
            # JCB: 2131, 1800, or 35xxx + 11 more digits (15-16 total)
            r"|(?:2131|1800|35\d{3})\d{11}"
            r")\b"
        ),
        "[REDACTED_CC]",
    ),
    # Email address: RFC 5321 simplified.
    (
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "[REDACTED_EMAIL]",
    ),
    # Phone: US/international formats with optional country code (+1 or 1).
    # Uses (?<!\w) instead of \b so that '+' before the digit is included in the match.
    (
        re.compile(
            r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        "[REDACTED_PHONE]",
    ),
    # API keys and Bearer tokens: Langfuse (pk-lf-*, sk-lf-*), HuggingFace
    # (hf_*), and generic Bearer tokens.
    (
        re.compile(
            r"\b(?:pk-lf-|sk-lf-|hf_|Bearer\s+)[A-Za-z0-9_\-]{8,}\b"
        ),
        "[REDACTED_API_KEY]",
    ),
]


class PIISanitizer:
    """Pre-ledger regex sanitization pipeline for ISO 42001 Annex A.6.

    Applies all five PII patterns sequentially to the input string.
    Each pattern is applied via ``re.sub()`` — the output of one pattern
    is the input to the next.

    Thread-safe: all state is in compiled regex objects (immutable after init).
    """

    def sanitize(self, text: str) -> str:
        """Sanitize *text* by redacting all detected PII patterns.

        Args:
            text: The input string to sanitize.  May be any length.

        Returns:
            A new string with all detected PII replaced by redaction tokens.
            Returns the original string unchanged if no patterns match.
            Returns an empty string if *text* is empty.
        """
        if not text:
            return text

        result = text
        for pattern, replacement in _PII_PATTERNS:
            result = pattern.sub(replacement, result)

        if result != text:
            logger.debug(
                "PIISanitizer: redacted PII from %d-char string "
                "(original_len=%d, sanitized_len=%d)",
                len(text), len(text), len(result),
            )

        return result

    def sanitize_dict(self, data: dict) -> dict:
        """Recursively sanitize all string values in a dict.

        Useful for sanitizing an entire request body or UCA record before
        WORM persistence.  Non-string values are passed through unchanged.

        Args:
            data: A dict (possibly nested) to sanitize.

        Returns:
            A new dict with all string values sanitized.
        """
        result: dict = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.sanitize(value)
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.sanitize(item) if isinstance(item, str)
                    else (self.sanitize_dict(item) if isinstance(item, dict) else item)
                    for item in value
                ]
            else:
                result[key] = value
        return result


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_pii_sanitizer: Optional[PIISanitizer] = None


def _get_pii_sanitizer() -> PIISanitizer:
    """Return the module-level PIISanitizer singleton.

    Lazily initialised on first call.  Thread-safe because Python's GIL
    guarantees atomic reference assignment for simple object creation.
    """
    global _pii_sanitizer
    if _pii_sanitizer is None:
        _pii_sanitizer = PIISanitizer()
    return _pii_sanitizer
