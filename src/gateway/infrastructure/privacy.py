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
privacy.py — PII scrubbing utility for the governed financial advisor.

FINDING-10 (LOW): scrub_pii() previously performed universal PII scrubbing
with no GDPR Art. 17 (right to erasure) logging or MAS Notice 655-specific
audit trail for EU_ECB and APAC_MAS deployments.

Added an optional ``emit_jurisdiction_audit`` parameter.  When
CAGE_DEPLOYMENT_REGION is EU_ECB or APAC_MAS, a structured audit log entry
is emitted citing the applicable regulation (R-3, R-4).
"""

import logging
import os
import re

from src.gateway.governance.pii_sanitizer import (
    CANONICAL_UUID_RE,
    CREDIT_CARD_PATTERN,
    EMAIL_PATTERN,
    PHONE_PATTERN,
    SSN_PATTERN,
    redact_preserving_uuids,
)

logger = logging.getLogger("GoverningFinancialAdvisor.Utils.Privacy")

# Shared compiled patterns from src.gateway.governance.pii_sanitizer (single
# canonical regex and UUID-preservation implementation across Layer 1).
_COMPILED_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "SSN": SSN_PATTERN,
    "EMAIL": EMAIL_PATTERN,
    "CREDIT_CARD": CREDIT_CARD_PATTERN,
    "PHONE": PHONE_PATTERN,
}

PII_PATTERNS: dict[str, str] = {
    entity: pattern.pattern for entity, pattern in _COMPILED_PII_PATTERNS.items()
}

_CANONICAL_UUID_RE = CANONICAL_UUID_RE


# ---------------------------------------------------------------------------
# FINDING-10 (LOW) — Jurisdictional erasure audit citation map
#
# PII scrubbing is universal (ISO 42001 A.9.2).
# EU_ECB and APAC_MAS require additional structured audit log entries
# citing the applicable regulation for the erasure/scrubbing event.
# ---------------------------------------------------------------------------

_ERASURE_CITATION: dict[str, str] = {
    "EU_ECB": "GDPR Art. 17 (right to erasure / right to be forgotten)",
    "APAC_MAS": "MAS Notice 655 §4.3 (data protection and audit logging)",
}


def _scrub_span(span: str, seen_entities: set[str]) -> str:
    scrubbed = span
    for entity, pattern in _COMPILED_PII_PATTERNS.items():
        new_text = pattern.sub(f"[REDACTED-{entity}-UCA-3]", scrubbed)
        if new_text != scrubbed:
            seen_entities.add(entity)
        scrubbed = new_text
    return scrubbed


def scrub_pii(
    text: str,
    emit_jurisdiction_audit: bool = False,
) -> str:
    """Deterministic PII scrubbing utility backed by shared ``pii_sanitizer`` primitives.

    Transforms sensitive data into non-identifying tokens while preserving
    canonical RFC-4122 ``8-4-4-4-12`` hex UUIDs (such as ``defer_id``,
    ``transaction_id``, and ``trace_id``) via :func:`redact_preserving_uuids`.

    FINDING-10 (LOW): Added ``emit_jurisdiction_audit`` parameter.  When True
    and CAGE_DEPLOYMENT_REGION is EU_ECB or APAC_MAS, emits a structured audit
    log entry citing the applicable regulation (GDPR Art. 17 / MAS Notice 655).

    Args:
        text:                   The input string to scrub.
        emit_jurisdiction_audit: When True, emit a structured audit log entry
                                 for EU_ECB (GDPR Art. 17) and APAC_MAS
                                 (MAS Notice 655 §4.3) deployments.

    Returns:
        The scrubbed string with PII replaced by redaction tokens.
    """
    if not isinstance(text, str):
        return text

    seen_entities: set[str] = set()
    scrubbed = redact_preserving_uuids(
        text, lambda span: _scrub_span(span, seen_entities)
    )
    redacted_entities = [
        entity for entity in _COMPILED_PII_PATTERNS if entity in seen_entities
    ]

    # Jurisdictional audit trail (R-3, R-4)
    if emit_jurisdiction_audit and redacted_entities:
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()
        citation = _ERASURE_CITATION.get(region)
        if citation:
            logger.info(
                "PII erasure audit: region=%s entities=%s citation=%s "
                "(ISO 42001 A.9.2 + jurisdictional extension)",
                region,
                redacted_entities,
                citation,
            )

    return scrubbed
