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

logger = logging.getLogger("GoverningFinancialAdvisor.Utils.Privacy")

# Deterministic patterns for Zero-Trust Redaction (Defense-in-Depth)
PII_PATTERNS = {
    "SSN": r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
    # Local part and domain are length-bounded (RFC 5321: local ≤64, domain
    # ≤255). The unbounded ``+`` form let a crafted no-TLD string like
    # "a@a.a.a.…!" force O(n²) backtracking in re.sub, stalling the event loop
    # (scrub_pii runs inline on unauthenticated /v1/chat/completions input).
    "EMAIL": r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Z|a-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PHONE": r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b",
}

_CANONICAL_UUID_RE = re.compile(
    r"(?<![0-9A-Za-z-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z-])"
)


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
    for entity, pattern in PII_PATTERNS.items():
        new_text = re.sub(pattern, f"[REDACTED-{entity}-UCA-3]", scrubbed)
        if new_text != scrubbed:
            seen_entities.add(entity)
        scrubbed = new_text
    return scrubbed


def scrub_pii(
    text: str,
    emit_jurisdiction_audit: bool = False,
) -> str:
    """Deterministic PII scrubbing utility.

    Transforms sensitive data into non-identifying tokens while preserving
    canonical RFC-4122 ``8-4-4-4-12`` hex UUIDs (such as ``defer_id``,
    ``transaction_id``, and ``trace_id``) whose 16-char ``8-4-4`` or ``4-12``
    groups happen to consist solely of decimal digits.

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
    out_parts: list[str] = []
    cursor = 0
    for match in _CANONICAL_UUID_RE.finditer(text):
        if match.start() > cursor:
            out_parts.append(_scrub_span(text[cursor : match.start()], seen_entities))
        out_parts.append(match.group(0))
        cursor = match.end()
    if cursor < len(text):
        out_parts.append(_scrub_span(text[cursor:], seen_entities))

    scrubbed = "".join(out_parts)
    redacted_entities = [entity for entity in PII_PATTERNS if entity in seen_entities]

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
