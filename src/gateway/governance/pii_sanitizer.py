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
import os
import re
from collections.abc import Callable
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# FINDING-08 (MEDIUM) — Jurisdictional retention authority citation map
#
# pii_audit_log() previously cited "FISMA AU-11" as the universal retention
# authority with no CAGE_DEPLOYMENT_REGION guard.  Added a ``region`` parameter
# so the correct citation is emitted based on the active deployment region.
# The underlying retention values are also sourced from the THRESHOLDS
# singleton (pii_audit_retention_days / pii_audit_retention_authority), which
# is itself region-aware — see src/gateway/governance/schemas/thresholds.py.
#
# The citation strings themselves live in constants.py (PII_RETENTION_AUTHORITY),
# which is intentionally excluded from the "no hardcoded regulatory strings"
# architecture guardrail (see test_governance_architecture.py) — this module
# imports the map rather than embedding citation literals directly.
# ---------------------------------------------------------------------------

logger = logging.getLogger("Gateway.Governance.PIISanitizer")


def _get_region() -> str:
    return os.environ.get("CAGE_DEPLOYMENT_REGION", "").strip().upper()


# ---------------------------------------------------------------------------
# AI600-002 — Presidio score threshold (configurable per jurisdiction).
#
# Presidio's entity recognizer returns a confidence score in [0.0, 1.0].
# Entities with score < PRESIDIO_SCORE_THRESHOLD are treated as non-PII.
# Default: 0.5 (balanced precision/recall for US_FED financial data).
# EU_ECB / APAC_MAS deployments may use a higher threshold (e.g. 0.65) to
# reduce false positives in multilingual contexts.
#
# Set PRESIDIO_SCORE_THRESHOLD env var to override at runtime.
# POAM: AI600-002 — Langfuse PII scrubbing policy: see docs/PII_SCRUBBING_POLICY.md
# ---------------------------------------------------------------------------

PRESIDIO_SCORE_THRESHOLD: float = float(
    os.environ.get("PRESIDIO_SCORE_THRESHOLD", "0.5")
)

# TELEMETRY_PII_SCRUBBING_ENABLED: When set to "true", the pii_audit_log()
# function applies the PIISanitizer to Langfuse span input/output fields
# before emitting them.  This prevents PII from appearing in compliance
# audit traces, satisfying AI 600-1 §2.2 and GDPR Art. 25 data minimisation.
# See docs/PII_SCRUBBING_POLICY.md for the full scrubbing field policy.
_TELEMETRY_PII_SCRUBBING_ENABLED: bool = (
    os.environ.get("TELEMETRY_PII_SCRUBBING_ENABLED", "true").lower() == "true"
)


# ---------------------------------------------------------------------------
# Compiled PII patterns — ordered from most-specific to least-specific to
# avoid partial matches (e.g. SSN before phone, CC before generic numbers).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# M-14: SWIFT/BIC (ISO 9362) detection
# ---------------------------------------------------------------------------
# A BIC is 4 bank letters + an ISO 3166-1 alpha-2 country code + 2 alphanumeric
# location characters + an optional 3-character alphanumeric branch. The
# previous shape-only pattern (any 8 or 11 upper-case characters) redacted
# ordinary upper-case vocabulary, e.g. APPROVED, REJECTED, ESCALATE, and
# governance verdicts recorded in the evidence stream. Requiring a valid
# country code at positions 5-6 is not enough on its own: ESCALATE ("AT"),
# DEPOSITS ("SI"), CONFIRMS ("IR") and many other words still pass. So a BIC is
# redacted only with a contextual cue:
#   * in free text, a preceding "BIC" / "SWIFT" label ("BIC: DEUTDEFF",
#     "SWIFT code DEUTDEFF500", "SWIFT/BIC BNPAFRPPXXX"); or
#   * in a dict, a value under a BIC/SWIFT key (``bic``, ``swift_code``,
#     ``beneficiaryBic``; see :func:`_is_bic_key`).
# In both cases the country code must also be valid.
# Trade-off: an unlabelled BIC in prose ("route via DEUTDEFF") is no longer
# redacted. A BIC identifies a bank, not a natural person, so a missed
# unlabelled BIC leaks much less than corrupted verdicts, which damage audit
# integrity and make distinct states hash the same.
# ---------------------------------------------------------------------------

# ISO 3166-1 alpha-2 officially assigned codes, plus XK (Kosovo, used by SWIFT).
_ISO_3166_ALPHA2: frozenset[str] = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ
    BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR
    CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
    MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF
    PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI
    SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR
    TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
    """.split()
)

_BIC_REDACTION = "[REDACTED_SWIFT]"
_BIC_SHAPE = r"[A-Z]{4}(?P<cc>[A-Z]{2})[A-Z0-9]{2}(?:[A-Z0-9]{3})?"
_BIC_END = r"(?![A-Za-z0-9_])"

# "BIC", "SWIFT", "SWIFT/BIC", "SWIFT code", "BIC no.", ... (case-insensitive),
# then ":", "=", "#" or whitespace, then an upper-case BIC.
_BIC_LABELLED = re.compile(
    r"(?P<label>(?i:\b(?:swift|bic)(?:[ \t/_-]*(?:swift|bic|code|address|id|number|no\.?))*)"
    r"(?:[ \t]*[:=#][ \t]*|[ \t]+))"
    rf"(?P<bic>{_BIC_SHAPE}){_BIC_END}"
)
_BIC_STANDALONE = re.compile(rf"(?<![A-Za-z0-9_])(?P<bic>{_BIC_SHAPE}){_BIC_END}")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_BIC_KEY = re.compile(r"(?:^|[^a-z])(?:bic|swift)(?:$|[^a-z]|code)")


def _redact_labelled_bic(match: re.Match[str]) -> str:
    if match.group("cc") not in _ISO_3166_ALPHA2:
        return match.group(0)
    return match.group("label") + _BIC_REDACTION


def _redact_standalone_bic(match: re.Match[str]) -> str:
    if match.group("cc") not in _ISO_3166_ALPHA2:
        return match.group(0)
    return _BIC_REDACTION


def _is_bic_key(key: str) -> bool:
    """True for dict keys that label a BIC (``bic``, ``swift_code``, ``payeeBIC``)."""
    snake = _CAMEL_BOUNDARY.sub("_", key).lower()
    return bool(_BIC_KEY.search(snake))


_PII_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    # SSN: 9 digits in NNN-NN-NNNN or NNNNNNNNN format.
    # Excludes invalid ranges: 000, 666, 9xx area codes.
    (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        "[REDACTED_SSN]",
    ),
    # Credit card: Visa, MC, Amex, Discover, JCB, Diners.
    # Allows optional spaces or dashes between 4-digit groups (e.g. 4111-1111-1111-1111).
    # Pattern: leading prefix digits followed by remaining digits with optional separators.
    (
        re.compile(
            r"\b(?:"
            # Visa: 16 digits in four 4-digit groups separated by [-\s]?. A
            # 12-digit form is not a valid Visa length and matched UUID
            # segments (e.g. "4365-4282-8412" inside a uuid4), corrupting
            # identifiers in evidence records.
            r"4\d{3}(?:[-\s]?\d{4}){3}"
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
    # M-14: IBAN — International Bank Account Number (up to 34 alphanumeric chars).
    # Format: 2-letter country code + 2 check digits + up to 30 BBAN chars.
    (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "[REDACTED_IBAN]",
    ),
    # M-14: SWIFT/BIC code (ISO 9362), only when labelled — see _BIC_LABELLED.
    (_BIC_LABELLED, _redact_labelled_bic),
    # Email address: RFC 5321 simplified.  Local part and domain are
    # length-bounded (RFC 5321: local ≤64, domain ≤255) — the unbounded ``+``
    # form let a crafted no-TLD string ("a@a.a.a.…!") drive O(n²) backtracking
    # in re.sub, which stalls the sanitizer on attacker-supplied text.
    (
        re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    # Phone: US/international formats with optional country code (+1 or 1).
    # Uses (?<!\w) instead of \b so that '+' before the digit is included in the match.
    (
        re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "[REDACTED_PHONE]",
    ),
    # API keys and Bearer tokens: Langfuse (pk-lf-*, sk-lf-*), HuggingFace
    # (hf_*), and generic Bearer tokens.
    (
        re.compile(r"\b(?:pk-lf-|sk-lf-|hf_|Bearer\s+)[A-Za-z0-9_\-]{8,}\b"),
        "[REDACTED_API_KEY]",
    ),
    # Compact JWS/JWT tokens (R5: ConsequenceToken leakage mitigation).
    # Pattern: three base64url segments separated by dots, with the first segment
    # starting with eyJ (base64url-encoded '{"' JSON header prefix).
    # Minimum segment lengths prevent false positives on dotted identifiers:
    #   - Header: ≥20 chars (typical JWT header is ~36 chars encoded)
    #   - Payload: ≥20 chars
    #   - Signature: ≥20 chars (typical RS256 signature is ~342 chars)
    # The eyJ anchor ensures we don't redact semantic version strings (1.2.3),
    # module paths (src.gateway.governance), or UUIDs (which contain hyphens, not dots).
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{17,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"
        ),
        "[REDACTED_JWS]",
    ),
]


# ---------------------------------------------------------------------------
# R5: Key-based redaction denylist for CONSEQUENCE_TOKEN findings
# ---------------------------------------------------------------------------
# Field names whose values should be unconditionally redacted, regardless of
# content. This complements the regex patterns above: a JWS that survives
# format changes (e.g. whitespace-padded base64) is still caught when emitted
# under a known-sensitive key.
#
# ConsequenceToken findings attach the raw JWS under the "token" key. Other
# governance contexts may use "consequence_token", "jws", or similar keys.
# Add keys in lowercase (the sanitizer normalizes before comparison).
# ---------------------------------------------------------------------------

_KEY_DENYLIST: set[str] = {
    "token",
    "consequence_token",
    "jws",
    "jwt",
    "bearer_token",
}


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
                len(text),
                len(text),
                len(result),
            )

        return result

    def sanitize_dict(self, data: dict) -> dict:
        """Recursively sanitize all string values in a dict.

        Useful for sanitizing an entire request body or UCA record before
        WORM persistence.  Non-string values are passed through unchanged.

        **R5 mitigation (key-based redaction):** If a key (case-insensitive)
        matches any entry in ``_KEY_DENYLIST``, its value is unconditionally
        redacted to ``[REDACTED_TOKEN]``, regardless of content. This ensures
        ConsequenceToken JWS strings are scrubbed even if the JWS regex
        pattern fails to match (e.g. due to format variations).

        Args:
            data: A dict (possibly nested) to sanitize.

        Returns:
            A new dict with all string values sanitized.
        """
        result: dict = {}
        for key, value in data.items():
            # R5: Key-based redaction for known-sensitive keys
            if key.lower() in _KEY_DENYLIST:
                if isinstance(value, str):
                    result[key] = "[REDACTED_TOKEN]"
                    logger.debug(
                        "PIISanitizer: redacted value for key-denylisted field '%s'",
                        key,
                    )
                else:
                    # Non-string value under a denylisted key: redact type but preserve shape
                    result[key] = f"[REDACTED_TOKEN:{type(value).__name__}]"
                    logger.debug(
                        "PIISanitizer: redacted non-string value for key-denylisted field '%s' (type=%s)",
                        key,
                        type(value).__name__,
                    )
            elif isinstance(value, str):
                result[key] = self.sanitize(value)
                if _is_bic_key(key):
                    # The key is the contextual cue for an unlabelled BIC value.
                    result[key] = _BIC_STANDALONE.sub(
                        _redact_standalone_bic, result[key]
                    )
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self._sanitize_list(value, bic_key=_is_bic_key(key))
            else:
                result[key] = value
        return result

    def _sanitize_list(self, items: list, bic_key: bool = False) -> list:
        """Sanitize list items, recursing into nested lists and dicts.

        Nested lists (e.g. table-shaped agent state) were previously passed
        through unsanitized.
        """
        out: list = []
        for item in items:
            if isinstance(item, str):
                redacted = self.sanitize(item)
                if bic_key:
                    redacted = _BIC_STANDALONE.sub(_redact_standalone_bic, redacted)
                out.append(redacted)
            elif isinstance(item, dict):
                out.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                out.append(self._sanitize_list(item, bic_key=bic_key))
            else:
                out.append(item)
        return out


# ---------------------------------------------------------------------------
# pii_audit_log — AI 600-1 §2.2 structured audit record
# ---------------------------------------------------------------------------


def pii_audit_log(
    trace_id: str,
    entity_types: list[str],
    redacted: bool,
    region: str | None = None,
) -> dict:
    """Return a structured audit record for PII detection events.

    Produces a JSON-serialisable dict suitable for writing to the WORM ledger
    (GCS WORM bucket, CMEK-encrypted) or emitting to a structured log sink.

    FINDING-08 (MEDIUM): the retention authority citation is jurisdiction-aware
    — US_FED cites FISMA AU-11, EU_ECB cites GDPR Art. 5(1)(e), APAC_MAS cites
    MAS Notice 655 §4.3. Deployments outside these three regions (or with the
    region unset) fall back to the universal ISO 42001 A.9.2 citation.

    Args:
        trace_id:     Langfuse trace ID for the governed request.
        entity_types: List of detected PII entity types
                      (e.g. ["PERSON", "EMAIL_ADDRESS"]).
        redacted:     True if PII was redacted from the request.
        region:       CAGE_DEPLOYMENT_REGION value. If None, reads from the
                      environment. One of "US_FED", "EU_ECB", "APAC_MAS".

    Returns:
        A dict with the following schema:
        {
            "event": "pii_detected",
            "trace_id": str,
            "entity_types": list[str],
            "redacted": bool,
            "timestamp": str,  # ISO 8601 UTC, e.g. "2026-06-15T12:00:00.000000Z"
            "retention_authority": str,  # jurisdiction-specific citation
        }

    Raises:
        ValueError: If ``redacted=True`` but ``entity_types`` is empty
                    (a redaction without detected entities is a logic error).
    """
    if redacted and not entity_types:
        raise ValueError(
            "pii_audit_log: entity_types must not be empty when redacted=True. "
            "A redaction event must identify at least one PII entity type."
        )

    from src.gateway.governance.constants import (
        PII_RETENTION_AUTHORITY,
        PII_RETENTION_AUTHORITY_DEFAULT,
    )

    active_region = region if region is not None else _get_region()
    retention_authority = PII_RETENTION_AUTHORITY.get(
        active_region, PII_RETENTION_AUTHORITY_DEFAULT
    )

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    record = {
        "event": "pii_detected",
        "trace_id": trace_id,
        "entity_types": entity_types,
        "redacted": redacted,
        "timestamp": timestamp,
        "retention_authority": retention_authority,
    }

    logger.debug(
        "PII audit record: trace_id=%s entity_types=%s redacted=%s retention_authority=%s",
        trace_id,
        entity_types,
        redacted,
        retention_authority,
    )

    return record


# ---------------------------------------------------------------------------
# Module-level singleton (lazy init)
# ---------------------------------------------------------------------------

_pii_sanitizer: PIISanitizer | None = None


def _get_pii_sanitizer() -> PIISanitizer:
    """Return the module-level PIISanitizer singleton.

    Lazily initialised on first call.  Thread-safe because Python's GIL
    guarantees atomic reference assignment for simple object creation.
    """
    global _pii_sanitizer
    if _pii_sanitizer is None:
        _pii_sanitizer = PIISanitizer()
    return _pii_sanitizer
