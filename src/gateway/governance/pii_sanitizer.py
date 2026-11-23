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

import base64
import binascii
import logging
import os
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from urllib.parse import unquote

from src.gateway.governance.env_posture import resolve_deployment_region

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
    return resolve_deployment_region()


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
# Label chain and separator runs are length-bounded to guarantee O(n) scanning
# on repeated label tokens without a trailing BIC (issue #405).
_BIC_LABELLED = re.compile(
    r"(?P<label>(?i:\b(?:swift|bic)(?:[ \t/_-]{0,3}(?:swift|bic|code|address|id|number|no\.?)){0,4})"
    r"(?:[ \t]{0,16}[:=#][ \t]{0,16}|[ \t]{1,16}))"
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


CANONICAL_UUID_RE: re.Pattern[str] = re.compile(
    r"(?<![0-9A-Za-z-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z-])"
)

# SSN: 9 digits in NNN-NN-NNNN or NNNNNNNNN format.
# Excludes invalid ranges: 000, 666, 9xx area codes.
SSN_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
)

# Credit card: Visa, MC (51-55 and 2221-2720), Amex, Discover, JCB, Diners.
# Allows optional spaces or dashes between 4-digit groups (e.g. 4111-1111-1111-1111).
CREDIT_CARD_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:"
    # Visa: 16 digits in four 4-digit groups separated by [-\s]?. A
    # 12-digit form is not a valid Visa length and matched UUID
    # segments (e.g. "4365-4282-8412" inside a uuid4), corrupting
    # identifiers in evidence records.
    r"4\d{3}(?:[-\s]?\d{4}){3}"
    # Mastercard: 51-55 or 2221-2720 + 12 more digits
    r"|(?:5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))(?:[-\s]?\d{4}){3}"
    # Amex: 34 or 37 + 13 more digits (15 total, groups 4-6-5)
    r"|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}"
    # Diners: 300-305, 36 or 38 prefix, 14 digits, with optional separators
    # split 4-6-4 ("3056 930902 5904") or 4-4-4-2 ("3056 9309 0259 04").
    r"|3(?:0[0-5]|[68]\d)\d(?:[-\s]?\d{6}[-\s]?\d{4}|(?:[-\s]?\d{4}){2}[-\s]?\d{2})"
    # Diners: 300-305, 36 or 38-39 prefix, 16 digits in four 4-digit groups.
    # 17-19 digit numbers in these ranges are not matched.
    r"|3(?:0[0-5]|[689]\d)\d(?:[-\s]?\d{4}){3}"
    # Discover: 6011, 644-649 or 65 prefix + 12 more digits (16 total)
    r"|6(?:011|4[4-9]\d|5\d{2})(?:[-\s]?\d{4}){3}"
    # JCB: 35xx, 16 digits in four 4-digit groups
    r"|35\d{2}(?:[-\s]?\d{4}){3}"
    # JCB: 2131 or 1800, 15 digits, optional separators split 4-6-5 as for Amex
    r"|(?:2131|1800)[-\s]?\d{6}[-\s]?\d{5}"
    r")\b"
)

# Email address: RFC 5321 simplified. Local part and domain are length-bounded
# (RFC 5321: local <=64, domain <=255) — the unbounded ``+`` form let a crafted
# no-TLD string ("a@a.a.a.…!") drive O(n^2) backtracking in re.sub.
EMAIL_PATTERN: re.Pattern[str] = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b"
)

# Phone: US/international formats with optional country code (+1 or 1).
# Uses (?<!\w) instead of \b so that '+' before the digit is included in the match.
PHONE_PATTERN: re.Pattern[str] = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)

# ---------------------------------------------------------------------------
# Hardened deterministic credential, payment-card, IBAN, and encoded-layer
# sanitization primitives (pure stdlib, linear O(n) bounded scanning).
# ---------------------------------------------------------------------------

_MAX_PEM_BODY_LEN: int = 16_384
_PEM_PRIVATE_KEY_HEADER_PATTERN: re.Pattern[str] = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----"
)
_PEM_PRIVATE_KEY_END_PATTERN: re.Pattern[str] = re.compile(
    r"-----END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----"
)


def _redact_pem_private_keys(text: str) -> str:
    """Scrub PEM/PGP private key blocks and truncated headers in linear O(n) time."""
    if "PRIVATE KEY" not in text:
        return text
    out_parts: list[str] = []
    cursor = 0
    text_len = len(text)
    while cursor < text_len:
        begin_match = _PEM_PRIVATE_KEY_HEADER_PATTERN.search(text, cursor)
        if begin_match is None:
            out_parts.append(text[cursor:])
            break
        out_parts.append(text[cursor : begin_match.start()])
        max_end = min(text_len, begin_match.end() + _MAX_PEM_BODY_LEN)
        next_begin = text.find("-----BEGIN ", begin_match.end(), max_end)
        search_limit = next_begin if next_begin != -1 else max_end
        end_match = _PEM_PRIVATE_KEY_END_PATTERN.search(
            text, begin_match.end(), search_limit
        )
        out_parts.append("[REDACTED_PRIVATE_KEY]")
        cursor = end_match.end() if end_match is not None else begin_match.end()
    return "".join(out_parts)


_URL_USERINFO_CREDENTIAL_PATTERN: re.Pattern[str] = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^:\s/\"'@]{1,128}):([^@\s/\"']{1,256})@([^\s\"']{1,255})"
)


def _redact_url_userinfo(match: re.Match[str]) -> str:
    if match.group(2) == "[REDACTED_PASSWORD]":
        return match.group(0)
    return f"{match.group(1)}:[REDACTED_PASSWORD]@{match.group(3)}"


def _luhn_valid(digits: str) -> bool:
    """Return True if *digits* is a 13-19 digit string satisfying ISO/IEC 7812 Luhn."""
    if not (13 <= len(digits) <= 19) or not digits.isascii() or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        val = ord(ch) - 48
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


# Additive Luhn-validated payment card matcher for obfuscated (dot-separated,
# irregular-grouped) and international 13-19 digit cards (IIN 2-6).
_LUHN_PAN_CANDIDATE_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9_])([2-6](?:[ \-.]?\d){12,18})(?![A-Za-z0-9_])"
)


def _redact_luhn_pan(match: re.Match[str]) -> str:
    raw = match.group(1)
    seps = {ch for ch in raw if ch in " -."}
    if len(seps) > 1:
        return raw
    if len(seps) == 1:
        sep = next(iter(seps))
        groups = raw.split(sep)
        # Preserve single-dot floating-point decimals (e.g. "3.141592653589793")
        # and single-digit dotted sequences.
        if sep == "." and len(groups) < 3:
            return raw
        if any(len(group) < 2 for group in groups):
            return raw
    digits = "".join(ch for ch in raw if ch.isdigit())
    if _luhn_valid(digits):
        return "[REDACTED_CC]"
    return raw


# Official ISO 13616 IBAN lengths by ISO 3166-1 alpha-2 country code.
_IBAN_LENGTHS: dict[str, int] = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BI": 27,
    "BR": 29,
    "BY": 28,
    "CH": 21,
    "CR": 22,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DJ": 27,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "EG": 29,
    "ES": 24,
    "FI": 18,
    "FK": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HN": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IQ": 23,
    "IS": 26,
    "IT": 27,
    "JO": 30,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "LY": 25,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MN": 20,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NI": 28,
    "NL": 18,
    "NO": 15,
    "OM": 23,
    "PK": 24,
    "PL": 28,
    "PS": 29,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "RS": 22,
    "RU": 33,
    "SA": 24,
    "SC": 31,
    "SD": 18,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "SO": 23,
    "ST": 25,
    "SV": 28,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "VA": 22,
    "VG": 24,
    "XK": 20,
    "YE": 30,
}

_SPACED_IBAN_CANDIDATE_PATTERN: re.Pattern[str] = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ \-][A-Z0-9]{1,4}){3,8}\b"
)


def _iban_mod97_valid(compact: str) -> bool:
    """Validate a contiguous uppercase IBAN via ISO 13616 length and Mod-97."""
    if not (15 <= len(compact) <= 34):
        return False
    expected_len = _IBAN_LENGTHS.get(compact[:2])
    if expected_len is None or len(compact) != expected_len:
        return False
    if not compact[2:4].isdigit() or not compact[4:].isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for ch in rearranged:
        if "0" <= ch <= "9":
            remainder = (remainder * 10 + (ord(ch) - 48)) % 97
        elif "A" <= ch <= "Z":
            remainder = (remainder * 100 + (ord(ch) - 55)) % 97
        else:
            return False
    return remainder == 1


def _redact_spaced_iban(match: re.Match[str]) -> str:
    raw = match.group(0)
    expected_len = _IBAN_LENGTHS.get(raw[:2])
    if expected_len is None:
        return raw
    compact_chunks: list[str] = []
    compact_len = 0
    consumed_end = 0
    idx = 0
    raw_len = len(raw)
    while idx < raw_len:
        group_start = idx
        while idx < raw_len and raw[idx] not in " -":
            idx += 1
        chunk = raw[group_start:idx]
        compact_chunks.append(chunk)
        compact_len += len(chunk)
        if compact_len == expected_len:
            consumed_end = idx
            break
        if compact_len > expected_len:
            return raw
        if idx < raw_len:
            idx += 1
    if consumed_end == 0:
        return raw
    if not _iban_mod97_valid("".join(compact_chunks)):
        return raw
    return "[REDACTED_IBAN]" + raw[consumed_end:]


_CREDENTIAL_PATTERNS: list[
    tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]
] = [
    # Compact JWS/JWT tokens (KG-05 / R5: ConsequenceToken & routing_seal leakage
    # mitigation). MUST run BEFORE generic Bearer redaction so ``Bearer eyJ...``
    # scrubs the entire 3-segment JWS instead of leaving ``.<payload>.<sig>``.
    (
        re.compile(
            r"(?:(?i:\bBearer)\s+)?\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_\-])"
        ),
        "[REDACTED_JWS]",
    ),
    # Redis / Valkey connection URLs carrying embedded credentials.
    (
        re.compile(r"\brediss?://[^:\s/\"']*:[^@\s\"']+@[^\s\"']+"),
        "[REDACTED_REDIS_URL]",
    ),
    # Generic URL userinfo credentials (runs after Redis URL scrubbing so
    # ``rediss?://`` retains ``[REDACTED_REDIS_URL]``).
    (_URL_USERINFO_CREDENTIAL_PATTERN, _redact_url_userinfo),
    # API keys and Bearer tokens: telemetry keys (pk-lf-*, sk-lf-*), model-hub
    # tokens (hf_*), cloud/VCS/messaging provider keys (GOOG*, AIza*,
    # AKIA*/ASIA*/ABIA*/ACCA*, gh[pousr]_*, github_pat_*, sk-*, xox[abprs]-*),
    # and generic Bearer tokens (run before UUID preservation so opaque
    # ``Bearer <uuid>`` tokens are scrubbed).
    (
        re.compile(
            r"\b(?:"
            r"pk-lf-[A-Za-z0-9_\-]{8,}"
            r"|sk-lf-[A-Za-z0-9_\-]{8,}"
            r"|hf_[A-Za-z0-9_\-]{8,}"
            r"|GOOG[A-Za-z0-9_\-]{12,}"
            r"|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{20,255}"
            r"|github_pat_[A-Za-z0-9_]{20,255}"
            r"|sk-(?:proj-|live-|ant-)?[A-Za-z0-9_\-]{20,255}"
            r"|xox[abprs]-[A-Za-z0-9\-]{10,255}"
            r"|AIza[0-9A-Za-z_\-]{35}"
            r"|(?i:Bearer)\s+[A-Za-z0-9_\-\.=]{8,}"
            r")(?![A-Za-z0-9_\-])"
        ),
        "[REDACTED_API_KEY]",
    ),
]

_SPAN_PII_PATTERNS: list[
    tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]
] = [
    # ISO 13616 Mod-97 validated space/hyphen-grouped IBANs MUST run before
    # credit-card patterns so multi-group IBANs (e.g. FR76 3000 6000 ...) are
    # never partially mangled as payment cards.
    (_SPACED_IBAN_CANDIDATE_PATTERN, _redact_spaced_iban),
    (SSN_PATTERN, "[REDACTED_SSN]"),
    (CREDIT_CARD_PATTERN, "[REDACTED_CC]"),
    (_LUHN_PAN_CANDIDATE_PATTERN, _redact_luhn_pan),
    # M-14: IBAN — International Bank Account Number (up to 34 alphanumeric chars).
    # Format: 2-letter country code + 2 check digits + up to 30 BBAN chars.
    (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "[REDACTED_IBAN]",
    ),
    # M-14: SWIFT/BIC code (ISO 9362), only when labelled — see _BIC_LABELLED.
    (_BIC_LABELLED, _redact_labelled_bic),
    (EMAIL_PATTERN, "[REDACTED_EMAIL]"),
    (PHONE_PATTERN, "[REDACTED_PHONE]"),
]

_PII_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    *_SPAN_PII_PATTERNS,
    *_CREDENTIAL_PATTERNS,
]

_MAX_UNWRAP_DEPTH: int = 3
_MAX_ENCODED_TOKEN_LEN: int = 4096
_MIN_B64_TOKEN_LEN: int = 12
_MIN_HEX_TOKEN_LEN: int = 18

_ENCODED_SPAN_PATTERN: re.Pattern[str] = re.compile(r"[^\s\"'<>()\[\]{},;]{6,}")
_QUERY_SPLIT_PATTERN: re.Pattern[str] = re.compile(r"([?&])")
_URL_PCT_ESCAPE_RE: re.Pattern[str] = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_TOKEN_RE: re.Pattern[str] = re.compile(r"^[0-9A-Fa-f]+$")
_B64_TOKEN_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def _is_printable_text(text: str) -> bool:
    if not text:
        return False
    return all(ch in "\t\n\r" or (ord(ch) >= 32 and ch.isprintable()) for ch in text)


def _try_decode_one_layer(token: str) -> str | None:
    if "%" in token and _URL_PCT_ESCAPE_RE.search(token):
        decoded = unquote(token)
        if decoded != token and _is_printable_text(decoded):
            return decoded

    if (
        len(token) >= _MIN_HEX_TOKEN_LEN
        and len(token) % 2 == 0
        and _HEX_TOKEN_RE.fullmatch(token)
    ):
        try:
            hex_decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            hex_decoded = ""
        if hex_decoded and _is_printable_text(hex_decoded):
            return hex_decoded

    if len(token) >= _MIN_B64_TOKEN_LEN and _B64_TOKEN_RE.fullmatch(token):
        stripped = token.rstrip("=")
        mod = len(stripped) % 4
        if mod == 1:
            return None
        has_std = "+" in stripped or "/" in stripped
        has_url = "-" in stripped or "_" in stripped
        if has_std and has_url:
            return None
        padded = stripped + ("=" * ((4 - mod) % 4))
        try:
            raw_bytes = (
                base64.urlsafe_b64decode(padded.encode("ascii"))
                if has_url
                else base64.b64decode(padded.encode("ascii"), validate=True)
            )
            b64_decoded = raw_bytes.decode("utf-8")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
        if b64_decoded != token and _is_printable_text(b64_decoded):
            return b64_decoded

    return None


def _apply_credential_patterns(text: str) -> str:
    result = _redact_pem_private_keys(text)
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _apply_plaintext_span_pii_patterns(span: str) -> str:
    result = span
    for pattern, replacement in _SPAN_PII_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _classify_decoded_layer(decoded: str) -> str | None:
    if _apply_credential_patterns(decoded) != decoded:
        return "CREDENTIAL"
    if redact_preserving_uuids(decoded, _apply_plaintext_span_pii_patterns) != decoded:
        return "PII"
    return None


def _classify_encoded_token(token: str, cache: dict[str, str | None]) -> str | None:
    if token in cache:
        return cache[token]
    if (
        len(token) < 6
        or len(token) > _MAX_ENCODED_TOKEN_LEN
        or token.startswith("REDACTED_")
    ):
        cache[token] = None
        return None

    current = token
    for _ in range(_MAX_UNWRAP_DEPTH):
        decoded = _try_decode_one_layer(current)
        if decoded is None:
            break
        kind = _classify_decoded_layer(decoded)
        if kind is not None:
            cache[token] = kind
            return kind
        current = decoded

    cache[token] = None
    return None


def _redact_encoded_atom(atom: str, cache: dict[str, str | None]) -> str:
    core = atom.rstrip(".,!?")
    trailing = atom[len(core) :]
    if len(core) < 6 or len(core) > _MAX_ENCODED_TOKEN_LEN:
        return atom

    eq_idx = core.find("=")
    if eq_idx > 0:
        rhs = core[eq_idx + 1 :]
        if rhs and set(rhs) != {"="}:
            rhs_kind = _classify_encoded_token(rhs, cache)
            if rhs_kind is not None:
                return f"{core[: eq_idx + 1]}[REDACTED_ENCODED_{rhs_kind}]{trailing}"

    if "://" not in core:
        colon_idx = core.find(":")
        if colon_idx > 0:
            rhs = core[colon_idx + 1 :]
            if rhs:
                rhs_kind = _classify_encoded_token(rhs, cache)
                if rhs_kind is not None:
                    return f"{core[: colon_idx + 1]}[REDACTED_ENCODED_{rhs_kind}]{trailing}"

    kind = _classify_encoded_token(core, cache)
    if kind is not None:
        return f"[REDACTED_ENCODED_{kind}]{trailing}"

    return atom


def _redact_encoded_tokens(span: str) -> str:
    """Detect and redact bounded Base64/Hex/URL-encoded PII or credentials."""
    cache: dict[str, str | None] = {}

    def _replace_span(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) > _MAX_ENCODED_TOKEN_LEN:
            return token
        if "?" in token or "&" in token:
            parts = _QUERY_SPLIT_PATTERN.split(token)
            return "".join(
                part if part in ("?", "&") else _redact_encoded_atom(part, cache)
                for part in parts
            )
        return _redact_encoded_atom(token, cache)

    return _ENCODED_SPAN_PATTERN.sub(_replace_span, span)


def redact_preserving_uuids(text: str, transform_span: Callable[[str], str]) -> str:
    """Apply ``transform_span`` to non-UUID text spans while preserving canonical UUIDs.

    Shared by :class:`PIISanitizer` and :func:`src.gateway.infrastructure.privacy.scrub_pii`
    so correlation identifiers (``defer_id``, ``trace_id``, ``transaction_id``,
    OSCAL UUIDs) whose ``8-4-4`` or ``4-12`` hex groups contain only decimal digits
    are never mangled by credit-card or numeric PII patterns.
    """
    out_parts: list[str] = []
    cursor = 0
    for match in CANONICAL_UUID_RE.finditer(text):
        if match.start() > cursor:
            out_parts.append(transform_span(text[cursor : match.start()]))
        out_parts.append(match.group(0))
        cursor = match.end()
    if cursor < len(text):
        out_parts.append(transform_span(text[cursor:]))
    return "".join(out_parts)


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


def _apply_span_pii_patterns(span: str) -> str:
    result = _apply_plaintext_span_pii_patterns(span)
    return _redact_encoded_tokens(result)


class PIISanitizer:
    """Pre-ledger regex sanitization pipeline for ISO 42001 Annex A.6.

    Applies credential patterns followed by UUID-preserving PII span redaction.
    Thread-safe: all state is in compiled regex objects (immutable after init).
    """

    def sanitize(self, text: str) -> str:
        """Sanitize *text* by redacting all detected PII patterns while preserving canonical UUIDs."""
        if not text:
            return text

        result = _apply_credential_patterns(text)
        result = redact_preserving_uuids(result, _apply_span_pii_patterns)

        if result != text:
            logger.debug(
                "PIISanitizer: redacted PII from %d-char string "
                "(original_len=%d, sanitized_len=%d)",
                len(text),
                len(text),
                len(result),
            )

        return result

    def sanitize_dict(self, data: Mapping) -> dict:
        """Recursively sanitize all string values in a mapping.

        Useful for sanitizing an entire request body or UCA record before
        WORM persistence.  Non-string values are passed through unchanged.

        **R5 mitigation (key-based redaction):** If a key (case-insensitive)
        matches any entry in ``_KEY_DENYLIST``, its value is unconditionally
        redacted to ``[REDACTED_TOKEN]``, regardless of content. This ensures
        ConsequenceToken JWS strings are scrubbed even if the JWS regex
        pattern fails to match (e.g. due to format variations).

        Args:
            data: A mapping (possibly nested) to sanitize.

        Returns:
            A new dict with all string values sanitized.
        """
        result: dict = {}
        for key, value in data.items():
            # R5: Key-based redaction for known-sensitive keys
            if str(key).lower() in _KEY_DENYLIST:
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
                if _is_bic_key(str(key)):
                    # The key is the contextual cue for an unlabelled BIC value.
                    result[key] = _BIC_STANDALONE.sub(
                        _redact_standalone_bic, result[key]
                    )
            elif isinstance(value, Mapping):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, tuple):
                result[key] = tuple(
                    self._sanitize_list(list(value), bic_key=_is_bic_key(str(key)))
                )
            elif isinstance(value, list):
                result[key] = self._sanitize_list(value, bic_key=_is_bic_key(str(key)))
            else:
                result[key] = value
        return result

    def _sanitize_list(self, items: list | tuple, bic_key: bool = False) -> list:
        """Sanitize list/tuple items, recursing into nested lists, tuples, and mappings.

        Nested lists and tuples (e.g. table-shaped agent state) are recursively
        sanitized.
        """
        out: list = []
        for item in items:
            if isinstance(item, str):
                redacted = self.sanitize(item)
                if bic_key:
                    redacted = _BIC_STANDALONE.sub(_redact_standalone_bic, redacted)
                out.append(redacted)
            elif isinstance(item, Mapping):
                out.append(self.sanitize_dict(item))
            elif isinstance(item, tuple):
                out.append(tuple(self._sanitize_list(list(item), bic_key=bic_key)))
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
    MAS Notice 655 §4.3. When ``region`` is omitted, ``resolve_deployment_region()``
    resolves it (refusing unknown values and unset enforcing postures); an
    unrecognised explicit ``region`` argument falls back to ISO 42001 A.9.2.

    Args:
        trace_id:     Langfuse trace ID for the governed request.
        entity_types: List of detected PII entity types
                      (e.g. ["PERSON", "EMAIL_ADDRESS"]).
        redacted:     True if PII was redacted from the request.
        region:       One of "US_FED", "EU_ECB", "APAC_MAS". If None,
                      ``resolve_deployment_region()``.

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

import threading

_pii_sanitizer: PIISanitizer | None = None
_pii_sanitizer_lock = threading.Lock()


def _get_pii_sanitizer() -> PIISanitizer:
    """Return the module-level PIISanitizer singleton (thread-safe lazy init)."""
    global _pii_sanitizer
    if _pii_sanitizer is None:
        with _pii_sanitizer_lock:
            if _pii_sanitizer is None:
                _pii_sanitizer = PIISanitizer()
    return _pii_sanitizer
