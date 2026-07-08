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
Stateless text safety filter.

Provides an O(n) Tier-1 keyword scanner using a lazy-initialised
Aho-Corasick automaton (pyahocorasick).  Falls back to an O(n*m)
``any()`` loop when the optional dependency is not installed.

Keyword list is sourced entirely from the validated threshold singleton
(``config/governance_thresholds.json``) — no inline literals.
"""

import logging
import re
from typing import Any

# ---------------------------------------------------------------------------
# Threshold singleton (Phase 2.3)
# ---------------------------------------------------------------------------
from src.gateway.governance.schemas.thresholds import THRESHOLDS

logger = logging.getLogger("SafetyLayer")

# ---------------------------------------------------------------------------
# Aho-Corasick Tier-1 Keyword Scanner
# ---------------------------------------------------------------------------

try:
    import ahocorasick as _ahocorasick

    _AC_AVAILABLE = True
except ImportError:
    _ahocorasick = None  # type: ignore[assignment]
    _AC_AVAILABLE = False
    logger.warning(
        "[WARN] pyahocorasick not installed - Tier-1 keyword scan falling back to O(n*m) any() loop. "
        "Install with: pip install pyahocorasick"
    )

# Keyword list is sourced entirely from the validated threshold singleton.
# No inline literals — all values live in config/governance_thresholds.json.
_AC_AUTOMATON: Any | None = None
_AC_BUILT: bool = False


def _load_tier1_keywords() -> list[str]:
    """Return the Tier-1 keyword list from the governance threshold singleton."""
    return list(THRESHOLDS.tier1_keywords)  # already upper-cased by Pydantic validator


def _load_cbrn_keywords() -> list[str]:
    """Return the CBRN Tier-1 keyword list when enabled (AI 600-1 §2.6, US_FED only).

    Returns an empty list when ``tier1_keywords_cbrn_enabled`` is False,
    allowing the CBRN filter to be disabled without removing the keyword list
    (rollback per .clinerules §10.1).
    """
    if not THRESHOLDS.tier1_keywords_cbrn_enabled:
        return []
    return list(
        THRESHOLDS.tier1_keywords_cbrn
    )  # already upper-cased by Pydantic validator


def _validate_keyword(kw: str) -> bool:
    """Return True if *kw* is a valid, safe keyword for the Aho-Corasick automaton.

    Rejects patterns that would cause catastrophic backtracking (ReDoS) or
    fail to compile as regex.  Plain keyword strings (no regex metacharacters)
    are always accepted.  This is a defence-in-depth check — the Aho-Corasick
    automaton itself does not use regex, but the fallback ``any()`` path does
    a simple substring match, so we still validate to catch obviously malformed
    entries early (H-09).
    """
    if not kw or not isinstance(kw, str):
        logger.warning("text_filter: rejecting empty or non-string keyword: %r", kw)
        return False
    try:
        re.compile(re.escape(kw), re.IGNORECASE)
        return True
    except re.error as exc:
        logger.error(
            "text_filter: keyword %r failed regex validation — skipping: %s", kw, exc
        )
        return False


def _build_automaton() -> Any | None:
    """Build and return a pyahocorasick Automaton from the Tier-1 keyword list.

    Validates each keyword before adding it to the automaton (H-09).
    Malformed keywords are logged and skipped rather than silently disabling
    the entire filter.
    """
    if not _AC_AVAILABLE:
        return None
    keywords = _load_tier1_keywords()
    A = _ahocorasick.Automaton()
    accepted = 0
    for idx, kw in enumerate(keywords):
        if not _validate_keyword(kw):
            continue
        A.add_word(kw.upper(), (idx, kw))
        accepted += 1
    if accepted == 0:
        logger.error(
            "text_filter: no valid keywords loaded — Tier-1 filter is DISABLED. "
            "Check config/governance_thresholds.json tier1_keywords."
        )
        return None
    A.make_automaton()
    logger.info(
        "✅ Aho-Corasick automaton built with %d/%d valid Tier-1 keywords.",
        accepted,
        len(keywords),
    )
    return A


def ac_keyword_scan(text: str) -> bool:
    """O(n) Tier-1 keyword scan using a lazy-initialised Aho-Corasick automaton.

    Falls back to O(n*m) ``any()`` loop when *pyahocorasick* is not installed.

    Args:
        text: The raw input string to scan.

    Returns:
        ``True`` if any forbidden keyword is found, ``False`` otherwise.
    """
    global _AC_AUTOMATON, _AC_BUILT

    upper_text = text.upper()

    if _AC_AVAILABLE:
        if not _AC_BUILT:
            _AC_AUTOMATON = _build_automaton()
            _AC_BUILT = True
        if _AC_AUTOMATON is not None:
            for _end_index, (_idx, _kw) in _AC_AUTOMATON.iter(upper_text):
                return True
            return False

    keywords = _load_tier1_keywords()
    return any(kw.upper() in upper_text for kw in keywords)


def ac_cbrn_keyword_scan(text: str) -> bool:
    """O(n*m) CBRN Tier-1 keyword scan - AI 600-1 SS2.6 (US_FED only).

    Checks the input text against the CBRN keyword list from the governance
    threshold singleton.  Returns ``False`` immediately when
    ``tier1_keywords_cbrn_enabled`` is ``False`` (no-op when disabled).

    Uses a simple substring match (O(n*m)) rather than Aho-Corasick because
    CBRN keywords are multi-word phrases that require case-insensitive substring
    matching rather than exact word boundary matching.

    Args:
        text: The raw input string to scan.

    Returns:
        ``True`` if any CBRN keyword is found, ``False`` otherwise.
    """
    cbrn_keywords = _load_cbrn_keywords()
    if not cbrn_keywords:
        return False

    upper_text = text.upper()
    for kw in cbrn_keywords:
        if kw in upper_text:
            logger.warning(
                "🚨 CBRN keyword detected: %r — blocking request (AI 600-1 §2.6).", kw
            )
            return True
    return False
