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
Aho-Corasick automaton (pyahocorasick).  Falls back to an O(n×m)
``any()`` loop when the optional dependency is not installed.

Keyword list is sourced entirely from the validated threshold singleton
(``config/governance_thresholds.json``) — no inline literals.
"""

import logging
from typing import Any, Optional

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
        "⚠️ pyahocorasick not installed — Tier-1 keyword scan falling back to O(n×m) any() loop. "
        "Install with: pip install pyahocorasick"
    )

# Keyword list is sourced entirely from the validated threshold singleton.
# No inline literals — all values live in config/governance_thresholds.json.
_AC_AUTOMATON: Optional[Any] = None
_AC_BUILT: bool = False


def _load_tier1_keywords() -> list[str]:
    """Return the Tier-1 keyword list from the governance threshold singleton."""
    return list(THRESHOLDS.tier1_keywords)  # already upper-cased by Pydantic validator


def _build_automaton() -> Optional[Any]:
    """Build and return a pyahocorasick Automaton from the Tier-1 keyword list."""
    if not _AC_AVAILABLE:
        return None
    keywords = _load_tier1_keywords()
    A = _ahocorasick.Automaton()
    for idx, kw in enumerate(keywords):
        A.add_word(kw.upper(), (idx, kw))
    A.make_automaton()
    logger.info("✅ Aho-Corasick automaton built with %d Tier-1 keywords.", len(keywords))
    return A


def ac_keyword_scan(text: str) -> bool:
    """O(n) Tier-1 keyword scan using a lazy-initialised Aho-Corasick automaton.

    Falls back to O(n×m) ``any()`` loop when *pyahocorasick* is not installed.

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
