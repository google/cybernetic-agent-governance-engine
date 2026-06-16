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

"""Prompt injection detector — ISO 42001 A.9.2 universal control.

Detects structural prompt injection patterns that bypass keyword-based filters.
Complements the Aho-Corasick Tier-1 keyword scanner (text_filter.py) with
semantic/structural pattern matching for injection attempts.

POAM: AI600-003
Controls: CausalGatekeeper (pre-check), CTRL_WAL_002 (WAL integrity)

FINDING-09 (MEDIUM): This module previously declared "Region: US_FED" in its
docstring but contained no runtime CAGE_DEPLOYMENT_REGION check.  Prompt
injection detection is a universal security control (ISO 42001 A.9.2) that
applies in all regions.  The AI 600-1 §2.3 citation is US_FED-specific;
EU_ECB and APAC_MAS cite equivalent controls from their applicable frameworks.

Correct behaviour (R-2, R-5):
  - Prompt injection detection itself is universal (ISO 42001 A.9.2).
  - AI 600-1 §2.3 citation is US_FED only.
  - EU_ECB cites EU AI Act Art. 9 (risk management system).
  - APAC_MAS cites MAS FEAT Principle 2 (Ethics / robustness).

The get_injection_regulatory_citation(region) function returns the applicable
regulatory citation for the active deployment region.

Usage::

    from src.gateway.governance.prompt_injection_detector import (
        detect_prompt_injection, InjectionResult,
        get_injection_regulatory_citation,
    )

    result = detect_prompt_injection("Ignore all previous instructions.")
    if result.detected:
        # block and log to uca_logger
        ...
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# FINDING-09 (MEDIUM) — Jurisdictional regulatory citation map
#
# Prompt injection detection is universal (ISO 42001 A.9.2).
# The regulatory citation for the detection event is jurisdictional.
# ---------------------------------------------------------------------------

from src.gateway.governance.constants import (
    INJECTION_CITATION as _INJECTION_CITATION,
    INJECTION_CITATION_DEFAULT as _INJECTION_CITATION_DEFAULT,
)


def get_injection_regulatory_citation(region: str | None = None) -> str:
    """Return the applicable regulatory citation for prompt injection detection.

    FINDING-09: AI 600-1 §2.3 is US_FED only.  EU_ECB and APAC_MAS have
    equivalent controls under their applicable frameworks.

    Args:
        region: CAGE_DEPLOYMENT_REGION value.  If None, reads from environment.

    Returns:
        Regulatory citation string for the applicable injection detection control.
    """
    active_region = region if region is not None else os.environ.get(
        "CAGE_DEPLOYMENT_REGION", ""
    ).strip().upper()
    return _INJECTION_CITATION.get(active_region, _INJECTION_CITATION_DEFAULT)

logger = logging.getLogger("Gateway.Governance.PromptInjectionDetector")

# ---------------------------------------------------------------------------
# Structural injection patterns — not keyword-based.
# These target the *structure* of injection attempts rather than specific words,
# making them harder to evade via synonym substitution.
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    ),
    (
        "persona_override",
        re.compile(
            r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|another)\s+(?:AI|assistant|model|bot)",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_system_prompt",
        re.compile(r"system\s*:\s*\[", re.IGNORECASE),
    ),
    (
        "chatml_injection",
        re.compile(r"<\|im_start\|>system", re.IGNORECASE),
    ),
    (
        "instruction_override",
        re.compile(r"###\s*instruction\s*###", re.IGNORECASE),
    ),
    (
        "disregard_training",
        re.compile(
            r"disregard\s+(?:your\s+)?(?:training|guidelines|rules|constraints|safety)",
            re.IGNORECASE,
        ),
    ),
    (
        "jailbreak_dan",
        re.compile(
            r"(?:do\s+anything\s+now|DAN\s+mode|jailbreak\s+mode)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_play_bypass",
        re.compile(
            r"(?:pretend|roleplay\s+as)\s+(?:you\s+(?:have\s+no|are\s+without)\s+(?:restrictions|limits|rules|guidelines))"
            r"|act\s+as\s+if\s+(?:you\s+(?:have\s+no|are\s+without)|there\s+(?:are\s+no|were\s+no))"
            r"(?:\s+\w+){0,3}\s+(?:restrictions|limits|rules|guidelines|safety)",
            re.IGNORECASE,
        ),
    ),
]


# ---------------------------------------------------------------------------
# InjectionResult — structured detection result
# ---------------------------------------------------------------------------

@dataclass
class InjectionResult:
    """Result of a prompt injection detection check.

    Attributes:
        detected:        True if an injection pattern was matched.
        pattern_matched: The pattern name that triggered detection, or None.
        confidence:      Detection confidence [0.0, 1.0].
                         0.95 for pattern matches (high confidence structural match).
                         0.0 for no match.
    """

    detected: bool
    pattern_matched: Optional[str]
    confidence: float


# ---------------------------------------------------------------------------
# detect_prompt_injection — main detection function
# ---------------------------------------------------------------------------

def detect_prompt_injection(text: str) -> InjectionResult:
    """Detect structural prompt injection patterns in the given text.

    Checks the input against all patterns in ``_INJECTION_PATTERNS``.
    Returns on the first match (fail-fast).

    Args:
        text: The raw input string to check.

    Returns:
        An ``InjectionResult`` with ``detected=True`` if any pattern matches,
        ``detected=False`` otherwise.
    """
    if not text:
        return InjectionResult(detected=False, pattern_matched=None, confidence=0.0)

    for pattern_name, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "🚨 Prompt injection detected: pattern=%s text_preview=%r "
                "(AI 600-1 §2.3 — blocking request)",
                pattern_name,
                text[:100],
            )
            return InjectionResult(
                detected=True,
                pattern_matched=pattern_name,
                confidence=0.95,
            )

    return InjectionResult(detected=False, pattern_matched=None, confidence=0.0)


def get_injection_patterns() -> list[str]:
    """Return the list of active injection pattern names.

    Used by tests to verify 100% pattern coverage.
    """
    return [name for name, _ in _INJECTION_PATTERNS]
