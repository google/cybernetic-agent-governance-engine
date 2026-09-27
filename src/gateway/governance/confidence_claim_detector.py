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
confidence_claim_detector.py — Stage 1E: Confidence-Spoofing / Review-Suppression Detector

Detects adversarial attempts to spoof model confidence scores or suppress human
review gates in user-supplied text.

Design principles:
  - Fail-closed: any match blocks immediately (returns ``detected=True``).
  - Domain-agnostic kernel core: ``DEFAULT_EXECUTION_VERBS`` contains only
    domain-neutral execution verbs; domain plugins contribute domain-specific
    verbs via ``PluginContribution.execution_verbs`` or the ``execution_verbs``
    keyword parameter.
  - Zero external dependencies: pure ``re`` stdlib module.
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass

from src.gateway.governance.authorization_claim_detector import (
    DEFAULT_EXECUTION_VERBS,
    _compile_verb_alternation,
)

logger = logging.getLogger(__name__)

_FLAGS = re.IGNORECASE | re.DOTALL

_HIGH_STAKES_ACTIONS: frozenset[str] = frozenset()


@functools.lru_cache(maxsize=32)
def _build_confclaim_patterns(
    verbs: frozenset[str],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Compile the five confidence-claim pattern categories for ``verbs``."""
    verb_alt = _compile_verb_alternation(verbs)
    return (
        # 1. numeric_confidence_override
        (
            "numeric_confidence_override",
            re.compile(
                r"\b(?:set|override|force|assign|make|with)\s+"
                r"(?:the\s+)?(?:model\s+)?confidence(?:_score)?\s*"
                r"(?:to|=|:|\s+is|\s+at)\s*"
                r"(?:1(?:\.0+)?|0\.9[5-9]\d*|100\s*%)\b",
                _FLAGS,
            ),
        ),
        (
            "numeric_confidence_override",
            re.compile(
                r"\bconfidence(?:_score)?\s*"
                r"(?:=|:|\s+is|\s+of|\s+at)\s*"
                r"(?:1\.0+|0\.9[5-9]\d*|100\s*%)\b",
                _FLAGS,
            ),
        ),
        # 2. api_parameter_injection
        (
            "api_parameter_injection",
            re.compile(
                r"""["']?(?:bypass_review|auto_approve|skip_review|force_approve|override_review)["']?\s*:\s*(?:true|1|"true"|'true')""",
                _FLAGS,
            ),
        ),
        (
            "api_parameter_injection",
            re.compile(
                r"""["']?(?:human_review|manual_review|require_review|review_required)["']?\s*:\s*(?:false|0|"false"|'false')""",
                _FLAGS,
            ),
        ),
        (
            "api_parameter_injection",
            re.compile(
                r"\b(?:approval_status|review_status)\s*(?:=|:)\s*['\"]?approved['\"]?",
                _FLAGS,
            ),
        ),
        (
            "api_parameter_injection",
            re.compile(
                r"\brisk_score\s*(?:to|=|:)\s*0(?:\.0+)?\b",
                _FLAGS,
            ),
        ),
        # 3. certainty_claim
        (
            "certainty_claim",
            re.compile(
                r"\b(?:absolute\s+certainty|100\s*%\s+(?:confidence|certain(?:ty)?)|complete\s+certainty|total\s+certainty|guaranteed\s+safe)\b",
                _FLAGS,
            ),
        ),
        # 4. negation_uncertainty
        (
            "negation_uncertainty",
            re.compile(
                r"\bzero\s+uncertainty\b",
                _FLAGS,
            ),
        ),
        (
            "negation_uncertainty",
            re.compile(
                r"\bno\s+uncertainty\b",
                _FLAGS,
            ),
        ),
        (
            "negation_uncertainty",
            re.compile(
                r"\bwithout\s+(?:any\s+)?uncertainty\b",
                _FLAGS,
            ),
        ),
        (
            "negation_uncertainty",
            re.compile(
                r"(?:\bno\b|\bzero\b)\s+(?:risk|doubt).{0,100}"
                r"(?:review|approval|oversight).{0,100}"
                r"(?:not\s+(?:required|needed|applicable)|does\s+not\s+apply)\b",
                _FLAGS,
            ),
        ),
        (
            "negation_uncertainty",
            re.compile(
                r"\breview\s+requirement.{0,100}"
                r"(?:does\s+not\s+apply|not\s+applicable|not\s+required|waived)\b",
                _FLAGS,
            ),
        ),
        # 5. skip_review_imperative
        (
            "skip_review_imperative",
            re.compile(
                r"\bskip\s+(?:the\s+)?(?:review|approval|oversight|human\s+review)\b",
                _FLAGS,
            ),
        ),
        (
            "skip_review_imperative",
            re.compile(
                r"\bno\s+(?:human|manual)\s+review\s+(?:is\s+)?(?:needed|necessary|required)\b",
                _FLAGS,
            ),
        ),
        (
            "skip_review_imperative",
            re.compile(
                r"\bbypass\s+(?:the\s+)?(?:review|human\s+review|approval|oversight)\b",
                _FLAGS,
            ),
        ),
        (
            "skip_review_imperative",
            re.compile(
                r"\bhuman\s+review\s+(?:is\s+)?(?:unnecessary|redundant|not\s+required|not\s+needed)\b",
                _FLAGS,
            ),
        ),
        (
            "skip_review_imperative",
            re.compile(
                r"\bhuman\s+review\s+would\s+be\s+(?:redundant|unnecessary)\b",
                _FLAGS,
            ),
        ),
        (
            "skip_review_imperative",
            re.compile(
                rf"\b(?:{verb_alt})\b.{{0,80}}\bwithout\s+(?:human\s+|manual\s+)?(?:review|approval|oversight)\b",
                _FLAGS,
            ),
        ),
    )


_CONFCLAIM_PATTERNS: list[tuple[str, re.Pattern[str]]] = list(
    _build_confclaim_patterns(DEFAULT_EXECUTION_VERBS)
)


@dataclass
class ConfidenceClaimResult:
    """Result of a confidence-spoofing / human-review-suppression detection check."""

    detected: bool
    pattern_matched: str | None = None
    confidence: float = 0.0
    details: str = ""


def get_confclaim_pattern_names() -> list[str]:
    """Return the ordered list of distinct pattern category names."""
    seen: list[str] = []
    for name, _ in _CONFCLAIM_PATTERNS:
        if name not in seen:
            seen.append(name)
    return seen


def detect_confidence_claim(
    text: str,
    *,
    execution_verbs: Iterable[str] | None = None,
    high_stakes_actions: Iterable[str] | None = None,
) -> ConfidenceClaimResult:
    """Stage 1E: Detect adversarial confidence-spoofing attempts.

    Args:
        text: The raw input string to check.
        execution_verbs: Optional iterable of domain execution verbs to union
            with ``DEFAULT_EXECUTION_VERBS``.
        high_stakes_actions: Optional iterable of high-stakes action names to
            union with ``_HIGH_STAKES_ACTIONS``.

    Returns:
        A ``ConfidenceClaimResult`` with ``detected=True`` if any pattern
        matches, ``detected=False`` otherwise.
    """
    if not text:
        return ConfidenceClaimResult(detected=False)

    text_lower = text.lower()
    if execution_verbs is None and high_stakes_actions is None:
        patterns: Iterable[tuple[str, re.Pattern[str]]] = _CONFCLAIM_PATTERNS
    else:
        patterns = _build_confclaim_patterns(
            DEFAULT_EXECUTION_VERBS
            | _HIGH_STAKES_ACTIONS
            | frozenset(execution_verbs or ())
            | frozenset(high_stakes_actions or ())
        )

    for name, pattern in patterns:
        if pattern.search(text_lower if pattern.flags & re.IGNORECASE else text):
            logger.warning(
                "🚨 ConfidenceClaimDetector: confidence-spoofing detected: "
                "pattern=%r text_snippet=%r",
                name,
                text[:120],
            )
            return ConfidenceClaimResult(
                detected=True,
                pattern_matched=name,
                confidence=0.95,
                details=(
                    f"Confidence-spoofing / review-suppression pattern matched: "
                    f"category='{name}'"
                ),
            )

    return ConfidenceClaimResult(
        detected=False,
        pattern_matched=None,
        confidence=0.0,
        details="",
    )


__all__ = [
    "ConfidenceClaimResult",
    "DEFAULT_EXECUTION_VERBS",
    "detect_confidence_claim",
    "get_confclaim_pattern_names",
]
