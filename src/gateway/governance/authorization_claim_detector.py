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
authorization_claim_detector.py — Stage 1D: Authorization-Claim / Impersonation Detector

Closes the ``rbac_escalation`` adversarial attack category by detecting
self-asserted authority, executive impersonation, fabricated override codes,
and urgency + role-claim combinations in user-supplied text.

Design principles:
  - Fail-closed: any match blocks immediately (returns ``detected=True``).
  - Low false-positive rate (FPR): patterns require the *co-occurrence* of a
    self-asserted authority/override signal AND an execution imperative or
    override directive.
  - Domain-agnostic kernel core: the default execution lexicon contains only
    domain-neutral verbs (``DEFAULT_EXECUTION_VERBS``); domain plugins
    contribute domain-specific verbs via ``PluginContribution.execution_verbs``
    or the ``execution_verbs`` / ``high_stakes_actions`` parameters.
  - Zero external dependencies: pure ``re`` stdlib module; sub-millisecond
    latency (0 ms p99 overhead).
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Iterable
from typing import NamedTuple

logger = logging.getLogger(__name__)

_FLAGS = re.IGNORECASE | re.DOTALL

DEFAULT_EXECUTION_VERBS: frozenset[str] = frozenset(
    {
        "execute",
        "submit",
        "process",
        "approve",
        "authorize",
        "place",
        "override",
        "commit",
    }
)

_HIGH_STAKES_ACTIONS: frozenset[str] = frozenset()


def _verb_to_regex(verb: str) -> str:
    """Convert an action verb or action identifier into a regex fragment."""
    v = verb.strip().lower()
    if not v:
        return ""
    if "_" in v:
        return re.escape(v)
    if v.endswith("e") and len(v) > 2 and not v.endswith("ee"):
        return rf"{re.escape(v[:-1])}(?:e|ing)"
    if v.endswith(("mit", "fer")):
        return rf"{re.escape(v)}(?:{re.escape(v[-1])}ing)?"
    return rf"{re.escape(v)}(?:ing)?"


def _compile_verb_alternation(verbs: frozenset[str]) -> str:
    fragments = sorted({_verb_to_regex(v) for v in verbs if v and v.strip()})
    if not fragments:
        fragments = [_verb_to_regex(v) for v in sorted(DEFAULT_EXECUTION_VERBS)]
    return "|".join(fragments)


@functools.lru_cache(maxsize=32)
def _build_authclaim_patterns(
    verbs: frozenset[str],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Compile the authorization-claim pattern categories for ``verbs``."""
    verb_alt = _compile_verb_alternation(verbs)
    action_verb_alt = _compile_verb_alternation(verbs - {"approve", "authorize"})

    return (
        (
            "elevated_title_execution",
            re.compile(
                r"(I\s+am|I'm|this\s+is|As\s+(the\s+)?)\s*(the\s+)?"
                r"(Chief|Head|Director|VP|SVP|EVP|Managing|Executive|"
                r"Chief\s+Trading|Chief\s+Risk|Chief\s+Compliance)\b"
                r".{0,200}"
                rf"({verb_alt})\b",
                _FLAGS,
            ),
        ),
        (
            "override_code",
            re.compile(
                r"\b(override|bypass|authorization)\s*code\b",
                _FLAGS,
            ),
        ),
        (
            "override_code",
            re.compile(
                r"\bADMIN-\d{3,}\b",
                _FLAGS,
            ),
        ),
        (
            "override_code",
            re.compile(
                r"\bROOT-ACCESS-\d{4}\b",
                _FLAGS,
            ),
        ),
        (
            "system_override_banner",
            re.compile(
                r"\bSYSTEM\s+OVERRIDE\b",
                _FLAGS,
            ),
        ),
        (
            "system_override_banner",
            re.compile(
                r"\bOVERRIDE\s+MODE\s+ACTIVATED\b",
                _FLAGS,
            ),
        ),
        (
            "urgency_impersonation",
            re.compile(
                r"\b(URGENT|CRITICAL|PRIORITY|time[- ]sensitive)\b"
                r".{0,100}"
                r"(from\s+(Compliance|Legal|Risk|Executive|the\s+Board)"
                r"|pre[- ]?approved"
                r"|on\s+behalf\s+of)"
                r".{0,150}"
                rf"({action_verb_alt})\b",
                _FLAGS,
            ),
        ),
        (
            "badge_id_escalation",
            re.compile(
                r"\b(ID|badge|employee)[- ]?\d{4,}\b"
                r".{0,150}"
                r"(authorized|permission|clearance|access)\b",
                _FLAGS,
            ),
        ),
        (
            "escalation_with_assertion",
            re.compile(
                r"(I\s+confirm|I\s+authorize|this\s+is\s+authorized|pre[- ]?approved|"
                r"I\s+have\s+(permission|clearance|authority|authorization))\b"
                r".{0,250}"
                rf"\b({action_verb_alt})\b",
                _FLAGS,
            ),
        ),
        (
            "escalation_with_assertion_reversed",
            re.compile(
                rf"\b({action_verb_alt})\b"
                r".{0,250}"
                r"\b(I\s+confirm|I\s+authorize|I\s+verify|this\s+is\s+(authorized|approved)|"
                r"pre[- ]?approved|I\s+have\s+(permission|clearance|authority|authorization))\b"
                r"(?!\s+(receipt|acknowledgement|understanding|the\s+(above|email|report|statement|order\s+was)))",
                _FLAGS,
            ),
        ),
    )


_AUTHCLAIM_PATTERNS: list[tuple[str, re.Pattern[str]]] = list(
    _build_authclaim_patterns(DEFAULT_EXECUTION_VERBS | _HIGH_STAKES_ACTIONS)
)


class AuthClaimDetectionResult(NamedTuple):
    """Structured result from ``detect_authorization_claim``."""

    detected: bool
    category: str | None = None
    confidence: float = 0.0
    matched_text: str | None = None


def get_authclaim_categories() -> list[str]:
    """Return the ordered list of distinct pattern category names."""
    seen: list[str] = []
    for category, _ in _AUTHCLAIM_PATTERNS:
        if category not in seen:
            seen.append(category)
    return seen


def detect_authorization_claim(
    text: str,
    *,
    execution_verbs: Iterable[str] | None = None,
    high_stakes_actions: Iterable[str] | None = None,
) -> AuthClaimDetectionResult:
    """Stage 1D: Detect adversarial authorization-claim and impersonation attempts.

    Args:
        text: Raw user input text to inspect.
        execution_verbs: Optional iterable of domain execution verbs to union
            with ``DEFAULT_EXECUTION_VERBS``.
        high_stakes_actions: Optional iterable of high-stakes action names to
            union with ``_HIGH_STAKES_ACTIONS``.

    Returns:
        ``AuthClaimDetectionResult`` with ``detected=True`` on match.
    """
    if not text:
        return AuthClaimDetectionResult(
            detected=False,
            category=None,
            confidence=0.0,
            matched_text=None,
        )

    if execution_verbs is None and high_stakes_actions is None:
        patterns: Iterable[tuple[str, re.Pattern[str]]] = _AUTHCLAIM_PATTERNS
    else:
        combined_verbs = (
            DEFAULT_EXECUTION_VERBS
            | _HIGH_STAKES_ACTIONS
            | frozenset(execution_verbs or ())
            | frozenset(high_stakes_actions or ())
        )
        patterns = _build_authclaim_patterns(combined_verbs)

    for category, pattern in patterns:
        match = pattern.search(text)
        if match:
            snippet = match.group(0)[:200]
            logger.warning(
                "🚨 AuthClaimDetector: authorization claim detected: "
                "category=%r snippet=%r",
                category,
                snippet,
            )
            return AuthClaimDetectionResult(
                detected=True,
                category=category,
                confidence=0.9,
                matched_text=snippet,
            )

    return AuthClaimDetectionResult(
        detected=False,
        category=None,
        confidence=0.0,
        matched_text=None,
    )


__all__ = [
    "DEFAULT_EXECUTION_VERBS",
    "AuthClaimDetectionResult",
    "detect_authorization_claim",
    "get_authclaim_categories",
]
