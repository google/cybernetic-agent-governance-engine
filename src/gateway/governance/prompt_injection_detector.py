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

"""Prompt injection detector — AI 600-1 §2.3 control.

Detects structural prompt injection patterns that bypass keyword-based filters.
Complements the Aho-Corasick Tier-1 keyword scanner (text_filter.py) with
semantic/structural pattern matching for injection attempts.

POAM: AI600-003
Controls: CausalGatekeeper (pre-check), CTRL_WAL_002 (WAL integrity)
Region: US_FED (CAGE_DEPLOYMENT_REGION=US_FED)

Usage::

    from src.gateway.governance.prompt_injection_detector import (
        detect_prompt_injection, InjectionResult
    )

    result = detect_prompt_injection("Ignore all previous instructions.")
    if result.detected:
        # block and log to uca_logger
        ...
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

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
    pattern_matched: str | None
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


def detect_indirect_injection(tool_name: str, response_text: str) -> InjectionResult:
    """Detect indirect prompt injection in an MCP tool response (AI 600-1 §2.3).

    Alias for ``detect_prompt_injection`` scoped to tool response sanitisation.
    Called by ``governance_middleware.sanitize_mcp_tool_response()`` after every
    MCP tool invocation to prevent tool-response-borne injection attacks.

    Args:
        tool_name:     Name of the MCP tool that produced the response (logged
                       on detection for SIEM correlation).
        response_text: Raw string content returned by the tool call.

    Returns:
        An ``InjectionResult`` with ``detected=True`` if any structural
        injection pattern is found in the tool response, ``detected=False``
        otherwise.
    """
    result = detect_prompt_injection(response_text)
    if result.detected:
        logger.warning(
            "🚨 [AI600-003] Indirect injection detected in tool response: "
            "tool=%s pattern=%s (AI 600-1 §2.3 — blocking response)",
            tool_name,
            result.pattern_matched,
        )
    return result
