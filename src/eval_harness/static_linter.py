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

"""Stage 0 Static SKILL.md Quality & Security Linter (`src/eval_harness/static_linter.py`).

Implements the zero-LLM-cost static pre-flight gate from:
* **SkillEval** (arXiv:2608.06891): Six intrinsic skill quality dimensions
  (Structural Integrity, Routing Trigger Clarity, Actionability & Parameter
  Specificity, Tool Cohesiveness, Robustness & Error Recovery, Safety & Scope
  Restraint) with explicit length-bias penalization (`Information Density`) so
  bloated markdown dumps cannot inflate scores.
* **ACES** (arXiv:2608.20614): Pre-execution verification of YAML frontmatter,
  workflow ordering steps, and embedded secret/injection hygiene.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.gateway.governance.authorization_claim_detector import (
    detect_authorization_claim,
)
from src.gateway.governance.confidence_claim_detector import (
    detect_confidence_claim,
)
from src.gateway.governance.pii_sanitizer import PIISanitizer

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)
_SECRET_OR_INJECTION_RE = re.compile(
    r"(?:nvapi-[A-Za-z0-9_-]{8,}|sk-lf-[A-Za-z0-9_-]{8,}|pk-lf-[A-Za-z0-9_-]{8,}"
    r"|hf_[A-Za-z0-9]{10,}|CANARY_SECRET_[A-Za-z0-9_-]+"
    r"|ignore\s+all\s+previous\s+instructions"
    r"|bypass\s+governance"
    r"|\brm\s+-[rRf]{1,3}\b"
    r"|\bcurl\b[^|;\n]*\|\s*(?:ba)?sh\b)",
    re.IGNORECASE,
)
_TRIGGER_KEYWORDS = (
    "use when",
    "trigger",
    "activate when",
    "do not use",
    "when the user",
    "should be used when",
)
_RECOVERY_KEYWORDS = (
    "fallback",
    "error",
    "recover",
    "retry",
    "if this fails",
    "fail-closed",
    "abort",
    "troubleshoot",
)
_SCOPE_BOUNDARY_KEYWORDS = (
    "do not use",
    "never",
    "out of scope",
    "boundary",
    "restraint",
    "forbidden",
    "must not",
)


@dataclass(frozen=True)
class SkillStaticLintReport:
    """Intrinsic 6-dimension static quality and security report for a SKILL.md file."""

    skill_name: str
    passed: bool
    structural_integrity: float
    routing_clarity: float
    actionability: float
    tool_cohesiveness: float
    robustness_recovery: float
    safety_restraint: float
    information_density_multiplier: float
    raw_mean_score: float
    length_adjusted_score: float
    word_count: int
    violations: tuple[str, ...] = ()


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Extract simple YAML frontmatter key-values and markdown body."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    raw_yaml = match.group(1)
    body = text[match.end() :]
    meta: dict[str, str] = {}
    for line in raw_yaml.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        meta[key.strip().lower()] = val.strip().strip("'\"")
    return meta, body


def lint_skill_markdown(
    content: str,
    *,
    skill_name: str = "unnamed-skill",
    min_score: float = 0.70,
    optimal_max_words: int = 1800,
) -> SkillStaticLintReport:
    """Evaluate a `SKILL.md` document across the 6 SkillEval dimensions and security gates.

    Applies length-orthogonalized density normalization (SkillEval §3.3):
    documents that pad length beyond ``optimal_max_words`` without proportional
    actionable artifacts (code blocks, numbered workflow steps, explicit flags)
    receive a decaying ``information_density_multiplier``.
    """
    violations: list[str] = []
    meta, body = _parse_frontmatter(content)
    lower_all = content.lower()
    words = re.findall(r"\S+", body)
    word_count = len(words)

    # 1. Structural Integrity (YAML frontmatter + name + description + headings)
    has_frontmatter = bool(meta)
    has_name = bool(meta.get("name"))
    has_desc = bool(meta.get("description")) and len(meta.get("description", "")) >= 15
    headings = re.findall(r"^#{1,3}\s+.+$", body, flags=re.MULTILINE)
    has_sections = len(headings) >= 2

    if not has_frontmatter:
        violations.append("missing_yaml_frontmatter")
    if not has_name:
        violations.append("missing_frontmatter_name")
    if not has_desc:
        violations.append("missing_or_trivial_frontmatter_description")
    if not has_sections:
        violations.append("insufficient_section_headings")

    structural_integrity = round(
        sum(
            1.0 if ok else 0.0
            for ok in (has_frontmatter, has_name, has_desc, has_sections)
        )
        / 4.0,
        4,
    )

    # 2. Routing Trigger Clarity (positive activation condition + negative boundary)
    desc_lower = meta.get("description", "").lower()
    has_positive_trigger = any(
        k in desc_lower or k in lower_all for k in _TRIGGER_KEYWORDS
    )
    has_negative_trigger = any(
        neg in lower_all
        for neg in (
            "do not use",
            "when not to use",
            "negative control",
            "do not activate",
        )
    )
    if not has_positive_trigger:
        violations.append("missing_routing_trigger_guidance")
    routing_clarity = round(
        (1.0 if has_positive_trigger else 0.0) * 0.65
        + (1.0 if has_negative_trigger else 0.0) * 0.35,
        4,
    )

    # 3. Actionability & Parameter Specificity (numbered workflow steps + code/CLI examples)
    numbered_steps = re.findall(r"^\s*\d+\.\s+.+$", body, flags=re.MULTILINE)
    code_blocks = re.findall(r"```[\s\S]*?```", body)
    inline_code = re.findall(r"`[^`\n]+`", body)
    has_workflow_order = len(numbered_steps) >= 2
    has_concrete_examples = len(code_blocks) >= 1 or len(inline_code) >= 3
    if not has_workflow_order:
        violations.append("missing_ordered_workflow_steps")
    if not has_concrete_examples:
        violations.append("missing_concrete_code_or_parameter_examples")
    actionability = round(
        (1.0 if has_workflow_order else 0.0) * 0.5
        + (1.0 if has_concrete_examples else 0.0) * 0.5,
        4,
    )

    # 4. Tool Cohesiveness (references to scripts/, tools, or structured I/O contracts)
    has_tool_refs = bool(
        re.search(
            r"(?:scripts/|\.py\b|\.sh\b|--[a-z0-9_-]+|input|output|arguments|parameters)",
            body,
            re.IGNORECASE,
        )
    )
    tool_cohesiveness = 1.0 if has_tool_refs else 0.3

    # 5. Robustness & Error Recovery (fallback/error handling instructions)
    recovery_hits = sum(1 for kw in _RECOVERY_KEYWORDS if kw in lower_all)
    if recovery_hits == 0:
        violations.append("missing_error_recovery_or_fallback_guidance")
    robustness_recovery = min(1.0, round(recovery_hits / 2.0, 4))

    # 6. Safety & Scope Restraint (zero secrets/PII/spoofing + explicit scope boundaries)
    sanitizer = PIISanitizer()
    sec_match = _SECRET_OR_INJECTION_RE.search(content)
    pii_clean = sanitizer.sanitize(content) == content
    conf_spoof = detect_confidence_claim(content).detected
    auth_spoof = detect_authorization_claim(content).detected

    security_clean = (
        sec_match is None and pii_clean and not conf_spoof and not auth_spoof
    )
    if sec_match is not None:
        violations.append(
            f"embedded_secret_or_unsafe_directive:{sec_match.group(0)[:20]}"
        )
    if not pii_clean:
        violations.append("embedded_pii_in_skill_markdown")
    if conf_spoof:
        violations.append("embedded_confidence_spoofing_directive")
    if auth_spoof:
        violations.append("embedded_authorization_spoofing_directive")

    has_scope_restraint = any(kw in lower_all for kw in _SCOPE_BOUNDARY_KEYWORDS)
    if not security_clean:
        safety_restraint = 0.0
    else:
        safety_restraint = 1.0 if has_scope_restraint else 0.7

    raw_mean = round(
        (
            structural_integrity
            + routing_clarity
            + actionability
            + tool_cohesiveness
            + robustness_recovery
            + safety_restraint
        )
        / 6.0,
        4,
    )

    # Length-orthogonalized density multiplier (SkillEval §3.3):
    # Penalize bloated prose that exceeds optimal_max_words without structural density.
    structural_signals = len(numbered_steps) + (2 * len(code_blocks)) + len(headings)
    if word_count == 0:
        density_multiplier = 0.0
    elif word_count <= optimal_max_words:
        density_multiplier = 1.0
    else:
        excess_ratio = optimal_max_words / float(word_count)
        signal_bonus = min(0.25, structural_signals * 0.01)
        density_multiplier = round(min(1.0, max(0.4, excess_ratio + signal_bonus)), 4)
        if density_multiplier < 0.85:
            violations.append(
                f"length_bloat_penalty(words={word_count},multiplier={density_multiplier})"
            )

    length_adjusted = round(raw_mean * density_multiplier, 4)
    resolved_name = meta.get("name") or skill_name
    passed = (
        security_clean
        and has_frontmatter
        and has_name
        and has_desc
        and length_adjusted >= min_score
    )

    return SkillStaticLintReport(
        skill_name=resolved_name,
        passed=passed,
        structural_integrity=structural_integrity,
        routing_clarity=routing_clarity,
        actionability=actionability,
        tool_cohesiveness=tool_cohesiveness,
        robustness_recovery=robustness_recovery,
        safety_restraint=safety_restraint,
        information_density_multiplier=density_multiplier,
        raw_mean_score=raw_mean,
        length_adjusted_score=length_adjusted,
        word_count=word_count,
        violations=tuple(violations),
    )


def lint_skill_file(
    skill_md_path: str | Path,
    *,
    min_score: float = 0.70,
    optimal_max_words: int = 1800,
) -> SkillStaticLintReport:
    """Read a `SKILL.md` file from disk and return its :class:`SkillStaticLintReport`."""
    path = Path(skill_md_path).resolve()
    content = path.read_text(encoding="utf-8")
    inferred_name = path.parent.name or path.stem
    return lint_skill_markdown(
        content,
        skill_name=inferred_name,
        min_score=min_score,
        optimal_max_words=optimal_max_words,
    )


__all__ = [
    "SkillStaticLintReport",
    "lint_skill_file",
    "lint_skill_markdown",
]
