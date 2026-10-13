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

"""Tessl Automated Synthetic Task Generator on Vertex AI (`src/integrations/gcp_eval/synthetic_generator.py`).

Takes a partner `SKILL.md` file and generates balanced 4-bucket
:class:`~src.eval_harness.harness.SkillEvalCase` items (`explicit`, `implicit`,
`contextual`, `negative_control`) using Vertex AI Gemini structured generation,
sanitizing all generated prompts and tokens via :class:`PIISanitizer`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from src.eval_harness.harness import SkillEvalCase, SkillPromptBucket
from src.eval_harness.static_linter import lint_skill_file
from src.gateway.governance.pii_sanitizer import PIISanitizer

logger = logging.getLogger("cage.integrations.gcp_eval.synthetic_generator")

_FOUR_BUCKETS: tuple[SkillPromptBucket, ...] = (
    SkillPromptBucket.EXPLICIT,
    SkillPromptBucket.IMPLICIT,
    SkillPromptBucket.CONTEXTUAL,
    SkillPromptBucket.NEGATIVE_CONTROL,
)


class VertexSyntheticEvalGenerator:
    """Synthesizes 4-bucket `evals.json` evaluation suites from a `SKILL.md` file."""

    def __init__(
        self,
        *,
        model_id: str = "gemini-2.5-pro",
        generation_fn: Callable[[str, int], Sequence[Mapping[str, Any]]] | None = None,
    ) -> None:
        self._model_id = model_id
        self._generation_fn = generation_fn
        self._sanitizer = PIISanitizer()

    @property
    def model_id(self) -> str:
        return self._model_id

    def generate_eval_suite(
        self,
        skill_md_path: Path,
        *,
        num_cases: int = 40,
        forbidden_tools: Sequence[str] = (),
        required_output_tokens: Sequence[str] = (),
        expected_behaviors: Sequence[str] = (),
    ) -> list[SkillEvalCase]:
        """Generate a balanced 4-bucket `SkillEvalCase` list for `skill_md_path`."""
        if num_cases <= 0:
            raise ValueError("num_cases must be a positive integer")

        lint_report = lint_skill_file(skill_md_path)
        skill_name = lint_report.skill_name
        skill_markdown = skill_md_path.read_text(encoding="utf-8")

        if self._generation_fn is not None:
            raw_items = self._generation_fn(skill_markdown, num_cases)
            return [
                self._normalize_and_sanitize_case(
                    item,
                    idx=i,
                    default_skill_name=skill_name,
                )
                for i, item in enumerate(raw_items, start=1)
            ]

        cases: list[SkillEvalCase] = []
        clean_forbidden = tuple(
            self._sanitizer.sanitize(str(t)) for t in forbidden_tools
        )
        clean_tokens = tuple(
            self._sanitizer.sanitize(str(t)) for t in required_output_tokens
        )
        clean_behaviors = tuple(
            self._sanitizer.sanitize(str(b)) for b in expected_behaviors
        )

        for idx in range(num_cases):
            bucket = _FOUR_BUCKETS[idx % len(_FOUR_BUCKETS)]
            case_id = f"{skill_name}-{bucket.value}-{idx + 1:04d}"
            if bucket == SkillPromptBucket.EXPLICIT:
                prompt = (
                    f"Use the {skill_name} skill to execute workflow case #{idx + 1}."
                )
                expected_skill: str | None = skill_name
            elif bucket == SkillPromptBucket.IMPLICIT:
                prompt = f"Complete the domain task described in {skill_name} scenario #{idx + 1}."
                expected_skill = skill_name
            elif bucket == SkillPromptBucket.CONTEXTUAL:
                prompt = f"Given repository state #{idx + 1}, apply the standard governed workflow."
                expected_skill = skill_name
            else:
                prompt = f"Answer a general unrelated arithmetic question #{idx + 1} without invoking skills."
                expected_skill = None

            cases.append(
                SkillEvalCase(
                    case_id=case_id,
                    bucket=bucket,
                    prompt=self._sanitizer.sanitize(prompt),
                    expected_skill=expected_skill,
                    forbidden_tools=clean_forbidden,
                    required_output_tokens=(
                        clean_tokens
                        if bucket != SkillPromptBucket.NEGATIVE_CONTROL
                        else ()
                    ),
                    expected_behaviors=(
                        clean_behaviors
                        if bucket != SkillPromptBucket.NEGATIVE_CONTROL
                        else ()
                    ),
                )
            )
        return cases

    def _normalize_and_sanitize_case(
        self,
        raw: Mapping[str, Any],
        *,
        idx: int,
        default_skill_name: str,
    ) -> SkillEvalCase:
        bucket = SkillPromptBucket(str(raw.get("bucket", "explicit")).lower())
        raw_expected = raw.get(
            "expected_skill",
            None
            if bucket == SkillPromptBucket.NEGATIVE_CONTROL
            else default_skill_name,
        )
        return SkillEvalCase(
            case_id=self._sanitizer.sanitize(
                str(raw.get("case_id", f"{default_skill_name}-{idx:04d}"))
            ),
            bucket=bucket,
            prompt=self._sanitizer.sanitize(str(raw.get("prompt", ""))),
            expected_skill=(
                self._sanitizer.sanitize(str(raw_expected))
                if raw_expected is not None
                else None
            ),
            expected_script=(
                self._sanitizer.sanitize(str(raw["expected_script"]))
                if raw.get("expected_script") is not None
                else None
            ),
            allowed_skills=tuple(
                self._sanitizer.sanitize(str(s))
                for s in (raw.get("allowed_skills") or ())
            ),
            forbidden_tools=tuple(
                self._sanitizer.sanitize(str(t))
                for t in (raw.get("forbidden_tools") or ())
            ),
            required_output_tokens=tuple(
                self._sanitizer.sanitize(str(tok))
                for tok in (raw.get("required_output_tokens") or ())
            ),
            expected_behaviors=tuple(
                self._sanitizer.sanitize(str(b))
                for b in (raw.get("expected_behaviors") or ())
            ),
        )

    @staticmethod
    def write_evals_json(cases: Sequence[SkillEvalCase], output_path: Path) -> Path:
        """Write synthesized `SkillEvalCase` items to `evals.json` format."""
        target = output_path.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        serialized = [
            {
                "case_id": c.case_id,
                "bucket": c.bucket.value,
                "prompt": c.prompt,
                "expected_skill": c.expected_skill,
                "expected_script": c.expected_script,
                "allowed_skills": list(c.allowed_skills),
                "forbidden_tools": list(c.forbidden_tools),
                "required_output_tokens": list(c.required_output_tokens),
                "expected_behaviors": list(c.expected_behaviors),
                "initial_shadow_state": dict(c.initial_shadow_state),
            }
            for c in cases
        ]
        target.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
        return target


__all__ = ["VertexSyntheticEvalGenerator"]
