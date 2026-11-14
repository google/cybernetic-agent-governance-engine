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

"""Fail-closed verifier for Lula OSCAL assessment-results.yaml files (R-12, F-106).

Lula v0.16.0 exits 0 even when a control evaluates to ``not-satisfied`` or
``lula-validation-error``. This verifier parses ``assessment-results.yaml`` and
returns non-zero if:
  1. There are 0 results or 0 observations across results, OR
  2. Any finding target status state is ``not-satisfied`` or
     ``lula-validation-error`` (or anything other than ``satisfied``), OR
  3. Any observation relevant-evidence description or remark reports
     ``not-satisfied`` or ``lula-validation-error``.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

FORBIDDEN_VERDICT_TOKENS = ("not-satisfied", "lula-validation-error")
_STARTUP_GRACE_RE = re.compile(
    r"\bassessment_status\s*=\s*startup_grace\b", re.IGNORECASE
)


def verify_assessment_results_data(
    data: dict[str, Any] | None,
    *,
    allow_startup_grace: bool = False,
) -> tuple[bool, list[str]]:
    """Validate parsed OSCAL assessment-results data.

    Returns ``(ok, errors)`` where ``ok`` is True iff there is at least one
    observation, every observation/finding is ``satisfied``, and (unless
    ``allow_startup_grace=True``) no observation or finding remark reports
    ``assessment_status=startup_grace``.
    """
    errors: list[str] = []
    if not isinstance(data, dict) or "assessment-results" not in data:
        return False, ["Missing top-level 'assessment-results' key"]

    ar = data.get("assessment-results")
    if not isinstance(ar, dict):
        return False, ["'assessment-results' must be a mapping"]

    results = ar.get("results")
    if not isinstance(results, list) or len(results) == 0:
        return False, ["'assessment-results.results' contains 0 results"]

    total_observations = 0
    total_findings = 0

    for idx, res in enumerate(results):
        if not isinstance(res, dict):
            errors.append(f"Result[{idx}] is not a mapping")
            continue

        observations = res.get("observations") or []
        if not isinstance(observations, list):
            errors.append(f"Result[{idx}].observations is not a list")
            observations = []
        total_observations += len(observations)

        for obs_idx, obs in enumerate(observations):
            if not isinstance(obs, dict):
                errors.append(f"Result[{idx}].observations[{obs_idx}] is not a mapping")
                continue
            obs_uuid = obs.get("uuid", f"obs-{obs_idx}")
            remarks = str(obs.get("remarks", ""))
            for token in FORBIDDEN_VERDICT_TOKENS:
                if token in remarks:
                    errors.append(
                        f"Observation {obs_uuid} remarks contain forbidden token {token!r}"
                    )
            if not allow_startup_grace and _STARTUP_GRACE_RE.search(remarks):
                errors.append(
                    f"Observation {obs_uuid} satisfied via startup_grace (assessment_status=startup_grace)"
                )
            rel_ev = obs.get("relevant-evidence") or []
            if isinstance(rel_ev, list):
                for ev in rel_ev:
                    if isinstance(ev, dict):
                        desc = str(ev.get("description", ""))
                        ev_rem = str(ev.get("remarks", ""))
                        for token in FORBIDDEN_VERDICT_TOKENS:
                            if token in desc:
                                errors.append(
                                    f"Observation {obs_uuid} evidence contains {token!r}: {desc.strip()}"
                                )
                            if token in ev_rem:
                                errors.append(
                                    f"Observation {obs_uuid} evidence remarks contain {token!r}: {ev_rem.strip()}"
                                )
                        if not allow_startup_grace and (
                            _STARTUP_GRACE_RE.search(desc)
                            or _STARTUP_GRACE_RE.search(ev_rem)
                        ):
                            errors.append(
                                f"Observation {obs_uuid} evidence satisfied via startup_grace: {ev_rem.strip() or desc.strip()}"
                            )

        findings = res.get("findings") or []
        if not isinstance(findings, list):
            errors.append(f"Result[{idx}].findings is not a list")
            findings = []
        total_findings += len(findings)

        for f_idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                errors.append(f"Result[{idx}].findings[{f_idx}] is not a mapping")
                continue
            f_uuid = finding.get("uuid", f"finding-{f_idx}")
            target = finding.get("target") or {}
            status = target.get("status") or {}
            state = str(status.get("state", "")).strip()
            if state != "satisfied":
                errors.append(
                    f"Finding {f_uuid} (target={target.get('target-id')!r}) has state={state!r} (expected 'satisfied')"
                )
            f_remarks = f"{finding.get('remarks', '')}\n{status.get('remarks', '')}"
            if not allow_startup_grace and _STARTUP_GRACE_RE.search(f_remarks):
                errors.append(
                    f"Finding {f_uuid} (target={target.get('target-id')!r}) satisfied via startup_grace"
                )

    if total_observations == 0:
        errors.append("Assessment results contain 0 observations")

    return len(errors) == 0, errors


def verify_assessment_results_file(
    path: Path,
    *,
    allow_startup_grace: bool = False,
) -> tuple[bool, list[str]]:
    """Load and validate an OSCAL ``assessment-results.yaml`` file."""
    if not path.is_file():
        return False, [f"Assessment results file does not exist: {path}"]
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except Exception as exc:
        return False, [f"Failed to parse YAML from {path}: {exc}"]
    return verify_assessment_results_data(data, allow_startup_grace=allow_startup_grace)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Lula assessment-results.yaml has >0 observations and 0 not-satisfied/error states."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to assessment-results.yaml",
    )
    args = parser.parse_args(argv)
    ok, errors = verify_assessment_results_file(args.path)
    if not ok:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1
    print(f"[PASS] {args.path}: all observations and findings satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
