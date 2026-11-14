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
    import yaml

    if not path.is_file():
        return False, [f"Assessment results file does not exist: {path}"]
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except Exception as exc:
        return False, [f"Failed to parse YAML from {path}: {exc}"]
    return verify_assessment_results_data(data, allow_startup_grace=allow_startup_grace)


_CLEAN_PASS_SUMMARY_RE = re.compile(
    r"^lula_audit PASS: (\d+)/(\d+) active validations satisfied$"
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def verify_lula_gate_w_job_logs(
    logs: str,
    *,
    expected_active_count: int = 1,
    expected_api_specs: list[str] | tuple[str, ...] = (),
) -> tuple[bool, list[str]]:
    """Fail-closed verifier for in-cluster ``Job/lula-gate-w`` stdout/stderr logs.

    Enforces both fast-fail negative guards and a positive structured
    ``cage_lula_audit_receipt_v1`` JSON receipt contract so message-format drift,
    unreadable/truncated logs, or unverified ``startup_grace`` state can never
    vacuously pass Gate W Phase 3.
    """
    import json

    if not logs or not logs.strip():
        return False, ["Job/lula-gate-w produced empty logs."]

    if "/v1/oscal/assessment-results" in logs:
        return False, [
            "Job/lula-gate-w referenced metrics-derived /v1/oscal/assessment-results instead of Lula assessment-results."
        ]

    if re.search(r"(?:state|Result)\s*:\s*not-satisfied|lula-validation-error", logs):
        return False, [
            "Job/lula-gate-w Lula assessment-results reported not-satisfied or lula-validation-error."
        ]

    if re.search(
        r"\bnot[-_]satisfied\s*[:=]\s*[1-9]\d*|\b[1-9]\d*\s+not[-_]satisfied\b",
        logs,
        re.IGNORECASE,
    ):
        return False, ["Job/lula-gate-w reported non-zero not-satisfied controls."]

    if re.search(
        r"assessment_status\s*=\s*startup_grace|\b[1-9]\d*\s+startup_grace\b",
        logs,
        re.IGNORECASE,
    ):
        return False, [
            "Job/lula-gate-w Lula assessment-results satisfied one or more controls via startup_grace."
        ]

    if not re.search(r"\b(?:assessment-results|satisfied|observations)\b", logs):
        return False, [
            "Job/lula-gate-w logs lack Lula assessment-results evaluation proof."
        ]

    has_custody_ack = bool(
        re.search(r'"status"\s*:\s*"INGESTED"|\bstatus\s*[=:]\s*INGESTED\b', logs)
        or re.search(
            r'"record_hash"\s*:\s*"[0-9a-f]{64}"|\brecord_hash\s*[=:]\s*[0-9a-f]{64}\b',
            logs,
        )
        or re.search(
            r"/v1/infra/events.*\b(?:200|201|202|INGESTED)\b|\bHTTP[/ ]1\.[01]\"?\s+(?:200|201|202)\b",
            logs,
        )
    )
    if not has_custody_ack:
        return False, [
            "Job/lula-gate-w logs lack /v1/infra/events custody receipt acknowledgment."
        ]

    receipts: list[dict[str, Any]] = []
    for raw_line in logs.splitlines():
        line = raw_line.strip()
        if not line.startswith("{") or "cage_lula_audit_receipt_v1" not in line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            return False, [
                f"Job/lula-gate-w emitted malformed cage_lula_audit_receipt_v1 JSON: {line[:160]}"
            ]
        if isinstance(parsed, dict) and isinstance(
            parsed.get("cage_lula_audit_receipt_v1"), dict
        ):
            receipts.append(parsed["cage_lula_audit_receipt_v1"])

    if len(receipts) != 1:
        return False, [
            f"Job/lula-gate-w logs must contain exactly 1 structured cage_lula_audit_receipt_v1 JSON receipt (found {len(receipts)}); refusing vacuous log pass."
        ]

    receipt = receipts[0]
    errors: list[str] = []

    if receipt.get("status") != "INGESTED":
        errors.append(
            f"cage_lula_audit_receipt_v1.status={receipt.get('status')!r} (expected 'INGESTED')"
        )
    rec_hash = receipt.get("record_hash")
    if not isinstance(rec_hash, str) or not _HEX64_RE.fullmatch(rec_hash):
        errors.append(
            f"cage_lula_audit_receipt_v1.record_hash={rec_hash!r} is not a 64-hex digest"
        )

    int_fields: dict[str, int] = {}
    for key in (
        "evaluated_count",
        "satisfied_count",
        "failed_count",
        "insufficient_traffic_count",
        "startup_grace_count",
    ):
        val = receipt.get(key)
        if type(val) is not int or val < 0:
            errors.append(
                f"cage_lula_audit_receipt_v1.{key}={val!r} must be a non-negative integer"
            )
        else:
            int_fields[key] = val

    sat_controls = receipt.get("satisfied_controls")
    if not isinstance(sat_controls, list) or not all(
        isinstance(c, str) and bool(c.strip()) for c in sat_controls
    ):
        errors.append(
            "cage_lula_audit_receipt_v1.satisfied_controls must be a list of non-empty strings"
        )
        sat_controls = []

    sg_controls = receipt.get("startup_grace_controls")
    if not isinstance(sg_controls, list):
        errors.append(
            "cage_lula_audit_receipt_v1.startup_grace_controls must be a list"
        )
        sg_controls = None

    if len(int_fields) == 5:
        floor = max(1, expected_active_count)
        if int_fields["evaluated_count"] < floor:
            errors.append(
                f"cage_lula_audit_receipt_v1.evaluated_count={int_fields['evaluated_count']} < expected active floor {floor}"
            )
        if int_fields["satisfied_count"] != int_fields["evaluated_count"]:
            errors.append(
                f"cage_lula_audit_receipt_v1.satisfied_count={int_fields['satisfied_count']} != evaluated_count={int_fields['evaluated_count']}"
            )
        if int_fields["failed_count"] != 0:
            errors.append(
                f"cage_lula_audit_receipt_v1.failed_count={int_fields['failed_count']} (expected 0)"
            )
        if int_fields["insufficient_traffic_count"] != 0:
            errors.append(
                f"cage_lula_audit_receipt_v1.insufficient_traffic_count={int_fields['insufficient_traffic_count']} (expected 0)"
            )
        if int_fields["startup_grace_count"] != 0:
            errors.append(
                "Job/lula-gate-w Lula assessment-results satisfied one or more controls via startup_grace "
                f"(startup_grace_count={int_fields['startup_grace_count']})."
            )
        if len(sat_controls) != int_fields["satisfied_count"]:
            errors.append(
                f"len(satisfied_controls)={len(sat_controls)} != satisfied_count={int_fields['satisfied_count']}"
            )

    if sg_controls is not None and len(sg_controls) != 0:
        errors.append(
            "Job/lula-gate-w Lula assessment-results satisfied one or more controls via startup_grace "
            f"(startup_grace_controls={sg_controls!r})."
        )

    summary = receipt.get("summary")
    m_sum = (
        _CLEAN_PASS_SUMMARY_RE.fullmatch(summary) if isinstance(summary, str) else None
    )
    if m_sum is None:
        errors.append(
            f"cage_lula_audit_receipt_v1.summary={summary!r} did not match strict post-grace clean pass format"
        )
    elif len(int_fields) == 5 and (
        int(m_sum.group(1)) != int_fields["satisfied_count"]
        or int(m_sum.group(2)) != int_fields["evaluated_count"]
    ):
        errors.append(
            f"cage_lula_audit_receipt_v1.summary ratio {m_sum.group(1)}/{m_sum.group(2)} disagrees with counts"
        )

    sat_set = set(sat_controls)
    for raw_spec in expected_api_specs:
        stem = raw_spec[:-5] if raw_spec.endswith(".yaml") else raw_spec
        if stem not in sat_set:
            errors.append(
                f"Deferred API-domain Lula spec {stem!r} missing from Job/lula-gate-w satisfied_controls"
            )

    return len(errors) == 0, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Lula assessment-results.yaml has >0 observations and 0 not-satisfied/error states."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=None,
        help="Path to assessment-results.yaml",
    )
    parser.add_argument(
        "--gate-w-job-logs",
        type=Path,
        default=None,
        help="Path to Job/lula-gate-w log file to verify against the positive receipt contract",
    )
    parser.add_argument(
        "--expected-active-count",
        type=int,
        default=1,
        help="Minimum active Lula manifests Job/lula-gate-w must have evaluated",
    )
    parser.add_argument(
        "--expected-api-spec",
        action="append",
        default=[],
        help="Deferred type:api Lula spec filename or stem that must appear in satisfied_controls",
    )
    args = parser.parse_args(argv)

    if args.gate_w_job_logs is not None:
        if not args.gate_w_job_logs.is_file():
            print(
                f"[FAIL] Job/lula-gate-w log file does not exist: {args.gate_w_job_logs}",
                file=sys.stderr,
            )
            return 1
        logs_text = args.gate_w_job_logs.read_text(encoding="utf-8")
        ok_logs, log_errs = verify_lula_gate_w_job_logs(
            logs_text,
            expected_active_count=args.expected_active_count,
            expected_api_specs=args.expected_api_spec,
        )
        if not ok_logs:
            for err in log_errs:
                print(err, file=sys.stderr)
            return 1
        if args.path is None:
            return 0

    if args.path is None:
        parser.error("either path or --gate-w-job-logs must be supplied")

    ok, errors = verify_assessment_results_file(args.path)
    if not ok:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1
    print(f"[PASS] {args.path}: all observations and findings satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
