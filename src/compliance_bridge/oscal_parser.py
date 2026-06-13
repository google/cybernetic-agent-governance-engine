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
oscal_parser.py

Deterministic, zero-inference OSCAL Assessment Result YAML parser.

Ported from src/langfuse-bridge/src/oscalParser.ts (js-yaml + Zod)
→ PyYAML + Pydantic.

OSCAL Assessment Results structure emitted by `lula validate`:

  assessment-results:
    uuid: <string>
    metadata:
      last-modified: <ISO8601>
    results:
      - uuid: <string>
        findings:
          - uuid: <string>
            title: <string>         # e.g. "A.5.2 validation"
            description: <string?>
            remarks: <string?>
            target:
              type: objective-id
              target-id: <control-id>   # A.5.2 | A.5.3 | A.9.2 | SC-4
              status:
                state: satisfied | not-satisfied
            props:                       # optional Lula extensions
              - name: safety_rate
                value: "0.995"
              - name: evidence_age_seconds
                value: "3600"
"""

from __future__ import annotations

import logging
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from .types import OscalFinding, OscalResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Raw OSCAL Pydantic shapes — permissive so we never throw on minor schema drift.
# We validate the *output* tightly via OscalFinding.
# ---------------------------------------------------------------------------

class RawProp(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    value: str


class RawStatus(BaseModel):
    model_config = ConfigDict(extra="allow")

    state: str


class RawTarget(BaseModel):
    model_config = ConfigDict(extra="allow")

    target_id: str  # mapped from "target-id"
    status: RawStatus

    @classmethod
    def from_raw(cls, data: dict[str, Any]) -> "RawTarget":
        """Normalise hyphenated OSCAL key 'target-id' to 'target_id'."""
        normalised = dict(data)
        if "target-id" in normalised:
            normalised["target_id"] = normalised.pop("target-id")
        return cls(**normalised)


class RawFinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    uuid: str
    title: str | None = None
    description: str | None = None
    remarks: str | None = None
    target: dict[str, Any]
    props: list[dict[str, Any]] | None = None


class RawResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    uuid: str | None = None
    findings: list[dict[str, Any]] | None = None


# ---------------------------------------------------------------------------
# mapState — converts OSCAL status.state to our PASS/FAIL enum.
# Lula uses "satisfied" / "not-satisfied"; fall back to direct PASS/FAIL.
# ---------------------------------------------------------------------------

def _map_state(state: str) -> OscalResult:
    """Map an OSCAL status.state string to our canonical OscalResult enum.

    Mapping rationale (NIST SP 800-53A §3.2 assessment attribute vocabulary):
      satisfied / pass / passed   → PASS           (assessment objective met)
      not-satisfied / fail/failed → FAIL           (assessment objective not met)
      not-applicable              → NOT_APPLICABLE (control does not apply to
                                                    this system component type)
      anything else               → ERROR          (unknown/unrecognised state —
                                                    must NOT be silently treated
                                                    as NOT_APPLICABLE; doing so
                                                    would mask a potential security
                                                    blind spot from auditors)
    """
    s = state.lower().strip()
    if s in ("satisfied", "pass", "passed"):
        return "PASS"
    if s in ("not-satisfied", "fail", "failed"):
        return "FAIL"
    if s in ("not-applicable", "not_applicable", "na"):
        return "NOT_APPLICABLE"
    # Unknown / unrecognised state — flag as ERROR so auditors see it.
    logger.warning(
        "[oscal_parser] Unrecognised OSCAL status.state %r — mapping to ERROR "
        "(not NOT_APPLICABLE). Verify the lula output schema.",
        state,
    )
    return "ERROR"


# ---------------------------------------------------------------------------
# _get_prop — safely extract a named prop value from a finding's props list.
# ---------------------------------------------------------------------------

def _get_prop(
    props: list[dict[str, Any]] | None,
    name: str,
) -> str | None:
    if not props:
        return None
    for p in props:
        if p.get("name") == name:
            return p.get("value")
    return None


# ---------------------------------------------------------------------------
# parse_oscal_yaml — public entry point.
#
# @param oscal_yaml  Raw OSCAL Assessment Result YAML string from `lula validate`.
# @returns           Validated list[OscalFinding] ready for Langfuse ingestion.
# @raises ValueError If YAML is malformed or contains no findings at all.
# ---------------------------------------------------------------------------

# M-09: Maximum OSCAL YAML payload size (5 MB) to prevent DoS via yaml.safe_load
_MAX_OSCAL_YAML_BYTES: int = 5 * 1024 * 1024  # 5 MB


def parse_oscal_yaml(oscal_yaml: str) -> list[OscalFinding]:
    # M-09: Reject oversized payloads before yaml.safe_load to prevent DoS
    if len(oscal_yaml.encode("utf-8")) > _MAX_OSCAL_YAML_BYTES:
        raise ValueError(
            f"[oscal_parser] OSCAL YAML payload exceeds maximum allowed size "
            f"({_MAX_OSCAL_YAML_BYTES // (1024 * 1024)} MB). Rejecting to prevent DoS."
        )
    # 1. Parse YAML (raises yaml.YAMLError on syntax error)
    try:
        raw = yaml.safe_load(oscal_yaml)
    except yaml.YAMLError as exc:
        raise ValueError(f"[oscal_parser] YAML syntax error: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("[oscal_parser] OSCAL document is not a YAML mapping.")

    # 2. Navigate to assessment-results.results
    assessment = raw.get("assessment-results")
    if not isinstance(assessment, dict):
        raise ValueError(
            "[oscal_parser] OSCAL document does not match expected structure: "
            "missing 'assessment-results' key."
        )

    results_raw = assessment.get("results") or []
    if not results_raw:
        raise ValueError("[oscal_parser] OSCAL Assessment Result contains no result entries.")

    # 3. Flatten all findings across all result entries
    findings: list[OscalFinding] = []

    for result_data in results_raw:
        if not isinstance(result_data, dict):
            continue
        raw_findings = result_data.get("findings") or []

        for raw_finding_data in raw_findings:
            if not isinstance(raw_finding_data, dict):
                continue

            # Parse raw finding permissively
            try:
                raw_finding = RawFinding(**raw_finding_data)
            except (ValidationError, TypeError) as exc:
                logger.warning(
                    "[oscal_parser] Skipping malformed finding entry: %s", exc
                )
                continue

            # Normalise target-id hyphenation
            target_data = raw_finding.target
            control_id = (
                target_data.get("target-id")
                or target_data.get("target_id")
                or ""
            )
            status_data = target_data.get("status", {})
            state = status_data.get("state", "") if isinstance(status_data, dict) else ""

            safety_rate_str   = _get_prop(raw_finding.props, "safety_rate")
            evidence_age_str  = _get_prop(raw_finding.props, "evidence_age_seconds")

            candidate: dict[str, Any] = {
                "control_id": control_id,
                "result":     _map_state(state),
                "finding_id": raw_finding.uuid,
                "remarks":    (
                    raw_finding.remarks
                    or raw_finding.description
                    or raw_finding.title
                ),
                "safety_rate":    float(safety_rate_str)  if safety_rate_str  is not None else None,
                "evidence_age_s": float(evidence_age_str) if evidence_age_str is not None else None,
            }

            # Strict validation before inclusion
            try:
                validated = OscalFinding(**candidate)
            except ValidationError as exc:
                logger.warning(
                    "[oscal_parser] Skipping finding %s (%s) — validation error: %s",
                    raw_finding.uuid, control_id, exc,
                )
                continue

            findings.append(validated)

    if not findings:
        raise ValueError(
            "[oscal_parser] Parsed OSCAL document but extracted zero valid findings."
        )

    logger.info("[oscal_parser] Extracted %d findings deterministically.", len(findings))
    return findings
