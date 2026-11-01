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

"""Run the proof checkers over exported JSONL and turn findings into reports.

``trace_conformance`` and ``stream_invariants`` are byte-identical copies of
the repository's ``proof/`` modules (``scripts/check_conformance_sync.py``
enforces it), so a report here applies exactly the checks CAGE's own test
suite applies. Each report holds one assertion per rule. A finding under a
rule not listed here still fails the report under its own name, and a run
that checked nothing is not conformant.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, TextIO

from .report import AssertionResult, ConformanceReport, InputDigest, Provenance
from .stream_invariants import check_stream
from .trace_conformance import TRACE_EVENT_TYPE, Finding, check_trace

#: Rules ``check_trace`` reports, with what each one requires.
TRACE_RULES: dict[str, str] = {
    "schema": "Every event has the fields and vocabulary of trace schema 1",
    "plan": "Plans run phase 1 before phase 2, and every planned tier runs under the profile",
    "coverage": "Governed runs plan the required kernel tiers; ungoverned runs plan only ungoverned tiers",
    "seal": "A seal is present exactly when the phase seals, and DRY_RUN never seals",
    "reachable": "Every decision projects onto a state the formal model reaches",
    "no_direct_bind": "Every EXECUTED event joins an earlier issued seal that resolves ALLOW",
    "single_use": "No seal is executed more than once",
}

#: Rules ``check_stream`` reports, with what each one requires.
STREAM_RULES: dict[str, str] = {
    "chain_schema": "Every record is a well-formed cage-audit/3.0 record",
    "chain_hash": "Every record_hash is the RFC 8785 SHA-256 link hash of its record",
    "chain_continuity": "Sequences are contiguous and prev_hash links each record to the one before",
    "thresholds": "Decisions are pinned to the loaded governance thresholds digest",
    "decision_schema": "Every GOVERNANCE_DECISION carries schema v2 stage coverage",
    "plan": "Decision plans run phase 1 before phase 2 under the profile",
    "coverage": "Governed decisions plan the required kernel tiers",
    "seal": "A decision seals exactly when its phase seals",
    "reachable": "Every decision projects onto a state the formal model reaches",
    "narrow_reverified": "A NARROW decision's clamped re-run plans and passes every stage",
    "no_direct_bind": "Every consumed seal and actuation binds to an earlier decision",
    "single_use": "Each decision and seal is consumed at most once",
    "cbf_barrier": "No CBF_COMMIT breaches the control barrier",
    "cbf_rollback": "A rollback restores exactly its ledgered cost, once",
    "settlement": "Settlements agree with rollback and actuation records",
    "refusal_evidence": "Every refusal carries a proof hash, expected refusals appear, and a refusal-triggered quarantine follows its refusal",
    "evidence_loss": "No evidence was dropped or failed to publish",
    "digest_format": "Every governance_decision_digest and refusal_proof_hash, at any depth of any record, is lowercase SHA-256 hex",
}

INPUT_ASSERTION = "input"
_MAX_DETAILS = 50


def _json_lines(stream: TextIO, source: str) -> Iterator[Any]:
    for number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{number}: {exc}") from exc


def iter_trace_events(stream: TextIO, source: str) -> Iterator[dict[str, Any]]:
    """``GOVERNANCE_TRACE`` events from JSONL, bare or wrapped in an ``event`` field.

    Lines of any other type are skipped, as ``scripts/check_trace_conformance.py``
    does. Events must be in emission order for the seal-join rules.
    """
    for record in _json_lines(stream, source):
        if not isinstance(record, dict):
            continue
        if record.get("type") == TRACE_EVENT_TYPE:
            yield record
        elif isinstance(record.get("event"), dict):
            if record["event"].get("type") == TRACE_EVENT_TYPE:
                yield record["event"]


def iter_stream_records(stream: TextIO, source: str) -> Iterator[dict[str, Any]]:
    """``cage-audit/3.0`` records from JSONL, one object per line, in stream order."""
    for number, record in enumerate(_json_lines(stream, source), start=1):
        if not isinstance(record, dict):
            raise ValueError(f"{source}:{number}: expected a JSON object")
        yield record


def _where(index: int) -> str:
    return "stream" if index < 0 else f"#{index}"


def _detail(findings: Sequence[Finding]) -> str:
    shown = "; ".join(f"{_where(f.index)}: {f.detail}" for f in findings[:_MAX_DETAILS])
    hidden = len(findings) - _MAX_DETAILS
    return f"{shown}; (+{hidden} more)" if hidden > 0 else shown


def _assertions(
    rules: Mapping[str, str], findings: Iterable[Finding], checked: int, noun: str
) -> tuple[AssertionResult, ...]:
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)
    results = [
        AssertionResult(
            assertion_id=INPUT_ASSERTION,
            title=f"At least one {noun} was checked",
            passed=checked > 0,
            detail="" if checked else f"no {noun}s in the input",
        )
    ]
    for rule, title in rules.items():
        found = by_rule.pop(rule, [])
        results.append(AssertionResult(rule, title, not found, _detail(found)))
    for rule, found in sorted(by_rule.items()):
        results.append(
            AssertionResult(rule, f"Rule {rule!r} (not listed)", False, _detail(found))
        )
    return tuple(results)


def verify_trace(
    events: Sequence[Mapping[str, Any]],
    *,
    provenance: Provenance,
    inputs: Sequence[InputDigest],
) -> ConformanceReport:
    """Check ``GOVERNANCE_TRACE`` events against the formal model."""
    findings = check_trace(events)
    return ConformanceReport(
        mode="trace",
        inputs=tuple(inputs),
        checked=len(events),
        provenance=provenance,
        assertions=_assertions(TRACE_RULES, findings, len(events), "trace event"),
    )


def verify_stream(
    records: Sequence[Mapping[str, Any]],
    *,
    provenance: Provenance,
    inputs: Sequence[InputDigest],
    expected_thresholds_digest: str | None = None,
    expected_refusal_hashes: Iterable[str] = (),
    expected_refusal_count: int | None = None,
    publish_failures: int = 0,
    require_thresholds_loaded: bool = False,
    require_settled: bool = False,
) -> ConformanceReport:
    """Check ``cage-audit/3.0`` records against the five stream invariants."""
    findings = check_stream(
        records,
        expected_thresholds_digest=expected_thresholds_digest,
        expected_refusal_hashes=expected_refusal_hashes,
        expected_refusal_count=expected_refusal_count,
        publish_failures=publish_failures,
        require_thresholds_loaded=require_thresholds_loaded,
        require_settled=require_settled,
    )
    return ConformanceReport(
        mode="stream",
        inputs=tuple(inputs),
        checked=len(records),
        provenance=provenance,
        assertions=_assertions(STREAM_RULES, findings, len(records), "stream record"),
    )
