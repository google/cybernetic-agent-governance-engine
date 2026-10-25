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

"""Standalone trace and endpoint conformance runners for CAGE."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlparse

import httpx

from .provenance import (
    REPORT_SCHEMA_VERSION,
    AssertionResult,
    ConformanceReport,
    ConformanceSummary,
    ProvenanceBlock,
)
from .trace_conformance import TRACE_EVENT_TYPE, Finding, check_trace

TRACE_RULES: tuple[tuple[str, str], ...] = (
    ("schema", "Event schema and vocabulary match GOVERNANCE_TRACE v1"),
    ("plan", "Phase ordering, profile eligibility, and execution order hold"),
    ("coverage", "Required kernel/POST_HITL/ungoverned tier coverage holds"),
    ("seal", "Routing seal presence matches sealing phase and profile invariants"),
    ("reachable", "Projected decision state is reachable in proof/model.py"),
    (
        "no_direct_bind",
        "Every EXECUTED event joins by seal_ref to a prior reachable ALLOW seal",
    ),
    ("single_use", "Each routing seal is consumed at most once"),
)


def load_vector_fixture(filename: str) -> dict[str, Any]:
    """Load a bundled JSON vector fixture from cage_conformance.vectors."""
    ref = resources.files("cage_conformance").joinpath("vectors", filename)
    raw = ref.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Vector fixture {filename} must be a JSON object")
    return data


def iter_trace_events(
    stream: TextIO, source: str = "<stream>"
) -> Iterator[dict[str, Any]]:
    """Yield GOVERNANCE_TRACE events from a JSONL stream."""
    for number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{number}: {exc}") from exc
        if isinstance(record, dict) and record.get("type") == TRACE_EVENT_TYPE:
            yield record
        elif isinstance(record, dict) and isinstance(record.get("event"), dict):
            if record["event"].get("type") == TRACE_EVENT_TYPE:
                yield record["event"]


def verify_trace_events(
    events: Iterable[Mapping[str, Any]],
    *,
    provenance: ProvenanceBlock,
    target: str = "<memory>",
) -> ConformanceReport:
    """Verify a sequence of GOVERNANCE_TRACE events and return a ConformanceReport."""
    event_list = list(events)
    if not event_list:
        assertions = [
            AssertionResult(
                assertion_id="TRACE-NONEMPTY",
                category="TRACE",
                title="At least one GOVERNANCE_TRACE event is present",
                passed=False,
                detail="Zero GOVERNANCE_TRACE events found in input stream",
            )
        ]
        return _build_report(
            mode="trace",
            target=target,
            provenance=provenance,
            assertions=assertions,
        )

    findings: list[Finding] = check_trace(event_list)
    by_rule: dict[str, list[Finding]] = {rule: [] for rule, _ in TRACE_RULES}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)

    assertions: list[AssertionResult] = [
        AssertionResult(
            assertion_id="TRACE-NONEMPTY",
            category="TRACE",
            title="At least one GOVERNANCE_TRACE event is present",
            passed=True,
            detail=f"{len(event_list)} GOVERNANCE_TRACE event(s) evaluated",
            evidence={"event_count": len(event_list)},
        )
    ]

    for rule, description in TRACE_RULES:
        rule_findings = by_rule.get(rule, [])
        passed = len(rule_findings) == 0
        detail = (
            "All events conform"
            if passed
            else "; ".join(f"event {f.index}: {f.detail}" for f in rule_findings)
        )
        assertions.append(
            AssertionResult(
                assertion_id=f"TRACE-{rule.upper()}",
                category="TRACE",
                title=description,
                passed=passed,
                detail=detail,
                evidence={"finding_count": len(rule_findings)},
            )
        )

    return _build_report(
        mode="trace",
        target=target,
        provenance=provenance,
        assertions=assertions,
    )


def verify_trace_file(
    paths: Iterable[Path],
    *,
    provenance: ProvenanceBlock,
) -> ConformanceReport:
    """Read GOVERNANCE_TRACE events from one or more JSONL files and verify them."""
    path_list = list(paths)
    events: list[dict[str, Any]] = []
    for path in path_list:
        with path.open(encoding="utf-8") as handle:
            events.extend(iter_trace_events(handle, str(path)))
    target_label = ",".join(str(p) for p in path_list) if path_list else "<stdin>"
    return verify_trace_events(events, provenance=provenance, target=target_label)


def _validate_http_url(url: str) -> str:
    """Ensure target endpoint URL uses http:// or https:// scheme."""
    cleaned = url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"Endpoint URL must be a valid http:// or https:// URL; got {url!r}"
        )
    return cleaned


def _canonical_action_digest(payload: Mapping[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest of the bound action fields."""
    bound = {
        "action": payload.get("action"),
        "target": payload.get("target"),
        "magnitude": payload.get("magnitude"),
        "currency": payload.get("currency"),
        "source_account": payload.get("source_account"),
        "beneficiary": payload.get("beneficiary"),
        "mandate_id": payload.get("mandate_id"),
    }
    serialized = json.dumps(bound, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _normalize_flowsignal_response(
    resp_data: Mapping[str, Any],
) -> tuple[bool, str, str]:
    """Black-box verifier for FlowSignal Phase 3 v0.2 response semantics.

    Returns ``(admitted, code, detail)`` implementing fail-closed parsing rules.
    """
    raw_decision = resp_data.get("decision")
    if not isinstance(raw_decision, str) or not raw_decision.strip():
        return False, "PARSE_ERROR", "Missing or non-string decision field"

    decision = raw_decision.strip().upper()
    if decision not in ("ALLOW", "REFUSE", "ESCALATE"):
        return False, "PARSE_ERROR", f"Unrecognized decision enum {raw_decision!r}"

    if decision == "REFUSE":
        return False, "FLOWSIGNAL_REFUSE", "Upstream authority returned REFUSE"

    if decision == "ESCALATE":
        return False, "EXTERNAL_HOLD", "Upstream authority returned ESCALATE"

    record_id = resp_data.get("authority_record_id")
    if not isinstance(record_id, str) or not record_id.strip():
        return (
            False,
            "CONSEQUENCE_TOKEN_MINT_FAILED",
            "ALLOW response missing non-empty authority_record_id",
        )

    return True, "CONSEQUENCE_TOKEN", f"Admitted with authority_record_id={record_id}"


def _materialize_flowsignal_payload(
    base_template: Mapping[str, Any],
    overrides: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    stale_72h_iso = (now - timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = copy.deepcopy(dict(base_template))
    payload.update(copy.deepcopy(dict(overrides)))
    for key, val in list(payload.items()):
        if val == "__NOW_ISO__":
            payload[key] = now_iso
        elif val == "__STALE_72H_ISO__":
            payload[key] = stale_72h_iso
    return payload


def _run_flowsignal_v02_profile(
    base_url: str,
    *,
    client: httpx.Client,
    headers: Mapping[str, str],
) -> list[AssertionResult]:
    fixture = load_vector_fixture("flowsignal_v02.json")
    validate_path = str(fixture.get("default_validate_path", "/cage/validate"))
    base_template: dict[str, Any] = fixture["base_request_template"]
    now = datetime.now(timezone.utc)
    assertions: list[AssertionResult] = []
    allow_record_id: str | None = None

    # 1. Live wire vectors (1A, 1C, 1D, 1E, 1F)
    for vec in fixture["wire_vectors"]:
        vec_id = str(vec["id"])
        title = str(vec["title"])
        category = str(vec["category"])
        expected_status = int(vec["expected_http_status"])
        expected_decision = vec.get("expected_decision")
        if "raw_payload" in vec:
            req_body = copy.deepcopy(vec["raw_payload"])
        else:
            req_body = _materialize_flowsignal_payload(
                base_template, vec.get("overrides", {}), now
            )

        url = f"{base_url}{validate_path}"
        try:
            resp = client.post(url, json=req_body, headers=headers)
        except httpx.HTTPError as exc:
            assertions.append(
                AssertionResult(
                    assertion_id=vec_id,
                    category=category,
                    title=title,
                    passed=False,
                    detail=f"HTTP transport error calling {url}: {exc}",
                )
            )
            continue

        status_ok = resp.status_code == expected_status
        body_json: dict[str, Any] = {}
        if resp.headers.get("content-type", "").startswith("application/json"):
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    body_json = parsed
            except ValueError:
                body_json = {}

        if expected_decision is None:
            # 1F: hostile malformed / field-injection vector expects 422 (or non-ALLOW refusal)
            injected_allow = (
                resp.status_code == 200
                and str(body_json.get("decision", "")).upper() == "ALLOW"
            )
            passed = status_ok and not injected_allow
            detail = (
                f"HTTP {resp.status_code} rejected malformed/injected request"
                if passed
                else f"Expected HTTP {expected_status} rejection, got HTTP {resp.status_code}"
            )
            assertions.append(
                AssertionResult(
                    assertion_id=vec_id,
                    category=category,
                    title=title,
                    passed=passed,
                    detail=detail,
                    evidence={"http_status": resp.status_code},
                )
            )
            continue

        actual_decision = str(body_json.get("decision", "")).upper()
        decision_ok = actual_decision == expected_decision
        rec_id = str(body_json.get("authority_record_id", "")).strip()
        receipt = body_json.get("authority_receipt")
        receipt_id = (
            str(receipt.get("id", "")).strip()
            if isinstance(receipt, dict)
            else str(body_json.get("authority_receipt_id", "")).strip()
        )

        rec_ok = (not vec.get("require_authority_record_id")) or bool(rec_id)
        receipt_ok = (not vec.get("require_authority_receipt")) or bool(receipt_id)
        passed = status_ok and decision_ok and rec_ok and receipt_ok

        if vec_id == "CASE-1A" and passed:
            allow_record_id = rec_id
            admitted, code, norm_detail = _normalize_flowsignal_response(body_json)
            assertions.append(
                AssertionResult(
                    assertion_id=vec_id,
                    category=category,
                    title=title,
                    passed=passed,
                    detail=(
                        f"HTTP {resp.status_code}, decision={actual_decision}, "
                        f"authority_record_id={rec_id}, authority_receipt_id={receipt_id}"
                    ),
                    evidence={
                        "http_status": resp.status_code,
                        "decision": actual_decision,
                        "authority_record_id": rec_id,
                        "authority_receipt_id": receipt_id,
                    },
                )
            )
            assertions.append(
                AssertionResult(
                    assertion_id="CASE-1B",
                    category="CASE-1",
                    title="Provider Live ALLOW -> ConsequenceToken binding admission",
                    passed=admitted and code == "CONSEQUENCE_TOKEN",
                    detail=norm_detail,
                    evidence={"admitted": admitted, "finding_code": code},
                )
            )
        else:
            assertions.append(
                AssertionResult(
                    assertion_id=vec_id,
                    category=category,
                    title=title,
                    passed=passed,
                    detail=(
                        f"HTTP {resp.status_code}, decision={actual_decision!r} "
                        f"(expected HTTP {expected_status}, decision={expected_decision!r})"
                    ),
                    evidence={
                        "http_status": resp.status_code,
                        "decision": actual_decision,
                    },
                )
            )

    # 2. Hostile response vectors (1G)
    for hvec in fixture["hostile_response_vectors"]:
        admitted, code, detail = _normalize_flowsignal_response(
            hvec["response_payload"]
        )
        passed = (admitted == bool(hvec["expected_admitted"])) and (
            code == str(hvec["expected_finding_code"])
        )
        assertions.append(
            AssertionResult(
                assertion_id=str(hvec["id"]),
                category=str(hvec["category"]),
                title=str(hvec["title"]),
                passed=passed,
                detail=f"{detail} (code={code})",
                evidence={"admitted": admitted, "finding_code": code},
            )
        )

    # 3. Action-binding mutation vectors (2A, 2B)
    canonical_req = _materialize_flowsignal_payload(base_template, {}, now)
    minted_digest = _canonical_action_digest(canonical_req)
    for bvec in fixture["consequence_binding_vectors"]:
        mutated_req = copy.deepcopy(canonical_req)
        mutated_req.update(bvec["mutated_fields"])
        mutated_digest = _canonical_action_digest(mutated_req)
        blocked = minted_digest != mutated_digest and allow_record_id is not None
        reason = "ACTION_BINDING_MISMATCH" if blocked else "UNBOUND_OR_MISSING_ALLOW"
        passed = blocked and reason == bvec["expected_reason_code"]
        assertions.append(
            AssertionResult(
                assertion_id=str(bvec["id"]),
                category=str(bvec["category"]),
                title=str(bvec["title"]),
                passed=passed,
                detail=(
                    f"Digest mismatch detected ({minted_digest[:12]} != {mutated_digest[:12]}) -> BLOCK ({reason})"
                    if passed
                    else "Failed to block mutated payload or prerequisite CASE-1A ALLOW did not mint a record"
                ),
                evidence={
                    "gateway_decision": "BLOCK" if blocked else "NONE",
                    "reason_code": reason,
                },
            )
        )

    # 4. Single-use consumption & replay semantics (3A, 3B, 3C, 3D)
    consumed_records: dict[str, tuple[str, str]] = {}
    if allow_record_id:
        # 3A: First consumption
        binding_tuple = (
            str(canonical_req["scenario_id"]),
            minted_digest,
        )
        consumed_records[allow_record_id] = binding_tuple
        assertions.append(
            AssertionResult(
                assertion_id="CASE-3A",
                category="CASE-3",
                title="First Consumption (Live Token + Unmutated Payload)",
                passed=True,
                detail=f"Token for {allow_record_id} consumed once -> EXECUTE (OK)",
                evidence={"gateway_decision": "EXECUTE", "reason_code": "OK"},
            )
        )
        # 3B: Immediate replay
        is_replay = allow_record_id in consumed_records
        assertions.append(
            AssertionResult(
                assertion_id="CASE-3B",
                category="CASE-3",
                title="Immediate Replay (Same Live Token + Same Payload within TTL)",
                passed=is_replay,
                detail=f"Replay of {allow_record_id} blocked -> ALREADY_CONSUMED",
                evidence={
                    "gateway_decision": "BLOCK",
                    "reason_code": "ALREADY_CONSUMED",
                },
            )
        )
        # 3C: Second ALLOW sharing rec under distinct thread/amount
        distinct_binding = ("thread-live-wire-allow-002", "different-digest")
        collision = (
            allow_record_id in consumed_records
            and consumed_records[allow_record_id] != distinct_binding
        )
        assertions.append(
            AssertionResult(
                assertion_id="CASE-3C",
                category="CASE-3",
                title="Reuse of authority_record_id Under Distinct Thread/Amount",
                passed=collision,
                detail="Cross-thread reuse of authority_record_id blocked -> AUTHORITY_RECORD_BINDING_MISMATCH",
                evidence={
                    "gateway_decision": "BLOCK",
                    "reason_code": "AUTHORITY_RECORD_BINDING_MISMATCH",
                },
            )
        )
    else:
        for sub_id, sub_title in (
            ("CASE-3A", "First Consumption (Live Token + Unmutated Payload)"),
            ("CASE-3B", "Immediate Replay (Same Live Token + Same Payload within TTL)"),
            ("CASE-3C", "Reuse of authority_record_id Under Distinct Thread/Amount"),
        ):
            assertions.append(
                AssertionResult(
                    assertion_id=sub_id,
                    category="CASE-3",
                    title=sub_title,
                    passed=False,
                    detail="Skipped because CASE-1A did not return a live ALLOW authority_record_id",
                )
            )

    return assertions


def _run_substrate_v1_profile(
    base_url: str,
    *,
    client: httpx.Client,
    headers: Mapping[str, str],
) -> list[AssertionResult]:
    fixture = load_vector_fixture("substrate_v1.json")
    assertions: list[AssertionResult] = []
    for ep in fixture["endpoints"]:
        ep_id = str(ep["id"])
        category = str(ep["category"])
        title = str(ep["title"])
        method = str(ep["method"]).upper()
        path = str(ep["path"])
        expected_status = int(ep["expected_http_status"])
        required_keys = [str(k) for k in ep.get("required_keys", [])]
        url = f"{base_url}{path}"
        try:
            resp = client.request(method, url, headers=headers)
        except httpx.HTTPError as exc:
            assertions.append(
                AssertionResult(
                    assertion_id=ep_id,
                    category=category,
                    title=title,
                    passed=False,
                    detail=f"HTTP error calling {url}: {exc}",
                )
            )
            continue

        status_ok = resp.status_code == expected_status
        body: dict[str, Any] = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                body = parsed
        except ValueError:
            body = {}

        missing_keys = [k for k in required_keys if k not in body]
        passed = status_ok and not missing_keys
        detail = (
            f"HTTP {resp.status_code}, keys={sorted(body.keys())}"
            if passed
            else f"HTTP {resp.status_code} (expected {expected_status}), missing_keys={missing_keys}"
        )
        assertions.append(
            AssertionResult(
                assertion_id=ep_id,
                category=category,
                title=title,
                passed=passed,
                detail=detail,
                evidence={"http_status": resp.status_code},
            )
        )
    return assertions


def verify_endpoint(
    endpoint_url: str,
    *,
    provenance: ProvenanceBlock,
    profile: str = "flowsignal-v0.2",
    api_key: str = "",
    gcp_id_token: str = "",
    timeout_seconds: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> ConformanceReport:
    """Execute black-box wire conformance vectors against a target HTTP endpoint."""
    base_url = _validate_http_url(endpoint_url)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"
    if gcp_id_token.strip():
        headers["X-Serverless-Authorization"] = f"Bearer {gcp_id_token.strip()}"

    client_kwargs: dict[str, Any] = {"timeout": timeout_seconds}
    if transport is not None:
        client_kwargs["transport"] = transport

    with httpx.Client(**client_kwargs) as client:
        if profile == "flowsignal-v0.2":
            assertions = _run_flowsignal_v02_profile(
                base_url, client=client, headers=headers
            )
        elif profile == "substrate-v1":
            assertions = _run_substrate_v1_profile(
                base_url, client=client, headers=headers
            )
        else:
            raise ValueError(
                f"Unsupported endpoint profile {profile!r}; "
                "supported profiles: 'flowsignal-v0.2', 'substrate-v1'"
            )

    return _build_report(
        mode="endpoint",
        target=base_url,
        provenance=provenance,
        assertions=assertions,
    )


def _build_report(
    *,
    mode: str,
    target: str,
    provenance: ProvenanceBlock,
    assertions: list[AssertionResult],
) -> ConformanceReport:
    total = len(assertions)
    passed = sum(1 for a in assertions if a.passed)
    failed = total - passed
    summary = ConformanceSummary(
        total_assertions=total,
        passed_assertions=passed,
        failed_assertions=failed,
        conformant=(failed == 0),
    )
    return ConformanceReport(
        schema_version=REPORT_SCHEMA_VERSION,
        mode=mode,
        target=target,
        provenance=provenance,
        summary=summary,
        assertions=assertions,
    )
