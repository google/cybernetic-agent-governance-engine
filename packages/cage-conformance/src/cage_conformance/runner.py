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

import copy
import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, TextIO

from .report import (
    ENDPOINT_PROFILES,
    AssertionResult,
    ConformanceReport,
    InputDigest,
    Provenance,
    ReportError,
)
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
    "reconciliation_fence": "Every reconciliation fence event or refusal follows a hash-chained RECONCILIATION_DISCREPANCY_FENCE cause record",
}

INPUT_ASSERTION = "input"
_MAX_DETAILS = 50
_VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
_PROFILE_VECTOR_FILES: Mapping[str, str] = MappingProxyType(
    {
        "substrate-v1": "substrate_v1.json",
        "provider-01-v0.2": "provider_01_v02.json",
    }
)
_SHA256_LOWER_RE = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_01_OFFSET_FIELDS: tuple[tuple[str, str], ...] = (
    ("mandate_valid_until_offset_seconds", "mandate_valid_until"),
    ("screening_captured_at_offset_seconds", "screening_captured_at"),
    ("requested_execution_time_offset_seconds", "requested_execution_time"),
)


@dataclass(frozen=True)
class HttpResponse:
    """One HTTP response captured during live endpoint verification."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


HttpRequester = Callable[
    [str, str, Mapping[str, str], bytes | None, float], HttpResponse
]


def _validate_http_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"endpoint URL must use http:// or https:// with a host, got {url!r}"
        )


def http_request(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None = None,
    timeout_s: float = 15.0,
) -> HttpResponse:
    """Stdlib HTTP requester with strict scheme validation (Bandit B310)."""
    _validate_http_url(url)
    request = urllib.request.Request(
        url=url,
        data=body,
        headers=dict(headers),
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(  # nosec B310  # http(s):// scheme validated in _validate_http_url
            request, timeout=timeout_s
        ) as resp:
            return HttpResponse(
                status_code=int(resp.status),
                headers=dict(resp.headers.items()),
                body=resp.read(),
            )
    except urllib.error.HTTPError as exc:
        err_body = exc.read() if exc.fp is not None else b""
        err_headers = dict(exc.headers.items()) if exc.headers is not None else {}
        return HttpResponse(
            status_code=int(exc.code),
            headers=err_headers,
            body=err_body,
        )


def _json_lines(stream: TextIO, source: str) -> Iterator[Any]:
    for number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{number}: {exc}") from exc


def iter_trace_events(stream: TextIO, source: str) -> Iterator[dict[str, Any]]:
    """``GOVERNANCE_TRACE`` events from JSONL or a ``trace-v1`` vector bundle.

    Lines of any other type are skipped, as ``scripts/check_trace_conformance.py``
    does. Events must be in emission order for the seal-join rules.
    """
    raw = stream.read()
    stripped = raw.lstrip()
    if stripped.startswith("{") and "\n" in stripped:
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("conformant_trace"), list):
            for item in doc["conformant_trace"]:
                if isinstance(item, dict) and item.get("type") == TRACE_EVENT_TYPE:
                    yield item
            return
    for record in _json_lines(io.StringIO(raw), source):
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


def _load_profile_vectors(profile: str) -> tuple[InputDigest, dict[str, Any]]:
    if profile not in _PROFILE_VECTOR_FILES:
        raise ReportError(
            f"contract_profile {profile!r} is not an endpoint profile "
            f"{list(ENDPOINT_PROFILES)}"
        )
    filename = _PROFILE_VECTOR_FILES[profile]
    vector_path = _VECTORS_DIR / filename
    raw = vector_path.read_bytes()
    return InputDigest.of_bytes(filename, raw), json.loads(raw.decode("utf-8"))


def _run_substrate_v1(
    base_url: str,
    headers: Mapping[str, str],
    vectors: Mapping[str, Any],
    requester: HttpRequester,
    timeout_s: float,
) -> tuple[int, tuple[AssertionResult, ...]]:
    checks = vectors.get("checks", [])
    assertions: list[AssertionResult] = []
    passed_payloads: dict[str, Mapping[str, Any]] = {}
    root = base_url.rstrip("/")

    for check in checks:
        cid = str(check["id"])
        title = str(check["title"])
        method = str(check.get("method", "GET")).upper()
        path = str(check["path"])
        expected_status = int(check.get("expected_status", 200))
        url = f"{root}/{path.lstrip('/')}"

        try:
            resp = requester(method, url, headers, None, timeout_s)
        except Exception as exc:
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=title,
                    passed=False,
                    detail=f"request error: {exc}",
                )
            )
            continue

        if resp.status_code != expected_status:
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=title,
                    passed=False,
                    detail=f"expected HTTP {expected_status}, got {resp.status_code}",
                )
            )
            continue

        try:
            payload = resp.json()
        except Exception as exc:
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=title,
                    passed=False,
                    detail=f"response body is not valid JSON: {exc}",
                )
            )
            continue

        if not isinstance(payload, Mapping):
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=title,
                    passed=False,
                    detail="response body must be a JSON object",
                )
            )
            continue

        failures: list[str] = []
        for key in check.get("required_keys", []):
            if key not in payload:
                failures.append(f"missing required key {key!r}")
        for key in check.get("sha256_hex_keys", []):
            value = payload.get(key)
            if not isinstance(value, str) or not _SHA256_LOWER_RE.match(value):
                failures.append(
                    f"key {key!r} must be a 64-character lowercase hex SHA-256 digest"
                )
        for key in check.get("list_keys", []):
            value = payload.get(key)
            if not isinstance(value, list):
                failures.append(f"key {key!r} must be a JSON array")
        matches_check = check.get("matches_check")
        if isinstance(matches_check, str) and matches_check:
            ref_payload = passed_payloads.get(matches_check)
            if ref_payload is None:
                failures.append(
                    f"cannot compare against {matches_check}: reference check did not pass"
                )
            else:
                for key in check.get("match_keys", []):
                    if payload.get(key) != ref_payload.get(key):
                        failures.append(f"key {key!r} does not match {matches_check}")

        if not failures:
            passed_payloads[cid] = payload

        assertions.append(
            AssertionResult(
                assertion_id=cid,
                title=title,
                passed=not failures,
                detail="; ".join(failures)
                if failures
                else f"HTTP {resp.status_code} OK",
            )
        )

    return len(checks), tuple(assertions)


def _iso_utc(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _extract_provider_01_receipt_id(body: Mapping[str, Any]) -> str:
    raw_receipt = body.get("authority_receipt")
    if isinstance(raw_receipt, Mapping):
        nested_id = raw_receipt.get("id")
        if isinstance(nested_id, str) and nested_id.strip():
            return nested_id.strip()
    top_level = body.get("authority_receipt_id")
    if isinstance(top_level, str) and top_level.strip():
        return top_level.strip()
    return ""


def _extract_provider_01_record_id(body: Mapping[str, Any]) -> str:
    raw = body.get("authority_record_id")
    return raw.strip() if isinstance(raw, str) else ""


def _build_provider_01_request_body(
    base_template: Mapping[str, Any],
    default_offsets: Mapping[str, Any],
    vec: Mapping[str, Any],
    *,
    now_utc: datetime,
    run_suffix: str,
) -> dict[str, Any]:
    if "request_body" in vec:
        raw_body = vec["request_body"]
        if not isinstance(raw_body, Mapping):
            raise ReportError("wire vector request_body must be a JSON object")
        return copy.deepcopy(dict(raw_body))

    vid_slug = str(vec["id"]).lower().replace("_", "-")
    req_body = copy.deepcopy(dict(base_template))
    raw_overrides = vec.get("request_overrides", {})
    overrides = dict(raw_overrides) if isinstance(raw_overrides, Mapping) else {}
    offsets = dict(default_offsets)

    for offset_key, target_field in _PROVIDER_01_OFFSET_FIELDS:
        if offset_key in overrides:
            offsets[offset_key] = int(overrides.pop(offset_key))
        elif target_field in overrides:
            offsets.pop(offset_key, None)

    execution_pinned = "execution_id" in overrides
    scenario_pinned = "scenario_id" in overrides
    evidence_pinned = "evidence_references" in overrides

    req_body.update(overrides)

    for offset_key, target_field in _PROVIDER_01_OFFSET_FIELDS:
        if offset_key in offsets:
            delta = timedelta(seconds=int(offsets[offset_key]))
            req_body[target_field] = _iso_utc(now_utc + delta)

    if not execution_pinned and isinstance(req_body.get("execution_id"), str):
        req_body["execution_id"] = f"{req_body['execution_id']}-{vid_slug}-{run_suffix}"
    if not scenario_pinned and isinstance(req_body.get("scenario_id"), str):
        req_body["scenario_id"] = f"{req_body['scenario_id']}-{vid_slug}-{run_suffix}"
    if not evidence_pinned and isinstance(req_body.get("execution_id"), str):
        req_body["evidence_references"] = [
            {
                "type": "governance_decision",
                "uri": f"cer://{req_body['execution_id']}",
            }
        ]

    return req_body


def _evaluate_provider_01_response(
    vec: Mapping[str, Any],
    resp: HttpResponse,
    body: Any,
) -> tuple[bool, str]:
    expected_status = int(vec["expected_status"])
    if expected_status != 200:
        has_decision = isinstance(body, Mapping) and "decision" in body
        passed = (
            resp.status_code == expected_status
            and isinstance(body, Mapping)
            and not has_decision
        )
        detail = (
            f"status={resp.status_code} expected_status={expected_status} "
            f"has_decision={has_decision}"
        )
        return passed, detail

    if not isinstance(body, Mapping):
        return False, f"status={resp.status_code} non_object_body"

    expected_decision = vec.get("expected_decision")
    decision = body.get("decision")
    record_id = _extract_provider_01_record_id(body)
    receipt_id = _extract_provider_01_receipt_id(body)
    requires_record = bool(vec.get("requires_authority_record_id", False))
    requires_receipt = bool(vec.get("requires_authority_receipt", False))

    passed = (
        resp.status_code == 200
        and isinstance(decision, str)
        and decision == expected_decision
        and (not requires_record or bool(record_id))
        and (not requires_receipt or bool(receipt_id))
    )
    detail = (
        f"status={resp.status_code} decision={decision!r} "
        f"authority_record_id={record_id or None!r} "
        f"receipt_id={receipt_id or None!r}"
    )
    return passed, detail


def _run_provider_01_v02(
    base_url: str,
    headers: Mapping[str, str],
    vectors: Mapping[str, Any],
    requester: HttpRequester,
    timeout_s: float,
) -> tuple[int, tuple[AssertionResult, ...]]:
    base_template = dict(vectors["base_request_template"])
    raw_offsets = vectors.get("default_offsets", {})
    default_offsets = dict(raw_offsets) if isinstance(raw_offsets, Mapping) else {}
    raw_path = str(vectors.get("default_validate_path", "/cage/validate")).strip()
    validate_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
    trimmed = base_url.rstrip("/")
    validate_url = (
        trimmed if trimmed.endswith(validate_path) else f"{trimmed}{validate_path}"
    )
    post_headers = {**headers, "Content-Type": "application/json"}

    now_utc = datetime.now(timezone.utc)
    run_suffix = uuid.uuid4().hex[:12]
    sent_requests: dict[str, bytes] = {}
    passed_bodies: dict[str, Mapping[str, Any]] = {}
    assertions: list[AssertionResult] = []

    for vec in vectors.get("wire_vectors", []):
        vid = str(vec["id"])
        title = str(vec["title"])
        replay_of = vec.get("replay_of")

        if isinstance(replay_of, str) and replay_of:
            if replay_of not in passed_bodies or replay_of not in sent_requests:
                assertions.append(
                    AssertionResult(
                        assertion_id=vid,
                        title=title,
                        passed=False,
                        detail=f"skipped: {replay_of} did not return a valid ALLOW receipt",
                    )
                )
                continue
            raw_req = sent_requests[replay_of]
        else:
            req_body = _build_provider_01_request_body(
                base_template,
                default_offsets,
                vec,
                now_utc=now_utc,
                run_suffix=run_suffix,
            )
            raw_req = json.dumps(req_body, sort_keys=True).encode("utf-8")
            sent_requests[vid] = raw_req

        try:
            resp = requester("POST", validate_url, post_headers, raw_req, timeout_s)
            body = resp.json()
        except Exception as exc:
            assertions.append(
                AssertionResult(
                    assertion_id=vid,
                    title=title,
                    passed=False,
                    detail=f"request error: {exc}",
                )
            )
            continue

        passed, detail = _evaluate_provider_01_response(vec, resp, body)
        if passed and isinstance(body, Mapping):
            passed_bodies[vid] = body
        if isinstance(replay_of, str) and replay_of in passed_bodies:
            first_receipt = _extract_provider_01_receipt_id(passed_bodies[replay_of])
            replay_receipt = (
                _extract_provider_01_receipt_id(body)
                if isinstance(body, Mapping)
                else ""
            )
            detail = (
                f"{detail} first_receipt_id={first_receipt or None!r} "
                f"replay_receipt_id={replay_receipt or None!r}"
            )
        assertions.append(
            AssertionResult(
                assertion_id=vid,
                title=title,
                passed=passed,
                detail=detail,
            )
        )

    return len(assertions), tuple(assertions)


def verify_endpoint(
    endpoint_url: str,
    *,
    profile: str,
    provenance: Provenance,
    api_key: str | None = None,
    gcp_id_token: str | None = None,
    timeout_s: float = 15.0,
    http_requester: HttpRequester = http_request,
) -> ConformanceReport:
    """Verify a live HTTP endpoint against an endpoint contract profile."""
    _validate_http_url(endpoint_url)
    input_digest, vectors = _load_profile_vectors(profile)

    headers: dict[str, str] = {"Accept": "application/json"}
    if profile == "provider-01-v0.2":
        if gcp_id_token:
            headers["X-Serverless-Authorization"] = f"Bearer {gcp_id_token}"
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    else:
        if gcp_id_token:
            headers["Authorization"] = f"Bearer {gcp_id_token}"
        if api_key:
            headers["X-API-Key"] = api_key

    if profile == "substrate-v1":
        checked, assertions = _run_substrate_v1(
            endpoint_url, headers, vectors, http_requester, timeout_s
        )
    elif profile == "provider-01-v0.2":
        checked, assertions = _run_provider_01_v02(
            endpoint_url, headers, vectors, http_requester, timeout_s
        )
    else:  # pragma: no cover - guarded by _load_profile_vectors
        raise ReportError(
            f"contract_profile {profile!r} is not an endpoint profile "
            f"{list(ENDPOINT_PROFILES)}"
        )

    return ConformanceReport(
        mode="endpoint",
        inputs=(input_digest,),
        checked=checked,
        provenance=provenance,
        assertions=assertions,
    )
