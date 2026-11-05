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
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Optional, TextIO

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


@dataclass(frozen=True)
class HttpResponse:
    """One HTTP response captured during live endpoint verification."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


HttpRequester = Callable[
    [str, str, Mapping[str, str], Optional[bytes], float], HttpResponse
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
    body: Optional[bytes] = None,
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
        with urllib.request.urlopen(request, timeout=timeout_s) as resp:  # nosec B310
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


def _validate_strict_response_schema(
    body: Mapping[str, Any], *, max_clock_skew_seconds: int = 300
) -> Optional[str]:
    """Validate a provider_01 v0.2 receipt against strict hash and timestamp rules."""
    for field_name in ("policy_pack_hash", "Canonical_payload_hash"):
        val = body.get(field_name)
        if not isinstance(val, str) or not _SHA256_LOWER_RE.match(val):
            return "INVALID_SHA256_HEX"

    evaluated_at = body.get("evaluated_at")
    if not isinstance(evaluated_at, str):
        return "MISSING_EVALUATED_AT"
    try:
        eval_dt = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    except ValueError:
        return "INVALID_TIMESTAMP_FORMAT"

    now_utc = datetime.now(timezone.utc)
    if eval_dt > now_utc + timedelta(seconds=max_clock_skew_seconds):
        return "FUTURE_TIMESTAMP_SKEW"
    return None


def _bind_consequence(verdict: str, *, signature_valid: bool = True) -> str:
    """Bind a normative verdict and signature status to the gateway enforcement action."""
    if not signature_valid:
        return "FAIL_CLOSED_ABORT"
    mapping = {
        "ALLOW": "EXECUTE",
        "ESCALATE": "HOLD_FOR_APPROVAL",
        "DENY": "ABORT",
    }
    return mapping.get(verdict, "FAIL_CLOSED_ABORT")


def _run_substrate_v1(
    base_url: str,
    headers: Mapping[str, str],
    vectors: Mapping[str, Any],
    requester: HttpRequester,
    timeout_s: float,
) -> tuple[int, tuple[AssertionResult, ...]]:
    checks = vectors.get("checks", [])
    assertions: list[AssertionResult] = []
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

        assertions.append(
            AssertionResult(
                assertion_id=cid,
                title=title,
                passed=not failures,
                detail="; ".join(failures) if failures else f"HTTP {resp.status_code} OK",
            )
        )

    return len(checks), tuple(assertions)


def _run_provider_01_v02(
    base_url: str,
    headers: Mapping[str, str],
    vectors: Mapping[str, Any],
    requester: HttpRequester,
    timeout_s: float,
) -> tuple[int, tuple[AssertionResult, ...]]:
    base_template = dict(vectors["base_request_template"])
    trimmed = base_url.rstrip("/")
    evaluate_url = (
        trimmed if trimmed.endswith("/v1/evaluate") else f"{trimmed}/v1/evaluate"
    )
    post_headers = {**headers, "Content-Type": "application/json"}
    assertions: list[AssertionResult] = []

    for vec in vectors.get("wire_vectors", []):
        vid = str(vec["id"])
        title = str(vec["title"])
        req_body = copy.deepcopy(base_template)
        overrides = vec.get("request_overrides", {})
        for key, value in overrides.items():
            if (
                key == "payload"
                and isinstance(value, Mapping)
                and isinstance(req_body.get("payload"), Mapping)
            ):
                merged_payload = dict(req_body["payload"])
                merged_payload.update(value)
                req_body["payload"] = merged_payload
            else:
                req_body[key] = value

        raw_req = json.dumps(req_body, sort_keys=True).encode("utf-8")
        case1a_passed_body: Optional[Mapping[str, Any]] = None

        try:
            resp = requester("POST", evaluate_url, post_headers, raw_req, timeout_s)
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
            if vid == "CASE-1A":
                assertions.append(
                    AssertionResult(
                        assertion_id="CASE-1B",
                        title="Deterministic receipt on identical request_id replay",
                        passed=False,
                        detail="skipped: CASE-1A did not return a valid ALLOW receipt",
                    )
                )
            continue

        expected_status = int(vec["expected_status"])
        if expected_status == 200:
            schema_err = (
                _validate_strict_response_schema(body)
                if isinstance(body, Mapping)
                else "NON_OBJECT_BODY"
            )
            sig_obj = body.get("signature") if isinstance(body, Mapping) else None
            has_sig = isinstance(sig_obj, Mapping) and bool(sig_obj.get("sig"))
            verdict = body.get("verdict") if isinstance(body, Mapping) else None
            reason_code = body.get("reason_code") if isinstance(body, Mapping) else None
            passed = (
                resp.status_code == 200
                and verdict == vec.get("expected_verdict")
                and reason_code == vec.get("expected_reason_code")
                and schema_err is None
                and (not vec.get("requires_receipt_signature", True) or has_sig)
            )
            detail = (
                f"status={resp.status_code} verdict={verdict} "
                f"reason_code={reason_code} schema_error={schema_err}"
            )
            assertions.append(
                AssertionResult(
                    assertion_id=vid,
                    title=title,
                    passed=passed,
                    detail=detail,
                )
            )
            if vid == "CASE-1A" and passed and isinstance(body, Mapping):
                case1a_passed_body = body
        else:
            error_obj = body.get("error") if isinstance(body, Mapping) else None
            err_code = (
                error_obj.get("code")
                if isinstance(error_obj, Mapping)
                else (body.get("code") if isinstance(body, Mapping) else None)
            )
            passed = (
                resp.status_code == expected_status
                and err_code == vec.get("expected_error_code")
            )
            assertions.append(
                AssertionResult(
                    assertion_id=vid,
                    title=title,
                    passed=passed,
                    detail=f"status={resp.status_code} error_code={err_code}",
                )
            )

        if vid == "CASE-1A":
            if case1a_passed_body is None:
                assertions.append(
                    AssertionResult(
                        assertion_id="CASE-1B",
                        title="Deterministic receipt on identical request_id replay",
                        passed=False,
                        detail="skipped: CASE-1A did not return a valid ALLOW receipt",
                    )
                )
            else:
                try:
                    replay_resp = requester(
                        "POST", evaluate_url, post_headers, raw_req, timeout_s
                    )
                    replay_body = replay_resp.json()
                    replay_ok = (
                        replay_resp.status_code == 200
                        and isinstance(replay_body, Mapping)
                        and replay_body.get("verdict") == "ALLOW"
                        and replay_body.get("receipt_id")
                        == case1a_passed_body.get("receipt_id")
                        and replay_body.get("Canonical_payload_hash")
                        == case1a_passed_body.get("Canonical_payload_hash")
                    )
                    replay_detail = (
                        f"first_receipt_id={case1a_passed_body.get('receipt_id')} "
                        f"replay_receipt_id="
                        f"{replay_body.get('receipt_id') if isinstance(replay_body, Mapping) else None}"
                    )
                except Exception as exc:
                    replay_ok = False
                    replay_detail = f"replay error: {exc}"
                assertions.append(
                    AssertionResult(
                        assertion_id="CASE-1B",
                        title="Deterministic receipt on identical request_id replay",
                        passed=replay_ok,
                        detail=replay_detail,
                    )
                )

    for hvec in vectors.get("hostile_response_vectors", []):
        hid = str(hvec["id"])
        htitle = str(hvec["title"])
        detected = _validate_strict_response_schema(hvec["response"])
        expected_err = str(hvec["expected_error_code"])
        assertions.append(
            AssertionResult(
                assertion_id=hid,
                title=htitle,
                passed=detected == expected_err,
                detail=f"detected_error={detected} expected_error={expected_err}",
            )
        )

    for cvec in vectors.get("consequence_vectors", []):
        cid = str(cvec["id"])
        ctitle = str(cvec["title"])
        if "verdicts" in cvec:
            actual_actions = [_bind_consequence(str(v)) for v in cvec["verdicts"]]
            expected_actions = list(cvec["expected_actions"])
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=ctitle,
                    passed=actual_actions == expected_actions,
                    detail=f"actions={actual_actions}",
                )
            )
        else:
            action = _bind_consequence(
                str(cvec["verdict"]),
                signature_valid=bool(cvec.get("signature_valid", True)),
            )
            assertions.append(
                AssertionResult(
                    assertion_id=cid,
                    title=ctitle,
                    passed=action == cvec["expected_action"],
                    detail=f"action={action}",
                )
            )

    return len(assertions), tuple(assertions)


def verify_endpoint(
    endpoint_url: str,
    *,
    profile: str,
    provenance: Provenance,
    api_key: Optional[str] = None,
    gcp_id_token: Optional[str] = None,
    timeout_s: float = 15.0,
    http_requester: HttpRequester = http_request,
) -> ConformanceReport:
    """Verify a live HTTP endpoint against an endpoint contract profile."""
    _validate_http_url(endpoint_url)
    input_digest, vectors = _load_profile_vectors(profile)

    headers: dict[str, str] = {"Accept": "application/json"}
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
