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

"""Reusable conformance verification driver for Advisor + Proxy E2E (POAM-2026-191).

Wraps ``cage_conformance`` (``verify_endpoint``, ``verify_stream``,
``verify_trace``, ``diagnose_receipt``) and ``src.compliance_bridge.evidence_verifier``
(``CustodyVerifier`` with ``kid``-resolved out-of-band trust anchors from
``EVIDENCE_KMS_KEY`` / ``EVIDENCE_TRUST_ANCHORS_FILE``) so both the hermetic PR
gate (``tests/integration/test_advisor_proxy_e2e_invariants.py``) and live GKE
staging W6 runs (``enable_e2e_advisor = true``) evaluate the exact same
18 stream rules, 7 trace rules, ``substrate-v1`` endpoint contract, and WORM
batch custody signature checks.

Security invariants:
- Every URL is validated to use ``http://`` or ``https://`` with a host prior to
  any request (Bandit B310).
- Signing public keys are resolved exclusively out-of-band by ``kid`` (never
  from embedded document fields). Unknown ``kid``s and 1-byte signature
  mutations fail closed.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import sys
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE_SRC = _REPO_ROOT / "packages" / "cage-conformance" / "src"
if str(_PACKAGE_SRC) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_SRC))

from cage_conformance import (  # noqa: E402
    AdapterUnderTest,
    ConformanceReport,
    HttpRequester,
    InputDigest,
    Provenance,
    ReceiptDiagnosis,
    RunnerProvenance,
    build_provenance,
    diagnose_receipt,
    http_request,
    iter_stream_records,
    iter_trace_events,
    validate_report,
    verify_endpoint,
    verify_stream,
    verify_trace,
)
from cage_conformance import (
    __version__ as _CONFORMANCE_VERSION,
)
from cage_conformance.trace_conformance import TRACE_EVENT_TYPE  # noqa: E402

from src.compliance_bridge.evidence_verifier import (  # noqa: E402
    CustodyVerificationReport,
    CustodyVerifier,
    build_attestation_verifier,
    load_evidence_trust_anchors,
)
from src.gateway.governance.evidence.cold_store import EvidenceColdStore  # noqa: E402

DEFAULT_PROVIDER_ID = "cage-advisor-e2e"
DEFAULT_AUTHOR_ORG = "Google LLC"
DEFAULT_COUNTERPARTY_ORG = "CAGE Reference Architecture"
DEFAULT_ADAPTER_VERSION = "3.2.0"
DEFAULT_COMMIT = "0000000"


def validate_http_url(url: str) -> str:
    """Assert ``url`` uses ``http`` or ``https`` with a non-empty host (B310)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"URL must use http:// or https:// with an explicit host, got {url!r}"
        )
    return url


def make_conformance_provenance(
    contract_profile: str,
    *,
    provider_id: str = DEFAULT_PROVIDER_ID,
    adapter_commit: str = DEFAULT_COMMIT,
    runner_identity: str = "advisor-proxy-e2e",
) -> Provenance:
    """Build a valid ``cage-conformance-provenance/1`` block for ``contract_profile``."""
    adapter = AdapterUnderTest(
        provider_id=provider_id,
        adapter_author_org=DEFAULT_AUTHOR_ORG,
        counterparty_org=DEFAULT_COUNTERPARTY_ORG,
        adapter_version=DEFAULT_ADAPTER_VERSION,
        adapter_commit=adapter_commit,
        contract_profile=contract_profile,
    )
    runner = RunnerProvenance(
        runner_org=DEFAULT_AUTHOR_ORG,
        runner_identity=runner_identity,
        cage_conformance_version=_CONFORMANCE_VERSION,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )
    return build_provenance(adapter, runner)


async def export_redis_evidence_stream_jsonl(
    redis_client: Any,
    stream_key: str = "cage:evidence:stream",
) -> tuple[bytes, list[dict[str, Any]]]:
    """Export Redis ``cage-audit/3.0`` stream entries to canonical NDJSON bytes.

    Preserves every signed/hashed ``cage-audit/3.0`` wire header (``schema``,
    ``canonicalization``, ``hash_algorithm``, ``chain_id``, ``trace_id``,
    ``sequence``, ``prev_hash``, ``event_type``, ``control_id``, exact
    ``payload`` string, ``record_hash``, and optional classification headers)
    identically to ``EvidenceCustodian._ndjson`` so ``verify_stream`` recomputes
    every RFC 8785 JCS SHA-256 link hash without re-encoding drift.
    """
    entries = await redis_client.xrange(stream_key, min="-", max="+")
    records: list[dict[str, Any]] = []
    lines: list[str] = []
    for raw_stream_id, raw_fields in entries:
        stream_id = (
            raw_stream_id.decode("utf-8")
            if isinstance(raw_stream_id, bytes)
            else str(raw_stream_id)
        )
        fields: dict[str, Any] = {
            (k.decode("utf-8") if isinstance(k, bytes) else str(k)): (
                v.decode("utf-8") if isinstance(v, bytes) else v
            )
            for k, v in raw_fields.items()
        }
        record: dict[str, Any] = {**fields, "stream_id": stream_id}
        records.append(record)
        lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    body = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    return body, records


def extract_trace_jsonl_from_stream(
    records: Sequence[Mapping[str, Any]],
) -> tuple[bytes, list[dict[str, Any]]]:
    """Extract ``GOVERNANCE_TRACE`` payloads in emission order as JSONL bytes."""
    events: list[dict[str, Any]] = []
    lines: list[str] = []
    for rec in records:
        raw_payload = rec.get("payload_json")
        if raw_payload is None:
            raw_payload = rec.get("payload")
        payload: Any = None
        if isinstance(raw_payload, str):
            try:
                payload = json.loads(raw_payload)
            except json.JSONDecodeError:
                payload = None
        elif isinstance(raw_payload, Mapping):
            payload = raw_payload
        if isinstance(payload, Mapping) and (
            payload.get("type") == TRACE_EVENT_TYPE
            or rec.get("event_type") == TRACE_EVENT_TYPE
        ):
            obj = dict(payload)
            if "type" not in obj:
                obj["type"] = TRACE_EVENT_TYPE
            events.append(obj)
            lines.append(json.dumps(obj, sort_keys=True, separators=(",", ":")))
    body = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    return body, events


def verify_advisor_e2e_endpoint(
    gateway_url: str,
    *,
    profile: str = "substrate-v1",
    http_requester: HttpRequester = http_request,
    adapter_commit: str = DEFAULT_COMMIT,
    timeout_s: float = 15.0,
) -> ConformanceReport:
    """Run ``cage_conformance.verify_endpoint`` against the gateway URL."""
    validate_http_url(gateway_url)
    provenance = make_conformance_provenance(profile, adapter_commit=adapter_commit)
    report = verify_endpoint(
        gateway_url,
        profile=profile,
        provenance=provenance,
        timeout_s=timeout_s,
        http_requester=http_requester,
    )
    validate_report(report.to_dict())
    return report


def verify_live_bridge_health(
    bridge_url: str,
    *,
    http_requester: HttpRequester = http_request,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    """Probe a live compliance-bridge ``/health`` endpoint over HTTP(S) (B310)."""
    base = validate_http_url(bridge_url).rstrip("/")
    resp = http_requester("GET", f"{base}/health", {}, None, timeout_s)
    if resp.status_code != 200:
        raise RuntimeError(
            f"compliance-bridge /health returned HTTP {resp.status_code}"
        )
    body = json.loads(resp.body.decode("utf-8"))
    if not isinstance(body, dict):
        raise RuntimeError("compliance-bridge /health did not return a JSON object")
    return body


def verify_advisor_e2e_stream(
    jsonl_bytes: bytes,
    *,
    input_name: str = "evidence-stream.jsonl",
    expected_thresholds_digest: str | None = None,
    expected_refusal_hashes: Iterable[str] = (),
    expected_refusal_count: int | None = None,
    require_thresholds_loaded: bool = True,
    require_settled: bool = True,
    adapter_commit: str = DEFAULT_COMMIT,
) -> ConformanceReport:
    """Run all 18 ``stream-v1`` invariant checks over exported stream JSONL."""
    records = list(
        iter_stream_records(io.StringIO(jsonl_bytes.decode("utf-8")), input_name)
    )
    provenance = make_conformance_provenance("stream-v1", adapter_commit=adapter_commit)
    report = verify_stream(
        records,
        provenance=provenance,
        inputs=(InputDigest.of_bytes(input_name, jsonl_bytes),),
        expected_thresholds_digest=expected_thresholds_digest,
        expected_refusal_hashes=tuple(expected_refusal_hashes),
        expected_refusal_count=expected_refusal_count,
        require_thresholds_loaded=require_thresholds_loaded,
        require_settled=require_settled,
    )
    validate_report(report.to_dict())
    return report


def verify_advisor_e2e_trace(
    jsonl_bytes: bytes,
    *,
    input_name: str = "governance-trace.jsonl",
    adapter_commit: str = DEFAULT_COMMIT,
) -> ConformanceReport:
    """Run all 7 ``trace-v1`` formal-model checks over ``GOVERNANCE_TRACE`` JSONL."""
    events = list(
        iter_trace_events(io.StringIO(jsonl_bytes.decode("utf-8")), input_name)
    )
    provenance = make_conformance_provenance("trace-v1", adapter_commit=adapter_commit)
    report = verify_trace(
        events,
        provenance=provenance,
        inputs=(InputDigest.of_bytes(input_name, jsonl_bytes),),
    )
    validate_report(report.to_dict())
    return report


async def verify_custodied_archive(
    cold_store: EvidenceColdStore,
    *,
    trust_anchors: dict[str, bytes] | None = None,
    prefix: str = "evidence-stream/",
    require_citable: bool = True,
) -> CustodyVerificationReport:
    """Verify signed WORM batches via out-of-band ``kid`` trust anchors."""
    anchors = load_evidence_trust_anchors() if trust_anchors is None else trust_anchors
    verifier_signer = build_attestation_verifier(anchors)
    verifier = CustodyVerifier(cold_store, verifier_signer, prefix=prefix)
    report = await verifier.verify_all()
    if require_citable:
        report.assert_citable()
    return report


def diagnose_actuation_receipt(
    receipt: Mapping[str, Any], *, input_name: str = "actuation-receipt.json"
) -> ReceiptDiagnosis:
    """Run ``cage_conformance.diagnose_receipt`` structural/preimage diagnosis."""
    return diagnose_receipt(receipt, input_name=input_name)


@dataclass(frozen=True)
class AdvisorE2EConformanceSummary:
    """Combined outcome of endpoint, stream, trace, and WORM custody checks."""

    endpoint_report: ConformanceReport | None
    stream_report: ConformanceReport | None
    trace_report: ConformanceReport | None
    custody_report: CustodyVerificationReport | None = None
    bridge_health: Mapping[str, Any] | None = None

    @property
    def passed(self) -> bool:
        if self.endpoint_report is not None and not self.endpoint_report.conformant:
            return False
        if self.stream_report is not None and not self.stream_report.conformant:
            return False
        if self.trace_report is not None and not self.trace_report.conformant:
            return False
        if self.custody_report is not None and not self.custody_report.citable:
            return False
        if (
            self.endpoint_report is None
            and self.stream_report is None
            and self.trace_report is None
            and self.custody_report is None
            and self.bridge_health is None
        ):
            return False
        return True

    def failed_assertions(self) -> dict[str, list[str]]:
        failures: dict[str, list[str]] = {}
        for label, rep in (
            ("endpoint", self.endpoint_report),
            ("stream", self.stream_report),
            ("trace", self.trace_report),
        ):
            if rep is not None:
                bad = [
                    f"{a.assertion_id}: {a.detail}"
                    for a in rep.assertions
                    if not a.passed
                ]
                if bad:
                    failures[label] = bad
        if self.custody_report is not None and not self.custody_report.citable:
            failures["custody"] = [
                f"{f.key}: {f.reason}" for f in self.custody_report.failures
            ] or ["archive contains no citable signed batches or has gaps"]
        return failures


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="advisor_proxy_conformance",
        description="Verify CAGE Advisor + Inference Proxy E2E conformance artifacts.",
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("CAGE_GATEWAY_URL", ""),
        help="Live gateway HTTP(S) base URL for substrate-v1 verification (default: $CAGE_GATEWAY_URL).",
    )
    parser.add_argument(
        "--bridge-url",
        default=os.environ.get("CAGE_BRIDGE_URL", ""),
        help="Live compliance-bridge HTTP(S) base URL for /health verification (default: $CAGE_BRIDGE_URL).",
    )
    parser.add_argument(
        "--stream-jsonl",
        default="",
        help="Path to exported cage-audit/3.0 evidence stream JSONL (required unless --gateway-url or --bridge-url is supplied).",
    )
    parser.add_argument(
        "--trace-jsonl",
        default="",
        help="Optional separate GOVERNANCE_TRACE JSONL (defaults to extracting from --stream-jsonl).",
    )
    parser.add_argument(
        "--expect-refusal-hash",
        action="append",
        default=[],
        help="Expected lowercase SHA-256 refusal proof hash (repeatable).",
    )
    parser.add_argument(
        "--expect-refusal-count",
        type=int,
        default=None,
        help="Expected count of refusal proof records in the stream.",
    )
    parser.add_argument(
        "--verify-custody",
        action="store_true",
        help="Also verify WORM cold-store custody batches via CustodyVerifier.from_env().",
    )
    parser.add_argument(
        "--adapter-commit",
        default=DEFAULT_COMMIT,
        help="Commit SHA (at least 7 chars) recorded in conformance provenance.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit JSON summary to stdout.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.stream_jsonl and not args.gateway_url and not args.bridge_url:
        parser.error(
            "at least one of --stream-jsonl, --gateway-url, or --bridge-url is required"
        )

    endpoint_report: ConformanceReport | None = None
    if args.gateway_url:
        endpoint_report = verify_advisor_e2e_endpoint(
            args.gateway_url, adapter_commit=args.adapter_commit
        )

    bridge_health: dict[str, Any] | None = None
    if args.bridge_url:
        bridge_health = verify_live_bridge_health(args.bridge_url)

    stream_report: ConformanceReport | None = None
    trace_report: ConformanceReport | None = None
    if args.stream_jsonl:
        stream_path = Path(args.stream_jsonl)
        stream_bytes = stream_path.read_bytes()
        stream_report = verify_advisor_e2e_stream(
            stream_bytes,
            input_name=stream_path.name,
            expected_refusal_hashes=args.expect_refusal_hash,
            expected_refusal_count=args.expect_refusal_count,
            adapter_commit=args.adapter_commit,
        )

        if args.trace_jsonl:
            trace_path = Path(args.trace_jsonl)
            trace_bytes = trace_path.read_bytes()
            trace_name = trace_path.name
        else:
            records = list(
                iter_stream_records(
                    io.StringIO(stream_bytes.decode("utf-8")), stream_path.name
                )
            )
            trace_bytes, _ = extract_trace_jsonl_from_stream(records)
            trace_name = f"{stream_path.stem}.trace.jsonl"

        trace_report = verify_advisor_e2e_trace(
            trace_bytes,
            input_name=trace_name,
            adapter_commit=args.adapter_commit,
        )

    custody_report: CustodyVerificationReport | None = None
    if args.verify_custody:
        verifier = CustodyVerifier.from_env()
        custody_report = asyncio.run(verifier.verify_all())

    summary = AdvisorE2EConformanceSummary(
        endpoint_report=endpoint_report,
        stream_report=stream_report,
        trace_report=trace_report,
        custody_report=custody_report,
        bridge_health=bridge_health,
    )
    if args.emit_json:
        output: dict[str, Any] = {
            "passed": summary.passed,
            "failures": summary.failed_assertions(),
        }
        if stream_report is not None:
            output["stream"] = stream_report.to_dict()
        if trace_report is not None:
            output["trace"] = trace_report.to_dict()
        if endpoint_report is not None:
            output["endpoint"] = endpoint_report.to_dict()
        if bridge_health is not None:
            output["bridge_health"] = bridge_health
        if custody_report is not None:
            output["custody"] = custody_report.to_dict()
        sys.stdout.write(json.dumps(output, indent=2, sort_keys=True) + "\n")
    elif not summary.passed:
        sys.stderr.write(
            json.dumps(summary.failed_assertions(), indent=2, sort_keys=True) + "\n"
        )
    return 0 if summary.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
