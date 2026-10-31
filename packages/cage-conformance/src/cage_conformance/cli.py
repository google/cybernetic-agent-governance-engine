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

"""``cage-conformance``: verify exported traces and evidence streams.

    cage-conformance verify --trace events.jsonl [provenance options]
    cage-conformance verify --stream evidence.jsonl [stream options] [provenance options]
    cage-conformance verify-report report.json

Every identity field is required and has no default, so a report never claims
an identity the runner did not state. Exit codes: ``verify`` returns 0 if
conformant, 1 if not, 2 on unreadable input or bad arguments. ``verify-report``
returns 0 for a valid report and 2 for an invalid one.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .report import (
    MODE_PROFILES,
    AdapterUnderTest,
    ConformanceReport,
    InputDigest,
    ReportError,
    RunnerProvenance,
    build_provenance,
    validate_report,
)
from .runner import iter_stream_records, iter_trace_events, verify_stream, verify_trace

Loader = Callable[[TextIO, str], Iterator[dict[str, Any]]]


def _read(
    paths: list[Path], loader: Loader
) -> tuple[list[dict[str, Any]], tuple[InputDigest, ...]]:
    """Parse every input and digest its bytes, recording file names, not paths."""
    items: list[dict[str, Any]] = []
    inputs: list[InputDigest] = []
    for path in paths:
        if str(path) == "-":
            name, source, data = "<stdin>", "<stdin>", sys.stdin.buffer.read()
        else:
            name, source, data = path.name, str(path), path.read_bytes()
        inputs.append(InputDigest.of_bytes(name, data))
        # newline=None reads universal newlines, as open() does.
        text = io.StringIO(data.decode("utf-8"), newline=None)
        items.extend(loader(text, source))
    return items, tuple(inputs)


def _add_verify_parser(subparsers: argparse._SubParsersAction) -> None:
    verify = subparsers.add_parser(
        "verify", help="Check a GOVERNANCE_TRACE export or an evidence stream"
    )
    target = verify.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--trace",
        nargs="+",
        type=Path,
        metavar="JSONL",
        help="GOVERNANCE_TRACE events in emission order ('-' reads stdin)",
    )
    target.add_argument(
        "--stream",
        nargs="+",
        type=Path,
        metavar="JSONL",
        help="cage-audit/3.0 evidence stream records in order ('-' reads stdin)",
    )

    stream = verify.add_argument_group("stream options")
    stream.add_argument(
        "--expected-thresholds-digest",
        default=None,
        help="Expected 64-hex governance thresholds digest",
    )
    stream.add_argument(
        "--expected-refusal-hash",
        action="append",
        default=[],
        help="Refusal proof_hash that must appear on the stream (repeatable)",
    )
    stream.add_argument(
        "--expected-refusal-count",
        type=int,
        default=None,
        help="Minimum number of distinct refusal decisions on the stream",
    )
    stream.add_argument(
        "--publish-failures",
        type=int,
        default=0,
        help="Observed evidence publish failure count (fails if non-zero)",
    )
    stream.add_argument(
        "--require-thresholds-loaded",
        action="store_true",
        help="Require a GOVERNANCE_THRESHOLDS_LOADED record",
    )
    stream.add_argument(
        "--require-settled",
        action="store_true",
        help="Require every CBF_COMMIT to be confirmed or rolled back",
    )

    provenance = verify.add_argument_group("provenance (all required)")
    provenance.add_argument("--provider-id", required=True)
    provenance.add_argument("--adapter-author-org", required=True)
    provenance.add_argument("--counterparty-org", required=True)
    provenance.add_argument("--adapter-version", required=True)
    provenance.add_argument("--adapter-commit", required=True)
    provenance.add_argument("--runner-org", required=True)
    provenance.add_argument("--runner-identity", required=True)
    verify.add_argument(
        "--output", type=Path, default=None, help="Write the JSON report here"
    )


def _verify(args: argparse.Namespace) -> int:
    mode = "trace" if args.trace else "stream"
    adapter = AdapterUnderTest(
        provider_id=args.provider_id,
        adapter_author_org=args.adapter_author_org,
        counterparty_org=args.counterparty_org,
        adapter_version=args.adapter_version,
        adapter_commit=args.adapter_commit,
        contract_profile=MODE_PROFILES[mode],
    )
    runner = RunnerProvenance(
        runner_org=args.runner_org,
        runner_identity=args.runner_identity,
        cage_conformance_version=__version__,
        timestamp_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    provenance = build_provenance(adapter, runner)
    if args.trace:
        events, inputs = _read(args.trace, iter_trace_events)
        report = verify_trace(events, provenance=provenance, inputs=inputs)
    else:
        records, inputs = _read(args.stream, iter_stream_records)
        report = verify_stream(
            records,
            provenance=provenance,
            inputs=inputs,
            expected_thresholds_digest=args.expected_thresholds_digest,
            expected_refusal_hashes=args.expected_refusal_hash,
            expected_refusal_count=args.expected_refusal_count,
            publish_failures=args.publish_failures,
            require_thresholds_loaded=args.require_thresholds_loaded,
            require_settled=args.require_settled,
        )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    _print(report)
    return 0 if report.conformant else 1


def _print(report: ConformanceReport) -> None:
    prov = report.provenance
    subject = prov.adapter_under_test
    status = "CONFORMANT" if report.conformant else "NOT CONFORMANT"
    print(f"cage-conformance {report.mode}: {status}")
    for item in report.inputs:
        print(f"  input:    {item.name} sha256:{item.sha256}")
    print(f"  checked:  {report.checked}")
    print(
        f"  subject:  {subject.provider_id} @ {subject.adapter_commit} "
        f"(author {subject.adapter_author_org}, counterparty {subject.counterparty_org})"
    )
    print(f"  runner:   {prov.runner.runner_identity} ({prov.runner.runner_org})")
    print(f"  posture:  {prov.verification_posture.value}")
    print(f"  digest:   {report.digest()}")
    for assertion in report.assertions:
        mark = "PASS" if assertion.passed else "FAIL"
        print(f"  [{mark}] {assertion.assertion_id}: {assertion.title}")
        if not assertion.passed and assertion.detail:
            print(f"         {assertion.detail}")


def _verify_report(args: argparse.Namespace) -> int:
    report = validate_report(json.loads(args.report.read_text(encoding="utf-8")))
    print(
        f"valid report: mode={report.mode} conformant={report.conformant} "
        f"posture={report.provenance.verification_posture.value} "
        f"digest={report.digest()}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cage-conformance",
        description="Verify CAGE governance traces and evidence streams",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_verify_parser(subparsers)
    report_parser = subparsers.add_parser(
        "verify-report", help="Check a report's integrity and derived posture"
    )
    report_parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-report":
            return _verify_report(args)
        return _verify(args)
    except (OSError, ValueError) as exc:
        # ReportError and JSONDecodeError are ValueErrors.
        kind = "invalid report" if isinstance(exc, ReportError) else "error"
        print(f"{kind}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
