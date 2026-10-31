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
    cage-conformance audience report.json
    cage-conformance attest report.json --output attested.json [--token-file FILE]
    cage-conformance verify-report report.json [--parties parties.json]

Every identity field is required and has no default, so a report never claims
an identity the runner did not state. ``audience`` prints the audience an OIDC
token must carry to attest a report; ``attest`` verifies such a token (read
from ``--token-file`` or ``$CAGE_CONFORMANCE_OIDC_TOKEN``, never from the
command line) and binds it to the report. Exit codes: ``verify`` returns 0 if
conformant, 1 if not, 2 on unreadable input or bad arguments. ``audience``,
``attest`` and ``verify-report`` return 0 on success and 2 otherwise.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .attestation import (
    OIDC_ENV_VAR,
    AttestationError,
    UnpinnedPartyError,
    attest,
    attested_posture,
    audience_for,
    default_parties,
    fetch_key_set,
    is_attested,
    parse_parties,
    validate_attested_report,
)
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
        "verify",
        help="Check a GOVERNANCE_TRACE export or an evidence stream",
        allow_abbrev=False,
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


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_token(token_file: Path | None) -> str:
    """The OIDC token, from a file or the environment, never from argv."""
    if token_file is not None:
        token = token_file.read_text(encoding="utf-8").strip()
    else:
        token = os.environ.get(OIDC_ENV_VAR, "").strip()
    if not token:
        raise AttestationError(
            f"no OIDC token: pass --token-file or set {OIDC_ENV_VAR}"
        )
    return token


def _audience(args: argparse.Namespace) -> int:
    print(audience_for(validate_report(_load_json(args.report))))
    return 0


def _attest(args: argparse.Namespace) -> int:
    report = validate_report(_load_json(args.report))
    attested = attest(
        report, _read_token(args.token_file), resolve=fetch_key_set, now=time.time()
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(attested.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    identity = attested.identity
    print(f"attested by {identity.principal} ({identity.iss})")
    print(f"  report:   {report.digest()}")
    print("  run verify-report to derive the posture under your party pins")
    return 0


def _verify_report(args: argparse.Namespace) -> int:
    raw = _load_json(args.report)
    if not is_attested(raw):
        report = validate_report(raw)
        print(
            f"valid report (unattested): mode={report.mode} "
            f"conformant={report.conformant} "
            f"posture={report.provenance.verification_posture.value} "
            f"digest={report.digest()}"
        )
        return 0
    parties = (
        parse_parties(_load_json(args.parties)) if args.parties else default_parties()
    )
    attested = validate_attested_report(raw, resolve=fetch_key_set, now=time.time())
    report = attested.report
    posture = attested_posture(
        attested.identity.principal,
        report.provenance.adapter_under_test.contract_profile,
        parties,
    )
    print(
        f"valid attested report: mode={report.mode} conformant={report.conformant} "
        f"posture={posture.value} attested_by={attested.identity.principal} "
        f"digest={report.digest()}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cage-conformance",
        description="Verify CAGE governance traces and evidence streams",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_verify_parser(subparsers)

    audience_parser = subparsers.add_parser(
        "audience",
        help="Print the audience an OIDC token needs to attest a report",
        allow_abbrev=False,
    )
    audience_parser.add_argument("report", type=Path)

    attest_parser = subparsers.add_parser(
        "attest", help="Bind a verified OIDC token to a report", allow_abbrev=False
    )
    attest_parser.add_argument("report", type=Path)
    attest_parser.add_argument("--output", type=Path, required=True)
    attest_parser.add_argument(
        "--token-file",
        type=Path,
        default=None,
        help=f"File holding the OIDC token (default: ${OIDC_ENV_VAR})",
    )

    report_parser = subparsers.add_parser(
        "verify-report",
        help="Check a report's integrity and derived posture",
        allow_abbrev=False,
    )
    report_parser.add_argument("report", type=Path)
    report_parser.add_argument(
        "--parties",
        type=Path,
        default=None,
        help="Your party pins for attested reports (default: the package's)",
    )

    args = parser.parse_args(argv)
    commands = {
        "verify": _verify,
        "audience": _audience,
        "attest": _attest,
        "verify-report": _verify_report,
    }
    try:
        return commands[args.command](args)
    except (OSError, ValueError) as exc:
        # ReportError, AttestationError and JSONDecodeError are ValueErrors.
        if isinstance(exc, UnpinnedPartyError):
            kind = "no verified posture"
        elif isinstance(exc, ReportError):
            kind = "invalid report"
        else:
            kind = "error"
        print(f"{kind}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
