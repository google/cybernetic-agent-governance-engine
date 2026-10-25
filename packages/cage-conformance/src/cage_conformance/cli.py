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

"""Command-line interface for cage-conformance."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .provenance import (
    AdapterUnderTest,
    ConformanceReport,
    IdentityProofType,
    ProvenanceValidationError,
    RunnerProvenance,
    build_provenance_block,
    inspect_oidc_jwt,
    utc_now_iso,
    validate_conformance_report,
)
from .runner import (
    iter_trace_events,
    verify_endpoint,
    verify_trace_events,
    verify_trace_file,
)

PACKAGE_VERSION = "0.1.0"


def _add_provenance_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--provider-id",
        default="provider_01",
        help="Identifier of the integration or component under test (default: provider_01)",
    )
    parser.add_argument(
        "--adapter-author-org",
        default="Google LLC",
        help="Organization that authored the adapter under test (default: 'Google LLC')",
    )
    parser.add_argument(
        "--counterparty-org",
        default="FlowSignal",
        help="Counterparty organization on the other side of the boundary (default: 'FlowSignal')",
    )
    parser.add_argument(
        "--adapter-version",
        default="0.2.0",
        help="Version of the adapter under test (default: 0.2.0)",
    )
    parser.add_argument(
        "--adapter-commit",
        default="5595a82ef907fec25aec7ccc8ed5832303bd9f26",
        help="Git commit SHA of the adapter under test",
    )
    parser.add_argument(
        "--runner-org",
        default=os.environ.get("CAGE_CONFORMANCE_RUNNER_ORG", ""),
        help="Organization executing this conformance run (default: inferred from OIDC or adapter-author-org)",
    )
    parser.add_argument(
        "--runner-identity",
        default=os.environ.get("CAGE_CONFORMANCE_RUNNER_IDENTITY", ""),
        help="Identity of the runner (default: OIDC sub or current OS user)",
    )
    parser.add_argument(
        "--oidc-token",
        default=os.environ.get("CAGE_CONFORMANCE_OIDC_TOKEN", ""),
        help="Optional OIDC JWT proving runner identity (or set CAGE_CONFORMANCE_OIDC_TOKEN)",
    )
    parser.add_argument(
        "--cage-commit",
        default=os.environ.get("CAGE_COMMIT", "HEAD-standalone"),
        help="CAGE reference commit identifier",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write the JSON conformance report",
    )


def _build_provenance_from_args(
    args: argparse.Namespace,
    *,
    profile: str,
) -> tuple[AdapterUnderTest, RunnerProvenance]:
    oidc_info: dict[str, str] = {}
    if args.oidc_token and args.oidc_token.strip():
        oidc_info = inspect_oidc_jwt(args.oidc_token)

    runner_org = (
        args.runner_org.strip()
        or oidc_info.get("inferred_org", "").strip()
        or args.adapter_author_org.strip()
    )
    runner_identity = (
        args.runner_identity.strip()
        or oidc_info.get("oidc_subject", "").strip()
        or getpass.getuser()
    )
    proof_type = (
        IdentityProofType(oidc_info["identity_proof"])
        if oidc_info
        else IdentityProofType.NONE
    )

    adapter = AdapterUnderTest(
        provider_id=args.provider_id,
        adapter_author_org=args.adapter_author_org,
        counterparty_org=args.counterparty_org,
        adapter_version=args.adapter_version,
        adapter_commit=args.adapter_commit,
        contract_profile=profile,
    )
    runner = RunnerProvenance(
        runner_org=runner_org,
        runner_identity=runner_identity,
        identity_proof=proof_type,
        oidc_issuer=oidc_info.get("oidc_issuer"),
        oidc_subject=oidc_info.get("oidc_subject"),
        oidc_token_sha256=oidc_info.get("oidc_token_sha256"),
        cage_conformance_version=PACKAGE_VERSION,
        cage_commit=args.cage_commit,
        timestamp_utc=utc_now_iso(),
    )
    return adapter, runner


def _emit_report(report: ConformanceReport, output_path: Path | None) -> int:
    payload = report.model_dump(mode="json")
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    posture = report.provenance.verification_posture.value
    status = (
        "CONFORMANT (PASS)" if report.summary.conformant else "NON-CONFORMANT (FAIL)"
    )
    print(f"CAGE Conformance Report [{report.mode}] — {status}")
    print(f"  Target:               {report.target}")
    print(
        f"  Adapter Under Test:   {report.provenance.adapter_under_test.provider_id} "
        f"(author={report.provenance.adapter_under_test.adapter_author_org}, "
        f"counterparty={report.provenance.adapter_under_test.counterparty_org})"
    )
    print(
        f"  Runner Identity:      {report.provenance.runner.runner_identity} "
        f"(org={report.provenance.runner.runner_org}, "
        f"proof={report.provenance.runner.identity_proof.value})"
    )
    print(f"  Verification Posture: {posture}")
    print(
        f"  Assertions:           {report.summary.passed_assertions}/{report.summary.total_assertions} passed"
    )
    for assertion in report.assertions:
        marker = "PASS" if assertion.passed else "FAIL"
        print(f"    [{marker}] {assertion.assertion_id}: {assertion.title}")
        if not assertion.passed and assertion.detail:
            print(f"           -> {assertion.detail}")

    return 0 if report.summary.conformant else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cage-conformance",
        description="Standalone black-box conformance and provenance verifier for CAGE",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. `cage-conformance verify --trace <file> | --endpoint <url>`
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a GOVERNANCE_TRACE JSONL file (--trace) or a live HTTP endpoint (--endpoint)",
    )
    target_group = verify_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--trace",
        type=Path,
        help="Path to JSONL file containing GOVERNANCE_TRACE events (use '-' for stdin)",
    )
    target_group.add_argument(
        "--endpoint",
        type=str,
        help="Base HTTP(S) URL of the partner or gateway endpoint to verify",
    )
    verify_parser.add_argument(
        "--profile",
        default="flowsignal-v0.2",
        help="Conformance contract profile for endpoint mode (default: flowsignal-v0.2)",
    )
    verify_parser.add_argument(
        "--api-key",
        default=os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", ""),
        help="Optional Bearer API key for endpoint authentication",
    )
    verify_parser.add_argument(
        "--gcp-id-token",
        default=os.environ.get("CAGE_NORMATIVE_GCP_ID_TOKEN", ""),
        help="Optional GCP IAM identity token for Cloud Run X-Serverless-Authorization",
    )
    _add_provenance_args(verify_parser)

    # 2. `cage-conformance verify-report <file>`
    report_parser = subparsers.add_parser(
        "verify-report",
        help="Validate a conformance report JSON file and verify its provenance posture",
    )
    report_parser.add_argument(
        "report_file",
        type=Path,
        help="Path to a conformance report JSON file",
    )

    args = parser.parse_args(argv)

    try:
        if args.subcommand == "verify-report":
            raw = json.loads(args.report_file.read_text(encoding="utf-8"))
            validated = validate_conformance_report(raw)
            print(
                f"VALID REPORT: posture={validated.provenance.verification_posture.value} "
                f"independent_of_author={validated.provenance.independent_of_author} "
                f"third_party_independent={validated.provenance.third_party_independent} "
                f"conformant={validated.summary.conformant}"
            )
            return 0

        profile = "trace-v1" if args.trace is not None else args.profile
        adapter, runner = _build_provenance_from_args(args, profile=profile)
        provenance = build_provenance_block(
            adapter_under_test=adapter,
            runner=runner,
        )

        if args.trace is not None:
            if str(args.trace) == "-":
                events = list(iter_trace_events(sys.stdin, "<stdin>"))
                report = verify_trace_events(
                    events, provenance=provenance, target="<stdin>"
                )
            else:
                report = verify_trace_file([args.trace], provenance=provenance)
        else:
            report = verify_endpoint(
                args.endpoint,
                provenance=provenance,
                profile=args.profile,
                api_key=args.api_key,
                gcp_id_token=args.gcp_id_token,
            )

        return _emit_report(report, args.output)
    except (OSError, ValueError, ProvenanceValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
