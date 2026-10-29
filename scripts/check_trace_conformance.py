#!/usr/bin/env python3
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

"""Check exported GOVERNANCE_TRACE events against proof/model.py.

Reads JSON Lines (one object per line) from the given files, or stdin. Each
line is either a trace event or an evidence record whose ``event`` field holds
one; lines of any other type are skipped. Events are checked in file order,
which must be emission order for the seal-join rules.

Usage:
    uv run python scripts/check_trace_conformance.py events.jsonl
    uv run python scripts/check_trace_conformance.py < events.jsonl

Exit codes: 0 conformant, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proof.stream_invariants import check_stream  # noqa: E402
from proof.trace_conformance import TRACE_EVENT_TYPE, check_trace  # noqa: E402


def _events(stream: TextIO, source: str) -> Iterator[dict[str, Any]]:
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


def _stream_records(stream: TextIO, source: str) -> Iterator[dict[str, Any]]:
    for number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{number}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{source}:{number}: expected JSON object")
        yield record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "files", nargs="*", type=Path, help="JSONL files (default: stdin)"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Check cage-audit/3.0 evidence stream records across all 5 invariants",
    )
    parser.add_argument(
        "--expected-thresholds-digest",
        default=None,
        help="Expected 64-hex GovernanceThresholds digest (stream mode)",
    )
    parser.add_argument(
        "--expected-refusal-hash",
        action="append",
        default=[],
        help="Refusal proof_hash that must appear on the stream (repeatable)",
    )
    parser.add_argument(
        "--expected-refusal-count",
        type=int,
        default=None,
        help="Minimum number of distinct refusal decisions expected on stream",
    )
    parser.add_argument(
        "--publish-failures",
        type=int,
        default=0,
        help="Observed evidence publish failure/shed count (fails if non-zero)",
    )
    parser.add_argument(
        "--require-thresholds-loaded",
        action="store_true",
        help="Require at least one GOVERNANCE_THRESHOLDS_LOADED record on stream",
    )
    parser.add_argument(
        "--require-settled",
        action="store_true",
        help="Require every CBF_COMMIT on stream to be confirmed or rolled back",
    )
    args = parser.parse_args(argv)
    loader = _stream_records if args.stream else _events
    items: list[dict[str, Any]] = []
    try:
        if args.files:
            for path in args.files:
                with path.open(encoding="utf-8") as handle:
                    items.extend(loader(handle, str(path)))
        else:
            items.extend(loader(sys.stdin, "<stdin>"))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stream:
        findings = check_stream(
            items,
            expected_thresholds_digest=args.expected_thresholds_digest,
            expected_refusal_hashes=args.expected_refusal_hash,
            expected_refusal_count=args.expected_refusal_count,
            publish_failures=args.publish_failures,
            require_thresholds_loaded=args.require_thresholds_loaded,
            require_settled=args.require_settled,
        )
        label = "stream records"
    else:
        findings = check_trace(items)
        label = "trace events"

    for finding in findings:
        print(f"event {finding.index}: [{finding.rule}] {finding.detail}")
    print(f"{len(items)} {label} checked, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
