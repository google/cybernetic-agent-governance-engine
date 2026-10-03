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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", type=Path, help="JSONL files (default: stdin)")
    args = parser.parse_args(argv)
    events: list[dict[str, Any]] = []
    try:
        if args.files:
            for path in args.files:
                with path.open(encoding="utf-8") as handle:
                    events.extend(_events(handle, str(path)))
        else:
            events.extend(_events(sys.stdin, "<stdin>"))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = check_trace(events)
    for finding in findings:
        print(f"event {finding.index}: [{finding.rule}] {finding.detail}")
    print(f"{len(events)} trace events checked, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
