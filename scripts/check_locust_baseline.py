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

"""
check_locust_baseline.py — Locust p95 latency regression gate.

Reads the Locust CSV stats file produced by `locust --csv <prefix>` and
asserts that the aggregated p95 response time is within the configured
baseline.  Exits with code 1 on regression; code 0 on pass.

Usage:
    uv run python scripts/check_locust_baseline.py \\
        --stats-csv /tmp/locust-stats_stats.csv \\
        --p95-baseline-ms 2000

The ``--stats-csv`` argument must point to the ``*_stats.csv`` file
(not ``*_stats_history.csv``).  The script reads the "Aggregated" row
(Name == "Aggregated") to obtain the overall p95.

Environment variable override:
    LOCUST_P95_BASELINE_MS — overrides --p95-baseline-ms when set.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

# Default p95 SLO in milliseconds (2 seconds).
_DEFAULT_P95_MS = 2000


def _load_aggregated_p95(stats_csv: str) -> float:
    """Return the p95 latency (ms) from the Aggregated row in the Locust stats CSV.

    Raises:
        FileNotFoundError: when stats_csv does not exist.
        ValueError: when the Aggregated row or the 95% column is missing.
    """
    if not os.path.exists(stats_csv):
        raise FileNotFoundError(f"Locust stats file not found: {stats_csv}")

    with open(stats_csv, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            # Locust writes "Aggregated" as the Name for the aggregate row.
            if row.get("Name", "").strip() == "Aggregated":
                col = row.get("95%") or row.get("95%ile") or row.get("95th Percentile")
                if col is None:
                    # Fall back: try any key containing "95"
                    for key in row:
                        if "95" in key:
                            col = row[key]
                            break
                if col is None:
                    raise ValueError(
                        f"Could not find 95th-percentile column in {stats_csv}. "
                        f"Available columns: {list(row.keys())}"
                    )
                return float(col)

    raise ValueError(
        f"No 'Aggregated' row found in {stats_csv}. "
        "Ensure locust ran with --csv and produced at least one request."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assert Locust p95 latency is within baseline.",
    )
    parser.add_argument(
        "--stats-csv",
        default=os.environ.get("LOCUST_STATS_CSV", "/tmp/locust-stats_stats.csv"),
        help="Path to the Locust *_stats.csv file.",
    )
    parser.add_argument(
        "--p95-baseline-ms",
        type=int,
        default=int(os.environ.get("LOCUST_P95_BASELINE_MS", str(_DEFAULT_P95_MS))),
        help="Maximum acceptable p95 response time in milliseconds (default: 2000).",
    )
    args = parser.parse_args()

    print(f"[check_locust_baseline] Reading: {args.stats_csv}")
    print(f"[check_locust_baseline] p95 baseline: {args.p95_baseline_ms} ms")

    try:
        p95 = _load_aggregated_p95(args.stats_csv)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[check_locust_baseline] ❌ FAIL — {exc}", file=sys.stderr)
        return 1

    print(f"[check_locust_baseline] Aggregated p95 = {p95:.1f} ms")

    if p95 > args.p95_baseline_ms:
        print(
            f"[check_locust_baseline] ❌ REGRESSION — p95 {p95:.1f} ms "
            f"> baseline {args.p95_baseline_ms} ms",
            file=sys.stderr,
        )
        return 1

    print(
        f"[check_locust_baseline] ✅ PASS — p95 {p95:.1f} ms "
        f"≤ baseline {args.p95_baseline_ms} ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
