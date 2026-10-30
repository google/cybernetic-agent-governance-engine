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
import tempfile
from pathlib import Path

# Default p95 SLO in milliseconds (2 seconds).
_DEFAULT_P95_MS = 2000


def _extract_p95_from_row(row: dict[str, str], stats_csv: str) -> float:
    """Extract the 95th-percentile value from a Locust stats CSV row."""
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


def _load_row_p95(stats_csv: str, row_name: str) -> float:
    """Return the p95 latency (ms) for ``row_name`` in the Locust stats CSV.

    Raises:
        FileNotFoundError: when stats_csv does not exist.
        ValueError: when ``row_name`` or the 95% column is missing.
    """
    if not os.path.exists(stats_csv):
        raise FileNotFoundError(f"Locust stats file not found: {stats_csv}")

    target = row_name.strip()
    with open(stats_csv, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = (row.get("Name") or "").strip()
            req_type = (row.get("Type") or "").strip()
            combined = f"{req_type} {name}".strip() if req_type else name
            if target in (name, combined):
                return _extract_p95_from_row(row, stats_csv)

    if target == "Aggregated":
        raise ValueError(
            f"No 'Aggregated' row found in {stats_csv}. "
            "Ensure locust ran with --csv and produced at least one request."
        )
    raise ValueError(f"No row matching {target!r} found in {stats_csv}.")


def _load_aggregated_p95(stats_csv: str) -> float:
    """Return the p95 latency (ms) from the Aggregated row in the Locust stats CSV."""
    return _load_row_p95(stats_csv, "Aggregated")


def _parse_endpoint_thresholds(raw_specs: list[str]) -> dict[str, float]:
    """Parse ``NAME=MS`` specifications into an endpoint -> threshold (ms) mapping."""
    thresholds: dict[str, float] = {}
    for spec in raw_specs:
        for item in spec.split(","):
            entry = item.strip()
            if not entry:
                continue
            if "=" not in entry:
                raise ValueError(
                    f"Invalid endpoint threshold {entry!r}; expected 'ENDPOINT=MS'."
                )
            endpoint, raw_ms = entry.rsplit("=", 1)
            endpoint_name = endpoint.strip()
            if not endpoint_name:
                raise ValueError(
                    f"Invalid endpoint threshold {entry!r}; endpoint name cannot be empty."
                )
            try:
                threshold_ms = float(raw_ms.strip())
            except ValueError as exc:
                raise ValueError(
                    f"Invalid threshold value in {entry!r}; expected numeric ms."
                ) from exc
            if threshold_ms <= 0:
                raise ValueError(
                    f"Invalid threshold value in {entry!r}; must be > 0 ms."
                )
            thresholds[endpoint_name] = threshold_ms
    return thresholds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assert Locust p95 latency is within baseline.",
    )
    parser.add_argument(
        "--stats-csv",
        default=os.environ.get(
            "LOCUST_STATS_CSV",
            str(Path(tempfile.gettempdir()) / "locust-stats_stats.csv"),
        ),
        help="Path to the Locust *_stats.csv file.",
    )
    parser.add_argument(
        "--p95-baseline-ms",
        type=int,
        default=int(os.environ.get("LOCUST_P95_BASELINE_MS", str(_DEFAULT_P95_MS))),
        help="Maximum acceptable aggregated p95 response time in milliseconds (default: 2000).",
    )
    parser.add_argument(
        "--endpoint-p95",
        action="append",
        default=[],
        metavar="ENDPOINT=MS",
        help=(
            "Optional per-endpoint p95 ceiling in milliseconds "
            "(e.g. 'POST /tools/execute=2500'). May be specified multiple times "
            "or via LOCUST_ENDPOINT_P95_MS (comma-separated)."
        ),
    )
    args = parser.parse_args(argv)

    raw_endpoint_specs: list[str] = []
    env_specs = os.environ.get("LOCUST_ENDPOINT_P95_MS", "").strip()
    if env_specs:
        raw_endpoint_specs.append(env_specs)
    if args.endpoint_p95:
        raw_endpoint_specs.extend(args.endpoint_p95)

    try:
        endpoint_thresholds = _parse_endpoint_thresholds(raw_endpoint_specs)
    except ValueError as exc:
        print(f"[check_locust_baseline] ❌ FAIL — {exc}", file=sys.stderr)
        return 1

    print(f"[check_locust_baseline] Reading: {args.stats_csv}")
    print(f"[check_locust_baseline] p95 baseline: {args.p95_baseline_ms} ms")

    try:
        p95 = _load_aggregated_p95(args.stats_csv)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[check_locust_baseline] ❌ FAIL — {exc}", file=sys.stderr)
        return 1

    print(f"[check_locust_baseline] Aggregated p95 = {p95:.1f} ms")

    failed = False
    if p95 > args.p95_baseline_ms:
        print(
            f"[check_locust_baseline] ❌ REGRESSION — p95 {p95:.1f} ms "
            f"> baseline {args.p95_baseline_ms} ms",
            file=sys.stderr,
        )
        failed = True

    for endpoint_name, limit_ms in endpoint_thresholds.items():
        try:
            ep_p95 = _load_row_p95(args.stats_csv, endpoint_name)
        except ValueError as exc:
            print(f"[check_locust_baseline] ❌ FAIL — {exc}", file=sys.stderr)
            return 1
        print(
            f"[check_locust_baseline] Endpoint {endpoint_name!r} p95 = {ep_p95:.1f} ms "
            f"(limit {limit_ms:.1f} ms)"
        )
        if ep_p95 > limit_ms:
            print(
                f"[check_locust_baseline] ❌ REGRESSION — {endpoint_name!r} p95 {ep_p95:.1f} ms "
                f"> threshold {limit_ms:.1f} ms",
                file=sys.stderr,
            )
            failed = True

    if failed:
        return 1

    print(
        f"[check_locust_baseline] ✅ PASS — p95 {p95:.1f} ms "
        f"≤ baseline {args.p95_baseline_ms} ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
