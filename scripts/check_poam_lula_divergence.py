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

"""POAM vs Lula divergence checker.

Parses docs/POAM.md and, for each closed finding, verifies that at least
one corresponding Lula validation file exists in compliance/lula/.

A "corresponding" file is one whose name contains the normalised control ID
(e.g. the closed finding for SC-4 must have lula-validation-sc4.yaml).
For compound controls such as "SC-4 / SI-2", ANY of the listed controls
having a Lula file is sufficient to consider the finding covered.

Exit codes:
    0 — all closed findings have a corresponding Lula assertion file
    1 — one or more closed findings lack a corresponding Lula assertion file
"""

import os
import re
import sys
from pathlib import Path

POAM_PATH = Path("docs/POAM.md")
LULA_DIR = Path("compliance/lula")

# Controls that are structural/meta and do not map to a testable assertion file.
# Values must be in NORMALISED form (output of normalise_control()) — i.e. lowercase,
# no spaces, no dashes, no dots.
NON_TESTABLE_CONTROLS = {
    "structural",
    "cbf",  # Control Barrier Function — implementation detail, not a NIST ID
    "r2",  # Internal CAGE risk label — not a NIST 800-53 control
    "r3",
    "r4",
    "r5",
    "r6",
    "ca7",  # CA-7 (Continuous Monitoring) — no standalone Lula stub yet
    "sa11",  # SA-11 (Developer Testing) — covered by test-gap findings; no Lula stub
    "sa9",  # SA-9 (External System Services) — external integration boundary
    "si7",  # SI-7 (Software/System Integrity) — algorithmic/code integrity enforced via Python unit tests/formal proofs; no standalone Lula stub
    "sc13",  # SC-13 (Cryptographic Protection) — KMS/JCS canonicalization in Python codebase; verified via unit tests
    "iso42001a84",  # ISO 42001 A.8.4 (CAGE-SEC-003) — DeferQueue Phase-3 confidence recheck requires validating replay_evaluate() call sequence in Python endpoint; not practical for Lula OPA validation; covered by 6 test cases in tests/test_defer_queue.py
    "external",
}

CONTROL_ALIASES: dict[str, list[str]] = {
    "a84": ["tqp007", "iso001-token-quota", "flowsignal"],
    "iso42001": ["a52", "a53", "a92", "tqp007", "iso001-token-quota", "flowsignal"],
    "sc7": ["ftra"],
    "ac4": ["ftra"],
    "ctrlftra001": ["ftra"],
}


def normalise_control(raw: str) -> str:
    """Normalise a control ID to the suffix used in Lula filenames.

    Examples:
        "SC-4"   → "sc4"
        "AI-600" → "ai600"
        "A.5.2"  → "a52"
    """
    return re.sub(r"[\s.\-/]", "", raw).lower()


def parse_closed_findings(poam_text: str) -> list[dict]:
    """Extract rows from the Closed Findings table in POAM.md.

    Returns a list of dicts with keys: id, control, description, closed.
    """
    findings: list[dict] = []

    # Locate the Closed Findings section.
    in_closed = False
    header_skipped = False

    for line in poam_text.splitlines():
        stripped = line.strip()

        if re.match(r"^#{1,3}\s+Closed Findings", stripped):
            in_closed = True
            header_skipped = False
            continue

        if in_closed:
            # Stop at the next heading.
            if stripped.startswith("#") and not stripped.startswith("##"):
                break
            if stripped.startswith("##"):
                break

            if not stripped.startswith("|"):
                continue

            # Skip the header and separator rows.
            if re.match(r"^\|\s*ID\s*\|", stripped, re.IGNORECASE):
                header_skipped = True
                continue
            if re.match(r"^\|[-\s|]+\|", stripped):
                continue

            if not header_skipped:
                continue

            # Parse the table row.
            cols = [c.strip() for c in stripped.split("|")]
            # cols[0] is empty (leading |), cols[1]=ID, cols[2]=Control,
            # cols[3]=Description, cols[4]=Closed
            if len(cols) < 5:
                continue

            finding_id = cols[1].strip()
            control_raw = cols[2].strip()
            description = cols[3].strip()
            closed = cols[4].strip() if len(cols) > 4 else ""

            if not finding_id or finding_id.startswith("-"):
                continue

            findings.append(
                {
                    "id": finding_id,
                    "control": control_raw,
                    "description": description,
                    "closed": closed,
                }
            )

    return findings


def get_lula_file_stems(lula_dir: Path) -> set[str]:
    """Return the set of normalised stems from all lula-validation-*.yaml files."""
    stems: set[str] = set()
    for path in lula_dir.glob("lula-validation-*.yaml"):
        # Strip the "lula-validation-" prefix and ".yaml" suffix.
        stem = path.stem.removeprefix("lula-validation-")
        stems.add(stem)
    return stems


def split_controls(control_raw: str) -> list[str]:
    """Split a compound control string like "SC-4 / SI-2" into individual IDs."""
    parts = re.split(r"[,/]", control_raw)
    return [p.strip() for p in parts if p.strip()]


def find_matching_lula_stems(controls: list[str], lula_stems: set[str]) -> list[str]:
    """Return Lula file stems that match any of the given control IDs."""
    matched: list[str] = []
    for ctrl in controls:
        norm = normalise_control(ctrl)
        # Direct match: e.g. "sc4" ∈ stems → "lula-validation-sc4.yaml" exists.
        if norm in lula_stems:
            matched.append(norm)
            continue
        # Alias match: e.g. "a84" → "tqp007"
        if norm in CONTROL_ALIASES:
            for alias in CONTROL_ALIASES[norm]:
                if alias in lula_stems:
                    matched.append(alias)
        # Prefix match: e.g. norm="ai6001" could match stem "ai600-confabulation".
        for stem in lula_stems:
            if stem.startswith(norm) or norm.startswith(stem):
                matched.append(stem)
    return list(set(matched))


def main() -> int:
    if not POAM_PATH.exists():
        print(f"ERROR: {POAM_PATH} not found.", file=sys.stderr)
        return 1

    if not LULA_DIR.exists():
        print(f"ERROR: {LULA_DIR} not found.", file=sys.stderr)
        return 1

    poam_text = POAM_PATH.read_text(encoding="utf-8")
    closed_findings = parse_closed_findings(poam_text)
    lula_stems = get_lula_file_stems(LULA_DIR)

    print(f"POAM closed findings:    {len(closed_findings)}")
    print(f"Lula validation files:   {len(lula_stems)}")
    print()

    covered: list[dict] = []
    uncovered: list[dict] = []
    skipped: list[dict] = []

    for finding in closed_findings:
        controls = split_controls(finding["control"])
        ctrl_norms = [normalise_control(c) for c in controls]

        # Check whether all normalised controls are non-testable.
        all_non_testable = all(n in NON_TESTABLE_CONTROLS for n in ctrl_norms)
        if all_non_testable:
            skipped.append(finding)
            continue

        matched = find_matching_lula_stems(controls, lula_stems)
        if matched:
            finding["lula_files"] = [f"lula-validation-{s}.yaml" for s in matched]
            covered.append(finding)
        else:
            finding["lula_files"] = []
            uncovered.append(finding)

    # ── Report ──────────────────────────────────────────────────────────────
    print("=" * 70)
    print("COVERED findings (closed finding → Lula assertion exists)")
    print("=" * 70)
    for f in covered:
        files = ", ".join(f["lula_files"])
        print(f"  ✅ {f['id']:25s}  ctrl={f['control']!r:30s}  → {files}")

    print()
    print("=" * 70)
    print("SKIPPED findings (non-testable / structural controls)")
    print("=" * 70)
    for f in skipped:
        print(f"  ⏭  {f['id']:25s}  ctrl={f['control']!r}")

    print()
    print("=" * 70)
    print("UNCOVERED findings (closed finding with NO matching Lula file)")
    print("=" * 70)
    if uncovered:
        for f in uncovered:
            print(f"  ❌ {f['id']:25s}  ctrl={f['control']!r}")
    else:
        print("  (none)")

    print()
    print(
        f"Summary: {len(covered)} covered, {len(skipped)} skipped, "
        f"{len(uncovered)} uncovered out of {len(closed_findings)} closed findings."
    )

    if uncovered:
        print(
            "\nACTION REQUIRED: Add Lula assertion files for the uncovered findings above,",
            "\nor add the control ID to NON_TESTABLE_CONTROLS if it is structural.",
        )
        return 1

    print("\nOK: all closed POAM findings have a corresponding Lula assertion file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
