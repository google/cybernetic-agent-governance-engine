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

"""Split the Lula specs a Gate W run evaluated by their README rating.

Gate W evaluates every ``compliance/lula/lula-validation-*.yaml`` manifest that
carries no ``# cage-status: planned`` or ``# cage-status: not-applicable``
header, so a result of "N of N satisfied" counts placeholder stubs as well as
the controls this project accepts as evidence. The Status column of
``compliance/lula/README.md`` is the stricter measure: only a manifest rated
Active there may be cited as evidence for closing a POA&M item, and
``scripts/check_poam_lula_divergence.py`` reads the column the same way
(``_load_active_lula_set``).

``scripts/staging_lifecycle.sh`` writes this script's output to
``<archive>/lula/rating-breakdown.json`` and copies it into the archive
manifest as ``lula.rating_breakdown``, so the satisfied count is never recorded
without the split. The lifecycle runs it with the system ``python3``, so it
uses the standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

#: The Status-column marker ``_load_active_lula_set`` matches.
ACTIVE_MARKER = "\u2705 Active"

_MANIFEST_NAME_RE = re.compile(r"lula-validation-[A-Za-z0-9_-]+\.yaml")
# The header patterns of scripts/check_lula_stub_count.py, which holds the
# evaluated / not-evaluated split equal to the SSPs. A manifest the lifecycle
# skipped that matches neither is a selector disagreement and fails below.
_PLANNED_HEADER_RE = re.compile(r"(?m)^#[ \t]*cage-status:[ \t]*planned(?:[ \t]|$)")
_NOT_APPLICABLE_HEADER_RE = re.compile(
    r"(?m)^#[ \t]*cage-status:[ \t]*not-applicable(?:[ \t]|$)"
)


def rated_active(readme_text: str) -> set[str]:
    """Return the names of the manifests the Lula README rates Active."""
    names: set[str] = set()
    for line in readme_text.splitlines():
        if ACTIVE_MARKER in line and "lula-validation-" in line:
            match = _MANIFEST_NAME_RE.search(line)
            if match:
                names.add(match.group(0))
    return names


def build_breakdown(
    lula_dir: Path, evaluated: Iterable[str], not_evaluated: Iterable[str]
) -> dict[str, Any]:
    """Split ``evaluated`` by README rating and ``not_evaluated`` by header.

    Raises ``OSError`` if the README or a not-evaluated manifest cannot be
    read, and ``ValueError`` if a not-evaluated manifest carries neither
    header, because then the run skipped it for a reason this cannot name.
    """
    active = rated_active((lula_dir / "README.md").read_text(encoding="utf-8"))
    evaluated_names = sorted(set(evaluated))
    rated = [name for name in evaluated_names if name in active]
    unrated = [name for name in evaluated_names if name not in active]

    planned: list[str] = []
    not_applicable: list[str] = []
    for name in sorted(set(not_evaluated)):
        text = (lula_dir / name).read_text(encoding="utf-8")
        if _NOT_APPLICABLE_HEADER_RE.search(text):
            not_applicable.append(name)
        elif _PLANNED_HEADER_RE.search(text):
            planned.append(name)
        else:
            raise ValueError(
                f"{name} was not evaluated but carries no "
                "'# cage-status: planned' or '# cage-status: not-applicable' header"
            )

    return {
        "rating_source": "compliance/lula/README.md Status column",
        "rating_meaning": (
            "Only a manifest rated Active may be cited as evidence for closing a "
            "POA&M item (scripts/check_poam_lula_divergence.py). The rating is the "
            "README's judgment of the manifest, not a measurement of what its Rego "
            "asserts; the README row says what each manifest checks."
        ),
        "counts": {
            "evaluated": len(evaluated_names),
            "evaluated_rated_active": len(rated),
            "evaluated_not_rated_active": len(unrated),
            "not_evaluated_planned": len(planned),
            "not_evaluated_not_applicable": len(not_applicable),
        },
        "evaluated_rated_active": rated,
        "evaluated_not_rated_active": unrated,
        "not_evaluated_planned": planned,
        "not_evaluated_not_applicable": not_applicable,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Split evaluated Lula specs by their compliance/lula/README.md rating."
    )
    parser.add_argument(
        "--lula-dir", type=Path, required=True, help="the compliance/lula directory"
    )
    parser.add_argument(
        "--evaluated",
        nargs="*",
        default=[],
        metavar="MANIFEST",
        help="manifest file names the run evaluated",
    )
    parser.add_argument(
        "--not-evaluated",
        nargs="*",
        default=[],
        metavar="MANIFEST",
        help="manifest file names the run skipped for a cage-status header",
    )
    args = parser.parse_args(argv)
    try:
        breakdown = build_breakdown(args.lula_dir, args.evaluated, args.not_evaluated)
    except (OSError, ValueError) as exc:
        print(f"lula_rating_breakdown: {exc}", file=sys.stderr)
        return 1
    json.dump(breakdown, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
