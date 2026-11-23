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
"""Derive ``compliance/standards/nist_sp_800_53_r5.json`` from NIST's OSCAL catalog.

The standards-citation gate (``scripts/check_standard_citations.py``) reads one
reference table per standard. For SP 800-53 Rev 5 the table is *derived*, never
hand-maintained: this script reads NIST's official OSCAL catalog
(``usnistgov/oscal-content``, ``nist.gov/SP800-53/rev5/json/
NIST_SP-800-53_rev5_catalog.json``) and keeps, for every family, base control
and enhancement, only the identifier label, title, withdrawn status and the
``incorporated-into`` / ``moved-to`` targets. Control prose is not copied.

Usage::

    python scripts/build_sp800_53_table.py --catalog /path/to/NIST_SP-800-53_rev5_catalog.json \
        --retrieved 2026-11-23 [--out compliance/standards/nist_sp_800_53_r5.json]

The SHA-256 of the catalog bytes read is recorded in ``source_sha256`` so a
reviewer can re-derive the table from the same upstream file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "compliance" / "standards" / "nist_sp_800_53_r5.json"
SOURCE_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
LICENSE_NOTE = (
    "NIST SP 800-53 and its OSCAL catalog are works of the U.S. Government "
    "(National Institute of Standards and Technology) and are not subject to "
    "copyright protection in the United States (17 U.S.C. 105). Attribution: "
    "NIST, usnistgov/oscal-content. Only identifiers, titles, withdrawn status "
    "and incorporation targets are retained here."
)


def _prop(ctrl: dict[str, Any], name: str, *, unclassed: bool = False) -> str | None:
    for prop in ctrl.get("props", []):
        if prop.get("name") != name:
            continue
        if unclassed and "class" in prop:
            continue
        value = prop.get("value")
        if isinstance(value, str):
            return value
    return None


def _label_for_href(href: str, labels: dict[str, str]) -> str:
    key = href.lstrip("#")
    if key in labels:
        return labels[key]
    return key.upper()


def _collect_labels(groups: list[dict[str, Any]]) -> dict[str, str]:
    labels: dict[str, str] = {}

    def walk(ctrls: list[dict[str, Any]]) -> None:
        for ctrl in ctrls:
            label = _prop(ctrl, "label", unclassed=True)
            if label is None:
                raise ValueError(f"control {ctrl.get('id')!r} has no unclassed label")
            labels[str(ctrl["id"])] = label
            walk(ctrl.get("controls", []))

    for group in groups:
        labels[str(group["id"])] = str(group["id"]).upper()
        walk(group.get("controls", []))
    return labels


def build_rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Return table rows (families, controls, enhancements) in catalog order."""
    groups = catalog["catalog"]["groups"]
    labels = _collect_labels(groups)
    rows: list[dict[str, Any]] = []

    def walk(ctrls: list[dict[str, Any]], kind: str) -> None:
        for ctrl in ctrls:
            row: dict[str, Any] = {
                "id": labels[str(ctrl["id"])],
                "title": str(ctrl["title"]),
                "status": "withdrawn"
                if _prop(ctrl, "status") == "withdrawn"
                else "active",
                "kind": kind,
            }
            targets = [
                _label_for_href(str(link["href"]), labels)
                for link in ctrl.get("links", [])
                if link.get("rel") in ("incorporated-into", "moved-to")
            ]
            if targets:
                row["replaced_by"] = targets
            if kind == "control":
                row["children_complete"] = True
            rows.append(row)
            walk(ctrl.get("controls", []), "enhancement")

    for group in groups:
        rows.append(
            {
                "id": str(group["id"]).upper(),
                "title": str(group["title"]),
                "status": "active",
                "kind": "family",
                "children_complete": True,
            }
        )
        walk(group.get("controls", []), "control")
    return rows


def build_table(raw: bytes, retrieved: str) -> dict[str, Any]:
    """Return the full reference-table document for ``raw`` catalog bytes."""
    catalog = json.loads(raw.decode("utf-8"))
    meta = catalog["catalog"]["metadata"]
    return {
        "schema_version": 1,
        "standard": "nist-sp-800-53-r5",
        "title": (
            "NIST SP 800-53 Rev. 5, Security and Privacy Controls for "
            "Information Systems and Organizations"
        ),
        "source_url": SOURCE_URL,
        "version": (
            f"SP 800-53 Rev {meta['version']} (OSCAL catalog last-modified "
            f"{meta['last-modified']})"
        ),
        "retrieved": retrieved,
        "source_quality": "primary",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_notes": (
            "Derived by scripts/build_sp800_53_table.py from the official NIST OSCAL "
            "catalog; do not edit by hand. source_sha256 is the digest of the catalog "
            "body as retrieved."
        ),
        "license": LICENSE_NOTE,
        "complete": True,
        "rows": build_rows(catalog),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Derive the SP 800-53 Rev 5 reference table from NIST's OSCAL catalog."
    )
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument(
        "--retrieved", required=True, help="ISO date the catalog was fetched"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    table = build_table(args.catalog.read_bytes(), args.retrieved)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(table, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    withdrawn = sum(1 for r in table["rows"] if r["status"] == "withdrawn")
    print(f"wrote {args.out} ({len(table['rows'])} rows, {withdrawn} withdrawn)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
