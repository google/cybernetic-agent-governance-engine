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

"""Keep the partner-content banner and canonical slot-to-vendor tables on docs/partners/.

Each Markdown document under ``docs/partners/`` carries, directly under its
title, a banner stating only what holds for all of them: the document is
third-party integration material, its presence here is not a Google
certification or endorsement of the partner, and the integration's verification
status is in the Live Verification Status table of ``docs/partners/README.md``.

Exempt from the banner:

* ``docs/partners/README.md``, which hosts that table;
* every file pinned by a ``MANIFEST.sha256`` in its own directory, since a
  banner would break the deposit's digest;
* everything that is not Markdown, so JSON records stay byte-for-byte.

The gate also checks ``docs/partners/README.md`` against ``PARTNER_SLOTS``:

* every ``docs/partners/<slot>/`` subdirectory is a registered slot in
  ``PARTNER_SLOTS`` and has a row in both ``## Directory Index`` and
  ``## Live Verification Status``;
* every row in ``## Directory Index`` names its slot's exact canonical vendor
  (rejecting foreign partner names or unknown vendor tokens), lists its required
  kernel seam protocol(s) without claiming seams the slot does not implement,
  and links to ``docs/partners/<slot>/``;
* every row in ``## Live Verification Status`` pairs its slot with its canonical
  adapter label.

Usage:
    uv run python scripts/check_partner_headers.py           # check
    uv run python scripts/check_partner_headers.py --apply   # insert or refresh
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTNERS_ROOT = REPO_ROOT / "docs" / "partners"

STATUS_DOC = "README.md"
INDEX_HEADING = "## Directory Index"
STATUS_HEADING = "## Live Verification Status"
STATUS_ANCHOR = "live-verification-status"
MANIFEST = "MANIFEST.sha256"

BANNER_START = "<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->"
BANNER_END = "<!-- /CAGE-PARTNER-CONTENT-HEADER -->"
_BANNER_BLOCK = re.compile(
    re.escape(BANNER_START) + r".*?" + re.escape(BANNER_END) + r"\n?", re.DOTALL
)
_MANIFEST_LINE = re.compile(r"^[0-9a-f]{64} [ *](?P<name>.+)$")
_STATUS_ADAPTER_CELL = re.compile(r"^`(?P<slot>[^`]+)`\s*(?P<label>.*)$")


@dataclass(frozen=True)
class PartnerSlot:
    """Canonical identity and kernel-seam role for one partner slot."""

    vendor: str
    status_label: str
    seams: tuple[str, ...]


ALL_SEAM_PROTOCOLS = frozenset(
    {
        "NormativeProvider",
        "AttestationProvider",
        "WarrantSource",
        "EstateProvider",
        "ExecutionActuator",
        "PolicyAdvisorBridge",
        "QuarantineActuator",
    }
)

PARTNER_SLOTS: Mapping[str, PartnerSlot] = {
    "provider_01": PartnerSlot(
        vendor="FlowSignal",
        status_label="FlowSignal",
        seams=("NormativeProvider",),
    ),
    "provider_02": PartnerSlot(
        vendor="NexArt",
        status_label="NexArt",
        seams=("AttestationProvider",),
    ),
    "provider_03": PartnerSlot(
        vendor="Veritas",
        status_label="Veritas",
        seams=("NormativeProvider",),
    ),
    "provider_05": PartnerSlot(
        vendor="Veraxis Execution Integrity Protocol (VEIP)",
        status_label="VEIP v0.2",
        seams=("WarrantSource", "AttestationProvider"),
    ),
    "provider_06": PartnerSlot(
        vendor="Guardian Cyber Agent Integrity",
        status_label="Guardian Cyber Agent Integrity",
        seams=("NormativeProvider",),
    ),
    "provider_07": PartnerSlot(
        vendor="InferTheta",
        status_label="InferTheta",
        seams=("NormativeProvider",),
    ),
    "provider_08": PartnerSlot(
        vendor="Verdict Systems",
        status_label="Verdict Systems",
        seams=("NormativeProvider",),
    ),
    "provider_09": PartnerSlot(
        vendor="OpsCanvas",
        status_label="OpsCanvas",
        seams=("EstateProvider",),
    ),
    "actuator_01": PartnerSlot(
        vendor="Archytan",
        status_label="Archytan",
        seams=("ExecutionActuator",),
    ),
    "actuator_02": PartnerSlot(
        vendor="NVIDIA OpenShell",
        status_label="NVIDIA OpenShell",
        seams=("ExecutionActuator", "PolicyAdvisorBridge"),
    ),
    "actuator_03": PartnerSlot(
        vendor="NVIDIA Sentry / DOCA",
        status_label="NVIDIA Sentry / DOCA",
        seams=("QuarantineActuator", "ExecutionActuator"),
    ),
}


def expected_banner(doc: Path, partners_root: Path = PARTNERS_ROOT) -> str:
    """The banner for ``doc``, linking to the status table by a relative path."""
    status = Path(os.path.relpath(partners_root / STATUS_DOC, doc.parent)).as_posix()
    return "\n".join(
        (
            BANNER_START,
            "> [!NOTE]",
            "> **Third-party integration material.** Its presence in this repository is not",
            "> a Google certification or endorsement of the partner or its products. For the",
            "> integration's current verification status, see",
            f"> [Live Verification Status]({status}#{STATUS_ANCHOR}).",
            BANNER_END,
        )
    )


def with_banner(text: str, banner: str) -> str:
    """``text`` with ``banner`` directly under its ``# `` title, replacing any old one."""
    body = _BANNER_BLOCK.sub("", text)
    title, _, rest = body.partition("\n")
    if title.startswith("# "):
        rest = rest.lstrip("\n")
        return f"{title}\n\n{banner}\n\n{rest}"
    body = body.lstrip("\n")
    return f"{banner}\n\n{body}"


def _manifest_pinned(partners_root: Path) -> set[Path]:
    pinned: set[Path] = set()
    for manifest in partners_root.rglob(MANIFEST):
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = _MANIFEST_LINE.match(line.strip())
            if match:
                pinned.add((manifest.parent / match["name"]).resolve())
    return pinned


def partner_docs(partners_root: Path = PARTNERS_ROOT) -> list[Path]:
    """Every Markdown document that must carry the banner."""
    pinned = _manifest_pinned(partners_root)
    status_doc = partners_root / STATUS_DOC
    return sorted(
        path
        for path in partners_root.rglob("*.md")
        if path != status_doc and path.resolve() not in pinned
    )


def _display(path: Path, partners_root: Path) -> str:
    """``path`` relative to the repository root (``docs/partners/...``)."""
    return Path(os.path.relpath(path, partners_root.parent.parent)).as_posix()


def _section_lines(lines: list[str], heading: str) -> list[str] | None:
    if heading not in lines:
        return None
    start = lines.index(heading) + 1
    end = next(
        (i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines)
    )
    return lines[start:end]


def _index_table_violations(
    shown: str, section: list[str], subdirs: list[str], partners_root: Path
) -> list[str]:
    errors: list[str] = []
    for subdir in subdirs:
        if subdir in PARTNER_SLOTS and not any(
            line.startswith(f"| `{subdir}`") for line in section
        ):
            errors.append(f"{shown}: '{INDEX_HEADING}' has no row for {subdir}")

    seen: set[str] = set()
    for line in section:
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        slot = cells[0].strip("`")
        if slot in seen:
            errors.append(f"{shown}: '{INDEX_HEADING}' has duplicate row for {slot}")
            continue
        seen.add(slot)
        if slot not in PARTNER_SLOTS:
            errors.append(
                f"{shown}: '{INDEX_HEADING}' row '{slot}' is not in PARTNER_SLOTS"
            )
            continue
        if not (partners_root / slot).is_dir():
            errors.append(
                f"{shown}: '{INDEX_HEADING}' row '{slot}' has no {slot}/ directory"
            )
        if len(cells) < 5:
            errors.append(
                f"{shown}: '{INDEX_HEADING}' row '{slot}' has {len(cells)} column(s), expected 5"
            )
            continue
        spec = PARTNER_SLOTS[slot]
        vendor_cell, role_cell, doc_cell = cells[1], cells[2], cells[3]
        expected_vendor = f"**{spec.vendor}**"
        if vendor_cell != expected_vendor:
            errors.append(
                f"{shown}: '{INDEX_HEADING}' row '{slot}' has vendor {vendor_cell!r}, "
                f"expected {expected_vendor!r}"
            )
        for seam in spec.seams:
            if f"`{seam}`" not in role_cell:
                errors.append(
                    f"{shown}: '{INDEX_HEADING}' row '{slot}' role cell is missing `{seam}`"
                )
        for other_seam in sorted(ALL_SEAM_PROTOCOLS - set(spec.seams)):
            if f"`{other_seam}`" in role_cell:
                errors.append(
                    f"{shown}: '{INDEX_HEADING}' row '{slot}' role cell names "
                    f"`{other_seam}`, which {slot} does not implement"
                )
        expected_doc = f"[`{slot}/`]({slot}/)"
        if doc_cell != expected_doc:
            errors.append(
                f"{shown}: '{INDEX_HEADING}' row '{slot}' has documentation link "
                f"{doc_cell!r}, expected {expected_doc!r}"
            )
    return errors


def _status_table_violations(partners_root: Path) -> list[str]:
    status_doc = partners_root / STATUS_DOC
    shown = _display(status_doc, partners_root)
    if not status_doc.is_file():
        return [f"{shown} does not exist"]
    lines = status_doc.read_text(encoding="utf-8").splitlines()
    subdirs = [p.name for p in sorted(partners_root.iterdir()) if p.is_dir()]
    errors: list[str] = [
        f"{shown}: unknown partner directory '{subdir}' (not in PARTNER_SLOTS)"
        for subdir in subdirs
        if subdir not in PARTNER_SLOTS
    ]

    index_section = _section_lines(lines, INDEX_HEADING)
    if index_section is None:
        errors.append(f"{shown} has no '{INDEX_HEADING}' heading")
    else:
        errors.extend(
            _index_table_violations(shown, index_section, subdirs, partners_root)
        )

    status_section = _section_lines(lines, STATUS_HEADING)
    if status_section is None:
        errors.append(
            f"{shown} has no '{STATUS_HEADING}' heading for banners to link to"
        )
        return errors

    for subdir in subdirs:
        if subdir in PARTNER_SLOTS and not any(
            line.startswith(f"| `{subdir}`") for line in status_section
        ):
            errors.append(f"{shown}: '{STATUS_HEADING}' has no row for {subdir}")

    seen: set[str] = set()
    for line in status_section:
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        match = _STATUS_ADAPTER_CELL.match(cells[0])
        if not match:
            continue
        slot = match["slot"]
        label = match["label"]
        if slot in seen:
            errors.append(f"{shown}: '{STATUS_HEADING}' has duplicate row for {slot}")
            continue
        seen.add(slot)
        if slot not in PARTNER_SLOTS:
            errors.append(
                f"{shown}: '{STATUS_HEADING}' row '{slot}' is not in PARTNER_SLOTS"
            )
            continue
        if not (partners_root / slot).is_dir():
            errors.append(
                f"{shown}: '{STATUS_HEADING}' row '{slot}' has no {slot}/ directory"
            )
        spec = PARTNER_SLOTS[slot]
        if label != spec.status_label:
            errors.append(
                f"{shown}: '{STATUS_HEADING}' row '{slot}' has adapter label "
                f"{label!r}, expected {spec.status_label!r}"
            )
    return errors


def violations(partners_root: Path = PARTNERS_ROOT) -> list[str]:
    """Each document whose banner is missing, stale or misplaced, and each table gap."""
    if not partners_root.is_dir():
        return [f"{partners_root} does not exist"]
    errors = _status_table_violations(partners_root)
    for doc in partner_docs(partners_root):
        text = doc.read_text(encoding="utf-8")
        if with_banner(text, expected_banner(doc, partners_root)) != text:
            errors.append(
                f"{_display(doc, partners_root)}: missing, stale or misplaced "
                "partner banner (run with --apply)"
            )
    return errors


def apply_banners(partners_root: Path = PARTNERS_ROOT) -> list[Path]:
    """Insert or refresh the banner in every partner document; return those changed."""
    changed: list[Path] = []
    for doc in partner_docs(partners_root):
        text = doc.read_text(encoding="utf-8")
        updated = with_banner(text, expected_banner(doc, partners_root))
        if updated != text:
            doc.write_text(updated, encoding="utf-8")
            changed.append(doc)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the partner-content banner on docs/partners/ documents"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Insert or refresh the banner in every partner document first",
    )
    args = parser.parse_args(argv)
    if args.apply:
        changed = apply_banners()
        print(f"partner banners: {len(changed)} document(s) updated")
    errors = violations()
    for error in errors:
        print(f"❌ {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"✅ partner banners: {len(partner_docs())} documents carry the banner")
    return 0


if __name__ == "__main__":
    sys.exit(main())
