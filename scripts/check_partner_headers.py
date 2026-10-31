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

"""Keep the partner-content banner on every document under docs/partners/.

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

The gate also fails if the table disappears or lacks a row for a partner
directory, since every banner points there.

Usage:
    uv run python scripts/check_partner_headers.py           # check
    uv run python scripts/check_partner_headers.py --apply   # insert or refresh
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTNERS_ROOT = REPO_ROOT / "docs" / "partners"

STATUS_DOC = "README.md"
STATUS_HEADING = "## Live Verification Status"
STATUS_ANCHOR = "live-verification-status"
MANIFEST = "MANIFEST.sha256"

BANNER_START = "<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->"
BANNER_END = "<!-- /CAGE-PARTNER-CONTENT-HEADER -->"
_BANNER_BLOCK = re.compile(
    re.escape(BANNER_START) + r".*?" + re.escape(BANNER_END) + r"\n?", re.DOTALL
)
_MANIFEST_LINE = re.compile(r"^[0-9a-f]{64} [ *](?P<name>.+)$")


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


def _status_table_violations(partners_root: Path) -> list[str]:
    status_doc = partners_root / STATUS_DOC
    shown = _display(status_doc, partners_root)
    if not status_doc.is_file():
        return [f"{shown} does not exist"]
    lines = status_doc.read_text(encoding="utf-8").splitlines()
    if STATUS_HEADING not in lines:
        return [f"{shown} has no '{STATUS_HEADING}' heading for banners to link to"]
    start = lines.index(STATUS_HEADING) + 1
    end = next(
        (i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines)
    )
    section = lines[start:end]
    return [
        f"{shown}: '{STATUS_HEADING}' has no row for {partner.name}"
        for partner in sorted(p for p in partners_root.iterdir() if p.is_dir())
        if not any(line.startswith(f"| `{partner.name}`") for line in section)
    ]


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
