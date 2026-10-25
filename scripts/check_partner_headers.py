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

"""Enforce standard partner content status headers under docs/partners/.

Verifies that every Markdown document in ``docs/partners/`` carries the
mandatory Partner Content Status Header stating:
- Partner-authored / bilateral specification material
- Not Google-authored product documentation and not Google-endorsed
- Covered by the repository CLA and Apache-2.0 license
- Current verification posture (`AUTHOR_SELF_TEST` vs. `COUNTERPARTY_VERIFIED`
  vs. `INDEPENDENT_PARTY_VERIFIED`) and whether independently verified.

Digest-locked directories (``docs/partners/provider_05/veip_v02/`` and
``docs/partners/provider_05/veip_v03/``) are verified by ``MANIFEST.sha256`` in
the test suite and must never be modified in place; instead, their status
headers live in sibling files ``VEIP_V02_STATUS_HEADER.md`` and
``VEIP_V03_STATUS_HEADER.md`` under ``docs/partners/provider_05/``.

Usage:
    uv run python scripts/check_partner_headers.py
    uv run python scripts/check_partner_headers.py --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTNERS_ROOT = REPO_ROOT / "docs" / "partners"

DIGEST_LOCKED_DIRS: tuple[Path, ...] = (
    PARTNERS_ROOT / "provider_05" / "veip_v02",
    PARTNERS_ROOT / "provider_05" / "veip_v03",
)

SIBLING_HEADER_FILES: dict[Path, Path] = {
    PARTNERS_ROOT / "provider_05" / "veip_v02": (
        PARTNERS_ROOT / "provider_05" / "VEIP_V02_STATUS_HEADER.md"
    ),
    PARTNERS_ROOT / "provider_05" / "veip_v03": (
        PARTNERS_ROOT / "provider_05" / "VEIP_V03_STATUS_HEADER.md"
    ),
}

HEADER_START_MARKER = "<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->"
HEADER_END_MARKER = "<!-- /CAGE-PARTNER-CONTENT-HEADER -->"

STANDARD_HEADER_BLOCK = """<!-- CAGE-PARTNER-CONTENT-HEADER: v1 -->
> **Partner Integration Status & Non-Endorsement Header**
> - **Authorship:** Partner-authored or bilateral integration specification material; **not Google-authored** product documentation.
> - **Endorsement:** **Not Google-endorsed.** Hosting in this repository is for technical interoperability and conformance reference only and does not constitute a Google certification, qualification, or regulatory endorsement.
> - **Contribution & License:** Contributed under the repository CLA and licensed under Apache-2.0.
> - **Verification Status:** `AUTHOR_SELF_TEST` — **not independently verified** (`independent_of_author: false`, `third_party_independent: false`). Independent or counterparty verification requires executing `cage-conformance` with verified OIDC runner provenance.
<!-- /CAGE-PARTNER-CONTENT-HEADER -->
"""

REQUIRED_PHRASES: tuple[str, ...] = (
    HEADER_START_MARKER,
    HEADER_END_MARKER,
    "Partner-authored",
    "not Google-authored",
    "Not Google-endorsed",
    "CLA",
    "Verification Status:",
    "not independently verified",
)


def _is_in_digest_locked_dir(path: Path) -> bool:
    resolved = path.resolve()
    for locked_dir in DIGEST_LOCKED_DIRS:
        try:
            resolved.relative_to(locked_dir.resolve())
            return True
        except ValueError:
            continue
    return False


def _has_valid_header(text: str) -> list[str]:
    missing: list[str] = []
    for phrase in REQUIRED_PHRASES:
        if phrase not in text:
            missing.append(phrase)
    return missing


def apply_headers() -> int:
    """Idempotently apply status headers to docs/partners/ Markdown files and sibling files."""
    updated = 0
    for locked_dir, sibling_path in SIBLING_HEADER_FILES.items():
        rel_dir = locked_dir.relative_to(REPO_ROOT)
        content = (
            f"{STANDARD_HEADER_BLOCK}\n"
            f"# Status Header for `{rel_dir}/` (Digest-Locked Deposit)\n\n"
            f"Files inside `{rel_dir}/` are cryptographically pinned by `MANIFEST.sha256` "
            "and must not be modified in place. This sibling status header governs all "
            f"specifications, schemas, and evidence artifacts deposited under `{rel_dir}/`.\n"
        )
        if (
            not sibling_path.is_file()
            or sibling_path.read_text(encoding="utf-8") != content
        ):
            sibling_path.write_text(content, encoding="utf-8")
            updated += 1

    for md_file in sorted(PARTNERS_ROOT.rglob("*.md")):
        if _is_in_digest_locked_dir(md_file):
            continue
        text = md_file.read_text(encoding="utf-8")
        if _has_valid_header(text):
            if HEADER_START_MARKER not in text:
                new_text = f"{STANDARD_HEADER_BLOCK}\n{text.lstrip()}"
                md_file.write_text(new_text, encoding="utf-8")
                updated += 1

    print(f"✅ Applied partner status headers ({updated} file(s) updated).")
    return 0


def check_partner_headers() -> list[str]:
    """Check all Markdown files under docs/partners/ for valid status headers."""
    errors: list[str] = []
    if not PARTNERS_ROOT.is_dir():
        return [f"Missing partner docs directory: {PARTNERS_ROOT}"]

    for locked_dir, sibling_path in SIBLING_HEADER_FILES.items():
        if not sibling_path.is_file():
            errors.append(
                f"Missing sibling status header {sibling_path.relative_to(REPO_ROOT)} "
                f"for digest-locked directory {locked_dir.relative_to(REPO_ROOT)}"
            )
        else:
            missing = _has_valid_header(sibling_path.read_text(encoding="utf-8"))
            if missing:
                errors.append(
                    f"{sibling_path.relative_to(REPO_ROOT)}: missing required header phrases: {missing}"
                )

    for md_file in sorted(PARTNERS_ROOT.rglob("*.md")):
        if _is_in_digest_locked_dir(md_file):
            continue
        rel = md_file.relative_to(REPO_ROOT)
        missing = _has_valid_header(md_file.read_text(encoding="utf-8"))
        if missing:
            errors.append(
                f"{rel}: missing required partner status header phrases: {missing}"
            )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Insert standard partner status headers where missing",
    )
    args = parser.parse_args(argv)

    if args.apply:
        return apply_headers()

    errors = check_partner_headers()
    if errors:
        for err in errors:
            print(f"❌ {err}", file=sys.stderr)
        return 1
    print("✅ All partner documents under docs/partners/ carry valid status headers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
