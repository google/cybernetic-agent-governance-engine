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

"""scripts/check_partner_headers.py: the banner on every docs/partners document.

The banner states only what holds for every partner document, sits directly
under the title, and links to a status table that lists every partner. Files a
MANIFEST.sha256 pins and anything that is not Markdown are never modified.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from scripts import check_partner_headers as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

_STATUS_README = """# Partners

## Live Verification Status

| Adapter | Result |
|---|---|
| `provider_01` Example | Not run |
| `provider_02` Example | Not run |

## Next section
"""


def _tree(tmp_path: Path) -> Path:
    """A minimal docs/partners tree with one pinned deposit and one JSON record."""
    root = tmp_path / "docs" / "partners"
    (root / "provider_01").mkdir(parents=True)
    (root / "provider_02" / "deposit").mkdir(parents=True)
    (root / "README.md").write_text(_STATUS_README, encoding="utf-8")
    (root / "provider_01" / "SPEC.md").write_text("# Spec\n\nBody.\n", encoding="utf-8")
    (root / "provider_01" / "record.json").write_text('{"a": 1}\n', encoding="utf-8")
    deposit = root / "provider_02" / "deposit"
    (deposit / "README.md").write_text("# Deposited\n", encoding="utf-8")
    (deposit / "NOTES.md").write_text("# Not pinned\n", encoding="utf-8")
    digest = hashlib.sha256((deposit / "README.md").read_bytes()).hexdigest()
    (deposit / "MANIFEST.sha256").write_text(f"{digest}  README.md\n", encoding="utf-8")
    return root


def _snapshot(root: Path) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_every_partner_document_in_the_repository_carries_the_banner() -> None:
    assert gate.violations() == []
    assert len(gate.partner_docs()) > 0


def test_banner_states_only_what_holds_for_every_document() -> None:
    banner = gate.expected_banner(gate.PARTNERS_ROOT / "provider_01" / "SPEC.md")
    prose = " ".join(line.removeprefix("> ") for line in banner.splitlines())
    assert "Third-party integration material" in prose
    assert "not a Google certification or endorsement of the partner" in prose
    assert "](../README.md#live-verification-status)" in prose
    # The prototype's claims do not hold for every document (spec §4.2, item 2).
    for claim in ("Partner-authored", "Google-authored", "CLA", "AUTHOR_SELF_TEST"):
        assert claim not in prose


def test_the_link_climbs_to_the_status_table_from_any_depth(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    nested = root / "provider_02" / "deposit" / "NOTES.md"
    assert "](../../README.md#live-verification-status)" in gate.expected_banner(
        nested, root
    )


def test_apply_inserts_the_banner_under_the_title_once(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    spec = root / "provider_01" / "SPEC.md"
    assert any("provider_01/SPEC.md" in error for error in gate.violations(root))

    changed = gate.apply_banners(root)
    assert spec in changed
    banner = gate.expected_banner(spec, root)
    assert spec.read_text(encoding="utf-8") == f"# Spec\n\n{banner}\n\nBody.\n"
    assert gate.violations(root) == []
    assert gate.apply_banners(root) == [], "applying twice must change nothing"


@pytest.mark.parametrize(
    "edit",
    [
        lambda text: text.replace("../README.md", "../OTHER.md"),
        lambda text: text.replace("Third-party", "Partner-authored"),
        lambda text: text.replace("# Spec\n\n", "# Spec\n\nIntro first.\n\n"),
    ],
    ids=["stale-link", "edited-wording", "misplaced"],
)
def test_stale_or_misplaced_banners_fail_and_apply_restores_them(
    tmp_path: Path, edit: Callable[[str], str]
) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    spec = root / "provider_01" / "SPEC.md"
    spec.write_text(edit(spec.read_text(encoding="utf-8")), encoding="utf-8")
    assert any("provider_01/SPEC.md" in error for error in gate.violations(root))
    gate.apply_banners(root)
    assert gate.violations(root) == []


def test_pinned_deposits_and_non_markdown_files_are_never_modified(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path)
    before = _snapshot(root)
    changed = set(gate.apply_banners(root))
    after = _snapshot(root)

    deposit = root / "provider_02" / "deposit"
    assert root / "README.md" not in changed
    assert deposit / "README.md" not in gate.partner_docs(root)
    assert deposit / "NOTES.md" in changed, "only files the manifest pins are exempt"
    untouched = [
        root / "README.md",
        root / "provider_01" / "record.json",
        deposit / "README.md",
        deposit / "MANIFEST.sha256",
    ]
    for path in untouched:
        assert after[path] == before[path], path


def test_the_status_table_must_list_every_partner_directory(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    (root / "provider_03").mkdir()
    assert gate.violations(root) == [
        "docs/partners/README.md: '## Live Verification Status' has no row for "
        "provider_03"
    ]


def test_the_status_heading_must_exist(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    gate.apply_banners(root)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace("## Live Verification", "## Old"),
        encoding="utf-8",
    )
    (error,) = gate.violations(root)
    assert "no '## Live Verification Status' heading" in error
