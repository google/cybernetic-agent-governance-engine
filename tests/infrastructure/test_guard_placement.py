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
"""POAM-2026-180: no new standalone guards in the Terraform configuration.

A targeted plan includes only its targets and what they depend on. A guard,
meaning a ``terraform_data`` or ``null_resource`` that only carries a
precondition, is skipped by ``terraform plan -target=<the resource it protects>``
when nothing in its module refers to it, and its check goes with it. The
placement matrix in the comment below ``control_plane_access_guard`` in
``infra/targets/gcp-gke/main.tf`` records where a check goes instead: a
lifecycle precondition on the resource it protects.

``KNOWN_STANDALONE_GUARDS`` lists the guards that predate the matrix. POAM-2026-180
tracks moving them. Remove an entry when its guard moves; never add one.

The scan relies on the layout ``terraform fmt`` writes: top-level blocks open at
column 0 and close with a ``}`` line at column 0. It drops whole-line comments,
and ignores references from ``output`` blocks, which a plan targeted at a
resource does not need.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRA_DIR = REPO_ROOT / "infra"

# (module directory relative to the repository root, resource name).
KNOWN_STANDALONE_GUARDS = frozenset(
    {
        ("infra/targets/gcp-gke", "control_plane_access_guard"),
        ("infra/targets/gcp-gke", "inference_backend_guard"),
        ("infra/targets/gcp-gke", "memorystore_ca_pinning_guard"),
        ("infra/targets/gcp-gke", "poam_019_empty_key_guard"),
        ("infra/targets/gcp-gke", "poam_019_shared_key_guard"),
    }
)

MATRIX = (
    "the placement matrix in the comment below "
    "terraform_data.control_plane_access_guard in infra/targets/gcp-gke/main.tf"
)

_TOP_LEVEL = re.compile(r"^[a-z_]+\b.*\{\s*$")
_GUARD_HEADER = re.compile(
    r'^resource\s+"(terraform_data|null_resource)"\s+"([^"]+)"\s*\{\s*$'
)
_GUARD_DECLARATION = re.compile(
    r'^resource\s+"(?:terraform_data|null_resource)"\s', re.MULTILINE
)
_CHECK = re.compile(r"\b(?:precondition|postcondition)\s*\{")
_PROVISIONER = re.compile(r'\bprovisioner\s+"')


def _top_level_blocks(text: str) -> list[str]:
    """Top-level blocks of one .tf file, whole-line comments removed."""
    lines = [
        line for line in text.splitlines() if not line.lstrip().startswith(("#", "//"))
    ]
    blocks: list[str] = []
    i = 0
    while i < len(lines):
        if _TOP_LEVEL.match(lines[i]):
            j = i
            while j < len(lines) and lines[j] != "}":
                j += 1
            blocks.append("\n".join(lines[i : j + 1]))
            i = j
        i += 1
    return blocks


def _is_guard(block: str) -> bool:
    return _GUARD_HEADER.match(block.split("\n", 1)[0]) is not None


def standalone_guards(module_dir: Path) -> set[str]:
    """Guards in one module that no other block in that module refers to."""
    blocks = [
        block
        for path in sorted(module_dir.glob("*.tf"))
        for block in _top_level_blocks(path.read_text(encoding="utf-8"))
    ]
    found: set[str] = set()
    for index, block in enumerate(blocks):
        header = _GUARD_HEADER.match(block.split("\n", 1)[0])
        if not header or not _CHECK.search(block) or _PROVISIONER.search(block):
            continue
        resource_type, name = header.groups()
        reference = re.compile(rf"\b{resource_type}\.{re.escape(name)}\b")
        referred_to = any(
            reference.search(other)
            for other_index, other in enumerate(blocks)
            if other_index != index and not other.startswith("output")
        )
        if not referred_to:
            found.add(name)
    return found


def _module_dirs() -> list[Path]:
    return sorted(
        {
            path.parent
            for path in INFRA_DIR.rglob("*.tf")
            if not any(part.startswith(".terraform") for part in path.parts)
        }
    )


def _all_standalone_guards() -> set[tuple[str, str]]:
    return {
        (module_dir.relative_to(REPO_ROOT).as_posix(), name)
        for module_dir in _module_dirs()
        for name in standalone_guards(module_dir)
    }


def test_no_new_standalone_guards() -> None:
    new = sorted(_all_standalone_guards() - KNOWN_STANDALONE_GUARDS)
    assert not new, (
        f"New standalone guard(s) {new}: nothing in the module refers to them, so a "
        "plan targeted at the resource they protect skips their check. Put the check "
        f"in a lifecycle precondition on that resource; see {MATRIX}."
    )


def test_known_standalone_guards_are_still_standalone() -> None:
    gone = sorted(KNOWN_STANDALONE_GUARDS - _all_standalone_guards())
    assert not gone, (
        f"{gone} are no longer standalone guards (moved, referred to or removed). "
        "Delete them from KNOWN_STANDALONE_GUARDS and record the change under "
        "POAM-2026-180 in docs/POAM.md."
    )


def test_scan_reads_every_guard_type_resource() -> None:
    """Every terraform_data and null_resource in infra/ parses as a whole block."""
    for module_dir in _module_dirs():
        for path in sorted(module_dir.glob("*.tf")):
            text = path.read_text(encoding="utf-8")
            parsed = [b for b in _top_level_blocks(text) if _is_guard(b)]
            assert len(parsed) == len(_GUARD_DECLARATION.findall(text)), path
            assert all(block.endswith("\n}") for block in parsed), path


# ─── The detector, on configurations whose answer is known ─────────────────────

_GUARD = """resource "terraform_data" "guard" {
  lifecycle {
    precondition {
      condition     = length(var.allowlist) > 0
      error_message = "the allowlist is empty"
    }
  }
}
"""

_CLUSTER = """resource "terraform_data" "cluster" {
  input = var.allowlist
}
"""


def _module(tmp_path: Path, *sources: str) -> Path:
    for number, source in enumerate(sources):
        (tmp_path / f"file_{number}.tf").write_text(source, encoding="utf-8")
    return tmp_path


def test_detector_finds_a_guard_nothing_refers_to(tmp_path: Path) -> None:
    assert standalone_guards(_module(tmp_path, _GUARD, _CLUSTER)) == {"guard"}


def test_detector_finds_a_null_resource_guard(tmp_path: Path) -> None:
    guard = _GUARD.replace('"terraform_data" "guard"', '"null_resource" "guard"')
    assert standalone_guards(_module(tmp_path, guard, _CLUSTER)) == {"guard"}


def test_detector_accepts_a_guard_the_protected_resource_depends_on(
    tmp_path: Path,
) -> None:
    cluster = _CLUSTER.replace(
        "  input = var.allowlist\n",
        "  input      = var.allowlist\n  depends_on = [terraform_data.guard]\n",
    )
    assert standalone_guards(_module(tmp_path, _GUARD, cluster)) == set()


def test_detector_accepts_a_precondition_on_the_protected_resource(
    tmp_path: Path,
) -> None:
    cluster = _GUARD.replace(
        '"terraform_data" "guard"', '"google_container_cluster" "primary"'
    )
    assert standalone_guards(_module(tmp_path, cluster)) == set()


def test_detector_accepts_a_resource_that_does_the_work(tmp_path: Path) -> None:
    deployer = _GUARD.replace(
        "  lifecycle {",
        '  provisioner "local-exec" {\n    command = "true"\n  }\n\n  lifecycle {',
    )
    assert standalone_guards(_module(tmp_path, deployer)) == set()


def test_detector_ignores_comments_and_outputs(tmp_path: Path) -> None:
    cluster = _CLUSTER.replace(
        "  input = var.allowlist\n",
        "  # Planned after terraform_data.guard.\n  input = var.allowlist\n",
    )
    output = 'output "guard_id" {\n  value = terraform_data.guard.id\n}\n'
    assert standalone_guards(_module(tmp_path, _GUARD, cluster, output)) == {"guard"}
