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

"""Keep packages/cage-conformance a byte-identical, standalone copy of proof/.

The standalone verifier must apply exactly the checks CAGE's own suite applies,
so it never forks the formal model or the checkers
(``docs/architecture/CONFORMANCE_VERIFIER_SPEC.md`` §2.2). This gate fails if:

1. a module in ``SYNC_PAIRS`` differs, byte for byte, from its ``proof/``
   original;
2. any package module imports ``src`` or ``proof`` (absolute ``proof`` imports
   would only resolve inside a CAGE checkout).

Fix a sync failure by copying from ``proof/`` into the package, never the other
way round.

Usage:
    uv run python scripts/check_conformance_sync.py
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_SRC = REPO_ROOT / "packages" / "cage-conformance" / "src" / "cage_conformance"

#: proof/ module -> its packaged copy (relative to the repository root).
SYNC_PAIRS: tuple[tuple[str, str], ...] = tuple(
    (f"proof/{name}", f"packages/cage-conformance/src/cage_conformance/{name}")
    for name in ("model.py", "trace_conformance.py", "stream_invariants.py")
)

FORBIDDEN_ROOTS = frozenset({"src", "proof"})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Each ``SYNC_PAIRS`` entry that is missing or differs from ``proof/``."""
    errors: list[str] = []
    for original, copy in SYNC_PAIRS:
        source, packaged = repo_root / original, repo_root / copy
        if not source.is_file() or not packaged.is_file():
            missing = original if not source.is_file() else copy
            errors.append(f"{missing} does not exist")
            continue
        if _sha256(source) != _sha256(packaged):
            errors.append(f"{copy} differs from {original}: copy it from proof/")
    return errors


def import_violations(package_src: Path = PACKAGE_SRC) -> list[str]:
    """Each import of ``src`` or ``proof`` in the package."""
    if not package_src.is_dir():
        return [f"{package_src} does not exist"]
    errors: list[str] = []
    for path in sorted(package_src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                if name.split(".")[0] in FORBIDDEN_ROOTS:
                    errors.append(
                        f"{path.relative_to(package_src.parent)}:{node.lineno}: "
                        f"imports {name!r}"
                    )
    return errors


def main() -> int:
    errors = sync_violations() + import_violations()
    for error in errors:
        print(f"❌ {error}", file=sys.stderr)
    if errors:
        return 1
    print(
        f"✅ cage-conformance: {len(SYNC_PAIRS)} proof modules byte-identical, "
        "no src/ or proof/ imports"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
