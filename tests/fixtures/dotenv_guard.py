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

"""No ``.env`` file may reach a hermetic test session.

Tests take configuration from the process environment and nowhere else. A
``.env`` file changes results without appearing in the command that produced
them, and ``git clean`` keeps it, so it survives in a reused worktree. On
2026-11-01 one left behind by a quickstart run turned 87 tests red. The same
mechanism could turn red tests green: a file that sets
``CAGE_SEAL_STRICT_MODE=false`` would do what twenty test modules once did,
with no test naming it (POAM-2026-120).

``tests/conftest.py`` no longer reads ``.env``, but other code still can.
litellm, which ``src`` imports, calls ``load_dotenv()`` when it is imported.
python-dotenv searches upward from the calling file, and the virtualenv lives
inside the repository, so that search reaches the repository's ``.env`` and
every parent directory's. A hermetic session therefore refuses to start while
any such file exists, instead of trusting that nothing loads it.

Live runs (the options in :data:`LIVE_RUN_OPTIONS`) are exempt: they depend on
the environment by design. They get their values from the shell, or explicitly
from ``uv run --env-file <file> pytest ...``.
"""

from __future__ import annotations

import sysconfig
from collections.abc import Iterable
from pathlib import Path

LIVE_RUN_OPTIONS = (
    "--run-integration",
    "--run-live-external",
    "--run-partner-integration",
    "--run-e2e",
)


def search_starts() -> tuple[Path, ...]:
    """Where a ``load_dotenv()`` call made during a test session starts searching.

    Test code (this directory), the working directory, and installed packages
    (litellm's call starts in ``site-packages``).
    """
    return (
        Path(__file__).resolve().parent,
        Path.cwd(),
        Path(sysconfig.get_paths()["purelib"]).resolve(),
    )


def reachable_dotenv_files(starts: Iterable[Path]) -> list[Path]:
    """Every ``.env`` file in one of ``starts`` or any of its parent directories."""
    found: list[Path] = []
    for start in starts:
        for directory in (start, *start.parents):
            candidate = directory / ".env"
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
    return found


def refusal(found: list[Path], *, live_run: bool) -> str | None:
    """Why the session must not start, or ``None`` if it may."""
    if live_run or not found:
        return None
    files = "\n".join(f"  {path}" for path in found)
    return (
        "Refusing to start a hermetic test session: a .env file can reach it.\n"
        f"{files}\n"
        "Tests take configuration from the process environment only. litellm,\n"
        "which src imports, loads the first .env above its install directory\n"
        "when it is imported, so this file could change results partway through\n"
        "the run. Move it aside for the run (mv .env .env.local-stack). A live\n"
        "run is exempt and can take the file's values explicitly:\n"
        "  uv run --env-file .env pytest --run-integration ..."
    )
