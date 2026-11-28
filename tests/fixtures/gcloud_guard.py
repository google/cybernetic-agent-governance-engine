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

"""Keep host ``gcloud`` unreachable across every hermetic test session.

``gcloud`` is one instance of a broader defect class: unmocked host
subprocesses in tests marked ``[unit, local]`` (alongside ``git``, ``kubectl``,
and ``terraform``). When a unit or local test forgets to mock ``_gcloud`` or
bind ``CAGE_CALLER_PRINCIPAL``, calling the runner's ``gcloud`` binary reads
host auth state locally or stalls up to the subprocess timeout in CI.

Unlike ``tests/fixtures/require_live.py`` (which fails *live* partner runs on
``skip``/``xfail``), this guard hardens *hermetic* sessions (none of
``tests.fixtures.dotenv_guard.LIVE_RUN_OPTIONS`` passed):

1. Allowance is strictly **explicit, never inferred from ``PATH`` or
   ``tmp_path`` resolution**: a hermetic test that legitimately invokes a
   test-local ``gcloud`` stub must carry ``@pytest.mark.allow_hermetic_gcloud``.
2. Without ``@pytest.mark.allow_hermetic_gcloud``, any direct ``subprocess``
   invocation targeting ``gcloud`` fails closed immediately in Python
   (:class:`HermeticGcloudError`), and any indirect child process (e.g.
   ``bash``) sees a blocker ``gcloud`` shim prepended at index 0 of ``PATH``
   that exits non-zero and logs to a teardown-checked sentinel.
3. Even with ``@pytest.mark.allow_hermetic_gcloud``, the blocker shim is
   inserted ahead of host ``gcloud`` directories in child ``PATH`` so host
   ``gcloud`` binaries remain unreachable by accident while test-local stubs
   prepended earlier in ``PATH`` execute normally.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

ALLOW_HERMETIC_GCLOUD_MARKER = "allow_hermetic_gcloud"
HERMETIC_GCLOUD_EXIT_CODE = 97
_GCLOUD_BASENAMES = frozenset({"gcloud", "gcloud.cmd", "gcloud.exe"})
_SHELL_SEGMENT_RE = re.compile(r"(?:&&|\|\||;|\|)")


class HermeticGcloudError(RuntimeError):
    """Raised when an un-opted-in hermetic test attempts to invoke ``gcloud``."""


def discover_host_gcloud_dirs(path_value: str | None = None) -> tuple[str, ...]:
    """Return every directory on ``PATH`` that holds a host ``gcloud`` binary."""
    search_path = os.environ.get("PATH", "") if path_value is None else path_value
    dirs: list[str] = []
    for entry in search_path.split(os.pathsep):
        if not entry:
            continue
        for candidate_name in _GCLOUD_BASENAMES:
            candidate = Path(entry) / candidate_name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                norm = os.path.normpath(entry)
                if norm not in dirs:
                    dirs.append(norm)
                break
    resolved = shutil.which("gcloud", path=search_path)
    if resolved:
        parent = os.path.normpath(str(Path(resolved).parent))
        if parent not in dirs:
            dirs.append(parent)
    return tuple(dirs)


def _basename_is_gcloud(token: str) -> bool:
    if not token:
        return False
    tail = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return tail in _GCLOUD_BASENAMES


def _first_command_token(args: object, executable: object = None) -> str | None:
    if executable is not None:
        return os.fsdecode(os.fspath(executable))  # type: ignore[arg-type]
    if isinstance(args, (bytes, os.PathLike)):
        return os.fsdecode(os.fspath(args))
    if isinstance(args, str):
        return args
    if isinstance(args, Sequence) and args:
        return os.fsdecode(os.fspath(args[0]))
    return None


def is_gcloud_command(
    args: object,
    executable: object = None,
    *,
    shell: bool = False,
) -> bool:
    """Return ``True`` when a subprocess invocation directly executes ``gcloud``."""
    if executable is not None and _basename_is_gcloud(
        os.fsdecode(os.fspath(executable))  # type: ignore[arg-type]
    ):
        return True
    if isinstance(args, (bytes, os.PathLike)):
        return _basename_is_gcloud(os.fsdecode(os.fspath(args)))
    if isinstance(args, str):
        return _shell_text_invokes_gcloud(args) if shell else _basename_is_gcloud(args)
    if isinstance(args, Sequence) and args:
        return _basename_is_gcloud(os.fsdecode(os.fspath(args[0])))
    return False


def targets_host_gcloud_dir(
    args: object,
    executable: object,
    host_gcloud_dirs: Iterable[str],
    *,
    shell: bool = False,
) -> bool:
    """Return ``True`` when an explicit path points directly at a host ``gcloud`` dir."""
    host_set = {os.path.normpath(d) for d in host_gcloud_dirs if d}
    if not host_set or not is_gcloud_command(args, executable, shell=shell):
        return False
    token = _first_command_token(args, executable)
    if not token or ("/" not in token and "\\" not in token):
        return False
    return os.path.normpath(str(Path(token).parent)) in host_set


def _shell_text_invokes_gcloud(cmd_text: str) -> bool:
    for segment in _SHELL_SEGMENT_RE.split(cmd_text):
        stripped = segment.strip()
        if not stripped:
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("env", "command"):
                idx += 1
                continue
            if "=" in tok and not tok.startswith("-"):
                idx += 1
                continue
            if _basename_is_gcloud(tok):
                return True
            break
    return False


def ensure_gcloud_blocker_dir(blocker_dir: Path, sentinel_log: Path) -> Path:
    """Create a fail-closed ``gcloud`` blocker executable in ``blocker_dir``."""
    blocker_dir.mkdir(parents=True, exist_ok=True)
    sentinel_log.parent.mkdir(parents=True, exist_ok=True)
    shim = blocker_dir / "gcloud"
    shim.write_text(
        "#!/usr/bin/env sh\n"
        f'printf "gcloud %s\\n" "$*" >> "{sentinel_log}"\n'
        'printf "[hermetic-gcloud-guard] Blocked unpermitted gcloud call: gcloud %s\\n" "$*" >&2\n'
        f"exit {HERMETIC_GCLOUD_EXIT_CODE}\n",
        encoding="utf-8",
    )
    shim.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return blocker_dir


def guard_subprocess_env(
    env: Mapping[str, str] | None,
    *,
    blocker_dir: Path,
    opted_in: bool,
    host_gcloud_dirs: Iterable[str] = (),
) -> dict[str, str]:
    """Return child ``env`` with ``blocker_dir`` positioned per opt-in policy."""
    merged: dict[str, str] = {}
    source = os.environ if env is None else env
    for key, val in source.items():
        k_str = os.fsdecode(key) if isinstance(key, bytes) else str(key)
        v_str = os.fsdecode(val) if isinstance(val, bytes) else str(val)
        merged[k_str] = v_str

    raw_path = merged.get("PATH", os.environ.get("PATH", ""))
    parts = [p for p in raw_path.split(os.pathsep) if p]
    blocker_str = os.path.normpath(str(blocker_dir))
    parts = [p for p in parts if os.path.normpath(p) != blocker_str]

    if not opted_in:
        merged["PATH"] = os.pathsep.join([blocker_str, *parts])
        return merged

    host_set = {os.path.normpath(d) for d in host_gcloud_dirs if d}
    if not host_set:
        return merged

    new_parts: list[str] = []
    inserted = False
    for part in parts:
        if not inserted and os.path.normpath(part) in host_set:
            new_parts.append(blocker_str)
            inserted = True
        new_parts.append(part)
    if not inserted:
        new_parts.append(blocker_str)
    merged["PATH"] = os.pathsep.join(new_parts)
    return merged


def direct_refusal_message(nodeid: str, args: object) -> str:
    """Format an actionable fail-closed error for un-opted-in ``gcloud`` calls."""
    return (
        f"Hermetic test {nodeid} attempted to invoke gcloud ({args!r}) without mocking "
        f"or @pytest.mark.{ALLOW_HERMETIC_GCLOUD_MARKER}.\n"
        "Hermetic [unit, local] runs never probe host gcloud auth/config state.\n"
        "Fix by mocking _gcloud / subprocess.run, setting CAGE_CALLER_PRINCIPAL / "
        "CAGE_GCP_ACCESS_TOKEN, adding @pytest.mark.allow_hermetic_gcloud for an explicit "
        "stub test, or marking a real cluster test @pytest.mark.integration / live_external."
    )
