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

"""check_command_payload_hygiene.py — Reproducible Command/Payload Contract Mirror (POAM-2026-214)

Pure-stdlib property mirror for the external pre-execution command guard's
path-vs-payload separation and 0-commit ``git push`` fail-closed invariant.

Shared Option-Set Contract
--------------------------
The external pre-execution guard's referenced-payload reader (``leak_guard.py:672-687``)
opens files named by:

* ``--body-file <path>`` and ``--body-file=<path>``
* ``--input <path>`` and ``--input=<path>``
* ``-F <key>=@<path>``, ``-F@<path>``, ``-F<key>=@<path>``, ``--field <key>=@<path>``,
  ``--field=<key>=@<path>``, ``--raw-field <key>=@<path>``, and ``--raw-field=<key>=@<path>``

This module excises **only** those exact file-naming option values from the
command-line scan and reads their referenced files using the same extractor so
the excision set and reader set cannot silently drift apart. Inline flags
(``--body``, ``--title``), heredoc bodies, and ``-F`` values without ``@``
remain in the scanned command text.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path

from scripts.check_project_id_hygiene import PROHIBITED_IDENTIFIERS

_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|"})

#: Exact option set mirrored from the external referenced-payload reader
#: (``leak_guard.py:672-687``). Any divergence between this set and the external
#: reader either reopens a path false positive or opens a payload bypass.
SUPPORTED_FILE_PAYLOAD_OPTIONS: tuple[str, ...] = (
    "--body-file",
    "--input",
    "-F @",
    "--field @",
    "--raw-field @",
)

_PATH_FLAGS = frozenset({"--body-file", "--input"})
_AT_VALUE_FLAGS = frozenset({"-F", "--field", "--raw-field"})


def _split_shell_segments(cmdline: str) -> list[list[str]]:
    lexer = shlex.shlex(cmdline, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    segments: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _extract_at_path(value: str) -> tuple[str, str] | None:
    if value.startswith("@"):
        return ("@", value[1:])
    if "=@" in value:
        key, _, path = value.partition("=@")
        return (f"{key}=@", path)
    return None


def _is_git_push_segment(tokens: Sequence[str]) -> bool:
    if not tokens or Path(tokens[0]).name != "git":
        return False
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return tok == "push"
    return False


def _inspect_segment(
    tokens: Sequence[str],
    *,
    cwd: Path,
    prohibited_identifiers: Sequence[str],
    unpushed_commit_count: int | None,
) -> list[str]:
    """Scan command tokens after excising file-payload paths, and scan those files."""
    violations: list[str] = []
    if unpushed_commit_count == 0 and _is_git_push_segment(tokens):
        violations.append(
            "git push guard refused vacuous 0-commit scan (split commit and push)"
        )

    scrubbed_tokens: list[str] = []
    referenced_paths: list[str] = []
    is_gh = bool(tokens) and Path(tokens[0]).name == "gh"
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if is_gh and tok in _PATH_FLAGS and idx + 1 < len(tokens):
            scrubbed_tokens.append(tok)
            next_val = tokens[idx + 1]
            if next_val == "-":
                scrubbed_tokens.append(next_val)
            else:
                referenced_paths.append(next_val)
            idx += 2
            continue
        if is_gh and any(tok.startswith(f"{flag}=") for flag in _PATH_FLAGS):
            flag_prefix, _, path_val = tok.partition("=")
            if path_val == "-":
                scrubbed_tokens.append(tok)
            else:
                scrubbed_tokens.append(f"{flag_prefix}=")
                referenced_paths.append(path_val)
            idx += 1
            continue
        if is_gh and tok in _AT_VALUE_FLAGS and idx + 1 < len(tokens):
            scrubbed_tokens.append(tok)
            extracted = _extract_at_path(tokens[idx + 1])
            if extracted is not None and extracted[1] != "-":
                scrubbed_tokens.append(extracted[0])
                referenced_paths.append(extracted[1])
            else:
                scrubbed_tokens.append(tokens[idx + 1])
            idx += 2
            continue
        if is_gh and (
            tok.startswith("-F")
            or tok.startswith("--field=")
            or tok.startswith("--raw-field=")
        ):
            prefix, sep, rhs = tok.partition("=")
            if not sep and tok.startswith("-F@"):
                scrubbed_tokens.append("-F@")
                if tok[3:] != "-":
                    referenced_paths.append(tok[3:])
                idx += 1
                continue
            if sep:
                extracted = _extract_at_path(rhs)
                if extracted is not None and extracted[1] != "-":
                    scrubbed_tokens.append(f"{prefix}={extracted[0]}")
                    referenced_paths.append(extracted[1])
                    idx += 1
                    continue
        scrubbed_tokens.append(tok)
        idx += 1

    scrubbed_text = " ".join(scrubbed_tokens)
    for ident in prohibited_identifiers:
        if ident in scrubbed_text:
            violations.append(
                f"command arguments/data contain prohibited identifier {ident!r}"
            )

    for raw_path in referenced_paths:
        resolved = Path(raw_path)
        if not resolved.is_absolute():
            resolved = cwd / resolved
        try:
            payload = resolved.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            violations.append(
                f"referenced payload file {raw_path!r} unreadable (fail closed): {exc}"
            )
            continue
        for ident in prohibited_identifiers:
            if ident in payload:
                violations.append(
                    f"referenced payload {raw_path!r} contains prohibited identifier {ident!r}"
                )
    return violations


def audit_command_payloads(
    cmdline: str,
    *,
    cwd: Path | None = None,
    prohibited_identifiers: Sequence[str] = PROHIBITED_IDENTIFIERS,
    unpushed_commit_count: int | None = None,
) -> list[str]:
    """Audit a shell command line by excising file-payload paths and reading their files.

    Mirrors the contract of the external referenced-payload reader
    (``leak_guard.py:672-687``): a clean payload referenced via
    :data:`SUPPORTED_FILE_PAYLOAD_OPTIONS` at a path containing a denylist token
    must pass, while leaks inside referenced files, inline flags, heredocs, or
    0-commit ``git push`` calls fail closed (``POAM-2026-214``).
    """
    base_dir = cwd if cwd is not None else Path(".")
    violations: list[str] = []
    try:
        segments = _split_shell_segments(cmdline)
    except ValueError as exc:
        violations.append(f"unparseable shell command line (fail closed): {exc}")
        for ident in prohibited_identifiers:
            if ident in cmdline:
                violations.append(
                    f"raw command line contains prohibited identifier {ident!r}"
                )
        return violations

    for segment in segments:
        violations.extend(
            _inspect_segment(
                segment,
                cwd=base_dir,
                prohibited_identifiers=prohibited_identifiers,
                unpushed_commit_count=unpushed_commit_count,
            )
        )
    return violations
