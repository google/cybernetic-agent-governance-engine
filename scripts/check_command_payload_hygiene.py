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

"""check_command_payload_hygiene.py — Reproducible Command/Payload Contract Mirror (POAM-2026-214 / POAM-2026-258)

Pure-stdlib property mirror for the external pre-execution command guard's
path-vs-payload separation, group-aware ``gh`` write classification and flag
parsing, upload-intended ``ask`` vs. public ``deny`` routing, 0-commit
``git push`` fail-closed invariant, and chained ``git commit && git push``
deny scoped per repository root.

Shared Option-Set & Shape Contract (Lockstep with External Guard)
-----------------------------------------------------------------------
* **Always-file long flags:** ``--body-file``, ``--input``, ``--notes-file``,
  and ``--from-file`` (space-separated and ``=`` forms).
* **Subcommand-gated ``@file`` vs. plain-path flags (``-F``, ``--field``):**
  * ``group in {"api", "workflow"}``: ``-F`` and ``--field`` resolve ``@<path>`` /
    ``<key>=@<path>`` (space-separated, ``=``-joined, and attached ``-F@<path>`` /
    ``-F<key>=@<path>``). Values without ``@`` stay in scanned inline text.
  * Other ``gh`` subcommands (``release``, ``agent-task``, ``pr``, ``issue``):
    ``-F`` treats its value as a plain filename (matching ``--notes-file``,
    ``--from-file``, and ``--body-file``); ``--field`` is ignored outside
    ``api``/``workflow``.
* **Group-gated file flags:**
  * ``group == "pr"``: ``-T`` / ``--template`` reads a template file. In
    ``gh api``, ``-t`` / ``--template`` is a Go output format string and stays
    scanned inline.
  * ``group in {"secret", "variable"}``: ``-f`` / ``--env-file`` reads a
    dotenv file and routes findings to ``ask_findings`` (upload-intended,
    matching the external ``ask_sc`` second ``Scanner`` rather than ``deny``).
    In ``api`` / ``workflow`` / ``pr`` etc., ``-f`` / ``--raw-field`` is a
    static string or non-file flag and stays scanned inline.
* **Group-aware write classification (``GH_GROUP_WRITE_VERBS``):**
  Classifies ``gh workflow run`` as a write while leaving ``gh run view`` /
  ``gh workflow view`` read-only, plus ``api`` method/payload write detection.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.check_project_id_hygiene import PROHIBITED_IDENTIFIERS

_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|"})

#: File-payload options and group-scoped shapes mirrored in lockstep with the
#: external guard after Patches 1, 2, 3a, group-aware write detection, and 3b.
SUPPORTED_FILE_PAYLOAD_OPTIONS: tuple[str, ...] = (
    "--body-file",
    "--input",
    "--notes-file",
    "--from-file",
    "--template (pr)",
    "--env-file (secret/variable)",
    "-F",
    "--field @",
    "-f (secret/variable)",
    "-T (pr)",
)

GH_AT_VALUE_GROUPS: frozenset[str] = frozenset({"api", "workflow"})
GH_ENV_FILE_GROUPS: frozenset[str] = frozenset({"secret", "variable"})
GH_GROUP_WRITE_VERBS: dict[str, frozenset[str]] = {
    "workflow": frozenset({"run"}),
    "release": frozenset({"create", "edit", "upload"}),
    "agent-task": frozenset({"create"}),
    "secret": frozenset({"set", "delete"}),
    "variable": frozenset({"set", "delete"}),
    "pr": frozenset({"create", "comment", "edit", "merge", "review", "revert"}),
    "issue": frozenset(
        {"create", "comment", "edit", "close", "reopen", "transfer", "develop"}
    ),
    "gist": frozenset({"create", "edit"}),
}

_PLAIN_PATH_FLAGS = frozenset({"--body-file", "--input", "--notes-file", "--from-file"})
_PR_TEMPLATE_FLAGS = frozenset({"--template", "-T"})
_ENV_FILE_FLAGS = frozenset({"--env-file", "-f"})
_API_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class CommandAuditOutcome:
    """Structured command/payload audit outcome separating deny vs. ask verdicts."""

    deny_violations: tuple[str, ...]
    ask_findings: tuple[str, ...] = ()
    gh_is_write: bool | None = None


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


def _extract_gh_group_verb(tokens: Sequence[str]) -> tuple[str | None, str | None]:
    group: str | None = None
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--":
            break
        if tok in {"-R", "--repo", "--hostname"}:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        if group is None:
            group = tok
            if group == "api":
                return ("api", None)
        else:
            return (group, tok)
        idx += 1
    return (group, None)


def _is_gh_write_invocation(
    tokens: Sequence[str], group: str | None, verb: str | None
) -> bool:
    if group == "api":
        method = "GET"
        has_payload_flag = False
        idx = tokens.index("api", 1) + 1 if "api" in tokens[1:] else 2
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in {"-X", "--method"} and idx + 1 < len(tokens):
                method = tokens[idx + 1].upper()
                idx += 2
                continue
            if tok.startswith(("--method=", "-X")) and len(tok) > 2:
                method = tok.split("=", 1)[1].upper() if "=" in tok else tok[2:].upper()
            if tok in {
                "-f",
                "-F",
                "--field",
                "--raw-field",
                "--input",
            } or tok.startswith(("-f", "-F", "--field=", "--raw-field=", "--input=")):
                has_payload_flag = True
            idx += 1
        return method in _API_WRITE_METHODS or has_payload_flag
    if group is None or verb is None:
        return False
    return verb in GH_GROUP_WRITE_VERBS.get(group, ())


def _git_repo_key(directory: Path) -> Path:
    resolved = directory.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / ".git").exists():
            return candidate
    return resolved


def _parse_git_segment(tokens: Sequence[str], cwd: Path) -> tuple[str | None, Path]:
    if not tokens or Path(tokens[0]).name != "git":
        return (None, cwd)
    git_dir = cwd
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "-C" and idx + 1 < len(tokens):
            git_dir = git_dir / Path(tokens[idx + 1]).expanduser()
            idx += 2
            continue
        if tok.startswith("-C") and len(tok) > 2:
            git_dir = git_dir / Path(tok[2:]).expanduser()
            idx += 1
            continue
        if tok in {"-c", "--git-dir", "--work-tree", "--namespace"} and idx + 1 < len(
            tokens
        ):
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return (tok, git_dir)
    return (None, git_dir)


def _consume_gh_file_option(
    tokens: Sequence[str],
    idx: int,
    group: str | None,
) -> tuple[str, str | None, bool, int] | None:
    """Parse a gh file-reference option at ``tokens[idx]``.

    Returns ``(scrubbed_stub, raw_path_or_none, is_upload_intended, next_idx)``
    or ``None`` if ``tokens[idx]`` stays inline in command text.
    """
    tok = tokens[idx]
    has_next = idx + 1 < len(tokens)
    next_val = tokens[idx + 1] if has_next else ""

    if tok in _PLAIN_PATH_FLAGS and has_next:
        if next_val == "-":
            return (f"{tok} -", None, False, idx + 2)
        return (tok, next_val, False, idx + 2)
    if any(tok.startswith(f"{flag}=") for flag in _PLAIN_PATH_FLAGS):
        prefix, _, path_val = tok.partition("=")
        if path_val == "-":
            return (tok, None, False, idx + 1)
        return (f"{prefix}=", path_val, False, idx + 1)

    if group == "pr":
        if tok in _PR_TEMPLATE_FLAGS and has_next:
            return (tok, None if next_val == "-" else next_val, False, idx + 2)
        if tok.startswith(("--template=", "-T=")):
            prefix, _, path_val = tok.partition("=")
            return (
                tok if path_val == "-" else f"{prefix}=",
                None if path_val == "-" else path_val,
                False,
                idx + 1,
            )

    if group in GH_ENV_FILE_GROUPS:
        if tok in _ENV_FILE_FLAGS and has_next:
            return (tok, None if next_val == "-" else next_val, True, idx + 2)
        if tok.startswith(("--env-file=", "-f=")):
            prefix, _, path_val = tok.partition("=")
            return (
                tok if path_val == "-" else f"{prefix}=",
                None if path_val == "-" else path_val,
                True,
                idx + 1,
            )

    is_at_group = group in GH_AT_VALUE_GROUPS
    if (tok == "-F" or (tok == "--field" and is_at_group)) and has_next:
        if is_at_group:
            extracted = _extract_at_path(next_val)
            if extracted is not None and extracted[1] != "-":
                return (f"{tok} {extracted[0]}", extracted[1], False, idx + 2)
            return (f"{tok} {next_val}", None, False, idx + 2)
        return (tok, None if next_val == "-" else next_val, False, idx + 2)

    if tok.startswith("-F=") or (tok.startswith("--field=") and is_at_group):
        prefix, _, rhs = tok.partition("=")
        if is_at_group:
            extracted = _extract_at_path(rhs)
            if extracted is not None and extracted[1] != "-":
                return (f"{prefix}={extracted[0]}", extracted[1], False, idx + 1)
            return (tok, None, False, idx + 1)
        return (f"{prefix}=", None if rhs == "-" else rhs, False, idx + 1)

    if tok.startswith("-F") and len(tok) > 2:
        attached = tok[2:]
        if is_at_group:
            extracted = _extract_at_path(attached)
            if extracted is not None and extracted[1] != "-":
                return (f"-F{extracted[0]}", extracted[1], False, idx + 1)
            return (tok, None, False, idx + 1)
        return ("-F", None if attached == "-" else attached, False, idx + 1)

    return None


def _inspect_segment(
    tokens: Sequence[str],
    *,
    cwd: Path,
    prohibited_identifiers: Sequence[str],
    unpushed_commit_count: int | None,
    pending_commits: set[Path] | None = None,
) -> tuple[list[str], list[str], bool | None]:
    """Scan tokens after excising subcommand-aware file paths, returning (deny, ask, gh_is_write)."""
    deny_violations: list[str] = []
    ask_findings: list[str] = []
    git_sub, git_dir = _parse_git_segment(tokens, cwd)
    if git_sub == "commit" and pending_commits is not None:
        pending_commits.add(_git_repo_key(git_dir))
    elif git_sub == "push":
        if pending_commits is not None and _git_repo_key(git_dir) in pending_commits:
            deny_violations.append(
                "git push guard refused chained git commit && git push (split commit and push)"
            )
        elif unpushed_commit_count == 0:
            deny_violations.append(
                "git push guard refused vacuous 0-commit scan (split commit and push)"
            )

    scrubbed_tokens: list[str] = []
    referenced_files: list[tuple[str, bool]] = []
    is_gh = bool(tokens) and Path(tokens[0]).name == "gh"
    group, verb = _extract_gh_group_verb(tokens) if is_gh else (None, None)
    gh_is_write = _is_gh_write_invocation(tokens, group, verb) if is_gh else None

    idx = 0
    while idx < len(tokens):
        if is_gh:
            consumed = _consume_gh_file_option(tokens, idx, group)
            if consumed is not None:
                stub, raw_path, is_ask_only, next_idx = consumed
                scrubbed_tokens.append(stub)
                if raw_path:
                    referenced_files.append((raw_path, is_ask_only))
                idx = next_idx
                continue
        scrubbed_tokens.append(tokens[idx])
        idx += 1

    scrubbed_text = " ".join(scrubbed_tokens)
    for ident in prohibited_identifiers:
        if ident in scrubbed_text:
            deny_violations.append(
                f"command arguments/data contain prohibited identifier {ident!r}"
            )

    for raw_path, is_ask_only in referenced_files:
        resolved = Path(raw_path)
        if not resolved.is_absolute():
            resolved = cwd / resolved
        try:
            payload = resolved.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            deny_violations.append(
                f"referenced payload file {raw_path!r} unreadable (fail closed): {exc}"
            )
            continue
        for ident in prohibited_identifiers:
            if ident in payload:
                if is_ask_only:
                    ask_findings.append(
                        f"upload-intended file {raw_path!r} contains prohibited identifier {ident!r}"
                    )
                else:
                    deny_violations.append(
                        f"referenced payload {raw_path!r} contains prohibited identifier {ident!r}"
                    )
    return deny_violations, ask_findings, gh_is_write


def audit_command_payloads_outcome(
    cmdline: str,
    *,
    cwd: Path | None = None,
    prohibited_identifiers: Sequence[str] = PROHIBITED_IDENTIFIERS,
    unpushed_commit_count: int | None = None,
) -> CommandAuditOutcome:
    """Audit a shell command line returning separate deny violations and upload-intended asks."""
    current_dir = cwd if cwd is not None else Path(".")
    deny_violations: list[str] = []
    ask_findings: list[str] = []
    seen_gh_write: bool | None = None
    pending_commits: set[Path] = set()
    try:
        segments = _split_shell_segments(cmdline)
    except ValueError as exc:
        deny_violations.append(f"unparseable shell command line (fail closed): {exc}")
        for ident in prohibited_identifiers:
            if ident in cmdline:
                deny_violations.append(
                    f"raw command line contains prohibited identifier {ident!r}"
                )
        return CommandAuditOutcome(
            deny_violations=tuple(deny_violations),
            ask_findings=(),
            gh_is_write=None,
        )

    for segment in segments:
        if segment and Path(segment[0]).name in {"cd", "pushd"}:
            target = segment[1] if len(segment) > 1 else str(Path.home())
            current_dir = current_dir / Path(target).expanduser()
            continue
        seg_deny, seg_ask, seg_gh_write = _inspect_segment(
            segment,
            cwd=current_dir,
            prohibited_identifiers=prohibited_identifiers,
            unpushed_commit_count=unpushed_commit_count,
            pending_commits=pending_commits,
        )
        deny_violations.extend(seg_deny)
        ask_findings.extend(seg_ask)
        if seg_gh_write is not None:
            seen_gh_write = bool(seen_gh_write) or seg_gh_write
    return CommandAuditOutcome(
        deny_violations=tuple(deny_violations),
        ask_findings=tuple(ask_findings),
        gh_is_write=seen_gh_write,
    )


def audit_command_payloads(
    cmdline: str,
    *,
    cwd: Path | None = None,
    prohibited_identifiers: Sequence[str] = PROHIBITED_IDENTIFIERS,
    unpushed_commit_count: int | None = None,
) -> list[str]:
    """Audit a shell command line and return fail-closed deny violations.

    Mirrors the external pre-execution command guard contract across ``POAM-2026-214``
    and ``POAM-2026-258``: clean payloads at paths matching a denylist token pass,
    leaks inside referenced public payloads/inline flags/heredocs and 0-commit
    ``git push`` calls fail closed in ``deny_violations``, and matches inside
    upload-intended ``--env-file`` / ``secret|variable -f`` files route to
    :attr:`CommandAuditOutcome.ask_findings` rather than ``deny_violations``.
    """
    return list(
        audit_command_payloads_outcome(
            cmdline,
            cwd=cwd,
            prohibited_identifiers=prohibited_identifiers,
            unpushed_commit_count=unpushed_commit_count,
        ).deny_violations
    )
