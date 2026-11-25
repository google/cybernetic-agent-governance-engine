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

"""scripts/check_doc_references.py

Validates that Markdown documentation files do not contain broken links,
dangling file paths, or outdated Python symbol references with respect to
the live repository tree.

Paths removed from HEAD are cited pinned to a commit where they existed, in
git's own revision syntax: `<sha>:<path>` or `<sha>^:<path>`. A pinned path is
verified against history: the commit must exist and be an ancestor of HEAD, and
the path must exist in that commit. Verification needs full history and fails
closed in a shallow clone (CI checks out with fetch-depth: 0). Pins break if
history is rewritten; whoever rewrites `main` owns re-pinning them.

The label of a Markdown link with a local target is display text: the target is
the reference, and it is what gets verified.

There is no waiver. A record withdrawn as untrue is preserved verbatim under
`compliance/archive/retracted/`, and its first non-empty line is a dated notice,
`> **RETRACTED YYYY-MM-DD** ...`, naming a POAM item that has a row in
`docs/POAM.md`. The gate verifies the notice and that row, then skips the
preserved body; a record there without both is reported and checked in full.

In a branch-naming table row, `| Purpose | <pattern> | <example> |` with the
pattern a backticked branch name built from `<placeholder>` parts, the example
is a branch name, not a path: it is verified against its pattern, not the
filesystem.

Usage:
    uv run --active python scripts/check_doc_references.py
    uv run --active python scripts/check_doc_references.py --output /tmp/doc_references_report.txt
    uv run --active python scripts/check_doc_references.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import functools
import io
import json
import re
import shutil
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import tomllib
import yaml

REPO_ROOT = Path.cwd().resolve()
STRICT_SYMBOL_ANCHORS = False


class _DuplicateKeyRejectingLoader(yaml.SafeLoader):
    """YAML SafeLoader that raises ConstructorError with 1-indexed line info on duplicate keys."""


def _construct_no_dup_yaml_mapping(
    loader: _DuplicateKeyRejectingLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            line_1 = (key_node.start_mark.line + 1) if key_node.start_mark else 1
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate YAML mapping key {key!r} at line {line_1}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_DuplicateKeyRejectingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_no_dup_yaml_mapping,
)

# The gate's scope, and the only copy of it: CI gate G9 and `make docs-check`
# run this script without --path. CHANGELOG.md and docs/partners/** are outside
# it by design (a changelog must be free to name removed paths; the partner tree
# carries a known backlog). Most of the rest of docs/ is outside it until
# POAM-2026-224 widens it area by area, so a document outside DOC_SCOPE is
# unverified, not verified.
DOC_SCOPE = (
    "README.md",
    "AGENTS.md",
    "COMPLIANCE.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/POAM.md",
    "docs/BREAKING_CHANGES.md",
    "docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md",
    "docs/compliance/cross-region/POAM_INDEX.md",
    "docs/compliance/us_fed/POAM_US_FED.md",
    "docs/compliance/universal/POAM_ISO42001.md",
    "docs/compliance/eu_ecb/POAM_EU_ECB.md",
    "docs/compliance/apac_mas/POAM_APAC_MAS.md",
    "docs/operations/ALERT_QUEUE_READBACK.md",
    "docs/architecture",
    "compliance",
    "infra",
)
DOC_ROOTS = [REPO_ROOT / entry for entry in DOC_SCOPE]

# A record withdrawn as untrue moves here verbatim. Its first non-empty line is a
# dated notice naming the POAM item that withdrew it; the gate verifies the
# notice and that item's row in docs/POAM.md, then skips the preserved body.
# This is the gate's only exclusion.
RETRACTED_ARCHIVE = "compliance/archive/retracted"
RETRACTION_NOTICE_PATTERN = re.compile(
    r"^> \*\*RETRACTED (?P<date>\d{4}-\d{2}-\d{2})\*\*.*?\b(?P<poam>POAM-\d{4}-\d{3,})\b"
)

# Markdown link: [text](target)
MD_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# Inline code backticks: `code`
INLINE_CODE_PATTERN = re.compile(r"`([^`\n]+)`")
# Revision-pinned path: `<sha>:<path>` or `<sha>^:<path>` (with optional trailing `:line` or `#anchor`)
PINNED_PATH_PATTERN = re.compile(
    r"^(?P<commit>[0-9a-f]{7,40})(?P<parent>\^?):(?P<path>(?:\.[A-Za-z0-9_]|[A-Za-z0-9_])[A-Za-z0-9_./-]*)(?::L?\d+(?:[-\u2013]L?\d+)?|#[^\s]+)?$"
)
GIT_TIMEOUT_SECONDS = 30

# Concrete file extensions to check
CONCRETE_EXTENSIONS = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".sh",
    ".rego",
    ".co",
    ".sql",
    ".proto",
    ".tf",
    ".tfvars",
    ".hcl",
    ".example",
    ".mk",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
}

# Literal words or tokens to ignore
IGNORED_TOKENS = {
    "true",
    "false",
    "null",
    "none",
    "main",
    "master",
    "head",
    "code",
    "default",
}


@dataclass
class Issue:
    source_file: Path
    line_number: int
    reference_type: str
    target: str
    reason: str


@dataclass(frozen=True)
class SymbolSpan:
    name: str
    kind: str
    start_line: int
    end_line: int


@dataclass
class AnchorStats:
    tier1_structural: int = 0
    tier2_scoped_subtoken: int = 0


# Markdown link line anchor: #L<start> or #L<start>-L<end>
LINE_ANCHOR_PATTERN = re.compile(r"#L(\d+)(?:-L(\d+))?$")
# Markdown or inline hash symbol anchor: #<symbol> or #<symbol>:<subtoken>
HASH_SYMBOL_ANCHOR_PATTERN = re.compile(r"#(?P<anchor>(?!L\d+(?:-L\d+)?$)[^#\s]+)$")
# Inline double-colon symbol anchor: path/to/file.ext::<symbol>[#<subtoken>]
DOUBLE_COLON_ANCHOR_PATTERN = re.compile(
    r"^(?P<path>[A-Za-z0-9_./-]+(?:\.[a-z0-9]+|Makefile|Dockerfile))::(?P<anchor>[^\s]+)$"
)
# Structured table-row ID anchor in Markdown files (e.g. #POAM-2026-011, #EU-001)
MD_ROW_ID_ANCHOR_PATTERN = re.compile(
    r"^(?:POAM|AI600|EU|MAS|UCA|H|SC)-[A-Za-z0-9_.-]+$"
)
# Inline colon line anchor: path/to/file.ext:<line_spec>
COLON_LINE_SPEC_PATTERN = re.compile(
    r"^(?P<path>[A-Za-z0-9_./-]+\.[a-z0-9]+):(?P<spec>\d+(?:[-\u2013]\d+)?(?:,\d+(?:[-\u2013]\d+)?)*)$"
)
# Prose line citation immediately following a file link or inline file path
PROSE_LINE_REF_PATTERN = re.compile(
    r"(?:\[(?P<label>[^\]]+)\]\((?P<link>[^)]+)\)|`(?P<codepath>[A-Za-z0-9_./-]+\.[a-z0-9]+)`)"
    r"(?:\s*,\s*|\s+|\s*\(\s*|\s+at\s+|\s*\(`)(?:`?lines?\s+(?P<spec>\d+(?:[-\u2013]\d+)?(?:\s*,\s*\d+(?:[-\u2013]\d+)?)*)`?)"
)
# Standalone line range on a line that also links a YAML file and a UUID
STANDALONE_LINE_RANGE_PATTERN = re.compile(r"`?lines\s+(?P<spec>\d+[-\u2013]\d+)`?")
# Unpinned prose line-number patterns rejected when STRICT_SYMBOL_ANCHORS is True
UNPINNED_PROSE_LINE_WORD_PATTERN = re.compile(
    r"\blines?\s+\d+(?:[-\u2013]\d+)?(?:\s*,\s*\d+(?:[-\u2013]\d+)?)*",
    re.IGNORECASE,
)
UNPINNED_PROSE_L_SPAN_PATTERN = re.compile(
    r"(?::L\d+(?:[-\u2013]L?\d+)?|\(\s*(?:L\d{2,}(?:[-\u2013,\s]+L?\d+)*|L[1-9][-\u2013,\s]+L?\d+(?:[-\u2013,\s]+L?\d+)*)\s*\)|\bL\d{2,}(?:[-\u2013]L?\d+)?\b|\bL[1-9][-\u2013]L?\d+\b)"
)
PINNED_CLAUSE_PREFIX_PATTERN = re.compile(
    r"(?:`[0-9a-f]{7,40}\^?:[A-Za-z0-9_./-]+`|(?:at|in|commit|commits)\s+`[0-9a-f]{7,40}\^?`)"
)

# HCL / Terraform block header in .tf files
HCL_HEADER_PATTERN = re.compile(
    r'^\s*(?:(?P<kind>resource|data)\s+"(?P<type>[a-zA-Z0-9_-]+)"\s+"(?P<name>[a-zA-Z0-9_-]+)"'
    r'|(?P<kind2>module|variable|output|check)\s+"(?P<name2>[a-zA-Z0-9_-]+)"'
    r"|(?P<kind3>locals|removed|moved))\s*\{",
    re.MULTILINE,
)
# HCL citations in Markdown backticks
HCL_DECL_SNIPPET_PATTERN = re.compile(
    r'^(?:(?P<kind>resource|data)\s+"(?P<type>[a-z0-9_]+)"\s+"(?P<name>[a-z0-9_]+)"'
    r'|(?P<kind2>module|variable|output|check)\s+"(?P<name2>[a-z0-9_]+)")$'
)
HCL_RES_SNIPPET_PATTERN = re.compile(
    r"^(?P<type>(?:google|kubernetes|helm|random|tls|null|time|local|external|http|archive|terraform)_[a-z0-9_]+)"
    r"\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))*$"
)
HCL_DATA_SNIPPET_PATTERN = re.compile(
    r"^data\.(?P<type>[a-z0-9_]+)\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))*$"
)
HCL_MOD_SNIPPET_PATTERN = re.compile(
    r"^module\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))?$"
)
HCL_NAMED_SNIPPET_PATTERN = re.compile(
    r"^(?P<prefix>var|variable|output|check|locals?)\.(?P<name>[a-z0-9_]+)$"
)
HCL_MOD_META_ARGS = {
    "source",
    "version",
    "count",
    "for_each",
    "providers",
    "depends_on",
}

# Contextual Python symbol patterns:
# 1) `<sym>` in [`file.py`](path.py) or `<sym>` in `path.py`
CTX_PY_IN_PATTERN = re.compile(
    r"(?<!no\s)`(?P<sym>[A-Za-z_][A-Za-z0-9_]*(?:\(\))?)`\s+in\s+"
    r"(?:\[`?(?P<label>[^`\]]+\.py)`?\]\((?P<link>[^)]+\.py(?:#L\d+(?:-L\d+)?)?)\)|`(?P<codepath>[^`]+\.py)`)"
)
# 2) [`file.py`](path.py) (`<sym>`, ...)
CTX_PY_PAREN_PATTERN = re.compile(
    r"\[[^\]]+\]\((?P<link>[^)]+\.py(?:#L\d+(?:-L\d+)?)?)\)\s*\((?P<parens>`[^)]+)\)"
)
PY_CHECKABLE_SYM_PATTERN = re.compile(
    r"^(?:test_[a-zA-Z0-9_]+|Test[A-Za-z0-9_]+|_?[A-Z][A-Z0-9_]{2,}|_[a-z][a-zA-Z0-9_]+|[a-z_][a-zA-Z0-9_]*\(\))$"
)
PY_PAREN_SYM_PATTERN = re.compile(
    r"^(?:test_[a-zA-Z0-9_]+|Test[A-Za-z0-9_]+|[a-z_][a-zA-Z0-9_]*\(\))$"
)
UUID_PATTERN = re.compile(
    r"`(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`"
)


@dataclass(frozen=True)
class TerraformBlock:
    address: str
    file_path: Path
    start_line: int
    end_line: int
    has_index: bool
    module_source: str = ""


def _parse_line_spec(spec: str) -> list[tuple[int, int]]:
    """Parse a line specification like '42', '10-20', or '12, 15-18' into (start, end) pairs."""
    spans: list[tuple[int, int]] = []
    for part in re.split(r"\s*,\s*", spec.strip()):
        match = re.match(r"^(\d+)(?:[-\u2013](\d+))?$", part.strip())
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) is not None else start
            spans.append((start, end))
    return spans


def find_markdown_files() -> list[Path]:
    """Collect all target Markdown files as resolved paths."""
    files: list[Path] = []
    for entry in DOC_SCOPE:
        resolved = (REPO_ROOT / entry).resolve()
        if resolved.is_file() and resolved.suffix == ".md":
            files.append(resolved)
        elif resolved.is_dir():
            files.extend(p.resolve() for p in resolved.rglob("*.md"))
    return sorted(set(files))


def resolve_scoped_markdown_files(path_args: list[str]) -> list[Path]:
    """Resolve explicit --path arguments, allowing .md files or directories outside DOC_ROOTS."""
    default_files = find_markdown_files()
    matched: list[Path] = []
    for raw_path in path_args:
        candidate = Path(raw_path)
        prefix = (
            candidate.resolve()
            if candidate.is_absolute()
            else (REPO_ROOT / candidate).resolve()
        )
        prefix_matches = [
            f for f in default_files if f == prefix or prefix in f.parents
        ]
        if prefix_matches:
            matched.extend(prefix_matches)
        elif prefix.is_file() and prefix.suffix == ".md":
            matched.append(prefix)
        elif prefix.is_dir():
            matched.extend(p.resolve() for p in prefix.rglob("*.md"))
    return sorted(set(matched))


def is_template_or_pattern(text: str) -> bool:
    """Return True if text contains template wildcards or URI markers."""
    # Ignore URI schemes (e.g. gs://, file://, http://)
    if "://" in text:
        return True
    # Ignore placeholders, shell globs, or brace interpolations
    if any(char in text for char in ("<", ">", "{", "}", "*")):
        return True
    return False


def _validate_line_anchor(
    resolved_path: Path, target_path_str: str, *, allow_colon: bool = False
) -> tuple[bool, str]:
    """Validate optional #L<start>[-L<end>] or :<line_spec> anchor against resolved file."""
    stripped = target_path_str.strip().strip("'\"`")
    match = LINE_ANCHOR_PATTERN.search(stripped)
    colon_match = (
        COLON_LINE_SPEC_PATTERN.match(stripped) if (allow_colon and not match) else None
    )
    if not match and not colon_match:
        return True, ""
    anchor_label = match.group(0) if match else f":{colon_match.group('spec')}"  # type: ignore[union-attr]
    if not resolved_path.is_file():
        return (
            False,
            f"Line anchor '{anchor_label}' targets directory '{resolved_path.name}', not a file",
        )
    try:
        file_lines = resolved_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        total_lines = len(file_lines)
    except Exception as err:
        return (
            False,
            f"Failed to read '{resolved_path.name}' for line anchor check: {err}",
        )

    if match:
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else None
        if start < 1:
            return False, f"Line anchor '{anchor_label}' has start line {start} < 1"
        if end is not None and end < start:
            return (
                False,
                f"Line anchor '{anchor_label}' has inverted range ({end} < {start})",
            )
        last_line = end if end is not None else start
        if last_line > total_lines:
            return (
                False,
                f"Line anchor '{anchor_label}' exceeds file length ({total_lines} lines)",
            )
        return True, ""

    for start, end in _parse_line_spec(colon_match.group("spec")):  # type: ignore[union-attr]
        if start < 1:
            return False, f"Line anchor '{anchor_label}' has start line {start} < 1"
        if end < start:
            return (
                False,
                f"Line anchor '{anchor_label}' has inverted range ({end} < {start})",
            )
        if end > total_lines:
            return (
                False,
                f"Line anchor '{anchor_label}' exceeds file length ({total_lines} lines)",
            )
    return True, ""


def _resolve_candidate_path(
    base_dir: Path,
    target_path_str: str,
    *,
    markdown_link: bool = False,
) -> Path | None:
    """Resolve a path string to an existing Path on disk without guessing subtree aliases."""
    stripped_target = target_path_str.strip().strip("'\"`")
    clean_target = re.split(r"[:#]", stripped_target)[0].strip()
    if (
        not clean_target
        or clean_target.lower() in IGNORED_TOKENS
        or is_template_or_pattern(clean_target)
    ):
        return None

    if markdown_link:
        candidates = (
            [REPO_ROOT / clean_target.lstrip("/")]
            if clean_target.startswith("/")
            else [base_dir / clean_target]
        )
    else:
        norm = clean_target[2:] if clean_target.startswith("./") else clean_target
        candidates = (
            [REPO_ROOT / clean_target.lstrip("/")]
            if clean_target.startswith("/")
            else [REPO_ROOT / norm, base_dir / clean_target]
        )

    has_file_anchor = bool(
        LINE_ANCHOR_PATTERN.search(stripped_target)
        or COLON_LINE_SPEC_PATTERN.match(stripped_target)
        or HASH_SYMBOL_ANCHOR_PATTERN.search(stripped_target)
        or DOUBLE_COLON_ANCHOR_PATTERN.match(stripped_target)
    )
    for cand in candidates:
        try:
            resolved = cand.resolve()
            if resolved.exists():
                if has_file_anchor and not resolved.is_file():
                    continue
                return resolved
        except Exception:
            continue
    return None


def _validate_resolved_path_anchors(
    resolved: Path,
    clean_target: str,
    stripped_target: str,
    *,
    allow_colon_anchor: bool = False,
    anchor_stats: AnchorStats | None = None,
) -> tuple[bool, str]:
    """Validate optional line, ::symbol, or #symbol anchors against an existing resolved path."""
    line_match = LINE_ANCHOR_PATTERN.search(stripped_target)
    colon_line_match = (
        COLON_LINE_SPEC_PATTERN.match(stripped_target)
        if (allow_colon_anchor and not line_match)
        else None
    )
    if line_match or colon_line_match:
        if STRICT_SYMBOL_ANCHORS:
            anchor_lbl = (
                line_match.group(0)
                if line_match
                else f":{colon_line_match.group('spec')}"  # type: ignore[union-attr]
            )
            return (
                False,
                f"Unpinned line-number anchor '{anchor_lbl}' is forbidden on live file "
                f"'{resolved.name}'; use a structural symbol anchor (#symbol or ::symbol) "
                f"or pin to '<sha>:{clean_target}'",
            )
        return _validate_line_anchor(
            resolved, stripped_target, allow_colon=allow_colon_anchor
        )

    dbl_match = (
        DOUBLE_COLON_ANCHOR_PATTERN.match(stripped_target)
        if allow_colon_anchor
        else None
    )
    if dbl_match is not None:
        if STRICT_SYMBOL_ANCHORS or "#" in dbl_match.group("anchor"):
            return resolve_symbol_anchor(
                resolved,
                dbl_match.group("anchor"),
                subtoken_sep="#",
                anchor_stats=anchor_stats,
            )
        return True, ""

    hash_match = HASH_SYMBOL_ANCHOR_PATTERN.search(stripped_target)
    if hash_match is not None:
        raw_anchor = hash_match.group("anchor")
        if resolved.suffix.lower() == ".md" and not STRICT_SYMBOL_ANCHORS:
            if not MD_ROW_ID_ANCHOR_PATTERN.match(raw_anchor.split(":", 1)[0]):
                return True, ""
        return resolve_symbol_anchor(
            resolved,
            raw_anchor,
            subtoken_sep=":",
            anchor_stats=anchor_stats,
        )

    return True, ""


def verify_file_path(
    base_dir: Path,
    target_path_str: str,
    *,
    allow_colon_anchor: bool = False,
    markdown_link: bool = False,
    anchor_stats: AnchorStats | None = None,
) -> tuple[bool, str]:
    """Verify if a relative or repo-root path exists on disk and validate any symbol or line anchor."""
    stripped_target = target_path_str.strip().strip("'\"`")
    clean_target = re.split(r"[:#]", stripped_target)[0].strip()
    if not clean_target or clean_target.lower() in IGNORED_TOKENS:
        return True, ""

    if is_template_or_pattern(clean_target):
        return True, ""

    resolved = _resolve_candidate_path(
        base_dir,
        target_path_str,
        markdown_link=markdown_link,
    )
    if resolved is not None:
        return _validate_resolved_path_anchors(
            resolved,
            clean_target,
            stripped_target,
            allow_colon_anchor=allow_colon_anchor,
            anchor_stats=anchor_stats,
        )

    return False, f"Target path '{clean_target}' does not exist on disk"


def _git(repo_root: Path, *args: str) -> tuple[bool, str]:
    """Run git with a fixed argument list (no shell) in *repo_root*."""
    git = shutil.which("git")
    if git is None:
        return False, "git is not installed"
    try:
        result = subprocess.run(
            [git, *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, str(err)
    return result.returncode == 0, result.stdout.strip()


@functools.lru_cache(maxsize=8)
def _history_unavailable(repo_root: Path) -> str:
    """Return why pinned paths cannot be verified in *repo_root*, or "" if they can."""
    if shutil.which("git") is None:
        return "git is not installed, so pinned paths cannot be verified"
    ok, out = _git(repo_root, "rev-parse", "--is-shallow-repository")
    if not ok:
        return "not a git repository, so pinned paths cannot be verified"
    if out == "true":
        return (
            "shallow clone: pinned paths need full history "
            "(git fetch --unshallow; in CI, actions/checkout fetch-depth: 0)"
        )
    return ""


def verify_pinned_path(commit: str, parent: str, path: str) -> tuple[bool, str]:
    """Verify `<commit>[^]:<path>`: an ancestor of HEAD whose tree holds *path*."""
    unavailable = _history_unavailable(REPO_ROOT)
    if unavailable:
        return False, unavailable
    if not _git(REPO_ROOT, "cat-file", "-e", f"{commit}^{{commit}}")[0]:
        return False, f"'{commit}' is not a commit in this repository"
    if not _git(REPO_ROOT, "merge-base", "--is-ancestor", commit, "HEAD")[0]:
        return False, f"commit '{commit}' is not an ancestor of HEAD"
    revision = f"{commit}{parent}"
    if not _git(REPO_ROOT, "cat-file", "-e", f"{revision}:{path}")[0]:
        return False, f"'{path}' does not exist at {revision}"
    return True, ""


def _parse_tf_blocks(text: str, tf_path: Path) -> list[TerraformBlock]:
    """Extract resource, data, module, variable, output, check, local, and removed/moved blocks."""
    lines = text.splitlines()
    blocks: list[TerraformBlock] = []
    resolved_tf = tf_path.resolve() if tf_path.is_absolute() else tf_path
    for match in HCL_HEADER_PATTERN.finditer(text):
        start_line = text.count("\n", 0, match.start()) + 1
        brace_pos = match.end() - 1
        depth = 0
        in_str = False
        esc = False
        end_pos = len(text)
        idx = brace_pos
        while idx < len(text):
            ch = text[idx]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == "#" or (
                    ch == "/" and idx + 1 < len(text) and text[idx + 1] == "/"
                ):
                    nl = text.find("\n", idx)
                    if nl == -1:
                        break
                    idx = nl
                elif ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_pos = idx + 1
                        break
            idx += 1
        end_line = text.count("\n", 0, end_pos) + 1
        block_body = text[match.start() : end_pos]
        has_index = bool(re.search(r"^\s*(?:count|for_each)\s*=", block_body, re.M))
        if match.group("kind"):
            kind = match.group("kind")
            res_type = match.group("type")
            res_name = match.group("name")
            addr = (
                f"{res_type}.{res_name}"
                if kind == "resource"
                else f"data.{res_type}.{res_name}"
            )
            blocks.append(
                TerraformBlock(addr, resolved_tf, start_line, end_line, has_index)
            )
        elif match.group("kind2"):
            kind2 = match.group("kind2")
            name2 = match.group("name2")
            if kind2 == "module":
                src_match = re.search(r'^\s*source\s*=\s*"([^"]+)"', block_body, re.M)
                mod_source = src_match.group(1) if src_match else ""
                blocks.append(
                    TerraformBlock(
                        f"module.{name2}",
                        resolved_tf,
                        start_line,
                        end_line,
                        has_index,
                        mod_source,
                    )
                )
            elif kind2 == "variable":
                blocks.append(
                    TerraformBlock(
                        f"var.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
                blocks.append(
                    TerraformBlock(
                        f"variable.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
            elif kind2 == "output":
                blocks.append(
                    TerraformBlock(
                        f"output.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
            elif kind2 == "check":
                blocks.append(
                    TerraformBlock(
                        f"check.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
        elif match.group("kind3") == "locals":
            brace_depth = 0
            local_starts: list[tuple[str, int]] = []
            for l_idx in range(start_line, end_line + 1):
                line_s = lines[l_idx - 1]
                clean_l = re.sub(r"(#|//).*$", "", line_s)
                if brace_depth == 1:
                    key_m = re.match(r"^\s*([a-zA-Z0-9_]+)\s*=", clean_l)
                    if key_m:
                        local_starts.append((key_m.group(1), l_idx))
                brace_depth += clean_l.count("{") - clean_l.count("}")
            for idx_k, (key_name, l_start) in enumerate(local_starts):
                l_end = (
                    local_starts[idx_k + 1][1] - 1
                    if idx_k + 1 < len(local_starts)
                    else end_line - 1
                )
                l_end = max(l_start, l_end)
                blocks.append(
                    TerraformBlock(
                        f"local.{key_name}", resolved_tf, l_start, l_end, False
                    )
                )
                blocks.append(
                    TerraformBlock(
                        f"locals.{key_name}", resolved_tf, l_start, l_end, False
                    )
                )
        elif match.group("kind3") in {"removed", "moved"}:
            from_m = re.search(r"^\s*from\s*=\s*([a-zA-Z0-9_.-]+)", block_body, re.M)
            if from_m:
                blocks.append(
                    TerraformBlock(
                        from_m.group(1), resolved_tf, start_line, end_line, False
                    )
                )
    return blocks


@functools.lru_cache(maxsize=8)
def _get_terraform_index(
    repo_root: Path,
) -> tuple[
    dict[str, list[TerraformBlock]],
    dict[Path, dict[str, tuple[int, int]]],
    dict[Path, set[str]],
]:
    """Index all .tf files under repo_root/infra."""
    by_addr: dict[str, list[TerraformBlock]] = {}
    by_file: dict[Path, dict[str, tuple[int, int]]] = {}
    mod_attrs: dict[Path, set[str]] = {}
    infra_dir = repo_root / "infra"
    if not infra_dir.is_dir():
        return by_addr, by_file, mod_attrs
    for tf_path in sorted(infra_dir.rglob("*.tf")):
        try:
            text = tf_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for block in _parse_tf_blocks(text, tf_path):
            by_addr.setdefault(block.address, []).append(block)
            by_file.setdefault(block.file_path, {})[block.address] = (
                block.start_line,
                block.end_line,
            )
            if block.address.startswith(("output.", "var.")):
                mod_attrs.setdefault(block.file_path.parent.resolve(), set()).add(
                    block.address.split(".", 1)[1]
                )
    return by_addr, by_file, mod_attrs


def verify_terraform_snippet(
    code_snippet: str, pinned_tf_addrs: set[str] | None = None
) -> tuple[bool, str] | None:
    """If *code_snippet* is a Terraform/HCL symbol or declaration, verify it against infra/*.tf."""
    if any(code_snippet.endswith(ext) for ext in CONCRETE_EXTENSIONS):
        return None
    by_addr, _, mod_attrs = _get_terraform_index(REPO_ROOT)
    if not by_addr:
        return None
    pinned = pinned_tf_addrs or set()

    decl_m = HCL_DECL_SNIPPET_PATTERN.match(code_snippet)
    if decl_m:
        if decl_m.group("kind"):
            addr = (
                f"{decl_m.group('type')}.{decl_m.group('name')}"
                if decl_m.group("kind") == "resource"
                else f"data.{decl_m.group('type')}.{decl_m.group('name')}"
            )
        else:
            kind2 = decl_m.group("kind2")
            name2 = decl_m.group("name2")
            addr = f"var.{name2}" if kind2 == "variable" else f"{kind2}.{name2}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform declaration '{code_snippet}' ({addr}) does not exist in infra/*.tf",
            )
        return True, ""

    res_m = HCL_RES_SNIPPET_PATTERN.match(code_snippet)
    if res_m:
        addr = f"{res_m.group('type')}.{res_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform resource '{addr}' does not exist in infra/*.tf",
            )
        if res_m.group("idx") and addr in by_addr:
            if not any(b.has_index for b in by_addr[addr]):
                return (
                    False,
                    f"Terraform resource '{addr}' has no count/for_each but is cited with index '{res_m.group('idx')}'",
                )
        return True, ""

    data_m = HCL_DATA_SNIPPET_PATTERN.match(code_snippet)
    if data_m:
        addr = f"data.{data_m.group('type')}.{data_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform data source '{addr}' does not exist in infra/*.tf",
            )
        return True, ""

    mod_m = HCL_MOD_SNIPPET_PATTERN.match(code_snippet)
    if mod_m:
        addr = f"module.{mod_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform module '{addr}' does not exist in infra/*.tf",
            )
        attr = mod_m.group("attr")
        if attr and attr not in HCL_MOD_META_ARGS and addr in by_addr:
            found_attr = False
            for block in by_addr[addr]:
                if block.module_source:
                    mod_dir = (block.file_path.parent / block.module_source).resolve()
                    if attr in mod_attrs.get(mod_dir, set()):
                        found_attr = True
                        break
            if not found_attr:
                return (
                    False,
                    f"Attribute/output '{attr}' not found in Terraform module '{addr}'",
                )
        return True, ""

    named_m = HCL_NAMED_SNIPPET_PATTERN.match(code_snippet)
    if named_m:
        addr = f"{named_m.group('prefix')}.{named_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform symbol '{code_snippet}' does not exist in infra/*.tf",
            )
        return True, ""

    return None


@functools.lru_cache(maxsize=256)
def _get_python_file_symbols(py_path: Path, _depth: int = 0) -> set[str]:
    """Collect defined, imported, attribute, and identifier-constant symbols from a Python file."""
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    syms: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            syms.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    syms.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            syms.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                syms.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                syms.add(alias.asname or alias.name)
            if _depth == 0 and node.module and node.module.startswith("src."):
                mod_file = (REPO_ROOT / Path(*node.module.split("."))).with_suffix(
                    ".py"
                )
                if mod_file.is_file():
                    syms.update(_get_python_file_symbols(mod_file, _depth=1))
        elif isinstance(node, ast.arg):
            syms.add(node.arg)
        elif isinstance(node, ast.Attribute):
            syms.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", node.value):
                syms.add(node.value)
    return syms


@functools.lru_cache(maxsize=256)
def _get_python_symbol_spans(py_path: Path) -> list[tuple[str, int, int]]:
    """Return (name, start_line, end_line) for functions and classes in a Python file."""
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    spans: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end_l = getattr(node, "end_lineno", None) or node.lineno
            spans.append((node.name.lower(), node.lineno, end_l))
    return spans


@functools.lru_cache(maxsize=64)
def _get_yaml_uuid_span(yaml_path: Path, uuid_str: str) -> tuple[int, int] | None:
    """Return the (start_line, end_line) of a `- uuid: <uuid_str>` list item in a YAML file."""
    try:
        lines = yaml_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    item_re = re.compile(r"^(\s*)-\s+uuid:\s*" + re.escape(uuid_str) + r"\s*$")
    for idx, line in enumerate(lines):
        match = item_re.match(line)
        if match:
            indent = len(match.group(1))
            start_line = idx + 1
            end_line = len(lines)
            for j in range(idx + 1, len(lines)):
                lj = lines[j]
                if not lj.strip() or lj.lstrip().startswith("#"):
                    continue
                cur_indent = len(lj) - len(lj.lstrip())
                if cur_indent < indent or (
                    cur_indent == indent and lj.lstrip().startswith("- ")
                ):
                    end_line = j
                    break
            return start_line, end_line
    return None


def _find_brace_block_end_line(text: str, open_brace_idx: int) -> int:
    """Return 1-indexed closing line for a `{` at *open_brace_idx*, skipping strings and comments."""
    depth = 0
    in_quote: str | None = None
    esc = False
    idx = open_brace_idx
    end_pos = len(text)
    while idx < len(text):
        ch = text[idx]
        if in_quote is not None:
            if esc:
                esc = False
            elif ch == "\\" and in_quote == '"':
                esc = True
            elif ch == in_quote:
                in_quote = None
        else:
            if ch == "#" or (
                ch == "/" and idx + 1 < len(text) and text[idx + 1] == "/"
            ):
                nl = text.find("\n", idx)
                if nl == -1:
                    break
                idx = nl
            elif ch in {'"', "'"}:
                in_quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_pos = idx + 1
                    break
        idx += 1
    return text.count("\n", 0, end_pos) + 1


def _merge_symbol_spans(spans: list[SymbolSpan]) -> tuple[SymbolSpan, ...]:
    """Merge identical (name, kind) spans (e.g. @overload, @property.setter, multi-clause Rego)."""
    merged: dict[tuple[str, str], SymbolSpan] = {}
    order: list[tuple[str, str]] = []
    for sp in spans:
        key = (sp.name, sp.kind)
        prev = merged.get(key)
        if prev is None:
            merged[key] = sp
            order.append(key)
        else:
            merged[key] = SymbolSpan(
                sp.name,
                sp.kind,
                min(prev.start_line, sp.start_line),
                max(prev.end_line, sp.end_line),
            )
    return tuple(merged[k] for k in order)


def _extract_python_structural_symbols(text: str) -> list[SymbolSpan]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[SymbolSpan] = []

    def _assign_names(target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in target.elts:
                names.extend(_assign_names(elt))
            return names
        return []

    def _walk_scope(stmts: list[ast.stmt], prefix: str) -> None:
        for node in stmts:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{node.name}" if prefix else node.name
                start_l = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                end_l = getattr(node, "end_lineno", None) or node.lineno
                out.append(SymbolSpan(qual, "py_func", start_l, end_l))
            elif isinstance(node, ast.ClassDef):
                qual = f"{prefix}.{node.name}" if prefix else node.name
                start_l = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                end_l = getattr(node, "end_lineno", None) or node.lineno
                out.append(SymbolSpan(qual, "py_class", start_l, end_l))
                _walk_scope(node.body, qual)
            elif isinstance(node, ast.Assign):
                end_l = getattr(node, "end_lineno", None) or node.lineno
                for name in [n for t in node.targets for n in _assign_names(t)]:
                    qual = f"{prefix}.{name}" if prefix else name
                    out.append(SymbolSpan(qual, "py_assign", node.lineno, end_l))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                end_l = getattr(node, "end_lineno", None) or node.lineno
                qual = f"{prefix}.{node.target.id}" if prefix else node.target.id
                out.append(SymbolSpan(qual, "py_assign", node.lineno, end_l))
            elif hasattr(ast, "TypeAlias") and isinstance(node, ast.TypeAlias):
                end_l = getattr(node, "end_lineno", None) or node.lineno
                qual = f"{prefix}.{node.name.id}" if prefix else node.name.id
                out.append(SymbolSpan(qual, "py_type", node.lineno, end_l))
            elif isinstance(node, ast.If):
                _walk_scope(node.body, prefix)
                _walk_scope(node.orelse, prefix)
            elif isinstance(node, ast.Try):
                _walk_scope(node.body, prefix)
                for handler in node.handlers:
                    _walk_scope(handler.body, prefix)
                _walk_scope(node.orelse, prefix)
                _walk_scope(node.finalbody, prefix)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                _walk_scope(node.body, prefix)

    _walk_scope(tree.body, "")
    return out


_HCL_TEST_BLOCK_RE = re.compile(
    r'^\s*(?:(?P<kind>run|mock_provider|provider)\s+"(?P<name>[A-Za-z0-9_-]+)"'
    r"|(?P<vars>variables))\s*\{",
    re.MULTILINE,
)


def _extract_hcl_test_symbols(text: str, resolved_path: Path) -> list[SymbolSpan]:
    out = [
        SymbolSpan(b.address, "tf_block", b.start_line, b.end_line)
        for b in _parse_tf_blocks(text, resolved_path)
    ]
    lines = text.splitlines()
    for match in _HCL_TEST_BLOCK_RE.finditer(text):
        start_l = text.count("\n", 0, match.start()) + 1
        end_l = _find_brace_block_end_line(text, match.end() - 1)
        if match.group("kind"):
            kind = match.group("kind")
            name = match.group("name")
            out.append(SymbolSpan(f"{kind}.{name}", "hcl_block", start_l, end_l))
            if kind == "run":
                out.append(SymbolSpan(name, "hcl_run", start_l, end_l))
        elif match.group("vars"):
            out.append(SymbolSpan("variables", "hcl_vars", start_l, end_l))
            depth = 0
            for l_idx in range(start_l, end_l + 1):
                clean = re.sub(r"(#|//).*$", "", lines[l_idx - 1])
                if depth == 1:
                    km = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=", clean)
                    if km:
                        out.append(
                            SymbolSpan(
                                f"variables.{km.group(1)}", "hcl_var", l_idx, l_idx
                            )
                        )
                depth += clean.count("{") - clean.count("}")
    return out


def _extract_tfvars_symbols(text: str) -> list[SymbolSpan]:
    out: list[SymbolSpan] = []
    lines = text.splitlines()
    depth = 0
    cur_key: str | None = None
    cur_start = 1
    for idx, raw in enumerate(lines, start=1):
        clean = re.sub(r"(#|//).*$", "", raw)
        if depth == 0:
            km = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=", clean)
            if km:
                cur_key = km.group(1)
                cur_start = idx
        delta = (
            clean.count("{") + clean.count("[") - clean.count("}") - clean.count("]")
        )
        depth = max(0, depth + delta)
        if cur_key is not None and depth == 0:
            out.append(SymbolSpan(cur_key, "tfvars_key", cur_start, idx))
            cur_key = None
    if cur_key is not None:
        out.append(SymbolSpan(cur_key, "tfvars_key", cur_start, len(lines)))
    return out


def _extract_yaml_symbols(text: str, resolved_path: Path) -> list[SymbolSpan]:
    out: list[SymbolSpan] = []
    total_lines = max(1, len(text.splitlines()))
    try:
        docs = list(yaml.compose_all(text, Loader=_DuplicateKeyRejectingLoader))
    except yaml.YAMLError:
        return out

    def _node_end_line(node: yaml.Node, start_l: int) -> int:
        if node.end_mark is None:
            return start_l
        # end_mark points at the line after a block mapping/sequence when column == 0
        raw_end = (
            node.end_mark.line
            if node.end_mark.column == 0 and node.end_mark.line >= start_l
            else node.end_mark.line + 1
        )
        return min(total_lines, max(start_l, raw_end))

    def _walk_yaml(node: yaml.Node | None, prefix: str) -> None:
        if isinstance(node, yaml.MappingNode):
            seen_keys: set[str] = set()
            for k_node, v_node in node.value:
                if not isinstance(k_node, yaml.ScalarNode):
                    continue
                key = str(k_node.value).strip()
                if not key or key in seen_keys:
                    continue
                seen_keys.add(key)
                start_l = (k_node.start_mark.line + 1) if k_node.start_mark else 1
                end_l = _node_end_line(v_node, start_l)
                qual = f"{prefix}.{key}" if prefix else key
                out.append(SymbolSpan(qual, "yaml_key", start_l, end_l))
                if prefix == "jobs":
                    out.append(SymbolSpan(key, "yaml_job", start_l, end_l))
                if key == "uuid" and isinstance(v_node, yaml.ScalarNode):
                    u_val = str(v_node.value).strip()
                    if u_val:
                        u_span = _get_yaml_uuid_span(resolved_path, u_val)
                        u_start, u_end = u_span if u_span else (start_l, end_l)
                        out.append(SymbolSpan(u_val, "yaml_uuid", u_start, u_end))
                        out.append(
                            SymbolSpan(f"uuid:{u_val}", "yaml_uuid", u_start, u_end)
                        )
                _walk_yaml(v_node, qual)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                if isinstance(item, yaml.MappingNode):
                    item_start = (item.start_mark.line + 1) if item.start_mark else 1
                    item_end = _node_end_line(item, item_start)
                    for k_node, v_node in item.value:
                        if (
                            isinstance(k_node, yaml.ScalarNode)
                            and isinstance(v_node, yaml.ScalarNode)
                            and k_node.value in {"id", "control-id"}
                        ):
                            id_val = str(v_node.value).strip()
                            if id_val:
                                out.append(
                                    SymbolSpan(
                                        f"{prefix}.{id_val}" if prefix else id_val,
                                        "yaml_item",
                                        item_start,
                                        item_end,
                                    )
                                )
                _walk_yaml(item, prefix)

    for doc_node in docs:
        if isinstance(doc_node, yaml.MappingNode):
            doc_start = (doc_node.start_mark.line + 1) if doc_node.start_mark else 1
            doc_end = _node_end_line(doc_node, doc_start)
            kind_val = ""
            meta_name = ""
            for dk, dv in doc_node.value:
                if isinstance(dk, yaml.ScalarNode):
                    if dk.value == "kind" and isinstance(dv, yaml.ScalarNode):
                        kind_val = str(dv.value).strip()
                    elif dk.value == "metadata" and isinstance(dv, yaml.MappingNode):
                        for mk, mv in dv.value:
                            if (
                                isinstance(mk, yaml.ScalarNode)
                                and mk.value == "name"
                                and isinstance(mv, yaml.ScalarNode)
                            ):
                                meta_name = str(mv.value).strip()
            if kind_val and meta_name:
                out.append(
                    SymbolSpan(
                        f"{kind_val}/{meta_name}", "k8s_resource", doc_start, doc_end
                    )
                )
        _walk_yaml(doc_node, "")
    return out


_JSON_TOK_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null'
)


def _extract_json_symbols(text: str) -> list[SymbolSpan]:
    try:
        json.loads(text)
    except ValueError:
        return []
    tokens = [
        (m.group(0), text.count("\n", 0, m.start()) + 1)
        for m in _JSON_TOK_RE.finditer(text)
    ]
    out: list[SymbolSpan] = []
    pos = 0
    n = len(tokens)

    def _parse_val(prefix: str) -> tuple[int, int, dict[str, str]]:
        nonlocal pos
        if pos >= n:
            return 1, 1, {}
        tok, start_l = tokens[pos]
        if tok == "{":
            pos += 1
            scalars: dict[str, str] = {}
            end_l = start_l
            while pos < n and tokens[pos][0] != "}":
                if tokens[pos][0] == ",":
                    pos += 1
                    continue
                k_tok, k_line = tokens[pos]
                pos += 1
                if pos < n and tokens[pos][0] == ":":
                    pos += 1
                key = json.loads(k_tok) if k_tok.startswith('"') else k_tok
                qual = f"{prefix}.{key}" if prefix else key
                v_tok = tokens[pos][0] if pos < n else ""
                _, v_end, _ = _parse_val(qual)
                end_l = v_end
                out.append(SymbolSpan(qual, "json_key", k_line, v_end))
                if v_tok.startswith('"'):
                    scalars[key] = json.loads(v_tok)
            if pos < n and tokens[pos][0] == "}":
                end_l = tokens[pos][1]
                pos += 1
            return start_l, end_l, scalars
        if tok == "[":
            pos += 1
            end_l = start_l
            while pos < n and tokens[pos][0] != "]":
                if tokens[pos][0] == ",":
                    pos += 1
                    continue
                i_start, i_end, scalars = _parse_val(prefix)
                end_l = i_end
                for id_field in (
                    "id",
                    "action",
                    "action_name",
                    "code",
                    "uca_id",
                    "control_id",
                ):
                    if scalars.get(id_field):
                        ident = scalars[id_field]
                        out.append(
                            SymbolSpan(
                                f"{prefix}.{ident}" if prefix else ident,
                                "json_item",
                                i_start,
                                i_end,
                            )
                        )
                        break
            if pos < n and tokens[pos][0] == "]":
                end_l = tokens[pos][1]
                pos += 1
            return start_l, end_l, {}
        pos += 1
        return start_l, start_l, {}

    _parse_val("")
    return out


def _extract_toml_symbols(text: str) -> list[SymbolSpan]:
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    lines = text.splitlines()
    out: list[SymbolSpan] = []
    cur_sec = ""
    cur_sec_start = 1
    is_array_sec = False
    sec_entries: list[tuple[str, int, bool, dict[str, str]]] = []
    cur_scalars: dict[str, str] = {}
    bracket_depth = 0
    cur_key: str | None = None
    cur_key_start = 1

    def _flush_section(end_line: int) -> None:
        if cur_sec:
            sec_entries.append(
                (cur_sec, cur_sec_start, is_array_sec, dict(cur_scalars))
            )
            out.append(SymbolSpan(cur_sec, "toml_table", cur_sec_start, end_line))
            if is_array_sec and "id" in cur_scalars:
                out.append(
                    SymbolSpan(
                        f"{cur_sec}.{cur_scalars['id']}",
                        "toml_item",
                        cur_sec_start,
                        end_line,
                    )
                )

    for idx, raw in enumerate(lines, start=1):
        clean = re.sub(r"#.*$", "", raw).strip()
        if not clean:
            continue
        if bracket_depth == 0 and clean.startswith("["):
            arr_m = re.match(r"^\[\[([A-Za-z0-9_.\"-]+)\]\]$", clean)
            tbl_m = re.match(r"^\[([A-Za-z0-9_.\"-]+)\]$", clean)
            if arr_m or tbl_m:
                _flush_section(max(cur_sec_start, idx - 1))
                cur_sec = (arr_m.group(1) if arr_m else tbl_m.group(1)).replace('"', "")  # type: ignore[union-attr]
                cur_sec_start = idx
                is_array_sec = bool(arr_m)
                cur_scalars = {}
                continue
        if bracket_depth == 0:
            km = re.match(r'^([A-Za-z0-9_"-]+)\s*=\s*(.*)$', clean)
            if km:
                cur_key = km.group(1).strip('"')
                cur_key_start = idx
                rhs = km.group(2).strip()
                sm = re.match(r'^["\']([^"\']+)["\']$', rhs)
                if sm:
                    cur_scalars[cur_key] = sm.group(1)
        bracket_depth = max(
            0,
            bracket_depth
            + clean.count("[")
            + clean.count("{")
            - clean.count("]")
            - clean.count("}"),
        )
        if cur_key is not None and bracket_depth == 0:
            qual = f"{cur_sec}.{cur_key}" if cur_sec else cur_key
            out.append(SymbolSpan(qual, "toml_key", cur_key_start, idx))
            cur_key = None
    _flush_section(max(1, len(lines)))
    return out


def _extract_rego_symbols(text: str) -> list[SymbolSpan]:
    out: list[SymbolSpan] = []
    pkg_m = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", text, re.MULTILINE)
    if pkg_m:
        ln = text.count("\n", 0, pkg_m.start()) + 1
        out.append(SymbolSpan("package", "rego_pkg", ln, ln))
        out.append(SymbolSpan(pkg_m.group(1), "rego_pkg", ln, ln))
    rule_re = re.compile(
        r"^(?:default\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^\n]*",
        re.MULTILINE,
    )
    reserved = {"package", "import", "as", "some", "every", "not", "with", "else"}
    for m in rule_re.finditer(text):
        name = m.group("name")
        if name in reserved:
            continue
        start_l = text.count("\n", 0, m.start()) + 1
        line_str = m.group(0)
        brace_offset = line_str.find("{")
        end_l = (
            _find_brace_block_end_line(text, m.start() + brace_offset)
            if brace_offset != -1
            else start_l
        )
        out.append(SymbolSpan(name, "rego_rule", start_l, end_l))
    return out


_SH_FUNC_RE = re.compile(
    r"^\s*(?:function\s+(?P<fn1>[A-Za-z_][A-Za-z0-9_-]*)(?:\s*\(\s*\))?|(?P<fn2>[A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\))\s*\{",
    re.MULTILINE,
)


def _extract_shell_functions(text: str) -> list[SymbolSpan]:
    """Tier 1 shell anchors are strictly shell function definitions (never bare vars or flags)."""
    out: list[SymbolSpan] = []
    for m in _SH_FUNC_RE.finditer(text):
        name = m.group("fn1") or m.group("fn2")
        start_l = text.count("\n", 0, m.start()) + 1
        end_l = _find_brace_block_end_line(text, m.end() - 1)
        out.append(SymbolSpan(name, "sh_func", start_l, end_l))
    return out


def _extract_makefile_targets(text: str) -> list[SymbolSpan]:
    lines = text.splitlines()
    out: list[SymbolSpan] = []
    starts: list[tuple[str, int]] = []
    for idx, raw in enumerate(lines, start=1):
        if raw.startswith("\t") or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", raw)
        if m and m.group(1) != ".PHONY":
            starts.append((m.group(1), idx))
    for i, (tgt, s_line) in enumerate(starts):
        next_start = starts[i + 1][1] - 1 if i + 1 < len(starts) else len(lines)
        e_line = s_line
        for ln in range(s_line + 1, next_start + 1):
            if lines[ln - 1].startswith("\t") or lines[ln - 1].rstrip().endswith("\\"):
                e_line = ln
            elif lines[ln - 1].strip():
                break
        out.append(SymbolSpan(tgt, "make_target", s_line, e_line))
    return out


def _github_heading_slug(heading_title: str) -> str:
    title = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading_title)
    title = title.replace("`", "")
    slug = title.lower()
    slug = re.sub(r"[^\w\s-]", "", slug, flags=re.UNICODE)
    return re.sub(r"\s", "-", slug)


def _extract_markdown_symbols(text: str) -> list[SymbolSpan]:
    lines = text.splitlines()
    out: list[SymbolSpan] = []
    headings: list[tuple[str, int, int]] = []
    slug_counts: dict[str, int] = {}
    in_fence = False
    row_re = re.compile(
        r"^\|\s*(?:\*\*)?`?((?:POAM|AI600|EU|MAS|F|UCA|H|SC)-[A-Za-z0-9_.-]+)`?(?:\*\*)?\s*\|"
    )
    id_in_heading_re = re.compile(
        r"\b((?:POAM|AI600|EU|MAS|UCA|H|SC)-\d[A-Za-z0-9_.-]*)\b"
    )
    for idx, raw in enumerate(lines, start=1):
        s = raw.strip()
        if s.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        hm = re.match(r"^(#{1,6})\s+(.+?)\s*#*$", s)
        if hm:
            lvl = len(hm.group(1))
            base_slug = _github_heading_slug(hm.group(2))
            if base_slug:
                cnt = slug_counts.get(base_slug, 0)
                slug_counts[base_slug] = cnt + 1
                slug = base_slug if cnt == 0 else f"{base_slug}-{cnt}"
                headings.append((slug, lvl, idx))
            for id_m in id_in_heading_re.finditer(hm.group(2)):
                out.append(SymbolSpan(id_m.group(1), "md_id_heading", idx, idx))
            continue
        rm = row_re.match(s)
        if rm:
            out.append(SymbolSpan(rm.group(1), "md_row", idx, idx))

    total = max(1, len(lines))
    for i, (slug, lvl, s_line) in enumerate(headings):
        e_line = total
        for _, next_lvl, next_line in headings[i + 1 :]:
            if next_lvl <= lvl:
                e_line = next_line - 1
                break
        out.append(SymbolSpan(slug, "md_heading", s_line, max(s_line, e_line)))
    return out


def _extract_dockerfile_symbols(text: str) -> list[SymbolSpan]:
    lines = text.splitlines()
    out: list[SymbolSpan] = []
    stages: list[tuple[str, int]] = []
    for idx, raw in enumerate(lines, start=1):
        clean = raw.strip()
        if not clean or clean.startswith("#"):
            continue
        fm = re.match(
            r"^FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?", clean, re.IGNORECASE
        )
        if fm:
            stage_name = fm.group(1) or f"stage-{len(stages)}"
            stages.append((stage_name, idx))
            continue
        am = re.match(r"^(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)", clean, re.IGNORECASE)
        if am:
            out.append(SymbolSpan(am.group(1), "docker_var", idx, idx))
    total = max(1, len(lines))
    for i, (st_name, s_line) in enumerate(stages):
        e_line = stages[i + 1][1] - 1 if i + 1 < len(stages) else total
        out.append(SymbolSpan(st_name, "docker_stage", s_line, max(s_line, e_line)))
        out.append(
            SymbolSpan(f"stage:{st_name}", "docker_stage", s_line, max(s_line, e_line))
        )
    return out


_SQL_CREATE_RE = re.compile(
    r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:UNIQUE\s+)?"
    r"(?:TABLE|INDEX|VIEW|MATERIALIZED\s+VIEW|FUNCTION|TRIGGER|TYPE|POLICY)"
    r"\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_sql_symbols(text: str) -> list[SymbolSpan]:
    out: list[SymbolSpan] = []
    for m in _SQL_CREATE_RE.finditer(text):
        name = m.group(1)
        start_l = text.count("\n", 0, m.start()) + 1
        semi_pos = text.find(";", m.end())
        end_l = (
            text.count("\n", 0, semi_pos) + 1
            if semi_pos != -1
            else max(start_l, len(text.splitlines()))
        )
        out.append(SymbolSpan(name, "sql_object", start_l, end_l))
    return out


_TS_DECL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?"
    r"(?P<kw>class|interface|type|enum|function|const|let)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)",
    re.MULTILINE,
)


def _extract_ts_symbols(text: str) -> list[SymbolSpan]:
    out: list[SymbolSpan] = []
    for m in _TS_DECL_RE.finditer(text):
        name = m.group("name")
        start_l = text.count("\n", 0, m.start()) + 1
        brace_pos = text.find("{", m.end())
        semi_pos = text.find(";", m.end())
        if brace_pos != -1 and (semi_pos == -1 or brace_pos < semi_pos):
            end_l = _find_brace_block_end_line(text, brace_pos)
        elif semi_pos != -1:
            end_l = text.count("\n", 0, semi_pos) + 1
        else:
            end_l = start_l
        out.append(SymbolSpan(name, "ts_decl", start_l, max(start_l, end_l)))
    return out


@functools.lru_cache(maxsize=512)
def _extract_structural_symbols_cached(
    resolved_path: Path, mtime_ns: int, size: int
) -> tuple[SymbolSpan, ...]:
    del mtime_ns, size
    try:
        text = resolved_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    suffix = resolved_path.suffix.lower()
    if resolved_path.name == "Makefile" or suffix == ".mk":
        return _merge_symbol_spans(_extract_makefile_targets(text))
    if resolved_path.name == "Dockerfile" or resolved_path.name.startswith(
        "Dockerfile."
    ):
        return _merge_symbol_spans(_extract_dockerfile_symbols(text))
    if suffix == ".py":
        return _merge_symbol_spans(_extract_python_structural_symbols(text))
    if suffix == ".tf":
        return _merge_symbol_spans(
            [
                SymbolSpan(b.address, "tf_block", b.start_line, b.end_line)
                for b in _parse_tf_blocks(text, resolved_path)
            ]
        )
    if suffix == ".hcl":
        return _merge_symbol_spans(_extract_hcl_test_symbols(text, resolved_path))
    if suffix in {".tfvars", ".example"}:
        return _merge_symbol_spans(_extract_tfvars_symbols(text))
    if suffix in {".yaml", ".yml"}:
        return _merge_symbol_spans(_extract_yaml_symbols(text, resolved_path))
    if suffix == ".json":
        return _merge_symbol_spans(_extract_json_symbols(text))
    if suffix == ".toml":
        return _merge_symbol_spans(_extract_toml_symbols(text))
    if suffix == ".rego":
        return _merge_symbol_spans(_extract_rego_symbols(text))
    if suffix == ".sh":
        return _merge_symbol_spans(_extract_shell_functions(text))
    if suffix == ".sql":
        return _merge_symbol_spans(_extract_sql_symbols(text))
    if suffix in {".ts", ".tsx", ".js", ".mjs"}:
        return _merge_symbol_spans(_extract_ts_symbols(text))
    if suffix == ".md":
        return _merge_symbol_spans(_extract_markdown_symbols(text))
    return ()


def extract_structural_symbols(resolved_path: Path) -> tuple[SymbolSpan, ...]:
    """Return Tier 1 structural symbol spans for *resolved_path*."""
    try:
        st = resolved_path.stat()
    except OSError:
        return ()
    return _extract_structural_symbols_cached(
        resolved_path.resolve(), st.st_mtime_ns, st.st_size
    )


def _strip_line_comments_outside_quotes(
    text: str, *, allow_hash: bool, allow_slash: bool, allow_sql_dash: bool
) -> str:
    cleaned_lines: list[str] = []
    for raw in text.splitlines():
        in_q: str | None = None
        esc = False
        cut = len(raw)
        i = 0
        n = len(raw)
        while i < n:
            ch = raw[i]
            if in_q is not None:
                if esc:
                    esc = False
                elif ch == "\\" and in_q in {'"', "'", "`"}:
                    esc = True
                elif ch == in_q:
                    in_q = None
            elif ch in {'"', "'", "`"}:
                in_q = ch
            elif allow_hash and ch == "#":
                cut = i
                break
            elif allow_slash and ch == "/" and i + 1 < n and raw[i + 1] == "/":
                cut = i
                break
            elif allow_sql_dash and ch == "-" and i + 1 < n and raw[i + 1] == "-":
                cut = i
                break
            i += 1
        cleaned_lines.append(raw[:cut])
    return "\n".join(cleaned_lines)


def _strip_comments_in_span(resolved_path: Path, start_line: int, end_line: int) -> str:
    """Return non-comment source lines in [start_line, end_line] for Tier 2 subtoken checks."""
    try:
        all_lines = resolved_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines(keepends=True)
    except OSError:
        return ""
    snippet = "".join(all_lines[max(0, start_line - 1) : end_line])
    suffix = resolved_path.suffix.lower()
    if suffix == ".py":
        kept: list[str] = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(snippet).readline):
                if tok.type != tokenize.COMMENT:
                    kept.append(tok.string)
            return " ".join(kept)
        except tokenize.TokenError:
            pass
    if suffix in {".ts", ".tsx", ".js", ".mjs", ".proto"}:
        no_block = re.sub(r"/\*.*?\*/", " ", snippet, flags=re.DOTALL)
        return _strip_line_comments_outside_quotes(
            no_block, allow_hash=False, allow_slash=True, allow_sql_dash=False
        )
    if suffix in {".tf", ".hcl", ".tfvars"}:
        no_block = re.sub(r"/\*.*?\*/", " ", snippet, flags=re.DOTALL)
        return _strip_line_comments_outside_quotes(
            no_block, allow_hash=True, allow_slash=True, allow_sql_dash=False
        )
    if suffix == ".sql":
        no_block = re.sub(r"/\*.*?\*/", " ", snippet, flags=re.DOTALL)
        return _strip_line_comments_outside_quotes(
            no_block, allow_hash=False, allow_slash=False, allow_sql_dash=True
        )
    if (
        suffix
        in {
            ".sh",
            ".example",
            ".yaml",
            ".yml",
            ".toml",
            ".rego",
        }
        or resolved_path.name in {"Makefile", "Dockerfile"}
        or resolved_path.name.startswith("Dockerfile.")
    ):
        return _strip_line_comments_outside_quotes(
            snippet, allow_hash=True, allow_slash=False, allow_sql_dash=False
        )
    return snippet


def resolve_symbol_anchor(
    resolved_path: Path,
    raw_anchor: str,
    *,
    subtoken_sep: str = ":",
    anchor_stats: AnchorStats | None = None,
) -> tuple[bool, str]:
    """Resolve a Tier 1 structural anchor (or Tier 2 `<symbol><sep><subtoken>` anchor)."""
    if not resolved_path.is_file():
        return (
            False,
            f"Symbol anchor '{raw_anchor}' targets directory '{resolved_path.name}', not a file",
        )
    subtoken: str | None = None
    sym_part = raw_anchor.strip()
    if subtoken_sep == "#":
        if "#" in sym_part:
            sym_part, subtoken = sym_part.split("#", 1)
    elif subtoken_sep == ":":
        if sym_part.startswith(("uuid:", "stage:")):
            pfx, rest = sym_part.split(":", 1)
            if ":" in rest:
                u_part, subtoken = rest.split(":", 1)
                sym_part = f"{pfx}:{u_part}"
        elif ":" in sym_part:
            sym_part, subtoken = sym_part.split(":", 1)

    sym_query = sym_part.replace("::", ".").strip()
    if resolved_path.suffix.lower() == ".py":
        if sym_query.endswith("()"):
            sym_query = sym_query[:-2]
        if "[" in sym_query and sym_query.endswith("]"):
            sym_query = sym_query.split("[", 1)[0]

    if not sym_query:
        return False, f"Empty symbol anchor on '{resolved_path.name}'"

    spans = extract_structural_symbols(resolved_path)
    exact = [s for s in spans if s.name == sym_query]
    if not exact and "." not in sym_query and resolved_path.suffix.lower() == ".py":
        leaf_matches = [s for s in spans if s.name.endswith(f".{sym_query}")]
        if len(leaf_matches) > 1:
            cands = ", ".join(sorted(s.name for s in leaf_matches))
            return (
                False,
                f"Ambiguous unqualified symbol '{sym_query}' in '{resolved_path.name}' "
                f"(matches {cands}); qualify as Class.member",
            )
        exact = leaf_matches

    if not exact:
        if resolved_path.suffix.lower() == ".sh":
            return (
                False,
                f"Shell anchor '{sym_query}' not found among function definitions in "
                f"'{resolved_path.name}' (only shell functions are valid Tier 1 anchors)",
            )
        return (
            False,
            f"Symbol anchor '{sym_query}' not found in '{resolved_path.name}'",
        )

    if len(exact) > 1:
        kinds = {s.kind for s in exact}
        # Merge md_row + md_id_heading for the same POAM ID in a single doc
        if kinds <= {"md_row", "md_id_heading"}:
            target_span = SymbolSpan(
                sym_query,
                "md_id",
                min(s.start_line for s in exact),
                max(s.end_line for s in exact),
            )
        else:
            lines_desc = ", ".join(f"L{s.start_line}" for s in exact)
            return (
                False,
                f"Ambiguous symbol anchor '{sym_query}' in '{resolved_path.name}' ({lines_desc})",
            )
    else:
        target_span = exact[0]

    if subtoken is not None:
        clean_sub = subtoken.strip()
        if len(clean_sub) < 2:
            return (
                False,
                f"Tier 2 subtoken '{clean_sub}' on '{sym_query}' in '{resolved_path.name}' must be >= 2 characters",
            )
        body_no_comments = _strip_comments_in_span(
            resolved_path, target_span.start_line, target_span.end_line
        )
        if clean_sub not in body_no_comments:
            return (
                False,
                f"Tier 2 subtoken '{clean_sub}' not found in non-comment body of "
                f"'{sym_query}' in '{resolved_path.name}'",
            )
        if anchor_stats is not None:
            anchor_stats.tier2_scoped_subtoken += 1
        return True, ""

    if anchor_stats is not None:
        anchor_stats.tier1_structural += 1
    return True, ""


def verify_python_symbol(symbol_str: str) -> tuple[bool, str]:
    """Verify qualified module.Symbol references (e.g. src.gateway.symbolic_governor.SymbolicGovernor)."""
    if is_template_or_pattern(symbol_str):
        return True, ""

    parts = symbol_str.split(".")
    if len(parts) < 2 or parts[0] not in {"src", "tests"}:
        return True, ""

    for i in range(len(parts), 0, -1):
        candidate_path = REPO_ROOT.joinpath(*parts[:i])
        candidate_file = candidate_path.with_suffix(".py")
        candidate_init = candidate_path / "__init__.py"
        if (
            candidate_file.is_file()
            or candidate_init.is_file()
            or candidate_path.is_dir()
        ):
            if candidate_init.is_file():
                candidate_file = candidate_init
            elif candidate_path.is_dir() and not candidate_file.is_file():
                return True, ""
            symbol_name = ".".join(parts[i:])
            if not symbol_name:
                return True, ""

            try:
                tree = ast.parse(candidate_file.read_text(encoding="utf-8"))
                top_level_defs = {
                    node.name
                    for node in tree.body
                    if isinstance(
                        node,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    )
                }
                for node in tree.body:
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                top_level_defs.add(target.id)

                root_symbol = symbol_name.split(".")[0]
                if root_symbol not in top_level_defs:
                    return (
                        False,
                        f"Symbol '{root_symbol}' not found in {candidate_file.relative_to(REPO_ROOT)}",
                    )
                return True, ""
            except Exception as err:
                return (
                    False,
                    f"Failed to parse {candidate_file.relative_to(REPO_ROOT)}: {err}",
                )

    return False, f"Could not resolve module path for symbol '{symbol_str}'"


def _audit_line_references_and_contextual_symbols(
    path: Path, line_idx: int, line: str, local_link_labels: list[tuple[int, int]]
) -> list[Issue]:
    """Validate prose line citations, YAML UUID block spans, and contextual Python symbols on *line*."""
    issues: list[Issue] = []
    historical_line = bool(
        re.search(
            r"(`#?\d+`\s+introduced|commits?\s+`[0-9a-f]{7,40}`|at\s+`[0-9a-f]{7,40}`)",
            line,
        )
    )
    code_spans = [
        (cm.start(), cm.end(), cm.group(1).strip())
        for cm in INLINE_CODE_PATTERN.finditer(line)
        if not any(ls <= cm.start() and cm.end() <= le for ls, le in local_link_labels)
    ]
    line_uuids = [m.group("uuid") for m in UUID_PATTERN.finditer(line)]
    if (
        "_STPA_IMPL_UUID" in line
        and "g7000099-stpa-4000-8000-compiler00001" not in line_uuids
    ):
        line_uuids.append("g7000099-stpa-4000-8000-compiler00001")

    for pm in (
        PROSE_LINE_REF_PATTERN.finditer(line) if not STRICT_SYMBOL_ANCHORS else ()
    ):
        target = pm.group("link") or pm.group("codepath")
        spec = pm.group("spec")
        if not target or is_template_or_pattern(target):
            continue
        resolved = _resolve_candidate_path(path.parent, target)
        if resolved is None or not resolved.is_file():
            continue
        try:
            flines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        total_lines = len(flines)
        spans = _parse_line_spec(spec)
        if not spans:
            continue
        bounds_failed = False
        for start, end in spans:
            if start < 1 or end < start or end > total_lines:
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Line Reference",
                        f"{target} (lines {spec})",
                        f"Cited line range {start}-{end} exceeds file length ({total_lines} lines)",
                    )
                )
                bounds_failed = True
            elif not historical_line and start == end and not flines[start - 1].strip():
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Line Reference",
                        f"{target} (line {start})",
                        f"Cited line {start} in '{resolved.name}' is blank",
                    )
                )
                bounds_failed = True
        if bounds_failed or historical_line:
            continue

        # Check clause-local code identifiers against the cited lines (+/- 1 line)
        window_chunks: list[str] = []
        for start, end in spans:
            lo = max(0, start - 2)
            hi = min(total_lines, end + 1)
            window_chunks.append("\n".join(flines[lo:hi]))
        if resolved.suffix == ".py":
            for sym_name, sym_s, sym_e in _get_python_symbol_spans(resolved):
                if any(sym_s <= end and sym_e >= start for start, end in spans):
                    window_chunks.append(sym_name)
        window_text = "\n".join(window_chunks).lower()

        tokens: set[str] = set()
        label_str = pm.group("label") or ""
        if label_str and not any(
            label_str.strip("`").endswith(ext) for ext in CONCRETE_EXTENSIONS
        ):
            for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{1,}", label_str):
                if ident.lower() not in IGNORED_TOKENS:
                    tokens.add(ident.lower())

        for cs_start, cs_end, cs in code_spans:
            if cs_end < pm.start() - 90 or cs_start > pm.end() + 90:
                continue
            between = line[min(cs_end, pm.end()) : max(cs_start, pm.start())]
            if (
                ";" in between
                or ". " in between
                or " — " in between
                or " | " in between
            ):
                continue
            if (
                cs.startswith(("line ", "lines "))
                or cs == resolved.name
                or cs in target
            ):
                continue
            if re.match(
                r"^(?:POAM-|EF\d|PF\d|W\d|Step\s|#\d+|[0-9a-f]{7,40}|\d+|rc=\d+)",
                cs,
                re.IGNORECASE,
            ):
                continue
            for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{1,}", cs):
                low = ident.lower()
                if (
                    low
                    not in {
                        "line",
                        "lines",
                        "true",
                        "false",
                        "none",
                        "null",
                        "staging",
                        "prod",
                        "main",
                        "yaml",
                        "json",
                        "bash",
                        "in",
                        "on",
                        "to",
                        "of",
                        "or",
                        "if",
                    }
                    and low not in resolved.name.lower()
                ):
                    tokens.add(low)
        if tokens and not any(tok in window_text for tok in tokens):
            issues.append(
                Issue(
                    path,
                    line_idx,
                    "Line Reference",
                    f"{target} (lines {spec})",
                    f"Cited line(s) {spec} in '{resolved.name}' do not contain expected clause token(s) {sorted(tokens)[:4]}",
                )
            )

    # Check YAML UUID span when a YAML link, UUID, and `(lines A-B)` appear on the same line
    if not STRICT_SYMBOL_ANCHORS and line_uuids and not historical_line:
        yaml_links = [
            _resolve_candidate_path(path.parent, m.group(2).strip())
            for m in MD_LINK_PATTERN.finditer(line)
            if m.group(2).strip().endswith((".yaml", ".yml"))
        ]
        resolved_yamls = [y for y in yaml_links if y is not None and y.is_file()]
        if len(resolved_yamls) == 1:
            y_file = resolved_yamls[0]
            for rm in STANDALONE_LINE_RANGE_PATTERN.finditer(line):
                spans = _parse_line_spec(rm.group("spec"))
                if len(spans) == 1:
                    s_line, e_line = spans[0]
                    for u_str in line_uuids:
                        uuid_span = _get_yaml_uuid_span(y_file, u_str)
                        if uuid_span is not None and (s_line, e_line) != uuid_span:
                            issues.append(
                                Issue(
                                    path,
                                    line_idx,
                                    "Line Reference",
                                    f"{y_file.name} (lines {rm.group('spec')})",
                                    f"UUID '{u_str}' block in '{y_file.name}' spans lines {uuid_span[0]}-{uuid_span[1]}, not {s_line}-{e_line}",
                                )
                            )

    # Contextual Python symbol checks:
    for m_in in CTX_PY_IN_PATTERN.finditer(line):
        raw_sym = m_in.group("sym")
        if not PY_CHECKABLE_SYM_PATTERN.match(raw_sym):
            continue
        sym = raw_sym[:-2] if raw_sym.endswith("()") else raw_sym
        target = m_in.group("link") or m_in.group("codepath")
        py_file = _resolve_candidate_path(path.parent, target)
        if py_file and py_file.suffix == ".py":
            py_rel = (
                py_file.relative_to(REPO_ROOT)
                if py_file.is_relative_to(REPO_ROOT)
                else py_file.name
            )
            if sym not in _get_python_file_symbols(py_file):
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Python Symbol",
                        f"{py_rel}::{sym}",
                        f"Symbol '{sym}' not found in {py_rel}",
                    )
                )

    for m_paren in CTX_PY_PAREN_PATTERN.finditer(line):
        target = m_paren.group("link")
        parens = m_paren.group("parens")
        py_file = _resolve_candidate_path(path.parent, target)
        if py_file and py_file.suffix == ".py":
            py_rel = (
                py_file.relative_to(REPO_ROOT)
                if py_file.is_relative_to(REPO_ROOT)
                else py_file.name
            )
            syms = _get_python_file_symbols(py_file)
            for cm in INLINE_CODE_PATTERN.finditer(parens):
                raw_s = cm.group(1).strip()
                if PY_PAREN_SYM_PATTERN.match(raw_s):
                    clean_s = raw_s[:-2] if raw_s.endswith("()") else raw_s
                    if clean_s not in syms:
                        issues.append(
                            Issue(
                                path,
                                line_idx,
                                "Python Symbol",
                                f"{py_rel}::{clean_s}",
                                f"Symbol '{clean_s}' not found in {py_rel}",
                            )
                        )

    return issues


def _is_retracted_record(path: Path) -> bool:
    """Return True if *path* lies under RETRACTED_ARCHIVE."""
    archive = (REPO_ROOT / RETRACTED_ARCHIVE).resolve()
    return archive in path.resolve().parents


def _poam_has_table_row(poam_id: str) -> bool:
    """Return True if docs/POAM.md has a table row `| <poam_id> |`."""
    try:
        poam_text = (REPO_ROOT / "docs" / "POAM.md").read_text(encoding="utf-8")
    except OSError:
        return False
    row = re.compile(rf"^\|\s*{re.escape(poam_id)}\s*\|", re.MULTILINE)
    return row.search(poam_text) is not None


def _audit_retraction_notice(path: Path, lines: list[str]) -> Issue | None:
    """Verify a retracted record's dated notice and its POAM row; None if both hold."""
    line_idx, first = next(
        (
            (idx, line.strip())
            for idx, line in enumerate(lines, start=1)
            if line.strip()
        ),
        (1, ""),
    )
    missing = (
        "Retracted record lacks a dated retraction notice naming an existing POAM item"
    )
    notice = RETRACTION_NOTICE_PATTERN.match(first)
    if notice is None:
        return Issue(
            path,
            line_idx,
            "Retraction Notice",
            first[:90] or path.name,
            f"{missing}: its first non-empty line must read "
            "'> **RETRACTED YYYY-MM-DD** ... POAM-YYYY-NNN ...'",
        )
    try:
        date.fromisoformat(notice["date"])
    except ValueError:
        return Issue(
            path,
            line_idx,
            "Retraction Notice",
            notice["date"],
            f"{missing}: '{notice['date']}' is not a calendar date",
        )
    if not _poam_has_table_row(notice["poam"]):
        return Issue(
            path,
            line_idx,
            "Retraction Notice",
            notice["poam"],
            f"{missing}: {notice['poam']} has no table row in docs/POAM.md",
        )
    return None


# Branch-naming table row: | Purpose | `<branch pattern>` | `<example>` |
BRANCH_PLACEHOLDER_PATTERN = re.compile(r"<([a-z][a-z0-9-]*)>")
BRANCH_LITERAL_PATTERN = re.compile(r"^[a-z0-9/-]*$")
BRANCH_SEMVER_PLACEHOLDERS = frozenset({"version", "semver"})
BRANCH_DESCRIPTION_PLACEHOLDERS = frozenset({"short-description", "description"})
BRANCH_DESCRIPTION_MAX_CHARS = 30  # AGENTS.md: description <= 30 characters
BRANCH_KEBAB_CASE = r"[a-z0-9]+(?:-[a-z0-9]+)*"
BRANCH_SEMVER = r"\d+\.\d+\.\d+"
TABLE_CELL_DELIMITER = re.compile(r"(?<!\\)\|")


def _branch_example_reason(example: str, pattern: str) -> str:
    """Return why *example* does not match branch *pattern*, or "" if it does."""
    parts = BRANCH_PLACEHOLDER_PATTERN.split(pattern)
    regex = "".join(
        re.escape(part)
        if idx % 2 == 0
        else f"({BRANCH_SEMVER if part in BRANCH_SEMVER_PLACEHOLDERS else BRANCH_KEBAB_CASE})"
        for idx, part in enumerate(parts)
    )
    match = re.fullmatch(regex, example)
    if match is None:
        return (
            f"Branch-name example does not match pattern '{pattern}' (<version> and "
            "<semver> are N.N.N; every other placeholder is lowercase kebab-case)"
        )
    for name, value in zip(parts[1::2], match.groups(), strict=True):
        if (
            name in BRANCH_DESCRIPTION_PLACEHOLDERS
            and len(value) > BRANCH_DESCRIPTION_MAX_CHARS
        ):
            return (
                f"Branch-name example's <{name}> part is {len(value)} characters "
                f"(at most {BRANCH_DESCRIPTION_MAX_CHARS})"
            )
    return ""


def _audit_branch_examples(
    path: Path, line_idx: int, line: str
) -> tuple[tuple[int, int] | None, list[Issue]]:
    """Verify the example cell of a branch-naming table row against its pattern cell.

    A row qualifies when its second cell is a single backticked branch pattern:
    `<placeholder>` parts and lowercase literal parts, at least one with a
    letter (`feat/<short-description>`, `rc-v<semver>`). Returns the third
    cell's span, whose backticked tokens are branch names rather than paths, and
    an Issue per mismatch.
    """
    bars = [m.start() for m in TABLE_CELL_DELIMITER.finditer(line)]
    if len(bars) < 4 or line[: bars[0]].strip():
        return None, []
    pattern_cell = re.fullmatch(r"`([^`\s]+)`", line[bars[1] + 1 : bars[2]].strip())
    if pattern_cell is None:
        return None, []
    pattern = pattern_cell.group(1)
    parts = BRANCH_PLACEHOLDER_PATTERN.split(pattern)
    literals = parts[::2]
    if (
        len(parts) < 3
        or not all(BRANCH_LITERAL_PATTERN.match(p) for p in literals)
        or not re.search(r"[a-z]", "".join(literals))
    ):
        return None, []
    cell = (bars[2] + 1, bars[3])
    issues = [
        Issue(path, line_idx, "Branch Example", cm.group(1).strip(), reason)
        for cm in INLINE_CODE_PATTERN.finditer(line, *cell)
        if (reason := _branch_example_reason(cm.group(1).strip(), pattern))
    ]
    return cell, issues


def _audit_unpinned_prose_line_numbers(
    path: Path, line_idx: int, line: str
) -> list[Issue]:
    """Reject unpinned prose `line(s) <n>` and `L<n>` spans when STRICT_SYMBOL_ANCHORS is True."""
    if not STRICT_SYMBOL_ANCHORS:
        return []
    issues: list[Issue] = []
    excluded_spans: list[tuple[int, int]] = [
        m.span(0) for m in re.finditer(r"https?://[^\s)]+", line)
    ]
    for lm in MD_LINK_PATTERN.finditer(line):
        excluded_spans.append(lm.span(2))

    def _is_pinned_clause(match_start: int) -> bool:
        window = line[max(0, match_start - 140) : match_start]
        if "|" in window:
            window = window.rsplit("|", 1)[-1]
        return bool(PINNED_CLAUSE_PREFIX_PATTERN.search(window))

    for pat in (UNPINNED_PROSE_LINE_WORD_PATTERN, UNPINNED_PROSE_L_SPAN_PATTERN):
        for m in pat.finditer(line):
            if any(s <= m.start() and m.end() <= e for s, e in excluded_spans):
                continue
            if _is_pinned_clause(m.start()):
                continue
            tok = m.group(0)
            issues.append(
                Issue(
                    path,
                    line_idx,
                    "Unpinned Line Number",
                    tok,
                    f"Unpinned line citation '{tok}' is forbidden on live files; "
                    "anchor to a structural symbol (#symbol or ::symbol) or pin to '<sha>:<path>'",
                )
            )
    return issues


def audit_markdown_file(
    path: Path,
    *,
    anchor_stats: AnchorStats | None = None,
) -> list[Issue]:
    """Scan a single markdown file for broken file paths, links, and code symbols."""
    issues: list[Issue] = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as err:
        return [Issue(path, 1, "File Read Error", str(path), str(err))]

    lines = content.splitlines()

    # 0. A retracted record: verify its notice and POAM row, then skip its body
    if _is_retracted_record(path):
        notice_issue = _audit_retraction_notice(path, lines)
        if notice_issue is None:
            return []
        issues.append(notice_issue)

    in_fence = False
    for line_idx, line in enumerate(lines, start=1):
        stripped_fence = line.strip()
        if stripped_fence.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue

        # Collect any revision-pinned .tf addresses on this line for historical HCL lookups
        pinned_tf_addrs: set[str] = set()
        for cm in INLINE_CODE_PATTERN.finditer(line):
            pm = PINNED_PATH_PATTERN.match(cm.group(1).strip())
            if pm and pm["path"].endswith(".tf"):
                rev = f"{pm['commit']}{pm['parent']}"
                ok, out = _git(REPO_ROOT, "show", f"{rev}:{pm['path']}")
                if ok:
                    for blk in _parse_tf_blocks(out, Path(pm["path"])):
                        pinned_tf_addrs.add(blk.address)

        # 1. Standard Markdown links: [Text](target)
        local_link_labels: list[tuple[int, int]] = []
        for link in MD_LINK_PATTERN.finditer(line):
            link_target = link.group(2).strip()
            if (
                link_target.startswith(("http://", "https://", "mailto:"))
                or link_target.startswith("#")
                or is_template_or_pattern(link_target)
            ):
                continue

            # The target is the reference; the label is display text.
            local_link_labels.append(link.span(1))
            valid, reason = verify_file_path(
                path.parent,
                link_target,
                markdown_link=True,
                anchor_stats=anchor_stats,
            )
            if not valid:
                issues.append(
                    Issue(path, line_idx, "Markdown Link", link_target, reason)
                )

        # 2. Inline code backticks: `target`. A branch-naming table row's example
        #    is a branch name, verified against its pattern, not a path.
        branch_cell, branch_issues = _audit_branch_examples(path, line_idx, line)
        issues.extend(branch_issues)
        is_mutation_row = bool(re.search(r"\|\s*(?:Re-declare|Restore)\s+`", line))
        for code_match in INLINE_CODE_PATTERN.finditer(line):
            if any(
                start <= code_match.start() and code_match.end() <= end
                for start, end in local_link_labels
            ):
                continue
            if branch_cell is not None and (
                branch_cell[0] <= code_match.start()
                and code_match.end() <= branch_cell[1]
            ):
                continue
            code_snippet = code_match.group(1).strip()

            if (
                not code_snippet
                or code_snippet.startswith(("-", "$", "@"))
                or is_template_or_pattern(code_snippet)
            ):
                continue

            if not is_mutation_row:
                tf_check = verify_terraform_snippet(code_snippet, pinned_tf_addrs)
                if tf_check is not None:
                    tf_valid, tf_reason = tf_check
                    if not tf_valid:
                        issues.append(
                            Issue(
                                path,
                                line_idx,
                                "Terraform Symbol",
                                code_snippet,
                                tf_reason,
                            )
                        )
                    continue

            if " " in code_snippet:
                continue

            pinned = PINNED_PATH_PATTERN.match(code_snippet)
            if pinned:
                valid, reason = verify_pinned_path(
                    pinned["commit"], pinned["parent"], pinned["path"]
                )
                if not valid:
                    issues.append(
                        Issue(path, line_idx, "Pinned Path", code_snippet, reason)
                    )
                continue

            clean_snippet = re.split(r"[:#]", code_snippet)[0].strip()
            if "=" in clean_snippet:
                continue
            has_ext = (
                any(clean_snippet.endswith(ext) for ext in CONCRETE_EXTENSIONS)
                or clean_snippet == "Makefile"
                or clean_snippet.endswith("/Makefile")
            )
            is_dockerfile = (
                clean_snippet == "Dockerfile"
                or clean_snippet.endswith("/Dockerfile")
                or Path(clean_snippet).name.startswith("Dockerfile.")
            )
            has_colon_spec = bool(COLON_LINE_SPEC_PATTERN.match(code_snippet))
            has_symbol_anchor = bool(
                HASH_SYMBOL_ANCHOR_PATTERN.search(code_snippet)
                or (
                    (STRICT_SYMBOL_ANCHORS or "#" in code_snippet)
                    and DOUBLE_COLON_ANCHOR_PATTERN.match(code_snippet)
                )
            )
            is_explicit_path = (
                (
                    "/" in clean_snippet
                    and (
                        clean_snippet.startswith(
                            (
                                "src/",
                                "tests/",
                                "docs/",
                                "compliance/",
                                "scripts/",
                                "infra/",
                            )
                        )
                        or has_ext
                    )
                )
                or ((has_ext or is_dockerfile) and has_colon_spec)
                or (
                    (has_ext or is_dockerfile)
                    and has_symbol_anchor
                    and not CENSUS_ID_PATTERN.fullmatch(code_snippet)
                    and _resolve_candidate_path(path.parent, code_snippet) is not None
                )
            )

            if is_explicit_path:
                valid, reason = verify_file_path(
                    path.parent,
                    code_snippet,
                    allow_colon_anchor=True,
                    anchor_stats=anchor_stats,
                )
                if not valid and not code_snippet.startswith("..."):
                    issues.append(
                        Issue(path, line_idx, "File Path", code_snippet, reason)
                    )

            elif (
                code_snippet.startswith(("src.", "tests."))
                and "." in code_snippet
                and not code_snippet.endswith(".")
            ):
                valid, reason = verify_python_symbol(code_snippet)
                if not valid:
                    issues.append(
                        Issue(path, line_idx, "Python Symbol", code_snippet, reason)
                    )

        # 3. Prose line references, YAML UUID spans, and contextual Python symbols
        if not in_fence:
            issues.extend(_audit_unpinned_prose_line_numbers(path, line_idx, line))
        issues.extend(
            _audit_line_references_and_contextual_symbols(
                path, line_idx, line, local_link_labels
            )
        )

        # 4. Historical assertions require state-serial, audit-log, or git/run history evidence (POAM-2026-169)
        issues.extend(_audit_historical_assertions(path, line_idx, line))

    # 5. Ring 3 OSCAL census claim ID resolution & summary-table binding (F-64 / PR-9)
    issues.extend(_audit_ring3_census_claims(path, lines))

    return issues


CENSUS_ID_PATTERN = re.compile(
    r"(?:compliance/oscal/)?(?P<cid>(?:"
    r"system-security-plan(?:-eu-ecb|-apac-mas)?\.yaml"
    r"|(?:sp800-53-)?component-definition\.yaml"
    r"|components/cage_client_sdk\.yaml"
    r"|common-controls-catalog\.yaml"
    r"|stpa_compiler_ssp_patch\.yaml"
    r"|eu-ai-act-profile\.yaml"
    r"|mas-feat-profile\.yaml"
    r")#[A-Za-z0-9_.-]+|\bSA11-SYSTEMIC\b)"
)

_CENSUS_WEAK_QUALIFIER_RE = re.compile(
    r"(?:\bWEAKER\b|\bNOT_IN_FORCE\b|\bnot\s+in\s+force\b|\breopened\b|\bopen\b|\bstub\b"
    r"|\bpartially[- ]implemented\b|\bwithdrawn\b|\bPOAM-\d|\bEU-(?:[A-Z]+-)?\d|\bMAS-(?:[A-Z]+-)?\d|\bAI600-\d)",
    re.IGNORECASE,
)

_OSCAL_PINNED_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./:-])(?P<commit>[0-9a-f]{7,40})(?P<parent>\^?):"
    r"(?P<path>(?:src|tests|infra|deployment|compliance|config|scripts|\.github|docs|proof|packages)/[A-Za-z0-9_./-]+)"
)

_OSCAL_REPO_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./:-])(?P<path>(?:src|tests|infra|deployment|compliance|config|scripts|\.github|docs|proof|packages)/"
    r"(?:[A-Za-z0-9_.*{}-]+/)*(?:Dockerfile(?![.A-Za-z0-9_-])|[A-Za-z0-9_.*{}-]+\.[a-z0-9]+))"
    r"(?P<anchor>(?:#[A-Za-z0-9_.:-]+|::[A-Za-z0-9_.:#-]+|:\d+(?:-\d+)?))?"
)


@functools.lru_cache(maxsize=8)
def _load_census_index(repo_root: Path) -> dict[str, str] | None:
    """Load `{claim_id: verdict}` from `compliance/oscal/evidence_claim_census.jsonl`, or None if absent."""
    census_file = repo_root / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    if not census_file.is_file():
        return None
    index: dict[str, str] = {}
    for raw_line in census_file.read_text(encoding="utf-8").splitlines():
        s = raw_line.strip()
        if not s:
            continue
        obj = json.loads(s)
        cid = str(obj.get("id", ""))
        if cid:
            index[cid] = str(obj.get("verdict", ""))
    return index


def _is_ring3_summary_section(path: Path, h2: str, h3: str) -> bool:
    name = path.name
    if name == "SECURITY.md":
        return h3.startswith("### Implemented Controls Summary")
    if name == "COMPLIANCE.md":
        return h3.startswith(("### 1.1 ", "### 1.2 ", "### 1.3 ", "### 1.4 "))
    if name == "POAM.md":
        return h2.startswith("## Security Strengths") and not h3
    return False


def _audit_ring3_census_claims(path: Path, lines: list[str]) -> list[Issue]:
    """Resolve cited OSCAL census claim IDs and require IDs on Ring 3 control summary rows."""
    issues: list[Issue] = []
    census_idx = _load_census_index(REPO_ROOT.resolve())
    in_fence = False
    h2 = ""
    h3 = ""
    seen_table_header_in_section = False

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        if stripped.startswith("## ") and not stripped.startswith("### "):
            h2 = stripped
            h3 = ""
            seen_table_header_in_section = False
            continue
        if stripped.startswith("### "):
            h3 = stripped
            seen_table_header_in_section = False
            continue

        matched_cids: list[str] = []
        for m in CENSUS_ID_PATTERN.finditer(line):
            cid = m.group("cid")
            if re.search(r"#L\d+(?:-L\d+)?$", cid):
                continue
            matched_cids.append(cid)
            if census_idx is not None:
                if cid not in census_idx:
                    issues.append(
                        Issue(
                            path,
                            line_idx,
                            "Census Claim ID",
                            cid,
                            f"Census claim ID '{cid}' not found in compliance/oscal/evidence_claim_census.jsonl",
                        )
                    )
                else:
                    verdict = census_idx[cid]
                    if (
                        verdict in {"WEAKER", "NOT_IN_FORCE"}
                        and path.name != "OSCAL_EVIDENCE_CLAIM_REGISTER.md"
                        and not _CENSUS_WEAK_QUALIFIER_RE.search(line)
                    ):
                        issues.append(
                            Issue(
                                path,
                                line_idx,
                                "Census Claim ID",
                                cid,
                                f"Present-tense claim cites '{cid}' (verdict={verdict}) without qualification",
                            )
                        )

        if _is_ring3_summary_section(path, h2, h3):
            if stripped.startswith("|"):
                if re.match(r"^\|\s*[-:]+", stripped):
                    continue
                if not seen_table_header_in_section:
                    seen_table_header_in_section = True
                    continue
                if not matched_cids:
                    issues.append(
                        Issue(
                            path,
                            line_idx,
                            "Uncited Control Claim",
                            stripped[:90],
                            "Ring 3 control summary row must cite a resolvable OSCAL census claim ID (F-64)",
                        )
                    )
            elif seen_table_header_in_section and not stripped:
                seen_table_header_in_section = False

    return issues


def _verify_pinned_path_in_root(
    repo_root: Path, commit: str, parent: str, path: str
) -> tuple[bool, str]:
    unavailable = _history_unavailable(repo_root)
    if unavailable:
        return False, unavailable
    if not _git(repo_root, "cat-file", "-e", f"{commit}^{{commit}}")[0]:
        return False, f"'{commit}' is not a commit in this repository"
    if not _git(repo_root, "merge-base", "--is-ancestor", commit, "HEAD")[0]:
        return False, f"commit '{commit}' is not an ancestor of HEAD"
    revision = f"{commit}{parent}"
    if not _git(repo_root, "cat-file", "-e", f"{revision}:{path}")[0]:
        return False, f"'{path}' does not exist at {revision}"
    return True, ""


def _find_line_1(raw_lines: list[str], needle: str) -> int:
    if needle:
        for idx, rl in enumerate(raw_lines, start=1):
            if needle in rl:
                return idx
    return 1


def _audit_oscal_prose_paths(
    y_file: Path,
    raw_lines: list[str],
    text: str,
    repo_root: Path,
    seen_checked: set[str],
    anchor_stats: AnchorStats | None = None,
) -> list[Issue]:
    issues: list[Issue] = []
    pinned_spans: list[tuple[int, int]] = []
    for pm in _OSCAL_PINNED_PATH_RE.finditer(text):
        token = pm.group(0).rstrip(".,;:)")
        pm_clean = PINNED_PATH_PATTERN.match(token)
        if not pm_clean:
            continue
        pinned_spans.append((pm.start(), pm.end()))
        if token in seen_checked:
            continue
        seen_checked.add(token)
        ok, reason = _verify_pinned_path_in_root(
            repo_root, pm_clean["commit"], pm_clean["parent"], pm_clean["path"]
        )
        if not ok:
            issues.append(
                Issue(
                    y_file,
                    _find_line_1(raw_lines, token),
                    "OSCAL Pinned Path",
                    token,
                    reason,
                )
            )

    for rm in _OSCAL_REPO_PATH_RE.finditer(text):
        if any(ps <= rm.start() and rm.end() <= pe for ps, pe in pinned_spans):
            continue
        cand = rm.group("path").rstrip(".,;:)")
        raw_anchor = (rm.group("anchor") or "").rstrip(".,;:)")
        full_cand = f"{cand}{raw_anchor}"
        if is_template_or_pattern(cand):
            continue
        if cand != "Dockerfile" and not cand.endswith("/Dockerfile"):
            if Path(cand).suffix not in CONCRETE_EXTENSIONS:
                continue
        if full_cand in seen_checked:
            continue
        seen_checked.add(full_cand)
        resolved_cand = (repo_root / cand).resolve()
        if not resolved_cand.exists():
            issues.append(
                Issue(
                    y_file,
                    _find_line_1(raw_lines, full_cand),
                    "OSCAL File Path",
                    full_cand,
                    f"OSCAL narrative path '{cand}' does not exist on disk",
                )
            )
            continue
        if raw_anchor and not CENSUS_ID_PATTERN.fullmatch(full_cand):
            anc_ok, anc_reason = _validate_resolved_path_anchors(
                resolved_cand,
                cand,
                full_cand,
                allow_colon_anchor=True,
                anchor_stats=anchor_stats,
            )
            if not anc_ok:
                issues.append(
                    Issue(
                        y_file,
                        _find_line_1(raw_lines, full_cand),
                        "OSCAL File Path",
                        full_cand,
                        anc_reason,
                    )
                )

    if STRICT_SYMBOL_ANCHORS:
        for pat in (UNPINNED_PROSE_LINE_WORD_PATTERN, UNPINNED_PROSE_L_SPAN_PATTERN):
            for pm in pat.finditer(text):
                if any(ps <= pm.start() and pm.end() <= pe for ps, pe in pinned_spans):
                    continue
                window_before = text[max(0, pm.start() - 140) : pm.start()]
                window_after = text[pm.end() : min(len(text), pm.end() + 90)]
                if PINNED_CLAUSE_PREFIX_PATTERN.search(
                    window_before
                ) or PINNED_CLAUSE_PREFIX_PATTERN.search(window_after):
                    continue
                token_str = pm.group(0)
                if f"unpinned:{token_str}" in seen_checked:
                    continue
                seen_checked.add(f"unpinned:{token_str}")
                issues.append(
                    Issue(
                        y_file,
                        _find_line_1(raw_lines, token_str),
                        "OSCAL Unpinned Line Number",
                        token_str,
                        "Unpinned line-number citation in OSCAL narrative; use a structural symbol anchor or pin to '<sha>:<path>'",
                    )
                )
    return issues


def _walk_oscal_node(
    node: Any,
    y_file: Path,
    raw_lines: list[str],
    bm_uuids: set[str],
    seen_paths: set[str],
    root: Path,
    issues: list[Issue],
    anchor_stats: AnchorStats | None = None,
) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "href" and isinstance(v, str):
                href_val = v.strip()
                if (
                    not href_val
                    or href_val == "lula.dev"
                    or href_val.startswith(
                        ("http://", "https://", "mailto:", "urn:", "lula://")
                    )
                    or is_template_or_pattern(href_val)
                ):
                    continue
                if href_val.startswith("#"):
                    if href_val[1:] not in bm_uuids:
                        issues.append(
                            Issue(
                                y_file,
                                _find_line_1(raw_lines, href_val),
                                "OSCAL Href Fragment",
                                href_val,
                                f"OSCAL fragment '{href_val}' missing from back-matter.resources in {y_file.name}",
                            )
                        )
                else:
                    clean_href = href_val.split("#", 1)[0].strip()
                    norm_href = clean_href.removeprefix("./")
                    rel_cand = y_file.parent / clean_href
                    root_cand = root / norm_href
                    if not rel_cand.exists() and not root_cand.exists():
                        issues.append(
                            Issue(
                                y_file,
                                _find_line_1(raw_lines, href_val),
                                "OSCAL Href Path",
                                href_val,
                                f"OSCAL local href '{clean_href}' does not exist on disk",
                            )
                        )
            elif k in {"description", "remarks", "value"} and isinstance(v, str):
                issues.extend(
                    _audit_oscal_prose_paths(
                        y_file,
                        raw_lines,
                        v,
                        root,
                        seen_paths,
                        anchor_stats=anchor_stats,
                    )
                )
            else:
                _walk_oscal_node(
                    v,
                    y_file,
                    raw_lines,
                    bm_uuids,
                    seen_paths,
                    root,
                    issues,
                    anchor_stats=anchor_stats,
                )
    elif isinstance(node, list):
        for item in node:
            _walk_oscal_node(
                item,
                y_file,
                raw_lines,
                bm_uuids,
                seen_paths,
                root,
                issues,
                anchor_stats=anchor_stats,
            )


def _audit_census_holds_paths(
    census_file: Path,
    repo_root: Path,
    anchor_stats: AnchorStats | None = None,
) -> list[Issue]:
    """Verify read_back.check and evidence_named paths on all HOLDS census rows (including non-implemented)."""
    issues: list[Issue] = []
    raw_lines = census_file.read_text(encoding="utf-8").splitlines()
    for line_idx, raw_line in enumerate(raw_lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as err:
            issues.append(
                Issue(census_file, line_idx, "Census JSON", census_file.name, str(err))
            )
            continue
        if row.get("verdict") != "HOLDS":
            continue
        read_back = row.get("read_back")
        rb_check = read_back.get("check", "") if isinstance(read_back, dict) else ""
        blobs = [str(rb_check), *(str(x) for x in (row.get("evidence_named") or []))]
        seen_row: set[str] = set()
        for blob in blobs:
            for iss in _audit_oscal_prose_paths(
                census_file,
                [raw_line],
                blob,
                repo_root,
                seen_row,
                anchor_stats=anchor_stats,
            ):
                issues.append(
                    Issue(
                        census_file,
                        line_idx,
                        "Census HOLDS Path",
                        iss.target,
                        f"{row.get('id')}: {iss.reason}",
                    )
                )
    return issues


def audit_oscal_and_lula_yaml(
    repo_root: Path | None = None,
    scoped_files: list[Path] | None = None,
    *,
    anchor_stats: AnchorStats | None = None,
) -> list[Issue]:
    """Validate duplicate-key-free YAML syntax, #uuid hrefs, local hrefs, and narrative paths
    across `compliance/oscal/*.yaml`, `compliance/lula/*.yaml`, and HOLDS census rows."""
    root = (repo_root or REPO_ROOT).resolve()
    issues: list[Issue] = []
    oscal_dir = root / "compliance" / "oscal"
    lula_dir = root / "compliance" / "lula"
    scope_set = (
        {p.resolve() for p in scoped_files} if scoped_files is not None else None
    )

    oscal_files = (
        sorted(p.resolve() for p in oscal_dir.glob("*.y*ml") if p.is_file())
        if oscal_dir.is_dir()
        else []
    )
    lula_files = (
        sorted(p.resolve() for p in lula_dir.glob("*.y*ml") if p.is_file())
        if lula_dir.is_dir()
        else []
    )
    if scope_set is not None:
        oscal_files = [p for p in oscal_files if p in scope_set]
        lula_files = [p for p in lula_files if p in scope_set]

    for y_file in lula_files:
        raw = y_file.read_text(encoding="utf-8")
        raw_lines = raw.splitlines()
        try:
            doc = yaml.load(raw, Loader=_DuplicateKeyRejectingLoader)  # nosec B506  # SafeLoader subclass rejecting duplicate keys
        except yaml.YAMLError as err:
            mark = getattr(err, "problem_mark", None)
            ln = (mark.line + 1) if mark is not None else 1
            ref_t = (
                "YAML Duplicate Key"
                if "duplicate YAML mapping key" in str(err)
                else "YAML Syntax"
            )
            issues.append(Issue(y_file, ln, ref_t, y_file.name, str(err)))
            continue
        if not isinstance(doc, dict):
            continue
        comp_def = doc.get("component-definition")
        if not isinstance(comp_def, dict):
            continue
        lula_seen_paths: set[str] = set()
        meta = comp_def.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("remarks"), str):
            issues.extend(
                _audit_oscal_prose_paths(
                    y_file,
                    raw_lines,
                    meta["remarks"],
                    root,
                    lula_seen_paths,
                    anchor_stats=anchor_stats,
                )
            )
        bm = comp_def.get("back-matter")
        resources = bm.get("resources") if isinstance(bm, dict) else []
        bm_uuids: set[str] = set()
        for res in resources if isinstance(resources, list) else []:
            if not isinstance(res, dict):
                continue
            ruuid = res.get("uuid")
            if isinstance(ruuid, str) and ruuid:
                bm_uuids.add(ruuid)
            desc = res.get("description")
            if isinstance(desc, str) and ("domain:" in desc or "provider:" in desc):
                try:
                    yaml.load(desc, Loader=_DuplicateKeyRejectingLoader)  # nosec B506  # SafeLoader subclass rejecting duplicate keys
                except yaml.YAMLError as err:
                    ref_t = (
                        "YAML Duplicate Key"
                        if "duplicate YAML mapping key" in str(err)
                        else "YAML Syntax"
                    )
                    issues.append(
                        Issue(
                            y_file,
                            _find_line_1(raw_lines, str(ruuid or "description")),
                            ref_t,
                            f"{y_file.name}#{ruuid}",
                            f"Embedded Lula resource YAML error: {err}",
                        )
                    )
        for comp in comp_def.get("components") or []:
            if not isinstance(comp, dict):
                continue
            for ci in comp.get("control-implementations") or []:
                if not isinstance(ci, dict):
                    continue
                for ir in ci.get("implemented-requirements") or []:
                    if not isinstance(ir, dict):
                        continue
                    for lnk in ir.get("links") or []:
                        if isinstance(lnk, dict):
                            href = str(lnk.get("href", "")).strip()
                            if href.startswith("#") and href[1:] not in bm_uuids:
                                issues.append(
                                    Issue(
                                        y_file,
                                        _find_line_1(raw_lines, href),
                                        "Lula Href Fragment",
                                        href,
                                        f"Fragment '{href}' missing from back-matter.resources in {y_file.name}",
                                    )
                                )

    for y_file in oscal_files:
        raw = y_file.read_text(encoding="utf-8")
        raw_lines = raw.splitlines()
        try:
            doc = yaml.load(raw, Loader=_DuplicateKeyRejectingLoader)  # nosec B506  # SafeLoader subclass rejecting duplicate keys
        except yaml.YAMLError as err:
            mark = getattr(err, "problem_mark", None)
            ln = (mark.line + 1) if mark is not None else 1
            ref_t = (
                "YAML Duplicate Key"
                if "duplicate YAML mapping key" in str(err)
                else "YAML Syntax"
            )
            issues.append(Issue(y_file, ln, ref_t, y_file.name, str(err)))
            continue
        if not isinstance(doc, dict):
            continue

        bm_uuids = set()
        for top_val in doc.values():
            if isinstance(top_val, dict):
                bm = top_val.get("back-matter")
                resources = bm.get("resources") if isinstance(bm, dict) else []
                if isinstance(resources, list):
                    for res in resources:
                        if isinstance(res, dict) and isinstance(res.get("uuid"), str):
                            bm_uuids.add(str(res["uuid"]))

        seen_paths: set[str] = set()
        _walk_oscal_node(
            doc,
            y_file,
            raw_lines,
            bm_uuids,
            seen_paths,
            root,
            issues,
            anchor_stats=anchor_stats,
        )

    census_file = oscal_dir / "evidence_claim_census.jsonl"
    if census_file.is_file() and (
        scope_set is None or census_file.resolve() in scope_set
    ):
        issues.extend(
            _audit_census_holds_paths(
                census_file.resolve(), root, anchor_stats=anchor_stats
            )
        )

    return issues


def _resolve_scoped_yaml_files(path_args: list[str]) -> tuple[bool, list[Path]]:
    """Return `(run_yaml_audit, matched_yaml_files)` for `--path` invocations."""
    root = REPO_ROOT.resolve()
    oscal_dir = (root / "compliance" / "oscal").resolve()
    lula_dir = (root / "compliance" / "lula").resolve()
    matched: list[Path] = []
    for raw_path in path_args:
        cand = Path(raw_path)
        prefix = cand.resolve() if cand.is_absolute() else (root / cand).resolve()
        if prefix.is_file() and prefix.suffix in {".yaml", ".yml", ".jsonl"}:
            if oscal_dir in prefix.parents or lula_dir in prefix.parents:
                matched.append(prefix)
        elif prefix.is_dir():
            for y_dir in (oscal_dir, lula_dir):
                if y_dir.is_dir() and (
                    prefix == y_dir
                    or prefix in y_dir.parents
                    or y_dir in prefix.parents
                ):
                    scan_root = prefix if y_dir in prefix.parents else y_dir
                    matched.extend(
                        p.resolve() for p in scan_root.glob("*.y*ml") if p.is_file()
                    )
                    matched.extend(
                        p.resolve() for p in scan_root.glob("*.jsonl") if p.is_file()
                    )
    deduped = sorted(set(matched))
    return bool(deduped), deduped


HISTORICAL_CLAIM_PATTERN = re.compile(
    r"\b("
    r"verified\s+unfired"
    r"|unfired\s+on"
    r"|therefore\s+unfired"
    r"|never\s+fired"
    r"|(?:has|have|had)\s+never\s+\w+"
    r"|(?:has|have|had)\s+always\s+\w+"
    r"|no\s+evidence\s+of\b"
    r"|was\s+applied\s+via\b"
    r"|always\s+applied\s+via\b"
    r")",
    re.IGNORECASE,
)

DEPLOYMENT_SUBJECT_PATTERN = re.compile(
    r"(<PROJECT_ID>|<WALK_PROJECT_ID>|\bcage-staging\b|\bwas\s+applied\s+via\b|\balways\s+applied\s+via\b|\btherefore\s+unfired\b)",
    re.IGNORECASE,
)

DEPLOYMENT_HISTORICAL_EVIDENCE_PATTERN = re.compile(
    r"("
    r"\bserial:\s*\d+"
    r"|\.tfstate\b"
    r"|\bstate\s+history\b"
    r"|\baudit[- ]log"
    r"|\bCloud Audit Log"
    r"|\bgcloud logging read\b"
    r"|\bprotoPayload\b"
    r"|\bUpdateCluster\b"
    r"|\bCreateCluster\b"
    r"|\boperation-\d+"
    r")",
    re.IGNORECASE,
)

REPO_HISTORICAL_EVIDENCE_PATTERN = re.compile(
    r"("
    r"\bgit\s+log\b"
    r"|\bgit\s+rev-list\b"
    r"|\bactivity_type="
    r"|\brulesets/\d+/history\b"
    r"|\btotal_count:\s*\d+"
    r"|\bcheck[- ]run\s+`?\d+"
    r"|\brun\s+`?\d{8,}"
    r"|\bjob\s+log\b"
    r")",
    re.IGNORECASE,
)


def _audit_historical_assertions(path: Path, line_idx: int, line: str) -> list[Issue]:
    """Flag historical assertions unaccompanied by audit-log, state-serial, or history evidence."""
    if line.lstrip().startswith("#"):
        return []
    match = HISTORICAL_CLAIM_PATTERN.search(line)
    if match is None:
        return []
    if DEPLOYMENT_HISTORICAL_EVIDENCE_PATTERN.search(line):
        return []
    if DEPLOYMENT_SUBJECT_PATTERN.search(line):
        return [
            Issue(
                path,
                line_idx,
                "Historical Claim",
                match.group(0),
                "Deployment/cluster historical assertion requires audit-log or Terraform state-serial (.tfstate / serial: N) evidence on the same line (POAM-2026-169)",
            )
        ]
    if REPO_HISTORICAL_EVIDENCE_PATTERN.search(line):
        return []
    return [
        Issue(
            path,
            line_idx,
            "Historical Claim",
            match.group(0),
            "Historical assertion requires audit-log, state-serial (.tfstate / serial: N), or git-log/run-history evidence on the same line (POAM-2026-169)",
        )
    ]


SEMVER_MAJOR_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
RELEASED_MAJOR_HEADING_PATTERN = re.compile(r"^#\s+v(\d+)\.x\s*$")
UNRELEASED_MAJOR_HEADING_PATTERN = re.compile(
    r"^#\s+Unreleased(?:\s*\(v(\d+)\.x\))?(?:\s*$|\b)",
    re.IGNORECASE,
)
VERSIONED_DOC_FILENAME_PATTERN = re.compile(
    r"(?:^|[_-])v\d+(?:[._-]|$)",
    re.IGNORECASE,
)
LULA_SCHEMA_FILENAME_PATTERN = re.compile(
    r"^lula_v(\d)(\d{2})(\d)_validation\.schema\.json$"
)


def _check_lula_schema_version(repo_root: Path, schema_path: Path) -> list[Issue]:
    """Verify compliance/lula/schemas/lula_v<NNN>_validation.schema.json matches pinned Lula CLI."""
    rel = schema_path.relative_to(repo_root).as_posix()
    match = LULA_SCHEMA_FILENAME_PATTERN.match(schema_path.name)
    if match is None:
        return [
            Issue(
                schema_path,
                1,
                "Version Hygiene",
                rel,
                "Unrecognized versioned Lula schema filename; expected lula_v<M><mm><p>_validation.schema.json",
            )
        ]

    expected_ver = f"v{int(match.group(1))}.{int(match.group(2))}.{int(match.group(3))}"
    issues: list[Issue] = []

    verifier_path = repo_root / "scripts" / "verify_lula_assessment_results.py"
    if verifier_path.is_file():
        verifier_text = verifier_path.read_text(encoding="utf-8")
        if f"Lula {expected_ver}" not in verifier_text:
            issues.append(
                Issue(
                    schema_path,
                    1,
                    "Version Hygiene",
                    rel,
                    f"Schema filename pins Lula {expected_ver}, which does not match scripts/verify_lula_assessment_results.py",
                )
            )

    return issues


def audit_version_hygiene(repo_root: Path | None = None) -> list[Issue]:
    """Verify BREAKING_CHANGES.md major-version parity and forbid version-suffixed living doc filenames."""
    root = REPO_ROOT if repo_root is None else repo_root
    issues: list[Issue] = []

    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "pyproject.toml",
                "pyproject.toml is missing",
            )
        )
        return issues

    try:
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "pyproject.toml",
                f"Invalid TOML in pyproject.toml: {exc}",
            )
        )
        return issues

    version_str = str(pyproject_data.get("project", {}).get("version", ""))
    ver_match = SEMVER_MAJOR_PATTERN.match(version_str)
    if ver_match is None:
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                version_str or "project.version",
                "pyproject.toml [project].version must start with major.minor.patch",
            )
        )
        return issues

    current_major = int(ver_match.group(1))
    breaking_doc = root / "docs" / "BREAKING_CHANGES.md"
    if not breaking_doc.is_file():
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "docs/BREAKING_CHANGES.md",
                "Canonical breaking-changes ledger docs/BREAKING_CHANGES.md is missing",
            )
        )
    else:
        released_majors: dict[int, int] = {}
        unreleased_headings: list[tuple[int, str, int | None]] = []
        in_fence = False
        for line_idx, raw_line in enumerate(
            breaking_doc.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = raw_line.strip()
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            rel_match = RELEASED_MAJOR_HEADING_PATTERN.match(stripped)
            if rel_match is not None:
                released_majors.setdefault(int(rel_match.group(1)), line_idx)
                continue
            unrel_match = UNRELEASED_MAJOR_HEADING_PATTERN.match(stripped)
            if unrel_match is not None:
                parsed_major = (
                    int(unrel_match.group(1))
                    if unrel_match.group(1) is not None
                    else None
                )
                unreleased_headings.append((line_idx, stripped, parsed_major))

        if current_major not in released_majors:
            issues.append(
                Issue(
                    breaking_doc,
                    1,
                    "Version Hygiene",
                    f"# v{current_major}.x",
                    f"docs/BREAKING_CHANGES.md lacks '# v{current_major}.x' section matching pyproject.toml version {version_str}",
                )
            )
        for maj, line_no in sorted(released_majors.items()):
            if maj > current_major:
                issues.append(
                    Issue(
                        breaking_doc,
                        line_no,
                        "Version Hygiene",
                        f"# v{maj}.x",
                        f"Released major section '# v{maj}.x' exceeds pyproject.toml version {version_str} (use '# Unreleased (v{current_major + 1}.x)')",
                    )
                )
        for line_no, heading_text, unrel_major in unreleased_headings:
            if unrel_major != current_major + 1:
                issues.append(
                    Issue(
                        breaking_doc,
                        line_no,
                        "Version Hygiene",
                        heading_text,
                        f"Unreleased major section must be '# Unreleased (v{current_major + 1}.x)' for pyproject.toml version {version_str}",
                    )
                )

    candidates: list[Path] = sorted(root.glob("*.md"))
    docs_dir = root / "docs"
    partners_dir = docs_dir / "partners"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.rglob("*")):
            if not path.is_file():
                continue
            if partners_dir in path.parents:
                continue
            candidates.append(path)

    compliance_dir = root / "compliance"
    lula_schemas_dir = compliance_dir / "lula" / "schemas"
    if compliance_dir.is_dir():
        for path in sorted(compliance_dir.rglob("*")):
            if path.is_file():
                candidates.append(path)

    for candidate in candidates:
        if VERSIONED_DOC_FILENAME_PATTERN.search(candidate.name) is None:
            continue
        if candidate.parent == lula_schemas_dir:
            issues.extend(_check_lula_schema_version(root, candidate))
            continue
        rel_path = candidate.relative_to(root).as_posix()
        issues.append(
            Issue(
                candidate,
                1,
                "Version Hygiene",
                rel_path,
                "Living documentation/compliance filenames must be version-neutral (organize per-version sections inside the file instead of '_v<N>' / '-v<N>' suffixes)",
            )
        )

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify doc references against repo code."
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None, help="Output file path"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--path",
        action="append",
        default=None,
        metavar="PREFIX",
        help=(
            "Restrict the audit to documents under this repo-relative path prefix. "
            "Repeatable. Omit to audit every discovered document."
        ),
    )
    args = parser.parse_args(argv)

    run_yaml = False
    scoped_yaml: list[Path] | None = None
    if args.path:
        files = resolve_scoped_markdown_files(args.path)
        run_yaml, matched_yaml = _resolve_scoped_yaml_files(args.path)
        scoped_yaml = matched_yaml
        print("Scoped to: " + ", ".join(args.path))
    else:
        files = find_markdown_files()
        run_yaml = True
        scoped_yaml = None

    all_issues: list[Issue] = []
    anchor_stats = AnchorStats()

    print(f"Auditing {len(files)} documentation files...")
    if len(files) == 0 and not run_yaml:
        msg = "No documentation files matched the requested scope.\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(msg, encoding="utf-8")
        else:
            print(msg)
        return 1

    for f in files:
        file_issues = audit_markdown_file(f, anchor_stats=anchor_stats)
        all_issues.extend(file_issues)

    if run_yaml:
        all_issues.extend(
            audit_oscal_and_lula_yaml(
                REPO_ROOT, scoped_files=scoped_yaml, anchor_stats=anchor_stats
            )
        )

    if not args.path:
        all_issues.extend(audit_version_hygiene(REPO_ROOT))

    out_lines: list[str] = [
        f"Anchor accounting: structural_anchors={anchor_stats.tier1_structural}, "
        f"scoped_subtoken_anchors={anchor_stats.tier2_scoped_subtoken}"
    ]
    if not all_issues:
        out_lines.append(
            "All documentation references, file paths, and symbols are valid."
        )
        exit_code = 0
    else:
        out_lines.append(f"Found {len(all_issues)} broken documentation references:\n")
        for issue in all_issues:
            try:
                rel_file = issue.source_file.relative_to(REPO_ROOT)
            except ValueError:
                rel_file = issue.source_file
            out_lines.append(
                f"  {rel_file}:{issue.line_number} [{issue.reference_type}] -> {issue.target} ({issue.reason})"
            )
        exit_code = 1

    report_text = "\n".join(out_lines) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report_text, encoding="utf-8")
        print(f"Report written to: {args.output} (Found {len(all_issues)} issues)")
    else:
        print(report_text)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
