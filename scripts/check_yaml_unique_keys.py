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

"""Zero-waiver YAML integrity gate for duplicate mapping keys and parse errors.

Scans multi-document YAML files under ``compliance/``, ``config/``, and
``.github/`` using a ``yaml.SafeLoader`` subclass that rejects:

1. Duplicate mapping keys at any nesting depth (recording file path, key name,
   first definition line, and duplicate line).
2. Any YAML syntax, scanner, parser, composer, or constructor error
   (``yaml.YAMLError``).

Zero waivers and zero allowlists are permitted.

Usage:
    uv run python scripts/check_yaml_unique_keys.py --verbose
    uv run python scripts/check_yaml_unique_keys.py --paths compliance/ config/
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, ScalarNode

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SCAN_ROOTS: tuple[str, ...] = (
    "compliance",
    "config",
    ".github",
)

YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})
MIN_EXPECTED_DEFAULT_YAML_FILES = 40
MIN_EXPECTED_DEFAULT_YAML_MAPPINGS = 200


class _MergeKeyTag:
    """Sentinel type distinguishing YAML 1.1 ``<<`` merge tags in seen-key maps."""


class DuplicateKeyError(ConstructorError):
    """Raised when ``UniqueKeySafeLoader`` encounters a duplicate mapping key."""

    def __init__(
        self,
        key: str,
        first_line: int,
        duplicate_line: int,
        start_mark: yaml.Mark | None = None,
        duplicate_mark: yaml.Mark | None = None,
    ) -> None:
        self.key = key
        self.first_line = first_line
        self.duplicate_line = duplicate_line
        super().__init__(
            "while constructing a mapping",
            start_mark,
            (
                f"duplicate mapping key {key!r} at line {duplicate_line} "
                f"(first defined at line {first_line})"
            ),
            duplicate_mark,
        )


@dataclass(frozen=True)
class YamlViolation:
    """Single YAML integrity violation (duplicate mapping key or parse failure)."""

    path: Path
    kind: Literal["duplicate_key", "parse_error"]
    line: int
    message: str
    key: str | None = None
    first_line: int | None = None
    error_type: str | None = None
    document_index: int = 0

    def format(self, repo_root: Path | None = None) -> str:
        display_path: Path | str = self.path
        if repo_root is not None:
            try:
                display_path = self.path.resolve().relative_to(repo_root.resolve())
            except ValueError:
                display_path = self.path
        if self.kind == "duplicate_key":
            return (
                f"{display_path}:{self.line}: duplicate key {self.key!r} "
                f"(first defined at line {self.first_line}, doc #{self.document_index + 1})"
            )
        err_prefix = f"{self.error_type}: " if self.error_type else ""
        return f"{display_path}:{self.line}: {err_prefix}{self.message}"


class UniqueKeySafeLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` subclass that rejects duplicate keys at every depth."""

    duplicate_sink: list[tuple[int, str, int, int]] | None = None
    current_document_index: int = 0
    mapping_count: int = 0

    def construct_mapping(
        self, node: MappingNode, deep: bool = False
    ) -> dict[Hashable, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )

        self.mapping_count += 1
        seen_keys: dict[tuple[type[Any], Hashable], int] = {}
        for key_node, _value_node in node.value:
            line_no = key_node.start_mark.line + 1
            if key_node.tag == "tag:yaml.org,2002:merge":
                typed_key: tuple[type[Any], Hashable] = (_MergeKeyTag, "<<")
                key_display = "<<"
            else:
                key_obj = self.construct_object(key_node, deep=True)
                if not isinstance(key_obj, Hashable):
                    raise ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        "found unhashable key",
                        key_node.start_mark,
                    )
                typed_key = (type(key_obj), key_obj)
                key_display = (
                    key_node.value
                    if isinstance(key_node, ScalarNode)
                    and isinstance(key_node.value, str)
                    else str(key_obj)
                )

            if typed_key in seen_keys:
                first_line = seen_keys[typed_key]
                if self.duplicate_sink is not None:
                    self.duplicate_sink.append(
                        (
                            self.current_document_index,
                            key_display,
                            first_line,
                            line_no,
                        )
                    )
                else:
                    raise DuplicateKeyError(
                        key=key_display,
                        first_line=first_line,
                        duplicate_line=line_no,
                        start_mark=node.start_mark,
                        duplicate_mark=key_node.start_mark,
                    )
            else:
                seen_keys[typed_key] = line_no

        self.flatten_mapping(node)
        return super().construct_mapping(node, deep=deep)


def load_all_unique(content: str) -> list[Any]:
    """Parse all YAML documents in ``content`` with ``UniqueKeySafeLoader``.

    Raises ``DuplicateKeyError`` on any duplicate mapping key and
    ``yaml.YAMLError`` on any YAML syntax/scanner/parser/constructor failure.
    """
    loader = UniqueKeySafeLoader(content)
    documents: list[Any] = []
    try:
        doc_idx = 0
        while loader.check_data():
            loader.current_document_index = doc_idx
            documents.append(loader.get_data())
            doc_idx += 1
    finally:
        loader.dispose()
    return documents


def scan_yaml_text_with_stats(
    content: str, path: Path
) -> tuple[list[YamlViolation], int]:
    """Scan a YAML string and return ``(violations, mapping_count)``."""
    duplicates: list[tuple[int, str, int, int]] = []

    class _RecordingUniqueKeyLoader(UniqueKeySafeLoader):
        duplicate_sink = duplicates

    violations: list[YamlViolation] = []
    loader = _RecordingUniqueKeyLoader(content)
    doc_idx = 0
    try:
        while loader.check_data():
            loader.current_document_index = doc_idx
            loader.get_data()
            doc_idx += 1
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        line_no = (mark.line + 1) if mark is not None else 1
        parts = [p for p in (exc.context, exc.problem) if p]
        detail = "; ".join(parts) if parts else str(exc)
        violations.append(
            YamlViolation(
                path=path,
                kind="parse_error",
                line=line_no,
                message=detail,
                error_type=type(exc).__name__,
                document_index=doc_idx,
            )
        )
    except yaml.YAMLError as exc:
        violations.append(
            YamlViolation(
                path=path,
                kind="parse_error",
                line=1,
                message=str(exc),
                error_type=type(exc).__name__,
                document_index=doc_idx,
            )
        )
    finally:
        loader.dispose()

    for dup_doc_idx, key_name, first_line, dup_line in duplicates:
        violations.append(
            YamlViolation(
                path=path,
                kind="duplicate_key",
                line=dup_line,
                first_line=first_line,
                key=key_name,
                message=(
                    f"duplicate mapping key {key_name!r} at line {dup_line} "
                    f"(first defined at line {first_line})"
                ),
                document_index=dup_doc_idx,
            )
        )

    violations.sort(key=lambda v: (str(v.path), v.line, v.kind, v.key or ""))
    return violations, loader.mapping_count


def scan_yaml_text(content: str, path: Path) -> list[YamlViolation]:
    """Scan a YAML string (including multi-document ``---`` streams) for violations."""
    violations, _ = scan_yaml_text_with_stats(content, path)
    return violations


def scan_yaml_file_with_stats(path: Path) -> tuple[list[YamlViolation], int]:
    """Read ``path`` as UTF-8 and return ``(violations, mapping_count)``."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            YamlViolation(
                path=path,
                kind="parse_error",
                line=1,
                message=f"failed to read YAML file: {exc}",
                error_type=type(exc).__name__,
            )
        ], 0
    return scan_yaml_text_with_stats(content, path=path)


def scan_yaml_file(path: Path) -> list[YamlViolation]:
    """Read ``path`` as UTF-8 and return any YAML integrity violations."""
    violations, _ = scan_yaml_file_with_stats(path)
    return violations


def collect_yaml_files(targets: Sequence[Path]) -> tuple[list[Path], list[Path]]:
    """Expand file/directory targets into sorted YAML files and missing paths."""
    files: set[Path] = set()
    missing: list[Path] = []
    for target in targets:
        if not target.exists():
            missing.append(target)
            continue
        if target.is_file():
            files.add(target)
            continue
        for candidate in target.rglob("*"):
            if candidate.is_file() and candidate.suffix.lower() in YAML_SUFFIXES:
                files.add(candidate)
    return sorted(files), missing


def scan_paths_with_stats(
    targets: Sequence[Path],
) -> tuple[list[Path], list[YamlViolation], int]:
    """Scan all YAML files under ``targets`` and return ``(files, violations, mapping_count)``."""
    files, missing = collect_yaml_files(targets)
    violations: list[YamlViolation] = [
        YamlViolation(
            path=missing_path,
            kind="parse_error",
            line=1,
            message="scan target path does not exist",
            error_type="FileNotFoundError",
        )
        for missing_path in missing
    ]
    total_mappings = 0
    for yaml_file in files:
        file_violations, file_mappings = scan_yaml_file_with_stats(yaml_file)
        violations.extend(file_violations)
        total_mappings += file_mappings
    return files, violations, total_mappings


def scan_paths(targets: Sequence[Path]) -> tuple[list[Path], list[YamlViolation]]:
    """Scan all YAML files under ``targets`` and return ``(files, violations)``."""
    files, violations, _ = scan_paths_with_stats(targets)
    return files, violations


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-waiver YAML integrity check: rejects duplicate mapping keys "
            "and YAML syntax/parse errors across compliance/, config/, and .github/."
        )
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        type=Path,
        default=None,
        help=(
            "Explicit YAML files or directories to scan "
            "(defaults to compliance/, config/, and .github/ under repo root)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print scanned file counts and per-root summary.",
    )
    parser.add_argument(
        "--min-files",
        type=int,
        default=None,
        help="Minimum YAML files expected in scanned corpus.",
    )
    parser.add_argument(
        "--min-mappings",
        type=int,
        default=None,
        help="Minimum YAML mappings expected in scanned corpus.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    default_repo_scan = args.paths is None
    if not default_repo_scan:
        targets = [p if p.is_absolute() else (Path.cwd() / p) for p in args.paths]
        display_root: Path | None = Path.cwd()
    else:
        targets = [REPO_ROOT / rel for rel in DEFAULT_SCAN_ROOTS]
        display_root = REPO_ROOT

    min_files = (
        args.min_files
        if args.min_files is not None
        else (MIN_EXPECTED_DEFAULT_YAML_FILES if default_repo_scan else 1)
    )
    min_mappings = (
        args.min_mappings
        if args.min_mappings is not None
        else (MIN_EXPECTED_DEFAULT_YAML_MAPPINGS if default_repo_scan else 1)
    )

    files, violations, total_mappings = scan_paths_with_stats(targets)
    if args.verbose:
        roots_label = ", ".join(
            str(t.relative_to(display_root))
            if display_root is not None and t.is_relative_to(display_root)
            else str(t)
            for t in targets
        )
        print(
            f"Scanning {len(files)} YAML file(s) ({total_mappings} mappings) "
            f"across [{roots_label}]..."
        )

    if violations:
        print(
            f"YAML integrity check FAILED: {len(violations)} violation(s) "
            f"in {len({v.path for v in violations})} file(s):",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  - {violation.format(display_root)}", file=sys.stderr)
        return 1

    corpus_failures: list[str] = []
    if len(files) < min_files:
        corpus_failures.append(
            f"scanned YAML files {len(files)} < minimum expected {min_files}"
        )
    if total_mappings < min_mappings:
        corpus_failures.append(
            f"recognized YAML mappings {total_mappings} < minimum expected {min_mappings}"
        )
    if corpus_failures:
        print(
            "YAML integrity check FAILED: vacuous/blind corpus floor not met:",
            file=sys.stderr,
        )
        for failure in corpus_failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    if args.verbose:
        print(
            f"YAML integrity check PASSED: {len(files)} YAML file(s), "
            f"{total_mappings} mappings verified (0 duplicate keys, 0 parse errors)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
