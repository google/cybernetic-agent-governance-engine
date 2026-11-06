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

"""Unit tests for the zero-waiver YAML unique-key and syntax integrity gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_yaml_unique_keys import (
    DuplicateKeyError,
    load_all_unique,
    main,
    scan_yaml_file,
    scan_yaml_text,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_duplicate_top_level_key_rejected_with_line_numbers(tmp_path: Path) -> None:
    """Top-level duplicate keys must be rejected with exact first and duplicate lines."""
    yaml_file = tmp_path / "top_level_dup.yaml"
    content = "alpha: 1\nbeta: 2\nalpha: 3\n"
    yaml_file.write_text(content, encoding="utf-8")

    violations = scan_yaml_file(yaml_file)
    assert len(violations) == 1
    violation = violations[0]
    assert violation.kind == "duplicate_key"
    assert violation.key == "alpha"
    assert violation.first_line == 1
    assert violation.line == 3
    assert "duplicate key 'alpha'" in violation.format(tmp_path)
    assert "first defined at line 1" in violation.format(tmp_path)

    with pytest.raises(DuplicateKeyError) as exc_info:
        load_all_unique(content)
    assert exc_info.value.key == "alpha"
    assert exc_info.value.first_line == 1
    assert exc_info.value.duplicate_line == 3

    assert main(["--paths", str(yaml_file)]) == 1


def test_duplicate_nested_mapping_key_rejected(tmp_path: Path) -> None:
    """Nested duplicate keys inside deep mappings or list-item mappings must fail."""
    yaml_file = tmp_path / "nested_dup.yaml"
    content = (
        "component-definition:\n"
        "  components:\n"
        "    - uuid: 12e40b44-a5eb-4e0d-b319-42bab7d5d10a\n"
        "      control-id: ac-3\n"
        "      description: first narrative\n"
        "      props:\n"
        "        - name: implementation-status\n"
        "          value: implemented\n"
        "      description: silently overwriting narrative\n"
    )
    yaml_file.write_text(content, encoding="utf-8")

    violations = scan_yaml_file(yaml_file)
    assert len(violations) == 1
    violation = violations[0]
    assert violation.kind == "duplicate_key"
    assert violation.key == "description"
    assert violation.first_line == 5
    assert violation.line == 9
    assert main(["--paths", str(yaml_file), "--verbose"]) == 1


def test_multi_document_yaml_supported_and_doc2_duplicate_rejected(
    tmp_path: Path,
) -> None:
    """Multi-document (`---`) YAML passes when clean and rejects duplicates in doc #2."""
    valid_multi = (
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: first-doc\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: second-doc\n"
    )
    assert scan_yaml_text(valid_multi, tmp_path / "valid_multi.yaml") == []
    docs = load_all_unique(valid_multi)
    assert len(docs) == 2

    invalid_multi_file = tmp_path / "invalid_multi.yaml"
    invalid_multi = (
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: first-doc\n"
        "---\n"
        "apiVersion: v1\n"
        "metadata:\n"
        "  name: second-doc\n"
        "  namespace: cage\n"
        "  name: overwritten-doc\n"
    )
    invalid_multi_file.write_text(invalid_multi, encoding="utf-8")

    violations = scan_yaml_file(invalid_multi_file)
    assert len(violations) == 1
    violation = violations[0]
    assert violation.kind == "duplicate_key"
    assert violation.key == "name"
    assert violation.document_index == 1
    assert violation.first_line == 8
    assert violation.line == 10
    assert "doc #2" in violation.format(tmp_path)
    assert main(["--paths", str(invalid_multi_file)]) == 1


def test_malformed_indentation_parser_error_rejected(tmp_path: Path) -> None:
    """Mapping key indented under a block sequence (`ParserError`) must fail closed."""
    malformed_file = tmp_path / "malformed_indentation.yaml"
    # Mirrors the `cage_client_sdk.yaml:264` defect: `related-components:` indented
    # at 4 spaces under a block sequence `components:` instead of 2 spaces under
    # `component-definition:`.
    content = (
        "component-definition:\n"
        "  uuid: 8a9f5c3d-2b1e-4f7a-9c8d-5e6f7a8b9c0d\n"
        "  components:\n"
        "    - uuid: 7c8e9f1a-3d4b-5c6e-8f9a-1b2c3d4e5f6a\n"
        "      title: CAGE Client SDK\n"
        "    related-components:\n"
        "      - component-uuid: 56654b26-d648-4e47-bbc8-19edd3ec67ba\n"
    )
    malformed_file.write_text(content, encoding="utf-8")

    violations = scan_yaml_file(malformed_file)
    assert len(violations) == 1
    violation = violations[0]
    assert violation.kind == "parse_error"
    assert violation.error_type == "ParserError"
    assert violation.line == 6
    assert "ParserError" in violation.format(tmp_path)
    assert main(["--paths", str(malformed_file)]) == 1


def test_sibling_sequence_items_with_same_keys_allowed(tmp_path: Path) -> None:
    """Distinct mappings in sibling YAML list items may reuse the same key names."""
    valid_file = tmp_path / "sibling_items.yaml"
    content = (
        "props:\n"
        "  - name: implementation-status\n"
        "    value: implemented\n"
        "  - name: control-origination\n"
        "    value: system-specific\n"
        "links:\n"
        "  - href: ../../packages/cage-client/src/cage_client/core.py\n"
        "    rel: implementation\n"
        "  - href: ../../packages/cage-client/src/cage_client/transport.py\n"
        "    rel: implementation\n"
    )
    valid_file.write_text(content, encoding="utf-8")

    assert scan_yaml_file(valid_file) == []
    assert main(["--paths", str(valid_file), "--verbose"]) == 0


def test_live_repository_yaml_scan_passes_with_zero_violations() -> None:
    """All YAML files under compliance/, config/, and .github/ must pass cleanly."""
    assert main(["--verbose"]) == 0


def test_empty_or_mapping_free_yaml_corpus_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Empty YAML directories or YAML corpora with 0 mappings must fail closed."""
    empty_dir = tmp_path / "empty_yaml"
    empty_dir.mkdir()
    assert main(["--paths", str(empty_dir)]) == 1
    captured = capsys.readouterr()
    assert "vacuous/blind corpus floor not met" in captured.err
    assert "scanned YAML files 0 < minimum expected 1" in captured.err

    scalar_only = tmp_path / "scalar_only.yaml"
    scalar_only.write_text("---\n- item1\n- item2\n", encoding="utf-8")
    assert main(["--paths", str(scalar_only)]) == 1
    captured = capsys.readouterr()
    assert "recognized YAML mappings 0 < minimum expected 1" in captured.err
