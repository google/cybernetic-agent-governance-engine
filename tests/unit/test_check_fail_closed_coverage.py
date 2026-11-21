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

"""Unit tests for ``scripts/check_fail_closed_coverage.py``.

Verifies both halves of the fail-closed test reachability gate:

1. Static AST discovery, census ``read_back`` parsing, ``module:qualname`` /
   ``module:qualname#anchor`` target resolution (including comment stripping,
   docstring skipping, compound branch-body expansion, nested-closure guard,
   and uniqueness/ambiguity enforcement), and exemption hygiene.
2. Live dynamic-context SQLite verification against real ``coverage.py``
   databases in both ``branch=True`` (``arc`` table) and ``branch=False``
   (``line_bits`` bitmap table) modes — including a regression reproducing a
   sibling-masked short-circuit and proving exact string equality
   (``WHERE c.context = ?``) is immune to the ``coverage.py`` regex ``|``
   alternation bug.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from coverage.numbits import nums_to_numbits

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_fail_closed_coverage.py"

_spec = importlib.util.spec_from_file_location(
    "check_fail_closed_coverage", SCRIPT_PATH
)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
sys.modules["check_fail_closed_coverage"] = gate
_spec.loader.exec_module(gate)


def _write_census(repo: Path, rows: list[dict[str, object]]) -> Path:
    path = repo / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n",
        encoding="utf-8",
    )
    return path


def _make_sample_module(repo: Path, rel: str, code: str) -> Path:
    dest = repo / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(code, encoding="utf-8")
    return dest


def test_parse_target_string_valid_and_invalid() -> None:
    spec = gate.parse_target_string("src.gateway.server.proxy:chat_completions")
    assert spec.module == "src.gateway.server.proxy"
    assert spec.qualname == "chat_completions"
    assert spec.anchor is None
    assert spec.scope == "all_params"

    anchored = gate.parse_target_string(
        "src.gateway.server.proxy:Proxy.handle#TOKEN_QUOTA_DENIED",
        scope="any_param",
        param_id="quota",
    )
    assert anchored.module == "src.gateway.server.proxy"
    assert anchored.qualname == "Proxy.handle"
    assert anchored.anchor == "TOKEN_QUOTA_DENIED"
    assert anchored.scope == "any_param"
    assert anchored.param_id == "quota"

    for bad in (
        "",
        "src.only_module",
        ":fn",
        "src.mod:",
        "src.mod:fn#",
        "src.mod:1bad",
        "bad-mod:fn",
    ):
        with pytest.raises(ValueError):
            gate.parse_target_string(bad)

    with pytest.raises(ValueError, match="scope"):
        gate.parse_target_string("src.mod:fn", scope="bogus")


def test_decode_numbits_matches_coverage_numbits() -> None:
    for sample in (
        [],
        [1],
        [7, 8, 9, 15, 16, 17],
        [1, 2, 3, 42, 128, 255, 256, 1023, 2048],
    ):
        blob = nums_to_numbits(sample)
        assert gate.decode_numbits(blob) == set(sample)


def test_target_resolver_excludes_def_and_docstring_and_ignores_comments(
    tmp_path: Path,
) -> None:
    _make_sample_module(
        tmp_path,
        "src/sample.py",
        '''\
def guard(flag: str) -> int:
    """Docstring mentioning TOKEN_QUOTA_DENIED should not match."""
    # Comment mentioning TOKEN_QUOTA_DENIED should not match or cause ambiguity.
    if flag == "early":
        return 503
    if flag == "quota":
        status = "TOKEN_QUOTA_DENIED"
        return 429 if status else 200
    try:
        return 200
    except RuntimeError:
        return 503

    def helper() -> int:
        return 999
''',
    )
    resolver = gate.TargetResolver(tmp_path)

    body_res = resolver.resolve(gate.parse_target_string("src.sample:guard"))
    assert 1 not in body_res.target_lines  # def header excluded
    assert 2 not in body_res.target_lines  # docstring excluded
    assert 14 not in body_res.target_lines  # nested def excluded
    assert 15 not in body_res.target_lines
    assert {4, 5, 6, 7, 8, 10, 12}.issubset(body_res.target_lines)

    # Unique statement anchor ignores docstring & comment mentioning the same token
    anchor_res = resolver.resolve(
        gate.parse_target_string("src.sample:guard#TOKEN_QUOTA_DENIED")
    )
    assert anchor_res.resolution_kind == "statement_anchor"
    assert anchor_res.target_lines == frozenset({7})

    # Anchoring on `if` header resolves to the branch BODY (line 5), NOT the header (line 4)!
    branch_res = resolver.resolve(
        gate.parse_target_string('src.sample:guard#flag == "early"')
    )
    assert branch_res.resolution_kind == "branch_body_anchor"
    assert branch_res.target_lines == frozenset({5})
    assert 4 not in branch_res.target_lines

    # Anchoring on `except` header resolves to handler BODY (line 12), NOT line 11!
    exc_res = resolver.resolve(
        gate.parse_target_string("src.sample:guard#RuntimeError")
    )
    assert exc_res.resolution_kind == "branch_body_anchor"
    assert exc_res.target_lines == frozenset({12})
    assert 11 not in exc_res.target_lines

    # Ambiguous anchor (line 5 and line 12 both have `return 503`) fails closed
    with pytest.raises(LookupError, match="ambiguous"):
        resolver.resolve(gate.parse_target_string("src.sample:guard#return 503"))

    # Missing anchor fails closed
    with pytest.raises(LookupError, match="not found"):
        resolver.resolve(gate.parse_target_string("src.sample:guard#DOES_NOT_EXIST"))

    # Anchor falling inside a nested def instructs caller to use nested qualname
    with pytest.raises(LookupError, match=r"guard\.helper"):
        resolver.resolve(gate.parse_target_string("src.sample:guard#999"))

    # Direct nested qualname works!
    nested_res = resolver.resolve(
        gate.parse_target_string("src.sample:guard.helper#999")
    )
    assert nested_res.target_lines == frozenset({15})


def test_static_discovery_catches_unmarked_syntax_stale_and_mutual_exclusion(
    tmp_path: Path,
) -> None:
    _make_sample_module(
        tmp_path,
        "src/mod.py",
        "def f():\n    return 503\n",
    )
    _write_census(
        tmp_path,
        [
            {"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_in_census.py"},
        ],
    )
    _make_sample_module(
        tmp_path,
        "tests/test_in_census.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

def test_unmarked_fails_closed():
    assert True

@pytest.mark.covers("src.mod:f")
@pytest.mark.covers_exempt(reason="negative-control: happy path verification test")
def test_both_markers_fail_closed():
    assert True

@pytest.mark.covers_exempt(reason="badcat: not a valid exemption prefix here")
def test_bad_exempt_cat_unavailable():
    assert True

@pytest.mark.covers_exempt(reason="negative-control: tiny")
def test_short_exempt_refuses():
    assert True

@pytest.mark.covers_exempt(reason="negative-control: stale marker on non-candidate test")
def test_ordinary_happy_path():
    assert True

@pytest.mark.covers("src.mod:deleted_fn")
def test_stale_target_blocked():
    assert True

@pytest.mark.covers(dynamic_var)
def test_non_literal_unavailable():
    assert True
""",
    )
    _make_sample_module(
        tmp_path,
        "tests/test_outside_census.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

def test_ordinary_503_assert():
    status = 503
    assert status == 503

def test_outside_census_name_only_fails_closed():
    assert True
""",
    )

    _, candidates, _, _, violations = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    assert "tests/test_outside_census.py::test_ordinary_503_assert" in candidates
    assert (
        "tests/test_outside_census.py::test_outside_census_name_only_fails_closed"
        not in candidates
    )

    by_code = {(v.code, v.nodeid.split("::")[-1]) for v in violations}
    assert ("UNMARKED_CANDIDATE", "test_unmarked_fails_closed") in by_code
    assert ("UNMARKED_CANDIDATE", "test_ordinary_503_assert") in by_code
    assert ("MUTUALLY_EXCLUSIVE", "test_both_markers_fail_closed") in by_code
    assert ("INVALID_EXEMPTION", "test_bad_exempt_cat_unavailable") in by_code
    assert ("INVALID_EXEMPTION", "test_short_exempt_refuses") in by_code
    assert ("STALE_EXEMPTION", "test_ordinary_happy_path") in by_code
    assert ("UNRESOLVED_TARGET", "test_stale_target_blocked") in by_code
    assert ("MARKER_SYNTAX", "test_non_literal_unavailable") in by_code


def test_census_loader_fails_closed_on_missing_empty_or_malformed(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        gate.load_census_readback_files(tmp_path)

    bad = tmp_path / "compliance" / "oscal" / "evidence_claim_census.jsonl"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        gate.load_census_readback_files(tmp_path)

    bad.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed JSONL"):
        gate.load_census_readback_files(tmp_path)

    bad.write_text(
        '{"id": "C1", "verdict": "HOLDS", "read_back": "docs/only.md"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Zero test files"):
        gate.load_census_readback_files(tmp_path)


@pytest.mark.parametrize("branch_mode", [True, False], ids=["arc_branch", "line_bits"])
def test_runtime_verification_catches_short_circuit_and_avoids_pipe_regex_trap(
    tmp_path: Path,
    branch_mode: bool,
) -> None:
    """Reproduce the short-circuit defect where two tests both return 503.

    Even though ``test_other_hits_quota`` executes the quota branch inside the
    SAME ``.coverage`` SQLite database, ``test_quota_short_circuits`` returns
    ``503`` from an upstream branch and MUST fail ``TARGET_NOT_REACHED`` under
    exact string lookup (immune to the ``coverage.py`` ``|`` regex alternation bug).
    """
    src_file = _make_sample_module(
        tmp_path,
        "src/proxy.py",
        """\
def handle(kind: str) -> int:
    if kind == "quarantine_unavailable":
        msg = "QUARANTINE_OUTAGE"
        return 503 if msg else 200
    if kind == "injection":
        msg = "INFERENCE_PROXY_BLOCK"
        return 503 if msg else 200
    if kind == "quota":
        msg = "TOKEN_QUOTA_DENIED"
        return 503 if msg else 200
    return 200
""",
    )
    _write_census(
        tmp_path,
        [{"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_proxy.py"}],
    )
    _make_sample_module(
        tmp_path,
        "tests/test_proxy.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("src.proxy:handle#TOKEN_QUOTA_DENIED")
def test_other_hits_quota():
    assert True

@pytest.mark.covers("src.proxy:handle#TOKEN_QUOTA_DENIED")
def test_quota_short_circuits():
    assert True

@pytest.mark.covers("src.proxy:handle#INFERENCE_PROXY_BLOCK")
def test_only_hit_in_setup():
    assert True
""",
    )

    db_path = tmp_path / ".coverage"
    runner = tmp_path / "_record_cov.py"
    runner.write_text(
        f"""\
import importlib.util
import coverage

cov = coverage.Coverage(
    data_file={str(db_path)!r},
    config_file=False,
    branch={branch_mode!r},
    source=[{str(tmp_path / "src")!r}],
)
spec = importlib.util.spec_from_file_location("tmp_proxy_mod", {str(src_file)!r})
mod = importlib.util.module_from_spec(spec)
cov.start()
try:
    spec.loader.exec_module(mod)
    cov.switch_context("tests/test_proxy.py::test_other_hits_quota|run")
    assert mod.handle("quota") == 503
    cov.switch_context("tests/test_proxy.py::test_quota_short_circuits|run")
    assert mod.handle("quarantine_unavailable") == 503
    cov.switch_context("tests/test_proxy.py::test_only_hit_in_setup|setup")
    assert mod.handle("injection") == 503
    cov.switch_context("tests/test_proxy.py::test_only_hit_in_setup|run")
    assert mod.handle("ok") == 200
finally:
    cov.stop()
    cov.save()
""",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(runner)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert db_path.is_file()

    all_tests, _, _, resolved, static_viols = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    assert static_viols == []

    checked, ctxs, runtime_viols = gate.verify_coverage_reachability(
        all_tests, resolved, db_path
    )
    assert checked == 3
    assert ctxs == 3
    viol_map = {v.nodeid: v.code for v in runtime_viols}
    assert "tests/test_proxy.py::test_other_hits_quota|run" not in viol_map
    assert (
        viol_map["tests/test_proxy.py::test_quota_short_circuits|run"]
        == "TARGET_NOT_REACHED"
    )
    assert (
        viol_map["tests/test_proxy.py::test_only_hit_in_setup|run"]
        == "TARGET_NOT_REACHED"
    )


def test_runtime_verification_fails_closed_without_dynamic_contexts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / ".coverage"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    conn.execute("INSERT INTO meta VALUES ('has_arcs', '1')")
    conn.execute("CREATE TABLE file (id INTEGER PRIMARY KEY, path TEXT)")
    conn.execute("CREATE TABLE context (id INTEGER PRIMARY KEY, context TEXT)")
    conn.execute("INSERT INTO context VALUES (1, '')")
    conn.execute(
        "CREATE TABLE arc (file_id INTEGER, context_id INTEGER, fromno INTEGER, tono INTEGER)"
    )
    conn.commit()
    conn.close()

    with pytest.raises(ValueError, match="zero per-test '\\|run' dynamic contexts"):
        gate.CoverageContextDB(db_path)


def test_parametrized_scopes_all_params_any_param_and_param_mark(
    tmp_path: Path,
) -> None:
    src_file = _make_sample_module(
        tmp_path,
        "src/multi.py",
        """\
def check(mode: str) -> int:
    if mode == "a":
        val = "HIT_A"
        return 503 if val else 200
    if mode == "b":
        val = "HIT_B"
        return 503 if val else 200
    return 200
""",
    )
    _write_census(
        tmp_path,
        [{"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_multi.py"}],
    )
    _make_sample_module(
        tmp_path,
        "tests/test_multi.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("src.multi:check#HIT_A")
@pytest.mark.parametrize("mode", ["a", "b"])
def test_strict_all_params(mode):
    assert True

@pytest.mark.covers("src.multi:check#HIT_A", scope="any_param")
@pytest.mark.parametrize("mode", ["a", "b"])
def test_any_param_passes(mode):
    assert True

@pytest.mark.parametrize(
    "mode",
    [
        pytest.param("a", id="case_a", marks=pytest.mark.covers("src.multi:check#HIT_A")),
        pytest.param("b", id="case_b", marks=pytest.mark.covers("src.multi:check#HIT_B")),
    ],
)
def test_per_param_mark(mode):
    assert True
""",
    )
    db_path = tmp_path / ".coverage"
    runner = tmp_path / "_record_multi.py"
    runner.write_text(
        f"""\
import importlib.util
import coverage

cov = coverage.Coverage(
    data_file={str(db_path)!r},
    config_file=False,
    branch=True,
    source=[{str(tmp_path / "src")!r}],
)
spec = importlib.util.spec_from_file_location("tmp_multi_mod", {str(src_file)!r})
mod = importlib.util.module_from_spec(spec)
cov.start()
try:
    spec.loader.exec_module(mod)
    for test_name in ("test_strict_all_params", "test_any_param_passes"):
        cov.switch_context(f"tests/test_multi.py::{{test_name}}[a]|run")
        mod.check("a")
        cov.switch_context(f"tests/test_multi.py::{{test_name}}[b]|run")
        mod.check("b")
    cov.switch_context("tests/test_multi.py::test_per_param_mark[case_a]|run")
    mod.check("a")
    cov.switch_context("tests/test_multi.py::test_per_param_mark[case_b]|run")
    mod.check("b")
finally:
    cov.stop()
    cov.save()
""",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(runner)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert db_path.is_file()

    all_tests, _, _, resolved, static_viols = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    assert static_viols == []

    _, _, viols = gate.verify_coverage_reachability(all_tests, resolved, db_path)
    # Only test_strict_all_params[b] misses HIT_A; any_param and per_param_mark both pass!
    assert len(viols) == 1
    assert viols[0].code == "TARGET_NOT_REACHED"
    assert viols[0].nodeid == "tests/test_multi.py::test_strict_all_params[b]|run"


def test_check_script_is_wired_in_ci_hooks_and_makefile() -> None:
    """Confirm scripts/check_fail_closed_coverage.py stays wired into CI, hooks, and Makefile."""
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    hooks_text = (REPO_ROOT / "scripts" / "setup_git_hooks.sh").read_text(
        encoding="utf-8"
    )
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "scripts/check_fail_closed_coverage.py" in ci_text
    assert "--cov-context=test" in ci_text
    assert "--verify-coverage .coverage" in ci_text
    assert "scripts/check_fail_closed_coverage.py" in hooks_text
    assert "scripts/check_fail_closed_coverage.py" in makefile_text
