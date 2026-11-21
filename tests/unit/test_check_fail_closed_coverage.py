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


def _write_shadow_baseline(
    repo: Path,
    count: int = 0,
    *,
    covered: int = 0,
    detector_sha256: str | None = None,
) -> Path:
    path = repo / "tests" / ".shadow-except-baseline"
    gate.write_initial_shadow_except_baseline(
        count,
        path,
        covered=covered,
        detector_sha256=detector_sha256,
        reason="Hermetic test baseline initialization.",
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

    _write_shadow_baseline(tmp_path)
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

    _write_shadow_baseline(tmp_path)
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

    _write_shadow_baseline(tmp_path)
    all_tests, _, _, resolved, static_viols = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    assert static_viols == []

    _, _, viols = gate.verify_coverage_reachability(all_tests, resolved, db_path)
    # Only test_strict_all_params[b] misses HIT_A; any_param and per_param_mark both pass!
    assert len(viols) == 1
    assert viols[0].code == "TARGET_NOT_REACHED"
    assert viols[0].nodeid == "tests/test_multi.py::test_strict_all_params[b]|run"


def test_shadow_except_finder_identifies_normalizing_pairs_and_prunes_disjoint_siblings(
    tmp_path: Path,
) -> None:
    _make_sample_module(
        tmp_path,
        "src/sample.py",
        """\
import asyncio
import httpx
import json
import jwt as pyjwt

class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code

class StoreError(Exception):
    pass

class StoreUnavailableError(StoreError):
    pass

class SiblingAError(Exception):
    pass

class SiblingBError(Exception):
    pass

class Verdict:
    def __init__(self, *, code: str, message: str) -> None:
        self.code = code
        self.message = message

class Service:
    def same_http_503(self, x: int) -> int:
        try:
            return 10 // x
        except ZeroDivisionError:
            msg = "E_ZERO_DIV"
            raise HTTPException(status_code=503, detail=msg)
        except ValueError:
            raise
        except Exception:
            raise HTTPException(503, "generic")

    def distinct_outcomes(self, x: int) -> int:
        try:
            return 10 // x
        except ZeroDivisionError:
            raise HTTPException(status_code=400, detail="bad")
        except Exception:
            raise HTTPException(status_code=503, detail="err")

    def fallthrough_pair(self) -> str:
        out = "ok"
        try:
            out = "work"
        except TimeoutError:
            msg = "TIMEOUT_FALLTHROUGH"
        except Exception:
            out = "err"
        return out

    def canonical_reraise_vs_wrap(self) -> None:
        try:
            pass
        except StoreError:
            raise
        except Exception as exc:
            raise StoreUnavailableError(str(exc)) from exc

    def conditional_if_reraise_vs_wrap(self, blocking: bool) -> None:
        try:
            pass
        except StoreUnavailableError:
            if blocking:
                raise
        except Exception as exc:
            if blocking:
                raise StoreUnavailableError(str(exc)) from exc

    def prose_only_return_diff_matches(self) -> Verdict:
        try:
            return Verdict(code="OK", message="ok")
        except TimeoutError as exc:
            return Verdict(code="OPA_UNAVAILABLE", message=f"timeout: {exc}")
        except Exception as exc:
            return Verdict(code="OPA_UNAVAILABLE", message=f"failed: {exc}")

    def structured_code_return_diff_skipped(self) -> Verdict:
        try:
            return Verdict(code="OK", message="ok")
        except TimeoutError as exc:
            return Verdict(code="OPA_TIMEOUT", message=str(exc))
        except Exception as exc:
            return Verdict(code="OPA_PARSE_ERR", message=str(exc))

    def superclass_non_exception_shadow(self) -> bool:
        try:
            return True
        except pyjwt.ExpiredSignatureError:
            return False
        except pyjwt.InvalidTokenError:
            return False

    def disjoint_siblings_skipped(self) -> bool:
        try:
            return True
        except FileNotFoundError:
            return False
        except json.JSONDecodeError:
            return False
        except httpx.HTTPStatusError:
            return False
        except httpx.RequestError:
            return False
        except SiblingAError:
            raise
        except SiblingBError:
            raise
        except StoreError:
            raise
        except asyncio.CancelledError:
            raise
""",
    )
    pairs = gate.find_outcome_normalizing_except_pairs(tmp_path)
    by_method = {p.qualname: p for p in pairs}
    assert set(by_method) == {
        "Service.same_http_503",
        "Service.fallthrough_pair",
        "Service.canonical_reraise_vs_wrap",
        "Service.conditional_if_reraise_vs_wrap",
        "Service.prose_only_return_diff_matches",
        "Service.superclass_non_exception_shadow",
    }
    assert by_method["Service.same_http_503"].outcome == "raise HTTPException:503"
    assert by_method["Service.fallthrough_pair"].outcome == "fallthrough"
    assert (
        by_method["Service.canonical_reraise_vs_wrap"].outcome
        == "raise StoreUnavailableError"
    )
    assert (
        by_method["Service.conditional_if_reraise_vs_wrap"].outcome
        == "raise StoreUnavailableError"
    )
    assert (
        "OPA_UNAVAILABLE" in by_method["Service.prose_only_return_diff_matches"].outcome
    )
    assert (
        by_method["Service.superclass_non_exception_shadow"].outcome == "return False"
    )


def test_shadow_except_finder_walks_packages_and_skips_vendored_jcs(
    tmp_path: Path,
) -> None:
    _make_sample_module(
        tmp_path,
        "packages/cage-client/src/cage_client/crypto.py",
        """\
class RoutingSealVerificationError(Exception):
    pass

def load_key() -> None:
    try:
        pass
    except RoutingSealVerificationError:
        tag = "PINNED_KEY_ERR"
        raise
    except Exception as exc:
        raise RoutingSealVerificationError(str(exc)) from exc
""",
    )
    _make_sample_module(
        tmp_path,
        "packages/cage-conformance/src/cage_conformance/verify.py",
        """\
class AttestationError(Exception):
    pass

def check_sig() -> bool:
    try:
        return True
    except AttestationError:
        tag = "ATTEST_ERR"
        return False
    except Exception:
        return False
""",
    )
    # Vendored _jcs directory must be excluded from shadow-except walk.
    _make_sample_module(
        tmp_path,
        "packages/cage-client/src/cage_client/_jcs/vendored.py",
        """\
def ignored() -> bool:
    try:
        return True
    except ValueError:
        return False
    except Exception:
        return False
""",
    )
    _write_census(
        tmp_path,
        [{"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_pkgs.py"}],
    )
    _make_sample_module(
        tmp_path,
        "tests/test_pkgs.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("cage_client.crypto:load_key#PINNED_KEY_ERR")
def test_client_pinned_key_fails_closed():
    assert True
""",
    )
    _write_shadow_baseline(tmp_path, 1, covered=1)

    _, _, _, resolved, violations = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    assert violations == []
    evaluated, uncovered = gate.evaluate_shadow_except_pairs(tmp_path, resolved)
    assert len(evaluated) == 2
    assert len(uncovered) == 1
    assert {p.rel_path for p in evaluated} == {
        "packages/cage-client/src/cage_client/crypto.py",
        "packages/cage-conformance/src/cage_conformance/verify.py",
    }
    assert uncovered[0].rel_path == (
        "packages/cage-conformance/src/cage_conformance/verify.py"
    )


def test_shadow_except_anchor_matching_requires_hitting_earlier_handler(
    tmp_path: Path,
) -> None:
    _make_sample_module(
        tmp_path,
        "src/guard.py",
        """\
def check_token(tok: str) -> bool:
    try:
        return tok == "ok"
    except KeyError:
        sentinel = "SHADOW_KEY_ERROR"
        return False
    except Exception:
        fallback = "FALLBACK_ERROR"
        return False
""",
    )
    _write_census(
        tmp_path,
        [{"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_guard.py"}],
    )
    _write_shadow_baseline(tmp_path, 0)

    # 1. Covering only the later handler or unanchored module:fn leaves the earlier pair UNCOVERED.
    test_file = _make_sample_module(
        tmp_path,
        "tests/test_guard.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("src.guard:check_token#FALLBACK_ERROR")
def test_only_hits_later_handler_fails_closed():
    assert True

@pytest.mark.covers("src.guard:check_token")
def test_unanchored_qualname_fails_closed():
    assert True
""",
    )
    _, _, _, resolved, violations = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    evaluated, uncovered = gate.evaluate_shadow_except_pairs(tmp_path, resolved)
    assert len(evaluated) == 1
    assert len(uncovered) == 1
    assert [v.code for v in violations] == ["SHADOW_EXCEPT_BASELINE_EXCEEDED"]

    # 2. Anchoring into the earlier handler marks the pair COVERED and passes the ratchet (0 <= 0).
    test_file.write_text(
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("src.guard:check_token#SHADOW_KEY_ERROR")
def test_hits_earlier_handler_fails_closed():
    assert True
""",
        encoding="utf-8",
    )
    _, _, _, resolved_ok, violations_ok = gate.verify_static(
        tmp_path, scope="readback-and-503"
    )
    evaluated_ok, uncovered_ok = gate.evaluate_shadow_except_pairs(
        tmp_path, resolved_ok
    )
    assert len(evaluated_ok) == 1
    assert uncovered_ok == []
    assert evaluated_ok[0].covered_by == (
        "tests/test_guard.py::test_hits_earlier_handler_fails_closed",
    )
    assert violations_ok == []


def test_shadow_except_ratchet_and_detector_bound_recompute_controls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _make_sample_module(
        tmp_path,
        "src/norm.py",
        """\
def normalize(flag: bool) -> bool:
    try:
        return flag
    except ValueError:
        tag = "VAL_ERR"
        return False
    except Exception:
        return False
""",
    )
    _write_census(
        tmp_path,
        [{"id": "C-1", "verdict": "HOLDS", "read_back": "tests/test_norm.py"}],
    )
    baseline_path = tmp_path / "tests" / ".shadow-except-baseline"

    # 1. Missing baseline with uncovered pairs -> SHADOW_EXCEPT_BASELINE_EXCEEDED.
    _, _, _, _, viol_missing = gate.verify_static(tmp_path, scope="readback-and-503")
    assert [v.code for v in viol_missing] == ["SHADOW_EXCEPT_BASELINE_EXCEEDED"]

    # 2. Corrupt, empty, legacy plain-int, tampered update (> before), or forged recompute (same sha) -> INVALID.
    live_sha = gate.compute_shadow_detector_fingerprint()
    forged_update = json.dumps(
        {
            "schema_version": 1,
            "baseline": 2,
            "detector_sha256": live_sha,
            "history": [
                {
                    "event": "initial_baseline",
                    "before_baseline": None,
                    "after_baseline": 1,
                    "after_covered": 0,
                    "after_total": 1,
                    "before_detector_sha256": None,
                    "detector_sha256": live_sha,
                    "reason": "init",
                },
                {
                    "event": "update",
                    "before_baseline": 1,
                    "after_baseline": 2,
                    "after_covered": 0,
                    "after_total": 2,
                    "before_detector_sha256": live_sha,
                    "detector_sha256": live_sha,
                    "reason": "forged upward update",
                },
            ],
        }
    )
    forged_recompute_same_sha = json.dumps(
        {
            "schema_version": 1,
            "baseline": 2,
            "detector_sha256": live_sha,
            "history": [
                {
                    "event": "initial_baseline",
                    "before_baseline": None,
                    "after_baseline": 1,
                    "after_covered": 0,
                    "after_total": 1,
                    "before_detector_sha256": None,
                    "detector_sha256": live_sha,
                    "reason": "init",
                },
                {
                    "event": "recompute",
                    "before_baseline": 1,
                    "after_baseline": 2,
                    "after_covered": 0,
                    "after_total": 2,
                    "before_detector_sha256": live_sha,
                    "detector_sha256": live_sha,
                    "reason": "Forged recompute with unchanged detector hash.",
                },
            ],
        }
    )
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    for bad in ("not-json\n", "47\n", "", forged_update, forged_recompute_same_sha):
        baseline_path.write_text(bad, encoding="utf-8")
        _, _, _, _, viol_bad = gate.verify_static(tmp_path, scope="readback-and-503")
        assert [v.code for v in viol_bad] == ["SHADOW_EXCEPT_BASELINE_INVALID"]

    # 3. Detector drift fails verify_static and blocks --update-baseline, requiring --recompute-baseline --reason.
    _write_shadow_baseline(tmp_path, 0, detector_sha256="stale-detector-sha-v0")
    _, _, _, _, viol_drift = gate.verify_static(tmp_path, scope="readback-and-503")
    assert [v.code for v in viol_drift] == ["SHADOW_EXCEPT_DETECTOR_DRIFT"]

    rc_upd_drift = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--update-baseline",
        ]
    )
    assert rc_upd_drift == 1
    assert "cannot absorb detector changes" in capsys.readouterr().err

    # --recompute-baseline without substantive --reason fails closed.
    rc_no_reason = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--recompute-baseline",
        ]
    )
    assert rc_no_reason == 1
    assert "--reason" in capsys.readouterr().err

    # --recompute-baseline with substantive --reason succeeds when detector_sha256 changed (0 -> 1).
    rc_recompute = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--recompute-baseline",
            "--reason",
            "Detector upgraded to bind bare raise to caught exception class.",
        ]
    )
    assert rc_recompute == 0
    capsys.readouterr()

    state_after_recompute, err = gate.read_shadow_except_baseline(baseline_path)
    assert err is None and state_after_recompute is not None
    assert state_after_recompute.baseline == 1
    assert state_after_recompute.detector_sha256 == live_sha
    assert state_after_recompute.history[-1]["event"] == "recompute"
    assert state_after_recompute.history[-1]["before_baseline"] == 0
    assert state_after_recompute.history[-1]["after_baseline"] == 1

    # 4. Immediate repeat --recompute-baseline with UNCHANGED detector_sha256 is refused!
    rc_repeat_recompute = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--recompute-baseline",
            "--reason",
            "Attempting to re-run recompute without changing detector.",
        ]
    )
    assert rc_repeat_recompute == 1
    assert "detector_sha256 is unchanged" in capsys.readouterr().err

    # 5. --update-baseline cannot raise baseline from 0 -> 1 under unchanged detector.
    _write_shadow_baseline(tmp_path, 0)
    rc_raise = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--update-baseline",
        ]
    )
    assert rc_raise == 1
    assert "monotonic ratchet" in capsys.readouterr().err

    # 6. Covering the pair drops uncovered to 0 and allows --update-baseline 1 -> 0.
    _write_shadow_baseline(tmp_path, 1)
    _make_sample_module(
        tmp_path,
        "tests/test_norm.py",
        """\
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

@pytest.mark.covers("src.norm:normalize#VAL_ERR")
def test_normalize_val_err_fails_closed():
    assert True
""",
    )
    rc_drop = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--update-baseline",
        ]
    )
    assert rc_drop == 0
    capsys.readouterr()
    state_dropped, err = gate.read_shadow_except_baseline(baseline_path)
    assert err is None and state_dropped is not None
    assert state_dropped.baseline == 0
    assert state_dropped.history[-1]["event"] == "update"
    assert state_dropped.history[-1]["before_baseline"] == 1
    assert state_dropped.history[-1]["after_baseline"] == 0

    rc_list = gate.main(
        [
            "--repo-root",
            str(tmp_path),
            "--scope",
            "readback-and-503",
            "--list-shadow-excepts",
        ]
    )
    assert rc_list == 0
    captured = capsys.readouterr()
    assert "COVERED\tsrc/norm.py:" in captured.out


def test_detector_fingerprint_ignores_comments_and_docstrings_but_tracks_logic(
    tmp_path: Path,
) -> None:
    base_script = tmp_path / "detector_a.py"
    comment_script = tmp_path / "detector_b.py"
    no_doc_script = tmp_path / "detector_no_doc.py"
    changed_script = tmp_path / "detector_c.py"

    base_script.write_text(
        "# BEGIN SHADOW_EXCEPT_DETECTOR\n"
        'def f(x: int) -> int:\n    """Docstring v1."""\n    return x + 1\n'
        "# END SHADOW_EXCEPT_DETECTOR\n",
        encoding="utf-8",
    )
    comment_script.write_text(
        "# BEGIN SHADOW_EXCEPT_DETECTOR\n"
        'def f(\n    x: int  # extra comment\n) -> int:\n    """Updated docstring."""\n    return x + 1\n'
        "# END SHADOW_EXCEPT_DETECTOR\n",
        encoding="utf-8",
    )
    no_doc_script.write_text(
        "# BEGIN SHADOW_EXCEPT_DETECTOR\n"
        "def f(x: int) -> int:\n    return x + 1\n"
        "# END SHADOW_EXCEPT_DETECTOR\n",
        encoding="utf-8",
    )
    changed_script.write_text(
        "# BEGIN SHADOW_EXCEPT_DETECTOR\n"
        'def f(x: int) -> int:\n    """Docstring v1."""\n    return x + 2\n'
        "# END SHADOW_EXCEPT_DETECTOR\n",
        encoding="utf-8",
    )
    sha_a = gate.compute_shadow_detector_fingerprint(base_script)
    sha_b = gate.compute_shadow_detector_fingerprint(comment_script)
    sha_no_doc = gate.compute_shadow_detector_fingerprint(no_doc_script)
    sha_c = gate.compute_shadow_detector_fingerprint(changed_script)
    assert sha_a == sha_b == sha_no_doc
    assert sha_a != sha_c


def test_repo_shadow_except_baseline_is_present_and_met() -> None:
    state, err = gate.read_shadow_except_baseline(
        REPO_ROOT / "tests" / ".shadow-except-baseline"
    )
    assert err is None
    assert state is not None
    assert state.baseline >= 0
    assert state.detector_sha256 == gate.compute_shadow_detector_fingerprint()
    assert len(state.history) >= 2
    assert state.history[1]["event"] == "recompute"
    assert state.history[1]["before_baseline"] == 47


def test_check_script_is_wired_in_ci_hooks_and_makefile() -> None:
    """Confirm scripts/check_fail_closed_coverage.py and package --cov scopes stay wired."""
    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    hooks_text = (REPO_ROOT / "scripts" / "setup_git_hooks.sh").read_text(
        encoding="utf-8"
    )
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "scripts/check_fail_closed_coverage.py" in ci_text
    assert "--cov-context=test" in ci_text
    assert "--cov=cage_client" in ci_text
    assert "--cov=packages/cage-conformance/src/cage_conformance" in ci_text
    assert "--verify-coverage .coverage" in ci_text
    assert "scripts/check_fail_closed_coverage.py" in hooks_text
    assert "scripts/check_fail_closed_coverage.py" in makefile_text
    assert "--cov=packages/cage-conformance/src/cage_conformance" in makefile_text
