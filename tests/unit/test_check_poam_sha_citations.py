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

"""Tests for the POA&M SHA-citation gate (``scripts/check_poam_sha_citations.py``).

Every test runs against a temporary git repository with real commits: a ``main``
line (including a rebased commit and an all-digit abbreviated SHA), a kept
squash-style feature branch head, a deleted branch whose tip is still in the
object store, a deleted-and-pruned branch, an annotated release tag, an
``archive/*`` tag on an off-main commit, and a root tree.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

import scripts.check_poam_sha_citations as gate

pytestmark = [pytest.mark.unit, pytest.mark.local]

SCRIPT = Path(gate.__file__).resolve()
REASON = "Initial baseline for the temporary test repository."


@dataclass(frozen=True)
class Repo:
    root: Path
    c0: str  # main, 2026-01-01
    c1: str  # main, 2026-01-05 (squash of #12)
    c2: str  # main, rebased: author 2026-01-01, committer 2026-01-06
    digits: str  # main, all-digit 8-char abbreviation, 2026-01-07
    head: str  # kept feature-branch head (off main), 2026-02-01
    head2: str  # second kept feature-branch head (off main)
    gone: str  # tip of a deleted branch, still in the object store
    pruned: str  # tip of a deleted, pruned branch (no object)
    archived: str  # off-main commit contained in tag archive/proto
    tree: str  # root tree of c1
    tag: str  # annotated tag object v1 (points at c1)


def _env(
    date: str = "2026-01-01T12:00:00+00:00", cdate: str | None = None
) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": cdate or date,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    return env


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        env=env or _env(),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _commit(root: Path, msg: str, date: str, cdate: str | None = None) -> str:
    _git(root, "commit", "--allow-empty", "-q", "-m", msg, env=_env(date, cdate))
    return _git(root, "rev-parse", "HEAD")


def _branch_commit(root: Path, branch: str, base: str, msg: str, date: str) -> str:
    _git(root, "checkout", "-q", "-b", branch, base)
    oid = _commit(root, msg, date)
    _git(root, "checkout", "-q", "main")
    return oid


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> Repo:
    root = tmp_path_factory.mktemp("poam-repo")
    _git(root, "init", "-q", "-b", "main")
    (root / "docs").mkdir()
    (root / "docs" / "POAM.md").write_text("placeholder\n", encoding="utf-8")
    _git(root, "add", ".")
    c0 = _commit(root, "c0", "2026-01-01T12:00:00+00:00")

    pruned = _branch_commit(root, "pruned", c0, "pruned", "2026-01-02T12:00:00+00:00")
    _git(root, "branch", "-q", "-D", "pruned")
    _git(root, "reflog", "expire", "--expire=now", "--all")
    _git(root, "gc", "-q", "--prune=now")

    c1 = _commit(root, "squash of #12", "2026-01-05T12:00:00+00:00")
    c2 = _commit(
        root, "rebased", "2026-01-01T09:00:00+00:00", "2026-01-06T09:00:00+00:00"
    )
    tree_oid = _git(root, "rev-parse", f"{c2}^{{tree}}")
    digits = ""
    for i in range(4000):
        cand = _git(
            root,
            "commit-tree",
            tree_oid,
            "-p",
            c2,
            "-m",
            f"digits {i}",
            env=_env("2026-01-07T12:00:00+00:00"),
        )
        if cand[:8].isdigit():
            digits = cand
            break
    assert digits, "could not mint an all-digit abbreviated SHA"
    _git(root, "update-ref", "refs/heads/main", digits)

    head = _branch_commit(root, "feat/x", c0, "head", "2026-02-01T12:00:00+00:00")
    head2 = _branch_commit(root, "feat/y", c0, "head2", "2026-02-02T12:00:00+00:00")
    gone = _branch_commit(root, "gone", c0, "gone", "2026-01-03T12:00:00+00:00")
    _git(root, "branch", "-q", "-D", "gone")
    archived = _branch_commit(root, "arch", c0, "arch", "2026-01-03T12:00:00+00:00")
    _git(root, "tag", "-a", "archive/proto", "-m", "archive", archived)
    _git(root, "branch", "-q", "-D", "arch")
    _git(root, "tag", "-a", "v1", "-m", "v1", c1)
    tag = _git(root, "rev-parse", "refs/tags/v1")
    return Repo(
        root=root,
        c0=c0,
        c1=c1,
        c2=c2,
        digits=digits,
        head=head,
        head2=head2,
        gone=gone,
        pruned=pruned,
        archived=archived,
        tree=_git(root, "rev-parse", f"{c1}^{{tree}}"),
        tag=tag,
    )


def _scan(repo: Repo, text: str, mod: ModuleType = gate) -> gate.ScanResult:
    (repo.root / "docs" / "POAM.md").write_text(text, encoding="utf-8")
    return mod.scan_repo(repo.root, main_ref="refs/heads/main")


def _verdicts(res: gate.ScanResult, token: str) -> list[str]:
    return [c.verdict for c in res.cites if c.token == token]


def _s(oid: str) -> str:
    return oid[:8]


# ---------------------------------------------------------------- object type


def test_main_ancestor_commit_needs_no_label(repo: Repo) -> None:
    res = _scan(repo, f"Fixed in `{_s(repo.c1)}`.\n")
    assert _verdicts(res, _s(repo.c1)) == ["main_commit"]
    assert res.violations == []


def test_all_digit_token_is_looked_up_before_any_numeric_reading(repo: Repo) -> None:
    tok = repo.digits[:8]
    assert tok.isdigit()
    res = _scan(repo, f"Landed as `{tok}`.\n")
    cite = next(c for c in res.cites if c.token == tok)
    assert (cite.raw_type, cite.canon_type, cite.verdict) == (
        "commit",
        "commit",
        "main_commit",
    )
    res = _scan(repo, "run `41362761903` and `41362761904`.\n")
    assert _verdicts(res, "41362761903") == ["id_labelled"]
    assert _verdicts(res, "41362761904") == ["unlabelled_unresolved"]


def test_tree_and_tag_require_matching_kind_label(repo: Repo) -> None:
    res = _scan(
        repo,
        f"tree `{repo.tree[:12]}`; `{repo.tree[:12]}`; tag `{repo.tree[:12]}`; "
        f"tag object `{_s(repo.tag)}`; tree `{_s(repo.tag)}`.\n",
    )
    assert _verdicts(res, repo.tree[:12]) == [
        "kind_labelled",
        "unlabelled_kind",
        "label_type_mismatch",
    ]
    assert _verdicts(res, _s(repo.tag)) == ["kind_labelled", "label_type_mismatch"]


def test_label_type_mismatch_for_id_absent_and_kind_labels(repo: Repo) -> None:
    res = _scan(
        repo,
        f"run `{_s(repo.c1)}`; absent `{_s(repo.c0)}`; tree `deadbee1`.\n",
    )
    assert _verdicts(res, _s(repo.c1)) == ["label_type_mismatch"]
    assert _verdicts(res, _s(repo.c0)) == ["label_type_mismatch"]
    assert _verdicts(res, "deadbee1") == ["label_type_mismatch"]


def test_absent_label_forms(repo: Repo) -> None:
    res = _scan(
        repo,
        "absent `1234abc`; `1234abd` (a non-existent SHA); commits `1234abe` "
        "(which resolves nowhere in `git log --all`).\n",
    )
    for tok in ("1234abc", "1234abd", "1234abe"):
        assert _verdicts(res, tok) == ["absent_labelled"], tok


def test_dead_commit_claim_vs_unlabelled_unresolved(repo: Repo) -> None:
    res = _scan(
        repo,
        "Remediation commit: `abcdef1`. Merged in `#44` (`abcdef2`). "
        "Remediation commits: `abcdef3`, `abcdef4`. Mentioned `abcdef5`.\n",
    )
    for tok in ("abcdef1", "abcdef2", "abcdef3", "abcdef4"):
        assert _verdicts(res, tok) == ["dead_commit_claim"], tok
    assert _verdicts(res, "abcdef5") == ["unlabelled_unresolved"]


def test_clone_local_object_does_not_change_the_verdict(repo: Repo) -> None:
    res = _scan(repo, f"Seen `{_s(repo.gone)}` and `{_s(repo.pruned)}`.\n")
    gone = next(c for c in res.cites if c.token == _s(repo.gone))
    pruned = next(c for c in res.cites if c.token == _s(repo.pruned))
    assert gone.raw_type == "commit" and pruned.raw_type == "missing"
    assert gone.canon_type is None and pruned.canon_type is None
    assert gone.verdict == pruned.verdict == "unlabelled_unresolved"


def test_off_main_commit_in_named_tag_is_ok(repo: Repo) -> None:
    res = _scan(
        repo,
        f"Kept at `{_s(repo.archived)}` (tag `archive/proto`). "
        f"Also `{_s(repo.archived)}` alone.\n",
    )
    assert _verdicts(res, _s(repo.archived)) == [
        "tagged_commit",
        "unlabelled_unresolved",
    ]


# ---------------------------------------------------------------- paired form


@pytest.mark.parametrize("which", ["head", "gone", "pruned"])
def test_paired_squash_and_branch_head_is_valid(repo: Repo, which: str) -> None:
    head = _s(getattr(repo, which))
    res = _scan(repo, f"Verified on `#12` (`{_s(repo.c1)}`, branch head `{head}`).\n")
    assert _verdicts(res, head) == ["paired_head"]
    assert res.violations == []


def test_paired_form_label_variants(repo: Repo) -> None:
    res = _scan(
        repo,
        f"Removed in `{_s(repo.c1)}` (#12, `2026-01-05`, PR commit `{_s(repo.head)}`). "
        f"merged in `#12` as `{_s(repo.c2)}` (sub-commit `{_s(repo.gone)}`).\n",
    )
    assert _verdicts(res, _s(repo.head)) == ["paired_head"]
    assert _verdicts(res, _s(repo.gone)) == ["paired_head"]


def test_paired_form_missing_pr_number(repo: Repo) -> None:
    res = _scan(repo, f"Landed (`{_s(repo.c1)}`, branch head `{_s(repo.head)}`).\n")
    assert _verdicts(res, _s(repo.head)) == ["paired_missing_pr"]


def test_paired_form_main_sha_not_ancestor(repo: Repo) -> None:
    res = _scan(
        repo,
        f"`#12` (`{_s(repo.head2)}`, branch head `{_s(repo.head)}`). "
        f"`#13` (`abcdef9`, branch head `{_s(repo.gone)}`).\n",
    )
    assert _verdicts(res, _s(repo.head)) == ["paired_main_not_ancestor"]
    assert _verdicts(res, _s(repo.gone)) == ["paired_main_not_ancestor"]


def test_same_citation_boundary(repo: Repo) -> None:
    c1, c2, h1, h2 = _s(repo.c1), _s(repo.c2), _s(repo.head), _s(repo.head2)
    # Several pairs inside one parenthetical bind in order.
    res = _scan(
        repo,
        f"(merged `#12` as `{c1}`, branch head `{h1}`, alongside `#13` as `{c2}`, "
        f"branch head `{h2}`).\n",
    )
    assert _verdicts(res, h1) == ["paired_head"]
    assert _verdicts(res, h2) == ["paired_head"]
    # A PR number and main commit bind at most one head.
    res = _scan(repo, f"(`#12` `{c1}`, branch head `{h1}`, branch head `{h2}`).\n")
    assert _verdicts(res, h2) == ["paired_missing_pr"]
    # A separate parenthetical does not reach back across a comma.
    res = _scan(repo, f"`#12` (`{c1}`), and later (branch head `{h1}`).\n")
    assert _verdicts(res, h1) == ["paired_missing_pr"]
    # At depth 0 a comma ends the citation; a sentence end always does.
    res = _scan(repo, f"`{c1}` shares nothing, unlike #15's head `{h1}`.\n")
    assert _verdicts(res, h1) == ["paired_main_not_ancestor"]
    res = _scan(repo, f"`#12` landed as `{c1}`. Its branch head `{h1}` differs.\n")
    assert _verdicts(res, h1) == ["paired_missing_pr"]
    # Table cells are hard boundaries.
    res = _scan(
        repo,
        f"| a | b |\n|---|---|\n| `#12` `{c1}` | branch head `{h1}` |\n",
    )
    assert _verdicts(res, h1) == ["paired_missing_pr"]


# ---------------------------------------------------------------- labels


def test_plural_labels_distribute_singular_labels_do_not(repo: Repo) -> None:
    res = _scan(
        repo,
        "dispatch runs `41482637392` and `42332320807`; "
        "job `136987863741` and `bc8e6f26`.\n",
    )
    assert _verdicts(res, "42332320807") == ["id_labelled"]
    assert _verdicts(res, "bc8e6f26") == ["unlabelled_unresolved"]


def test_table_header_label(repo: Repo) -> None:
    res = _scan(repo, "| Image | Build |\n|---|---|\n| gateway | `3e268752` |\n")
    assert _verdicts(res, "3e268752") == ["id_labelled"]


# ---------------------------------------------------------------- fail closed


def test_shallow_clone_fails_closed(repo: Repo, tmp_path: Path) -> None:
    (repo.root / "docs" / "POAM.md").write_text(f"`{_s(repo.c1)}`\n", encoding="utf-8")
    dst = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", f"file://{repo.root}", str(dst))
    (dst / "docs" / "POAM.md").write_text(f"`{_s(repo.c1)}`\n", encoding="utf-8")
    with pytest.raises(gate.CitationGateError, match="[Ss]hallow"):
        gate.scan_repo(dst)
    assert gate.main(["--repo-root", str(dst)]) == 1


def test_missing_poam_and_vacuous_scan_fail_closed(repo: Repo, tmp_path: Path) -> None:
    with pytest.raises(gate.CitationGateError, match="not found"):
        gate.scan_repo(tmp_path)
    with pytest.raises(gate.CitationGateError, match="zero hex citations"):
        _scan(repo, "No citations here.\n")


# ---------------------------------------------------------------- chronology


def _chron(res: gate.ScanResult) -> dict[str, str]:
    return {r.token: r.verdict for r in res.chronology}


def test_closure_before_commit_fails_and_same_day_passes(repo: Repo) -> None:
    c1 = _s(repo.c1)
    res = _scan(repo, f"**Status:** Closed (2026-01-04) — merged in `#12` as `{c1}`.\n")
    assert _chron(res) == {c1: "chronology_violation"}
    assert [v.cls for v in res.violations] == ["chronology_violation"]
    res = _scan(repo, f"**Status:** Closed (2026-01-05) — merged in `#12` as `{c1}`.\n")
    assert _chron(res) == {c1: "chronology_ok"}
    assert res.violations == []


def test_rebased_commit_is_dated_by_committer_not_author(repo: Repo) -> None:
    c2 = _s(repo.c2)
    res = _scan(repo, f"Closed `2026-01-03` (`{c2}`, `#12`).\n")
    record = res.chronology[0]
    assert (record.author_date, record.committer_date) == ("2026-01-01", "2026-01-06")
    assert record.verdict == "chronology_violation"


def test_unparseable_closure_date_is_counted(repo: Repo) -> None:
    res = _scan(repo, f"Closed soon — remediation commit `{_s(repo.c1)}`.\n")
    assert [v.cls for v in res.violations] == ["closure_date_unparseable"]


def test_paired_form_chronology_enforced_on_main_sha(repo: Repo) -> None:
    c1, h1 = _s(repo.c1), _s(repo.head)
    res = _scan(repo, f"Closed (2026-01-05) — `#12` (`{c1}`, branch head `{h1}`).\n")
    record = res.chronology[0]
    assert (record.token, record.verdict, record.head_token) == (
        c1,
        "chronology_ok",
        h1,
    )
    assert record.head_dates == "author 2026-02-01, committer 2026-02-01"
    res = _scan(repo, f"Closed (2026-01-04) — `#12` (`{c1}`, branch head `{h1}`).\n")
    assert _chron(res) == {c1: "chronology_violation"}


def test_undatable_evidence_and_closed_column_rows(repo: Repo) -> None:
    c1, c2 = _s(repo.c1), _s(repo.c2)
    res = _scan(repo, "Closed `2026-01-09` (`abcdef1`, `#12`).\n")
    assert _chron(res) == {"abcdef1": "chronology_undatable"}
    assert sorted(v.cls for v in res.violations) == [
        "chronology_undatable",
        "dead_commit_claim",
    ]
    table = (
        "| ID | Description | Closed |\n|---|---|---|\n"
        f"| P-1 | Remediation commit: `{c1}`. **Update (2026-03-01):** "
        f"see `#13` (`{c2}`). | 2026-01-05 |\n"
    )
    res = _scan(repo, table)
    assert _chron(res) == {c1: "chronology_ok"}


def test_later_reference_in_unanchored_parenthetical_is_not_evidence(
    repo: Repo,
) -> None:
    res = _scan(
        repo,
        f"Closed `2026-01-05` (`{_s(repo.c1)}`, `#12`) while drifting "
        f"(`#13` `{_s(repo.c2)}` merged later).\n",
    )
    assert _chron(res) == {_s(repo.c1): "chronology_ok"}


# ---------------------------------------------------------------- ratchet

TWO_DEFECTS = "Remediation commit: `abcdef1`.\n\nMentioned `abcdef5`.\n"
SWAPPED = "Remediation commit: `abcdef1`.\n\nMentioned `abcdef6`.\n"


def _baseline(
    repo: Repo, tmp_path: Path, text: str, name: str = "baseline.json"
) -> Path:
    path = tmp_path / name
    (repo.root / "docs" / "POAM.md").write_text(text, encoding="utf-8")
    rc = gate.main(
        [
            "--repo-root",
            str(repo.root),
            "--baseline",
            str(path),
            "--recompute-baseline",
            "--reason",
            REASON,
        ]
    )
    assert rc == 0
    return path


def _check(repo: Repo, path: Path, text: str, *extra: str) -> int:
    (repo.root / "docs" / "POAM.md").write_text(text, encoding="utf-8")
    return gate.main(["--repo-root", str(repo.root), "--baseline", str(path), *extra])


def test_ratchet_passes_at_baseline_and_records_classes(
    repo: Repo, tmp_path: Path
) -> None:
    path = _baseline(repo, tmp_path, TWO_DEFECTS)
    data = json.loads(path.read_text())
    assert data["class_counts"]["dead_commit_claim"] == 1
    assert data["class_counts"]["unlabelled_unresolved"] == 1
    assert data["history"][0]["event"] == "initial_baseline"
    assert _check(repo, path, TWO_DEFECTS) == 0


def test_new_violation_fails_even_when_total_does_not_rise(
    repo: Repo, tmp_path: Path
) -> None:
    path = _baseline(repo, tmp_path, TWO_DEFECTS)
    swapped = SWAPPED
    assert _check(repo, path, swapped) == 1


def test_lowering_allowed_and_raising_refused(repo: Repo, tmp_path: Path) -> None:
    path = _baseline(repo, tmp_path, TWO_DEFECTS)
    one = "Remediation commit: `abcdef1`.\n"
    assert _check(repo, path, one) == 0
    assert _check(repo, path, one, "--update-baseline") == 0
    data = json.loads(path.read_text())
    assert data["baseline"] == 1 and data["history"][-1]["event"] == "update"
    assert _check(repo, path, TWO_DEFECTS) == 1
    assert _check(repo, path, TWO_DEFECTS, "--update-baseline") == 1
    assert json.loads(path.read_text())["baseline"] == 1


def test_detector_change_requires_recompute_with_reason(
    repo: Repo, tmp_path: Path
) -> None:
    path = tmp_path / "baseline.json"
    res = _scan(repo, TWO_DEFECTS)
    old = "0" * 64
    gate.write_baseline(
        path,
        res,
        detector_sha256=old,
        history=[gate.history_entry("initial_baseline", REASON, res, old, None)],
    )
    live = gate.compute_detector_fingerprint()
    state, err = gate.read_baseline(path)
    assert state is not None, err
    assert "drifted" in gate.compare_to_baseline(res, state, detector_sha256=live)[0]
    assert _check(repo, path, TWO_DEFECTS) == 1
    assert _check(repo, path, TWO_DEFECTS, "--update-baseline") == 1
    assert (
        _check(repo, path, TWO_DEFECTS, "--recompute-baseline", "--reason", "short")
        == 1
    )
    assert (
        _check(repo, path, TWO_DEFECTS, "--recompute-baseline", "--reason", REASON) == 0
    )
    data = json.loads(path.read_text())
    last = data["history"][-1]
    assert last["event"] == "recompute"
    assert (last["before_detector_sha256"], last["detector_sha256"]) == (old, live)
    assert (
        _check(repo, path, TWO_DEFECTS, "--recompute-baseline", "--reason", REASON) == 1
    )


def test_baseline_tampering_is_rejected(repo: Repo, tmp_path: Path) -> None:
    path = _baseline(repo, tmp_path, TWO_DEFECTS)
    data = json.loads(path.read_text())
    ident = next(iter(data["violations"]))
    data["violations"][ident]["context"] = "edited"
    path.write_text(json.dumps(data))
    assert "identity" in str(gate.read_baseline(path)[1])

    data = json.loads(_baseline(repo, tmp_path, TWO_DEFECTS, "b2.json").read_text())
    raised = dict(data["history"][0])
    raised.update(
        event="update",
        before_baseline=data["baseline"],
        before_class_counts=data["class_counts"],
        before_detector_sha256=data["detector_sha256"],
        after_baseline=data["baseline"] + 1,
        after_class_counts={**data["class_counts"], "dead_commit_claim": 2},
    )
    data["history"].append(raised)
    assert "monotonic" in str(gate._validate_history(data["history"]))


def test_fingerprint_stable_under_line_moves(repo: Repo) -> None:
    body = "Remediation commit: `abcdef1` was claimed.\n"
    first = {v.identity for v in _scan(repo, body).violations}
    moved = {v.identity for v in _scan(repo, "# Title\n\nIntro.\n\n" + body).violations}
    assert first == moved
    edited = {
        v.identity
        for v in _scan(repo, "Remediation commit: `abcdef1` was refuted.\n").violations
    }
    assert edited != first


def test_detector_fingerprint_ignores_comments_but_not_code(tmp_path: Path) -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    base = gate.compute_detector_fingerprint(SCRIPT)
    commented = tmp_path / "commented.py"
    commented.write_text(
        src.replace("PRIMARY_POAM: Final", "# note\nPRIMARY_POAM: Final", 1)
    )
    assert gate.compute_detector_fingerprint(commented) == base
    changed = tmp_path / "changed.py"
    changed.write_text(src.replace('"bucket",\n)', '"bucket",\n    "lease",\n)', 1))
    assert gate.compute_detector_fingerprint(changed) != base


# ---------------------------------------------------------------- mutations
# PSC-M1..PSC-M10: each mutant of the detector must be killed by its scenario.


def _load_mutant(tmp_path: Path, old: str, new: str) -> ModuleType:
    src = SCRIPT.read_text(encoding="utf-8")
    assert src.count(old) == 1, old
    path = tmp_path / "check_poam_sha_citations.py"
    path.write_text(src.replace(old, new), encoding="utf-8")
    name = f"_psc_mutant_{abs(hash(old))}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


Text = Callable[[Repo], str]


def _verdict_of(token: Text, text: Text) -> Callable[[Repo, ModuleType], object]:
    def run(repo: Repo, mod: ModuleType) -> object:
        res = _scan(repo, text(repo), mod)
        return [c.verdict for c in res.cites if c.token == token(repo)]

    return run


def _chron_of(text: Text) -> Callable[[Repo, ModuleType], object]:
    def run(repo: Repo, mod: ModuleType) -> object:
        return [r.verdict for r in _scan(repo, text(repo), mod).chronology]

    return run


def _swap_fails(repo: Repo, mod: ModuleType) -> object:
    base = _scan(repo, TWO_DEFECTS, mod)
    det = mod.compute_detector_fingerprint()
    state = mod.BaselineState(
        len(base.violations),
        det,
        base.class_counts(),
        {
            v.identity: {
                "class": v.cls,
                "subject": v.subject,
                "context": v.context,
                "count": 1,
            }
            for v in base.violations
        },
        [],
    )
    swapped = _scan(repo, SWAPPED, mod)
    return bool(mod.compare_to_baseline(swapped, state, detector_sha256=det))


MUTANTS: list[tuple[str, str, str, Callable[[Repo, ModuleType], object]]] = [
    (
        "PSC-M1 canonical universe widened to --all",
        '"rev-list", "--objects", self.main_oid',
        '"rev-list", "--objects", "--all"',
        _verdict_of(lambda r: _s(r.head), lambda r: f"Seen `{_s(r.head)}`.\n"),
    ),
    (
        "PSC-M2 paired form without PR number",
        '        if pr is None:\n            cite.verdict = "paired_missing_pr"',
        '        if pr is None and False:\n            cite.verdict = "paired_missing_pr"',
        _verdict_of(
            lambda r: _s(r.head),
            lambda r: f"Landed (`{_s(r.c1)}`, branch head `{_s(r.head)}`).\n",
        ),
    ),
    (
        "PSC-M3 paired main SHA need not be a main ancestor",
        '            and c.canon_type == "commit"\n            and c.label_family != "head"',
        '            and c.label_family != "head"',
        _verdict_of(
            lambda r: _s(r.head),
            lambda r: f"`#12` (`abcdef9`, branch head `{_s(r.head)}`).\n",
        ),
    ),
    (
        "PSC-M4 kind label not compared with object type",
        'if fam == "kind" and KIND_LABELS[val or ""] == cite.canon_type:',
        'if fam == "kind":',
        _verdict_of(lambda r: r.tree[:12], lambda r: f"tag `{r.tree[:12]}`.\n"),
    ),
    (
        "PSC-M5 id label accepted on a resolving object",
        'if fam in {"kind", "id", "absent"}:',
        'if fam in {"kind", "absent"}:',
        _verdict_of(lambda r: _s(r.c1), lambda r: f"run `{_s(r.c1)}`.\n"),
    ),
    (
        "PSC-M6 singular label distributes over a list",
        "if cite.label_family is None and prev.label_plural:",
        "if cite.label_family is None and prev.label_family:",
        _verdict_of(
            lambda r: "bc8e6f26", lambda r: "job `136987863741` and `bc8e6f26`.\n"
        ),
    ),
    (
        "PSC-M7 chronology dated by author date",
        "cday, aday = _utc_day(cts), _utc_day(ats)",
        "cday, aday = _utc_day(ats), _utc_day(ats)",
        _chron_of(lambda r: f"Closed `2026-01-03` (`{_s(r.c2)}`, `#12`).\n"),
    ),
    (
        "PSC-M8 new identity tolerated when totals do not rise",
        "if not isinstance(allowed, int) or n > allowed:",
        "if not isinstance(allowed, int):",
        _swap_fails,
    ),
    (
        "PSC-M9 depth-0 citation crosses commas",
        'self.masked[i] in ",;" or self.is_sentence_end(i)',
        'self.masked[i] in ";" or self.is_sentence_end(i)',
        _verdict_of(
            lambda r: _s(r.head),
            lambda r: (
                f"`{_s(r.c1)}` shares nothing, unlike #15's head `{_s(r.head)}`.\n"
            ),
        ),
    ),
    (
        "PSC-M10 clone-local objects count as resolved",
        "        c.canon_type, c.canon_oid = canon[c.token]",
        "        c.canon_type, c.canon_oid = canon[c.token]\n"
        '        if c.raw_type == "commit":\n'
        '            c.canon_type, c.canon_oid = "commit", c.raw_oid',
        _verdict_of(lambda r: _s(r.gone), lambda r: f"Seen `{_s(r.gone)}`.\n"),
    ),
]


@pytest.mark.parametrize(
    ("mid", "old", "new", "scenario"), MUTANTS, ids=[m[0].split()[0] for m in MUTANTS]
)
def test_mutant_is_killed(
    repo: Repo,
    tmp_path: Path,
    mid: str,
    old: str,
    new: str,
    scenario: Callable[[Repo, ModuleType], object],
) -> None:
    original = scenario(repo, gate)
    mutant = scenario(repo, _load_mutant(tmp_path, old, new))
    assert original != mutant, f"{mid} survived: {original!r}"
