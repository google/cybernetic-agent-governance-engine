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

"""Tests for scripts/review_bypass_attestation.py and its two workflows (POAM-2026-115).

The required check `Approved review or recorded bypass` passes on an approving
review, or on a verified signed record that the head was unreviewed; the
post-merge ledger records each unreviewed merge. A record is not a review.

These tests hold the decision rule, the subject and predicate formats a reader
recomputes from public data, the refusals, and the workflow properties that
make the check fail closed: nothing continues on error, nothing runs after a
failure, every action is pinned, and the last step passes only on an approval
or a verified record.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PREMERGE_WORKFLOW = WORKFLOWS / "review-bypass-attestation.yml"
LEDGER_WORKFLOW = WORKFLOWS / "review-bypass-ledger.yml"
WORKFLOW_FILES = (PREMERGE_WORKFLOW, LEDGER_WORKFLOW)
PROTECTION_DOC = REPO_ROOT / ".github" / "branch-protection-rules.md"


def _load(name: str, filename: str) -> Any:
    path = REPO_ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rba = _load("review_bypass_attestation", "review_bypass_attestation.py")
rules_mod = _load("check_repo_rules", "check_repo_rules.py")

REPO = "google/cybernetic-agent-governance-engine"
AUTHOR = "maintainer"
HEAD = "a" * 40
OLD_HEAD = "b" * 40
BASE = "c" * 40
MERGE = "d" * 40
BEFORE = "e" * 40
MERGED_AT = "2026-11-15T12:00:00Z"
NOW = datetime(2026, 11, 15, 20, 0, 0, tzinfo=timezone.utc)
PREMERGE_REF = (
    f"{REPO}/.github/workflows/review-bypass-attestation.yml@refs/pull/769/merge"
)
LEDGER_REF = f"{REPO}/.github/workflows/review-bypass-ledger.yml@refs/heads/main"

PREMERGE_STATEMENT = (
    "This record shows the pull request had no approving review when this check "
    "ran. It is not a review or an approval and makes no claim about the change."
)
LEDGER_STATEMENT = (
    "This record shows the pull request was merged without an approving review. "
    "It is not a review or an approval and makes no claim about the change."
)
RECORDED_BY = "the repository's own CI workflow; not an independent party"
# The printf template §10 of .github/branch-protection-rules.md gives readers.
PRINTF_SUBJECT = '{"head_sha":"%s","pr":%d,"repo":"%s"}'
UNREVIEWED_LEAD = (
    "UNREVIEWED: no approving review. "
    "This check records the bypass; it does not review the change."
)


def _review(
    review_id: int,
    login: str,
    state: str,
    *,
    commit: str = HEAD,
    at: str | None = "2026-11-15T10:00:00Z",
    user_type: str = "User",
) -> dict[str, Any]:
    return {
        "id": review_id,
        "user": {"login": login, "type": user_type},
        "state": state,
        "commit_id": commit,
        "submitted_at": at,
        "author_association": "COLLABORATOR",
    }


def _decide(
    items: list[dict[str, Any]],
    permissions: dict[str, str] | None = None,
    *,
    before: datetime | None = None,
) -> Any:
    reviews = rba.parse_reviews(json.dumps(items))
    if permissions is None:
        permissions = {
            item["user"]["login"]: "write" for item in items if item.get("user")
        }
    return rba.decide(
        reviews, author=AUTHOR, head_sha=HEAD, permissions=permissions, before=before
    )


# --------------------------------------------------------------------------
# decide()
# --------------------------------------------------------------------------


def test_an_approval_of_the_head_by_a_writer_is_approved() -> None:
    decision = _decide([_review(1, "reviewer", "APPROVED")])
    assert decision == rba.Decision(rba.APPROVED, ("reviewer",))


def test_an_approval_then_dismissed_is_unreviewed() -> None:
    # The API reports a dismissed approval with the state DISMISSED.
    assert _decide([_review(1, "reviewer", "DISMISSED")]).outcome == rba.UNREVIEWED
    # A dismissal recorded as a later review leaves no approval either.
    later = [
        _review(1, "reviewer", "APPROVED", at="2026-11-15T10:00:00Z"),
        _review(2, "reviewer", "DISMISSED", at="2026-11-15T11:00:00Z"),
    ]
    assert _decide(later).outcome == rba.UNREVIEWED


@pytest.mark.parametrize("login", [AUTHOR, AUTHOR.upper()])
def test_the_authors_own_review_is_ignored(login: str) -> None:
    # GitHub refuses a self-approval; a payload claiming one must not count.
    assert _decide([_review(1, login, "APPROVED")]).outcome == rba.UNREVIEWED


def test_changes_requested_only_is_unreviewed() -> None:
    items = [_review(1, "reviewer", "CHANGES_REQUESTED")]
    assert _decide(items).outcome == rba.UNREVIEWED


def test_no_reviews_is_unreviewed() -> None:
    assert _decide([]) == rba.Decision(rba.UNREVIEWED, ())


def test_each_reviewers_latest_decisive_review_is_what_counts() -> None:
    items = [
        # The first reviewer approves, then requests changes.
        _review(1, "first", "APPROVED", at="2026-11-15T09:00:00Z"),
        _review(2, "first", "CHANGES_REQUESTED", at="2026-11-15T10:00:00Z"),
        # The second requests changes, then approves.
        _review(3, "second", "CHANGES_REQUESTED", at="2026-11-15T09:30:00Z"),
        _review(4, "second", "APPROVED", at="2026-11-15T10:30:00Z"),
    ]
    assert _decide(items) == rba.Decision(rba.APPROVED, ("second",))
    assert _decide(items[:3]).outcome == rba.UNREVIEWED


def test_reviews_are_ordered_by_submission_time_not_by_list_position() -> None:
    items = [
        _review(2, "reviewer", "CHANGES_REQUESTED", at="2026-11-15T11:00:00Z"),
        _review(1, "reviewer", "APPROVED", at="2026-11-15T10:00:00Z"),
    ]
    assert _decide(items).outcome == rba.UNREVIEWED


def test_a_comment_after_an_approval_leaves_the_approval_in_force() -> None:
    items = [
        _review(1, "reviewer", "APPROVED", at="2026-11-15T10:00:00Z"),
        _review(2, "reviewer", "COMMENTED", at="2026-11-15T11:00:00Z"),
    ]
    assert _decide(items).outcome == rba.APPROVED


def test_an_approval_of_an_earlier_commit_does_not_cover_the_head() -> None:
    items = [_review(1, "reviewer", "APPROVED", commit=OLD_HEAD)]
    assert _decide(items).outcome == rba.UNREVIEWED


@pytest.mark.parametrize("permission", ["read", "triage", "none"])
def test_an_approval_without_write_access_does_not_count(permission: str) -> None:
    items = [_review(1, "reviewer", "APPROVED")]
    assert _decide(items, {"reviewer": permission}).outcome == rba.UNREVIEWED


@pytest.mark.parametrize("permission", ["admin", "maintain", "write"])
def test_an_approval_with_write_access_counts(permission: str) -> None:
    items = [_review(1, "reviewer", "APPROVED")]
    assert _decide(items, {"reviewer": permission}).outcome == rba.APPROVED


def test_a_bot_approval_does_not_count() -> None:
    items = [
        _review(1, "helper[bot]", "APPROVED", user_type="Bot"),
        _review(2, "Copilot", "APPROVED", user_type="Bot"),
    ]
    assert _decide(items, {}).outcome == rba.UNREVIEWED


def test_pending_reviews_and_deleted_accounts_are_ignored() -> None:
    pending = _review(1, "reviewer", "PENDING", at=None)
    deleted = _review(2, "ghost", "APPROVED") | {"user": None}
    assert _decide([pending, deleted], {}).outcome == rba.UNREVIEWED


def test_a_candidate_whose_permission_was_not_looked_up_is_an_error() -> None:
    with pytest.raises(rba.InputError, match="no repository permission"):
        _decide([_review(1, "reviewer", "APPROVED")], {})


def test_the_ledger_ignores_approvals_submitted_after_the_merge() -> None:
    merged_at = rba.require_timestamp(MERGED_AT, "merged_at")
    late = _review(1, "late", "APPROVED", at="2026-11-15T12:00:01Z")
    on_time = _review(2, "prompt", "APPROVED", at=MERGED_AT)
    assert _decide([late], before=merged_at).outcome == rba.UNREVIEWED
    assert _decide([late, on_time], before=merged_at) == rba.Decision(
        rba.APPROVED, ("prompt",)
    )


def test_candidates_are_the_approvers_whose_permission_must_be_looked_up() -> None:
    items = [
        _review(1, "beta", "APPROVED"),
        _review(2, "Alpha", "APPROVED"),
        _review(3, AUTHOR, "APPROVED"),
        _review(4, "stale", "APPROVED", commit=OLD_HEAD),
        _review(5, "objector", "CHANGES_REQUESTED"),
        _review(6, "helper[bot]", "APPROVED", user_type="Bot"),
    ]
    reviews = rba.parse_reviews(json.dumps(items))
    assert rba.approval_candidates(reviews, author=AUTHOR, head_sha=HEAD) == [
        "Alpha",
        "beta",
    ]


# --------------------------------------------------------------------------
# Parsing what gh api returns
# --------------------------------------------------------------------------


def test_pages_written_back_to_back_are_read_as_one_list() -> None:
    first = json.dumps([_review(1, "first", "COMMENTED")])
    second = json.dumps([_review(2, "second", "APPROVED")])
    reviews = rba.parse_reviews(first + "\n" + second)
    assert [review.review_id for review in reviews] == [1, 2]


@pytest.mark.parametrize(
    "text",
    [
        "",
        '{"message": "Not Found"}',
        "[1]",
        json.dumps([[_review(1, "reviewer", "APPROVED")]]),
        json.dumps([_review(1, "reviewer", "SURPRISE")]),
        json.dumps([_review(1, "a", "APPROVED"), _review(1, "b", "APPROVED")]),
        json.dumps([_review(1, "reviewer", "APPROVED", at=None)]),
        json.dumps([_review(1, "reviewer", "APPROVED", commit="A" * 40)]),
        json.dumps([_review(1, "two words", "APPROVED")]),
        json.dumps([_review(1, "reviewer", "APPROVED", at="2026-11-15 10:00:00")]),
        json.dumps([_review(1, "reviewer", "APPROVED") | {"id": True}]),
    ],
    ids=[
        "empty",
        "error body",
        "not objects",
        "slurped pages",
        "unknown state",
        "repeated id",
        "approval without a time",
        "uppercase commit",
        "bad login",
        "bad time",
        "boolean id",
    ],
)
def test_unexpected_review_payloads_are_refused(text: str) -> None:
    with pytest.raises(ValueError):
        rba.parse_reviews(text)


def test_permission_lines_are_parsed() -> None:
    assert rba.parse_permissions("") == {}
    assert rba.parse_permissions("alpha\twrite\nbeta\tread\n") == {
        "alpha": "write",
        "beta": "read",
    }


@pytest.mark.parametrize(
    "text",
    [
        "alpha write\n",
        "alpha\tsuperuser\n",
        "alpha\twrite\nALPHA\tread\n",
        "a b\twrite\n",
        "\n",
    ],
    ids=["no tab", "unknown permission", "repeated login", "bad login", "blank line"],
)
def test_bad_permission_lines_are_refused(text: str) -> None:
    with pytest.raises(rba.InputError):
        rba.parse_permissions(text)


# --------------------------------------------------------------------------
# subject()
# --------------------------------------------------------------------------


def test_the_subject_is_canonical_json_of_exactly_repo_pr_and_head() -> None:
    data = rba.subject(REPO, 769, HEAD)
    assert (
        data == ('{"head_sha":"' + HEAD + '","pr":769,"repo":"' + REPO + '"}').encode()
    )
    assert json.loads(data) == {"repo": REPO, "pr": 769, "head_sha": HEAD}


def test_the_subject_and_its_digest_are_stable() -> None:
    assert rba.subject(REPO, 769, HEAD) == rba.subject(REPO, "769", HEAD)
    # A fixed subject's digest is pinned, so any change to the canonical form
    # (and to every digest a reader recomputes) fails here.
    head = "0123456789abcdef0123456789abcdef01234567"
    assert rba.sha256_hex(rba.subject(REPO, 769, head)) == (
        "458b2d2fcb35d5181dca67aac3d3414ecdf5f0670e6c64f1868ef82cc0699829"
    )


def test_anyone_can_recompute_the_digest_from_public_data() -> None:
    public = PRINTF_SUBJECT % (HEAD, 769, REPO)
    expected = hashlib.sha256(public.encode("ascii")).hexdigest()
    assert rba.sha256_hex(rba.subject(REPO, "769", HEAD)) == expected


def test_the_ledger_subject_is_canonical_json_of_exactly_repo_and_merge_sha() -> None:
    data = rba.ledger_subject(REPO, MERGE)
    assert data == ('{"merge_sha":"' + MERGE + '","repo":"' + REPO + '"}').encode()


def _documented_printf_templates() -> list[str]:
    text = PROTECTION_DOC.read_text(encoding="utf-8")
    return re.findall(r"printf '(\{[^']*\})'", text)


def test_the_documented_commands_rebuild_both_subjects() -> None:
    """§10's printf templates must produce the bytes the workflows sign."""
    templates = _documented_printf_templates()
    premerge = [t for t in templates if '"head_sha"' in t]
    ledger = [t for t in templates if '"merge_sha"' in t]
    assert premerge and ledger, templates
    for template in premerge:
        assert (template % (HEAD, 769, REPO)).encode() == rba.subject(REPO, 769, HEAD)
    for template in ledger:
        assert (template % (MERGE, REPO)).encode() == rba.ledger_subject(REPO, MERGE)


@pytest.mark.parametrize(
    "sha", ["A" * 40, "a" * 39, "a" * 41, "g" * 40, "", None, 123, " " + "a" * 39]
)
def test_bad_head_shas_are_refused(sha: object) -> None:
    with pytest.raises(rba.InputError):
        rba.subject(REPO, 1, sha)


@pytest.mark.parametrize(
    "pr", [0, -1, "0", "-1", "01", "1.5", "abc", "", True, None, 1.0, "12345678901"]
)
def test_bad_pull_request_numbers_are_refused(pr: object) -> None:
    with pytest.raises(rba.InputError):
        rba.subject(REPO, pr, HEAD)


@pytest.mark.parametrize(
    "repo",
    [
        "owner",
        "owner/",
        "/name",
        "own er/name",
        "owner/name/extra",
        "owner/..",
        "owner/.",
        "https://github.com/owner/name",
        "-owner/name",
        "",
        None,
    ],
)
def test_bad_repositories_are_refused(repo: object) -> None:
    with pytest.raises(rba.InputError):
        rba.subject(repo, 1, HEAD)


# --------------------------------------------------------------------------
# predicate()
# --------------------------------------------------------------------------

PREDICATE_FIELDS = {
    "repo",
    "pr",
    "head_sha",
    "base_ref",
    "base_sha",
    "author",
    "reason",
    "reviewed",
    "approving_reviews",
    "recorded_by",
    "statement",
    "evaluated_at",
    "event",
    "run_id",
    "run_attempt",
    "workflow_ref",
}


def _predicate(**overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "repo": REPO,
        "pr": "769",
        "head_sha": HEAD,
        "head_repo": REPO,
        "base_ref": "main",
        "base_sha": BASE,
        "author": AUTHOR,
        "decision": rba.Decision(rba.UNREVIEWED, ()),
        "event": "pull_request",
        "run_id": "123456",
        "run_attempt": "2",
        "workflow_ref": PREMERGE_REF,
        "evaluated_at": NOW,
    }
    arguments.update(overrides)
    return rba.predicate(**arguments)


def test_the_predicate_records_the_pull_request_the_run_and_the_decision() -> None:
    assert _predicate() == {
        "repo": REPO,
        "pr": 769,
        "head_sha": HEAD,
        "base_ref": "main",
        "base_sha": BASE,
        "author": AUTHOR,
        "reason": "no_approving_review",
        "reviewed": False,
        "approving_reviews": 0,
        "recorded_by": RECORDED_BY,
        "statement": PREMERGE_STATEMENT,
        "evaluated_at": "2026-11-15T20:00:00Z",
        "event": "pull_request",
        "run_id": 123456,
        "run_attempt": 2,
        "workflow_ref": PREMERGE_REF,
    }
    assert set(_predicate()) == PREDICATE_FIELDS


def test_the_predicate_says_plainly_that_it_is_not_a_review() -> None:
    value = _predicate(event="pull_request_review")
    assert value["reviewed"] is False
    assert value["approving_reviews"] == 0
    assert value["statement"] == PREMERGE_STATEMENT
    assert value["recorded_by"] == RECORDED_BY


def test_only_the_ledger_statement_claims_a_merge() -> None:
    # The pre-merge record is written before any merge, and for heads that may
    # never merge, so it must not say the pull request was merged.
    assert "merged" not in PREMERGE_STATEMENT
    assert "merged" in LEDGER_STATEMENT
    assert _predicate()["statement"] != _ledger()["statement"]
    for statement in (PREMERGE_STATEMENT, LEDGER_STATEMENT):
        assert statement.endswith(
            "It is not a review or an approval and makes no claim about the change."
        )
    assert "maintainer" not in RECORDED_BY


def test_the_predicate_refuses_an_approved_head() -> None:
    approved = rba.Decision(rba.APPROVED, ("reviewer",))
    with pytest.raises(rba.InputError, match="no bypass to record"):
        _predicate(decision=approved)


@pytest.mark.parametrize(
    "head_repo", ["someone/cybernetic-agent-governance-engine", "", None]
)
def test_the_predicate_refuses_a_forks_head(head_repo: object) -> None:
    with pytest.raises(rba.InputError, match="fork"):
        _predicate(head_repo=head_repo)


@pytest.mark.parametrize(
    "overrides",
    [
        {"event": "push"},
        {"event": "pull_request_target"},
        {"workflow_ref": f"{REPO}/.github/workflows/ci.yml@refs/pull/769/merge"},
        {
            "workflow_ref": "other/repo/.github/workflows/review-bypass-attestation.yml@refs/pull/1/merge"
        },
        {"workflow_ref": f"{REPO}/.github/workflows/review-bypass-attestation.yml@"},
        {"run_id": "0"},
        {"run_attempt": "first"},
        {"base_ref": "main..evil"},
        {"base_sha": "main"},
        {"author": "two words"},
        {"evaluated_at": datetime(2026, 11, 15, 20, 0, 0)},
    ],
    ids=lambda overrides: next(iter(overrides)),
)
def test_the_predicate_refuses_unexpected_run_and_pull_request_values(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(rba.InputError):
        _predicate(**overrides)


# --------------------------------------------------------------------------
# The ledger
# --------------------------------------------------------------------------


def _pull(**overrides: Any) -> dict[str, Any]:
    pull: dict[str, Any] = {
        "number": 769,
        "merged": True,
        "merged_at": MERGED_AT,
        "merge_commit_sha": MERGE,
        "base": {"ref": "main", "repo": {"full_name": REPO}},
        "head": {"sha": HEAD, "repo": {"full_name": REPO}},
        "user": {"login": AUTHOR},
        "merged_by": {"login": AUTHOR},
    }
    pull.update(overrides)
    return pull


def _commit(*parents: str, sha: str = MERGE) -> dict[str, Any]:
    return {"sha": sha, "parents": [{"sha": parent} for parent in parents or (BEFORE,)]}


def test_merged_pr_finds_the_one_pull_request_merged_as_the_commit() -> None:
    pulls = [
        _pull(number=12, merge_commit_sha="f" * 40),
        _pull(number=13, merged=False, merged_at=None),
        _pull(),
        _pull(number=14, base={"ref": "dev", "repo": {"full_name": REPO}}),
    ]
    assert rba.merged_pull_request(json.dumps(pulls), repo=REPO, merge_sha=MERGE) == 769


@pytest.mark.parametrize(
    "pulls",
    [
        [],
        [_pull(merged_at=None)],
        [_pull(base={"ref": "dev", "repo": {"full_name": REPO}})],
        [_pull(base={"ref": "main", "repo": {"full_name": "someone/fork"}})],
        [_pull(), _pull(number=770)],
    ],
    ids=["none", "not merged", "other branch", "other repository", "two"],
)
def test_merged_pr_refuses_anything_but_exactly_one(
    pulls: list[dict[str, Any]],
) -> None:
    with pytest.raises(rba.InputError, match="exactly one"):
        rba.merged_pull_request(json.dumps(pulls), repo=REPO, merge_sha=MERGE)


def _facts(
    pull: dict[str, Any] | None = None, commit: dict[str, Any] | None = None
) -> Any:
    return rba.merge_facts(
        json.dumps(pull or _pull()),
        json.dumps(commit or _commit()),
        repo=REPO,
        merge_sha=MERGE,
        before_sha=BEFORE,
    )


def test_merge_facts_are_read_from_the_pull_request() -> None:
    facts = _facts(_pull(merged_by={"login": "merger"}))
    assert (facts.pr, facts.head_sha, facts.author, facts.merged_by) == (
        769,
        HEAD,
        AUTHOR,
        "merger",
    )
    assert rba.format_timestamp(facts.merged_at) == MERGED_AT


@pytest.mark.parametrize(
    ("pull", "commit"),
    [
        (_pull(merged=False), None),
        (_pull(merge_commit_sha="f" * 40), None),
        (_pull(base={"ref": "dev", "repo": {"full_name": REPO}}), None),
        (_pull(merged_by=None), None),
        (_pull(head={"sha": "short"}), None),
        (None, _commit(BEFORE, "f" * 40)),
        (None, _commit("f" * 40)),
        (None, _commit(sha="f" * 40)),
    ],
    ids=[
        "not merged",
        "other merge commit",
        "other branch",
        "no merger",
        "bad head",
        "merge commit",
        "more than one new commit",
        "other commit",
    ],
)
def test_merge_facts_refuse_anything_but_one_squash_merge(
    pull: dict[str, Any] | None, commit: dict[str, Any] | None
) -> None:
    with pytest.raises(rba.InputError):
        _facts(pull, commit)


LEDGER_FIELDS = {
    "repo",
    "merge_sha",
    "pr",
    "head_sha",
    "author",
    "merged_by",
    "merged_at",
    "premerge_subject_digest",
    "premerge_predicate_type",
    "reason",
    "reviewed",
    "approving_reviews",
    "recorded_by",
    "statement",
    "recorded_at",
    "event",
    "run_id",
    "run_attempt",
    "workflow_ref",
}


def _ledger(decision: Any = None, **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "decision": decision or rba.Decision(rba.UNREVIEWED, ()),
        "event": "push",
        "run_id": "99",
        "run_attempt": "1",
        "workflow_ref": LEDGER_REF,
        "recorded_at": NOW,
    }
    arguments.update(overrides)
    return rba.ledger_predicate(_facts(), **arguments)


def test_the_ledger_predicate_records_the_merge_and_the_premerge_digest() -> None:
    value = _ledger()
    assert set(value) == LEDGER_FIELDS
    premerge = PRINTF_SUBJECT % (HEAD, 769, REPO)
    assert value["premerge_subject_digest"] == (
        "sha256:" + hashlib.sha256(premerge.encode("ascii")).hexdigest()
    )
    assert value["premerge_predicate_type"] == rba.PREDICATE_TYPE
    assert (value["merge_sha"], value["pr"], value["head_sha"]) == (MERGE, 769, HEAD)
    assert (value["merged_by"], value["merged_at"]) == (AUTHOR, MERGED_AT)
    assert (value["recorded_at"], value["event"]) == ("2026-11-15T20:00:00Z", "push")


def test_the_ledger_predicate_says_plainly_that_it_is_not_a_review() -> None:
    value = _ledger()
    assert value["reviewed"] is False
    assert value["approving_reviews"] == 0
    assert value["statement"] == LEDGER_STATEMENT
    assert value["recorded_by"] == RECORDED_BY


def test_the_ledger_predicate_refuses_an_approved_merge_and_other_workflows() -> None:
    with pytest.raises(rba.InputError, match="no bypass to record"):
        _ledger(rba.Decision(rba.APPROVED, ("reviewer",)))
    with pytest.raises(rba.InputError):
        _ledger(workflow_ref=PREMERGE_REF)
    with pytest.raises(rba.InputError):
        _ledger(event="pull_request")


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: Any) -> str:
    path = tmp_path / name
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return str(path)


def _argv(command: str, **options: str) -> list[str]:
    argv = [command]
    for key, value in options.items():
        argv += [f"--{key.replace('_', '-')}", value]
    return argv


def test_cli_refuses_bad_input_with_exit_status_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert rba.main(_argv("subject", repo=REPO, pr="0", head_sha=HEAD)) == 1
    assert "positive integer" in capsys.readouterr().err


def test_cli_subject_writes_the_bytes_and_prints_their_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "subject.json"
    argv = _argv("subject", repo=REPO, pr="769", head_sha=HEAD, output=str(output))
    assert rba.main(argv) == 0
    assert output.read_bytes() == rba.subject(REPO, 769, HEAD)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    assert capsys.readouterr().out == digest + "\n"


def test_cli_decide_prints_only_the_outcome(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reviews = _write(tmp_path, "reviews.json", [_review(1, "reviewer", "APPROVED")])
    for permission, outcome in (("write", "APPROVED"), ("read", "UNREVIEWED")):
        permissions = _write(tmp_path, f"{permission}.tsv", f"reviewer\t{permission}\n")
        argv = _argv(
            "decide",
            reviews=reviews,
            permissions=permissions,
            author=AUTHOR,
            head_sha=HEAD,
        )
        assert rba.main(argv) == 0
        assert capsys.readouterr().out == outcome + "\n"


def test_cli_predicate_recomputes_the_decision(tmp_path: Path) -> None:
    output = tmp_path / "predicate.json"
    options = {
        "repo": REPO,
        "pr": "769",
        "head_sha": HEAD,
        "head_repo": REPO,
        "base_ref": "main",
        "base_sha": BASE,
        "author": AUTHOR,
        "permissions": _write(tmp_path, "permissions.tsv", "reviewer\twrite\n"),
        "event": "pull_request",
        "run_id": "1",
        "run_attempt": "1",
        "workflow_ref": PREMERGE_REF,
        "output": str(output),
    }
    approved = _write(tmp_path, "approved.json", [_review(1, "reviewer", "APPROVED")])
    assert rba.main(_argv("predicate", reviews=approved, **options)) == 1
    assert not output.exists()
    unreviewed = _write(tmp_path, "none.json", [])
    assert rba.main(_argv("predicate", reviews=unreviewed, **options)) == 0
    value = json.loads(output.read_text())
    assert value["reviewed"] is False
    assert (value["statement"], value["pr"]) == (PREMERGE_STATEMENT, 769)


def test_cli_merge_facts_prints_github_output_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _argv(
        "merge-facts",
        repo=REPO,
        merge_sha=MERGE,
        before_sha=BEFORE,
        pull=_write(tmp_path, "pull.json", _pull(merged_by={"login": "merger"})),
        commit=_write(tmp_path, "commit.json", _commit()),
    )
    assert rba.main(argv) == 0
    assert capsys.readouterr().out == (
        f"pr=769\nhead_sha={HEAD}\nauthor={AUTHOR}\n"
        f"merged_by=merger\nmerged_at={MERGED_AT}\n"
    )


def test_cli_ledger_predicate_recomputes_the_decision(tmp_path: Path) -> None:
    output = tmp_path / "ledger.json"
    options = {
        "repo": REPO,
        "merge_sha": MERGE,
        "before_sha": BEFORE,
        "pull": _write(tmp_path, "pull.json", _pull()),
        "commit": _write(tmp_path, "commit.json", _commit()),
        "permissions": _write(tmp_path, "permissions.tsv", "reviewer\twrite\n"),
        "event": "push",
        "run_id": "1",
        "run_attempt": "1",
        "workflow_ref": LEDGER_REF,
        "output": str(output),
    }
    approved = _write(tmp_path, "approved.json", [_review(1, "reviewer", "APPROVED")])
    assert rba.main(_argv("ledger-predicate", reviews=approved, **options)) == 1
    assert not output.exists()
    # An approval submitted after the merge does not cover it.
    late = [_review(1, "reviewer", "APPROVED", at="2026-11-15T12:30:00Z")]
    after_merge = _write(tmp_path, "late.json", late)
    assert rba.main(_argv("ledger-predicate", reviews=after_merge, **options)) == 0
    assert json.loads(output.read_text())["reviewed"] is False


# --------------------------------------------------------------------------
# The workflows
# --------------------------------------------------------------------------


def _workflow(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), path.name
    return document


def _on(document: dict[str, Any]) -> Any:
    # PyYAML (YAML 1.1) reads a bare `on:` key as True.
    return document["on"] if "on" in document else document.get(True)


def _jobs(path: Path) -> dict[str, dict[str, Any]]:
    jobs = _workflow(path)["jobs"]
    assert isinstance(jobs, dict) and jobs, path.name
    return jobs


def _only_job(path: Path) -> dict[str, Any]:
    jobs = _jobs(path)
    assert len(jobs) == 1, f"{path.name} must hold exactly one job"
    return next(iter(jobs.values()))


def _steps(path: Path) -> list[dict[str, Any]]:
    return list(_only_job(path)["steps"])


def _step(path: Path, step_id: str) -> tuple[int, dict[str, Any]]:
    for index, step in enumerate(_steps(path)):
        if step.get("id") == step_id:
            return index, step
    raise AssertionError(f"{path.name} has no step with id {step_id!r}")


def test_the_job_name_is_the_pinned_required_check() -> None:
    job = _only_job(PREMERGE_WORKFLOW)
    assert rules_mod.REVIEW_BYPASS_CHECK == "Approved review or recorded bypass"
    assert job["name"] == rules_mod.REVIEW_BYPASS_CHECK
    assert (
        rules_mod.EXPECTED_REQUIRED_CHECKS[rules_mod.REVIEW_BYPASS_CHECK]
        == rules_mod.GITHUB_ACTIONS_APP_ID
    )


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_no_job_is_skipped_by_a_condition(path: Path) -> None:
    # GitHub reports a job skipped by its `if:` as a success, which satisfies
    # a required check without evaluating anything.
    for job_id, job in _jobs(path).items():
        assert "if" not in job, f"{path.name}: job {job_id} has an `if:`"


def test_no_other_workflow_reports_the_required_check_name() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path == PREMERGE_WORKFLOW:
            continue
        for job_id, job in (_workflow(path).get("jobs") or {}).items():
            name = str((job or {}).get("name", job_id))
            assert name != rules_mod.REVIEW_BYPASS_CHECK, path.name


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_nothing_continues_on_error(path: Path) -> None:
    for job_id, job in _jobs(path).items():
        assert "continue-on-error" not in job, f"{path.name}: job {job_id}"
        for step in job["steps"]:
            assert "continue-on-error" not in step, f"{path.name}: {step.get('name')}"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_no_step_runs_after_a_failure(path: Path) -> None:
    status = re.compile(r"\b(?:always|failure|cancelled)\s*\(")
    for job in _jobs(path).values():
        for condition in [job.get("if")] + [step.get("if") for step in job["steps"]]:
            if condition is not None:
                assert not status.search(str(condition)), (
                    f"{path.name}: if: {condition}"
                )


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_full_commit_sha(path: Path) -> None:
    pinned = re.compile(
        r"^\s*(?:- )?uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(?:\.\d+)*$"
    )
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\s*(?:- )?uses:", line)
    ]
    assert lines, path.name
    for line in lines:
        assert pinned.match(line), f"{path.name}: {line.strip()}"
    for step in _steps(path):
        if "uses" in step:
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), step


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_shell_steps_stop_at_the_first_error(path: Path) -> None:
    for step in _steps(path):
        if "run" not in step:
            continue
        script = step["run"]
        assert script.startswith("set -euo pipefail\n"), step["name"]
        assert not re.search(r"\|\|\s*(?:true\b|:(?=\s|$))", script), step["name"]
        # Expressions reach the shell through env, never by interpolation.
        assert "${{" not in script, step["name"]


EXPECTED_PERMISSIONS = {
    "contents": "read",
    "pull-requests": "read",
    "id-token": "write",
    "attestations": "write",
}


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_permissions_are_exactly_what_the_job_needs(path: Path) -> None:
    assert _workflow(path)["permissions"] == {}
    assert _only_job(path)["permissions"] == EXPECTED_PERMISSIONS


def test_the_triggers() -> None:
    on = _on(_workflow(PREMERGE_WORKFLOW))
    assert set(on) == {"pull_request", "pull_request_review"}
    assert set(on["pull_request"]["types"]) == {
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    }
    assert set(on["pull_request_review"]["types"]) == {
        "submitted",
        "dismissed",
        "edited",
    }
    for trigger in on.values():
        # A stacked pull request needs the check before it targets main
        # (POAM-2026-153).
        assert not {"branches", "branches-ignore", "paths", "paths-ignore"} & set(
            trigger
        )
    assert _on(_workflow(LEDGER_WORKFLOW)) == {"push": {"branches": ["main"]}}
    assert "concurrency" not in _workflow(LEDGER_WORKFLOW)


UNREVIEWED_ONLY = "steps.decide.outputs.decision == 'UNREVIEWED'"


def _assert_signs_then_verifies(
    path: Path,
    *,
    attest_id: str,
    verify_id: str,
    predicate_type: str,
    signer: str,
    subject_name: str,
) -> int:
    attest_index, attest = _step(path, attest_id)
    verify_index, verify = _step(path, verify_id)
    assert attest["uses"].startswith("actions/attest@")
    assert attest["if"] == verify["if"] == UNREVIEWED_ONLY
    inputs = attest["with"]
    assert inputs["predicate-type"] == predicate_type
    assert inputs["subject-name"].startswith(subject_name)
    assert inputs["subject-digest"] == "sha256:${{ steps.subject.outputs.digest }}"
    assert verify["env"]["PREDICATE_TYPE"] == predicate_type
    script = verify["run"]
    assert "gh attestation verify" in script
    assert '--predicate-type "${PREDICATE_TYPE}"' in script
    assert f'--signer-workflow "${{GITHUB_REPOSITORY}}/{signer}"' in script
    assert "--source-ref" in script
    assert 'echo "verified=true" >> "${GITHUB_OUTPUT}"' in script
    assert attest_index < verify_index
    return verify_index


def _assert_last_step_needs_positive_evidence(path: Path, verified: list[str]) -> str:
    steps = _steps(path)
    last = steps[-1]
    assert "if" not in last, "the last step must run whenever nothing failed"
    assert last["env"]["DECISION"] == "${{ steps.decide.outputs.decision }}"
    for name in verified:
        assert name in last["env"]
        assert f'[ "${{{name}}}" != "true" ]' in last["run"]
    script = last["run"]
    assert "APPROVED)" in script and "UNREVIEWED)" in script
    assert re.search(r"\*\)\s*\n\s*echo \"::error[^\n]*\n\s*exit 1", script)
    return script


def test_the_premerge_check_passes_only_on_an_approval_or_a_verified_record() -> None:
    path = PREMERGE_WORKFLOW
    decide_index, _ = _step(path, "decide")
    subject_index, subject_step = _step(path, "subject")
    assert subject_step["if"] == UNREVIEWED_ONLY
    verify_index = _assert_signs_then_verifies(
        path,
        attest_id="attest",
        verify_id="verify",
        predicate_type=rba.PREDICATE_TYPE,
        signer=rba.ATTESTATION_WORKFLOW,
        subject_name="review-bypass/pr-",
    )
    assert decide_index < subject_index < verify_index < len(_steps(path)) - 1
    script = _assert_last_step_needs_positive_evidence(path, ["VERIFIED"])
    # The fork refusal comes before anything is signed.
    fork_index = next(
        index
        for index, step in enumerate(_steps(path))
        if "HEAD_REPO" in step.get("env", {}) and step.get("id") is None
    )
    assert decide_index < fork_index < subject_index
    assert '"${HEAD_REPO}" != "${GITHUB_REPOSITORY}"' in _steps(path)[fork_index]["run"]
    assert "exit 1" in _steps(path)[fork_index]["run"]
    assert "ATTESTATION_URL" in script


def test_the_ledger_verifies_the_premerge_record_then_records_the_merge() -> None:
    path = LEDGER_WORKFLOW
    premerge_index, premerge = _step(path, "premerge")
    assert premerge["if"] == UNREVIEWED_ONLY
    assert premerge["env"]["PREDICATE_TYPE"] == rba.PREDICATE_TYPE
    assert "gh attestation verify" in premerge["run"]
    assert (
        f'--signer-workflow "${{GITHUB_REPOSITORY}}/{rba.ATTESTATION_WORKFLOW}"'
        in (premerge["run"])
    )
    assert '--source-ref "refs/pull/${PR}/merge"' in premerge["run"]
    subject_index, _ = _step(path, "subject")
    verify_index = _assert_signs_then_verifies(
        path,
        attest_id="attest",
        verify_id="verify",
        predicate_type=rba.LEDGER_PREDICATE_TYPE,
        signer=rba.LEDGER_WORKFLOW,
        subject_name="review-bypass-ledger/",
    )
    assert premerge_index < subject_index < verify_index < len(_steps(path)) - 1
    _assert_last_step_needs_positive_evidence(path, ["PREMERGE_VERIFIED", "VERIFIED"])


def test_the_unreviewed_summary_leads_with_the_disclosure() -> None:
    script = _steps(PREMERGE_WORKFLOW)[-1]["run"]
    unreviewed = script.split("UNREVIEWED)", 1)[1]
    first_heading = re.search(r'echo "(### [^"]*)"', unreviewed)
    assert first_heading is not None
    assert first_heading.group(1) == f"### {UNREVIEWED_LEAD}"


def test_the_summary_shows_the_canonical_subject() -> None:
    script = _steps(PREMERGE_WORKFLOW)[-1]["run"]
    line = next(line for line in script.splitlines() if "- Subject:" in line)
    template = line.split("\\`")[1].replace('\\"', '"')
    shown = (
        template.replace("${HEAD_SHA}", HEAD)
        .replace("${PR}", "769")
        .replace("${GITHUB_REPOSITORY}", REPO)
    )
    assert shown.encode() == rba.subject(REPO, 769, HEAD)


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_no_name_or_summary_heading_calls_a_bypass_attested(path: Path) -> None:
    for job in _jobs(path).values():
        names = [job.get("name", "")] + [step.get("name", "") for step in job["steps"]]
        headings = [
            heading
            for step in job["steps"]
            for heading in re.findall(r'echo "(###[^"]*)"', step.get("run", ""))
        ]
        for text in names + headings:
            assert "attested" not in text.lower(), f"{path.name}: {text}"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_the_workflows_run_the_script_this_file_tests(path: Path) -> None:
    for step in _steps(path):
        for match in re.findall(r"python3 (\S+)", step.get("run", "")):
            assert match == "scripts/review_bypass_attestation.py"
            assert (REPO_ROOT / match).is_file()
    assert (REPO_ROOT / rba.ATTESTATION_WORKFLOW) == PREMERGE_WORKFLOW
    assert (REPO_ROOT / rba.LEDGER_WORKFLOW) == LEDGER_WORKFLOW


def test_the_recorded_ruleset_requires_the_check() -> None:
    fixture = (
        REPO_ROOT / "tests" / "fixtures" / "repo_rules" / "rules_branches_main.json"
    )
    rules = json.loads(fixture.read_text(encoding="utf-8"))
    rule = next(rule for rule in rules if rule["type"] == "required_status_checks")
    contexts = [
        check["context"] for check in rule["parameters"]["required_status_checks"]
    ]
    assert rules_mod.REVIEW_BYPASS_CHECK in contexts
