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

"""scripts/review_bypass_attestation.py

Decide whether a pull request's head was independently reviewed, and build the
signed record (a Sigstore attestation) that discloses it when it was not
(POAM-2026-115).

Ruleset 19769096 requires one approving review on ``main``, and its
repository-admin bypass skips that rule. Ruleset 25966171 has no bypass actor
and requires the check ``Approved review or recorded bypass``, which
``.github/workflows/review-bypass-attestation.yml`` reports by running this
script: the check passes when the head was approved, or when a signed record
that it was not has been created and verified. After each merge,
``.github/workflows/review-bypass-ledger.yml`` runs it again to confirm the
pre-merge record and to record the merge commit.

A record is not a review. The check passing means "approved, or unreviewed
and recorded". Each record says ``"reviewed": false`` and that it is not a
review or an approval, and the repository's own CI makes it, not an
independent party. No claim that a change was reviewed may rest on it.

An approval counts only when all of these hold, so that ``APPROVED`` is never
reported for a head the review rule would not accept as approved:

* the reviewer is not the pull request's author and is not a bot;
* the reviewer's latest review that changes where they stand (an approval, a
  change request, or a dismissal; comment-only and pending reviews do not)
  is an approval;
* that approval was submitted on the head commit, because ruleset 19769096
  dismisses approvals when new commits are pushed;
* the reviewer has write access to the repository (``admin``, ``maintain`` or
  ``write``), because GitHub counts no other approval;
* for the ledger, the approval was submitted no later than the merge.

Anything else is ``UNREVIEWED``. The workflows fetch every input with
``gh api``; this script makes no network calls and reads only files and
arguments.

The record's subject is the canonical JSON (sorted keys, no whitespace,
ASCII) of ``{"repo", "pr", "head_sha"}`` before a merge and of
``{"repo", "merge_sha"}`` after one. Its sha256 is the subject digest, so
anyone can rebuild the subject from public data, for example::

    printf '{"head_sha":"%s","pr":%d,"repo":"%s"}' "$HEAD" "$PR" "$REPO" | sha256sum

Usage::

    review_bypass_attestation.py candidates --reviews F --author LOGIN --head-sha SHA
    review_bypass_attestation.py decide --reviews F --permissions F --author LOGIN --head-sha SHA
    review_bypass_attestation.py subject --repo OWNER/NAME --pr N --head-sha SHA [--output F]
    review_bypass_attestation.py predicate --repo ... --output F
    review_bypass_attestation.py merged-pr --repo OWNER/NAME --merge-sha SHA --pulls F
    review_bypass_attestation.py merge-facts --repo ... --pull F --commit F
    review_bypass_attestation.py ledger-subject --repo OWNER/NAME --merge-sha SHA [--output F]
    review_bypass_attestation.py ledger-predicate --repo ... --output F

``candidates`` and ``decide`` take ``--before TIMESTAMP`` for the ledger.
Exit status: 0 on success; 1 on a refusal or on any input that is not exactly
what is expected; 2 on a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PREDICATE_TYPE = (
    "https://github.com/google/cybernetic-agent-governance-engine"
    "/attestations/review-bypass/v1"
)
LEDGER_PREDICATE_TYPE = (
    "https://github.com/google/cybernetic-agent-governance-engine"
    "/attestations/review-bypass-ledger/v1"
)
ATTESTATION_WORKFLOW = ".github/workflows/review-bypass-attestation.yml"
LEDGER_WORKFLOW = ".github/workflows/review-bypass-ledger.yml"
PROTECTED_BRANCH = "main"
REASON = "no_approving_review"

APPROVED = "APPROVED"
UNREVIEWED = "UNREVIEWED"

# Every record carries these, before and after the merge, so that no reader
# can take one for a review. The pre-merge record is written before any merge,
# and for heads that may never merge, so its statement claims no merge.
REVIEWED = False
RECORDED_BY = "the repository's own CI workflow; not an independent party"
PREMERGE_STATEMENT = (
    "This record shows the pull request had no approving review when this check "
    "ran. It is not a review or an approval and makes no claim about the change."
)
LEDGER_STATEMENT = (
    "This record shows the pull request was merged without an approving review. "
    "It is not a review or an approval and makes no claim about the change."
)

FORK_REFUSAL = (
    "the pull request comes from a fork and has no approving review: a fork's "
    "pull request needs an approving review from a maintainer, and a recorded "
    "bypass is only for pull requests from this repository's own branches"
)

# Every state the REST API reports for a pull request review.
REVIEW_STATES = frozenset(
    {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"}
)
# The states that change where a reviewer stands. A comment-only review leaves
# an earlier approval in force, as it does on GitHub; a dismissed review leaves
# the reviewer with no standing at all.
DECISIVE_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
# What GET /repos/{repo}/collaborators/{user}/permission reports in
# `permission`. GitHub reports maintain as write and triage as read; both are
# accepted in case that changes.
KNOWN_PERMISSIONS = frozenset({"admin", "maintain", "write", "triage", "read", "none"})
WRITE_PERMISSIONS = frozenset({"admin", "maintain", "write"})

PREMERGE_EVENTS = frozenset({"pull_request", "pull_request_review"})
LEDGER_EVENTS = frozenset({"push"})

_SHA = re.compile(r"[0-9a-f]{40}")
_PR = re.compile(r"[1-9][0-9]{0,9}")
_POSITIVE_INT = re.compile(r"[1-9][0-9]{0,18}")
_OWNER = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
_REPO = re.compile(_OWNER + r"/[A-Za-z0-9._-]{1,100}")
_LOGIN = re.compile(_OWNER)
_BOT_LOGIN = re.compile(_OWNER + r"\[bot\]")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_REF = re.compile(r"[A-Za-z0-9._/-]{1,255}")


class InputError(ValueError):
    """An input this script will not act on."""


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def require_sha(value: object, what: str = "commit SHA") -> str:
    """Return ``value`` if it is a full, lowercase hex commit SHA."""
    if isinstance(value, str) and _SHA.fullmatch(value):
        return value
    raise InputError(f"{what} must be 40 lowercase hex characters, got {value!r}")


def _digits(value: object) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    return value if isinstance(value, str) else ""


def require_pr(value: object) -> int:
    """Return ``value`` as a pull request number: a positive integer."""
    text = _digits(value)
    if _PR.fullmatch(text):
        return int(text)
    raise InputError(f"pull request number must be a positive integer, got {value!r}")


def require_positive_int(value: object, what: str) -> int:
    """Return ``value`` as a positive integer."""
    text = _digits(value)
    if _POSITIVE_INT.fullmatch(text):
        return int(text)
    raise InputError(f"{what} must be a positive integer, got {value!r}")


def require_repo(value: object) -> str:
    """Return ``value`` if it names a repository as ``OWNER/NAME``."""
    if isinstance(value, str) and _REPO.fullmatch(value):
        if value.split("/", 1)[1] not in {".", ".."}:
            return value
    raise InputError(f"repository must be OWNER/NAME, got {value!r}")


def require_login(value: object, what: str, *, allow_bot: bool = False) -> str:
    """Return ``value`` if it is a GitHub login (or, if allowed, an app's)."""
    if isinstance(value, str) and (
        _LOGIN.fullmatch(value) or (allow_bot and _BOT_LOGIN.fullmatch(value))
    ):
        return value
    raise InputError(f"{what} is not a GitHub login: {value!r}")


def require_timestamp(value: object, what: str) -> datetime:
    """Parse a UTC timestamp in the form the GitHub API returns."""
    if isinstance(value, str) and _TIMESTAMP.fullmatch(value):
        try:
            parsed = datetime.strptime(value, _TIMESTAMP_FORMAT)
        except ValueError:
            pass
        else:
            return parsed.replace(tzinfo=timezone.utc)
    raise InputError(
        f"{what} must be a UTC timestamp such as 2026-01-31T23:59:59Z, got {value!r}"
    )


def format_timestamp(moment: datetime) -> str:
    """Format a timezone-aware time as a UTC timestamp."""
    if moment.tzinfo is None:
        raise InputError("a timestamp must carry a timezone")
    return moment.astimezone(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def require_ref(value: object, what: str = "branch") -> str:
    """Return ``value`` if it is a plain branch or ref name."""
    if (
        isinstance(value, str)
        and _REF.fullmatch(value)
        and ".." not in value
        and "//" not in value
        and not value.startswith("/")
        and not value.endswith("/")
    ):
        return value
    raise InputError(f"{what} is not a valid ref name: {value!r}")


# --------------------------------------------------------------------------
# API responses
# --------------------------------------------------------------------------


def load_json_documents(text: str) -> list[Any]:
    """Decode one or more JSON documents written back to back.

    ``gh api --paginate`` joins the pages of an array into one array; some
    releases wrote one array per page. Both are accepted.
    """
    decoder = json.JSONDecoder()
    documents: list[Any] = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            break
        document, index = decoder.raw_decode(text, index)
        documents.append(document)
    if not documents:
        raise InputError("expected JSON, got an empty input")
    return documents


def _array_items(text: str, what: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for document in load_json_documents(text):
        if not isinstance(document, list):
            raise InputError(f"{what} must be a JSON array of objects")
        for item in document:
            if not isinstance(item, dict):
                raise InputError(f"every entry in {what} must be a JSON object")
            items.append(item)
    return items


def _single_object(text: str, what: str) -> dict[str, Any]:
    documents = load_json_documents(text)
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise InputError(f"{what} must be a single JSON object")
    return documents[0]


@dataclass(frozen=True)
class Review:
    """One pull request review, as the reviews endpoint reports it."""

    review_id: int
    login: str | None  # None when the reviewer's account was deleted
    is_bot: bool
    state: str
    commit_id: str | None
    submitted_at: datetime | None


def parse_reviews(text: str) -> list[Review]:
    """Parse ``GET /repos/{repo}/pulls/{pr}/reviews`` output, refusing anything unexpected."""
    reviews = [_parse_review(item) for item in _array_items(text, "the reviews")]
    ids = [review.review_id for review in reviews]
    if len(ids) != len(set(ids)):
        raise InputError("the reviews repeat a review id")
    return reviews


def _parse_review(item: Mapping[str, Any]) -> Review:
    review_id = require_positive_int(item.get("id"), "review id")
    state = item.get("state")
    if state not in REVIEW_STATES:
        raise InputError(f"review {review_id} has an unknown state {state!r}")

    user = item.get("user")
    login: str | None = None
    is_bot = False
    if user is not None:
        if not isinstance(user, dict):
            raise InputError(f"review {review_id} has a malformed user")
        login = require_login(
            user.get("login"), f"review {review_id} reviewer", allow_bot=True
        )
        is_bot = user.get("type") == "Bot" or login.endswith("[bot]")

    commit_id = item.get("commit_id")
    if commit_id is not None:
        commit_id = require_sha(commit_id, f"review {review_id} commit")

    submitted = item.get("submitted_at")
    submitted_at = (
        None
        if submitted is None
        else require_timestamp(submitted, f"review {review_id} submitted_at")
    )
    if state in DECISIVE_STATES and submitted_at is None:
        raise InputError(f"review {review_id} is {state} but has no submitted_at")
    return Review(review_id, login, is_bot, state, commit_id, submitted_at)


def parse_permissions(text: str) -> dict[str, str]:
    """Parse the ``LOGIN<TAB>PERMISSION`` lines the workflow writes, one per candidate."""
    permissions: dict[str, str] = {}
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 2:
            raise InputError(f"permissions line {number} is not LOGIN<TAB>PERMISSION")
        login = require_login(fields[0], f"permissions line {number} login")
        permission = fields[1]
        if permission not in KNOWN_PERMISSIONS:
            raise InputError(
                f"permissions line {number} has an unknown permission {permission!r}"
            )
        if login.casefold() in seen:
            raise InputError(f"permissions line {number} repeats {login}")
        seen.add(login.casefold())
        permissions[login] = permission
    return permissions


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------


def _order(review: Review) -> tuple[datetime, int]:
    if review.submitted_at is None:
        raise InputError(f"review {review.review_id} has no submitted_at")
    return (review.submitted_at, review.review_id)


def latest_decisive_reviews(
    reviews: Iterable[Review], *, author: str, before: datetime | None = None
) -> dict[str, Review]:
    """Each reviewer's latest review in a decisive state, keyed by folded login.

    Leaves out the author's own reviews, reviews by deleted accounts and, when
    ``before`` is given, reviews submitted after it.
    """
    author_key = author.casefold()
    latest: dict[str, Review] = {}
    for review in reviews:
        if review.state not in DECISIVE_STATES or review.login is None:
            continue
        key = review.login.casefold()
        if key == author_key:
            continue
        if before is not None and _order(review)[0] > before:
            continue
        current = latest.get(key)
        if current is None or _order(review) > _order(current):
            latest[key] = review
    return latest


def approval_candidates(
    reviews: Iterable[Review],
    *,
    author: str,
    head_sha: str,
    before: datetime | None = None,
) -> list[str]:
    """Reviewers whose approval of ``head_sha`` counts if they have write access.

    The workflow looks up each one's repository permission and passes the
    result to :func:`decide`.
    """
    author = require_login(author, "author", allow_bot=True)
    head_sha = require_sha(head_sha, "head SHA")
    latest = latest_decisive_reviews(reviews, author=author, before=before)
    return sorted(
        (
            review.login
            for review in latest.values()
            if review.login is not None
            and review.state == "APPROVED"
            and not review.is_bot
            and review.commit_id == head_sha
        ),
        key=str.casefold,
    )


@dataclass(frozen=True)
class Decision:
    """The outcome for one head, and the reviewers whose approval counted."""

    outcome: str
    approvers: tuple[str, ...]


def decide(
    reviews: Iterable[Review],
    *,
    author: str,
    head_sha: str,
    permissions: Mapping[str, str],
    before: datetime | None = None,
) -> Decision:
    """``APPROVED`` if at least one approval counts (module docstring), else ``UNREVIEWED``.

    ``permissions`` maps each candidate's login to the permission GitHub
    reports for them. A candidate missing from it is an error rather than an
    approval that does not count, so a lookup the workflow skipped is reported
    instead of read as a missing approval.
    """
    by_login = {login.casefold(): value for login, value in permissions.items()}
    approvers: list[str] = []
    for login in approval_candidates(
        reviews, author=author, head_sha=head_sha, before=before
    ):
        permission = by_login.get(login.casefold())
        if permission is None:
            raise InputError(f"no repository permission was looked up for {login}")
        if permission not in KNOWN_PERMISSIONS:
            raise InputError(f"{login} has an unknown permission {permission!r}")
        if permission in WRITE_PERMISSIONS:
            approvers.append(login)
    return Decision(APPROVED if approvers else UNREVIEWED, tuple(approvers))


# --------------------------------------------------------------------------
# Subjects and predicates
# --------------------------------------------------------------------------


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Sorted keys, no whitespace, ASCII: the bytes a subject digest covers."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    """The lowercase hex sha256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def subject(repo: object, pr: object, head_sha: object) -> bytes:
    """The pre-merge subject: which pull request, at which head, in which repository."""
    return canonical_json(
        {
            "repo": require_repo(repo),
            "pr": require_pr(pr),
            "head_sha": require_sha(head_sha, "head SHA"),
        }
    )


def ledger_subject(repo: object, merge_sha: object) -> bytes:
    """The ledger subject: the merge commit on ``main``."""
    return canonical_json(
        {"repo": require_repo(repo), "merge_sha": require_sha(merge_sha, "merge SHA")}
    )


@dataclass(frozen=True)
class Run:
    """The workflow run that evaluates and signs."""

    event: str
    run_id: int
    run_attempt: int
    workflow_ref: str


def _run(
    *,
    repo: str,
    workflow: str,
    events: frozenset[str],
    event: object,
    run_id: object,
    run_attempt: object,
    workflow_ref: object,
) -> Run:
    if not isinstance(event, str) or event not in events:
        raise InputError(f"event must be one of {sorted(events)}, got {event!r}")
    prefix = f"{repo}/{workflow}@"
    if not isinstance(workflow_ref, str) or not workflow_ref.startswith(prefix):
        raise InputError(f"workflow ref must start with {prefix}, got {workflow_ref!r}")
    require_ref(workflow_ref[len(prefix) :], "workflow ref")
    return Run(
        event=event,
        run_id=require_positive_int(run_id, "run id"),
        run_attempt=require_positive_int(run_attempt, "run attempt"),
        workflow_ref=workflow_ref,
    )


def predicate(
    *,
    repo: object,
    pr: object,
    head_sha: object,
    head_repo: object,
    base_ref: object,
    base_sha: object,
    author: object,
    decision: Decision,
    event: object,
    run_id: object,
    run_attempt: object,
    workflow_ref: object,
    evaluated_at: datetime,
) -> dict[str, Any]:
    """The pre-merge predicate. Refuses an approved head and a fork's head."""
    repo = require_repo(repo)
    if decision.outcome != UNREVIEWED:
        raise InputError(
            "the head has an approving review; there is no bypass to record"
        )
    if head_repo != repo:
        raise InputError(FORK_REFUSAL)
    run = _run(
        repo=repo,
        workflow=ATTESTATION_WORKFLOW,
        events=PREMERGE_EVENTS,
        event=event,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
    )
    return {
        "repo": repo,
        "pr": require_pr(pr),
        "head_sha": require_sha(head_sha, "head SHA"),
        "base_ref": require_ref(base_ref, "base branch"),
        "base_sha": require_sha(base_sha, "base SHA"),
        "author": require_login(author, "author", allow_bot=True),
        "reason": REASON,
        "reviewed": REVIEWED,
        "approving_reviews": len(decision.approvers),
        "recorded_by": RECORDED_BY,
        "statement": PREMERGE_STATEMENT,
        "evaluated_at": format_timestamp(evaluated_at),
        "event": run.event,
        "run_id": run.run_id,
        "run_attempt": run.run_attempt,
        "workflow_ref": run.workflow_ref,
    }


# --------------------------------------------------------------------------
# The merge a push to main carries
# --------------------------------------------------------------------------


def _merged_into_main(pull: Mapping[str, Any], repo: str) -> bool:
    base = pull.get("base")
    if not isinstance(base, dict):
        return False
    base_repo = base.get("repo")
    return (
        base.get("ref") == PROTECTED_BRANCH
        and isinstance(base_repo, dict)
        and base_repo.get("full_name") == repo
    )


def merged_pull_request(text: str, *, repo: object, merge_sha: object) -> int:
    """The number of the one pull request merged into ``main`` as ``merge_sha``.

    ``text`` is ``GET /repos/{repo}/commits/{merge_sha}/pulls``.
    """
    repo = require_repo(repo)
    merge_sha = require_sha(merge_sha, "merge SHA")
    numbers = sorted(
        {
            require_pr(pull.get("number"))
            for pull in _array_items(text, "the commit's pull requests")
            if pull.get("merge_commit_sha") == merge_sha
            and pull.get("merged_at")
            and _merged_into_main(pull, repo)
        }
    )
    if len(numbers) != 1:
        raise InputError(
            f"{merge_sha} is the merge commit of {len(numbers)} pull requests into "
            f"{repo} {PROTECTED_BRANCH}; exactly one was expected"
        )
    return numbers[0]


@dataclass(frozen=True)
class MergeFacts:
    """A squash merge into ``main`` and the pull request it came from."""

    repo: str
    merge_sha: str
    pr: int
    head_sha: str
    author: str
    merged_by: str
    merged_at: datetime


def merge_facts(
    pull_text: str,
    commit_text: str,
    *,
    repo: object,
    merge_sha: object,
    before_sha: object,
) -> MergeFacts:
    """Validate a merged pull request and the commit its merge put on ``main``.

    ``pull_text`` is ``GET /repos/{repo}/pulls/{pr}`` and ``commit_text`` is
    ``GET /repos/{repo}/commits/{merge_sha}``. The commit must have exactly one
    parent, the commit ``main`` pointed to before the push, so the push added
    this squash merge and nothing else.
    """
    repo = require_repo(repo)
    merge_sha = require_sha(merge_sha, "merge SHA")
    before_sha = require_sha(before_sha, "previous main SHA")

    pull = _single_object(pull_text, "the pull request")
    pr = require_pr(pull.get("number"))
    if pull.get("merged") is not True or pull.get("merge_commit_sha") != merge_sha:
        raise InputError(f"pull request #{pr} was not merged as {merge_sha}")
    if not _merged_into_main(pull, repo):
        raise InputError(
            f"pull request #{pr} was not merged into {repo} {PROTECTED_BRANCH}"
        )
    head, user, merger = pull.get("head"), pull.get("user"), pull.get("merged_by")
    if not (
        isinstance(head, dict) and isinstance(user, dict) and isinstance(merger, dict)
    ):
        raise InputError(f"pull request #{pr} lacks its head, author or merger")

    commit = _single_object(commit_text, "the merge commit")
    parents = commit.get("parents")
    if commit.get("sha") != merge_sha:
        raise InputError(f"the commit read back is not {merge_sha}")
    if not (
        isinstance(parents, list)
        and len(parents) == 1
        and isinstance(parents[0], dict)
        and parents[0].get("sha") == before_sha
    ):
        raise InputError(
            f"{merge_sha} is not one commit on top of {before_sha}: "
            "the push to main did not add exactly one squash merge"
        )

    return MergeFacts(
        repo=repo,
        merge_sha=merge_sha,
        pr=pr,
        head_sha=require_sha(head.get("sha"), "head SHA"),
        author=require_login(user.get("login"), "author", allow_bot=True),
        merged_by=require_login(merger.get("login"), "merged_by", allow_bot=True),
        merged_at=require_timestamp(pull.get("merged_at"), "merged_at"),
    )


def ledger_predicate(
    facts: MergeFacts,
    *,
    decision: Decision,
    event: object,
    run_id: object,
    run_attempt: object,
    workflow_ref: object,
    recorded_at: datetime,
) -> dict[str, Any]:
    """The ledger predicate for an unreviewed merge. Refuses an approved one."""
    if decision.outcome != UNREVIEWED:
        raise InputError(
            f"pull request #{facts.pr} was approved at {facts.head_sha}; "
            "there is no bypass to record"
        )
    run = _run(
        repo=facts.repo,
        workflow=LEDGER_WORKFLOW,
        events=LEDGER_EVENTS,
        event=event,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
    )
    premerge = subject(facts.repo, facts.pr, facts.head_sha)
    return {
        "repo": facts.repo,
        "merge_sha": facts.merge_sha,
        "pr": facts.pr,
        "head_sha": facts.head_sha,
        "author": facts.author,
        "merged_by": facts.merged_by,
        "merged_at": format_timestamp(facts.merged_at),
        "premerge_subject_digest": f"sha256:{sha256_hex(premerge)}",
        "premerge_predicate_type": PREDICATE_TYPE,
        "reason": REASON,
        "reviewed": REVIEWED,
        "approving_reviews": len(decision.approvers),
        "recorded_by": RECORDED_BY,
        "statement": LEDGER_STATEMENT,
        "recorded_at": format_timestamp(recorded_at),
        "event": run.event,
        "run_id": run.run_id,
        "run_attempt": run.run_attempt,
        "workflow_ref": run.workflow_ref,
    }


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _predicate_bytes(value: Mapping[str, Any]) -> bytes:
    text = json.dumps(
        value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False
    )
    return (text + "\n").encode("ascii")


def _before(args: argparse.Namespace) -> datetime | None:
    before = getattr(args, "before", None)
    if before is None:
        return None
    return require_timestamp(before, "--before")


def _decision(args: argparse.Namespace) -> Decision:
    return decide(
        parse_reviews(_read(args.reviews)),
        author=args.author,
        head_sha=args.head_sha,
        permissions=parse_permissions(_read(args.permissions)),
        before=_before(args),
    )


def _cmd_candidates(args: argparse.Namespace) -> int:
    for login in approval_candidates(
        parse_reviews(_read(args.reviews)),
        author=args.author,
        head_sha=args.head_sha,
        before=_before(args),
    ):
        print(login)
    return 0


def _cmd_decide(args: argparse.Namespace) -> int:
    decision = _decision(args)
    if decision.approvers:
        detail = "approved by " + ", ".join(decision.approvers)
    else:
        detail = (
            "no reviewer other than the author with write access approved this head"
        )
    print(f"{decision.outcome}: {detail}", file=sys.stderr)
    print(decision.outcome)
    return 0


def _emit_subject(data: bytes, output: str | None) -> int:
    if output is not None:
        Path(output).write_bytes(data)
    print(sha256_hex(data))
    return 0


def _cmd_subject(args: argparse.Namespace) -> int:
    return _emit_subject(subject(args.repo, args.pr, args.head_sha), args.output)


def _cmd_ledger_subject(args: argparse.Namespace) -> int:
    return _emit_subject(ledger_subject(args.repo, args.merge_sha), args.output)


def _cmd_predicate(args: argparse.Namespace) -> int:
    value = predicate(
        repo=args.repo,
        pr=args.pr,
        head_sha=args.head_sha,
        head_repo=args.head_repo,
        base_ref=args.base_ref,
        base_sha=args.base_sha,
        author=args.author,
        decision=_decision(args),
        event=args.event,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        workflow_ref=args.workflow_ref,
        evaluated_at=datetime.now(timezone.utc),
    )
    Path(args.output).write_bytes(_predicate_bytes(value))
    return 0


def _cmd_merged_pr(args: argparse.Namespace) -> int:
    print(
        merged_pull_request(_read(args.pulls), repo=args.repo, merge_sha=args.merge_sha)
    )
    return 0


def _facts(args: argparse.Namespace) -> MergeFacts:
    return merge_facts(
        _read(args.pull),
        _read(args.commit),
        repo=args.repo,
        merge_sha=args.merge_sha,
        before_sha=args.before_sha,
    )


def _cmd_merge_facts(args: argparse.Namespace) -> int:
    facts = _facts(args)
    # KEY=VALUE lines for $GITHUB_OUTPUT. Every value was validated above, so
    # none can carry a newline into another output.
    print(f"pr={facts.pr}")
    print(f"head_sha={facts.head_sha}")
    print(f"author={facts.author}")
    print(f"merged_by={facts.merged_by}")
    print(f"merged_at={format_timestamp(facts.merged_at)}")
    return 0


def _cmd_ledger_predicate(args: argparse.Namespace) -> int:
    facts = _facts(args)
    decision = decide(
        parse_reviews(_read(args.reviews)),
        author=facts.author,
        head_sha=facts.head_sha,
        permissions=parse_permissions(_read(args.permissions)),
        before=facts.merged_at,
    )
    value = ledger_predicate(
        facts,
        decision=decision,
        event=args.event,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        workflow_ref=args.workflow_ref,
        recorded_at=datetime.now(timezone.utc),
    )
    Path(args.output).write_bytes(_predicate_bytes(value))
    return 0


Handler = Callable[[argparse.Namespace], int]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decide, and record, merges into main without an approving review."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name: str, handler: Handler, text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=text, description=text)
        sub.set_defaults(handler=handler)
        return sub

    def options(sub: argparse.ArgumentParser, *flags: str) -> None:
        for flag in flags:
            sub.add_argument(flag, required=True)

    run_flags = ("--event", "--run-id", "--run-attempt", "--workflow-ref", "--output")
    merge_flags = ("--repo", "--merge-sha", "--before-sha", "--pull", "--commit")

    sub = command("candidates", _cmd_candidates, "List the reviewers to look up.")
    options(sub, "--reviews", "--author", "--head-sha")
    sub.add_argument("--before", help="ignore reviews submitted after this time")

    sub = command("decide", _cmd_decide, "Print APPROVED or UNREVIEWED.")
    options(sub, "--reviews", "--permissions", "--author", "--head-sha")
    sub.add_argument("--before", help="ignore reviews submitted after this time")

    sub = command("subject", _cmd_subject, "Write the subject; print its sha256.")
    options(sub, "--repo", "--pr", "--head-sha")
    sub.add_argument("--output")

    sub = command("predicate", _cmd_predicate, "Write the pre-merge predicate.")
    options(sub, "--repo", "--pr", "--head-sha", "--head-repo", "--base-ref")
    options(sub, "--base-sha", "--author", "--reviews", "--permissions", *run_flags)

    sub = command(
        "merged-pr", _cmd_merged_pr, "Print the pull request merged as a commit."
    )
    options(sub, "--repo", "--merge-sha", "--pulls")

    sub = command(
        "merge-facts", _cmd_merge_facts, "Print a merge's facts as KEY=VALUE."
    )
    options(sub, *merge_flags)

    sub = command("ledger-subject", _cmd_ledger_subject, "Write the ledger subject.")
    options(sub, "--repo", "--merge-sha")
    sub.add_argument("--output")

    sub = command(
        "ledger-predicate", _cmd_ledger_predicate, "Write the ledger predicate."
    )
    options(sub, *merge_flags, "--reviews", "--permissions", *run_flags)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (ValueError, OSError) as exc:
        print(f"review_bypass_attestation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
