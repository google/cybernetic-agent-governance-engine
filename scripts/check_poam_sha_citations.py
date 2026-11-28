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

"""POA&M SHA-citation gate: typed citation grammar + detector-bound ratchet.

Gate G9 (``scripts/check_doc_references.py``) verifies ``<sha>:<path>`` pins, but
a bare hexadecimal citation in a POA&M tracker is never checked, so closure and
remediation evidence can cite commits that are off ``main`` or that never
existed. This gate classifies every such citation **by git object first, then by
a typed label**, and ratchets the standing debt so it can only shrink.

Scope
-----
``POAM_SCOPE`` (``docs/POAM.md`` and ``docs/compliance/**/POAM_*.md``). A
*token* is a Markdown code span whose entire content is 7-40 lowercase hex
digits. Hex digits outside code spans are not citations under this grammar.

Resolution (object type first)
------------------------------
1. Every token is looked up with ``git cat-file --batch-check`` (the *raw* type:
   ``commit`` / ``tree`` / ``blob`` / ``tag`` / missing / ambiguous). All-digit
   tokens are looked up like any other; nothing is classified as "numeric"
   before the lookup.
2. The verdict uses the **canonical universe**: objects reachable from ``main``
   (``git rev-list --objects <main>``) plus tag objects named by ``refs/tags/*``.
   Pull-request heads, deleted-branch tips, reflog and dangling objects exist only
   in some clones (CI's ``fetch-depth: 0`` checkout has none of them), so they
   must not change a verdict: an object outside the canonical universe is treated
   as *no object*. The raw type is still reported (``--list-all``).
3. A shallow clone fails closed (shared with ``check_advisory_traces.py``).

Citation grammar
----------------
*Labels* are matched immediately before a token (case-insensitive, optional
plural ``s``, then only whitespace, ``:``, ``-`` or ``(``). A **plural** label
distributes over a token list joined by ``,`` / ``and`` / ``or`` / ``/`` / an
en dash; a singular label types exactly one token. A table column whose header
is exactly a label types the tokens in that column. Closed vocabulary:

* **head**: ``branch head``, ``PR head``, ``PR commit``, ``sub-commit``,
  ``head``. A pre-squash commit; it may be off ``main`` or absent.
* **kind**: ``tree``, ``blob``, ``tag``, ``tag object``, ``annotated tag``. Must
  equal the canonical object type.
* **id**: non-git identifiers, valid only when no canonical object exists.
  ``run`` and ``job`` (GitHub Actions run/job IDs), ``check run`` /
  ``check-run`` (check-run IDs), ``ruleset`` (repository ruleset IDs),
  ``revision`` (Kubernetes ReplicaSet pod-template hashes), ``build`` (Cloud
  Build IDs), ``image`` (container image IDs), ``claim ID`` (OSCAL census
  claim IDs), ``bucket`` (evidence event-bucket IDs).
* **absent**: deliberate negative evidence. ``absent`` / ``non-existent`` /
  ``nonexistent`` before the token, or a parenthetical right after it opening
  with ``absent``, ``(a) non-existent`` or ``(which) resolves nowhere``. Valid
  only when no canonical object exists.

*Commit-claim positions* (not labels; they mark severity and chronology
evidence): a token after ``commit`` / ``SHA`` / ``squash`` / ``remediated in`` /
``fixed in`` / ``merged in`` / ``merged as`` / ``landed as`` (distributing over a
list); a token directly after a PR number (``#391 `e1f46eca```,
``#724 (`e1421593`)``, ``#617 as ...``, ``#312 / ...``); or the first token of
the parenthetical right after a closure date (``Closed `2026-10-03` (`9c...`)``).

*Same citation* (for the paired form): if the head token is inside a
parenthetical group, the citation is that innermost group plus its **lead-in**
(the text between the previous ``,`` ``;`` ``(`` ``)`` or sentence end and the
group's ``(``). Otherwise it is the ``,`` / ``;`` / sentence-delimited clause
at parenthesis depth 0. Table cells are hard boundaries; code-span contents and
link targets are masked first. Within a citation each head binds the nearest
*preceding* unconsumed PR number and main-ancestor commit, else the nearest
following one; each PR number and main commit binds at most one head.

Verdicts
--------
OK: ``main_commit`` (ancestor of ``main``, no label needed); ``paired_head``
(head label + PR number + main-ancestor commit in the same citation, e.g.
``#628 (`a3ab1b52`, branch head `e92e2d12`)``); ``tagged_commit`` (off-main
commit contained in a tag named in a code span in the same citation, e.g.
``(tag `archive/causal-outcome-detector`)``); ``kind_labelled``;
``id_labelled``; ``absent_labelled``.

Violations: ``dead_commit_claim`` (no canonical object, commit-claim position,
no label), ``unlabelled_unresolved``, ``unlabelled_kind``,
``label_type_mismatch``, ``paired_missing_pr``, ``paired_main_not_ancestor``,
``ambiguous_abbreviation``, and the chronology classes below.

Chronology
----------
A closure row is a row of a table whose header has a ``Closed`` column, or a
line carrying a ``Closed`` / ``CLOSED`` status keyword followed by a date
(``Closed (D)``, ``Closed (`D`)``, ``Closed `D```, ``Closed D``,
``**Closed:** D``). The closure clause runs from the keyword to the next
depth-0 sentence end (the whole row for a ``Closed`` column). Evidence is every
unlabelled token in a commit-claim position or bound as a paired main SHA. The
main commit's **committer** date (UTC day) must be <= the closure date
(``chronology_violation``); evidence with no canonical commit cannot be dated
offline (``chronology_undatable``); a line with a ``Closed`` keyword and
evidence but no parseable date is ``closure_date_unparseable``.

Ratchet
-------
``tests/.poam-sha-citation-baseline`` records per-class counts and per-violation
identities ``sha256(class, token, normalized 4-word context)`` (line numbers are
not part of the identity), bound to ``detector_sha256`` (a token hash of the
detector section of this file). A live identity not in the baseline fails even
if totals did not rise. ``--update-baseline`` only lowers counts under an
unchanged detector; ``--recompute-baseline --reason`` is required when the
detector changes, and every write appends to an audit history.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import subprocess
import sys
import tokenize
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Final

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from check_advisory_traces import (  # noqa: E402
    AdvisoryTraceError,
    _run_git,
    resolve_main_commit,
)

REPO_ROOT_DEFAULT: Final[Path] = _SCRIPTS_DIR.parent
BASELINE_REL_PATH: Final[Path] = Path("tests/.poam-sha-citation-baseline")
BASELINE_SCHEMA_VERSION: Final[int] = 1
MIN_RECOMPUTE_REASON_LEN: Final[int] = 24
STANDING_DEBT_POLICY: Final[str] = (
    "Non-regression ratchet over standing POA&M citation debt: no new violation "
    "identity may appear and no class count may rise. dead_commit_claim (closure "
    "or remediation evidence resolving to no object reachable from main) and "
    "chronology_violation (evidence landed after the closure date) are the "
    "serious classes and are burned down first by correcting the citations."
)


class CitationGateError(RuntimeError):
    """Raised when the gate cannot evaluate citations (fail closed)."""


# >>> POAM-SHA-CITATION DETECTOR BEGIN >>>
POAM_SCOPE: Final[tuple[str, ...]] = (
    "docs/POAM.md",
    "docs/compliance/**/POAM_*.md",
)
PRIMARY_POAM: Final[str] = "docs/POAM.md"

OK_CLASSES: Final[tuple[str, ...]] = (
    "main_commit",
    "paired_head",
    "tagged_commit",
    "kind_labelled",
    "id_labelled",
    "absent_labelled",
)
VIOLATION_CLASSES: Final[tuple[str, ...]] = (
    "dead_commit_claim",
    "unlabelled_unresolved",
    "unlabelled_kind",
    "label_type_mismatch",
    "paired_missing_pr",
    "paired_main_not_ancestor",
    "ambiguous_abbreviation",
    "chronology_violation",
    "chronology_undatable",
    "closure_date_unparseable",
)

HEAD_LABELS: Final[tuple[str, ...]] = (
    "branch head",
    "pr head",
    "pr commit",
    "sub-commit",
    "head",
)
KIND_LABELS: Final[dict[str, str]] = {
    "tag object": "tag",
    "annotated tag": "tag",
    "tree": "tree",
    "blob": "blob",
    "tag": "tag",
}
ID_LABELS: Final[tuple[str, ...]] = (
    "check run",
    "check-run",
    "run",
    "job",
    "ruleset",
    "revision",
    "build",
    "image",
    "claim id",
    "bucket",
)
ABSENT_LABELS: Final[tuple[str, ...]] = ("absent", "non-existent", "nonexistent")
CLAIM_CUES: Final[tuple[str, ...]] = (
    "remediated in",
    "fixed in",
    "merged in",
    "merged as",
    "landed as",
    "commit",
    "squash",
    "sha",
)

_LABEL_FAMILY: Final[dict[str, str]] = {
    **dict.fromkeys(HEAD_LABELS, "head"),
    **dict.fromkeys(KIND_LABELS, "kind"),
    **dict.fromkeys(ID_LABELS, "id"),
    **dict.fromkeys(ABSENT_LABELS, "absent"),
    **dict.fromkeys(CLAIM_CUES, "claim"),
}
_LABEL_ALT: Final[str] = "|".join(
    re.escape(lab).replace(r"\ ", r"\s+")
    for lab in sorted(_LABEL_FAMILY, key=len, reverse=True)
)
_PRE_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?<![\w-])(?P<label>{_LABEL_ALT})(?P<plural>s?)[\s:(\-]*$", re.IGNORECASE
)
_HEADER_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    rf"^(?P<label>{_LABEL_ALT})s?$", re.IGNORECASE
)
_POST_ABSENT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*\(\s*(?:(?:a|an|which)\s+)?(?:absent|non-?existent|resolves\s+nowhere)\b",
    re.IGNORECASE,
)
_PR_ANCHOR_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[^\w&])#\d+`?\s*(?:[(/,]\s*)?(?:(?:as|at)\s+)?$"
)
_LIST_JOIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:,|/|\u2013|-|and|or|,\s*and|,\s*or)\s*$"
)
_CODE_SPAN_RE: Final[re.Pattern[str]] = re.compile(r"`([^`\n]*)`")
_HEX_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{7,40}")
_PR_SPAN_RE: Final[re.Pattern[str]] = re.compile(r"#\d{1,6}")
_PR_PROSE_RE: Final[re.Pattern[str]] = re.compile(r"(?<![\w&/#])#\d{1,6}\b")
_LINK_TARGET_RE: Final[re.Pattern[str]] = re.compile(r"\]\([^)\s]*\)")
_SENTENCE_END_RE: Final[re.Pattern[str]] = re.compile(r"\.(?=[*_]*(?:\s|$))")
_CLOSED_KEYWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])(?:Closed|CLOSED)(?![\w-])"
)
_CLOSED_DATE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:Closed|CLOSED)(?:\*\*)?\s*:?\s*(?:\*\*)?\s*\(?\s*`?(\d{4}-\d{2}-\d{2})`?"
)
_CLOSURE_ANCHOR_RE: Final[re.Pattern[str]] = re.compile(r"^\s*\)?\s*\(\s*$")
_ANNOTATION_RE: Final[re.Pattern[str]] = re.compile(
    r"\*\*[A-Z][\w /-]*\(\s*`?\d{4}-\d{2}-\d{2}"
)
_PR_OPENED_RE: Final[re.Pattern[str]] = re.compile(r"#\d+`?\s*$")
_CELL_DATE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[\s*\u2705]*`?(\d{4}-\d{2}-\d{2})"
)
_TABLE_SEP_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*(?::?-{3,}:?\s*)?$"
)
_MASK: Final[str] = "\x01"
_CONTEXT_WORDS: Final[int] = 4


@dataclass
class Cite:
    """One hexadecimal code-span token and its classification."""

    file: str
    line_no: int
    token: str
    open: int
    close: int
    context: str
    label_family: str | None = None
    label_value: str | None = None
    label_plural: bool = False
    claim: bool = False
    claim_cue: bool = False
    raw_type: str = "missing"
    raw_oid: str | None = None
    canon_type: str | None = None
    canon_oid: str | None = None
    verdict: str = ""
    detail: str = ""
    paired_main: bool = False
    paired_head_token: str | None = None


@dataclass(frozen=True)
class Violation:
    """One ratcheted violation instance."""

    cls: str
    subject: str
    file: str
    line_no: int
    context: str
    message: str

    @property
    def identity(self) -> str:
        return violation_identity(self.cls, self.subject, self.context)


@dataclass(frozen=True)
class ChronologyRecord:
    """One evidence commit checked against a closure date."""

    file: str
    line_no: int
    closure_date: str
    token: str
    committer_date: str | None
    author_date: str | None
    verdict: str
    head_token: str | None = None
    head_dates: str | None = None


@dataclass
class ScanResult:
    """Full scan output."""

    main_ref: str
    main_oid: str
    cites: list[Cite] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    chronology: list[ChronologyRecord] = field(default_factory=list)

    def class_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(VIOLATION_CLASSES, 0)
        for v in self.violations:
            counts[v.cls] += 1
        return counts

    def identity_counts(self) -> Counter[str]:
        return Counter(v.identity for v in self.violations)


def violation_identity(cls: str, subject: str, context: str) -> str:
    """Line-number-free identity of a violation."""
    payload = f"{cls}\x00{subject}\x00{context}".encode()
    return hashlib.sha256(payload).hexdigest()[:24]


def _normalize_words(text: str) -> list[str]:
    return re.sub(r"[`*_\[\]]", " ", text.lower()).split()


def context_window(raw: str, start: int, end: int) -> str:
    """Return the normalized N-word window around ``raw[start:end]``."""
    before = _normalize_words(raw[:start])[-_CONTEXT_WORDS:]
    after = _normalize_words(raw[end:])[:_CONTEXT_WORDS]
    return " ".join([*before, "<>", *after])


def resolve_scope(repo_root: Path) -> list[Path]:
    """Return every in-scope POA&M file (fails closed without docs/POAM.md)."""
    primary = repo_root / PRIMARY_POAM
    if not primary.is_file():
        raise CitationGateError(f"{PRIMARY_POAM} not found under {repo_root}")
    files: set[Path] = set()
    for pattern in POAM_SCOPE:
        files.update(p for p in repo_root.glob(pattern) if p.is_file())
    return sorted(files)


class _Line:
    """Masked structural model of one Markdown line."""

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.spans = [
            (m.start(), m.end(), m.group(1)) for m in _CODE_SPAN_RE.finditer(raw)
        ]
        chars = list(raw)
        for s, e, _ in self.spans:
            for i in range(s + 1, e - 1):
                chars[i] = _MASK
        for m in _LINK_TARGET_RE.finditer("".join(chars)):
            for i in range(m.start() + 1, m.end()):
                chars[i] = _MASK
        self.masked = "".join(chars)
        self.is_table = raw.lstrip().startswith("|")
        self.units = self._units()
        self.depth = [0] * (len(raw) + 1)
        self.groups: list[tuple[int, int]] = []
        for us, ue in self.units:
            self._parse_groups(us, ue)

    def _units(self) -> list[tuple[int, int]]:
        if not self.is_table:
            return [(0, len(self.raw))]
        units: list[tuple[int, int]] = []
        prev = 0
        for i, c in enumerate(self.masked):
            if c == "|" and (i == 0 or self.masked[i - 1] != "\\"):
                units.append((prev, i))
                prev = i + 1
        units.append((prev, len(self.raw)))
        return units

    def cell_index(self, pos: int) -> int:
        for idx, (s, e) in enumerate(self.units):
            if s <= pos < e:
                return idx
        return len(self.units) - 1

    def unit_of(self, pos: int) -> tuple[int, int]:
        return self.units[self.cell_index(pos)]

    def _parse_groups(self, us: int, ue: int) -> None:
        stack: list[int] = []
        for i in range(us, ue):
            c = self.masked[i]
            if c == "(":
                stack.append(i)
                self.depth[i] = len(stack) - 1
            elif c == ")" and stack:
                self.groups.append((stack.pop(), i))
                self.depth[i] = len(stack)
            else:
                self.depth[i] = len(stack)
        for o in stack:
            self.groups.append((o, ue))

    def innermost_group(self, pos: int) -> tuple[int, int] | None:
        best: tuple[int, int] | None = None
        for o, c in self.groups:
            if o < pos < c and (best is None or o > best[0]):
                best = (o, c)
        return best

    def is_sentence_end(self, i: int) -> bool:
        return self.masked[i] == "." and bool(_SENTENCE_END_RE.match(self.masked, i))

    def _is_boundary(self, i: int) -> bool:
        return self.depth[i] == 0 and (
            self.masked[i] in ",;" or self.is_sentence_end(i)
        )

    def leadin_start(self, group_open: int) -> int:
        us, _ = self.unit_of(group_open)
        for i in range(group_open - 1, us - 1, -1):
            if self.masked[i] in ",;()" or self.is_sentence_end(i):
                return i + 1
        return us

    def segment(self, pos: int) -> tuple[int, int]:
        us, ue = self.unit_of(pos)
        start = next(
            (i + 1 for i in range(pos - 1, us - 1, -1) if self._is_boundary(i)), us
        )
        end = next((i for i in range(pos, ue) if self._is_boundary(i)), ue)
        return start, end

    def citation_span(self, pos: int) -> tuple[int, int]:
        group = self.innermost_group(pos)
        if group is None:
            return self.segment(pos)
        return self.leadin_start(group[0]), group[1]

    def clause_end(self, pos: int) -> int:
        _, ue = self.unit_of(pos)
        return next(
            (
                i
                for i in range(pos, ue)
                if self.depth[i] == 0 and self.is_sentence_end(i)
            ),
            ue,
        )

    def pr_positions(self) -> list[int]:
        out = [s for s, _, content in self.spans if _PR_SPAN_RE.fullmatch(content)]
        out.extend(m.start() for m in _PR_PROSE_RE.finditer(self.masked))
        return sorted(out)

    def tag_names_in(self, start: int, end: int, tags: frozenset[str]) -> list[str]:
        return [c for s, _, c in self.spans if start <= s < end and c in tags]


def _set_label(cite: Cite, label: str, plural: bool) -> None:
    family = _LABEL_FAMILY[label]
    if family == "claim":
        cite.claim = cite.claim_cue = True
    elif cite.label_family is None:
        cite.label_family, cite.label_value = family, label
        cite.label_plural = plural


def _apply_labels(line: _Line, cites: list[Cite], header: list[str] | None) -> None:
    prev: Cite | None = None
    for cite in cites:
        us, _ = line.unit_of(cite.open)
        m = _PRE_LABEL_RE.search(line.masked[us : cite.open][-64:])
        if m is not None:
            label = re.sub(r"\s+", " ", m.group("label").lower())
            _set_label(cite, label, bool(m.group("plural")))
        if cite.label_family is None and _POST_ABSENT_RE.match(line.raw[cite.close :]):
            cite.label_family, cite.label_value = "absent", "absent"
        joined = prev is not None and bool(
            _LIST_JOIN_RE.match(line.raw[prev.close : cite.open])
        )
        if prev is not None and joined:
            if cite.label_family is None and prev.label_plural:
                cite.label_family, cite.label_value = (
                    prev.label_family,
                    prev.label_value,
                )
                cite.label_plural = True
            cite.claim = cite.claim or prev.claim
            cite.claim_cue = cite.claim_cue or prev.claim_cue
        if cite.label_family is None and header is not None:
            idx = line.cell_index(cite.open)
            hm = _HEADER_LABEL_RE.match(header[idx]) if idx < len(header) else None
            if hm is not None:
                label = re.sub(r"\s+", " ", hm.group("label").lower())
                if _LABEL_FAMILY[label] != "claim":
                    _set_label(cite, label, True)
        if not cite.claim and _PR_ANCHOR_RE.search(line.raw[us : cite.open][-24:]):
            cite.claim = True
        prev = cite


def _normalize_header_cell(cell: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[`*]", "", cell)).strip().lower()


def _split_cells(line: _Line) -> list[str]:
    return [line.raw[s:e] for s, e in line.units]


class _Git:
    """Thin batched git access for one scan."""

    def __init__(self, repo_root: Path, main_ref: str | None) -> None:
        self.root = repo_root
        try:
            self.main_ref, self.main_oid = resolve_main_commit(
                repo_root, explicit_ref=main_ref
            )
        except AdvisoryTraceError as exc:
            raise CitationGateError(str(exc)) from exc
        objs = self._run("rev-list", "--objects", self.main_oid)
        universe = {line[:40] for line in objs.splitlines() if line}
        tag_rows = self._run(
            "for-each-ref",
            "refs/tags",
            "--format=%(objectname) %(objecttype) %(refname:strip=2)",
        )
        tags: set[str] = set()
        for row in tag_rows.splitlines():
            parts = row.split(" ", 2)
            if len(parts) == 3:
                tags.add(parts[2])
                if parts[1] == "tag":
                    universe.add(parts[0])
        self.tag_names = frozenset(tags)
        self.universe = sorted(universe)
        self._types: dict[str, str] = {}

    def _run(self, *args: str, stdin: str | None = None) -> str:
        if stdin is None:
            proc = _run_git(self.root, *args)
        else:
            proc = subprocess.run(
                ["git", *args],
                cwd=self.root,
                input=stdin,
                capture_output=True,
                text=True,
                check=False,
            )
        if proc.returncode != 0:
            raise CitationGateError(
                f"git {' '.join(args[:2])} failed: {proc.stderr.strip()}"
            )
        return proc.stdout

    def batch_check(self, names: list[str]) -> dict[str, tuple[str, str | None]]:
        if not names:
            return {}
        out = self._run(
            "cat-file", "--batch-check", stdin="\n".join(names) + "\n"
        ).splitlines()
        if len(out) != len(names):
            raise CitationGateError("git cat-file --batch-check returned short output")
        result: dict[str, tuple[str, str | None]] = {}
        for name, row in zip(names, out, strict=True):
            parts = row.split()
            if len(parts) == 3 and parts[1] in {"commit", "tree", "blob", "tag"}:
                result[name] = (parts[1], parts[0])
            elif row.endswith(" ambiguous"):
                result[name] = ("ambiguous", None)
            else:
                result[name] = ("missing", None)
        return result

    def canonical(self, tokens: list[str]) -> dict[str, tuple[str | None, str | None]]:
        matches: dict[str, list[str]] = {}
        for tok in tokens:
            i = bisect_left(self.universe, tok)
            found: list[str] = []
            while i < len(self.universe) and self.universe[i].startswith(tok):
                found.append(self.universe[i])
                i += 1
            matches[tok] = found
        need = sorted({o for f in matches.values() for o in f} - set(self._types))
        for oid, (typ, _) in self.batch_check(need).items():
            self._types[oid] = typ
        result: dict[str, tuple[str | None, str | None]] = {}
        for tok, found in matches.items():
            if len(found) > 1:
                found = [o for o in found if self._types.get(o) == "commit"]
                if len(found) != 1:
                    result[tok] = ("ambiguous", None)
                    continue
            if not found:
                result[tok] = (None, None)
                continue
            result[tok] = (self._types.get(found[0]), found[0])
        return result

    def contained_in_tag(self, oid: str, tag: str) -> bool:
        proc = _run_git(
            self.root, "merge-base", "--is-ancestor", oid, f"refs/tags/{tag}^{{commit}}"
        )
        return proc.returncode == 0

    def dates(self, oids: list[str]) -> dict[str, tuple[int, int]]:
        if not oids:
            return {}
        out = self._run("show", "-s", "--format=%H %ct %at", *oids)
        result: dict[str, tuple[int, int]] = {}
        for row in out.splitlines():
            parts = row.split()
            if len(parts) == 3:
                result[parts[0]] = (int(parts[1]), int(parts[2]))
        return result


def _utc_day(ts: int) -> date:
    return datetime.fromtimestamp(ts, tz=timezone.utc).date()


def _pick(cands: list[int], pos: int) -> int | None:
    before = [c for c in cands if c < pos]
    if before:
        return max(before)
    after = [c for c in cands if c > pos]
    return min(after) if after else None


def _classify_resolved(cite: Cite, main_ref: str) -> bool:
    """Classify a token with a canonical object; return False if unresolved."""
    fam, val = cite.label_family, cite.label_value
    if cite.canon_type == "ambiguous":
        cite.verdict = "ambiguous_abbreviation"
        cite.detail = "prefix matches several canonical objects"
    elif cite.canon_type == "commit":
        if fam in {"kind", "id", "absent"}:
            cite.verdict = "label_type_mismatch"
            cite.detail = f"label '{val}' but resolves to a commit on {main_ref}"
        else:
            cite.verdict = "main_commit"
    elif cite.canon_type in {"tree", "blob", "tag"}:
        if fam == "kind" and KIND_LABELS[val or ""] == cite.canon_type:
            cite.verdict = "kind_labelled"
        elif fam is None:
            cite.verdict = "unlabelled_kind"
            cite.detail = f"{cite.canon_type} object needs a '{cite.canon_type}' label"
        else:
            cite.verdict = "label_type_mismatch"
            cite.detail = f"label '{val}' but resolves to a {cite.canon_type} object"
    else:
        return False
    return True


def _classify_unresolved(cite: Cite, main_ref: str) -> None:
    fam, val = cite.label_family, cite.label_value
    if fam == "id":
        cite.verdict = "id_labelled"
    elif fam == "absent":
        cite.verdict = "absent_labelled"
    elif fam == "kind":
        cite.verdict = "label_type_mismatch"
        cite.detail = f"label '{val}' but no {val} object reachable from {main_ref}"
    elif cite.claim:
        cite.verdict = "dead_commit_claim"
        cite.detail = f"cited as a commit; no object reachable from {main_ref}"
    else:
        cite.verdict = "unlabelled_unresolved"
        cite.detail = f"no object reachable from {main_ref} and no typed label"


def _bind_heads(line: _Line, cites: list[Cite], main_ref: str) -> None:
    prs = line.pr_positions()
    used_prs: set[int] = set()
    used_mains: set[int] = set()
    by_pos = {c.open: c for c in cites}
    for cite in cites:
        if cite.verdict or cite.label_family != "head":
            continue
        start, end = line.citation_span(cite.open)
        free_prs = [p for p in prs if start <= p < end and p not in used_prs]
        pr = _pick(free_prs, cite.open)
        if pr is None:
            cite.verdict = "paired_missing_pr"
            cite.detail = f"'{cite.label_value}' without a PR number in its citation"
            continue
        mains = [
            c.open
            for c in cites
            if start <= c.open < end
            and c.open not in used_mains
            and c.canon_type == "commit"
            and c.label_family != "head"
        ]
        main_pos = _pick(mains, cite.open)
        if main_pos is None:
            cite.verdict = "paired_main_not_ancestor"
            cite.detail = f"'{cite.label_value}' has no {main_ref}-ancestor commit in its citation"
            continue
        used_prs.add(pr)
        used_mains.add(main_pos)
        main_cite = by_pos[main_pos]
        main_cite.paired_main = True
        main_cite.paired_head_token = cite.token
        cite.verdict, cite.detail = "paired_head", f"paired with {main_cite.token}"


def _classify_line(line: _Line, cites: list[Cite], git: _Git) -> None:
    for cite in cites:
        if _classify_resolved(cite, git.main_ref):
            continue
        if cite.raw_type == "commit" and cite.raw_oid is not None:
            start, end = line.citation_span(cite.open)
            for tag in line.tag_names_in(start, end, git.tag_names):
                if git.contained_in_tag(cite.raw_oid, tag):
                    cite.verdict, cite.detail = "tagged_commit", f"in tag {tag}"
                    break
            if cite.verdict:
                continue
        if cite.label_family != "head":
            _classify_unresolved(cite, git.main_ref)
    _bind_heads(line, cites, git.main_ref)


def _parse_day(text: str | None) -> str | None:
    if text is None:
        return None
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        return None


def _in_scope(line: _Line, cite: Cite, base_depth: int, anchor: int | None) -> bool:
    """Explicit claim cue, top-level in its clause, or in an anchored group?"""
    if cite.claim_cue:
        return True
    group = line.innermost_group(cite.open)
    if group is None or line.depth[group[0]] < base_depth:
        return True
    us, _ = line.unit_of(group[0])
    return group[0] == anchor or bool(_PR_OPENED_RE.search(line.raw[us : group[0]]))


def _evidence(
    line: _Line, sel: list[Cite], base_depth: int = 0, anchor: int | None = None
) -> list[Cite]:
    return [
        c
        for c in sel
        if c.paired_main
        or (
            c.claim
            and c.label_family is None
            and _in_scope(line, c, base_depth, anchor)
        )
    ]


def _annotation_end(line: _Line, start: int, end: int) -> int:
    """Truncate a closure clause at the next dated ``**Word (D)`` annotation."""
    m = _ANNOTATION_RE.search(line.raw, start, end)
    return m.start() if m else end


def _closure_rows(
    line: _Line, cites: list[Cite], closed_col: int | None
) -> tuple[list[tuple[str, list[Cite]]], bool]:
    """Return ``[(closure_date, evidence)]`` and whether the row is unparseable."""
    if closed_col is not None:
        cells = _split_cells(line)
        if closed_col < len(cells):
            m = _CELL_DATE_RE.match(cells[closed_col])
            day = _parse_day(m.group(1) if m else None)
            if day is None:
                return [], bool(_evidence(line, cites))
            end = _annotation_end(line, 0, len(line.raw))
            return [(day, _evidence(line, [c for c in cites if c.open < end]))], False
    markers: list[tuple[int, int, str | None]] = []
    for km in _CLOSED_KEYWORD_RE.finditer(line.masked):
        dm = _CLOSED_DATE_RE.match(line.raw, km.start())
        day = _parse_day(dm.group(1) if dm else None)
        markers.append((km.start(), dm.end() if dm else km.end(), day))
    if not markers:
        return [], False
    dated = [(s, e, d) for s, e, d in markers if d is not None]
    if not dated:
        return [], bool(_evidence(line, cites))
    rows: list[tuple[str, list[Cite]]] = []
    for idx, (kstart, kend, day) in enumerate(dated):
        nxt = dated[idx + 1][0] if idx + 1 < len(dated) else len(line.raw)
        end = _annotation_end(line, kend, min(nxt, line.clause_end(kend)))
        am = re.match(r"\s*\)?\s*\(", line.raw[kend:])
        anchor = kend + am.end() - 1 if am else None
        for c in cites:
            anchored = _CLOSURE_ANCHOR_RE.match(line.raw[kend : c.open])
            if kend <= c.open < end and anchored:
                c.claim = True
                if c.verdict == "unlabelled_unresolved":
                    c.verdict = "dead_commit_claim"
                    c.detail = "closure evidence with no object reachable from main"
        clause = [c for c in cites if kstart <= c.open < end]
        base = line.depth[kstart]
        rows.append((str(day), _evidence(line, clause, base, anchor)))
    return rows, False


def _parse_files(
    repo_root: Path,
) -> list[tuple[str, int, _Line, list[Cite], int | None]]:
    per_line: list[tuple[str, int, _Line, list[Cite], int | None]] = []
    for path in resolve_scope(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        header: list[str] | None = None
        closed_col: int | None = None
        for idx, raw in enumerate(raw_lines):
            line = _Line(raw)
            if not line.is_table:
                header, closed_col = None, None
            elif _TABLE_SEP_RE.match(raw):
                continue
            elif idx + 1 < len(raw_lines) and _TABLE_SEP_RE.match(raw_lines[idx + 1]):
                header = [_normalize_header_cell(c) for c in _split_cells(line)]
                closed_col = header.index("closed") if "closed" in header else None
                continue
            cites = [
                Cite(rel, idx + 1, content, s, e, context_window(raw, s, e))
                for s, e, content in line.spans
                if _HEX_TOKEN_RE.fullmatch(content)
            ]
            _apply_labels(line, cites, header)
            per_line.append((rel, idx + 1, line, cites, closed_col))
    return per_line


def _chronology(
    result: ScanResult,
    pending: list[tuple[str, int, str, list[Cite]]],
    git: _Git,
) -> None:
    oids = {c.canon_oid for *_, ev in pending for c in ev if c.canon_type == "commit"}
    heads = {c.raw_oid for c in result.cites if c.label_family == "head"}
    dates = git.dates(sorted(o for o in oids | heads if o))
    head_dates: dict[str, str] = {}
    for c in result.cites:
        if c.label_family == "head" and c.raw_oid in dates:
            cts, ats = dates[c.raw_oid]
            head_dates[c.token] = f"author {_utc_day(ats)}, committer {_utc_day(cts)}"
    for rel, line_no, day, ev in pending:
        closure = date.fromisoformat(day)
        for c in ev:
            if c.canon_type != "commit" or c.canon_oid not in dates:
                result.chronology.append(
                    ChronologyRecord(
                        rel, line_no, day, c.token, None, None, "chronology_undatable"
                    )
                )
                result.violations.append(
                    Violation(
                        "chronology_undatable",
                        c.token,
                        rel,
                        line_no,
                        c.context,
                        f"closure {day} evidence is not a commit on {git.main_ref}; "
                        "it cannot be dated offline",
                    )
                )
                continue
            cts, ats = dates[c.canon_oid]
            cday, aday = _utc_day(cts), _utc_day(ats)
            late = cday > closure
            result.chronology.append(
                ChronologyRecord(
                    rel,
                    line_no,
                    day,
                    c.token,
                    cday.isoformat(),
                    aday.isoformat(),
                    "chronology_violation" if late else "chronology_ok",
                    c.paired_head_token,
                    head_dates.get(c.paired_head_token or ""),
                )
            )
            if late:
                result.violations.append(
                    Violation(
                        "chronology_violation",
                        c.token,
                        rel,
                        line_no,
                        c.context,
                        f"committer date {cday} (UTC) is after closure date {day}",
                    )
                )


def scan_repo(repo_root: Path, *, main_ref: str | None = None) -> ScanResult:
    """Scan every in-scope POA&M file and classify each citation."""
    repo_root = repo_root.resolve()
    per_line = _parse_files(repo_root)
    git = _Git(repo_root, main_ref)
    result = ScanResult(main_ref=git.main_ref, main_oid=git.main_oid)
    all_cites = [c for row in per_line for c in row[3]]
    if not any(c.file == PRIMARY_POAM for c in all_cites):
        raise CitationGateError(
            f"{PRIMARY_POAM} yielded zero hex citations; refusing a vacuous pass"
        )
    tokens = sorted({c.token for c in all_cites})
    raw = git.batch_check(tokens)
    canon = git.canonical(tokens)
    for c in all_cites:
        c.raw_type, c.raw_oid = raw[c.token]
        c.canon_type, c.canon_oid = canon[c.token]
    pending: list[tuple[str, int, str, list[Cite]]] = []
    for rel, line_no, line, cites, closed_col in per_line:
        _classify_line(line, cites, git)
        rows, unparseable = _closure_rows(line, cites, closed_col)
        if unparseable:
            km = _CLOSED_KEYWORD_RE.search(line.masked)
            pos = km.start() if km else 0
            result.violations.append(
                Violation(
                    "closure_date_unparseable",
                    "row",
                    rel,
                    line_no,
                    context_window(line.raw, pos, pos),
                    "closure row cites commit evidence but has no parseable date",
                )
            )
        pending.extend((rel, line_no, day, ev) for day, ev in rows)
        result.cites.extend(cites)
    result.violations.extend(
        Violation(c.verdict, c.token, c.file, c.line_no, c.context, c.detail)
        for c in result.cites
        if c.verdict in VIOLATION_CLASSES
    )
    _chronology(result, pending, git)
    return result


def _source_section(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    begin = "# >>> POAM-SHA-CITATION DETECTOR " + "BEGIN >>>"
    end = "# <<< POAM-SHA-CITATION DETECTOR " + "END <<<"
    start_idx, end_idx = source.find(begin), source.find(end)
    if start_idx < 0 or end_idx <= start_idx:
        raise CitationGateError(f"missing detector sentinels in {path}")
    return source[start_idx + len(begin) : end_idx]


def compute_detector_fingerprint(script_path: Path | None = None) -> str:
    """SHA-256 over the detector section's logical tokens (no comments/docstrings)."""
    section = _source_section(script_path or Path(__file__).resolve())
    doc_starts: set[tuple[int, int]] = set()
    for node in ast.walk(ast.parse(section)):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_starts.add((body[0].value.lineno, body[0].value.col_offset))
    digest = hashlib.sha256()
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER}
    for tok in tokenize.generate_tokens(io.StringIO(section).readline):
        if tok.type in skip or (
            tok.type == tokenize.STRING and tok.start in doc_starts
        ):
            continue
        if tok.type in {tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE}:
            payload = tokenize.tok_name[tok.type]
        else:
            payload = f"{tok.type}:{tok.string}"
        digest.update(payload.encode("utf-8") + b"\0")
    return digest.hexdigest()


# <<< POAM-SHA-CITATION DETECTOR END <<<


@dataclass(frozen=True)
class BaselineState:
    """Validated contents of ``tests/.poam-sha-citation-baseline``."""

    baseline: int
    detector_sha256: str
    class_counts: dict[str, int]
    violations: dict[str, dict[str, object]]
    history: list[dict[str, object]]


def _is_count(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val >= 0


def _validate_counts(
    raw: object, where: str
) -> tuple[dict[str, int] | None, str | None]:
    if not isinstance(raw, dict) or set(raw) != set(VIOLATION_CLASSES):
        return None, f"{where} must map exactly the classes {list(VIOLATION_CLASSES)}"
    if not all(_is_count(v) for v in raw.values()):
        return None, f"{where} values must be non-negative integers"
    return {k: int(raw[k]) for k in VIOLATION_CLASSES}, None


def _validate_transition(
    idx: int, entry: dict[str, object], prev: dict[str, object], after: dict[str, int]
) -> str | None:
    event = entry.get("event")
    if event not in {"update", "recompute"}:
        return f"history[{idx}].event must be 'update' or 'recompute', got {event!r}"
    for key, prev_key in (
        ("before_baseline", "after_baseline"),
        ("before_class_counts", "after_class_counts"),
        ("before_detector_sha256", "detector_sha256"),
    ):
        if entry.get(key) != prev.get(prev_key):
            return f"history[{idx}].{key} does not match history[{idx - 1}].{prev_key}"
    before = prev.get("after_class_counts")
    assert isinstance(before, dict)
    same_detector = entry.get("detector_sha256") == prev.get("detector_sha256")
    if event == "update":
        if not same_detector:
            return f"history[{idx}] ('update') cannot change detector_sha256; use 'recompute'"
        raised = [k for k in VIOLATION_CLASSES if after[k] > int(before[k])]
        if raised:
            return f"history[{idx}] ('update') raised class counts {raised} (monotonic violation)"
        return None
    if same_detector:
        return f"history[{idx}] ('recompute') has an unchanged detector_sha256"
    reason = str(entry.get("reason", "")).strip()
    if len(reason) < MIN_RECOMPUTE_REASON_LEN:
        return f"history[{idx}] ('recompute') reason must be >= {MIN_RECOMPUTE_REASON_LEN} chars"
    return None


def _validate_history(history: object) -> str | None:
    if not isinstance(history, list) or not history:
        return "history must be a non-empty list"
    prev: dict[str, object] | None = None
    for idx, entry in enumerate(history):
        if not isinstance(entry, dict):
            return f"history[{idx}] must be an object"
        det, reason = entry.get("detector_sha256"), entry.get("reason")
        if not isinstance(det, str) or not det:
            return f"history[{idx}].detector_sha256 must be a non-empty string"
        if not isinstance(reason, str) or not reason.strip():
            return f"history[{idx}].reason must be a non-empty string"
        after, err = _validate_counts(
            entry.get("after_class_counts"), f"history[{idx}].after_class_counts"
        )
        if after is None:
            return err
        if entry.get("after_baseline") != sum(after.values()):
            return f"history[{idx}].after_baseline must equal sum(after_class_counts)"
        if prev is None:
            if entry.get("event") != "initial_baseline":
                return "history[0].event must be 'initial_baseline'"
            if (
                entry.get("before_baseline") is not None
                or entry.get("before_detector_sha256") is not None
            ):
                return (
                    "history[0] must set before_baseline/before_detector_sha256 to null"
                )
            if len(reason.strip()) < MIN_RECOMPUTE_REASON_LEN:
                return f"history[0].reason must be >= {MIN_RECOMPUTE_REASON_LEN} chars"
        else:
            terr = _validate_transition(idx, entry, prev, after)
            if terr is not None:
                return terr
        prev = entry
    return None


def _validate_violations(
    raw_viol: object, counts: dict[str, int]
) -> tuple[dict[str, dict[str, object]] | None, str | None]:
    if not isinstance(raw_viol, dict):
        return None, "violations must be an object"
    tally = dict.fromkeys(VIOLATION_CLASSES, 0)
    for ident, rec in raw_viol.items():
        if not isinstance(rec, dict):
            return None, f"violation {ident} must be an object"
        cls, subj = rec.get("class"), rec.get("subject")
        ctx, cnt = rec.get("context"), rec.get("count")
        if (
            not isinstance(cls, str)
            or cls not in tally
            or not isinstance(subj, str)
            or not isinstance(ctx, str)
            or not isinstance(cnt, int)
            or not _is_count(cnt)
            or cnt == 0
        ):
            return None, f"violation {ident} is malformed"
        if violation_identity(cls, subj, ctx) != ident:
            return None, f"violation {ident} identity does not match its content"
        tally[cls] += cnt
    if tally != counts:
        return None, f"per-violation counts {tally} disagree with class_counts"
    return raw_viol, None


def read_baseline(path: Path) -> tuple[BaselineState | None, str | None]:
    """Read and validate the baseline file and its audit history."""
    if not path.is_file():
        return None, f"missing baseline file {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"
    if not isinstance(payload, dict) or (
        payload.get("schema_version") != BASELINE_SCHEMA_VERSION
    ):
        return None, f"{path}: unsupported or missing schema_version"
    det = payload.get("detector_sha256")
    if not isinstance(det, str) or not det:
        return None, f"{path}: invalid detector_sha256"
    counts, err = _validate_counts(payload.get("class_counts"), "class_counts")
    if counts is None:
        return None, f"{path}: {err}"
    if payload.get("baseline") != sum(counts.values()):
        return None, f"{path}: baseline must equal the sum of class_counts"
    viol, verr = _validate_violations(payload.get("violations"), counts)
    if viol is None:
        return None, f"{path}: {verr}"
    hist = payload.get("history")
    herr = _validate_history(hist)
    if herr is not None:
        return None, f"{path}: {herr}"
    assert isinstance(hist, list)
    last = hist[-1]
    if last.get("after_class_counts") != counts or last.get("detector_sha256") != det:
        return None, f"{path}: top-level state disagrees with history[-1]"
    if not isinstance(payload.get("standing_debt_policy"), str):
        return None, f"{path}: missing standing_debt_policy"
    return BaselineState(sum(counts.values()), det, counts, viol, hist), None


def _violation_records(result: ScanResult) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    counts = result.identity_counts()
    for v in result.violations:
        records.setdefault(
            v.identity,
            {
                "class": v.cls,
                "subject": v.subject,
                "file": v.file,
                "context": v.context,
                "count": counts[v.identity],
            },
        )
    return dict(sorted(records.items()))


def write_baseline(
    path: Path,
    result: ScanResult,
    *,
    detector_sha256: str,
    history: list[dict[str, object]],
) -> BaselineState:
    """Serialize the live scan as the new baseline and re-validate it."""
    counts = result.class_counts()
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "baseline": sum(counts.values()),
        "detector_sha256": detector_sha256,
        "class_counts": counts,
        "standing_debt_policy": STANDING_DEBT_POLICY,
        "violations": _violation_records(result),
        "history": history,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    state, err = read_baseline(path)
    if state is None:
        raise CitationGateError(f"refusing to keep an invalid baseline: {err}")
    return state


def history_entry(
    event: str,
    reason: str,
    result: ScanResult,
    detector_sha256: str,
    prev: BaselineState | None,
) -> dict[str, object]:
    """Build one append-only audit-history entry."""
    counts = result.class_counts()
    return {
        "event": event,
        "reason": reason,
        "before_baseline": prev.baseline if prev else None,
        "after_baseline": sum(counts.values()),
        "before_class_counts": prev.class_counts if prev else None,
        "after_class_counts": counts,
        "before_detector_sha256": prev.detector_sha256 if prev else None,
        "detector_sha256": detector_sha256,
    }


def compare_to_baseline(
    result: ScanResult,
    state: BaselineState,
    *,
    detector_sha256: str,
    allow_slack: bool = False,
) -> list[str]:
    """Return ratchet failures (empty when live scan matches the baseline)."""
    if state.detector_sha256 != detector_sha256:
        return [
            f"detector fingerprint drifted from {state.detector_sha256[:12]} to "
            f"{detector_sha256[:12]}; run --recompute-baseline --reason "
            "'<why the detector changed>'"
        ]
    failures: list[str] = []
    by_id = {v.identity: v for v in result.violations}
    for ident, n in sorted(result.identity_counts().items()):
        rec = state.violations.get(ident)
        allowed = rec.get("count", 0) if rec else 0
        if not isinstance(allowed, int) or n > allowed:
            v = by_id[ident]
            failures.append(
                f"NEW {v.file}:{v.line_no}: [{v.cls}] `{v.subject}`: {v.message}"
            )
    counts = result.class_counts()
    failures.extend(
        f"class {cls} rose from {state.class_counts[cls]} to {counts[cls]}"
        for cls in VIOLATION_CLASSES
        if counts[cls] > state.class_counts[cls]
    )
    if not failures and not allow_slack:
        lowered = [
            f"{cls}: {state.class_counts[cls]} -> {counts[cls]}"
            for cls in VIOLATION_CLASSES
            if counts[cls] < state.class_counts[cls]
        ]
        if lowered:
            live_total = sum(counts.values())
            failures.append(
                f"ratchet slack: observed debt dropped below baseline "
                f"({state.baseline} -> {live_total}; {', '.join(lowered)})"
            )
    return failures


def _print_summary(result: ScanResult) -> None:
    ok = Counter(c.verdict for c in result.cites if c.verdict in OK_CLASSES)
    unique = len({c.token for c in result.cites})
    print(f"POA&M SHA citations vs {result.main_ref} ({result.main_oid[:12]}):")
    print(f"  tokens: {len(result.cites)} occurrences, {unique} unique")
    for cls in OK_CLASSES:
        print(f"  ok        {cls:26} {ok.get(cls, 0)}")
    counts = result.class_counts()
    for cls in VIOLATION_CLASSES:
        print(f"  violation {cls:26} {counts[cls]}")


def _print_listings(result: ScanResult, args: argparse.Namespace) -> None:
    if args.list_all:
        for c in result.cites:
            print(
                f"{c.file}:{c.line_no}: {c.token} raw={c.raw_type} "
                f"canonical={c.canon_type or 'none'} label={c.label_value} "
                f"claim={c.claim} -> {c.verdict} {c.detail}"
            )
    if args.chronology:
        for r in result.chronology:
            head = f" head={r.head_token} ({r.head_dates})" if r.head_token else ""
            print(
                f"{r.file}:{r.line_no}: closed {r.closure_date} {r.token} "
                f"committer={r.committer_date} author={r.author_date} "
                f"-> {r.verdict}{head}"
            )
    if args.verbose:
        for v in sorted(result.violations, key=lambda x: (x.file, x.line_no, x.cls)):
            print(f"  {v.file}:{v.line_no}: [{v.cls}] `{v.subject}`: {v.message}")


def _recompute(
    baseline_path: Path,
    result: ScanResult,
    detector: str,
    reason: str,
) -> int:
    if len(reason) < MIN_RECOMPUTE_REASON_LEN:
        print(
            f"FAIL: --recompute-baseline requires --reason of at least "
            f"{MIN_RECOMPUTE_REASON_LEN} chars",
            file=sys.stderr,
        )
        return 1
    if baseline_path.is_file():
        state, err = read_baseline(baseline_path)
        if state is None:
            print(f"FAIL: existing baseline is invalid: {err}", file=sys.stderr)
            return 1
        if state.detector_sha256 == detector:
            print(
                "FAIL: detector_sha256 is unchanged; use --update-baseline to lower "
                "the ratchet",
                file=sys.stderr,
            )
            return 1
        history = [
            *state.history,
            history_entry("recompute", reason, result, detector, state),
        ]
    else:
        history = [history_entry("initial_baseline", reason, result, detector, None)]
    new = write_baseline(
        baseline_path, result, detector_sha256=detector, history=history
    )
    print(f"✅ Baseline written: {new.baseline} violation(s) at {baseline_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT_DEFAULT)
    parser.add_argument("--main-ref", default=None, help="Explicit ref used as main")
    parser.add_argument("--baseline", type=Path, default=None, help="Baseline path")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Lower the ratchet (unchanged detector only)",
    )
    parser.add_argument(
        "--recompute-baseline",
        action="store_true",
        help="Re-derive after a detector change (requires --reason)",
    )
    parser.add_argument("--reason", default="", help="Reason (>= 24 chars)")
    parser.add_argument("--verbose", action="store_true", help="List violations")
    parser.add_argument("--list-all", action="store_true", help="List every token")
    parser.add_argument("--chronology", action="store_true", help="List date checks")
    args = parser.parse_args(argv)
    if args.update_baseline and args.recompute_baseline:
        print(
            "ERROR: --update-baseline and --recompute-baseline are exclusive",
            file=sys.stderr,
        )
        return 2

    repo_root = args.repo_root.resolve()
    baseline_path = args.baseline or (repo_root / BASELINE_REL_PATH)
    try:
        result = scan_repo(repo_root, main_ref=args.main_ref)
        detector = compute_detector_fingerprint()
    except CitationGateError as exc:
        print(f"❌ POA&M SHA-citation gate failed closed: {exc}", file=sys.stderr)
        return 1
    _print_listings(result, args)
    _print_summary(result)

    if args.recompute_baseline:
        return _recompute(baseline_path, result, detector, args.reason.strip())
    state, err = read_baseline(baseline_path)
    if state is None:
        print(f"❌ {err}", file=sys.stderr)
        return 1
    failures = compare_to_baseline(
        result,
        state,
        detector_sha256=detector,
        allow_slack=args.update_baseline,
    )
    if failures:
        print("❌ POA&M SHA-citation ratchet failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        if all(f.startswith("ratchet slack:") for f in failures):
            print(
                "  Run `python scripts/check_poam_sha_citations.py "
                "--update-baseline` and commit tests/.poam-sha-citation-baseline.",
                file=sys.stderr,
            )
        else:
            print(
                "  Fix the citation; the grammar is in "
                "scripts/check_poam_sha_citations.py.",
                file=sys.stderr,
            )
        return 1
    live_total = len(result.violations)
    if args.update_baseline:
        if result.class_counts() == state.class_counts:
            print("Baseline already matches the live scan; nothing to lower.")
            return 0
        reason = args.reason.strip() or "Lower the ratchet after citation fixes."
        history = [
            *state.history,
            history_entry("update", reason, result, detector, state),
        ]
        new = write_baseline(
            baseline_path, result, detector_sha256=detector, history=history
        )
        print(f"✅ Baseline lowered from {state.baseline} to {new.baseline}")
        return 0
    print(
        f"✅ POA&M SHA-citation gate passed: {live_total} standing violation(s) "
        f"matches baseline {state.baseline}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
