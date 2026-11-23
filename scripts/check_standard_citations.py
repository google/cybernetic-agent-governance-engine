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
"""Standards-citation gate (POAM-2026-247).

Checks that every citation of an external standard's section, article, control
or principle names an identifier that exists in that standard and, where a title
or meaning is attached to it, that the meaning matches the standard. The
reference data lives only in ``compliance/standards/*.json`` (one sourced table
per standard); this script holds no title lists of its own.

Extraction is anchored on the standard's name. An identifier is only read as a
citation of standard *S* when it follows an anchor for *S* on the same line
(``NIST AI 600-1 §2.8``, ``ISO/IEC 42001 A.6.2.8``, ``EU AI Act Art. 72``,
``MAS TRM §6.3``) within a short window, chains from such a citation
(``ISO 42001 A.5.2, A.5.3``), or sits in a structured slot whose standard is
fixed (OSCAL ``control-id``, profile ``with-ids``, the
``config/oscal/framework_mappings/*.json`` keys, the ``*_MAP`` literals in
``src/gateway/governance/iso_control.py``). A bare ``2.7`` with no anchor is
never read as a citation.

Violation classes:

* ``NONEXISTENT`` - the identifier is not in the table and its nearest listed
  ancestor declares its children complete (or the table is complete).
* ``WITHDRAWN`` - the identifier is listed as withdrawn.
* ``WRONG_TITLE`` - prose attaches a title or meaning that matches a *different*
  row of the table clearly better than the cited one, or a separator- or
  parenthesis-introduced title shares nothing with the cited row.
* ``EXACT_TITLE_MISMATCH`` - a structured title slot (framework-mapping
  ``control_descriptions``, ``*_MAP`` values, OSCAL ``title:`` fields) whose
  title text is not exactly the table title.
* ``ID_COLLISION`` - an internal identifier that shares an SP 800-53 shape
  (STPA ``SC-n``, finding ``CA-0n``, breaking-change ``CP-n``,
  ``SR-26-2-*``) appears unprefixed in a NIST control context.

Ratchet: ``tests/.standard-citation-baseline`` records every standing
violation as ``standard|id|class|context-hash`` (the hash is over the path and
the whitespace-normalised line text, never the line number) with a count, bound
to ``detector_sha256`` (the detector code plus the canonical content of every
reference table). Any violation identity whose count exceeds the baseline
fails, even when the total falls. ``--update-baseline`` only lowers counts
under an unchanged fingerprint; ``--recompute-baseline --reason`` is allowed
only when the fingerprint changed; history is append-only.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import sys
import tokenize
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
TABLES_REL: Final[str] = "compliance/standards"
BASELINE_REL: Final[str] = "tests/.standard-citation-baseline"
BASELINE_SCHEMA_VERSION: Final[int] = 1
MIN_RECOMPUTE_REASON_LEN: Final[int] = 24
_DETECTOR_BEGIN: Final[str] = "# BEGIN " + "STANDARD_CITATION_DETECTOR\n"
_DETECTOR_END: Final[str] = "# END " + "STANDARD_CITATION_DETECTOR"

STANDING_DEBT_POLICY: Final[str] = (
    "Non-regression ratchet over standing standards-citation debt (POAM-2026-247). "
    "New violation identities fail immediately. Corrections are a follow-up, ordered: "
    "generated sources (config/oscal/framework_mappings, iso_control.py maps) first, "
    "then OSCAL/Lula/census, then prose and tests; each correction lowers the "
    "baseline with --update-baseline."
)

TABLE_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "schema_version",
    "standard",
    "title",
    "source_url",
    "version",
    "retrieved",
    "source_quality",
    "rows",
)
SOURCE_QUALITIES: Final[frozenset[str]] = frozenset(
    {"primary", "secondary", "knowledge-unverified"}
)
ROW_STATUSES: Final[frozenset[str]] = frozenset({"active", "withdrawn"})
_DATE_RE: Final[re.Pattern[str]] = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------------------
# Reference tables
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    """One identifier in a reference table."""

    id: str
    title: str
    status: str
    aliases: tuple[str, ...]
    replaced_by: tuple[str, ...]
    children_complete: bool


@dataclass(frozen=True)
class Table:
    """A sourced reference table for one standard."""

    standard: str
    path: str
    complete: bool
    rows: dict[str, Row]


def validate_table_doc(doc: object, name: str) -> list[str]:
    """Return schema errors for one reference-table document."""
    if not isinstance(doc, dict):
        return [f"{name}: table must be a JSON object"]
    errors = [
        f"{name}: missing key {key!r}" for key in TABLE_REQUIRED_KEYS if key not in doc
    ]
    if errors:
        return errors
    if doc["schema_version"] != 1:
        errors.append(f"{name}: unsupported schema_version {doc['schema_version']!r}")
    for key in ("standard", "title", "source_url", "version"):
        if not isinstance(doc[key], str) or not doc[key].strip():
            errors.append(f"{name}: {key} must be a non-empty string")
    if not str(doc["source_url"]).startswith("https://"):
        errors.append(f"{name}: source_url must be an https:// URL")
    if not isinstance(doc["retrieved"], str) or not _DATE_RE.match(doc["retrieved"]):
        errors.append(f"{name}: retrieved must be an ISO date (YYYY-MM-DD)")
    if doc["source_quality"] not in SOURCE_QUALITIES:
        errors.append(
            f"{name}: source_quality must be one of {sorted(SOURCE_QUALITIES)}, "
            f"got {doc['source_quality']!r}"
        )
    if doc["source_quality"] == "secondary" and not doc.get("secondary_sources"):
        errors.append(f"{name}: secondary tables must list secondary_sources")
    rows = doc["rows"]
    if not isinstance(rows, list) or not rows:
        errors.append(f"{name}: rows must be a non-empty list")
        return errors
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"{name}: rows[{idx}] must be an object")
            continue
        rid = row.get("id")
        if not isinstance(rid, str) or not rid.strip():
            errors.append(f"{name}: rows[{idx}].id must be a non-empty string")
            continue
        if rid in seen:
            errors.append(f"{name}: duplicate row id {rid!r}")
        seen.add(rid)
        if not isinstance(row.get("title"), str) or not row["title"].strip():
            errors.append(f"{name}: row {rid!r} needs a title")
        if row.get("status") not in ROW_STATUSES:
            errors.append(f"{name}: row {rid!r} status must be active or withdrawn")
        replaced = row.get("replaced_by")
        if replaced is not None and not (
            isinstance(replaced, list) and all(isinstance(x, str) for x in replaced)
        ):
            errors.append(f"{name}: row {rid!r} replaced_by must be a list of strings")
        aliases = row.get("aliases")
        if aliases is not None and not (
            isinstance(aliases, list) and all(isinstance(x, str) for x in aliases)
        ):
            errors.append(f"{name}: row {rid!r} aliases must be a list of strings")
    return errors


def load_tables(tables_dir: Path) -> tuple[dict[str, Table], list[str]]:
    """Load and validate every ``*.json`` reference table under ``tables_dir``."""
    tables: dict[str, Table] = {}
    errors: list[str] = []
    paths = sorted(tables_dir.glob("*.json"))
    if not paths:
        return tables, [f"no reference tables found under {tables_dir}"]
    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: cannot load: {exc}")
            continue
        errs = validate_table_doc(doc, path.name)
        if errs:
            errors.extend(errs)
            continue
        rows = {
            r["id"]: Row(
                id=r["id"],
                title=r["title"],
                status=r["status"],
                aliases=tuple(r.get("aliases", ())),
                replaced_by=tuple(r.get("replaced_by", ())),
                children_complete=bool(r.get("children_complete", False)),
            )
            for r in doc["rows"]
        }
        std = doc["standard"]
        if std in tables:
            errors.append(f"{path.name}: duplicate standard {std!r}")
            continue
        tables[std] = Table(
            standard=std, path=path.name, complete=bool(doc.get("complete")), rows=rows
        )
    return tables, errors


def tables_digest(tables_dir: Path) -> str:
    """Return a digest over the canonical JSON content of every table."""
    digest = hashlib.sha256()
    for path in sorted(tables_dir.glob("*.json")):
        try:
            canon = json.dumps(
                json.loads(path.read_text(encoding="utf-8")),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except (OSError, json.JSONDecodeError):
            canon = "<unreadable>"
        digest.update(path.name.encode("utf-8") + b"\0" + canon.encode("utf-8") + b"\0")
    return digest.hexdigest()


# BEGIN STANDARD_CITATION_DETECTOR
STD_AI600: Final[str] = "nist-ai-600-1"
STD_RMF: Final[str] = "nist-ai-rmf-1.0"
STD_ISO: Final[str] = "iso-iec-42001-2023"
STD_853: Final[str] = "nist-sp-800-53-r5"
STD_EU: Final[str] = "eu-ai-act"
STD_GDPR: Final[str] = "gdpr"
STD_DORA: Final[str] = "dora"
STD_TRM: Final[str] = "mas-trm"
STD_655: Final[str] = "mas-notice-655"
STD_FEAT: Final[str] = "mas-feat"

NONEXISTENT: Final[str] = "NONEXISTENT"
WITHDRAWN: Final[str] = "WITHDRAWN"
WRONG_TITLE: Final[str] = "WRONG_TITLE"
EXACT_TITLE_MISMATCH: Final[str] = "EXACT_TITLE_MISMATCH"
ID_COLLISION: Final[str] = "ID_COLLISION"

SCAN_DIRS: Final[tuple[str, ...]] = ("docs", "compliance", "config/oscal")
SCAN_FILES: Final[tuple[str, ...]] = ("README.md", "COMPLIANCE.md")
SCAN_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".md", ".yaml", ".yml", ".json", ".jsonl", ".txt"}
)
SRC_DIR: Final[str] = "src"
EXCLUDED_PREFIXES: Final[tuple[str, ...]] = (
    "compliance/standards/",
    "compliance/archive/",
    "docs/partners/",
    "docs/BREAKING_CHANGES.md",
    "CHANGELOG.md",
)
FRAMEWORK_MAPPINGS_REL: Final[str] = "config/oscal/framework_mappings"
FRAMEWORK_MAPPING_STANDARD: Final[dict[str, str]] = {
    "ISO_42001.json": STD_ISO,
    "EU_AI_ACT.json": STD_EU,
    "NIST_SP800_53.json": STD_853,
}
ISO_CONTROL_REL: Final[str] = "src/gateway/governance/iso_control.py"
# map name -> (standard of the keys, standard every value must cite or None)
ISO_CONTROL_MAPS: Final[dict[str, tuple[str, str | None]]] = {
    "NIST_MAP": (STD_ISO, STD_853),
    "EU_MAP": (STD_ISO, STD_EU),
    "MAS_MAP": (STD_ISO, None),
}
OSCAL_WITH_IDS_FILES: Final[frozenset[str]] = frozenset(
    {"compliance/oscal/sp800053-profile.yaml"}
)

ANCHORS: Final[dict[str, re.Pattern[str]]] = {
    STD_AI600: re.compile(r"(?<![\d.-])600-1(?![\d])"),
    STD_853: re.compile(
        r"800-53(?![A\d])|\bNIST\b(?!\s*(?:AI|SP\s*800-(?!53)|RMF|CSF|Cybersecurity))"
        r"|\bnist_controls\b|\bcontrol-id\b|\bwith-ids\b"
    ),
    STD_ISO: re.compile(r"(?<!\d)42001(?!\d)"),
    STD_RMF: re.compile(r"\bAI\s?RMF\b|\bAI\s100-1\b|\bRMF\b"),
    STD_EU: re.compile(r"\bAI\s+Act\b|2024/1689|\bEU\s?AIA\b"),
    STD_GDPR: re.compile(r"\bGDPR\b|2016/679"),
    STD_DORA: re.compile(r"\bDORA\b|2022/2554"),
    STD_TRM: re.compile(r"\bTRM\b"),
    STD_655: re.compile(r"\bNotice\s*655\b|\bMAS[\s-]655\b"),
    STD_FEAT: re.compile(r"\bFEAT\b"),
}
# Standards with no table: their names cut an anchor's zone but cite nothing.
BLOCKERS: Final[re.Pattern[str]] = re.compile(
    r"\b2700[12]\b|800-37|800-171|\bCSF\b|\bSR\s?26-2\b"
)
NIST_CONTEXT: Final[re.Pattern[str]] = re.compile(
    r"800-53|\bNIST\b(?!\s*AI)|\bnist_controls\b|\bcontrol-id\b|\bwith-ids\b"
)

ZONE_MAX: Final[int] = 160
FIRST_GAP_MAX: Final[int] = 30
CHAIN_GAP_MAX: Final[int] = 40
# A chained citation never continues across a table cell or a sentence end.
CHAIN_BREAK: Final[re.Pattern[str]] = re.compile(r"\||\.\s+[A-Z(*`]")
BACK_LINK: Final[re.Pattern[str]] = re.compile(
    r"^[\s(\[,:]*(?:of|in|under|from)?\s*(?:the\s+)?(?:NIST\s+|ISO/IEC\s+|ISO\s+|EU\s+|MAS\s+)?$"
)

_SEC = r"(?:§§?\s?|\b[Ss]ections?\s|\b[Ss]ec\.\s?)"
TOKENS: Final[dict[str, tuple[re.Pattern[str], ...]]] = {
    STD_AI600: (
        re.compile(_SEC + r"(?P<id>\d{1,2}(?:\.\d{1,2}){0,3})(?![\d])"),
        re.compile(r"\bApp(?:endix|\.)\s?(?P<app>[A-Z])\b"),
    ),
    STD_ISO: (
        re.compile(
            r"(?<![\w.])(?P<ann>A\.\d{1,2}(?:\.\d{1,2}){0,2})(?:\s?§\s?(?P<letter>[a-z])\b)?(?![\w]|\.\d)"
        ),
        re.compile(
            r"(?:§\s?|\b[Cc]lauses?\s)(?P<id>\d{1,2}(?:\.\d{1,2}){0,2})(?![\d])"
        ),
    ),
    STD_853: (
        re.compile(
            r"(?<![\w-])(?P<fam>[A-Z]{2})-(?P<num>\d{1,2})(?:\s?\((?P<enh>\d{1,2})\))?(?![\w-])"
        ),
        re.compile(
            r"(?<![\w-])(?P<lfam>[a-z]{2})-(?P<lnum>\d{1,2})(?:\.(?P<lenh>\d{1,2}))?(?![\w.-])"
        ),
    ),
    STD_RMF: (
        re.compile(
            r"\b(?P<fn>GOVERN|MAP|MEASURE|MANAGE|Govern|Map|Measure|Manage|GV|MP|MS|MG)"
            r"[\s-]?(?P<cat>\d{1,2})(?:\.(?P<sub>\d{1,2}))?(?![\d]|\.\d|-\d)"
        ),
    ),
    STD_EU: (
        re.compile(
            r"\bArt(?:icles?|s?\.)\s?(?P<art>\d{1,3}[a-z]?)"
            r"(?P<sub>(?:\s?\((?:\d{1,2}[a-z]?|[a-z]{1,4})\))*)(?:\s?§\s?(?P<para>\d{1,2}))?"
        ),
        re.compile(
            r"\bAnnex\s(?P<annex>[IVX]{1,5})\b(?:\s?§?\s?(?P<anum>\d{1,2})\s?\((?P<apt>[a-z])\))?"
        ),
    ),
    STD_TRM: (
        re.compile(
            r"(?:§\s?|\b[Ss]ections?\s|\bs(?=\d))(?P<id>\d{1,2}(?:\.\d{1,2}){0,2})(?![\d])"
        ),
    ),
    STD_655: (
        re.compile(
            r"(?:§\s?|¶\s?|\b[Pp]ara(?:graph)?s?\.?\s)(?P<id>\d{1,2}(?:\.\d{1,2})?)(?![\d])"
        ),
    ),
    STD_FEAT: (re.compile(r"\bPrinciples?\s(?P<id>\d{1,2})(?![\d.])"),),
}
TOKENS[STD_GDPR] = (TOKENS[STD_EU][0],)
TOKENS[STD_DORA] = (TOKENS[STD_EU][0],)
# Bare numeric section right after the anchor ("MAS TRM 6.3", "TRM Guidelines 4.2").
TRM_BARE: Final[re.Pattern[str]] = re.compile(
    r"^\W{0,3}(?:Guidelines?\s+)?(?P<id>\d{1,2}\.\d{1,2})(?![\d.])"
)
RMF_SELF_ANCHORED: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])(?P<fn>GOVERN|MAP|MEASURE|MANAGE)[\s-](?P<cat>\d{1,2})"
    r"(?:\.(?P<sub>\d{1,2}))?(?![\d]|\.\d|-\d)"
)
RMF_FUNCTIONS: Final[dict[str, str]] = {
    "GV": "GOVERN",
    "MP": "MAP",
    "MS": "MEASURE",
    "MG": "MANAGE",
}

INTERNAL_STPA_SC: Final[re.Pattern[str]] = re.compile(
    r"(?:System\s+Constraints?|\bSTPA(?:\s+[Cc]onstraints?)?|\bCAGE(?:\s+custom)?"
    r"(?:\s+System\s+Constraint)?|ISO(?:/IEC)?\s?42001)\s+(?P<id>SC-\d{1,2})(?![\w-])"
)
INTERNAL_CA0: Final[re.Pattern[str]] = re.compile(r"(?<![\w-])(?P<id>CA-0\d)(?![\w-])")
INTERNAL_SR262: Final[re.Pattern[str]] = re.compile(r"(?<![\w-])(?P<id>SR-26-2-[\w-]+)")
INTERNAL_CP: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])(?P<id>CP-\d{1,2})(?![\w-])"
)
BREAKING_CONTEXT: Final[re.Pattern[str]] = re.compile(r"BREAKING|breaking change", re.I)

OSCAL_TITLE_LINE: Final[re.Pattern[str]] = re.compile(r"^\s*-?\s*title:\s")
OSCAL_CONTROL_ID: Final[re.Pattern[str]] = re.compile(
    r"^\s*-?\s*control-id:\s*['\"]?(?P<cid>[A-Za-z]{1,3}[-.][\w.()-]+)['\"]?\s*$"
)
OSCAL_WITH_ID_ITEM: Final[re.Pattern[str]] = re.compile(
    r"^\s*-\s*['\"]?(?P<cid>[a-z]{2}-\d{1,2}(?:\.\d{1,2})?)['\"]?\s*$"
)

STOPWORDS: Final[frozenset[str]] = frozenset(
    "the of and or a an for to in on with by ai gai system systems control controls nist "
    "iso iec art article section principle mas eu act trm feat its their is are be as at "
    "via from that this these stub phase implementation lula validation manifest manifests "
    "cage nemo opa".split()
)
PROSE_LEAD_WORDS: Final[frozenset[str]] = frozenset(
    "is are was were be been of and or to the a an in on for with by as at via from that "
    "which who maps map requires require covers cover says states see per cf e.g i.e "
    "also only applies apply has have does do not no".split()
)
TITLE_DELIMS: Final[re.Pattern[str]] = re.compile(
    r"\s+[—\u2013]\s+|[|;`]|\*\*|\.\s|\.$|,\s|\s/\s|\s\+\s|\s&\s(?=[A-Z§])|\]\(|\s\(|\)|\""
)
SHORT_TITLE_TOKENS: Final[int] = 4
GENERIC_WORDS: Final[tuple[str, ...]] = tuple(
    "data information management record security risk process use content review "
    "requirement general".split()
)
WRONG_TITLE_OTHER_MIN: Final[float] = 0.75
WRONG_TITLE_MARGIN: Final[float] = 0.34
TITLE_MAX_WORDS: Final[int] = 8
PLAIN_TITLE_MAX_WORDS: Final[int] = 6


@dataclass(frozen=True)
class Citation:
    """One extracted standard citation."""

    standard: str
    cited: str  # canonical identifier
    start: int
    end: int
    raw: str
    title: str | None = None
    title_introduced: bool = False
    title_mode: str = "fuzzy"  # fuzzy | exact | exact_prefix


@dataclass(frozen=True)
class Violation:
    """One gate violation."""

    path: str
    line: int
    standard: str
    cited: str
    vclass: str
    message: str
    context: str

    @property
    def key(self) -> str:
        """Return the line-number-free identity used by the ratchet."""
        norm = " ".join(self.context.split())
        digest = hashlib.sha256(f"{self.path}\0{norm}".encode()).hexdigest()[:16]
        return f"{self.standard}|{self.cited}|{self.vclass}|{digest}"


# --- identifier helpers -----------------------------------------------------


def parent_id(rid: str) -> str | None:
    """Return the structural parent of ``rid`` or ``None`` at the top level."""
    m = re.match(r"^(.*\S)\s?\([^()]*\)$", rid)
    if m:
        return m.group(1)
    if re.match(r"^Annex [IVX]+ \d+$", rid):
        return rid.rsplit(" ", 1)[0]
    if "." in rid and not rid.startswith("Appendix"):
        head = rid.rsplit(".", 1)[0]
        return head
    m = re.match(r"^(GOVERN|MAP|MEASURE|MANAGE) \d+$", rid)
    if m:
        return m.group(1)
    m = re.match(r"^([A-Z]{2})-\d+$", rid)
    if m:
        return m.group(1)
    return None


def ancestors(rid: str) -> list[str]:
    """Return every structural ancestor of ``rid`` nearest first."""
    out: list[str] = []
    cur = parent_id(rid)
    while cur is not None and cur not in out:
        out.append(cur)
        cur = parent_id(cur)
    return out


def existence_violation(table: Table, rid: str) -> tuple[str, str] | None:
    """Return ``(class, message)`` if ``rid`` is withdrawn or does not exist."""
    row = table.rows.get(rid)
    if row is not None:
        if row.status == "withdrawn":
            repl = ", ".join(row.replaced_by) or "no successor listed"
            return WITHDRAWN, f"{rid} ({row.title}) is withdrawn; replaced by {repl}"
        return None
    for anc in ancestors(rid):
        arow = table.rows.get(anc)
        if arow is None:
            continue
        if arow.children_complete:
            return (
                NONEXISTENT,
                f"{rid} does not exist ({anc} '{arow.title}' has no such child)",
            )
        return None
    if table.complete:
        return NONEXISTENT, f"{rid} does not exist in {table.path}"
    return None


# --- title matching ---------------------------------------------------------


def _stem(word: str) -> str:
    for suffix in ("ments", "ment", "ings", "ing"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            word = word[: -len(suffix)]
            break
    if word.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss") and len(word) > 3:
        return word[:-1]
    return word


def title_tokens(text: str) -> frozenset[str]:
    """Return the normalised content tokens of ``text``."""
    words = re.findall(r"[a-z0-9]+", text.casefold())
    return frozenset(_stem(w) for w in words if w not in STOPWORDS and not w.isdigit())


GENERIC_TOKENS: Final[frozenset[str]] = frozenset(_stem(w) for w in GENERIC_WORDS)


def _row_score(
    attached: frozenset[str], row: Row, *, cited: bool
) -> tuple[float, float]:
    """Return ``(score, dice)`` of ``attached`` against ``row``'s title and aliases.

    Short attached phrases (<= ``SHORT_TITLE_TOKENS`` tokens) score by how much
    of a candidate title they contain; longer ones by Dice overlap. For the
    cited row, an attached phrase wholly contained in its title also scores 1.
    For other rows, a single shared generic token never counts.
    """
    best = (0.0, 0.0)
    if not attached:
        return best
    for cand in (row.title, *row.aliases):
        ctoks = title_tokens(cand)
        if not ctoks:
            continue
        shared = attached & ctoks
        dice = 2 * len(shared) / (len(attached) + len(ctoks))
        if len(attached) <= SHORT_TITLE_TOKENS:
            score = len(shared) / len(ctoks)
        else:
            score = dice
        if cited:
            score = max(score, len(shared) / len(attached))
        elif len(shared) == 1 and shared <= GENERIC_TOKENS:
            score = 0.0
        best = max(best, (score, dice))
    return best


def fuzzy_title_violation(
    table: Table, rid: str, title: str, introduced: bool
) -> str | None:
    """Return a message if the attached ``title`` does not fit ``rid``."""
    attached = title_tokens(title)
    if not attached:
        return None
    prefix_paren = rid + "("
    prefix_dot = rid + "."
    related = {rid, *ancestors(rid)} | {
        r for r in table.rows if r.startswith((prefix_paren, prefix_dot))
    }
    cited = max(
        (
            _row_score(attached, table.rows[r], cited=True)[0]
            for r in related
            if r in table.rows
        ),
        default=0.0,
    )
    best: tuple[float, float, int] = (0.0, 0.0, 0)
    best_row: Row | None = None
    for orow in table.rows.values():
        if orow.id in related:
            continue
        score = (*_row_score(attached, orow, cited=False), len(ancestors(orow.id)))
        if score > best:
            best, best_row = score, orow
    best_other = best[0]
    expected = table.rows[rid].title if rid in table.rows else "?"
    if (
        best_row is not None
        and best_other >= WRONG_TITLE_OTHER_MIN
        and (best_other - cited >= WRONG_TITLE_MARGIN)
    ):
        return (
            f"'{title}' attached to {rid} ('{expected}') matches "
            f"{best_row.id} ('{best_row.title}')"
        )
    if introduced and cited == 0.0 and _looks_like_title(title):
        return f"'{title}' attached to {rid} does not match its title '{expected}'"
    return None


def _looks_like_title(title: str) -> bool:
    """Return True when ``title`` reads as a name, not an identifier or prose."""
    if not title[:1].isupper() or re.search(r"[_\d]", title):
        return False
    return not re.fullmatch(r"[A-Z][A-Z-]*(?:\s.*)?", title.split()[0] + " ")


_UNICODE_DASH_RE: Final[re.Pattern[str]] = re.compile(r"[\u2010-\u2015\u2212]")


def _norm_exact_title(text: str) -> str:
    """Normalize whitespace and Unicode dashes to ASCII '-' for exact-title matching."""
    return " ".join(_UNICODE_DASH_RE.sub("-", text).split())


def exact_title_violation(table: Table, rid: str, title: str, mode: str) -> str | None:
    """Return a message if a structured title slot is not the exact table title."""
    row = table.rows.get(rid)
    if row is None or not title_tokens(title):
        return None
    got = " ".join(title.split())
    want = " ".join(row.title.split())
    got_norm = _norm_exact_title(title)
    want_norm = _norm_exact_title(row.title)
    if mode == "exact":
        ok = got_norm == want_norm
    else:
        low = got_norm.casefold()
        ok = any(
            low.startswith(c) and (len(low) == len(c) or not low[len(c)].isalnum())
            for c in (
                _norm_exact_title(x).casefold() for x in (row.title, *row.aliases)
            )
        )
    if ok:
        return None
    return f"title '{got}' for {rid} is not the exact table title '{want}'"


def attached_title(line: str, end: int) -> tuple[str | None, bool]:
    """Return ``(title, introduced)`` for text attached right after a citation."""
    tail = line[end : end + 140]
    tail = tail[len(tail) - len(tail.lstrip("*_`")) :]  # closing markdown emphasis
    m = re.match(r"\s*\(([^()]{2,90})\)", tail)
    if m:
        return _clip(m.group(1)), True
    m = re.match(r"\s*(?:[—\u2013:]|\s-\s)\s*(.{2,120})", tail)
    if m:
        return _clip(m.group(1)), True
    m = re.match(r"\s*[\"“']([^\"”']{2,90})[\"”']", tail)
    if m:
        return _clip(m.group(1)), True
    m = re.match(r"\s+([A-Za-z][^\n]{1,120})", tail)
    if not m:
        return None, False
    text = _clip(m.group(1), PLAIN_TITLE_MAX_WORDS)
    if not text:
        return None, False
    first = text.split()[0].casefold().strip(".,")
    if first in PROSE_LEAD_WORDS:
        return None, False
    return text, False


def _clip(text: str, max_words: int = TITLE_MAX_WORDS) -> str:
    """Cut ``text`` at the first delimiter; drop it if longer than ``max_words``."""
    cut = TITLE_DELIMS.search(text)
    if cut:
        text = text[: cut.start()]
    words = text.strip().strip("*_`'\"").split()
    if len(words) > max_words:
        return (
            " ".join(words[:max_words]).rstrip(".,:")
            if max_words == TITLE_MAX_WORDS
            else ""
        )
    return " ".join(words).rstrip(".,:")


# --- canonicalisation -------------------------------------------------------


def _canon_853(fam: str, num: str, enh: str | None) -> str:
    base = f"{fam.upper()}-{int(num)}"
    return f"{base}({int(enh)})" if enh else base


def _canon_article(m: re.Match[str]) -> str:
    sub = re.sub(r"\s", "", m.group("sub") or "")
    para = m.group("para")
    if para and not sub:
        sub = f"({para})"
    return f"{m.group('art')}{sub}"


def canon_token(std: str, m: re.Match[str], families: frozenset[str]) -> str | None:
    """Return the canonical identifier for token match ``m`` of ``std``."""
    gd = m.groupdict()
    if std == STD_AI600:
        return f"Appendix {gd['app']}" if gd.get("app") else gd["id"]
    if std == STD_ISO:
        if gd.get("ann"):
            return f"{gd['ann']} §{gd['letter']}" if gd.get("letter") else gd["ann"]
        return gd["id"]
    if std == STD_853:
        if gd.get("fam"):
            if gd["fam"] not in families:
                return None
            return _canon_853(gd["fam"], gd["num"], gd.get("enh"))
        if gd.get("lfam") and gd["lfam"].upper() in families:
            return _canon_853(gd["lfam"], gd["lnum"], gd.get("lenh"))
        return None
    if std == STD_RMF:
        fn = gd["fn"].upper()
        fn = RMF_FUNCTIONS.get(fn, fn)
        return f"{fn} {gd['cat']}" + (f".{gd['sub']}" if gd.get("sub") else "")
    if std in (STD_EU, STD_GDPR, STD_DORA):
        if gd.get("annex"):
            base = f"Annex {gd['annex']}"
            if gd.get("anum"):
                return f"{base} {gd['anum']}({gd['apt']})"
            return base
        return _canon_article(m)
    return gd["id"]


# --- line extraction --------------------------------------------------------


def _anchor_spans(line: str) -> list[tuple[int, int, str | None]]:
    spans: list[tuple[int, int, str | None]] = []
    for std, rx in ANCHORS.items():
        spans.extend((m.start(), m.end(), std) for m in rx.finditer(line))
    spans.extend((m.start(), m.end(), None) for m in BLOCKERS.finditer(line))
    spans.sort()
    return spans


def _is_ca0_zero_padded(m: re.Match[str]) -> bool:
    return m.group("fam") == "CA" and m.group("num").startswith("0")


def extract_line(
    line: str,
    families: frozenset[str],
    *,
    title_mode: str = "fuzzy",
    excluded: Iterable[tuple[int, int]] = (),
) -> list[Citation]:
    """Extract anchored citations from one line of text."""
    spans = _anchor_spans(line)
    claimed: list[tuple[int, int]] = list(excluded)
    out: list[Citation] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in claimed)

    def add(std: str, cid: str, m_start: int, m_end: int, raw: str) -> None:
        title, introduced = attached_title(line, m_end)
        out.append(
            Citation(std, cid, m_start, m_end, raw, title, introduced, title_mode)
        )
        claimed.append((m_start, m_end))

    for idx, (a_start, a_end, std) in enumerate(spans):
        if std is None:
            continue
        next_start = next((s for s, _, _ in spans[idx + 1 :] if s >= a_end), len(line))
        zone_end = min(next_start, a_end + ZONE_MAX)
        found: list[tuple[int, int, str, str]] = []
        for rx in TOKENS.get(std, ()):
            for m in rx.finditer(line, a_end, zone_end):
                if (
                    std == STD_853
                    and m.groupdict().get("fam")
                    and _is_ca0_zero_padded(m)
                ):
                    continue
                cid = canon_token(std, m, families)
                if cid is not None:
                    found.append((m.start(), m.end(), cid, m.group(0)))
        if std == STD_TRM:
            bm = TRM_BARE.match(line, a_end)
            if bm and bm.end() <= zone_end:
                found.append(
                    (bm.start("id"), bm.end("id"), bm.group("id"), bm.group("id"))
                )
        found.sort()
        prev_end = a_end
        for t_start, t_end, cid, raw in found:
            first = prev_end == a_end
            gap_max = FIRST_GAP_MAX if first else CHAIN_GAP_MAX
            if t_start - prev_end > gap_max:
                break
            if not first and CHAIN_BREAK.search(line, prev_end, t_start):
                break
            if not free(t_start, t_end):
                continue
            add(std, cid, t_start, t_end, raw)
            prev_end = t_end
        # one citation immediately before the anchor ("A.5.2 (ISO 42001)")
        prev_anchor_end = spans[idx - 1][1] if idx else 0
        window_start = max(prev_anchor_end, a_start - 40)
        best: tuple[int, int, str, str] | None = None
        for rx in TOKENS.get(std, ()):
            for m in rx.finditer(line, window_start, a_start):
                if (
                    std == STD_853
                    and m.groupdict().get("fam")
                    and _is_ca0_zero_padded(m)
                ):
                    continue
                if not BACK_LINK.match(line[m.end() : a_start]):
                    continue
                cid = canon_token(std, m, families)
                if cid is not None and free(m.start(), m.end()):
                    best = (m.start(), m.end(), cid, m.group(0))
        if best is not None:
            out.append(
                Citation(
                    std, best[2], best[0], best[1], best[3], None, False, title_mode
                )
            )
            claimed.append((best[0], best[1]))
    for m in RMF_SELF_ANCHORED.finditer(line):
        if free(m.start(), m.end()):
            cid = canon_token(STD_RMF, m, families)
            if cid is not None:
                add(STD_RMF, cid, m.start(), m.end(), m.group(0))
    out.sort(key=lambda c: c.start)
    return out


def internal_collisions(
    line: str, nist_context: bool
) -> tuple[list[tuple[int, int, str]], list[tuple[int, int]]]:
    """Return ``(collisions, internal_spans)`` for internal 800-53-shaped IDs."""
    spans: list[tuple[int, int, str]] = []
    for m in INTERNAL_STPA_SC.finditer(line):
        spans.append((m.start("id"), m.end("id"), m.group("id")))
    for m in INTERNAL_CA0.finditer(line):
        spans.append((m.start("id"), m.end("id"), m.group("id")))
    for m in INTERNAL_SR262.finditer(line):
        spans.append((m.start("id"), m.end("id"), m.group("id")))
    if BREAKING_CONTEXT.search(line):
        for m in INTERNAL_CP.finditer(line):
            spans.append((m.start("id"), m.end("id"), m.group("id")))
    excluded = [(s, e) for s, e, _ in spans]
    return (spans if nist_context else []), excluded


# --- file walkers -----------------------------------------------------------


def _check_citation(table: Table, cit: Citation) -> tuple[str, str] | None:
    ev = existence_violation(table, cit.cited)
    if ev is not None:
        return ev
    if not cit.title or cit.cited not in table.rows:
        return None
    if cit.title_mode == "fuzzy":
        msg = fuzzy_title_violation(table, cit.cited, cit.title, cit.title_introduced)
        return (WRONG_TITLE, msg) if msg else None
    msg = exact_title_violation(table, cit.cited, cit.title, cit.title_mode)
    return (EXACT_TITLE_MISMATCH, msg) if msg else None


def scan_text_lines(
    rel: str,
    lines: Iterable[tuple[int, str]],
    tables: dict[str, Table],
    families: frozenset[str],
    *,
    oscal: bool = False,
) -> Iterator[Violation]:
    """Scan ``(lineno, text)`` pairs from one file and yield violations."""
    with_ids_file = rel in OSCAL_WITH_IDS_FILES
    for lineno, line in lines:
        if not line.strip():
            continue
        nist_ctx = bool(NIST_CONTEXT.search(line))
        collisions, internal = internal_collisions(line, nist_ctx)
        for _, _, iid in collisions:
            yield Violation(
                rel,
                lineno,
                STD_853,
                iid,
                ID_COLLISION,
                f"internal identifier {iid} appears unprefixed in a NIST control context; "
                f"write it with a distinguishing prefix (e.g. CAGE-{iid})",
                line,
            )
        mode = "exact_prefix" if oscal and OSCAL_TITLE_LINE.match(line) else "fuzzy"
        cits = extract_line(line, families, title_mode=mode, excluded=internal)
        structured = (
            _structured_oscal_citation(line, families)
            if oscal or with_ids_file
            else None
        )
        if structured is not None and all(c.start != structured.start for c in cits):
            cits.append(structured)
        for cit in cits:
            table = tables.get(cit.standard)
            if table is None:
                continue
            res = _check_citation(table, cit)
            if res is not None:
                yield Violation(
                    rel, lineno, cit.standard, cit.cited, res[0], res[1], line
                )


def _structured_oscal_citation(line: str, families: frozenset[str]) -> Citation | None:
    m = OSCAL_CONTROL_ID.match(line) or OSCAL_WITH_ID_ITEM.match(line)
    if not m:
        return None
    cid = m.group("cid")
    if re.match(r"^A\.\d", cid):
        return Citation(STD_ISO, cid, m.start("cid"), m.end("cid"), cid)
    tm = TOKENS[STD_853][0].fullmatch(cid) or TOKENS[STD_853][1].fullmatch(cid)
    if tm is None:
        return None
    canon = canon_token(STD_853, tm, families)
    if canon is None:
        return None
    return Citation(STD_853, canon, m.start("cid"), m.end("cid"), cid)


def docstring_lines(source: str) -> list[tuple[int, str]]:
    """Return ``(lineno, text)`` for every line of every docstring in ``source``."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = node.body
        if not (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            continue
        start = body[0].value.lineno
        for offset, text in enumerate(body[0].value.value.splitlines()):
            out.append((start + offset, text))
    return out


def scan_map_literals(
    rel: str, source: str, tables: dict[str, Table], families: frozenset[str]
) -> Iterator[Violation]:
    """Check ``*_MAP`` dict literals: values are exact control-title slots."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if not (isinstance(target, ast.Name) and target.id.endswith("_MAP")):
            continue
        if not isinstance(value, ast.Dict):
            continue
        implicit = ISO_CONTROL_MAPS.get(target.id) if rel == ISO_CONTROL_REL else None
        for k, v in zip(value.keys, value.values, strict=True):
            if (
                implicit is not None
                and isinstance(k, ast.Constant)
                and isinstance(k.value, str)
            ):
                yield from _check_map_key(
                    rel, k.lineno, k.value, implicit[0], tables, target.id
                )
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                yield from _check_map_value(
                    rel,
                    v.lineno,
                    v.value,
                    implicit[1] if implicit else None,
                    tables,
                    families,
                )


def _check_map_key(
    rel: str, lineno: int, key: str, std: str, tables: dict[str, Table], map_name: str
) -> Iterator[Violation]:
    context = f"{map_name}[{key!r}]"
    if re.fullmatch(r"SC-\d{1,2}", key):
        yield Violation(
            rel,
            lineno,
            STD_853,
            key,
            ID_COLLISION,
            f"internal STPA constraint {key} is a key of {map_name} (a NIST control "
            f"mapping); write it with a distinguishing prefix (e.g. CAGE-{key})",
            context,
        )
        return
    table = tables.get(std)
    if table is None:
        return
    ev = existence_violation(table, key)
    if ev is not None:
        yield Violation(rel, lineno, std, key, ev[0], ev[1], context)


def _check_map_value(
    rel: str,
    lineno: int,
    value: str,
    implicit_std: str | None,
    tables: dict[str, Table],
    families: frozenset[str],
) -> Iterator[Violation]:
    line = value
    if implicit_std is not None and not ANCHORS[implicit_std].search(value):
        line = f"{_IMPLICIT_ANCHOR_TEXT[implicit_std]} {value}"
    cits = extract_line(line, families, title_mode="exact")
    if implicit_std is not None and not any(c.standard == implicit_std for c in cits):
        yield Violation(
            rel,
            lineno,
            implicit_std,
            value.strip(),
            NONEXISTENT,
            f"'{value}' is in a {implicit_std} slot but is not a {implicit_std} identifier",
            value,
        )
        return
    for cit in cits:
        if implicit_std is not None and cit.standard != implicit_std:
            continue
        table = tables.get(cit.standard)
        if table is None:
            continue
        title = cit.title
        if title is not None:
            cit = Citation(
                cit.standard,
                cit.cited,
                cit.start,
                cit.end,
                cit.raw,
                title,
                True,
                "exact",
            )
        res = _check_citation(table, cit)
        if res is not None:
            yield Violation(rel, lineno, cit.standard, cit.cited, res[0], res[1], value)


_IMPLICIT_ANCHOR_TEXT: Final[dict[str, str]] = {
    STD_853: "NIST SP 800-53",
    STD_EU: "EU AI Act",
    STD_ISO: "ISO/IEC 42001",
}


def scan_framework_mapping(
    rel: str, text: str, std: str, tables: dict[str, Table], families: frozenset[str]
) -> Iterator[Violation]:
    """Check ``control_descriptions`` of a framework mapping (exact titles)."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return
    descs = doc.get("control_descriptions") if isinstance(doc, dict) else None
    if not isinstance(descs, dict):
        return
    lines = text.splitlines()
    for key, desc in descs.items():
        if not isinstance(key, str) or not isinstance(desc, str):
            continue
        lineno = next(
            (
                i
                for i, ln in enumerate(lines, 1)
                if f'"{key}"' in ln and ":" in ln and desc[:20] in ln
            ),
            0,
        )
        key_std = std
        probe = key
        if std == STD_EU and key.startswith("GDPR"):
            key_std = STD_GDPR
        elif not ANCHORS[std].search(key):
            probe = f"{_IMPLICIT_ANCHOR_TEXT.get(std, '')} {key}"
        cits = [
            c
            for c in extract_line(probe, families, title_mode="exact")
            if c.standard == key_std
        ]
        context = f"{key}: {desc}"
        if not cits:
            yield Violation(
                rel,
                lineno,
                key_std,
                key,
                NONEXISTENT,
                f"mapping key '{key}' is not a {key_std} identifier",
                context,
            )
            continue
        cit = cits[0]
        table = tables.get(key_std)
        if table is None:
            continue
        parts = re.split(r"\s+[—\u2013]\s+", desc)
        title_part = parts[0]
        for k in range(1, len(parts) + 1):
            candidate = " — ".join(parts[:k])
            if exact_title_violation(table, cit.cited, candidate, "exact") is None:
                title_part = candidate
                break
        cit = Citation(
            cit.standard,
            cit.cited,
            cit.start,
            cit.end,
            cit.raw,
            title_part,
            True,
            "exact",
        )
        res = _check_citation(table, cit)
        if res is not None:
            yield Violation(rel, lineno, key_std, cit.cited, res[0], res[1], context)


def iter_scan_files(root: Path) -> Iterator[Path]:
    """Yield every in-scope file under ``root``."""
    for name in SCAN_FILES:
        path = root / name
        if path.is_file():
            yield path
    for d in SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in SCAN_SUFFIXES:
                yield path
    src = root / SRC_DIR
    if src.is_dir():
        yield from sorted(p for p in src.rglob("*.py") if p.is_file())


def is_excluded(rel: str) -> bool:
    """Return True for history records and the tables themselves."""
    return any(rel == p or rel.startswith(p) for p in EXCLUDED_PREFIXES)


def scan_repo(root: Path, tables: dict[str, Table]) -> list[Violation]:
    """Scan every in-scope file under ``root`` and return all violations."""
    families = frozenset(
        rid
        for rid, row in tables.get(STD_853, Table(STD_853, "", False, {})).rows.items()
        if re.fullmatch(r"[A-Z]{2}", rid)
    )
    out: list[Violation] = []
    for path in iter_scan_files(root):
        rel = path.relative_to(root).as_posix()
        if is_excluded(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if path.suffix == ".py":
            out.extend(scan_text_lines(rel, docstring_lines(text), tables, families))
            out.extend(scan_map_literals(rel, text, tables, families))
            continue
        if rel.startswith(FRAMEWORK_MAPPINGS_REL + "/"):
            std = FRAMEWORK_MAPPING_STANDARD.get(path.name)
            if std is not None:
                out.extend(scan_framework_mapping(rel, text, std, tables, families))
        oscal = rel.startswith("compliance/oscal/") and path.suffix in (".yaml", ".yml")
        out.extend(
            scan_text_lines(
                rel, enumerate(text.splitlines(), 1), tables, families, oscal=oscal
            )
        )
    return out


# END STANDARD_CITATION_DETECTOR


# ---------------------------------------------------------------------------
# Fingerprint and ratchet
# ---------------------------------------------------------------------------


def compute_detector_fingerprint(
    script_path: Path | None = None, tables_dir: Path | None = None
) -> str:
    """Hash the detector's logical tokens plus the canonical table content.

    Comments, non-logical newlines and docstrings are ignored, so reformatting
    the detector does not move the fingerprint; any change to detector logic,
    constants, scope, or any reference table does.
    """
    path = script_path if script_path is not None else Path(__file__).resolve()
    source = path.read_text(encoding="utf-8")
    start = source.find(_DETECTOR_BEGIN)
    end = source.find(_DETECTOR_END)
    if start < 0 or end <= start:
        raise RuntimeError(f"missing detector sentinels in {path}")
    section = source[start + len(_DETECTOR_BEGIN) : end]
    tree = ast.parse(section)
    doc_starts: set[tuple[int, int]] = set()
    doc_ends: set[int] = set()
    for node in ast.walk(tree):
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
                doc_ends.add(body[0].value.end_lineno or body[0].value.lineno)
    digest = hashlib.sha256()
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.ENCODING, tokenize.ENDMARKER}
    for tok in tokenize.generate_tokens(io.StringIO(section).readline):
        if tok.type in skip:
            continue
        if tok.type == tokenize.STRING and tok.start in doc_starts:
            continue
        if tok.type == tokenize.NEWLINE and tok.start[0] in doc_ends:
            continue
        if tok.type == tokenize.INDENT:
            payload = "INDENT"
        elif tok.type == tokenize.DEDENT:
            payload = "DEDENT"
        elif tok.type == tokenize.NEWLINE:
            payload = "NEWLINE"
        else:
            payload = f"{tok.type}:{tok.string}"
        digest.update(payload.encode("utf-8") + b"\0")
    tdir = tables_dir if tables_dir is not None else REPO_ROOT / TABLES_REL
    digest.update(b"TABLES\0" + tables_digest(tdir).encode("ascii"))
    return digest.hexdigest()


def summarize(counts: dict[str, int]) -> dict[str, dict[str, int]]:
    """Group a ``key -> count`` mapping by standard and class."""
    out: dict[str, dict[str, int]] = {}
    for key, n in counts.items():
        std, _, cls, _ = key.split("|")
        out.setdefault(std, {}).setdefault(cls, 0)
        out[std][cls] += n
    return {s: dict(sorted(c.items())) for s, c in sorted(out.items())}


@dataclass(frozen=True)
class BaselineState:
    """Validated baseline: per-identity counts bound to a detector fingerprint."""

    detector_sha256: str
    violations: dict[str, int]
    history: tuple[dict[str, object], ...]

    @property
    def total(self) -> int:
        """Return the total violation count."""
        return sum(self.violations.values())


def _non_neg_int(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val >= 0


def _validate_history(history: object) -> str | None:
    if not isinstance(history, list) or not history:
        return "history must be a non-empty list"
    prev: dict[str, object] | None = None
    for idx, entry in enumerate(history):
        if not isinstance(entry, dict):
            return f"history[{idx}] must be an object"
        sha = entry.get("detector_sha256")
        reason = entry.get("reason")
        after = entry.get("after_baseline")
        if not isinstance(sha, str) or not sha:
            return f"history[{idx}].detector_sha256 must be a non-empty string"
        if not isinstance(reason, str) or not reason.strip():
            return f"history[{idx}].reason must be a non-empty string"
        if not _non_neg_int(after):
            return f"history[{idx}].after_baseline must be a non-negative integer"
        event = entry.get("event")
        if idx == 0:
            if event != "initial_baseline":
                return f"history[0].event must be 'initial_baseline', got {event!r}"
            if (
                entry.get("before_baseline") is not None
                or entry.get("before_detector_sha256") is not None
            ):
                return "history[0] must set before_baseline and before_detector_sha256 to null"
            prev = entry
            continue
        assert prev is not None
        if event not in ("update", "recompute"):
            return (
                f"history[{idx}].event must be 'update' or 'recompute', got {event!r}"
            )
        if entry.get("before_baseline") != prev.get("after_baseline"):
            return f"history[{idx}].before_baseline does not match history[{idx - 1}].after_baseline"
        if entry.get("before_detector_sha256") != prev.get("detector_sha256"):
            return f"history[{idx}].before_detector_sha256 does not match history[{idx - 1}]"
        before = entry.get("before_baseline")
        if event == "update":
            if sha != entry.get("before_detector_sha256"):
                return f"history[{idx}] ('update') cannot change detector_sha256; use 'recompute'"
            if isinstance(before, int) and isinstance(after, int) and after > before:
                return f"history[{idx}] ('update') raised baseline {before} -> {after}"
        else:
            if sha == entry.get("before_detector_sha256"):
                return (
                    f"history[{idx}] ('recompute') requires a changed detector_sha256"
                )
            if len(reason.strip()) < MIN_RECOMPUTE_REASON_LEN:
                return f"history[{idx}] ('recompute') reason must be >= {MIN_RECOMPUTE_REASON_LEN} chars"
        prev = entry
    return None


def read_baseline(path: Path) -> tuple[BaselineState | None, str | None]:
    """Read and validate the baseline file."""
    if not path.is_file():
        return None, f"missing baseline {path}"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"invalid baseline {path}: {exc}"
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != BASELINE_SCHEMA_VERSION
    ):
        return None, f"unsupported baseline schema in {path}"
    sha = doc.get("detector_sha256")
    violations = doc.get("violations")
    if not isinstance(sha, str) or not sha:
        return None, f"invalid detector_sha256 in {path}"
    if not isinstance(violations, dict) or not all(
        isinstance(k, str) and k.count("|") == 3 and _non_neg_int(v) and v > 0
        for k, v in violations.items()
    ):
        return (
            None,
            f"violations must map 'std|id|class|hash' to positive integers in {path}",
        )
    total = sum(violations.values())
    if doc.get("baseline") != total:
        return (
            None,
            f"baseline ({doc.get('baseline')!r}) != sum(violations) ({total}) in {path}",
        )
    if doc.get("counts") != summarize(violations):
        return None, f"counts do not match violations in {path}"
    err = _validate_history(doc.get("history"))
    if err is not None:
        return None, f"{path}: {err}"
    last = doc["history"][-1]
    if last["after_baseline"] != total or last["detector_sha256"] != sha:
        return (
            None,
            f"{path}: top-level baseline/detector_sha256 disagrees with history[-1]",
        )
    return BaselineState(sha, dict(violations), tuple(doc["history"])), None


def write_baseline(
    path: Path,
    sha: str,
    counts: dict[str, int],
    history: list[dict[str, object]],
) -> None:
    """Write a baseline document and re-validate it."""
    doc = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "detector_sha256": sha,
        "baseline": sum(counts.values()),
        "standing_debt_policy": STANDING_DEBT_POLICY,
        "counts": summarize(counts),
        "violations": dict(sorted(counts.items())),
        "history": history,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    _, err = read_baseline(path)
    if err is not None:
        raise ValueError(f"refusing to write invalid baseline: {err}")


def history_entry(
    event: str,
    sha: str,
    counts: dict[str, int],
    reason: str,
    prev: BaselineState | None,
) -> dict[str, object]:
    """Build one append-only history entry."""
    return {
        "event": event,
        "date": date.today().isoformat(),
        "detector_sha256": sha,
        "before_detector_sha256": prev.detector_sha256 if prev else None,
        "before_baseline": prev.total if prev else None,
        "after_baseline": sum(counts.values()),
        "counts": summarize(counts),
        "reason": reason,
    }


def new_violations(current: dict[str, int], baseline: dict[str, int]) -> dict[str, int]:
    """Return identities whose current count exceeds the baseline count."""
    return {
        k: n - baseline.get(k, 0) for k, n in current.items() if n > baseline.get(k, 0)
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _fmt(v: Violation) -> str:
    return f"{v.path}:{v.line}: [{v.standard}] {v.cited} {v.vclass}: {v.message}"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Standards-citation gate (POAM-2026-247)."
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--tables-dir", type=Path, default=None)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument("--verbose", action="store_true", help="list every violation")
    parser.add_argument(
        "--json", type=Path, default=None, help="write all violations as JSON"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--update-baseline", action="store_true")
    mode.add_argument("--recompute-baseline", action="store_true")
    mode.add_argument("--init-baseline", action="store_true")
    parser.add_argument("--reason", default="")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    tables_dir = args.tables_dir or root / TABLES_REL
    baseline_path = args.baseline or root / BASELINE_REL
    tables, errors = load_tables(tables_dir)
    if errors:
        for err in errors:
            print(f"FAIL: table schema: {err}", file=sys.stderr)
        return 1
    violations = scan_repo(root, tables)
    current = dict(Counter(v.key for v in violations))
    sha = compute_detector_fingerprint(tables_dir=tables_dir)

    if args.json is not None:
        args.json.write_text(
            json.dumps(
                [{**v.__dict__, "key": v.key} for v in violations],
                indent=1,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    if args.verbose:
        for v in violations:
            print(_fmt(v))

    if args.init_baseline:
        if baseline_path.exists():
            print(
                f"FAIL: {baseline_path} exists; use --update-baseline or --recompute-baseline",
                file=sys.stderr,
            )
            return 1
        if len(args.reason.strip()) < MIN_RECOMPUTE_REASON_LEN:
            print(
                f"FAIL: --init-baseline requires --reason (>= {MIN_RECOMPUTE_REASON_LEN} chars)",
                file=sys.stderr,
            )
            return 1
        write_baseline(
            baseline_path,
            sha,
            current,
            [history_entry("initial_baseline", sha, current, args.reason, None)],
        )
        print(f"wrote initial baseline: {sum(current.values())} violations")
        return 0

    state, baseline_err = read_baseline(baseline_path)
    if baseline_err is not None or state is None:
        print(f"FAIL: {baseline_err}", file=sys.stderr)
        return 1

    if args.recompute_baseline:
        if len(args.reason.strip()) < MIN_RECOMPUTE_REASON_LEN:
            print(
                f"FAIL: --recompute-baseline requires --reason (>= {MIN_RECOMPUTE_REASON_LEN} chars)",
                file=sys.stderr,
            )
            return 1
        if sha == state.detector_sha256:
            print(
                "FAIL: detector_sha256 is unchanged; use --update-baseline to lower the ceiling",
                file=sys.stderr,
            )
            return 1
        hist = [
            *state.history,
            history_entry("recompute", sha, current, args.reason, state),
        ]
        write_baseline(baseline_path, sha, current, hist)
        print(f"recomputed baseline: {state.total} -> {sum(current.values())}")
        return 0

    if sha != state.detector_sha256:
        print(
            "FAIL: the detector or a reference table changed (detector_sha256 "
            f"{state.detector_sha256[:12]} -> {sha[:12]}); run --recompute-baseline "
            "--reason '<why>' and review the before/after counts",
            file=sys.stderr,
        )
        return 1

    added = new_violations(current, state.violations)
    if added:
        print(
            f"FAIL: {sum(added.values())} new standards-citation violation(s):",
            file=sys.stderr,
        )
        for v in violations:
            if v.key in added:
                print(f"  {_fmt(v)}", file=sys.stderr)
        return 1

    if args.update_baseline:
        hist = [
            *state.history,
            history_entry(
                "update",
                sha,
                current,
                args.reason.strip() or "lower baseline after corrections",
                state,
            ),
        ]
        write_baseline(baseline_path, sha, current, hist)
        print(f"updated baseline: {state.total} -> {sum(current.values())}")
        return 0

    fixed = state.total - sum(current.values())
    print(
        f"OK: {sum(current.values())} standing standards-citation violations "
        f"(baseline {state.total}); no new violations."
    )
    if fixed > 0:
        print(
            f"  {fixed} baselined violation(s) cleared; run --update-baseline to lower the ceiling."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
