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

"""POA&M closure-evidence & OSCAL claim four-check gate (PR-9).

Replaces legacy control-ID filename matching, ``NON_TESTABLE_CONTROLS``,
``CODE_EVIDENCE_FINDINGS``, and ``CONTROL_ALIASES`` with four deterministic,
waiver-free checks across all six POA&M markdown documents (summary tables AND
``### POAM-...`` detail sections) and all seven structured OSCAL YAML artifacts:

1. **Check 1 - Read-Back, Detail Parity & Finding-ID Binding**:
   Every closed POA&M row and closed ``### POAM-...`` detail section across
   ``docs/POAM.md`` and the four regional POA&M trackers (plus ``POAM_INDEX.md``
   summary parity) must cite at least one resolvable runnable evidence artifact
   (``tests/**/test_*.py`` with ``def test_`` and a PR-CI ``pytest.mark.*``
   marker ``unit``/``local``/``integration``, ``infra/**/*.tftest.hcl`` with
   ``run "``, an ``Active`` Lula v0.16.0 manifest in ``compliance/lula/``, a
   CI-wired ``scripts/check_*.py`` gate, or a workflow explicitly binding the
   finding ID) that explicitly binds ``\b<ID>\b``. Reopened open rows/sections
   must declare explicit ``Closes on`` / ``Closure Criteria``.
2. **Check 2 - Lifetime (``EVIDENCE_STORE_REGISTRY``)**:
   Consults ``EVIDENCE_STORE_REGISTRY`` per sentence/clause across open/in-progress
   closure criteria, closed rows, detail sections, and OSCAL ``HOLDS`` / ``implemented``
   census entries. Rejects short-lived stores (0-day pod-ephemeral ``opa_decision_logs``,
   1-day unlocked staging WORM, 30-day ``_Default``, 400-day ``_Required``, and
   24-month ``gmp_monarch``) for multi-year retention obligations without
   clause-local scoping to the persistent ``>= 2555``-day locked evidence domain.
3. **Check 3 - Custody (``EVIDENCE_STORE_REGISTRY`` ``GOV_WRITABLE`` Rejection)**:
   Consults ``EVIDENCE_STORE_REGISTRY`` per sentence/clause to reject ``GOV_WRITABLE``
   stores (``langfuse_app``, ClickHouse ``infra_events``, bare/shared ``valkey_app``,
   ``opa_decision_logs``, and ``gmp_monarch``) as authoritative or tamper-evident
   audit/decision custody. Only Redis DB 1 ``cage:evidence:stream`` paired with
   GCS/S3 WORM ``EVIDENCE_ARCHIVE_BUCKET`` / ``evidence_domain`` satisfies
   tamper-evident custody-chain claims; ``gmp_monarch`` is operational ``AU-12``/``SI-4``
   plane telemetry (``custody="GOV_WRITABLE"``, ``plane="PLANE"``, ``lifetime="24m"``),
   never non-repudiable ``AU-10`` decision custody.
4. **Check 4 - OSCAL Census Completeness, ``HOLDS`` Path Verification & Parity**:
   Validates 1-to-1 claim extraction, ``description_sha256`` freshness, zero
   ``implemented`` claims with ``WEAKER`` / ``NOT_IN_FORCE`` verdicts, path
   existence on all ``HOLDS`` rows (including non-``implemented`` ``HOLDS``),
   and byte-for-byte parity of ``docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md``.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PRIMARY_POAM_REL = "docs/POAM.md"
POAM_INDEX_REL = "docs/compliance/cross-region/POAM_INDEX.md"
REGIONAL_POAM_RELS: tuple[str, ...] = (
    "docs/compliance/universal/POAM_ISO42001.md",
    "docs/compliance/us_fed/POAM_US_FED.md",
    "docs/compliance/eu_ecb/POAM_EU_ECB.md",
    "docs/compliance/apac_mas/POAM_APAC_MAS.md",
)
LULA_README_REL = "compliance/lula/README.md"
OSCAL_CENSUS_REL = "compliance/oscal/evidence_claim_census.jsonl"
OSCAL_REGISTER_REL = "docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md"

_MIN_WORM_RETENTION_DAYS = 2555


@dataclass(frozen=True)
class EvidenceStoreSpec:
    """Authoritative custody, plane, and retention metadata for an evidence/telemetry store."""

    store_id: str
    custody: str
    plane: str
    lifetime: str
    retention_days: int | None
    locked: bool
    match_re: re.Pattern[str]
    description: str
    custody_qualifier_re: re.Pattern[str] | None = None
    forbidden_custody_controls_re: re.Pattern[str] | None = None


EVIDENCE_STORE_REGISTRY: dict[str, EvidenceStoreSpec] = {
    "persistent_evidence_worm": EvidenceStoreSpec(
        store_id="persistent_evidence_worm",
        custody="PLANE",
        plane="PLANE",
        lifetime="2555d",
        retention_days=2555,
        locked=True,
        match_re=re.compile(
            r"(?:\bEVIDENCE_ARCHIVE_BUCKET\b|\bevidence_domain\b"
            r"|\bpersistent\s+(?:>=\s*2555|\u2265\s*2555|2555[- ]day|locked)\b"
            r"|\blocked\s+(?:log|evidence|WORM)\s+(?:bucket|domain)\b)",
            re.IGNORECASE,
        ),
        description=(
            "Persistent >=2555-day retention-locked GCS/S3 WORM evidence domain "
            "(EVIDENCE_ARCHIVE_BUCKET / evidence_domain, POAM-2026-197)"
        ),
    ),
    "redis_evidence_stream": EvidenceStoreSpec(
        store_id="redis_evidence_stream",
        custody="PLANE",
        plane="PLANE",
        lifetime="hot_stream_to_worm",
        retention_days=None,
        locked=False,
        match_re=re.compile(
            r"(?:\bcage:evidence:stream\b|\bRedis\s+DB\s*1\b|\bdb\s*=\s*1\b|\bEvidenceStream(?:Sink)?\b)",
            re.IGNORECASE,
        ),
        description=(
            "Redis DB 1 cage:evidence:stream hot custody buffer feeding KMS-signed WORM archival"
        ),
    ),
    "staging_workload_worm": EvidenceStoreSpec(
        store_id="staging_workload_worm",
        custody="PLANE",
        plane="PLANE",
        lifetime="1d",
        retention_days=1,
        locked=False,
        match_re=re.compile(
            r"(?:\bstaging\s+(?:workload\s+)?WORM\s+bucket\b"
            r"|\b1-day\s+(?:unlocked\s+)?(?:staging\s+)?(?:workload\s+)?WORM\b"
            r"|\bretention[_A-Za-z]*\s*(?:=|:)\s*86400\b"
            r"|\bevidence-worm-staging\b)",
            re.IGNORECASE,
        ),
        description="Ephemeral 1-day (86400 s) unlocked staging workload WORM bucket (F-94)",
    ),
    "cloud_logging_default": EvidenceStoreSpec(
        store_id="cloud_logging_default",
        custody="PROVIDER",
        plane="PROVIDER",
        lifetime="30d",
        retention_days=30,
        locked=False,
        match_re=re.compile(
            r"(?:\b_Default\b|\bgcloud\s+logging\s+read\b)", re.IGNORECASE
        ),
        description="GCP Cloud Logging _Default bucket (30-day retention, F-88)",
    ),
    "cloud_logging_required": EvidenceStoreSpec(
        store_id="cloud_logging_required",
        custody="PROVIDER",
        plane="PROVIDER",
        lifetime="400d",
        retention_days=400,
        locked=True,
        match_re=re.compile(r"\b_Required\b"),
        description="GCP Cloud Logging _Required Admin Activity bucket (400-day retention, F-88)",
    ),
    "langfuse_app": EvidenceStoreSpec(
        store_id="langfuse_app",
        custody="GOV_WRITABLE",
        plane="APP",
        lifetime="1d",
        retention_days=1,
        locked=False,
        match_re=re.compile(r"\bLangfuse\b", re.IGNORECASE),
        description=(
            "Operational Langfuse telemetry project shared with governed workloads (F-84, F-105)"
        ),
    ),
    "infra_events": EvidenceStoreSpec(
        store_id="infra_events",
        custody="GOV_WRITABLE",
        plane="APP",
        lifetime="mutable",
        retention_days=None,
        locked=False,
        match_re=re.compile(
            r"(?:/v1/infra/events|\binfra_events\b|\bClickHouse\b)",
            re.IGNORECASE,
        ),
        custody_qualifier_re=re.compile(
            r"(?:\bINSERT-only\b|\bcage_evidence_sink\b|\bsink\s+moved\s+to\b"
            r"|\bWORM\s+custody\s+or\s+OSCAL\s+claim\s+retirement\b"
            r"|\bunchained\s+`?/v1/infra/events`?"
            r"|\bnon-authoritative\b|\bnot\s+authoritative\b|\bnot\s+audit\s+custody\b"
            r"|\bGOV_WRITABLE\b)",
            re.IGNORECASE,
        ),
        description="Compliance-bridge /v1/infra/events ClickHouse infra_events sink (F-85)",
    ),
    "valkey_app": EvidenceStoreSpec(
        store_id="valkey_app",
        custody="GOV_WRITABLE",
        plane="APP",
        lifetime="hot",
        retention_days=None,
        locked=False,
        match_re=re.compile(r"\bValkey\b", re.IGNORECASE),
        custody_qualifier_re=re.compile(
            r"(?:\brate[- ]limit|\bcache\b|\bport\s+6379\b|\b6379\b"
            r"|\bMemorystore\s+Valkey\s+instances\b|\bsnapshot\b"
            r"|\bgovernance\s+Valkey\s+AOF\b"
            r"|\bnon-authoritative\b|\bnot\s+authoritative\b|\bnot\s+audit\s+custody\b"
            r"|\bGOV_WRITABLE\b)",
            re.IGNORECASE,
        ),
        description=(
            "Shared/bare Valkey (DB 0) hot keyspace; non-authoritative for tamper-evident custody (F-100)"
        ),
    ),
    "opa_decision_logs": EvidenceStoreSpec(
        store_id="opa_decision_logs",
        custody="GOV_WRITABLE",
        plane="APP",
        lifetime="ephemeral",
        retention_days=0,
        locked=False,
        match_re=re.compile(
            r"(?:\bopa_decision_logs\b|\bOPA\s+decision[_\s]+logs?\b|\bdecision_logs\b)",
            re.IGNORECASE,
        ),
        custody_qualifier_re=re.compile(
            r"(?:\bpod-ephemeral\b|\bephemeral\b|\bno\s+`?decision_logs`?\b"
            r"|\bdecision_logs`?\s+(?:is\s+|are\s+)?(?:not\s+configured|disabled)\b"
            r"|\bwithout\s+WORM\b|\bnon-custody\b|\bnon-authoritative\b"
            r"|\bnot\s+authoritative\b|\bnot\s+audit\s+custody\b|\bGOV_WRITABLE\b)",
            re.IGNORECASE,
        ),
        description="Pod-ephemeral OPA runtime decision_logs without WORM custody (F-19, F-102)",
    ),
    "gmp_monarch": EvidenceStoreSpec(
        store_id="gmp_monarch",
        custody="GOV_WRITABLE",
        plane="PLANE",
        lifetime="24m",
        retention_days=730,
        locked=False,
        match_re=re.compile(
            r"(?:\bgmp_monarch\b|\bGoogle\s+Managed\s+Prometheus\b"
            r"|\bManaged\s+Prometheus\b|\bMonarch\b|\bGMP\b)"
        ),
        custody_qualifier_re=re.compile(
            r"(?:\boperational(?:\s+telemetry|\s+metrics?|\s+health)?\b"
            r"|\btelemetry[- ]only\b|\btelemetry\s+only\b"
            r"|\bPodMonitoring\b|\bscrape\b|\bscraping\b"
            r"|\bAU-12\b|\bSI-4\b|\bnon-authoritative\b"
            r"|\bnot\s+authoritative\b|\bnot\s+audit\s+custody\b"
            r"|\bnot\s+non[- ]repudiable\b|\bnot\s+decision\s+custody\b|\bGOV_WRITABLE\b)",
            re.IGNORECASE,
        ),
        forbidden_custody_controls_re=re.compile(
            r"(?:\bAU-10\b|\bnon[- ]repudiat)",
            re.IGNORECASE,
        ),
        description=(
            "Google Managed Prometheus / Monarch operational AU-12/SI-4 plane telemetry "
            "(custody=GOV_WRITABLE, plane=PLANE, lifetime=24m; never non-repudiable AU-10 custody)"
        ),
    ),
}


@dataclass(frozen=True)
class PoamRow:
    """Normalized representation of a summary-table row or detail section in a POA&M file."""

    source_rel: str
    line_number: int
    finding_id: str
    control: str
    status: str  # "open" | "in_progress" | "closed" | "accepted_risk"
    severity: str
    description: str
    milestone: str
    closed_date: str = ""
    is_detail_section: bool = False

    @property
    def full_text(self) -> str:
        return f"{self.description} {self.milestone}".strip()


class _DuplicateKeyRejectingLoader(yaml.SafeLoader):
    """YAML SafeLoader that raises ConstructorError on duplicate mapping keys."""


def _construct_no_dup_mapping(
    loader: _DuplicateKeyRejectingLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate YAML key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_DuplicateKeyRejectingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_no_dup_mapping,
)

_POAM_RANGE_HEADER_RE = re.compile(
    r"^###\s+(POAM-\d{4}-\d+)\s+to\s+(POAM-\d{4}-\d+)\b",
    re.MULTILINE,
)
_POAM_LIST_HEADER_RE = re.compile(
    r"^###\s+(POAM-\d{4}-\d+(?:-[A-Z])?(?:\s*,\s*(?:and\s+)?POAM-\d{4}-\d+(?:-[A-Z])?|\s+and\s+POAM-\d{4}-\d+(?:-[A-Z])?)+)\b",
    re.MULTILINE,
)
_POAM_HEADER_RE = re.compile(
    r"^###\s+((?:POAM-\d{4}-\d+(?:-[A-Z])?|CAGE-SEC-\d+))\b",
    re.MULTILINE,
)

_RUNNABLE_PATH_RE = re.compile(
    r"(?:\.\./)*("
    r"tests/[A-Za-z0-9_./-]+\.py"
    r"|infra/[A-Za-z0-9_./-]+\.tftest\.hcl"
    r"|compliance/lula/lula-validation-[A-Za-z0-9_-]+\.yaml"
    r"|scripts/check_[A-Za-z0-9_]+\.py"
    r"|\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml"
    r")"
)
_PINNED_RUNNABLE_PREFIX_RE = re.compile(r"[0-9a-f]{7,40}\^?:$")
_OBSERVED_RECORD_RE = re.compile(
    r"\bObserved\s+\d{4}-\d{2}-\d{2}:\s+[^|;\n]+?(?:->|\u2192)\s+[^|;\n]+"
)
_TEST_FN_RE = re.compile(
    r"^\s*(?:async\s+)?def\s+test_[A-Za-z0-9_]*\s*\(", re.MULTILINE
)
_PR_CI_PYTEST_MARKER_RE = re.compile(r"pytest\.mark\.(?:unit|local|integration)\b")
_TFTEST_RUN_RE = re.compile(r'^\s*run\s+"[^"]+"\s*\{', re.MULTILINE)

# Controls requiring authoritative multi-year tamper-evident custody & retention.
_AUDIT_RETENTION_CTRL_RE = re.compile(
    r"(?:"
    r"\bAU-(?:2|3|9|10|11|12)\b"
    r"|\bSC-12\b"
    r"|\bMAS\s+Notice\s+655\b"
    r"|\bEU\s+AI\s+Act\s+Art\.\s*12\b"
    r"|\bA\.5\.3\b"
    r"|\bDORA\s+Art\.\s*10\b"
    r")",
    re.IGNORECASE,
)
_WORM_RETENTION_CTRL_RE = re.compile(
    r"(?:\bAU-(?:9|11)\b|\bMAS\s+Notice\s+655\b|\bEU\s+AI\s+Act\s+Art\.\s*12\b)",
    re.IGNORECASE,
)
_AUDIT_CUSTODY_CTRL_RE = re.compile(
    r"(?:"
    r"\bAU-(?:2|3|9|10|11|12)\b"
    r"|\bMAS\s+Notice\s+655\b"
    r"|\bEU\s+AI\s+Act\s+Art\.\s*12\b"
    r"|\bA\.5\.3\b"
    r")",
    re.IGNORECASE,
)

# Forbidden unqualified GOV_WRITABLE durability/tamper-evidence assertions on ANY clause.
_UNCONDITIONAL_GOV_WRITABLE_CLAIM_RE = re.compile(
    r"(?:"
    r"\bpersisted\s+to\s+Langfuse\s+backend\b"
    r"|\bLangfuse\s+(?:provides|satisfies|enforces|serves\s+as|is\s+the)\s+(?:authoritative\s+|immutable\s+|tamper[- ]evident\s+|non[- ]repudiable\s+)?(?:audit|custody|durability)\b"
    r"|\bimmutable\s+Langfuse\s+audit\b"
    r"|\bauthoritative\s+(?:AU-\d+\s+|audit\s+|decision\s+)?(?:records?|logs?|custody|durability)\s+in\s+(?:Langfuse|Valkey|ClickHouse|infra_events|OPA|GMP|Monarch|Managed\s+Prometheus)\b"
    r"|(?:/v1/infra/events|\binfra_events\b|\bClickHouse(?:\s+`?infra_events`?)?)\s+(?:provides|satisfies|enforces|serves\s+as|is\s+the)\s+(?:authoritative|immutable|tamper[- ]evident|non[- ]repudiable|WORM)\b"
    r"|\b(?:tamper[- ]evident|non[- ]repudiable|immutable|WORM|authoritative)\s+(?:audit\s+|decision\s+)?(?:custody|trail|records?|logs?|durability)\s+(?:in|via|through|backed\s+by|on)\s+(?:`?Langfuse`?|`?/v1/infra/events`?|`?infra_events`?|ClickHouse(?:\s+`?infra_events`?)?|(?:shared\s+|application\s+|app\s+)?`?Valkey`?|OPA\s+`?decision_logs`?|`?opa_decision_logs`?|`?gmp_monarch`?|GMP|Monarch|Managed\s+Prometheus)\b"
    r"|\b(?:(?:application|app|shared)\s+)?Valkey\s+(?:provides|satisfies|enforces|serves\s+as|is\s+the)\s+(?:authoritative|immutable|tamper[- ]evident|non[- ]repudiable|WORM|audit\s+durability|audit\s+custody)\b"
    r"|\b(?:OPA\s+`?decision_logs`?|`?opa_decision_logs`?)\s+(?:provides?|satisf(?:y|ies)|enforces?|serves?\s+as|is\s+the)\s+(?:authoritative|immutable|tamper[- ]evident|non[- ]repudiable|durable|WORM|audit\s+custody)\b"
    r"|\b(?:`?gmp_monarch`?|GMP|Monarch|(?:Google\s+)?Managed\s+Prometheus)\s+(?:provides|satisfies|enforces|serves\s+as|is\s+the)\s+(?:non[- ]repudiable|AU-10|tamper[- ]evident\s+decision|authoritative\s+(?:AU-10|decision))\b"
    r")",
    re.IGNORECASE,
)

# Authoritative custody-chain qualification for Redis DB 1 + WORM archival.
_AUTHORITATIVE_CUSTODY_CHAIN_RE = re.compile(
    r"(?:\bcage:evidence:stream\b|\bRedis\s+DB\s*1\b|\bdb\s*=\s*1\b|\bEvidenceStream(?:Sink)?\b)"
    r"[\s\S]*?(?:\bEVIDENCE_ARCHIVE_BUCKET\b|\bevidence_domain\b|\bWORM\b)",
    re.IGNORECASE,
)

# Clause-scoped operational telemetry / non-custody qualifier (NEVER applied across full_text).
_TELEMETRY_QUALIFIER_RE = re.compile(
    r"(?:"
    r"operational\s+telemetry"
    r"|telemetry[- ]only"
    r"|telemetry\s+only"
    r"|telemetry[- ]startup"
    r"|startup/health\s+validation\s+only"
    r"|telemetry\s+credentials"
    r"|telemetry\s+project"
    r"|telemetry\s+isolation"
    r"|telemetry\s+TTLs?"
    r"|compliance\s+telemetry/reports"
    r"|non-authoritative"
    r"|not\s+authoritative"
    r"|not\s+audit\s+custody"
    r"|not\s+decision\s+custody"
    r"|GOV_WRITABLE"
    r"|scoped\s+out\s+of"
    r"|EvidenceStream(?:Sink)?`?\s*(?:\u2192|->)\s*(?:persistent\s+|KMS[- ]signed\s+|KMS\s+|locked\s+)*WORM"
    r")",
    re.IGNORECASE,
)

_NEGATED_DECISION_CUSTODY_RE = re.compile(
    r"(?:"
    r"\bnot\s+(?:non[- ]repudiable|AU-10|decision\s+custody|audit\s+custody|authoritative)\b"
    r"|\bnever\s+(?:non[- ]repudiable|AU-10|decision\s+custody)\b"
    r"|\bdoes\s+not\s+(?:satisfy|provide|establish)\s+(?:AU-10|non[- ]repudiat|decision\s+custody)\b"
    r"|\bauthoritative\s+AU-10[^.;]*\buses\s+`?EvidenceStream"
    r")",
    re.IGNORECASE,
)

_TAMPER_CUSTODY_ASSERTION_RE = re.compile(
    r"(?:\btamper[- ]evident\b|\bnon[- ]repudiab|\bimmutable\s+audit\b|\bauthoritative\s+(?:audit|decision|custody)\b|\bcustody\s+chain\b)",
    re.IGNORECASE,
)

_PERSISTENT_RETENTION_QUALIFIER_RE = re.compile(
    r"(?:POAM-2026-197|2555[- ]day|2555\s*d\b|>=\s*2555|\u2265\s*2555|persistent\s+locked|locked\s+(?:log|evidence|WORM)\s+(?:bucket|domain)|EVIDENCE_ARCHIVE_BUCKET|evidence_domain)",
    re.IGNORECASE,
)

_NEGATED_STAGING_WORM_RE = re.compile(
    r"(?:never\s+the\s+1-day|not\s+the\s+1-day|does\s+not\s+close|unsigned\s+attestations|non-evidentiary|vs\.\s*2555[- ]day|diverges\s+from)",
    re.IGNORECASE,
)

_NEGATED_EPHEMERAL_LOG_RE = re.compile(
    r"(?:no\s+`?decision_logs`?|not\s+configured|disabled|pod-ephemeral|ephemeral|without\s+WORM|not\s+audit\s+custody|non-custody)",
    re.IGNORECASE,
)

_REOPENED_MARKER_RE = re.compile(
    r"\b(?:Reopened|Closure\s+withdrawn)\b",
    re.IGNORECASE,
)

_CLOSURE_CLAUSE_SPLIT_RE = re.compile(
    r"(?:\bCloses\s+(?:only\s+)?(?:on|when|with|after)\b:?"
    r"|\bRemains\s+Open\s+(?:pending|until)\b:?"
    r"|\b(?:Remaining\s+)?Closure\s+Criteria\b:?"
    r"|\bRemediation(?:\s+Plan)?\s*:)",
    re.IGNORECASE,
)

# Clauses that solely recount a historical rejected closure rather than current/target posture.
_HISTORICAL_CLOSURE_CLAUSE_RE = re.compile(
    r"(?:\bPreviously\s+closed\b|\bOriginally\s+closed\b|\bPrior\s+closure\b"
    r"|\bClosure\s+withdrawn\b|\bwas\s+closed\s+on\b|\bdeprecated\b)",
    re.IGNORECASE,
)


def _expand_poam_range(start_id: str, end_id: str) -> list[str]:
    m_start = re.fullmatch(r"(POAM-\d{4}-)(\d+)", start_id)
    m_end = re.fullmatch(r"(POAM-\d{4}-)(\d+)", end_id)
    if not m_start or not m_end or m_start.group(1) != m_end.group(1):
        return [start_id, end_id]
    prefix = m_start.group(1)
    width = len(m_start.group(2))
    lo = int(m_start.group(2))
    hi = int(m_end.group(2))
    if hi < lo or (hi - lo) > 50:
        return [start_id, end_id]
    return [f"{prefix}{num:0{width}d}" for num in range(lo, hi + 1)]


def split_md_row(line: str) -> list[str]:
    """Split a Markdown table row on unescaped ``|`` outside inline backticks."""
    cols: list[str] = []
    cur: list[str] = []
    in_code = False
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    for idx, ch in enumerate(s):
        if ch == "`":
            in_code = not in_code
            cur.append(ch)
        elif ch == "|" and not in_code and (idx == 0 or s[idx - 1] != "\\"):
            cols.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    cols.append("".join(cur).strip())
    return cols


def _is_separator_row(cols: list[str]) -> bool:
    return bool(cols) and all(
        re.fullmatch(r":?-{2,}:?", c.strip()) is not None for c in cols
    )


def _extract_grouped_header_ids(heading_line: str) -> list[str] | None:
    range_m = _POAM_RANGE_HEADER_RE.match(heading_line)
    if range_m:
        return _expand_poam_range(range_m.group(1), range_m.group(2))
    list_m = _POAM_LIST_HEADER_RE.match(heading_line)
    if list_m:
        return re.findall(r"POAM-\d{4}-\d+(?:-[A-Z])?", list_m.group(1))
    return None


def find_duplicate_poam_headers(poam_text: str) -> list[str]:
    """Return sorted POAM IDs appearing in more than one ``### POAM-YYYY-NNN`` heading."""
    seen: set[str] = set()
    duplicates: set[str] = set()
    grouped_spans: list[tuple[int, int]] = []
    for rmatch in _POAM_RANGE_HEADER_RE.finditer(poam_text):
        grouped_spans.append((rmatch.start(), rmatch.end()))
        for pid in _expand_poam_range(rmatch.group(1), rmatch.group(2)):
            if pid in seen:
                duplicates.add(pid)
            seen.add(pid)
    for lmatch in _POAM_LIST_HEADER_RE.finditer(poam_text):
        if any(lo <= lmatch.start() < hi for lo, hi in grouped_spans):
            continue
        grouped_spans.append((lmatch.start(), lmatch.end()))
        for pid in re.findall(r"POAM-\d{4}-\d+(?:-[A-Z])?", lmatch.group(1)):
            if pid in seen:
                duplicates.add(pid)
            seen.add(pid)
    for match in _POAM_HEADER_RE.finditer(poam_text):
        if any(lo <= match.start() < hi for lo, hi in grouped_spans):
            continue
        poam_id = match.group(1)
        if poam_id in seen:
            duplicates.add(poam_id)
        seen.add(poam_id)
    return sorted(duplicates)


def parse_closed_findings(poam_text: str) -> list[dict[str, str]]:
    """Extract summary rows from ``## Closed Findings`` in ``docs/POAM.md``."""
    rows, _ = _parse_primary_poam_text(poam_text, PRIMARY_POAM_REL)
    return [
        {
            "id": r.finding_id,
            "control": r.control,
            "description": r.description,
            "closed": r.closed_date,
        }
        for r in rows
        if r.status == "closed" and not r.is_detail_section
    ]


def _clean_status(raw: str) -> str:
    cleaned = re.sub(r"[*_`\u2705\U0001f504\U0001f7e1\u2b1c]+", "", raw).strip().lower()
    cleaned = " ".join(cleaned.split())
    if cleaned == "open":
        return "open"
    if cleaned in {"in progress", "in-progress"}:
        return "in_progress"
    if cleaned == "closed":
        return "closed"
    return cleaned


def _clean_detail_status(raw: str) -> str:
    low = re.sub(r"\([^)]*(?:originally|previously)[^)]*\)", " ", raw.lower())
    if "pending merge" in low or "moves to closed" in low:
        return "open"
    if "reopened" in low or re.search(r"\bopen\b", low):
        if (
            re.match(r"^[^a-z]*closed\b", low)
            and "reopened" not in low
            and "withdrawn" not in low
        ):
            return "closed"
        return "open"
    if "accepted risk" in low:
        return "accepted_risk"
    if "in progress" in low or "in-progress" in low:
        return "in_progress"
    if "closed" in low:
        return "closed"
    return _clean_status(raw)


def _clean_cell_int(raw: str) -> int | None:
    cleaned = re.sub(r"[*_`]+", "", raw).strip()
    return int(cleaned) if cleaned.isdigit() else None


def _parse_primary_detail_sections(
    poam_text: str,
    source_rel: str,
    summary_by_id: dict[str, PoamRow],
) -> tuple[list[PoamRow], list[str]]:
    """Parse all ``### POAM-...`` detail sections in ``docs/POAM.md`` (Bypass 3)."""
    errors: list[str] = []
    detail_rows: list[PoamRow] = []

    heading_re = re.compile(
        r"^###\s+((?:POAM-\d{4}-\d+(?:-[A-Z])?|CAGE-SEC-\d+).*)$",
        re.MULTILINE,
    )
    matches = list(heading_re.finditer(poam_text))
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(poam_text)
        next_h2 = re.search(r"^##\s+", poam_text[match.end() : end], re.MULTILINE)
        if next_h2:
            end = match.end() + next_h2.start()
        body = poam_text[match.end() : end].strip()
        line_no = poam_text[:start].count("\n") + 1
        heading_line = poam_text[start : match.end()].strip()

        expected_ids = _extract_grouped_header_ids(heading_line)
        if expected_ids is not None:
            sub_header: list[str] = []
            sub_rows_by_id: dict[str, tuple[int, str, str, str]] = {}
            body_lines = body.splitlines()
            for sub_offset, bline in enumerate(body_lines, start=1):
                bstripped = bline.strip()
                if not bstripped.startswith("|"):
                    if sub_header and sub_rows_by_id:
                        break
                    continue
                bcols = split_md_row(bstripped)
                if _is_separator_row(bcols):
                    continue
                if bcols and bcols[0].strip().lower() == "id":
                    sub_header = [c.strip().lower() for c in bcols]
                    continue
                if sub_header and len(bcols) >= 4:
                    sfid = re.sub(r"[*_`]+", "", bcols[0]).strip()
                    sctrl = bcols[1].strip()
                    ssev = re.sub(r"[*_`]+", "", bcols[2]).strip()
                    sst = _clean_detail_status(bcols[3])
                    sub_rows_by_id[sfid] = (line_no + sub_offset, sctrl, ssev, sst)

            for efid in expected_ids:
                if efid not in sub_rows_by_id:
                    errors.append(
                        f"[Check 1: Detail Parity] {source_rel}:{line_no}: grouped section "
                        f"{heading_line!r} omits status row for {efid}"
                    )
                    continue
                sline, sctrl, ssev, sst = sub_rows_by_id[efid]
                srow = summary_by_id.get(efid)
                if srow is None:
                    errors.append(
                        f"[Check 1: Detail Parity] {source_rel}:{sline} ({efid}): detail section "
                        f"has no matching summary-table row in {source_rel}"
                    )
                else:
                    norm_sum = (
                        "open"
                        if srow.status in {"open", "in_progress"}
                        else srow.status
                    )
                    norm_det = "open" if sst in {"open", "in_progress"} else sst
                    if norm_sum != norm_det:
                        errors.append(
                            f"[Check 1: Detail Parity] {source_rel}:{sline} ({efid}): detail status "
                            f"{sst!r} diverges from summary-table status {srow.status!r} (line {srow.line_number})"
                        )
                # Scope numbered item for this ID if present, plus shared Verification footer.
                item_pat = re.compile(
                    r"(?:^\d+\.\s+\*\*"
                    + re.escape(efid)
                    + r"\b[\s\S]*?)(?=^\d+\.\s+\*\*POAM-|\Z)",
                    re.MULTILINE,
                )
                item_m = item_pat.search(body)
                verif_m = re.search(r"^\*\*Verification\b[\s\S]*$", body, re.MULTILINE)
                scoped_desc = (
                    f"{item_m.group(0) if item_m else body}\n{verif_m.group(0) if verif_m else ''}"
                ).strip()
                detail_rows.append(
                    PoamRow(
                        source_rel=source_rel,
                        line_number=sline,
                        finding_id=efid,
                        control=sctrl or (srow.control if srow else ""),
                        status=sst,
                        severity=ssev,
                        description=scoped_desc,
                        milestone="",
                        is_detail_section=True,
                    )
                )
            continue

        id_m = _POAM_HEADER_RE.match(heading_line)
        if not id_m:
            continue
        fid = id_m.group(1)
        ctrl_m = re.search(r"\*\*Control:\*\*\s*([^\n]+)", body)
        status_m = re.search(r"\*\*Status:\*\*\s*([^\n]+)", body)
        sev_m = re.search(r"\*\*Severity:\*\*\s*([^\n]+)", body)

        srow = summary_by_id.get(fid)
        if status_m is None:
            errors.append(
                f"[Check 1: Detail Parity] {source_rel}:{line_no} ({fid}): detail section "
                f"lacks explicit '**Status:**' metadata line"
            )
            detail_status = srow.status if srow else "open"
        else:
            detail_status = _clean_detail_status(status_m.group(1))

        if detail_status not in {"open", "in_progress", "closed", "accepted_risk"}:
            errors.append(
                f"[Check 1: Detail Parity] {source_rel}:{line_no} ({fid}): unrecognized "
                f"detail section status {status_m.group(1) if status_m else detail_status!r}"
            )
            continue

        if srow is None:
            errors.append(
                f"[Check 1: Detail Parity] {source_rel}:{line_no} ({fid}): detail section "
                f"(status={detail_status!r}) has no matching summary-table row in {source_rel}"
            )
        else:
            norm_sum = "open" if srow.status in {"open", "in_progress"} else srow.status
            norm_det = (
                "open" if detail_status in {"open", "in_progress"} else detail_status
            )
            if norm_sum != norm_det:
                errors.append(
                    f"[Check 1: Detail Parity] {source_rel}:{line_no} ({fid}): detail section "
                    f"status {detail_status!r} diverges from summary-table status "
                    f"{srow.status!r} (line {srow.line_number})"
                )

        ctrl_val = (
            ctrl_m.group(1).strip()
            if ctrl_m is not None
            else (srow.control if srow is not None else "")
        )
        sev_val = (
            sev_m.group(1).strip()
            if sev_m is not None
            else (srow.severity if srow is not None else "")
        )
        detail_rows.append(
            PoamRow(
                source_rel=source_rel,
                line_number=line_no,
                finding_id=fid,
                control=ctrl_val,
                status=detail_status,
                severity=sev_val,
                description=body,
                milestone="",
                is_detail_section=True,
            )
        )

    return detail_rows, errors


def _parse_primary_poam_text(
    poam_text: str, source_rel: str = PRIMARY_POAM_REL
) -> tuple[list[PoamRow], list[str]]:
    errors: list[str] = []
    rows: list[PoamRow] = []

    dup_headers = find_duplicate_poam_headers(poam_text)
    if dup_headers:
        errors.append(
            f"[Check 1: Schema] Duplicate ### POAM headers in {source_rel}: "
            f"{', '.join(dup_headers)}"
        )

    section: str | None = None
    subsection = ""
    header: list[str] = []
    seen_in_scope: dict[tuple[str, str], dict[str, int]] = {}
    seen_open: dict[str, int] = {}
    seen_closed: dict[str, int] = {}
    summary_by_id: dict[str, PoamRow] = {}

    for line_idx, line in enumerate(poam_text.splitlines(), start=1):
        stripped = line.strip()
        if re.match(r"^##\s+Open Findings\b", stripped):
            section = "open"
            subsection = "open_root"
            header = []
            continue
        if re.match(r"^##\s+Accepted Risks\b", stripped):
            section = "accepted_risk"
            subsection = "accepted_risk"
            header = []
            continue
        if re.match(r"^##\s+Closed Findings\b", stripped):
            section = "closed"
            subsection = "closed"
            header = []
            continue
        if stripped.startswith("## ") and section is not None:
            section = None
            subsection = ""
            header = []
            continue
        # Stop Closed Findings summary-table scan once ### POAM-... detail sections begin.
        if section == "closed" and (
            _POAM_HEADER_RE.match(stripped)
            or _POAM_RANGE_HEADER_RE.match(stripped)
            or _POAM_LIST_HEADER_RE.match(stripped)
        ):
            section = None
            subsection = ""
            header = []
            continue
        if section is None or not stripped.startswith("|"):
            if stripped.startswith("### "):
                subsection = stripped
                header = []
            continue

        cols = split_md_row(stripped)
        if _is_separator_row(cols):
            continue
        if cols and cols[0].strip().lower() == "id":
            header = [c.strip().lower() for c in cols]
            continue
        if not header:
            continue

        if section == "open":
            if len(cols) < 5:
                errors.append(
                    f"[Check 1: Schema] {source_rel}:{line_idx}: malformed Open Findings row "
                    f"(expected 5 columns, got {len(cols)})"
                )
                continue
            fid = cols[0].strip("* `")
            row = PoamRow(
                source_rel=source_rel,
                line_number=line_idx,
                finding_id=fid,
                control=cols[1].strip(),
                status="open",
                severity=cols[3].strip("* "),
                description=cols[2].strip(),
                milestone="",
            )
            seen_open.setdefault(fid, line_idx)
        elif section == "accepted_risk":
            if len(cols) < 4:
                continue
            fid = cols[0].strip("* `")
            row = PoamRow(
                source_rel=source_rel,
                line_number=line_idx,
                finding_id=fid,
                control=cols[1].strip(),
                status="accepted_risk",
                severity="",
                description=cols[2].strip(),
                milestone="",
            )
            summary_by_id.setdefault(fid, row)
            continue
        else:
            if len(cols) < 4:
                errors.append(
                    f"[Check 1: Schema] {source_rel}:{line_idx}: malformed Closed Findings row "
                    f"(expected 4 columns, got {len(cols)})"
                )
                continue
            fid = cols[0].strip("* `")
            row = PoamRow(
                source_rel=source_rel,
                line_number=line_idx,
                finding_id=fid,
                control=cols[1].strip(),
                status="closed",
                severity="",
                description=cols[2].strip(),
                milestone="",
                closed_date=cols[3].strip(),
            )
            seen_closed.setdefault(fid, line_idx)
            if fid in seen_open:
                errors.append(
                    f"[Check 1: Schema] {source_rel}:{line_idx}: finding {fid!r} appears in both "
                    f"Open Findings (line {seen_open[fid]}) and Closed Findings"
                )

        scope_map = seen_in_scope.setdefault((section, subsection), {})
        if fid in scope_map:
            errors.append(
                f"[Check 1: Schema] {source_rel}:{line_idx}: duplicate table row ID {fid!r} "
                f"(first seen at line {scope_map[fid]})"
            )
        else:
            scope_map[fid] = line_idx
        summary_by_id.setdefault(fid, row)
        rows.append(row)

    detail_rows, detail_errs = _parse_primary_detail_sections(
        poam_text, source_rel, summary_by_id
    )
    errors.extend(detail_errs)
    rows.extend(r for r in detail_rows if r.status != "accepted_risk")

    return rows, errors


def _parse_regional_poam_file(
    path: Path, source_rel: str
) -> tuple[list[PoamRow], list[str]]:
    errors: list[str] = []
    rows: list[PoamRow] = []
    text = path.read_text(encoding="utf-8")

    in_summary = False
    summary_counts: dict[str, int] = {}
    header: list[str] = []
    seen_ids: dict[str, int] = {}

    for line_idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if re.match(r"^##\s+POA&M Summary\b", stripped):
            in_summary = True
            header = []
            continue
        if stripped.startswith("## ") and not re.match(
            r"^##\s+POA&M Summary\b", stripped
        ):
            in_summary = False

        if not stripped.startswith("|"):
            if stripped.startswith("#"):
                header = []
            continue

        cols = split_md_row(stripped)
        if _is_separator_row(cols):
            continue

        if in_summary and len(cols) >= 2:
            metric = re.sub(r"[*_`]+", "", cols[0]).strip().lower()
            total_val = _clean_cell_int(cols[-1])
            if total_val is not None and metric in {
                "total items",
                "total entries",
                "open",
                "in progress",
                "closed",
            }:
                key = (
                    "total" if metric.startswith("total") else metric.replace(" ", "_")
                )
                summary_counts[key] = total_val
            continue

        if "POA&M ID" in stripped and "Status" in stripped:
            header = [c.strip() for c in cols]
            continue
        if not header:
            continue

        if len(cols) != len(header):
            errors.append(
                f"[Check 1: Schema] {source_rel}:{line_idx}: column count {len(cols)} != "
                f"header count {len(header)}"
            )
            continue

        row_map = dict(zip(header, cols, strict=True))
        fid = re.sub(r"[*_`]+", "", row_map.get("POA&M ID", "")).strip()
        if not fid:
            errors.append(f"[Check 1: Schema] {source_rel}:{line_idx}: empty POA&M ID")
            continue

        status_norm = _clean_status(row_map.get("Status", ""))
        if status_norm not in {"open", "in_progress", "closed"}:
            errors.append(
                f"[Check 1: Schema] {source_rel}:{line_idx} ({fid}): invalid Status "
                f"{row_map.get('Status')!r}"
            )
            continue

        control_val = (
            row_map.get("Control ID")
            or row_map.get("ISO 42001 Control")
            or row_map.get("Primary Framework")
            or ""
        )
        severity = re.sub(r"[*_`]+", "", row_map.get("Risk Level", "")).strip()
        r_obj = PoamRow(
            source_rel=source_rel,
            line_number=line_idx,
            finding_id=fid,
            control=control_val.strip(),
            status=status_norm,
            severity=severity,
            description=row_map.get("Weakness Description", "").strip(),
            milestone=row_map.get("Milestone", "").strip(),
        )
        if fid in seen_ids:
            errors.append(
                f"[Check 1: Schema] {source_rel}:{line_idx}: duplicate POA&M ID {fid!r} in {source_rel}"
            )
        else:
            seen_ids[fid] = line_idx
        rows.append(r_obj)

    actual = {
        "total": len(rows),
        "open": sum(1 for r in rows if r.status == "open"),
        "in_progress": sum(1 for r in rows if r.status == "in_progress"),
        "closed": sum(1 for r in rows if r.status == "closed"),
    }
    for key, declared in summary_counts.items():
        if actual[key] != declared:
            errors.append(
                f"[Check 1: Index Parity] {source_rel}: POA&M Summary '{key}' declares "
                f"{declared}, parsed {actual[key]}"
            )

    return rows, errors


def _audit_poam_index(
    repo_root: Path, regional_by_file: dict[str, list[PoamRow]]
) -> list[str]:
    errors: list[str] = []
    idx_path = repo_root / POAM_INDEX_REL
    if not idx_path.is_file():
        return [f"[Check 1: Scope] Missing required POA&M index: {POAM_INDEX_REL}"]

    text = idx_path.read_text(encoding="utf-8")
    in_registry = False
    in_xref = False
    seen_files: set[str] = set()
    raw_totals_row: tuple[int, int, int, int] | None = None
    dedup_totals_row: tuple[int, int, int, int] | None = None
    same_weakness_ids: set[str] = set()

    for line_idx, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if re.match(r"^##\s+File Registry\b", s):
            in_registry = True
            in_xref = False
            continue
        if re.match(r"^##\s+Cross-Reference Matrix\b", s):
            in_registry = False
            in_xref = True
            continue
        if s.startswith("## "):
            in_registry = False
            in_xref = False
            continue
        if not s.startswith("|"):
            continue
        cols = split_md_row(s)
        if _is_separator_row(cols):
            continue

        if in_xref and len(cols) >= 4:
            entry_id = re.sub(r"[*_`]+", "", cols[0]).strip()
            rel_desc = cols[3].strip().lower()
            if entry_id.lower() != "entry" and "same weakness" in rel_desc:
                same_weakness_ids.add(entry_id)
            continue

        if not in_registry or len(cols) < 7:
            continue
        if cols[0].strip().lower() == "file":
            continue

        c_entries = _clean_cell_int(cols[3])
        c_open = _clean_cell_int(cols[4])
        c_inprog = _clean_cell_int(cols[5])
        c_closed = _clean_cell_int(cols[6])
        if None in (c_entries, c_open, c_inprog, c_closed):
            continue
        assert (
            c_entries is not None
            and c_open is not None
            and c_inprog is not None
            and c_closed is not None
        )

        label_clean = re.sub(r"[*_`]+", "", cols[0]).strip().lower()
        if "raw row sum" in label_clean:
            raw_totals_row = (c_entries, c_open, c_inprog, c_closed)
            continue
        if "deduplicated" in label_clean:
            dedup_totals_row = (c_entries, c_open, c_inprog, c_closed)
            continue
        if "total" in label_clean:
            continue

        matched_rel: str | None = None
        for rel in REGIONAL_POAM_RELS:
            if Path(rel).name in cols[0]:
                matched_rel = rel
                break
        if matched_rel is None:
            continue

        seen_files.add(matched_rel)
        frows = regional_by_file.get(matched_rel, [])
        exp = (
            len(frows),
            sum(1 for r in frows if r.status == "open"),
            sum(1 for r in frows if r.status == "in_progress"),
            sum(1 for r in frows if r.status == "closed"),
        )
        got = (c_entries, c_open, c_inprog, c_closed)
        if got != exp:
            errors.append(
                f"[Check 1: Index Parity] {POAM_INDEX_REL}:{line_idx}: File Registry counts for "
                f"{matched_rel} are {got} (Entries/Open/InProgress/Closed), expected {exp}"
            )

    missing_in_index = sorted(set(REGIONAL_POAM_RELS) - seen_files)
    for mrel in missing_in_index:
        errors.append(
            f"[Check 1: Index Parity] {POAM_INDEX_REL}: regional tracker {mrel} missing from File Registry"
        )

    all_reg = [r for rel in REGIONAL_POAM_RELS for r in regional_by_file.get(rel, [])]
    exp_raw = (
        len(all_reg),
        sum(1 for r in all_reg if r.status == "open"),
        sum(1 for r in all_reg if r.status == "in_progress"),
        sum(1 for r in all_reg if r.status == "closed"),
    )
    if raw_totals_row is not None and raw_totals_row != exp_raw:
        errors.append(
            f"[Check 1: Index Parity] {POAM_INDEX_REL}: Raw Row Sum {raw_totals_row} != expected {exp_raw}"
        )

    if dedup_totals_row is not None:
        dup_open = dup_inprog = dup_closed = 0
        for sid in sorted(same_weakness_ids):
            matches = [r for r in all_reg if r.finding_id == sid]
            if len(matches) < 2:
                errors.append(
                    f"[Check 1: Index Parity] {POAM_INDEX_REL}: Cross-Reference 'Same weakness' "
                    f"entry {sid} appears {len(matches)} time(s) across regional POA&Ms (expected >=2)"
                )
                continue
            statuses = {r.status for r in matches}
            if len(statuses) > 1:
                errors.append(
                    f"[Check 1: Index Parity] {POAM_INDEX_REL}: Cross-Reference 'Same weakness' "
                    f"entry {sid} has divergent statuses across regional POA&Ms: {sorted(statuses)}"
                )
                continue
            extra = len(matches) - 1
            st = matches[0].status
            if st == "open":
                dup_open += extra
            elif st == "in_progress":
                dup_inprog += extra
            elif st == "closed":
                dup_closed += extra
        exp_dedup = (
            exp_raw[0] - (dup_open + dup_inprog + dup_closed),
            exp_raw[1] - dup_open,
            exp_raw[2] - dup_inprog,
            exp_raw[3] - dup_closed,
        )
        if dedup_totals_row != exp_dedup:
            errors.append(
                f"[Check 1: Index Parity] {POAM_INDEX_REL}: Deduplicated Total "
                f"{dedup_totals_row} (Entries/Open/InProgress/Closed) != expected {exp_dedup}"
            )

    return errors


def _load_active_lula_set(repo_root: Path) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    active: set[str] = set()
    readme = repo_root / LULA_README_REL
    if not readme.is_file():
        return active, [f"[Check 1: Lula] Missing {LULA_README_REL}"]
    for line in readme.read_text(encoding="utf-8").splitlines():
        if "\u2705 Active" in line and "lula-validation-" in line:
            match = re.search(r"lula-validation-[A-Za-z0-9_-]+\.yaml", line)
            if match:
                active.add(f"compliance/lula/{match.group(0)}")
    return active, errors


def _validate_active_lula_manifest(
    repo_root: Path, rel_path: str, active_lula: set[str]
) -> tuple[bool, str]:
    if rel_path not in active_lula:
        return (
            False,
            f"{rel_path} is a stub or unlisted in {LULA_README_REL} (not Active)",
        )
    full = repo_root / rel_path
    if not full.is_file():
        return False, f"{rel_path} does not exist"
    raw = full.read_text(encoding="utf-8")
    if "TODO: STUB" in raw or "default validate = true" in raw:
        return False, f"{rel_path} contains stub Rego/TODO markers"
    try:
        doc = yaml.load(raw, Loader=_DuplicateKeyRejectingLoader)  # nosec B506  # SafeLoader subclass rejecting duplicate keys
    except yaml.YAMLError as exc:
        return False, f"{rel_path} failed YAML validation: {exc}"
    if not isinstance(doc, dict):
        return False, f"{rel_path} is not a YAML mapping"
    comp_def = doc.get("component-definition")
    if not isinstance(comp_def, dict):
        return False, f"{rel_path} lacks Lula v0.16.0 top-level component-definition"
    meta = comp_def.get("metadata")
    if not isinstance(meta, dict) or not meta.get("oscal-version"):
        return False, f"{rel_path} lacks component-definition.metadata.oscal-version"

    back_matter = comp_def.get("back-matter")
    resources = back_matter.get("resources") if isinstance(back_matter, dict) else None
    if not isinstance(resources, list) or not resources:
        return False, f"{rel_path} lacks component-definition.back-matter.resources"
    res_by_uuid: dict[str, dict[str, object]] = {}
    for res in resources:
        if isinstance(res, dict) and isinstance(res.get("uuid"), str):
            res_by_uuid[str(res["uuid"])] = res

    lula_hrefs: list[str] = []
    for comp in comp_def.get("components") or []:
        if not isinstance(comp, dict):
            continue
        for ci in comp.get("control-implementations") or []:
            if not isinstance(ci, dict):
                continue
            for ir in ci.get("implemented-requirements") or []:
                if not isinstance(ir, dict):
                    continue
                for link in ir.get("links") or []:
                    if isinstance(link, dict) and link.get("rel") == "lula":
                        href = str(link.get("href", ""))
                        lula_hrefs.append(href)
    if not lula_hrefs:
        return False, f"{rel_path} lacks implemented-requirements link with rel=='lula'"

    for href in lula_hrefs:
        if not href.startswith("#") or href[1:] not in res_by_uuid:
            return (
                False,
                f"{rel_path} has dangling lula link href {href!r} missing from back-matter.resources",
            )
        desc = res_by_uuid[href[1:]].get("description")
        if not isinstance(desc, str) or not desc.strip():
            return (
                False,
                f"{rel_path} resource {href} lacks embedded Lula YAML description",
            )
        try:
            inner = yaml.load(desc, Loader=_DuplicateKeyRejectingLoader)  # nosec B506  # SafeLoader subclass rejecting duplicate keys
        except yaml.YAMLError as exc:
            return (
                False,
                f"{rel_path} resource {href} failed embedded Lula YAML validation: {exc}",
            )
        if not isinstance(inner, dict):
            return (
                False,
                f"{rel_path} resource {href} embedded description is not a YAML mapping",
            )
        domain = inner.get("domain")
        provider = inner.get("provider")
        if not isinstance(domain, dict) or domain.get("type") not in {
            "kubernetes",
            "api",
        }:
            return False, f"{rel_path} resource {href} has unsupported domain.type"
        if not isinstance(provider, dict) or provider.get("type") != "opa":
            return False, f"{rel_path} resource {href} lacks provider.type == 'opa'"
        opa_spec = provider.get("opa-spec")
        rego = opa_spec.get("rego") if isinstance(opa_spec, dict) else None
        if not isinstance(rego, str) or not rego.strip():
            return (
                False,
                f"{rel_path} resource {href} lacks non-empty provider.opa-spec.rego",
            )
        if "TODO: STUB" in rego or "default validate = true" in rego:
            return False, f"{rel_path} resource {href} contains stub Rego/TODO markers"

    return True, ""


def _ci_referenced_scripts(repo_root: Path) -> set[str]:
    referenced: set[str] = set()
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return referenced
    pat = re.compile(r"scripts/check_[A-Za-z0-9_]+\.py")
    for wf in sorted(wf_dir.glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8", errors="replace")
        referenced.update(pat.findall(text))
    return referenced


def _extract_unpinned_runnable_candidates(text: str) -> list[str]:
    """Extract runnable candidate paths, ignoring historical ``<sha>^:<path>`` pins and struck ``~~...~~`` text."""
    active_text = re.sub(r"~~[\s\S]*?~~", " ", text)
    found: set[str] = set()
    for match in _RUNNABLE_PATH_RE.finditer(active_text):
        prefix = active_text[max(0, match.start() - 45) : match.start()]
        if _PINNED_RUNNABLE_PREFIX_RE.search(prefix):
            continue
        found.add(re.sub(r"^(?:\.\./)+", "", match.group(1)))
    return sorted(found)


def _audit_check1_read_back_for_row(
    repo_root: Path,
    row: PoamRow,
    active_lula: set[str],
    ci_scripts: set[str],
) -> list[str]:
    """Enforce Check 1 (runnable read-back + exact finding-ID binding) on a closed row or detail section."""
    text = row.full_text
    candidates = _extract_unpinned_runnable_candidates(text)
    id_re = re.compile(r"\b" + re.escape(row.finding_id) + r"\b")

    valid_runnable: list[str] = []
    bound_runnable: list[str] = []
    diagnostics: list[str] = []

    for rel in candidates:
        full = repo_root / rel
        if not full.is_file():
            diagnostics.append(f"{rel} (missing on disk)")
            continue
        file_text = full.read_text(encoding="utf-8", errors="replace")

        if rel.startswith("tests/"):
            if not Path(rel).name.startswith("test_"):
                diagnostics.append(f"{rel} (helper/fixture, not test_*.py)")
                continue
            if not _TEST_FN_RE.search(file_text):
                diagnostics.append(f"{rel} (no def test_* function)")
                continue
            if "pytest.mark." not in file_text:
                diagnostics.append(f"{rel} (missing pytest.mark.* selection marker)")
                continue
            if not _PR_CI_PYTEST_MARKER_RE.search(file_text):
                diagnostics.append(
                    f"{rel} (live_external/non-PR-CI marker only; lacks unit/local/integration marker)"
                )
                continue
            valid_runnable.append(rel)
            if id_re.search(file_text):
                bound_runnable.append(rel)

        elif rel.endswith(".tftest.hcl"):
            if not _TFTEST_RUN_RE.search(file_text):
                diagnostics.append(f"{rel} (no Terraform test run block)")
                continue
            valid_runnable.append(rel)
            if id_re.search(file_text):
                bound_runnable.append(rel)

        elif rel.startswith("compliance/lula/"):
            ok, reason = _validate_active_lula_manifest(repo_root, rel, active_lula)
            if not ok:
                diagnostics.append(reason)
                continue
            valid_runnable.append(rel)
            if id_re.search(file_text):
                bound_runnable.append(rel)

        elif rel.startswith("scripts/check_"):
            if rel not in ci_scripts:
                diagnostics.append(f"{rel} (not invoked in .github/workflows/)")
                continue
            valid_runnable.append(rel)
            if id_re.search(file_text):
                bound_runnable.append(rel)

        elif rel.startswith(".github/workflows/"):
            # Bypass 6 closed: workflow citation NEVER auto-binds via 'Observed ...' alone.
            # It counts as valid_runnable only if it defines jobs:, and counts as bound_runnable
            # ONLY if the workflow file itself binds \b<finding_id>\b (otherwise a paired
            # test/tftest/active-Lula/CI-gate must bind \b<finding_id>\b).
            if "jobs:" not in file_text:
                diagnostics.append(f"{rel} (workflow lacks jobs: mapping)")
                continue
            valid_runnable.append(rel)
            if id_re.search(file_text):
                bound_runnable.append(rel)
            else:
                diagnostics.append(
                    f"{rel} (workflow does not bind {row.finding_id!r}; require explicit finding-ID or paired regression test binding)"
                )

    kind = "detail section" if row.is_detail_section else "finding"
    if not valid_runnable:
        detail = (
            f"; rejected candidates: {', '.join(diagnostics)}" if diagnostics else ""
        )
        return [
            f"[Check 1: Read-Back] {row.source_rel}:{row.line_number} ({row.finding_id}, ctrl={row.control!r}): "
            f"closed {kind} cites zero PR-CI runnable test/tftest/active-Lula/CI-gate artifacts{detail}"
        ]

    if not bound_runnable:
        detail = f"; notes: {', '.join(diagnostics)}" if diagnostics else ""
        return [
            f"[Check 1: Read-Back] {row.source_rel}:{row.line_number} ({row.finding_id}, ctrl={row.control!r}): "
            f"runnable evidence {valid_runnable} on closed {kind} does not bind exact finding ID {row.finding_id!r}{detail}"
        ]

    return []


def _audit_reopened_open_row(row: PoamRow) -> list[str]:
    """Enforce Bypass 4 closure: reopened open rows/sections MUST declare explicit closure criteria."""
    if row.status == "closed":
        return []
    if not _REOPENED_MARKER_RE.search(row.full_text):
        return []
    has_explicit_closure_clause = bool(
        _CLOSURE_CLAUSE_SPLIT_RE.search(row.description)
    ) or bool(row.milestone.strip())
    if not has_explicit_closure_clause:
        kind = "detail section" if row.is_detail_section else "row"
        return [
            f"[Check 1: Reopened Schema] {row.source_rel}:{row.line_number} ({row.finding_id}): "
            f"reopened open {kind} lacks explicit 'Closes on' / 'Closure Criteria' / Milestone clause"
        ]
    return []


def _extract_target_text_for_open_row(row: PoamRow) -> str:
    """Return closure-criterion clauses + Milestone for an open/in-progress row (never silent '' on Reopened)."""
    parts: list[str] = []
    if row.milestone:
        parts.append(row.milestone)
    desc = row.description
    splits = _CLOSURE_CLAUSE_SPLIT_RE.split(desc)
    if len(splits) > 1:
        parts.extend(splits[1:])
    elif desc.strip():
        # Bypass 4 closed: even when a Reopened row omits 'Closes on', NEVER return ''
        # so Check 2 and Check 3 still audit its clauses alongside [Check 1: Reopened Schema].
        parts.append(desc)
    return "\n".join(parts)


def _split_clauses(text: str) -> list[str]:
    """Split text into sentence/semicolon/line clauses so qualifiers stay clause-local (Bypass 5)."""
    raw_parts = re.split(
        r"(?:\n+|;\s+|(?<!\bArt)(?<!\be\.g)(?<!\bi\.e)(?<!\bvs)(?<!\bv\d)\.\s+(?=[A-Z0-9`*\"(\[]))",
        text,
    )
    return [c.strip() for c in raw_parts if c and c.strip()]


def _audit_check2_lifetime_for_row(row: PoamRow) -> list[str]:
    """Enforce Check 2 (store lifetime >= obligation lifetime via EVIDENCE_STORE_REGISTRY)."""
    errors: list[str] = []
    ctrl_blob = f"{row.control} {row.description[:160]}"
    inspect_text = (
        row.full_text
        if row.status == "closed"
        else _extract_target_text_for_open_row(row)
    )
    if not inspect_text:
        return errors

    short_stores = [
        spec
        for spec in EVIDENCE_STORE_REGISTRY.values()
        if spec.retention_days is not None
        and spec.retention_days < _MIN_WORM_RETENTION_DAYS
    ]

    if _AUDIT_RETENTION_CTRL_RE.search(ctrl_blob):
        for clause in _split_clauses(inspect_text):
            if _HISTORICAL_CLOSURE_CLAUSE_RE.search(clause):
                continue
            for spec in short_stores:
                if spec.store_id not in {
                    "cloud_logging_default",
                    "cloud_logging_required",
                    "opa_decision_logs",
                }:
                    continue
                if not spec.match_re.search(clause):
                    continue
                if (
                    spec.store_id == "opa_decision_logs"
                    and _NEGATED_EPHEMERAL_LOG_RE.search(clause)
                ):
                    continue
                # Bypass 5 closed: check persistent retention qualifier ONLY on `clause`.
                if not _PERSISTENT_RETENTION_QUALIFIER_RE.search(clause):
                    errors.append(
                        f"[Check 2: Lifetime] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                        f"clause cites short-lived store {spec.store_id!r} (lifetime={spec.lifetime}, retention_days={spec.retention_days}) "
                        f"for audit/retention obligation {row.control!r} without clause-local persistent >=2555-day locked export (POAM-2026-197)"
                    )
                    break
            if errors:
                break

    if _WORM_RETENTION_CTRL_RE.search(ctrl_blob):
        for clause in _split_clauses(inspect_text):
            if _HISTORICAL_CLOSURE_CLAUSE_RE.search(clause):
                continue
            staging_spec = EVIDENCE_STORE_REGISTRY["staging_workload_worm"]
            if staging_spec.match_re.search(
                clause
            ) and not _NEGATED_STAGING_WORM_RE.search(clause):
                errors.append(
                    f"[Check 2: Lifetime] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                    f"clause cites {staging_spec.store_id!r} ({staging_spec.retention_days} d, unlocked) "
                    f"for multi-year retention control {row.control!r}; require persistent >=2555-day locked evidence domain (POAM-2026-197)"
                )
                break
            gmp_spec = EVIDENCE_STORE_REGISTRY["gmp_monarch"]
            if (
                gmp_spec.match_re.search(clause)
                and not _PERSISTENT_RETENTION_QUALIFIER_RE.search(clause)
                and not _TELEMETRY_QUALIFIER_RE.search(clause)
                and (
                    gmp_spec.custody_qualifier_re is None
                    or not gmp_spec.custody_qualifier_re.search(clause)
                )
            ):
                errors.append(
                    f"[Check 2: Lifetime] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                    f"clause cites {gmp_spec.store_id!r} (lifetime={gmp_spec.lifetime}, {gmp_spec.retention_days} d < {_MIN_WORM_RETENTION_DAYS} d) "
                    f"for multi-year retention control {row.control!r} without persistent >=2555-day WORM scoping"
                )
                break
            cites_generic_worm_proof = bool(
                re.search(
                    r"\b(?:in|against|to)\s+the\s+WORM\s+bucket\b",
                    clause,
                    re.IGNORECASE,
                )
            )
            # Bypass 5 closed: evaluate _PERSISTENT_RETENTION_QUALIFIER_RE strictly on `clause`.
            if (
                cites_generic_worm_proof
                and not _PERSISTENT_RETENTION_QUALIFIER_RE.search(clause)
                and not _NEGATED_STAGING_WORM_RE.search(clause)
            ):
                errors.append(
                    f"[Check 2: Lifetime] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                    f"clause cites unqualified 'WORM bucket' for {row.control!r} without scoping to the persistent >=2555-day locked domain (POAM-2026-197)"
                )
                break

    return errors


def _audit_check3_custody_for_row(row: PoamRow) -> list[str]:
    """Enforce Check 3 (GOV_WRITABLE rejection via EVIDENCE_STORE_REGISTRY with clause-local scoping)."""
    errors: list[str] = []
    inspect_text = (
        row.full_text
        if row.status == "closed"
        else _extract_target_text_for_open_row(row)
    )
    if not inspect_text:
        return errors

    gov_writable_specs = [
        spec
        for spec in EVIDENCE_STORE_REGISTRY.values()
        if spec.custody == "GOV_WRITABLE"
    ]
    ctrl_blob = f"{row.control} {row.description[:120]}"
    is_audit_custody_ctrl = bool(_AUDIT_CUSTODY_CTRL_RE.search(ctrl_blob))

    for clause in _split_clauses(inspect_text):
        if _HISTORICAL_CLOSURE_CLAUSE_RE.search(clause):
            continue

        if _UNCONDITIONAL_GOV_WRITABLE_CLAIM_RE.search(clause):
            # Allow Valkey ONLY when the same clause explicitly qualifies it as Redis DB 1
            # cage:evidence:stream + WORM custody chain rather than bare/shared Valkey.
            if (
                EVIDENCE_STORE_REGISTRY["valkey_app"].match_re.search(clause)
                and _AUTHORITATIVE_CUSTODY_CHAIN_RE.search(clause)
                and not re.search(
                    r"(?:\bLangfuse\b|/v1/infra/events|\binfra_events\b|\bClickHouse\b"
                    r"|\bopa_decision_logs\b|\bdecision_logs\b|\bgmp_monarch\b|\bGMP\b|\bMonarch\b|\bManaged\s+Prometheus\b)",
                    clause,
                    re.IGNORECASE,
                )
            ):
                continue
            matched_ids = [
                s.store_id for s in gov_writable_specs if s.match_re.search(clause)
            ]
            store_tag = f" ({', '.join(matched_ids)})" if matched_ids else ""
            errors.append(
                f"[Check 3: Custody] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                f"clause asserts GOV_WRITABLE store{store_tag} satisfies authoritative / tamper-evident / non-repudiable custody"
            )
            return errors

        for spec in gov_writable_specs:
            if not spec.match_re.search(clause):
                continue

            # Bypass 1 (gmp_monarch): operational AU-12/SI-4 telemetry (custody=GOV_WRITABLE,
            # plane=PLANE, lifetime=24m) is NEVER non-repudiable AU-10 decision custody.
            if spec.forbidden_custody_controls_re is not None and (
                spec.forbidden_custody_controls_re.search(row.control)
                or spec.forbidden_custody_controls_re.search(clause)
            ):
                scoped_to_au12_si4 = bool(
                    re.search(r"\b(?:AU-12|SI-4)\b", row.control, re.IGNORECASE)
                    and spec.custody_qualifier_re is not None
                    and spec.custody_qualifier_re.search(clause)
                    and not spec.forbidden_custody_controls_re.search(clause)
                )
                if (
                    not _NEGATED_DECISION_CUSTODY_RE.search(clause)
                    and not scoped_to_au12_si4
                ):
                    errors.append(
                        f"[Check 3: Custody] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                        f"store {spec.store_id!r} (custody={spec.custody!r}, plane={spec.plane!r}, lifetime={spec.lifetime!r}) "
                        f"cannot satisfy non-repudiable AU-10 decision custody"
                    )
                    return errors

            # Bypass 2 (bare Valkey & ClickHouse infra_events): reject tamper-evident / custody-chain
            # claims on any control unless Valkey is explicitly Redis DB 1 cage:evidence:stream -> WORM.
            if spec.store_id in {
                "valkey_app",
                "infra_events",
                "opa_decision_logs",
            } and (
                _TAMPER_CUSTODY_ASSERTION_RE.search(clause)
                and not _NEGATED_DECISION_CUSTODY_RE.search(clause)
            ):
                if (
                    spec.store_id == "valkey_app"
                    and _AUTHORITATIVE_CUSTODY_CHAIN_RE.search(clause)
                ):
                    continue
                if (
                    spec.custody_qualifier_re is not None
                    and spec.custody_qualifier_re.search(clause)
                    and not re.search(
                        r"\b(?:in|via|through|using|from)\s+(?:`?Valkey`?|ClickHouse|`?infra_events`?|`?/v1/infra/events`?|OPA\s+`?decision_logs`?)\b",
                        clause,
                        re.IGNORECASE,
                    )
                ):
                    continue
                errors.append(
                    f"[Check 3: Custody] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                    f"non-authoritative store {spec.store_id!r} (custody={spec.custody!r}) cited in tamper-evident / custody assertion "
                    f"(only Redis DB 1 cage:evidence:stream + WORM EVIDENCE_ARCHIVE_BUCKET / evidence_domain satisfy custody)"
                )
                return errors

            if not is_audit_custody_ctrl:
                continue

            # Bypass 5 closed: evaluate qualifiers strictly on `clause`, NEVER on `row.full_text`.
            clause_qualified = bool(_TELEMETRY_QUALIFIER_RE.search(clause)) or (
                spec.custody_qualifier_re is not None
                and bool(spec.custody_qualifier_re.search(clause))
            )
            if spec.store_id == "valkey_app" and _AUTHORITATIVE_CUSTODY_CHAIN_RE.search(
                clause
            ):
                clause_qualified = True

            if not clause_qualified:
                errors.append(
                    f"[Check 3: Custody] {row.source_rel}:{row.line_number} ({row.finding_id}, status={row.status}): "
                    f"clause references GOV_WRITABLE store {spec.store_id!r} (plane={spec.plane!r}, lifetime={spec.lifetime!r}) "
                    f"in audit-custody control {row.control!r} without clause-local operational-telemetry / non-custody scoping"
                )
                return errors

    return errors


def _load_census_module(repo_root: Path) -> Any:
    script_path = repo_root / "scripts" / "check_oscal_claim_census.py"
    if not script_path.is_file():
        script_path = Path(__file__).resolve().parent / "check_oscal_claim_census.py"
    spec = importlib.util.spec_from_file_location(
        "_check_oscal_claim_census", script_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {script_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _audit_oscal_checks(
    repo_root: Path, active_lula: set[str], ci_scripts: set[str]
) -> tuple[list[str], int]:
    """Run Check 4 census validation plus Check 1/2/3 invariants on OSCAL implemented & HOLDS claims."""
    errors: list[str] = []
    census_path = repo_root / OSCAL_CENSUS_REL
    oscal_dir = repo_root / "compliance" / "oscal"
    register_path = repo_root / OSCAL_REGISTER_REL

    if not census_path.is_file():
        return [f"[Check 4: Census] Missing census file: {OSCAL_CENSUS_REL}"], 0
    if not oscal_dir.is_dir():
        return ["[Check 4: Census] Missing OSCAL directory: compliance/oscal"], 0

    census_mod = _load_census_module(repo_root)
    rows: list[dict[str, Any]] = census_mod.load_census(census_path)
    extracted: dict[str, dict[str, Any]] = census_mod.extract_all_oscal_claims(
        oscal_dir
    )
    for cerr in census_mod.validate_census(rows, extracted, repo_root):
        errors.append(f"[Check 4: Census] {cerr}")

    if not register_path.is_file():
        errors.append(
            f"[Check 4: Census] Missing rendered register: {OSCAL_REGISTER_REL}"
        )
    else:
        expected_md = census_mod.render_register_markdown(rows)
        actual_md = register_path.read_text(encoding="utf-8")
        if actual_md != expected_md:
            errors.append(
                f"[Check 4: Census] {OSCAL_REGISTER_REL} is out of sync with {OSCAL_CENSUS_REL}"
            )

    impl_count = 0
    for row in rows:
        rid = str(row.get("id", ""))
        verdict = str(row.get("verdict", ""))
        disp = str(row.get("disposition", ""))
        status_ex = row.get("status_extracted")

        if verdict in {"WEAKER", "NOT_IN_FORCE"} and disp == "holds":
            errors.append(
                f"[Check 4: Census] {rid}: verdict {verdict!r} cannot carry disposition 'holds'"
            )

        # Deliverable 2: verify read_back.check & evidence_named repo paths on ALL HOLDS rows
        # (including non-implemented HOLDS rows such as partial/customer-configured).
        if verdict == "HOLDS":
            read_back_obj = row.get("read_back")
            rb_texts: list[str] = []
            if isinstance(read_back_obj, dict):
                rb_texts.append(str(read_back_obj.get("check", "")))
                rb_texts.append(str(read_back_obj.get("note", "")))
            for ev in row.get("evidence_named") or []:
                rb_texts.append(str(ev))
            for text_frag in rb_texts:
                unpinned = census_mod.PINNED_READ_BACK_REPO_PATH_RE.sub(" ", text_frag)
                for pm in census_mod.READ_BACK_REPO_PATH_RE.finditer(unpinned):
                    rel_p = pm.group(1)
                    if not (repo_root / rel_p).exists():
                        errors.append(
                            f"[Check 4: HOLDS Path] OSCAL {rid} (status={status_ex!r}): "
                            f"HOLDS claim references missing file {rel_p!r}"
                        )

        if status_ex != "implemented":
            continue
        impl_count += 1

        if verdict not in {"HOLDS", "INHERITED", "ROLLUP"}:
            errors.append(
                f"[Check 4: Census] {rid}: OSCAL status 'implemented' has failing verdict {verdict!r}"
            )
            continue

        if verdict in {"INHERITED", "ROLLUP"}:
            continue

        custody = row.get("custody")
        c_grade = custody.get("grade") if isinstance(custody, dict) else custody
        if c_grade in {"GOV_WRITABLE", "UNKNOWN", None, "n/a"}:
            errors.append(
                f"[Check 3: Custody] OSCAL {rid}: implemented claim has forbidden custody grade {c_grade!r}"
            )

        lifetime = row.get("lifetime")
        lt_grade = lifetime.get("grade") if isinstance(lifetime, dict) else lifetime
        if lt_grade in {"SHORTER", "UNKNOWN", None, "n/a"}:
            errors.append(
                f"[Check 2: Lifetime] OSCAL {rid}: implemented claim has insufficient lifetime grade {lt_grade!r}"
            )

        read_back = row.get("read_back")
        rb_grade = read_back.get("grade") if isinstance(read_back, dict) else read_back
        if rb_grade not in {"OBSERVES", "PRESENCE"}:
            errors.append(
                f"[Check 1: Read-Back] OSCAL {rid}: implemented claim has read_back grade {rb_grade!r}"
            )
            continue

        blob = " ".join(
            [
                str(
                    read_back.get("check", "")
                    if isinstance(read_back, dict)
                    else read_back
                ),
                str(read_back.get("note", "") if isinstance(read_back, dict) else ""),
                " ".join(str(x) for x in (row.get("cites") or [])),
                " ".join(str(x) for x in (row.get("evidence_named") or [])),
            ]
        )
        candidates = _extract_unpinned_runnable_candidates(blob)
        runnable_ok = False
        for rel in candidates:
            full = repo_root / rel
            if not full.is_file():
                continue
            if rel.startswith("tests/") and Path(rel).name.startswith("test_"):
                ft = full.read_text(encoding="utf-8", errors="replace")
                if _TEST_FN_RE.search(ft) and _PR_CI_PYTEST_MARKER_RE.search(ft):
                    runnable_ok = True
                    break
            elif rel.endswith(".tftest.hcl"):
                ft = full.read_text(encoding="utf-8", errors="replace")
                if _TFTEST_RUN_RE.search(ft):
                    runnable_ok = True
                    break
            elif rel.startswith("compliance/lula/"):
                ok, _ = _validate_active_lula_manifest(repo_root, rel, active_lula)
                if ok:
                    runnable_ok = True
                    break
            elif rel.startswith("scripts/check_") and rel in ci_scripts:
                runnable_ok = True
                break
        if not runnable_ok and not _OBSERVED_RECORD_RE.search(blob):
            errors.append(
                f"[Check 1: Read-Back] OSCAL {rid}: implemented claim cites no resolvable runnable test/tftest/active-Lula/CI-gate"
            )

    return errors, impl_count


def parse_all_poam_rows(repo_root: Path) -> tuple[list[PoamRow], list[str]]:
    """Parse every open, in-progress, and closed row + detail section across all 5 row-bearing
    POA&M files and verify cross-file summary parity against ``POAM_INDEX.md``."""
    errors: list[str] = []
    all_rows: list[PoamRow] = []

    primary_path = repo_root / PRIMARY_POAM_REL
    if not primary_path.is_file():
        errors.append(
            f"[Check 1: Scope] Missing primary POA&M file: {PRIMARY_POAM_REL}"
        )
    else:
        p_rows, p_errs = _parse_primary_poam_text(
            primary_path.read_text(encoding="utf-8"), PRIMARY_POAM_REL
        )
        all_rows.extend(p_rows)
        errors.extend(p_errs)

    regional_by_file: dict[str, list[PoamRow]] = {}
    for rel in REGIONAL_POAM_RELS:
        r_path = repo_root / rel
        if not r_path.is_file():
            errors.append(f"[Check 1: Scope] Missing regional POA&M file: {rel}")
            continue
        r_rows, r_errs = _parse_regional_poam_file(r_path, rel)
        regional_by_file[rel] = r_rows
        all_rows.extend(r_rows)
        errors.extend(r_errs)

    errors.extend(_audit_poam_index(repo_root, regional_by_file))
    return all_rows, errors


def audit_poam_and_oscal(
    repo_root: Path,
) -> tuple[list[str], dict[str, int]]:
    """Run all four PR-9 checks across ``repo_root`` and return ``(errors, stats)``."""
    repo_root = repo_root.resolve()
    rows, errors = parse_all_poam_rows(repo_root)
    active_lula, lula_errs = _load_active_lula_set(repo_root)
    errors.extend(lula_errs)
    ci_scripts = _ci_referenced_scripts(repo_root)

    for lula_rel in sorted(active_lula):
        ok, reason = _validate_active_lula_manifest(repo_root, lula_rel, active_lula)
        if not ok:
            errors.append(f"[Check 1: Lula] {reason}")

    summary_rows = [r for r in rows if not r.is_detail_section]
    detail_rows = [r for r in rows if r.is_detail_section]

    closed_count = sum(1 for r in summary_rows if r.status == "closed")
    open_count = sum(1 for r in summary_rows if r.status != "closed")

    for row in rows:
        if row.status == "closed":
            errors.extend(
                _audit_check1_read_back_for_row(repo_root, row, active_lula, ci_scripts)
            )
        else:
            errors.extend(_audit_reopened_open_row(row))
        errors.extend(_audit_check2_lifetime_for_row(row))
        errors.extend(_audit_check3_custody_for_row(row))

    oscal_errs, oscal_impl = _audit_oscal_checks(repo_root, active_lula, ci_scripts)
    errors.extend(oscal_errs)

    stats = {
        "poam_total_rows": len(summary_rows),
        "poam_closed_rows": closed_count,
        "poam_open_or_in_progress_rows": open_count,
        "poam_detail_sections": len(detail_rows),
        "active_lula_manifests": len(active_lula),
        "oscal_implemented_claims": oscal_impl,
        "errors": len(errors),
    }
    return errors, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enforce PR-9 four-check gate across all POA&M trackers and OSCAL claims."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="Repository root directory (defaults to current working directory).",
    )
    args = parser.parse_args(argv)

    errors, stats = audit_poam_and_oscal(args.root)
    print(
        f"POA&M rows audited:      {stats['poam_total_rows']} "
        f"({stats['poam_closed_rows']} closed, {stats['poam_open_or_in_progress_rows']} open/in-progress)"
    )
    print(f"POA&M detail sections:   {stats['poam_detail_sections']}")
    print(f"Active Lula manifests:   {stats['active_lula_manifests']}")
    print(f"OSCAL implemented rows:  {stats['oscal_implemented_claims']}")

    if errors:
        print(f"\nFAILED ({len(errors)} violation(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        "\nOK: 0 uncovered closures, 0 detail-section/reopened divergences, "
        "0 lifetime/custody violations, and 0 OSCAL census divergences."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
