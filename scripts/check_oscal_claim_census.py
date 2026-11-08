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
"""Deterministic census validator and markdown renderer for OSCAL evidence claims.

Implements PR-9 Check 4 ("OSCAL census diff"):
1. Extracts every structured control claim from the 7 OSCAL YAML artifacts under
   ``compliance/oscal/`` (Ring 1 SSPs + Ring 2 component definitions, STPA patch,
   and common-controls catalog) plus the ``SA11-SYSTEMIC`` synthetic rollup.
2. Verifies 1-to-1 completeness against ``compliance/oscal/evidence_claim_census.jsonl``
   (zero ungraded claims and zero orphaned census rows).
3. Verifies freshness: every entry's ``description_sha256`` and ``status_extracted``
   must match the live OSCAL YAML at HEAD.
4. Verifies schema invariants, prohibits legacy ``N-nn`` finding IDs, and resolves
   all repository file paths cited in ``cites`` and ``read_back.check`` against the
   working tree (or git history when revision-pinned as ``<sha>^:<path>``).
5. Renders ``docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md`` deterministically
   (``--render``) and verifies byte-for-byte parity (``--verify-rendered``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OSCAL_DIR = REPO_ROOT / "compliance/oscal"
DEFAULT_CENSUS_PATH = DEFAULT_OSCAL_DIR / "evidence_claim_census.jsonl"
DEFAULT_REGISTER_PATH = REPO_ROOT / "docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md"

RING1_FILES = {
    "system-security-plan.yaml",
    "system-security-plan-eu-ecb.yaml",
    "system-security-plan-apac-mas.yaml",
}

VALID_VERDICTS = {
    "HOLDS",
    "WEAKER",
    "NOT_IN_FORCE",
    "INHERITED",
    "ROLLUP",
    "NOT_A_CLAIM",
}
VALID_DISPOSITIONS = {
    "holds",
    "restate",
    "fix",
    "reopen",
    "n/a",
}
VALID_CUSTODY_GRADES = {
    "PLANE",
    "CONFIG",
    "GOV_WRITABLE",
    "UNKNOWN",
    "PROVIDER",
    "n/a",
    None,
}
VALID_READ_BACK_GRADES = {"OBSERVES", "PRESENCE", "NONE", "n/a", None}
VALID_LIFETIME_GRADES = {"OUTLIVES", "REPO", "SHORTER", "UNKNOWN", "n/a", None}

LEGACY_N_FINDING_RE = re.compile(r"\bN-\d+\b")
PINNED_CITE_PATH_RE = re.compile(
    r"^(?P<rev>[0-9a-f]{7,40}\^?):(?P<path>(?:src|infra|tests|compliance|deployment|scripts|config|docs|\.github|packages|proof)/[^\s:();,]+)"
)
CITED_REPO_PATH_RE = re.compile(
    r"^((?:src|infra|tests|compliance|deployment|scripts|config|docs|\.github|packages|proof)/[^\s:();,]+)"
)
PINNED_READ_BACK_REPO_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./:-])(?P<rev>[0-9a-f]{7,40}\^?):(?P<path>(?:src|infra|tests|compliance|deployment|scripts|config|docs|\.github|packages|proof)/[A-Za-z0-9_./-]+\.[A-Za-z0-9_]+)"
)
READ_BACK_REPO_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./:-])((?:src|infra|tests|compliance|deployment|scripts|config|docs|\.github|packages|proof)/[A-Za-z0-9_./-]+\.[A-Za-z0-9_]+)"
)


@dataclass(frozen=True)
class EvidenceStoreProvenance:
    """Authoritative custody and retention provenance for an evidence/telemetry store."""

    store_id: str
    label: str
    storage_custody: str
    content_custody: str
    retention: str
    writer_and_credential: str
    forgery_or_suppression_surface: str
    retention_and_integrity_detail: str
    cited_for: str


EVIDENCE_STORE_PROVENANCE: tuple[EvidenceStoreProvenance, ...] = (
    EvidenceStoreProvenance(
        store_id="evidence_stream_worm",
        label="**Evidence stream -> bridge -> WORM** (`evidence_stream_worm`)",
        storage_custody="PLANE",
        content_custody="PLANE",
        retention="2555d (prod) / 1d (staging)",
        writer_and_credential=(
            "Gateway appends unsigned records to IAM-authenticated Valkey (DB 1); "
            "bridge re-verifies chain, signs **one `cage-evidence-batch/1` attestation "
            "per batch** (`compliance-evidence`, `F-90`), and writes WORM"
        ),
        forgery_or_suppression_surface=(
            "Governance-plane identities; a node compromise (`F-72`); on staging before "
            "`PR-10`, documented teardown (`F-94`) and workload CMEK key (`F-97`)"
        ),
        retention_and_integrity_detail=(
            "Locked `2555 d` (prod) or `1 d` (staging). Staging objects are deleted at "
            "teardown until `PR-10` (`R-10`). Unkeyed hash until bridge batch signature"
        ),
        cited_for="`AU-2`, `AU-9`, `AU-10`, `AU-12` evidence-of-execution",
    ),
    EvidenceStoreProvenance(
        store_id="langfuse_app",
        label="**Langfuse application project** (`langfuse_app`)",
        storage_custody="PLANE",
        content_custody="GOV_WRITABLE",
        retention="2555d (prod) / 1d (staging)",
        writer_and_credential=(
            "Gateway and advisor share one key pair (`advisor-secrets`, `F-84` until `PR-5`)"
        ),
        forgery_or_suppression_surface=(
            "Governed advisor can write (`GOV_WRITABLE`) and feed causal world-model "
            "inputs (`F-92`); any key holder can delete from the ClickHouse query plane"
        ),
        retention_and_integrity_detail=(
            "Raw events locked `2555 d` (prod) / `1 d` (staging); `langfuse_event_upload` "
            "bucket lacks CMEK and versioning (`F-105`)"
        ),
        cited_for="SSP `AU-2` and `AU-12` decision-time (reclassified to telemetry in `PR-7c`)",
    ),
    EvidenceStoreProvenance(
        store_id="langfuse_compliance",
        label="**Langfuse compliance project** (`langfuse_compliance`)",
        storage_custody="PLANE",
        content_custody="PLANE",
        retention="query-plane",
        writer_and_credential="Bridge audit workflow with dedicated keys (`POAM-019` guard)",
        forgery_or_suppression_surface="Compliance bridge",
        retention_and_integrity_detail=(
            'Query plane only; `iso_42001_outcome == "PASSED"` has zero writers in `src/` (`F-103`)'
        ),
        cited_for="`AU-9` isolation",
    ),
    EvidenceStoreProvenance(
        store_id="container_stdout",
        label="**Container stdout** (`container_stdout`)",
        storage_custody="PROVIDER",
        content_custody="GOV_WRITABLE",
        retention="30d",
        writer_and_credential="Each container, through the GKE node logging agent",
        forgery_or_suppression_surface="Each container, for its own stream",
        retention_and_integrity_detail="Cloud Logging `_Default`, `30 d` (`F-88`)",
        cited_for="Operational debugging only",
    ),
    EvidenceStoreProvenance(
        store_id="gmp_monarch",
        label="**GMP / Monarch metrics** (`gmp_monarch`)",
        storage_custody="PLANE",
        content_custody="GOV_WRITABLE",
        retention="24m",
        writer_and_credential=(
            "Google Managed Prometheus scrapes gateway `:9090/metrics` via Terraform "
            "`PodMonitoring/gateway-metrics` (`#664`); metric values are pod-emitted"
        ),
        forgery_or_suppression_surface=(
            "`PLANE` Managed Prometheus TSDB storage; scraped pod controls counter/gauge "
            "content (`GOV_WRITABLE` for compromised target pod)"
        ),
        retention_and_integrity_detail=(
            "Google Cloud Managed Service for Prometheus (`24m` / 24-month TSDB retention)"
        ),
        cited_for="SSP `AU-12` operational safety & custody counters",
    ),
    EvidenceStoreProvenance(
        store_id="actuator_receipts",
        label="**Actuator receipts** (`actuator_receipts`)",
        storage_custody="PLANE",
        content_custody="PROVIDER",
        retention="chain-bound",
        writer_and_credential="Partner asymmetric key, verified out-of-band by `kid`",
        forgery_or_suppression_surface="Partner signing key",
        retention_and_integrity_detail="Bound into the gateway `cage:evidence:stream` hash chain",
        cited_for="`no_direct_bind`",
    ),
    EvidenceStoreProvenance(
        store_id="reconciler_state",
        label="**Reconciler** (`reconciler_state`)",
        storage_custody="PLANE",
        content_custody="PLANE",
        retention="300s TTL",
        writer_and_credential=(
            "`reconciliation-worker` (`#664` in Terraform); custodian defaults to "
            "`_DefaultSimulatedProvider` unless non-simulated ledger wired"
        ),
        forgery_or_suppression_surface="Reconciler GSA (`reconciler-snapshot` KMS key)",
        retention_and_integrity_detail=(
            "Redis 300 s TTL; discrepancy fences are not hash-chained on DB 1 until `§11b` (`F-86`)"
        ),
        cited_for="`CA-7` / `SI-10` (`POAM-2026-096`)",
    ),
    EvidenceStoreProvenance(
        store_id="dataplane_v2_logs",
        label="**Dataplane V2 policy logs** (`dataplane_v2_logs`, planned `PR-7b`)",
        storage_custody="PROVIDER",
        content_custody="PLANE",
        retention="30d",
        writer_and_credential="Node datapath (`k8s_node`)",
        forgery_or_suppression_surface=(
            "Node compromise; drops logs above `500 conn/s` per node (`F-87`)"
        ),
        retention_and_integrity_detail="Cloud Logging `_Default`, `30 d`",
        cited_for="`SC-7` (`D-195-4`, `R-5`)",
    ),
    EvidenceStoreProvenance(
        store_id="vpc_firewall_nat_logs",
        label="**VPC firewall and Cloud NAT logs** (`vpc_firewall_nat_logs`, inert until `PR-2`)",
        storage_custody="PROVIDER",
        content_custody="PROVIDER",
        retention="30d",
        writer_and_credential="Google VPC network (`cage-vpc-staging`, `F-01`, `F-87`)",
        forgery_or_suppression_surface=(
            "Project network admins (`SetIamPolicy` / Admin Activity records changes)"
        ),
        retention_and_integrity_detail="Cloud Logging `_Default`, `30 d`",
        cited_for="`SC-7` egress corroboration (`R-5`)",
    ),
    EvidenceStoreProvenance(
        store_id="cloud_audit_admin_activity",
        label="**Cloud Audit Logs — Admin Activity** (`cloud_audit_admin_activity`)",
        storage_custody="PROVIDER",
        content_custody="PROVIDER",
        retention="400d",
        writer_and_credential="Google Cloud control plane",
        forgery_or_suppression_surface="Cannot be disabled by project owners",
        retention_and_integrity_detail="`_Required`, `400 d`; not exported until `R-4` (`F-88`)",
        cited_for="Control-plane mutation audit",
    ),
    EvidenceStoreProvenance(
        store_id="cloud_audit_kms_data_access",
        label="**Cloud Audit Logs — KMS Data Access (`AsymmetricSign`)** (`cloud_audit_kms_data_access`, `AS-6`)",
        storage_custody="PROVIDER",
        content_custody="PROVIDER",
        retention="30d",
        writer_and_credential="Google Cloud KMS",
        forgery_or_suppression_surface=(
            "Disabled by default (`F-83`, `F-96`); holders of `setIamPolicy` can turn off "
            "(Admin Activity records it, `F-89`)"
        ),
        retention_and_integrity_detail=(
            "`_Default`, `30 d` unless exported to `PR-10` locked log bucket (`R-4`)"
        ),
        cited_for="`AS-6` / `R-4` Q2 governor corroboration",
    ),
    EvidenceStoreProvenance(
        store_id="infra_events",
        label="**INFRA events (`/v1/infra/events`)** (`infra_events`)",
        storage_custody="PROVIDER",
        content_custody="GOV_WRITABLE",
        retention="30d",
        writer_and_credential=(
            "Any holder of shared `CAGE_INTERNAL_TOKEN`, including the advisor (`advisor-secrets`, `F-85`)"
        ),
        forgery_or_suppression_surface=(
            "Governed advisor (`GOV_WRITABLE`) until `§11a` (`R-3`) enforces mesh identity "
            "and full-payload hash"
        ),
        retention_and_integrity_detail=(
            "After `#667` retired ClickHouse `cage_evidence`, `src/compliance_bridge/main.py:765` "
            "logs unchained JSON to container stdout (`Cloud Logging _Default`, `30 d`); "
            "`record_hash` excludes payload until `§11a` (`F-85`)"
        ),
        cited_for="`AU-2`, `SI-7` (`POAM-021`)",
    ),
)


def status_of(node: dict[str, Any]) -> str | None:
    """Extract the OSCAL implementation-status state from a requirement or by-component."""
    st = node.get("implementation-status")
    if isinstance(st, dict) and st.get("state"):
        return str(st["state"])
    for prop in node.get("props", []) or []:
        if isinstance(prop, dict) and prop.get("name") in (
            "implementation-status",
            "implementation_status",
        ):
            return str(prop.get("value"))
    return None


def links_of(node: dict[str, Any]) -> list[str]:
    """Return href strings from an OSCAL node's links array."""
    return [
        str(link.get("href", ""))
        for link in node.get("links", []) or []
        if isinstance(link, dict)
    ]


def text_of(node: dict[str, Any]) -> str:
    """Return normalized description, statements, and non-status props text."""
    parts = [str(node.get("description", "") or "")]
    for st in node.get("statements", []) or []:
        if isinstance(st, dict):
            parts.append(str(st.get("description", "") or ""))
    for prop in node.get("props", []) or []:
        if isinstance(prop, dict) and prop.get("name") not in (
            "implementation-status",
        ):
            pname = prop.get("name")
            pval = prop.get("value")
            parts.append(f"[{pname}={pval}]")
    return " ".join(" ".join(p.split()) for p in parts if p)


def compute_description_sha256(text: str, links: list[str]) -> str:
    """Compute canonical SHA-256 over normalized claim text and link hrefs."""
    norm = " ".join((text + " " + " ".join(links)).split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _ssp_components(doc: dict[str, Any]) -> dict[str, str]:
    ssp = doc.get("system-security-plan", {})
    comps = (ssp.get("system-implementation", {}) or {}).get("components", []) or []
    return {
        str(c.get("uuid")): str(c.get("title", ""))
        for c in comps
        if isinstance(c, dict) and c.get("uuid")
    }


def extract_ssp(path: Path, doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract requirement and by-component claims from a Ring-1 SSP YAML document."""
    out: list[dict[str, Any]] = []
    titles = _ssp_components(doc)
    ci = doc["system-security-plan"].get("control-implementation", {}) or {}
    for req in ci.get("implemented-requirements", []) or []:
        cid = req.get("control-id")
        rstat = status_of(req)
        ruuid = req.get("uuid")
        rtext = text_of(req)
        rlinks = links_of(req)
        out.append(
            {
                "ring": 1,
                "file": path.name,
                "id": f"{path.name}#{ruuid}",
                "level": "requirement",
                "control": cid,
                "component": "",
                "status": rstat,
                "text": rtext,
                "links": rlinks,
                "description_sha256": compute_description_sha256(rtext, rlinks),
            }
        )
        containers = [req] + [
            s for s in req.get("statements", []) or [] if isinstance(s, dict)
        ]
        for cont in containers:
            for bc in cont.get("by-components", []) or []:
                bcuuid = bc.get("uuid")
                comp_uuid = str(bc.get("component-uuid", ""))
                btext = text_of(bc)
                blinks = links_of(bc)
                out.append(
                    {
                        "ring": 1,
                        "file": path.name,
                        "id": f"{path.name}#{bcuuid}",
                        "level": "by-component",
                        "control": cid,
                        "component": titles.get(comp_uuid, comp_uuid),
                        "status": status_of(bc) or rstat,
                        "text": btext,
                        "links": blinks,
                        "description_sha256": compute_description_sha256(btext, blinks),
                    }
                )
    return out


def extract_generic(path: Path, doc: object) -> list[dict[str, Any]]:
    """Extract control-bearing entries from a Ring-2 OSCAL YAML document."""
    out: list[dict[str, Any]] = []

    def walk(node: object, comp: str, trail: str) -> None:
        if isinstance(node, dict):
            here = (
                str(node.get("title") or "")
                if "control-implementations" in node
                else comp
            )
            if "control-id" in node and ("description" in node or "statements" in node):
                uid = node.get("uuid") or f"path:{trail}"
                ntext = text_of(node)
                nlinks = links_of(node)
                out.append(
                    {
                        "ring": 2,
                        "file": path.name,
                        "id": f"{path.name}#{uid}",
                        "level": "entry",
                        "control": node.get("control-id"),
                        "component": here or "",
                        "status": status_of(node),
                        "text": ntext,
                        "links": nlinks,
                        "description_sha256": compute_description_sha256(ntext, nlinks),
                    }
                )
            for k, v in node.items():
                walk(v, here or comp, f"{trail}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, comp, f"{trail}[{i}]")

    walk(doc, "", "")
    return out


def extract_all_oscal_claims(
    oscal_dir: Path = DEFAULT_OSCAL_DIR,
) -> dict[str, dict[str, Any]]:
    """Extract all structured claims across ``oscal_dir/*.yaml`` keyed by ``<file>#<uuid>``."""
    extracted: dict[str, dict[str, Any]] = {}
    for path in sorted(oscal_dir.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        rows = (
            extract_ssp(path, doc)
            if path.name in RING1_FILES
            else extract_generic(path, doc)
        )
        for row in rows:
            extracted[row["id"]] = row
    return extracted


def load_census(census_path: Path = DEFAULT_CENSUS_PATH) -> list[dict[str, Any]]:
    """Load census rows from a JSONL file."""
    return [
        json.loads(line)
        for line in census_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _pinned_path_exists_in_git(rev: str, rel_path: str, repo_root: Path) -> bool:
    """Verify a revision-pinned ``<sha>^:<path>`` citation against git history."""
    proc = subprocess.run(
        ["git", "cat-file", "-e", f"{rev}:{rel_path}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def validate_census(
    census_rows: list[dict[str, Any]],
    extracted: dict[str, dict[str, Any]],
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """Validate completeness, freshness, schema, finding IDs, and cited paths."""
    errors: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}

    for idx, row in enumerate(census_rows, 1):
        rid = row.get("id")
        if not rid or not isinstance(rid, str):
            errors.append(f"Row {idx}: missing string 'id'")
            continue
        if rid in by_id:
            errors.append(f"Row {idx} ({rid}): duplicate census id")
        by_id[rid] = row

        raw_row = json.dumps(row, ensure_ascii=False)
        legacy_n = LEGACY_N_FINDING_RE.findall(raw_row)
        if legacy_n:
            errors.append(
                f"Row {idx} ({rid}): un-renumbered legacy finding ID(s) {sorted(set(legacy_n))}"
            )

        verdict = row.get("verdict")
        if verdict not in VALID_VERDICTS:
            errors.append(f"Row {idx} ({rid}): invalid verdict {verdict!r}")

        disp = row.get("disposition") or "n/a"
        if disp not in VALID_DISPOSITIONS:
            errors.append(f"Row {idx} ({rid}): invalid disposition {disp!r}")

        custody = row.get("custody")
        c_grade = custody.get("grade") if isinstance(custody, dict) else custody
        if c_grade not in VALID_CUSTODY_GRADES:
            errors.append(f"Row {idx} ({rid}): invalid custody grade {c_grade!r}")

        read_back = row.get("read_back")
        rb_grade = read_back.get("grade") if isinstance(read_back, dict) else read_back
        if rb_grade not in VALID_READ_BACK_GRADES:
            errors.append(f"Row {idx} ({rid}): invalid read_back grade {rb_grade!r}")

        lifetime = row.get("lifetime")
        lt_grade = lifetime.get("grade") if isinstance(lifetime, dict) else lifetime
        if lt_grade not in VALID_LIFETIME_GRADES:
            errors.append(f"Row {idx} ({rid}): invalid lifetime grade {lt_grade!r}")

        for cite in row.get("cites") or []:
            for part in str(cite).split(";"):
                segment = part.strip()
                mp = PINNED_CITE_PATH_RE.match(segment)
                if mp:
                    rev = mp.group("rev")
                    rel_path = mp.group("path").rstrip(".,;")
                    if not _pinned_path_exists_in_git(rev, rel_path, repo_root):
                        errors.append(
                            f"Row {idx} ({rid}): pinned repository path does not resolve in git: {rev}:{rel_path}"
                        )
                    continue
                m = CITED_REPO_PATH_RE.match(segment)
                if m:
                    rel_path = m.group(1).rstrip(".,;")
                    if not (repo_root / rel_path).exists():
                        errors.append(
                            f"Row {idx} ({rid}): cited repository path does not exist: {rel_path}"
                        )

        rb_check = read_back.get("check", "") if isinstance(read_back, dict) else ""
        for mp_rb in PINNED_READ_BACK_REPO_PATH_RE.finditer(str(rb_check)):
            rev = mp_rb.group("rev")
            rel_path = mp_rb.group("path").rstrip(".,;")
            if not _pinned_path_exists_in_git(rev, rel_path, repo_root):
                errors.append(
                    f"Row {idx} ({rid}): pinned read_back.check repository path does not resolve in git: {rev}:{rel_path}"
                )
        for m_rb in READ_BACK_REPO_PATH_RE.finditer(str(rb_check)):
            rel_path = m_rb.group(1).rstrip(".,;")
            if not (repo_root / rel_path).exists():
                errors.append(
                    f"Row {idx} ({rid}): read_back.check repository path does not exist: {rel_path}"
                )

    census_oscal_ids = set(by_id.keys()) - {"SA11-SYSTEMIC"}
    extracted_ids = set(extracted.keys())

    missing_from_census = sorted(extracted_ids - census_oscal_ids)
    for mid in missing_from_census:
        errors.append(f"Ungraded OSCAL claim missing from census: {mid}")

    orphaned_in_census = sorted(census_oscal_ids - extracted_ids)
    for oid in orphaned_in_census:
        errors.append(f"Orphaned census entry not present in OSCAL files: {oid}")

    sa11_rollup_hashes: list[str] = []
    for rid in sorted(census_oscal_ids & extracted_ids):
        row = by_id[rid]
        ext = extracted[rid]
        expected_sha = ext["description_sha256"]
        actual_sha = row.get("description_sha256")
        if actual_sha != expected_sha:
            errors.append(
                f"{rid}: description_sha256 drift (census={actual_sha}, oscal={expected_sha})"
            )
        expected_status = ext["status"]
        actual_status = row.get("status_extracted")
        if actual_status != expected_status:
            errors.append(
                f"{rid}: status drift (census={actual_status!r}, oscal={expected_status!r})"
            )
        if row.get("verdict") == "ROLLUP" and row.get("control") == "sa-11":
            sa11_rollup_hashes.append(f"{rid}:{expected_sha}")

    if "SA11-SYSTEMIC" not in by_id:
        errors.append("Missing required synthetic rollup entry: SA11-SYSTEMIC")
    else:
        expected_sa11_sha = hashlib.sha256(
            "\n".join(sorted(sa11_rollup_hashes)).encode("utf-8")
        ).hexdigest()
        actual_sa11_sha = by_id["SA11-SYSTEMIC"].get("description_sha256")
        if actual_sa11_sha != expected_sa11_sha:
            errors.append(
                f"SA11-SYSTEMIC: rollup description_sha256 drift "
                f"(census={actual_sa11_sha}, expected={expected_sa11_sha})"
            )

    return errors


def _esc(val: object, maxlen: int | None = None) -> str:
    if val is None:
        return "—"
    text = str(val).replace("|", "\\|").replace("\n", " ").strip()
    if maxlen and len(text) > maxlen:
        text = text[: maxlen - 1].rstrip() + "…"
    return text


def _grade_str(obj: object, maxlen: int = 80) -> str:
    if isinstance(obj, dict):
        grade = obj.get("grade", "—")
        note = obj.get("note") or obj.get("check") or ""
        return f"**`{grade}`**: {_esc(note, maxlen)}"
    return f"**`{_esc(obj, maxlen)}`**"


def _wb_str(obj: object, maxlen: int = 55) -> str:
    if isinstance(obj, dict):
        val = obj.get("value", False)
        note = obj.get("object") or obj.get("note") or ""
        return f"**`{val}`**" + (
            f" ({_esc(note, maxlen)})" if val and note and note != "n/a" else ""
        )
    return f"**`{bool(obj)}`**"


def _slice_counts(srows: list[dict[str, Any]]) -> dict[str, int]:
    out = {
        "total": len(srows),
        "HOLDS": 0,
        "WEAKER": 0,
        "NOT_IN_FORCE": 0,
        "INHERITED": 0,
        "ROLLUP": 0,
        "NOT_A_CLAIM": 0,
        "w_binding": 0,
        "reopen": 0,
    }
    for r in srows:
        v = str(r.get("verdict"))
        if v in out:
            out[v] += 1
        wb = r.get("w_binding")
        wb_val = wb.get("value", False) if isinstance(wb, dict) else bool(wb)
        if wb_val:
            out["w_binding"] += 1
        if r.get("disposition") == "reopen":
            out["reopen"] += 1
    return out


def _pct(num: int, den: int) -> str:
    if den == 0:
        return "0.0%"
    return f"{(100.0 * num / den):.1f}%"


def render_register_markdown(rows: list[dict[str, Any]]) -> str:
    """Render the complete OSCAL Evidence-Claim Sweep Register in Markdown."""
    rel_root = "../.."
    by_slice: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_slice.setdefault(str(row["slice"]), []).append(row)

    tot = _slice_counts(rows)
    n_oscal = tot["total"] - (
        1 if any(r.get("id") == "SA11-SYSTEMIC" for r in rows) else 0
    )
    n_graded = tot["HOLDS"] + tot["WEAKER"] + tot["NOT_IN_FORCE"]
    sa11_rollups = sum(
        1 for r in rows if r.get("verdict") == "ROLLUP" and r.get("control") == "sa-11"
    )
    dup_rollups = tot["ROLLUP"] - sa11_rollups

    lines: list[str] = []
    lines.append(
        f"# OSCAL Evidence-Claim Sweep Register (Rings 1 & 2 — {tot['total']} Entries, Generated)"
    )
    lines.append("")
    lines.append(
        f"**Source of truth:** [`compliance/oscal/evidence_claim_census.jsonl`]({rel_root}/compliance/oscal/evidence_claim_census.jsonl) | "
        f"**Generator & Validator:** [`scripts/check_oscal_claim_census.py`]({rel_root}/scripts/check_oscal_claim_census.py) | "
        f"**POA&M trackers:** [`docs/POAM.md`](../POAM.md) · [`docs/compliance/us_fed/POAM_US_FED.md`](us_fed/POAM_US_FED.md)"
    )
    lines.append("")
    lines.append("## 1. Executive Summary & Cross-Tabulation")
    lines.append("")
    lines.append(
        f"Across all 7 structured OSCAL files (`{n_oscal}` entries plus `SA11-SYSTEMIC` = **`{tot['total']}` entries**), "
        f"**`{n_graded}` entries are substantively graded CAGE claims** "
        f"(`{tot['HOLDS']} HOLDS` / `{_pct(tot['HOLDS'], n_graded)}`, "
        f"`{tot['WEAKER']} WEAKER`, `{tot['NOT_IN_FORCE']} NOT_IN_FORCE`), "
        f"alongside **`{tot['INHERITED']} INHERITED`** (`common-controls-catalog.yaml`), "
        f"**`{tot['ROLLUP']} ROLLUP`** (`{sa11_rollups}` generated `SA-11` by-components "
        f"evaluated together under `SA11-SYSTEMIC` plus `{dup_rollups}` duplicate "
        f"`component-definition.yaml` entries), and "
        f"**`{tot['NOT_A_CLAIM']} NOT_A_CLAIM`** (`planned` or `under-development`)."
    )
    lines.append("")
    lines.append(
        "| Slice | OSCAL File(s) | Entries | `HOLDS` | `WEAKER` | `NOT_IN_FORCE` | `INHERITED` | `ROLLUP` | `NOT_A_CLAIM` | `w_binding=true` | Reopen |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    slice_specs = [
        (
            "ring1_usfed",
            "**Ring 1a**",
            f"[`system-security-plan.yaml`]({rel_root}/compliance/oscal/system-security-plan.yaml) (`US_FED`)",
        ),
        (
            "ring1_euapac",
            "**Ring 1b**",
            f"[`system-security-plan-eu-ecb.yaml`]({rel_root}/compliance/oscal/system-security-plan-eu-ecb.yaml), "
            f"[`system-security-plan-apac-mas.yaml`]({rel_root}/compliance/oscal/system-security-plan-apac-mas.yaml) + `SA11-SYSTEMIC`",
        ),
        (
            "ring2_sp80053cd",
            "**Ring 2a**",
            f"[`sp800-53-component-definition.yaml`]({rel_root}/compliance/oscal/sp800-53-component-definition.yaml)",
        ),
        (
            "ring2_cd_patch",
            "**Ring 2b**",
            f"[`component-definition.yaml`]({rel_root}/compliance/oscal/component-definition.yaml), "
            f"[`stpa_compiler_ssp_patch.yaml`]({rel_root}/compliance/oscal/stpa_compiler_ssp_patch.yaml)",
        ),
        (
            "ring2_ccc",
            "**Ring 2c**",
            f"[`common-controls-catalog.yaml`]({rel_root}/compliance/oscal/common-controls-catalog.yaml)",
        ),
    ]
    for sl_key, sl_label, sl_desc in slice_specs:
        sc = _slice_counts(by_slice.get(sl_key, []))
        lines.append(
            f"| {sl_label} | {sl_desc} | {sc['total']} | {sc['HOLDS']} | {sc['WEAKER']} | "
            f"{sc['NOT_IN_FORCE']} | {sc['INHERITED']} | {sc['ROLLUP']} | {sc['NOT_A_CLAIM']} | "
            f"{sc['w_binding']} | {sc['reopen']} |"
        )
    lines.append(
        f"| **Total** | **All 7 OSCAL structured files + `SA11-SYSTEMIC`** | **{tot['total']}** | "
        f"**{tot['HOLDS']}** | **{tot['WEAKER']}** | **{tot['NOT_IN_FORCE']}** | "
        f"**{tot['INHERITED']}** | **{tot['ROLLUP']}** | **{tot['NOT_A_CLAIM']}** | "
        f"**{tot['w_binding']}** | **{tot['reopen']}** |"
    )
    lines.append("")
    lines.append(
        f"### Read-Back x Verdict ({n_graded} Substantively Graded Entries: `HOLDS` + `WEAKER` + `NOT_IN_FORCE`)"
    )
    lines.append("")
    lines.append(
        "| `read_back` Grade | `HOLDS` | `WEAKER` | `NOT_IN_FORCE` | Total | Rate Holding |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|")

    rb_labels = [
        ("OBSERVES", "| **`OBSERVES`** (behavioural / runtime check exists)"),
        ("PRESENCE", "| **`PRESENCE`** (static / shape / consistency check only)"),
        ("NONE", "| **`NONE`** (no check or schema-broken Lula check)"),
    ]
    graded_all = [
        r for r in rows if r.get("verdict") in ("HOLDS", "WEAKER", "NOT_IN_FORCE")
    ]
    for rb_key, rb_label in rb_labels:
        rb_rows = [
            r
            for r in graded_all
            if (
                r.get("read_back", {}).get("grade")
                if isinstance(r.get("read_back"), dict)
                else r.get("read_back")
            )
            == rb_key
        ]
        h_c = sum(1 for r in rb_rows if r.get("verdict") == "HOLDS")
        w_c = sum(1 for r in rb_rows if r.get("verdict") == "WEAKER")
        n_c = sum(1 for r in rb_rows if r.get("verdict") == "NOT_IN_FORCE")
        t_c = len(rb_rows)
        lines.append(f"{rb_label} | {h_c} | {w_c} | {n_c} | {t_c} | {_pct(h_c, t_c)} |")
    lines.append(
        f"| **Total** | **{tot['HOLDS']}** | **{tot['WEAKER']}** | **{tot['NOT_IN_FORCE']}** | "
        f"**{n_graded}** | **{_pct(tot['HOLDS'], n_graded)}** |"
    )
    lines.append("")
    lines.append("### Baseline Sweep Reopenings (Classified by Closure-Failure Shape)")
    lines.append("")
    lines.append(
        "| POA&M ID | Control | Closed On | Closure-Failure Shape | Sweep Entry(s) | Why Baseline Closure Evidence Did Not Hold |"
    )
    lines.append("|---|---|---|---|---|---|")
    lines.append(
        f"| **`POAM-2026-011`** | `SC-8` | `2026-08-27` ([`docs/POAM.md:L178`](../POAM.md#L178)) | **Dead-code closure** (mechanism exists in `src/`; nothing in production calls it) | `component-definition.yaml#tls-req-2026-0827-sc8-us-fed-001` | Closed on `create_hardened_client_context()` ([`tls_context.py:L35`]({rel_root}/src/gateway/infrastructure/tls_context.py#L35)) and [`test_tls_enforcement.py`]({rel_root}/tests/test_tls_enforcement.py). Zero production call sites in `src/` call `create_hardened_client_context()`, and the cited commit `c8d66189…` resolves nowhere (`POAM-2026-119`, `F-104`). |"
    )
    lines.append(
        f"| **`POAM-2026-072`** | `AC-3` / `SC-4` | `2026-09-14` ([`docs/POAM.md:L229`](../POAM.md#L229)) | **Dead-code closure** (mechanism exists in `src/`; nothing in production calls it) | `system-security-plan.yaml#g7000009-5000-4000-8000-000000000017` (`sc-17`), `sp800-53-component-definition.yaml#c3-au10-attestation-2026-0909` (`au-10`, restated onto `RelianceRecord` in `#669`) | Closed on `BrokerActuator` + `sp800-53-component-definition.yaml` updates; `CredentialBrokerAdapter` ([`credential_broker.py:L110`]({rel_root}/src/gateway/governance/seams/credential_broker.py#L110)) is a `Protocol` with zero concrete implementations in `src/`, [`broker_actuator.py:L57`]({rel_root}/src/cage_finance/actuators/broker_actuator.py#L57) reads `BROKER_API_KEY` directly, and [`adapter.py:L411-L421`]({rel_root}/src/integrations/actuator_01/adapter.py#L411-L421) skips the broker gate when `broker=None` (`F-104`). |"
    )
    lines.append(
        "| **`POAM-021`** | `SI-4` | `2026-05-27` ([`docs/compliance/us_fed/POAM_US_FED.md:L76`](us_fed/POAM_US_FED.md#L76)) | **Out-of-state closure** (artifact outside Terraform state) | `system-security-plan.yaml#h8000003-0000-4000-8000-000000000004` (`au-2`), `sp800-53-component-definition.yaml#42c2150e-0256-4ef0-b49b-8a7ee847f9cc` (`si-4`) | Closed on unmanaged AgentSight daemon config (out of Terraform state, unbuilt `agentsight-bpf` image, posts to `/v1/infra/events` `F-85`). |"
    )
    lines.append(
        "| **`POAM-2026-080`** | `IA-9` / `AC-3` / `SC-8` | `2026-09-27` ([`docs/POAM.md:L235`](../POAM.md#L235)) | **Out-of-state closure** (shadow manifest + loopback identity bypass) | `system-security-plan.yaml#g7000010-0000-4000-8000-000000000010`, `system-security-plan.yaml#p8000001-plat-sc8-8000-platform0001`; `sp800-53-component-definition.yaml#230de322-4b76-4a0d-b07d-267f4fa23769` (`sc-8`) | Closed citing unmanaged `de5534ac:deployment/k8s/linkerd-mtls-policy.yaml` (out of Terraform state; `infra/modules/service_mesh` omits OPA and NeMo `Server`/`AuthorizationPolicy`, `F-17`/`F-19`) and `WorkloadIdentityMiddleware` loopback header trust (`F-38`/`F-39`, `F-106`, remediated in `#684`). |"
    )
    lines.append(
        f"| **`POAM-2026-096`** | `CA-7` / `SI-10` | `2026-10-03` ([`docs/POAM.md:L245`](../POAM.md#L245)) | **Out-of-state / simulated closure** | `sp800-53-component-definition.yaml#17537e23-e213-4c9c-b583-68992eb29794` (`ca-7`) | Closed on unmanaged `de5534ac:deployment/k8s/reconciliation-worker.yaml` (reconciler KSA and workload moved into Terraform in `#664` at [`iam.tf:L341-L345`]({rel_root}/infra/targets/gcp-gke/iam.tf#L341-L345)), while `ReconciliationDaemon.from_env()` ([`daemon.py:L1015`]({rel_root}/src/gateway/governance/reconciliation/daemon.py#L1015)) defaults to `_DefaultSimulatedProvider` and discrepancy fencing emits no chained DB 1 evidence record (`F-86`). |"
    )
    lines.append("")
    lines.append(
        "### Evidence Store & Provenance Registry (Backing Custody & Lifetime Checks)"
    )
    lines.append("")
    lines.append(
        "| Source | Custody (`storage` / `content`) | Retention | Writer and Credential | Who Can Forge, Suppress, or Delete | Retention and Integrity | Cited For |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for sp in EVIDENCE_STORE_PROVENANCE:
        lines.append(
            f"| {sp.label} | `{sp.storage_custody}` / `{sp.content_custody}` | `{sp.retention}` | "
            f"{sp.writer_and_credential} | {sp.forgery_or_suppression_surface} | "
            f"{sp.retention_and_integrity_detail} | {sp.cited_for} |"
        )
    lines.append("")

    titles = {
        "ring1_usfed": f"## 2. Ring 1a — `system-security-plan.yaml` (`US_FED`, {len(by_slice.get('ring1_usfed', []))} entries)",
        "ring1_euapac": f"## 3. Ring 1b — `system-security-plan-eu-ecb.yaml`, `system-security-plan-apac-mas.yaml` & `SA11-SYSTEMIC` ({len(by_slice.get('ring1_euapac', []))} entries)",
        "ring2_sp80053cd": f"## 4. Ring 2a — `sp800-53-component-definition.yaml` ({len(by_slice.get('ring2_sp80053cd', []))} entries)",
        "ring2_cd_patch": f"## 5. Ring 2b — `component-definition.yaml` & `stpa_compiler_ssp_patch.yaml` ({len(by_slice.get('ring2_cd_patch', []))} entries)",
        "ring2_ccc": f"## 6. Ring 2c — `common-controls-catalog.yaml` ({len(by_slice.get('ring2_ccc', []))} entries)",
    }

    for sl in [
        "ring1_usfed",
        "ring1_euapac",
        "ring2_sp80053cd",
        "ring2_cd_patch",
        "ring2_ccc",
    ]:
        srows = by_slice.get(sl, [])
        lines.append(titles[sl])
        lines.append("")
        if sl == "ring2_ccc":
            caveated = [
                r
                for r in srows
                if r.get("control")
                in ("cm-2", "cm-8", "cp-2", "cp-9", "cp-10", "sc-28")
            ]
            pure = [r for r in srows if r not in caveated]
            lines.append(
                f"All {len(srows)} controls in [`common-controls-catalog.yaml`]({rel_root}/compliance/oscal/common-controls-catalog.yaml) are cloud-provider (`GCP-Inherited`) or customer-organization (`Inherited` / `Hybrid`) inheritance boundaries (`verdict: INHERITED`, `disposition: holds`, `w_binding: false`). Six controls carry boundary scope caveats (cannot be claimed as pure `GCP-Inherited` without customer configuration):"
            )
            lines.append("")
            lines.append("| ID | Control | Claim | Boundary Caveat | Verdict | Disp. |")
            lines.append("|---|---|---|---|---|---|")
            for r in caveated:
                cid = _esc(str(r["id"]).split("#")[-1], 36)
                ctrl = _esc(r.get("control"), 16)
                claim = _esc(r.get("claim"), 90)
                cust = r.get("custody")
                cnote = _esc(cust.get("note") if isinstance(cust, dict) else cust, 160)
                lines.append(
                    f"| `{cid}` | `{ctrl}` | {claim} | {cnote} | `INHERITED` | `holds` |"
                )
            lines.append("")
            p_items = [
                f"`{r.get('control')}` (`{str(r['id']).split('#')[-1]}`)" for r in pure
            ]
            lines.append(
                f"**Remaining {len(pure)} `INHERITED` (`holds`) controls:** "
                + ", ".join(p_items)
                + "."
            )
            lines.append("")
            continue

        graded_rows = [
            r for r in srows if r.get("verdict") in ("HOLDS", "WEAKER", "NOT_IN_FORCE")
        ]
        rollup_rows = [r for r in srows if r.get("verdict") == "ROLLUP"]
        nac_rows = [r for r in srows if r.get("verdict") == "NOT_A_CLAIM"]

        lines.append(
            "| ID | Ctrl | Component / Status | Claim | Custody | Read-Back | Lifetime | `w_binding` | Verdict / Disp. | `read_back_to_hold` (What Read-Back Makes It Hold) |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in graded_rows:
            rid_str = str(r["id"])
            cid = _esc(rid_str.split("#")[-1] if "#" in rid_str else rid_str, 38)
            ctrl = _esc(r.get("control"), 16)
            comp = _esc(r.get("component") or "req", 24)
            st = _esc(r.get("status_written") or "—", 12)
            claim = _esc(r.get("claim"), 85)
            cg = _grade_str(r.get("custody"), 75)
            rg = _grade_str(r.get("read_back"), 75)
            lg = _grade_str(r.get("lifetime"), 50)
            wb = _wb_str(r.get("w_binding"), 50)
            verd = r.get("verdict")
            disp = r.get("disposition") or "n/a"
            vd = f"**`{verd}`** (`{disp}`)"
            rb_hold = _esc(r.get("read_back_to_hold") or "—", 115)
            if r.get("refs"):
                ref_list = ",".join(str(x) for x in r["refs"])
                rb_hold += f" [`{_esc(ref_list, 35)}`]"
            lines.append(
                f"| `{cid}` | `{ctrl}` | {comp} (`{st}`) | {claim} | {cg} | {rg} | {lg} | {wb} | {vd} | {rb_hold} |"
            )
        lines.append("")
        if rollup_rows:
            r_items = [
                f"`{str(r['id']).split('#')[-1]}` (`{r.get('control')}`)"
                for r in rollup_rows
            ]
            lines.append(
                f"**`ROLLUP` entries (`{len(rollup_rows)}`, graded under `SA11-SYSTEMIC` in §3, disposition `restate`):** "
                + ", ".join(r_items)
                + "."
            )
            lines.append("")
        if nac_rows:
            n_items = [
                f"`{str(r['id']).split('#')[-1]}` (`{r.get('control')}`, `{r.get('status_written')}`)"
                for r in nac_rows
            ]
            lines.append(
                f"**`NOT_A_CLAIM` entries (`{len(nac_rows)}`, `planned` or `not-applicable`):** "
                + ", ".join(n_items)
                + "."
            )
            lines.append("")

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the OSCAL evidence-claim census and render the markdown register."
    )
    parser.add_argument(
        "--census",
        type=Path,
        default=DEFAULT_CENSUS_PATH,
        help="Path to evidence_claim_census.jsonl",
    )
    parser.add_argument(
        "--oscal-dir",
        type=Path,
        default=DEFAULT_OSCAL_DIR,
        help="Path to compliance/oscal directory",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root for resolving cited file paths",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        default=True,
        help="Validate census completeness, hashes, schema, and path citations (default)",
    )
    parser.add_argument(
        "--render",
        type=Path,
        default=None,
        help="Write rendered markdown register to this path",
    )
    parser.add_argument(
        "--verify-rendered",
        type=Path,
        default=None,
        help="Verify that the markdown file at this path matches rendered output byte-for-byte",
    )
    args = parser.parse_args(argv)

    if not args.census.exists():
        print(f"ERROR: census file not found: {args.census}", file=sys.stderr)
        return 1

    rows = load_census(args.census)
    extracted = extract_all_oscal_claims(args.oscal_dir)
    errors = validate_census(rows, extracted, args.repo_root)
    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1

    rendered_md = render_register_markdown(rows)
    if args.render is not None:
        args.render.parent.mkdir(parents=True, exist_ok=True)
        args.render.write_text(rendered_md, encoding="utf-8")
        print(f"Rendered {len(rows)} entries to {args.render}")

    if args.verify_rendered is not None:
        if not args.verify_rendered.exists():
            print(
                f"FAIL: rendered markdown file not found: {args.verify_rendered}",
                file=sys.stderr,
            )
            return 1
        actual_md = args.verify_rendered.read_text(encoding="utf-8")
        if actual_md != rendered_md:
            print(
                f"FAIL: {args.verify_rendered} is out of sync with {args.census}; "
                f"re-run with --render {args.verify_rendered}",
                file=sys.stderr,
            )
            return 1

    print(
        f"OK: {len(rows)} census entries validated against {len(extracted)} OSCAL claims (0 errors)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
