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

"""
oscal_exporter.py — OSCAL Assessment Results exporter  (Tier 2.3)

Generates a standards-compliant OSCAL Assessment Results document from the
current compliance posture returned by get_compliance_metrics().

Used by GET /v1/oscal/assessment-results to close the loop with Lula — Lula
can consume this output directly for automated re-validation without requiring
a separate CronJob run.

OSCAL Assessment Results structure (NIST OSCAL 1.1.x):
  assessment-results
    uuid
    metadata
    results[]
      uuid
      title
      start / end
      reviewed-controls
      findings[]
        uuid
        title
        target
          target-id (control_id)
          status.state  (satisfied | not-satisfied | not-applicable)
        props[]
          name: safety_rate  value: <float>
          name: evidence_age_seconds  value: <int>
          name: framework  value: iso42001 | fedramp | eu_ai_act | nist_ai_rmf
          name: window_hours  value: <int>

References:
  https://pages.nist.gov/OSCAL/reference/latest/assessment-results/json-reference/
  https://lula.dev/docs/oscal-overview
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import cast

from .aarm_mapper import AARM_THREAT_VECTORS
from .types import CONTROL_META, FRAMEWORK_CONTROLS, OscalFinding, OscalResult

# ---------------------------------------------------------------------------
# GCP Adaptation: Agent Registry audit reference for AC-3 evidence
# ---------------------------------------------------------------------------
# When CAGE_AGENT_REGISTRY_PROJECT is set, the GEAP Agent Registry resource
# name is included in AC-3 (Access Enforcement) finding evidence as an
# additional attestation source.  Cloud-agnostic deployments are unaffected.

_REGISTRY_PROJECT = os.environ.get("CAGE_AGENT_REGISTRY_PROJECT", "")

if _REGISTRY_PROJECT:
    try:
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter as _AgentRegistryAdapter,
        )

        _reg_adapter = _AgentRegistryAdapter()
        _REGISTRY_AUDIT_REF: str = _reg_adapter.get_registry_audit_reference()
    except ImportError:
        _REGISTRY_AUDIT_REF = ""
else:
    _REGISTRY_AUDIT_REF = ""

# ---------------------------------------------------------------------------
# State mapping helpers
# ---------------------------------------------------------------------------


def _finding_to_state(finding: OscalFinding) -> str:
    """Convert OscalFinding.result to the OSCAL finding state vocabulary.

    NIST OSCAL 1.1.x assessment-results state vocabulary:
      satisfied      — control objective met (PASS)
      not-satisfied  — control objective not met (FAIL)
      not-applicable — control does not apply to this system component
      error          — scanner/collector failure; evidence could not be gathered.
                       Must NOT be mapped to "not-applicable" — that would hide
                       a potential security blind spot from auditors.
                       (NIST SP 800-53A §3.2 / FedRAMP assessment guide)
    """
    if finding.result == "PASS":
        return "satisfied"
    if finding.result == "FAIL":
        return "not-satisfied"
    if finding.result == "NOT_APPLICABLE":
        return "not-applicable"
    # ERROR (or any future unknown value) — surface as "error" so auditors see it.
    return "error"


# ---------------------------------------------------------------------------
# Core exporter
# ---------------------------------------------------------------------------


def build_oscal_assessment_results(
    findings: list[OscalFinding],
    audit_id: str,
    window_hours: int = 24,
    system_name: str = "Cybernetic Governance Engine",
    assessor: str = "compliance-bridge",
    chain_root: str | None = None,
    chain_sealed_utc: str | None = None,
    cer_uris: dict[str, str] | None = None,
) -> dict:
    """
    Build an OSCAL Assessment Results document from a list of OscalFindings.

    Args:
        findings:         List of OscalFinding objects from the audit pipeline or
                          from live get_compliance_metrics() calls.
        audit_id:         Identifier for the assessment run (used as assessment UUID seed).
        window_hours:     Evidence look-back window (embedded in finding props).
        system_name:      System name embedded in the OSCAL metadata title.
        assessor:         Party responsible for the assessment.
        chain_root:       SHA-256 root of the Context Accumulator chain (CAGE v0.1.0).
        chain_sealed_utc: ISO-8601 UTC timestamp when the chain was sealed.
        cer_uris:         Optional mapping of control_id → NexArt CER URI for external
                          attestation links.  When present, each finding entry gets an
                          OSCAL ``links[]`` array with ``rel: evidence`` entries.

    Returns:
        A dict representing the OSCAL Assessment Results document.
        Serialise with json.dumps() or yaml.dump() depending on caller.
    """
    now_utc = datetime.now(tz=timezone.utc).isoformat()
    result_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cage-result-{audit_id}"))
    doc_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cage-ar-{audit_id}"))
    party_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, "cage-compliance-bridge"))

    # Build frameworks cross-reference map for props annotation (includes AARM)
    control_frameworks: dict[str, list[str]] = {}
    for fw, cids in FRAMEWORK_CONTROLS.items():
        for cid in cids:
            control_frameworks.setdefault(cid, []).append(fw)

    # Build AARM vector lookup: control_id → list of vector IDs it neutralizes
    aarm_vector_by_control: dict[str, list[str]] = {}
    for vid, vector in AARM_THREAT_VECTORS.items():
        for ctrl_id in vector.neutralizing_controls:
            aarm_vector_by_control.setdefault(ctrl_id, []).append(vid)

    # Build finding entries
    oscal_findings = []
    for f in findings:
        props = [
            {"name": "source", "value": assessor},
            {"name": "audit_id", "value": audit_id},
            {"name": "window_hours", "value": str(window_hours)},
        ]
        if f.safety_rate is not None:
            props.append({"name": "safety_rate", "value": str(round(f.safety_rate, 6))})
        if f.evidence_age_s is not None:
            props.append(
                {"name": "evidence_age_seconds", "value": str(int(f.evidence_age_s))}
            )
        for fw in control_frameworks.get(f.control_id, []):
            props.append({"name": "framework", "value": fw})
        # AARM vector cross-references (CAGE v0.1.0)
        for vid in aarm_vector_by_control.get(f.control_id, []):
            vector_meta = AARM_THREAT_VECTORS.get(vid)
            props.append(
                {
                    "name": "aarm-vector",
                    "value": f"{vid} ({vector_meta.name})" if vector_meta else vid,
                }
            )

        entry: dict = {
            "uuid": f.finding_id,
            "title": (
                CONTROL_META.get(f.control_id, {}).get("name", f.control_id)
                + f" — {f.result}"
            ),
            "target": {
                "type": "objective-id",
                "target-id": f.control_id,
                "status": {"state": _finding_to_state(f)},
            },
            "props": props,
        }
        if f.remarks:
            entry["description"] = f.remarks

        # NexArt CER attestation link (Feature 2 — OSCAL CER Links)
        if cer_uris and f.control_id in cer_uris:
            cer_uri = cer_uris[f.control_id]
            entry["links"] = [
                {
                    "href": cer_uri,
                    "rel": "evidence",
                    "text": f"NexArt CER attestation receipt for {f.control_id}",
                }
            ]
            # Extract certificate hash from URI (last path segment)
            cer_hash = (
                cer_uri.rstrip("/").rsplit("/", 1)[-1] if "/" in cer_uri else cer_uri
            )
            props.append({"name": "cer-hash", "value": cer_hash})

        # GCP Adaptation: include GEAP Agent Registry resource name in AC-3 evidence.
        # AC-3 (Access Enforcement) — the registry is the authoritative source of
        # agent tool authorization policies in GCP deployments.
        # Cloud-agnostic deployments: _REGISTRY_AUDIT_REF is "" — this block is skipped.
        if _REGISTRY_AUDIT_REF and f.control_id == "AC-3":
            registry_link = {
                "href": f"https://console.cloud.google.com/vertex-ai/agents?project={_REGISTRY_PROJECT}",
                "rel": "gcp-agent-registry",
                "text": f"GEAP Agent Registry — {_REGISTRY_AUDIT_REF}",
            }
            entry.setdefault("links", []).append(registry_link)
            props.append(
                {
                    "name": "gcp-agent-registry-resource",
                    "value": _REGISTRY_AUDIT_REF,
                }
            )
            # Augment remarks with registry reference for auditor visibility
            existing_remarks = entry.get("description", "")
            registry_remark = (
                f"GCP Adaptation: Agent tool authorization policies are enforced via "
                f"GEAP Agent Registry ({_REGISTRY_AUDIT_REF}). "
                f"Registry catalog is synced to OPA data.agent_catalog_data at runtime."
            )
            entry["description"] = (
                f"{existing_remarks}\n{registry_remark}".strip()
                if existing_remarks
                else registry_remark
            )

        oscal_findings.append(entry)

    # Collect all reviewed control IDs
    control_ids = sorted({f.control_id for f in findings})

    return {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": {
                "title": f"CAGE Compliance Assessment Results — {system_name}",
                "last-modified": now_utc,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "parties": [
                    {
                        "uuid": party_uuid,
                        "type": "tool",
                        "name": assessor,
                        "remarks": "Automated assessor — CAGE Compliance Bridge",
                    }
                ],
            },
            "results": [
                {
                    "uuid": result_uuid,
                    "title": f"Assessment Run {audit_id}",
                    "start": now_utc,
                    "end": now_utc,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "include-controls": [
                                    {"control-id": cid} for cid in control_ids
                                ]
                            }
                        ]
                    },
                    "attestations": [
                        {
                            "responsible-parties": [
                                {"role-id": "assessor", "party-uuids": [party_uuid]}
                            ],
                            "parts": [
                                {
                                    "name": "assessment-method",
                                    "prose": (
                                        "Automated evidence aggregation via OpenTelemetry spans, "
                                        "deterministic OSCAL parsing (lula-compatible), and "
                                        "Langfuse compliance scoring. No LLM inference was used "
                                        "in control determination."
                                    ),
                                }
                            ],
                        }
                    ],
                    # CAGE v0.1.0 AARM Context Accumulator chain provenance
                    "props": [
                        p
                        for p in [
                            {
                                "name": "context-accumulator-chain-root",
                                "value": chain_root,
                            }
                            if chain_root
                            else None,
                            {
                                "name": "context-accumulator-sealed-utc",
                                "value": chain_sealed_utc,
                            }
                            if chain_sealed_utc
                            else None,
                            {"name": "aarm-spec-version", "value": "CSA-AARM-v1.0"},
                        ]
                        if p is not None
                    ],
                    "findings": oscal_findings,
                }
            ],
        }
    }


def findings_from_metrics_dict(
    metrics_by_control: dict,
    audit_id: str,
) -> list[OscalFinding]:
    """
    Convert a dict of {control_id: ComplianceMetrics} (as returned by
    /v1/metrics/summary) into a list of OscalFinding objects for export.

    Controls with 'error' keys (Langfuse fetch failures / timeouts) are
    emitted as ERROR findings — they are NOT silently skipped.

    Rationale (NIST SP 800-53A §3.2 / FedRAMP assessment guide):
      A data-collection failure ("fetch failed") is NOT the same as
      NOT_APPLICABLE.  NOT_APPLICABLE means the control does not apply to
      this system component (e.g. a wireless control on a wired-only system).
      A fetch failure means the control applies but the scanner broke trying
      to check it.  Silently dropping the finding hides a potential security
      blind spot.  Auditing frameworks require such states to be flagged as
      Error / Incomplete / Unknown — never masked as Not Applicable.
    """
    findings: list[OscalFinding] = []
    for cid, data in metrics_by_control.items():
        if "error" in data:
            # Scanner/collector failure — emit an ERROR finding so auditors
            # can see the gap.  Do NOT skip or map to NOT_APPLICABLE.
            findings.append(
                OscalFinding(
                    control_id=cid,
                    result="ERROR",
                    finding_id=str(
                        uuid.uuid5(uuid.NAMESPACE_URL, f"{audit_id}-{cid}-error")
                    ),
                    safety_rate=None,
                    evidence_age_s=None,
                    remarks=f"Evidence collection error: {data['error']}",
                )
            )
            continue
        sr = data.get("safety_rate")
        # M-10: safety_rate is None when no traces exist — treat as NOT_APPLICABLE
        # (no evidence yet) rather than crashing or falsely reporting PASS/FAIL.
        if sr is None:
            result: OscalResult = cast(OscalResult, "NOT_APPLICABLE")
        else:
            result = cast(OscalResult, "PASS" if sr >= 1.0 else "FAIL")
        findings.append(
            OscalFinding(
                control_id=cid,
                result=result,
                finding_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{audit_id}-{cid}")),
                safety_rate=sr,
                evidence_age_s=data.get("evidence_age_seconds"),
                remarks=None,
            )
        )
    return findings
