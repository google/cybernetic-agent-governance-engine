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
types.py — Canonical ISO 42001 control metadata and Pydantic models (CAGE v2.0.0).

Ported from src/langfuse-bridge/src/types.ts.

This module is the single authoritative source of truth for:
  - CONTROL_META       — control ID → name + scoreName + framework cross-refs
                         Now includes "aarm" cross-references for CSA AARM v1.0
  - ISO_CONTROL_MAP    — governance event name → control ID
  - SUPPORTED_CONTROLS — ordered list of supported control IDs
  - CRITICAL_CONTROLS  — controls requiring immediate alerting on FAIL
  - FRAMEWORK_CONTROLS — framework name → list of control IDs  (Tier 2.1)
  - SUPPORTED_FRAMEWORKS — sorted list of supported framework short-names
  - EVIDENCE_SLA_SECONDS — per-control max-stale evidence window (Tier 2.5)
  - OscalFinding       — Pydantic model for OSCAL assessment findings
  - ComplianceMetrics  — Pydantic model for /v1/metrics response

src/governed_financial_advisor/utils/langfuse_utils.py imports ISO_CONTROL_MAP
from here (single source of truth). src/gateway/governance/ontology.py keeps
a separate short-form alias map — see TradingKnowledgeGraph.ISO_CONTROL_MAP.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# ComplianceMetrics — the JSON response shape returned by GET /v1/metrics/:control_id
# This is the exact object that Lula's OPA Rego provider receives as `input`.
# ---------------------------------------------------------------------------

class ComplianceMetrics(BaseModel):
    control_id: str
    safety_rate: float = Field(ge=0.0, le=1.0)
    total_traces: int = Field(ge=0)
    blocked_traces: int = Field(ge=0)
    passed_traces: int = Field(ge=0)
    window_hours: float = Field(gt=0)
    last_event_utc: str  # ISO 8601 datetime string
    evidence_age_seconds: float = Field(ge=0)
    startup_grace_active: bool
    startup_grace_remaining_hours: float = Field(ge=0)


# ---------------------------------------------------------------------------
# OscalFinding — used by parse_oscal_yaml() and audit_workflow
# Mirrors the Zod OscalFindingSchema in types.ts
# ---------------------------------------------------------------------------

OscalResult = Literal["PASS", "FAIL", "NOT_APPLICABLE", "ERROR"]
# ERROR semantics (per NIST SP 800-53A assessment procedures):
#   PASS           — evidence meets the assessment objective (Satisfied)
#   FAIL           — evidence fails the assessment objective (Not-Satisfied)
#   NOT_APPLICABLE — the control does not apply to this system component
#                    (e.g. a wireless control on a wired-only system)
#   ERROR          — the control applies but the scanner/collector failed to
#                    gather evidence ("fetch failed", timeout, etc.).
#                    Must NEVER be masked as NOT_APPLICABLE — auditing frameworks
#                    require this to be flagged as Incomplete/Unknown so the
#                    security blind spot is visible.  (NIST SP 800-53A §3.2)


class OscalFinding(BaseModel):
    """Immutable OSCAL assessment finding produced by the audit pipeline.

    This model is **frozen** (``ConfigDict(frozen=True)``) to enforce immutability
    of the intent payload after construction.  The hash-chained
    ``ContextAccumulator`` relies on the payload being stable once appended —
    any post-construction mutation would silently corrupt the SHA-256 chain and
    invalidate tamper-detection (ISO 42001 A.5.3 / CSA AARM Context Accumulator
    mandate).

    Downstream consumers that need a modified copy must create a new instance::

        updated = finding.model_copy(update={"finding_id": new_id})

    Never mutate a finding in-place after it has been passed to
    ``ContextAccumulator.append_finding()``.
    """

    model_config = ConfigDict(frozen=True)

    control_id:  str
    result:      OscalResult
    safety_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_age_s: float | None = Field(default=None, ge=0)
    finding_id:  str
    remarks:     str | None = None
    # Optional position in the Context Accumulator chain (CAGE v2.0.0)
    # Populated by audit_workflow after the ContextAccumulator appends the finding.
    chain_index: int | None = None


# ---------------------------------------------------------------------------
# CONTROL_META — control ID → display name + Langfuse score name +
#                multi-framework cross-references (Tier 2.1)
#
# frameworks: dict mapping framework short-name → clause / article reference.
#   "iso42001"    — ISO/IEC 42001:2023 AI Management System
#   "eu_ai_act"   — EU AI Act (2024/1689)
#   "nist_ai_rmf" — NIST AI Risk Management Framework 1.0
#   "fedramp"     — FedRAMP HIGH baseline (NIST SP 800-53 Rev 5)
# ---------------------------------------------------------------------------

CONTROL_META: dict[str, dict] = {
    "A.5.2": {
        "name":      "Social Impact Assessment",
        "scoreName": "iso42001.A.5.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.5.2",
        "frameworks": {
            "iso42001":    "Annex A.5.2",
            "eu_ai_act":   "Art. 9 (Risk Management System)",
            "nist_ai_rmf": "GOVERN 1.1, MAP 3.5",
            "aarm":        "AARM-V2 (Goal Hijacking), AARM-V5 (Prompt Injection)",
        },
    },
    "A.5.3": {
        "name":      "Logging and Monitoring",
        "scoreName": "iso42001.A.5.3.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.5.3",
        "frameworks": {
            "iso42001":    "Annex A.5.3",
            "eu_ai_act":   "Art. 12 (Record-Keeping)",
            "nist_ai_rmf": "MEASURE 2.6, GOVERN 5.1",
            "fedramp":     "AU-12 (Audit Record Generation)",
            "aarm":        "AARM-V1 (Memory Poisoning), AARM-V8 (Temporal Deception)",
        },
    },
    "A.6.2": {
        "name":      "AI System Lifecycle Controls",
        "scoreName": "iso42001.A.6.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.6.2",
        "frameworks": {
            "iso42001":    "Annex A.6.2",
            "eu_ai_act":   "Art. 9 §4 (Lifecycle Risk Management)",
            "nist_ai_rmf": "MANAGE 2.2, MAP 1.6",
            "aarm":        "AARM-V6 (Reward Hacking)",
        },
    },
    "A.8.4": {
        "name":      "AI System Operation Controls",
        "scoreName": "iso42001.A.8.4.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.8.4",
        "frameworks": {
            "iso42001":    "Annex A.8.4",
            "eu_ai_act":   "Art. 13 (Transparency & Human Oversight)",
            "nist_ai_rmf": "GOVERN 4.1, MANAGE 3.1",
            "aarm":        "AARM-V1 (Memory Poisoning), AARM-V3 (Confused Deputy), "
                           "AARM-V7 (Context Window Overflow / DEFER), "
                           "AARM-V9 (Privilege Escalation)",
        },
    },
    "A.9.2": {
        "name":      "Data Transfer to Suppliers",
        "scoreName": "iso42001.A.9.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.9.2",
        "frameworks": {
            "iso42001":    "Annex A.9.2",
            "eu_ai_act":   "Art. 10 (Data Governance)",
            "nist_ai_rmf": "MAP 2.3",
            "fedramp":     "SA-9 (External System Services)",
            "aarm":        "AARM-V5 (Prompt Injection), AARM-V10 (Data Exfiltration)",
        },
    },
    "SC-4": {
        "name":      "Fiscal Limits and RBAC",
        "scoreName": "iso42001.SC-4.passed",
        "iso_clause": "System Constraint SC-4",
        "frameworks": {
            "fedramp":     "AC-6 (Least Privilege), AC-3 (Access Enforcement)",
            "aarm":        "AARM-V2 (Goal Hijacking), AARM-V3 (Confused Deputy), "
                           "AARM-V4 (Cross-Agent Propagation), "
                           "AARM-V9 (Privilege Escalation), "
                           "AARM-V10 (Data Exfiltration), AARM-V11 (Model Substitution)",
        },
    },
    "SA-11": {
        "name":      "STPA Compiler — Developer Safety Testing",
        "scoreName": "nist.SA-11.passed",
        "iso_clause": "NIST SP 800-53 Rev 5 SA-11",
        "frameworks": {
            "fedramp":     "SA-11 (Developer Testing and Evaluation)",
            "eu_ai_act":   "Art. 9 §7 (Testing Procedures)",
            "nist_ai_rmf": "MEASURE 1.1",
        },
    },
    "SC-7": {
        "name":      "Boundary Protection — Cilium L7 Egress Lockdown",
        "scoreName": "nist.SC-7.passed",
        "iso_clause": "NIST SP 800-53 Rev 5 SC-7",
        "frameworks": {
            "fedramp":     "SC-7 (Boundary Protection)",
            "aarm":        "AARM-V10 (Data Exfiltration)",
        },
    },
    "SC-8": {
        "name":      "Transmission Confidentiality — Linkerd mTLS",
        "scoreName": "nist.SC-8.passed",
        "iso_clause": "NIST SP 800-53 Rev 5 SC-8",
        "frameworks": {
            "fedramp":     "SC-8 (Transmission Confidentiality and Integrity)",
            "aarm":        "AARM-V4 (Cross-Agent Propagation), AARM-V11 (Model Substitution)",
        },
    },
    "AC-2": {
        "name":      "Account Management",
        "scoreName": "fedramp.AC-2.passed",
        "iso_clause": "NIST SP 800-53 Rev 5 AC-2",
        "frameworks": {
            "fedramp": "AC-2 (Account Management)",
        },
    },
    "IR-1": {
        "name":      "Incident Response Policy and Procedures",
        "scoreName": "fedramp.IR-1.passed",
        "iso_clause": "NIST SP 800-53 Rev 5 IR-1",
        "frameworks": {
            "fedramp": "IR-1 (Incident Response Policy and Procedures)",
        },
    },
    "Article 12": {
        "name":      "Record-Keeping",
        "scoreName": "eu_ai_act.Article_12.passed",
        "iso_clause": "EU AI Act Art. 12",
        "frameworks": {
            "eu_ai_act": "Art. 12 (Record-Keeping)",
        },
    },
    "Article 13": {
        "name":      "Transparency & Human Oversight",
        "scoreName": "eu_ai_act.Article_13.passed",
        "iso_clause": "EU AI Act Art. 13",
        "frameworks": {
            "eu_ai_act": "Art. 13 (Transparency & Human Oversight)",
        },
    },
}

# Ordered list — order mirrors the TypeScript `as const` tuple
SUPPORTED_CONTROLS: list[str] = list(CONTROL_META.keys())

# Controls that trigger immediate Slack/PagerDuty alert on FAIL (Step 4 of workflow)
CRITICAL_CONTROLS: set[str] = {"A.9.2", "SC-4", "A.8.4"}

# ---------------------------------------------------------------------------
# FRAMEWORK_CONTROLS — framework short-name → list[control_id]  (Tier 2.1)
#
# Derived automatically from CONTROL_META so it never drifts out of sync.
# Used by GET /v1/controls?framework=eu_ai_act to return a filtered view.
# ---------------------------------------------------------------------------

FRAMEWORK_CONTROLS: dict[str, list[str]] = {}
for _cid, _meta in CONTROL_META.items():
    for _fw in _meta.get("frameworks", {}).keys():
        FRAMEWORK_CONTROLS.setdefault(_fw, []).append(_cid)

# Sorted list of valid framework short-names for input validation
SUPPORTED_FRAMEWORKS: list[str] = sorted(FRAMEWORK_CONTROLS.keys())

# ---------------------------------------------------------------------------
# EVIDENCE_SLA_SECONDS — per-control maximum acceptable staleness (Tier 2.5)
#
# The SLA monitor background task fires a notifier alert when
# evidence_age_seconds for a control exceeds its SLA threshold.
# Controls absent from this dict are still monitored but not SLA-gated.
# ---------------------------------------------------------------------------

EVIDENCE_SLA_SECONDS: dict[str, int] = {
    "A.9.2": 3_600,    # PII masking — max 1 h stale
    "SC-4":  7_200,    # Fiscal controls — max 2 h stale
    "A.8.4": 3_600,    # STPA operation — max 1 h stale
    "A.5.3": 14_400,   # Logging — max 4 h stale
    "SC-8":  86_400,   # mTLS — daily is fine (infrastructure-level)
    "SC-7":  86_400,   # Cilium L7 — daily is fine
}

# ---------------------------------------------------------------------------
# ISO_CONTROL_MAP — governance event name → control ID
#
# This is the canonical, single source of truth for the entire codebase.
# All other modules must import from here rather than defining their own copy.
#
# Maps governance event hook names (emitted by OTel spans in the Python nodes
# and TypeScript gateway middleware) to the ISO 42001 Annex A control ID that
# those events provide evidence for.
# ---------------------------------------------------------------------------

ISO_CONTROL_MAP: dict[str, str] = {
    "nemo_input_scan":    "A.9.2",   # Data Privacy / PII Masking
    "nemo_output_rail":   "A.5.2",   # Social Impact / Content Safety
    "opa_policy_check":   "SC-4",    # Fiscal Controls / RBAC
    "otel_trace":         "A.5.3",   # Logging & Monitoring / Audit Trail
    "stpa_validation":    "A.8.4",   # AI System Operation — STPA UCA checks
    "stpa_compile":       "SA-11",   # Developer Safety Testing — compiler run
    "causal_gatekeeper":  "A.6.2",   # AI Lifecycle — DoWhy causal refutation
    "linkerd_mtls":       "SC-8",    # Transmission Confidentiality — Linkerd mTLS
    "cilium_l7_egress":   "SC-7",    # Boundary Protection — Cilium FQDN filtering
    "saga_rollback":      "A.8.4",   # AI System Operation — Saga compensating node execution
    # CAGE v2.0.0 — AARM primitives
    "context_accumulate": "A.5.3",   # Context Accumulator chain node — Logging & Monitoring
    "defer_parking":      "A.8.4",   # DEFER state machine — AI System Operation Controls
}

