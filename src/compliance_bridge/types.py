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
types.py — Canonical ISO 42001 control metadata and Pydantic models (CAGE v3.0.0+).

Ported from src/langfuse-bridge/src/types.ts.

This module is the single authoritative source of truth for:
  - _UNIVERSAL_CONTROLS       — ISO 42001 controls applicable to ALL regions
  - _JURISDICTIONAL_CONTROLS  — region-keyed dict of framework-specific controls
  - get_control_meta(region)  — accessor returning universal + jurisdictional controls
  - _UNIVERSAL_CONTROL_MAP    — governance event name → control ID (universal)
  - _JURISDICTIONAL_CONTROL_MAP — region-keyed event → control mappings
  - get_iso_control_map(region) — accessor returning universal + jurisdictional map
  - SUPPORTED_CONTROLS        — ordered list of universal control IDs
  - CRITICAL_CONTROLS         — controls requiring immediate alerting on FAIL
  - FRAMEWORK_CONTROLS        — framework name → list of control IDs  (Tier 2.1)
  - SUPPORTED_FRAMEWORKS      — sorted list of supported framework short-names
  - _UNIVERSAL_SLA            — per-control max-stale evidence window (ISO 42001 only)
  - _JURISDICTIONAL_SLA       — region-keyed SLA overrides for jurisdictional controls
  - get_sla_seconds(region)   — accessor returning universal + jurisdictional SLA dict
  - OscalFinding              — Pydantic model for OSCAL assessment findings
  - ComplianceMetrics         — Pydantic model for /v1/metrics response

v3.0.0 Breaking Changes:
  - CONTROL_META alias removed — use get_control_meta(region)
  - EVIDENCE_SLA_SECONDS alias removed — use get_sla_seconds(region)
  - ISO_CONTROL_MAP alias removed — use get_iso_control_map(region)

FINDING-01 (CRITICAL): CONTROL_META was a flat dict mixing ISO 42001 (universal)
with NIST SP 800-53 / FedRAMP (US_FED only) and EU AI Act (EU_ECB only) controls.
Restructured into _UNIVERSAL_CONTROLS + _JURISDICTIONAL_CONTROLS with get_control_meta()
accessor so each region only receives its applicable controls.

FINDING-05 (HIGH, REMEDIATED): EVIDENCE_SLA_SECONDS mixed ISO and NIST SLA
targets in a flat dict. Restructured into _UNIVERSAL_SLA + _JURISDICTIONAL_SLA
with get_sla_seconds() accessor so the SLA monitor can alert only on controls
applicable to the active region. sla_monitor.py now calls
get_sla_seconds(CAGE_DEPLOYMENT_REGION) via its _active_sla_seconds() helper,
resolved fresh on every poll cycle. See FINDING-05 in
docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md.

src/governed_financial_advisor/utils/langfuse_utils.py uses get_iso_control_map()
from here (single source of truth). src/gateway/governance/ontology.py provides
its own TradingKnowledgeGraph.get_control_map(region) for short-form event mapping.
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
    # M-10: None when no traces exist in the window (avoids false-positive 1.0 score)
    safety_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    total_traces: int = Field(ge=0)
    blocked_traces: int = Field(ge=0)
    passed_traces: int = Field(ge=0)
    window_hours: float = Field(gt=0)
    last_event_utc: str  # ISO 8601 datetime string
    evidence_age_seconds: float = Field(ge=0)
    startup_grace_active: bool
    startup_grace_remaining_hours: float = Field(ge=0)
    # AI600-001: Confabulation / hallucination scoring fields.
    # None until the first confabulation_risk Langfuse score is observed.
    # confabulation_rate = confabulation_blocked_traces / total_traces
    # when total_traces > 0; None otherwise.
    confabulation_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    confabulation_blocked_traces: int = Field(default=0, ge=0)


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

    control_id: str
    result: OscalResult
    safety_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_age_s: float | None = Field(default=None, ge=0)
    finding_id: str
    remarks: str | None = None
    # Optional position in the Context Accumulator chain (CAGE v2.0.0+)
    # Populated by audit_workflow after the ContextAccumulator appends the finding.
    chain_index: int | None = None


# ---------------------------------------------------------------------------
# FINDING-01 (CRITICAL) — Region-keyed control metadata
#
# _UNIVERSAL_CONTROLS: ISO 42001 controls applicable to ALL regions.
#   No CAGE_DEPLOYMENT_REGION guard required — these always apply.
#
# _JURISDICTIONAL_CONTROLS: region-keyed dict of framework-specific controls.
#   US_FED  → NIST SP 800-53 / FedRAMP HIGH controls
#   EU_ECB  → EU AI Act (2024/1689) controls
#   APAC_MAS → MAS FEAT / MAS Notice 655 controls
#
# Use get_control_meta(region) to obtain the merged view for a given region.
# Never iterate CONTROL_META directly in new code — it is a backward-compat alias.
#
# frameworks: dict mapping framework short-name → clause / article reference.
#   "iso42001"    — ISO/IEC 42001:2023 AI Management System  (universal)
#   "eu_ai_act"   — EU AI Act (2024/1689)                    (EU_ECB only)
#   "nist_ai_rmf" — NIST AI Risk Management Framework 1.0    (US_FED only)
#   "fedramp"     — FedRAMP HIGH baseline (NIST SP 800-53 Rev 5) (US_FED only)
#   "mas_feat"    — MAS FEAT                                  (APAC_MAS only)
# ---------------------------------------------------------------------------

_UNIVERSAL_CONTROLS: dict[str, dict] = {
    "A.5.2": {
        "name": "Social Impact Assessment",
        "scoreName": "iso42001.A.5.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.5.2",
        "frameworks": {
            "iso42001": "Annex A.5.2",
            "aarm": "AARM-V2 (Goal Hijacking), AARM-V5 (Prompt Injection)",
        },
    },
    "A.5.3": {
        "name": "Logging and Monitoring",
        "scoreName": "iso42001.A.5.3.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.5.3",
        "frameworks": {
            "iso42001": "Annex A.5.3",
            "aarm": "AARM-V1 (Memory Poisoning), AARM-V8 (Temporal Deception)",
        },
    },
    "A.6.2": {
        "name": "AI System Lifecycle Controls",
        "scoreName": "iso42001.A.6.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.6.2",
        "frameworks": {
            "iso42001": "Annex A.6.2",
            "aarm": "AARM-V6 (Reward Hacking)",
        },
    },
    "A.8.4": {
        "name": "AI System Operation Controls",
        "scoreName": "iso42001.A.8.4.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.8.4",
        "frameworks": {
            "iso42001": "Annex A.8.4",
            "aarm": "AARM-V1 (Memory Poisoning), AARM-V3 (Confused Deputy), "
            "AARM-V7 (Context Window Overflow / DEFER), "
            "AARM-V9 (Privilege Escalation)",
        },
    },
    "A.9.2": {
        "name": "Data Transfer to Suppliers",
        "scoreName": "iso42001.A.9.2.passed",
        "iso_clause": "ISO/IEC 42001:2023 Annex A.9.2",
        "frameworks": {
            "iso42001": "Annex A.9.2",
            "aarm": "AARM-V5 (Prompt Injection), AARM-V10 (Data Exfiltration)",
        },
    },
    # SC-4 is a CAGE-internal system constraint (not a NIST control).
    # It is universal because fiscal limits and RBAC apply in all regions.
    "SC-4": {
        "name": "Fiscal Limits and RBAC",
        "scoreName": "iso42001.SC-4.passed",
        "iso_clause": "System Constraint SC-4",
        "frameworks": {
            "aarm": "AARM-V2 (Goal Hijacking), AARM-V3 (Confused Deputy), "
            "AARM-V4 (Cross-Agent Propagation), "
            "AARM-V9 (Privilege Escalation), "
            "AARM-V10 (Data Exfiltration), AARM-V11 (Model Substitution)",
        },
    },
}

_JURISDICTIONAL_CONTROLS: dict[str, dict[str, dict]] = {
    # ------------------------------------------------------------------
    # US_FED — NIST SP 800-53 Rev 5 / FedRAMP HIGH / NIST AI 600-1
    # CAGE_DEPLOYMENT_REGION=US_FED only. No legal force in EU_ECB or APAC_MAS.
    # ------------------------------------------------------------------
    "US_FED": {
        "SA-11": {
            "name": "STPA Compiler — Developer Safety Testing",
            "scoreName": "nist.SA-11.passed",
            "iso_clause": "NIST SP 800-53 Rev 5 SA-11",
            "frameworks": {
                "fedramp": "SA-11 (Developer Testing and Evaluation)",
                "nist_ai_rmf": "MEASURE 1.1",
            },
        },
        "SC-7": {
            "name": "Boundary Protection — Cilium L7 Egress Lockdown",
            "scoreName": "nist.SC-7.passed",
            "iso_clause": "NIST SP 800-53 Rev 5 SC-7",
            "frameworks": {
                "fedramp": "SC-7 (Boundary Protection)",
                "aarm": "AARM-V10 (Data Exfiltration)",
            },
        },
        "SC-8": {
            "name": "Transmission Confidentiality — Linkerd mTLS",
            "scoreName": "nist.SC-8.passed",
            "iso_clause": "NIST SP 800-53 Rev 5 SC-8",
            "frameworks": {
                "fedramp": "SC-8 (Transmission Confidentiality and Integrity)",
                "aarm": "AARM-V4 (Cross-Agent Propagation), AARM-V11 (Model Substitution)",
            },
        },
        "AC-2": {
            "name": "Account Management",
            "scoreName": "fedramp.AC-2.passed",
            "iso_clause": "NIST SP 800-53 Rev 5 AC-2",
            "frameworks": {
                "fedramp": "AC-2 (Account Management)",
            },
        },
        "IR-1": {
            "name": "Incident Response Policy and Procedures",
            "scoreName": "fedramp.IR-1.passed",
            "iso_clause": "NIST SP 800-53 Rev 5 IR-1",
            "frameworks": {
                "fedramp": "IR-1 (Incident Response Policy and Procedures)",
            },
        },
    },
    # ------------------------------------------------------------------
    # EU_ECB — EU AI Act (2024/1689) / GDPR / DORA
    # CAGE_DEPLOYMENT_REGION=EU_ECB only.
    # ------------------------------------------------------------------
    "EU_ECB": {
        "Article 12": {
            "name": "Record-Keeping",
            "scoreName": "eu_ai_act.Article_12.passed",
            "iso_clause": "EU AI Act Art. 12",
            "frameworks": {
                "eu_ai_act": "Art. 12 (Record-Keeping)",
            },
        },
        "Article 13": {
            "name": "Transparency & Human Oversight",
            "scoreName": "eu_ai_act.Article_13.passed",
            "iso_clause": "EU AI Act Art. 13",
            "frameworks": {
                "eu_ai_act": "Art. 13 (Transparency & Human Oversight)",
            },
        },
    },
    # ------------------------------------------------------------------
    # APAC_MAS — MAS FEAT / MAS Notice 655 / MAS TRM
    # CAGE_DEPLOYMENT_REGION=APAC_MAS only.
    # ------------------------------------------------------------------
    "APAC_MAS": {
        "MAS-FEAT-1": {
            "name": "Fairness Assessment",
            "scoreName": "mas_feat.MAS_FEAT_1.passed",
            "iso_clause": "MAS FEAT Principle 1 (Fairness)",
            "frameworks": {
                "mas_feat": "MAS FEAT Principle 1 — Fairness",
            },
        },
    },
}


def get_control_meta(region: str) -> dict[str, dict]:
    """Return controls applicable to the given deployment region.

    Merges the universal ISO 42001 controls with the jurisdictional controls
    for the specified region.  Controls from other regions are excluded so
    that each deployment only exposes its applicable compliance framework.

    Args:
        region: CAGE_DEPLOYMENT_REGION value — one of "US_FED", "EU_ECB",
                "APAC_MAS".  Unknown values return universal controls only.

    Returns:
        A dict mapping control_id → control metadata for the given region.
    """
    return {
        **_UNIVERSAL_CONTROLS,
        **_JURISDICTIONAL_CONTROLS.get(region, {}),
    }


# ---------------------------------------------------------------------------
# SUPPORTED_CONTROLS — ordered list of ALL known control IDs.
#
# Includes universal ISO 42001 controls AND all jurisdictional controls
# (US_FED, EU_ECB, APAC_MAS) so that:
#   - FRAMEWORK_CONTROLS values are always a subset of SUPPORTED_CONTROLS
#   - ISO_CONTROL_MAP values (universal only) are always a subset
#   - The /v1/controls endpoint can filter by region at request time
#
# Note: CONTROL_META (backward-compat alias) contains universal controls only.
# Use get_control_meta(region) to obtain the region-filtered view.
# ---------------------------------------------------------------------------

_ALL_CONTROLS: dict[str, dict] = dict(_UNIVERSAL_CONTROLS)
for _region_controls in _JURISDICTIONAL_CONTROLS.values():
    _ALL_CONTROLS.update(_region_controls)

SUPPORTED_CONTROLS: list[str] = list(_ALL_CONTROLS.keys())

# Controls that trigger immediate Slack/PagerDuty alert on FAIL (Step 4 of workflow)
CRITICAL_CONTROLS: set[str] = {"A.9.2", "SC-4", "A.8.4"}

# ---------------------------------------------------------------------------
# FRAMEWORK_CONTROLS — framework short-name → list[control_id]  (Tier 2.1)
#
# Derived automatically from ALL controls (universal + jurisdictional) so it
# never drifts out of sync.  All control IDs in FRAMEWORK_CONTROLS are
# guaranteed to be in SUPPORTED_CONTROLS.
# Used by GET /v1/controls?framework=iso42001 to return a filtered view.
# For region-filtered views, callers must use get_control_meta(region).
# ---------------------------------------------------------------------------

FRAMEWORK_CONTROLS: dict[str, list[str]] = {}
for _cid, _meta in _ALL_CONTROLS.items():
    for _fw in _meta.get("frameworks", {}).keys():
        FRAMEWORK_CONTROLS.setdefault(_fw, []).append(_cid)

# Sorted list of valid framework short-names for input validation
SUPPORTED_FRAMEWORKS: list[str] = sorted(FRAMEWORK_CONTROLS.keys())

# ---------------------------------------------------------------------------
# FINDING-05 (HIGH, REMEDIATED) — Region-keyed SLA targets
#
# _UNIVERSAL_SLA: ISO 42001 controls only — applicable in all regions.
# _JURISDICTIONAL_SLA: region-keyed SLA overrides for jurisdictional controls.
#
# The SLA monitor background task (src/compliance_bridge/sla_monitor.py) calls
# get_sla_seconds(region) rather than iterating EVIDENCE_SLA_SECONDS directly,
# so that NIST SLA targets (SC-7, SC-8) do not generate spurious breach alerts
# in EU_ECB / APAC_MAS, and jurisdictional targets are monitored in their
# applicable region.
# ---------------------------------------------------------------------------

_UNIVERSAL_SLA: dict[str, int] = {
    "A.9.2": 3_600,  # PII masking — max 1 h stale  (ISO 42001 A.9.2)
    "SC-4": 7_200,  # Fiscal controls — max 2 h stale  (CAGE-internal SC-4)
    "A.8.4": 3_600,  # STPA operation — max 1 h stale  (ISO 42001 A.8.4)
    "A.5.3": 14_400,  # Logging — max 4 h stale  (ISO 42001 A.5.3)
}

_JURISDICTIONAL_SLA: dict[str, dict[str, int]] = {
    # US_FED: NIST SP 800-53 infrastructure controls — daily cadence is acceptable
    "US_FED": {
        "SC-8": 86_400,  # mTLS — daily is fine (infrastructure-level, NIST SC-8)
        "SC-7": 86_400,  # Cilium L7 — daily is fine (NIST SC-7)
    },
    # EU_ECB: DORA Art. 10 mandates tighter audit logging cadence
    "EU_ECB": {
        "Article 12": 14_400,  # EU AI Act Art. 12 record-keeping — max 4 h stale
    },
    # APAC_MAS: MAS Notice 655 audit logging
    "APAC_MAS": {
        "MAS-FEAT-1": 86_400,  # MAS FEAT fairness — daily assessment
    },
}


def get_sla_seconds(region: str) -> dict[str, int]:
    """Return SLA thresholds applicable to the given deployment region.

    Merges the universal ISO 42001 SLA targets with the jurisdictional SLA
    overrides for the specified region.  SLA targets for other regions are
    excluded so the SLA monitor only alerts on applicable controls.

    Args:
        region: CAGE_DEPLOYMENT_REGION value — one of "US_FED", "EU_ECB",
                "APAC_MAS".  Unknown values return universal SLA targets only.

    Returns:
        A dict mapping control_id → max acceptable staleness in seconds.
    """
    return {
        **_UNIVERSAL_SLA,
        **_JURISDICTIONAL_SLA.get(region, {}),
    }


# ---------------------------------------------------------------------------
# ISO_CONTROL_MAP — governance event name → control ID (universal / ISO 42001)
#
# This is the canonical, single source of truth for the entire codebase.
# All other modules must import from here rather than defining their own copy.
#
# Maps governance event hook names (emitted by OTel spans in the Python nodes
# and TypeScript gateway middleware) to the ISO 42001 Annex A control ID that
# those events provide evidence for.
#
# FINDING-01 follow-up: US_FED-only entries (stpa_compile→SA-11,
# linkerd_mtls→SC-8, cilium_l7_egress→SC-7) have been moved to
# _JURISDICTIONAL_CONTROL_MAP["US_FED"] below.  ISO_CONTROL_MAP now contains
# only universal (ISO 42001 / CAGE-internal) controls so that
# SUPPORTED_CONTROLS ⊇ ISO_CONTROL_MAP.values() holds in all regions.
# Use get_iso_control_map(region) to obtain the merged view for a given region.
# ---------------------------------------------------------------------------

_UNIVERSAL_CONTROL_MAP: dict[str, str] = {
    "nemo_input_scan": "A.9.2",  # Data Privacy / PII Masking
    "nemo_output_rail": "A.5.2",  # Social Impact / Content Safety
    "opa_policy_check": "SC-4",  # Fiscal Controls / RBAC
    "otel_trace": "A.5.3",  # Logging & Monitoring / Audit Trail
    "stpa_validation": "A.8.4",  # AI System Operation — STPA UCA checks
    "causal_gatekeeper": "A.6.2",  # AI Lifecycle — DoWhy causal refutation
    "saga_rollback": "A.8.4",  # AI System Operation — Saga compensating node execution
    # CAGE v2.0.0+ — AARM primitives
    "context_accumulate": "A.5.3",  # Context Accumulator chain node — Logging & Monitoring
    "defer_parking": "A.8.4",  # DEFER state machine — AI System Operation Controls
}

_JURISDICTIONAL_CONTROL_MAP: dict[str, dict[str, str]] = {
    # US_FED — NIST SP 800-53 / FedRAMP HIGH governance event mappings.
    # SR 26-2: these control IDs have no legal force outside US_FED.
    "US_FED": {
        "stpa_compile": "SA-11",  # Developer Safety Testing — compiler run
        "linkerd_mtls": "SC-8",  # Transmission Confidentiality — Linkerd mTLS
        "cilium_l7_egress": "SC-7",  # Boundary Protection — Cilium FQDN filtering
    },
}


def get_iso_control_map(region: str) -> dict[str, str]:
    """Return the governance event → control ID map for the given deployment region.

    Merges the universal ISO 42001 control map with the jurisdictional
    event mappings for the specified region.  Entries from other regions
    are excluded so each deployment only exposes its applicable framework.

    Args:
        region: CAGE_DEPLOYMENT_REGION value — one of "US_FED", "EU_ECB",
                "APAC_MAS".  Unknown values return universal controls only.

    Returns:
        A dict mapping governance event name → control identifier.
    """
    return {
        **_UNIVERSAL_CONTROL_MAP,
        **_JURISDICTIONAL_CONTROL_MAP.get(region, {}),
    }
