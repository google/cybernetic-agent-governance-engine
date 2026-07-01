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
aarm_mapper.py — AARM Threat Vector Ledger (CAGE v0.1.0)

AARM Conformance: Satisfies the "Native AARM Threat Vector Mapping" mandate from
the CSA Autonomous Agent Risk Management (AARM) specification — machine-readable
proof that specific CAGE control points neutralize each of the 11 AARM attack
vectors.

Architecture:
  ``AARM_THREAT_VECTORS`` is a static, version-pinned ledger mapping each of the
  11 AARM vectors to:
    - The CAGE control ID(s) that neutralize it
    - The corresponding Lula validation file(s)
    - The implementation file(s) that enforce the control
    - The AARM severity rating

  ``build_aarm_conformance_report()`` joins this static ledger against live
  OscalFinding results from the audit pipeline to produce a dynamic conformance
  verdict per vector:
    NEUTRALIZED — all neutralizing controls PASS
    PARTIAL     — at least one neutralizing control PASS, at least one FAIL
    EXPOSED     — all neutralizing controls FAIL or not found in findings

  The report is auto-serialized to GCS/S3 at the end of every Lula scheduled run
  (``<audit_id>/aarm_conformance.json``) and also available on-demand via
  GET /v1/aarm/conformance-report.

AARM Threat Vector Reference:
  11 vectors from CSA AARM v1.0 specification (Cloud Security Alliance, 2025).
  Severity levels: CRITICAL | HIGH | MEDIUM.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel

from .types import CONTROL_META, OscalFinding

# ---------------------------------------------------------------------------
# AARMSeverity, ConformanceStatus
# ---------------------------------------------------------------------------

AARMSeverity      = Literal["CRITICAL", "HIGH", "MEDIUM"]
ConformanceStatus = Literal["NEUTRALIZED", "PARTIAL", "EXPOSED", "UNKNOWN"]


# ---------------------------------------------------------------------------
# AARMVector — static descriptor for one threat vector
# ---------------------------------------------------------------------------

class AARMVector(BaseModel):
    """Static descriptor for one AARM threat vector.

    Attributes:
        vector_id:            AARM canonical ID (e.g. "AARM-V1").
        name:                 Short human-readable name.
        description:          Concise attack description.
        aarm_severity:        CSA severity classification.
        neutralizing_controls: CAGE control IDs that together neutralize this vector.
        lula_validation_files: Relative paths to lula-validation-*.yaml manifests.
        implementation_files:  Key source files enforcing the controls.
        notes:                 Additional context for report card consumers.
    """

    vector_id:             str
    name:                  str
    description:           str
    aarm_severity:         AARMSeverity
    neutralizing_controls: list[str]
    lula_validation_files: list[str]
    implementation_files:  list[str]
    notes:                 str = ""


# ---------------------------------------------------------------------------
# AARM_THREAT_VECTORS — the 11-vector threat ledger
# ---------------------------------------------------------------------------

AARM_THREAT_VECTORS: dict[str, AARMVector] = {
    "AARM-V1": AARMVector(
        vector_id    = "AARM-V1",
        name         = "Memory Poisoning",
        description  = (
            "Adversary injects malicious content into the agent's persistent memory "
            "or context store, causing future reasoning to be corrupted."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["A.5.3", "A.8.4"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a53.yaml",
            "compliance/lula/lula-validation-a84.yaml",
        ],
        implementation_files   = [
            "src/compliance_bridge/context_accumulator.py",
            "src/compliance_bridge/audit_workflow.py",
        ],
        notes=(
            "SHA-256 hash-chained Context Accumulator (CAGE v0.1.0) provides "
            "tamper-evident append-only session state logging. Any poisoning attempt "
            "breaks the chain at the mutated node and is detected by verify_integrity()."
        ),
    ),
    "AARM-V2": AARMVector(
        vector_id    = "AARM-V2",
        name         = "Goal Hijacking",
        description  = (
            "Adversary manipulates agent objectives via crafted prompts or tool "
            "responses to redirect the agent toward unauthorized goals."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["A.5.2", "SC-4"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a52.yaml",
            "compliance/lula/lula-validation-sc4.yaml",
        ],
        implementation_files   = [
            "src/gateway/governance/nemo/manager.py",
            "src/governed_financial_advisor/governance/policy/trade_governance.rego",
            "config/rails/",
        ],
        notes=(
            "NeMo Guardrails Colang rails enforce topic lock-down at Layer 0. "
            "OPA trade_governance.rego provides declarative goal constraints at Layer 3, "
            "independent of LLM reasoning."
        ),
    ),
    "AARM-V3": AARMVector(
        vector_id    = "AARM-V3",
        name         = "Confused Deputy",
        description  = (
            "Malicious caller exploits the agent's elevated privileges by coercing "
            "it to perform actions on the attacker's behalf."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["SC-4", "A.8.4"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-sc4.yaml",
        ],
        implementation_files   = [
            "src/governed_financial_advisor/graph/nodes/evaluator_node.py",
            "src/gateway/server/hybrid_server.py",
        ],
        notes=(
            "HMAC-SHA256 governance signature (Layer 4 Signed Handshake) gates every "
            "evaluator→executor transition. Missing or invalid signatures route the "
            "graph to the explainer node — trade never executes."
        ),
    ),
    "AARM-V4": AARMVector(
        vector_id    = "AARM-V4",
        name         = "Cross-Agent Propagation",
        description  = (
            "Compromise of one agent spreads laterally to other agents sharing "
            "state, tool access, or communication channels."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["SC-4", "SC-8"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-sc4.yaml",
            "compliance/lula/lula-validation-sc8.yaml",
        ],
        implementation_files   = [
            "src/gateway/governance/fiscal_limit_guard.py",
            "deployment/k8s/linkerd-annotations.yaml",
        ],
        notes=(
            "FiscalLimitGuard atomically pre-reserves capacity (Redis WATCH/MULTI/EXEC) "
            "to prevent concurrent agents from exceeding daily caps (TOCTOU elimination). "
            "Linkerd mTLS encrypts all intra-cluster agent communications."
        ),
    ),
    "AARM-V5": AARMVector(
        vector_id    = "AARM-V5",
        name         = "Prompt Injection",
        description  = (
            "Attacker embeds adversarial instructions in external content that the "
            "agent processes, hijacking its execution flow."
        ),
        aarm_severity          = "HIGH",
        neutralizing_controls  = ["A.5.2", "A.9.2"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a52.yaml",
            "compliance/lula/lula-validation-a92.yaml",
        ],
        implementation_files   = [
            "src/gateway/governance/nemo/manager.py",
        ],
        notes=(
            "Three-tier semantic shielding: Tier 1 Aho-Corasick heuristic, "
            "Tier 2 SLM semantic similarity, NeMo Guardrails Colang rails. "
            "Presidio strips PII from all injection payloads before they reach inference."
        ),
    ),
    "AARM-V6": AARMVector(
        vector_id    = "AARM-V6",
        name         = "Reward Hacking",
        description  = (
            "Agent discovers unintended shortcuts to maximize its reward signal "
            "in ways misaligned with operator intent."
        ),
        aarm_severity          = "HIGH",
        neutralizing_controls  = ["A.6.2"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a92.yaml",  # closest available Lula manifest
        ],
        implementation_files   = [
            "src/gateway/governance/causal_gatekeeper.py",
            "src/gateway/governance/telemetry_provider.py",
        ],
        notes=(
            "DoWhy Causal Gatekeeper placebo refutation test validates world-model "
            "integrity before every trade. If replacing the real treatment with noise "
            "still produces a significant effect (p<0.05 or |effect|>0.2), the model "
            "is blocked — reward hacking is detectable as causal model corruption."
        ),
    ),
    "AARM-V7": AARMVector(
        vector_id    = "AARM-V7",
        name         = "Context Window Overflow",
        description  = (
            "Agent's effective context window is deliberately overflowed with "
            "irrelevant or adversarial content, causing key state to be evicted."
        ),
        aarm_severity          = "HIGH",
        neutralizing_controls  = ["A.8.4"],
        lula_validation_files  = [],
        implementation_files   = [
            "src/gateway/governance/defer_queue.py",
        ],
        notes=(
            "DEFER state machine (CAGE v0.1.0) parks execution context when "
            "confidence_score < 0.70 (Confidence-Starvation Boundary), preventing "
            "the agent from proceeding on fundamentally incomplete context. "
            "DeferQueue provides Redis-backed low-latency parking pending data injection."
        ),
    ),
    "AARM-V8": AARMVector(
        vector_id    = "AARM-V8",
        name         = "Temporal Deception",
        description  = (
            "Adversary manipulates time-sensitive inputs (stale prices, outdated "
            "policies) to create false beliefs about the current state of the world."
        ),
        aarm_severity          = "HIGH",
        neutralizing_controls  = ["A.5.3"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a53.yaml",
        ],
        implementation_files   = [
            "src/compliance_bridge/sla_monitor.py",
            "src/compliance_bridge/types.py",
        ],
        notes=(
            "Evidence SLA Monitor enforces per-control staleness thresholds "
            "(EVIDENCE_SLA_SECONDS in types.py). Lula validation gates reject "
            "evidence_age_seconds > 172800 (48h). Causal Gatekeeper uses "
            "live Langfuse telemetry with explicit evidence_age tracking."
        ),
    ),
    "AARM-V9": AARMVector(
        vector_id    = "AARM-V9",
        name         = "Privilege Escalation",
        description  = (
            "Agent attempts to acquire permissions beyond its designated scope, "
            "enabling unauthorized actions."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["SC-4", "A.8.4"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-sc4.yaml",
        ],
        implementation_files   = [
            "src/governed_financial_advisor/governance/policy/trade_governance.rego",
            "deployment/system_authz.rego",
            "config/agent_scope.yaml",
        ],
        notes=(
            "OPA RBAC enforces hard fiscal limits per role (junior: $5k/$10k, "
            "senior: $500k/$1M). agent_scope.yaml is the machine-readable scope "
            "declaration parsed by OPA and referenced by OSCAL SSP. "
            "SR 26-2 confidence_sufficient ≥ 0.95 gate in system_authz.rego "
            "prevents low-confidence escalation attempts from executing."
        ),
    ),
    "AARM-V10": AARMVector(
        vector_id    = "AARM-V10",
        name         = "Data Exfiltration",
        description  = (
            "Agent leaks sensitive data (PII, credentials, trade plans) to "
            "unauthorized external endpoints."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["A.9.2", "SC-7"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-a92.yaml",
            "compliance/lula/lula-validation-sc4.yaml",
        ],
        implementation_files   = [
            "src/gateway/governance/nemo/manager.py",
            "deployment/k8s/cilium-network-policy.yaml",
        ],
        notes=(
            "Presidio PII masking (20 entity types, spaCy en_core_web_sm) strips "
            "sensitive fields before any data leaves the cluster. Cilium L7 network "
            "policy enforces strict FQDN egress allowlist — sovereign agent pods "
            "cannot establish connections to unlisted external endpoints."
        ),
    ),
    "AARM-V11": AARMVector(
        vector_id    = "AARM-V11",
        name         = "Model Substitution",
        description  = (
            "Adversary replaces the production model with a compromised version "
            "that behaves identically under normal conditions but has backdoors."
        ),
        aarm_severity          = "CRITICAL",
        neutralizing_controls  = ["SC-8", "SC-4"],
        lula_validation_files  = [
            "compliance/lula/lula-validation-sc8.yaml",
        ],
        implementation_files   = [
            "Dockerfile.vllm",
            "deployment/k8s/vllm-deployment.yaml",
            "src/compliance_bridge/cmek_guard.py",
        ],
        notes=(
            "Sovereign vLLM deployment on GKE: all inference runs within cluster "
            "boundary (no external LLM API calls). CAGE_ROUTING_SEAL_SECRET "
            "(POAM-012 / NIST SC-12) provides cryptographic enforcement of governance "
            "routing seals. CMEK encryption guard (POAM-014 / NIST SC-28) protects "
            "model artifacts at rest."
        ),
    ),
}


# ---------------------------------------------------------------------------
# AARMVectorResult — per-vector conformance verdict
# ---------------------------------------------------------------------------

class AARMVectorResult(BaseModel):
    """Conformance verdict for a single AARM threat vector.

    Attributes:
        vector_id:              AARM canonical ID.
        name:                   Human-readable vector name.
        aarm_severity:          CSA severity classification.
        status:                 Machine-readable conformance verdict.
        neutralizing_controls:  CAGE control IDs mapped to this vector.
        control_results:        Mapping of control_id → "PASS" | "FAIL" | "NOT_FOUND".
        pass_count:             Number of controls that passed.
        fail_count:             Number of controls that failed.
        not_found_count:        Number of controls with no finding in the audit.
        lula_validation_files:  Lula manifest file paths for automated verification.
        implementation_files:   Source files enforcing the control.
        notes:                  Context narrative.
    """

    vector_id:             str
    name:                  str
    aarm_severity:         AARMSeverity
    status:                ConformanceStatus
    neutralizing_controls: list[str]
    control_results:       dict[str, str]
    pass_count:            int
    fail_count:            int
    not_found_count:       int
    lula_validation_files: list[str]
    implementation_files:  list[str]
    notes:                 str


# ---------------------------------------------------------------------------
# AARMConformanceReport — the full report card
# ---------------------------------------------------------------------------

class AARMConformanceReport(BaseModel):
    """Complete AARM Conformance Report Card for one audit run.

    Attributes:
        schema_version:   "cage-aarm-conformance/1.0"
        audit_id:         Parent audit run identifier.
        generated_utc:    ISO-8601 UTC timestamp of report generation.
        aarm_spec_version: CSA AARM specification version mapped against.
        total_vectors:    Always 11.
        neutralized:      Count of NEUTRALIZED vectors.
        partial:          Count of PARTIAL vectors.
        exposed:          Count of EXPOSED vectors.
        unknown:          Count of vectors with no finding data.
        overall_posture:  "SECURE" | "DEGRADED" | "CRITICAL" summary.
        vectors:          Per-vector AARMVectorResult list.
        chain_root:       SHA-256 chain root from the Context Accumulator (if available).
    """

    schema_version:    str = "cage-aarm-conformance/1.0"
    audit_id:          str
    generated_utc:     str
    aarm_spec_version: str = "CSA-AARM-v1.0"
    total_vectors:     int = 11
    neutralized:       int
    partial:           int
    exposed:           int
    unknown:           int
    overall_posture:   str
    vectors:           list[AARMVectorResult]
    chain_root:        str | None = None


# ---------------------------------------------------------------------------
# build_aarm_conformance_report — primary public function
# ---------------------------------------------------------------------------

def build_aarm_conformance_report(
    findings: list[OscalFinding],
    audit_id: str,
    chain_root: str | None = None,
) -> AARMConformanceReport:
    """Generate an AARM Conformance Report Card from live OscalFindings.

    Joins the static AARM_THREAT_VECTORS ledger against the audit findings to
    compute a per-vector conformance verdict.

    Args:
        findings:   OscalFinding list from the audit pipeline (Step 2 output).
        audit_id:   Parent audit run identifier.
        chain_root: SHA-256 chain root from the Context Accumulator, if available.

    Returns:
        AARMConformanceReport containing all 11 vector results.
    """
    # Build a lookup from control_id → finding result for O(1) access
    finding_index: dict[str, str] = {}
    for f in findings:
        # If the same control appears multiple times, FAIL takes precedence
        existing = finding_index.get(f.control_id)
        if existing is None or f.result == "FAIL":
            finding_index[f.control_id] = f.result

    vector_results: list[AARMVectorResult] = []
    neutralized = partial = exposed = unknown = 0

    for vector in AARM_THREAT_VECTORS.values():
        control_results: dict[str, str] = {}
        pass_count = fail_count = not_found = 0

        for ctrl_id in vector.neutralizing_controls:
            result = finding_index.get(ctrl_id)
            if result is None:
                control_results[ctrl_id] = "NOT_FOUND"
                not_found += 1
            elif result == "PASS":
                control_results[ctrl_id] = "PASS"
                pass_count += 1
            else:
                control_results[ctrl_id] = result  # "FAIL" or "NOT_APPLICABLE"
                fail_count += 1

        total_controls = pass_count + fail_count + not_found

        if total_controls == 0:
            status: ConformanceStatus = "UNKNOWN"
            unknown += 1
        elif fail_count == 0 and not_found == 0:
            status = "NEUTRALIZED"
            neutralized += 1
        elif pass_count == 0:
            status = "EXPOSED"
            exposed += 1
        else:
            status = "PARTIAL"
            partial += 1

        vector_results.append(AARMVectorResult(
            vector_id             = vector.vector_id,
            name                  = vector.name,
            aarm_severity         = vector.aarm_severity,
            status                = status,
            neutralizing_controls = vector.neutralizing_controls,
            control_results       = control_results,
            pass_count            = pass_count,
            fail_count            = fail_count,
            not_found_count       = not_found,
            lula_validation_files = vector.lula_validation_files,
            implementation_files  = vector.implementation_files,
            notes                 = vector.notes,
        ))

    # Derive overall posture
    if exposed > 0:
        overall_posture = "CRITICAL"
    elif partial > 0:
        overall_posture = "DEGRADED"
    else:
        overall_posture = "SECURE"

    return AARMConformanceReport(
        audit_id         = audit_id,
        generated_utc    = datetime.now(tz=timezone.utc).isoformat(),
        neutralized      = neutralized,
        partial          = partial,
        exposed          = exposed,
        unknown          = unknown,
        overall_posture  = overall_posture,
        vectors          = vector_results,
        chain_root       = chain_root,
    )
