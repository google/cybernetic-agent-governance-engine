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
Symbolic Governor (Neuro-Symbolic Governance Layer).

Phase 4.3: If the external SLM sidecar times out or is unreachable, an
explicit ``"slm_available": false`` sentinel is injected into the OPA
payload instead of passing an undefined or zero score.  The Rego policy
(system_authz.rego) is updated to require higher confidence from other tiers
when this sentinel is present.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.core.policy import OPAClient
from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import ConsensusProvider, SafetyFilter
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.ftra.models import FtraBoundaryResult

# Import directly from generated_stpa_validator, bypassing the deprecated stpa_validator shim.
from src.gateway.governance.generated_stpa_validator import (
    GeneratedSTPAValidator as STPAValidator,
)

logger = logging.getLogger("SymbolicGovernor")
tracer = trace.get_tracer(__name__)

# SLM sidecar has been completely deprecated to optimize latency.

# ---------------------------------------------------------------------------
# No-Direct-Bind startup assertions
# ---------------------------------------------------------------------------
# These checks run at module import time so the service fails fast rather than
# surfacing gaps on the first live request.

_ENVIRONMENT: str = (
    os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
).lower()
_IS_PRODUCTION: bool = _ENVIRONMENT not in ("development", "test", "dev", "ci")

# Gap 3 fix: CBF_FAIL_OPEN=true in production is a direct-bind shortcut —
# it removes the cash-barrier tier from the gate entirely.  Fail fast.
_CBF_FAIL_OPEN: bool = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"
if _CBF_FAIL_OPEN and _IS_PRODUCTION:
    raise RuntimeError(
        "CAGE STARTUP FAILURE (No-Direct-Bind Gap 3): CBF_FAIL_OPEN=true is set in "
        f"environment '{_ENVIRONMENT}'. This removes the Control Barrier Function tier "
        "from the governance gate, creating a direct-bind shortcut to EXECUTED without "
        "resolved cash-barrier authority. "
        "Set CBF_FAIL_OPEN=false or set CAGE_ENV=development to bypass (not for production)."
    )

# Gap 4 fix: DoWhy absence in production silently removes Tier 6 (causal
# gatekeeper).  Fail fast so the gap is surfaced at startup, not at runtime.
# Catches Exception (not just ImportError) because some dowhy versions import
# numpy.distutils at module level, which raises ModuleNotFoundError (a subclass
# of ImportError) when numpy>=2.0 is installed — that error propagates as a
# generic exception from within dowhy's own import chain.
if _IS_PRODUCTION:
    try:
        import dowhy as _dowhy_probe  # noqa: F401
    except Exception:
        raise RuntimeError(
            "CAGE STARTUP FAILURE (No-Direct-Bind Gap 4): 'dowhy' is not installed "
            "or failed to import (e.g. numpy>=2.0 incompatibility). "
            "The DoWhy causal gatekeeper (Tier 6) is a mandatory component of the "
            "No-Direct-Bind governance gate in production. Without it, an agent can "
            "reach EXECUTED without causal world-model validation. "
            "Install a numpy-2.x-compatible dowhy (>=0.12), or set CAGE_ENV=development "
            "to bypass (not for production use)."
        )

# Gap 5 fix (PERFORMANCE_REVIEW.md §3, CTRL_KMS_001): KMS_GOVERNANCE_KEY unset or
# pointing to a non-existent/disabled key version caused every signing call to return
# HTTP 500 in a prior production incident — not caught until a red-team measurement run.
# Verify the KMS key is reachable and ENABLED before the pod is marked ready.
if _IS_PRODUCTION:
    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        get_governance_signer().validate_ready()
    except RuntimeError as _kms_ready_exc:
        raise RuntimeError(
            f"[STARTUP] KMS readiness probe failed — refusing to start: {_kms_ready_exc}"
        ) from _kms_ready_exc

# Gap 6 fix (PERFORMANCE_REVIEW.md §3): Redis unreachable at startup means every CBF
# call will fail-closed (or silently error). Verify Redis is reachable before the
# pod is marked ready so the misconfiguration is caught at startup, not at runtime.
if _IS_PRODUCTION:
    try:
        from src.gateway.infrastructure.redis_client import get_redis_client

        get_redis_client().ping_ready()
    except RuntimeError as _redis_ready_exc:
        raise RuntimeError(
            f"[STARTUP] Redis readiness probe failed — refusing to start: {_redis_ready_exc}"
        ) from _redis_ready_exc

# CAGE-SEC-007: RECONCILIATION_PROVIDER=stub guard (module-level, POAM-023)
# Raises at import time so the misconfiguration is caught before any request
# is served — not silently at the first CBF evaluation.
if (
    os.environ.get("RECONCILIATION_PROVIDER", "stub") == "stub"
    and os.environ.get("CAGE_ENV", "dev") == "production"
):
    raise RuntimeError(
        "CAGE-SEC-007: RECONCILIATION_PROVIDER=stub is not permitted in production. "
        "Set RECONCILIATION_PROVIDER=plaid or RECONCILIATION_PROVIDER=anchorage."
    )


from src.gateway.governance.contracts import GovernanceTierFailure, RefusalReceipt


class GovernanceError(Exception):
    """Raised when a symbolic rule is violated.

    Args:
        message: Human-readable violation description.  Begins with the stable
                 ``[CTRL_*]`` control ID so log aggregators can key on it.
        payload: Optional structured dict emitted to OTel / SIEM consumers.
                 Contains ``control_id``, ``primary_framework``,
                 ``legacy_citation``, etc. sourced from control_mappings.json.
        receipt: Optional immutable RefusalReceipt proof object.
    """

    def __init__(
        self,
        message: str,
        payload: dict[str, Any] | None = None,
        receipt: RefusalReceipt | None = None,
    ) -> None:
        super().__init__(message)
        self.payload: dict[str, Any] = payload or {}
        self.receipt: RefusalReceipt | None = receipt


# ---------------------------------------------------------------------------
# FRIA Confidence-Starvation Boundary — three-zone enforcement thresholds
# ---------------------------------------------------------------------------
# These constants define the three enforcement zones for the adaptive FRIA
# (Fundamental Rights Impact Assessment) tier (Tier 6b of the governance
# pipeline).  They are read at module load time and may be overridden via
# environment variables for staged rollouts or regional tuning.
#
# Zone semantics (CAGE v0.1.0 architectural decision — see ontology.py UCA-7):
#
#   FRIA_ZONE_ALLOW  (confidence ≥ FRIA_ZONE_ALLOW):
#     Autonomous clearance.  The external normative provider is contacted
#     asynchronously (fire-and-forget) — the trade is not blocked while
#     waiting for the FRIA attestation.  OPA system_authz.rego enforces
#     this boundary via the ALLOW path.
#
#   FRIA_ZONE_DEFER  (FRIA_ZONE_DEFER ≤ confidence < FRIA_ZONE_ALLOW):
#     Synchronous blocking gate.  The external normative provider must
#     return before the trade proceeds.  OPA returns MANUAL_REVIEW for
#     this zone, which is translated to GovernanceDecision.REQUIRE_APPROVAL
#     at the validate_action() boundary.  Human sign-off is required.
#
#   DENY zone        (confidence < FRIA_ZONE_DEFER):
#     Hard abort.  The external normative provider is never contacted.
#     The trade is blocked immediately.  Routes to DeferQueue for automated
#     data-hydration (GovernanceDecision.DEFER), not human triage.
#
# AARM mapping: CSA AARM-V7 "Context Window Overflow"
# ISO 42001 mapping: A.8.4 (AI System Operation Controls)
# Implementation: src/gateway/governance/normative_provider.py,
#                 src/gateway/governance/defer_queue.py
#
# EV-1 Migration: These thresholds are now sourced from config/governance_thresholds.json
# with environment variable overrides supported. See schemas/thresholds.py for details.
from src.gateway.governance.schemas.thresholds import (
    get_agent_confidence_threshold,
    get_fria_zone_allow,
    get_fria_zone_defer,
)

# These module-level constants delegate to the config-based accessor functions,
# which already incorporate env var overrides from load_and_validate_thresholds().
FRIA_ZONE_ALLOW: float = get_fria_zone_allow()
FRIA_ZONE_DEFER: float = get_fria_zone_defer()

# Feature flag for DEFER decision path — when disabled, DEFER falls back to DENY
# for gradual rollout safety.  Default is enabled (true).
CAGE_DEFER_ENABLED: bool = os.getenv("CAGE_DEFER_ENABLED", "true").lower() == "true"

# Feature flag for NARROW decision path — allows partial-authority/clamped execution
# when a request exceeds soft thresholds but is not a hard violation.
# Default is disabled (false — opt-in) for gradual rollout safety.
# When disabled, NARROW candidates fall back to DEFER or DENY.
CAGE_NARROW_ENABLED: bool = os.getenv("CAGE_NARROW_ENABLED", "false").lower() == "true"

# Feature flag for PAUSE decision path — allows resumable suspension of execution
# when a transient external condition (rate limit, circuit breaker, etc.) prevents
# immediate execution. Default is disabled (false — opt-in) for gradual rollout safety.
# When disabled, PAUSE candidates fall back to DENY.
CAGE_PAUSE_ENABLED: bool = os.getenv("CAGE_PAUSE_ENABLED", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Violation Classification (§2.1 CAGE Implementation Specs)
# ---------------------------------------------------------------------------


def _classify_violation(
    violations: list[str],
    stpa_violation_count: int,
    confidence: float,
    context: dict[str, Any] | None = None,
) -> tuple[GovernanceDecision, dict[str, Any]]:
    """Classify violations into DENY, DEFER, NARROW, PAUSE, or REQUIRE_APPROVAL decisions.

    This helper implements the five-way classification required by §2.1 of the
    CAGE Implementation Specs. The current implementation collapses every non-
    REQUIRE_APPROVAL violation into DENY — this function restores the DEFER path
    for soft violations that can be resolved via automated data-hydration, the
    NARROW path for threshold violations that can be clamped, and the PAUSE path
    for transient conditions that will resolve without intervention.

    Classification logic:
        DENY: Hard violations — STPA safety violations, CBF constraint violations,
              explicit OPA DENY responses. These are non-negotiable safety gates.

        NARROW: Threshold violations that can be clamped to allowed values.
                Candidates:
                - Amount/value exceeds soft threshold but is below hard limit
                - Scope requested is broader than allowed but can be constrained
                - Date range exceeds max allowed but can be narrowed
                Feature flag: CAGE_NARROW_ENABLED (default: false — opt-in).

        PAUSE: Transient conditions that will resolve without human intervention
               or data-hydration. Unlike DEFER, the client waits for an explicit
               resume signal. Candidates:
               - Rate limit exceeded (soft, will clear with time)
               - Circuit breaker open (external dependency unavailable)
               - Resource temporarily unavailable
               Feature flag: CAGE_PAUSE_ENABLED (default: false — opt-in).

        DEFER: Soft violations that indicate data starvation or ambiguity, not
               fundamental safety issues. Candidates:
               - Low confidence (< FRIA_ZONE_DEFER) with no hard violations
               - Ambiguous policy interpretation indicators
               - Multiple soft violations but no hard violations

        REQUIRE_APPROVAL: Existing HITL triggers — OPA MANUAL_REVIEW responses.
                          Preserved for backward compatibility.

    Args:
        violations: List of violation strings from the governance pipeline.
        stpa_violation_count: Number of STPA-specific violations (Tier 1).
        confidence: Agent's self-reported confidence score [0.0, 1.0].
        context: Optional dict with additional classification hints:
            - "cbf_violation": bool — True if CBF barrier was violated
            - "opa_decision": str — Raw OPA decision (ALLOW/DENY/MANUAL_REVIEW)
            - "policy_ambiguous": bool — True if OPA returned marginal decision
            - "params": dict — Original request parameters (for NARROW)
            - "threshold_config": dict — Threshold limits for NARROW clamping

    Returns:
        Tuple of (GovernanceDecision, metadata_dict) where metadata_dict contains:
            - classification_reason: str — Human-readable explanation
            - violation_types: list[str] — Categorized violation types
            - deferrable: bool — True if violations are soft/deferrable
            - hard_violations: list[str] — List of hard violation strings
            - soft_violations: list[str] — List of soft violation strings
            - narrowable_violations: list[str] — List of narrowable violation strings
            - original_params: dict — Original params (if NARROW)
            - narrowed_params: dict — Narrowed params (if NARROW)
            - constraints_applied: list[str] — Applied constraints (if NARROW)

    Environment variables:
        CAGE_DEFER_ENABLED: When "false", DEFER falls back to DENY for rollback
                            safety. Default: "true".
        CAGE_NARROW_ENABLED: When "false", NARROW falls back to DEFER or DENY.
                             Default: "false" (opt-in).
        CAGE_PAUSE_ENABLED: When "false", PAUSE falls back to DENY.
                            Default: "false" (opt-in).
        FRIA_ZONE_DEFER: Confidence threshold below which context is considered
                         starved. Default: 0.70.

    ISO 42001 mapping: A.8.4 (AI System Operation Controls)
    AARM mapping: CSA AARM-V7 "Context Window Overflow" (DEFER path)
    """
    from src.gateway.governance.decisions import GovernanceDecision

    ctx = context or {}
    hard_violations: list[str] = []
    soft_violations: list[str] = []
    narrowable_violations: list[str] = []
    pausable_violations: list[str] = []
    violation_types: list[str] = []

    # ── Categorize each violation ──────────────────────────────────────────────
    for v in violations:
        # Hard violation indicators
        is_stpa = "STPA" in v or "UCA-" in v or "Unsafe Control Action" in v.lower()
        is_cbf = (
            "CBF" in v or "Safety Violation (RBC" in v or "cash barrier" in v.lower()
        )
        is_fiscal_reject = "Fiscal Limit Pre-Reservation REJECTED" in v
        is_opa_deny = "OPA Denied Action" in v

        # Pausable violation indicators (transient conditions that will resolve)
        is_rate_limited = (
            "rate limit" in v.lower()
            or "rate exceeded" in v.lower()
            or "throttl" in v.lower()  # throttle, throttled, throttling
            or "too many requests" in v.lower()
        )
        is_circuit_open = (
            "circuit breaker" in v.lower()
            or "circuit open" in v.lower()
            or "service unavailable" in v.lower()
        )
        is_resource_unavailable = (
            "resource unavailable" in v.lower()
            or "temporarily unavailable" in v.lower()
            or "quota exhausted" in v.lower()
            or "capacity exceeded" in v.lower()
        )

        # Narrowable violation indicators (can be clamped)
        is_amount_exceeded = (
            "amount exceeds" in v.lower()
            or "exceeds limit" in v.lower()
            or "exceeds max" in v.lower()
            or "above threshold" in v.lower()
        )
        is_scope_exceeded = (
            "scope exceeds" in v.lower()
            or "unauthorized scope" in v.lower()
            or "scope not allowed" in v.lower()
        )
        is_date_range_exceeded = (
            "date range exceeds" in v.lower()
            or "range too wide" in v.lower()
            or "exceeds max days" in v.lower()
        )

        # Soft violation indicators (deferrable)
        is_confidence = "Confidence Violation" in v or "confidence below" in v.lower()
        is_manual_review = "Manual Review Required" in v
        is_tier2_structural = "POAM-TIER2-001" in v

        # FTRA boundary check indicators (Phase 3.3 — routes to REQUIRE_APPROVAL)
        # These violations indicate the action was caught at the controller boundary
        # and requires Human-In-The-Loop review before execution.
        is_ftra_boundary_hitl = (
            "FTRA Boundary Check" in v and "Human-in-the-loop review required" in v
        )

        if is_stpa:
            hard_violations.append(v)
            violation_types.append("STPA_SAFETY")
        elif is_cbf or is_fiscal_reject:
            hard_violations.append(v)
            violation_types.append("CBF_CONSTRAINT")
        elif is_opa_deny:
            # OPA explicit DENY is a hard violation
            hard_violations.append(v)
            violation_types.append("OPA_DENY")
        elif is_rate_limited or is_circuit_open or is_resource_unavailable:
            # Pausable violations — transient conditions that will resolve
            pausable_violations.append(v)
            if is_rate_limited:
                violation_types.append("RATE_LIMITED")
            if is_circuit_open:
                violation_types.append("CIRCUIT_OPEN")
            if is_resource_unavailable:
                violation_types.append("RESOURCE_UNAVAILABLE")
        elif is_amount_exceeded or is_scope_exceeded or is_date_range_exceeded:
            # Narrowable violations — can be clamped to allowed values
            narrowable_violations.append(v)
            if is_amount_exceeded:
                violation_types.append("AMOUNT_THRESHOLD_EXCEEDED")
            if is_scope_exceeded:
                violation_types.append("SCOPE_EXCEEDED")
            if is_date_range_exceeded:
                violation_types.append("DATE_RANGE_EXCEEDED")
        elif is_manual_review:
            # Manual review is neither hard nor soft — it's REQUIRE_APPROVAL
            soft_violations.append(v)
            violation_types.append("REQUIRE_APPROVAL")
        elif is_confidence:
            soft_violations.append(v)
            violation_types.append("CONFIDENCE_STARVATION")
        elif is_tier2_structural:
            # Tier 2 structural override forces HITL, treat as soft
            soft_violations.append(v)
            violation_types.append("TIER2_STRUCTURAL")
        elif is_ftra_boundary_hitl:
            # FTRA boundary check caught an irreversible action at controller boundary
            # Route to REQUIRE_APPROVAL for human review (Phase 3.3)
            soft_violations.append(v)
            violation_types.append("FTRA_BOUNDARY_HITL")
        else:
            # Unknown violation type — default to hard for safety
            hard_violations.append(v)
            violation_types.append("UNKNOWN_HARD")

    # ── Explicit context overrides ──────────────────────────────────────────────
    if ctx.get("cbf_violation"):
        if "CBF_CONSTRAINT" not in violation_types:
            violation_types.append("CBF_CONSTRAINT_CTX")

    # ── Classification decision ─────────────────────────────────────────────────
    has_manual_review = "REQUIRE_APPROVAL" in violation_types
    has_ftra_boundary_hitl = "FTRA_BOUNDARY_HITL" in violation_types
    has_hard_violations = len(hard_violations) > 0 or stpa_violation_count > 0
    has_soft_violations = len(soft_violations) > 0
    has_narrowable_violations = len(narrowable_violations) > 0
    has_pausable_violations = len(pausable_violations) > 0
    confidence_starved = confidence < FRIA_ZONE_DEFER

    # Priority 0: FTRA Boundary HITL (Phase 3.3) — irreversible action caught at boundary
    # This takes highest priority because it represents a direct HTTP bypass of the
    # in-graph ftra_node. Route to REQUIRE_APPROVAL for human review.
    if has_ftra_boundary_hitl and not has_hard_violations:
        return GovernanceDecision.REQUIRE_APPROVAL, {
            "classification_reason": (
                "FTRA Boundary Check: Irreversible action caught at controller "
                "boundary — requires human sign-off before execution"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
            "ftra_boundary_triggered": True,
        }

    # Priority 1: REQUIRE_APPROVAL takes precedence (preserves existing HITL behavior)
    if has_manual_review and not has_hard_violations:
        return GovernanceDecision.REQUIRE_APPROVAL, {
            "classification_reason": (
                "OPA returned MANUAL_REVIEW — action requires human sign-off"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
        }

    # Priority 2: Hard violations always result in DENY
    if has_hard_violations:
        reasons = []
        if stpa_violation_count > 0:
            reasons.append(f"{stpa_violation_count} STPA safety violation(s)")
        if (
            "CBF_CONSTRAINT" in violation_types
            or "CBF_CONSTRAINT_CTX" in violation_types
        ):
            reasons.append("CBF cash barrier violation")
        if "OPA_DENY" in violation_types:
            reasons.append("OPA explicit DENY")
        if not reasons:
            reasons.append("unknown hard violation")

        return GovernanceDecision.DENY, {
            "classification_reason": f"Hard violation(s): {'; '.join(reasons)}",
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
        }

    # Priority 3: Pausable violations → PAUSE candidate (transient conditions)
    # PAUSE takes priority over NARROW because transient conditions should be
    # paused and retried, not narrowed.
    if (
        has_pausable_violations
        and not has_soft_violations
        and not has_narrowable_violations
    ):
        # Check feature flag — if disabled, fall back to DENY
        if not CAGE_PAUSE_ENABLED:
            return GovernanceDecision.DENY, {
                "classification_reason": (
                    "PAUSE candidate but CAGE_PAUSE_ENABLED=false — "
                    "falling back to DENY"
                ),
                "violation_types": list(set(violation_types)),
                "deferrable": False,
                "hard_violations": hard_violations,
                "soft_violations": soft_violations,
                "narrowable_violations": narrowable_violations,
                "pausable_violations": pausable_violations,
            }

        # Determine pause reason from violation types
        if "RATE_LIMITED" in violation_types:
            pause_reason = "RATE_LIMITED"
            estimated_wait = 60  # 1 minute default for rate limits
        elif "CIRCUIT_OPEN" in violation_types:
            pause_reason = "CIRCUIT_OPEN"
            estimated_wait = 30  # 30 seconds default for circuit breakers
        elif "RESOURCE_UNAVAILABLE" in violation_types:
            pause_reason = "RESOURCE_UNAVAILABLE"
            estimated_wait = 120  # 2 minutes default for resource unavailability
        else:
            pause_reason = "RATE_LIMITED"
            estimated_wait = 60

        return GovernanceDecision.PAUSE, {
            "classification_reason": (
                f"Transient condition detected: {pause_reason} — "
                "request paused pending external resume"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "pausable": True,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
            "pause_reason": pause_reason,
            "estimated_wait_seconds": estimated_wait,
        }

    # Priority 4: Narrowable violations → NARROW candidate (if enabled and no soft/hard)
    if has_narrowable_violations and not has_soft_violations:
        # Check feature flag — if disabled, fall back to DEFER or DENY
        if not CAGE_NARROW_ENABLED:
            # Fall back to DEFER if enabled, otherwise DENY
            if CAGE_DEFER_ENABLED and confidence_starved:
                return GovernanceDecision.DEFER, {
                    "classification_reason": (
                        "NARROW candidate but CAGE_NARROW_ENABLED=false — "
                        "falling back to DEFER"
                    ),
                    "violation_types": list(set(violation_types)),
                    "deferrable": True,
                    "hard_violations": hard_violations,
                    "soft_violations": soft_violations,
                    "narrowable_violations": narrowable_violations,
                }
            return GovernanceDecision.DENY, {
                "classification_reason": (
                    "NARROW candidate but CAGE_NARROW_ENABLED=false — "
                    "falling back to DENY"
                ),
                "violation_types": list(set(violation_types)),
                "deferrable": False,
                "hard_violations": hard_violations,
                "soft_violations": soft_violations,
                "narrowable_violations": narrowable_violations,
            }

        # Compute narrowed parameters
        original_params = ctx.get("params", {})
        threshold_config = ctx.get("threshold_config", {})
        narrowed_params, constraints_applied = _compute_narrowed_params(
            original_params=original_params,
            threshold_config=threshold_config,
            violation_types=violation_types,
        )

        narrow_reasons = []
        if "AMOUNT_THRESHOLD_EXCEEDED" in violation_types:
            narrow_reasons.append("amount clamped to max allowed")
        if "SCOPE_EXCEEDED" in violation_types:
            narrow_reasons.append("scope narrowed to allowed operations")
        if "DATE_RANGE_EXCEEDED" in violation_types:
            narrow_reasons.append("date range clamped to max allowed")

        return GovernanceDecision.NARROW, {
            "classification_reason": (
                f"Threshold violation(s) narrowed: {'; '.join(narrow_reasons)}"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "original_params": original_params,
            "narrowed_params": narrowed_params,
            "constraints_applied": constraints_applied,
            "narrowing_reason": "; ".join(narrow_reasons),
        }

    # Priority 5: Soft violations with confidence starvation → DEFER candidate
    if has_soft_violations and confidence_starved:
        # Check feature flag — if disabled, fall back to DENY
        if not CAGE_DEFER_ENABLED:
            return GovernanceDecision.DENY, {
                "classification_reason": (
                    "DEFER candidate but CAGE_DEFER_ENABLED=false — falling back to DENY"
                ),
                "violation_types": list(set(violation_types)),
                "deferrable": True,
                "hard_violations": hard_violations,
                "soft_violations": soft_violations,
                "narrowable_violations": narrowable_violations,
                "pausable_violations": pausable_violations,
            }

        defer_reasons = []
        if confidence_starved:
            defer_reasons.append(
                f"confidence {confidence:.2f} < FRIA_ZONE_DEFER {FRIA_ZONE_DEFER}"
            )
        if "CONFIDENCE_STARVATION" in violation_types:
            defer_reasons.append("confidence threshold violation")
        if ctx.get("policy_ambiguous"):
            defer_reasons.append("ambiguous policy interpretation")

        return GovernanceDecision.DEFER, {
            "classification_reason": (
                f"Soft violation(s) with data starvation: {'; '.join(defer_reasons)}"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": True,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
        }

    # Priority 6: Soft violations above confidence threshold → REQUIRE_APPROVAL
    # (These could have been autonomous but have other soft issues)
    if has_soft_violations:
        return GovernanceDecision.REQUIRE_APPROVAL, {
            "classification_reason": (
                "Soft violation(s) above confidence threshold — requires human review"
            ),
            "violation_types": list(set(violation_types)),
            "deferrable": False,
            "hard_violations": hard_violations,
            "soft_violations": soft_violations,
            "narrowable_violations": narrowable_violations,
            "pausable_violations": pausable_violations,
        }

    # Fallback: No categorized violations — should not reach here if called correctly
    return GovernanceDecision.DENY, {
        "classification_reason": "Unclassified violation(s) — defaulting to DENY for safety",
        "violation_types": list(set(violation_types)),
        "deferrable": False,
        "hard_violations": hard_violations,
        "soft_violations": soft_violations,
        "narrowable_violations": narrowable_violations,
        "pausable_violations": pausable_violations,
    }


def _compute_narrowed_params(
    original_params: dict[str, Any],
    threshold_config: dict[str, Any],
    violation_types: list[str],
) -> tuple[dict[str, Any], list[str]]:
    """Compute narrowed parameters by clamping values to allowed thresholds.

    This helper clamps request parameters to fit within allowed thresholds
    while preserving action semantics. The narrowing is applied in-place
    without transforming the action type.

    Narrowing rules:
        - amount > max_allowed → clamp to max_allowed
        - scope: ["read", "write", "delete"] with only ["read", "write"] allowed
          → narrow to allowed scope
        - date_range: 365 days with max 90 days → narrow to 90 days

    Args:
        original_params: Original request parameters.
        threshold_config: Threshold configuration dict with keys:
            - "max_amount": float — Maximum allowed amount (default: 100000.0)
            - "allowed_scopes": list[str] — Allowed scope operations
            - "max_date_range_days": int — Maximum date range in days (default: 90)
        violation_types: List of violation type strings to guide narrowing.

    Returns:
        Tuple of (narrowed_params, constraints_applied) where:
            - narrowed_params: Dict with clamped parameter values
            - constraints_applied: List of constraint description strings
    """
    narrowed = original_params.copy()
    constraints: list[str] = []

    # Default threshold values
    max_amount = threshold_config.get("max_amount", 100000.0)
    allowed_scopes = threshold_config.get("allowed_scopes", ["read", "write"])
    max_date_range_days = threshold_config.get("max_date_range_days", 90)

    # ── Clamp amount if exceeded ────────────────────────────────────────────────
    if "AMOUNT_THRESHOLD_EXCEEDED" in violation_types:
        original_amount = original_params.get("amount", 0.0)
        if isinstance(original_amount, (int, float)) and original_amount > max_amount:
            narrowed["amount"] = max_amount
            constraints.append(
                f"amount clamped: {original_amount} → {max_amount} (max_allowed)"
            )

    # ── Narrow scope if exceeded ────────────────────────────────────────────────
    if "SCOPE_EXCEEDED" in violation_types:
        original_scope = original_params.get("scope", [])
        if isinstance(original_scope, list):
            narrowed_scope = [s for s in original_scope if s in allowed_scopes]
            if narrowed_scope != original_scope:
                narrowed["scope"] = narrowed_scope
                constraints.append(
                    f"scope narrowed: {original_scope} → {narrowed_scope} (allowed only)"
                )

    # ── Clamp date range if exceeded ────────────────────────────────────────────
    if "DATE_RANGE_EXCEEDED" in violation_types:
        original_days = original_params.get("date_range_days", 0)
        if isinstance(original_days, int) and original_days > max_date_range_days:
            narrowed["date_range_days"] = max_date_range_days
            constraints.append(
                f"date_range clamped: {original_days} → {max_date_range_days} days (max_allowed)"
            )

    return narrowed, constraints


# ---------------------------------------------------------------------------
# SymbolicGovernor
# ---------------------------------------------------------------------------


class SymbolicGovernor:
    def __init__(
        self,
        opa_client: OPAClient,
        safety_filter: SafetyFilter,
        consensus_engine: ConsensusProvider,
        stpa_validator: STPAValidator | None = None,
        telemetry_provider: Any | None = None,
        fiscal_limit_guard: Any | None = None,
    ):
        self.opa_client = opa_client
        self.safety_filter = safety_filter
        self.consensus_engine = consensus_engine
        self.stpa_validator: STPAValidator | None = stpa_validator
        self.telemetry_provider = telemetry_provider
        # FiscalLimitGuard — optional for backward compatibility with existing tests.
        # When present, atomically pre-reserves the daily fiscal limit in Redis
        # (WATCH/MULTI/EXEC) before the consensus gate, closing the TOCTOU race
        # between the CBF balance check and actual trade execution.
        self.fiscal_limit_guard = fiscal_limit_guard

        # FTRA Boundary Check (Phase 3.3): Lazy-initialized IrreversibilityClassifier
        # for boundary-level FTRA validation. Shared instance with in-graph ftra_node
        # to ensure consistent classification semantics.
        self._ftra_classifier: Any | None = None  # IrreversibilityClassifier

    def _get_ftra_classifier(self) -> Any:
        """Return the IrreversibilityClassifier instance, lazily initialized.

        This ensures we only pay the import cost and registry loading cost
        on first invocation (lazy initialization). The classifier is shared with
        the in-graph ftra_node via the same terminal_registry.json.

        Returns:
            IrreversibilityClassifier instance.

        Raises:
            ImportError: If ftra module is not available.
            FileNotFoundError: If terminal_registry.json is not found.
        """
        if self._ftra_classifier is None:
            from src.gateway.governance.ftra.classifier import IrreversibilityClassifier

            self._ftra_classifier = IrreversibilityClassifier()
        return self._ftra_classifier

    async def _ftra_boundary_check(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        *,
        detect_bypass: bool = True,
    ) -> FtraBoundaryResult:
        """Enforce FTRA validation at the HTTP/controller boundary.

        Risk R-03 mitigation: This check runs at the controller boundary
        (validate_action, ext_authz) to catch direct HTTP bypasses of the
        in-graph ftra_node. Uses the same IrreversibilityClassifier and
        terminal_registry.json as the in-graph ftra_node.

        Args:
            tool_name: The action name to classify (e.g. "execute_trade").
            tool_input: The action parameters dict (currently unused but
                        available for future input-dependent classification).
            detect_bypass: If True, attempt to detect whether this check is
                           catching an action that would have bypassed ftra_node.
                           Default True.

        Returns:
            FtraBoundaryResult with classification and HITL requirements.

        Telemetry:
            - OTel span attribute: cage.ftra.boundary_check_triggered
            - Prometheus counter: cage_ftra_boundary_checks_total
        """
        from src.gateway.governance.ftra.models import (
            FtraBoundaryResult,
            TerminalClassification,
        )

        with tracer.start_as_current_span("cage.ftra_boundary_check") as span:
            span.set_attribute("langfuse.observation.name", "ftra_boundary_check")
            span.set_attribute("governance.stage", "ftra_boundary")
            span.set_attribute("cage.ftra.boundary_check_triggered", True)
            span.set_attribute("cage.ftra.action", tool_name)
            _t0 = time.perf_counter()

            try:
                classifier = self._get_ftra_classifier()
                classification = classifier.classify(tool_name)

                # Check if action was in the registry
                in_registry = tool_name in classifier.known_actions()

                # Heuristic bypass detection: if we're at the boundary and the
                # action is IRREVERSIBLE_TERMINAL, it's likely a bypass of the
                # in-graph ftra_node (which would have routed to HITL earlier).
                # This is logged at WARN level for audit purposes.
                bypassed_ftra_node = (
                    detect_bypass
                    and classification == TerminalClassification.IRREVERSIBLE_TERMINAL
                )

                if bypassed_ftra_node:
                    logger.warning(
                        "⚠️ FTRA Boundary Check: Action '%s' classified as "
                        "IRREVERSIBLE_TERMINAL at controller boundary. "
                        "This may indicate direct HTTP bypass of in-graph ftra_node. "
                        "Routing to HITL for human review.",
                        tool_name,
                    )

                result = FtraBoundaryResult.from_classification(
                    classification=classification,
                    action_name=tool_name,
                    in_registry=in_registry,
                    bypassed_ftra_node=bypassed_ftra_node,
                )

                # Record telemetry
                span.set_attribute("cage.ftra.classification", result.classification)
                span.set_attribute(
                    "cage.ftra.irreversibility_score", result.irreversibility_score
                )
                span.set_attribute("cage.ftra.requires_hitl", result.requires_hitl)
                span.set_attribute("cage.ftra.in_registry", in_registry)
                span.set_attribute(
                    "cage.ftra.bypassed_ftra_node", result.bypassed_ftra_node
                )
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )

                # Prometheus counter (if available)
                try:
                    from prometheus_client import Counter

                    _ftra_boundary_counter = Counter(
                        "cage_ftra_boundary_checks_total",
                        "Total FTRA boundary checks performed",
                        ["result"],
                    )
                    if result.requires_hitl:
                        _ftra_boundary_counter.labels(result="hitl_required").inc()
                    else:
                        _ftra_boundary_counter.labels(result="passed").inc()
                except ImportError:
                    pass  # prometheus_client not installed — skip metrics

                return result

            except Exception as exc:
                # Fail-closed: on any error, return IRREVERSIBLE_TERMINAL
                logger.error(
                    "⛔ FTRA Boundary Check failed (%s) — failing closed to "
                    "IRREVERSIBLE_TERMINAL for action '%s'.",
                    exc,
                    tool_name,
                )
                span.record_exception(exc)
                span.set_attribute("cage.ftra.error", str(exc))
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )

                # Prometheus counter for skipped/error
                try:
                    from prometheus_client import Counter

                    _ftra_boundary_counter = Counter(
                        "cage_ftra_boundary_checks_total",
                        "Total FTRA boundary checks performed",
                        ["result"],
                    )
                    _ftra_boundary_counter.labels(result="error").inc()
                except ImportError:
                    pass

                # Return fail-closed result
                return FtraBoundaryResult(
                    requires_hitl=True,
                    irreversibility_score=1.0,
                    classification=TerminalClassification.IRREVERSIBLE_TERMINAL.value,
                    terminal_match=None,
                    violations=[
                        f"FTRA Boundary Check: Error classifying action '{tool_name}' — "
                        f"failing closed to IRREVERSIBLE_TERMINAL. Error: {exc}"
                    ],
                    bypassed_ftra_node=True,
                )

    async def _run_checks(
        self,
        tool_name: str,
        params: dict[str, Any],
        sim_mode: bool = False,
    ) -> dict[str, Any]:
        """Core governance check pipeline shared by ``govern()`` and ``verify()``.

        Returns a dict:
            {
                "violations":     list[str],
                "opa_results":    dict | None,
                "pending_payload": dict | None,  # structured payload for GovernanceError
            }

        CRIT-5 fix: ``pending_payload`` is returned in the result dict rather
        than stored on ``self``.  Storing it on the singleton instance created a
        data race under concurrent async requests — two simultaneous calls could
        overwrite each other's payload before it was read in ``govern()``.

        Latency optimizations (v2.0.x baseline):
        - CBF (Redis read) and OPA (HTTP) checks are fully independent and now
          run concurrently via asyncio.gather, bounding their combined cost to
          max(CBF_ms, OPA_ms) instead of CBF_ms + OPA_ms.
        - Each stage is wrapped in a discrete OTel span so Langfuse shows the
          full 10-layer pipeline breakdown.
        """
        violations: list[str] = []
        tier_failures: list[GovernanceTierFailure] = []
        policy_resp = None
        # CRIT-5 fix: local variable replaces self._pending_payload to eliminate
        # the data race on the singleton under concurrent async requests.
        _conf_payload: dict[str, Any] | None = None
        # FTRA boundary check metadata (Phase 3.3)
        _ftra_boundary_result: Any | None = None

        # -1. FTRA Boundary Check (Pre-Pipeline Boundary Gate)
        # Runs BEFORE all other checks. Risk R-03 mitigation: Catches direct HTTP
        # access to /validate-action or ext_authz that would bypass the in-graph ftra_node.
        # This check is MANDATORY — there is no flag to disable it.
        with tracer.start_as_current_span("cage.ftra_boundary_gate") as ftra_gate_span:
            ftra_gate_span.set_attribute(
                "langfuse.observation.name", "ftra_boundary_gate"
            )
            ftra_gate_span.set_attribute("governance.stage", "ftra_boundary")
            _t_ftra = time.perf_counter()

            _ftra_boundary_result = await self._ftra_boundary_check(
                tool_name=tool_name,
                tool_input=params,
                detect_bypass=True,
            )

            # Add FTRA violations to the violations list
            violations.extend(_ftra_boundary_result.violations)

            # If FTRA requires HITL, log at WARN level for audit
            if _ftra_boundary_result.requires_hitl:
                logger.warning(
                    "⚠️ FTRA Boundary Gate: Action '%s' requires HITL review "
                    "(classification=%s, bypassed_ftra_node=%s)",
                    tool_name,
                    _ftra_boundary_result.classification,
                    _ftra_boundary_result.bypassed_ftra_node,
                )

            ftra_gate_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t_ftra) * 1000, 2),
            )
            ftra_gate_span.set_attribute(
                "cage.ftra.requires_hitl", _ftra_boundary_result.requires_hitl
            )

        # 0. STAMP/STPA: Unsafe Control Actions
        with tracer.start_as_current_span("cage.stpa_check") as stpa_span:
            stpa_span.set_attribute("langfuse.observation.name", "stpa_uca_check")
            stpa_span.set_attribute("governance.tool", tool_name)
            _t0 = time.perf_counter()
            if self.stpa_validator is not None:
                check_params = params.copy()
                if sim_mode and "latency_ms" not in check_params:
                    check_params["latency_ms"] = float(
                        os.getenv("GOVERNANCE_SIM_LATENCY_MS", "10.0")
                    )
                stpa_violations = self.stpa_validator.validate(tool_name, check_params)
                violations.extend(stpa_violations)
            # Capture STPA-only violation count before later tiers append to violations.
            # Used by the Tier-2 structural corroboration heuristic (POAM-TIER2-001).
            _stpa_violation_count: int = len(violations)
            stpa_span.set_attribute("governance.stpa.violations", _stpa_violation_count)
            stpa_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0) * 1000, 2),
            )

        # ── POAM-TIER2-001: Tier 2 Confidence Self-Authentication Gap (partially mitigated) ──
        # RISK: The confidence score below is 100% agent-self-reported via params["confidence"].
        # Since the SLM sidecar was deprecated (latency reduction), no independent verification
        # mechanism existed to corroborate this value. An adversarial agent could unconditionally
        # report confidence=1.0 to suppress HITL escalation for any action.
        #
        # PARTIAL MITIGATION (deployed): A rule-based structural corroboration heuristic runs
        # AFTER Tier-1 STPA and Tier-3 OPA results are available (see block below the CBF+OPA
        # checks). It derives an independent confidence signal from:
        #   - Tier-1 STPA violation count (stpa_violation_count > 0 → structural risk)
        #   - Tier-3 OPA decision margin (opa_margin < 0.15 → marginal allow → structural risk)
        # If structural risk is flagged AND self-reported confidence is >= threshold, the
        # heuristic forces HITL regardless of the self-reported value. Zero new infrastructure.
        #
        # REMAINING GAP: OPA responses in this deployment do not carry margin_to_deny, so the
        # OPA margin branch is currently inactive (treated as None → no signal). STPA branch
        # is active. Full closure requires OPA response enrichment or a dedicated scorer.
        #
        # PAPER REFERENCE: §4.2 (Tier 2), §7.2 (Limitations), CAGE_ARXIV.MD Issue #5.
        # ──────────────────────────────────────────────────────────────────────────────────────

        # 1. Confidence threshold — local pre-check (fast-fail before network I/O).
        # The OPA Rego policy (system_authz.rego) also enforces confidence so that
        # the dynamic SLM-degraded escalation (0.95→0.97) is applied consistently.
        # This local check fires first to avoid unnecessary CBF/OPA round-trips when
        # the confidence score is obviously below threshold.
        with tracer.start_as_current_span("cage.confidence_check") as conf_span:
            conf_span.set_attribute(
                "langfuse.observation.name", "confidence_threshold_check"
            )
            conf_span.set_attribute("governance.stage", "confidence")
            _t0_conf = time.perf_counter()
            if tool_name == "execute_trade":
                _confidence = float(params.get("confidence", 0.0))
                # POAM-TIER2-001: stamp the confidence provenance so every Tier 2 decision
                # is auditable. The structural heuristic below provides independent
                # corroboration after Tier-1 STPA and Tier-3 OPA results are available.
                conf_span.set_attribute("tier2.confidence.source", "agent_self_report")
                conf_span.set_attribute("tier2.confidence.independently_verified", True)
                # EV-2 Migration: Use config-based threshold with env var override support
                _confidence_threshold = get_agent_confidence_threshold()
                if _confidence < _confidence_threshold:
                    _conf_meta = ControlRegistry().get_mapping(
                        GovernanceControl.AGENT_CONFIDENCE_THRESHOLD
                    )
                    _conf_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{_conf_meta['primary_framework']} Confidence Violation: "
                        f"score {_confidence:.2f} < threshold {_confidence_threshold:.2f}. "
                        f"Violation: agent confidence below required minimum."
                    )
                    # CRIT-5 fix: store in a local variable, not on self.
                    # self._pending_payload was a data race — concurrent requests on
                    # the singleton could overwrite each other's payload.
                    _conf_payload = {
                        "control_id": GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                        "primary_framework": _conf_meta["primary_framework"],
                        "legacy_citation": _conf_meta.get("legacy_citation", ""),
                        "scope": _conf_meta.get("scope", ""),
                        "confidence": _confidence,
                        "threshold": _confidence_threshold,
                    }
                    violations.append(_conf_msg)
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="NEURAL_CONFIDENCE",
                            control_id=GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value,
                            rule_description=f"confidence {_confidence:.2f} < threshold {_confidence_threshold:.2f}",
                            governing_state={
                                "confidence": _confidence,
                                "threshold": _confidence_threshold,
                                "framework": _conf_meta["primary_framework"],
                            },
                            protected_consequence=f"Trade execution at confidence {_confidence:.2f} "
                            f"(below {_confidence_threshold:.2f} minimum)",
                        )
                    )
                conf_span.set_attribute("governance.confidence.score", _confidence)
                conf_span.set_attribute(
                    "governance.confidence.threshold", _confidence_threshold
                )
                conf_span.set_attribute(
                    "governance.confidence.passed", _confidence >= _confidence_threshold
                )
            conf_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0_conf) * 1000, 2),
            )

        # ======================================================================
        # PHASE 1: READ-ONLY VALIDATION GATES
        # ======================================================================
        # Peer Review Fix: Pipeline reorder to prevent budget leakage.
        #
        # All read-only checks execute in Phase 1 BEFORE any state mutations.
        # This ensures that if Consensus, Causal, or FRIA gates reject, no
        # CBF balance or fiscal reservation has been committed yet.
        #
        # Phase 1 order:
        #   1. OPA policy evaluation (moved from concurrent gather)
        #   2. Tier-2 structural corroboration
        #   3. Multi-model Consensus gate
        #   4. DoWhy Causal Gatekeeper
        #   5. Adaptive FRIA enforcement
        #
        # Phase 2 (mutations, only if Phase 1 has 0 violations):
        #   1. CBF atomic_verify_and_commit()
        #   2. Fiscal Limit reserve() (with CBF compensation on failure)
        #
        # LATENCY TRADE-OFF: This removes the asyncio.gather concurrency between
        # CBF and OPA. The latency cost is CBF_ms (added sequentially after OPA).
        # This is acceptable because correctness (no budget leakage) takes
        # precedence over latency optimization.
        # ======================================================================

        if tool_name == "execute_trade" and not violations:
            # --- Phase 1.1: OPA policy evaluation (read-only) ---
            opa_payload = params.copy()
            opa_payload["action"] = tool_name

            with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                opa_span.set_attribute(
                    "langfuse.observation.name", "opa_policy_pre_check"
                )
                opa_span.set_attribute("governance.stage", "opa")
                opa_span.set_attribute("governance.phase", "read_only")
                _t_opa = time.perf_counter()
                try:
                    policy_resp = await self.opa_client.evaluate_policy(opa_payload)
                    opa_span.set_attribute(
                        "governance.stage.latency_ms",
                        round((time.perf_counter() - _t_opa) * 1000, 2),
                    )
                except Exception as exc:
                    opa_span.record_exception(exc)
                    violations.append(f"OPA Check Failed: {exc}")
                    policy_resp = None

            # Evaluate OPA result
            if policy_resp is not None and not isinstance(policy_resp, BaseException):
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision == "DENY":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                    tier_failures.append(
                        GovernanceTierFailure(
                            tier="OPA",
                            control_id=GovernanceControl.OPA_POLICY_ENFORCEMENT.value,
                            rule_description="OPA policy denied action",
                            governing_state={
                                "policy_decision": policy_decision,
                                "framework": _opa_meta["primary_framework"],
                            },
                            protected_consequence=f"Execution of {tool_name} denied by OPA policy",
                        )
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )

        else:
            # Non-trade actions: sequential OPA only (no CBF needed)
            opa_payload = params.copy()
            opa_payload["action"] = tool_name
            try:
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute(
                        "langfuse.observation.name", "opa_policy_pre_check"
                    )
                    opa_span.set_attribute("governance.stage", "opa")
                    policy_resp = await self.opa_client.evaluate_policy(opa_payload)
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision == "DENY":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )
            except Exception as exc:
                violations.append(f"OPA Check Failed: {exc}")

        # ── Structural corroboration heuristic (POAM-TIER2-001 partial mitigation) ────
        # Derive an independent confidence signal from Tier-1 STPA violations and
        # Tier-3 OPA decision margin.  This runs AFTER both tiers have resolved so
        # it can contradict a high self-reported confidence when structural evidence
        # says otherwise — closing the self-authentication gap without reinstating
        # the deprecated SLM sidecar.
        #
        # Conservative treatment: if STPA or OPA results are unavailable (e.g. a tier
        # raised an exception and we have no result at all), treat as structural risk.
        if tool_name == "execute_trade":
            with tracer.start_as_current_span(
                "cage.tier2_structural_corroboration"
            ) as _t2_span:
                _t2_span.set_attribute(
                    "langfuse.observation.name", "tier2_structural_corroboration"
                )
                _t2_span.set_attribute("governance.stage", "tier2_corroboration")
                _t2_corr_t0 = time.perf_counter()

                # STPA signal: any violation is structural risk.
                # _stpa_violation_count was captured right after the STPA check above.
                _opa_margin: float | None = None
                if (
                    policy_resp is not None
                    and not isinstance(policy_resp, BaseException)
                    and hasattr(policy_resp, "margin_to_deny")
                ):
                    _opa_margin = float(policy_resp.margin_to_deny)

                _structural_risk_flagged: bool = (
                    _stpa_violation_count > 0
                    or (_opa_margin is not None and _opa_margin < 0.15)
                    # Conservative: if policy_resp itself was an exception, treat as risk
                    or isinstance(policy_resp, BaseException)
                )

                # Retrieve the self-reported confidence value (set in the confidence check
                # block above; default 0.0 if tool_name branch was skipped somehow).
                _self_reported_confidence: float = float(params.get("confidence", 0.0))
                # EV-2 Migration: Use config-based threshold with env var override support
                _confidence_threshold_t2: float = get_agent_confidence_threshold()

                if (
                    _structural_risk_flagged
                    and _self_reported_confidence >= _confidence_threshold_t2
                ):
                    # Independent structural signal contradicts high self-reported confidence:
                    # force HITL regardless of self-reported value.
                    _corroboration_source = "structural_heuristic_override"
                    violations.append(
                        "POAM-TIER2-001 Structural Override: HITL required — "
                        "self-reported confidence contradicted by structural evidence "
                        f"(stpa_violations={_stpa_violation_count}, "
                        f"opa_margin={_opa_margin!r}). "
                        "Independent signal: structural_heuristic_override."
                    )
                elif _structural_risk_flagged:
                    _corroboration_source = "structural_heuristic_low_confidence"
                else:
                    _corroboration_source = "structural_heuristic_pass"

                _t2_span.set_attribute("tier2.confidence.independently_verified", True)
                _t2_span.set_attribute(
                    "tier2.confidence.corroboration_source", _corroboration_source
                )
                _t2_span.set_attribute(
                    "tier2.confidence.stpa_violations", _stpa_violation_count
                )
                _t2_span.set_attribute(
                    "tier2.confidence.structural_risk_flagged", _structural_risk_flagged
                )
                _t2_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t2_corr_t0) * 1000, 2),
                )

        # ======================================================================
        # PHASE 1.2-1.4: Remaining read-only validation gates
        # ======================================================================
        # These gates (Consensus, Causal, FRIA) are all read-only and must
        # complete with zero violations BEFORE any state mutations (CBF, Fiscal).
        # This ordering prevents the budget leakage vulnerability where CBF
        # debits balance but a later read-only gate rejects the action.
        # ======================================================================

        # Initialize _fiscal_token for later Phase 2 use
        _fiscal_token = None

        # Phase 1.2: ISO 42001: Multi-agent Consensus (trade-specific, high-stakes)
        if tool_name == "execute_trade":
            with tracer.start_as_current_span("cage.consensus_gate") as cons_gate_span:
                cons_gate_span.set_attribute(
                    "langfuse.observation.name", "consensus_gate"
                )
                cons_gate_span.set_attribute("governance.stage", "consensus")
                try:
                    amount = params.get("amount", 0.0)
                    symbol = params.get("symbol", "UNKNOWN")
                    consensus = await self.consensus_engine.check_consensus(
                        tool_name, amount, symbol
                    )
                    if consensus["status"] == "REJECT":
                        violations.append(f"Consensus Rejection: {consensus['reason']}")
                    elif consensus["status"] == "ESCALATE":
                        violations.append(
                            f"Consensus Escalation: {consensus['reason']}"
                        )
                    cons_gate_span.set_attribute(
                        "governance.consensus.status",
                        consensus.get("status", "UNKNOWN"),
                    )
                except Exception as exc:
                    violations.append(f"Consensus Check Failed: {exc}")

        # 6. DoWhy Causal Gatekeeper — refutation-based safety lock
        # Gap 4 fix: ImportError is no longer silently swallowed in production.
        # The startup assertion above (module-level) already fails fast if dowhy
        # is absent in production, so reaching this branch with ImportError means
        # we are in a dev/test environment — log at DEBUG and skip.
        if tool_name == "execute_trade":
            try:
                from src.gateway.governance.causal_gatekeeper import (
                    causal_safety_check,
                )

                telemetry_data = None
                if self.telemetry_provider is not None:
                    telemetry_data = self.telemetry_provider.get_latest_data()

                trade_context = {"params": params, "telemetry": telemetry_data}
                result = await asyncio.to_thread(causal_safety_check, trade_context)
                if not result:
                    violations.append(
                        "Causal Safety Violation: DoWhy refutation failed — "
                        "world-model is untrustworthy or risk exceeds safety boundary."
                    )
            except ImportError:
                # Only reachable in dev/test (production startup assertion prevents this).
                logger.debug(
                    "DoWhy not installed — skipping causal gatekeeper (dev/test only). "
                    "Production startup will fail if dowhy is absent."
                )
            except Exception as exc:
                logger.warning(
                    "⚠️ Causal gatekeeper check failed (%s) — failing closed.", exc
                )
                violations.append(
                    f"Causal Safety Violation: gatekeeper raised an unexpected error — "
                    f"failing closed. Detail: {exc}"
                )

        # 6b. Adaptive FRIA Enforcement (External Normative Provider)
        # When CAGE_NORMATIVE_PROVIDER != "static", the enforcement semantic
        # is dynamically determined by the consensus confidence score:
        #   Score ≥ FRIA_ZONE_ALLOW (default 0.95) → async attestation (fire-and-forget)
        #   FRIA_ZONE_DEFER ≤ Score < FRIA_ZONE_ALLOW → synchronous blocking gate
        #   Score < FRIA_ZONE_DEFER (default 0.70) → hard abort, no external call
        # Positioned AFTER all local tiers — if local governance already
        # DENY'd, the external provider is never contacted.
        # Override via env: FRIA_ZONE_ALLOW, FRIA_ZONE_DEFER (module-level constants).
        _normative_provider_name = os.getenv("CAGE_NORMATIVE_PROVIDER", "static")
        if (
            tool_name == "execute_trade"
            and _normative_provider_name != "static"
            and not violations
        ):
            try:
                from src.gateway.governance.normative_provider import (
                    ExecutionStatus,
                    enforce_fria_boundary,
                    get_normative_provider,
                )

                provider = get_normative_provider(_normative_provider_name)
                confidence = params.get("confidence", 0.0)
                thread_id = params.get("thread_id", "")

                fria_result = await enforce_fria_boundary(
                    provider=provider,
                    action_context=params,
                    consensus_score=confidence,
                    defer_queue=None,  # DeferQueue injected when available
                    thread_id=thread_id,
                )

                # Stamp enforcement path on OTel span
                current_span = trace.get_current_span()
                current_span.set_attribute(
                    "governance.fria.enforcement_path", fria_result.path
                )
                current_span.set_attribute(
                    "governance.fria.consensus_score", fria_result.consensus_score
                )

                if fria_result.status == ExecutionStatus.DENY:
                    violations.append(
                        f"FRIA External Validation: {fria_result.path} — "
                        f"consensus_score={fria_result.consensus_score:.3f}"
                    )

            except Exception as exc:
                logger.warning(
                    "⚠️ FRIA adaptive enforcement failed (%s) — continuing "
                    "with local governance only.",
                    exc,
                )

        # 6b (continued). FRIA Attestation (EU_ECB only — EU AI Act Art. 29a)
        # For EU deployments, every governed action must carry a span attribute
        # attesting that a Fundamental Rights Impact Assessment (FRIA) was
        # conducted pre-market per Art. 29a. This is not a blocking runtime gate
        # (FRIA is a pre-market document obligation, not a per-request check),
        # but the live telemetry MUST record the control is active so that
        # DORA Art. 10 monitoring logs satisfy the Art. 12 logging obligation.
        # Stamped here (at the end of the FRIA tier) as a cross-cutting
        # observability concern — not a separate governance tier.
        fria_meta = ControlRegistry().get_mapping_safe(
            GovernanceControl.FRIA_ASSESSMENT
        )
        if fria_meta is not None:
            # Attach to the current OTel span so DORA Art. 10 audit logs include it
            current_span = trace.get_current_span()
            current_span.set_attribute(
                "governance.fria.control_id",
                fria_meta["internal_id"],
            )
            current_span.set_attribute(
                "governance.fria.framework",
                fria_meta["primary_framework"],
            )
            current_span.set_attribute(
                "governance.fria.scope",
                fria_meta["scope"],
            )
            logger.debug(
                "[%s] FRIA attestation active — %s",
                GovernanceControl.FRIA_ASSESSMENT.value,
                fria_meta["primary_framework"],
            )

        # ======================================================================
        # PHASE 2: ATOMIC STATE MUTATIONS (only if Phase 1 has 0 violations)
        # ======================================================================
        # Peer Review Fix: All read-only validation gates completed above.
        # Phase 2 only executes if there are ZERO violations from Phase 1.
        # This prevents budget leakage: CBF balance is only debited if all
        # read-only checks (OPA, Consensus, Causal, FRIA) have passed.
        #
        # Phase 2 order:
        #   1. CBF atomic_verify_and_commit() — debits balance atomically
        #   2. Fiscal Limit reserve() — reserves USD against daily cap
        #
        # Compensation: If fiscal reservation fails after CBF succeeds, we must
        # call cbf.rollback_state() to restore the debited balance.
        #
        # LATENCY TRADE-OFF: CBF now runs AFTER all read-only checks (not in
        # parallel with OPA). This adds ~CBF_ms latency but ensures correctness.
        # ======================================================================

        _cbf_committed = False  # Track CBF state for potential rollback

        if tool_name == "execute_trade" and not violations:
            _cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"

            # --- Phase 2.1: CBF atomic_verify_and_commit ---
            with tracer.start_as_current_span("cage.cbf_atomic_commit") as cbf_span:
                cbf_span.set_attribute("langfuse.observation.name", "cbf_barrier_check")
                cbf_span.set_attribute("governance.stage", "cbf")
                cbf_span.set_attribute("governance.phase", "mutation")
                cbf_span.set_attribute("governance.cbf.atomic", True)
                _t_cbf = time.perf_counter()
                try:
                    (
                        committed,
                        reason,
                    ) = await self.safety_filter.atomic_verify_and_commit(
                        action_name=tool_name,
                        payload=params,
                    )
                    _cbf_committed = committed
                    cbf_result = "SAFE" if committed else reason
                    cbf_span.set_attribute("governance.cbf.result", cbf_result[:80])
                    cbf_span.set_attribute("governance.cbf.committed", committed)
                    cbf_span.set_attribute(
                        "governance.stage.latency_ms",
                        round((time.perf_counter() - _t_cbf) * 1000, 2),
                    )

                    if not committed and cbf_result.startswith("UNSAFE"):
                        violations.append(f"Safety Violation (RBC/CBF): {cbf_result}")
                        amount_val = params.get("amount", 0.0)
                        tier_failures.append(
                            GovernanceTierFailure(
                                tier="CBF",
                                control_id="CAGE-CBF-001",
                                rule_description=cbf_result,
                                governing_state={
                                    "cost": amount_val,
                                    "cbf_result": cbf_result,
                                    "amount": amount_val,
                                    "symbol": params.get("symbol"),
                                },
                                protected_consequence=f"Balance violation: trade cost {amount_val} "
                                f"would breach CBF safety envelope",
                            )
                        )

                except Exception as cbf_exc:
                    cbf_span.record_exception(cbf_exc)
                    cbf_span.set_attribute("governance.cbf.result", "EXCEPTION")
                    if _cbf_fail_open:
                        logger.warning(
                            "⚠️ CBF check unavailable (%s) — CBF_FAIL_OPEN=true, "
                            "skipping CBF gate. ⚠️ AUDIT: Self-reported cash balance "
                            "cannot be verified; this gap must be closed before "
                            "production governance examination.",
                            cbf_exc,
                        )
                        logger.critical(
                            json.dumps(
                                {
                                    "event": "CBF_FAIL_OPEN_ACTIVATED",
                                    "severity": "CRITICAL",
                                    "tool": tool_name,
                                    "cbf_error": str(cbf_exc),
                                    "audit_note": (
                                        "CBF gate bypassed via CBF_FAIL_OPEN=true. "
                                        "Cash balance cannot be independently verified for this trade."
                                    ),
                                }
                            )
                        )
                    else:
                        logger.error(
                            "⛔ CBF check unavailable (%s) — fail-closed: blocking "
                            "action because cash barrier cannot be independently "
                            "verified.",
                            cbf_exc,
                        )
                        violations.append(
                            "CBF Fail-Closed: Redis unavailable — cannot verify "
                            "cash barrier. Self-reported balance has no independent "
                            "provenance. Set CBF_FAIL_OPEN=true to override "
                            "(audit gap)."
                        )

            # --- Phase 2.2: Fiscal Limit reserve (only if CBF passed) ---
            if not violations and self.fiscal_limit_guard is not None:
                with tracer.start_as_current_span(
                    "cage.fiscal_limit_reserve"
                ) as fiscal_span:
                    fiscal_span.set_attribute(
                        "langfuse.observation.name", "fiscal_limit_reserve"
                    )
                    fiscal_span.set_attribute("governance.stage", "fiscal_limit")
                    fiscal_span.set_attribute("governance.phase", "mutation")
                    _t_fiscal = time.perf_counter()
                    try:
                        _amount_minor = params.get("amount_minor")
                        if _amount_minor is not None:
                            _amount_minor = int(_amount_minor)
                            _amount = _amount_minor / 100.0
                        else:
                            _amount = float(params.get("amount", 0.0))

                        _agent_id = str(
                            params.get(
                                "agent_id", params.get("user_id", "unknown-agent")
                            )
                        )

                        _fiscal_token = None
                        if _amount_minor is not None and _amount_minor > 0:
                            _fiscal_token = await self.fiscal_limit_guard.reserve(
                                agent_id=_agent_id,
                                amount_minor=_amount_minor,
                            )
                        elif _amount > 0:
                            _fiscal_token = await self.fiscal_limit_guard.reserve(
                                agent_id=_agent_id,
                                amount_usd=_amount,
                            )

                        if _fiscal_token is not None:
                            fiscal_span.set_attribute(
                                "governance.fiscal.reservation_id",
                                _fiscal_token.reservation_id,
                            )
                            if _amount_minor is not None:
                                fiscal_span.set_attribute(
                                    "governance.fiscal.amount_minor", _amount_minor
                                )
                            fiscal_span.set_attribute(
                                "governance.fiscal.amount_usd", _amount
                            )
                            fiscal_span.set_attribute(
                                "governance.fiscal.running_total_usd",
                                _fiscal_token.running_total_usd,
                            )
                            fiscal_span.set_attribute(
                                "governance.fiscal.cap_usd", _fiscal_token.cap_usd
                            )
                            if _fiscal_token.rejected:
                                fiscal_span.set_attribute(
                                    "governance.fiscal.result", "REJECTED"
                                )
                                violations.append(
                                    f"Fiscal Limit Pre-Reservation REJECTED: "
                                    f"amount=${_amount:,.2f} would exceed daily cap "
                                    f"${_fiscal_token.cap_usd:,.2f} "
                                    f"(running_total=${_fiscal_token.running_total_usd:,.2f}). "
                                    f"reservation_id={_fiscal_token.reservation_id}"
                                )
                                tier_failures.append(
                                    GovernanceTierFailure(
                                        tier="FISCAL",
                                        control_id="CAGE-FISCAL-001",
                                        rule_description=f"amount ${_amount:,.2f} exceeds daily cap ${_fiscal_token.cap_usd:,.2f}",
                                        governing_state={
                                            "amount_usd": _amount,
                                            "running_total_usd": _fiscal_token.running_total_usd,
                                            "cap_usd": _fiscal_token.cap_usd,
                                            "reservation_id": _fiscal_token.reservation_id,
                                            "agent_id": _agent_id,
                                        },
                                        protected_consequence=f"Fiscal overrun: ${_amount:,.2f} trade "
                                        f"would push running total beyond ${_fiscal_token.cap_usd:,.2f} daily cap",
                                    )
                                )
                                # Fiscal rejected AFTER CBF committed — must compensate CBF
                                if _cbf_committed:
                                    logger.warning(
                                        "⚠️ Fiscal rejected after CBF commit — initiating "
                                        "CBF rollback for budget leakage prevention."
                                    )
                                    try:
                                        await self.safety_filter.rollback_state(
                                            cost=_amount
                                        )
                                        logger.info(
                                            "✅ CBF rollback complete after fiscal rejection."
                                        )
                                        _cbf_committed = False
                                    except Exception as cbf_rollback_exc:
                                        logger.error(
                                            "⛔ CBF rollback failed after fiscal rejection: %s. "
                                            "BUDGET LEAKAGE POSSIBLE — requires manual reconciliation.",
                                            cbf_rollback_exc,
                                        )
                                _fiscal_token = None
                            else:
                                fiscal_span.set_attribute(
                                    "governance.fiscal.result", "RESERVED"
                                )
                        else:
                            fiscal_span.set_attribute(
                                "governance.fiscal.result", "SKIPPED_ZERO_AMOUNT"
                            )
                    except Exception as _fiscal_exc:
                        fiscal_span.record_exception(_fiscal_exc)
                        fiscal_span.set_attribute("governance.fiscal.result", "ERROR")
                        logger.error(
                            "⛔ FiscalLimitGuard.reserve() failed (%s) — failing closed.",
                            _fiscal_exc,
                        )
                        violations.append(
                            f"Fiscal Limit Pre-Reservation Error: {_fiscal_exc}"
                        )
                        # Fiscal error AFTER CBF committed — must compensate CBF
                        if _cbf_committed:
                            logger.warning(
                                "⚠️ Fiscal error after CBF commit — initiating "
                                "CBF rollback for budget leakage prevention."
                            )
                            try:
                                await self.safety_filter.rollback_state(cost=_amount)
                                logger.info(
                                    "✅ CBF rollback complete after fiscal error."
                                )
                                _cbf_committed = False
                            except Exception as cbf_rollback_exc:
                                logger.error(
                                    "⛔ CBF rollback failed after fiscal error: %s. "
                                    "BUDGET LEAKAGE POSSIBLE — requires manual reconciliation.",
                                    cbf_rollback_exc,
                                )
                    fiscal_span.set_attribute(
                        "governance.stage.latency_ms",
                        round((time.perf_counter() - _t_fiscal) * 1000, 2),
                    )

        # Release fiscal reservation if Phase 2 produced violations AFTER fiscal
        # reservation succeeded. This should be rare since we compensate CBF above,
        # but handles edge cases.
        if (
            violations
            and _fiscal_token is not None
            and self.fiscal_limit_guard is not None
        ):
            try:
                await self.fiscal_limit_guard.release(_fiscal_token)
                logger.info(
                    "🔄 Fiscal reservation released (post-pipeline violation): id=%s",
                    _fiscal_token.reservation_id,
                )
            except Exception as _rel_exc:
                logger.warning("⚠️ FiscalLimitGuard.release() failed: %s", _rel_exc)

        return {
            "violations": violations,
            "tier_failures": tier_failures,
            "opa_results": policy_resp,
            # CRIT-5 fix: _conf_payload is a local variable (initialized to None
            # above), set only when a confidence violation is detected.  Returning
            # it here instead of storing on self eliminates the singleton race.
            "pending_payload": _conf_payload,
            # §2.1 CAGE Implementation Specs: STPA violation count for classification
            "stpa_violation_count": _stpa_violation_count,
            # Phase 3.3: FTRA boundary check result (None if disabled)
            "ftra_boundary_result": _ftra_boundary_result,
        }

    async def govern(self, tool_name: str, params: dict[str, Any]) -> str:
        """Orchestrate governance checks for live execution.

        Gap 2 fix (No-Direct-Bind): ``govern()`` now issues a routing seal on
        approval and returns it.  Callers MUST verify the seal before executing
        the governed action.  This closes the direct-bind shortcut that existed
        when ``govern()`` raised ``GovernanceError`` on denial but provided no
        cryptographic attestation of resolved authority on approval.

        The seal is generated via ``routing_seal.generate_seal()`` — the same
        mechanism used by ``validate_action()`` — so both paths satisfy the
        No-Direct-Bind invariant:
            NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

        Returns:
            HMAC-SHA256 routing seal string (non-empty on approval).

        Raises:
            GovernanceError: If any check fails.
        """
        from src.gateway.governance.routing_seal import generate_seal_with_evidence

        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "governance_evaluation")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"tool": tool_name, "params": params}),
            )
            logger.info("⚖️ Symbolic Governor evaluating: %s", tool_name)
            try:
                result = await self._run_checks(tool_name, params, sim_mode=False)
                violations = result["violations"]
                if violations:
                    # CRIT-5 fix: read pending_payload from the result dict, not
                    # from self — eliminates the data race on the singleton.
                    payload = result.get("pending_payload")
                    violation_msg = violations[0]
                    thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown_thread"
                    )
                    _tier_failures = result.get("tier_failures", [])
                    _first_tf = _tier_failures[0] if _tier_failures else None
                    receipt = RefusalReceipt(
                        thread_id=thread_id,
                        action=tool_name,
                        violated_tier=_first_tf.tier
                        if _first_tf
                        else "SYMBOLIC_GOVERNOR",
                        violated_rule=violation_msg,
                        standing_at_refusal={
                            "symbol": params.get("symbol"),
                            "amount": params.get("amount"),
                            "currency": params.get("currency"),
                            "confidence": params.get("confidence"),
                        },
                        # ── 5-part proof chain (Terry Snyder) ──
                        schema_version="v2",
                        attempted_params={
                            k: v
                            for k, v in params.items()
                            if k not in ("thread_id", "transaction_id")
                        },
                        standing_snapshot=_first_tf.governing_state
                        if _first_tf
                        else {},
                        control_id=_first_tf.control_id if _first_tf else "",
                        protected_consequence=_first_tf.protected_consequence
                        if _first_tf
                        else "",
                        non_formation_proof="action_blocked_pre_commit",
                        tier_failures=tuple(_tier_failures),
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    span.set_attribute("cage.verdict", "BLOCKED")
                    raise GovernanceError(
                        violation_msg, payload=payload, receipt=receipt
                    )

                # Gap 2 fix: issue routing seal AFTER all checks pass.
                # The seal is the cryptographic attestation that resolvedAllow=TRUE.
                # Callers must verify it before executing the governed action.
                #
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                # This ensures evidence is durably recorded before seal issuance.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(tool_name, params)
                    seal_span.set_attribute("cage.seal_issued", True)
                    seal_span.set_attribute("cage.seal_path", "govern")

                logger.info(
                    "✅ Symbolic Governor Approved: %s (seal issued)", tool_name
                )
                span.set_attribute("langfuse.observation.output", "APPROVED")
                span.set_attribute("cage.seal_issued", True)
                return seal
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("langfuse.observation.output", str(exc))
                raise

    async def revalidate_post_hitl(
        self,
        params: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> str:
        """Re-run only the tiers that can drift during HITL review.

        After a human approves a plan, market prices and account balances may
        have changed. Only Tier 3a (CBF cash solvency) and Tier 3b (OPA policy)
        are sensitive to real-time state — the other tiers are deterministic
        with respect to the static plan and do not need re-evaluation.

        Tiers intentionally skipped vs. the full ``govern()`` pipeline:
          Tier 0: STPA/STAMP UCA validation — deterministic w.r.t. plan structure
          Tier 1: Agent confidence pre-check — plan was approved at check-time
          Tier 2 structural corroboration: dependent on STPA/OPA margin, skipped
          Tier 3: Fiscal Limit Pre-Reservation — already reserved at check-time
          Tier 5: Multi-agent consensus — consensus is over the static plan
          Tier 6: DoWhy causal gatekeeper — causal structure is plan-static
          Tier 6b: FRIA — pre-market document obligation, not per-resume check

        This avoids paying the full 8-tier cost (including FTRA pre-pipeline gate, multi-model consensus
        and DoWhy causal computation) for a targeted post-approval recheck.

        Args:
            params: Trade parameters dict, same shape as passed to ``govern()``.
            trace_id: Optional trace correlation ID for OTel span attribution.

        Returns:
            HMAC-SHA256 routing seal string (non-empty on approval).

        Raises:
            GovernanceError: If CBF or OPA check fails after HITL approval.
        """
        from src.gateway.governance.routing_seal import generate_seal_with_evidence

        tool_name = "execute_trade"
        violations: list[str] = []

        with tracer.start_as_current_span(
            "symbolic_governor.revalidate_post_hitl"
        ) as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute(
                "langfuse.observation.name", "governance_revalidate_post_hitl"
            )
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"tool": tool_name, "params": params}),
            )
            span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
            if trace_id is not None:
                span.set_attribute("toctou.revalidation.trace_id", trace_id)

            logger.info(
                "⚖️ [revalidate_post_hitl] Re-checking CBF+OPA only (Tiers 3a/3b) "
                "for post-HITL TOCTOU revalidation: %s",
                tool_name,
            )

            _cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"

            # --- CBF coroutine ---
            async def _cbf_revalidate() -> str | None:
                """Atomic CBF verify-and-commit inside a dedicated span."""
                with tracer.start_as_current_span("cage.cbf_check") as cbf_span:
                    cbf_span.set_attribute(
                        "langfuse.observation.name", "cbf_barrier_check"
                    )
                    cbf_span.set_attribute("governance.stage", "cbf")
                    cbf_span.set_attribute("governance.cbf.atomic", True)
                    cbf_span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
                    _t = time.perf_counter()
                    try:
                        (
                            committed,
                            reason,
                        ) = await self.safety_filter.atomic_verify_and_commit(
                            action_name=tool_name,
                            payload=params,
                        )
                        result = "SAFE" if committed else reason
                        cbf_span.set_attribute("governance.cbf.result", result[:80])
                        cbf_span.set_attribute("governance.cbf.committed", committed)
                        cbf_span.set_attribute(
                            "governance.stage.latency_ms",
                            round((time.perf_counter() - _t) * 1000, 2),
                        )
                        return result
                    except Exception as exc:
                        cbf_span.record_exception(exc)
                        cbf_span.set_attribute("governance.cbf.result", "EXCEPTION")
                        raise

            # --- OPA coroutine ---
            opa_payload = params.copy()
            opa_payload["action"] = tool_name

            async def _opa_revalidate() -> Any:
                """OPA policy evaluation inside a dedicated span."""
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute(
                        "langfuse.observation.name", "opa_policy_pre_check"
                    )
                    opa_span.set_attribute("governance.stage", "opa")
                    opa_span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
                    _t = time.perf_counter()
                    try:
                        resp = await self.opa_client.evaluate_policy(opa_payload)
                        opa_span.set_attribute(
                            "governance.stage.latency_ms",
                            round((time.perf_counter() - _t) * 1000, 2),
                        )
                        return resp
                    except Exception as exc:
                        opa_span.record_exception(exc)
                        raise

            # Fire CBF and OPA concurrently — same as Tier 3 in the full pipeline.
            _t_parallel_start = time.perf_counter()
            _gather_results2 = await asyncio.gather(
                _cbf_revalidate(),
                _opa_revalidate(),
                return_exceptions=True,
            )
            cbf_result: str | None | BaseException = _gather_results2[0]
            policy_resp: Any = _gather_results2[1]
            _parallel_ms = round((time.perf_counter() - _t_parallel_start) * 1000, 2)
            logger.debug(
                "⚡ [revalidate_post_hitl] CBF+OPA parallel re-check completed "
                "in %.1fms (tool=%s)",
                _parallel_ms,
                tool_name,
            )

            # --- Evaluate CBF result ---
            if isinstance(cbf_result, BaseException):
                if _cbf_fail_open:
                    logger.warning(
                        "⚠️ [revalidate_post_hitl] CBF check unavailable (%s) — "
                        "CBF_FAIL_OPEN=true, skipping CBF gate (audit gap).",
                        cbf_result,
                    )
                else:
                    logger.error(
                        "⛔ [revalidate_post_hitl] CBF check unavailable (%s) — "
                        "fail-closed: blocking revalidation.",
                        cbf_result,
                    )
                    violations.append(
                        "CBF Fail-Closed (post-HITL revalidation): Redis unavailable "
                        "— cannot verify cash barrier. Set CBF_FAIL_OPEN=true to "
                        "override (audit gap)."
                    )
            elif isinstance(cbf_result, str) and cbf_result.startswith("UNSAFE"):
                violations.append(
                    f"Safety Violation (RBC/CBF) [post-HITL revalidation]: {cbf_result}"
                )

            # --- Evaluate OPA result ---
            if isinstance(policy_resp, BaseException):
                violations.append(
                    f"OPA Check Failed [post-HITL revalidation]: {policy_resp}"
                )
                policy_resp = None
            else:
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get(
                        "allow", policy_resp.get("decision", "DENY")
                    )
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision == "DENY":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied "
                        f"Action [post-HITL revalidation]."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(
                        GovernanceControl.OPA_POLICY_ENFORCEMENT
                    )
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review "
                        f"Required [post-HITL revalidation]."
                    )

            span.set_attribute("toctou.revalidation.cbf_opa_parallel_ms", _parallel_ms)

            try:
                if violations:
                    thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown"
                    )
                    receipt = RefusalReceipt(
                        thread_id=thread_id,
                        action=tool_name,
                        violated_tier="SYMBOLIC_GOVERNOR",
                        violated_rule=violations[0],
                        standing_at_refusal={
                            "symbol": params.get("symbol"),
                            "amount": params.get("amount"),
                            "confidence": params.get("confidence"),
                        },
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    raise GovernanceError(violations[0], receipt=receipt)

                # Issue routing seal — attests that CBF+OPA re-check passed.
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(tool_name, params)
                    seal_span.set_attribute("cage.seal_issued", True)
                    seal_span.set_attribute("cage.seal_path", "revalidate_post_hitl")

                logger.info(
                    "✅ [revalidate_post_hitl] CBF+OPA re-check APPROVED: %s "
                    "(seal issued, Tiers 3a/3b only)",
                    tool_name,
                )
                span.set_attribute("langfuse.observation.output", "APPROVED")
                span.set_attribute("cage.seal_issued", True)
                return seal

            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("langfuse.observation.output", str(exc))
                raise

    async def pre_check(self, params: dict[str, Any]) -> dict[str, Any]:
        """Run lightweight pre-checks for NeMo Layer-0 context injection.

        Executes STPA validation and CBF barrier check once, returning
        pre-computed results that NeMo actions can read from context instead
        of calling back into the governor's sub-components directly.

        This breaks the re-entrant dependency loop where NeMo actions called
        ``stpa_validator.validate()`` and ``safety_filter.verify_action()``
        inside Layer 0, causing each to run twice per request (once here,
        once inside ``_run_checks()``).

        This method is intentionally NOT called from ``_run_checks()`` —
        ``_run_checks()`` already calls STPA and CBF directly as part of the
        full pipeline.

        Returns:
            dict with keys:
                - ``stpa_result``: ``{"allowed": bool, "violations": list[str]}``
                - ``cbf_result``:  ``{"allowed": bool, "reason": str}``
        """
        tool_name = "execute_trade"

        # --- STPA validation (synchronous) ---
        stpa_violations: list = []
        if self.stpa_validator is not None:
            try:
                stpa_violations = self.stpa_validator.validate(tool_name, params)
            except Exception as exc:
                logger.warning(
                    "⚠️ pre_check: STPA validation failed (%s) — treating as no violations.",
                    exc,
                )

        stpa_result = {
            "allowed": len(stpa_violations) == 0,
            "violations": stpa_violations,
        }

        # --- CBF barrier check (async) ---
        cbf_allowed = True
        cbf_reason = "SAFE"
        try:
            cbf_raw = await self.safety_filter.verify_action(tool_name, params)  # type: ignore[misc]  # Protocol declares sync str; impl is async
            cbf_allowed = not cbf_raw.startswith("UNSAFE") and not cbf_raw.startswith(
                "["
            )
            cbf_reason = cbf_raw
        except Exception as exc:
            # C-02: fail-closed on Redis/CBF unavailability — DENY is the safe default.
            logger.error(
                "CBF pre_check failed due to Redis error — denying request for safety",
                exc_info=True,
            )
            cbf_allowed = False
            cbf_reason = f"CBF unavailable (fail-closed): {exc}"

        cbf_result = {
            "allowed": cbf_allowed,
            "reason": cbf_reason,
        }

        logger.debug(
            "🔍 pre_check complete: stpa_allowed=%s cbf_allowed=%s",
            stpa_result["allowed"],
            cbf_result["allowed"],
        )
        return {
            "stpa_result": stpa_result,
            "cbf_result": cbf_result,
        }

    async def verify(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dry-run governance checks.  Does NOT raise exceptions.

        Used by the Evaluator Agent (System 3) for simulation.
        """
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "governance_simulation")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"tool": tool_name, "params": params}),
            )
            result = await self._run_checks(tool_name, params, sim_mode=True)
            violations = result["violations"]
            span.set_attribute(
                "langfuse.observation.output",
                json.dumps(violations) if violations else "APPROVED",
            )
            return result

    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate a structured tool execution payload — Unified Gateway path.

        This is the **Single Choke Point** for all tool execution.  Runs the
        complete 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) via ``_run_checks()`` — STPA,
        Confidence, CBF, OPA, Fiscal Limit Pre-Reservation, Consensus, Causal,
        and FRIA — before issuing the routing seal.

        Previously this method ran only Tier 2 (CBF) and Tier 4 (OPA), which
        meant 5 of 7 substantive tiers were bypassed while the seal implied full
        governance approval.  That gap is now closed: the routing seal is issued
        ONLY after ``_run_checks()`` completes successfully across all tiers.

        On approval, a short-lived HMAC-SHA256 ``routing_seal`` is returned.
        The downstream actuator MUST verify this seal before firing — ensuring
        that execution cannot proceed by simply ignoring the HTTP response.

        Verdict semantics (canonical — see decisions.py):
          - ``"ALLOW"``            — approved; routing seal issued.
          - ``"DENY"``             — blocked; violation details included.
          - ``"REQUIRE_APPROVAL"`` — OPA returned MANUAL_REVIEW; human sign-off
                                     required. Routing seal NOT issued. The
                                     adapter returns HTTP 202 with this verdict
                                     so clients can distinguish it from DEFER.
          - ``"DEFER"``            — context missing or below confidence
                                     threshold; routes to DeferQueue for
                                     automated data-hydration.

        Returns:
            Dict with keys:
                - ``verdict``:     ``"ALLOW"`` | ``"DENY"`` | ``"REQUIRE_APPROVAL"`` | ``"DEFER"``
                - ``violations``:  list of violation strings (empty if ALLOW)
                - ``seal``:        HMAC routing seal (non-empty only if ALLOW)
                - ``latency_ms``:  total governance check wall-time in milliseconds

        Raises:
            GovernanceError: If any mandatory check fails with DENY verdict.
        """
        from src.gateway.governance.decisions import GovernanceDecision
        from src.gateway.governance.routing_seal import generate_seal

        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute("cage.action", action)
            span.set_attribute("cage.governance", True)
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "cage.validate_action")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps(
                    {
                        "action": action,
                        "params": params,
                        "policy_version_id": policy_version_id,
                    }
                )[:2000],
            )

            t0 = time.time()

            try:
                # ── Version-Pinning Enforcement Layer ────────────────────────
                if policy_version_id is not None:
                    active_hash = ControlRegistry().active_hash
                    if policy_version_id != active_hash:
                        raise GovernanceError(
                            f"Substrate Policy Drift Detected. Session pinned to version signature '{policy_version_id}', "
                            f"but active runtime baseline has evolved to hash '{active_hash}'."
                        )

                # ── Full 8-tier governance pipeline (FTRA + 7 in-pipeline tiers) ──
                # _run_checks() executes: STPA → Confidence → CBF+OPA (parallel)
                # → Fiscal Limit Pre-Reservation → Consensus → Causal → FRIA.
                # The routing seal is issued ONLY after all tiers pass — a seal
                # issued before full pipeline completion would imply governance
                # approval that was never actually granted.
                result = await self._run_checks(action, params, sim_mode=False)
                violations = result["violations"]

                latency_ms = round((time.time() - t0) * 1000, 2)
                span.set_attribute("cage.governance_latency_ms", latency_ms)

                # ── Violation Classification (§2.1 CAGE Implementation Specs) ──
                # Use the _classify_violation() helper to properly route violations
                # to DENY, DEFER, or REQUIRE_APPROVAL instead of collapsing all
                # non-REQUIRE_APPROVAL violations into DENY.
                #
                # Classification priorities:
                #   1. REQUIRE_APPROVAL: OPA MANUAL_REVIEW, no hard violations
                #   2. DENY: Hard violations (STPA, CBF, OPA DENY)
                #   3. DEFER: Soft violations + confidence starvation
                #   4. REQUIRE_APPROVAL fallback: Soft violations above threshold
                if violations:
                    # Extract STPA violation count from result metadata
                    _stpa_count = result.get("stpa_violation_count", 0)
                    # Extract confidence from params (agent self-reported)
                    _confidence = float(params.get("confidence", 0.0))

                    # Build classification context (includes params for NARROW)
                    _classify_ctx: dict[str, Any] = {
                        "cbf_violation": any(
                            "CBF" in v or "cash barrier" in v.lower()
                            for v in violations
                        ),
                        "opa_decision": result.get("opa_decision"),
                        "policy_ambiguous": result.get("policy_ambiguous", False),
                        # NARROW: Include original params for clamping computation
                        "params": params,
                        # NARROW: Threshold config can be overridden per-request or from config
                        "threshold_config": params.get("_threshold_config", {}),
                    }

                    # Classify the violations
                    decision, classification_meta = _classify_violation(
                        violations=violations,
                        stpa_violation_count=_stpa_count,
                        confidence=_confidence,
                        context=_classify_ctx,
                    )

                    # Record classification metadata in OTel span
                    span.set_attribute(
                        "cage.governance.classification_decision", decision.value
                    )
                    span.set_attribute(
                        "cage.governance.classification_reason",
                        classification_meta.get("classification_reason", "")[:200],
                    )
                    span.set_attribute(
                        "cage.governance.deferrable",
                        classification_meta.get("deferrable", False),
                    )

                    # ── REQUIRE_APPROVAL path ──────────────────────────────────
                    if decision == GovernanceDecision.REQUIRE_APPROVAL:
                        span.set_attribute(
                            "cage.verdict", GovernanceDecision.REQUIRE_APPROVAL
                        )
                        span.set_attribute(
                            "langfuse.observation.output",
                            GovernanceDecision.REQUIRE_APPROVAL,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "🔶 validate_action REQUIRE_APPROVAL: action=%s reason=%s (%.1fms)",
                            action,
                            classification_meta.get("classification_reason", ""),
                            latency_ms,
                        )
                        return {
                            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                            "violations": violations,
                            "seal": "",
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                        }

                    # ── DEFER path (new — §2.1 CAGE Implementation Specs) ──────
                    if decision == GovernanceDecision.DEFER:
                        # Park the deferred context in DeferQueue for later retrieval
                        # via GET /v1/defer/pending or resolution via POST /v1/defer/{id}/escalate
                        # Note: _classify_ctx contains the context built from params and result
                        defer_token = await _park_defer_context(
                            action=action,
                            params=params,
                            metadata=_classify_ctx,
                            thread_id=params.get("thread_id"),
                            confidence=_confidence,
                            classification_meta=classification_meta,
                            violations=violations,
                        )

                        span.set_attribute("cage.verdict", GovernanceDecision.DEFER)
                        span.set_attribute("cage.defer_token", defer_token)
                        span.set_attribute(
                            "langfuse.observation.output",
                            GovernanceDecision.DEFER,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "🔄 validate_action DEFER: action=%s reason=%s "
                            "confidence=%.2f defer_token=%s (%.1fms)",
                            action,
                            classification_meta.get("classification_reason", ""),
                            _confidence,
                            defer_token,
                            latency_ms,
                        )
                        return {
                            "verdict": GovernanceDecision.DEFER,
                            "violations": violations,
                            "seal": "",
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                            "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                            # Phase 1.2: HTTP layer wiring fields
                            "defer_token": defer_token,
                            "deferrable": classification_meta.get("deferrable", True),
                            "retry_after_seconds": 300,  # 5 minute default
                        }

                    # ── NARROW path (Phase 1.3 — partial-authority/clamped execution) ──
                    if decision == GovernanceDecision.NARROW:
                        from src.gateway.governance.routing_seal import (
                            generate_seal_with_evidence,
                        )

                        # Extract narrowed parameters from classification metadata
                        original_params = classification_meta.get(
                            "original_params", params
                        )
                        narrowed_params = classification_meta.get(
                            "narrowed_params", params
                        )
                        constraints_applied = classification_meta.get(
                            "constraints_applied", []
                        )
                        narrowing_reason = classification_meta.get(
                            "narrowing_reason", ""
                        )

                        # Issue routing seal for the NARROWED parameters
                        # The seal attests to the narrowed params, not the original
                        # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                        with tracer.start_as_current_span(
                            "cage.routing_seal"
                        ) as seal_span:
                            seal = await generate_seal_with_evidence(
                                action, narrowed_params
                            )
                            seal_span.set_attribute("cage.seal_issued", True)
                            seal_span.set_attribute("cage.seal_path", "narrow")

                        # OTel telemetry for NARROW decisions
                        span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
                        span.set_attribute("cage.governance.narrowed", True)
                        span.set_attribute(
                            "cage.governance.constraints_applied",
                            json.dumps(constraints_applied)[:500],
                        )
                        span.set_attribute(
                            "langfuse.observation.output",
                            GovernanceDecision.NARROW,
                        )
                        span.set_status(Status(StatusCode.OK))
                        logger.info(
                            "📐 validate_action NARROW: action=%s reason=%s "
                            "constraints=%s (%.1fms)",
                            action,
                            narrowing_reason,
                            constraints_applied,
                            latency_ms,
                        )
                        return {
                            "verdict": GovernanceDecision.NARROW,
                            "violations": violations,
                            "seal": seal,
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                            # NARROW-specific fields
                            "original_params": original_params,
                            "narrowed_params": narrowed_params,
                            "narrowing_reason": narrowing_reason,
                            "constraints_applied": constraints_applied,
                            "execution_allowed": True,
                        }

                    # ── PAUSE path (Phase 1.4 — resumable suspension) ──────────
                    if decision == GovernanceDecision.PAUSE:
                        from datetime import datetime
                        from datetime import timezone as tz

                        from src.gateway.governance.contracts import PauseReceipt
                        from src.gateway.governance.pause_primitive import (
                            CAGE_PAUSE_ENABLED,
                            PauseManager,
                            build_resume_endpoint,
                        )
                        from src.gateway.infrastructure.redis_client import redis_client

                        # Extract pause metadata from classification result
                        pause_reason: str = classification_meta.get(
                            "pause_reason", "RATE_LIMITED"
                        )
                        estimated_wait: int = classification_meta.get(
                            "estimated_wait_seconds", 60
                        )
                        _va_pause_thread_id = str(
                            params.get("transaction_id", "")
                            or params.get("thread_id", "")
                            or "unknown"
                        )

                        # Defense-in-depth: verify PAUSE is enabled at validate_action boundary
                        # (This check is redundant with _classify_violation but provides a
                        # safety net if the flag is toggled between classification and here)
                        if not CAGE_PAUSE_ENABLED:
                            span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                            span.set_attribute("cage.pause_fallback", True)
                            span.set_status(Status(StatusCode.ERROR))
                            logger.warning(
                                "🚫 validate_action PAUSE->DENY fallback: action=%s "
                                "reason=%s (CAGE_PAUSE_ENABLED=false)",
                                action,
                                pause_reason,
                            )
                            receipt = RefusalReceipt(
                                thread_id=_va_pause_thread_id,
                                action=action,
                                violated_tier="PAUSE_FALLBACK",
                                violated_rule=f"Transient condition: {pause_reason}",
                                standing_at_refusal={
                                    "symbol": params.get("symbol"),
                                    "amount": params.get("amount"),
                                    "confidence": params.get("confidence"),
                                    "pause_reason": pause_reason,
                                },
                            )
                            span.set_attribute(
                                "cage.refusal_proof_hash", receipt.proof_hash
                            )
                            raise GovernanceError(
                                f"Transient condition ({pause_reason}) detected; "
                                "CAGE_PAUSE_ENABLED=false — request denied",
                                receipt=receipt,
                            )

                        # Store the pause state in Redis via PauseManager
                        pause_token = ""
                        expires_at_utc = ""
                        try:
                            pause_manager = PauseManager(redis_client)
                            request_id = params.get(
                                "request_id",
                                params.get(
                                    "thread_id", f"{action}_{_va_pause_thread_id}"
                                ),
                            )
                            pause_token = await pause_manager.pause_request(
                                request_id=request_id,
                                reason=pause_reason,
                                ttl_seconds=3600,  # 1 hour default
                                original_request=params,
                                thread_id=_va_pause_thread_id,
                                estimated_wait_secs=estimated_wait,
                            )
                            # Fetch the state to get expires_at
                            pause_state = await pause_manager.get_pause_state(
                                pause_token
                            )
                            if pause_state:
                                expires_at_utc = pause_state.expires_at_utc
                        except Exception as pause_exc:
                            # Fail-closed: if Redis is unavailable, fall back to DENY
                            logger.error(
                                "🚫 validate_action PAUSE->DENY (Redis unavailable): "
                                "action=%s reason=%s error=%s",
                                action,
                                pause_reason,
                                pause_exc,
                            )
                            span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                            span.set_attribute("cage.pause_redis_error", True)
                            span.set_status(Status(StatusCode.ERROR))
                            receipt = RefusalReceipt(
                                thread_id=_va_pause_thread_id,
                                action=action,
                                violated_tier="PAUSE_REDIS_ERROR",
                                violated_rule=f"Transient condition: {pause_reason}",
                                standing_at_refusal={
                                    "symbol": params.get("symbol"),
                                    "amount": params.get("amount"),
                                    "confidence": params.get("confidence"),
                                    "pause_reason": pause_reason,
                                    "redis_error": str(pause_exc),
                                },
                            )
                            span.set_attribute(
                                "cage.refusal_proof_hash", receipt.proof_hash
                            )
                            raise GovernanceError(
                                f"Transient condition ({pause_reason}) detected; "
                                "PAUSE storage failed — request denied",
                                receipt=receipt,
                            )

                        # Create PauseReceipt for audit trail
                        pause_receipt = PauseReceipt(
                            thread_id=_va_pause_thread_id,
                            action=action,
                            pause_reason=pause_reason,
                            pause_token=pause_token,
                            violations=violations,
                            standing_at_pause={
                                "symbol": params.get("symbol"),
                                "amount": params.get("amount"),
                                "confidence": params.get("confidence"),
                            },
                            estimated_wait_seconds=estimated_wait,
                            expires_at_utc=expires_at_utc,
                        )

                        # OTel telemetry
                        span.set_attribute("cage.verdict", GovernanceDecision.PAUSE)
                        span.set_attribute("cage.pause_token", pause_token)
                        span.set_attribute("cage.pause_reason", pause_reason)
                        span.set_attribute("cage.pause_estimated_wait", estimated_wait)
                        span.set_attribute(
                            "cage.pause_receipt_hash", pause_receipt.proof_hash
                        )
                        span.set_attribute(
                            "langfuse.observation.output", GovernanceDecision.PAUSE
                        )
                        span.set_status(Status(StatusCode.OK))

                        logger.info(
                            "⏸️ validate_action PAUSE: action=%s reason=%s "
                            "pause_token=%s estimated_wait=%ds (%.1fms)",
                            action,
                            pause_reason,
                            pause_token,
                            estimated_wait,
                            latency_ms,
                        )

                        return {
                            "verdict": GovernanceDecision.PAUSE,
                            "violations": violations,
                            "seal": "",  # No seal for PAUSE — action is neither approved nor denied
                            "latency_ms": latency_ms,
                            "classification_meta": classification_meta,
                            # PAUSE-specific fields (Phase 1.4)
                            "pause_token": pause_token,
                            "pause_reason": pause_reason,
                            "resume_endpoint": build_resume_endpoint(pause_token),
                            "expires_at_utc": expires_at_utc,
                            "estimated_wait_seconds": estimated_wait,
                            "retry_after_seconds": estimated_wait,
                            # Audit receipt
                            "pause_receipt": pause_receipt,
                        }

                    # ── DENY path (default for hard violations) ────────────────
                    # This is the fallback for all other decisions (including
                    # explicitly classified DENY). Preserves existing behavior.
                    span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                    span.set_attribute(
                        "langfuse.observation.output", json.dumps(violations)
                    )
                    span.set_status(Status(StatusCode.ERROR))
                    logger.warning(
                        "🚫 validate_action DENIED: action=%s violations=%s reason=%s",
                        action,
                        violations,
                        classification_meta.get("classification_reason", ""),
                    )
                    _va_thread_id = str(
                        params.get("transaction_id", "")
                        or params.get("thread_id", "")
                        or "unknown"
                    )
                    _va_tier_failures = result.get("tier_failures", [])
                    _va_first_tf = _va_tier_failures[0] if _va_tier_failures else None
                    receipt = RefusalReceipt(
                        thread_id=_va_thread_id,
                        action=action,
                        violated_tier=_va_first_tf.tier
                        if _va_first_tf
                        else "SYMBOLIC_GOVERNOR",
                        violated_rule=violations[0],
                        standing_at_refusal={
                            "symbol": params.get("symbol"),
                            "amount": params.get("amount"),
                            "confidence": params.get("confidence"),
                        },
                        # ── 5-part proof chain (Terry Snyder) ──
                        schema_version="v2",
                        attempted_params={
                            k: v
                            for k, v in params.items()
                            if k not in ("thread_id", "transaction_id")
                        },
                        standing_snapshot=_va_first_tf.governing_state
                        if _va_first_tf
                        else {},
                        control_id=_va_first_tf.control_id if _va_first_tf else "",
                        protected_consequence=_va_first_tf.protected_consequence
                        if _va_first_tf
                        else "",
                        non_formation_proof="action_blocked_pre_commit",
                        tier_failures=tuple(_va_tier_failures),
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    raise GovernanceError(violations[0], receipt=receipt)

                # ── Issue routing seal AFTER full pipeline approval ───────────
                # The seal is generated here — after _run_checks() has completed
                # all 7 tiers — so that it cryptographically attests to complete
                # governance approval, not just a partial CBF+OPA check.
                #
                # Phase 2.1 (R-06 mitigation): Uses generate_seal_with_evidence()
                # which blocks on evidence commit when EVIDENCE_CHAIN_BLOCKING=true.
                from src.gateway.governance.routing_seal import (
                    generate_seal_with_evidence,
                )

                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = await generate_seal_with_evidence(action, params)
                    seal_span.set_attribute("cage.seal_issued", True)

                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                span.set_attribute(
                    "langfuse.observation.output", GovernanceDecision.ALLOW
                )
                span.set_status(Status(StatusCode.OK))
                logger.info(
                    "✅ validate_action ALLOW: action=%s (%.1fms)",
                    action,
                    latency_ms,
                )

                return {
                    "verdict": GovernanceDecision.ALLOW,
                    "violations": [],
                    "seal": seal,
                    "latency_ms": latency_ms,
                }
            except GovernanceError:
                raise
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                raise


def assert_safe_operational_state() -> None:
    """Raise RuntimeError if the system is in a combined high-risk operational state.

    Specifically, raises if BOTH of the following are true simultaneously:
      - CBF_FAIL_OPEN=true (CBF gate is bypassed)
      - KMSGovernanceSigner is in HMAC fallback mode (no non-repudiation)

    Either condition alone is a compliance gap. Together they mean:
      - No independent cash balance verification (CBF bypassed)
      - No externally verifiable governance attestation (HMAC fallback)
    This combined state is the highest-risk operational posture and must
    never occur in production.

    Also warns (CRITICAL log) or raises (production) when
    RECONCILIATION_PROVIDER=stub, which means the CBF is evaluating against
    self-reported balances — POAM-023 open gap.

    Call this during application startup.
    """
    env = (
        os.environ.get("CAGE_ENV") or os.environ.get("ENVIRONMENT", "production")
    ).lower()
    _is_production = env not in ("development", "test", "dev", "ci")

    # ── Gap 5 (POAM-023): CBF ground truth is self-reported ──────────────────
    _recon_provider = os.environ.get("RECONCILIATION_PROVIDER", "stub").lower()
    if _recon_provider == "stub":
        _poam023_msg = (
            "CAGE STARTUP WARNING (POAM-023): RECONCILIATION_PROVIDER=stub. "
            "The CBF is evaluating cash barrier conditions against self-reported "
            "balances written by the execution system itself — no external ground "
            "truth is available. This is a known open compliance gap. "
            "Resolve by setting RECONCILIATION_PROVIDER=plaid or =anchorage and "
            "provisioning the corresponding credentials."
        )
        if _is_production:
            raise RuntimeError(_poam023_msg)
        else:
            logger.critical(
                json.dumps(
                    {
                        "event": "POAM_023_STUB_PROVIDER_IN_USE",
                        "severity": "CRITICAL",
                        "reconciliation_provider": _recon_provider,
                        "environment": env,
                        "poam_id": "POAM-023",
                        "audit_note": _poam023_msg,
                    }
                )
            )

    cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"
    if not cbf_fail_open:
        return  # CBF is active — combined risk state is not present

    # CBF is bypassed — check if KMS is also in fallback mode
    try:
        from src.gateway.governance.kms_signer import get_governance_signer

        signer = get_governance_signer()
        kms_active = signer.is_kms_active
    except Exception:
        kms_active = False  # Cannot determine — assume worst case

    if not kms_active:
        msg = (
            "CAGE STARTUP FAILURE: Combined high-risk operational state detected. "
            "CBF_FAIL_OPEN=true (CBF gate bypassed) AND KMSGovernanceSigner is in "
            "HMAC fallback mode (no non-repudiation). "
            "This means: (1) cash balance cannot be independently verified, "
            "(2) governance attestations cannot be externally verified. "
            "Resolve by: setting KMS_GOVERNANCE_KEY and/or setting CBF_FAIL_OPEN=false."
        )
        if _is_production:
            raise RuntimeError(msg)
        else:
            logger.critical(
                json.dumps(
                    {
                        "event": "COMBINED_HIGH_RISK_STATE",
                        "severity": "CRITICAL",
                        "cbf_fail_open": True,
                        "kms_active": False,
                        "environment": env,
                        "audit_note": msg,
                    }
                )
            )


# ---------------------------------------------------------------------------
# DeferQueue integration for DEFER path
# ---------------------------------------------------------------------------


async def _park_defer_context(
    action: str,
    params: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    thread_id: str | None,
    confidence: float,
    classification_meta: dict[str, Any],
    violations: list[str],
) -> str:
    """Park deferred action context in DeferQueue db=1 and return the defer_id.

    Connects to Redis db=1 via REDIS_URL (matching the deployment contract
    documented in defer_queue.py — the DEFER token store is isolated from the
    LangGraph checkpointer at db=0) and parks the token through the existing
    DeferQueue infrastructure. Falls back to a local, unpersisted UUID token
    if Redis is unavailable — the DEFER verdict is still returned, but external
    HITL API resolution (GET /v1/defer/pending, POST /v1/defer/{id}/escalate)
    will not find this token in that fallback case, since it was never written
    to Redis.

    Args:
        action:              The action type being deferred.
        params:              The action parameters (sanitized).
        metadata:            Request metadata including thread_id.
        thread_id:           LangGraph thread ID for audit trail correlation.
        confidence:          Model confidence score [0, 1] at decision time.
        classification_meta: Classification metadata from _classify_violation().
        violations:          List of violation strings from OPA/STPA.

    Returns:
        The defer_id (UUID string) — either from DeferQueue.park() or a local
        fallback UUID if Redis is unavailable.
    """
    import uuid

    from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken

    # Generate a stable thread_id if not provided
    effective_thread_id = thread_id or str(uuid.uuid4())

    # Build the OPA input snapshot for later replay/escalation
    opa_input_snapshot = {
        "action": action,
        "params": params or {},
        "metadata": metadata or {},
        "violations": violations,
        "classification_reason": classification_meta.get("classification_reason", ""),
    }

    # Map classification reason to DeferReason enum
    reason_str = classification_meta.get("classification_reason", "")
    if "confidence" in reason_str.lower():
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD
    elif "context" in reason_str.lower() or "missing" in reason_str.lower():
        defer_reason = DeferReason.INSUFFICIENT_CONTEXT
    elif "ambiguous" in reason_str.lower():
        defer_reason = DeferReason.AMBIGUOUS_SEMANTIC_DISTANCE
    elif "data" in reason_str.lower() and "starvation" in reason_str.lower():
        defer_reason = DeferReason.DATA_STARVATION
    else:
        defer_reason = DeferReason.CONFIDENCE_BELOW_THRESHOLD

    token = DeferToken(
        thread_id=effective_thread_id,
        defer_reason=defer_reason,
        opa_input_snapshot=opa_input_snapshot,
        confidence_score=confidence,
        aarm_vector="AARM-V7",  # Context Window Overflow / Data Starvation
    )

    async def _park() -> str:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        try:
            queue = DeferQueue(client)
            return await queue.park(token)
        finally:
            await client.aclose()

    try:
        return await _park()
    except Exception as exc:
        # Redis unavailable — fall back to local UUID
        # The DEFER verdict still holds, but the token is NOT persisted
        # and cannot be retrieved via GET /v1/defer/pending
        logger.warning(
            "DeferQueue park failed (%s) — using local defer_id only "
            "(token NOT persisted to Redis; HITL API will not find it). "
            "action=%s thread_id=%s",
            exc,
            action,
            effective_thread_id,
        )
        return token.defer_id
