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


from src.gateway.governance.contracts import RefusalReceipt


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
FRIA_ZONE_ALLOW: float = float(os.getenv("FRIA_ZONE_ALLOW", "0.95"))
FRIA_ZONE_DEFER: float = float(os.getenv("FRIA_ZONE_DEFER", "0.70"))


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
        policy_resp = None
        # CRIT-5 fix: local variable replaces self._pending_payload to eliminate
        # the data race on the singleton under concurrent async requests.
        _conf_payload: dict[str, Any] | None = None

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
                _confidence_threshold = float(
                    os.getenv("AGENT_CONFIDENCE_THRESHOLD", "0.95")
                )
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

        if tool_name == "execute_trade" and not violations:
            # 2 + 4. CBF (Redis) and OPA policy checks run CONCURRENTLY.
            # They have no data dependency on each other — parallelising them
            # reduces combined latency from CBF_ms+OPA_ms to max(CBF_ms, OPA_ms).
            _cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"

            # --- CBF coroutine (wrapped to capture span) ---
            async def _cbf_check_with_span() -> str | None:
                """Run the CBF Redis check inside a dedicated Langfuse span.

                A1 (Issue #6): Uses atomic_verify_and_commit() instead of the
                deprecated verify_action() to collapse the CBF barrier check and
                the balance debit into a single atomic Redis Lua hop, eliminating
                the TOCTOU window between the read-only check and the write-commit
                phases that allowed two concurrent govern() calls to both observe
                the same pre-trade balance and both pass (CBF Invariance Theorem
                atomicity premise, §5.1/§5.2).

                Return convention: mirrors verify_action() — returns "SAFE" on
                commit, or the UNSAFE reason string on envelope violation, so
                all downstream cbf_result handling remains unchanged.
                """
                with tracer.start_as_current_span("cage.cbf_check") as cbf_span:
                    cbf_span.set_attribute(
                        "langfuse.observation.name", "cbf_barrier_check"
                    )
                    cbf_span.set_attribute("governance.stage", "cbf")
                    cbf_span.set_attribute("governance.cbf.atomic", True)
                    _t = time.perf_counter()
                    try:
                        (
                            committed,
                            reason,
                        ) = await self.safety_filter.atomic_verify_and_commit(
                            action_name=tool_name,
                            payload=params,
                        )
                        # Normalise to the str result that downstream code expects:
                        #   committed=True  → "SAFE" (balance was debited atomically)
                        #   committed=False → the UNSAFE reason from the Lua script
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

            # --- OPA coroutine (wrapped to capture span timing) ---
            opa_payload = params.copy()
            opa_payload["action"] = tool_name

            async def _opa_check_with_span() -> Any:
                """Run OPA policy evaluation inside a dedicated Langfuse span."""
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute(
                        "langfuse.observation.name", "opa_policy_pre_check"
                    )
                    opa_span.set_attribute("governance.stage", "opa")
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

            # Fire both checks concurrently
            _t_parallel_start = time.perf_counter()
            _gather_results = await asyncio.gather(
                _cbf_check_with_span(),
                _opa_check_with_span(),
                return_exceptions=True,
            )
            cbf_result: str | None | BaseException = _gather_results[0]
            policy_resp = _gather_results[1]  # Any — asyncio.gather with return_exceptions=True
            _parallel_ms = round((time.perf_counter() - _t_parallel_start) * 1000, 2)
            logger.debug(
                "⚡ CBF+OPA parallel gate completed in %.1fms (tool=%s)",
                _parallel_ms,
                tool_name,
            )

            # --- Evaluate CBF result ---
            if isinstance(cbf_result, BaseException):
                if _cbf_fail_open:
                    logger.warning(
                        "⚠️ CBF check unavailable (%s) — CBF_FAIL_OPEN=true, "
                        "skipping CBF gate. ⚠️ AUDIT: Self-reported cash balance "
                        "cannot be verified; this gap must be closed before "
                        "production governance examination.",
                        cbf_result,
                    )
                    logger.critical(
                        json.dumps(
                            {
                                "event": "CBF_FAIL_OPEN_ACTIVATED",
                                "severity": "CRITICAL",
                                "tool": tool_name,
                                "cbf_error": str(cbf_result),
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
                        cbf_result,
                    )
                    violations.append(
                        "CBF Fail-Closed: Redis unavailable — cannot verify "
                        "cash barrier. Self-reported balance has no independent "
                        "provenance. Set CBF_FAIL_OPEN=true to override "
                        "(audit gap)."
                    )
            elif isinstance(cbf_result, str) and cbf_result.startswith("UNSAFE"):
                violations.append(f"Safety Violation (RBC/CBF): {cbf_result}")

            # --- Evaluate OPA result ---
            if isinstance(policy_resp, BaseException):
                violations.append(f"OPA Check Failed: {policy_resp}")
                policy_resp = None
            else:
                if isinstance(policy_resp, dict):
                    # OPA trade.governance policy returns {"allow": "ALLOW"/"DENY"/"MANUAL_REVIEW"}.
                    # Fall back to "decision" key for backward compat with other policy packages.
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
                _confidence_threshold_t2: float = float(
                    os.getenv("AGENT_CONFIDENCE_THRESHOLD", "0.95")
                )

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

        # 3. Fiscal Limit Pre-Reservation (trade-specific).
        # Atomically reserves the requested USD amount against the daily fiscal
        # cap in Redis (WATCH/MULTI/EXEC) BEFORE the consensus gate.  This closes
        # the TOCTOU race between the CBF balance check and actual trade execution:
        # without this step, two concurrent agents could both pass CBF and OPA
        # against the same remaining balance and together exceed the daily cap.
        # The reservation is released in the finally block if any subsequent tier
        # (consensus, causal, FRIA) raises a violation.
        # If fiscal_limit_guard is None (e.g. in tests), this step is skipped.
        _fiscal_token = None
        if (
            tool_name == "execute_trade"
            and self.fiscal_limit_guard is not None
            and not violations
        ):
            with tracer.start_as_current_span(
                "cage.fiscal_limit_reserve"
            ) as fiscal_span:
                fiscal_span.set_attribute(
                    "langfuse.observation.name", "fiscal_limit_reserve"
                )
                fiscal_span.set_attribute("governance.stage", "fiscal_limit")
                _t_fiscal = time.perf_counter()
                try:
                    _amount = float(params.get("amount", 0.0))
                    _agent_id = str(
                        params.get("agent_id", params.get("user_id", "unknown-agent"))
                    )
                    if _amount > 0:
                        _fiscal_token = await self.fiscal_limit_guard.reserve(
                            agent_id=_agent_id,
                            amount_usd=_amount,
                        )
                        fiscal_span.set_attribute(
                            "governance.fiscal.reservation_id",
                            _fiscal_token.reservation_id,
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
                            _fiscal_token = (
                                None  # Nothing to release — reservation was denied
                            )
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
                fiscal_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t_fiscal) * 1000, 2),
                )

        # If any tier up to this point has already produced violations, release
        # the fiscal reservation immediately so capacity is not held unnecessarily.
        if violations and _fiscal_token is not None:
            try:
                await self.fiscal_limit_guard.release(_fiscal_token)  # type: ignore[union-attr]
                logger.info(
                    "🔄 Fiscal reservation released (pre-consensus violation): id=%s",
                    _fiscal_token.reservation_id,
                )
            except Exception as _rel_exc:
                logger.warning("⚠️ FiscalLimitGuard.release() failed: %s", _rel_exc)
            _fiscal_token = None

        # 5. ISO 42001: Multi-agent Consensus (trade-specific, high-stakes)
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

        # Release fiscal reservation if any post-reservation tier (consensus,
        # causal, FRIA) produced violations.  The reservation was held optimistically
        # through those tiers; if they fail we must return the capacity to the pool.
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
            "opa_results": policy_resp,
            # CRIT-5 fix: _conf_payload is a local variable (initialized to None
            # above), set only when a confidence violation is detected.  Returning
            # it here instead of storing on self eliminates the singleton race.
            "pending_payload": _conf_payload,
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
        from src.gateway.governance.routing_seal import generate_seal

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
                    receipt = RefusalReceipt(
                        thread_id=thread_id,
                        action=tool_name,
                        violated_tier="SYMBOLIC_GOVERNOR",
                        violated_rule=violation_msg,
                        standing_at_refusal={
                            "symbol": params.get("symbol"),
                            "amount": params.get("amount"),
                            "currency": params.get("currency"),
                            "confidence": params.get("confidence"),
                        },
                    )
                    span.set_attribute("cage.refusal_proof_hash", receipt.proof_hash)
                    span.set_attribute("cage.verdict", "BLOCKED")
                    raise GovernanceError(
                        violation_msg, payload=payload, receipt=receipt
                    )

                # Gap 2 fix: issue routing seal AFTER all checks pass.
                # The seal is the cryptographic attestation that resolvedAllow=TRUE.
                # Callers must verify it before executing the governed action.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = generate_seal(tool_name, params)
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

        This avoids paying the full 7-tier cost (including multi-model consensus
        and DoWhy causal computation) for a targeted post-approval recheck.

        Args:
            params: Trade parameters dict, same shape as passed to ``govern()``.
            trace_id: Optional trace correlation ID for OTel span attribution.

        Returns:
            HMAC-SHA256 routing seal string (non-empty on approval).

        Raises:
            GovernanceError: If CBF or OPA check fails after HITL approval.
        """
        from src.gateway.governance.routing_seal import generate_seal

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
                    raise GovernanceError(violations[0])

                # Issue routing seal — attests that CBF+OPA re-check passed.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = generate_seal(tool_name, params)
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
        complete 7-tier governance pipeline via ``_run_checks()`` — STPA,
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

                # ── Full 7-tier governance pipeline ──────────────────────────
                # _run_checks() executes: STPA → Confidence → CBF+OPA (parallel)
                # → Fiscal Limit Pre-Reservation → Consensus → Causal → FRIA.
                # The routing seal is issued ONLY after all tiers pass — a seal
                # issued before full pipeline completion would imply governance
                # approval that was never actually granted.
                result = await self._run_checks(action, params, sim_mode=False)
                violations = result["violations"]

                latency_ms = round((time.time() - t0) * 1000, 2)
                span.set_attribute("cage.governance_latency_ms", latency_ms)

                # ── Detect REQUIRE_APPROVAL (OPA MANUAL_REVIEW) ──────────────
                # When OPA returns MANUAL_REVIEW, _run_checks() appends a
                # violation string containing "Manual Review Required".  We
                # detect this specific case and return REQUIRE_APPROVAL rather
                # than raising GovernanceError, so the adapter can surface the
                # correct HTTP 202 body with verdict="REQUIRE_APPROVAL" instead
                # of collapsing it into a generic DENY or DEFERRED response.
                _is_manual_review = violations and any(
                    "Manual Review Required" in v for v in violations
                )

                if _is_manual_review:
                    span.set_attribute(
                        "cage.verdict", GovernanceDecision.REQUIRE_APPROVAL
                    )
                    span.set_attribute(
                        "langfuse.observation.output",
                        GovernanceDecision.REQUIRE_APPROVAL,
                    )
                    span.set_status(Status(StatusCode.OK))
                    logger.info(
                        "🔶 validate_action REQUIRE_APPROVAL: action=%s (%.1fms)",
                        action,
                        latency_ms,
                    )
                    return {
                        "verdict": GovernanceDecision.REQUIRE_APPROVAL,
                        "violations": violations,
                        "seal": "",
                        "latency_ms": latency_ms,
                    }

                if violations:
                    span.set_attribute("cage.verdict", GovernanceDecision.DENY)
                    span.set_attribute(
                        "langfuse.observation.output", json.dumps(violations)
                    )
                    span.set_status(Status(StatusCode.ERROR))
                    logger.warning(
                        "🚫 validate_action DENIED: action=%s violations=%s",
                        action,
                        violations,
                    )
                    raise GovernanceError(violations[0])

                # ── Issue routing seal AFTER full pipeline approval ───────────
                # The seal is generated here — after _run_checks() has completed
                # all 7 tiers — so that it cryptographically attests to complete
                # governance approval, not just a partial CBF+OPA check.
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = generate_seal(action, params)
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
