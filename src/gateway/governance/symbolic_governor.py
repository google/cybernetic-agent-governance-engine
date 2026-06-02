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
from typing import Any, Dict, List, Optional

import httpx
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.core.policy import OPAClient
from src.gateway.governance.constants import GovernanceControl, ControlRegistry
from src.gateway.governance.contracts import SafetyFilter, ConsensusProvider
from src.gateway.governance.stpa_validator import STPAValidator
from src.gateway.governance.schemas.thresholds import THRESHOLDS

logger = logging.getLogger("SymbolicGovernor")
tracer = trace.get_tracer(__name__)

# SLM sidecar has been completely deprecated to optimize latency.

class GovernanceError(Exception):
    """Raised when a symbolic rule is violated.

    Args:
        message: Human-readable violation description.  Begins with the stable
                 ``[CTRL_*]`` control ID so log aggregators can key on it.
        payload: Optional structured dict emitted to OTel / SIEM consumers.
                 Contains ``control_id``, ``primary_framework``,
                 ``legacy_citation``, etc. sourced from control_mappings.json.
    """

    def __init__(self, message: str, payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.payload: Dict[str, Any] = payload or {}




# ---------------------------------------------------------------------------
# SymbolicGovernor
# ---------------------------------------------------------------------------


class SymbolicGovernor:
    def __init__(
        self,
        opa_client: OPAClient,
        safety_filter: SafetyFilter,
        consensus_engine: ConsensusProvider,
        stpa_validator: Optional[STPAValidator] = None,
        telemetry_provider: Optional[Any] = None,
    ):
        self.opa_client = opa_client
        self.safety_filter = safety_filter
        self.consensus_engine = consensus_engine
        self.stpa_validator: Optional[STPAValidator] = stpa_validator
        self.telemetry_provider = telemetry_provider

    async def _run_checks(
        self,
        tool_name: str,
        params: Dict[str, Any],
        sim_mode: bool = False,
    ) -> Dict[str, Any]:
        """Core governance check pipeline shared by ``govern()`` and ``verify()``.

        Returns a dict: {"violations": list[str], "opa_results": dict | None}

        Latency optimizations (v2.0.x baseline):
        - CBF (Redis read) and OPA (HTTP) checks are fully independent and now
          run concurrently via asyncio.gather, bounding their combined cost to
          max(CBF_ms, OPA_ms) instead of CBF_ms + OPA_ms.
        - Each stage is wrapped in a discrete OTel span so Langfuse shows the
          full 10-layer pipeline breakdown.
        """
        violations: List[str] = []
        policy_resp = None

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
            stpa_span.set_attribute("governance.stpa.violations", len(violations))
            stpa_span.set_attribute("governance.stage.latency_ms",
                                    round((time.perf_counter() - _t0) * 1000, 2))

        # 1. Agentic model confidence threshold (trade-specific).
        # Governed under CTRL_AGT_001 — see config/control_mappings.json for the
        # active regulatory framework mapping.  Agentic AI is explicitly outside
        # the prescriptive MRM scope; the registry records both the primary
        # framework and the legacy citation for SIEM backward-compatibility.
        if tool_name == "execute_trade":
            with tracer.start_as_current_span("cage.confidence_check") as conf_span:
                conf_span.set_attribute("langfuse.observation.name", "agent_confidence_check")
                default_confidence = (
                    float(os.getenv("GOVERNANCE_SIM_CONFIDENCE", "0.99"))
                    if sim_mode
                    else 0.0  # Fail-closed in live mode
                )
                confidence = params.get("confidence", default_confidence)
                # Threshold from singleton (Phase 2.3)
                min_confidence = THRESHOLDS.confidence.min_trade_confidence
                conf_span.set_attribute("governance.confidence.value", confidence)
                conf_span.set_attribute("governance.confidence.threshold", min_confidence)
                if confidence < min_confidence:
                    registry = ControlRegistry()
                    meta = registry.get_mapping(GovernanceControl.AGENT_CONFIDENCE_THRESHOLD)
                    error_msg = (
                        f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] "
                        f"{meta['primary_framework']} Violation: "
                        f"Agentic Model Confidence {confidence} < {min_confidence}."
                    )
                    structured_payload = {
                        "control_id": meta["internal_id"],
                        "primary_framework": meta["primary_framework"],
                        "co_frameworks": meta["co_frameworks"],
                        "legacy_citation": meta["legacy_citation"],
                        "scope": meta["scope"],
                    }
                    violations.append(error_msg)
                    # Attach payload to the first violation so govern() can
                    # surface it on the raised GovernanceError.
                    if not hasattr(self, "_pending_payload"):
                        self._pending_payload = structured_payload
                    conf_span.set_attribute("governance.confidence.result", "FAIL")
                else:
                    conf_span.set_attribute("governance.confidence.result", "PASS")

            # 2 + 4. CBF (Redis) and OPA policy checks run CONCURRENTLY.
            # They have no data dependency on each other — parallelising them
            # reduces combined latency from CBF_ms+OPA_ms to max(CBF_ms, OPA_ms).
            _cbf_fail_open = os.getenv("CBF_FAIL_OPEN", "false").lower() == "true"

            # --- CBF coroutine (wrapped to capture span) ---
            async def _cbf_check_with_span() -> Optional[str]:
                """Run the CBF Redis check inside a dedicated Langfuse span."""
                with tracer.start_as_current_span("cage.cbf_check") as cbf_span:
                    cbf_span.set_attribute("langfuse.observation.name", "cbf_barrier_check")
                    cbf_span.set_attribute("governance.stage", "cbf")
                    _t = time.perf_counter()
                    try:
                        result = await self.safety_filter.verify_action(tool_name, params)
                        cbf_span.set_attribute("governance.cbf.result", result[:80])
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
            slm_score: Optional[float] = None
            slm_available: bool = False  # SLM sidecar deprecated (v2.0.x)

            opa_payload = params.copy()
            opa_payload["action"] = tool_name
            # Inject SLM sentinel — Phase 4.3
            opa_payload["slm_available"] = slm_available
            if slm_score is not None:
                opa_payload["slm_similarity_score"] = slm_score

            async def _opa_check_with_span() -> Any:
                """Run OPA policy evaluation inside a dedicated Langfuse span."""
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute("langfuse.observation.name", "opa_policy_pre_check")
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
            cbf_result, policy_resp = await asyncio.gather(
                _cbf_check_with_span(),
                _opa_check_with_span(),
                return_exceptions=True,
            )
            _parallel_ms = round((time.perf_counter() - _t_parallel_start) * 1000, 2)
            logger.debug(
                "⚡ CBF+OPA parallel gate completed in %.1fms (tool=%s)",
                _parallel_ms, tool_name,
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
                    policy_decision = policy_resp.get("allow", policy_resp.get("decision", "DENY"))
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision == "DENY":
                    _opa_meta = ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )

        else:
            # Non-trade actions: sequential OPA only (no CBF needed)
            slm_score: Optional[float] = None  # type: ignore[assignment]
            slm_available: bool = False  # type: ignore[assignment]
            opa_payload = params.copy()
            opa_payload["action"] = tool_name
            opa_payload["slm_available"] = slm_available
            try:
                with tracer.start_as_current_span("cage.opa_pre_check") as opa_span:
                    opa_span.set_attribute("langfuse.observation.name", "opa_policy_pre_check")
                    opa_span.set_attribute("governance.stage", "opa")
                    policy_resp = await self.opa_client.evaluate_policy(opa_payload)
                if isinstance(policy_resp, dict):
                    policy_decision = policy_resp.get("allow", policy_resp.get("decision", "DENY"))
                elif isinstance(policy_resp, str):
                    policy_decision = policy_resp
                else:
                    policy_decision = "DENY"
                if policy_decision == "DENY":
                    _opa_meta = ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Violation: OPA Denied Action."
                    )
                elif policy_decision == "MANUAL_REVIEW":
                    _opa_meta = ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)
                    violations.append(
                        f"[{GovernanceControl.OPA_POLICY_ENFORCEMENT.value}] "
                        f"{_opa_meta['primary_framework']} Check: Manual Review Required."
                    )
            except Exception as exc:
                violations.append(f"OPA Check Failed: {exc}")

        # 5. ISO 42001: Multi-agent Consensus (trade-specific, high-stakes)
        if tool_name == "execute_trade":
            with tracer.start_as_current_span("cage.consensus_gate") as cons_gate_span:
                cons_gate_span.set_attribute("langfuse.observation.name", "consensus_gate")
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
                        violations.append(f"Consensus Escalation: {consensus['reason']}")
                    cons_gate_span.set_attribute(
                        "governance.consensus.status", consensus.get("status", "UNKNOWN")
                    )
                except Exception as exc:
                    violations.append(f"Consensus Check Failed: {exc}")

        # 6. DoWhy Causal Gatekeeper — refutation-based safety lock
        if tool_name == "execute_trade":
            try:
                from src.gateway.governance.causal_gatekeeper import causal_safety_check

                telemetry_data = None
                if self.telemetry_provider is not None:
                    telemetry_data = self.telemetry_provider.get_latest_data()

                if not causal_safety_check(params, telemetry_data):
                    violations.append(
                        "Causal Safety Violation: DoWhy refutation failed — "
                        "world-model is untrustworthy or risk exceeds safety boundary."
                    )
            except ImportError:
                logger.debug("DoWhy not installed — skipping causal gatekeeper.")
            except Exception as exc:
                logger.warning("⚠️ Causal gatekeeper check failed (%s) — skipping.", exc)

        # 6b. Adaptive FRIA Enforcement (External Normative Provider)
        # When CAGE_NORMATIVE_PROVIDER != "static", the enforcement semantic
        # is dynamically determined by the consensus confidence score:
        #   Score ≥ 0.95 → ALLOW → async attestation (fire-and-forget)
        #   0.70 ≤ Score < 0.95 → DEFER → synchronous blocking gate
        #   Score < 0.70 → DENY → hard abort, no external call
        # Positioned AFTER all local tiers — if local governance already
        # DENY'd, the external provider is never contacted.
        _normative_provider_name = os.getenv("CAGE_NORMATIVE_PROVIDER", "static")
        if tool_name == "execute_trade" and _normative_provider_name != "static" and not violations:
            try:
                from src.gateway.governance.normative_provider import (
                    enforce_fria_boundary,
                    get_normative_provider,
                    ExecutionStatus,
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

        # 7. FRIA Attestation (EU_ECB only — EU AI Act Art. 29a)
        # For EU deployments, every governed action must carry a span attribute
        # attesting that a Fundamental Rights Impact Assessment (FRIA) was
        # conducted pre-market per Art. 29a. This is not a blocking runtime gate
        # (FRIA is a pre-market document obligation, not a per-request check),
        # but the live telemetry MUST record the control is active so that
        # DORA Art. 10 monitoring logs satisfy the Art. 12 logging obligation.
        fria_meta = ControlRegistry().get_mapping_safe(GovernanceControl.FRIA_ASSESSMENT)
        if fria_meta is not None:
            # Attach to the current OTel span so DORA Art. 10 audit logs include it
            current_span = trace.get_current_span()
            current_span.set_attribute(
                "governance.fria.control_id",    fria_meta["internal_id"],
            )
            current_span.set_attribute(
                "governance.fria.framework",     fria_meta["primary_framework"],
            )
            current_span.set_attribute(
                "governance.fria.scope",         fria_meta["scope"],
            )
            logger.debug(
                "[%s] FRIA attestation active — %s",
                GovernanceControl.FRIA_ASSESSMENT.value,
                fria_meta["primary_framework"],
            )

        return {"violations": violations, "opa_results": policy_resp}

    async def govern(self, tool_name: str, params: Dict[str, Any]) -> None:
        """Orchestrate governance checks for live execution.

        Raises:
            GovernanceError: If any check fails.
        """
        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "governance_evaluation")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"tool": tool_name, "params": params}),
            )
            logger.info("⚖️ Symbolic Governor evaluating: %s", tool_name)
            try:
                # Reset per-invocation payload state
                if hasattr(self, "_pending_payload"):
                    del self._pending_payload
                result = await self._run_checks(tool_name, params, sim_mode=False)
                violations = result["violations"]
                if violations:
                    payload = getattr(self, "_pending_payload", None)
                    raise GovernanceError(violations[0], payload=payload)
                logger.info("✅ Symbolic Governor Approved: %s", tool_name)
                span.set_attribute("langfuse.observation.output", "APPROVED")
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("langfuse.observation.output", str(exc))
                raise

    async def verify(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
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
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Validate a structured tool execution payload — Unified Gateway path.

        This is the entry point for **Option 2: Unified Gateway Governance
        Routing**.  Executes only Tier 2 (CBF) and Tier 4 (OPA), skipping
        Tier 1 (Aho-Corasick text scan) and Tier 3 (semantic similarity SLM)
        which are irrelevant for deterministic, structured tool payloads.

        On approval, a short-lived HMAC-SHA256 ``routing_seal`` is returned.
        The downstream actuator MUST verify this seal before firing — ensuring
        that execution cannot proceed by simply ignoring the HTTP response.

        Returns:
            Dict with keys:
                - ``verdict``:     ``"APPROVED"`` | ``"DENIED"`` | ``"MANUAL_REVIEW"``
                - ``violations``:  list of violation strings (empty if APPROVED)
                - ``seal``:        HMAC routing seal (empty string if not APPROVED)
                - ``latency_ms``:  total governance check wall-time in milliseconds

        Raises:
            GovernanceError: If any mandatory check fails.
        """
        from src.gateway.governance.routing_seal import generate_seal

        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute("cage.action", action)
            span.set_attribute("cage.governance", True)
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "cage.validate_action")
            span.set_attribute(
                "langfuse.observation.input",
                json.dumps({"action": action, "params": params})[:2000],
            )

            t0 = time.time()
            violations: List[str] = []

            try:
                # ── Parallel Safety Checks ───────────────────────────────────
                async def run_cbf():
                    with tracer.start_as_current_span("cage.cbf_action_check") as cbf_span:
                        cbf_span.set_attribute("cage.tier", 2)
                        cbf_span.set_attribute("cage.stage", "cbf")
                        try:
                            cbf_result = await self.safety_filter.verify_action(action, params)
                            cbf_ok = cbf_result == "SAFE"
                            cbf_span.set_attribute("cage.cbf_result", "PASS" if cbf_ok else "BLOCKED")
                            if not cbf_ok:
                                return f"CBF safety violation: {cbf_result}"
                        except Exception as cbf_exc:
                            logger.warning("⚠️ CBF action check failed: %s", cbf_exc)
                            cbf_span.record_exception(cbf_exc)
                            cbf_span.set_attribute("cage.cbf_result", "ERROR")
                    return None

                async def run_opa():
                    with tracer.start_as_current_span("cage.opa_action_check") as opa_span:
                        opa_span.set_attribute("cage.tier", 4)
                        opa_span.set_attribute("cage.stage", "opa")
                        try:
                            opa_payload = {
                                "action": action,
                                **{k: v for k, v in params.items()
                                   if k in ("symbol", "amount", "currency",
                                            "confidence", "trader_role", "user_id",
                                            "risk_profile", "drawdown_pct",
                                            "portfolio_fraction")},
                            }
                            opa_decision = await self.opa_client.evaluate_policy(opa_payload)
                            opa_span.set_attribute("cage.opa_decision", opa_decision)
                            if opa_decision == "DENY":
                                return f"OPA: policy denied '{action}'"
                            elif opa_decision == "MANUAL_REVIEW":
                                return f"OPA: '{action}' requires manual review"
                        except Exception as opa_exc:
                            logger.error("❌ OPA action check failed: %s", opa_exc)
                            opa_span.record_exception(opa_exc)
                            return f"OPA: evaluation error — {opa_exc}"
                    return None

                # Execute in parallel to maximize throughput and minimize latency
                import asyncio
                cbf_error, opa_error = await asyncio.gather(run_cbf(), run_opa())
                if cbf_error:
                    violations.append(cbf_error)
                if opa_error:
                    violations.append(opa_error)

                latency_ms = round((time.time() - t0) * 1000, 2)
                span.set_attribute("cage.governance_latency_ms", latency_ms)

                if violations:
                    span.set_attribute("cage.verdict", "DENIED")
                    span.set_attribute("langfuse.observation.output", json.dumps(violations))
                    span.set_status(Status(StatusCode.ERROR))
                    logger.warning(
                        "🚫 validate_action DENIED: action=%s violations=%s",
                        action, violations,
                    )
                    raise GovernanceError(violations[0])

                # ── Issue routing seal on APPROVED ────────────────────────────
                with tracer.start_as_current_span("cage.routing_seal") as seal_span:
                    seal = generate_seal(action, params)
                    seal_span.set_attribute("cage.seal_issued", True)

                span.set_attribute("cage.verdict", "APPROVED")
                span.set_attribute("langfuse.observation.output", "APPROVED")
                span.set_status(Status(StatusCode.OK))
                logger.info(
                    "✅ validate_action APPROVED: action=%s (%.1fms)", action, latency_ms
                )

                return {
                    "verdict": "APPROVED",
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

