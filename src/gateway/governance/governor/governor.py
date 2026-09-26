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

from collections.abc import Sequence
from typing import Any
import inspect
import json
import logging
import math
import time
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.core.policy import OPAClient
from src.gateway.governance.contracts import ConsensusProvider, GovernanceTierPlugin, SafetyFilter, Violation, ViolationKind
from src.gateway.governance.classification_engine import ClassificationContext, ClassificationEngine
from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.governor.pipeline import run_pipeline, Profile, StageContext
from src.gateway.governance.governor.stages.opa import OpaStage
from src.gateway.governance.governor.stages.stpa import StpaStage
from src.gateway.governance.governor.stages.ftra import FtraStage
from src.gateway.governance.governor.stages.confidence import ConfidenceStage
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.verdicts import (
    handle_defer,
    handle_deny,
    handle_narrow,
    handle_pause,
    handle_require_approval,
    issue_seal,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.contracts import InvariantModel
from src.gateway.observability.attributes import OBSERVATION_INPUT, OBSERVATION_NAME, OBSERVATION_OUTPUT, OBSERVATION_TYPE
from src.gateway.governance.governor.errors import GovernanceError

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

class SymbolicGovernor:
    def __init__(
        self,
        opa_client: OPAClient,
        safety_filter: SafetyFilter,
        consensus_engine: ConsensusProvider,
        classification_engine: ClassificationEngine | None = None,
        domain_tiers: Sequence[GovernanceTierPlugin] = (),
        stpa_validator: Any | None = None,
        **kwargs,
    ) -> None:
        self._classifier = classification_engine or ClassificationEngine()
        
        self.stages = [
            FtraStage(),
            StpaStage(stpa_validator),
            OpaStage(opa_client),
            ConfidenceStage(),
            *order_stages(domain_tiers)
        ]
        
        self.domain_tiers = list(domain_tiers)
        self._domain_tiers = self.domain_tiers
        self.safety_filter = safety_filter
        self.opa_client = opa_client
        self.consensus_engine = consensus_engine
        self._invariants: list[InvariantModel] = []

    def registered_tier_names(self) -> list[str]:
        return [t.tier_name for t in sorted(self._domain_tiers, key=lambda x: (x.phase, x.order, x.tier_name))]
        
    def register_invariant(self, invariant: InvariantModel) -> None:
        self._invariants.append(invariant)

    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_validate")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": action, "params": params}))
            
            _check_policy_pin(policy_version_id)

            t0 = time.perf_counter()
            ctx = StageContext(action=action, params=params, profile=Profile.FULL)
            result = await run_pipeline(self.stages, ctx, profile=Profile.FULL)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            span.set_attribute("cage.governance_latency_ms", latency_ms)

            if not result.violations:
                seal = await issue_seal(action, params, path="validate_action")
                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.ALLOW)
                span.set_status(Status(StatusCode.OK))
                return {
                    "verdict": GovernanceDecision.ALLOW,
                    "violations": [],
                    "seal": seal,
                    "latency_ms": latency_ms,
                    "agent_id": params.get("_caller_principal", ""),
                }

            violations = list(result.violations)
            classification = self._classifier.classify(
                ClassificationContext(
                    violations=violations,
                    confidence=_reported_confidence(params),
                    opa_decision=result.opa_verdict.value if result.opa_verdict else None,
                    policy_ambiguous=False,
                    params=params,
                ),
                action,
            )
            meta = {**_ftra_meta(result), **classification.metadata}
            span.set_attribute("cage.governance.classification_decision", classification.decision.value)
            span.set_attribute("cage.governance.classification_reason", str(meta.get("classification_reason", ""))[:200])

            # Unmapped decisions fall through to DENY (fail-closed).
            handler = _VERDICT_HANDLERS.get(classification.decision, handle_deny)
            verdict = handler(action, params, violations, list(result.tier_failures), meta, latency_ms)
            return await verdict if inspect.isawaitable(verdict) else verdict

    async def govern(self, tool_name: str, params: dict[str, Any]) -> str:
        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_evaluation")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params}))
            
            ctx = StageContext(action=tool_name, params=params, profile=Profile.FULL)
            result = await run_pipeline(self.stages, ctx, profile=Profile.FULL)
            
            if result.violations:
                classification_meta = {}
                if result.ftra:
                    classification_meta = {
                        "terminal_classification": result.ftra.classification,
                        "requires_hitl": result.ftra.requires_hitl,
                        "bypassed_ftra_node": result.ftra.bypassed_ftra_node,
                        "in_registry": result.ftra.terminal_match is not None,
                    }
                await handle_deny(tool_name, params, list(result.violations), list(result.tier_failures), classification_meta)
                
            seal = await issue_seal(tool_name, params, path="govern")
            span.set_attribute("cage.seal_issued", True)
            span.set_attribute(OBSERVATION_OUTPUT, "APPROVED")
            return seal
            
    async def revalidate_post_hitl(self, action: str, params: dict[str, Any], *, trace_id: str | None = None) -> str:
        with tracer.start_as_current_span("symbolic_governor.revalidate_post_hitl") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_revalidate_post_hitl")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": action, "params": params}))
            span.set_attribute("toctou.revalidation.scope", "cbf_opa_only")
            if trace_id is not None:
                span.set_attribute("toctou.revalidation.trace_id", trace_id)
                
            ctx = StageContext(action=action, params=params, profile=Profile.POST_HITL)
            result = await run_pipeline(self.stages, ctx, profile=Profile.POST_HITL)
            
            if result.violations:
                classification_meta = {}
                if result.ftra:
                    classification_meta = {
                        "terminal_classification": result.ftra.classification,
                        "requires_hitl": result.ftra.requires_hitl,
                        "bypassed_ftra_node": result.ftra.bypassed_ftra_node,
                        "in_registry": result.ftra.terminal_match is not None,
                    }
                await handle_deny(action, params, list(result.violations), list(result.tier_failures), classification_meta)
                
            seal = await issue_seal(action, params, path="revalidate_post_hitl")
            return seal
            
    async def verify(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_simulation")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params}))
            
            ctx = StageContext(action=tool_name, params=params, profile=Profile.DRY_RUN)
            result = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
            
            violations = list(result.violations)
            span.set_attribute(
                OBSERVATION_OUTPUT,
                json.dumps([{'tier': v.tier, 'code': v.code, 'message': v.message, 'kind': v.kind.value} for v in violations]) if violations else "APPROVED"
            )
            return {
                "violations": violations,
                "tier_failures": list(result.tier_failures),
                "opa_results": result.opa_verdict,
                "pending_payload": None,
                "stpa_violation_count": ctx.stpa_violation_count,
                "ftra_boundary_result": result.ftra,
                "tier_violations": violations,
            }

    async def _run_checks(self, tool_name: str, params: dict[str, Any], sim_mode: bool = False, policy_version_id: str | None = None) -> dict[str, Any]:
        """Legacy test compat."""
        return await self.verify(tool_name, params)

    def _build_standing(self, tier_violations: list[Violation]) -> dict[str, Any]:
        """Legacy helper for tests."""
        return {"failures": self._violations_to_failures(tier_violations)}

    def _violations_to_failures(self, violations: list[Violation]) -> list[dict[str, Any]]:
        """Legacy helper for tests."""
        return [
            {
                "tier": v.tier,
                "code": v.code,
                "message": v.message,
                "kind": v.kind.value,
            }
            for v in violations
        ]

    def _is_governed_action(self, action: str, params: dict[str, Any]) -> bool:
        """Legacy helper for tests."""
        return any(t.claims_action(action, params) for t in self.domain_tiers)


_VERDICT_HANDLERS = {
    GovernanceDecision.DENY: handle_deny,
    GovernanceDecision.REQUIRE_APPROVAL: handle_require_approval,
    GovernanceDecision.DEFER: handle_defer,
    GovernanceDecision.PAUSE: handle_pause,
    GovernanceDecision.NARROW: handle_narrow,
}


def _check_policy_pin(policy_version_id: str | None) -> None:
    """Reject a session pinned to a policy baseline that has since drifted."""
    if policy_version_id is None:
        return
    active_hash = ControlRegistry().active_hash
    if policy_version_id != active_hash:
        raise GovernanceError(
            f"Substrate Policy Drift Detected. Session pinned to version signature "
            f"'{policy_version_id}', but active runtime baseline has evolved to hash '{active_hash}'."
        )


def _reported_confidence(params: dict[str, Any]) -> float:
    """Agent self-reported confidence; unparseable values classify as 0.0.

    ConfidenceStage already emits a HARD violation for invalid values, so this
    only feeds classification and can never widen a verdict.
    """
    try:
        value = float(params.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) else 0.0


def _ftra_meta(result: Any) -> dict[str, Any]:
    if not result.ftra:
        return {}
    return {
        "terminal_classification": result.ftra.classification,
        "requires_hitl": result.ftra.requires_hitl,
        "bypassed_ftra_node": result.ftra.bypassed_ftra_node,
        "in_registry": result.ftra.terminal_match is not None,
    }
