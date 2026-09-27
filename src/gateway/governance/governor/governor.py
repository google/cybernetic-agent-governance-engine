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

"""The governor: runs every entry point through one staged pipeline.

A ``SymbolicGovernor`` is immutable. It is built once, from
:class:`~src.gateway.governance.governor.assembly.GovernorComponents`, by the
composition root :func:`~src.gateway.governance.governor.assembly.assemble_governor`.
Nothing installs tiers, invariants or engines on it after construction.
"""

from __future__ import annotations

import copy
import inspect
import json
import logging
import math
import time
from typing import TYPE_CHECKING, Any, NoReturn

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.governance.classification_engine import ClassificationContext
from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.pipeline import PipelineResult, Profile, Stage, StageContext, run_pipeline
from src.gateway.governance.governor.sealing import run_sealed
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.verdicts import (
    handle_defer,
    handle_deny,
    handle_narrow,
    handle_pause,
    handle_require_approval,
)
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_NAME,
    OBSERVATION_OUTPUT,
    OBSERVATION_TYPE,
)

if TYPE_CHECKING:
    from src.gateway.governance.governor.assembly import GovernorComponents

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class SymbolicGovernor:
    """Immutable governor over one set of assembled components."""

    __slots__ = ("_components", "_stages")

    def __init__(self, components: GovernorComponents) -> None:
        # order_stages rejects duplicate tier names and sorts by (phase, order).
        stages = (*components.core_stages, *order_stages(components.domain_tiers))
        object.__setattr__(self, "_components", components)
        object.__setattr__(self, "_stages", stages)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"SymbolicGovernor is immutable; cannot set {name!r}")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"SymbolicGovernor is immutable; cannot delete {name!r}")

    @property
    def components(self) -> GovernorComponents:
        return self._components

    @property
    def stages(self) -> tuple[Stage, ...]:
        return self._stages

    @property
    def domain_tiers(self) -> tuple[GovernanceTierPlugin, ...]:
        return tuple(sorted(self._components.domain_tiers, key=lambda t: (t.phase, t.order, t.tier_name)))

    def registered_tier_names(self) -> list[str]:
        return [t.tier_name for t in self.domain_tiers]

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
            result, seal = await run_sealed(self.stages, ctx, params, path="validate_action")
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            span.set_attribute("cage.governance_latency_ms", latency_ms)

            if seal is not None:
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
            classification = self._components.classifier.classify(
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

            if classification.decision == GovernanceDecision.NARROW:
                return await self._narrow(action, params, result, meta, t0)

            if classification.decision == GovernanceDecision.PAUSE:
                return await handle_pause(
                    action,
                    params,
                    violations,
                    list(result.tier_failures),
                    meta,
                    latency_ms,
                    standing_projector=self._components.standing_projector,
                )

            # Unmapped decisions fall through to DENY (fail-closed).
            handler = _VERDICT_HANDLERS.get(classification.decision, handle_deny)
            verdict = handler(action, params, violations, list(result.tier_failures), meta, latency_ms)
            return await verdict if inspect.isawaitable(verdict) else verdict

    async def _narrow(
        self, action: str, params: dict[str, Any], result: PipelineResult, meta: dict[str, Any], t0: float
    ) -> dict[str, Any]:
        """Seal a narrower's proposal only if the FULL profile passes on it.

        proof/model.py NARROW (c): the clamped params are re-verified in a new
        ReservationScope, so their commits back the seal (or are rolled back).
        The re-run is never classified, so the narrower runs once per request.
        """
        proposal = meta.get("narrowed_params")
        if not isinstance(proposal, dict):
            await _deny(action, params, result)
        verified = copy.deepcopy(proposal)  # the exact params that get sealed
        ctx = StageContext(action=action, params=copy.deepcopy(verified), profile=Profile.FULL)
        rerun, seal = await run_sealed(self.stages, ctx, verified, path="narrow")
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        trace.get_current_span().set_attribute("cage.governance.narrow_reverified", seal is not None)
        if seal is None:
            deny_meta = {**meta, **_ftra_meta(rerun), "classification_reason": "narrow_reverification_failed"}
            await handle_deny(action, verified, list(rerun.violations), list(rerun.tier_failures), deny_meta, latency_ms)
            raise GovernanceError(f"handle_deny returned without raising; refusing {action}")  # fail closed
        return handle_narrow(
            action, params, verified,
            seal=seal, violations=list(result.violations), classification_meta=meta, latency_ms=latency_ms,
        )

    async def govern(self, tool_name: str, params: dict[str, Any]) -> str:
        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_evaluation")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params}))

            ctx = StageContext(action=tool_name, params=params, profile=Profile.FULL)
            result, seal = await run_sealed(self.stages, ctx, params, path="govern")
            if seal is None:
                await _deny(tool_name, params, result)
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
            if not self._is_governed_action(action, params):
                # POST_HITL re-runs only claimed barriers; with none there is
                # nothing to re-verify, so the approval cannot be honoured.
                await handle_deny(action, params, [_UNGOVERNED_POST_HITL], [], {})
                raise GovernanceError(f"no tier governs {action}; post-HITL re-validation refused")
            ctx = StageContext(action=action, params=params, profile=Profile.POST_HITL)
            result, seal = await run_sealed(self.stages, ctx, params, path="revalidate_post_hitl")
            if seal is None:
                await _deny(action, params, result)
            return seal

    async def verify(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_simulation")
            span.set_attribute(OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params}))

            # DRY_RUN never commits, so no ReservationScope: run_pipeline refuses one.
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

    def _is_governed_action(self, action: str, params: dict[str, Any]) -> bool:
        """True if any domain tier claims ``action``."""
        return any(t.claims_action(action, params) for t in self.domain_tiers)


_UNGOVERNED_POST_HITL = Violation(
    tier="kernel", code="UNGOVERNED_POST_HITL", kind=ViolationKind.HARD,
    message="post-HITL re-validation requested for an action no domain tier claims",
)

_VERDICT_HANDLERS = {
    GovernanceDecision.DENY: handle_deny,
    GovernanceDecision.REQUIRE_APPROVAL: handle_require_approval,
    GovernanceDecision.DEFER: handle_defer,
    GovernanceDecision.PAUSE: handle_pause,
    # NARROW is not here: it is sealed only via SymbolicGovernor._narrow().
}


async def _deny(action: str, params: dict[str, Any], result: PipelineResult) -> NoReturn:
    await handle_deny(action, params, list(result.violations), list(result.tier_failures), _ftra_meta(result))
    raise GovernanceError(f"handle_deny returned without raising; refusing {action}")  # fail closed


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
