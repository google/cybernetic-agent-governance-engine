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
import logging
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, NoReturn

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.governance.classification_engine import (
    REASON_RELIANCE_INELIGIBLE,
    ClassificationContext,
    ClassificationOutcome,
    InfrastructureOutcome,
)
from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.contracts import (
    GovernanceTier,
    ServerInputUnavailableError,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.env_posture import is_enforcing
from src.gateway.governance.governance_envelope import envelope_action_hash
from src.gateway.governance.governor.approval import PostHitlApproval
from src.gateway.governance.governor.errors import (
    ApprovalSpendUnavailableError,
    DeferQueueUnavailableError,
    GovernanceDeferred,
    GovernanceError,
    GovernanceInfrastructureError,
)
from src.gateway.governance.governor.pipeline import (
    BarrierPreview,
    PipelineResult,
    Profile,
    Stage,
    StageContext,
    plan_pipeline,
    resolve_claims,
    run_pipeline,
)
from src.gateway.governance.governor.sealing import SealedAction, run_sealed
from src.gateway.governance.governor.server_inputs import (
    KERNEL_SERVER_INPUT_ACTIONS,
    KERNEL_SERVER_INPUT_KEYS,
    bind_server_inputs,
    inspect_prompt_injection_params,
    online_governance_scope,
    strip_untrusted_shadow_params,
    verified_post_hitl_approval,
)
from src.gateway.governance.governor.settlement import SettlementLedger, settle
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.trace import decision_trace_event, publish_trace
from src.gateway.governance.governor.verdicts import (
    handle_defer,
    handle_deny,
    handle_infrastructure_block,
    handle_narrow,
    handle_post_hitl_defer,
    handle_require_approval,
    publish_settlement,
    reported_confidence,
)
from src.gateway.governance.narrow_receipt import issue_narrow_receipt
from src.gateway.governance.warrant.reliance import (
    reliance_attestations,
    reliance_evidence,
)
from src.gateway.observability.attributes import (
    OBSERVATION_NAME,
    OBSERVATION_TYPE,
    SPAN_ATTR_GOVERNANCE_TOOL,
)
from src.gateway.server.workload_identity import current_client_identity

if TYPE_CHECKING:
    from src.gateway.governance.governor.assembly import GovernorComponents

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class SymbolicGovernor:
    """Immutable governor over one set of assembled components."""

    __slots__ = ("_components", "_settlements", "_stages")
    _components: GovernorComponents
    _stages: tuple[Stage, ...]
    _settlements: SettlementLedger

    def __init__(self, components: GovernorComponents) -> None:
        # order_stages rejects duplicate tier names and sorts by (phase, order);
        # jurisdiction tiers sort in with the domain's.
        stages = (*components.core_stages, *order_stages(components.plugin_tiers))
        object.__setattr__(self, "_components", components)
        object.__setattr__(self, "_stages", stages)
        # The ledger's binding is fixed; its entries are the per-seal commits
        # awaiting settle().  The governor's configuration stays immutable.
        object.__setattr__(self, "_settlements", SettlementLedger())

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
    def domain_tiers(self) -> tuple[GovernanceTier, ...]:
        return tuple(
            sorted(
                self._components.domain_tiers,
                key=lambda t: (t.phase, t.order, t.tier_name),
            )
        )

    @property
    def tiers(self) -> tuple[GovernanceTier, ...]:
        """Domain and jurisdiction tiers in pipeline order."""
        return tuple(
            sorted(
                self._components.plugin_tiers,
                key=lambda t: (t.phase, t.order, t.tier_name),
            )
        )

    def registered_tier_names(self) -> list[str]:
        return [t.tier_name for t in self.tiers]

    async def bind_server_inputs(
        self, action: str, params: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Resolve server-authoritative parameters for ``action`` before evaluation.

        Strips kernel-owned security keys (``approval_token``, ``semantic_score``,
        ``prompt_injection_verified``) and any domain ``ServerInputResolver``
        owned keys (e.g. ``trader_role``, ``trader_id``) from caller ``params``
        and stamps their server-verified values so advisory prechecks and
        committing runs evaluate identical authoritative inputs (F-100).
        """
        with online_governance_scope(True):
            return await bind_server_inputs(
                self._components.server_inputs, action, params
            )

    async def validate_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        """Decide ``action`` without committing anything or minting a seal.

        Runs the DRY_RUN profile: phase-2 (mutating) stages answer through
        their side-effect-free ``preview()``, so no barrier state moves and no
        ``ReservationScope`` exists. The verdict (ALLOW, NARROW candidate,
        REQUIRE_APPROVAL with a ``deferred_id``, DEFER, or DENY via
        ``GovernanceError``) only routes the caller. The single committing run
        is :meth:`govern` or, after approval, :meth:`revalidate_post_hitl`.

        The params are bound first (:func:`bind_server_inputs`): caller values
        for keys a domain resolves server-side are replaced, so the preview
        evaluates the same inputs as the committing run.
        """
        with online_governance_scope(True):
            return await self._evaluate_dry_run(
                action,
                params,
                policy_version_id,
                emit_side_effects=True,
            )

    async def preview_action(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        """Offline counterfactual DRY_RUN evaluation with no queue or evidence writes.

        Reserved strictly for non-enforcing postures (e.g. offline evaluation
        and trajectory replay). Refuses to run under ``STAGING`` or ``PRODUCTION``
        posture so an enforcing gateway can never route online decisions around
        ``DeferQueue`` parking or blocking refusal/deferral evidence.
        """
        if is_enforcing(self._components.posture):
            raise RuntimeError(
                "SymbolicGovernor.preview_action is forbidden in enforcing posture "
                f"({self._components.posture.value}); online validation must use "
                "validate_action() so deferrals and refusals commit to the evidence chain."
            )
        with online_governance_scope(False):
            return await self._evaluate_dry_run(
                action,
                params,
                policy_version_id,
                emit_side_effects=False,
            )

    def _server_input_unavailable_result(
        self,
        action: str,
        params: dict[str, Any],
        *,
        profile: Profile,
        exc: ServerInputUnavailableError,
    ) -> tuple[Violation, PipelineResult]:
        ctx = StageContext(action=action, params=params, profile=profile)
        _claims, is_governed, _ro, _mut, plan = plan_pipeline(
            self.stages, ctx, profile=profile
        )
        violation = Violation(
            tier=exc.dependency,
            code=exc.failure_code,
            message=str(exc),
            kind=ViolationKind.INFRASTRUCTURE,
            infra_dependency=exc.dependency,
            infra_error_code="server_input_unavailable",
        )
        result = PipelineResult(
            violations=(violation,),
            tier_failures=(),
            opa_verdict=None,
            ftra=None,
            committed_stages=(),
            plan=plan,
            stage_outcomes=(),
            governed=is_governed,
        )
        return violation, result

    async def _evaluate_dry_run(
        self,
        action: str,
        params: dict[str, Any],
        policy_version_id: str | None = None,
        *,
        emit_side_effects: bool = True,
    ) -> dict[str, Any]:
        try:
            params = await bind_server_inputs(
                self._components.server_inputs, action, params
            )
        except ServerInputUnavailableError as exc:
            _check_policy_pin(policy_version_id)
            violation, infra_result = self._server_input_unavailable_result(
                action, params, profile=Profile.DRY_RUN, exc=exc
            )
            if emit_side_effects:
                await _trace(
                    infra_result,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                )
            await handle_infrastructure_block(
                action,
                params,
                [violation],
                [],
                {"infra_error_code": exc.error_code},
                emit_side_effects=emit_side_effects,
            )
        # The audit binding of the params the stages evaluate (server inputs
        # bound) is attached to returned verdicts only (ALLOW, NARROW,
        # REQUIRE_APPROVAL, DEFER) after run_pipeline(); computing it ahead of
        # the stages would reject non-finite inputs (NaN/Inf) with
        # SealCanonicalizationError before the confidence stage can emit a
        # [CTRL_AGT_001] refusal receipt.
        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_validate")
            span.set_attribute(SPAN_ATTR_GOVERNANCE_TOOL, action)

            _check_policy_pin(policy_version_id)

            t0 = time.perf_counter()
            ctx = StageContext(action=action, params=params, profile=Profile.DRY_RUN)
            result = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            span.set_attribute("cage.governance_latency_ms", latency_ms)

            if not result.violations:
                if emit_side_effects:
                    await _trace(
                        result,
                        action,
                        Profile.DRY_RUN,
                        "validate_action",
                        GovernanceDecision.ALLOW,
                    )
                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                span.set_status(Status(StatusCode.OK))
                return {
                    "verdict": GovernanceDecision.ALLOW,
                    "violations": [],
                    "latency_ms": latency_ms,
                    "agent_id": current_client_identity() or "",
                    **_context_meta(result),
                    **_reliance_meta(result),
                    "evaluated_action_hash": envelope_action_hash(action, params),
                }

            violations = list(result.violations)
            classification = self._components.classifier.classify(
                ClassificationContext(
                    violations=violations,
                    confidence=reported_confidence(params),
                    opa_decision=result.opa_verdict.value
                    if result.opa_verdict
                    else None,
                    policy_ambiguous=False,
                    params=params,
                ),
                action,
            )
            meta = {
                **_ftra_meta(result),
                **_barrier_meta(result),
                **classification.metadata,
            }
            span.set_attribute(
                "cage.governance.classification_decision", classification.decision.value
            )
            span.set_attribute(
                "cage.governance.classification_reason",
                str(meta.get("classification_reason", ""))[:200],
            )

            if classification.decision == GovernanceDecision.NARROW:
                return {
                    **await self._narrow_candidate(
                        action,
                        params,
                        result,
                        meta,
                        t0,
                        emit_side_effects=emit_side_effects,
                    ),
                    "evaluated_action_hash": envelope_action_hash(action, params),
                }

            if classification.decision == GovernanceDecision.REQUIRE_APPROVAL:
                meta = await self._reverified_narrow_hint(
                    action, meta, emit_side_effects=emit_side_effects
                )

            # Unmapped decisions fall through to DENY (fail-closed).
            handler = _VERDICT_HANDLERS.get(classification.decision, handle_deny)
            if emit_side_effects:
                await _trace(
                    result,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    classification.decision
                    if classification.decision in _UNSEALED_CHECKING_OUTCOMES
                    else GovernanceDecision.DENY,
                )
            handler_kwargs: dict[str, Any] = {"reliance": result.reliance}
            if handler is handle_deny:
                handler_kwargs["evaluated_param_specs"] = (
                    self._components.evaluated_param_specs
                )
                handler_kwargs.update(_stage_coverage_kwargs(result))
            if not emit_side_effects:
                handler_kwargs["emit_side_effects"] = False
            verdict = handler(
                action,
                params,
                violations,
                list(result.tier_failures),
                meta,
                latency_ms,
                **handler_kwargs,
            )
            resolved = await verdict if inspect.isawaitable(verdict) else verdict
            return {
                **resolved,
                **_context_meta(result),
                "evaluated_action_hash": envelope_action_hash(action, params),
            }

    async def _rebind(self, action: str, proposal: dict[str, Any]) -> dict[str, Any]:
        """A narrower's proposal with its server inputs resolved afresh.

        A proposal copies the request's bound params and clamps some of them;
        any server input derived from a clamped value would otherwise describe
        the original request.
        """
        return await bind_server_inputs(
            self._components.server_inputs, action, copy.deepcopy(proposal)
        )

    async def _reverified_narrow_hint(
        self,
        action: str,
        meta: dict[str, Any],
        *,
        emit_side_effects: bool = True,
    ) -> dict[str, Any]:
        """Keep the classifier's ``narrow_hint`` only if DRY_RUN vouches for it.

        The hint tells the reviewer which clamped params would clear every
        barrier, leaving only the approval to give. It is kept iff a DRY_RUN
        over those params (phase 2 previewed, nothing reserved) reports only
        HITL findings; otherwise it is dropped, never shown. It authorises
        nothing: executing it is the committing run, after approval.
        """
        hint = meta.get("narrow_hint")
        if not isinstance(hint, dict):
            return meta
        without = {k: v for k, v in meta.items() if k != "narrow_hint"}
        proposal = hint.get("narrowed_params")
        if not isinstance(proposal, dict):
            return without
        # The exact params the response names, server inputs re-bound so the
        # derived values describe the clamped request, not the original one.
        try:
            verified = await self._rebind(action, proposal)
        except ServerInputUnavailableError as exc:
            violation, infra_result = self._server_input_unavailable_result(
                action, proposal, profile=Profile.DRY_RUN, exc=exc
            )
            if emit_side_effects:
                await _trace(
                    infra_result,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                    narrower_present=True,
                    clamped_params_valid=False,
                )
            await handle_infrastructure_block(
                action,
                proposal,
                [violation],
                [],
                {"infra_error_code": exc.error_code},
                emit_side_effects=emit_side_effects,
            )
        ctx = StageContext(
            action=action, params=copy.deepcopy(verified), profile=Profile.DRY_RUN
        )
        rerun = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
        if self._blocks_on_infrastructure(rerun):
            if emit_side_effects:
                await _trace(
                    rerun,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                    narrower_present=True,
                    clamped_params_valid=False,
                )
            await _block_infrastructure(
                action, verified, rerun, emit_side_effects=emit_side_effects
            )
        kept = all(v.kind == ViolationKind.HITL for v in rerun.violations)
        trace.get_current_span().set_attribute(
            "cage.governance.narrow_hint_reverified", kept
        )
        if not kept:
            return without
        return {**without, "narrow_hint": {**hint, "narrowed_params": verified}}

    async def _narrow_candidate(
        self,
        action: str,
        params: dict[str, Any],
        result: PipelineResult,
        meta: dict[str, Any],
        t0: float,
        *,
        emit_side_effects: bool = True,
    ) -> dict[str, Any]:
        """Offer a narrower's proposal only if the DRY_RUN profile passes on it.

        proof/model.py NARROW (c): the clamped params must pass every stage.
        The re-check previews phase-2 stages (nothing is reserved) and is never
        classified, so the narrower runs once per request. No seal is minted:
        executing the proposal is a separate committing run over it.
        """
        proposal = meta.get("narrowed_params")
        if not isinstance(proposal, dict):
            if emit_side_effects:
                await _trace(
                    result,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    GovernanceDecision.DENY,
                )
            await _deny(
                action,
                params,
                result,
                emit_side_effects=emit_side_effects,
                evaluated_param_specs=self._components.evaluated_param_specs,
            )
        try:
            verified = await self._rebind(
                action, proposal
            )  # the params the response names
        except ServerInputUnavailableError as exc:
            violation, _infra_result = self._server_input_unavailable_result(
                action, proposal, profile=Profile.DRY_RUN, exc=exc
            )
            if emit_side_effects:
                await _trace(
                    result,
                    action,
                    Profile.DRY_RUN,
                    "validate_action",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                    narrower_present=True,
                    clamped_params_valid=False,
                )
            await handle_infrastructure_block(
                action,
                proposal,
                [violation],
                [],
                {"infra_error_code": exc.error_code},
                emit_side_effects=emit_side_effects,
            )
        ctx = StageContext(
            action=action, params=copy.deepcopy(verified), profile=Profile.DRY_RUN
        )
        rerun = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        reverified = not rerun.violations
        rerun_infra = not reverified and self._blocks_on_infrastructure(rerun)
        if emit_side_effects:
            await _trace(
                result,
                action,
                Profile.DRY_RUN,
                "validate_action",
                GovernanceDecision.NARROW
                if reverified
                else (
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK
                    if rerun_infra
                    else GovernanceDecision.DENY
                ),
                narrower_present=True,
                clamped_params_valid=reverified,
            )
        trace.get_current_span().set_attribute(
            "cage.governance.narrow_reverified", reverified
        )
        if not reverified:
            extra_kwargs: dict[str, Any] = (
                {"emit_side_effects": False} if not emit_side_effects else {}
            )
            if rerun_infra:
                await _block_infrastructure(
                    action, verified, rerun, emit_side_effects=emit_side_effects
                )
            if self._defers_on_reliance(rerun):
                return {
                    **(
                        await handle_defer(
                            action,
                            verified,
                            list(rerun.violations),
                            list(rerun.tier_failures),
                            {**meta, **_ftra_meta(rerun), **_RELIANCE_DEFER_META},
                            latency_ms,
                            reliance=rerun.reliance,
                            **extra_kwargs,
                        )
                    ),
                    **_context_meta(rerun),
                }
            deny_meta = {
                **meta,
                **_ftra_meta(rerun),
                "classification_reason": "narrow_reverification_failed",
            }
            await handle_deny(
                action,
                verified,
                list(rerun.violations),
                list(rerun.tier_failures),
                deny_meta,
                latency_ms,
                reliance=rerun.reliance,
                evaluated_param_specs=self._components.evaluated_param_specs,
                **_stage_coverage_kwargs(rerun),
                **extra_kwargs,
            )
            raise GovernanceError(
                f"handle_deny returned without raising; refusing {action}"
            )  # fail closed
        # The envelope attests the warrants the *re-verified* params relied on.
        return {
            **handle_narrow(
                action,
                params,
                verified,
                violations=list(result.violations),
                classification_meta=meta,
                latency_ms=latency_ms,
            ),
            **_context_meta(rerun),
            **_reliance_meta(rerun),
        }

    async def govern(self, tool_name: str, params: dict[str, Any]) -> SealedAction:
        """The committing run: commit phase 2 and seal, or refuse.

        Returns a :class:`~.sealing.SealedAction`: the seal and the evaluated
        params it commits to. ``params`` is snapshotted on entry and the
        action's server inputs are bound into the snapshot exactly once. The
        result, the evaluated params, is what every stage evaluates, what the
        seal's ``action_hash`` and the ``GOVERNANCE_DECISION`` event commit
        to, what every refusal receipt and deferral snapshot names, and what
        the caller must verify the seal against and actuate. Caller values
        for server-owned keys never reach the seal or the evidence.

        When the run refuses with only NARROWABLE findings and a narrower
        proposes clamped params, the seal covers *those* params (server
        inputs re-bound) instead (see :meth:`_sealed_narrow`), a NARROW
        receipt names them, and the returned ``params`` are them. Any other
        refusal raises ``GovernanceError``.

        The snapshot keeps a concurrent holder of the caller's dict from
        changing a value during the evidence-commit await, so the seal can
        never name params no stage had evaluated (issue #379). The stages
        get their own deep copy of the evaluated params, as on the narrow
        path, so a stage cannot mutate what is sealed either. If a server
        input cannot be bound, no evaluated params exist: the
        infrastructure block names the snapshot.
        """
        with online_governance_scope(True):
            snapshot = copy.deepcopy(params)
            with tracer.start_as_current_span("symbolic_governor.govern") as span:
                span.set_attribute(OBSERVATION_TYPE, "span")
                span.set_attribute(OBSERVATION_NAME, "governance_evaluation")
                span.set_attribute(SPAN_ATTR_GOVERNANCE_TOOL, tool_name)

                try:
                    evaluated = await bind_server_inputs(
                        self._components.server_inputs, tool_name, snapshot
                    )
                except ServerInputUnavailableError as exc:
                    await self._block_unbound(
                        tool_name, snapshot, exc, profile=Profile.FULL, path="govern"
                    )
                ctx = StageContext(
                    action=tool_name,
                    params=copy.deepcopy(evaluated),
                    profile=Profile.FULL,
                )
                result, seal = await run_sealed(
                    self.stages,
                    ctx,
                    evaluated,
                    path="govern",
                    settlements=self._settlements,
                )
                if seal is None:
                    sealed = await self._sealed_narrow(tool_name, evaluated, result)
                else:
                    await _trace(
                        result,
                        tool_name,
                        Profile.FULL,
                        "govern",
                        GovernanceDecision.ALLOW,
                        seal=seal,
                    )
                    sealed = SealedAction(tool_name, seal, evaluated)
                span.set_attribute("cage.seal_issued", True)
                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                return sealed

    async def _block_unbound(
        self,
        action: str,
        snapshot: dict[str, Any],
        exc: ServerInputUnavailableError,
        *,
        profile: Profile,
        path: str,
        meta: Mapping[str, Any] | None = None,
    ) -> NoReturn:
        """Block a committing run whose server inputs could not be bound.

        No evaluated params exist, so the ``INFRASTRUCTURE_BLOCK`` record
        names the snapshot of the caller's params. Nothing was evaluated,
        committed or sealed, and no approval is spent (POAM-2026-233).
        """
        violation, infra_result = self._server_input_unavailable_result(
            action, snapshot, profile=profile, exc=exc
        )
        await _trace(
            infra_result,
            action,
            profile,
            path,
            InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
        )
        await handle_infrastructure_block(
            action,
            snapshot,
            [violation],
            [],
            {**(meta or {}), "infra_error_code": exc.error_code},
        )
        raise GovernanceInfrastructureError(
            f"handle_infrastructure_block returned without raising; blocking {action}",
            dependency=exc.dependency,
            failure_code=exc.failure_code,
            error_code=exc.error_code,
        )  # fail closed

    async def _sealed_narrow(
        self, action: str, params: dict[str, Any], result: PipelineResult
    ) -> SealedAction:
        """Seal a narrower's proposal in the committing path, or deny.

        proof/model.py NARROW: (a) every violation NARROWABLE and (b) a
        narrower proposal — both decided by the classifier — and (c) the
        clamped params pass a fresh FULL run, which commits and seals them.
        The re-run is never classified, so the narrower runs once. The NARROW
        receipt is stored inside that run's ``ReservationScope``: if it
        cannot be stored, the commits are rolled back and the request denied.

        ``params`` are the original run's evaluated params: the
        classification and every refusal of the original run name them.
        Returns the :class:`~.sealing.SealedAction` naming the clamped params
        with their server inputs re-bound, which the re-run evaluated and the
        seal commits to.
        """
        if self._blocks_on_infrastructure(result):
            await _trace(
                result,
                action,
                Profile.FULL,
                "govern",
                InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
            )
            await _block_infrastructure(action, params, result)
        if self._defers_on_reliance(result):
            # A warrant failure removes reliance on the norm; it never becomes
            # a DENY of its own (proof/model.py verdict_of). An independent
            # HARD finding still denies: the classifier ranks HARD first.
            await _trace(
                result, action, Profile.FULL, "govern", GovernanceDecision.DEFER
            )
            await _defer_commit(action, params, result)
        classification = self._components.classifier.classify(
            ClassificationContext(
                violations=list(result.violations),
                confidence=reported_confidence(params),
                opa_decision=result.opa_verdict.value if result.opa_verdict else None,
                policy_ambiguous=False,
                params=params,
            ),
            action,
        )
        proposal = classification.metadata.get("narrowed_params")
        if classification.decision != GovernanceDecision.NARROW or not isinstance(
            proposal, dict
        ):
            await _trace(
                result, action, Profile.FULL, "govern", GovernanceDecision.DENY
            )
            await _deny(
                action,
                params,
                result,
                evaluated_param_specs=self._components.evaluated_param_specs,
            )
        # The exact params the seal and receipt name, server inputs re-bound.
        try:
            narrowed = await self._rebind(action, proposal)
        except ServerInputUnavailableError as exc:
            violation, _infra_result = self._server_input_unavailable_result(
                action, proposal, profile=Profile.FULL, exc=exc
            )
            await _trace(
                result,
                action,
                Profile.FULL,
                "govern_narrow",
                InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                narrower_present=True,
                clamped_params_valid=False,
            )
            await handle_infrastructure_block(
                action,
                proposal,
                [violation],
                [],
                {"infra_error_code": exc.error_code},
            )

        async def _deliver(seal: str) -> None:
            await issue_narrow_receipt(
                seal,
                narrowed,
                constraints_applied=classification.metadata.get(
                    "constraints_applied", []
                ),
                narrowing_reason=str(
                    classification.metadata.get("narrowing_reason", "")
                ),
            )

        ctx = StageContext(
            action=action, params=copy.deepcopy(narrowed), profile=Profile.FULL
        )
        rerun, seal = await run_sealed(
            self.stages,
            ctx,
            narrowed,
            path="govern_narrow",
            settlements=self._settlements,
            on_seal=_deliver,
            original_result=result,
        )
        span = trace.get_current_span()
        span.set_attribute("cage.governance.narrow_reverified", seal is not None)
        rerun_infra = seal is None and self._blocks_on_infrastructure(rerun)
        # The model's NARROW state records where the *original* run failed.
        await _trace(
            result,
            action,
            Profile.FULL,
            "govern_narrow",
            GovernanceDecision.NARROW
            if seal is not None
            else (
                InfrastructureOutcome.INFRASTRUCTURE_BLOCK
                if rerun_infra
                else GovernanceDecision.DENY
            ),
            seal=seal,
            narrower_present=True,
            clamped_params_valid=seal is not None,
        )
        if seal is None:
            if rerun_infra:
                await _block_infrastructure(action, narrowed, rerun)
            if self._defers_on_reliance(rerun):
                await _defer_commit(action, narrowed, rerun)
            await handle_deny(
                action,
                narrowed,
                list(rerun.violations),
                list(rerun.tier_failures),
                {
                    **_ftra_meta(rerun),
                    "classification_reason": "narrow_reverification_failed",
                },
                reliance=rerun.reliance,
                evaluated_param_specs=self._components.evaluated_param_specs,
                **_stage_coverage_kwargs(rerun),
            )
            raise GovernanceError(
                f"handle_deny returned without raising; refusing {action}"
            )  # fail closed
        span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
        return SealedAction(action, seal, narrowed)

    async def revalidate_post_hitl(
        self,
        action: str,
        params: dict[str, Any],
        *,
        approval: PostHitlApproval,
    ) -> SealedAction:
        """The post-approval committing run: POST_HITL commit + seal, or not.

        ``approval`` is the verified, unspent human approval
        (:class:`~.approval.PostHitlApproval`). ``params`` is snapshotted and
        the action's server inputs (e.g. quote staleness, drawdown, portfolio
        NAV, the trader's role) are bound into the snapshot exactly once,
        afresh, under the verified approval, so no telemetry goes stale
        across the human review window. The result, the evaluated params, is
        what every stage evaluates, what the seal and every refusal or
        deferral record name, what the approval's coverage is checked
        against, and what the returned :class:`~.sealing.SealedAction`
        carries. If a server input cannot be bound, no evaluated params
        exist and the records name the snapshot.

        An approval is consumed only by a run that seals exactly the params
        it covers. Coverage is evaluated against the evaluated (sealed)
        params, before any stage runs (``approval.covers``) and again inside
        the compare-and-swap that consumes the approval (``approval.spend``).
        There is no second server-input lookup. A refused run burns the
        approval through the same coverage-checked ``spend`` (DENY below), so
        only an approval that covers its evaluated params; it never seals.

        The run decides first and spends second:

        * **NOT COVERED** — the approval does not cover the evaluated params
          (the request, or a server-bound input such as the trader's role,
          differs from what was approved). The run is refused
          ``[APPROVAL_NOT_REDEEMABLE]`` before any stage runs; nothing is
          committed or sealed, and the approval is **not** spent.
        * **ALLOW** — the run is clean; ``approval.spend(evaluated)`` consumes
          the approval atomically inside the run's ``ReservationScope``,
          before the seal is minted. If it was already spent (a replay or a
          concurrent redemption won) or no longer covers the evaluated
          params, the run is refused ``[APPROVAL_NOT_REDEEMABLE]``, nothing
          is sealed and every commit rolls back: at most one redemption seals.
        * **DEFER** — the only findings are ``RELIANCE_INELIGIBLE`` (a
          warranted norm lost its warrant while the human decided). Nothing
          is sealed or committed, and the approval is **not** spent: the
          deferral is hash-chained naming it, and
          :class:`~.errors.GovernanceDeferred` is raised. The same approval
          redeems once the warrant is eligible again (POAM-2026-104).
        * **INFRASTRUCTURE_BLOCK** — an authority (or a server-input source)
          is unreachable or returns an undecodable reply without any HARD
          policy breach. Nothing is sealed or committed, and the approval is
          **not** spent (POAM-2026-233).
        * **DENY** — any other finding. The approval is spent (it covers the
          evaluated params), then the run is refused, so the operator must
          approve a fresh request.

        The approval covers only the context it was given against
        (``approval.barrier_preview``, bound into every ``ApprovalRecord`` by
        ``DeferQueue.approve``): if the reviewer was told the barriers would
        PASS and the committing run's barriers now refuse, the refusal is
        ``[APPROVAL_CONTEXT_DRIFT]``. An unrecognised snapshot is refused
        before anything runs. An approval given against ``FAIL`` (e.g. of a
        ``narrow_hint``'s clamped params) is honoured only if the barriers
        now admit the executed params.

        The same holds for human-review holds. POST_HITL re-runs OPA, the
        warrant gate and every read-only stage whose verdict can change while
        a human decides (``revalidated_after_approval``). A HITL hold any of
        them reports, OPA's ``MANUAL_REVIEW`` included, is answered only if
        the approval was given against it (``approval.approved_holds``). A
        hold the reviewer was never shown is refused
        ``[APPROVAL_CONTEXT_DRIFT]``, and a HARD finding (an authority that
        now refuses, or is unreachable) denies.
        """
        snapshot = copy.deepcopy(params)
        bound: dict[str, Any] | ServerInputUnavailableError
        with (
            online_governance_scope(True),
            verified_post_hitl_approval(approval.approval_id),
        ):
            try:
                bound = await bind_server_inputs(
                    self._components.server_inputs, action, snapshot
                )
            except ServerInputUnavailableError as exc:
                bound = exc
        # What the refusals ahead of the binding check name: the evaluated
        # params, or the snapshot when no evaluated params exist.
        named = snapshot if isinstance(bound, ServerInputUnavailableError) else bound
        with tracer.start_as_current_span(
            "symbolic_governor.revalidate_post_hitl"
        ) as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_revalidate_post_hitl")
            span.set_attribute(SPAN_ATTR_GOVERNANCE_TOOL, action)
            span.set_attribute(
                "toctou.revalidation.scope", "opa+warrant+revalidated+phase2"
            )
            span.set_attribute(
                "toctou.server_inputs_rebound",
                not isinstance(bound, ServerInputUnavailableError),
            )
            span.set_attribute("toctou.approval_id", approval.approval_id)
            span.set_attribute(
                "toctou.approved_holds",
                sorted(f"{tier}/{code}" for tier, code in approval.approved_holds),
            )
            try:
                approved = _parse_barrier_snapshot(approval.barrier_preview)
            except ValueError:
                await _spend_refused(approval, named)
                await handle_deny(
                    action,
                    named,
                    [
                        _approval_drift(
                            f"unrecognised approval snapshot {approval.barrier_preview!r}"
                        )
                    ],
                    [],
                    {"approved_barrier_preview": str(approval.barrier_preview)},
                    evaluated_param_specs=self._components.evaluated_param_specs,
                    evaluated_stages=(),
                    skipped_stages=tuple(s.name for s in self.stages),
                )
                raise GovernanceError(
                    f"handle_deny returned without raising; refusing {action}"
                )  # fail closed
            span.set_attribute(
                "toctou.approved_barrier_preview", approved.value if approved else ""
            )
            if not self._is_governed_action(action, named):
                # POST_HITL re-runs only claimed barriers; with none there is
                # nothing to re-verify, so the approval cannot be honoured.
                await _spend_refused(approval, named)
                await handle_deny(
                    action,
                    named,
                    [_UNGOVERNED_POST_HITL],
                    [],
                    {},
                    evaluated_param_specs=self._components.evaluated_param_specs,
                    evaluated_stages=(),
                    skipped_stages=tuple(s.name for s in self.stages),
                )
                raise GovernanceError(
                    f"no tier governs {action}; post-HITL re-validation refused"
                )
            if isinstance(bound, ServerInputUnavailableError):
                span.set_attribute("toctou.approval_spent", False)
                await self._block_unbound(
                    action,
                    snapshot,
                    bound,
                    profile=Profile.POST_HITL,
                    path="revalidate_post_hitl",
                    meta={"approval_id": approval.approval_id},
                )
            evaluated = bound
            if not _approval_covers(approval, evaluated):
                # The approval did not authorise these evaluated params; it
                # stays unspent and nothing runs.
                span.set_attribute("toctou.approval_covers", False)
                span.set_attribute("toctou.approval_spent", False)
                await handle_deny(
                    action,
                    evaluated,
                    [_approval_not_covering(approval.approval_id)],
                    [],
                    {"approval_id": approval.approval_id},
                    evaluated_param_specs=self._components.evaluated_param_specs,
                    evaluated_stages=(),
                    skipped_stages=tuple(s.name for s in self.stages),
                )
                raise GovernanceError(
                    f"handle_deny returned without raising; refusing {action}"
                )  # fail closed
            span.set_attribute("toctou.approval_covers", True)
            ctx = StageContext(
                action=action,
                params=copy.deepcopy(evaluated),
                profile=Profile.POST_HITL,
                approved_holds=approval.approved_holds,
            )

            async def _admit() -> bool:
                # Spent only iff the approval covers exactly the params sealed.
                return await approval.spend(copy.deepcopy(evaluated))

            # The approval is spent only by the run it authorises: admit()
            # runs after every stage passed and before the seal is minted.
            try:
                result, seal = await run_sealed(
                    self.stages,
                    ctx,
                    evaluated,
                    path="revalidate_post_hitl",
                    settlements=self._settlements,
                    admit=_admit,
                )
            except ApprovalSpendUnavailableError as exc:
                span.set_attribute("toctou.approval_spent", False)
                trace_result = exc.pipeline_result
                if not isinstance(trace_result, PipelineResult):
                    _c, is_gov, _ro, _mut, plan = plan_pipeline(
                        self.stages, ctx, profile=Profile.POST_HITL
                    )
                    trace_result = PipelineResult(
                        violations=(),
                        tier_failures=(),
                        opa_verdict=None,
                        ftra=None,
                        committed_stages=(),
                        plan=plan,
                        stage_outcomes=(),
                        governed=is_gov,
                    )
                await _trace(
                    trace_result,
                    action,
                    Profile.POST_HITL,
                    "revalidate_post_hitl",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                )
                await handle_infrastructure_block(
                    action,
                    evaluated,
                    [
                        Violation(
                            tier="defer_queue",
                            code="DEFER_QUEUE_UNAVAILABLE",
                            message=str(exc),
                            kind=ViolationKind.INFRASTRUCTURE,
                            infra_dependency="defer_queue",
                            infra_error_code="defer_queue_unavailable",
                        )
                    ],
                    [],
                    {"approval_id": approval.approval_id},
                )
            except GovernanceInfrastructureError as exc:
                if isinstance(exc.__cause__, ApprovalSpendUnavailableError):
                    span.set_attribute("toctou.approval_spent", False)
                    cause_exc = exc.__cause__
                    trace_result = cause_exc.pipeline_result
                    if isinstance(trace_result, PipelineResult):
                        await _trace(
                            trace_result,
                            action,
                            Profile.POST_HITL,
                            "revalidate_post_hitl",
                            InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                        )
                    await handle_infrastructure_block(
                        action,
                        evaluated,
                        [
                            Violation(
                                tier="defer_queue",
                                code="DEFER_QUEUE_UNAVAILABLE",
                                message=f"{cause_exc}; {exc}",
                                kind=ViolationKind.INFRASTRUCTURE,
                                infra_dependency="defer_queue",
                                infra_error_code="defer_queue_unavailable",
                            )
                        ],
                        [],
                        {"approval_id": approval.approval_id},
                    )
                raise
            if result.barrier_outcome is not None:
                span.set_attribute(
                    "toctou.barrier_outcome", result.barrier_outcome.value
                )
            if seal is not None:
                span.set_attribute("toctou.approval_spent", True)
                await _trace(
                    result,
                    action,
                    Profile.POST_HITL,
                    "revalidate_post_hitl",
                    GovernanceDecision.ALLOW,
                    seal=seal,
                )
                return SealedAction(action, seal, evaluated)
            if not result.violations:
                # Clean, but the approval could not be spent: replayed, lost a
                # concurrent redemption, expired or no longer covering.
                span.set_attribute("toctou.approval_spent", False)
                await _trace(
                    result,
                    action,
                    Profile.POST_HITL,
                    "revalidate_post_hitl",
                    GovernanceDecision.DENY,
                )
                await handle_deny(
                    action,
                    evaluated,
                    [_approval_not_redeemable(approval.approval_id)],
                    [],
                    {"approval_id": approval.approval_id},
                    reliance=result.reliance,
                    evaluated_param_specs=self._components.evaluated_param_specs,
                    **_stage_coverage_kwargs(result),
                )
                raise GovernanceError(
                    f"handle_deny returned without raising; refusing {action}"
                )  # fail closed
            # Neither an infrastructure outage (POAM-2026-233, Consumer 11) nor
            # an unavailable warrant freshness source is a policy refusal:
            # preserve the human approval unspent so the caller can retry once
            # the dependency or warrant source recovers.
            if self._blocks_on_infrastructure(result):
                span.set_attribute("toctou.approval_spent", False)
                await _trace(
                    result,
                    action,
                    Profile.POST_HITL,
                    "revalidate_post_hitl",
                    InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
                )
                await _block_infrastructure(action, evaluated, result)
            if self._defers_on_reliance(result):
                span.set_attribute("toctou.approval_spent", False)
                await _trace(
                    result,
                    action,
                    Profile.POST_HITL,
                    "revalidate_post_hitl",
                    GovernanceDecision.DEFER,
                )
                await handle_post_hitl_defer(
                    action,
                    evaluated,
                    list(result.violations),
                    dict(_RELIANCE_DEFER_META),
                    approval_id=approval.approval_id,
                    thread_id=approval.thread_id,
                    barrier_preview=approval.barrier_preview,
                    reliance=result.reliance,
                )
            await _spend_refused(approval, evaluated)
            span.set_attribute("toctou.approval_spent", True)
            await _trace(
                result,
                action,
                Profile.POST_HITL,
                "revalidate_post_hitl",
                GovernanceDecision.DENY,
            )
            if (
                approved == BarrierPreview.PASS
                and result.barrier_outcome == BarrierPreview.FAIL
            ):
                await _deny_drift(
                    action,
                    evaluated,
                    result,
                    approved,
                    evaluated_param_specs=self._components.evaluated_param_specs,
                )
            if unapproved := _unapproved_holds(result):
                await _deny_unapproved_holds(
                    action,
                    evaluated,
                    result,
                    unapproved,
                    evaluated_param_specs=self._components.evaluated_param_specs,
                )
            await _deny(
                action,
                evaluated,
                result,
                evaluated_param_specs=self._components.evaluated_param_specs,
            )

    def _blocks_on_infrastructure(self, result: PipelineResult) -> bool:
        """True iff the run's findings block fail-closed on dependency unavailability."""
        return self._components.classifier.blocks_on_infrastructure(result.violations)

    def _defers_on_reliance(self, result: PipelineResult) -> bool:
        """True iff the run's findings defer on an ineligible warrant.

        Asks the classifier's side-effect-free
        :meth:`~src.gateway.governance.classification_engine.ClassificationEngine.defers_on_reliance`
        (no narrower runs), so every committing path agrees with
        :meth:`validate_action`'s classification: ``RELIANCE_INELIGIBLE``
        without a HARD finding is a DEFER; a HARD finding still denies.
        """
        return self._components.classifier.defers_on_reliance(result.violations)

    def held_receipt(self, seal: str, tier: str) -> Any | None:
        """Return the held ``CommitReceipt.token`` for ``tier`` behind ``seal`` before settlement."""
        for held in self._settlements.peek(seal):
            if held.stage.name == tier:
                return held.receipt.token
        return None

    async def settle(self, seal: str, *, executed: bool) -> list[Violation]:
        """Settle the phase-2 commits behind ``seal`` after the sealed action.

        Call once the action has run (``executed=True``: every mutating tier
        confirms its reservation) or definitively has not (``executed=False``:
        every reservation is released, last in first out).  Returns one HARD
        ``CONFIRM_FAILED`` / ``ROLLBACK_FAILED`` violation per failed hook;
        those need manual reconciliation.

        Idempotent: a seal with no held commits (none were made, it was
        already settled, or it outlived the ledger's hold window) settles to
        ``[]``.  A seal that is never settled is left to each tier's own
        expiry; see :mod:`.settlement`.
        """
        with tracer.start_as_current_span("symbolic_governor.settle") as span:
            commits = self._settlements.take(seal)
            span.set_attribute("cage.settlement.executed", executed)
            span.set_attribute("cage.settlement.commit_count", len(commits))
            failures = await settle(commits, executed=executed)
            span.set_attribute("cage.settlement.failure_count", len(failures))
            if commits or failures:
                await publish_settlement(
                    seal=seal,
                    executed=executed,
                    commits=commits,
                    failures=failures,
                )
            if failures:
                span.set_status(Status(StatusCode.ERROR, "settlement failed"))
                logger.critical(
                    "settlement (executed=%s) failed for %s; manual reconciliation required",
                    executed,
                    ", ".join(v.tier for v in failures),
                )
            return failures

    async def verify(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dry-run the pipeline and classify it; commit, park and seal nothing.

        ``decision`` is ``ALLOW`` iff there are no violations, otherwise the
        classifier's decision over them. Unlike :meth:`validate_action` no
        NARROW proposal is re-verified and no approval token is parked.
        Params are bound as in :meth:`validate_action`.
        """
        try:
            params = await bind_server_inputs(
                self._components.server_inputs, tool_name, params
            )
        except ServerInputUnavailableError as exc:
            with tracer.start_as_current_span("symbolic_governor.verify") as span:
                span.set_attribute(OBSERVATION_TYPE, "span")
                span.set_attribute(OBSERVATION_NAME, "governance_simulation")
                span.set_attribute(SPAN_ATTR_GOVERNANCE_TOOL, tool_name)
                violation = Violation(
                    tier=exc.dependency,
                    code=exc.failure_code,
                    message=str(exc),
                    kind=ViolationKind.INFRASTRUCTURE,
                )
                infra_decision = InfrastructureOutcome.INFRASTRUCTURE_BLOCK
                span.set_attribute("cage.verdict", infra_decision.value)
                span.set_attribute(
                    "cage.governance.violation_codes",
                    [f"{violation.tier}/{violation.code}"],
                )
                return {
                    "decision": infra_decision,
                    "violations": [violation],
                    "tier_failures": [],
                    "opa_results": None,
                    "pending_payload": None,
                    "ftra_boundary_result": None,
                    "tier_violations": [violation],
                }
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_simulation")
            span.set_attribute(SPAN_ATTR_GOVERNANCE_TOOL, tool_name)

            # DRY_RUN never commits, so no ReservationScope: run_pipeline refuses one.
            ctx = StageContext(action=tool_name, params=params, profile=Profile.DRY_RUN)
            result = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)

            violations = list(result.violations)
            decision: GovernanceDecision | InfrastructureOutcome = (
                GovernanceDecision.ALLOW
            )
            if violations:
                decision = self._components.classifier.classify(
                    ClassificationContext(
                        violations=violations,
                        confidence=reported_confidence(params),
                        opa_decision=result.opa_verdict.value
                        if result.opa_verdict
                        else None,
                        policy_ambiguous=False,
                        params=params,
                    ),
                    tool_name,
                ).decision
            span.set_attribute("cage.verdict", decision.value)
            if violations:
                span.set_attribute(
                    "cage.governance.violation_codes",
                    [f"{v.tier}/{v.code}" for v in violations],
                )
            return {
                "decision": decision,
                "violations": violations,
                "tier_failures": list(result.tier_failures),
                "opa_results": result.opa_verdict,
                "pending_payload": None,
                "ftra_boundary_result": result.ftra,
                "tier_violations": violations,
            }

    def _is_governed_action(self, action: str, params: dict[str, Any]) -> bool:
        """True if any domain or jurisdiction stage claims ``action``.

        Delegates to :func:`resolve_claims` — the function ``run_pipeline``
        uses — so the two agree by construction.  A stage whose claim raises
        counts as claiming it (fail closed): the pipeline then records the
        raise as a HARD TIER_EXCEPTION.
        """
        ctx = StageContext(action=action, params=params, profile=Profile.POST_HITL)
        return resolve_claims(self.stages, ctx).governed


_UNGOVERNED_POST_HITL = Violation(
    tier="kernel",
    code="UNGOVERNED_POST_HITL",
    kind=ViolationKind.HARD,
    message="post-HITL re-validation requested for an action no domain tier claims",
)

APPROVAL_CONTEXT_DRIFT = "APPROVAL_CONTEXT_DRIFT"
APPROVAL_NOT_REDEEMABLE = "APPROVAL_NOT_REDEEMABLE"


def _approval_not_redeemable(approval_id: str) -> Violation:
    return Violation(
        tier="kernel",
        code=APPROVAL_NOT_REDEEMABLE,
        kind=ViolationKind.HARD,
        message=(
            f"[{APPROVAL_NOT_REDEEMABLE}] approval {approval_id!r} was already "
            "spent, expired or no longer covers the request; nothing was sealed"
        ),
    )


def _approval_not_covering(approval_id: str) -> Violation:
    return Violation(
        tier="kernel",
        code=APPROVAL_NOT_REDEEMABLE,
        kind=ViolationKind.HARD,
        message=(
            f"[{APPROVAL_NOT_REDEEMABLE}] approval {approval_id!r} does not cover "
            "the evaluated params (the request or a server-bound input differs "
            "from what was approved); nothing ran and the approval was not spent"
        ),
    )


def _approval_covers(approval: PostHitlApproval, evaluated: dict[str, Any]) -> bool:
    """``approval.covers`` over a copy of the evaluated params; an error is ``False``.

    The copy keeps a misbehaving matcher from changing the params the run
    evaluates and seals.
    """
    try:
        return bool(approval.covers(copy.deepcopy(evaluated)))
    except Exception as exc:  # a raising matcher never authorises
        logger.warning(
            "approval %s coverage check raised: %s", approval.approval_id, exc
        )
        return False


#: Classification metadata of a warrant-ineligible DEFER (``handle_defer``
#: maps it to ``DeferReason.WARRANT_INELIGIBLE``).
_RELIANCE_DEFER_META: dict[str, Any] = {
    "classification_reason": REASON_RELIANCE_INELIGIBLE,
    "deferrable": True,
}


async def _defer_commit(
    action: str, params: dict[str, Any], result: PipelineResult
) -> NoReturn:
    """DEFER a committing run on an ineligible warrant: park, evidence, raise.

    Nothing was sealed and the run's commits were rolled back. The request
    parks as a ``WARRANT_INELIGIBLE`` token with its reliance records, and
    the ``GOVERNANCE_DEFERRAL`` event is hash-chained (``handle_defer``,
    exactly as for a DEFER preview). No refusal receipt is issued.

    Raises:
        GovernanceDeferred: Always, naming the parked token.
    """
    verdict = await handle_defer(
        action,
        params,
        list(result.violations),
        list(result.tier_failures),
        {**_ftra_meta(result), **_RELIANCE_DEFER_META},
        reliance=result.reliance,
    )
    findings = [f"[{v.code}] {v.message}" for v in result.violations]
    parked_token = verdict.get("defer_token")
    if not isinstance(parked_token, str) or not parked_token:
        raise DeferQueueUnavailableError(
            f"[DEFER_PARK_FAILED] [{verdict['defer_reason']}] committing run "
            "deferral could not be persisted to DeferQueue: " + "; ".join(findings),
            defer_reason=str(verdict["defer_reason"]),
            violations=findings,
        )
    raise GovernanceDeferred(
        f"[{verdict['defer_reason']}] committing run deferred as "
        f"{parked_token!r}: " + "; ".join(findings),
        defer_reason=str(verdict["defer_reason"]),
        deferred_id=parked_token,
        reliance=list(verdict.get("reliance", [])),
        violations=findings,
    )


async def _spend_refused(approval: PostHitlApproval, params: dict[str, Any]) -> None:
    """Spend the approval of a run about to be refused (DENY burns it).

    ``params`` are the run's evaluated params (the snapshot only when the
    binding itself failed): the approval is consumed only if it covers them,
    since an approval that does not cover the refused request did not
    authorise it. Best effort: the run is refused either way, so a failed
    spend only leaves an approval that the committing run's own spend would
    still re-check before any seal.
    """
    try:
        if not await approval.spend(copy.deepcopy(params)):
            logger.info(
                "approval %s was already spent, or does not cover the request, "
                "when its run was refused",
                approval.approval_id,
            )
    except Exception as exc:  # the refusal stands regardless
        logger.error(
            "could not spend approval %s of a refused run: %s",
            approval.approval_id,
            exc,
        )


def _parse_barrier_snapshot(
    value: BarrierPreview | str | None,
) -> BarrierPreview | None:
    """The approval's barrier snapshot; ``ValueError`` if it is not PASS/FAIL/None."""
    return None if value is None else BarrierPreview(value)


def _approval_drift(detail: str, *, quarantine_trigger: Any = None) -> Violation:
    return Violation(
        tier="kernel",
        code=APPROVAL_CONTEXT_DRIFT,
        kind=ViolationKind.HARD,
        message=f"[{APPROVAL_CONTEXT_DRIFT}] {detail}",
        quarantine_trigger=quarantine_trigger,
    )


def _stage_coverage_kwargs(result: PipelineResult) -> dict[str, Any]:
    """Stage coverage kwargs for ``RefusalReceipt`` schema ``v5`` (POAM-2026-233)."""
    evaluated: list[tuple[str, str]] = []
    for stage_name, stage_outcome in result.stage_outcomes:
        if stage_outcome == "PASS":
            evaluated.append((stage_name, "PASS"))
        elif stage_name in result.infra_only_stages:
            evaluated.append((stage_name, "INFRASTRUCTURE"))
        else:
            evaluated.append((stage_name, stage_outcome))
    ran = {stage_name for stage_name, _ in evaluated}
    skipped = tuple(
        stage_name for stage_name, _phase in result.plan if stage_name not in ran
    )
    return {
        "evaluated_stages": tuple(evaluated),
        "skipped_stages": skipped,
    }


async def _deny_drift(
    action: str,
    params: dict[str, Any],
    result: PipelineResult,
    approved: BarrierPreview,
    *,
    evaluated_param_specs: Any = None,
) -> NoReturn:
    """Refuse a committing run whose barriers no longer match the approval.

    The drift violation leads (it decided the refusal); the barrier findings
    follow, so the receipt still names what now refuses.
    """
    cause = next(
        (v.message for v in result.violations if v.kind == ViolationKind.HARD),
        "phase-2 barriers refused",
    )
    cause_quarantine = next(
        (
            v.quarantine_trigger
            for v in result.violations
            if v.kind == ViolationKind.HARD and v.quarantine_trigger is not None
        ),
        None,
    )
    drift = _approval_drift(
        f"approved against barrier preview {approved.value}, but the committing "
        f"run's barriers now refuse: {cause}",
        quarantine_trigger=cause_quarantine,
    )
    await handle_deny(
        action,
        params,
        [drift, *result.violations],
        list(result.tier_failures),
        {
            **_ftra_meta(result),
            "classification_reason": "approval_context_drift",
            "approved_barrier_preview": approved.value,
            "barrier_outcome": BarrierPreview.FAIL.value,
        },
        reliance=result.reliance,
        evaluated_param_specs=evaluated_param_specs,
        **_stage_coverage_kwargs(result),
    )
    raise GovernanceError(
        f"handle_deny returned without raising; refusing {action}"
    )  # fail closed


def _unapproved_holds(result: PipelineResult) -> tuple[Violation, ...]:
    """The human-review holds a POST_HITL run reports that its approval did not answer.

    ``run_pipeline`` already answered every hold the approval was given
    against (``answered_by_approval``), so any HITL finding left is one the
    reviewer was never shown. Empty when a HARD finding is present: that
    finding decided the refusal on its own.
    """
    if any(v.kind == ViolationKind.HARD for v in result.violations):
        return ()
    return tuple(v for v in result.violations if v.kind == ViolationKind.HITL)


async def _deny_unapproved_holds(
    action: str,
    params: dict[str, Any],
    result: PipelineResult,
    holds: tuple[Violation, ...],
    *,
    evaluated_param_specs: Any = None,
) -> NoReturn:
    """Refuse a committing run that reports a hold its approval was not given against.

    The approval answered the holds the reviewer was shown; one that
    appeared while the request waited needs a fresh approval. The drift
    violation leads (it decided the refusal); the holds follow, so the
    receipt names what now asks for a human.
    """
    named = ", ".join(f"{v.tier}/{v.code}" for v in holds)
    drift = _approval_drift(
        f"the approval was not given against hold(s) {named}, which the "
        f"committing run now reports: {holds[0].message}; approve the request "
        "afresh"
    )
    await handle_deny(
        action,
        params,
        [drift, *result.violations],
        list(result.tier_failures),
        {
            **_ftra_meta(result),
            "classification_reason": "approval_context_drift",
            "unapproved_holds": [f"{v.tier}/{v.code}" for v in holds],
        },
        reliance=result.reliance,
        evaluated_param_specs=evaluated_param_specs,
        **_stage_coverage_kwargs(result),
    )
    raise GovernanceError(
        f"handle_deny returned without raising; refusing {action}"
    )  # fail closed


#: Decisions/outcomes that do not transition to REFUSED (model phase CHECKING).
_PENDING_DECISIONS = frozenset(
    {GovernanceDecision.REQUIRE_APPROVAL, GovernanceDecision.DEFER}
)
_UNSEALED_CHECKING_OUTCOMES: frozenset[ClassificationOutcome] = frozenset(
    {
        GovernanceDecision.REQUIRE_APPROVAL,
        GovernanceDecision.DEFER,
        InfrastructureOutcome.INFRASTRUCTURE_BLOCK,
    }
)


async def _trace(
    result: PipelineResult,
    action: str,
    profile: Profile,
    path: str,
    verdict: ClassificationOutcome,
    *,
    seal: str | None = None,
    narrower_present: bool = False,
    clamped_params_valid: bool = False,
) -> None:
    """Publish this decision's ``GOVERNANCE_TRACE`` event (best effort)."""
    await publish_trace(
        decision_trace_event(
            result,
            action=action,
            profile=profile,
            path=path,
            verdict=verdict.value,
            seal=seal,
            narrower_present=narrower_present,
            clamped_params_valid=clamped_params_valid,
        )
    )


_VERDICT_HANDLERS: dict[ClassificationOutcome, Callable[..., Any]] = {
    GovernanceDecision.DENY: handle_deny,
    InfrastructureOutcome.INFRASTRUCTURE_BLOCK: handle_infrastructure_block,
    GovernanceDecision.REQUIRE_APPROVAL: handle_require_approval,
    GovernanceDecision.DEFER: handle_defer,
    # NARROW is not here: SymbolicGovernor._narrow_candidate() re-verifies it.
}


async def _block_infrastructure(
    action: str,
    params: dict[str, Any],
    result: PipelineResult,
    *,
    emit_side_effects: bool = True,
) -> NoReturn:
    await handle_infrastructure_block(
        action,
        params,
        list(result.violations),
        list(result.tier_failures),
        _ftra_meta(result),
        reliance=result.reliance,
        emit_side_effects=emit_side_effects,
    )
    raise GovernanceInfrastructureError(
        f"handle_infrastructure_block returned without raising; blocking {action}",
        dependency="governance",
        failure_code="INFRASTRUCTURE_UNAVAILABLE",
    )  # fail closed


async def _deny(
    action: str,
    params: dict[str, Any],
    result: PipelineResult,
    *,
    emit_side_effects: bool = True,
    evaluated_param_specs: Any = None,
) -> NoReturn:
    deny_kwargs: dict[str, Any] = {
        "reliance": result.reliance,
        "evaluated_param_specs": evaluated_param_specs,
        **_stage_coverage_kwargs(result),
    }
    if not emit_side_effects:
        deny_kwargs["emit_side_effects"] = False
    await handle_deny(
        action,
        params,
        list(result.violations),
        list(result.tier_failures),
        _ftra_meta(result),
        **deny_kwargs,
    )
    raise GovernanceError(
        f"handle_deny returned without raising; refusing {action}"
    )  # fail closed


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


def _ftra_meta(result: Any) -> dict[str, Any]:
    if not result.ftra:
        return {}
    return {
        "terminal_classification": result.ftra.classification,
        "requires_hitl": result.ftra.requires_hitl,
        "bypassed_ftra_node": result.ftra.bypassed_ftra_node,
        "in_registry": result.ftra.terminal_match is not None,
        "ftra_registry_state": (
            result.ftra.registry_state.value if result.ftra.registry_state else None
        ),
        "ftra_auto_cleared": result.ftra.auto_cleared,
    }


def _reliance_meta(result: PipelineResult) -> dict[str, Any]:
    """Warrant evidence for an admissible (ALLOW / NARROW) response.

    ``reliance`` is the evidence form of every warranted norm the run relied
    on; ``external_attestations`` the matching ``WARRANT`` attestations
    (always ``UNVERIFIED``) that the gateway signs into the governance
    envelope. Both are absent when no warranted norm governs the action.
    """
    if not result.reliance:
        return {}
    return {
        "reliance": reliance_evidence(result.reliance),
        "external_attestations": reliance_attestations(result.reliance),
    }


def _barrier_meta(result: PipelineResult) -> dict[str, Any]:
    """What the phase-2 preview said, for the reviewer (absent if none ran).

    ``barrier_preview`` is ``PASS`` or ``FAIL``; on ``FAIL`` the breaches an
    approved request would hit are listed (e.g. "would breach daily cap").
    """
    if result.barrier_preview is None:
        return {}
    return {
        "barrier_preview": result.barrier_preview.value,
        "barrier_preview_violations": [v.to_dict() for v in result.preview_violations],
    }


def _context_meta(result: PipelineResult) -> dict[str, Any]:
    """Stage outcomes for the governance envelope context."""
    return {
        "tiers_passed": [
            name for name, outcome in result.stage_outcomes if outcome == "PASS"
        ],
    }
