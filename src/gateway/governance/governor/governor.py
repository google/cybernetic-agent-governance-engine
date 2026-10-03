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
import time
from typing import TYPE_CHECKING, Any, NoReturn

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from src.gateway.governance.classification_engine import ClassificationContext
from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.contracts import (
    GovernanceTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.pipeline import (
    BarrierPreview,
    PipelineResult,
    Profile,
    Stage,
    StageContext,
    run_pipeline,
)
from src.gateway.governance.governor.sealing import run_sealed
from src.gateway.governance.governor.settlement import SettlementLedger, settle
from src.gateway.governance.governor.stages.domain_tiers import order_stages
from src.gateway.governance.governor.trace import decision_trace_event, publish_trace
from src.gateway.governance.governor.verdicts import (
    handle_defer,
    handle_deny,
    handle_narrow,
    handle_require_approval,
    reported_confidence,
)
from src.gateway.governance.narrow_receipt import issue_narrow_receipt
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

    __slots__ = ("_components", "_settlements", "_stages")

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
        """
        with tracer.start_as_current_span("cage.validate_action") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_validate")
            span.set_attribute(
                OBSERVATION_INPUT, json.dumps({"tool": action, "params": params})
            )

            _check_policy_pin(policy_version_id)

            t0 = time.perf_counter()
            ctx = StageContext(action=action, params=params, profile=Profile.DRY_RUN)
            result = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            span.set_attribute("cage.governance_latency_ms", latency_ms)

            if not result.violations:
                await _trace(result, action, Profile.DRY_RUN, "validate_action", GovernanceDecision.ALLOW)
                span.set_attribute("cage.verdict", GovernanceDecision.ALLOW)
                span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.ALLOW)
                span.set_status(Status(StatusCode.OK))
                return {
                    "verdict": GovernanceDecision.ALLOW,
                    "violations": [],
                    "latency_ms": latency_ms,
                    "agent_id": params.get("_caller_principal", ""),
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
            meta = {**_ftra_meta(result), **_barrier_meta(result), **classification.metadata}
            span.set_attribute(
                "cage.governance.classification_decision", classification.decision.value
            )
            span.set_attribute(
                "cage.governance.classification_reason",
                str(meta.get("classification_reason", ""))[:200],
            )

            if classification.decision == GovernanceDecision.NARROW:
                return await self._narrow_candidate(action, params, result, meta, t0)

            if classification.decision == GovernanceDecision.REQUIRE_APPROVAL:
                meta = await self._reverified_narrow_hint(action, meta)

            # Unmapped decisions fall through to DENY (fail-closed).
            handler = _VERDICT_HANDLERS.get(classification.decision, handle_deny)
            await _trace(
                result,
                action,
                Profile.DRY_RUN,
                "validate_action",
                classification.decision
                if classification.decision in _PENDING_DECISIONS
                else GovernanceDecision.DENY,
            )
            verdict = handler(
                action, params, violations, list(result.tier_failures), meta, latency_ms
            )
            return await verdict if inspect.isawaitable(verdict) else verdict

    async def _reverified_narrow_hint(
        self, action: str, meta: dict[str, Any]
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
        verified = copy.deepcopy(proposal)  # the exact params the response names
        ctx = StageContext(
            action=action, params=copy.deepcopy(verified), profile=Profile.DRY_RUN
        )
        rerun = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
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
    ) -> dict[str, Any]:
        """Offer a narrower's proposal only if the DRY_RUN profile passes on it.

        proof/model.py NARROW (c): the clamped params must pass every stage.
        The re-check previews phase-2 stages (nothing is reserved) and is never
        classified, so the narrower runs once per request. No seal is minted:
        executing the proposal is a separate committing run over it.
        """
        proposal = meta.get("narrowed_params")
        if not isinstance(proposal, dict):
            await _trace(result, action, Profile.DRY_RUN, "validate_action", GovernanceDecision.DENY)
            await _deny(action, params, result)
        verified = copy.deepcopy(proposal)  # the exact params the response names
        ctx = StageContext(
            action=action, params=copy.deepcopy(verified), profile=Profile.DRY_RUN
        )
        rerun = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        reverified = not rerun.violations
        await _trace(
            result,
            action,
            Profile.DRY_RUN,
            "validate_action",
            GovernanceDecision.NARROW if reverified else GovernanceDecision.DENY,
            narrower_present=True,
            clamped_params_valid=reverified,
        )
        trace.get_current_span().set_attribute(
            "cage.governance.narrow_reverified", reverified
        )
        if not reverified:
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
            )
            raise GovernanceError(
                f"handle_deny returned without raising; refusing {action}"
            )  # fail closed
        return handle_narrow(
            action,
            params,
            verified,
            violations=list(result.violations),
            classification_meta=meta,
            latency_ms=latency_ms,
        )

    async def govern(self, tool_name: str, params: dict[str, Any]) -> str:
        """The committing run: commit phase 2 and seal, or refuse.

        Returns the seal. When the run refuses with only NARROWABLE findings
        and a narrower proposes clamped params, the seal covers *those*
        params instead (see :meth:`_sealed_narrow`) and a NARROW receipt
        names them. Any other refusal raises ``GovernanceError``.
        """
        with tracer.start_as_current_span("symbolic_governor.govern") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_evaluation")
            span.set_attribute(
                OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params})
            )

            ctx = StageContext(action=tool_name, params=params, profile=Profile.FULL)
            result, seal = await run_sealed(
                self.stages, ctx, params, path="govern", settlements=self._settlements
            )
            if seal is None:
                seal = await self._sealed_narrow(tool_name, params, result)
            else:
                await _trace(
                    result, tool_name, Profile.FULL, "govern", GovernanceDecision.ALLOW, seal=seal
                )
            span.set_attribute("cage.seal_issued", True)
            span.set_attribute(OBSERVATION_OUTPUT, GovernanceDecision.ALLOW)
            return seal

    async def _sealed_narrow(
        self, action: str, params: dict[str, Any], result: PipelineResult
    ) -> str:
        """Seal a narrower's proposal in the committing path, or deny.

        proof/model.py NARROW: (a) every violation NARROWABLE and (b) a
        narrower proposal — both decided by the classifier — and (c) the
        clamped params pass a fresh FULL run, which commits and seals them.
        The re-run is never classified, so the narrower runs once. The NARROW
        receipt is stored inside that run's ``ReservationScope``: if it
        cannot be stored, the commits are rolled back and the request denied.
        """
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
        if classification.decision != GovernanceDecision.NARROW or not isinstance(proposal, dict):
            await _trace(result, action, Profile.FULL, "govern", GovernanceDecision.DENY)
            await _deny(action, params, result)
        narrowed = copy.deepcopy(proposal)  # the exact params the seal and receipt name

        async def _deliver(seal: str) -> None:
            await issue_narrow_receipt(
                seal,
                narrowed,
                constraints_applied=classification.metadata.get("constraints_applied", []),
                narrowing_reason=str(classification.metadata.get("narrowing_reason", "")),
            )

        ctx = StageContext(action=action, params=copy.deepcopy(narrowed), profile=Profile.FULL)
        rerun, seal = await run_sealed(
            self.stages,
            ctx,
            narrowed,
            path="govern_narrow",
            settlements=self._settlements,
            on_seal=_deliver,
        )
        span = trace.get_current_span()
        span.set_attribute("cage.governance.narrow_reverified", seal is not None)
        # The model's NARROW state records where the *original* run failed.
        await _trace(
            result,
            action,
            Profile.FULL,
            "govern_narrow",
            GovernanceDecision.NARROW if seal is not None else GovernanceDecision.DENY,
            seal=seal,
            narrower_present=True,
            clamped_params_valid=seal is not None,
        )
        if seal is None:
            await handle_deny(
                action,
                narrowed,
                list(rerun.violations),
                list(rerun.tier_failures),
                {**_ftra_meta(rerun), "classification_reason": "narrow_reverification_failed"},
            )
            raise GovernanceError(
                f"handle_deny returned without raising; refusing {action}"
            )  # fail closed
        span.set_attribute("cage.verdict", GovernanceDecision.NARROW)
        return seal

    async def revalidate_post_hitl(
        self,
        action: str,
        params: dict[str, Any],
        *,
        approved_barrier_preview: BarrierPreview | str | None,
        trace_id: str | None = None,
    ) -> str:
        """The post-approval committing run: POST_HITL commit + seal, or refuse.

        ``approved_barrier_preview`` is the phase-2 preview the approval was
        given against (``DeferToken.opa_input_snapshot["barrier_preview"]``,
        bound into every ``ApprovalRecord`` by ``DeferQueue.approve``). The
        approval covers only that context: if the reviewer was told the
        barriers would PASS and the committing run's barriers now refuse, the
        refusal is ``[APPROVAL_CONTEXT_DRIFT]`` — the operator approved a
        request that no longer exists. An unrecognised snapshot is refused
        before anything runs. Either way no seal is minted. An approval given
        against ``FAIL`` (e.g. of a ``narrow_hint``'s clamped params) is
        honoured only if the barriers now admit the executed params.
        """
        with tracer.start_as_current_span(
            "symbolic_governor.revalidate_post_hitl"
        ) as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_revalidate_post_hitl")
            span.set_attribute(
                OBSERVATION_INPUT, json.dumps({"tool": action, "params": params})
            )
            span.set_attribute("toctou.revalidation.scope", "opa+phase2")
            if trace_id is not None:
                span.set_attribute("toctou.revalidation.trace_id", trace_id)
            try:
                approved = _parse_barrier_snapshot(approved_barrier_preview)
            except ValueError:
                await handle_deny(
                    action,
                    params,
                    [_approval_drift(f"unrecognised approval snapshot {approved_barrier_preview!r}")],
                    [],
                    {"approved_barrier_preview": str(approved_barrier_preview)},
                )
                raise GovernanceError(
                    f"handle_deny returned without raising; refusing {action}"
                )  # fail closed
            span.set_attribute(
                "toctou.approved_barrier_preview", approved.value if approved else ""
            )
            if not self._is_governed_action(action, params):
                # POST_HITL re-runs only claimed barriers; with none there is
                # nothing to re-verify, so the approval cannot be honoured.
                await handle_deny(action, params, [_UNGOVERNED_POST_HITL], [], {})
                raise GovernanceError(
                    f"no tier governs {action}; post-HITL re-validation refused"
                )
            ctx = StageContext(action=action, params=params, profile=Profile.POST_HITL)
            result, seal = await run_sealed(
                self.stages,
                ctx,
                params,
                path="revalidate_post_hitl",
                settlements=self._settlements,
            )
            if result.barrier_outcome is not None:
                span.set_attribute("toctou.barrier_outcome", result.barrier_outcome.value)
            await _trace(
                result,
                action,
                Profile.POST_HITL,
                "revalidate_post_hitl",
                GovernanceDecision.ALLOW if seal is not None else GovernanceDecision.DENY,
                seal=seal,
            )
            if seal is None:
                if (
                    approved == BarrierPreview.PASS
                    and result.barrier_outcome == BarrierPreview.FAIL
                ):
                    await _deny_drift(action, params, result, approved)
                await _deny(action, params, result)
            return seal

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
        """
        with tracer.start_as_current_span("symbolic_governor.verify") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "governance_simulation")
            span.set_attribute(
                OBSERVATION_INPUT, json.dumps({"tool": tool_name, "params": params})
            )

            # DRY_RUN never commits, so no ReservationScope: run_pipeline refuses one.
            ctx = StageContext(action=tool_name, params=params, profile=Profile.DRY_RUN)
            result = await run_pipeline(self.stages, ctx, profile=Profile.DRY_RUN)

            violations = list(result.violations)
            decision = GovernanceDecision.ALLOW
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
            span.set_attribute(
                OBSERVATION_OUTPUT,
                json.dumps(
                    [
                        {
                            "tier": v.tier,
                            "code": v.code,
                            "message": v.message,
                            "kind": v.kind.value,
                        }
                        for v in violations
                    ]
                )
                if violations
                else GovernanceDecision.ALLOW,
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
        """True if any domain or jurisdiction tier claims ``action``.

        A tier whose ``claims_action`` raises counts as claiming it (fail
        closed): the pipeline then records the raise as a HARD TIER_EXCEPTION.
        """
        for tier in self.tiers:
            try:
                if tier.claims_action(action, params):
                    return True
            except Exception:
                return True
        return False


_UNGOVERNED_POST_HITL = Violation(
    tier="kernel",
    code="UNGOVERNED_POST_HITL",
    kind=ViolationKind.HARD,
    message="post-HITL re-validation requested for an action no domain tier claims",
)

APPROVAL_CONTEXT_DRIFT = "APPROVAL_CONTEXT_DRIFT"


def _parse_barrier_snapshot(value: BarrierPreview | str | None) -> BarrierPreview | None:
    """The approval's barrier snapshot; ``ValueError`` if it is not PASS/FAIL/None."""
    return None if value is None else BarrierPreview(value)


def _approval_drift(detail: str) -> Violation:
    return Violation(
        tier="kernel",
        code=APPROVAL_CONTEXT_DRIFT,
        kind=ViolationKind.HARD,
        message=f"[{APPROVAL_CONTEXT_DRIFT}] {detail}",
    )


async def _deny_drift(
    action: str,
    params: dict[str, Any],
    result: PipelineResult,
    approved: BarrierPreview,
) -> NoReturn:
    """Refuse a committing run whose barriers no longer match the approval.

    The drift violation leads (it decided the refusal); the barrier findings
    follow, so the receipt still names what now refuses.
    """
    cause = next(
        (v.message for v in result.violations if v.kind == ViolationKind.HARD),
        "phase-2 barriers refused",
    )
    drift = _approval_drift(
        f"approved against barrier preview {approved.value}, but the committing "
        f"run's barriers now refuse: {cause}"
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
    )
    raise GovernanceError(
        f"handle_deny returned without raising; refusing {action}"
    )  # fail closed


#: Decisions that park the request instead of refusing it (model phase CHECKING).
_PENDING_DECISIONS = frozenset({GovernanceDecision.REQUIRE_APPROVAL, GovernanceDecision.DEFER})


async def _trace(
    result: PipelineResult,
    action: str,
    profile: Profile,
    path: str,
    verdict: GovernanceDecision,
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


_VERDICT_HANDLERS = {
    GovernanceDecision.DENY: handle_deny,
    GovernanceDecision.REQUIRE_APPROVAL: handle_require_approval,
    GovernanceDecision.DEFER: handle_defer,
    # NARROW is not here: SymbolicGovernor._narrow_candidate() re-verifies it.
}


async def _deny(
    action: str, params: dict[str, Any], result: PipelineResult
) -> NoReturn:
    await handle_deny(
        action,
        params,
        list(result.violations),
        list(result.tier_failures),
        _ftra_meta(result),
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
