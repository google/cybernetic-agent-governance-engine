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

import logging
import time
from typing import Any

from opentelemetry import trace

from src.gateway.governance.agent_confidence import reported_confidence
from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.ftra.autonomy import (
    MagnitudeExtractor,
    conditional_clear_reason,
    safe_magnitude,
)
from src.gateway.governance.ftra.models import (
    FtraBoundaryResult,
    RegistryState,
    TerminalClassification,
)
from src.gateway.governance.ftra.semantic_validator import validate_tool_input
from src.gateway.governance.governor.metrics import GovernorMetrics, governor_metrics
from src.gateway.governance.governor.pipeline import Stage, StageContext
from src.gateway.governance.schemas.thresholds import get_fria_zone_allow

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)
OBSERVATION_NAME = "observation.name"


class FtraStage(Stage):
    """Stage for FTRA boundary check.

    Classifies the action against the active domain's terminal registry and,
    for a registered terminal with an autonomous envelope, applies the
    conditional-FTRA predicate (``autonomy.conditional_clear_reason``) using
    the domain's ``magnitude_extractor`` and the agent's reported confidence.
    Without an extractor no magnitude is known, so nothing clears.
    """

    result: FtraBoundaryResult | None = None

    name: str = "ftra"
    mutating: bool = False

    def __init__(
        self,
        metrics: GovernorMetrics | None = None,
        magnitude_extractor: MagnitudeExtractor | None = None,
    ) -> None:
        self._ftra_classifier = None
        self._metrics = metrics if metrics is not None else governor_metrics()
        self._magnitude_extractor = magnitude_extractor

    def _get_ftra_classifier(self) -> Any:
        if self._ftra_classifier is None:
            from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
            self._ftra_classifier = IrreversibilityClassifier()
        return self._ftra_classifier

    async def run(self, ctx: StageContext) -> list[Violation]:
        self.result = await self._ftra_boundary_check(
            tool_name=ctx.action,
            tool_input=dict(ctx.params),
            detect_bypass=True,
        )
        return list(self.result.violations)

    async def _ftra_boundary_check(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        *,
        detect_bypass: bool = True,
    ) -> FtraBoundaryResult:
        if not isinstance(tool_input, dict):
            raise TypeError(
                f"FTRA boundary invariant violation: 'tool_input' must be a dict, "
                f"received {type(tool_input).__name__}."
            )

        with tracer.start_as_current_span("cage.ftra_boundary_gate") as span:
            span.set_attribute(OBSERVATION_NAME, "ftra_boundary_check")
            span.set_attribute("governance.stage", "ftra_boundary")
            span.set_attribute("cage.ftra.boundary_check_triggered", True)
            span.set_attribute("cage.ftra.action", tool_name)
            _t0 = time.perf_counter()

            try:
                semantic_result = validate_tool_input(tool_name, tool_input)
                span.set_attribute(
                    "cage.ftra.semantic_validation_passed", semantic_result.is_valid
                )
                if not semantic_result.is_valid:
                    span.set_attribute(
                        "cage.ftra.semantic_failure_code", semantic_result.failure_code
                    )
                    span.set_attribute(
                        "cage.ftra.semantic_failed_parameter",
                        semantic_result.failed_parameter or "",
                    )

                classifier = self._get_ftra_classifier()
                provenance = classifier.classify_with_provenance(tool_name)
                classification = provenance.classification
                registry_state = provenance.registry_state

                bypassed_ftra_node = (
                    detect_bypass
                    and classification == TerminalClassification.IRREVERSIBLE_TERMINAL
                )

                if not semantic_result.is_valid:
                    logger.warning(
                        "⚠️ FTRA Semantic Boundary Breach: Action '%s' failed semantic "
                        "validation. Failure code: %s. Violations: %s",
                        tool_name,
                        semantic_result.failure_code,
                        semantic_result.violations,
                    )
                    result = FtraBoundaryResult.from_semantic_breach(
                        semantic_result=semantic_result,
                        action_name=tool_name,
                        classification=classification,
                        registry_state=registry_state,
                    )
                else:
                    clear_reason = conditional_clear_reason(
                        classification=classification,
                        registry_state=registry_state,
                        envelope=provenance.envelope,
                        magnitude=safe_magnitude(self._magnitude_extractor, tool_input),
                        confidence=reported_confidence(tool_input),
                        confidence_floor=get_fria_zone_allow(),
                    )
                    result = FtraBoundaryResult.from_classification(
                        classification=classification,
                        action_name=tool_name,
                        registry_state=registry_state,
                        bypassed_ftra_node=bypassed_ftra_node,
                        clear_reason=clear_reason,
                    )

                if result.bypassed_ftra_node:
                    logger.warning(
                        "⚠️ FTRA Boundary Check: Action '%s' classified as "
                        "IRREVERSIBLE_TERMINAL at controller boundary. "
                        "This may indicate direct HTTP bypass of in-graph ftra_node. "
                        "Routing to HITL for human review.",
                        tool_name,
                    )

                span.set_attribute("cage.ftra.classification", result.classification)
                span.set_attribute(
                    "cage.ftra.irreversibility_score", result.irreversibility_score
                )
                span.set_attribute("cage.ftra.requires_hitl", result.requires_hitl)
                span.set_attribute("cage.ftra.registry_state", registry_state.value)
                span.set_attribute("cage.ftra.auto_cleared", result.auto_cleared)
                if result.clear_reason is not None:
                    span.set_attribute("cage.ftra.clear_reason", result.clear_reason)
                span.set_attribute(
                    "cage.ftra.bypassed_ftra_node", result.bypassed_ftra_node
                )
                span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )

                self._metrics.ftra_boundary_check(_metric_outcome(result))

                return result

            except Exception as exc:
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

                self._metrics.ftra_boundary_check("error")

                return FtraBoundaryResult(
                    requires_hitl=True,
                    irreversibility_score=1.0,
                    classification=TerminalClassification.IRREVERSIBLE_TERMINAL.value,
                    terminal_match=None,
                    violations=[
                        Violation(
                            tier="ftra",
                            code="FTRA_ERROR",
                            message=f"FTRA Boundary Check: Error classifying action '{tool_name}' — failing closed to IRREVERSIBLE_TERMINAL. Error: {exc}",
                            kind=ViolationKind.HARD
                        )
                    ],
                    bypassed_ftra_node=True,
                )


def _metric_outcome(result: FtraBoundaryResult) -> str:
    """``ftra_boundary_checks`` label: an unreadable registry counts as an error."""
    if result.registry_state is RegistryState.UNAVAILABLE:
        return "error"
    if result.auto_cleared:
        return "conditional_clear"
    return "hitl_required" if result.requires_hitl else "passed"
