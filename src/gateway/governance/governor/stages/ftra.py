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

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.ftra.models import FtraBoundaryResult, TerminalClassification
from src.gateway.governance.ftra.semantic_validator import validate_tool_input
from src.gateway.governance.governor.pipeline import Stage, StageContext

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)
OBSERVATION_NAME = "observation.name"

try:
    from prometheus_client import Counter
    _ftra_boundary_counter = Counter(
        "cage_ftra_boundary_checks_total",
        "Total number of FTRA boundary checks executed",
        ["result"],
    )
except (ImportError, ValueError):
    _ftra_boundary_counter = None


class FtraStage(Stage):
    result: FtraBoundaryResult | None = None
    """Stage for FTRA boundary check."""

    name: str = "ftra"
    mutating: bool = False

    def __init__(self) -> None:
        self._ftra_classifier = None

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
                classification = classifier.classify(tool_name)

                in_registry = tool_name in classifier.known_actions()

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
                        in_registry=in_registry,
                    )
                else:
                    result = FtraBoundaryResult.from_classification(
                        classification=classification,
                        action_name=tool_name,
                        in_registry=in_registry,
                        bypassed_ftra_node=bypassed_ftra_node,
                    )

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

                if _ftra_boundary_counter is not None:
                    if result.requires_hitl:
                        _ftra_boundary_counter.labels(result="hitl_required").inc()
                    else:
                        _ftra_boundary_counter.labels(result="passed").inc()

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

                if _ftra_boundary_counter is not None:
                    _ftra_boundary_counter.labels(result="error").inc()

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
