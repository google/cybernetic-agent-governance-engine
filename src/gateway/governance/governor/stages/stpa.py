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

import dataclasses
import logging
import time

from opentelemetry import trace

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Stage, StageContext
from src.gateway.governance.stpa_validator import STPAValidator

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)
OBSERVATION_NAME = "observation.name"


class StpaStage(Stage):
    """Stage for STPA Unsafe Control Actions validation."""

    name: str = "stpa"
    mutating: bool = False

    def __init__(self, validator: STPAValidator | None = None) -> None:
        self.validator = validator

    async def run(self, ctx: StageContext) -> list[Violation]:
        if self.validator is None:
            return []

        with tracer.start_as_current_span("cage.stpa_check") as stpa_span:
            stpa_span.set_attribute(OBSERVATION_NAME, "stpa_uca_check")
            stpa_span.set_attribute("governance.tool", ctx.action)
            _t0 = time.perf_counter()

            # Previews and committing runs evaluate the same params: measured
            # inputs are bound server-side before the pipeline runs
            # (``bind_server_inputs``), never defaulted here.
            check_params = dict(ctx.params)

            try:
                stpa_violations = self.validator.validate(ctx.action, check_params)
            except Exception as exc:
                stpa_span.record_exception(exc)
                stpa_span.set_attribute(
                    "governance.stage.latency_ms",
                    round((time.perf_counter() - _t0) * 1000, 2),
                )
                return [
                    Violation(
                        tier="stpa",
                        code="STPA_ERROR",
                        message=f"STPA Validator Failed: {exc}",
                        kind=ViolationKind.HARD,
                    )
                ]

            violations = [_as_hard(v) for v in stpa_violations]
            promoted = [
                v.code
                for v, raw in zip(violations, stpa_violations, strict=True)
                if raw.kind != v.kind
            ]
            if promoted:
                logger.warning(
                    "STPA validator returned non-HARD violation(s) %s for '%s'; "
                    "promoted to HARD (a UCA is never routable to a human).",
                    promoted,
                    ctx.action,
                )
            stpa_span.set_attribute("governance.stpa.violations", len(violations))
            stpa_span.set_attribute("governance.stpa.promoted_to_hard", len(promoted))
            stpa_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0) * 1000, 2),
            )

            return violations


def _as_hard(violation: Violation) -> Violation:
    """``violation`` with ``kind=HARD``.

    An STPA finding is an unsafe control action: it is refused outright, never
    deferred, narrowed or routed to a human. Promoting here makes that a
    property of the stage rather than of each validator, and guarantees
    ``run_pipeline`` stops before ``ConfidenceStage`` on any STPA finding.
    """
    if violation.kind == ViolationKind.HARD:
        return violation
    return dataclasses.replace(violation, kind=ViolationKind.HARD)
