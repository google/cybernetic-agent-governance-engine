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
import os
import time

from opentelemetry import trace

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Stage, StageContext, Profile
from src.gateway.governance.generated_stpa_validator import GeneratedSTPAValidator as STPAValidator

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

            check_params = dict(ctx.params)
            # Default latency_ms for DRY_RUN profile or sim_mode
            if ctx.profile == Profile.DRY_RUN and "latency_ms" not in check_params:
                check_params["latency_ms"] = float(
                    os.getenv("GOVERNANCE_SIM_LATENCY_MS", "10.0")
                )

            try:
                stpa_violations = self.validator.validate(ctx.action, check_params)
            except Exception as exc:
                stpa_span.record_exception(exc)
                stpa_span.set_attribute("governance.stage.latency_ms", round((time.perf_counter() - _t0) * 1000, 2))
                return [
                    Violation(
                        tier="stpa",
                        code="STPA_ERROR",
                        message=f"STPA Validator Failed: {exc}",
                        kind=ViolationKind.HARD
                    )
                ]

            stpa_span.set_attribute("governance.stpa.violations", len(stpa_violations))
            stpa_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0) * 1000, 2),
            )

            return list(stpa_violations)
