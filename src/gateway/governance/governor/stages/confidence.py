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

import math
import time

from opentelemetry import trace

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.governor.pipeline import Stage, StageContext, OpaVerdict
from src.gateway.governance.constants import GovernanceControl, ControlRegistry

tracer = trace.get_tracer(__name__)
OBSERVATION_NAME = "observation.name"

from src.gateway.governance.schemas.thresholds import get_fria_zone_defer


from src.gateway.governance.schemas.thresholds import get_agent_confidence_threshold


class ConfidenceStage(Stage):
    """Stage for agent confidence validation and structural corroboration."""

    name: str = "confidence"
    mutating: bool = False

    async def run(self, ctx: StageContext) -> list[Violation]:
        violations = []
        with tracer.start_as_current_span("cage.confidence_check") as conf_span:
            conf_span.set_attribute(OBSERVATION_NAME, "confidence_threshold_check")
            conf_span.set_attribute("governance.stage", "confidence")
            _t0_conf = time.perf_counter()
            
            confidence_score = ctx.params.get("confidence")
            
            conf_span.set_attribute("tier2.confidence.source", "agent_self_report")
            
            _confidence_threshold = get_agent_confidence_threshold()
            _conf_meta = ControlRegistry().get_mapping(
                GovernanceControl.AGENT_CONFIDENCE_THRESHOLD
            )
            
            _confidence_valid = True
            
            if confidence_score is None:
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score missing (required for all actions)",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif not isinstance(confidence_score, (int, float)):
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score invalid type: {type(confidence_score).__name__}",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif math.isnan(confidence_score):
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score is NaN (invalid)",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif math.isinf(confidence_score):
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score is infinite (invalid)",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif confidence_score < 0:
                _confidence = float(confidence_score)
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score {_confidence} is negative (invalid)",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif confidence_score > 1.0:
                _confidence = float(confidence_score)
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_INVALID",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: Confidence score {_confidence} exceeds maximum 1.0",
                    kind=ViolationKind.HARD
                ))
                _confidence_valid = False
            elif confidence_score < _confidence_threshold:
                _confidence = float(confidence_score)
                violations.append(Violation(
                    tier="governance",
                    code="CONFIDENCE_BELOW_THRESHOLD",
                    message=f"[{GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value}] {_conf_meta['primary_framework']} Confidence Violation: score {_confidence:.2f} < threshold {_confidence_threshold:.2f}. Violation: agent confidence below required minimum.",
                    kind=ViolationKind.DEFERRABLE if _confidence < get_fria_zone_defer() else ViolationKind.HITL
                ))
                _confidence_valid = False
            else:
                _confidence = float(confidence_score)
            
            if _confidence_valid:
                conf_span.set_attribute("governance.confidence.score", _confidence)
            conf_span.set_attribute(
                "governance.confidence.threshold", _confidence_threshold
            )
            conf_span.set_attribute(
                "governance.confidence.passed", _confidence_valid
            )
            conf_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t0_conf) * 1000, 2),
            )

        # Structural corroboration
        with tracer.start_as_current_span(
            "cage.tier2_structural_corroboration"
        ) as _t2_span:
            _t2_span.set_attribute(
                OBSERVATION_NAME, "tier2_structural_corroboration"
            )
            _t2_span.set_attribute("governance.stage", "tier2_corroboration")
            _t2_corr_t0 = time.perf_counter()

            # We don't have opa_margin easily accessible in StageContext. 
            # The instructions say: "The corroboration needs the STPA outcome and OPA verdict: 
            # read them from StageContext ... Remove the misleading span attribute tier2.confidence.independently_verified=True;
            # replace with tier2.confidence.source='agent_self_report'."
            
            _structural_risk_flagged: bool = (
                ctx.stpa_violation_count > 0
                or (ctx.opa_verdict is None) # treat as risk if unavailable
            )

            try:
                _self_reported_confidence = float(ctx.params.get("confidence", 0.0))
            except (TypeError, ValueError):
                _self_reported_confidence = 0.0

            if (
                _structural_risk_flagged
                and _self_reported_confidence >= _confidence_threshold
            ):
                _corroboration_source = "structural_heuristic_override"
                violations.append(Violation(
                    tier="governance",
                    code="TIER2_STRUCTURAL_OVERRIDE",
                    message=f"POAM-TIER2-001 Structural Override: HITL required — self-reported confidence contradicted by structural evidence (stpa_violations={ctx.stpa_violation_count}, opa_margin=None). Independent signal: structural_heuristic_override.",
                    kind=ViolationKind.HITL
                ))
            elif _structural_risk_flagged:
                _corroboration_source = "structural_heuristic_low_confidence"
            else:
                _corroboration_source = "structural_heuristic_pass"

            _t2_span.set_attribute(
                "tier2.confidence.corroboration_source", _corroboration_source
            )
            _t2_span.set_attribute(
                "tier2.confidence.stpa_violations", ctx.stpa_violation_count
            )
            _t2_span.set_attribute(
                "tier2.confidence.structural_risk_flagged", _structural_risk_flagged
            )
            _t2_span.set_attribute(
                "governance.stage.latency_ms",
                round((time.perf_counter() - _t2_corr_t0) * 1000, 2),
            )

        return violations
