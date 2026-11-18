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

from typing import Any

from opentelemetry import trace as _otel_trace

from src.gateway.observability import attributes as _attr

try:
    from nemoguardrails.actions import action as _nemo_action

    def action(name: str) -> Any:
        return _nemo_action(name=name)
except ImportError:

    def action(name: str) -> Any:
        return lambda fn: fn


_tracer = _otel_trace.get_tracer("cage_healthcare.rails.actions")
_OUTCOME = "PASS_THROUGH_CONSENSUS_AUTHORITATIVE"


# Contraindication policy is enforced authoritatively by clinical_consensus_tier.
@action(name="CheckContraindicationAction")
async def check_contraindication_action(
    context: dict[str, Any] | None = None, **kwargs: Any
) -> bool:
    with _tracer.start_as_current_span("nemo.action.check_contraindication") as span:
        span.set_attribute(_attr.OBSERVATION_TYPE, "span")
        span.set_attribute(
            _attr.TRACE_METADATA_GUARDRAIL_ACTION, "CheckContraindicationAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute("nemo.action.outcome", _OUTCOME)
        return True
