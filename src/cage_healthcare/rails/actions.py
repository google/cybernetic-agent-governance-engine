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

"""Healthcare-specific NeMo Guardrails UCA checks."""

import logging
from collections.abc import Callable
from typing import Any

from opentelemetry import trace as _otel_trace

from src.gateway.observability.attributes import (
    OBSERVATION_TYPE,
    TRACE_METADATA_GUARDRAIL_ACTION,
)

try:
    from nemoguardrails.actions import action as _nemo_action

    def action(name: str) -> Any:
        """Thin wrapper that delegates to nemoguardrails.actions.action."""
        return _nemo_action(name=name)
except ImportError:

    def action(name: str) -> Any:
        """No-op decorator used when nemoguardrails is not installed."""

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


logger = logging.getLogger(__name__)
_tracer = _otel_trace.get_tracer("cage_healthcare.rails.actions")


@action(name="CheckContraindicationAction")
async def check_contraindication_action(
    context: dict[str, Any] | None = None, **kwargs: Any
) -> bool:
    """Pass-through stub — contraindication enforcement owned by OPA/clinical tier.

    Clinical policy (medication contraindications, allergies, drug interactions)
    is enforced by the clinical_consensus_tier → multi-critic consensus path.
    """
    with _tracer.start_as_current_span("nemo.action.check_contraindication") as span:
        span.set_attribute(OBSERVATION_TYPE, "span")
        span.set_attribute(
            TRACE_METADATA_GUARDRAIL_ACTION, "CheckContraindicationAction"
        )
        span.set_attribute("iso42001.control_id", "A.6.1.2")
        span.set_attribute(
            "nemo.action.outcome", "PASS_THROUGH_CONSENSUS_AUTHORITATIVE"
        )
        logger.debug(
            "CheckContraindicationAction: pass-through (clinical_consensus_tier is authoritative)"
        )
        return True
