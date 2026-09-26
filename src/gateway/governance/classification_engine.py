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

"""Classification Engine for routing violations to governance decisions.

Implements the five-way decision tree:
  DENY ← ViolationKind.HARD
  REQUIRE_APPROVAL ← ViolationKind.HITL or OPA MANUAL_REVIEW
  DEFER ← ViolationKind.DEFERRABLE + confidence below threshold
  PAUSE ← ViolationKind.TRANSIENT (feature-gated)
  NARROW ← ViolationKind.NARROWABLE + registered narrower available
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.gateway.governance.contracts import Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.narrower import NarrowerRegistry


@dataclass(frozen=True)
class ClassificationContext:
    """Context required for violation classification."""
    
    violations: list[Violation]
    stpa_violation_count: int
    confidence: float
    opa_decision: str | None
    policy_ambiguous: bool
    params: dict[str, Any]
    cbf_violation: bool


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classification with decision and metadata."""
    
    decision: GovernanceDecision
    metadata: dict[str, Any]


class ClassificationEngine:
    """Standalone classification engine for governance decisions.
    
    Routes violations to DENY, DEFER, NARROW, PAUSE, or REQUIRE_APPROVAL
    based on ViolationKind, confidence thresholds, and registered narrowers.
    """
    
    def __init__(
        self,
        narrower_registry: NarrowerRegistry,
        confidence_threshold: float = 0.70,
        defer_enabled: bool = True,
        narrow_enabled: bool = False,
        pause_enabled: bool = False,
    ):
        self._narrower_registry = narrower_registry
        self._confidence_threshold = confidence_threshold
        self._defer_enabled = defer_enabled
        self._narrow_enabled = narrow_enabled
        self._pause_enabled = pause_enabled
    
    def classify(
        self,
        context: ClassificationContext,
        action: str,
    ) -> ClassificationResult:
        """Classify violations to a governance decision.
        
        Classification priority (fail-closed):
          1. HARD violations → DENY
          2. OPA MANUAL_REVIEW → REQUIRE_APPROVAL
          3. HITL violations → REQUIRE_APPROVAL
          4. TRANSIENT violations → PAUSE (if enabled, else DENY)
          5. NARROWABLE violations → NARROW (if narrower available, else DENY)
          6. DEFERRABLE violations + low confidence → DEFER (if enabled, else DENY)
          7. Default → DENY
        """
        if not context.violations:
            # Should not be called with empty violations
            raise ValueError("classify() called with no violations")
        
        # Step 1: Check for HARD violations (always DENY)
        if any(v.kind == ViolationKind.HARD for v in context.violations):
            return ClassificationResult(
                decision=GovernanceDecision.DENY,
                metadata={
                    "classification_reason": "hard_violation",
                    "deferrable": False,
                },
            )
        
        # Step 2: OPA MANUAL_REVIEW → REQUIRE_APPROVAL
        if context.opa_decision == "MANUAL_REVIEW":
            return ClassificationResult(
                decision=GovernanceDecision.REQUIRE_APPROVAL,
                metadata={
                    "classification_reason": "opa_manual_review",
                    "deferrable": False,
                },
            )
        
        # Step 3: HITL violations → REQUIRE_APPROVAL
        if any(v.kind == ViolationKind.HITL for v in context.violations):
            return ClassificationResult(
                decision=GovernanceDecision.REQUIRE_APPROVAL,
                metadata={
                    "classification_reason": "hitl_required",
                    "deferrable": False,
                },
            )
        
        # Step 4: TRANSIENT violations → PAUSE (if enabled)
        if any(v.kind == ViolationKind.TRANSIENT for v in context.violations):
            if self._pause_enabled:
                return ClassificationResult(
                    decision=GovernanceDecision.PAUSE,
                    metadata={
                        "classification_reason": "transient_condition",
                        "pause_reason": "RESOURCE_UNAVAILABLE",
                    },
                )
            else:
                return ClassificationResult(
                    decision=GovernanceDecision.DENY,
                    metadata={
                        "classification_reason": "transient_disabled_fallback",
                        "deferrable": False,
                    },
                )
        
        # Step 5: NARROWABLE violations → NARROW (if narrower available)
        narrowable_violations = [
            v for v in context.violations if v.kind == ViolationKind.NARROWABLE
        ]
        if narrowable_violations and self._narrow_enabled:
            # Attempt to narrow for the first NARROWABLE violation
            violation = narrowable_violations[0]
            narrower = self._narrower_registry.find_narrower(
                violation, action, context.params
            )
            if narrower:
                result = narrower.narrow(violation, action, context.params)
                if result.can_narrow:
                    return ClassificationResult(
                        decision=GovernanceDecision.NARROW,
                        metadata={
                            "classification_reason": "narrowable_resolved",
                            "original_params": context.params,
                            "narrowed_params": result.narrowed_params,
                            "constraints_applied": result.constraints_applied,
                            "narrowing_reason": result.narrowing_reason,
                        },
                    )
        
        # Step 6: DEFERRABLE violations + low confidence → DEFER
        deferrable_violations = [
            v for v in context.violations if v.kind == ViolationKind.DEFERRABLE
        ]
        if deferrable_violations and self._defer_enabled:
            if context.confidence < self._confidence_threshold:
                return ClassificationResult(
                    decision=GovernanceDecision.DEFER,
                    metadata={
                        "classification_reason": "confidence_below_threshold",
                        "deferrable": True,
                        "confidence": context.confidence,
                        "threshold": self._confidence_threshold,
                    },
                )
        
        # Step 7: Default fallback → DENY
        return ClassificationResult(
            decision=GovernanceDecision.DENY,
            metadata={
                "classification_reason": "default_deny",
                "deferrable": False,
            },
        )
