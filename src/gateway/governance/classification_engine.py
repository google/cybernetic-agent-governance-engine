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

Implements the four-way decision tree over violations:
  DENY ← ViolationKind.HARD
  DEFER ← ViolationKind.RELIANCE_INELIGIBLE (whatever the confidence: a
          warrant failure removes CAGE's right to rely on a norm; no human can
          repair it, and it is never a DENY)
  REQUIRE_APPROVAL ← ViolationKind.HITL or OPA MANUAL_REVIEW (with an advisory
                     ``narrow_hint`` when every other finding is NARROWABLE)
  DEFER ← ViolationKind.DEFERRABLE + confidence below threshold
  NARROW ← every violation NARROWABLE + a narrower proposal (candidate only:
           SymbolicGovernor re-verifies the clamped params before sealing)

There is no PAUSE: a transient infrastructure fault is a DENY with a refusal
receipt, never a suspended request.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from src.gateway.governance.contracts import NarrowingResult, Violation, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.narrower import NarrowerRegistry

#: ``classification_reason`` values that accompany a DEFER decision.  The
#: governor maps them to a ``DeferReason`` by exact match
#: (``verdicts._reason_from_classification``), never by substring.
REASON_CONFIDENCE_BELOW_THRESHOLD = "confidence_below_threshold"
REASON_RELIANCE_INELIGIBLE = "reliance_ineligible"
DEFER_REASONS: frozenset[str] = frozenset(
    {REASON_CONFIDENCE_BELOW_THRESHOLD, REASON_RELIANCE_INELIGIBLE}
)


@dataclass(frozen=True)
class ClassificationContext:
    """Context required for violation classification."""

    violations: list[Violation]
    confidence: float
    opa_decision: str | None
    policy_ambiguous: bool
    params: dict[str, Any]


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classification with decision and metadata."""

    decision: GovernanceDecision
    metadata: dict[str, Any]


class ClassificationEngine:
    """Standalone classification engine for governance decisions.

    Routes violations to DENY, DEFER, NARROW, or REQUIRE_APPROVAL based on
    ViolationKind, confidence thresholds, and registered narrowers.
    """

    def __init__(
        self,
        narrower_registry: NarrowerRegistry,
        confidence_threshold: float = 0.70,
        defer_enabled: bool = True,
        narrow_enabled: bool = False,
    ):
        self._narrower_registry = narrower_registry
        self._confidence_threshold = confidence_threshold
        self._defer_enabled = defer_enabled
        self._narrow_enabled = narrow_enabled

    def defers_on_reliance(self, violations: Sequence[Violation]) -> bool:
        """True iff :meth:`classify` answers DEFER for an ineligible warrant.

        Steps 1 and 2 of :meth:`classify`, side-effect free (no narrower
        runs): no HARD finding, at least one ``RELIANCE_INELIGIBLE`` finding,
        and DEFER enabled. Every committing path of the governor asks this, so
        a warrant failure is a DEFER on all of them and a HARD finding still
        outranks it (``proof/model.py`` ``verdict_of``).
        """
        kinds = {v.kind for v in violations}
        return (
            self._defer_enabled
            and ViolationKind.RELIANCE_INELIGIBLE in kinds
            and ViolationKind.HARD not in kinds
        )

    def classify(
        self,
        context: ClassificationContext,
        action: str,
    ) -> ClassificationResult:
        """Classify violations to a governance decision.

        Classification priority (fail-closed):
          1. HARD violations → DENY
          2. RELIANCE_INELIGIBLE violations → DEFER, regardless of confidence
             (DENY only if DEFER is disabled, which assembly refuses whenever
             a warranted norm is configured)
          3. OPA MANUAL_REVIEW → REQUIRE_APPROVAL
          4. HITL violations → REQUIRE_APPROVAL
          5. Every violation NARROWABLE + narrower proposal → NARROW candidate
             (the governor re-runs FULL on the clamped params; else DENY)
          6. DEFERRABLE violations + low confidence → DEFER (if enabled, else DENY)
          7. Default → DENY
        """
        if not context.violations:
            # Should not be called with empty violations
            raise ValueError("classify() called with no violations")

        for v in context.violations:
            if isinstance(v, str):
                raise TypeError(
                    f"classify() received string violation instead of Violation object: {v}"
                )

        normalized_violations = context.violations

        # Step 1: Check for HARD violations (always DENY)
        if any(v.kind == ViolationKind.HARD for v in normalized_violations):
            return ClassificationResult(
                decision=GovernanceDecision.DENY,
                metadata={
                    "classification_reason": "hard_violation",
                    "deferrable": False,
                },
            )

        # Step 2: a norm CAGE may not rely on → DEFER.  Ranked above approval:
        # a human approver cannot repair a warrant.  Never a DENY of its own
        # (proof/model.py verdict_of; assembly refuses a warranted norm when
        # DEFER is disabled, so the DENY branch below is unreachable there).
        ineligible = [
            v
            for v in normalized_violations
            if v.kind == ViolationKind.RELIANCE_INELIGIBLE
        ]
        if ineligible:
            if not self._defer_enabled:
                return ClassificationResult(
                    decision=GovernanceDecision.DENY,
                    metadata={
                        "classification_reason": "reliance_ineligible_defer_disabled",
                        "deferrable": False,
                    },
                )
            return ClassificationResult(
                decision=GovernanceDecision.DEFER,
                metadata={
                    "classification_reason": REASON_RELIANCE_INELIGIBLE,
                    "deferrable": True,
                    "reliance_ineligible": [v.to_dict() for v in ineligible],
                },
            )

        # Step 3: OPA MANUAL_REVIEW → REQUIRE_APPROVAL
        if context.opa_decision == "MANUAL_REVIEW":
            return self._require_approval("opa_manual_review", context, action)

        # Step 4: HITL violations → REQUIRE_APPROVAL
        if any(v.kind == ViolationKind.HITL for v in normalized_violations):
            return self._require_approval("hitl_required", context, action)

        # Step 5: NARROW only if EVERY violation is NARROWABLE and a narrower
        # proposes clamped params (proof/model.py NARROW conditions (a), (b)).
        # A mixed set falls through (fail closed).  The proposal is NOT an
        # authorisation: the governor re-runs the FULL profile on it (c);
        # any violation the proposal leaves unresolved fails that re-run.
        all_narrowable = all(
            v.kind == ViolationKind.NARROWABLE for v in normalized_violations
        )
        if all_narrowable and self._narrow_enabled:
            result = self.propose_narrowing(
                normalized_violations, action, context.params
            )
            if result is not None:
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
            v for v in normalized_violations if v.kind == ViolationKind.DEFERRABLE
        ]
        if deferrable_violations and self._defer_enabled:
            if context.confidence < self._confidence_threshold:
                return ClassificationResult(
                    decision=GovernanceDecision.DEFER,
                    metadata={
                        "classification_reason": REASON_CONFIDENCE_BELOW_THRESHOLD,
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

    def propose_narrowing(
        self,
        violations: list[Violation],
        action: str,
        params: dict[str, Any],
    ) -> NarrowingResult | None:
        """Ask the narrowers to resolve the NARROWABLE findings; never authorises.

        Findings are tried tightest ``bound`` first (unbounded ones last), so
        the proposal satisfies the most restrictive tier that said how much
        it would admit. The first narrower proposal wins; the caller must
        still re-run the pipeline on it.
        """
        narrowable = sorted(
            (v for v in violations if v.kind == ViolationKind.NARROWABLE),
            key=lambda v: (v.bound is None, v.bound or 0.0),
        )
        for violation in narrowable:
            narrower = self._narrower_registry.find_narrower(violation, action, params)
            if narrower is None:
                continue
            result = narrower.narrow(violation, action, params)
            if result is not None and result.can_narrow:
                return result
        return None

    def _require_approval(
        self, reason: str, context: ClassificationContext, action: str
    ) -> ClassificationResult:
        """REQUIRE_APPROVAL, with a ``narrow_hint`` when one can be proposed.

        The hint is offered only when narrowing is enabled and every finding
        other than the approval itself (HITL) is NARROWABLE: then clamped
        params might leave the human only the approval to give. It is
        advisory; ``SymbolicGovernor.validate_action`` keeps it only if a
        DRY_RUN over the clamped params reports only HITL findings.
        """
        metadata: dict[str, Any] = {
            "classification_reason": reason,
            "deferrable": False,
        }
        others = [v for v in context.violations if v.kind != ViolationKind.HITL]
        if (
            self._narrow_enabled
            and others
            and all(v.kind == ViolationKind.NARROWABLE for v in others)
        ):
            hint = self.propose_narrowing(others, action, context.params)
            if hint is not None:
                metadata["narrow_hint"] = {
                    "narrowed_params": hint.narrowed_params,
                    "constraints_applied": hint.constraints_applied,
                    "narrowing_reason": hint.narrowing_reason,
                }
        return ClassificationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL, metadata=metadata
        )
