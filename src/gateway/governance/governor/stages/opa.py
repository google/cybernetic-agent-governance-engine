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
from typing import Any

from src.gateway.governance.constants import ControlRegistry, GovernanceControl
from src.gateway.governance.contracts import (
    PolicyClient,
    PolicyEngineUnavailableError,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.pipeline import (
    OpaVerdict,
    Stage,
    StageContext,
    StageOutput,
)

logger = logging.getLogger(__name__)

_OPA_CTRL = GovernanceControl.OPA_POLICY_ENFORCEMENT.value


def _opa_framework() -> str:
    return ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)[
        "primary_framework"
    ]


def decode_opa_verdict(raw: object) -> OpaVerdict | None:
    """
    Decode an raw OPA response into a canonical OpaVerdict.
    - str: ALLOW, DENY, MANUAL_REVIEW (exact match after .strip().upper())
      "GOVERNANCE_VIOLATION" maps to DENY.
    - dict: prefer key "decision" then "allow"; bool True->ALLOW, False->DENY; else recurse.
    - bool: True->ALLOW, False->DENY.
    - otherwise: None
    """
    if isinstance(raw, str):
        val = raw.strip().upper()
        if val == "ALLOW":
            return OpaVerdict.ALLOW
        if val in ("DENY", "GOVERNANCE_VIOLATION"):
            return OpaVerdict.DENY
        if val == "MANUAL_REVIEW":
            return OpaVerdict.MANUAL_REVIEW
        return None

    if isinstance(raw, dict):
        if "decision" in raw:
            decision = raw["decision"]
        elif "allow" in raw:
            decision = raw["allow"]
        else:
            return None

        if isinstance(decision, bool):
            return OpaVerdict.ALLOW if decision else OpaVerdict.DENY
        return decode_opa_verdict(decision)

    if isinstance(raw, bool):
        return OpaVerdict.ALLOW if raw else OpaVerdict.DENY

    return None


class OpaStage(Stage):
    """
    Evaluates the action against the Open Policy Agent (OPA).

    Returns a :class:`StageOutput` carrying the decoded verdict (``None`` when
    OPA failed or answered something undecodable); the instance is shared
    across requests and holds nothing about any one of them.

    ``MANUAL_REVIEW`` is a HITL finding (``OPA_MANUAL_REVIEW``) under every
    profile. The stage never decides whether a human already answered it:
    after approval (``POST_HITL``) ``run_pipeline`` answers it only if the
    approval being redeemed was given against it
    (:func:`~src.gateway.governance.governor.pipeline.answered_by_approval`),
    so a review OPA first asks for while the request waited refuses the run.

    Engine unavailability or undecodable verdicts emit
    ``ViolationKind.INFRASTRUCTURE`` (``OPA_UNAVAILABLE``), blocking fail-closed
    without fabricating a policy refusal receipt (POAM-2026-233).
    """

    name = "opa"
    mutating = False

    def __init__(self, opa_client: PolicyClient):
        self.opa_client = opa_client

    async def run(self, ctx: StageContext) -> StageOutput:
        opa_payload = {**ctx.params, "action": ctx.action}

        try:
            raw_result = await self.opa_client.evaluate_policy(opa_payload)
            verdict = decode_opa_verdict(raw_result)
        except PolicyEngineUnavailableError as e:
            logger.error("OPA unavailable (%s): %s", e.reason, e)
            return StageOutput(
                violations=(
                    Violation(
                        tier="governance",
                        code="OPA_UNAVAILABLE",
                        message=f"[{_OPA_CTRL}] OPA policy engine unavailable ({e.reason}): {e}",
                        kind=ViolationKind.INFRASTRUCTURE,
                    ),
                )
            )
        except Exception as e:
            logger.error("OPA error: %s", e)
            return StageOutput(
                violations=(
                    Violation(
                        tier="governance",
                        code="OPA_UNAVAILABLE",
                        message=f"[{_OPA_CTRL}] OPA policy evaluation failed: {e}",
                        kind=ViolationKind.INFRASTRUCTURE,
                    ),
                )
            )

        return StageOutput(
            violations=tuple(_violations_for(verdict, raw_result)),
            opa_verdict=verdict,
        )


def _violations_for(verdict: OpaVerdict | None, raw_result: object) -> list[Violation]:
    if verdict == OpaVerdict.ALLOW:
        return []

    if verdict == OpaVerdict.DENY:
        return [
            Violation(
                tier="governance",
                code="OPA_DENY",
                message=f"[{_OPA_CTRL}] {_opa_framework()} Violation: OPA Denied Action.",
                kind=ViolationKind.HARD,
            )
        ]

    if verdict == OpaVerdict.MANUAL_REVIEW:
        return [
            Violation(
                tier="governance",
                code="OPA_MANUAL_REVIEW",
                message=f"[{_OPA_CTRL}] {_opa_framework()} Check: Manual Review Required.",
                kind=ViolationKind.HITL,
            )
        ]

    return [
        Violation(
            tier="governance",
            code="OPA_UNAVAILABLE",
            message=f"[{_OPA_CTRL}] OPA policy engine returned undecodable verdict '{raw_result}'",
            kind=ViolationKind.INFRASTRUCTURE,
        )
    ]
