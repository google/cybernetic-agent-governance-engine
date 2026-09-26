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
from src.gateway.governance.contracts import PolicyClient, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import StageContext
from src.gateway.governance.governor.pipeline import OpaVerdict


logger = logging.getLogger(__name__)

_OPA_CTRL = GovernanceControl.OPA_POLICY_ENFORCEMENT.value


def _opa_framework() -> str:
    return ControlRegistry().get_mapping(GovernanceControl.OPA_POLICY_ENFORCEMENT)["primary_framework"]



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


class OpaStage:
    """
    Evaluates the action against the Open Policy Agent (OPA).
    """

    name = "opa"
    mutating = False

    def __init__(self, opa_client: PolicyClient):
        self.opa_client = opa_client

    async def run(self, ctx: StageContext) -> list[Violation]:
        opa_payload = {**ctx.params, "action": ctx.action, "tool_input": ctx.params}
        
        try:
            client_any: Any = self.opa_client
            raw_result = await client_any.evaluate_policy(opa_payload)
            verdict = decode_opa_verdict(raw_result)
        except Exception as e:
            logger.error("OPA error: %s", e)
            self.decoded_verdict = None
            return [Violation(
                tier="governance",
                code="OPA_ERROR",
                message=f"[{_OPA_CTRL}] OPA policy evaluation failed: {e}",
                kind=ViolationKind.HARD
            )]

        self.decoded_verdict = verdict

        if verdict == OpaVerdict.ALLOW:
            return []
        
        if verdict == OpaVerdict.DENY:
            return [Violation(
                tier="governance",
                code="OPA_DENY",
                message=f"[{_OPA_CTRL}] {_opa_framework()} Violation: OPA Denied Action.",
                kind=ViolationKind.HARD
            )]
        
        if verdict == OpaVerdict.MANUAL_REVIEW:
            return [Violation(
                tier="governance",
                code="OPA_MANUAL_REVIEW",
                message=f"[{_OPA_CTRL}] {_opa_framework()} Check: Manual Review Required.",
                kind=ViolationKind.HITL
            )]
        
        return [Violation(
            tier="governance",
            code="OPA_UNKNOWN_VERDICT",
            message=f"[{_OPA_CTRL}] OPA Policy Violation: Unexpected verdict '{raw_result}'",
            kind=ViolationKind.HARD
        )]
