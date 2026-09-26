import logging
from typing import Any

from src.gateway.governance.contracts import PolicyClient, Violation, ViolationKind
from src.gateway.governance.governor.pipeline import OpaVerdict, Stage

logger = logging.getLogger(__name__)


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
    """

    name = "opa"
    mutating = False

    def __init__(self, opa_client: PolicyClient):
        self.opa_client = opa_client

    async def run(self, action: str, params: dict[str, Any]) -> list[Violation]:
        opa_payload = {**params, "action": action, "tool_input": params}
        
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
                message=f"OPA policy evaluation failed: {e}",
                kind=ViolationKind.HARD
            )]

        self.decoded_verdict = verdict

        if verdict == OpaVerdict.ALLOW:
            return []
        
        if verdict == OpaVerdict.DENY:
            return [Violation(
                tier="governance",
                code="OPA_DENY",
                message="OPA policy denied the action.",
                kind=ViolationKind.HARD
            )]
        
        if verdict == OpaVerdict.MANUAL_REVIEW:
            return [Violation(
                tier="governance",
                code="OPA_MANUAL_REVIEW",
                message="OPA policy requires manual review.",
                kind=ViolationKind.HITL
            )]
        
        return [Violation(
            tier="governance",
            code="OPA_UNKNOWN_VERDICT",
            message=f"OPA policy returned unknown verdict: {raw_result}",
            kind=ViolationKind.HARD
        )]
