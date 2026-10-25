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

"""Healthcare tool provider."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from src.cage_healthcare.tools.dose_order import DoseOrder
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import (
    dispatch_actuation,
    get_actuator_registry,
)
from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    verify_and_consume_seal,
)
from src.gateway.governance.seams import actuation as _seam
from src.gateway.server.governance_middleware import ActionDeferred, enforce_governance

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor


class ClinicalDoseActuator:
    """Healthcare domain actuator for governed clinical dose administration."""

    actuator_id: str = "cage_healthcare_clinical"

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set[_seam.ActuatorCapability]:
        return {_seam.ActuatorCapability.REPLAY_PROTECTED}

    async def actuate(
        self, clearance: _seam.ExecutionClearance
    ) -> _seam.ActuationReceipt:
        ts = datetime.now(tz=timezone.utc).isoformat()
        valid = (
            clearance.executor_id == self.actuator_id
            and clearance.decision == "ALLOW"
            and bool(clearance.governance_decision_digest)
        )
        if not valid:
            bad = [{"code": "CLEARANCE_INVALID"}]
            return _seam.ActuationReceipt(False, None, None, None, bad, False, ts)
        raw = DoseOrder(**clearance.params).model_dump()  # type: ignore[arg-type]
        ok = (True, clearance.nonce, clearance.thread_id, raw, [], False, ts)
        return _seam.ActuationReceipt(*ok)


if get_actuator_registry().get_actuator("administer_dose") is None:
    get_actuator_registry().register(
        ClinicalDoseActuator(), claims={"administer_dose", "dose_order"}
    )


async def administer_dose_action(
    patient_id: str,
    medication: str,
    dose_mg: float,
    confidence: float = 0.99,
    *,
    governor: SymbolicGovernor,
) -> dict[str, object]:
    """Govern, seal, actuate, and settle a clinical dose order."""
    order = DoseOrder(patient_id=patient_id, medication=medication, dose_mg=dose_mg)
    params: dict[str, Any] = {**order.model_dump(), "confidence": confidence}
    try:
        seal = await enforce_governance(governor, "administer_dose", params)
    except ActionDeferred as exc:
        msg = str(exc)
        return {"status": "DEFERRED", "deferred_id": exc.deferred_id, "reason": msg}
    except PermissionError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    if not seal or not isinstance(seal, str) or not seal.strip():
        raise SymbolicGovernorViolation("No seal", action="administer_dose")
    executed = False
    try:
        try:
            await verify_and_consume_seal(seal, "administer_dose", params)
        except SymbolicGovernorViolation as exc:
            return {"status": "BLOCKED", "reason": exc.reason}
        actuator = get_actuator_registry().get_actuator("administer_dose")
        if actuator is None:
            raise SymbolicGovernorViolation("No actuator", action="administer_dose")
        tid = str(uuid.uuid4())
        digest = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()
        c1 = (tid, "ALLOW", "DIRECT", "administer_dose", order.patient_id)
        c2 = ("clinician_001", int(time.time()), "CONSTRUCTION_TIME", tid)
        c3 = ("THREAD_DERIVED", seal, digest, uuid.uuid4().hex[:32], params)
        c4 = ("cage_healthcare_clinical", "local://default", "HIGH_CLINICAL")
        clearance = _seam.ExecutionClearance(*c1, *c2, *c3, *c4, routing_seal=seal)  # type: ignore[arg-type]
        receipt = await dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed
        if not receipt.accepted:
            return {"status": "BLOCKED", "reason": "Actuation rejected"}
        rid = receipt.receipt_id
        return {"status": "GOVERNED", **order.model_dump(), "receipt_id": rid}
    finally:
        await governor.settle(seal, executed=executed)


class ClinicalToolProvider(DomainToolProvider):
    """Provides healthcare domain tools to the MCP tool server."""

    def register_tools(self, server: FastMCP, governor: SymbolicGovernor) -> None:
        """Register healthcare tools with the MCP server."""
        if not hasattr(server, "tool"):
            return

        @server.tool()
        async def administer_dose(
            patient_id: str, medication: str, dose_mg: float, confidence: float = 0.99
        ) -> dict[str, object]:
            return await administer_dose_action(
                patient_id, medication, dose_mg, confidence, governor=governor
            )
