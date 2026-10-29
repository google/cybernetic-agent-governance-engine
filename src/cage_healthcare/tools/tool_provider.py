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
from src.gateway.governance import execution_actuator as _act
from src.gateway.governance import routing_seal as _rs
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import get_actuator_registry
from src.gateway.governance.routing_seal import verify_and_consume_seal
from src.gateway.governance.seams import actuation as _seam
from src.gateway.server import governance_middleware as _gm
from src.gateway.server.governance_middleware import enforce_governance

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor


def _blocked(reason: str, ph: object = "") -> dict[str, object]:
    out: dict[str, object] = {"status": "BLOCKED", "reason": reason}
    return {**out, "proof_hash": str(ph)} if ph else out


async def _refuse(reason: str, params: dict[str, Any]) -> dict[str, object]:
    ph = await _gm.record_refusal(
        "administer_dose", reason, oscal_control_ref="AC-3", params=params
    )
    return _blocked(reason, ph)


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
        ts, c = datetime.now(tz=timezone.utc).isoformat(), clearance
        # The digest is validated by the contract; the seal is what binds.
        if (
            c.executor_id != self.actuator_id
            or c.decision != "ALLOW"
            or not c.routing_seal
        ):
            bad = [{"code": "CLEARANCE_INVALID"}]
            return _seam.ActuationReceipt(False, None, None, None, bad, False, ts)
        raw = DoseOrder(**c.params).model_dump()  # type: ignore[arg-type]
        return _seam.ActuationReceipt(True, c.nonce, c.thread_id, raw, [], False, ts)


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
    except _gm.ActionDeferred as exc:
        msg = str(exc)
        return {"status": "DEFERRED", "deferred_id": exc.deferred_id, "reason": msg}
    except PermissionError as exc:
        return _blocked(str(exc), getattr(exc, "proof_hash", ""))
    if not seal or not isinstance(seal, str) or not seal.strip():
        raise _rs.SymbolicGovernorViolation("No seal", action="administer_dose")
    executed = False
    try:
        try:
            await verify_and_consume_seal(seal, "administer_dose", params)
        except _rs.SymbolicGovernorViolation as exc:
            return await _refuse(exc.reason, params)
        actuator = get_actuator_registry().get_actuator("administer_dose")
        if actuator is None:
            raise _rs.SymbolicGovernorViolation("No actuator", action="administer_dose")
        tid, nonce = str(uuid.uuid4()), uuid.uuid4().hex[:32]
        digest = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()
        c1 = (tid, "ALLOW", "DIRECT", "administer_dose", order.patient_id)
        c2 = ("clinician_001", int(time.time()), "CONSTRUCTION_TIME", tid)
        c3 = ("THREAD_DERIVED", _rs.seal_digest(seal), digest, nonce, params)
        c4 = ("cage_healthcare_clinical", "local://default", "HIGH_CLINICAL")
        clearance = _seam.ExecutionClearance(*c1, *c2, *c3, *c4, routing_seal=seal)  # type: ignore[arg-type]
        receipt = await _act.dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed
        if not receipt.accepted:
            return await _refuse("Actuation rejected", params)
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
