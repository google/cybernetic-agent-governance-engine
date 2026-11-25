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

from __future__ import annotations

import asyncio  # noqa: E401
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from src.cage_healthcare import ground_truth as _gt
from src.cage_healthcare.tools.dose_order import DoseOrder
from src.gateway.governance import contracts as _ct
from src.gateway.governance import execution_actuator as _act
from src.gateway.governance import execution_idempotency as _ei
from src.gateway.governance import routing_seal as _rs
from src.gateway.governance.execution_actuator import get_actuator_registry
from src.gateway.governance.routing_seal import verify_and_consume_seal
from src.gateway.governance.seams import actuation as _seam
from src.gateway.server import governance_middleware as _gm
from src.gateway.server.governance_middleware import enforce_governance

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor

_R, _O = _seam.ActuationReceipt, _seam.ActuationOutcome
_ACC, _REJ, _UNK = _O.ACCEPTED, _O.REJECTED, _O.UNKNOWN


def _blocked(reason: str, ph: object = "") -> dict[str, object]:
    out: dict[str, object] = {"status": "BLOCKED", "reason": reason}
    return {**out, "proof_hash": str(ph)} if ph else out


async def _refuse(reason: str, params: dict[str, Any]) -> dict[str, object]:
    ph = await _gm.record_refusal(
        "administer_dose", reason, oscal_control_ref="AC-3", params=params
    )
    return _blocked(reason, ph)


def _deny(code: str, ts: str, detail: str = "") -> _seam.ActuationReceipt:
    f = {"code": code, "detail": detail} if detail else {"code": code}
    return _R(False, None, None, None, [f], False, None, ts, outcome=_REJ)


class ClinicalDoseActuator:
    actuator_id: str = "cage_healthcare_clinical"

    def __init__(self, ledger: Any = None) -> None:
        self._ledger = ledger

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set[_seam.ActuatorCapability]:
        return {_seam.ActuatorCapability.REPLAY_PROTECTED}

    async def actuate(self, c: _seam.ExecutionClearance) -> _seam.ActuationReceipt:
        ts, s = datetime.now(tz=timezone.utc).isoformat(), c.routing_seal
        ok = c.executor_id == self.actuator_id and c.decision == "ALLOW"
        if not ok or not isinstance(s, str) or not s.strip():
            return _deny("CLEARANCE_INVALID", ts)
        if c.target_route.rstrip("/") not in ("local://default", "*"):
            return _deny("TARGET_ROUTE_MISMATCH", ts, c.target_route)
        if len(c.approvals) < c.required_quorum:
            return _deny("QUORUM_NOT_MET", ts)
        if not hmac.compare_digest(_rs.seal_digest(s), c.governance_decision_digest):
            return _deny("SEAL_DIGEST_MISMATCH", ts)
        p = dict(c.params)
        try:
            if not _rs.verify_seal(s, c.action, p):
                return _deny("INVALID_ROUTING_SEAL", ts, "verify_seal False")
        except _rs.SymbolicGovernorViolation as exc:
            return _deny("INVALID_ROUTING_SEAL", ts, exc.reason)
        try:
            raw = DoseOrder(**p).model_dump()  # type: ignore[arg-type]
            debit = _gt.healthcare_cost_resolver(c.action, p)
        except Exception as exc:
            return _deny("ORDER_INVALID", ts, str(exc))
        if debit > 0.0:
            if self._ledger is None:
                self._ledger = _gt.SimulatedSerumAssayProvider()
            try:
                kw = {"submitted_at": time.time(), "debit_id": c.nonce}
                await asyncio.to_thread(self._ledger.record_debit, debit, **kw)
            except Exception as exc:
                f = [{"code": "ASSAY_JOURNAL_FAILED", "detail": str(exc)}]
                return _R(
                    False, None, c.thread_id, None, f, False, None, ts, outcome=_UNK
                )
        doc = {**raw, "assay_debit_mg_l": debit}
        return _R(True, c.nonce, c.thread_id, doc, [], False, None, ts, outcome=_ACC)


_clinical_actuator = ClinicalDoseActuator()
_reg = get_actuator_registry()
if _reg.get_actuator("administer_dose") is None:
    _reg.register(_clinical_actuator, {"administer_dose", "dose_order"})


async def administer_dose_action(
    patient_id: str,
    medication: str,
    dose_mg: float,
    confidence: float = 0.99,
    *,
    governor: SymbolicGovernor,
) -> dict[str, object]:
    from src.gateway.governance.governor.errors import GovernanceInfrastructureError

    order = DoseOrder(patient_id=patient_id, medication=medication, dose_mg=dose_mg)
    params: dict[str, Any] = {**order.model_dump(), "confidence": confidence}
    try:
        governed = await enforce_governance(governor, "administer_dose", params)
    except GovernanceInfrastructureError as e:
        u: dict[str, object] = {"status": "UNAVAILABLE", "error": e.error_code}
        return u | {
            "dependency": e.dependency,
            "failure_code": e.failure_code,
            "reason": str(e),
        }
    except _gm.ActionDeferred as exc:
        return {
            "status": "DEFERRED",
            "deferred_id": exc.deferred_id,
            "reason": str(exc),
        }
    except PermissionError as exc:
        return _blocked(str(exc), getattr(exc, "proof_hash", ""))
    # The seal commits to the evaluated params the run returned; they, never
    # the caller's params, are verified, digested and actuated.
    seal, evaluated = getattr(governed, "seal", None), getattr(governed, "params", None)
    if not isinstance(seal, str) or not seal.strip() or not isinstance(evaluated, dict):
        raise _rs.SymbolicGovernorViolation("No seal", action="administer_dose")
    tid, nonce = str(uuid.uuid4()), uuid.uuid4().hex[:32]
    dig = hashlib.sha256(json.dumps(evaluated, sort_keys=True).encode()).hexdigest()
    kw: dict[str, Any] = {"thread_id": tid, "decision": "ALLOW", "nonce": nonce}
    kw |= {"decision_path": "DIRECT", "action": "administer_dose"}
    kw |= {"params": evaluated, "consequence_ceiling": "HIGH_CLINICAL"}
    kw |= {"target": order.patient_id, "operator_urn": "clinician_001"}
    kw |= {"issued_at": int(time.time()), "correlation_id": tid}
    kw |= {"issued_at_provenance": "CONSTRUCTION_TIME", "opa_input_digest": dig}
    kw |= {"correlation_id_source": "THREAD_DERIVED", "routing_seal": seal}
    kw |= {"governance_decision_digest": _rs.seal_digest(seal)}
    kw |= {"executor_id": "cage_healthcare_clinical", "required_quorum": 0}
    # The kernel's attempt record, written only by dispatch_actuation(), says
    # whether the dose may have been given (POAM-2026-252); no local copy.
    with _ei.actuation_attempt_scope() as attempt:
        try:
            try:
                await verify_and_consume_seal(seal, "administer_dose", evaluated)
            except _rs.SymbolicGovernorViolation as exc:
                return await _refuse(exc.reason, evaluated)
            act = get_actuator_registry().get_actuator("administer_dose")
            if act is None:
                raise _rs.SymbolicGovernorViolation("No actuator", action=kw["action"])
            rec = await _act.dispatch_actuation(act, _seam.ExecutionClearance(**kw))
            if attempt.status is _ei.ExecutionStatus.UNKNOWN:
                return {
                    "status": "INDETERMINATE",
                    "reason": "Actuation indeterminate (reservations confirmed)",
                    "receipt_id": rec.receipt_id,
                    "findings": list(rec.findings),
                }
            if attempt.status is _ei.ExecutionStatus.BLOCKED:
                return await _refuse("Actuation rejected", evaluated)
            return {
                "status": "GOVERNED",
                **order.model_dump(),
                "receipt_id": rec.receipt_id,
            }
        finally:
            await governor.settle(seal, executed=attempt.may_have_executed)


class ClinicalToolProvider(_ct.DomainToolProvider):
    def register_tools(self, server: FastMCP, governor: SymbolicGovernor) -> None:
        if not hasattr(server, "tool"):
            return

        @server.tool()
        async def administer_dose(
            patient_id: str, medication: str, dose_mg: float, confidence: float = 0.99
        ) -> dict[str, object]:
            return await administer_dose_action(
                patient_id, medication, dose_mg, confidence, governor=governor
            )
