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
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from mcp.types import CallToolResult

from src.cage_healthcare import ground_truth as _gt
from src.cage_healthcare.tools.dose_order import DoseOrder
from src.gateway.governance import commit_outcome as _co
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

_R, _O, _ACT = _seam.ActuationReceipt, _seam.ActuationOutcome, "administer_dose"
_ACC, _REJ, _UNK = _O.ACCEPTED, _O.REJECTED, _O.UNKNOWN
_CS, _CO = _co.CommitStatus, _co.CommitOutcome
_BOUND = ("patient_id", "medication", "route", "indication")
_INDET = "Actuation indeterminate (reservations confirmed)"


async def _refuse(reason: str, params: dict[str, Any]) -> _co.CommitOutcome:
    await _gm.record_refusal(_ACT, reason, oscal_control_ref="AC-3", params=params)
    return _CO(_CS.REFUSED, f"BLOCKED: {reason}")


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
        ts, tid = datetime.now(tz=timezone.utc).isoformat(), c.thread_id
        if c.executor_id != self.actuator_id or not (c.routing_seal or "").strip():
            return _deny("CLEARANCE_INVALID", ts)
        if (err := _act.verify_clearance_contract(c, self.actuator_id)) is not None:
            return _deny(err[0], ts, err[1])
        p = dict(c.params)
        try:
            raw = DoseOrder(**p).model_dump()  # type: ignore[arg-type]
            debit = _gt.healthcare_cost_resolver(c.action, p)
        except Exception as exc:
            return _deny("ORDER_INVALID", ts, str(exc))
        if debit > 0.0:
            self._ledger = self._ledger or _gt.SimulatedSerumAssayProvider()
            try:
                kw = {"submitted_at": time.time(), "debit_id": c.nonce}
                await asyncio.to_thread(self._ledger.record_debit, debit, **kw)
            except Exception as exc:
                f = [{"code": "ASSAY_JOURNAL_FAILED", "detail": str(exc)}]
                return _R(False, None, tid, None, f, False, None, ts, outcome=_UNK)
        doc = {**raw, "assay_debit_mg_l": debit}
        return _R(True, c.nonce, tid, doc, [], False, None, ts, outcome=_ACC)


_clinical_actuator = ClinicalDoseActuator()
if get_actuator_registry().get_actuator(_ACT) is None:
    get_actuator_registry().register(_clinical_actuator, {_ACT, "dose_order"})


def _covers(a: dict[str, Any], r: dict[str, Any]) -> bool:
    return _act.approval_covers_bounded(a, r, _BOUND, "dose_mg")


async def administer_dose_action(
    patient_id: str,
    medication: str,
    dose_mg: float,
    idempotency_key: str,
    confidence: float = 0.99,
    deferred_id: str | None = None,
    *,
    governor: SymbolicGovernor,
) -> _co.CommitOutcome:
    base: dict[str, Any] = {"patient_id": patient_id, "medication": medication}
    raw: dict[str, Any] = {**base, "dose_mg": dose_mg, "confidence": confidence}
    raw["idempotency_key"] = str(idempotency_key or "")
    ckw: dict[str, Any] = {"action": _ACT, "idempotency_key": idempotency_key}
    ckw |= {"params": raw, "reclaim_blocked": bool(deferred_id)}
    async with _ei.execution_claim_scope(governor, **ckw) as scope:
        if (early := scope.early_outcome) is not None:
            return early
        key = scope.idempotency_key or ""
        order = DoseOrder(**base, dose_mg=dose_mg, idempotency_key=key)
        params: dict[str, Any] = {**order.model_dump(), "confidence": confidence}
        try:
            if deferred_id:
                fn = _gm.enforce_approved_governance
                gkw: dict[str, Any] = {"deferred_id": deferred_id}
                governed = await fn(
                    governor, _ACT, params, approval_covers=_covers, **gkw
                )
            else:
                governed = await enforce_governance(governor, _ACT, params)
        except PermissionError as exc:
            out = _ei.commit_outcome_from_governance_error(exc)
            scope.set_outcome_summary(out.message)
            return out
        seal, evaluated = _act.require_sealed_action(governed, _ACT)
        ca = (_ACT, key, order.patient_id, "clinician_001")
        cb = ("cage_healthcare_clinical", "HIGH_CLINICAL", evaluated, seal)
        clr = _act.build_execution_clearance(*ca, *cb)
        attempt = scope.attempt
        try:
            try:
                await verify_and_consume_seal(seal, _ACT, evaluated)
            except _rs.SymbolicGovernorViolation as exc:
                scope.set_outcome_summary(f"BLOCKED: {exc.reason}")
                return await _refuse(exc.reason, evaluated)
            act = get_actuator_registry().get_actuator(_ACT)
            if act is None:
                raise _rs.SymbolicGovernorViolation("No actuator", action=_ACT)
            rec = await _act.dispatch_actuation(act, clr)
            if attempt.status is _ei.ExecutionStatus.UNKNOWN:
                codes = "; ".join(f.get("code", "UNKNOWN") for f in rec.findings)
                msg = f"UNKNOWN: {_INDET}" + (f" ({codes})" if codes else "")
                scope.set_outcome_summary(msg)
                return _CO(_CS.INDETERMINATE, msg)
            if attempt.status is _ei.ExecutionStatus.BLOCKED:
                scope.set_outcome_summary("BLOCKED: Actuation rejected")
                return await _refuse("Actuation rejected", evaluated)
            msg = f"EXECUTED: {order.patient_id} {medication} {dose_mg}mg (Receipt ID: {rec.receipt_id})"
            scope.set_outcome_summary(msg)
            return _CO(_CS.EXECUTED, msg)
        finally:
            await governor.settle(seal, executed=attempt.may_have_executed)


class ClinicalToolProvider(_ct.DomainToolProvider):
    def register_tools(self, server: FastMCP, governor: SymbolicGovernor) -> None:
        if not hasattr(server, "tool"):
            return

        @server.tool()
        async def administer_dose(
            patient_id: str,
            medication: str,
            dose_mg: float,
            idempotency_key: str,
            confidence: float = 0.99,
            deferred_id: str | None = None,
        ) -> CallToolResult:
            a = (patient_id, medication, dose_mg, idempotency_key)
            coro = administer_dose_action(
                *a, confidence, deferred_id, governor=governor
            )
            return await _ei.run_commit_tool(coro)
