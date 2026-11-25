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

_R, _O, _ACT = _seam.ActuationReceipt, _seam.ActuationOutcome, "administer_dose"
_ACC, _REJ, _UNK = _O.ACCEPTED, _O.REJECTED, _O.UNKNOWN
_BOUND = ("patient_id", "medication", "route", "indication")
_INDET = "Actuation indeterminate (reservations confirmed)"


def _blocked(reason: str, ph: object = "") -> dict[str, object]:
    out: dict[str, object] = {"status": "BLOCKED", "reason": reason}
    return {**out, "proof_hash": str(ph)} if ph else out


async def _refuse(reason: str, params: dict[str, Any]) -> dict[str, object]:
    ph = await _gm.record_refusal(_ACT, reason, oscal_control_ref="AC-3", params=params)
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
) -> dict[str, object]:
    from src.gateway.governance.governor.errors import GovernanceInfrastructureError

    base: dict[str, Any] = {"patient_id": patient_id, "medication": medication}
    raw: dict[str, Any] = {**base, "dose_mg": dose_mg, "confidence": confidence}
    raw["idempotency_key"] = str(idempotency_key or "")
    ckw: dict[str, Any] = {"action": _ACT, "idempotency_key": idempotency_key}
    ckw |= {"params": raw, "reclaim_blocked": bool(deferred_id)}
    async with _ei.execution_claim_scope(governor, **ckw) as scope:
        if (bad := scope.invalid_key_reason) is not None:
            return _blocked(bad, scope.proof_hash)
        if (dup := scope.duplicate) is not None:
            if dup.status is _ei.ExecutionStatus.EXECUTED:
                return {"status": "GOVERNED", "replayed": True, "outcome": dup.outcome}
            return _blocked(dup.outcome or "duplicate blocked", scope.proof_hash)
        key = scope.idempotency_key or ""
        order = DoseOrder(**base, dose_mg=dose_mg, idempotency_key=key)
        params: dict[str, Any] = {**order.model_dump(), "confidence": confidence}
        try:
            if deferred_id:
                fn = _gm.enforce_approved_governance
                gkw: dict[str, Any] = {"deferred_id": deferred_id}
                gkw["approval_covers"] = _covers
                governed = await fn(governor, _ACT, params, **gkw)
            else:
                governed = await enforce_governance(governor, _ACT, params)
        except GovernanceInfrastructureError as e:
            scope.mark_pre_dispatch_infra_failure()
            u: dict[str, object] = {"status": "UNAVAILABLE", "error": e.error_code}
            u |= {"dependency": e.dependency, "failure_code": e.failure_code}
            return u | {"reason": str(e)}
        except _gm.ActionDeferred as exc:
            scope.set_outcome_summary(f"DEFERRED: {exc}")
            d: dict[str, object] = {"status": "DEFERRED", "reason": str(exc)}
            return d | {"deferred_id": exc.deferred_id}
        except PermissionError as exc:
            scope.set_outcome_summary(f"BLOCKED: {exc}")
            return _blocked(str(exc), getattr(exc, "proof_hash", ""))
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
                scope.set_outcome_summary(f"UNKNOWN: {_INDET}")
                ind: dict[str, object] = {"status": "INDETERMINATE", "reason": _INDET}
                ind |= {"receipt_id": rec.receipt_id, "findings": list(rec.findings)}
                return ind
            if attempt.status is _ei.ExecutionStatus.BLOCKED:
                scope.set_outcome_summary("BLOCKED: Actuation rejected")
                return await _refuse("Actuation rejected", evaluated)
            scope.set_outcome_summary(f"GOVERNED: {medication} {dose_mg}mg")
            rid = rec.receipt_id
            return {"status": "GOVERNED", **order.model_dump(), "receipt_id": rid}
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
        ) -> dict[str, object]:
            a = (patient_id, medication, dose_mg, idempotency_key)
            b = (confidence, deferred_id)
            return await administer_dose_action(*a, *b, governor=governor)
