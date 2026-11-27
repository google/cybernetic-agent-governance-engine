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

"""Unit tests for cage_healthcare ClinicalDoseActuator, DoseOrder, and SerumConcentrationBarrier."""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from src.cage_healthcare.ground_truth import SimulatedSerumAssayProvider
from src.cage_healthcare.invariants import (
    SerumConcentrationBarrier,
    healthcare_cost_resolver,
)
from src.cage_healthcare.tools.dose_order import DoseOrder
from src.cage_healthcare.tools.tool_provider import (
    ClinicalDoseActuator,
    administer_dose_action,
)
from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.gateway.governance.execution_idempotency import ExecutionLedger
from src.gateway.governance.governor.sealing import SealedAction
from src.gateway.governance.routing_seal import generate_seal, seal_digest
from src.gateway.governance.safety.cbf_engine import ControlBarrierFunction
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ExecutionClearance,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture(autouse=True)
def _allow_hmac_test_seals(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.gateway.governance.jwks as jwks_mod
    import src.gateway.governance.kms_signer as ks

    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=None))
    monkeypatch.setattr(jwks_mod, "_global_jwks", None)


async def _make_clinical_clearance(
    params: dict[str, Any] | None = None,
    *,
    seal: str | None = None,
    digest: str | None = None,
    executor_id: str = "cage_healthcare_clinical",
    decision: str = "ALLOW",
    target_route: str = "local://default",
    required_quorum: int = 0,
    approvals: list[dict[str, Any]] | None = None,
) -> ExecutionClearance:
    tid = str(uuid.uuid4())
    payload = params or {
        "patient_id": "P-101",
        "medication": "vancomycin",
        "dose_mg": 2.5,
        "idempotency_key": tid,
        "route": "iv",
        "indication": "sepsis",
        "confidence": 0.99,
    }
    minted_seal = (
        seal
        if seal is not None
        else await generate_seal("administer_dose", payload, record_hash="e" * 64)
    )
    gov_digest = digest if digest is not None else seal_digest(minted_seal)
    return ExecutionClearance(
        thread_id=tid,
        decision=decision,  # type: ignore[arg-type]
        decision_path="DIRECT",
        action="administer_dose",
        target="P-101",
        operator_urn="clinician_001",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=tid,
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=gov_digest,
        opa_input_digest=hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest(),
        nonce=uuid.uuid4().hex[:32],
        params=payload,
        executor_id=executor_id,
        target_route=target_route,
        consequence_ceiling="HIGH_CLINICAL",
        approvals=approvals if approvals is not None else [],
        required_quorum=required_quorum,
        routing_seal=minted_seal,
    )


class TestDoseOrderAndCostResolver:
    @pytest.mark.parametrize(
        "bad_dose", [True, False, 0, 0.0, -1.5, math.nan, math.inf, -math.inf]
    )
    def test_dose_order_rejects_bool_non_positive_and_non_finite(
        self, bad_dose: Any
    ) -> None:
        with pytest.raises((ValidationError, ValueError)):
            DoseOrder(
                patient_id="P1",
                medication="heparin",
                dose_mg=bad_dose,
                idempotency_key=str(uuid.uuid4()),
            )

    @pytest.mark.parametrize(
        "bad_dose", [True, False, 0, 0.0, -5.0, math.nan, math.inf]
    )
    def test_cost_resolver_rejects_invalid_doses(self, bad_dose: Any) -> None:
        with pytest.raises(ValueError, match="Invalid clinical dose"):
            healthcare_cost_resolver("administer_dose", {"dose_mg": bad_dose})

    def test_cost_resolver_rejects_conflicting_fields_and_non_mg_units(self) -> None:
        with pytest.raises(ValueError, match="Conflicting clinical dose"):
            healthcare_cost_resolver(
                "administer_dose", {"dose_mg": 2.0, "concentration_delta": 5.0}
            )
        with pytest.raises(ValueError, match="Invalid clinical dose unit"):
            healthcare_cost_resolver("administer_dose", {"dose_mg": 2.0, "unit": "g"})


class TestSerumConcentrationBarrierPolarity:
    def test_headroom_polarity_depletes_toward_toxic_ceiling(self) -> None:
        barrier = SerumConcentrationBarrier()
        # Toxic ceiling 20.0 - baseline 5.0 = 15.0 mg/L remaining headroom
        assert barrier.initial_state == pytest.approx(15.0)
        assert barrier.gamma == pytest.approx(0.4)

        assay = SimulatedSerumAssayProvider()
        snap_before = assay.fetch_snapshot_sync()
        assert snap_before.scalar == pytest.approx(15.0)
        assert snap_before.metadata["serum_concentration_mg_l"] == pytest.approx(5.0)

        assay.record_debit(3.0, debit_id="dose-1")
        snap_after = assay.fetch_snapshot_sync()
        assert snap_after.scalar == pytest.approx(12.0)
        assert snap_after.metadata["serum_concentration_mg_l"] == pytest.approx(8.0)

        cbf = ControlBarrierFunction(
            barrier, healthcare_cost_resolver, skip_epoch_seed=True
        )
        # Remaining headroom 15.0, floor 5.0 => h(x)=10.0, max single step gamma*10 = 4.0
        ok_safe, _ = cbf.verify_trajectory(
            [{"action": "administer_dose", "params": {"dose_mg": 3.5}}],
            initial_state=15.0,
        )
        assert ok_safe is True
        ok_toxic, recs = cbf.verify_trajectory(
            [{"action": "administer_dose", "params": {"dose_mg": 4.5}}],
            initial_state=15.0,
        )
        assert ok_toxic is False
        assert recs[0]["safe"] is False


class TestClinicalDoseActuatorSecurity:
    @pytest.mark.asyncio
    async def test_valid_clearance_verifies_seal_and_journals_assay_debit(self) -> None:
        assay = SimulatedSerumAssayProvider()
        actuator = ClinicalDoseActuator(ledger=assay)
        clearance = await _make_clinical_clearance()

        receipt = await actuator.actuate(clearance)
        assert receipt.accepted is True
        assert receipt.outcome is ActuationOutcome.ACCEPTED
        assert assay.fetch_snapshot_sync().scalar == pytest.approx(12.5)

    @pytest.mark.asyncio
    async def test_rejects_forged_seal_digest_mismatch_route_and_quorum(self) -> None:
        assay = SimulatedSerumAssayProvider()
        actuator = ClinicalDoseActuator(ledger=assay)

        # Forged seal string with matching sha256 digest -> fails verify_seal()
        forged = "forged-truthy-seal"
        r_forged = await actuator.actuate(
            await _make_clinical_clearance(seal=forged, digest=seal_digest(forged))
        )
        assert r_forged.accepted is False
        assert r_forged.outcome is ActuationOutcome.REJECTED
        assert r_forged.findings[0]["code"] == "INVALID_ROUTING_SEAL"

        # Digest mismatch
        r_digest = await actuator.actuate(
            await _make_clinical_clearance(digest="0" * 64)
        )
        assert r_digest.outcome is ActuationOutcome.REJECTED
        assert r_digest.findings[0]["code"] == "SEAL_DIGEST_MISMATCH"

        # Target route mismatch
        r_route = await actuator.actuate(
            await _make_clinical_clearance(target_route="https://rogue.example")
        )
        assert r_route.outcome is ActuationOutcome.REJECTED
        assert r_route.findings[0]["code"] == "TARGET_ROUTE_MISMATCH"

        # Quorum not met
        r_quorum = await actuator.actuate(
            await _make_clinical_clearance(
                required_quorum=2, approvals=[{"approver_urn": "op1"}]
            )
        )
        assert r_quorum.outcome is ActuationOutcome.REJECTED
        assert r_quorum.findings[0]["code"] == "QUORUM_NOT_MET"
        assert assay.fetch_snapshot_sync().scalar == pytest.approx(15.0)

    @pytest.mark.asyncio
    async def test_assay_journal_failure_returns_unknown_and_settles_executed_true(
        self,
    ) -> None:
        broken_ledger = MagicMock()
        broken_ledger.record_debit.side_effect = RuntimeError("assay db timeout")
        actuator = ClinicalDoseActuator(ledger=broken_ledger)

        receipt = await actuator.actuate(await _make_clinical_clearance())
        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.findings[0]["code"] == "ASSAY_JOURNAL_FAILED"

        governor = MagicMock()
        governor.settle = AsyncMock(return_value=[])
        governor.components.execution_ledger = ExecutionLedger(None)
        dose_key = str(uuid.uuid4())
        params = {
            **DoseOrder(
                patient_id="P-101",
                medication="vancomycin",
                dose_mg=2.0,
                idempotency_key=dose_key,
            ).model_dump(),
            "confidence": 0.99,
        }
        real_seal = await generate_seal("administer_dose", params, record_hash="e" * 64)
        with (
            patch(
                "src.cage_healthcare.tools.tool_provider.enforce_governance",
                AsyncMock(
                    return_value=SealedAction("administer_dose", real_seal, params)
                ),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.verify_and_consume_seal",
                AsyncMock(return_value=None),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.get_actuator_registry",
                return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
            ),
            patch(
                "src.gateway.governance.execution_actuator.ingest_actuation_receipt",
                AsyncMock(),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider._gm.record_refusal",
                new_callable=AsyncMock,
            ) as mock_refuse,
        ):
            res = await administer_dose_action(
                patient_id="P-101",
                medication="vancomycin",
                dose_mg=2.0,
                idempotency_key=dose_key,
                governor=governor,
            )
        assert isinstance(res, CommitOutcome)
        assert res.status is CommitStatus.INDETERMINATE
        assert "indeterminate" in res.message.lower()
        mock_refuse.assert_not_awaited()
        governor.settle.assert_awaited_once_with(real_seal, executed=True)


class _RecordingClinicalActuator(ClinicalDoseActuator):
    """The real clinical actuator, keeping every clearance it is handed."""

    def __init__(self) -> None:
        super().__init__(ledger=SimulatedSerumAssayProvider())
        self.clearances: list[ExecutionClearance] = []

    async def actuate(self, c: ExecutionClearance) -> Any:
        self.clearances.append(c)
        return await super().actuate(c)


class TestAdministerDoseActuatesTheSealedParams:
    """The dose tool verifies, digests and actuates ``SealedAction.params``."""

    _DOSE_KEY = "a4a4a4a4-1111-4222-8333-444444444444"

    @classmethod
    def _caller_params(cls) -> dict[str, Any]:
        order = DoseOrder(
            patient_id="P-101",
            medication="vancomycin",
            dose_mg=2.0,
            idempotency_key=cls._DOSE_KEY,
        )
        return {**order.model_dump(), "confidence": 0.99}

    @pytest.mark.asyncio
    async def test_seal_digest_and_clearance_name_the_evaluated_params(self) -> None:
        """The committing run's evaluated params, never the caller's dict, are used.

        The seal is minted over evaluated params that differ from the dict the
        tool hands governance (a server-bound input was added). The real
        clinical actuator re-verifies the seal against the clearance params,
        so the dose is only governed if the clearance names the evaluated
        params.
        """
        evaluated = {**self._caller_params(), "renal_clearance_ml_min": 85.0}
        seal = await generate_seal("administer_dose", evaluated, record_hash="e" * 64)
        actuator = _RecordingClinicalActuator()
        verify = AsyncMock(return_value=None)
        enforce = AsyncMock(
            return_value=SealedAction("administer_dose", seal, evaluated)
        )
        governor = MagicMock(settle=AsyncMock(return_value=[]))
        governor.components.execution_ledger = ExecutionLedger(None)

        with (
            patch(
                "src.cage_healthcare.tools.tool_provider.enforce_governance", enforce
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.verify_and_consume_seal",
                verify,
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.get_actuator_registry",
                return_value=MagicMock(get_actuator=MagicMock(return_value=actuator)),
            ),
            patch(
                "src.gateway.governance.execution_actuator.ingest_actuation_receipt",
                AsyncMock(),
            ),
        ):
            res = await administer_dose_action(
                patient_id="P-101",
                medication="vancomycin",
                dose_mg=2.0,
                idempotency_key=self._DOSE_KEY,
                governor=governor,
            )

        assert res.status is CommitStatus.EXECUTED, res
        handed = enforce.await_args.args[2]
        assert handed == self._caller_params()
        verify.assert_awaited_once_with(seal, "administer_dose", evaluated)
        (clearance,) = actuator.clearances
        assert clearance.params == evaluated
        assert clearance.routing_seal == seal
        assert clearance.governance_decision_digest == seal_digest(seal)
        assert (
            clearance.opa_input_digest
            == hashlib.sha256(
                json.dumps(evaluated, sort_keys=True).encode()
            ).hexdigest()
        )
        governor.settle.assert_awaited_once_with(seal, executed=True)

    @pytest.mark.asyncio
    async def test_refusal_names_the_evaluated_params(self) -> None:
        """An invalid seal is refused (AC-3) naming the evaluated params."""
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation

        evaluated = {**self._caller_params(), "renal_clearance_ml_min": 85.0}
        governor = MagicMock(settle=AsyncMock(return_value=[]))
        governor.components.execution_ledger = ExecutionLedger(None)

        with (
            patch(
                "src.cage_healthcare.tools.tool_provider.enforce_governance",
                AsyncMock(
                    return_value=SealedAction("administer_dose", "seal-x", evaluated)
                ),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.verify_and_consume_seal",
                AsyncMock(
                    side_effect=SymbolicGovernorViolation(
                        "nonce already consumed", action="administer_dose"
                    )
                ),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider._gm.record_refusal",
                new_callable=AsyncMock,
                return_value="",
            ) as refuse,
        ):
            res = await administer_dose_action(
                patient_id="P-101",
                medication="vancomycin",
                dose_mg=2.0,
                idempotency_key=self._DOSE_KEY,
                governor=governor,
            )

        assert res.status is CommitStatus.REFUSED
        refuse.assert_awaited_once()
        assert refuse.await_args.kwargs["params"] == evaluated
        assert refuse.await_args.kwargs["oscal_control_ref"] == "AC-3"
        governor.settle.assert_awaited_once_with("seal-x", executed=False)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "governed",
        [
            "bare-seal-string",
            SealedAction("administer_dose", "", {"dose_mg": 2.0}),
            SealedAction("administer_dose", "seal-x", None),  # type: ignore[arg-type]
        ],
        ids=["bare-seal", "empty-seal", "no-params"],
    )
    async def test_a_result_without_seal_and_params_fails_closed(
        self, governed: Any
    ) -> None:
        from src.gateway.governance.routing_seal import SymbolicGovernorViolation

        governor = MagicMock(settle=AsyncMock(return_value=[]))
        governor.components.execution_ledger = ExecutionLedger(None)
        verify = AsyncMock(return_value=None)

        with (
            patch(
                "src.cage_healthcare.tools.tool_provider.enforce_governance",
                AsyncMock(return_value=governed),
            ),
            patch(
                "src.cage_healthcare.tools.tool_provider.verify_and_consume_seal",
                verify,
            ),
            pytest.raises(SymbolicGovernorViolation, match="No seal"),
        ):
            await administer_dose_action(
                patient_id="P-101",
                medication="vancomycin",
                dose_mg=2.0,
                idempotency_key=self._DOSE_KEY,
                governor=governor,
            )

        verify.assert_not_awaited()
        governor.settle.assert_not_awaited()
