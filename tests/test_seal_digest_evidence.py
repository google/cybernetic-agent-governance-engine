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

"""A routing seal never enters evidence; its SHA-256 digest does (POAM-2026-149).

Both domain tool providers used to pass the raw routing seal as
``ExecutionClearance.governance_decision_digest``. ``dispatch_actuation``
writes that field into every actuation receipt on the evidence stream, and the
stream's durable copy is WORM-retained, so a bearer credential written there
can never be redacted. These tests pin the three parts of the fix:

1. ``routing_seal.seal_digest`` is the only digest, and it is the decision
   trace's ``seal_ref``, so a seal's issuance and its actuation join on it.
2. ``ExecutionClearance`` refuses anything but a lowercase SHA-256 hex digest.
   A seal in the digest field fails at construction, in every domain.
3. Finance and healthcare record ``seal_digest(seal)``. The seal reaches the
   actuator only through the out-of-band ``routing_seal`` field.

Seals are minted by the production ``generate_seal`` in both formats: HMAC
(test/dev posture) and JWT (asymmetric, here a software Ed25519 key).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import src.gateway.governance.kms_signer as ks
import src.gateway.governance.routing_seal as rs
from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.ground_truth import SimulatedCashLedgerProvider
from src.cage_healthcare.tools.tool_provider import ClinicalDoseActuator
from src.gateway.governance.execution_actuator import ActuatorRegistry
from src.gateway.governance.governor.trace import seal_ref
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.governance.seams.ground_truth import InMemoryLedgerJournal
from tests.fixtures.trade_inputs import trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SINK = "src.gateway.governance.evidence.stream.get_evidence_sink"


@pytest.fixture(autouse=True)
def _test_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)


@pytest.fixture(params=["hmac", "jwt"])
async def seal(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """A real seal from ``generate_seal``, in each of its two formats."""
    provider = (
        ks.SoftwareEd25519Provider(key_id="seal-digest-k1")
        if request.param == "jwt"
        else None
    )
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=provider))
    minted = await rs.generate_seal(
        "execute_trade", {"symbol": "AAPL", "amount": 10.0}, record_hash="c" * 64
    )
    assert rs._is_jwt_seal(minted) is (request.param == "jwt")
    return minted


class _CapturingSink:
    """An evidence sink that keeps every record it is handed."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def ingest(self, event: dict[str, Any]) -> str:
        self.events.append(event)
        return f"{len(self.events)}-0"

    def only(self, event_type: str) -> dict[str, Any]:
        matching = [e for e in self.events if e.get("type") == event_type]
        assert len(matching) == 1, [e.get("type") for e in self.events]
        return matching[0]


def _assert_seal_absent(events: list[dict[str, Any]], seal: str) -> None:
    blob = json.dumps(events, default=str)
    assert seal not in blob, "a routing seal reached the evidence stream"


def _clearance(*, digest: Any, routing_seal: str | None = None) -> ExecutionClearance:
    return ExecutionClearance(
        thread_id="t-1",
        decision="ALLOW",
        decision_path="DIRECT",
        action="execute_trade",
        target="AAPL",
        operator_urn="agent_001",
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="t-1",
        correlation_id_source="THREAD_DERIVED",
        governance_decision_digest=digest,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        routing_seal=routing_seal,
    )


# ---------------------------------------------------------------------------
# 1. One digest, shared with the decision trace
# ---------------------------------------------------------------------------


async def test_seal_digest_is_sha256_and_the_trace_join_key(seal: str) -> None:
    digest = rs.seal_digest(seal)
    assert digest == hashlib.sha256(seal.encode()).hexdigest()
    assert digest == seal_ref(seal)


# ---------------------------------------------------------------------------
# 2. The clearance contract
# ---------------------------------------------------------------------------


async def test_clearance_refuses_a_seal_in_the_digest_field(seal: str) -> None:
    with pytest.raises(ValueError, match="SHA-256") as refused:
        _clearance(digest=seal, routing_seal=seal)
    # An echoed value would carry the seal into logs and receipt findings.
    assert seal not in str(refused.value)


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "A" * 64,  # uppercase hex
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "a" * 64 + "\n",  # passes a `^...$` regex, fails a full match
        None,
        64,
    ],
    ids=["empty", "upper", "short", "long", "non-hex", "newline", "none", "int"],
)
def test_clearance_refuses_any_non_digest(digest: Any) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        _clearance(digest=digest)


async def test_clearance_keeps_the_seal_out_of_its_serialised_forms(seal: str) -> None:
    clearance = _clearance(digest=rs.seal_digest(seal), routing_seal=seal)
    assert clearance.routing_seal == seal
    assert clearance.to_dict()["governance_decision_digest"] == rs.seal_digest(seal)
    assert seal not in json.dumps(clearance.to_dict())
    assert seal not in repr(clearance)


# ---------------------------------------------------------------------------
# 3. Both domains, end to end through dispatch_actuation
# ---------------------------------------------------------------------------


async def test_finance_records_the_digest_and_hands_the_broker_the_seal(
    seal: str,
) -> None:
    sink = _CapturingSink()
    ledger = SimulatedCashLedgerProvider(
        journal=InMemoryLedgerJournal(), settlement_lag_s=0.0
    )
    registry = ActuatorRegistry()
    registry.register(BrokerActuator(ledger=ledger), claims={"execute_trade"})
    broker_execute = AsyncMock(return_value="EXECUTED (mock): AAPL x 10.0 buy")
    from src.cage_finance.tools.tool_provider import execute_trade_action

    with ExitStack() as stack:
        for target, value in (
            (
                "src.cage_finance.tools.tool_provider.enforce_governance",
                AsyncMock(return_value=seal),
            ),
            (
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                AsyncMock(),
            ),
            ("src.gateway.infrastructure.redis_client.redis_client", None),
            (
                "src.cage_finance.tools.tool_provider.get_actuator_registry",
                MagicMock(return_value=registry),
            ),
            (
                "src.cage_finance.actuators.broker_actuator.execute_trade",
                broker_execute,
            ),
            (_SINK, MagicMock(return_value=sink)),
        ):
            stack.enter_context(patch(target, value))
        result = await execute_trade_action(
            symbol="AAPL",
            amount=10.0,
            currency="USD",
            confidence=0.99,
            governor=trade_governor(),
            transaction_id=str(uuid.uuid4()),
        )

    assert result.startswith("EXECUTED"), result
    # The broker re-checks the seal itself, never the digest.
    assert broker_execute.await_args.kwargs["routing_seal"] == seal
    receipt = sink.only("ACTUATION_RECEIPT")
    assert receipt["governance_decision_digest"] == rs.seal_digest(seal)
    _assert_seal_absent(sink.events, seal)


async def test_healthcare_records_the_digest_not_the_seal(seal: str) -> None:
    from src.cage_healthcare.tools import tool_provider as clinical

    sink = _CapturingSink()
    registry = ActuatorRegistry()
    registry.register(ClinicalDoseActuator(), claims={"administer_dose"})
    governor = MagicMock(settle=AsyncMock(return_value=[]))

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(clinical, "enforce_governance", AsyncMock(return_value=seal))
        )
        stack.enter_context(
            patch.object(clinical, "verify_and_consume_seal", AsyncMock())
        )
        stack.enter_context(
            patch.object(
                clinical, "get_actuator_registry", MagicMock(return_value=registry)
            )
        )
        stack.enter_context(patch(_SINK, MagicMock(return_value=sink)))
        result = await clinical.administer_dose_action(
            "patient-1", "heparin", 2.0, governor=governor
        )

    assert result["status"] == "GOVERNED", result
    receipt = sink.only("ACTUATION_RECEIPT")
    assert receipt["governance_decision_digest"] == rs.seal_digest(seal)
    _assert_seal_absent(sink.events, seal)
    governor.settle.assert_awaited_once_with(seal, executed=True)


async def test_clinical_actuator_refuses_a_clearance_without_its_seal() -> None:
    clearance = _clearance(digest=rs.seal_digest("seal-under-test"))
    clearance.executor_id = ClinicalDoseActuator.actuator_id
    receipt = await ClinicalDoseActuator().actuate(clearance)
    assert receipt.accepted is False
    assert receipt.findings == [{"code": "CLEARANCE_INVALID"}]
