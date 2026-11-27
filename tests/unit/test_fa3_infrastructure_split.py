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

"""Regression tests for FA-3 infrastructure vs. policy refusal split (POAM-2026-233)."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proof.stream_invariants import check_stream, compute_cage_audit_hash, jcs_bytes
from scripts.automated_auditor import TraceAuditor
from scripts.measure_paper_metrics import _classify_response
from src.eval_harness.harness import FoundationModelEvalHarness
from src.gateway.governance.contracts import RefusalReceipt, ViolationKind
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governor.errors import GovernanceInfrastructureError
from src.gateway.governance.governor.metrics import (
    track_gated_request,
    was_request_refused,
)
from src.gateway.governance.stpa_validator import UcaRule
from src.integrations.provider_02.adapter import (
    GraphTopology,
    ProjectBundleStepEntry,
    _classify_terminal_path,
    _is_gateway_error_step,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _synthetic_chain(
    events: list[dict[str, object]], *, chain_id: str = "fa3-chain"
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    prev_hash = ""
    for seq, event in enumerate(events):
        payload_json = jcs_bytes(event).decode("utf-8")
        event_type = str(event.get("type", "UNKNOWN"))
        control_id = str(event.get("controlId") or event.get("control_id") or "AC-3")
        trace_id = "0123456789abcdef0123456789abcdef"
        record_hash = compute_cage_audit_hash(
            prev_hash=prev_hash,
            sequence=seq,
            event_type=event_type,
            control_id=control_id,
            payload_json=payload_json,
            chain_id=chain_id,
            trace_id=trace_id,
        )
        records.append(
            {
                "schema": "cage-audit/3.0",
                "chain_id": chain_id,
                "sequence": str(seq),
                "timestamp_utc": "2026-10-29T12:00:00+00:00",
                "event_type": event_type,
                "control_id": control_id,
                "trace_id": trace_id,
                "hash_algorithm": "SHA-256",
                "canonicalization": "RFC8785",
                "evidence_class": "GOVERNANCE",
                "prev_hash": prev_hash,
                "record_hash": record_hash,
                "payload_json": payload_json,
            }
        )
        prev_hash = record_hash
    return records


def test_stpa_rule_exception_emits_infrastructure_violation() -> None:
    def _boom(_action: str, _params: dict[str, object]) -> None:
        raise RuntimeError("rule evaluator crashed")

    rule = UcaRule(
        uca_id="UCA-TEST-01",
        action="execute_trade",
        description="test",
        predicate=_boom,
    )
    [violation] = rule.evaluate("execute_trade", {"amount": 100.0})

    assert violation.tier == "stpa"
    assert violation.code == "STPA_ERROR"
    assert violation.kind == ViolationKind.INFRASTRUCTURE
    assert violation.infra_dependency == "stpa"
    assert violation.infra_error_code == "stpa_evaluation_error"


@pytest.mark.asyncio
async def test_generated_stpa_uca_exception_emits_infrastructure_violation() -> None:
    from src.cage_finance.stpa.uca_rules import GeneratedSTPAValidator

    bad_params = MagicMock()
    bad_params.get.side_effect = RuntimeError("corrupt param mapping")

    violation = GeneratedSTPAValidator()._check_uca_2("execute_trade", bad_params)

    assert violation is not None
    assert violation.code == "STPA_ERROR"
    assert violation.kind == ViolationKind.INFRASTRUCTURE
    assert violation.infra_dependency == "stpa"
    assert violation.infra_error_code == "stpa_evaluation_error"


@pytest.mark.asyncio
async def test_consensus_no_critics_returns_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance.consensus.engine import (
        CONSENSUS_NO_CRITICS_CONFIGURED,
        ConsensusGate,
    )
    from src.gateway.governance.feature_flags import (
        CAGE_CONSENSUS_CRITICS_ENABLED_ENV,
    )

    monkeypatch.setenv(CAGE_CONSENSUS_CRITICS_ENABLED_ENV, "true")
    gate = ConsensusGate(critics=())
    res = await gate.check_consensus("execute_trade", {}, magnitude=1e9)

    assert res["status"] == "UNAVAILABLE"
    assert res["decision"] == "UNAVAILABLE"
    assert res["reason_code"] == CONSENSUS_NO_CRITICS_CONFIGURED


@pytest.mark.asyncio
async def test_healthcare_administer_dose_propagates_infra_error_for_503() -> None:
    """POAM-2026-255 / DA-05: pre-dispatch infra error propagates (HTTP 503) without refusal."""
    from src.cage_healthcare.tools.tool_provider import administer_dose_action
    from src.gateway.governance.execution_idempotency import ExecutionLedger

    governor = MagicMock()
    governor.components.execution_ledger = ExecutionLedger(None)
    infra_err = GovernanceInfrastructureError(
        "Consensus backend down",
        dependency="consensus",
        failure_code="CONSENSUS_UNAVAILABLE",
        error_code="consensus_backend_unavailable",
    )

    with (
        patch(
            "src.cage_healthcare.tools.tool_provider.enforce_governance",
            AsyncMock(side_effect=infra_err),
        ),
        patch(
            "src.cage_healthcare.tools.tool_provider._gm.record_refusal",
            AsyncMock(),
        ) as mock_refusal,
        pytest.raises(GovernanceInfrastructureError) as exc_info,
    ):
        await administer_dose_action(
            patient_id="P001",
            medication="vancomycin",
            dose_mg=2.0,
            idempotency_key="55555555-5555-4555-8555-555555555555",
            governor=governor,
        )

    assert exc_info.value.error_code == "consensus_backend_unavailable"
    assert exc_info.value.dependency == "consensus"
    assert exc_info.value.failure_code == "CONSENSUS_UNAVAILABLE"
    mock_refusal.assert_not_awaited()


@pytest.mark.asyncio
async def test_mcp_evaluate_policy_error_returns_unavailable_without_refusal_mark(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.server import mcp_tool_server

    class _BrokenOpa:
        async def evaluate_policy(self, _payload: dict[str, object]) -> str:
            raise ConnectionError("OPA down")

    fake_gov = SimpleNamespace(components=SimpleNamespace(opa=_BrokenOpa()))
    monkeypatch.setattr(mcp_tool_server, "governor_of", lambda _app: fake_gov)

    with track_gated_request():
        out = await mcp_tool_server._evaluate_policy_internal(
            action="execute_trade", subject_role="analyst", amount=10.0
        )
        assert out.startswith("UNAVAILABLE:")
        assert was_request_refused() is False


def test_provider_02_excludes_infrastructure_block_from_cbf_block() -> None:
    topology = GraphTopology(
        nodes=frozenset({"analyst", "executor", "terminal"}),
        parent_edges={"executor": ["analyst"], "terminal": ["executor"]},
        terminal_node="terminal",
    )
    ts = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc).isoformat()
    for status in ("GATEWAY_ERROR", "INFRASTRUCTURE_BLOCK", "UNAVAILABLE"):
        step = ProjectBundleStepEntry(
            node_name="analyst",
            timestamp_utc=ts,
            signals={"safetyStatus": status},
            metadata={},
        )
        assert _is_gateway_error_step(step) is True
        assert _classify_terminal_path([step], topology) == "unknown"


def test_stream_invariants_reject_refusal_for_infra_code_and_validate_infra_event() -> (
    None
):
    bad_refusal = _synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            {
                "type": "GOVERNANCE_REFUSAL_RECEIPT",
                "proof_hash": "b" * 64,
                "violated_rule": "[CTRL_OPA] OPA_UNAVAILABLE: timeout",
            },
        ]
    )
    rules = {f.rule for f in check_stream(bad_refusal)}
    assert "refusal_evidence" in rules

    good_infra = _synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            {
                "type": "GOVERNANCE_INFRASTRUCTURE_BLOCK",
                "dependency": "opa",
                "failure_code": "OPA_UNAVAILABLE",
                "params_hash": "c" * 64,
                "detail": "OPA connection timed out",
            },
        ]
    )
    assert check_stream(good_infra) == []

    bad_infra = _synthetic_chain(
        [
            {"type": "GOVERNANCE_THRESHOLDS_LOADED", "thresholds_digest": "a" * 64},
            {
                "type": "GOVERNANCE_INFRASTRUCTURE_BLOCK",
                "dependency": "",
                "failure_code": "OPA_UNAVAILABLE",
                "params_hash": "c" * 64,
                "proof_hash": "d" * 64,
            },
        ]
    )
    bad_rules = {f.rule for f in check_stream(bad_infra)}
    assert "infrastructure_block" in bad_rules


@pytest.mark.asyncio
async def test_eval_harness_preserves_infrastructure_error_and_skips_in_dpo_harvest() -> (
    None
):
    fake_gov = MagicMock()
    fake_gov.validate_action = AsyncMock(
        return_value={
            "verdict": "INFRASTRUCTURE_BLOCK",
            "dependency": "opa",
            "failure_code": "OPA_UNAVAILABLE",
        }
    )
    harness = FoundationModelEvalHarness(governor=fake_gov)

    with pytest.raises(GovernanceInfrastructureError):
        await harness._evaluate_single("execute_trade", {"amount": 100.0}, {})

    infra_receipt = RefusalReceipt(
        thread_id="t-infra",
        action="execute_trade",
        violated_tier="opa",
        violated_rule="OPA_UNAVAILABLE: upstream 503",
        standing_at_refusal={},
        attempted_params={"amount": 100.0},
    )
    harvested = await harness.harvest_refusal_receipts(
        [infra_receipt], verify_receipt_hash=False
    )
    assert harvested == []


def test_automated_auditor_distinguishes_infrastructure_block() -> None:
    auditor = TraceAuditor()
    trace = {
        "trace_id": "trace-infra-1",
        "spans": [
            {
                "name": "governance.check",
                "start_time": 10,
                "end_time": 20,
                "attributes": {
                    "cage.verdict": "INFRASTRUCTURE_BLOCK",
                    "governance.decision": "INFRASTRUCTURE_BLOCK",
                },
            },
            {
                "name": "tool.execution",
                "start_time": 30,
                "end_time": 40,
                "attributes": {},
            },
        ],
    }
    auditor.audit_trace(trace)
    assert auditor.violations == [
        {
            "trace_id": "trace-infra-1",
            "reason": "Execution despite INFRASTRUCTURE_BLOCK",
        }
    ]


def test_measure_paper_metrics_classifies_infra_unavailability_as_crashed() -> None:
    assert (
        _classify_response(
            {},
            200,
            "Governance unavailable (gateway infrastructure error): ReadTimeout",
        )
        == "CRASHED"
    )
    assert (
        _classify_response(
            {},
            200,
            "Blocked by GOVERNANCE_INFRASTRUCTURE_BLOCK (opa)",
        )
        == "CRASHED"
    )
    assert GovernanceDecision.DENY.value == "DENY"
