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

"""Provider 02 ``stateHash`` is a gateway-issued, independently verifiable commitment.

Drives the real adapter through the HITL approval path with the real kernel
state-commitment service (in-process, recording evidence sink) and checks
that every emitted ``stateHash`` recomputes from a retained, PII-sanitized
preimage — and that nothing is emitted when a commitment fails.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.gateway.governance.evidence.state_commitment import verify_state_commitment
from src.gateway.governance.seams.state_commitment import (
    STATE_COMMITMENT_METHOD,
    StateCommitmentError,
)
from src.integrations.provider_02.adapter import (
    STATE_COMMITMENT_NAMESPACE,
    Provider02AttestationCallback,
    submit_attested_bundle,
)
from tests.integrations.provider_02.state_commitment_support import (
    InProcessCommitter,
    RecordingEvidenceSink,
    seal,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[3]
REVIEWER_EMAIL = "reviewer@example.com"


def _drive(cb: Provider02AttestationCallback) -> None:
    pre = {"risk_status": "approved", "loop_count": 1, "user_id": "u-1"}
    for node in (
        "nemo_guardrail",
        "thinker_node",
        "doer_node",
        "execution_analyst",
        "evaluator",
        "ftra_node",
        "safety_check",
    ):
        cb.on_chain_start(node, pre)
        cb.on_chain_end(node, pre)
    approved = {
        **pre,
        "approval_required": True,
        "approval_decision": {
            "approved": True,
            "reviewer": REVIEWER_EMAIL,
            "rationale": "within limits",
            "timestamp": "2026-10-04T12:00:00Z",
        },
    }
    cb.handle_hitl_interrupt(approved)
    for node in ("governed_trader", "explainer", "nemo_output_rail"):
        cb.on_chain_start(node, approved)
        cb.on_chain_end(node, approved)


def _callback(
    committer: Any, thread_id: str = "thread-1"
) -> Provider02AttestationCallback:
    return Provider02AttestationCallback(
        topology=FINANCIAL_ADVISOR_TOPOLOGY, committer=committer, thread_id=thread_id
    )


class TestSealedBundle:
    def test_every_state_hash_recomputes_from_a_retained_preimage(self) -> None:
        committer = InProcessCommitter()
        cb = _callback(committer)
        _drive(cb)
        seal(cb)
        bundle = cb.get_bundle()

        payloads = committer.sink.payloads
        assert len(payloads) == len(bundle.steps) == 7
        for step, payload_json in zip(bundle.steps, payloads, strict=True):
            assert verify_state_commitment(step.state_hash, payload_json)
            assert REVIEWER_EMAIL not in payload_json

    def test_steps_carry_exact_method_metadata(self) -> None:
        cb = _callback(InProcessCommitter())
        _drive(cb)
        seal(cb)
        for step in cb.get_bundle().to_dict()["steps"]:
            for key, value in STATE_COMMITMENT_METHOD.items():
                assert step["metadata"][key] == value

    def test_linkage_joins_steps_to_evidence(self) -> None:
        committer = InProcessCommitter()
        cb = _callback(committer)
        _drive(cb)
        seal(cb)
        bundle = cb.get_bundle()
        assert [lk.step_id for lk in committer.linkages] == [
            s.step_id for s in bundle.steps
        ]
        assert {lk.bundle_id for lk in committer.linkages} == {bundle.bundle_id}
        assert {lk.namespace for lk in committer.linkages} == {
            STATE_COMMITMENT_NAMESPACE
        }
        assert [lk.label for lk in committer.linkages] == [
            s.node_name for s in bundle.steps
        ]
        recorded = json.loads(committer.sink.payloads[3])
        assert recorded["linkage"]["label"] == "hitl_interrupt"


class TestFailClosed:
    def test_unsealed_bundle_is_refused(self) -> None:
        cb = _callback(InProcessCommitter())
        _drive(cb)
        assert not cb.is_sealed
        with pytest.raises(StateCommitmentError):
            cb.get_bundle()

    def test_chain_outage_emits_nothing_and_is_retryable(self) -> None:
        sink = RecordingEvidenceSink(fail=True)
        cb = _callback(InProcessCommitter(sink))
        _drive(cb)
        with pytest.raises(StateCommitmentError):
            seal(cb)
        with pytest.raises(StateCommitmentError):
            cb.get_bundle()
        assert all(step.state_hash == "" for step in cb._steps)

        sink.fail = False
        seal(cb)
        assert cb.is_sealed
        assert len(cb.get_bundle().steps) == 7

    def test_thread_id_outside_linkage_alphabet_fails_closed(self) -> None:
        cb = _callback(InProcessCommitter(), thread_id="thread/with/slashes")
        _drive(cb)
        with pytest.raises(StateCommitmentError):
            seal(cb)

    def test_forged_receipt_method_is_rejected(self) -> None:
        class _Forger(InProcessCommitter):
            async def commit_state(self, snapshot, *, linkage):  # type: ignore[no-untyped-def]
                receipt = await super().commit_state(snapshot, linkage=linkage)
                object.__setattr__(receipt, "method", {"stateHashAlg": "md5"})
                return receipt

        cb = _callback(_Forger())
        _drive(cb)
        with pytest.raises(StateCommitmentError):
            seal(cb)


class TestSubmitPath:
    def test_seals_before_registering(self) -> None:
        cb = _callback(InProcessCommitter())
        _drive(cb)
        client = AsyncMock()
        client.register_project_bundle.return_value = {"bundleHash": "x"}

        result = asyncio.run(submit_attested_bundle(cb, client))

        assert result == {"bundleHash": "x"}
        (submitted,), _ = client.register_project_bundle.call_args
        assert all(len(s["stateHash"]) == 64 for s in submitted["steps"])

    def test_commit_failure_submits_nothing(self) -> None:
        cb = _callback(InProcessCommitter(RecordingEvidenceSink(fail=True)))
        _drive(cb)
        client = AsyncMock()
        with pytest.raises(StateCommitmentError):
            asyncio.run(submit_attested_bundle(cb, client))
        client.register_project_bundle.assert_not_called()


class TestAdvisorHoldsNoStorage:
    """The advisor forwards snapshots; it never builds a cold store."""

    FORBIDDEN = {"get_cold_store", "EvidenceColdStore", "GcsColdStore", "NullColdStore"}

    def test_advisor_package_never_references_cold_storage(self) -> None:
        offenders: list[str] = []
        for path in (REPO_ROOT / "src" / "governed_financial_advisor").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                name = (
                    node.id
                    if isinstance(node, ast.Name)
                    else node.attr
                    if isinstance(node, ast.Attribute)
                    else None
                )
                if isinstance(node, ast.ImportFrom):
                    names = {a.name for a in node.names}
                    if (node.module or "").endswith(("cold_store", "evidence.factory")):
                        offenders.append(f"{path}: imports {node.module}")
                    names &= self.FORBIDDEN
                    offenders.extend(f"{path}: imports {n}" for n in names)
                elif name in self.FORBIDDEN:
                    offenders.append(f"{path}: references {name}")
        assert offenders == []

    def test_graph_factory_builds_per_run_callbacks_with_gateway_committer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.governed_financial_advisor.graph.graph import create_graph
        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )

        monkeypatch.setenv("PROVIDER_02_ATTESTATION_ENABLED", "true")
        factory = create_graph(None)._provider_02_callback_factory
        first, second = factory("thread-a"), factory("thread-b")
        assert first is not second
        assert isinstance(first._committer, GatewayClient)
        assert first._thread_id == "thread-a"
