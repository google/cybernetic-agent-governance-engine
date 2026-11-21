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

"""Refusal receipts fail closed when they cannot be signed.

``_emit_refusal_receipt`` used to log a signing failure and still commit the
``GOVERNANCE_REFUSAL_RECEIPT`` with ``kms_signature=""``, putting an unsigned
receipt into the tamper-evident chain. A signing failure now blocks as an
infrastructure outage (``GOVERNANCE_INFRASTRUCTURE_BLOCK``, ``dependency="kms"``,
HTTP 503) and nothing unsigned is committed. Only a non-enforcing posture with
no signer configured by design emits an unsigned receipt.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.gateway.governance.env_posture import DeploymentPosture
from src.gateway.governance.governor.errors import (
    GovernanceError,
    GovernanceInfrastructureError,
)
from src.gateway.governance.governor.verdicts import INFRASTRUCTURE_BLOCK_EVENT_TYPE
from src.gateway.server import governance_middleware as gm

pytestmark = [pytest.mark.unit, pytest.mark.local]

_RECEIPT_LABEL = "GOVERNANCE_REFUSAL_RECEIPT"


def _active_signer(**sign_async: Any) -> MagicMock:
    signer = MagicMock()
    signer.is_kms_active = True
    signer.sign_async = AsyncMock(**sign_async)
    return signer


def _inactive_signer() -> MagicMock:
    signer = MagicMock()
    signer.is_kms_active = False
    signer.sign_async = AsyncMock(side_effect=AssertionError("must not sign"))
    return signer


@contextmanager
def _harness(
    signer: MagicMock, posture: DeploymentPosture = DeploymentPosture.DEV
) -> Iterator[tuple[AsyncMock, MagicMock]]:
    """Patch the signer, posture, evidence sink and commit; yield (commit, metrics)."""
    sink = MagicMock()
    metrics = MagicMock()
    with (
        patch.object(gm, "get_governance_signer", return_value=signer),
        patch.object(gm, "get_evidence_sink", return_value=sink),
        patch.object(gm, "governor_metrics", return_value=metrics),
        patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.governance.env_posture.resolve_posture",
            return_value=posture,
        ),
        patch(
            "src.gateway.governance.evidence.stream.commit_decision_evidence",
            new=AsyncMock(),
        ) as commit,
    ):
        gm.set_last_refusal_proof_hash(None)
        yield commit, metrics


def _labels(commit: AsyncMock) -> list[str]:
    return [c.kwargs.get("label") for c in commit.await_args_list]


async def _emit() -> str:
    return await gm._emit_refusal_receipt(
        action_id="execute_trade",
        refusal_reason="[OPA_DENY] denied",
        oscal_control_ref="SC-4",
        params={"amount": 10},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_signature", ["", "   ", None, 123])
async def test_empty_or_non_string_signature_fails_closed(bad_signature: Any) -> None:
    with _harness(_active_signer(return_value=bad_signature)) as (commit, metrics):
        with pytest.raises(GovernanceInfrastructureError) as excinfo:
            await _emit()
    assert (excinfo.value.dependency, excinfo.value.failure_code) == (
        "kms",
        "KMS_SIGNING_UNAVAILABLE",
    )
    assert _labels(commit) == [INFRASTRUCTURE_BLOCK_EVENT_TYPE]
    assert gm.get_last_refusal_proof_hash() is None
    metrics.refusal_decided.assert_not_called()


@pytest.mark.asyncio
async def test_signer_exception_fails_closed_in_every_posture() -> None:
    for posture in (DeploymentPosture.DEV, DeploymentPosture.PRODUCTION):
        signer = _active_signer(side_effect=RuntimeError("KMS unavailable"))
        with _harness(signer, posture) as (commit, metrics):
            with pytest.raises(GovernanceInfrastructureError):
                await _emit()
        assert _labels(commit) == [INFRASTRUCTURE_BLOCK_EVENT_TYPE], posture
        metrics.refusal_decided.assert_not_called()


@pytest.mark.asyncio
async def test_enforcing_posture_without_active_signer_fails_closed() -> None:
    with _harness(_inactive_signer(), DeploymentPosture.PRODUCTION) as (commit, _m):
        with pytest.raises(GovernanceInfrastructureError) as excinfo:
            await _emit()
    assert excinfo.value.dependency == "kms"
    assert _labels(commit) == [INFRASTRUCTURE_BLOCK_EVENT_TYPE]


@pytest.mark.asyncio
async def test_non_enforcing_posture_without_signer_emits_unsigned_receipt() -> None:
    """The one exemption: no signer configured by design, outside enforcing postures."""
    with _harness(_inactive_signer(), DeploymentPosture.DEV) as (commit, metrics):
        proof_hash = await _emit()
    assert _labels(commit) == [_RECEIPT_LABEL]
    assert commit.await_args_list[0].args[0]["kms_signature"] == ""
    assert proof_hash and gm.get_last_refusal_proof_hash() == proof_hash
    metrics.refusal_decided.assert_called_once_with("MIDDLEWARE")


@pytest.mark.asyncio
async def test_signed_receipt_is_committed_then_counted_and_advertised() -> None:
    signer = _active_signer(return_value="sig-abc")
    with _harness(signer, DeploymentPosture.PRODUCTION) as (commit, metrics):
        proof_hash = await _emit()
    assert _labels(commit) == [_RECEIPT_LABEL]
    committed = commit.await_args_list[0].args[0]
    assert committed["kms_signature"] == "sig-abc"
    signed_subset = signer.sign_async.await_args.args[0]
    assert "kms_signature" not in signed_subset
    assert proof_hash and gm.get_last_refusal_proof_hash() == proof_hash
    metrics.refusal_decided.assert_called_once_with("MIDDLEWARE")


@pytest.mark.asyncio
async def test_record_refusal_propagates_signing_failure() -> None:
    signer = _active_signer(side_effect=RuntimeError("KMS unavailable"))
    with _harness(signer) as (commit, _m):
        with pytest.raises(GovernanceInfrastructureError):
            await gm.record_refusal(
                "execute_trade",
                "duplicate transaction_id",
                oscal_control_ref="AC-3",
                params={"transaction_id": "t-1"},
            )
    assert _RECEIPT_LABEL not in _labels(commit)


@pytest.mark.asyncio
async def test_enforce_governance_surfaces_block_not_refusal() -> None:
    """The action stays refused, but the caller sees an outage, not a signed 403."""
    from src.gateway.governance.governor.governor import SymbolicGovernor

    gov = MagicMock(spec=SymbolicGovernor)
    gov.govern = AsyncMock(side_effect=GovernanceError("[OPA_DENY] denied"))
    signer = _active_signer(side_effect=RuntimeError("KMS unavailable"))
    with _harness(signer) as (commit, _m):
        with pytest.raises(GovernanceInfrastructureError):
            await gm.enforce_governance(gov, "execute_trade", {"amount": 10})
    assert _RECEIPT_LABEL not in _labels(commit)


def test_validate_action_refusal_with_unsignable_receipt_returns_503() -> None:
    from src.gateway.governance.governor.governor import SymbolicGovernor

    gov = MagicMock(spec=SymbolicGovernor)
    gov.validate_action = AsyncMock(side_effect=GovernanceError("[OPA_DENY] denied"))
    signer = _active_signer(side_effect=RuntimeError("KMS unavailable"))
    previous = getattr(gm.governance_app.state, "governor", None)
    gm.governance_app.state.governor = gov
    try:
        with (
            _harness(signer) as (commit, _m),
            patch.object(gm, "GovernanceEnvelopeBuilder") as builder,
        ):
            resp = TestClient(gm.governance_app, raise_server_exceptions=False).post(
                "/validate-action",
                json={"action": "execute_trade", "params": {"amount": 10}},
            )
    finally:
        gm.governance_app.state.governor = previous

    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert (body["dependency"], body["failure_code"]) == (
        "kms",
        "KMS_SIGNING_UNAVAILABLE",
    )
    builder.assert_not_called()
    assert _RECEIPT_LABEL not in _labels(commit)
