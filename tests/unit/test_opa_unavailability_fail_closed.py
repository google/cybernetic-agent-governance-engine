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

"""Red-before-green fail-closed and taxonomy tests for POAM-2026-233.

Proves two coupled invariants whenever OPA (or a Phase-2 dependency) is
unreachable, times out, returns 5xx/malformed JSON, or returns an undefined
decision document:
  1. Blocking stays strictly fail-closed: no ALLOW/NARROW, no routing seal,
     Phase 2 skipped on Phase-1 outage, and prior Phase-2 reservations rolled
     back on Phase-2 outage.
  2. Evidence and HTTP surfaces record infrastructure unavailability rather
     than fabricating a KMS-signed policy refusal: ``GOVERNANCE_INFRASTRUCTURE_BLOCK``
     event, ``cage_governance_infrastructure_blocks_total`` counter, HTTP 503
     without ``Retry-After`` or ``proof_hash``, zero ``GOVERNANCE_REFUSAL`` /
     ``GOVERNANCE_REFUSAL_RECEIPT`` records, and zero KMS refusal signatures.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry

import src.gateway.governance.contracts as _contracts
import src.gateway.governance.governor.errors as _gov_errors
from src.gateway.core.policy import BreakerState, OPAClient
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    ReadOnlyTier,
    RefusalReceipt,
    Violation,
    ViolationKind,
)
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.metrics import (
    governor_metrics,
    track_gated_request,
    was_request_refused,
)
from src.gateway.server.governance_middleware import (
    enforce_governance,
    get_last_refusal_proof_hash,
    governance_app,
    set_last_refusal_proof_hash,
)
from tests.fixtures.governor import make_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _SpyMutatingBarrier(MutatingTier):
    """Mutating Phase-2 barrier that records commit/preview/rollback calls."""

    order = 10

    def __init__(
        self, name: str = "spy_barrier", *, fail_infra_on_commit: bool = False
    ) -> None:
        self._tier_name = name
        self.commit_calls = 0
        self.preview_calls = 0
        self.rollback_calls = 0
        self.confirm_calls = 0
        self._fail_infra_on_commit = fail_infra_on_commit

    @property
    def tier_name(self) -> str:
        return self._tier_name

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in ("execute_trade", "governed_op")

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        self.preview_calls += 1
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        self.commit_calls += 1
        if self._fail_infra_on_commit:
            infra_kind = getattr(ViolationKind, "INFRASTRUCTURE", None)
            assert infra_kind is not None, "ViolationKind.INFRASTRUCTURE missing"
            return (
                [
                    Violation(
                        tier=self.tier_name,
                        code="REDIS_BARRIER_UNAVAILABLE",
                        message="Barrier state store unreachable",
                        kind=infra_kind,
                    )
                ],
                None,
            )
        return [], CommitReceipt(tier=self.tier_name, magnitude=1.0, token="tok-1")

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.rollback_calls += 1

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.confirm_calls += 1


class _MemoryEvidenceSink:
    """In-memory synchronous evidence sink capturing every committed event."""

    def __init__(self) -> None:
        self._redis = object()
        self.is_running = True
        self.events: list[dict[str, Any]] = []

    async def ingest_sync(
        self, record: dict[str, Any], *, timeout_seconds: float | None = None
    ) -> Any:
        from types import SimpleNamespace

        self.events.append(dict(record))
        seq = len(self.events)
        return SimpleNamespace(
            hash="a" * 64,
            evidence_id=f"1700000000000-{seq}",
            sequence=seq,
        )

    def submit(self, record: dict[str, Any]) -> None:
        self.events.append(dict(record))

    def ingest(self, record: dict[str, Any]) -> None:
        self.events.append(dict(record))


def _make_mock_http_client(
    *,
    exc: Exception | None = None,
    status_code: int = 200,
    json_body: Any = None,
    raw_text: str | None = None,
) -> MagicMock:
    client = MagicMock()
    client.is_closed = False
    if exc is not None:
        client.post = AsyncMock(side_effect=exc)
        return client
    response = MagicMock()
    response.status_code = status_code
    if raw_text is not None:
        response.json.side_effect = ValueError("No JSON object could be decoded")
    else:
        response.json.return_value = json_body
    client.post = AsyncMock(return_value=response)
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "client_kwargs", "expected_reason"),
    [
        (
            "connect_error",
            {"exc": httpx.ConnectError("OPA connection refused")},
            "SYSTEM_FAILURE",
        ),
        (
            "read_timeout",
            {"exc": httpx.ReadTimeout("OPA timed out")},
            "SYSTEM_FAILURE",
        ),
        (
            "pool_timeout",
            {"exc": httpx.PoolTimeout("Pool exhausted")},
            "LOCAL_POOL_SATURATED",
        ),
        (
            "local_protocol_error",
            {"exc": httpx.LocalProtocolError("Bad header")},
            "LOCAL_MISCONFIGURATION",
        ),
        (
            "http_503",
            {"status_code": 503, "json_body": {"error": "unavailable"}},
            "SYSTEM_FAILURE",
        ),
        (
            "http_429",
            {"status_code": 429, "json_body": {"error": "throttled"}},
            "SYSTEM_FAILURE",
        ),
        (
            "http_400",
            {"status_code": 400, "json_body": {"code": "bad_request"}},
            "OPA_REJECTED",
        ),
        (
            "malformed_json",
            {"status_code": 200, "raw_text": "<<<not-json>>>"},
            "MALFORMED_RESPONSE",
        ),
        (
            "non_object_json",
            {"status_code": 200, "json_body": ["ALLOW"]},
            "MALFORMED_RESPONSE",
        ),
        (
            "undefined_decision_missing_result",
            {"status_code": 200, "json_body": {}},
            "UNDEFINED_DECISION",
        ),
        (
            "undefined_decision_empty_result_dict",
            {"status_code": 200, "json_body": {"result": {}}},
            "UNDEFINED_DECISION",
        ),
        (
            "ambiguous_conflicting_result_dict",
            {
                "status_code": 200,
                "json_body": {"result": {"allow": True, "decision": "DENY"}},
            },
            "UNDEFINED_DECISION",
        ),
    ],
)
async def test_opa_client_raises_unavailable_across_all_outage_modes(
    label: str,
    client_kwargs: dict[str, Any],
    expected_reason: str,
) -> None:
    opa = OPAClient(package="cage.finance.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(**client_kwargs)  # type: ignore[method-assign]

    err_cls = getattr(_contracts, "PolicyEngineUnavailableError", None)
    assert err_cls is not None, "PolicyEngineUnavailableError missing from contracts"

    with pytest.raises(err_cls) as exc_info:
        await opa.evaluate_policy({"action": "execute_trade", "amount": 100})

    assert exc_info.value.reason == expected_reason, label


@pytest.mark.asyncio
async def test_opa_client_circuit_breaker_opens_and_raises_unavailable() -> None:
    opa = OPAClient(package="cage.finance.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
        exc=httpx.ConnectError("OPA killed")
    )

    err_cls = getattr(_contracts, "PolicyEngineUnavailableError", None)
    assert err_cls is not None, "PolicyEngineUnavailableError missing from contracts"

    for _ in range(opa.cb.failure_threshold):
        with pytest.raises(err_cls):
            await opa.evaluate_policy({"action": "execute_trade"})

    assert opa.cb.state == BreakerState.OPEN

    with pytest.raises(err_cls) as open_exc:
        await opa.evaluate_policy({"action": "execute_trade"})
    assert open_exc.value.reason == "CIRCUIT_BREAKER_OPEN"

    with pytest.raises(err_cls) as budget_exc:
        await opa.evaluate_policy(
            {"action": "execute_trade"},
            current_latency_ms=opa.cb.max_latency_budget + 500.0,
        )
    assert budget_exc.value.reason == "LATENCY_BUDGET_EXCEEDED"


@pytest.mark.asyncio
async def test_govern_with_opa_down_blocks_fail_closed_and_emits_infra_event() -> None:
    opa = OPAClient(package="cage.test.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
        exc=httpx.ConnectError("OPA sidecar unreachable")
    )

    spy_barrier = _SpyMutatingBarrier()
    governor = make_governor(opa=opa, domain_tiers=[spy_barrier])

    sink = _MemoryEvidenceSink()
    reg = CollectorRegistry()
    metrics = governor_metrics(reg)
    signer = MagicMock()
    signer.sign_async = AsyncMock(return_value="sig-should-never-be-called")
    set_last_refusal_proof_hash(None)

    infra_err_cls = getattr(_gov_errors, "GovernanceInfrastructureError", None)
    assert infra_err_cls is not None, "GovernanceInfrastructureError missing"

    with (
        patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            return_value=signer,
        ),
        patch(
            "src.gateway.governance.governor.verdicts.governor_metrics",
            return_value=metrics,
        ),
        track_gated_request(),
    ):
        with pytest.raises(infra_err_cls) as exc_info:
            await enforce_governance(
                governor,
                "execute_trade",
                {"symbol": "AAPL", "quantity": 10, "confidence": 0.99},
            )
        assert isinstance(exc_info.value, GovernanceError)
        assert exc_info.value.receipt is None
        assert exc_info.value.dependency == "opa"
        assert exc_info.value.failure_code == "OPA_UNAVAILABLE"
        assert not was_request_refused()

    # 1. Strictly fail-closed: Phase 2 never ran, no seal minted, no KMS refusal signed.
    assert spy_barrier.commit_calls == 0
    assert spy_barrier.preview_calls == 0
    assert signer.sign_async.await_count == 0
    assert get_last_refusal_proof_hash() is None

    # 2. Evidence records infrastructure block, NEVER a policy refusal.
    event_types = [e.get("type") for e in sink.events]
    assert "GOVERNANCE_INFRASTRUCTURE_BLOCK" in event_types
    assert "GOVERNANCE_REFUSAL" not in event_types
    assert "GOVERNANCE_REFUSAL_RECEIPT" not in event_types

    infra_event = next(
        e for e in sink.events if e.get("type") == "GOVERNANCE_INFRASTRUCTURE_BLOCK"
    )
    assert infra_event["dependency"] == "opa"
    assert infra_event["failure_code"] == "OPA_UNAVAILABLE"
    assert infra_event["action"] == "execute_trade"
    assert len(infra_event["params_hash"]) == 64
    assert "proof_hash" not in infra_event

    # 3. Refusal counter stays 0; infrastructure-block counter increments.
    refusal_samples = [
        s.value
        for m in reg.collect()
        if m.name == "cage_governance_refusals"
        for s in m.samples
        if s.name == "cage_governance_refusals_total"
    ]
    assert sum(refusal_samples) == 0.0

    infra_samples = [
        s.value
        for m in reg.collect()
        if m.name == "cage_governance_infrastructure_blocks"
        for s in m.samples
        if s.name == "cage_governance_infrastructure_blocks_total"
        and s.labels == {"dependency": "opa", "code": "OPA_UNAVAILABLE"}
    ]
    assert infra_samples == [1.0]

    # 4. Emitted GOVERNANCE_TRACE conforms to proof/trace_conformance.py.
    from proof.trace_conformance import check_trace

    trace_events = [e for e in sink.events if e.get("type") == "GOVERNANCE_TRACE"]
    assert len(trace_events) == 1
    assert trace_events[0]["verdict"] == "INFRASTRUCTURE_BLOCK"
    assert trace_events[0]["phase"] == "CHECKING"
    assert trace_events[0]["seal_present"] is False
    assert check_trace(trace_events) == []


@pytest.mark.asyncio
async def test_phase2_infra_failure_rolls_back_earlier_commit_and_blocks() -> None:
    stage1 = _SpyMutatingBarrier("cbf_stage1", fail_infra_on_commit=False)
    stage1.order = 10

    stage2 = _SpyMutatingBarrier("fiscal_stage2", fail_infra_on_commit=True)
    stage2.order = 20

    governor = make_governor(core_stages=(), domain_tiers=[stage1, stage2])
    sink = _MemoryEvidenceSink()
    infra_err_cls = getattr(_gov_errors, "GovernanceInfrastructureError", None)
    assert infra_err_cls is not None, "GovernanceInfrastructureError missing"

    with patch(
        "src.gateway.governance.evidence.stream.get_evidence_sink",
        return_value=sink,
    ):
        with pytest.raises(infra_err_cls) as exc_info:
            await governor.govern(
                "execute_trade",
                {"symbol": "AAPL", "quantity": 5, "confidence": 0.99},
            )

    assert stage1.commit_calls == 1
    assert stage1.rollback_calls == 1
    assert stage2.commit_calls == 1
    assert exc_info.value.receipt is None
    assert [
        e["type"]
        for e in sink.events
        if e["type"] in ("GOVERNANCE_REFUSAL", "GOVERNANCE_INFRASTRUCTURE_BLOCK")
    ] == ["GOVERNANCE_INFRASTRUCTURE_BLOCK"]


def test_validate_action_endpoint_returns_typed_503_without_proof_hash_when_opa_down() -> (
    None
):
    opa = OPAClient(package="cage.test.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
        exc=httpx.ConnectError("OPA killed")
    )

    spy_barrier = _SpyMutatingBarrier()
    governor = make_governor(opa=opa, domain_tiers=[spy_barrier])
    sink = _MemoryEvidenceSink()
    signer = MagicMock()
    signer.sign_async = AsyncMock(return_value="sig-must-not-run")

    with (
        patch(
            "src.gateway.server.governance_middleware.governor_of",
            return_value=governor,
        ),
        patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.server.governance_middleware.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.server.governance_middleware.get_governance_signer",
            return_value=signer,
        ),
    ):
        client = TestClient(governance_app)
        resp = client.post(
            "/validate-action",
            json={
                "action": "execute_trade",
                "params": {"symbol": "AAPL", "quantity": 10, "confidence": 0.99},
            },
        )

    assert resp.status_code == 503
    assert "Retry-After" not in resp.headers
    body = resp.json()
    assert body["error"] == "policy_engine_unavailable"
    assert body["dependency"] == "opa"
    assert body["failure_code"] == "OPA_UNAVAILABLE"
    assert "retry_after_seconds" not in body
    assert "proof_hash" not in body
    assert "refusal_receipt" not in body
    assert "verdict" not in body
    assert signer.sign_async.await_count == 0
    assert any(e.get("type") == "GOVERNANCE_INFRASTRUCTURE_BLOCK" for e in sink.events)
    assert not any(
        e.get("type") in ("GOVERNANCE_REFUSAL", "GOVERNANCE_REFUSAL_RECEIPT")
        for e in sink.events
    )


class _AlwaysHardReadOnlyTier(ReadOnlyTier):
    """Phase-1 read-only tier that deterministically emits a HARD domain violation."""

    order = 10

    @property
    def tier_name(self) -> str:
        return "cbf_margin"

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return [
            Violation(
                tier="cbf_margin",
                code="CBF_MARGIN_BREACH",
                message="Margin ceiling exceeded",
                kind=ViolationKind.HARD,
            )
        ]


@pytest.mark.asyncio
async def test_hard_plus_opa_unavailable_signs_v5_receipt_with_skipped_opa_stage() -> (
    None
):
    """When HARD short-circuits before unreachable OPA (or co-occurs), v5 RefusalReceipt attests exact stage coverage."""
    opa = OPAClient(package="cage.test.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
        exc=httpx.ConnectError("OPA unreachable during concurrent HARD check")
    )

    stpa_validator = MagicMock()
    stpa_validator.validate.return_value = [
        Violation(
            tier="stpa",
            code="STPA_UCA_TEST",
            message="UCA test breach",
            kind=ViolationKind.HARD,
        )
    ]
    hard_tier = _AlwaysHardReadOnlyTier()
    spy_barrier = _SpyMutatingBarrier()
    governor = make_governor(
        opa=opa,
        stpa_validator=stpa_validator,
        domain_tiers=[hard_tier, spy_barrier],
    )
    sink = _MemoryEvidenceSink()

    with patch(
        "src.gateway.governance.evidence.stream.get_evidence_sink",
        return_value=sink,
    ):
        with pytest.raises(GovernanceError) as exc_info:
            await governor.govern(
                "execute_trade",
                {"symbol": "AAPL", "quantity": 10, "confidence": 0.99},
            )

    assert not isinstance(exc_info.value, _gov_errors.GovernanceInfrastructureError)
    receipt = exc_info.value.receipt
    assert receipt is not None
    assert receipt.schema_version == "v5"
    assert receipt.evaluated_stages == (("ftra", "FAIL"), ("stpa", "FAIL"))
    assert "opa" in receipt.skipped_stages
    assert "cbf_margin" in receipt.skipped_stages
    assert receipt.verify_proof_hash() is True

    gov_refusals = [e for e in sink.events if e.get("type") == "GOVERNANCE_REFUSAL"]
    assert len(gov_refusals) == 1
    worm_rec = dict(gov_refusals[0]["receipt"])  # type: ignore[arg-type]
    assert worm_rec["schema_version"] == "v5"
    assert "opa" in worm_rec["skipped_stages"]
    assert worm_rec["evaluated_stages"] == [["ftra", "FAIL"], ["stpa", "FAIL"]]
    assert RefusalReceipt.from_worm_dict(worm_rec).verify_proof_hash() is True

    # Also verify co-occurring INFRASTRUCTURE + HARD excludes INFRASTRUCTURE from policy tier_failures
    from src.gateway.governance.contracts import GovernanceTierFailure
    from src.gateway.governance.governor.verdicts import build_refusal_receipt

    co_receipt = build_refusal_receipt(
        "execute_trade",
        {"symbol": "AAPL", "quantity": 10},
        [
            Violation(
                tier="governance",
                code="OPA_UNAVAILABLE",
                message="OPA down",
                kind=ViolationKind.INFRASTRUCTURE,
            ),
            Violation(
                tier="cbf_margin",
                code="CBF_MARGIN_BREACH",
                message="Margin ceiling exceeded",
                kind=ViolationKind.HARD,
            ),
        ],
        [
            GovernanceTierFailure(
                tier="governance",
                control_id="OPA_UNAVAILABLE",
                rule_description="OPA down",
            ),
            GovernanceTierFailure(
                tier="cbf_margin",
                control_id="CBF_MARGIN_BREACH",
                rule_description="Margin ceiling exceeded",
            ),
        ],
        evaluated_stages=(("opa", "INFRASTRUCTURE"), ("cbf_margin", "FAIL")),
        skipped_stages=("spy_barrier",),
    )
    assert [tf.control_id for tf in co_receipt.tier_failures] == ["CBF_MARGIN_BREACH"]
    assert co_receipt.violated_rule == "[CBF_MARGIN_BREACH] Margin ceiling exceeded"
    assert co_receipt.evaluated_stages == (
        ("opa", "INFRASTRUCTURE"),
        ("cbf_margin", "FAIL"),
    )
    assert co_receipt.verify_proof_hash() is True


@pytest.mark.asyncio
async def test_advisor_gateway_client_does_not_retry_503_validate_action() -> None:
    """GatewayClient.validate_action must not retry HTTP 503 policy_engine_unavailable."""
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        CageGatewayError,
        GatewayClient,
    )

    GatewayClient._instance = None
    try:
        mock_http = AsyncMock()
        mock_http.is_closed = False
        req = httpx.Request("POST", "http://localhost:8000/governance/validate-action")
        mock_http.post.return_value = httpx.Response(
            503,
            json={
                "error": "policy_engine_unavailable",
                "dependency": "opa",
                "failure_code": "OPA_UNAVAILABLE",
                "message": "OPA unreachable",
            },
            request=req,
        )

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = GatewayClient()
            with pytest.raises((httpx.HTTPStatusError, CageGatewayError)) as exc_info:
                await client.validate_action(
                    "execute_trade",
                    {"symbol": "AAPL", "quantity": 10},
                    policy_version_id="sha256:pinned",
                )

        assert "503" in str(exc_info.value)
        assert mock_http.post.call_count == 1
    finally:
        GatewayClient._instance = None


@pytest.mark.asyncio
async def test_revalidate_post_hitl_preserves_approval_when_opa_unavailable() -> None:
    """Post-HITL OPA outage raises GovernanceInfrastructureError without spending the human approval."""
    from src.gateway.governance.governor.approval import PostHitlApproval

    opa = OPAClient(package="cage.test.policy")
    opa._endpoint = ("http://127.0.0.1:8181", None)
    opa._endpoint_error = None
    opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
        exc=httpx.ConnectError("OPA unreachable during post-HITL redemption")
    )

    spy_barrier = _SpyMutatingBarrier()
    governor = make_governor(opa=opa, domain_tiers=[spy_barrier])
    sink = _MemoryEvidenceSink()
    spend_mock = AsyncMock(return_value=True)
    covers_mock = MagicMock(return_value=True)
    approval = PostHitlApproval(
        approval_id="appr-233",
        barrier_preview="PASS",
        spend=spend_mock,
        covers=covers_mock,
        thread_id="thread-233",
        approved_holds=frozenset({("governance", "OPA_MANUAL_REVIEW")}),
    )
    # No server input binds anything for execute_trade here, so the evaluated
    # params the approval is checked and spent against are the request.
    evaluated = {"symbol": "AAPL", "quantity": 10, "confidence": 0.99}

    with (
        patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=sink,
        ),
        patch(
            "src.gateway.governance.governor.sealing.issue_seal",
            new_callable=AsyncMock,
            return_value="seal-233",
        ),
    ):
        with pytest.raises(_gov_errors.GovernanceInfrastructureError) as exc_info:
            await governor.revalidate_post_hitl(
                "execute_trade",
                {"symbol": "AAPL", "quantity": 10, "confidence": 0.99},
                approval=approval,
            )

        assert exc_info.value.dependency == "opa"
        assert exc_info.value.failure_code == "OPA_UNAVAILABLE"
        assert spend_mock.await_count == 0
        # Coverage was checked (side-effect free) before any stage ran.
        covers_mock.assert_called_once_with(evaluated)
        assert spy_barrier.commit_calls == 0
        assert not any(e.get("type") == "GOVERNANCE_REFUSAL" for e in sink.events)
        assert any(
            e.get("type") == "GOVERNANCE_INFRASTRUCTURE_BLOCK" for e in sink.events
        )

        # Once OPA recovers, the exact same unspent approval redeems and mints a seal.
        opa._get_client = lambda: _make_mock_http_client(  # type: ignore[method-assign]
            status_code=200, json_body={"result": "ALLOW"}
        )
        governed = await governor.revalidate_post_hitl(
            "execute_trade",
            {"symbol": "AAPL", "quantity": 10, "confidence": 0.99},
            approval=approval,
        )
        assert governed.seal == "seal-233"
        assert governed.params == evaluated
        assert spend_mock.await_count == 1
        # Spent exactly for the evaluated params the seal commits to.
        spend_mock.assert_awaited_once_with(evaluated)
        assert spy_barrier.commit_calls == 1


@pytest.mark.asyncio
async def test_mcp_execute_tool_returns_503_on_governance_infrastructure_error() -> (
    None
):
    """MCP /tools/execute returns HTTP 503 ERROR without proof_hash when GovernanceInfrastructureError is raised."""
    import json
    from types import SimpleNamespace

    from starlette.requests import Request

    from src.gateway.server import mcp_tool_server
    from src.gateway.server.rate_limit import RateLimitVerdict

    async def _infra_failing_tool(**_kwargs: Any) -> str:
        raise _gov_errors.GovernanceInfrastructureError(
            "OPA sidecar unreachable",
            dependency="opa",
            failure_code="OPA_UNAVAILABLE",
            error_code="policy_engine_unavailable",
        )

    fake_limiter = MagicMock()
    fake_limiter.check_request = AsyncMock(
        return_value=RateLimitVerdict(allowed=True, retry_after_seconds=0)
    )
    req = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/tools/execute",
            "headers": [],
            "client": ("10.0.0.5", 50000),
        }
    )

    with (
        patch(
            "src.gateway.server.workload_identity.extract_client_identity",
            return_value="spiffe://test/advisor",
        ),
        patch(
            "src.gateway.server.workload_identity.load_identity_policy",
            return_value=SimpleNamespace(trusted=frozenset({"spiffe://test/advisor"})),
        ),
        patch.object(
            mcp_tool_server,
            "get_shared_rate_limiter",
            return_value=fake_limiter,
        ),
        patch.object(
            mcp_tool_server.mcp._tool_manager,
            "list_tools",
            return_value=[
                SimpleNamespace(name="dummy_governed_tool", fn=_infra_failing_tool)
            ],
        ),
    ):
        resp = await mcp_tool_server.execute_tool_endpoint(
            mcp_tool_server.ToolExecutionRequest(
                tool_name="dummy_governed_tool", params={}
            ),
            req,
        )

    assert resp.status_code == 503
    assert resp["status"] == "ERROR"
    assert resp["error"] == "policy_engine_unavailable"
    assert resp["dependency"] == "opa"
    assert resp["failure_code"] == "OPA_UNAVAILABLE"
    payload = json.loads(bytes(resp.body))
    assert "proof_hash" not in payload
    assert "Retry-After" not in resp.headers
