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

"""Adversarial stress test suite for Milestone 2 Iteration 2 remediations.

Verifies:
1. SVID Case Evasion & Monotonic Epoch Gating across mixed-case, uppercase, whitespace,
   and diverse SPIFFE schemes in quarantine_actuator.py.
2. Ingress Epoch Gating in governance_middleware.py and mcp_tool_server.py:
   - Omitted x-cage-epoch header -> HTTP 403 missing_workload_epoch.
   - Malformed x-cage-epoch (letters, floats, NaN, negative, huge numbers) -> 403.
   - Stale epoch (< min_epoch) -> HTTP 403 stale_workload_epoch.
   - Current/forward epoch (>= min_epoch) -> pass.
3. MagicMock and JSON serialization safety in mcp_tool_server.py.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

from src.gateway.governance.arm_containment_ring import (
    ArmContainmentRing,
    ArmRole,
    advance_workload_epoch,
    get_workload_min_epoch,
)
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.quarantine_actuator import (
    InferenceProxySvidQuarantineActuator,
    QuarantineDirective,
    QuarantineReceipt,
    QuarantineTriggerReason,
    clear_local_quarantine_state,
    dispatch_quarantine,
    is_workload_quarantined,
    unquarantine_workload,
)
from src.gateway.governance.seams.actuation import ActuationOutcome, ReceiptVerification

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ===========================================================================
# 1. Adversarial Test 1: SVID Case Evasion & Whitespace Robustness
# ===========================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "quarantine_svid,query_svids",
    [
        (
            "spiffe://Cluster.Local/Ns/Agents/Sa/Victim-Agent-1",
            [
                "spiffe://cluster.local/ns/agents/sa/victim-agent-1",
                "SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/VICTIM-AGENT-1",
                "sPiFfE://cLuStEr.LoCaL/nS/aGeNtS/sA/vIcTiM-aGeNt-1",
                "  spiffe://Cluster.Local/Ns/Agents/Sa/Victim-Agent-1  ",
                "\tspiffe://cluster.local/ns/agents/sa/victim-agent-1\n",
            ],
        ),
        (
            "  spiffe://cluster.local/ns/agents/sa/Victim-Agent-Whitespace  ",
            [
                "spiffe://cluster.local/ns/agents/sa/victim-agent-whitespace",
                "SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/VICTIM-AGENT-WHITESPACE",
                "  spiffe://cluster.local/ns/agents/sa/victim-agent-whitespace  ",
            ],
        ),
        (
            "SPIFFE://PROD-VPC-1.CORP.INTERNAL/NS/FINANCE-SERVICES/SA/PAYMENT-DISPATCHER",
            [
                "spiffe://prod-vpc-1.corp.internal/ns/finance-services/sa/payment-dispatcher",
                "Spiffe://Prod-Vpc-1.Corp.Internal/Ns/Finance-Services/Sa/Payment-Dispatcher",
                "  spiffe://prod-vpc-1.corp.internal/ns/finance-services/sa/payment-dispatcher  ",
            ],
        ),
        (
            "spiffe://alpha.beta.gamma/ns/test/sa/agent_worker",
            [
                "SPIFFE://ALPHA.BETA.GAMMA/NS/TEST/SA/AGENT_WORKER",
                "  SPIFFE://alpha.beta.gamma/ns/test/sa/agent_worker  ",
                "sPiFfE://AlPhA.bEtA.gAmMa/Ns/TeSt/Sa/AgEnT_wOrKeR",
            ],
        ),
    ],
)
async def test_svid_case_and_whitespace_evasion_redis(quarantine_svid: str, query_svids: list[str], monkeypatch):
    """Assert 100% detection rate when querying quarantined SVID across diverse casings and whitespace with Redis."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    directive = QuarantineDirective(
        thread_id="t-adv-case-1",
        agent_svid=quarantine_svid,
        sandbox_id="sb-adv-case",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="c-adv-case",
        nonce=f"nonce-{time.time_ns()}",
        governance_decision_digest="8" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive, redis_client=redis_client)

    # All variations MUST be recognized as quarantined
    for query_svid in query_svids:
        is_quarantined = await is_workload_quarantined(agent_svid=query_svid, redis_client=redis_client)
        assert is_quarantined is True, f"Failed to detect quarantined SVID for variation: {query_svid!r}"


@pytest.mark.asyncio
async def test_svid_case_and_whitespace_evasion_local_fallback(monkeypatch):
    """Assert 100% detection rate in hermetic local fallback mode (redis_client is None)."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()

    svid_quarantine = "  spiffe://Cluster.Local/Ns/Agents/Sa/Local-Agent-Alpha  "
    actuator = InferenceProxySvidQuarantineActuator(redis_client=None)

    directive = QuarantineDirective(
        thread_id="t-local-adv",
        agent_svid=svid_quarantine,
        sandbox_id="sb-local-adv",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="c-local-adv",
        nonce="nonce-local-adv",
        governance_decision_digest="7" * 64,
        ttl_seconds=300,
    )
    receipt = await actuator.quarantine_workload(directive)
    assert receipt.quarantined is True

    test_queries = [
        "spiffe://cluster.local/ns/agents/sa/local-agent-alpha",
        "SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/LOCAL-AGENT-ALPHA",
        "sPiFfE://cLuStEr.LoCaL/nS/aGeNtS/sA/lOcAl-AgEnT-aLpHa",
        "  spiffe://cluster.local/ns/agents/sa/local-agent-alpha  ",
        "\tspiffe://cluster.local/ns/agents/sa/local-agent-alpha\n",
    ]
    for q in test_queries:
        assert await is_workload_quarantined(agent_svid=q, redis_client=None) is True, f"Local query failed for {q!r}"


@pytest.mark.asyncio
async def test_monotonic_workload_epoch_advancement_cross_casing(monkeypatch):
    """Verify advance_workload_epoch and get_workload_min_epoch across mismatched casing and whitespace."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    base_svid = "spiffe://Cluster.Local/Ns/Agents/Sa/Epoch-Agent"

    # Initially 0
    assert await get_workload_min_epoch(base_svid, redis_client=redis_client) == 0

    # Advance with leading/trailing whitespace and uppercase
    svid_advance_1 = "  SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/EPOCH-AGENT  "
    new_epoch_1 = await advance_workload_epoch(svid_advance_1, 5, redis_client=redis_client)
    assert new_epoch_1 == 5

    # Query with lowercase
    assert await get_workload_min_epoch("spiffe://cluster.local/ns/agents/sa/epoch-agent", redis_client=redis_client) == 5
    # Query with toggle-case
    assert await get_workload_min_epoch("sPiFfE://cLuStEr.LoCaL/Ns/AgEnTs/Sa/EpOcH-aGeNt", redis_client=redis_client) == 5
    # Query with whitespace
    assert await get_workload_min_epoch("   spiffe://cluster.local/ns/agents/sa/epoch-agent   ", redis_client=redis_client) == 5

    # Attempt rollback with lowercase and lower epoch (3 < 5)
    rollback_res = await advance_workload_epoch("spiffe://cluster.local/ns/agents/sa/epoch-agent", 3, redis_client=redis_client)
    assert rollback_res == 5, "Rollback attempt must not decrease min_epoch"
    assert await get_workload_min_epoch(base_svid, redis_client=redis_client) == 5

    # Advance higher with toggle case (12 > 5)
    adv_res_2 = await advance_workload_epoch("sPiFfE://CLUSTER.local/NS/agents/SA/epoch-agent", 12, redis_client=redis_client)
    assert adv_res_2 == 12

    # Query with uppercase
    assert await get_workload_min_epoch("SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/EPOCH-AGENT", redis_client=redis_client) == 12


@pytest.mark.asyncio
async def test_unquarantine_workload_cross_casing(monkeypatch):
    """Verify that unquarantine_workload clears quarantine state regardless of casing."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    svid_q = "SPIFFE://Cluster.Local/Ns/Agents/Sa/Unquarantine-Agent"
    directive = QuarantineDirective(
        thread_id="t-unq-1",
        agent_svid=svid_q,
        sandbox_id="sb-unq",
        reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
        violation_codes=["CBF_01"],
        issued_at=int(time.time()),
        correlation_id="c-unq",
        nonce="nonce-unq",
        governance_decision_digest="6" * 64,
        ttl_seconds=300,
    )
    await dispatch_quarantine(directive, redis_client=redis_client)

    assert await is_workload_quarantined(agent_svid=svid_q, redis_client=redis_client) is True
    assert await is_workload_quarantined(agent_svid="spiffe://cluster.local/ns/agents/sa/unquarantine-agent", redis_client=redis_client) is True

    # Unquarantine using lowercase stripped SVID
    await unquarantine_workload(agent_svid="spiffe://cluster.local/ns/agents/sa/unquarantine-agent", redis_client=redis_client)

    # Both casing queries MUST now return False
    assert await is_workload_quarantined(agent_svid=svid_q, redis_client=redis_client) is False
    assert await is_workload_quarantined(agent_svid="spiffe://cluster.local/ns/agents/sa/unquarantine-agent", redis_client=redis_client) is False


# ===========================================================================
# 2. Adversarial Test 2: Ingress Epoch Gating (governance_middleware & mcp_tool_server)
# ===========================================================================

@pytest.mark.asyncio
async def test_ingress_epoch_gating_governance_middleware(monkeypatch):
    """Thoroughly attack /governance/validate-action epoch validation when min_epoch > 0."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    from src.gateway.server.governance_middleware import governance_app

    mock_gov = MagicMock(spec=SymbolicGovernor)
    mock_gov.profile = MagicMock()
    mock_gov.validate_action = AsyncMock()
    mock_gov.validate_action.return_value = MagicMock(
        admissible=True,
        verdict="ALLOW",
        rule_violations=[],
        obligation_directives=[],
    )
    governance_app.state.governor = mock_gov

    client = TestClient(governance_app)
    svid = "spiffe://cluster.local/ns/agents/sa/ingress-epoch-target"
    min_epoch = 10
    await advance_workload_epoch(svid, min_epoch)
    assert await get_workload_min_epoch(svid) == min_epoch

    payload = {
        "action": "READ_RECORDS",
        "params": {
            "agent_svid": svid,
            "thread_id": "thread-epoch-1",
        },
    }

    # a) Omitted header and omitted param -> 403 missing_workload_epoch
    resp_omitted = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid},
    )
    assert resp_omitted.status_code == 403
    assert resp_omitted.json()["error"] == "missing_workload_epoch"

    # b) Malformed header values:
    malformed_vectors = [
        "letters",
        "-1",         # negative: parses to -1, which is < 10 -> stale_workload_epoch
        "-99999",     # negative: parses to -99999 < 10 -> stale_workload_epoch
        "3.14159",    # float string -> missing_workload_epoch
        "NaN",        # non-int string -> missing_workload_epoch
        "inf",        # non-int string -> missing_workload_epoch
        "-inf",       # non-int string -> missing_workload_epoch
        "0x10",       # hex notation -> missing_workload_epoch
        "",           # empty string -> missing_workload_epoch
        "   ",        # whitespace string -> missing_workload_epoch
        "9" * 4500,   # exceeds Python 4300 digits -> missing_workload_epoch
    ]

    for val in malformed_vectors:
        resp = client.post(
            "/validate-action",
            json=payload,
            headers={"x-cage-agent-svid": svid, "x-cage-epoch": val},
        )
        assert resp.status_code == 403, f"Expected 403 for epoch vector {val!r}, got {resp.status_code}"
        assert resp.json().get("error") in ("missing_workload_epoch", "stale_workload_epoch"), (
            f"Unexpected error code for {val!r}: {resp.json()}"
        )

    # c) Stale epoch (< min_epoch):
    stale_vectors = ["0", "1", "5", "9"]
    for stale_val in stale_vectors:
        resp = client.post(
            "/validate-action",
            json=payload,
            headers={"x-cage-agent-svid": svid, "x-cage-epoch": stale_val},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "stale_workload_epoch"

    # d) Current epoch (10 == min_epoch) -> passes epoch gate
    resp_exact = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "10"},
    )
    assert resp_exact.status_code != 403 or resp_exact.json().get("error") not in (
        "missing_workload_epoch",
        "stale_workload_epoch",
    )

    # e) Forward epoch (15 > min_epoch) -> passes epoch gate
    resp_forward = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid, "x-cage-epoch": "15"},
    )
    assert resp_forward.status_code != 403 or resp_forward.json().get("error") not in (
        "missing_workload_epoch",
        "stale_workload_epoch",
    )


@pytest.mark.asyncio
async def test_ingress_epoch_gating_zero_baseline(monkeypatch):
    """Verify that when min_epoch == 0 (unsevered agent), requests without epoch header pass."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    from src.gateway.server.governance_middleware import governance_app

    mock_gov = MagicMock(spec=SymbolicGovernor)
    mock_gov.profile = MagicMock()
    mock_gov.validate_action = AsyncMock()
    mock_gov.validate_action.return_value = MagicMock(
        admissible=True,
        verdict="ALLOW",
        rule_violations=[],
        obligation_directives=[],
    )
    governance_app.state.governor = mock_gov

    client = TestClient(governance_app)
    svid = "spiffe://cluster.local/ns/agents/sa/baseline-agent-clean"
    assert await get_workload_min_epoch(svid) == 0

    payload = {
        "action": "READ_RECORDS",
        "params": {
            "agent_svid": svid,
            "thread_id": "thread-clean-1",
        },
    }

    # Clean agent with min_epoch == 0 omits x-cage-epoch: MUST NOT be blocked by epoch gate
    resp = client.post(
        "/validate-action",
        json=payload,
        headers={"x-cage-agent-svid": svid},
    )
    assert resp.status_code != 403 or resp.json().get("error") not in (
        "missing_workload_epoch",
        "stale_workload_epoch",
    )


# ===========================================================================
# 3. Adversarial Test 3: MagicMock & JSON Serialization in mcp_tool_server.py
# ===========================================================================

@pytest.mark.asyncio
async def test_mcp_execute_tool_magicmock_json_serialization_safety(monkeypatch):
    """Assert zero TypeError: Object of type MagicMock is not JSON serializable across mock permutations."""
    import sys
    from fastapi.responses import JSONResponse

    trusted_id = "governed-financial-advisor.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", trusted_id)
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()

    from tests.test_gateway_server_mcp_tool_server import _mcp_import_stubs

    with patch.dict("sys.modules", _mcp_import_stubs()):
        sys.modules.pop("src.gateway.server.mcp_tool_server", None)
        import src.gateway.server.mcp_tool_server as mod

        mod._rate_limit_buckets = {}

        # -------------------------------------------------------------------
        # Scenario A: Quarantined SVID with MagicMock headers & redis
        # -------------------------------------------------------------------
        # Advance min epoch & quarantine the workload
        await advance_workload_epoch(trusted_id, 1)

        req_mock = MagicMock()
        req_mock.scope = {
            "headers": [(b"l5d-client-id", trusted_id.encode("latin-1"))],
            "client": ("127.0.0.1", 50000),
        }
        req_mock.client = MagicMock(host="127.0.0.1")
        # Ensure headers.get returns a MagicMock to stress-test attribute handling
        req_mock.headers = MagicMock()
        req_mock.headers.get.return_value = MagicMock(name="mock_header_return")
        req_mock.app = MagicMock()
        req_mock.app.state = MagicMock()
        req_mock.app.state.redis = MagicMock(name="mock_redis_instance")

        # Quarantine the SVID
        directive = QuarantineDirective(
            thread_id="t-mock-q",
            agent_svid=trusted_id,
            sandbox_id="sb-mock",
            reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
            violation_codes=["CBF_01"],
            issued_at=int(time.time()),
            correlation_id="c-mock",
            nonce="nonce-mock",
            governance_decision_digest="5" * 64,
            ttl_seconds=300,
        )
        actuator = InferenceProxySvidQuarantineActuator(redis_client=None)
        await actuator.quarantine_workload(directive)

        body = mod.ToolExecutionRequest(
            tool_name="trigger_safety_intervention",
            params={"reason": "test_magicmock_serialization"},
        )

        # Call endpoint
        response = await mod.execute_tool_endpoint(body, req_mock)
        assert isinstance(response, JSONResponse)
        assert response.status_code == 403

        # Critical: Attempting to serialize the response body MUST NOT raise TypeError!
        body_bytes = response.body
        parsed = json.loads(body_bytes.decode("utf-8"))
        assert parsed["error"] == "workload_quarantined"
        assert parsed["agent_id"] == trusted_id

        # -------------------------------------------------------------------
        # Scenario B: Unquarantined but min_epoch > 0 and header is a MagicMock
        # -------------------------------------------------------------------
        clear_local_quarantine_state()
        await advance_workload_epoch(trusted_id, 8)

        # Calling with mock headers (where raw_epoch is MagicMock, hence not int/str)
        response_epoch = await mod.execute_tool_endpoint(body, req_mock)
        assert isinstance(response_epoch, JSONResponse)
        assert response_epoch.status_code == 403

        parsed_epoch = json.loads(response_epoch.body.decode("utf-8"))
        assert parsed_epoch["error"] == "missing_workload_epoch"
        assert parsed_epoch["min_epoch"] == 8

        # -------------------------------------------------------------------
        # Scenario C: Stale epoch provided via body params with MagicMock headers
        # When request.headers.get returns a MagicMock, the mock is sanitized to None
        # and safely rejected with missing_workload_epoch (zero crash).
        # -------------------------------------------------------------------
        body_stale = mod.ToolExecutionRequest(
            tool_name="trigger_safety_intervention",
            params={"reason": "test_stale_epoch", "epoch": 3},
        )
        response_mock_hdr = await mod.execute_tool_endpoint(body_stale, req_mock)
        assert isinstance(response_mock_hdr, JSONResponse)
        assert response_mock_hdr.status_code == 403
        parsed_mock_hdr = json.loads(response_mock_hdr.body.decode("utf-8"))
        assert parsed_mock_hdr["error"] == "missing_workload_epoch"
        assert parsed_mock_hdr["min_epoch"] == 8

        # -------------------------------------------------------------------
        # Scenario D: Header returns None (absent header), param fallback reads epoch 3
        # -------------------------------------------------------------------
        req_mock.headers.get.return_value = None
        response_stale = await mod.execute_tool_endpoint(body_stale, req_mock)
        assert isinstance(response_stale, JSONResponse)
        assert response_stale.status_code == 403
        parsed_stale = json.loads(response_stale.body.decode("utf-8"))
        assert parsed_stale["error"] == "stale_workload_epoch"
        assert parsed_stale["min_epoch"] == 8

        # -------------------------------------------------------------------
        # Scenario E: Header returns None, param fallback reads valid epoch 8 -> passes epoch check
        # -------------------------------------------------------------------
        body_valid = mod.ToolExecutionRequest(
            tool_name="trigger_safety_intervention",
            params={"reason": "test_valid_epoch", "epoch": 8},
        )
        response_valid = await mod.execute_tool_endpoint(body_valid, req_mock)
        # Should not be blocked by epoch gate (passes epoch check, reaches tool execution)
        assert not (isinstance(response_valid, JSONResponse) and response_valid.status_code == 403 and
                    json.loads(response_valid.body.decode("utf-8")).get("error") in ("missing_workload_epoch", "stale_workload_epoch"))


# ===========================================================================
# 4. Adversarial Test 4: Ingress Epoch Gating on /tools/execute & /mcp ASGI
# ===========================================================================

@pytest.mark.asyncio
async def test_tools_execute_ingress_epoch_matrix(monkeypatch):
    """Exhaustively test /tools/execute epoch gating when min_epoch > 0."""
    import sys
    from fastapi.responses import JSONResponse

    trusted_id = "governed-financial-advisor.governance-stack.serviceaccount.identity.linkerd.cluster.local"
    monkeypatch.setenv("CAGE_TRUSTED_CLIENT_IDENTITIES", trusted_id)
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()

    from tests.test_gateway_server_mcp_tool_server import _mcp_import_stubs

    with patch.dict("sys.modules", _mcp_import_stubs()):
        sys.modules.pop("src.gateway.server.mcp_tool_server", None)
        import src.gateway.server.mcp_tool_server as mod

        mod._rate_limit_buckets = {}
        min_epoch = 6
        await advance_workload_epoch(trusted_id, min_epoch)

        def make_req(header_epoch: str | None = None) -> Any:
            req = MagicMock()
            req.scope = {
                "headers": [(b"l5d-client-id", trusted_id.encode("latin-1"))],
                "client": ("127.0.0.1", 50000),
            }
            req.client = MagicMock(host="127.0.0.1")
            req.headers = {}
            if header_epoch is not None:
                req.headers["x-cage-epoch"] = header_epoch
            req.app = MagicMock()
            req.app.state = MagicMock()
            req.app.state.redis = None
            return req

        body = mod.ToolExecutionRequest(
            tool_name="trigger_safety_intervention",
            params={"reason": "matrix_test"},
        )

        # 1. Omitted header -> 403 missing_workload_epoch
        res_omitted = await mod.execute_tool_endpoint(body, make_req(None))
        assert isinstance(res_omitted, JSONResponse) and res_omitted.status_code == 403
        assert json.loads(res_omitted.body.decode("utf-8"))["error"] == "missing_workload_epoch"

        # 2. Malformed non-integer header -> 403 missing_workload_epoch
        for malformed in ["letters", "3.14159", "NaN", "0x12", "   "]:
            res_mal = await mod.execute_tool_endpoint(body, make_req(malformed))
            assert isinstance(res_mal, JSONResponse) and res_mal.status_code == 403
            assert json.loads(res_mal.body.decode("utf-8"))["error"] == "missing_workload_epoch"

        # 3. Negative epoch -> 403 stale_workload_epoch (since negative < 6)
        res_neg = await mod.execute_tool_endpoint(body, make_req("-1"))
        assert isinstance(res_neg, JSONResponse) and res_neg.status_code == 403
        assert json.loads(res_neg.body.decode("utf-8"))["error"] == "stale_workload_epoch"

        # 4. Stale epoch (4 < 6) -> 403 stale_workload_epoch
        res_stale = await mod.execute_tool_endpoint(body, make_req("4"))
        assert isinstance(res_stale, JSONResponse) and res_stale.status_code == 403
        assert json.loads(res_stale.body.decode("utf-8"))["error"] == "stale_workload_epoch"

        # 5. Exact epoch (6 == 6) -> passes epoch gate
        res_exact = await mod.execute_tool_endpoint(body, make_req("6"))
        assert not (isinstance(res_exact, JSONResponse) and res_exact.status_code == 403 and
                    json.loads(res_exact.body.decode("utf-8")).get("error") in ("missing_workload_epoch", "stale_workload_epoch"))

        # 6. Forward epoch (10 > 6) -> passes epoch gate
        res_forward = await mod.execute_tool_endpoint(body, make_req("10"))
        assert not (isinstance(res_forward, JSONResponse) and res_forward.status_code == 403 and
                    json.loads(res_forward.body.decode("utf-8")).get("error") in ("missing_workload_epoch", "stale_workload_epoch"))


@pytest.mark.asyncio
async def test_mcp_asgi_epoch_and_quarantine_middleware(monkeypatch):
    """Test raw ASGI /mcp ingress middleware for epoch validation and quarantine rejection."""
    import sys

    trusted_id = "spiffe://cluster.local/ns/agents/sa/mcp-asgi-agent"
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()

    from tests.test_gateway_server_mcp_tool_server import _mcp_import_stubs

    with patch.dict("sys.modules", _mcp_import_stubs()):
        sys.modules.pop("src.gateway.server.mcp_tool_server", None)
        import src.gateway.server.mcp_tool_server as mod

        min_epoch = 7
        await advance_workload_epoch(trusted_id, min_epoch)

        async def run_asgi(headers: list[tuple[bytes, bytes]]) -> tuple[int, dict[str, Any]]:
            response_start: dict[str, Any] = {}
            body_parts: list[bytes] = []

            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message: dict[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    response_start.update(message)
                elif message["type"] == "http.response.body":
                    body_parts.append(message.get("body", b""))

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/mcp/",
                "headers": headers,
                "client": ("127.0.0.1", 50000),
            }

            # Call the raw ASGI application
            try:
                await mod.app(scope, receive, send)
            except Exception:
                pass
            status = response_start.get("status", 0)
            body = b"".join(body_parts)
            parsed: dict[str, Any] = {}
            if body:
                try:
                    parsed = json.loads(body.decode("utf-8"))
                except Exception:
                    pass
            return status, parsed

        # 1. Omitted epoch -> 403 missing_workload_epoch
        st_omitted, body_omitted = await run_asgi([
            (b"x-cage-agent-svid", trusted_id.encode("latin-1")),
        ])
        assert st_omitted == 403
        assert body_omitted.get("error") == "missing_workload_epoch"

        # 2. Malformed epoch -> 403 missing_workload_epoch
        st_mal, body_mal = await run_asgi([
            (b"x-cage-agent-svid", trusted_id.encode("latin-1")),
            (b"x-cage-epoch", b"not_an_int"),
        ])
        assert st_mal == 403
        assert body_mal.get("error") == "missing_workload_epoch"

        # 3. Stale epoch (3 < 7) -> 403 stale_workload_epoch
        st_stale, body_stale = await run_asgi([
            (b"x-cage-agent-svid", trusted_id.encode("latin-1")),
            (b"x-cage-epoch", b"3"),
        ])
        assert st_stale == 403
        assert body_stale.get("error") == "stale_workload_epoch"

        # 4. Quarantined workload -> 403 workload_quarantined
        directive = QuarantineDirective(
            thread_id="t-mcp-q",
            agent_svid=trusted_id,
            sandbox_id="sb-mcp",
            reason=QuarantineTriggerReason.CRITICAL_CBF_BREACH,
            violation_codes=["CBF_01"],
            issued_at=int(time.time()),
            correlation_id="c-mcp",
            nonce="nonce-mcp",
            governance_decision_digest="4" * 64,
            ttl_seconds=300,
        )
        actuator = InferenceProxySvidQuarantineActuator(redis_client=None)
        await actuator.quarantine_workload(directive)

        st_q, body_q = await run_asgi([
            (b"x-cage-agent-svid", trusted_id.encode("latin-1")),
            (b"x-cage-epoch", b"7"),
        ])
        assert st_q == 403
        assert body_q.get("error") == "workload_quarantined"


@pytest.mark.asyncio
async def test_concurrent_epoch_advancement_mixed_casing_redis(monkeypatch):
    """Stress test: 30 concurrent tasks advancing workload epochs with randomized casing and values against Redis Lua CAS."""
    monkeypatch.setenv("CAGE_ENV", "dev")
    clear_local_quarantine_state()
    server = fakeredis.FakeServer()
    redis_client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    base_svid = "spiffe://cluster.local/ns/agents/sa/concurrent-casing-agent"
    casings = [
        "spiffe://cluster.local/ns/agents/sa/concurrent-casing-agent",
        "SPIFFE://CLUSTER.LOCAL/NS/AGENTS/SA/CONCURRENT-CASING-AGENT",
        "  spiffe://Cluster.Local/Ns/Agents/Sa/Concurrent-Casing-Agent  ",
        "sPiFfE://cLuStEr.LoCaL/nS/aGeNtS/sA/cOnCuRrEnT-cAsInG-aGeNt",
        "\tSPIFFE://cluster.local/ns/agents/sa/concurrent-casing-agent\n",
    ]

    import random
    random.seed(42)
    epoch_values = [random.randint(1, 150) for _ in range(30)]
    expected_max = max(epoch_values)

    async def worker(casing: str, epoch: int) -> int:
        return await advance_workload_epoch(casing, epoch, redis_client=redis_client)

    tasks = [
        worker(casings[i % len(casings)], epoch_values[i])
        for i in range(len(epoch_values))
    ]
    results = await asyncio.gather(*tasks)

    # Every query across every casing MUST return the exact expected maximum
    for c in casings:
        res = await get_workload_min_epoch(c, redis_client=redis_client)
        assert res == expected_max, f"Expected {expected_max} for casing {c!r}, got {res}"

