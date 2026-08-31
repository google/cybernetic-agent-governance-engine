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

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.gateway.governance.constants import ControlRegistry
from src.gateway.governance.symbolic_governor import GovernanceError, SymbolicGovernor
from src.gateway.server.governance_middleware import governance_app

pytestmark = pytest.mark.unit


@pytest.fixture
def registry():
    """Returns the ControlRegistry singleton."""
    return ControlRegistry()


@pytest.fixture
def mock_dependencies():
    """Mock SymbolicGovernor dependencies for testing."""
    opa_client = AsyncMock()
    opa_client.evaluate_policy.return_value = "ALLOW"

    safety_filter = AsyncMock()
    safety_filter.verify_action.return_value = "SAFE"

    consensus_engine = AsyncMock()
    consensus_engine.check_consensus.return_value = {"status": "APPROVE"}

    return opa_client, safety_filter, consensus_engine


@pytest.mark.asyncio
async def test_symbolic_governor_version_matching(registry, mock_dependencies):
    """SymbolicGovernor validate_action should succeed when policy_version_id matches active_hash."""
    from src.gateway.governance.ftra.models import FtraBoundaryResult

    opa_client, safety_filter, consensus_engine = mock_dependencies
    gov = SymbolicGovernor(opa_client)
    from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

    gov.register_domain_tier(CBFTierPlugin(safety_filter))
    gov.register_domain_tier(ConsensusTierPlugin(consensus_engine))

    # Mock FTRA boundary check to return a safe result
    safe_ftra_result = FtraBoundaryResult(
        requires_hitl=False,
        irreversibility_score=0.0,
        classification="READ_ONLY",
        terminal_match=None,
        violations=[],
        bypassed_ftra_node=False,
    )
    gov._ftra_boundary_check = AsyncMock(return_value=safe_ftra_result)

    ControlRegistry.reconfigure("US_FED")
    active_hash = registry.active_hash
    assert active_hash != ""  # Should be populated from baseline loading

    # Mock _run_checks to return no violations, and generate_seal_with_evidence to avoid Redis
    with (
        patch.object(gov, "_run_checks", new_callable=AsyncMock) as mock_run,
        patch(
            "src.gateway.governance.routing_seal.generate_seal_with_evidence",
            new=AsyncMock(return_value="mock-seal-token"),
        ),
    ):
        mock_run.return_value = {"violations": []}

        # 1. Matching version
        res = await gov.validate_action(
            action="execute_trade",
            params={"confidence": 0.99, "amount": 100},
            policy_version_id=active_hash,
        )
        assert res["verdict"] == "ALLOW"

        # 2. Omitted version should also pass (default)
        res = await gov.validate_action(
            action="execute_trade",
            params={"confidence": 0.99, "amount": 100},
            policy_version_id=None,
        )
        assert res["verdict"] == "ALLOW"


@pytest.mark.asyncio
async def test_symbolic_governor_version_mismatch_raises_governance_error(
    registry, mock_dependencies
):
    """SymbolicGovernor validate_action should raise GovernanceError on mismatched policy_version_id."""
    opa_client, safety_filter, consensus_engine = mock_dependencies
    gov = SymbolicGovernor(opa_client)
    from src.cage_finance.tiers.cbf_tier import CBFTierPlugin
    from src.cage_finance.tiers.consensus_tier import ConsensusTierPlugin

    gov.register_domain_tier(CBFTierPlugin(safety_filter))
    gov.register_domain_tier(ConsensusTierPlugin(consensus_engine))

    with pytest.raises(GovernanceError) as exc_info:
        await gov.validate_action(
            action="execute_trade",
            params={"confidence": 0.99, "amount": 100},
            policy_version_id="mismatched-stale-hash-value-12345",
        )

    assert "Substrate Policy Drift Detected" in str(exc_info.value)
    assert "mismatched-stale-hash-value-12345" in str(exc_info.value)


def test_middleware_validate_action_version_matching(registry):
    """FastAPI validate-action endpoint should pass when correct version_id is provided."""
    import src.gateway.server.governance_middleware as mw

    # Disable seal enforcement for this test
    original_secret = mw._CAGE_SEAL_SECRET
    original_env = mw._ENVIRONMENT
    mw._CAGE_SEAL_SECRET = None
    mw._ENVIRONMENT = "test"

    try:
        client = TestClient(governance_app, raise_server_exceptions=False)
        active_hash = registry.active_hash

        mock_gov_result = {
            "verdict": "APPROVED",
            "violations": [],
            "seal": "mock-seal-hash",
            "latency_ms": 12.5,
        }

        # Patch SymbolicGovernor validate_action
        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor.validate_action",
            new_callable=AsyncMock,
        ) as mock_validate:
            mock_validate.return_value = mock_gov_result

            # Request with matching version
            resp = client.post(
                "/validate-action",
                json={
                    "action": "execute_trade",
                    "params": {"amount": 100},
                    "policy_version_id": active_hash,
                },
            )
            assert resp.status_code == 200
            assert resp.json()["verdict"] == "APPROVED"
            mock_validate.assert_awaited_once_with(
                action="execute_trade",
                params={"amount": 100},
                policy_version_id=active_hash,
            )
    finally:
        mw._CAGE_SEAL_SECRET = original_secret
        mw._ENVIRONMENT = original_env


def test_middleware_validate_action_version_mismatch_returns_403(registry):
    """FastAPI validate-action endpoint should return 403 when a version mismatch occurs."""
    import src.gateway.server.governance_middleware as mw

    # Disable seal enforcement for this test
    original_secret = mw._CAGE_SEAL_SECRET
    original_env = mw._ENVIRONMENT
    mw._CAGE_SEAL_SECRET = None
    mw._ENVIRONMENT = "test"

    try:
        client = TestClient(governance_app, raise_server_exceptions=False)

        # Patch SymbolicGovernor validate_action to raise GovernanceError
        with patch(
            "src.gateway.server.governance_middleware.symbolic_governor.validate_action",
            new_callable=AsyncMock,
        ) as mock_validate:
            mock_validate.side_effect = GovernanceError(
                "Substrate Policy Drift Detected. Session pinned to version..."
            )

            with patch(
                "src.gateway.server.governance_middleware._emit_refusal_receipt",
                new_callable=AsyncMock,
            ) as mock_emit:
                resp = client.post(
                    "/validate-action",
                    json={
                        "action": "execute_trade",
                        "params": {"amount": 100},
                        "policy_version_id": "stale-policy-hash",
                    },
                )
                assert resp.status_code == 403
                assert resp.json()["verdict"] == "DENIED"
                assert "Substrate Policy Drift" in resp.json()["violations"][0]
                mock_emit.assert_awaited_once()
    finally:
        mw._CAGE_SEAL_SECRET = original_secret
        mw._ENVIRONMENT = original_env


def test_serialization_float_coercion_consistency():
    """Verify float coercion prevents signature variance between 1.0 and 1."""
    # Test values with float vs int variations
    data_a = {"alert_threshold": 1.0, "risk_coefficient": 0.75, "nested": [1.0, 2.0]}
    data_b = {"alert_threshold": 1, "risk_coefficient": 0.75, "nested": [1, 2]}

    coerced_a = ControlRegistry._coerce_floats(data_a)
    coerced_b = ControlRegistry._coerce_floats(data_b)

    import json

    hash_a = json.dumps(coerced_a, sort_keys=True, separators=(",", ":"))
    hash_b = json.dumps(coerced_b, sort_keys=True, separators=(",", ":"))

    assert hash_a == hash_b


def test_policy_version_get_endpoint(registry):
    """GET /policy-version should return the active hash."""
    client = TestClient(governance_app, raise_server_exceptions=False)
    resp = client.get("/policy-version")
    assert resp.status_code == 200
    assert resp.json()["active_hash"] == registry.active_hash


@pytest.mark.asyncio
async def test_gateway_client_recovery_loop_on_policy_drift():
    """GatewayClient should fetch active version and retry once on 403 Substrate drift."""
    import httpx
    import respx

    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )

    client = GatewayClient()
    client._base_url = "http://localhost:8080"
    client._http = httpx.AsyncClient(base_url="http://localhost:8080")

    with respx.mock(base_url="http://localhost:8080") as mock_api:
        # Mock the sequential post response: 403 on first call, 200 on second call
        call_count = 0

        def response_callback(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    status_code=403,
                    json={
                        "verdict": "DENIED",
                        "violations": [
                            "Substrate Policy Drift Detected. Session pinned to version signature 'stale'"
                        ],
                    },
                )
            else:
                return httpx.Response(
                    status_code=200,
                    json={
                        "verdict": "APPROVED",
                        "violations": [],
                        "seal": "valid-retry-seal",
                        "latency_ms": 10.0,
                    },
                )

        mock_api.post("/governance/validate-action").mock(side_effect=response_callback)

        # Discovery GET endpoint returns fresh hash
        mock_api.get("/governance/policy-version").mock(
            return_value=httpx.Response(
                status_code=200, json={"active_hash": "fresh-hash-12345"}
            )
        )

        # Call validate_action
        res = await client.validate_action(
            action="execute_trade",
            params={"amount": 100},
            policy_version_id="stale-hash",
        )

        assert res["verdict"] == "APPROVED"
        assert res["seal"] == "valid-retry-seal"
        # Verify 3 calls total: 2 POSTs and 1 GET
        assert len(mock_api.calls) == 3
