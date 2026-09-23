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

"""Live integration tests for Provider 07 (InferTheta Bayesian Causal Suitability Oracle).

Executes live HTTP requests against the deployed Provider 07 staging endpoint
when configured via environment variables.

Markers:
    partner_integration: External partner integration tests
    live_external: Hits external partner APIs (requires network and credentials)
    partner: Partner adapter facet
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

from src.gateway.governance.seams.normative import (
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_07.adapter import Provider07NormativeProvider
from src.integrations.provider_07.schema import (
    InferThetaBaselineResponse,
    InferThetaInferenceRequest,
    InferThetaInferenceResponse,
)

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _get_live_credentials() -> tuple[str, str]:
    """Retrieve endpoint and API key from environment variables."""
    endpoint = (
        os.environ.get("PROVIDER_07_ENDPOINT", "")
        .split("#")[0]
        .strip()
    )
    api_key = (
        os.environ.get("PROVIDER_07_API_KEY", "")
        .split("#")[0]
        .strip()
    )
    return endpoint, api_key


@pytest.fixture
def live_credentials() -> tuple[str, str]:
    """Fixture providing live credentials or skipping if unconfigured."""
    endpoint, api_key = _get_live_credentials()
    if not endpoint:
        pytest.skip("PROVIDER_07_ENDPOINT not configured (skipping live partner test)")
    return endpoint, api_key


@pytest.fixture
def live_adapter(live_credentials: tuple[str, str]) -> Provider07NormativeProvider:
    """Create a default live Provider 07 adapter instance."""
    endpoint, api_key = live_credentials
    return Provider07NormativeProvider(
        endpoint=endpoint,
        api_key=api_key,
        timeout_seconds=10.0,
    )


@pytest.fixture
def canonical_vectors() -> list[dict[str, Any]]:
    """Three canonical test vectors agreed with partner for Step 1."""
    return [
        {
            "id": "allow",
            "expected_decision": "ALLOW",
            "request": {
                "scenario_id": "11111111-1111-4111-8111-111111111111",
                "action": "rebalance_portfolio",
                "target": "urn:account:client-allow:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.4,
                    "INTL_EQUITY": 0.1,
                    "FIXED_INCOME": 0.4,
                    "CASH": 0.1,
                },
                "proposed_trade": {
                    "asset": "VANGUARD_TOTAL_BOND_INDEX",
                    "side": "BUY",
                    "amount": 25000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "MODERATE",
                    "investment_horizon_years": 12,
                    "liquidity_need": "LOW",
                },
                "market_volatility_index": 0.12,
                "context": {
                    "session_id": "advise-allow",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
        },
        {
            "id": "refuse",
            "expected_decision": "REFUSE",
            "request": {
                "scenario_id": "22222222-2222-4222-8222-222222222222",
                "action": "execute_trade",
                "target": "urn:account:client-refuse:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.7,
                    "INTL_EQUITY": 0.15,
                    "FIXED_INCOME": 0.1,
                    "CASH": 0.05,
                },
                "proposed_trade": {
                    "asset": "VANGUARD_TOTAL_STOCK_MARKET",
                    "side": "BUY",
                    "amount": 150000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "CONSERVATIVE",
                    "investment_horizon_years": 3,
                    "liquidity_need": "HIGH",
                },
                "market_volatility_index": 0.42,
                "context": {
                    "session_id": "advise-refuse",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
        },
        {
            "id": "escalate",
            "expected_decision": "ESCALATE",
            "request": {
                "scenario_id": "33333333-3333-4333-8333-333333333333",
                "action": "execute_trade",
                "target": "urn:account:client-escalate:portfolio-main",
                "actor_id": "urn:agent:financial-advisor-bot-v2",
                "portfolio_vector": {
                    "US_EQUITY": 0.5,
                    "INTL_EQUITY": 0.15,
                    "FIXED_INCOME": 0.25,
                    "CASH": 0.1,
                },
                "proposed_trade": {
                    "asset": "SPDR_S_AND_P_500",
                    "side": "BUY",
                    "amount": 40000,
                    "currency": "USD",
                },
                "client_profile": {
                    "risk_tolerance": "MODERATE",
                    "investment_horizon_years": 8,
                    "liquidity_need": "MEDIUM",
                },
                "market_volatility_index": 0.28,
                "context": {
                    "session_id": "advise-escalate",
                    "timestamp_utc": "2026-09-17T09:00:00Z",
                },
            },
        },
    ]


@pytest.mark.asyncio
async def test_live_fetch_baseline(
    live_adapter: Provider07NormativeProvider,
) -> None:
    """Verify live baseline retrieval from staging endpoint."""
    region = "US_FED"
    baseline = await live_adapter.fetch_baseline(region)

    assert isinstance(baseline, NormativeBaseline)
    assert baseline.region == region
    assert baseline.error is None, f"Baseline fetch failed: {baseline.error}"
    assert baseline.profile, "Baseline profile should not be empty"
    assert "rules" in baseline.profile
    assert len(baseline.profile["rules"]) >= 1
    assert baseline.etag.startswith("sha256:")


@pytest.mark.asyncio
async def test_live_infer_contract_vectors(
    live_credentials: tuple[str, str],
    canonical_vectors: list[dict[str, Any]],
) -> None:
    """Verify live HTTP POST /infer against staging parses cleanly with correct decision semantics."""
    endpoint, api_key = live_credentials
    url = f"{endpoint}/infer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}" if api_key else "",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        for vector in canonical_vectors:
            req_model = InferThetaInferenceRequest(**vector["request"])
            response = await client.post(url, json=req_model.model_dump(), headers=headers)
            assert response.status_code == 200, f"Inference failed: {response.text}"

            resp_data = response.json()
            resp_model = InferThetaInferenceResponse(**resp_data)

            # Assert tri-state decision matches partner expectation
            assert resp_model.decision == vector["expected_decision"]

            # Token mint invariant: authority_record_id populated only on ALLOW
            if resp_model.decision == "ALLOW":
                assert resp_model.authority_record_id is not None
                assert len(resp_model.authority_record_id) > 0
                assert resp_model.posterior_risk_score < 0.20
                assert resp_model.utility_rankings[0].action == "rebalance_to_proposed"
            elif resp_model.decision == "REFUSE":
                assert resp_model.authority_record_id is None
                assert resp_model.posterior_risk_score >= 0.40
                assert resp_model.utility_rankings[0].action == "reject_trade"
            elif resp_model.decision == "ESCALATE":
                assert resp_model.authority_record_id is None
                assert 0.20 <= resp_model.posterior_risk_score < 0.40
                assert resp_model.utility_rankings[0].action == "defer_to_human"

            # Check marginal risk aggregation formula
            # posterior_risk_score = 0.5 * P(drawdown) + 0.3 * P(volatility) + 0.2 * P(liquidity)
            p_dd = resp_model.marginal_probabilities.get("drawdown_gt_15pct", 0.0)
            p_vs = resp_model.marginal_probabilities.get("volatility_spike", 0.0)
            p_ls = resp_model.marginal_probabilities.get("liquidity_stress", 0.0)
            expected_risk = 0.5 * p_dd + 0.3 * p_vs + 0.2 * p_ls
            assert resp_model.posterior_risk_score == pytest.approx(expected_risk, abs=1e-4)


@pytest.mark.asyncio
async def test_live_adapter_step1_unsigned_mode(
    live_credentials: tuple[str, str],
    canonical_vectors: list[dict[str, Any]],
) -> None:
    """Verify Provider07NormativeProvider with allow_step1_unsigned=True against staging."""
    endpoint, api_key = live_credentials
    adapter = Provider07NormativeProvider(
        endpoint=endpoint,
        api_key=api_key,
        timeout_seconds=15.0,
        allow_step1_unsigned=True,
    )

    for vector in canonical_vectors:
        result = await adapter.validate_fria(vector["request"])
        assert isinstance(result, ValidationResult)

        if vector["expected_decision"] == "ALLOW":
            assert result.admitted is True
            assert result.findings[0]["code"] == "INFERTHETA_ALLOW"
            assert result.findings[0].get("step1_demo_mode") is True
            assert result.findings[0]["authority_record_id"] == "infertheta-step1-allow-unsigned"
        elif vector["expected_decision"] == "REFUSE":
            assert result.admitted is False
            assert result.findings[0]["code"] == "INFERTHETA_UNSUITABLE"
        elif vector["expected_decision"] == "ESCALATE":
            assert result.admitted is False
            assert result.findings[0]["code"] == "INFERTHETA_ESCALATE"
            assert result.findings[0]["needs_human_review"] is True


@pytest.mark.asyncio
async def test_live_adapter_default_fail_closed(
    live_adapter: Provider07NormativeProvider,
    canonical_vectors: list[dict[str, Any]],
) -> None:
    """Verify default adapter posture fails closed against staging because Step 2 signatures are deferred."""
    allow_vector = next(v for v in canonical_vectors if v["id"] == "allow")
    result = await live_adapter.validate_fria(allow_vector["request"])

    # Must fail closed because staging does not yet serve a JWKS endpoint (Step 2)
    assert isinstance(result, ValidationResult)
    assert result.admitted is False
    assert result.findings[0]["code"] in (
        "INFERTHETA_JWKS_ERROR",
        "INFERTHETA_UNKNOWN_KEY",
        "INFERTHETA_SIGNATURE_INVALID",
    )

