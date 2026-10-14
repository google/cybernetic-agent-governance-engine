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
import uuid
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_07.adapter import Provider07NormativeProvider
from src.integrations.provider_07.jwks_client import Provider07JwksClient
from src.integrations.provider_07.schema import (
    InferThetaBaselineResponse,
    InferThetaEvidenceResponse,
    InferThetaInferenceRequest,
    InferThetaInferenceResponse,
)
from src.integrations.provider_07.signature import verify_inference_signature

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]

ACTIVE_PROD_KID = "infertheta-provider07-prod-2026-01"
ACTIVE_STAGING_KID = "infertheta-provider07-2026-01"


def _get_live_credentials() -> tuple[str, str]:
    """Retrieve endpoint and API key from environment variables."""
    endpoint = os.environ.get("PROVIDER_07_ENDPOINT", "").split("#")[0].strip()
    api_key = os.environ.get("PROVIDER_07_API_KEY", "").split("#")[0].strip()
    return endpoint, api_key


def _get_live_jwks_url(endpoint: str) -> str:
    """Resolve JWKS URL from PROVIDER_07_JWKS_URL or default well-known path."""
    explicit = os.environ.get("PROVIDER_07_JWKS_URL", "").split("#")[0].strip()
    return explicit or f"{endpoint.rstrip('/')}/.well-known/jwks.json"


def _get_expected_kid(endpoint: str) -> str:
    """Resolve expected signing key ID for production vs. staging endpoints."""
    explicit = os.environ.get("PROVIDER_07_EXPECTED_KID", "").split("#")[0].strip()
    if explicit:
        return explicit
    if "staging" in endpoint.lower():
        return ACTIVE_STAGING_KID
    return ACTIVE_PROD_KID


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
        jwks_url=_get_live_jwks_url(endpoint),
        timeout_seconds=10.0,
    )


@pytest.fixture
def canonical_vectors() -> list[dict[str, Any]]:
    """Three canonical test vectors agreed with partner for Step 1 & Step 2."""
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
async def test_live_health_check(
    live_credentials: tuple[str, str],
) -> None:
    """Verify live /health endpoint returns HTTP 200."""
    endpoint, _ = live_credentials
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{endpoint.rstrip('/')}/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_live_fetch_baseline(
    live_credentials: tuple[str, str],
    live_adapter: Provider07NormativeProvider,
) -> None:
    """Verify live US_FED baseline retrieval, stable content-addressed baseline_hash, and HTTP ETag alignment."""
    endpoint, api_key = live_credentials
    region = "US_FED"
    baseline_1 = await live_adapter.fetch_baseline(region)
    baseline_2 = await live_adapter.fetch_baseline(region)

    assert isinstance(baseline_1, NormativeBaseline)
    assert baseline_1.region == region
    assert baseline_1.is_valid, f"Baseline fetch failed: {baseline_1.error}"
    assert baseline_1.profile, "Baseline profile should not be empty"
    assert "rules" in baseline_1.profile
    assert len(baseline_1.profile["rules"]) >= 4
    assert baseline_1.etag.startswith("sha256:")
    # Content-addressed baseline_hash must be stable across fetches
    assert baseline_1.etag == baseline_2.etag
    assert (
        baseline_1.profile["baseline_hash"]
        == "sha256:ca507cf6a254b49d54c025be8989af5a534ca9be0a787764d59a59bb154fe62c"
    )

    # Verify HTTP ETag header aligns with body baseline_hash
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{endpoint.rstrip('/')}/baseline/{region}", headers=headers
        )
        assert resp.status_code == 200
        http_etag = resp.headers.get("etag", "")
        assert baseline_1.etag in http_etag


@pytest.mark.asyncio
@pytest.mark.parametrize("reserved_region", ["EU_ECB", "APAC_MAS"])
async def test_live_fetch_baseline_reserved_regions_fail_closed(
    live_adapter: Provider07NormativeProvider,
    reserved_region: str,
) -> None:
    """Verify reserved but unpopulated regional baselines (EU_ECB, APAC_MAS) fail closed rather than reusing US_FED."""
    baseline = await live_adapter.fetch_baseline(reserved_region)
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.region == reserved_region
    assert not baseline.is_valid
    assert baseline.error is not None
    assert "404" in baseline.error


@pytest.mark.asyncio
async def test_live_jwks_resolution(
    live_credentials: tuple[str, str],
) -> None:
    """Verify live out-of-band JWKS key resolution for active key."""
    endpoint, _ = live_credentials
    jwks_url = _get_live_jwks_url(endpoint)
    expected_kid = _get_expected_kid(endpoint)
    jwks_client = Provider07JwksClient(jwks_url=jwks_url, timeout_seconds=10.0)

    public_key = await jwks_client.get_key(expected_kid)
    assert public_key is not None, f"Active key {expected_kid} not found in JWKS"
    assert isinstance(public_key, Ed25519PublicKey)
    assert len(public_key.public_bytes_raw()) == 32

    # Unknown kid must return None (fail-closed contract)
    unknown_key = await jwks_client.get_key("infertheta-unknown-kid-9999")
    assert unknown_key is None


@pytest.mark.asyncio
async def test_live_infer_contract_vectors(
    live_credentials: tuple[str, str],
    canonical_vectors: list[dict[str, Any]],
) -> None:
    """Verify live HTTP POST /infer parses cleanly with Ed25519 JCS signatures and decision semantics."""
    endpoint, api_key = live_credentials
    base_url = endpoint.rstrip("/")
    url = f"{base_url}/infer"
    expected_kid = _get_expected_kid(endpoint)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}" if api_key else "",
    }
    jwks_client = Provider07JwksClient(
        jwks_url=_get_live_jwks_url(endpoint), timeout_seconds=10.0
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        for vector in canonical_vectors:
            req_model = InferThetaInferenceRequest(**vector["request"])
            response = await client.post(
                url, json=req_model.model_dump(), headers=headers
            )
            assert response.status_code == 200, f"Inference failed: {response.text}"

            resp_data = response.json()
            assert "authority_record_id" in resp_data
            resp_model = InferThetaInferenceResponse(**resp_data)

            # Assert tri-state decision matches partner expectation
            assert resp_model.decision == vector["expected_decision"]

            # Cryptographic invariants: active kid and 86-char unpadded base64url Ed25519 signature
            assert resp_model.kid == expected_kid
            assert len(resp_model.signature) == 86
            assert "=" not in resp_model.signature
            public_key = await jwks_client.get_key(resp_model.kid)
            assert public_key is not None
            assert verify_inference_signature(
                payload=resp_data,
                public_key=public_key,
                signature_b64=resp_model.signature,
            )

            # Token mint invariant: authority_record_id populated only on ALLOW
            if resp_model.decision == "ALLOW":
                assert resp_model.authority_record_id is not None
                assert resp_model.authority_record_id.startswith("infertheta-ar-")
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
            assert resp_model.posterior_risk_score == pytest.approx(
                expected_risk, abs=1e-4
            )


@pytest.mark.asyncio
async def test_live_adapter_step2_enforcing_validation(
    live_adapter: Provider07NormativeProvider,
    canonical_vectors: list[dict[str, Any]],
) -> None:
    """Verify default enforcing Provider07NormativeProvider verifies Step 2 signed responses end-to-end."""
    for vector in canonical_vectors:
        result = await live_adapter.validate_fria(vector["request"])
        assert isinstance(result, ValidationResult)

        if vector["expected_decision"] == "ALLOW":
            assert result.admitted is True
            assert result.findings[0]["code"] == "INFERTHETA_ALLOW"
            assert "step1_demo_mode" not in result.findings[0]
            assert result.findings[0]["authority_record_id"].startswith(
                "infertheta-ar-"
            )
            assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.094135)
        elif vector["expected_decision"] == "REFUSE":
            assert result.admitted is False
            assert result.findings[0]["code"] == "INFERTHETA_UNSUITABLE"
            assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.449457)
        elif vector["expected_decision"] == "ESCALATE":
            assert result.admitted is False
            assert result.findings[0]["code"] == "INFERTHETA_ESCALATE"
            assert result.findings[0]["needs_human_review"] is True
            assert result.findings[0]["posterior_risk_score"] == pytest.approx(0.257988)


@pytest.mark.asyncio
async def test_live_submit_evidence(
    live_credentials: tuple[str, str],
    live_adapter: Provider07NormativeProvider,
) -> None:
    """Verify Step 3 POST /evidence-chain/{thread_id} persistence, idempotent replay, and Bearer auth enforcement."""
    endpoint, _ = live_credentials
    thread_id = f"cage-live-evidence-{uuid.uuid4().hex[:12]}"
    evidence_hash = (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    # 1. Initial evidence submission succeeds and returns persisted seal
    seal_1 = await live_adapter.submit_evidence(thread_id, evidence_hash)
    assert isinstance(seal_1, EvidenceSeal)
    assert seal_1.error is None, f"Evidence seal failed: {seal_1.error}"
    assert seal_1.thread_id == thread_id
    assert len(seal_1.seal_hash) == 64
    assert seal_1.sealed_at > 0

    # 2. Idempotent replay of the same (thread_id, evidence_hash) returns identical seal_hash and timestamp
    seal_2 = await live_adapter.submit_evidence(thread_id, evidence_hash)
    assert seal_2.error is None
    assert seal_2.thread_id == thread_id
    assert seal_2.seal_hash == seal_1.seal_hash
    assert seal_2.sealed_at == pytest.approx(seal_1.sealed_at, abs=1e-6)

    # 3. Unauthenticated submission fails closed (HTTP 401)
    unauthenticated_adapter = Provider07NormativeProvider(
        endpoint=endpoint,
        api_key="",
        timeout_seconds=10.0,
    )
    unauth_seal = await unauthenticated_adapter.submit_evidence(
        thread_id, evidence_hash
    )
    assert unauth_seal.seal_hash == ""
    assert unauth_seal.error is not None
    assert "401" in unauth_seal.error
