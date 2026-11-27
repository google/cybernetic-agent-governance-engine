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

"""
GovernanceEnvelope v3.0 handling in the advisor's ``GatewayClient().sdk_client()``.

``GatewayClient().sdk_client()`` returns the installed ``cage-client`` ``CageClient``
bound to the advisor transport, which verifies the envelope's out-of-band ``kid``
signature, ``expires_at`` freshness, and ``subject.action_hash`` binding.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest
from cage_client import (
    CageGatewayError,
    GovernanceDecision,
    PolicyViolationException,
    RoutingSealVerificationError,
)

from src.governed_financial_advisor.graph.governance.tool_guard import (
    preview_trade_with_drift_revalidation,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from tests.fixtures.signed_gateway import SignedGatewayStub

pytestmark = [pytest.mark.unit, pytest.mark.local]

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler, *, sign: bool = True) -> GatewayClient:
    GatewayClient._instance = None
    transport_handler = (
        SignedGatewayStub().transport_handler(handler) if sign else handler
    )
    client = GatewayClient()
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(transport_handler),
        base_url="http://gateway.test",
    )
    return client


@pytest.fixture(autouse=True)
def _reset_singleton():
    yield
    GatewayClient._instance = None


@pytest.mark.asyncio
async def test_gfa_unwraps_v3_envelope_correctly() -> None:
    """A verified ALLOW envelope carries verified payload fields plus provenance."""
    client = _client(
        lambda request: httpx.Response(
            200,
            json={
                "envelope_id": "env-test-12345",
                "payload": {"verdict": "ALLOW", "violations": [], "latency_ms": 42.5},
            },
        )
    )

    sdk = await client.sdk_client()
    env = await sdk.validate_action(
        "execute_trade",
        {"symbol": "AAPL", "amount": 1000},
        "governed-financial-advisor",
    )

    assert env.payload["verdict"] == "ALLOW"
    assert env.payload["violations"] == []
    assert env.payload["latency_ms"] == 42.5
    assert env.envelope_id == "env-test-12345"
    assert env.envelope_version == "3.0"
    assert env.issuer["service"] == "cage-gateway"
    assert env.subject["action"] == "execute_trade"
    assert env.governance_context["tiers_passed"] == ["stpa"]


@pytest.mark.asyncio
async def test_gfa_raises_policy_violation_on_denied_verdict() -> None:
    """A verified DENIED envelope raises PolicyViolationException naming the violation."""
    client = _client(
        lambda request: httpx.Response(
            200,
            json={
                "verdict": "DENIED",
                "violations": ["OPA policy violation: trade_amount exceeds limit"],
                "latency_ms": 15.2,
            },
        )
    )

    sdk = await client.sdk_client()
    with pytest.raises(PolicyViolationException) as exc_info:
        await sdk.validate_action(
            "execute_trade",
            {"symbol": "AAPL", "amount": 999999},
            "governed-financial-advisor",
        )

    assert "trade_amount exceeds limit" in str(exc_info.value.violation_details)


@pytest.mark.asyncio
async def test_gfa_preserves_envelope_metadata() -> None:
    """Envelope metadata is preserved on the returned GovernanceEnvelope."""
    client = _client(
        lambda request: httpx.Response(
            200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 12.0}
        )
    )

    sdk = await client.sdk_client()
    env = await sdk.validate_action(
        "execute_trade", {"symbol": "AAPL"}, "governed-financial-advisor"
    )

    dumped = env.model_dump()
    for field in (
        "envelope_id",
        "envelope_version",
        "issuer",
        "subject",
        "signature",
        "governance_context",
        "external_attestations",
        "payload",
    ):
        assert field in dumped
    assert set(env.signature) == {"algorithm", "kid", "value"}


@pytest.mark.asyncio
async def test_gfa_refuses_an_unsigned_legacy_flat_dict() -> None:
    """A pre-v3.0 flat verdict carries no signature, so it is never routed."""
    client = _client(
        lambda request: httpx.Response(
            200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 30.0}
        ),
        sign=False,
    )

    sdk = await client.sdk_client()
    with pytest.raises(CageGatewayError, match="missing required 'envelope' field"):
        await sdk.validate_action(
            "execute_trade", {"symbol": "AAPL"}, "governed-financial-advisor"
        )


@pytest.mark.asyncio
async def test_gfa_refuses_a_tampered_envelope() -> None:
    """A DENIED envelope rewritten to ALLOW after signing fails verification."""
    stub = SignedGatewayStub()

    def tampered(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        envelope = stub.envelope(
            sent["action"], sent["params"], {"verdict": "DENIED", "violations": ["no"]}
        )
        envelope["payload"] = {"verdict": "ALLOW", "violations": []}
        return httpx.Response(200, json=envelope)

    GatewayClient._instance = None
    client = GatewayClient()
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(stub.transport_handler(tampered)),
        base_url="http://gateway.test",
    )

    sdk = await client.sdk_client()
    with pytest.raises(RoutingSealVerificationError):
        await sdk.validate_action(
            "execute_trade", {"symbol": "AAPL"}, "governed-financial-advisor"
        )


@pytest.mark.asyncio
async def test_gfa_refuses_an_envelope_bound_to_other_params() -> None:
    """An envelope signed for different parameters fails the subject binding."""
    stub = SignedGatewayStub()

    def substituted(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        return httpx.Response(
            200,
            json=stub.envelope(
                sent["action"], {"symbol": "AAPL", "amount": 1}, {"verdict": "ALLOW"}
            ),
        )

    GatewayClient._instance = None
    client = GatewayClient()
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(stub.transport_handler(substituted)),
        base_url="http://gateway.test",
    )

    sdk = await client.sdk_client()
    with pytest.raises(RoutingSealVerificationError):
        await sdk.validate_action(
            "execute_trade",
            {"symbol": "AAPL", "amount": 9000},
            "governed-financial-advisor",
        )


@pytest.mark.asyncio
async def test_gfa_unwraps_v3_envelope_on_retry_path() -> None:
    """A policy-drift 403 replays with the fresh pin and the replay is verified."""
    pins: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/governance/policy-version":
            return httpx.Response(200, json={"active_hash": "sha256:policy-v2"})
        pins.append(json.loads(request.content)["policy_version_id"])
        if len(pins) == 1:
            return httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": [
                        "Substrate Policy Drift Detected: policy version mismatch"
                    ],
                    "proof_hash": "sha256:test-drift-refusal",
                },
            )
        return httpx.Response(
            200,
            json={
                "envelope_id": "env-test-12345",
                "payload": {"verdict": "ALLOW", "violations": [], "latency_ms": 18.0},
            },
        )

    client = _client(handler)
    sdk = await client.sdk_client()
    result = await preview_trade_with_drift_revalidation(
        sdk,
        "execute_trade",
        {"symbol": "AAPL"},
        "governed-financial-advisor",
        {"policy_version_id": "sha256:policy-v1"},
    )

    assert pins == ["sha256:policy-v1", "sha256:policy-v2"]
    assert result.decision is GovernanceDecision.ALLOWED
    assert result.envelope is not None
    assert result.envelope.envelope_id == "env-test-12345"
    assert result.envelope.envelope_version == "3.0"
