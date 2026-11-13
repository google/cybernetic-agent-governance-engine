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
GovernanceEnvelope v3.0 handling in the advisor's ``GatewayClient``.

``GatewayClient.validate_action()`` delegates the exchange to the installed
``cage-client`` wheel, which verifies the envelope's out-of-band ``kid``
signature, ``expires_at`` freshness and ``subject.action_hash`` binding. These
tests drive the real client over an ``httpx.MockTransport`` and check that a
verified envelope is unwrapped into the advisor's routing dictionary, and that
an unsigned or tampered answer is never routed.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest
from cage_client import RoutingSealVerificationError

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
    """A verified ALLOW envelope is unwrapped: payload fields plus provenance."""
    client = _client(
        lambda request: httpx.Response(
            200,
            json={
                "envelope_id": "env-test-12345",
                "payload": {"verdict": "ALLOW", "violations": [], "latency_ms": 42.5},
            },
        )
    )

    result = await client.validate_action(
        "execute_trade", {"symbol": "AAPL", "amount": 1000}
    )

    assert result["verdict"] == "ALLOW"
    assert "seal" not in result
    assert result["violations"] == []
    assert result["latency_ms"] == 42.5
    assert result["envelope_id"] == "env-test-12345"
    assert result["envelope_version"] == "3.0"
    assert result["issuer"]["service"] == "cage-gateway"
    assert result["subject"]["action"] == "execute_trade"
    assert result["governance_context"]["tiers_passed"] == ["stpa"]


@pytest.mark.asyncio
async def test_gfa_raises_permission_error_on_denied_verdict() -> None:
    """A verified DENIED envelope raises PermissionError naming the violation."""
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

    with pytest.raises(PermissionError) as exc_info:
        await client.validate_action(
            "execute_trade", {"symbol": "AAPL", "amount": 999999}
        )

    assert "execute_trade" in str(exc_info.value)
    assert "trade_amount exceeds limit" in str(exc_info.value)


@pytest.mark.asyncio
async def test_gfa_preserves_envelope_metadata() -> None:
    """Envelope metadata sits alongside the payload fields in the result."""
    client = _client(
        lambda request: httpx.Response(
            200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 12.0}
        )
    )

    result = await client.validate_action("execute_trade", {"symbol": "AAPL"})

    for field in (
        "envelope_id",
        "envelope_version",
        "issuer",
        "subject",
        "signature",
        "governance_context",
        "external_attestations",
        "verdict",
        "violations",
        "latency_ms",
    ):
        assert field in result
    assert "seal" not in result
    assert set(result["signature"]) == {"algorithm", "kid", "value"}


@pytest.mark.asyncio
async def test_gfa_refuses_an_unsigned_legacy_flat_dict() -> None:
    """A pre-v3.0 flat verdict carries no signature, so it is never routed."""
    client = _client(
        lambda request: httpx.Response(
            200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 30.0}
        ),
        sign=False,
    )

    with pytest.raises(PermissionError, match="no routable verdict"):
        await client.validate_action("execute_trade", {"symbol": "AAPL"})


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

    with pytest.raises(RoutingSealVerificationError):
        await client.validate_action("execute_trade", {"symbol": "AAPL"})


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

    with pytest.raises(RoutingSealVerificationError):
        await client.validate_action(
            "execute_trade", {"symbol": "AAPL", "amount": 9000}
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
                    "violations": [
                        "Substrate Policy Drift Detected: policy version mismatch"
                    ]
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
    result = await client.validate_action(
        "execute_trade", {"symbol": "AAPL"}, policy_version_id="sha256:policy-v1"
    )

    assert pins == ["sha256:policy-v1", "sha256:policy-v2"]
    assert result["verdict"] == "ALLOW"
    assert result["envelope_id"] == "env-test-12345"
    assert result["envelope_version"] == "3.0"
