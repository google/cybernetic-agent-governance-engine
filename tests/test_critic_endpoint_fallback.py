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
"""POAM-2026-127: a consensus critic never falls through to the OpenAI SDK's default.

A critic with no dedicated URL used ``GatewayClient``, which built
``AsyncOpenAI(base_url=VLLM_REASONING_API_BASE)``. Unset, the SDK targets
``https://api.openai.com/v1`` with the operator's ``VLLM_API_KEY`` and the trade
prompt. The documented minimum for ``CAGE_INFERENCE_BACKEND=external``
(``VLLM_BASE_URL`` + ``VLLM_API_KEY``) produced exactly that.

No test here makes a network call: every assertion reads a client's configured
base URL, and the refusal is raised before any request is built.
"""

from __future__ import annotations

import pytest

from config.settings import Config
from src.gateway.core.llm import GatewayClient, InferenceEndpointMissing

pytestmark = [pytest.mark.unit, pytest.mark.local]

OPENAI_PUBLIC = "api.openai.com"
_ENDPOINT_SETTINGS = (
    "VLLM_GATEWAY_URL",
    "VLLM_BASE_URL",
    "VLLM_REASONING_API_BASE",
    "VLLM_FAST_API_BASE",
    "VLLM_API_KEY",
)


def _configure(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for name in _ENDPOINT_SETTINGS:
        monkeypatch.setattr(Config, name, values.get(name))
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)


def test_external_minimum_routes_every_critic_to_the_configured_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(
        monkeypatch,
        VLLM_BASE_URL="https://models.example.test/v1",
        VLLM_API_KEY="sk-operator",
    )
    client = GatewayClient()
    for mode in ("verifier", "chat"):
        route_client, _model = client._get_route(mode)
        assert route_client is not None, f"mode {mode!r} has no client"
        base = str(route_client.base_url)
        assert OPENAI_PUBLIC not in base
        assert base.startswith("https://models.example.test/v1")


def test_routed_endpoints_still_take_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(
        monkeypatch,
        VLLM_BASE_URL="https://base.example.test/v1",
        VLLM_REASONING_API_BASE="https://reasoning.example.test/v1",
        VLLM_FAST_API_BASE="https://fast.example.test/v1",
        VLLM_API_KEY="k",
    )
    client = GatewayClient()
    assert str(client._get_route("verifier")[0].base_url).startswith(
        "https://reasoning.example.test/v1"
    )
    assert str(client._get_route("chat")[0].base_url).startswith(
        "https://fast.example.test/v1"
    )


@pytest.mark.asyncio
async def test_no_endpoint_refuses_instead_of_using_the_public_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, VLLM_API_KEY="sk-operator")
    client = GatewayClient()
    # Checked first, so a regression fails here rather than reaching the network.
    assert client.reasoning_client is None
    assert client.governance_client is None
    with pytest.raises(InferenceEndpointMissing, match="INFERENCE_BACKEND_URL_MISSING"):
        await client.generate(prompt="Approve this trade?", mode="verifier")


@pytest.mark.asyncio
async def test_a_critic_with_no_endpoint_votes_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.cage_finance.tiers.consensus_tier import build_finance_consensus_gate
    from src.gateway.governance.consensus.engine import ConsensusModelRegistry

    _configure(monkeypatch, VLLM_API_KEY="sk-operator")
    engine = build_finance_consensus_gate()
    engine._registry = ConsensusModelRegistry(
        {critic.role: {"base_url": "", "model": ""} for critic in engine.critics}
    )
    engine._default_client = GatewayClient()
    assert engine._default_client.reasoning_client is None  # no network below
    vote = await engine._get_critic_vote(
        engine.critics[0],
        "execute_trade",
        {"symbol": "AAPL", "amount": 25000.0},
        25000.0,
    )
    assert vote == "ERROR"
