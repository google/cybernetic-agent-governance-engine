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

"""RoutedCriticBackend: the critic transport that left the kernel (POAM-2026-168).

Covers both client paths: the per-role dedicated client and the shared
fallback client. The kernel's prompt rendering and vote parsing are tested in
tests/cage_finance/test_consensus_gate.py. No test makes a network call.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.gateway.governance.seams.critic import CriticBackend, CriticRequest
from src.integrations.inference_client.critic_backend import RoutedCriticBackend

pytestmark = [pytest.mark.unit, pytest.mark.local]

_FORMAT: dict[str, Any] = {"type": "json_schema", "json_schema": {"name": "vote"}}


def _request(role: str = "Risk Manager", model: str = "spec-model") -> CriticRequest:
    return CriticRequest(
        role=role,
        model=model,
        system_instruction="You are a strict Risk Manager.",
        prompt="ACTION: execute_trade",
        timeout_s=7.5,
        response_format=_FORMAT,
    )


def _completion(content: str | None) -> MagicMock:
    return MagicMock(choices=[MagicMock(message=MagicMock(content=content))])


def test_it_satisfies_the_kernel_seam() -> None:
    backend = RoutedCriticBackend({}, fallback=MagicMock())
    assert isinstance(backend, CriticBackend)


@pytest.mark.asyncio
async def test_a_dedicated_role_calls_its_own_endpoint() -> None:
    fallback = MagicMock()
    fallback.generate = AsyncMock()
    backend = RoutedCriticBackend(
        {"Risk Manager": {"base_url": "https://risk.example.test/v1", "model": "r1"}},
        fallback=fallback,
    )
    assert backend.has_dedicated_backend("Risk Manager")
    dedicated = backend._clients["Risk Manager"]
    assert str(dedicated.base_url).startswith("https://risk.example.test/v1")
    dedicated.chat.completions.create = AsyncMock(return_value=_completion("APPROVE"))

    assert await backend.complete(_request()) == "APPROVE"

    kwargs = dedicated.chat.completions.create.await_args.kwargs
    assert kwargs["model"] == "r1"  # the role's own model wins over the spec's
    assert kwargs["temperature"] == 0.0
    assert kwargs["timeout"] == 7.5
    assert kwargs["response_format"] == _FORMAT
    assert kwargs["messages"] == [
        {"role": "system", "content": "You are a strict Risk Manager."},
        {"role": "user", "content": "ACTION: execute_trade"},
    ]
    fallback.generate.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_dedicated_role_without_a_model_uses_the_spec_model() -> None:
    backend = RoutedCriticBackend(
        {"Risk Manager": {"base_url": "https://risk.example.test/v1", "model": ""}},
        fallback=MagicMock(),
    )
    dedicated = backend._clients["Risk Manager"]
    dedicated.chat.completions.create = AsyncMock(return_value=_completion(None))

    assert await backend.complete(_request(model="spec-model")) is None
    assert dedicated.chat.completions.create.await_args.kwargs["model"] == "spec-model"


@pytest.mark.asyncio
async def test_a_role_without_an_endpoint_uses_the_shared_client() -> None:
    fallback = MagicMock()
    fallback.generate = AsyncMock(return_value='{"decision": "REJECT", "reason": "x"}')
    backend = RoutedCriticBackend(
        {"Risk Manager": {"base_url": "", "model": ""}}, fallback=fallback
    )
    assert not backend.has_dedicated_backend("Risk Manager")

    assert await backend.complete(_request()) == '{"decision": "REJECT", "reason": "x"}'
    fallback.generate.assert_awaited_once_with(
        prompt="ACTION: execute_trade",
        system_instruction="You are a strict Risk Manager.",
        mode="verifier",
        temperature=0.0,
        response_format=_FORMAT,
    )


def test_from_env_reads_per_role_settings_and_alternates_split_brain_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CONSENSUS_RISK_MANAGER_URL", "https://risk.example.test/v1")
    monkeypatch.setenv("CONSENSUS_RISK_MANAGER_MODEL", "r1")
    monkeypatch.delenv("CONSENSUS_COMPLIANCE_OFFICER_URL", raising=False)
    monkeypatch.delenv("CONSENSUS_COMPLIANCE_OFFICER_MODEL", raising=False)
    monkeypatch.setenv("VLLM_FAST_API_BASE", "https://fast.example.test/v1")
    monkeypatch.setenv("MODEL_FAST", "fast-model")

    backend = RoutedCriticBackend.from_env(["Risk Manager", "Compliance Officer"])

    assert backend.model_for("Risk Manager") == "r1"
    # Second role, no dedicated URL: the fast split-brain endpoint.
    assert backend.has_dedicated_backend("Compliance Officer")
    assert str(backend._clients["Compliance Officer"].base_url).startswith(
        "https://fast.example.test/v1"
    )
    assert backend.model_for("Compliance Officer") == "fast-model"
