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

"""Unit tests for CagePolicyProvider and STPA policy loader."""

from __future__ import annotations

import httpx
import pytest

from openshell_provider_cage.models import PolicyProposal
from openshell_provider_cage.ocsf import scrub_credentials
from openshell_provider_cage.provider import CagePolicyProvider
from openshell_provider_cage.stpa_loader import load_cage_sandbox_policy

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture()
def proposal() -> PolicyProposal:
    return PolicyProposal(
        sandbox_id="sbx-test-1",
        thread_id="thread-test-1",
        action="transfer_funds",
        requested_endpoint="https://bank.internal/api/transfer",
        requested_http_verb="POST",
        params={"amount": 500.0, "currency": "USD"},
    )


class TestCagePolicyProvider:
    """Tests for CagePolicyProvider evaluating proposals against CAGE."""

    @pytest.mark.asyncio
    async def test_evaluate_allows_clean_proposal(self, proposal: PolicyProposal) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["l5d-client-id"] == "spiffe://cluster.local/ns/cage/sa/openshell"
            return httpx.Response(
                200,
                json={
                    "verdict": "ALLOW",
                    "seal": "seal-hex-abc123",
                    "latency_ms": 1.2,
                },
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = CagePolicyProvider(
            endpoint="https://cage-gateway.internal:8080",
            client_identity="spiffe://cluster.local/ns/cage/sa/openshell",
            http_client=client,
        )
        outcome = await provider.evaluate(proposal)
        assert outcome.allowed is True
        assert outcome.deferred is False
        assert outcome.rejected is False
        assert outcome.decision == "ALLOW"
        assert outcome.routing_seal == "seal-hex-abc123"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_evaluate_parks_require_approval_proposal(self, proposal: PolicyProposal) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "verdict": "REQUIRE_APPROVAL",
                    "deferred_id": "defer-tok-999",
                    "classification_reason": "High risk action requires dual-control HITL",
                },
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = CagePolicyProvider(
            endpoint="https://cage-gateway.internal:8080",
            http_client=client,
        )
        outcome = await provider.evaluate(proposal)
        assert outcome.allowed is False
        assert outcome.deferred is True
        assert outcome.rejected is False
        assert outcome.decision == "REQUIRE_APPROVAL"
        assert outcome.defer_id == "defer-tok-999"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_evaluate_detects_quarantine_on_hard_denial(self, proposal: PolicyProposal) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={
                    "error": "GovernanceError",
                    "message": "CBF safety barrier breached",
                    "payload": {
                        "quarantined": True,
                        "quarantine_rule_id": "qrule-cbf-01",
                    },
                    "violations": ["[CBF_BARRIER_BREACH] Barrier breached"],
                },
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = CagePolicyProvider(
            endpoint="https://cage-gateway.internal:8080",
            http_client=client,
        )
        outcome = await provider.evaluate(proposal)
        assert outcome.allowed is False
        assert outcome.deferred is False
        assert outcome.rejected is True
        assert outcome.decision == "DENY"
        assert outcome.quarantine_triggered is True
        assert "barrier breached" in outcome.rejection_reason.lower()
        await client.aclose()

    @pytest.mark.asyncio
    async def test_evaluate_fails_closed_on_network_error(self, proposal: PolicyProposal) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused by gateway")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = CagePolicyProvider(
            endpoint="https://cage-gateway.internal:8080",
            http_client=client,
        )
        outcome = await provider.evaluate(proposal)
        assert outcome.allowed is False
        assert outcome.deferred is False
        assert outcome.rejected is True
        assert "unreachable" in outcome.rejection_reason
        assert "FAIL_CLOSED_GATEWAY_UNREACHABLE" in outcome.violations
        await client.aclose()


class TestStpaPolicyLoaderAndOcsf:
    """Tests for policy loading and OCSF scrubbing."""

    def test_load_cage_sandbox_policy(self, tmp_path: pytest.TempPathFactory) -> None:
        p = tmp_path / "sandbox.yaml"
        p.write_text(
            """\
metadata:
  system: "TestSystem"
  require_cage_stera_seal: true
filesystem_policy:
  read_only: ["/usr", "/lib"]
  read_write: ["/sandbox", "/var/sandbox/scratch"]
process:
  allowed_binaries: ["/bin/ls", "/usr/bin/curl"]
credential_broker_rules:
  api_key: "vault:secret/api"
network_policies:
  egress:
    - endpoint: "https://api.internal"
"""
        )
        parsed = load_cage_sandbox_policy(p)
        assert parsed["landlock_ro_paths"] == ["/usr", "/lib"]
        assert parsed["landlock_rw_paths"] == ["/sandbox", "/var/sandbox/scratch"]
        assert parsed["allowed_binaries"] == ["/bin/ls", "/usr/bin/curl"]

    def test_scrub_credentials(self) -> None:
        data = {
            "token": "sk-lf-secret123456",
            "hf": "hf_abcdefghijklmnopqrstuvwxyz",
            "normal": "safe_value",
        }
        cleaned = scrub_credentials(data)
        assert cleaned["token"] == "[REDACTED_CREDENTIAL]"
        assert cleaned["hf"] == "[REDACTED_CREDENTIAL]"
        assert cleaned["normal"] == "safe_value"
