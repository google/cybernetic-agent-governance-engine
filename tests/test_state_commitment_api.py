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

"""``POST /governance/state-commitments`` and its advisor-side client.

The endpoint is exercised behind the production ``WorkloadIdentityMiddleware``
(Linkerd ``l5d-client-id`` allow-list) mounted exactly as in ``hybrid_server``;
``GatewayClient.commit_state`` is exercised against the real endpoint through
an ASGI transport, so both halves of the wire contract are covered.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from src.gateway.governance.evidence.state_commitment import StateCommitmentService
from src.gateway.governance.seams.state_commitment import (
    STATE_COMMITMENT_METHOD,
    StateCommitmentError,
    StateCommitmentLinkage,
)
from src.gateway.server.state_commitment_api import router
from src.gateway.server.workload_identity import (
    IdentityPolicy,
    WorkloadIdentityMiddleware,
)
from tests.integrations.provider_02.state_commitment_support import (
    RecordingEvidenceSink,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

TRUSTED = "advisor.cage.serviceaccount.identity.linkerd.cluster.local"
UNTRUSTED = "intruder.cage.serviceaccount.identity.linkerd.cluster.local"


def _apps(sink: RecordingEvidenceSink | None, *, with_service: bool = True) -> FastAPI:
    governance = FastAPI()
    governance.include_router(router)
    if with_service:
        governance.state.state_commitments = StateCommitmentService(sink)
    root = FastAPI()
    root.mount("/governance", governance)
    root.add_middleware(
        WorkloadIdentityMiddleware, policy=IdentityPolicy(trusted=frozenset({TRUSTED}))
    )
    return root


def _body(**snapshot: Any) -> dict[str, Any]:
    return {
        "snapshot": snapshot or {"loop_count": 1, "note": "mail a@example.com"},
        "linkage": StateCommitmentLinkage(
            namespace="provider_02",
            bundle_id="b-1",
            step_id="s-1",
            thread_id="t-1",
            label="evaluator",
        ).to_dict(),
    }


async def _post(
    app: FastAPI, body: Any, headers: dict[str, str] | None = None
) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
        return await client.post(
            "/governance/state-commitments", json=body, headers=headers or {}
        )


class TestEndpointIdentity:
    @pytest.mark.asyncio
    async def test_missing_identity_is_refused(self) -> None:
        sink = RecordingEvidenceSink()
        response = await _post(_apps(sink), _body())
        assert response.status_code == 403
        assert sink.payloads == []

    @pytest.mark.asyncio
    async def test_untrusted_identity_is_refused(self) -> None:
        sink = RecordingEvidenceSink()
        response = await _post(_apps(sink), _body(), {"l5d-client-id": UNTRUSTED})
        assert response.status_code == 403
        assert sink.payloads == []

    @pytest.mark.asyncio
    async def test_hmac_seal_header_is_not_authentication(self) -> None:
        sink = RecordingEvidenceSink()
        response = await _post(
            _apps(sink), _body(), {"x-cage-routing-seal": "deadbeef" * 8}
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_trusted_identity_commits_and_is_recorded(self) -> None:
        sink = RecordingEvidenceSink()
        response = await _post(_apps(sink), _body(), {"l5d-client-id": TRUSTED})
        assert response.status_code == 200, response.text
        receipt = response.json()
        assert receipt["method"] == dict(STATE_COMMITMENT_METHOD)
        (payload_json,) = sink.payloads
        payload = json.loads(payload_json)
        assert payload["callerIdentity"] == TRUSTED
        assert payload["stateHash"] == receipt["stateHash"]
        assert "a@example.com" not in payload_json


class TestEndpointErrors:
    @pytest.mark.asyncio
    async def test_chain_outage_is_503(self) -> None:
        response = await _post(
            _apps(RecordingEvidenceSink(fail=True)),
            _body(),
            {"l5d-client-id": TRUSTED},
        )
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_missing_service_is_503(self) -> None:
        response = await _post(
            _apps(None, with_service=False), _body(), {"l5d-client-id": TRUSTED}
        )
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_bad_linkage_is_422(self) -> None:
        body = _body()
        body["linkage"]["stepId"] = "../../etc"
        response = await _post(
            _apps(RecordingEvidenceSink()), body, {"l5d-client-id": TRUSTED}
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_oversized_snapshot_is_413(self) -> None:
        from src.gateway.governance.evidence.state_commitment import (
            MAX_PREIMAGE_BYTES,
        )

        response = await _post(
            _apps(RecordingEvidenceSink()),
            _body(blob="x" * (MAX_PREIMAGE_BYTES + 1)),
            {"l5d-client-id": TRUSTED},
        )
        assert response.status_code == 413

    def test_oversized_snapshot_rejected_before_pii_sanitization(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Issue #405: MAX_PREIMAGE_BYTES is checked before PII regex sanitization runs."""
        from src.gateway.governance.evidence import state_commitment as sc

        called = False

        def _forbid_sanitize(_val: Any) -> Any:
            nonlocal called
            called = True
            raise AssertionError("_sanitize must not run on oversized snapshots")

        monkeypatch.setattr(sc, "_sanitize", _forbid_sanitize)
        with pytest.raises(
            StateCommitmentError, match="canonical preimage is .* bytes; limit"
        ):
            sc.canonicalize_state({"blob": "x" * (sc.MAX_PREIMAGE_BYTES + 1)})
        assert called is False



class TestGatewayClientCommitState:
    """``GatewayClient.commit_state`` against the real endpoint (ASGI transport)."""

    @staticmethod
    def _client(app: FastAPI, identity: str | None = TRUSTED) -> Any:
        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )

        client = object.__new__(GatewayClient)
        headers = {"l5d-client-id": identity} if identity else {}
        client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
            transport=httpx.ASGITransport(app=app),
            base_url="http://gw",
            headers=headers,  # stands in for the Linkerd proxy
        )
        client._base_url = "http://gw"  # type: ignore[attr-defined]
        return client

    @staticmethod
    def _linkage() -> StateCommitmentLinkage:
        return StateCommitmentLinkage.from_dict(_body()["linkage"])

    @pytest.mark.asyncio
    async def test_returns_validated_receipt(self) -> None:
        sink = RecordingEvidenceSink()
        client = self._client(_apps(sink))
        receipt = await client.commit_state({"loop_count": 3}, linkage=self._linkage())
        assert dict(receipt.method) == dict(STATE_COMMITMENT_METHOD)
        assert len(sink.payloads) == 1

    @pytest.mark.asyncio
    async def test_refusal_raises(self) -> None:
        client = self._client(_apps(RecordingEvidenceSink()), identity=UNTRUSTED)
        with pytest.raises(StateCommitmentError):
            await client.commit_state({"a": 1}, linkage=self._linkage())

    @pytest.mark.asyncio
    async def test_chain_outage_raises(self) -> None:
        client = self._client(_apps(RecordingEvidenceSink(fail=True)))
        with pytest.raises(StateCommitmentError):
            await client.commit_state({"a": 1}, linkage=self._linkage())

    @pytest.mark.asyncio
    async def test_transport_error_raises(self) -> None:
        def _boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("gateway down", request=request)

        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )

        client = object.__new__(GatewayClient)
        client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
            transport=httpx.MockTransport(_boom), base_url="http://gw"
        )
        with pytest.raises(StateCommitmentError):
            await client.commit_state({"a": 1}, linkage=self._linkage())

    @pytest.mark.asyncio
    async def test_receipt_with_wrong_method_is_rejected(self) -> None:
        def _forged(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "stateHash": "a" * 64,
                    "evidenceId": "1-0",
                    "evidenceRecordHash": "b" * 64,
                    "sequence": 0,
                    "method": {"stateHashAlg": "md5"},
                },
            )

        from src.governed_financial_advisor.infrastructure.gateway_client import (
            GatewayClient,
        )

        client = object.__new__(GatewayClient)
        client._http = httpx.AsyncClient(  # type: ignore[attr-defined]
            transport=httpx.MockTransport(_forged), base_url="http://gw"
        )
        with pytest.raises(StateCommitmentError):
            await client.commit_state({"a": 1}, linkage=self._linkage())
