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

"""test_compliance_bridge_infra_events.py

Unit tests for the POST /v1/infra/events endpoint in compliance_bridge.main.
Validates:
  - Authentication via verified Linkerd workload identity (refusing legacy Bearer tokens)
  - Schema validation and event type routing across jurisdictional maps
  - Secret scrubbing in summary text prior to canonical hashing
  - Rejection (422) for unregistered event types
  - Fail-closed durable persistence to InfraEvidenceChain
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

from src.compliance_bridge.infra_custody import InfraEvidenceChain
from src.compliance_bridge.main import app

pytestmark = [pytest.mark.unit, pytest.mark.local]

POD_IP = "10.24.1.7"
PROXY_PEER = (POD_IP, 50000)
BASE_URL = f"http://{POD_IP}:3001"
STREAM_KEY = "cage:evidence:infra:bridge-unit"
AGENTSIGHT_L5D = (
    "agentsight-daemon.governance-stack.serviceaccount.identity.linkerd.cluster.local"
)
LEGACY_TOKEN = "test-internal-token-secret"


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"l5d-client-id": AGENTSIGHT_L5D}


@pytest.fixture
def fake_server() -> fakeredis.FakeServer:
    return fakeredis.FakeServer()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, fake_server: fakeredis.FakeServer):
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.setenv("EVIDENCE_STREAM_ENABLED", "false")
    chain = InfraEvidenceChain(
        fakeredis.FakeAsyncRedis(server=fake_server, decode_responses=True),
        stream_key=STREAM_KEY,
    )
    app.state.infra_evidence_chain = chain
    try:
        with patch("src.compliance_bridge.main.Langfuse", return_value=MagicMock()):
            with TestClient(
                app,
                client=PROXY_PEER,
                base_url=BASE_URL,
                raise_server_exceptions=False,
            ) as c:
                yield c
    finally:
        if hasattr(app.state, "infra_evidence_chain"):
            delattr(app.state, "infra_evidence_chain")


class TestInfraEventsAuth:
    def test_missing_identity_returns_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", LEGACY_TOKEN)
        payload = {
            "event_type": "agentsight_syscall",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "execve(/usr/bin/python3)",
            "control_hint": "AU-2",
        }
        res = client.post("/v1/infra/events", json=payload)
        assert res.status_code == 401

    def test_bearer_token_without_mesh_identity_returns_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", LEGACY_TOKEN)
        payload = {
            "event_type": "agentsight_syscall",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "execve(/usr/bin/python3)",
            "control_hint": "AU-2",
        }
        res = client.post(
            "/v1/infra/events",
            json=payload,
            headers={"Authorization": f"Bearer {LEGACY_TOKEN}"},
        )
        assert res.status_code == 401


class TestInfraEventsIngestion:
    @pytest.mark.parametrize(
        ("event_type", "expected_control"),
        [
            ("agentsight_syscall", "AU-2"),
            ("agentsight_fim", "SI-7"),
            ("cilium_l7_flow", "SC-7"),
        ],
    )
    def test_valid_infra_event_ingestion(
        self,
        client: TestClient,
        fake_server: fakeredis.FakeServer,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        event_type: str,
        expected_control: str,
    ) -> None:
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        payload = {
            "event_type": event_type,
            "source": "agentsight-daemon",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": f"Observed event for {event_type}",
            "control_hint": expected_control,
        }

        res = client.post("/v1/infra/events", json=payload, headers=auth_headers)

        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "INGESTED"
        assert data["event_type"] == event_type
        assert data["control_id"] == expected_control
        assert data["evidence_class"] == "INFRA"
        assert data["source"] == "agentsight-daemon"
        assert data["namespace"] == "governance-stack"
        assert data["producer_timestamp_utc"] == "2026-09-06T20:00:00Z"
        assert data["received_at_utc"] != "2026-09-06T20:00:00Z"

        sync_redis = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
        entries = sync_redis.xrange(STREAM_KEY)
        assert len(entries) == 1
        _, ingested_record = entries[0]
        assert ingested_record["evidence_class"] == "INFRA"
        assert ingested_record["control_id"] == expected_control
        assert ingested_record["record_hash"] == data["record_hash"]

    def test_secret_scrubbing_in_summary(
        self,
        client: TestClient,
        fake_server: fakeredis.FakeServer,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        payload = {
            "event_type": "agentsight_syscall",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "connect with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and sk-lf-12345678abcdef",
            "control_hint": "AU-2",
        }

        res = client.post("/v1/infra/events", json=payload, headers=auth_headers)

        assert res.status_code == 200
        sync_redis = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
        entries = sync_redis.xrange(STREAM_KEY)
        assert len(entries) == 1
        _, ingested_record = entries[0]
        payload_data = json.loads(ingested_record["payload_json"])
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in payload_data["summary"]
        assert "sk-lf-12345678abcdef" not in payload_data["summary"]
        assert "[REDACTED]" in payload_data["summary"]

    def test_invalid_event_type_rejected(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        payload = {
            "event_type": "invalid_event_type",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "exploit",
            "control_hint": "NONE",
        }
        res = client.post("/v1/infra/events", json=payload, headers=auth_headers)
        assert res.status_code == 422
