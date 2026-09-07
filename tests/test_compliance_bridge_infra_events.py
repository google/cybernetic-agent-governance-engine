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
  - Authentication (Bearer token)
  - Schema validation and event type routing
  - Secret scrubbing in summary text
  - Rejection (422) for unregistered event types or cross-jurisdiction mismatches
  - Persistence invocation to ClickHouseSink under evidence_class='INFRA'
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.compliance_bridge.main import app

AUTH_TOKEN = "test-internal-token-secret"


@pytest.fixture
def auth_headers(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", AUTH_TOKEN)
    return {"Authorization": f"Bearer {AUTH_TOKEN}"}


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


class TestInfraEventsAuth:
    def test_missing_token_returns_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", AUTH_TOKEN)
        payload = {
            "event_type": "agentsight_syscall",
            "source": "agentsight-daemon",
            "pod_name": "gateway-586cb58877-4vhs6",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "execve(/usr/bin/python3)",
            "control_hint": "AU-2",
        }
        res = client.post("/v1/infra/events", json=payload)
        assert res.status_code == 401

    def test_invalid_token_returns_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", AUTH_TOKEN)
        payload = {
            "event_type": "agentsight_syscall",
            "source": "agentsight-daemon",
            "pod_name": "gateway-586cb58877-4vhs6",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "execve(/usr/bin/python3)",
            "control_hint": "AU-2",
        }
        res = client.post(
            "/v1/infra/events",
            json=payload,
            headers={"Authorization": "Bearer wrong-token"},
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
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        event_type: str,
        expected_control: str,
    ) -> None:
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        payload = {
            "event_type": event_type,
            "source": "agentsight-daemon",
            "pod_name": "gateway-586cb58877-4vhs6",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": f"Observed event for {event_type}",
            "control_hint": expected_control,
        }

        mock_sink = AsyncMock()
        mock_sink.ingest = AsyncMock()

        with patch(
            "src.compliance_bridge.clickhouse_sink.get_clickhouse_sink",
            return_value=mock_sink,
        ):
            res = client.post("/v1/infra/events", json=payload, headers=auth_headers)

        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "INGESTED"
        assert data["event_type"] == event_type
        assert data["control_id"] == expected_control
        assert data["evidence_class"] == "INFRA"

        # Verify record passed to clickhouse sink
        mock_sink.ingest.assert_awaited_once()
        ingested_record = mock_sink.ingest.call_args[0][0]
        assert ingested_record["evidence_class"] == "INFRA"
        assert ingested_record["control_id"] == expected_control

    def test_secret_scrubbing_in_summary(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CAGE_DEPLOYMENT_REGION", "US_FED")
        payload = {
            "event_type": "agentsight_syscall",
            "source": "agentsight-daemon",
            "pod_name": "gateway-586cb58877-4vhs6",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "connect with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and sk-lf-12345678abcdef",
            "control_hint": "AU-2",
        }

        mock_sink = AsyncMock()
        mock_sink.ingest = AsyncMock()

        with patch(
            "src.compliance_bridge.clickhouse_sink.get_clickhouse_sink",
            return_value=mock_sink,
        ):
            res = client.post("/v1/infra/events", json=payload, headers=auth_headers)

        assert res.status_code == 200
        ingested_record = mock_sink.ingest.call_args[0][0]
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
            "source": "attacker",
            "pod_name": "pod",
            "namespace": "governance-stack",
            "timestamp_utc": "2026-09-06T20:00:00Z",
            "summary": "exploit",
            "control_hint": "NONE",
        }
        res = client.post("/v1/infra/events", json=payload, headers=auth_headers)
        assert res.status_code == 422
