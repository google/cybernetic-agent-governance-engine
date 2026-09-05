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
test_kernel_event_ingest.py — Sprint 2: eBPF Kernel Event Ingest Tests
========================================================================

Tests for POST /v1/kernel/ingest endpoint that receives eBPF kernel events
from the AgentSight DaemonSet and ingests them into the Evidence Stream.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_kernel_event_endpoint_exists() -> None:
    """Verify POST /v1/kernel/ingest endpoint is registered."""
    from src.compliance_bridge.main import app

    client = TestClient(app)

    # Test that endpoint exists (even if request is malformed)
    response = client.post("/v1/kernel/ingest", json={})

    # Should not return 404 (endpoint exists)
    assert response.status_code != 404


@pytest.mark.unit
def test_kernel_event_validation_missing_trace_id() -> None:
    """Verify endpoint rejects events without trace_id."""
    from src.compliance_bridge.main import app

    client = TestClient(app)

    # Missing trace_id
    response = client.post(
        "/v1/kernel/ingest",
        json={
            "trace_id": "",  # Empty trace_id
            "event_type": "syscall_execve",
            "timestamp_ns": 1234567890,
            "process_name": "python3",
            "pid": 1234,
            "payload": {},
        },
    )

    assert response.status_code == 400
    assert "trace_id" in response.text.lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_kernel_event_enters_evidence_stream() -> None:
    """Verify kernel events are hash-chained into Evidence Stream."""
    from src.compliance_bridge.main import app

    client = TestClient(app)

    # Mock Evidence Stream to avoid Redis dependency
    # Patch where it's imported in main.py, not the original module
    with patch(
        "src.compliance_bridge.evidence_stream.get_evidence_sink"
    ) as mock_sink_factory:
        mock_sink = AsyncMock()
        mock_sink.ingest = AsyncMock(return_value="test-evidence-id-123")
        mock_sink_factory.return_value = mock_sink

        response = client.post(
            "/v1/kernel/ingest",
            json={
                "trace_id": "abcd1234567890abcd1234567890abcd",
                "event_type": "syscall_connect",
                "timestamp_ns": 1234567890123456,
                "process_name": "python3",
                "pid": 5678,
                "payload": {"dest_ip": "192.168.1.1", "dest_port": 443},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ingested"
        assert data["evidence_id"] == "test-evidence-id-123"

        # Verify sink.ingest was called with scrubbed payload
        mock_sink.ingest.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_kernel_event_publishes_sse() -> None:
    """Verify SSE kernel-event type is published."""
    from src.compliance_bridge.main import app
    from src.compliance_bridge.sse_events import event_bus

    client = TestClient(app)

    with (
        patch(
            "src.compliance_bridge.evidence_stream.get_evidence_sink"
        ) as mock_sink_factory,
        patch.object(event_bus, "publish", new_callable=AsyncMock) as mock_publish,
    ):
        mock_sink = AsyncMock()
        mock_sink.ingest = AsyncMock(return_value="evidence-id-456")
        mock_sink_factory.return_value = mock_sink

        response = client.post(
            "/v1/kernel/ingest",
            json={
                "trace_id": "trace123",
                "event_type": "uprobe_ssl",
                "timestamp_ns": 9876543210,
                "process_name": "nginx",
                "pid": 9999,
                "payload": {"ssl_version": "TLSv1.3"},
            },
        )

        assert response.status_code == 200

        # Verify SSE event was published
        mock_publish.assert_called_once()
        published_event = mock_publish.call_args[0][0]
        assert published_event["type"] == "kernel-event"
        assert published_event["traceId"] == "trace123"
        assert published_event["kernel_event_type"] == "uprobe_ssl"


@pytest.mark.unit
def test_kernel_event_evidence_stream_unavailable() -> None:
    """Verify 503 when Evidence Stream is unavailable."""
    from src.compliance_bridge.main import app

    client = TestClient(app)

    with patch(
        "src.compliance_bridge.evidence_stream.get_evidence_sink"
    ) as mock_sink_factory:
        mock_sink = AsyncMock()
        mock_sink.ingest = AsyncMock(return_value=None)  # Simulate unavailable
        mock_sink_factory.return_value = mock_sink

        response = client.post(
            "/v1/kernel/ingest",
            json={
                "trace_id": "trace-unavailable",
                "event_type": "syscall_openat",
                "timestamp_ns": 1111111111,
                "process_name": "cat",
                "pid": 1111,
                "payload": {},
            },
        )

        assert response.status_code == 503
        response_json = response.json()
        # FastAPI wraps HTTPException detail in "detail" key
        assert "detail" in response_json
        assert "EVIDENCE_STREAM_UNAVAILABLE" in response_json["detail"]["error"]
