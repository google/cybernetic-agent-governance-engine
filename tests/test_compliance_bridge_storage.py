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

"""tests/test_compliance_bridge_storage.py — Unit tests for compliance bridge artifact storage."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.compliance_bridge import storage
from src.gateway.governance.evidence.cold_store import ColdStoreReceipt
from src.gateway.governance.evidence.null_cold_store import NullColdStore


@pytest.mark.local
@pytest.mark.unit
def test_build_object_key_and_sha256():
    ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
    key = storage._build_object_key("audit-999", ts)
    assert key == "oscal-artifacts/2026-08-16/audit-999.yaml"

    digest = storage._sha256("test-content")
    assert isinstance(digest, str)
    assert len(digest) == 64


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_atomic_delegates_to_injected_store():
    mock_store = AsyncMock()
    mock_receipt = ColdStoreReceipt(
        uri="gs://test-bucket/oscal-artifacts/2026-08-16/audit-123.yaml",
        key="oscal-artifacts/2026-08-16/audit-123.yaml",
        content_sha256=storage._sha256("dummy-yaml"),
        backend_id="gcs",
        written_at=datetime.now(tz=timezone.utc),
    )
    mock_store.put_if_absent = AsyncMock(return_value=(mock_receipt, True))

    ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
    key, created = await storage.put_oscal_artifact_atomic(
        audit_id="audit-123",
        oscal_yaml="dummy-yaml",
        timestamp=ts,
        cold_store=mock_store,
    )

    assert key == "oscal-artifacts/2026-08-16/audit-123.yaml"
    assert created is True

    mock_store.put_if_absent.assert_awaited_once()
    call_kwargs = mock_store.put_if_absent.call_args.kwargs
    assert call_kwargs["key"] == "oscal-artifacts/2026-08-16/audit-123.yaml"
    assert call_kwargs["content"] == b"dummy-yaml"
    assert call_kwargs["metadata"]["x-audit-id"] == "audit-123"
    assert call_kwargs["metadata"]["x-standard"] == "ISO/IEC 42001:2023"
    assert call_kwargs["metadata"]["content-type"] == "application/yaml"


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_idempotent():
    """Test that put_oscal_artifact returns existing key when artifact already exists."""
    mock_store = AsyncMock()
    mock_receipt = ColdStoreReceipt(
        uri="s3://test-bucket/oscal-artifacts/2026-08-16/audit-123.yaml",
        key="oscal-artifacts/2026-08-16/audit-123.yaml",
        content_sha256=storage._sha256("dummy-yaml"),
        backend_id="s3",
        written_at=datetime.now(tz=timezone.utc),
    )
    mock_store.put_if_absent = AsyncMock(return_value=(mock_receipt, False))

    ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
    key = await storage.put_oscal_artifact(
        audit_id="audit-123",
        oscal_yaml="dummy-yaml",
        timestamp=ts,
        cold_store=mock_store,
    )

    assert key == "oscal-artifacts/2026-08-16/audit-123.yaml"


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_null_store_integration():
    """Test full integration between OSCAL storage and NullColdStore."""
    null_store = NullColdStore()
    ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)

    key1, created1 = await storage.put_oscal_artifact_atomic(
        audit_id="audit-456",
        oscal_yaml="test-oscal-content",
        timestamp=ts,
        cold_store=null_store,
    )
    assert key1 == "oscal-artifacts/2026-08-16/audit-456.yaml"
    assert created1 is True

    # Second atomic write with same key should indicate not created
    key2, created2 = await storage.put_oscal_artifact_atomic(
        audit_id="audit-456",
        oscal_yaml="test-oscal-content",
        timestamp=ts,
        cold_store=null_store,
    )
    assert key2 == "oscal-artifacts/2026-08-16/audit-456.yaml"
    assert created2 is False


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_resolves_factory_when_none():
    """Test ambient factory resolution when cold_store is None."""
    null_store = NullColdStore()
    ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)

    with patch(
        "src.gateway.governance.evidence.factory.get_cold_store",
        return_value=null_store,
    ) as mock_factory:
        key = await storage.put_oscal_artifact(
            audit_id="audit-789",
            oscal_yaml="test-oscal-content",
            timestamp=ts,
            cold_store=None,
        )
        assert key == "oscal-artifacts/2026-08-16/audit-789.yaml"
        mock_factory.assert_called_once()
