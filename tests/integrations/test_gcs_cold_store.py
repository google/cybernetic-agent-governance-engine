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

"""test_gcs_cold_store.py — Hermetic Unit Tests for GcsColdStore Adapter (Layer 3)

Validates:
1. EvidenceColdStore runtime protocol compliance
2. put_batch / exists / put_if_absent behavior using mocked GCS client
3. Generation-0 precondition checking for atomic CAS
4. Proper mapping of PreconditionFailed to (receipt, False)
5. Proper wrapping of GCS errors into ColdStoreError
6. Health check reporting
"""

import hashlib
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import PreconditionFailed

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    EvidenceColdStore,
)
from src.integrations.storage_gcs import GcsColdStore

pytestmark = [pytest.mark.unit]


def _create_mock_client():
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    return mock_client, mock_bucket, mock_blob


def test_gcs_cold_store_protocol_conformance():
    """GcsColdStore must satisfy the EvidenceColdStore protocol."""
    store = GcsColdStore(bucket_name="test-bucket")
    assert isinstance(store, EvidenceColdStore)
    assert store.backend_id == "gcs"


@pytest.mark.asyncio
async def test_gcs_cold_store_put_batch_success():
    """put_batch uploads content bytes and returns ColdStoreReceipt."""
    store = GcsColdStore(bucket_name="test-bucket", timeout=10.0)
    mock_client, mock_bucket, mock_blob = _create_mock_client()
    store._client = mock_client

    content = b'{"event": "EVIDENCE_TEST", "seq": 42}\n'
    expected_sha = hashlib.sha256(content).hexdigest()

    receipt = await store.put_batch(
        key="evidence/2026/09/batch_42.ndjson",
        content=content,
        metadata={"x-control": "ISO_42001"},
    )

    mock_client.bucket.assert_called_once_with("test-bucket")
    mock_bucket.blob.assert_called_once_with(
        "evidence/2026/09/batch_42.ndjson", kms_key_name=None
    )
    mock_blob.upload_from_string.assert_called_once_with(
        content,
        content_type="application/x-ndjson",
        timeout=10.0,
    )
    assert mock_blob.metadata == {"x-control": "ISO_42001"}

    assert receipt.uri == "gs://test-bucket/evidence/2026/09/batch_42.ndjson"
    assert receipt.key == "evidence/2026/09/batch_42.ndjson"
    assert receipt.content_sha256 == expected_sha
    assert receipt.backend_id == "gcs"


@pytest.mark.asyncio
async def test_gcs_cold_store_exists():
    """exists checks blob existence via GCS SDK."""
    store = GcsColdStore(bucket_name="test-bucket")
    mock_client, _, mock_blob = _create_mock_client()
    store._client = mock_client

    mock_blob.exists.return_value = True
    assert await store.exists("key1") is True

    mock_blob.exists.return_value = False
    assert await store.exists("key2") is False


@pytest.mark.asyncio
async def test_gcs_cold_store_put_if_absent_created():
    """put_if_absent passes if_generation_match=0 and returns created=True when new."""
    store = GcsColdStore(bucket_name="test-bucket")
    mock_client, _, mock_blob = _create_mock_client()
    store._client = mock_client

    content = b"batch data"
    receipt, created = await store.put_if_absent("key_new", content)

    mock_blob.upload_from_string.assert_called_once_with(
        content,
        content_type="application/x-ndjson",
        if_generation_match=0,
        timeout=15.0,
    )
    assert created is True
    assert receipt.uri == "gs://test-bucket/key_new"


@pytest.mark.asyncio
async def test_gcs_cold_store_put_if_absent_collision():
    """put_if_absent catches PreconditionFailed and returns created=False without raising."""
    store = GcsColdStore(bucket_name="test-bucket")
    mock_client, _, mock_blob = _create_mock_client()
    store._client = mock_client

    mock_blob.upload_from_string.side_effect = PreconditionFailed("Generation mismatch")

    content = b"colliding batch data"
    receipt, created = await store.put_if_absent("key_exists", content)

    assert created is False
    assert receipt.uri == "gs://test-bucket/key_exists"
    assert receipt.content_sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.asyncio
async def test_gcs_cold_store_upload_error_wrapped():
    """Upload failures must be wrapped into ColdStoreError."""
    store = GcsColdStore(bucket_name="test-bucket")
    mock_client, _, mock_blob = _create_mock_client()
    store._client = mock_client

    mock_blob.upload_from_string.side_effect = ConnectionResetError("network lost")

    with pytest.raises(ColdStoreError) as exc_info:
        await store.put_batch("key_err", b"data")

    assert exc_info.value.backend_id == "gcs"
    assert "network lost" in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, ConnectionResetError)


@pytest.mark.asyncio
async def test_gcs_cold_store_missing_bucket_raises(monkeypatch):
    """put_batch without a bucket name raises ColdStoreError."""
    for var in (
        "EVIDENCE_COLD_STORE_BUCKET",
        "EVIDENCE_COLD_STORE_BUCKET_GCS",
        "GCS_BUCKET",
    ):
        monkeypatch.delenv(var, raising=False)
    store = GcsColdStore(bucket_name=None)
    store._client = MagicMock()

    with pytest.raises(ColdStoreError, match="GCS bucket name not configured"):
        await store.put_batch("key", b"content")


def test_gcs_cold_store_health_reporting(monkeypatch):
    """health() reports status based on configuration and client availability."""
    for var in (
        "EVIDENCE_COLD_STORE_BUCKET",
        "EVIDENCE_COLD_STORE_BUCKET_GCS",
        "GCS_BUCKET",
    ):
        monkeypatch.delenv(var, raising=False)
    store_no_bucket = GcsColdStore(bucket_name=None)
    health1 = store_no_bucket.health()
    assert health1.available is False
    assert health1.backend_id == "gcs"

    store_with_bucket = GcsColdStore(bucket_name="prod-bucket")
    store_with_bucket._client = MagicMock()
    health2 = store_with_bucket.health()
    assert health2.available is True
    assert health2.backend_id == "gcs"
    assert "bucket=prod-bucket" in health2.detail
