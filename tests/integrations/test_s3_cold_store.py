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

"""test_s3_cold_store.py — Hermetic Unit Tests for S3ColdStore Adapter (Layer 3)

Validates:
1. EvidenceColdStore runtime protocol compliance
2. put_batch / exists / put_if_absent behavior using mocked boto3 client
3. IfNoneMatch conditional put handling
4. Fallback HEAD+PUT when IfNoneMatch is unsupported
5. Error wrapping into ColdStoreError
6. Health check reporting
"""

import hashlib
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    EvidenceColdStore,
)
from src.integrations.storage_s3 import S3ColdStore

pytestmark = [pytest.mark.unit]


def _make_client_error(code: str, message: str = "Error"):
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "operation_name",
    )


def test_s3_cold_store_protocol_conformance():
    """S3ColdStore must satisfy the EvidenceColdStore protocol."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    assert isinstance(store, EvidenceColdStore)
    assert store.backend_id == "s3"


@pytest.mark.asyncio
async def test_s3_cold_store_put_batch_success():
    """put_batch uploads bytes via S3 put_object."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    mock_client = MagicMock()
    store._client = mock_client

    content = b"audit evidence batch 123"
    expected_sha = hashlib.sha256(content).hexdigest()

    receipt = await store.put_batch(
        key="evidence/s3_batch.ndjson",
        content=content,
        metadata={"region": "US_FED"},
    )

    mock_client.put_object.assert_called_once_with(
        Bucket="my-s3-bucket",
        Key="evidence/s3_batch.ndjson",
        Body=content,
        ContentType="application/x-ndjson",
        Metadata={"region": "US_FED"},
    )

    assert receipt.uri == "s3://my-s3-bucket/evidence/s3_batch.ndjson"
    assert receipt.key == "evidence/s3_batch.ndjson"
    assert receipt.content_sha256 == expected_sha
    assert receipt.backend_id == "s3"


@pytest.mark.asyncio
async def test_s3_cold_store_exists():
    """exists checks key via head_object and distinguishes 404 from errors."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    mock_client = MagicMock()
    store._client = mock_client

    # Key exists
    mock_client.head_object.return_value = {"ContentLength": 100}
    assert await store.exists("file.ndjson") is True

    # Key does not exist (404)
    mock_client.head_object.side_effect = _make_client_error("404", "Not Found")
    assert await store.exists("file.ndjson") is False

    # Key does not exist (NoSuchKey)
    mock_client.head_object.side_effect = _make_client_error("NoSuchKey", "Not Found")
    assert await store.exists("file.ndjson") is False

    # Server error raises ColdStoreError
    mock_client.head_object.side_effect = _make_client_error("500", "Internal Error")
    with pytest.raises(ColdStoreError) as exc_info:
        await store.exists("file.ndjson")
    assert exc_info.value.backend_id == "s3"


@pytest.mark.asyncio
async def test_s3_cold_store_put_if_absent_success():
    """put_if_absent uses IfNoneMatch and reports created=True."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    mock_client = MagicMock()
    store._client = mock_client

    content = b"unique batch"
    receipt, created = await store.put_if_absent("unique_key", content)

    mock_client.put_object.assert_called_once_with(
        Bucket="my-s3-bucket",
        Key="unique_key",
        Body=content,
        ContentType="application/x-ndjson",
        IfNoneMatch="*",
    )
    assert created is True
    assert receipt.uri == "s3://my-s3-bucket/unique_key"


@pytest.mark.asyncio
async def test_s3_cold_store_put_if_absent_precondition_failed():
    """put_if_absent catches PreconditionFailed and returns created=False."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    mock_client = MagicMock()
    store._client = mock_client

    mock_client.put_object.side_effect = _make_client_error("PreconditionFailed")

    content = b"colliding batch"
    receipt, created = await store.put_if_absent("existing_key", content)

    assert created is False
    assert receipt.uri == "s3://my-s3-bucket/existing_key"


@pytest.mark.asyncio
async def test_s3_cold_store_put_if_absent_fallback_when_ifnonematch_unsupported():
    """Falls back to HEAD check + PUT if endpoint does not support IfNoneMatch."""
    store = S3ColdStore(bucket_name="my-s3-bucket")
    mock_client = MagicMock()
    store._client = mock_client

    # First call with IfNoneMatch raises NotImplemented / 501
    mock_client.put_object.side_effect = [
        _make_client_error("NotImplemented", "IfNoneMatch unsupported"),
        {"ETag": "abc"},
    ]
    # HEAD check returns 404 (object absent)
    mock_client.head_object.side_effect = _make_client_error("404")

    content = b"fallback batch"
    receipt, created = await store.put_if_absent("fallback_key", content)

    assert created is True
    assert receipt.uri == "s3://my-s3-bucket/fallback_key"
    assert mock_client.head_object.called
    assert mock_client.put_object.call_count == 2
    # Second put_object call should NOT have IfNoneMatch
    assert "IfNoneMatch" not in mock_client.put_object.call_args_list[1].kwargs


@pytest.mark.asyncio
async def test_s3_cold_store_missing_bucket_raises(monkeypatch):
    """put_batch without a bucket name raises ColdStoreError."""
    for var in ("EVIDENCE_STREAM_BUCKET_S3", "EVIDENCE_STREAM_S3_BUCKET", "S3_BUCKET", "OSCAL_S3_BUCKET"):
        monkeypatch.delenv(var, raising=False)
    store = S3ColdStore(bucket_name=None)
    store._client = MagicMock()

    with pytest.raises(ColdStoreError, match="S3 bucket name not configured"):
        await store.put_batch("key", b"content")


def test_s3_cold_store_health_reporting(monkeypatch):
    """health() reports status based on configuration."""
    for var in ("EVIDENCE_STREAM_BUCKET_S3", "EVIDENCE_STREAM_S3_BUCKET", "S3_BUCKET", "OSCAL_S3_BUCKET"):
        monkeypatch.delenv(var, raising=False)
    store_no_bucket = S3ColdStore(bucket_name=None)
    health1 = store_no_bucket.health()
    assert health1.available is False
    assert health1.backend_id == "s3"

    store_with_bucket = S3ColdStore(bucket_name="my-bucket", endpoint_url="http://minio:9000")
    store_with_bucket._client = MagicMock()
    health2 = store_with_bucket.health()
    assert health2.available is True
    assert health2.backend_id == "s3"
    assert "bucket=my-bucket" in health2.detail

