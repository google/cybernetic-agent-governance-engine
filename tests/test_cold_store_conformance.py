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
tests/test_cold_store_conformance.py — Universal Cold Store Conformance Suite

Parameterized test suite verifying that all cold storage implementations
(GcsColdStore, S3ColdStore, NullColdStore) conform to the EvidenceColdStore protocol.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.evidence.cold_store import (
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)
from src.gateway.governance.evidence.null_cold_store import NullColdStore
from src.integrations.storage_gcs.cold_store import GcsColdStore
from src.integrations.storage_s3.cold_store import S3ColdStore

pytestmark = [pytest.mark.local, pytest.mark.unit]


@pytest.fixture
def mock_gcs_store():
    """Create a GcsColdStore with mocked underlying GCS client."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()

    mock_client.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True

    store = GcsColdStore(bucket="us-test-bucket")
    store._client = mock_client
    return store


@pytest.fixture
def mock_s3_store():
    """Create an S3ColdStore with mocked underlying boto3 S3 client."""
    mock_client = MagicMock()
    store = S3ColdStore(
        bucket="us-test-bucket",
        endpoint_url="http://localhost:9000",
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
    )
    store._client = mock_client
    return store


@pytest.fixture
def null_store():
    """Create a NullColdStore instance."""
    return NullColdStore()


@pytest.fixture(params=["mock_gcs_store", "mock_s3_store", "null_store"])
def cold_store_instance(request):
    """Yield each cold store implementation fixture."""
    return request.getfixturevalue(request.param)


def test_conforms_to_protocol(cold_store_instance):
    """Verify runtime checkable protocol compliance."""
    assert isinstance(cold_store_instance, EvidenceColdStore)


def test_backend_id_property(cold_store_instance):
    """Verify backend_id property returns valid identifier."""
    assert cold_store_instance.backend_id in ("gcs", "s3", "null")


@pytest.mark.asyncio
async def test_put_batch_receipt_structure(cold_store_instance):
    """Verify put_batch returns a valid ColdStoreReceipt with matching SHA-256."""
    key = "evidence-stream/2026/09/05/batch-test.ndjson"
    content = b'{"event": "test_conformance", "seq": 1}\n'
    expected_digest = hashlib.sha256(content).hexdigest()

    receipt = await cold_store_instance.put_batch(key, content)

    assert isinstance(receipt, ColdStoreReceipt)
    assert receipt.key == key
    assert receipt.content_sha256 == expected_digest
    assert receipt.backend_id == cold_store_instance.backend_id
    assert isinstance(receipt.written_at, datetime)
    assert receipt.uri.startswith(("gs://", "s3://", "null://"))


@pytest.mark.asyncio
async def test_exists_contract(cold_store_instance):
    """Verify exists method returns a boolean."""
    key = "evidence-stream/2026/09/05/batch-test.ndjson"
    result = await cold_store_instance.exists(key)
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_put_if_absent_contract(cold_store_instance):
    """Verify put_if_absent returns (ColdStoreReceipt, bool)."""
    key = "evidence-stream/2026/09/05/batch-test.ndjson"
    content = b'{"event": "test_conformance_atomic"}\n'

    receipt, created = await cold_store_instance.put_if_absent(key, content)

    assert isinstance(receipt, ColdStoreReceipt)
    assert isinstance(created, bool)
    assert receipt.key == key


def test_health_contract(cold_store_instance):
    """Verify health() returns ColdStoreHealth."""
    health = cold_store_instance.health()
    assert isinstance(health, ColdStoreHealth)
    assert isinstance(health.available, bool)
    assert health.backend_id == cold_store_instance.backend_id
    assert isinstance(health.detail, str)
