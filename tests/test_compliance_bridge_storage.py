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
tests/test_compliance_bridge_storage.py — Unit tests for compliance bridge artifact storage.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.compliance_bridge import storage


@pytest.mark.local
@pytest.mark.unit
def test_get_storage_backend():
    with patch.dict(os.environ, {"STORAGE_BACKEND": "GCS"}, clear=False):
        assert storage._get_storage_backend() == "gcs"

    with patch.dict(os.environ, {"STORAGE_BACKEND": "s3"}, clear=False):
        assert storage._get_storage_backend() == "s3"


@pytest.mark.local
@pytest.mark.unit
def test_get_bucket():
    with patch.dict(os.environ, {"OSCAL_S3_BUCKET": "my-bucket"}, clear=False):
        assert storage._get_bucket() == "my-bucket"

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(
            RuntimeError, match="Missing required env var: OSCAL_S3_BUCKET"
        ):
            storage._get_bucket()


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
def test_gcs_operations():
    mock_blob = MagicMock()
    mock_blob.exists.return_value = True
    mock_bucket = MagicMock()
    mock_bucket.blob.return_value = mock_blob
    mock_client = MagicMock()
    mock_client.bucket.return_value = mock_bucket

    with patch.object(storage, "_gcs_client", mock_client):
        assert storage._gcs_blob_exists("test-bucket", "key-1") is True
        mock_bucket.blob.assert_called_with("key-1")

        ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
        uri = storage._gcs_upload("test-bucket", "key-1", "sample-yaml", "audit-1", ts)
        assert uri == "gs://test-bucket/key-1"
        mock_blob.upload_from_string.assert_called_once()


@pytest.mark.local
@pytest.mark.unit
def test_s3_operations():
    mock_s3 = MagicMock()
    mock_s3.head_object.return_value = {}

    with patch.object(storage, "_s3_client", mock_s3):
        assert storage._s3_blob_exists("test-bucket", "key-1") is True

        ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
        uri = storage._s3_upload("test-bucket", "key-1", "sample-yaml", "audit-1", ts)
        assert uri == "s3://test-bucket/key-1"
        mock_s3.put_object.assert_called_once()


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_idempotent():
    """Test that put_oscal_artifact returns existing key when artifact already exists."""
    with (
        patch.dict(os.environ, {"OSCAL_S3_BUCKET": "test-bucket"}, clear=False),
        # HIGH-4 FIX: Now uses atomic _s3_upload_if_not_exists instead of artifact_exists
        patch.object(
            storage,
            "_s3_upload_if_not_exists",
            return_value=("s3://test-bucket/oscal-artifacts/2026-08-16/audit-123.yaml", False),
        ),
    ):
        ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
        key = await storage.put_oscal_artifact("audit-123", "dummy-yaml", timestamp=ts)
        assert key == "oscal-artifacts/2026-08-16/audit-123.yaml"


@pytest.mark.local
@pytest.mark.unit
@pytest.mark.asyncio
async def test_put_oscal_artifact_upload_when_missing():
    """Test that put_oscal_artifact uploads artifact when it doesn't exist."""
    with (
        patch.dict(os.environ, {"OSCAL_S3_BUCKET": "test-bucket"}, clear=False),
        # HIGH-4 FIX: Now uses atomic _s3_upload_if_not_exists instead of artifact_exists + upload_artifact
        patch.object(
            storage,
            "_s3_upload_if_not_exists",
            return_value=("s3://test-bucket/oscal-artifacts/2026-08-16/audit-123.yaml", True),
        ) as mock_upload,
    ):
        ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
        key = await storage.put_oscal_artifact("audit-123", "dummy-yaml", timestamp=ts)
        assert key == "oscal-artifacts/2026-08-16/audit-123.yaml"
        mock_upload.assert_called_once()
