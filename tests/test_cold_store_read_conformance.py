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

"""Read-side conformance for EvidenceColdStore: ``get`` and ``list_keys``.

The evidence verifier depends on two properties of every backend:

* ``get`` returns the exact stored bytes, and a missing object raises
  ``ColdStoreNotFoundError`` — distinct from a backend failure, which raises
  plain ``ColdStoreError``. Conflating the two would turn an outage into an
  "evidence deleted" verdict, or a deletion into a retry.
* ``list_keys`` returns every matching key across all pages, sorted.

GCS and S3 are exercised with injected SDK clients and the real SDK
exception types; NullColdStore runs for real.
"""

from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from google.api_core.exceptions import Forbidden, NotFound

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    ColdStoreNotFoundError,
)
from src.gateway.governance.evidence.null_cold_store import NullColdStore
from src.integrations.storage_gcs.cold_store import GcsColdStore
from src.integrations.storage_s3.cold_store import S3ColdStore

pytestmark = [pytest.mark.local, pytest.mark.unit]

KEY = "evidence-stream/2026/09/29/chain/000000000000-000000000001.ndjson"


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetObject")


# ---------------------------------------------------------------------------
# NullColdStore (real)
# ---------------------------------------------------------------------------


class TestNullReadSide:
    @pytest.mark.asyncio
    async def test_get_returns_exact_bytes(self):
        store = NullColdStore()
        await store.put_if_absent(KEY, b"\x00line\n")
        assert await store.get(KEY) == b"\x00line\n"

    @pytest.mark.asyncio
    async def test_get_missing_raises_not_found(self):
        with pytest.raises(ColdStoreNotFoundError):
            await NullColdStore().get(KEY)

    @pytest.mark.asyncio
    async def test_list_keys_filters_and_sorts(self):
        store = NullColdStore()
        for key in ("evidence-stream/b", "oscal/x", "evidence-stream/a"):
            await store.put_batch(key, b"x")
        assert await store.list_keys("evidence-stream/") == [
            "evidence-stream/a",
            "evidence-stream/b",
        ]

    @pytest.mark.asyncio
    async def test_put_if_absent_never_overwrites_readable_bytes(self):
        store = NullColdStore()
        await store.put_if_absent(KEY, b"first")
        _receipt, created = await store.put_if_absent(KEY, b"second")
        assert created is False
        assert await store.get(KEY) == b"first"


# ---------------------------------------------------------------------------
# GCS (injected client, real google.api_core exceptions)
# ---------------------------------------------------------------------------


def _gcs(blob: MagicMock | None = None, blobs: list[str] | None = None) -> GcsColdStore:
    client = MagicMock()
    client.bucket.return_value.blob.return_value = blob or MagicMock()
    client.list_blobs.return_value = [SimpleNamespace(name=n) for n in (blobs or [])]
    store = GcsColdStore(bucket="us-test-bucket")
    store._client = client
    return store


class TestGcsReadSide:
    @pytest.mark.asyncio
    async def test_get_returns_bytes(self):
        blob = MagicMock()
        blob.download_as_bytes.return_value = b"payload"
        assert await _gcs(blob).get(KEY) == b"payload"

    @pytest.mark.asyncio
    async def test_get_not_found_maps_to_not_found(self):
        blob = MagicMock()
        blob.download_as_bytes.side_effect = NotFound("gone")
        with pytest.raises(ColdStoreNotFoundError):
            await _gcs(blob).get(KEY)

    @pytest.mark.asyncio
    async def test_get_other_error_is_not_not_found(self):
        blob = MagicMock()
        blob.download_as_bytes.side_effect = Forbidden("denied")
        with pytest.raises(ColdStoreError) as info:
            await _gcs(blob).get(KEY)
        assert not isinstance(info.value, ColdStoreNotFoundError)

    @pytest.mark.asyncio
    async def test_list_keys_sorted(self):
        store = _gcs(blobs=["evidence-stream/b", "evidence-stream/a"])
        assert await store.list_keys("evidence-stream/") == [
            "evidence-stream/a",
            "evidence-stream/b",
        ]
        store._client.list_blobs.assert_called_once()
        assert store._client.list_blobs.call_args.kwargs["prefix"] == "evidence-stream/"

    @pytest.mark.asyncio
    async def test_list_keys_error_raises(self):
        store = _gcs()
        store._client.list_blobs.side_effect = Forbidden("denied")
        with pytest.raises(ColdStoreError):
            await store.list_keys("evidence-stream/")


# ---------------------------------------------------------------------------
# S3 (injected client, real botocore ClientError)
# ---------------------------------------------------------------------------


def _s3() -> S3ColdStore:
    store = S3ColdStore(
        bucket="us-test-bucket",
        endpoint_url="http://localhost:9000",
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
    )
    store._client = MagicMock()
    return store


class TestS3ReadSide:
    @pytest.mark.asyncio
    async def test_get_returns_bytes(self):
        store = _s3()
        store._client.get_object.return_value = {"Body": io.BytesIO(b"payload")}
        assert await store.get(KEY) == b"payload"

    @pytest.mark.asyncio
    async def test_get_no_such_key_maps_to_not_found(self):
        store = _s3()
        store._client.get_object.side_effect = _client_error("NoSuchKey")
        with pytest.raises(ColdStoreNotFoundError):
            await store.get(KEY)

    @pytest.mark.asyncio
    async def test_get_access_denied_is_not_not_found(self):
        store = _s3()
        store._client.get_object.side_effect = _client_error("AccessDenied")
        with pytest.raises(ColdStoreError) as info:
            await store.get(KEY)
        assert not isinstance(info.value, ColdStoreNotFoundError)

    @pytest.mark.asyncio
    async def test_list_keys_reads_every_page(self):
        store = _s3()
        store._client.get_paginator.return_value.paginate.return_value = [
            {"Contents": [{"Key": "evidence-stream/c"}, {"Key": "evidence-stream/a"}]},
            {"Contents": [{"Key": "evidence-stream/b"}]},
            {},  # empty final page
        ]
        assert await store.list_keys("evidence-stream/") == [
            "evidence-stream/a",
            "evidence-stream/b",
            "evidence-stream/c",
        ]

    @pytest.mark.asyncio
    async def test_list_keys_error_raises(self):
        store = _s3()
        store._client.get_paginator.side_effect = _client_error("AccessDenied")
        with pytest.raises(ColdStoreError):
            await store.list_keys("evidence-stream/")
