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

"""cold_store.py — S3-Compatible Cold Storage Adapter (Layer 3)

Implements the EvidenceColdStore protocol for S3-compatible endpoints
(AWS S3, MinIO, Ceph, GCS XML interop) using lazy-loaded boto3.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.evidence.cold_store import (
    ColdStoreError,
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)

logger = logging.getLogger("cage.integrations.storage_s3")


class S3ColdStore(EvidenceColdStore):
    """S3-compatible adapter conforming to the EvidenceColdStore protocol.

    Features:
        - Thread-safe lazy client initialization with double-checked locking
        - Non-blocking async interface executing blocking I/O in thread pool
        - Supports path-style addressing for MinIO/Ceph compatibility
        - Atomic conditional write with `IfNoneMatch: "*"` (AWS S3) and HEAD+PUT fallback
        - Unified ColdStoreError exception mapping

    Atomicity Notice (per master plan W1.3):
        AWS S3 supports atomic conditional writes via `IfNoneMatch: "*"`. For endpoints
        that do not support conditional headers (older MinIO, local stubs), this adapter
        falls back to a two-step check-then-write (HEAD+PUT) which has weaker TOCTOU
        guarantees than GCS generation preconditions.
    """

    def __init__(
        self,
        bucket_name: str | None = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._bucket_name = (
            bucket_name
            or os.environ.get("EVIDENCE_STREAM_BUCKET_S3")
            or os.environ.get("EVIDENCE_STREAM_S3_BUCKET")
            or os.environ.get("S3_BUCKET")
            or os.environ.get("OSCAL_S3_BUCKET")
        )
        self._endpoint_url = (
            endpoint_url
            or os.environ.get("S3_ENDPOINT_URL")
            or os.environ.get("AWS_ENDPOINT_URL")
        )
        self._region_name = (
            region_name
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )
        self._timeout = timeout

        self._client: Any = None
        self._lock = threading.Lock()

    @property
    def backend_id(self) -> str:
        return "s3"

    @property
    def bucket_name(self) -> str | None:
        return self._bucket_name

    def _get_client(self) -> Any:
        """Lazy thread-safe boto3 S3 client resolution."""
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is not None:
                return self._client

            try:
                import boto3  # type: ignore[import-untyped]
                from botocore.client import Config  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ColdStoreError(
                    "boto3 and botocore are required for S3ColdStore. "
                    "Install with: uv add boto3",
                    backend_id="s3",
                ) from exc

            try:
                config = Config(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                    connect_timeout=self._timeout,
                    read_timeout=self._timeout,
                    retries={"max_attempts": 1},
                )
                self._client = boto3.client(
                    "s3",
                    endpoint_url=self._endpoint_url,
                    region_name=self._region_name,
                    config=config,
                )
                logger.info(
                    "[storage_s3] Initialized S3 client (endpoint=%s, region=%s)",
                    self._endpoint_url or "aws-default",
                    self._region_name,
                )
                return self._client
            except Exception as exc:
                raise ColdStoreError(
                    f"Failed to initialize S3 client: {exc}",
                    backend_id="s3",
                ) from exc

    def _resolve_bucket(self) -> str:
        if not self._bucket_name:
            raise ColdStoreError(
                "S3 bucket name not configured. Set EVIDENCE_STREAM_BUCKET_S3 or pass bucket_name.",
                backend_id="s3",
            )
        return self._bucket_name

    def _sync_put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        client = self._get_client()
        bucket_name = self._resolve_bucket()
        digest = hashlib.sha256(content).hexdigest()

        kwargs: dict[str, Any] = {
            "Bucket": bucket_name,
            "Key": key,
            "Body": content,
            "ContentType": "application/x-ndjson",
        }
        if metadata:
            kwargs["Metadata"] = dict(metadata)

        try:
            client.put_object(**kwargs)
        except Exception as exc:
            raise ColdStoreError(
                f"S3 upload failed for key '{key}': {exc}",
                backend_id="s3",
            ) from exc

        return ColdStoreReceipt(
            uri=f"s3://{bucket_name}/{key}",
            key=key,
            content_sha256=digest,
            backend_id="s3",
            written_at=datetime.now(timezone.utc),
        )

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        return await asyncio.to_thread(self._sync_put_batch, key, content, metadata)

    def _sync_exists(self, key: str) -> bool:
        client = self._get_client()
        bucket_name = self._resolve_bucket()

        try:
            client.head_object(Bucket=bucket_name, Key=key)
            return True
        except Exception as exc:
            # Check for 404/NoSuchKey
            from botocore.exceptions import ClientError  # type: ignore[import-untyped]

            if isinstance(exc, ClientError):
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("404", "NoSuchKey", "NotFound"):
                    return False
            raise ColdStoreError(
                f"S3 exists check failed for key '{key}': {exc}",
                backend_id="s3",
            ) from exc

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._sync_exists, key)

    def _sync_put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        client = self._get_client()
        bucket_name = self._resolve_bucket()
        digest = hashlib.sha256(content).hexdigest()

        from botocore.exceptions import ClientError  # type: ignore[import-untyped]

        kwargs: dict[str, Any] = {
            "Bucket": bucket_name,
            "Key": key,
            "Body": content,
            "ContentType": "application/x-ndjson",
            "IfNoneMatch": "*",
        }
        if metadata:
            kwargs["Metadata"] = dict(metadata)

        try:
            client.put_object(**kwargs)
            created = True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("PreconditionFailed", "412"):
                created = False
            elif code in ("NotImplemented", "501", "InvalidArgument", "400"):
                # Fallback to HEAD-then-PUT if IfNoneMatch is not supported by backend
                logger.warning(
                    "[storage_s3] IfNoneMatch not supported by endpoint, falling back to HEAD check"
                )
                if self._sync_exists(key):
                    created = False
                else:
                    kwargs.pop("IfNoneMatch", None)
                    client.put_object(**kwargs)
                    created = True
            else:
                raise ColdStoreError(
                    f"S3 put_if_absent failed for key '{key}': {exc}",
                    backend_id="s3",
                ) from exc
        except Exception as exc:
            raise ColdStoreError(
                f"S3 put_if_absent failed for key '{key}': {exc}",
                backend_id="s3",
            ) from exc

        receipt = ColdStoreReceipt(
            uri=f"s3://{bucket_name}/{key}",
            key=key,
            content_sha256=digest,
            backend_id="s3",
            written_at=datetime.now(timezone.utc),
        )
        return receipt, created

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        return await asyncio.to_thread(self._sync_put_if_absent, key, content, metadata)

    def health(self) -> ColdStoreHealth:
        if not self._bucket_name:
            return ColdStoreHealth(
                available=False,
                backend_id="s3",
                detail="S3 bucket name not configured",
            )

        try:
            self._get_client()
            return ColdStoreHealth(
                available=True,
                backend_id="s3",
                detail=f"bucket={self._bucket_name}, endpoint={self._endpoint_url or 'aws-default'}",
            )
        except Exception as exc:
            return ColdStoreHealth(
                available=False,
                backend_id="s3",
                detail=f"Client initialization failed: {exc}",
            )
