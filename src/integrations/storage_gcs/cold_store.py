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

"""cold_store.py — Google Cloud Storage (GCS) Cold Storage Adapter (Layer 3)

Implements the EvidenceColdStore protocol for Google Cloud Storage using
lazy-loaded google-cloud-storage with atomic conditional upload support.
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

logger = logging.getLogger("cage.integrations.storage_gcs")


class GcsColdStore(EvidenceColdStore):
    """GCS adapter conforming to the EvidenceColdStore protocol.

    Features:
        - Thread-safe lazy client initialization with double-checked locking
        - Non-blocking async interface executing blocking I/O in thread pool
        - Atomic conditional write via GCS generation preconditions (`if_generation_match=0`)
        - Customer-Managed Encryption Key (CMEK) support
        - Unified ColdStoreError exception mapping
    """

    def __init__(
        self,
        bucket_name: str | None = None,
        project_id: str | None = None,
        cmek_key: str | None = None,
        timeout: float = 15.0,
        bucket: str | None = None,
        timeout_seconds: float | None = None,
        project: str | None = None,
    ) -> None:
        self._bucket_name = (
            bucket
            or bucket_name
            or os.environ.get("EVIDENCE_COLD_STORE_BUCKET_GCS")
            or os.environ.get("EVIDENCE_COLD_STORE_BUCKET")
            or os.environ.get("GCS_BUCKET")
        )
        self._project_id = (
            project
            or project_id
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCS_PROJECT_ID")
        )
        self._timeout = timeout_seconds if timeout_seconds is not None else timeout
        self._cmek_key = cmek_key

        self._client: Any = None
        self._lock = threading.Lock()

    @property
    def backend_id(self) -> str:
        return "gcs"

    @property
    def bucket_name(self) -> str | None:
        return self._bucket_name

    def _get_client(self) -> Any:
        """Lazy thread-safe GCS client resolution."""
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is not None:
                return self._client

            try:
                from google.cloud import storage as gcs  # type: ignore[attr-defined]
            except ImportError as exc:
                raise ColdStoreError(
                    "google-cloud-storage is required for GcsColdStore. "
                    "Install it with: uv add google-cloud-storage",
                    backend_id="gcs",
                ) from exc

            try:
                self._client = gcs.Client(project=self._project_id)
                logger.info(
                    "[storage_gcs] Initialized GCS client (project=%s)",
                    self._project_id or "inferred",
                )
                return self._client
            except Exception as exc:
                raise ColdStoreError(
                    f"Failed to initialize GCS client: {exc}",
                    backend_id="gcs",
                ) from exc

    def _resolve_bucket(self) -> str:
        if not self._bucket_name:
            raise ColdStoreError(
                "GCS bucket name not configured. Set EVIDENCE_STREAM_BUCKET_GCS or pass bucket_name.",
                backend_id="gcs",
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
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(key, kms_key_name=self._cmek_key)

        digest = hashlib.sha256(content).hexdigest()
        if metadata:
            blob.metadata = dict(metadata)

        try:
            blob.upload_from_string(
                content,
                content_type="application/x-ndjson",
                timeout=self._timeout,
            )
        except Exception as exc:
            raise ColdStoreError(
                f"GCS upload failed for key '{key}': {exc}",
                backend_id="gcs",
            ) from exc

        return ColdStoreReceipt(
            uri=f"gs://{bucket_name}/{key}",
            key=key,
            content_sha256=digest,
            backend_id="gcs",
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
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(key)

        try:
            return bool(blob.exists(timeout=self._timeout))
        except Exception as exc:
            raise ColdStoreError(
                f"GCS exists check failed for key '{key}': {exc}",
                backend_id="gcs",
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
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(key, kms_key_name=self._cmek_key)

        digest = hashlib.sha256(content).hexdigest()
        if metadata:
            blob.metadata = dict(metadata)

        from google.api_core.exceptions import PreconditionFailed

        try:
            blob.upload_from_string(
                content,
                content_type="application/x-ndjson",
                if_generation_match=0,
                timeout=self._timeout,
            )
            created = True
        except PreconditionFailed:
            created = False
        except Exception as exc:
            raise ColdStoreError(
                f"GCS atomic put_if_absent failed for key '{key}': {exc}",
                backend_id="gcs",
            ) from exc

        receipt = ColdStoreReceipt(
            uri=f"gs://{bucket_name}/{key}",
            key=key,
            content_sha256=digest,
            backend_id="gcs",
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
                backend_id="gcs",
                detail="GCS bucket name not configured",
            )

        try:
            self._get_client()
            return ColdStoreHealth(
                available=True,
                backend_id="gcs",
                detail=f"bucket={self._bucket_name}, project={self._project_id or 'inferred'}",
            )
        except Exception as exc:
            return ColdStoreHealth(
                available=False,
                backend_id="gcs",
                detail=f"Client initialization failed: {exc}",
            )
