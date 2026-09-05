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

"""cold_store.py — Vendor-Decoupled Evidence Cold Storage Protocol (Layer 1)

Provides the vendor-neutral protocol and receipt abstractions for durable
evidence archival and OSCAL artifact persistence to cloud object storage.

Layer Invariant (Layer 1 Kernel):
    This module defines the abstract seam only. It contains ZERO vendor imports
    (no google-cloud-storage, boto3, or azure-storage-blob). Concrete adapters
    live strictly in Layer 3 integrations (src/integrations/storage_*).

Contract Specification:
    - EvidenceColdStore: runtime-checkable Protocol for async cold storage
    - ColdStoreReceipt: immutable record of successful persistence
    - ColdStoreHealth: snapshot of storage backend availability
    - ColdStoreError: unified exception boundary for cold storage failures
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, runtime_checkable


class ColdStoreError(Exception):
    """Base exception for all evidence cold storage operations.

    Vendor-specific exceptions (e.g. GoogleAPICallError, ClientError) must never
    cross the seam and must be wrapped into ColdStoreError with the underlying
    cause attached via `__cause__`.
    """

    def __init__(self, message: str, backend_id: str = "unknown") -> None:
        super().__init__(message)
        self.backend_id = backend_id


@dataclasses.dataclass(frozen=True)
class ColdStoreReceipt:
    """Immutable receipt returned upon successful persistence to cold storage.

    Attributes:
        uri: Complete URI where content is stored (e.g. gs://bucket/key, s3://bucket/key, null://key).
        key: Storage key / object path within the storage bucket.
        content_sha256: Hexadecimal SHA-256 digest computed over the persisted content bytes.
        backend_id: Identifier of the storage backend ('gcs', 's3', 'null').
        written_at: UTC timestamp when the write was confirmed.
    """

    uri: str
    key: str
    content_sha256: str
    backend_id: str
    written_at: datetime


@dataclasses.dataclass(frozen=True)
class ColdStoreHealth:
    """Health status snapshot of a cold storage backend.

    Attributes:
        available: True if backend connectivity and authorization are operational.
        backend_id: Identifier of the storage backend ('gcs', 's3', 'null').
        detail: Human-readable diagnostic or error string.
    """

    available: bool
    backend_id: str
    detail: str


@runtime_checkable
class EvidenceColdStore(Protocol):
    """Protocol for vendor-agnostic asynchronous evidence cold storage.

    All methods operate on bytes (never str) to ensure exact cryptographic
    hash consistency across storage and retrieval.
    """

    @property
    def backend_id(self) -> str:
        """Identifier of the backend adapter ('gcs', 's3', 'null')."""
        ...

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        """Persist content bytes to cold storage under key.

        Args:
            key: Target object key/path in the cold storage bucket.
            content: Raw bytes to persist (e.g. NDJSON evidence stream batch).
            metadata: Optional key-value metadata to attach to the stored object.

        Returns:
            ColdStoreReceipt confirming URI, digest, and write timestamp.

        Raises:
            ColdStoreError: On network, authorization, or I/O failure.
        """
        ...

    async def exists(self, key: str) -> bool:
        """Check whether an object exists under key in cold storage.

        Args:
            key: Object key/path to check.

        Returns:
            True if the object exists, False otherwise.

        Raises:
            ColdStoreError: On connectivity or permission errors.
        """
        ...

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        """Atomically persist content only if no object exists under key.

        Backends supporting native generation / precondition checks (e.g. GCS
        if_generation_match=0) must execute this atomically.

        Args:
            key: Target object key/path.
            content: Raw bytes to persist.
            metadata: Optional key-value metadata.

        Returns:
            Tuple of (ColdStoreReceipt, created). If the object already existed,
            created is False.

        Raises:
            ColdStoreError: On backend failure.
        """
        ...

    def health(self) -> ColdStoreHealth:
        """Synchronously report backend health and accessibility.

        Returns:
            ColdStoreHealth reporting availability status and details.
        """
        ...
