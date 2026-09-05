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
null_cold_store.py — In-Memory Null Evidence Cold Store

Provides a succeed-locally, in-memory implementation of EvidenceColdStore for
local development, offline testing, and environments without cloud object storage.

Semantics (Wave 1, Task W1.5d):
    - Succeeds locally: maintains a bounded in-memory ring buffer of written keys.
    - Generates honest `null://` receipts with accurate cryptographic SHA-256 digests.
    - Fails closed on startup if CAGE_ENV=prod unless CAGE_ALLOW_NONBLOCKING_PROD=true.
    - Reports ColdStoreHealth(available=True, backend_id="null").
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timezone

from .cold_store import ColdStoreHealth, ColdStoreReceipt, EvidenceColdStore

logger = logging.getLogger(__name__)


class NullColdStore(EvidenceColdStore):
    """Succeed-locally EvidenceColdStore with bounded in-memory state.

    Attributes:
        max_entries: Maximum number of keys to retain in the in-memory ring buffer.
    """

    def __init__(self, max_entries: int = 1000) -> None:
        """Initialize NullColdStore with prod safety check.

        Raises:
            RuntimeError: If CAGE_ENV=prod and CAGE_ALLOW_NONBLOCKING_PROD is not true.
        """
        cage_env = os.environ.get("CAGE_ENV", "dev").lower()
        allow_nonblocking_prod = (
            os.environ.get("CAGE_ALLOW_NONBLOCKING_PROD", "false").lower() == "true"
        )
        if cage_env == "prod" and not allow_nonblocking_prod:
            raise RuntimeError(
                "[NullColdStore] CAGE_ENV=prod requires durable cold storage. "
                "Configure EVIDENCE_COLD_STORE (gcs or s3) and regional bucket. "
                "Set CAGE_ALLOW_NONBLOCKING_PROD=true to explicitly override."
            )

        self._max_entries = max_entries
        self._entries: OrderedDict[str, str] = OrderedDict()  # key -> sha256
        logger.warning(
            "[NullColdStore] Initialized with in-memory storage (max_entries=%d). "
            "No durable off-cluster cold storage is active.",
            max_entries,
        )

    @property
    def backend_id(self) -> str:
        return "null"

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        """Simulate batch upload by computing SHA-256 and buffering key."""
        digest = hashlib.sha256(content).hexdigest()
        if len(self._entries) >= self._max_entries:
            self._entries.popitem(last=False)
        self._entries[key] = digest

        logger.debug(
            "[NullColdStore] Stored key '%s' (%d bytes, sha256=%s...)",
            key,
            len(content),
            digest[:8],
        )
        return ColdStoreReceipt(
            uri=f"null://{key}",
            key=key,
            content_sha256=digest,
            backend_id="null",
            written_at=datetime.now(timezone.utc),
        )

    async def exists(self, key: str) -> bool:
        """Return True if the key was previously written to the in-memory buffer."""
        return key in self._entries

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        """Atomic put-if-absent simulation against in-memory key buffer."""
        if key in self._entries:
            existing_digest = self._entries[key]
            receipt = ColdStoreReceipt(
                uri=f"null://{key}",
                key=key,
                content_sha256=existing_digest,
                backend_id="null",
                written_at=datetime.now(timezone.utc),
            )
            return receipt, False

        receipt = await self.put_batch(key, content, metadata)
        return receipt, True

    def health(self) -> ColdStoreHealth:
        """Return operational health of the in-memory cold store."""
        return ColdStoreHealth(
            available=True,
            backend_id="null",
            detail=f"In-memory simulation active ({len(self._entries)} items tracked)",
        )
