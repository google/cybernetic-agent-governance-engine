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

"""``put_if_absent_verified``: conflicts are detected by read-back, not receipts.

The double below reproduces the GCS behaviour that motivates the helper: on an
``if_generation_match=0`` precondition failure ``GcsColdStore`` returns a
receipt whose digest is computed over the *supplied* bytes, so the receipt
alone cannot reveal that a different object is already stored.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from src.gateway.governance.evidence.cold_store import (
    ColdStoreIntegrityError,
    ColdStoreReceipt,
    put_if_absent_verified,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _GcsQuirkStore:
    backend_id = "gcs-quirk"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    async def put_if_absent(self, key, content, metadata=None):
        created = key not in self.objects
        if created:
            self.objects[key] = content
        # Digest of the SUPPLIED bytes, even when nothing was written.
        return (
            ColdStoreReceipt(
                uri=f"gs://b/{key}",
                key=key,
                content_sha256=hashlib.sha256(content).hexdigest(),
                backend_id=self.backend_id,
                written_at=datetime.now(timezone.utc),
            ),
            created,
        )

    async def get(self, key):
        return self.objects[key]


@pytest.mark.asyncio
async def test_first_write_is_created() -> None:
    store = _GcsQuirkStore()
    _receipt, created = await put_if_absent_verified(store, "k", b"v1")
    assert created is True


@pytest.mark.asyncio
async def test_identical_rewrite_is_accepted_with_stored_digest() -> None:
    store = _GcsQuirkStore()
    await put_if_absent_verified(store, "k", b"v1")
    receipt, created = await put_if_absent_verified(store, "k", b"v1")
    assert created is False
    assert receipt.content_sha256 == hashlib.sha256(b"v1").hexdigest()


@pytest.mark.asyncio
async def test_conflicting_rewrite_is_an_integrity_error() -> None:
    store = _GcsQuirkStore()
    await put_if_absent_verified(store, "k", b"v1")
    with pytest.raises(ColdStoreIntegrityError):
        await put_if_absent_verified(store, "k", b"v2")
    assert store.objects["k"] == b"v1"


@pytest.mark.asyncio
async def test_equivalence_predicate_can_accept_a_differing_object() -> None:
    store = _GcsQuirkStore()
    await put_if_absent_verified(store, "k", b"body|sig-1")
    receipt, created = await put_if_absent_verified(
        store,
        "k",
        b"body|sig-2",
        equivalent=lambda stored, new: stored.split(b"|")[0] == new.split(b"|")[0],
    )
    assert created is False
    # The receipt reflects what is stored, never the supplied bytes.
    assert receipt.content_sha256 == hashlib.sha256(b"body|sig-1").hexdigest()
