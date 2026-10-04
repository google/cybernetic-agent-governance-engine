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
"""Live WORM verification for retained state-commitment preimages.

Runs against the **staging** evidence WORM bucket provisioned by
``infra/targets/gcp-gke/main.tf`` (``<project>-evidence-worm-staging``:
retention 86400 s, policy locked). It proves the properties that the
hermetic suites can only simulate:

(a) ``put_if_absent_verified()`` detects a conflicting object by reading it
    back and comparing it, even though GCS's ``PreconditionFailed`` path reports
    the digest of the *supplied* content;
(b) the bucket refuses delete and overwrite while the object is under retention;
(c) a ``STATE_COMMITMENT`` record taken through the real evidence sink, the
    compliance-bridge custodian and GCS, then read back, passes
    ``verify_state_commitment()``;
(d) custodied objects carry ``x-data-classification: internal-pii-sanitized``.

Marker: ``live_external`` only. GCS is a first-party Tier 2 backend, not a
partner API, so ``partner_integration`` does not apply. The Redis stream is
fakeredis because WORM storage is what is under test here. Attestations are
written unsigned (KMS signing is outside this test's scope), so these objects
are ``evidentiary=false``.

Every run writes new objects. The bucket's retention policy keeps them for
24 h, and they cannot be cleaned up sooner (that is property (b)).

Configuration (the test skips cleanly when either is missing):
    CAGE_LIVE_WORM_BUCKET   staging WORM bucket name
    Application Default Credentials with objectCreator/objectViewer on it

    uv run pytest tests/integrations/test_state_commitment_worm_live.py \
        --run-live-external -n0

On a workstation with context-aware-access client certificates configured,
google-auth injects pyOpenSSL into urllib3, and pyOpenSSL >= 25 then fails with
"Context has already been used". Set ``GOOGLE_API_USE_CLIENT_CERTIFICATE=false``
for the run.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import fakeredis
import pytest

from src.compliance_bridge.evidence_custodian import (
    DATA_CLASSIFICATION,
    EvidenceCustodian,
)
from src.gateway.governance.evidence.cold_store import (
    ColdStoreIntegrityError,
    put_if_absent_verified,
)
from src.gateway.governance.evidence.state_commitment import (
    StateCommitmentService,
    verify_state_commitment,
)
from src.gateway.governance.evidence.stream import EvidenceStreamSink
from src.gateway.governance.seams.state_commitment import StateCommitmentLinkage

pytestmark = [pytest.mark.live_external]

_BUCKET_ENV = "CAGE_LIVE_WORM_BUCKET"
_STREAM_KEY = "cage:evidence:live-worm-test"
_PII_MARKERS = ("jane.doe@example.com", "123-45-6789", "4111 1111 1111 1111")


def _bucket_or_skip() -> str:
    bucket = os.environ.get(_BUCKET_ENV, "").strip()
    if not bucket:
        pytest.skip(f"{_BUCKET_ENV} not set; live WORM verification skipped")
    try:
        import google.auth  # type: ignore[import-untyped]
        from google.cloud import storage  # noqa: F401  # type: ignore[attr-defined]

        google.auth.default()
    except Exception as exc:  # noqa: BLE001 - any credential failure means skip
        pytest.skip(f"Google Cloud credentials unavailable: {type(exc).__name__}")
    return bucket


@pytest.fixture
def bucket_name() -> str:
    return _bucket_or_skip()


@pytest.fixture
def cold_store(bucket_name: str) -> Any:
    from src.integrations.storage_gcs.cold_store import GcsColdStore

    return GcsColdStore(bucket=bucket_name)


@pytest.fixture
def raw_bucket(bucket_name: str) -> Any:
    from google.cloud import storage  # type: ignore[attr-defined]

    return storage.Client().bucket(bucket_name)


class _PrefixedStore:
    """Confine custodian writes to ``live-tests/`` in the staging bucket.

    The staging ``CustodyVerifier`` treats unexpected objects under
    ``evidence-stream/`` as a failure, and WORM retention means test objects
    cannot be removed. A prefix keeps this test out of the real archive.
    """

    def __init__(self, inner: Any, prefix: str) -> None:
        self._inner = inner
        self.prefix = prefix

    @property
    def backend_id(self) -> str:
        return str(self._inner.backend_id)

    async def put_if_absent(
        self, key: str, content: bytes, metadata: Any = None
    ) -> Any:
        return await self._inner.put_if_absent(self.prefix + key, content, metadata)

    async def put_batch(self, key: str, content: bytes, metadata: Any = None) -> Any:
        return await self._inner.put_batch(self.prefix + key, content, metadata)

    async def exists(self, key: str) -> bool:
        return bool(await self._inner.exists(self.prefix + key))

    async def get(self, key: str) -> bytes:
        return bytes(await self._inner.get(self.prefix + key))


def _key(suffix: str) -> str:
    return f"live-tests/state-commitment/{uuid.uuid4()}/{suffix}"


def test_bucket_retention_policy_is_locked(raw_bucket: Any) -> None:
    """Precondition: this is the locked staging WORM bucket, not a dev bucket."""
    raw_bucket.reload()
    assert raw_bucket.retention_period and raw_bucket.retention_period >= 86400
    assert raw_bucket.retention_policy_locked is True


@pytest.mark.asyncio
async def test_a_conflicting_put_is_detected_by_read_back(cold_store: Any) -> None:
    key = _key("conflict.json")
    original = b'{"stateHash":"original"}'
    _receipt, created = await put_if_absent_verified(cold_store, key, original)
    assert created is True

    # An identical re-put is idempotent ("exists"), not a conflict.
    _receipt, created = await put_if_absent_verified(cold_store, key, original)
    assert created is False

    with pytest.raises(ColdStoreIntegrityError):
        await put_if_absent_verified(cold_store, key, b'{"stateHash":"forged"}')
    assert await cold_store.get(key) == original


def test_b_delete_and_overwrite_refused_within_retention(raw_bucket: Any) -> None:
    """The retained bytes cannot be destroyed or replaced inside the retention window.

    The staging bucket has object versioning enabled. There, an unconditional
    upload is *accepted* but creates a new live generation; the original
    generation stays retained and readable. So the guarantee checked here is
    on the original generation: it cannot be deleted, and its bytes are
    unchanged. CAGE's own write path never replaces an object (create-only
    ``if_generation_match=0``; see test (a)).
    """
    from google.api_core import exceptions as gexc

    original = b'{"retained":true}'
    key = _key("retained.json")
    blob = raw_bucket.blob(key)
    blob.upload_from_string(original, if_generation_match=0)
    generation = blob.generation
    assert generation

    with pytest.raises(gexc.GoogleAPICallError):
        blob.delete()

    try:
        raw_bucket.blob(key).upload_from_string(b'{"retained":false}')
        replaced = True
    except gexc.GoogleAPICallError:
        replaced = False

    pinned = raw_bucket.blob(key, generation=generation)
    assert pinned.download_as_bytes() == original
    with pytest.raises(gexc.GoogleAPICallError):
        pinned.delete()
    if not replaced:
        assert raw_bucket.blob(key).download_as_bytes() == original


@pytest.mark.asyncio
async def test_c_d_custodied_state_commitment_round_trips(
    cold_store: Any, raw_bucket: Any
) -> None:
    redis = fakeredis.FakeAsyncRedis(
        server=fakeredis.FakeServer(), decode_responses=True
    )
    sink = EvidenceStreamSink(stream_key=_STREAM_KEY)
    sink._redis = redis
    sink._running = True

    linkage = StateCommitmentLinkage(
        namespace="provider_02",
        bundle_id=f"live-{uuid.uuid4()}",
        step_id="step-1",
        thread_id="live-worm",
        label="safety_check",
    )
    snapshot = {
        "user_id": "u-live-test",
        "loop_count": 1,
        "messages": [
            {"role": "user", "content": f"{_PII_MARKERS[0]} {_PII_MARKERS[1]}"}
        ],
        "card_on_file": _PII_MARKERS[2],
    }
    receipt = await StateCommitmentService(sink).commit_state(snapshot, linkage=linkage)

    store = _PrefixedStore(cold_store, _key("custody/"))
    custodian = EvidenceCustodian(
        redis,
        store,
        None,
        stream_key=_STREAM_KEY,
        require_signature=False,
    )
    outcome = await custodian.flush_once()
    assert outcome.data_key

    # (c) read back from WORM and verify the commitment independently.
    stored = await store.get(outcome.data_key)
    records = [json.loads(line) for line in stored.decode("utf-8").splitlines()]
    assert len(records) == 1
    payload_json = records[0]["payload_json"]
    assert verify_state_commitment(receipt.state_hash, payload_json, linkage=linkage)
    for marker in _PII_MARKERS:
        assert marker not in stored.decode("utf-8")

    # (d) the data-classification label is on both custodied objects.
    for key in (outcome.data_key, outcome.attestation_key):
        blob = raw_bucket.get_blob(store.prefix + key)
        assert blob is not None
        assert (blob.metadata or {}).get("x-data-classification") == DATA_CLASSIFICATION
