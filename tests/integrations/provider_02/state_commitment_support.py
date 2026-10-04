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

"""In-process state-commitment fixtures for Provider 02 adapter tests.

Not a test module (no ``test_`` prefix, nothing collected). It wires the real
kernel :class:`StateCommitmentService` to a recording evidence sink that
reproduces the production sink's payload pipeline
(``sanitize_dict`` → ``_normalize_for_jcs`` → JCS), so adapter tests exercise
the same sanitize/canonicalize/hash path as the gateway without a network or
Redis. The kernel service is tested against the real ``EvidenceStreamSink``
in ``tests/test_state_commitment_service.py``.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.evidence.state_commitment import StateCommitmentService
from src.gateway.governance.evidence.stream import (
    EvidenceChainUnavailableError,
    EvidenceCommitResult,
    _normalize_for_jcs,
)
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.pii_sanitizer import _get_pii_sanitizer
from src.gateway.governance.seams.state_commitment import (
    StateCommitmentLinkage,
    StateCommitmentReceipt,
)

ADVISOR_IDENTITY = "advisor.cage.serviceaccount.identity.linkerd.cluster.local"


class RecordingEvidenceSink:
    """Evidence sink double: stores ``payload_json`` exactly as the real sink."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.payloads: list[str] = []

    @property
    def is_running(self) -> bool:
        return True

    async def ingest_sync(self, event: dict[str, Any]) -> EvidenceCommitResult:
        if self.fail:
            raise EvidenceChainUnavailableError("injected evidence-chain outage")
        payload_json = jcs_canonicalize_plan(
            _normalize_for_jcs(_get_pii_sanitizer().sanitize_dict(event))
        ).decode("utf-8")
        self.payloads.append(payload_json)
        sequence = len(self.payloads) - 1
        return EvidenceCommitResult(
            success=True,
            evidence_id=f"{1_700_000_000_000 + sequence}-0",
            commit_timestamp=datetime.now(tz=timezone.utc),
            hash=hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
            sequence=sequence,
        )


class InProcessCommitter:
    """A :class:`StateCommitter` backed by the real kernel service."""

    def __init__(self, sink: RecordingEvidenceSink | None = None) -> None:
        self.sink = sink or RecordingEvidenceSink()
        self.service = StateCommitmentService(self.sink)
        self.linkages: list[StateCommitmentLinkage] = []

    async def commit_state(
        self,
        snapshot: Mapping[str, Any],
        *,
        linkage: StateCommitmentLinkage,
    ) -> StateCommitmentReceipt:
        self.linkages.append(linkage)
        return await self.service.commit_state(
            snapshot, linkage=linkage, caller_identity=ADVISOR_IDENTITY
        )


def seal(callback: Any) -> None:
    """Run ``callback.seal()`` from synchronous test code."""
    asyncio.run(callback.seal())


def sealed_bundle(callback: Any) -> Any:
    """Seal ``callback`` and return its bundle."""
    seal(callback)
    return callback.get_bundle()
