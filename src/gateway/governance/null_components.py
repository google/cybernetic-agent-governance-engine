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

"""Fail-closed null objects for bare-kernel mode.

When no domain plugin is loaded (CAGE_ACTIVE_PLUGINS=""), the kernel uses these
null implementations. They are NOT no-ops: every method returns a denial verdict.

A kernel with no plugin denies everything by intent (G2 gate), not by accident.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from src.gateway.governance.evidence.cold_store import (
    ColdStoreHealth,
    ColdStoreReceipt,
    EvidenceColdStore,
)


class NullSafetyFilter:
    """Fail-closed SafetyFilter used when no domain plugin is loaded.

    Every method returns a denial verdict. This ensures that a missing plugin
    produces explicit DENY verdicts rather than silent failures or AttributeError
    exceptions that might be caught by CBF_FAIL_OPEN error handlers.
    """

    def verify_action(self, action_name: str, payload: dict) -> str:
        return "UNSAFE: no domain safety filter registered (bare-kernel mode)"

    async def atomic_verify_and_commit(
        self, action_name: str, payload: dict, governance_signature: str = ""
    ) -> tuple[bool, str]:
        """Always denies. Returns (False, reason).

        Critical: This must return (False, ...) NOT raise an exception.
        If it raised, the exception would be caught by broad exception handlers
        in the CBF tier, and with CBF_FAIL_OPEN=true that could produce a
        silent fail-open. Returning False ensures the denial travels the normal
        verdict path.
        """
        return (
            False,
            "UNSAFE: no domain safety filter registered (bare-kernel mode)",
        )

    async def rollback_state(
        self, magnitude: float, governance_signature: str | None = None
    ) -> None:
        """No-op rollback — there was no state to commit in the first place."""
        return None


class NullConsensusProvider:
    """Fail-closed ConsensusProvider used when no domain plugin is loaded.

    Always returns REJECT status.
    """

    async def check_consensus(
        self, action: str, context: dict[str, Any], magnitude: float | None = None
    ) -> dict[str, Any]:
        """Always rejects.

        Returns a properly structured consensus response with REJECT status
        so the denial integrates cleanly with the tier loop.
        """
        return {
            "status": "REJECT",
            "reason": "no consensus provider registered (bare-kernel mode)",
            "agreement_level": 0.0,
            "critics_polled": 0,
            "critics_agreed": 0,
        }


class NullColdStore(EvidenceColdStore):
    """Fail-closed EvidenceColdStore used when no cloud storage is configured.

    Succeeds locally/dev but fails on startup if CAGE_ENV=prod.
    Emits distinct metric label for observability.

    This allows local development without GCS/S3 credentials while enforcing
    that production deployments MUST have cold storage configured for compliance.
    """

    def __init__(self) -> None:
        """Initialize NullColdStore.

        Raises:
            RuntimeError: If CAGE_ENV=prod (production must have real cold storage)
        """
        cage_env = os.environ.get("CAGE_ENV", "dev")
        if cage_env == "prod":
            raise RuntimeError(
                "[NullColdStore] CAGE_ENV=prod requires real cold storage. "
                "Configure EVIDENCE_STREAM_BUCKET_{region} and use "
                "GcsColdStore or S3ColdStore."
            )
        self._logger = logging.getLogger("cage.evidence.null_cold_store")

    @property
    def backend_id(self) -> str:
        return "null"

    async def put_batch(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> ColdStoreReceipt:
        """No-op upload for local/dev environments.

        Computes exact SHA-256 digest and returns a simulated receipt.
        """
        digest = hashlib.sha256(content).hexdigest()
        self._logger.warning(
            "[NullColdStore] Skipping cold storage for key '%s' (%d bytes) — dev/local mode",
            key,
            len(content),
        )
        return ColdStoreReceipt(
            uri=f"null://{key}",
            key=key,
            content_sha256=digest,
            backend_id="null",
            written_at=datetime.now(timezone.utc),
        )

    async def exists(self, key: str) -> bool:
        """NullColdStore does not persist objects; always returns False."""
        return False

    async def put_if_absent(
        self,
        key: str,
        content: bytes,
        metadata: Mapping[str, str] | None = None,
    ) -> tuple[ColdStoreReceipt, bool]:
        """Simulates atomic put_if_absent (always succeeds in dev)."""
        receipt = await self.put_batch(key, content, metadata)
        return receipt, True

    def health(self) -> ColdStoreHealth:
        """Synchronously reports availability for dev/local environments."""
        return ColdStoreHealth(
            available=True,
            backend_id="null",
            detail="in-memory dev null cold store (no durable persistence)",
        )
