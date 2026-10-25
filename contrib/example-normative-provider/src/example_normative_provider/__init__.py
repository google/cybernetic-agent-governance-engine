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

"""Minimal inbound NormativeProvider SPI reference implementation."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    FindingStatus,
    NormativeBaseline,
    ValidationResult,
)


class ExampleNormativeProvider:
    """Reference external NormativeProvider registered via entry_points."""

    @classmethod
    def from_env(cls) -> ExampleNormativeProvider:
        """Construct provider from environment configuration."""
        return cls()

    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        """Return a minimal synthetic regulatory baseline for region."""
        return NormativeBaseline(
            region=region,
            profile={"region": region, "controls": ["EU-AI-ACT-ART-9"]},
            fetched_at=time.time(),
            etag=f"example-{region.lower()}-v1",
        )

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        """Validate a FRIA decision payload and return standardized findings."""
        action = str(payload.get("action", "unknown"))
        return ValidationResult(
            admitted=True,
            findings=[
                {
                    "control_id": "EU-AI-ACT-ART-9",
                    "status": FindingStatus.PASS.value,
                    "detail": f"Admitted action {action}",
                }
            ],
            sealed_at=time.time(),
        )

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        """Seal an evidence chain digest."""
        digest = hashlib.sha256(f"{thread_id}:{evidence_hash}".encode()).hexdigest()
        return EvidenceSeal(
            thread_id=thread_id,
            seal_hash=f"sha256:{digest}",
            sealed_at=time.time(),
        )
