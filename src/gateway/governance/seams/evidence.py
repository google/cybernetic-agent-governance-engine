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
Evidence Collector Seam — Vendor-Neutral Evidence Ingestion & Buffering Interface.

This module defines the contract between CAGE's governance kernel and external
evidence collection and buffering sinks.

Architectural Invariant:
    This module must NEVER import from src.gateway.governance or any other kernel
    module. It defines pure data contracts and protocols only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class EvidenceRecord:
    """An individual evidence record captured during governance execution.

    Attributes:
        record_id:  Unique record identifier.
        event_type: Category of governance event (e.g. 'DECISION', 'ACTUATION').
        payload:    Event payload details.
        timestamp:  Unix epoch timestamp when the record was captured.
        metadata:   Provider-specific supplementary metadata.
    """

    record_id: str
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceReceipt:
    """Receipt confirming evidence persistence or ingestion.

    Attributes:
        receipt_id:     Unique receipt identifier.
        stored:         True if ingestion or write succeeded.
        stream_offset:  Stream sequence number or offset.
        receipt_sha256: Cryptographic hash of the stored evidence batch or entry.
        error:          Error message if operation failed; None on success.
    """

    receipt_id: str
    stored: bool
    stream_offset: int = 0
    receipt_sha256: str = ""
    error: str | None = None


@runtime_checkable
class EvidenceCollector(Protocol):
    """Protocol for external evidence collection and buffering sinks.

    Implementations buffer or forward governance events to durable audit stores.
    """

    @property
    def collector_name(self) -> str:
        """Unique collector identifier for telemetry and logging."""
        ...

    async def collect_evidence(self, record: EvidenceRecord) -> EvidenceReceipt:
        """Collect and persist or buffer an individual evidence record."""
        ...

    async def flush_batch(self, batch_id: str) -> EvidenceReceipt:
        """Flush any pending buffered evidence records for the specified batch."""
        ...
