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

"""storage.py — Durable OSCAL artifact persistence via EvidenceColdStore seam.

Consolidated under Wave 1 Task W1.5c:
All direct GCS / S3 SDK calls and client caches have been removed. Storage I/O
delegates entirely to the injected or ambient EvidenceColdStore protocol
implementation (Layer 1 kernel seam).

Object key pattern (frozen wire format):
  oscal-artifacts/<ISO-date>/<auditId>.yaml

SHA-256 digest and ISO 42001 compliance metadata are attached to all object
writes for content verifiability and deduplication.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gateway.governance.evidence.cold_store import EvidenceColdStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Key formatters & hashing helpers (frozen wire format)
# ---------------------------------------------------------------------------


def _build_object_key(audit_id: str, timestamp: datetime) -> str:
    """Deterministic path from audit timestamp + ID."""
    date = timestamp.strftime("%Y-%m-%d")
    return f"oscal-artifacts/{date}/{audit_id}.yaml"


def _sha256(content: str) -> str:
    """Return lowercase hex SHA-256 digest of utf-8 content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public async API
# ---------------------------------------------------------------------------


async def put_oscal_artifact_atomic(
    audit_id: str,
    oscal_yaml: str,
    timestamp: datetime | None = None,
    cold_store: EvidenceColdStore | None = None,
) -> tuple[str, bool]:
    """Atomic idempotent OSCAL artifact upload via EvidenceColdStore seam.

    Args:
        audit_id:   Unique run identifier.
        oscal_yaml: Raw YAML string from `lula validate`.
        timestamp:  Audit timestamp (used in object key path). Defaults to now.
        cold_store: Optional EvidenceColdStore implementation. If None, resolved
                    from ambient factory configuration.

    Returns:
        Tuple of (object key, created: bool). created=False if artifact existed.
    """
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc)

    if cold_store is None:
        from src.gateway.governance.evidence.factory import get_cold_store

        cold_store = get_cold_store()

    key = _build_object_key(audit_id, timestamp)
    content_bytes = oscal_yaml.encode("utf-8")
    digest = _sha256(oscal_yaml)

    metadata = {
        "x-audit-id": audit_id,
        "x-content-sha256": digest,
        "x-standard": "ISO/IEC 42001:2023",
        "x-audit-ts": timestamp.isoformat(),
        "content-type": "application/yaml",
    }

    receipt, created = await cold_store.put_if_absent(
        key=key,
        content=content_bytes,
        metadata=metadata,
    )

    logger.info(
        "[storage] OSCAL artifact persisted (%s): %s (created=%s, sha256=%s…)",
        receipt.backend_id,
        receipt.uri,
        created,
        digest[:12],
    )
    return key, created


async def put_oscal_artifact(
    audit_id: str,
    oscal_yaml: str,
    timestamp: datetime | None = None,
    cold_store: EvidenceColdStore | None = None,
) -> str:
    """Idempotent OSCAL artifact upload via EvidenceColdStore seam.

    Delegates to `put_oscal_artifact_atomic`.

    Args:
        audit_id:   Unique run identifier.
        oscal_yaml: Raw YAML string from `lula validate`.
        timestamp:  Audit timestamp (used in object key path). Defaults to now.
        cold_store: Optional EvidenceColdStore implementation.

    Returns:
        Object key (not the full URI).
    """
    key, _ = await put_oscal_artifact_atomic(
        audit_id=audit_id,
        oscal_yaml=oscal_yaml,
        timestamp=timestamp,
        cold_store=cold_store,
    )
    return key
