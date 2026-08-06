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
context_accumulator.py — Cryptographic Hash-Chained Context Accumulator (CAGE v0.1.0)

AARM Conformance: Satisfies the "Context Accumulator" mandate from the Cloud Security
Alliance (CSA) Autonomous Agent Risk Management (AARM) specification — an append-only,
tamper-evident log of session states (original request, tool responses, prior states)
that provides an unalterable chain of custody before serialization into NIST OSCAL.

Architecture:
  Each ContextAccumulatorEntry captures the SHA-256 fingerprint of the preceding entry,
  forming a blockchain-style linked list. The genesis entry's ``prev_hash`` is seeded from
  the ``audit_id`` SHA-256, deterministically tying the chain to its audit run.

  Hash function: SHA-256(prev_hash_hex || canonical_header || json.dumps(content,
  sort_keys=True)), where canonical_header binds the node's schema, index,
  audit_id, control_id and event_type into the link.

  This matches the existing production pattern established in examples/telemetry.py
  (``PlaygroundTelemetry``) and validated by governance_demo.py ACT 3, now promoted to
  the core compliance pipeline.

Wire format (NDJSON, one JSON object per line):
  {
    "schema":        "cage-context-accumulator/1.0",
    "node_index":    0,
    "audit_id":      "<audit-run-id>",
    "control_id":    "<ISO-42001-control-id>",
    "event_type":    "OSCAL_FINDING" | "AUDIT_START" | "CHAIN_SEALED",
    "content_hash":  "<sha256 of content JSON>",
    "prev_hash":     "<sha256 of preceding entry>",
    "record_hash":   "<sha256(prev_hash + header_json + content_json)>",
    "timestamp_utc": "<ISO-8601>",
    "payload":       { ... }   // OscalFinding fields
  }

ISO 42001 mapping: A.5.3 (Logging and Monitoring) — the chain provides the
tamper-evident audit trail required by Annex A.5.3 §b.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .types import OscalFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA = "cage-context-accumulator/1.0"
_GENESIS = "GENESIS"  # sentinel used as prev_hash for the first node


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _link_hash(
    prev_hash: str,
    node_index: int,
    audit_id: str,
    control_id: str,
    event_type: str,
    content_json: str,
) -> str:
    """Compute a node's ``record_hash`` over its identifying header + payload.

    The header carries the metadata that ``to_dict()`` persists alongside the
    payload, so re-labelling a node's control or event type, moving it to a
    different position, or re-attributing it to another audit changes the link
    and breaks the chain.  ``timestamp_utc`` is deliberately excluded to keep
    ``record_hash`` a deterministic function of the node's content.
    """
    header = json.dumps(
        {
            "schema": _SCHEMA,
            "node_index": node_index,
            "audit_id": audit_id,
            "control_id": control_id,
            "event_type": event_type,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256(prev_hash + header + content_json)


def _content_hash(payload: dict) -> str:
    """Return the SHA-256 hash of a JSON-serialised payload (deterministic key ordering)."""
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))


# ---------------------------------------------------------------------------
# ContextAccumulatorEntry — one node in the chain
# ---------------------------------------------------------------------------


@dataclass
class ContextAccumulatorEntry:
    """A single node in the cryptographic hash chain.

    Fields:
        schema        — always "cage-context-accumulator/1.0" for parsers.
        node_index    — 0-based position in this audit's chain.
        audit_id      — the parent audit run identifier.
        control_id    — ISO 42001 control ID (e.g. "A.5.3", "SC-4").
        event_type    — semantic label for this node's payload.
        payload       — the original content dict (OscalFinding fields, etc.).
        content_hash  — SHA-256 of ``json.dumps(payload, sort_keys=True)``.
        prev_hash     — SHA-256 of the *preceding* entry's ``record_hash``
                        (genesis constant for the first node).
        record_hash   — SHA-256(prev_hash + canonical header + json.dumps(
                        payload, sort_keys=True)), where the header covers
                        schema, node_index, audit_id, control_id and event_type.
        timestamp_utc — ISO-8601 UTC wall-clock at append time.
        kms_signature — Cloud KMS asymmetric signature of this record (hex-encoded).
                        Empty string when per-record KMS signing is disabled.
                        Populated asynchronously by the AsyncBatchSigner when enabled.
    """

    schema: str
    node_index: int
    audit_id: str
    control_id: str
    event_type: str
    payload: dict
    content_hash: str
    prev_hash: str
    record_hash: str
    timestamp_utc: str
    kms_signature: str = ""

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict for NDJSON output."""
        d = {
            "schema": self.schema,
            "node_index": self.node_index,
            "audit_id": self.audit_id,
            "control_id": self.control_id,
            "event_type": self.event_type,
            "content_hash": self.content_hash,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "timestamp_utc": self.timestamp_utc,
            "payload": self.payload,
        }
        if self.kms_signature:
            d["kms_signature"] = self.kms_signature
        return d


# ---------------------------------------------------------------------------
# ContextAccumulator — stateful chain builder
# ---------------------------------------------------------------------------


class ContextAccumulator:
    """Append-only, hash-chained accumulator for OSCAL audit session state.

    Usage::

        acc = ContextAccumulator(audit_id="cage-audit-2026-001")
        for finding in findings:
            acc.append_finding(finding)
        acc.seal()

        # Verify integrity before persisting
        valid, fail_at = acc.verify_integrity()
        assert valid, f"Chain broken at node {fail_at}"

        # Serialise to NDJSON for GCS/S3 persistence
        ndjson = acc.export_ndjson()

    Per-record KMS signing (opt-in)::

        acc = ContextAccumulator(audit_id="...", kms_sign=True)
        # Records are enqueued to the AsyncBatchSigner ring buffer.
        # Signatures arrive asynchronously — call ``await drain()``
        # before persisting to ensure all signatures are populated.
    """

    def __init__(self, audit_id: str, kms_sign: bool = False) -> None:
        self._audit_id = audit_id
        self._entries: list[ContextAccumulatorEntry] = []
        self._kms_sign = kms_sign
        # Genesis: seed the chain from the audit_id SHA-256 so the chain is
        # deterministically tied to this audit run.
        self._prev_hash: str = _sha256(audit_id)
        logger.debug(
            "[context_accumulator] Initialised chain for audit_id=%s genesis=%s… kms_sign=%s",
            audit_id,
            self._prev_hash[:16],
            kms_sign,
        )

    # ------------------------------------------------------------------
    # append_finding — primary production entry point
    # ------------------------------------------------------------------

    def append_finding(self, finding: OscalFinding) -> ContextAccumulatorEntry:
        """Append an OscalFinding as a chained node.

        Args:
            finding: Parsed OscalFinding from the audit pipeline.

        Returns:
            The newly created ContextAccumulatorEntry.
        """
        payload = finding.model_dump()
        return self._append_node(
            control_id=finding.control_id,
            event_type="OSCAL_FINDING",
            payload=payload,
        )

    # ------------------------------------------------------------------
    # seal — write the terminal CHAIN_SEALED sentinel
    # ------------------------------------------------------------------

    def seal(self) -> ContextAccumulatorEntry:
        """Append a CHAIN_SEALED sentinel node that locks the chain.

        The sentinel's payload contains the total node count and chain root
        hash, providing a single-record summary for quick integrity checks.
        """
        payload: dict[str, Any] = {
            "chain_length": len(self._entries),
            "chain_root": self.chain_root(),
            "audit_id": self._audit_id,
            "sealed_utc": datetime.now(tz=timezone.utc).isoformat(),
            "aarm_compliance": "CONTEXT_ACCUMULATOR/AARM-V1",
            "iso_42001_control": "A.5.3",
        }
        entry = self._append_node(
            control_id="A.5.3",
            event_type="CHAIN_SEALED",
            payload=payload,
        )
        logger.info(
            "[context_accumulator] Chain sealed: audit_id=%s nodes=%d root=%s…",
            self._audit_id,
            len(self._entries),
            self.chain_root()[:16],
        )
        return entry

    # ------------------------------------------------------------------
    # verify_integrity — tamper detection
    # ------------------------------------------------------------------

    def verify_integrity(self) -> tuple[bool, int]:
        """Recompute every SHA-256 link and verify consistency.

        Returns:
            (True, node_count)     if the entire chain is intact.
            (False, fail_index)    where fail_index is the 0-based index of the
                                   first node whose computed hash does not match
                                   its stored ``record_hash``.

        The verification recomputes the link over ``prev_hash``, the node's
        committed header fields and ``content_json`` for every node, comparing
        against the stored ``record_hash`` and ``content_hash``.  Any mutation
        to any field in any node will cause the check to fail at that node
        *and* every subsequent node (because prev_hash forward-propagates).
        """
        if not self._entries:
            return True, 0

        expected_prev = _sha256(self._audit_id)  # genesis seed

        for i, entry in enumerate(self._entries):
            content_json = json.dumps(entry.payload, sort_keys=True, default=str)
            expected_hash = _link_hash(
                prev_hash=expected_prev,
                node_index=entry.node_index,
                audit_id=entry.audit_id,
                control_id=entry.control_id,
                event_type=entry.event_type,
                content_json=content_json,
            )

            if (
                entry.prev_hash != expected_prev
                or entry.record_hash != expected_hash
                or entry.content_hash != _sha256(content_json)
            ):
                logger.warning(
                    "[context_accumulator] Chain integrity FAILED at node %d "
                    "(audit_id=%s). Expected prev=%s… got %s…; "
                    "expected record=%s… got %s…",
                    i,
                    self._audit_id,
                    expected_prev[:16],
                    entry.prev_hash[:16],
                    expected_hash[:16],
                    entry.record_hash[:16],
                )
                return False, i

            expected_prev = entry.record_hash  # advance for next node

        logger.debug(
            "[context_accumulator] Chain integrity OK: %d node(s) verified (audit_id=%s)",
            len(self._entries),
            self._audit_id,
        )
        return True, len(self._entries)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def export_ndjson(self) -> str:
        """Serialise the entire chain as NDJSON (one JSON object per line)."""
        lines = [json.dumps(e.to_dict(), default=str) for e in self._entries]
        return "\n".join(lines) + ("\n" if lines else "")

    def chain_root(self) -> str:
        """Return the ``record_hash`` of the last committed entry.

        Returns the genesis seed if the chain is empty.
        """
        if not self._entries:
            return _sha256(self._audit_id)
        return self._entries[-1].record_hash

    @property
    def length(self) -> int:
        """Number of committed nodes (including the CHAIN_SEALED sentinel if present)."""
        return len(self._entries)

    @property
    def entries(self) -> list[ContextAccumulatorEntry]:
        """Read-only view of all committed entries."""
        return list(self._entries)

    # ------------------------------------------------------------------
    # Internal append — shared by append_finding() and seal()
    # ------------------------------------------------------------------

    def _append_node(
        self,
        control_id: str,
        event_type: str,
        payload: dict,
    ) -> ContextAccumulatorEntry:
        """Compute the SHA-256 link and commit a new entry to the chain.

        When ``kms_sign=True``, the record is enqueued to the AsyncBatchSigner
        ring buffer for non-blocking background signing.  The ``kms_signature``
        field will be populated asynchronously.
        """
        now_utc = datetime.now(tz=timezone.utc).isoformat()
        content_json = json.dumps(payload, sort_keys=True, default=str)
        chash = _sha256(content_json)
        node_index = len(self._entries)
        record_hash = _link_hash(
            prev_hash=self._prev_hash,
            node_index=node_index,
            audit_id=self._audit_id,
            control_id=control_id,
            event_type=event_type,
            content_json=content_json,
        )

        entry = ContextAccumulatorEntry(
            schema=_SCHEMA,
            node_index=node_index,
            audit_id=self._audit_id,
            control_id=control_id,
            event_type=event_type,
            payload=payload,
            content_hash=chash,
            prev_hash=self._prev_hash,
            record_hash=record_hash,
            timestamp_utc=now_utc,
        )
        self._entries.append(entry)
        self._prev_hash = record_hash

        # Enqueue for async KMS signing (non-blocking)
        if self._kms_sign:
            self._enqueue_for_signing(entry)

        return entry

    def _enqueue_for_signing(self, entry: ContextAccumulatorEntry) -> None:
        """Enqueue a record to the AsyncBatchSigner ring buffer.

        The callback writes the signature back to the entry's kms_signature
        field when signing completes.
        """
        from .kms_batch_signer import get_batch_signer

        def _on_signed(record_hash: str, signature: str) -> None:
            entry.kms_signature = signature

        signer = get_batch_signer()
        signer.enqueue(
            record_hash=entry.record_hash,
            payload=entry.payload,
            callback=_on_signed,
        )
