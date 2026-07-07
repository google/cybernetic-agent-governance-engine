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

"""Provenance chain — AI 600-1 §2.7 information integrity control.

Builds a cryptographic hash chain linking each LangGraph governance node's
input and output, creating an immutable audit trail of governance decisions.

In production, each record is signed with the US_FED KMS key ring via
``src/gateway/governance/kms_signer.py`` and written to the GCS WORM bucket
under ``provenance/<date>/<trace_id>.json``.

POAM: AI600-005
Controls: AgentSight daemon, KMS signing
Region: US_FED (CAGE_DEPLOYMENT_REGION=US_FED)

Usage::

    from src.gateway.governance.provenance_chain import (
        build_provenance_record, compute_hash, ProvenanceRecord
    )

    record = build_provenance_record(
        trace_id="trace-123",
        node_id="opa_node",
        input_data={"action": "execute_trade", "amount": 5000},
        output_data={"decision": "ALLOW"},
        decision="ALLOW",
        parent_hash=None,
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger("Gateway.Governance.ProvenanceChain")

# ---------------------------------------------------------------------------
# Valid decision values — enforced by build_provenance_record
# ---------------------------------------------------------------------------

VALID_DECISIONS = frozenset({"ALLOW", "BLOCK", "ESCALATE"})


# ---------------------------------------------------------------------------
# ProvenanceRecord — a single node in the provenance chain
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceRecord:
    """A single cryptographic provenance record for a LangGraph governance node.

    Attributes:
        trace_id:     Langfuse trace ID for the governed request.
        node_id:      LangGraph node name (e.g. "opa_node", "causal_gatekeeper").
        input_hash:   SHA-256 hex digest of the node's input data.
        output_hash:  SHA-256 hex digest of the node's output data.
        decision:     Governance decision: "ALLOW" | "BLOCK" | "ESCALATE".
        parent_hash:  SHA-256 hex digest of the previous record in the chain,
                      or None for the first record.
    """

    trace_id: str
    node_id: str
    input_hash: str
    output_hash: str
    decision: str
    parent_hash: str | None

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict representation of this record."""
        return {
            "trace_id": self.trace_id,
            "node_id": self.node_id,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "decision": self.decision,
            "parent_hash": self.parent_hash,
        }

    def chain_hash(self) -> str:
        """Return the SHA-256 hash of this record (for use as parent_hash of the next).

        The hash is computed over the full record dict (sorted keys) so that
        any tampering with any field invalidates the chain.
        """
        return compute_hash(self.to_dict())


# ---------------------------------------------------------------------------
# compute_hash — deterministic SHA-256 hash of a dict
# ---------------------------------------------------------------------------


def compute_hash(data: dict) -> str:
    """Return the SHA-256 hex digest of the JSON-serialised dict.

    Keys are sorted to ensure deterministic output regardless of insertion order.
    Non-serialisable values are coerced to strings.

    Args:
        data: A dict to hash.

    Returns:
        A 64-character lowercase hex string (SHA-256 digest).
    """
    safe = {
        k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
        for k, v in data.items()
    }
    serialised = json.dumps(safe, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# build_provenance_record — main factory function
# ---------------------------------------------------------------------------


def build_provenance_record(
    trace_id: str,
    node_id: str,
    input_data: dict,
    output_data: dict,
    decision: str,
    parent_hash: str | None = None,
) -> ProvenanceRecord:
    """Build a ProvenanceRecord for a LangGraph governance node execution.

    Args:
        trace_id:    Langfuse trace ID for the governed request.
        node_id:     LangGraph node name (e.g. "opa_node").
        input_data:  The node's input dict (will be hashed, not stored).
        output_data: The node's output dict (will be hashed, not stored).
        decision:    Governance decision: "ALLOW" | "BLOCK" | "ESCALATE".
        parent_hash: Hash of the previous record in the chain, or None.

    Returns:
        A ``ProvenanceRecord`` with computed input/output hashes.

    Raises:
        ValueError: If ``decision`` is not one of ALLOW | BLOCK | ESCALATE.
    """
    if decision not in VALID_DECISIONS:
        raise ValueError(
            f"Invalid decision '{decision}'. Must be one of: {sorted(VALID_DECISIONS)}"
        )

    record = ProvenanceRecord(
        trace_id=trace_id,
        node_id=node_id,
        input_hash=compute_hash(input_data),
        output_hash=compute_hash(output_data),
        decision=decision,
        parent_hash=parent_hash,
    )

    logger.debug(
        "Provenance record built: trace_id=%s node_id=%s decision=%s "
        "input_hash=%s... output_hash=%s... parent_hash=%s",
        trace_id,
        node_id,
        decision,
        record.input_hash[:8],
        record.output_hash[:8],
        (parent_hash[:8] + "...") if parent_hash else "None",
    )

    return record


def verify_chain_integrity(records: list[ProvenanceRecord]) -> bool:
    """Verify the integrity of a provenance chain.

    Checks that each record's ``parent_hash`` matches the ``chain_hash()``
    of the preceding record.  The first record must have ``parent_hash=None``.

    Args:
        records: Ordered list of ProvenanceRecord objects (oldest first).

    Returns:
        True if the chain is intact, False if any link is broken.
    """
    if not records:
        return True

    if records[0].parent_hash is not None:
        logger.warning(
            "Provenance chain integrity check FAILED: first record has non-None parent_hash=%s",
            records[0].parent_hash,
        )
        return False

    for i in range(1, len(records)):
        expected_parent = records[i - 1].chain_hash()
        actual_parent = records[i].parent_hash
        if actual_parent != expected_parent:
            logger.warning(
                "Provenance chain integrity check FAILED at index %d: "
                "expected parent_hash=%s... got %s...",
                i,
                expected_parent[:8],
                (actual_parent[:8] + "...") if actual_parent else "None",
            )
            return False

    logger.debug(
        "Provenance chain integrity verified: %d records, all links intact.",
        len(records),
    )
    return True
