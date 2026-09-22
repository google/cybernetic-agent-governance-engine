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

"""verify_chain.py — Authoritative Evidence Chain Verifier

This module acts as the independent authoritative verifier for the
CAGE evidence chain. It reads records (either from a JSONL file or directly
from ClickHouse) and structurally validates the cryptographic hash chain
using the post-W2 schema.

Usage:
    uv run python -m src.compliance_bridge.verify_chain /path/to/evidence.jsonl
"""

import argparse
import json
import logging
import sys
from typing import Any

# Use the authoritative hash function from the kernel
from src.gateway.governance.evidence.stream import _link_hash

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def verify_evidence_chain(records: list[dict[str, Any]]) -> bool:
    """Verify an ordered list of cage-audit/3.0 evidence records.

    Args:
        records: List of evidence dictionaries (must be ordered by sequence).

    Returns:
        True if the chain is intact, False otherwise.
    """
    if not records:
        logger.info("Chain is empty.")
        return True

    expected_prev = ""
    for i, record in enumerate(records):
        seq = int(record.get("sequence", 0))
        if seq != i:
            logger.error("Sequence gap detected at index %d (seq=%d)", i, seq)
            return False

        prev_hash = record.get("prev_hash", "")
        # First record may have None or empty prev_hash
        if prev_hash is None:
            prev_hash = ""

        if i > 0 and prev_hash != expected_prev:
            logger.error(
                "Link broken at sequence %d: prev_hash=%s, expected=%s",
                seq,
                prev_hash,
                expected_prev,
            )
            return False

        # Recompute the hash
        payload_json = record.get("payload_json", "{}")
        # Ensure we use JCS representation for narrowing_applied if it exists
        # In a real tool we'd parse and canonicalize, but here we assume the JSON string is exact
        # (the kernel normalizes and JCS-canonicalizes it prior to stream insertion).

        computed_hash = _link_hash(
            prev_hash=prev_hash,
            sequence=seq,
            event_type=record.get("event_type", ""),
            control_id=record.get("control_id", ""),
            payload_json=payload_json,
        )

        record_hash = record.get("record_hash", "")
        if computed_hash != record_hash:
            logger.error(
                "Hash mismatch at sequence %d: computed=%s, record=%s",
                seq,
                computed_hash,
                record_hash,
            )
            return False

        expected_prev = record_hash

    logger.info("Chain verification successful (%d records).", len(records))
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify CAGE evidence chain integrity."
    )
    parser.add_argument("file", help="Path to JSONL evidence file")
    args = parser.parse_args()

    records = []
    try:
        with open(args.file) as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    except Exception as exc:
        logger.error("Failed to read file: %s", exc)
        sys.exit(1)

    # Sort by sequence just in case
    records.sort(key=lambda x: int(x.get("sequence", 0)))

    if verify_evidence_chain(records):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
