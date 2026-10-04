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
CAGE evidence chain. It reads records from a JSONL export and structurally
validates the cryptographic hash chain under the ``cage-audit/3.0`` contract.

Per-record hash recomputation is delegated to the kernel's
:func:`~src.gateway.governance.evidence.stream.verify_record`, so the header
members inside the hash (``chain_id``, ``trace_id`` and the sparse
``classification_reason`` / ``narrowing_applied`` / ``pause_token``) are read
in exactly one place. A schema change to ``_link_hash`` therefore cannot
silently desynchronise this CLI from the emitter again (issue #286).

Exit codes:
    0  chain verified
    1  chain broken (sequence gap, broken link, chain splice, hash mismatch)
    2  nothing verified (unreadable file, malformed record, or empty chain)

Usage:
    uv run python -m src.compliance_bridge.verify_chain /path/to/evidence.jsonl
"""

import argparse
import enum
import json
import logging
import sys
from typing import Any

from src.gateway.governance.evidence.stream import verify_record

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


class ChainStatus(enum.IntEnum):
    """Outcome of a chain verification; the value is the CLI exit code."""

    VALID = 0
    BROKEN = 1
    UNVERIFIED = 2


def _parse_sequence(record: dict[str, Any], index: int) -> int:
    """Return the record's integer sequence or raise ``ValueError``."""
    raw = record.get("sequence")
    if raw is None:
        raise ValueError(f"record at index {index} has no sequence")
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"record at index {index} has non-integer sequence {raw!r}"
        ) from exc


def verify_evidence_chain(records: list[dict[str, Any]]) -> ChainStatus:
    """Verify an ordered list of ``cage-audit/3.0`` evidence records.

    An empty chain is reported as :attr:`ChainStatus.UNVERIFIED` rather than
    valid, so an empty export can never read as a verified one.

    Args:
        records: Evidence dictionaries, ordered by sequence.

    Returns:
        The chain status.
    """
    if not records:
        logger.error("Chain is empty — nothing was verified.")
        return ChainStatus.UNVERIFIED

    chain_id = records[0].get("chain_id", "")
    expected_prev = ""
    for i, record in enumerate(records):
        try:
            seq = _parse_sequence(record, i)
        except ValueError as exc:
            logger.error("Malformed record: %s", exc)
            return ChainStatus.UNVERIFIED

        if seq != i:
            logger.error("Sequence gap detected at index %d (seq=%d)", i, seq)
            return ChainStatus.BROKEN

        if record.get("chain_id", "") != chain_id:
            logger.error(
                "Chain splice at sequence %d: chain_id=%r, expected=%r",
                seq,
                record.get("chain_id", ""),
                chain_id,
            )
            return ChainStatus.BROKEN

        # Genesis records carry "" (Redis) or None (ClickHouse NULL).
        prev_hash = record.get("prev_hash") or ""
        if prev_hash != expected_prev:
            logger.error(
                "Link broken at sequence %d: prev_hash=%s, expected=%s",
                seq,
                prev_hash,
                expected_prev,
            )
            return ChainStatus.BROKEN

        result = verify_record(record, prev_hash)
        if not result.valid:
            logger.error("Record invalid at sequence %d: %s", seq, result.error)
            return ChainStatus.BROKEN

        expected_prev = result.expected_hash

    logger.info("Chain verification successful (%d records).", len(records))
    return ChainStatus.VALID


def _load_records(path: str) -> list[dict[str, Any]]:
    """Read a JSONL evidence export, sorted by sequence.

    Raises:
        OSError: If the file cannot be read.
        ValueError: If a line is not a JSON object or a sequence is not an
            integer.
    """
    records: list[dict[str, Any]] = []
    with open(path) as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"line {line_no} is not a JSON object")
            records.append(record)

    keyed = [(_parse_sequence(r, i), r) for i, r in enumerate(records)]
    keyed.sort(key=lambda pair: pair[0])
    return [r for _, r in keyed]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify CAGE evidence chain integrity."
    )
    parser.add_argument("file", help="Path to JSONL evidence file")
    args = parser.parse_args(argv)

    try:
        records = _load_records(args.file)
    except (OSError, ValueError) as exc:
        logger.error("Failed to read evidence file: %s", exc)
        return int(ChainStatus.UNVERIFIED)

    return int(verify_evidence_chain(records))


if __name__ == "__main__":
    sys.exit(main())
