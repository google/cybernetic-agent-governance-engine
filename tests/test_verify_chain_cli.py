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

"""Tests for the offline evidence-chain verifier CLI (issue #286).

Chains are built with the real emitter (``EvidenceStreamSink._seal_record``)
so the CLI is checked against exactly the bytes the kernel hashes, including
the ``cage-audit/3.0`` header members ``chain_id`` / ``trace_id`` and the
sparse ``narrowing_applied`` / ``classification_reason`` members.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.compliance_bridge.verify_chain import (
    ChainStatus,
    main,
    verify_evidence_chain,
)
from src.gateway.governance.evidence.stream import EvidenceStreamSink

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _build_chain(n: int = 5) -> list[dict[str, str]]:
    """Emit ``n`` sealed wire records, advancing chain state as _append would."""
    sink = EvidenceStreamSink(stream_key="cage:evidence:verify-chain-test")
    sink._chain_id = str(uuid.uuid4())
    records: list[dict[str, str]] = []
    for i in range(n):
        event: dict = {"action": "noop", "i": i}
        if i == 1:
            event["narrowing_applied"] = {"max_amount": 100, "scope": "read"}
        if i == 2:
            event["classification_reason"] = "EXTERNAL_VALIDATION"
        payload_json = json.dumps({"i": i}, separators=(",", ":"), sort_keys=True)
        entry, record_hash = sink._seal_record(
            event,
            payload_json,
            "GOVERNANCE_DECISION",
            "AU-10",
            datetime.now(UTC),
        )
        records.append(entry)
        sink._prev_hash = record_hash
        sink._sequence += 1
    return records


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def test_valid_chain_verifies() -> None:
    assert verify_evidence_chain(_build_chain()) is ChainStatus.VALID


@pytest.mark.parametrize(
    ("index", "field", "value"),
    [
        (3, "payload_json", '{"i":999}'),
        (0, "trace_id", "0" * 32),
        (1, "narrowing_applied", '{"max_amount":1000000,"scope":"read"}'),
        (2, "classification_reason", "TAMPERED"),
    ],
)
def test_tampered_field_breaks_chain(index: int, field: str, value: str) -> None:
    records = _build_chain()
    records[index][field] = value
    assert verify_evidence_chain(records) is ChainStatus.BROKEN


def test_chain_splice_detected() -> None:
    records = _build_chain()
    records[2]["chain_id"] = str(uuid.uuid4())
    assert verify_evidence_chain(records) is ChainStatus.BROKEN


def test_sequence_gap_detected() -> None:
    records = _build_chain()
    del records[2]
    assert verify_evidence_chain(records) is ChainStatus.BROKEN


def test_empty_chain_is_not_reported_valid() -> None:
    assert verify_evidence_chain([]) is ChainStatus.UNVERIFIED


def test_cli_valid_chain_exits_zero(tmp_path: Path) -> None:
    path = _write_jsonl(tmp_path / "chain.jsonl", _build_chain())
    assert main([str(path)]) == 0


def test_cli_tampered_chain_exits_one(tmp_path: Path) -> None:
    records = _build_chain()
    records[4]["payload_json"] = '{"i":-1}'
    path = _write_jsonl(tmp_path / "chain.jsonl", records)
    assert main([str(path)]) == 1


def test_cli_empty_file_exits_two(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    assert main([str(path)]) == 2


def test_cli_non_numeric_sequence_exits_two(tmp_path: Path) -> None:
    records = _build_chain(2)
    records[1]["sequence"] = "one"
    path = _write_jsonl(tmp_path / "chain.jsonl", records)
    assert main([str(path)]) == 2


def test_cli_missing_file_exits_two(tmp_path: Path) -> None:
    assert main([str(tmp_path / "missing.jsonl")]) == 2
