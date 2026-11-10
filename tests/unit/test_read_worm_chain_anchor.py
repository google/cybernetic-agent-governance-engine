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

"""Unit tests for scripts/read_worm_chain_anchor.py (F-94, R-10)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.read_worm_chain_anchor import (
    WormAnchorError,
    _validate_http_url,
    extract_chain_anchor,
    main,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

HASH_A = "a" * 64
ATTEST_A = "b" * 64
HASH_B = "c" * 64
ATTEST_B = "d" * 64


def _make_batch(
    chain_id: str,
    first_seq: int,
    last_seq: int,
    last_hash: str,
    attest_sha: str,
    *,
    rotated_from_chain_id: str | None = None,
    bound_chain_rotation: bool = False,
) -> dict[str, object]:
    return {
        "attestation_key": f"evidence-stream/2026/11/09/{chain_id}/{first_seq:012d}-{last_seq:012d}.ndjson.attestation.json",
        "data_key": f"evidence-stream/2026/11/09/{chain_id}/{first_seq:012d}-{last_seq:012d}.ndjson",
        "chain_id": chain_id,
        "first_sequence": first_seq,
        "last_sequence": last_seq,
        "entries": last_seq - first_seq + 1,
        "first_prev_hash": "",
        "last_record_hash": last_hash,
        "attestation_sha256": attest_sha,
        "rotated_from_chain_id": rotated_from_chain_id,
        "bound_chain_rotation": bound_chain_rotation,
    }


def test_extract_chain_anchor_resolves_tail_across_bound_rotation_regardless_of_hex_sort() -> (
    None
):
    """When chain 'ffff0001' rotates into '0000aaaa', the unreplaced successor is selected."""
    report = {
        "ok": True,
        "citable": True,
        "verified": [
            _make_batch(
                "0000aaaa",
                0,
                3,
                HASH_B,
                ATTEST_B,
                rotated_from_chain_id="ffff0001",
                bound_chain_rotation=True,
            ),
            _make_batch("ffff0001", 0, 12, HASH_A, ATTEST_A),
        ],
        "failures": [],
        "declared_gaps": [],
        "bound_rotations": [
            {
                "previous_chain_id": "ffff0001",
                "new_chain_id": "0000aaaa",
                "previous_last_sequence": 12,
                "previous_chain_head_hash": HASH_A,
                "previous_batch_attestation_digest": ATTEST_A,
                "kind": "BOUND_CHAIN_ROTATION",
            }
        ],
        "non_evidentiary": [],
    }
    anchor = extract_chain_anchor(report)
    assert anchor.chain_id == "0000aaaa"
    assert anchor.last_sequence == 3
    assert anchor.last_record_hash == HASH_B
    assert anchor.attestation_sha256 == ATTEST_B
    assert anchor.verified_batches == 2
    assert anchor.bound_rotations == 1


@pytest.mark.parametrize(
    ("mutated_report", "expected_error"),
    [
        (
            {
                "ok": True,
                "citable": False,
                "verified": [_make_batch("c1", 0, 1, HASH_A, ATTEST_A)],
                "failures": [],
                "declared_gaps": [{"chain_id": "c0", "missing_from": 5}],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "not citable",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "0 verified signed batches",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [
                    _make_batch("c1", 0, 1, HASH_A, ATTEST_A),
                    _make_batch("c2", 0, 1, HASH_B, ATTEST_B),
                ],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "Ambiguous multi-head WORM archive",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [_make_batch("c1", 0, 1, "not-a-hex-digest", ATTEST_A)],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "last_record_hash is missing or not a 64-hex",
        ),
        (
            {
                "ok": True,
                "citable": True,
                "verified": [_make_batch("c1", 0, 1, HASH_A, "")],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            },
            "attestation_sha256 is missing or not a 64-hex",
        ),
    ],
)
def test_extract_chain_anchor_fails_closed_on_invalid_or_gapped_reports(
    mutated_report: dict[str, object], expected_error: str
) -> None:
    with pytest.raises(WormAnchorError, match=expected_error):
        extract_chain_anchor(mutated_report)


def test_validate_http_url_rejects_non_http_schemes() -> None:
    with pytest.raises(WormAnchorError, match="scheme must be http or https"):
        _validate_http_url("file:///etc/passwd")
    assert (
        _validate_http_url("http://localhost:3002/v1/evidence/verify")
        == "http://localhost:3002/v1/evidence/verify"
    )


def test_cli_writes_anchor_json_and_prints_env_exports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "verify_report.json"
    anchor_out = tmp_path / "pre_teardown_anchor.json"
    report_path.write_text(
        json.dumps(
            {
                "ok": True,
                "citable": True,
                "verified": [_make_batch("chain42", 0, 7, HASH_A, ATTEST_A)],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            }
        ),
        encoding="utf-8",
    )

    rc = main(
        [
            "--report-file",
            str(report_path),
            "--format",
            "env",
            "--output",
            str(anchor_out),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert f"TF_VAR_evidence_previous_chain_head_hash={HASH_A}" in out
    assert f"TF_VAR_evidence_previous_batch_attestation_digest={ATTEST_A}" in out
    written = json.loads(anchor_out.read_text(encoding="utf-8"))
    assert written["chain_id"] == "chain42"
    assert written["last_record_hash"] == HASH_A
    assert written["attestation_sha256"] == ATTEST_A


def test_extract_chain_anchor_disambiguates_governance_vs_infra_stream() -> None:
    gov_batch = {
        **_make_batch("gov-chain-1", 0, 5, HASH_A, ATTEST_A),
        "stream_key": "cage:evidence:stream",
    }
    infra_batch = {
        **_make_batch("infra-chain-1", 0, 2, HASH_B, ATTEST_B),
        "stream_key": "cage:evidence:infra:stream",
    }
    report = {
        "ok": True,
        "citable": True,
        "verified": [gov_batch, infra_batch],
        "failures": [],
        "declared_gaps": [],
        "bound_rotations": [],
        "non_evidentiary": [],
    }
    anchor = extract_chain_anchor(report)
    assert anchor.chain_id == "gov-chain-1"
    assert anchor.last_record_hash == HASH_A
    assert anchor.attestation_sha256 == ATTEST_A
    assert anchor.stream_key == "cage:evidence:stream"
    # Archive-wide verified count preserved so PRE_WORM_BATCH_COUNT + 1 stays aligned.
    assert anchor.verified_batches == 2

    infra_anchor = extract_chain_anchor(report, stream_key="cage:evidence:infra:stream")
    assert infra_anchor.chain_id == "infra-chain-1"
    assert infra_anchor.last_record_hash == HASH_B

    with pytest.raises(
        WormAnchorError, match="0 verified signed batches for stream_key"
    ):
        extract_chain_anchor(report, stream_key="cage:evidence:nonexistent")


def test_main_export_format_and_if_exists_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty_inv = tmp_path / "inv-zero.json"
    empty_inv.write_text(
        json.dumps({"pre_run_evidence_stream_object_count": 0}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "--gcs-bucket=unused-bucket",
                f"--pre-run-inventory={empty_inv}",
                "--if-exists",
                "--format=export",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == ""

    infra_only_report = tmp_path / "infra-only.json"
    infra_only_report.write_text(
        json.dumps(
            {
                "ok": True,
                "citable": True,
                "verified": [
                    {
                        **_make_batch("infra-chain", 0, 0, HASH_B, ATTEST_B),
                        "stream_key": "cage:evidence:infra:stream",
                    }
                ],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            }
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                f"--report-file={infra_only_report}",
                "--stream-key=cage:evidence:stream",
                "--if-exists",
                "--format=export",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == ""

    gov_report = tmp_path / "gov.json"
    gov_report.write_text(
        json.dumps(
            {
                "ok": True,
                "citable": True,
                "verified": [
                    {
                        **_make_batch("gov-chain", 0, 0, HASH_A, ATTEST_A),
                        "stream_key": "cage:evidence:stream",
                    }
                ],
                "failures": [],
                "declared_gaps": [],
                "bound_rotations": [],
                "non_evidentiary": [],
            }
        ),
        encoding="utf-8",
    )
    nonzero_inv = tmp_path / "inv-two.json"
    nonzero_inv.write_text(
        json.dumps({"pre_run_evidence_stream_object_count": 2}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                f"--report-file={gov_report}",
                f"--pre-run-inventory={nonzero_inv}",
                "--stream-key=cage:evidence:stream",
                "--if-exists",
                "--format=export",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert f"export TF_VAR_evidence_previous_chain_head_hash={HASH_A}" in out
    assert f"export TF_VAR_evidence_previous_batch_attestation_digest={ATTEST_A}" in out
