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

"""Unit tests for scripts/check_gate_w_freshness.py (Gate W 90-day cadence gate)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.check_gate_w_freshness import main  # noqa: E402


def _write_fixture(
    tmp_path: Path,
    cert: dict[str, object],
    *,
    codeowners: str = "/compliance/gate_w_certification.json @lahlfors\n",
    poam: str = "| POAM-024 | CA-2 | Open | High | 2026-11-30 |\n",
) -> tuple[Path, Path, Path]:
    cert_file = tmp_path / "gate_w_certification.json"
    codeowners_file = tmp_path / "CODEOWNERS"
    poam_file = tmp_path / "POAM.md"
    cert_file.write_text(json.dumps(cert), encoding="utf-8")
    codeowners_file.write_text(codeowners, encoding="utf-8")
    poam_file.write_text(poam, encoding="utf-8")
    return cert_file, codeowners_file, poam_file


def _valid_certified() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "status": "CERTIFIED",
        "owner": "@lahlfors",
        "cadence_days": 90,
        "last_verified_utc": "2026-11-10T12:00:00Z",
        "expires_at_utc": "2027-02-08T12:00:00Z",
        "certified_git_sha": "a" * 40,
        "deployment_target_mode": "fresh_project_clean_room",
        "archive_worm_uri": "gs://demo-worm-bucket/gate-w/2026-11-10/manifest.json",
        "archive_manifest_sha256": "b" * 64,
        "partner_conformance_status": "passed",
    }


def test_repo_committed_gate_w_certification_passes() -> None:
    rc = main([])
    assert rc == 0


def test_certified_record_passes_within_90_day_window(tmp_path: Path) -> None:
    cert_file, codeowners_file, poam_file = _write_fixture(tmp_path, _valid_certified())
    rc = main(
        [
            "--cert-file",
            str(cert_file),
            "--codeowners-file",
            str(codeowners_file),
            "--poam-file",
            str(poam_file),
            "--now-utc",
            "2026-12-15T00:00:00Z",
            "--require-certified",
        ]
    )
    assert rc == 0


def test_certified_record_fails_closed_after_expiry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_file, codeowners_file, poam_file = _write_fixture(tmp_path, _valid_certified())
    rc = main(
        [
            "--cert-file",
            str(cert_file),
            "--codeowners-file",
            str(codeowners_file),
            "--poam-file",
            str(poam_file),
            "--now-utc",
            "2027-02-09T00:00:00Z",
        ]
    )
    assert rc == 1
    assert "EXPIRED" in capsys.readouterr().err


def test_certified_record_rejects_cadence_over_90_days_or_missing_target_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = _valid_certified()
    bad["cadence_days"] = 180
    bad["deployment_target_mode"] = None
    cert_file, codeowners_file, poam_file = _write_fixture(tmp_path, bad)
    rc = main(
        [
            "--cert-file",
            str(cert_file),
            "--codeowners-file",
            str(codeowners_file),
            "--poam-file",
            str(poam_file),
            "--now-utc",
            "2026-11-11T00:00:00Z",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "cadence_days" in err
    assert "deployment_target_mode" in err


def test_pending_status_fails_when_poam_closes_citing_gate_w_or_codeowners_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pending = {
        "schema_version": "1.0",
        "status": "PENDING_INITIAL_CERTIFICATION",
        "owner": "@lahlfors",
        "cadence_days": 90,
    }
    cert_file, codeowners_file, poam_file = _write_fixture(
        tmp_path,
        pending,
        codeowners="* @someoneelse\n",
        poam="| POAM-024 | CA-2 | ✅ **CLOSED — verified via compliance/gate_w_certification.json** | 2026-11-10 |\n",
    )
    rc = main(
        [
            "--cert-file",
            str(cert_file),
            "--codeowners-file",
            str(codeowners_file),
            "--poam-file",
            str(poam_file),
            "--now-utc",
            "2026-11-11T00:00:00Z",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "CODEOWNERS" in err
    assert "cannot remain PENDING_INITIAL_CERTIFICATION" in err
