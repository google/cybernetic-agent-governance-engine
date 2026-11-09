#!/usr/bin/env python3
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

"""Enforce quarterly (90-day) Gate W certification freshness and ownership.

Verifies ``compliance/gate_w_certification.json`` against:
1. Schema integrity, ``cadence_days`` in ``1..90``, and valid ``@owner`` handle.
2. Explicit ``/compliance/gate_w_certification.json`` rule in ``.github/CODEOWNERS``
   matching the declared ``owner``.
3. Anti-regression / POA&M coupling: once any ``docs/POAM.md`` row is closed
   citing ``gate_w_certification.json`` (or ``--require-certified`` is passed),
   ``PENDING_INITIAL_CERTIFICATION`` is refused fail-closed.
4. Active certification freshness when ``status == "CERTIFIED"``:
   - ``deployment_target_mode`` in ``{"fresh_project_clean_room", "existing_operated_project"}``
   - ``certified_git_sha`` is 40-hex, ``archive_manifest_sha256`` is 64-hex,
     and ``archive_worm_uri`` starts with ``gs://``
   - ``partner_conformance_status`` in ``{"passed", "unreachable_waived"}``
   - ``expires_at_utc <= last_verified_utc + timedelta(days=cadence_days)``
   - ``now_utc < expires_at_utc`` (fails closed on expiry).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CERT_FILE = REPO_ROOT / "compliance" / "gate_w_certification.json"
DEFAULT_CODEOWNERS_FILE = REPO_ROOT / ".github" / "CODEOWNERS"
DEFAULT_POAM_FILE = REPO_ROOT / "docs" / "POAM.md"

MAX_CADENCE_DAYS = 90
VALID_STATUSES = frozenset({"PENDING_INITIAL_CERTIFICATION", "CERTIFIED"})
VALID_TARGET_MODES = frozenset(
    {
        "fresh_project_clean_room",
        "fresh_project_with_phase0_kms_residue",
        "existing_operated_project",
    }
)
VALID_PARTNER_STATUSES = frozenset({"passed", "unreachable_waived"})

_OWNER_RE = re.compile(r"^@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA64_RE = re.compile(r"^[0-9a-f]{64}$")


def _parse_utc(raw: object, field: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{field} must be a non-empty ISO-8601 UTC string")
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include an explicit UTC timezone offset")
    return parsed.astimezone(timezone.utc)


def _check_codeowners(codeowners_path: Path, expected_owner: str) -> list[str]:
    if not codeowners_path.is_file():
        return [f"CODEOWNERS file not found: {codeowners_path}"]
    for raw_line in codeowners_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "/compliance/gate_w_certification.json":
            owners = set(parts[1:])
            if expected_owner not in owners:
                return [
                    "/compliance/gate_w_certification.json in CODEOWNERS lists "
                    f"{sorted(owners)}, missing declared owner {expected_owner!r}"
                ]
            return []
    return [
        ".github/CODEOWNERS must include an explicit '/compliance/gate_w_certification.json' entry"
    ]


def _poam_has_closed_gate_w_citation(poam_path: Path) -> bool:
    if not poam_path.is_file():
        return False
    for line in poam_path.read_text(encoding="utf-8").splitlines():
        if "✅ **CLOSED" in line and "gate_w_certification.json" in line:
            return True
    return False


def validate_certification(
    *,
    cert_path: Path,
    codeowners_path: Path,
    poam_path: Path,
    now_utc: datetime,
    require_certified: bool = False,
) -> list[str]:
    errors: list[str] = []
    if not cert_path.is_file():
        return [f"Gate W certification file missing: {cert_path}"]

    try:
        payload = json.loads(cert_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"Invalid JSON in {cert_path}: {exc}"]

    if not isinstance(payload, dict):
        return [f"{cert_path} root must be a JSON object"]

    if payload.get("schema_version") != "1.0":
        errors.append(
            f"schema_version must be '1.0', got {payload.get('schema_version')!r}"
        )

    owner = payload.get("owner")
    if not isinstance(owner, str) or not _OWNER_RE.match(owner):
        errors.append(f"owner must be a valid GitHub @handle, got {owner!r}")
    else:
        errors.extend(_check_codeowners(codeowners_path, owner))

    cadence_days = payload.get("cadence_days")
    if (
        isinstance(cadence_days, bool)
        or not isinstance(cadence_days, int)
        or cadence_days < 1
        or cadence_days > MAX_CADENCE_DAYS
    ):
        errors.append(
            f"cadence_days must be an integer between 1 and {MAX_CADENCE_DAYS}, got {cadence_days!r}"
        )

    status = payload.get("status")
    if status not in VALID_STATUSES:
        errors.append(f"status must be one of {sorted(VALID_STATUSES)}, got {status!r}")
        return errors

    poam_requires_cert = _poam_has_closed_gate_w_citation(poam_path)
    if status == "PENDING_INITIAL_CERTIFICATION":
        if require_certified:
            errors.append(
                "status is PENDING_INITIAL_CERTIFICATION, but --require-certified was specified"
            )
        if poam_requires_cert:
            errors.append(
                "docs/POAM.md contains a CLOSED item citing gate_w_certification.json, "
                "so status cannot remain PENDING_INITIAL_CERTIFICATION"
            )
        return errors

    # status == "CERTIFIED"
    target_mode = payload.get("deployment_target_mode")
    if target_mode not in VALID_TARGET_MODES:
        errors.append(
            f"CERTIFIED record requires deployment_target_mode in {sorted(VALID_TARGET_MODES)}, "
            f"got {target_mode!r}"
        )

    git_sha = payload.get("certified_git_sha")
    if not isinstance(git_sha, str) or not _SHA40_RE.match(git_sha):
        errors.append(
            f"CERTIFIED record requires 40-char hex certified_git_sha, got {git_sha!r}"
        )

    worm_uri = payload.get("archive_worm_uri")
    if (
        not isinstance(worm_uri, str)
        or not worm_uri.startswith("gs://")
        or len(worm_uri) <= 6
    ):
        errors.append(
            f"CERTIFIED record requires gs:// archive_worm_uri, got {worm_uri!r}"
        )

    manifest_sha = payload.get("archive_manifest_sha256")
    if not isinstance(manifest_sha, str) or not _SHA64_RE.match(manifest_sha):
        errors.append(
            "CERTIFIED record requires 64-char hex archive_manifest_sha256, "
            f"got {manifest_sha!r}"
        )

    partner_status = payload.get("partner_conformance_status")
    if partner_status not in VALID_PARTNER_STATUSES:
        errors.append(
            f"CERTIFIED record requires partner_conformance_status in {sorted(VALID_PARTNER_STATUSES)}, "
            f"got {partner_status!r}"
        )

    try:
        verified_dt = _parse_utc(payload.get("last_verified_utc"), "last_verified_utc")
        expires_dt = _parse_utc(payload.get("expires_at_utc"), "expires_at_utc")
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    if verified_dt > now_utc + timedelta(minutes=5):
        errors.append(
            f"last_verified_utc ({verified_dt.isoformat()}) is in the future relative to now ({now_utc.isoformat()})"
        )
    if expires_dt <= verified_dt:
        errors.append(
            f"expires_at_utc ({expires_dt.isoformat()}) must be strictly after last_verified_utc ({verified_dt.isoformat()})"
        )
    if isinstance(cadence_days, int) and not isinstance(cadence_days, bool):
        max_expiry = verified_dt + timedelta(days=cadence_days)
        if expires_dt > max_expiry:
            errors.append(
                f"expires_at_utc ({expires_dt.isoformat()}) exceeds cadence_days={cadence_days} "
                f"window from last_verified_utc (max {max_expiry.isoformat()})"
            )
    if now_utc >= expires_dt:
        errors.append(
            f"Gate W certification EXPIRED at {expires_dt.isoformat()} (now={now_utc.isoformat()}); "
            "re-run scripts/staging_lifecycle.sh and refresh compliance/gate_w_certification.json"
        )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Gate W quarterly (90-day) certification freshness and CODEOWNERS custody."
    )
    parser.add_argument("--cert-file", type=Path, default=DEFAULT_CERT_FILE)
    parser.add_argument("--codeowners-file", type=Path, default=DEFAULT_CODEOWNERS_FILE)
    parser.add_argument("--poam-file", type=Path, default=DEFAULT_POAM_FILE)
    parser.add_argument(
        "--now-utc",
        type=str,
        default="",
        help="Optional ISO-8601 UTC timestamp override for deterministic verification.",
    )
    parser.add_argument(
        "--require-certified",
        action="store_true",
        default=False,
        help="Fail closed unless status is CERTIFIED.",
    )
    args = parser.parse_args(argv)

    try:
        now_utc = (
            _parse_utc(args.now_utc, "--now-utc")
            if args.now_utc
            else datetime.now(tz=timezone.utc)
        )
    except ValueError as exc:
        print(f"[gate-w-freshness] ERROR: {exc}", file=sys.stderr)
        return 1

    errors = validate_certification(
        cert_path=args.cert_file,
        codeowners_path=args.codeowners_file,
        poam_path=args.poam_file,
        now_utc=now_utc,
        require_certified=args.require_certified,
    )
    if errors:
        for err in errors:
            print(f"[gate-w-freshness] FAIL: {err}", file=sys.stderr)
        return 1

    payload = json.loads(args.cert_file.read_text(encoding="utf-8"))
    print(
        f"[gate-w-freshness] OK: status={payload.get('status')} "
        f"owner={payload.get('owner')} cadence_days={payload.get('cadence_days')} "
        f"target_mode={payload.get('deployment_target_mode')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
