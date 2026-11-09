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

"""Gate W Phase 5 live Cloud Audit Log corroboration (``AS-6``).

Fetches Cloud KMS ``AsymmetricSign`` Data Access records and Admin Activity
records for the workload project from the Cloud Logging API, and the signed
``cage-evidence-batch/1`` attestations in the WORM evidence bucket, then runs
``cage_conformance.audit_corroboration.verify_audit_corroboration`` over a
settled verification window::

    window = [--since, now - --settle-seconds]

Records are fetched from ``--since`` minus ``--max-skew-seconds``, so
attestations and ``AsymmetricSign`` records near the window start still find
their counterparts. The ``compliance-evidence`` key family is corroborated in
both directions; ``gateway-seal`` and ``reconciler-snapshot`` calls are checked
for caller isolation. Offline exports are verified with
``cage-conformance verify-audit-corroboration`` instead.

The caller needs ``roles/logging.privateLogViewer`` on the workload project
(Data Access logs) and ``roles/storage.objectViewer`` on the evidence bucket.

Exit codes:
    0  corroborated, with at least one attestation in the window
    1  corroboration findings, or no attestation in the window
    2  configuration, credential, or API error
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404  # invokes resolved gcloud CLI binary without shell
import sys
import urllib.parse
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFORMANCE_SRC = REPO_ROOT / "packages" / "cage-conformance" / "src"
if str(CONFORMANCE_SRC) not in sys.path:
    sys.path.insert(0, str(CONFORMANCE_SRC))

from cage_conformance.audit_corroboration import (  # noqa: E402
    COMPLIANCE_EVIDENCE_KEY,
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    expected_key_callers_for_project,
    extract_signed_artifacts,
    verify_audit_corroboration,
)

LOGGING_ENTRIES_URL = "https://logging.googleapis.com/v2/entries:list"
STORAGE_API_BASE = "https://storage.googleapis.com/storage/v1/b"
EVIDENCE_PREFIX = "evidence-stream/"
SIGNED_ATTESTATION_SUFFIX = ".attestation.json"
DEFAULT_SETTLE_SECONDS = 60.0
DEFAULT_LOOKBACK_MINUTES = 120
READ_ONLY_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"


def _parse_rfc3339(text: str) -> datetime | None:
    candidate = text.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _format_rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _https_json(
    method: str,
    url: str,
    token: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing non-https URL {url!r}")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout_s) as response:  # nosec B310  # https scheme verified above
        body = json.loads(response.read().decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError(f"expected a JSON object from {parsed.netloc}{parsed.path}")
    return body


def _gcloud(*args: str) -> str:
    gcloud = shutil.which("gcloud")
    if gcloud is None:
        return ""
    completed = subprocess.run(  # nosec B603  # fixed gcloud argv resolved via shutil.which without shell
        [gcloud, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or value == "(unset)":
        return ""
    return value


def resolve_access_token() -> str:
    """Bearer token from ``$CAGE_GCP_ACCESS_TOKEN``, ADC, or ``gcloud``."""
    token = os.environ.get("CAGE_GCP_ACCESS_TOKEN", "").strip()
    if token:
        return token
    adc_error: Exception | None = None
    try:
        import google.auth
        import google.auth.transport.requests

        credentials, _ = google.auth.default(scopes=[READ_ONLY_SCOPE])
        credentials.refresh(google.auth.transport.requests.Request())
        if credentials.token:
            return str(credentials.token)
    except Exception as exc:  # ADC is optional; gcloud is the fallback.
        adc_error = exc
    token = _gcloud("auth", "print-access-token")
    if token:
        return token
    raise RuntimeError(
        "no GCP access token: set CAGE_GCP_ACCESS_TOKEN, configure Application "
        "Default Credentials, or log in with gcloud"
    ) from adc_error


def trusted_deployers(
    project_id: str, environment: str, extra: Iterable[str]
) -> list[str]:
    """Principals allowed to mutate the control plane during the run.

    The Terraform deployer and Cloud Build service accounts, the operator
    running the gate (``$CAGE_CALLER_PRINCIPAL`` or the active ``gcloud``
    account, which applied the stack), ``--trusted-deployer`` values, and
    ``$CAGE_TRUSTED_DEPLOYER_PRINCIPALS``.
    """
    principals = {
        f"sa-cage-deployer@{project_id}.iam.gserviceaccount.com",
        f"cage-cloudbuild-{environment}@{project_id}.iam.gserviceaccount.com",
    }
    env_extra = os.environ.get("CAGE_TRUSTED_DEPLOYER_PRINCIPALS", "").split(",")
    principals.update(p.strip() for p in [*extra, *env_extra] if p.strip())
    operator = os.environ.get("CAGE_CALLER_PRINCIPAL", "").strip() or _gcloud(
        "config", "get-value", "account"
    )
    if operator:
        principals.add(operator)
    return sorted(principals)


def fetch_audit_log_entries(
    project_id: str,
    environment: str,
    token: str,
    since: datetime,
) -> list[dict[str, Any]]:
    """KMS ``AsymmetricSign`` and Admin Activity entries logged since ``since``."""
    keyring = f"/keyRings/cage-signing-{environment}/cryptoKeys/"
    log_filter = (
        f'timestamp >= "{_format_rfc3339(since)}" AND ('
        f'(logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Fdata_access"'
        ' AND protoPayload.serviceName="cloudkms.googleapis.com"'
        ' AND protoPayload.methodName="AsymmetricSign"'
        f' AND protoPayload.resourceName:"{keyring}")'
        f' OR logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity"'
        ")"
    )
    entries: list[dict[str, Any]] = []
    page_token = ""
    while True:
        body: dict[str, Any] = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": log_filter,
            "orderBy": "timestamp asc",
            "pageSize": 1000,
        }
        if page_token:
            body["pageToken"] = page_token
        page = _https_json("POST", LOGGING_ENTRIES_URL, token, payload=body)
        entries.extend(
            entry for entry in page.get("entries") or () if isinstance(entry, dict)
        )
        page_token = str(page.get("nextPageToken") or "")
        if not page_token:
            return entries


def fetch_signed_attestations(
    bucket: str,
    token: str,
    created_since: datetime,
) -> list[dict[str, Any]]:
    """Signed evidence attestations written to ``bucket`` since ``created_since``."""
    bucket_path = f"{STORAGE_API_BASE}/{urllib.parse.quote(bucket, safe='')}/o"
    attestations: list[dict[str, Any]] = []
    page_token = ""
    while True:
        params = {
            "prefix": EVIDENCE_PREFIX,
            "fields": "items(name,timeCreated),nextPageToken",
        }
        if page_token:
            params["pageToken"] = page_token
        listing = _https_json(
            "GET", f"{bucket_path}?{urllib.parse.urlencode(params)}", token
        )
        for item in listing.get("items") or ():
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            if not name.endswith(SIGNED_ATTESTATION_SUFFIX):
                continue
            created = _parse_rfc3339(str(item.get("timeCreated", "")))
            if created is not None and created < created_since:
                continue
            object_url = f"{bucket_path}/{urllib.parse.quote(name, safe='')}?alt=media"
            attestations.append(_https_json("GET", object_url, token))
        page_token = str(listing.get("nextPageToken") or "")
        if not page_token:
            return attestations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Corroborate live Cloud KMS AsymmetricSign and Admin Activity audit "
            "logs against the WORM evidence archive (AS-6)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--project",
        default=os.environ.get("GOOGLE_CLOUD_PROJECT", ""),
        help="Workload GCP project ID (default: $GOOGLE_CLOUD_PROJECT)",
    )
    parser.add_argument(
        "--environment",
        default="staging",
        help="Deployment environment, selecting the cage-signing-<env> keyring",
    )
    parser.add_argument(
        "--evidence-project",
        default="",
        help="Persistent evidence domain project ID (default: --project)",
    )
    parser.add_argument(
        "--evidence-bucket",
        default="",
        help="WORM evidence bucket (default: <evidence-project>-evidence-worm-<env>)",
    )
    start = parser.add_mutually_exclusive_group()
    start.add_argument(
        "--since",
        default="",
        help="Verification window start as RFC 3339 UTC, e.g. 2026-11-08T17:00:00Z",
    )
    start.add_argument(
        "--lookback-minutes",
        type=int,
        default=DEFAULT_LOOKBACK_MINUTES,
        help=f"Window start before now when --since is omitted (default: {DEFAULT_LOOKBACK_MINUTES})",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=DEFAULT_SETTLE_SECONDS,
        help=(
            "End the window this long before now so in-flight writes and log "
            f"ingestion land (default: {DEFAULT_SETTLE_SECONDS:g})"
        ),
    )
    parser.add_argument(
        "--max-skew-seconds",
        type=float,
        default=DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        help=(
            "Maximum attestation-to-AsymmetricSign timestamp skew "
            f"(default: {DEFAULT_MAX_CLOCK_SKEW_SECONDS:g})"
        ),
    )
    parser.add_argument(
        "--trusted-deployer",
        action="append",
        default=[],
        metavar="PRINCIPAL",
        help="Additional principal allowed to mutate the control plane (repeatable)",
    )
    parser.add_argument(
        "--allow-empty-evidence",
        action="store_true",
        help="Pass with no attestation in the window (idle clusters only)",
    )
    parser.add_argument(
        "--output", type=Path, default=None, help="Write the JSON report here"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        project_id = args.project.strip()
        environment = args.environment.strip()
        if not project_id:
            raise ValueError("--project (or $GOOGLE_CLOUD_PROJECT) is required")
        if not environment:
            raise ValueError("--environment must be non-empty")
        if args.settle_seconds < 0 or args.max_skew_seconds < 0:
            raise ValueError("--settle-seconds and --max-skew-seconds must be >= 0")

        now = datetime.now(timezone.utc)
        if args.since:
            window_start = _parse_rfc3339(args.since)
            if window_start is None:
                raise ValueError(
                    f"--since must be an RFC 3339 timestamp with a zone, got {args.since!r}"
                )
        elif args.lookback_minutes > 0:
            window_start = now - timedelta(minutes=args.lookback_minutes)
        else:
            raise ValueError("--lookback-minutes must be positive")
        window_end = now - timedelta(seconds=args.settle_seconds)
        if window_end <= window_start:
            raise ValueError(
                f"verification window {_format_rfc3339(window_start)} .. "
                f"{_format_rfc3339(window_end)} is empty; run at least "
                f"{args.settle_seconds:g}s after --since"
            )
        fetch_from = window_start - timedelta(seconds=args.max_skew_seconds)
        evidence_project = args.evidence_project.strip() or project_id
        bucket = (
            args.evidence_bucket.strip()
            or f"{evidence_project}-evidence-worm-{environment}"
        )

        token = resolve_access_token()
        entries = fetch_audit_log_entries(project_id, environment, token, fetch_from)
        attestations = fetch_signed_attestations(bucket, token, fetch_from)
        report = verify_audit_corroboration(
            entries,
            signed_artifacts=extract_signed_artifacts(
                attestations, COMPLIANCE_EVIDENCE_KEY
            ),
            expected_key_callers=expected_key_callers_for_project(project_id),
            trusted_deployer_principals=trusted_deployers(
                project_id, environment, args.trusted_deployer
            ),
            corroborated_key_families={COMPLIANCE_EVIDENCE_KEY},
            max_skew_seconds=args.max_skew_seconds,
            verification_window=(window_start.timestamp(), window_end.timestamp()),
        )
        if args.output is not None:
            args.output.write_text(
                json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8"
            )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("\n".join(report.summary_lines("verify-audit-corroboration")))
    if report.checked_artifacts == 0 and not args.allow_empty_evidence:
        print(
            "error: no signed evidence attestation in the verification window "
            f"(bucket {bucket}); pass --allow-empty-evidence only for an idle cluster",
            file=sys.stderr,
        )
        return 1
    return 0 if report.corroborated else 1


if __name__ == "__main__":
    sys.exit(main())
