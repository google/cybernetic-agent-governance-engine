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

"""Extract the cryptographic WORM chain-tail anchor for bound genesis rotation (F-94, R-10).

Reads a ``CustodyVerificationReport`` from ``GET /v1/evidence/verify?require_citable=true``
(via HTTP URL, ``kubectl exec``, file path, or stdin), verifies that the archive is
``ok`` and ``citable`` with zero failures, zero declared gaps, and zero unsigned
batches, resolves the single active unreplaced chain head across any prior
``BOUND_CHAIN_ROTATION`` links, and emits the 64-hex ``last_record_hash`` and
``attestation_sha256`` required to bind a rebuilt cluster's genesis record.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_GOVERNANCE_STREAM_KEY = "cage:evidence:stream"


class WormAnchorError(ValueError):
    """Raised when a citable WORM chain-tail anchor cannot be extracted safely."""


@dataclass(frozen=True)
class WormChainAnchor:
    """Cryptographic anchor of the active tail batch in the WORM evidence archive."""

    chain_id: str
    first_sequence: int
    last_sequence: int
    last_record_hash: str
    attestation_sha256: str
    attestation_key: str
    data_key: str
    verified_batches: int
    bound_rotations: int
    declared_gaps: int
    stream_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_env_lines(self) -> str:
        return "\n".join(
            [
                f"EVIDENCE_PREVIOUS_CHAIN_HEAD_HASH={self.last_record_hash}",
                f"EVIDENCE_PREVIOUS_BATCH_ATTESTATION_DIGEST={self.attestation_sha256}",
                f"TF_VAR_evidence_previous_chain_head_hash={self.last_record_hash}",
                f"TF_VAR_evidence_previous_batch_attestation_digest={self.attestation_sha256}",
                f"WORM_ANCHOR_CHAIN_ID={self.chain_id}",
                f"WORM_ANCHOR_LAST_SEQUENCE={self.last_sequence}",
                f"WORM_ANCHOR_VERIFIED_BATCHES={self.verified_batches}",
                f"WORM_ANCHOR_BOUND_ROTATIONS={self.bound_rotations}",
            ]
        )

    def to_export_lines(self) -> str:
        if not _HEX64_RE.match(self.last_record_hash) or not _HEX64_RE.match(
            self.attestation_sha256
        ):
            raise WormAnchorError("Refusing shell export for non-hex64 anchor digest")
        return "\n".join(
            [
                f"export TF_VAR_evidence_previous_chain_head_hash={self.last_record_hash}",
                f"export TF_VAR_evidence_previous_batch_attestation_digest={self.attestation_sha256}",
            ]
        )


def _validate_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise WormAnchorError(
            f"Invalid compliance-bridge URL {url!r}: scheme must be http or https"
        )
    return url


def fetch_verify_report_http(
    bridge_url: str, *, timeout_s: int = DEFAULT_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """Fetch ``GET /v1/evidence/verify?require_citable=true`` over HTTP/HTTPS."""
    base = bridge_url.rstrip("/")
    url = _validate_http_url(f"{base}/v1/evidence/verify?require_citable=true")
    req = Request(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(req, timeout=timeout_s) as resp:  # nosec B310  # scheme validated to http/https above
        if resp.status != 200:
            raise WormAnchorError(f"HTTP {resp.status} from {url}")
        raw = resp.read().decode("utf-8")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WormAnchorError(f"Invalid JSON from {url}: {exc}") from exc
    if not isinstance(doc, dict):
        raise WormAnchorError(
            f"Expected JSON object from {url}, got {type(doc).__name__}"
        )
    return doc


def fetch_verify_report_gcs(
    gcs_bucket: str,
    *,
    gcs_project: str,
    kms_key: str,
    timeout_s: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Run ``src.compliance_bridge.evidence_verifier --json`` directly against GCS + Cloud KMS."""
    import os

    bucket = gcs_bucket.strip()
    project = gcs_project.strip()
    key = kms_key.strip()
    if not bucket or not project or not key:
        raise WormAnchorError(
            "--gcs-bucket requires non-empty --gcs-project and --kms-key"
        )
    repo_root = Path(__file__).resolve().parents[1]
    child_env = dict(os.environ)
    child_env.update(
        {
            "EVIDENCE_COLD_STORE": "gcs",
            "EVIDENCE_COLD_STORE_BUCKET": bucket,
            "GOOGLE_CLOUD_PROJECT": project,
            "CAGE_KMS_PROVIDER": "gcp",
            "EVIDENCE_KMS_KEY": key,
            "GOOGLE_API_USE_CLIENT_CERTIFICATE": "false",
        }
    )
    proc = subprocess.run(
        [sys.executable, "-m", "src.compliance_bridge.evidence_verifier", "--json"],
        cwd=str(repo_root),
        env=child_env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    raw = proc.stdout.strip()
    if not raw:
        detail = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise WormAnchorError(
            f"GCS CustodyVerifier returned empty stdout for gs://{bucket}: {detail}"
        )
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WormAnchorError(
            f"Invalid JSON from GCS CustodyVerifier for gs://{bucket}: {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise WormAnchorError(
            f"Expected JSON object from GCS CustodyVerifier, got {type(doc).__name__}"
        )
    return doc


def fetch_verify_report_kubectl(
    namespace: str = "governance-stack",
    *,
    timeout_s: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch ``GET /v1/evidence/verify?require_citable=true`` via in-cluster compliance-bridge pod."""
    inline_py = (
        "import sys, urllib.request; "
        f"resp = urllib.request.urlopen('http://127.0.0.1:3001/v1/evidence/verify?require_citable=true', timeout={int(timeout_s)}); "
        "sys.exit(1) if resp.status != 200 else sys.stdout.write(resp.read().decode('utf-8'))"
    )
    proc = subprocess.run(
        [
            "kubectl",
            "exec",
            "-n",
            namespace,
            "deploy/compliance-bridge",
            "--",
            "python3",
            "-c",
            inline_py,
        ],
        capture_output=True,
        text=True,
        timeout=timeout_s + 30,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = (proc.stderr or proc.stdout).strip()
        raise WormAnchorError(
            f"kubectl exec /v1/evidence/verify failed (rc={proc.returncode}): {detail}"
        )
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise WormAnchorError(
            f"Invalid JSON from kubectl exec /v1/evidence/verify: {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise WormAnchorError(
            f"Expected JSON object from kubectl exec, got {type(doc).__name__}"
        )
    return doc


def extract_chain_anchor(
    report: Mapping[str, Any],
    *,
    stream_key: str | None = DEFAULT_GOVERNANCE_STREAM_KEY,
) -> WormChainAnchor:
    """Resolve the active unreplaced chain tail batch from a citable verification report."""
    if report.get("ok") is not True or report.get("citable") is not True:
        raise WormAnchorError(
            f"WORM archive is not citable (ok={report.get('ok')!r}, citable={report.get('citable')!r})"
        )

    failures = report.get("failures", [])
    if not isinstance(failures, list) or len(failures) != 0:
        raise WormAnchorError(
            f"WORM archive has {len(failures) if isinstance(failures, list) else 'invalid'} failure(s)"
        )

    declared_gaps = report.get("declared_gaps", [])
    gaps_legacy = report.get("gaps", [])
    gap_count = max(
        len(declared_gaps)
        if isinstance(declared_gaps, list)
        else int(declared_gaps or 0),
        len(gaps_legacy) if isinstance(gaps_legacy, list) else int(gaps_legacy or 0),
    )
    if gap_count != 0:
        raise WormAnchorError(
            f"WORM archive has {gap_count} declared gap(s); refusing to anchor on a gapped chain"
        )

    non_evidentiary = report.get("non_evidentiary", [])
    unsigned_legacy = report.get("unsigned", [])
    unsigned_count = max(
        len(non_evidentiary)
        if isinstance(non_evidentiary, list)
        else int(non_evidentiary or 0),
        len(unsigned_legacy)
        if isinstance(unsigned_legacy, list)
        else int(unsigned_legacy or 0),
    )
    if unsigned_count != 0:
        raise WormAnchorError(
            f"WORM archive contains {unsigned_count} unsigned non-evidentiary batch(es)"
        )

    verified = report.get("verified")
    if not isinstance(verified, list) or len(verified) == 0:
        raise WormAnchorError("WORM archive contains 0 verified signed batches")

    for idx, item in enumerate(verified):
        if not isinstance(item, Mapping):
            raise WormAnchorError(f"verified[{idx}] is not an object")

    target_stream = (stream_key or "").strip()
    any_stream_key_present = any(
        bool(str(item.get("stream_key") or "").strip()) for item in verified
    )
    if target_stream and any_stream_key_present:
        candidate_batches = [
            item
            for item in verified
            if str(item.get("stream_key") or "").strip() == target_stream
        ]
        if not candidate_batches:
            raise WormAnchorError(
                f"WORM archive contains 0 verified signed batches for stream_key={target_stream!r}"
            )
    else:
        candidate_batches = list(verified)

    by_chain: dict[str, list[Mapping[str, Any]]] = {}
    superseded_chains: set[str] = set()

    for idx, item in enumerate(candidate_batches):
        cid = str(item.get("chain_id") or "").strip()
        if not cid:
            raise WormAnchorError(f"verified[{idx}] is missing non-empty chain_id")
        by_chain.setdefault(cid, []).append(item)
        rotated_from = str(item.get("rotated_from_chain_id") or "").strip()
        if rotated_from:
            superseded_chains.add(rotated_from)

    bound_rotations_raw = report.get("bound_rotations", [])
    if not isinstance(bound_rotations_raw, list):
        raise WormAnchorError("bound_rotations must be a list")
    for rot in bound_rotations_raw:
        if isinstance(rot, Mapping):
            prev_cid = str(rot.get("previous_chain_id") or "").strip()
            if prev_cid and prev_cid in by_chain:
                superseded_chains.add(prev_cid)

    active_chains = [cid for cid in by_chain if cid not in superseded_chains]
    if len(active_chains) == 0:
        raise WormAnchorError(
            "Cyclic or empty chain rotation graph: zero unreplaced active chains found"
        )
    if len(active_chains) > 1:
        raise WormAnchorError(
            f"Ambiguous multi-head WORM archive: {len(active_chains)} unreplaced chains ({sorted(active_chains)})"
        )

    active_cid = active_chains[0]
    chain_batches = sorted(
        by_chain[active_cid],
        key=lambda b: (
            int(b.get("first_sequence", -1)),
            int(b.get("last_sequence", -1)),
        ),
    )
    tail = chain_batches[-1]

    last_record_hash = str(tail.get("last_record_hash") or "").strip().lower()
    attestation_sha256 = str(tail.get("attestation_sha256") or "").strip().lower()
    if not _HEX64_RE.match(last_record_hash):
        raise WormAnchorError(
            f"Tail batch last_record_hash is missing or not a 64-hex SHA-256 digest: {last_record_hash!r}"
        )
    if not _HEX64_RE.match(attestation_sha256):
        raise WormAnchorError(
            f"Tail batch attestation_sha256 is missing or not a 64-hex SHA-256 digest: {attestation_sha256!r}"
        )

    first_seq = int(tail.get("first_sequence", -1))
    last_seq = int(tail.get("last_sequence", -1))
    if first_seq < 0 or last_seq < first_seq:
        raise WormAnchorError(
            f"Tail batch sequence range [{first_seq}, {last_seq}] is invalid"
        )

    resolved_stream_key = str(tail.get("stream_key") or target_stream).strip()

    return WormChainAnchor(
        chain_id=active_cid,
        first_sequence=first_seq,
        last_sequence=last_seq,
        last_record_hash=last_record_hash,
        attestation_sha256=attestation_sha256,
        attestation_key=str(tail.get("attestation_key") or ""),
        data_key=str(tail.get("data_key") or ""),
        verified_batches=len(verified),
        bound_rotations=len(bound_rotations_raw),
        declared_gaps=gap_count,
        stream_key=resolved_stream_key,
    )


def _has_no_stream_batches_yet(
    report: Mapping[str, Any], *, stream_key: str | None
) -> bool:
    """Return True only when the archive is healthy/empty for ``stream_key``."""
    if report.get("ok") is not True:
        return False
    if (
        report.get("failures")
        or report.get("declared_gaps")
        or report.get("non_evidentiary")
    ):
        return False
    verified = report.get("verified")
    if not isinstance(verified, list) or len(verified) == 0:
        return True
    target = (stream_key or "").strip()
    if not target:
        return False
    any_stream_key_present = any(
        isinstance(item, Mapping) and bool(str(item.get("stream_key") or "").strip())
        for item in verified
    )
    if not any_stream_key_present:
        return False
    return not any(
        isinstance(item, Mapping)
        and str(item.get("stream_key") or "").strip() == target
        for item in verified
    )


def main(argv: list[str] | None = None) -> int:
    import os

    parser = argparse.ArgumentParser(
        description="Extract the cryptographic WORM chain-tail anchor for bound genesis rotation."
    )
    src_group = parser.add_mutually_exclusive_group()
    src_group.add_argument(
        "--from-stdin",
        action="store_true",
        help="Read GET /v1/evidence/verify JSON payload from stdin",
    )
    src_group.add_argument(
        "--report-file",
        type=Path,
        help="Read GET /v1/evidence/verify JSON payload from a file",
    )
    src_group.add_argument(
        "--bridge-url",
        type=str,
        help="Compliance bridge base URL (e.g. http://localhost:3002)",
    )
    src_group.add_argument(
        "--kubectl",
        action="store_true",
        help="Query deploy/compliance-bridge in-cluster via kubectl exec",
    )
    src_group.add_argument(
        "--gcs-bucket",
        type=str,
        help="Verify a GCS WORM bucket directly via CustodyVerifier + Cloud KMS",
    )
    parser.add_argument(
        "--gcs-project",
        type=str,
        default="",
        help="GCP project ID when --gcs-bucket is used",
    )
    parser.add_argument(
        "--kms-key",
        type=str,
        default="",
        help="Cloud KMS CryptoKeyVersion resource name when --gcs-bucket is used",
    )
    parser.add_argument(
        "--pre-run-inventory",
        type=Path,
        default=None,
        help="Optional pre-run-project-inventory.json path; skips GCS query when pre_run_evidence_stream_object_count == 0",
    )
    parser.add_argument(
        "--if-exists",
        action="store_true",
        help="Exit 0 with empty stdout when the target stream has 0 custodied batches yet",
    )
    parser.add_argument(
        "--namespace",
        default="governance-stack",
        help="Kubernetes namespace when --kubectl is used (default: governance-stack)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Verification HTTP timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--format",
        choices=("json", "env", "export"),
        default="json",
        help="Stdout output format (default: json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write the JSON anchor artifact",
    )
    parser.add_argument(
        "--stream-key",
        type=str,
        default=os.environ.get("EVIDENCE_STREAM_KEY", DEFAULT_GOVERNANCE_STREAM_KEY),
        help=(
            "Target Redis Stream key when multiple custodied streams share one WORM prefix "
            f"(default: {DEFAULT_GOVERNANCE_STREAM_KEY})"
        ),
    )
    args = parser.parse_args(argv)

    try:
        if args.pre_run_inventory is not None:
            if not args.pre_run_inventory.is_file():
                if args.if_exists:
                    return 0
                raise WormAnchorError(
                    f"Pre-run inventory file not found: {args.pre_run_inventory}"
                )
            inv = json.loads(args.pre_run_inventory.read_text(encoding="utf-8"))
            if (
                isinstance(inv, Mapping)
                and int(inv.get("pre_run_evidence_stream_object_count", 0) or 0) == 0
                and args.if_exists
            ):
                return 0

        if args.from_stdin:
            report = json.loads(sys.stdin.read())
        elif args.report_file is not None:
            report = json.loads(args.report_file.read_text(encoding="utf-8"))
        elif args.bridge_url:
            report = fetch_verify_report_http(args.bridge_url, timeout_s=args.timeout)
        elif args.kubectl:
            report = fetch_verify_report_kubectl(args.namespace, timeout_s=args.timeout)
        elif args.gcs_bucket:
            report = fetch_verify_report_gcs(
                args.gcs_bucket,
                gcs_project=args.gcs_project,
                kms_key=args.kms_key,
                timeout_s=args.timeout,
            )
        else:
            env_url = os.environ.get("COMPLIANCE_BRIDGE_URL", "").strip()
            if env_url:
                report = fetch_verify_report_http(env_url, timeout_s=args.timeout)
            else:
                report = fetch_verify_report_kubectl(
                    args.namespace, timeout_s=args.timeout
                )

        if not isinstance(report, Mapping):
            raise WormAnchorError("Verification report must be a JSON object")

        if args.if_exists and _has_no_stream_batches_yet(
            report, stream_key=args.stream_key
        ):
            return 0

        anchor = extract_chain_anchor(report, stream_key=args.stream_key)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(anchor.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if args.format == "env":
            print(anchor.to_env_lines())
        elif args.format == "export":
            print(
                f"[INFO] Pre-existing WORM chain anchor resolved for {anchor.stream_key or args.stream_key}: "
                f"chain={anchor.chain_id}, batches={anchor.verified_batches}, head={anchor.last_record_hash[:12]}...",
                file=sys.stderr,
            )
            print(anchor.to_export_lines())
        else:
            print(json.dumps(anchor.to_dict(), indent=2, sort_keys=True))
        return 0
    except (
        WormAnchorError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
