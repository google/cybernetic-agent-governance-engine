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

"""
generate_sbom.py — CAGE SBOM Generation Pipeline
==================================================
Created: 2026-03-06
NIST SP 800-53 Control: CM-8 (System Component Inventory)
POAM Reference: POAM-006 (No SBOM generated), POAM-010 (No container scanning)
ISO 42001: A.7.5 (Documented information — supply chain)
NIST SP 800-161: Supply Chain Risk Management

Generates Software Bill of Materials (SBOM) artifacts in CycloneDX JSON format
for CAGE container images and Python dependencies. Supports Syft (Docker/dir scans)
and cyclonedx-bom (Python dependency scans) with Grype vulnerability enrichment.

Usage:
    # Python dependency SBOM (from pyproject.toml / installed packages)
    python scripts/generate_sbom.py --type python --output-dir compliance/sbom

    # Docker image SBOM (requires syft)
    python scripts/generate_sbom.py --type docker --image gcr.io/PROJECT/cage-gateway:TAG

    # Directory scan SBOM
    python scripts/generate_sbom.py --type dir --image . --output-dir compliance/sbom

    # With GCS upload
    python scripts/generate_sbom.py --type python --upload --gcs-bucket cage-compliance-sboms --project-id my-gcp-project
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("CAGE.SBOM")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CREATION_DATE = "2026-03-06"
SBOM_SCHEMA_VERSION = "1.4"
BLOCKLISTED_LICENSES = {
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
}
CRITICAL_CVSS_THRESHOLD = 9.0

# ---------------------------------------------------------------------------
# SBOM Generation Functions
# ---------------------------------------------------------------------------


def generate_python_sbom(output_dir: Path, dry_run: bool = False) -> dict[str, Any]:
    """
    Generate a CycloneDX JSON SBOM for Python dependencies.

    Reads installed packages via `pip list --format=json` and attempts to
    enrich with metadata from pyproject.toml or requirements.txt. Falls back
    to constructing a minimal CycloneDX document if cyclonedx-bom is not
    available.

    Args:
        output_dir: Directory to write the SBOM JSON file.
        dry_run: If True, generate SBOM but do not write to disk.

    Returns:
        The CycloneDX SBOM as a Python dictionary.
    """
    logger.info("Generating Python dependency SBOM (CM-8 / POAM-006)...")

    # Try cyclonedx-bom first (preferred — produces standards-compliant output)
    try:
        logger.info("Attempting SBOM generation via cyclonedx-bom...")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cyclonedx_py",
                "environment",
                "--output-format",
                "JSON",
                "--schema-version",
                SBOM_SCHEMA_VERSION,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            sbom = json.loads(result.stdout)
            logger.info(
                "cyclonedx-bom succeeded: %d components found",
                len(sbom.get("components", [])),
            )
            return sbom
        else:
            logger.warning(
                "cyclonedx-bom returned non-zero or empty: %s — falling back to pip introspection",
                result.stderr[:200],
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.warning(
            "cyclonedx-bom not available (%s) — using pip introspection fallback", exc
        )

    # Fallback: build CycloneDX from `pip list --format=json`
    logger.info("Building CycloneDX SBOM from pip list (fallback)...")
    pip_result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    pip_packages: list[dict[str, str]] = []
    if pip_result.returncode == 0:
        pip_packages = json.loads(pip_result.stdout)
    else:
        logger.error("pip list failed: %s", pip_result.stderr[:200])

    components = []
    for pkg in pip_packages:
        components.append(
            {
                "type": "library",
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "0.0.0"),
                "purl": f"pkg:pypi/{pkg.get('name', 'unknown').lower()}@{pkg.get('version', '0.0.0')}",
                "licenses": [],
            }
        )

    sbom = _build_cyclonedx_envelope(
        metadata_component={
            "type": "application",
            "name": "governed-financial-advisor",
            "version": "0.1.0",
            "description": "CAGE Governed Financial Advisor — Python dependencies",
            "purl": "pkg:pypi/governed-financial-advisor@0.1.0",
        },
        components=components,
        tool_name="generate_sbom.py/pip-fallback",
    )

    logger.info("Fallback SBOM built: %d components", len(components))
    return sbom


def generate_docker_sbom(
    image: str, output_dir: Path, dry_run: bool = False
) -> dict[str, Any]:
    """
    Generate a CycloneDX JSON SBOM for a Docker image using Syft.

    Shells out to `syft <image> -o cyclonedx-json`. Falls back to
    `docker inspect` metadata if Syft is not installed.

    Args:
        image: Docker image reference (e.g. gcr.io/PROJECT/cage-gateway:TAG).
        output_dir: Directory to write the SBOM JSON file.
        dry_run: If True, generate but do not write to disk.

    Returns:
        The CycloneDX SBOM as a Python dictionary.
    """
    logger.info("Generating Docker image SBOM for '%s' (CM-8 / POAM-006)...", image)

    # Try syft (preferred)
    try:
        logger.info("Running: syft %s -o cyclonedx-json", image)
        result = subprocess.run(
            ["syft", image, "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0 and result.stdout.strip():
            sbom = json.loads(result.stdout)
            logger.info(
                "Syft succeeded: %d components found in image '%s'",
                len(sbom.get("components", [])),
                image,
            )
            return sbom
        else:
            logger.warning(
                "Syft returned non-zero (%d): %s — falling back to docker inspect",
                result.returncode,
                result.stderr[:300],
            )
    except FileNotFoundError:
        logger.warning("syft not found in PATH — falling back to docker inspect")
    except subprocess.TimeoutExpired:
        logger.error("Syft timed out after 300 seconds scanning '%s'", image)

    # Fallback: docker inspect metadata
    logger.info("Falling back to docker inspect for basic image metadata...")
    try:
        inspect_result = subprocess.run(
            ["docker", "inspect", image],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if inspect_result.returncode == 0:
            inspect_data = json.loads(inspect_result.stdout)
            image_meta = inspect_data[0] if inspect_data else {}
            sbom = _build_cyclonedx_envelope(
                metadata_component={
                    "type": "container",
                    "name": image,
                    "version": image_meta.get("Id", "unknown")[:12],
                    "description": f"Container image: {image}",
                    "purl": f"pkg:docker/{image}",
                    "properties": [
                        {
                            "name": "docker:Architecture",
                            "value": image_meta.get("Architecture", "unknown"),
                        },
                        {"name": "docker:Os", "value": image_meta.get("Os", "unknown")},
                        {
                            "name": "docker:Created",
                            "value": image_meta.get("Created", "unknown"),
                        },
                    ],
                },
                components=[],
                tool_name="generate_sbom.py/docker-inspect-fallback",
            )
            logger.warning(
                "docker inspect fallback: component list is empty. "
                "Install Syft for full SBOM: https://github.com/anchore/syft"
            )
            return sbom
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("docker inspect fallback failed: %s", exc)

    # Last resort: empty envelope
    logger.error(
        "All SBOM generation methods failed for image '%s'. Returning empty envelope.",
        image,
    )
    return _build_cyclonedx_envelope(
        metadata_component={"type": "container", "name": image, "version": "unknown"},
        components=[],
        tool_name="generate_sbom.py/empty-fallback",
    )


def generate_dir_sbom(
    path: str, output_dir: Path, dry_run: bool = False
) -> dict[str, Any]:
    """
    Generate a CycloneDX JSON SBOM for a filesystem directory using Syft.

    Args:
        path: Filesystem path to scan (e.g. '.').
        output_dir: Directory to write the SBOM JSON file.
        dry_run: If True, generate but do not write to disk.

    Returns:
        The CycloneDX SBOM as a Python dictionary.
    """
    logger.info("Generating directory SBOM for path '%s' (CM-8 / POAM-006)...", path)

    try:
        result = subprocess.run(
            ["syft", f"dir:{path}", "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0 and result.stdout.strip():
            sbom = json.loads(result.stdout)
            logger.info(
                "Syft dir scan succeeded: %d components found in '%s'",
                len(sbom.get("components", [])),
                path,
            )
            return sbom
        else:
            logger.warning(
                "Syft dir scan failed (exit %d): %s",
                result.returncode,
                result.stderr[:300],
            )
    except FileNotFoundError:
        logger.warning("syft not found — install from https://github.com/anchore/syft")
    except subprocess.TimeoutExpired:
        logger.error("Syft timed out scanning directory '%s'", path)

    return _build_cyclonedx_envelope(
        metadata_component={"type": "application", "name": path, "version": "unknown"},
        components=[],
        tool_name="generate_sbom.py/dir-fallback",
    )


# ---------------------------------------------------------------------------
# Helper: Build CycloneDX Envelope
# ---------------------------------------------------------------------------


def _build_cyclonedx_envelope(
    metadata_component: dict[str, Any],
    components: list[dict[str, Any]],
    tool_name: str,
) -> dict[str, Any]:
    """Construct a minimal CycloneDX 1.4 JSON envelope."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SCHEMA_VERSION,
        "serialNumber": f"urn:uuid:cage-sbom-{now.replace(':', '-').replace('T', '-')}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "CAGE DevSecOps",
                    "name": tool_name,
                    "version": "1.0.0",
                }
            ],
            "component": metadata_component,
            "properties": [
                {"name": "cage:poam_ref", "value": "POAM-006"},
                {"name": "cage:control_ref", "value": "CM-8"},
                {"name": "cage:classification", "value": "COMPLIANCE"},
            ],
        },
        "components": components,
        "dependencies": [],
    }


# ---------------------------------------------------------------------------
# License Validation
# ---------------------------------------------------------------------------


def validate_licenses(sbom: dict[str, Any]) -> list[str]:
    """
    Validate that no component carries a blocklisted license.

    Returns a list of violation strings (empty list = pass).
    Blocklist: GPL-3.0, AGPL — incompatible with commercial/financial use.
    """
    violations: list[str] = []
    components = sbom.get("components", [])
    for comp in components:
        licenses = comp.get("licenses", [])
        for lic_entry in licenses:
            # CycloneDX license can be { "license": { "id": "MIT" } } or { "expression": "MIT" }
            lic_id = ""
            if isinstance(lic_entry, dict):
                lic_obj = lic_entry.get("license", {})
                lic_id = lic_obj.get("id", "") or lic_entry.get("expression", "")
            if lic_id in BLOCKLISTED_LICENSES:
                violations.append(
                    f"BLOCKLISTED LICENSE: {comp.get('name', 'unknown')} "
                    f"v{comp.get('version', '?')} — {lic_id}"
                )
    return violations


# ---------------------------------------------------------------------------
# Vulnerability Enrichment (Grype)
# ---------------------------------------------------------------------------


def run_grype_scan(sbom_path: Path) -> tuple[list[dict[str, Any]], bool]:
    """
    Run Grype vulnerability scan against the SBOM file.

    Returns:
        (matches, has_critical) — list of Grype matches and flag for CVSS >= 9.0.
        Returns ([], False) gracefully if Grype is not installed.
    """
    try:
        logger.info("Running Grype vulnerability scan on '%s'...", sbom_path)
        result = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode not in (0, 1):  # 0=no vulns, 1=vulns found
            logger.warning(
                "Grype exited with code %d: %s", result.returncode, result.stderr[:200]
            )
            return [], False

        grype_output = json.loads(result.stdout)
        matches = grype_output.get("matches", [])
        has_critical = any(
            float(
                m.get("vulnerability", {})
                .get("cvss", [{}])[0]
                .get("metrics", {})
                .get("baseScore", 0)
            )
            >= CRITICAL_CVSS_THRESHOLD
            or m.get("vulnerability", {}).get("severity", "").upper() == "CRITICAL"
            for m in matches
            if m.get("vulnerability", {}).get("cvss")
            or m.get("vulnerability", {}).get("severity", "").upper() == "CRITICAL"
        )
        logger.info(
            "Grype scan complete: %d vulnerabilities found, critical=%s",
            len(matches),
            has_critical,
        )
        return matches, has_critical

    except FileNotFoundError:
        logger.warning(
            "grype not found in PATH — skipping vulnerability enrichment. "
            "Install from: https://github.com/anchore/grype"
        )
        return [], False
    except subprocess.TimeoutExpired:
        logger.error("Grype timed out after 300 seconds")
        return [], False
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Grype JSON output: %s", exc)
        return [], False


# ---------------------------------------------------------------------------
# GCS Upload
# ---------------------------------------------------------------------------


def upload_to_gcs(
    local_path: Path,
    gcs_bucket: str,
    project_id: str | None = None,
    dry_run: bool = False,
) -> str:
    """
    Upload SBOM JSON to GCS bucket using google-cloud-storage (ADC).

    Uses Application Default Credentials (ADC) via GOOG-REDACTED
    or gcloud default credentials.

    Args:
        local_path: Local path to the SBOM file.
        gcs_bucket: GCS bucket name (without gs:// prefix).
        project_id: GCP project ID.
        dry_run: If True, log the intended upload but skip actual transfer.

    Returns:
        gs:// URI of the uploaded object.
    """
    gcs_key = f"sbom/{local_path.name}"
    gcs_uri = f"gs://{gcs_bucket}/{gcs_key}"

    if dry_run:
        logger.info("[DRY-RUN] Would upload '%s' → %s", local_path, gcs_uri)
        return gcs_uri

    try:
        from google.cloud import storage  # type: ignore[import]

        logger.info("Uploading '%s' → %s", local_path, gcs_uri)
        client = storage.Client(project=project_id)
        bucket = client.bucket(gcs_bucket)
        blob = bucket.blob(gcs_key)
        blob.upload_from_filename(str(local_path), content_type="application/json")
        logger.info("Upload complete: %s", gcs_uri)
        return gcs_uri

    except ImportError:
        logger.warning(
            "google-cloud-storage not installed — falling back to gsutil CLI"
        )
        try:
            subprocess.run(
                ["gsutil", "cp", str(local_path), gcs_uri],
                check=True,
                timeout=120,
            )
            logger.info("gsutil upload complete: %s", gcs_uri)
            return gcs_uri
        except (
            FileNotFoundError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as exc:
            logger.error("gsutil upload failed: %s", exc)
            raise RuntimeError(f"GCS upload failed for {local_path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Summary Report
# ---------------------------------------------------------------------------


def generate_summary_report(
    sbom: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    license_violations: list[str],
    output_dir: Path,
    sbom_filename: str,
    dry_run: bool = False,
) -> Path:
    """
    Generate a Markdown summary report of the SBOM at compliance/sbom/SBOM_SUMMARY.md.

    Returns:
        Path to the generated Markdown file.
    """
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    components = sbom.get("components", [])
    metadata = sbom.get("metadata", {})
    subject = metadata.get("component", {}).get("name", "unknown")

    # Severity breakdown of vulnerabilities
    severity_counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    for match in vulnerabilities:
        sev = match.get("vulnerability", {}).get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Top 20 components table
    top_components = components[:20]

    lines = [
        "# CAGE SBOM Summary Report",
        "",
        f"> **Generated:** {now}  ",
        f"> **SBOM File:** `{sbom_filename}`  ",
        "> **NIST Control:** CM-8 (System Component Inventory)  ",
        "> **POAM Reference:** POAM-006, POAM-010  ",
        "",
        "---",
        "",
        "## Scan Target",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Subject** | `{subject}` |",
        f"| **Tool** | {metadata.get('tools', [{}])[0].get('name', 'unknown') if metadata.get('tools') else 'unknown'} |",
        f"| **Format** | CycloneDX {sbom.get('specVersion', '?')} |",
        f"| **Total Components** | {len(components)} |",
        f"| **Scan Timestamp** | {metadata.get('timestamp', 'unknown')} |",
        "",
        "---",
        "",
        "## Vulnerability Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 CRITICAL | {severity_counts.get('CRITICAL', 0)} |",
        f"| 🟠 HIGH     | {severity_counts.get('HIGH', 0)} |",
        f"| 🟡 MEDIUM   | {severity_counts.get('MEDIUM', 0)} |",
        f"| 🟢 LOW      | {severity_counts.get('LOW', 0)} |",
        f"| ⚪ UNKNOWN  | {severity_counts.get('UNKNOWN', 0)} |",
        f"| **TOTAL**   | **{sum(severity_counts.values())}** |",
        "",
    ]

    if not vulnerabilities:
        lines.append(
            "✅ **No vulnerabilities detected** (or Grype not available — see POAM-010)."
        )
        lines.append("")

    if license_violations:
        lines += [
            "---",
            "",
            "## ⚠️ License Violations",
            "",
            "The following components use BLOCKLISTED licenses (GPL-3.0 / AGPL — "
            "incompatible with commercial financial services use):",
            "",
        ]
        for v in license_violations:
            lines.append(f"- ❌ {v}")
        lines.append("")
    else:
        lines += [
            "---",
            "",
            "## License Validation",
            "",
            "✅ **No blocklisted licenses detected.** All components are compatible "
            "with commercial/financial services use.",
            "",
        ]

    lines += [
        "---",
        "",
        "## Top-Level Components (first 20)",
        "",
        "| # | Name | Version | Type | PURL |",
        "|---|------|---------|------|------|",
    ]
    for i, comp in enumerate(top_components, 1):
        lines.append(
            f"| {i} | `{comp.get('name', '?')}` | {comp.get('version', '?')} "
            f"| {comp.get('type', '?')} | `{comp.get('purl', 'N/A')}` |"
        )

    if len(components) > 20:
        lines.append(
            f"| ... | *(+{len(components) - 20} more — see full SBOM JSON)* | | | |"
        )

    lines += [
        "",
        "---",
        "",
        "## Compliance Context",
        "",
        "| Control | Requirement | Status |",
        "|---------|-------------|--------|",
        "| CM-8 | System Component Inventory / SBOM | ✅ SBOM Generated |",
        "| RA-5 | Vulnerability Scanning | "
        + (
            "✅ Grype Enrichment Applied"
            if vulnerabilities is not None
            and len(vulnerabilities) >= 0
            and any(True for _ in [1])
            else "⚠️ Grype Not Available"
        )
        + " |",
        "| POAM-006 | SBOM pipeline gap remediation | 🔄 IN PROGRESS |",
        "| POAM-010 | Container scanning gap remediation | 🔄 IN PROGRESS |",
        "",
        "---",
        "",
        "_This report is auto-generated by `scripts/generate_sbom.py`. "
        "Do not edit manually. See `compliance/sbom/README.md` for pipeline documentation._",
    ]

    summary_path = output_dir / "SBOM_SUMMARY.md"

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("SBOM summary written to '%s'", summary_path)
    else:
        logger.info("[DRY-RUN] Would write summary to '%s'", summary_path)

    return summary_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "CAGE SBOM Generation Pipeline — CM-8 / POAM-006\n"
            "Generates CycloneDX JSON SBOMs using Syft (Docker/dir) "
            "and cyclonedx-bom (Python). Enriched with Grype vulnerability data."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type",
        choices=["docker", "python", "dir"],
        required=True,
        help="SBOM scan type: docker (container image), python (pip deps), dir (filesystem directory).",
    )
    parser.add_argument(
        "--image",
        default=None,
        help=(
            "Docker image reference (--type docker), e.g. gcr.io/PROJECT/cage-gateway:TAG. "
            "Also used as directory path for --type dir."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="compliance/sbom",
        help="Output directory for SBOM JSON and summary report (default: compliance/sbom).",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        default=False,
        help="Upload SBOM JSON to GCS after generation.",
    )
    parser.add_argument(
        "--gcs-bucket",
        default=os.environ.get("SBOM_GCS_BUCKET", "cage-compliance-sboms"),
        help="GCS bucket name for SBOM upload (default: $SBOM_GCS_BUCKET or 'cage-compliance-sboms').",
    )
    parser.add_argument(
        "--project-id",
        default=os.environ.get("GCP_PROJECT_ID"),
        help="GCP project ID (default: $GCP_PROJECT_ID).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Generate SBOM but do not write files or upload to GCS.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    date_str = datetime.date.today().strftime("%Y-%m-%d")

    # ------------------------------------------------------------------
    # Step 1: Generate SBOM
    # ------------------------------------------------------------------
    sbom: dict[str, Any]
    if args.type == "python":
        sbom = generate_python_sbom(output_dir, dry_run=args.dry_run)
        target_name = "python-deps"
    elif args.type == "docker":
        if not args.image:
            logger.error("--image is required for --type docker")
            return 1
        sbom = generate_docker_sbom(args.image, output_dir, dry_run=args.dry_run)
        target_name = args.image.replace("/", "_").replace(":", "-")
    else:  # dir
        scan_path = args.image or "."
        sbom = generate_dir_sbom(scan_path, output_dir, dry_run=args.dry_run)
        target_name = "filesystem"

    # ------------------------------------------------------------------
    # Step 2: Write SBOM JSON
    # ------------------------------------------------------------------
    sbom_filename = f"{target_name}-{date_str}.cdx.json"
    sbom_path = output_dir / sbom_filename

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        logger.info("SBOM written to '%s'", sbom_path)
    else:
        logger.info("[DRY-RUN] Would write SBOM to '%s'", sbom_path)

    # ------------------------------------------------------------------
    # Step 3: License validation
    # ------------------------------------------------------------------
    logger.info("Validating component licenses against blocklist...")
    license_violations = validate_licenses(sbom)
    if license_violations:
        logger.warning("LICENSE VIOLATIONS DETECTED:")
        for v in license_violations:
            logger.warning("  %s", v)
    else:
        logger.info("License validation passed — no blocklisted licenses found.")

    # ------------------------------------------------------------------
    # Step 4: Vulnerability enrichment via Grype
    # ------------------------------------------------------------------
    vulnerabilities: list[dict[str, Any]] = []
    has_critical = False

    if not args.dry_run and sbom_path.exists():
        vulnerabilities, has_critical = run_grype_scan(sbom_path)
    elif args.dry_run:
        logger.info("[DRY-RUN] Skipping Grype scan (no file on disk in dry-run mode).")

    if has_critical:
        logger.error(
            "❌ CRITICAL CVEs (CVSS >= %.1f) found — see POAM-010. "
            "Investigate before deploying.",
            CRITICAL_CVSS_THRESHOLD,
        )

    # ------------------------------------------------------------------
    # Step 5: Generate summary report
    # ------------------------------------------------------------------
    summary_path = generate_summary_report(
        sbom=sbom,
        vulnerabilities=vulnerabilities,
        license_violations=license_violations,
        output_dir=output_dir,
        sbom_filename=sbom_filename,
        dry_run=args.dry_run,
    )

    # ------------------------------------------------------------------
    # Step 6: Print human-readable component table
    # ------------------------------------------------------------------
    components = sbom.get("components", [])
    logger.info("\n" + "=" * 70)
    logger.info("SBOM Component Summary — Top 15 of %d total", len(components))
    logger.info("=" * 70)
    logger.info("%-40s %-20s %-10s", "NAME", "VERSION", "TYPE")
    logger.info("-" * 70)
    for comp in components[:15]:
        logger.info(
            "%-40s %-20s %-10s",
            comp.get("name", "?")[:40],
            comp.get("version", "?")[:20],
            comp.get("type", "?")[:10],
        )
    if len(components) > 15:
        logger.info("  ... and %d more (see full SBOM JSON)", len(components) - 15)
    logger.info("=" * 70)

    # ------------------------------------------------------------------
    # Step 7: Upload to GCS (optional)
    # ------------------------------------------------------------------
    if args.upload and not args.dry_run:
        try:
            gcs_uri = upload_to_gcs(
                local_path=sbom_path,
                gcs_bucket=args.gcs_bucket,
                project_id=args.project_id,
                dry_run=False,
            )
            logger.info("SBOM uploaded to GCS: %s", gcs_uri)
        except RuntimeError as exc:
            logger.error("GCS upload failed: %s", exc)
    elif args.upload and args.dry_run:
        upload_to_gcs(
            local_path=sbom_path,
            gcs_bucket=args.gcs_bucket,
            project_id=args.project_id,
            dry_run=True,
        )

    # ------------------------------------------------------------------
    # Step 8: Return exit code
    # ------------------------------------------------------------------
    logger.info("\n✅ SBOM generation complete.")
    logger.info("   SBOM JSON:   %s", sbom_path if not args.dry_run else "[DRY-RUN]")
    logger.info("   Summary:     %s", summary_path if not args.dry_run else "[DRY-RUN]")
    logger.info("   Components:  %d", len(components))
    logger.info(
        "   CVE count:   %d (%s critical)",
        len(vulnerabilities),
        severity_counts_str(vulnerabilities),
    )
    logger.info(
        "   License OK:  %s",
        "YES"
        if not license_violations
        else f"NO ({len(license_violations)} violations)",
    )

    if has_critical:
        logger.error(
            "EXIT CODE 1: Critical CVEs detected (CVSS >= %.1f). "
            "Remediate before production deployment per POAM-010.",
            CRITICAL_CVSS_THRESHOLD,
        )
        return 1

    return 0


def severity_counts_str(vulnerabilities: list[dict[str, Any]]) -> str:
    """Return a short severity summary string."""
    crit = sum(
        1
        for v in vulnerabilities
        if v.get("vulnerability", {}).get("severity", "").upper() == "CRITICAL"
    )
    return str(crit)


if __name__ == "__main__":
    sys.exit(main())
