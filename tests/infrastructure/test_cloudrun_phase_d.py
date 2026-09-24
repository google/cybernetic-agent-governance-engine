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
Test suite for Cloud Run Phase D: Posture Workloads Restoration.

Validates:
- Requirement 9: NeMo Guardrails multi-container service (AC-3, input validation)
- Requirement 10: Compliance jobs + Cloud Scheduler triggers (CA-7, CM-8, RA-5)
- Requirement 11: Reconciliation daemon with continuous mode (min_instance_count=1, cpu_idle=false)
- Requirement 12: POAM-019 telemetry isolation precondition (AU-9, SC-7)

Reference: docs/architecture/CLOUD_RUN_IMPLEMENTATION_PLAN.md Phase D
"""

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

CLOUDRUN_TARGET_DIR = Path(__file__).parent.parent.parent / "infra" / "targets" / "gcp-cloudrun"
MAIN_TF = CLOUDRUN_TARGET_DIR / "main.tf"


def _parse_terraform_hcl(tf_path: Path) -> str:
    """Read Terraform HCL file content."""
    return tf_path.read_text()


# ─── Requirement 9: NeMo Guardrails Service ──────────────────────────────────


def test_nemo_service_exists():
    """NeMo Guardrails service resource must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_run_v2_service" "nemo_guardrails"' in content, (
        "NeMo Guardrails service resource not found"
    )


def test_nemo_service_internal_ingress():
    """NeMo service must use INGRESS_TRAFFIC_INTERNAL_ONLY (AC-3)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    # Find NeMo service and check for INTERNAL_ONLY ingress
    nemo_match = re.search(
        r'resource "google_cloud_run_v2_service" "nemo_guardrails" \{.*?ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"',
        content,
        re.DOTALL
    )
    assert nemo_match, (
        "NeMo service must restrict ingress to INTERNAL_ONLY for AC-3 boundary protection"
    )


def test_nemo_service_port_8000():
    """NeMo service must expose port 8000."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    # Look for NeMo container port configuration
    nemo_match = re.search(
        r'resource "google_cloud_run_v2_service" "nemo_guardrails" \{.*?container_port = 8000',
        content,
        re.DOTALL
    )
    assert nemo_match, "NeMo service must expose container_port = 8000"


def test_nemo_service_health_checks():
    """NeMo service must have startup and liveness probes on /health port 8000."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    # Extract NeMo service block
    nemo_match = re.search(
        r'resource "google_cloud_run_v2_service" "nemo_guardrails" \{.*?(?=\n(?:resource|#|$))',
        content,
        re.DOTALL
    )
    assert nemo_match, "NeMo service resource not found"
    nemo_block = nemo_match.group(0)
    
    # Verify startup probe
    assert 'startup_probe' in nemo_block, "NeMo service must have startup_probe"
    assert re.search(r'path\s*=\s*"/health"', nemo_block), "startup_probe must check /health"
    assert re.search(r'port\s*=\s*8000', nemo_block), "startup_probe must use port 8000"
    
    # Verify liveness probe
    assert 'liveness_probe' in nemo_block, "NeMo service must have liveness_probe"


def test_nemo_service_langfuse_compliance_credentials():
    """NeMo service must use Langfuse compliance credentials (AU-9)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    # Extract NeMo service block
    nemo_match = re.search(
        r'resource "google_cloud_run_v2_service" "nemo_guardrails" \{.*?(?=\n(?:resource|#|$))',
        content,
        re.DOTALL
    )
    assert nemo_match, "NeMo service resource not found"
    nemo_block = nemo_match.group(0)
    
    # Verify Langfuse compliance credentials are referenced
    assert 'langfuse_compliance_public_key' in nemo_block, (
        "NeMo service must reference langfuse_compliance_public_key for AU-9 telemetry isolation"
    )
    assert 'langfuse_compliance_secret_key' in nemo_block, (
        "NeMo service must reference langfuse_compliance_secret_key for AU-9 telemetry isolation"
    )


# ─── Requirement 10: Compliance Jobs ──────────────────────────────────────────


def test_lula_job_exists():
    """Lula compliance audit job must be defined (CA-7)."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_run_v2_job" "lula_audit"' in content, (
        "Lula audit job resource not found (CA-7 continuous monitoring)"
    )


def test_sbom_job_exists():
    """SBOM generator job must be defined (CM-8)."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_run_v2_job" "sbom_generator"' in content, (
        "SBOM generator job resource not found (CM-8 component inventory)"
    )


def test_security_scan_job_exists():
    """Security scan job must be defined (RA-5)."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_run_v2_job" "security_scan"' in content, (
        "Security scan job resource not found (RA-5 vulnerability scanning)"
    )


def test_lula_job_timeout():
    """Lula job must have 10-minute timeout."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    lula_match = re.search(
        r'resource "google_cloud_run_v2_job" "lula_audit" \{.*?timeout = "600s"',
        content,
        re.DOTALL
    )
    assert lula_match, "Lula job must have timeout = 600s (10 minutes)"


def test_sbom_job_timeout():
    """SBOM job must have 1-hour timeout."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    sbom_match = re.search(
        r'resource "google_cloud_run_v2_job" "sbom_generator" \{.*?timeout = "3600s"',
        content,
        re.DOTALL
    )
    assert sbom_match, "SBOM job must have timeout = 3600s (1 hour)"


def test_security_scan_job_timeout():
    """Security scan job must have 30-minute timeout."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    scan_match = re.search(
        r'resource "google_cloud_run_v2_job" "security_scan" \{.*?timeout = "1800s"',
        content,
        re.DOTALL
    )
    assert scan_match, "Security scan job must have timeout = 1800s (30 minutes)"


# ─── Requirement 10: Cloud Scheduler Triggers ─────────────────────────────────


def test_lula_scheduler_exists():
    """Lula audit Cloud Scheduler trigger must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_scheduler_job" "lula_audit_trigger"' in content, (
        "Lula audit scheduler trigger not found"
    )


def test_lula_scheduler_cron():
    """Lula scheduler must run every 6 hours (0 */6 * * *)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    lula_sched_match = re.search(
        r'resource "google_cloud_scheduler_job" "lula_audit_trigger" \{.*?schedule\s*=\s*"0 \*/6 \* \* \*"',
        content,
        re.DOTALL
    )
    assert lula_sched_match, (
        'Lula scheduler must have schedule = "0 */6 * * *" (every 6 hours)'
    )


def test_sbom_scheduler_exists():
    """SBOM generator Cloud Scheduler trigger must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_scheduler_job" "sbom_trigger"' in content, (
        "SBOM scheduler trigger not found"
    )


def test_sbom_scheduler_cron():
    """SBOM scheduler must run daily at 02:00 UTC (0 2 * * *)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    sbom_sched_match = re.search(
        r'resource "google_cloud_scheduler_job" "sbom_trigger" \{.*?schedule\s*=\s*"0 2 \* \* \*"',
        content,
        re.DOTALL
    )
    assert sbom_sched_match, (
        'SBOM scheduler must have schedule = "0 2 * * *" (daily 02:00 UTC)'
    )


def test_security_scan_scheduler_exists():
    """Security scan Cloud Scheduler trigger must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_scheduler_job" "security_scan_trigger"' in content, (
        "Security scan scheduler trigger not found"
    )


def test_security_scan_scheduler_cron():
    """Security scan scheduler must run weekly Sunday at 03:00 UTC (0 3 * * 0)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    scan_sched_match = re.search(
        r'resource "google_cloud_scheduler_job" "security_scan_trigger" \{.*?schedule\s*=\s*"0 3 \* \* 0"',
        content,
        re.DOTALL
    )
    assert scan_sched_match, (
        'Security scan scheduler must have schedule = "0 3 * * 0" (weekly Sunday 03:00 UTC)'
    )


# ─── Requirement 11: Reconciliation Daemon ────────────────────────────────────


def test_reconciliation_daemon_exists():
    """Reconciliation daemon service must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_cloud_run_v2_service" "reconciliation_daemon"' in content, (
        "Reconciliation daemon service resource not found"
    )


def test_reconciliation_daemon_min_instance_count():
    """Reconciliation daemon must have min_instance_count = 1."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    recon_match = re.search(
        r'resource "google_cloud_run_v2_service" "reconciliation_daemon" \{.*?min_instance_count = 1',
        content,
        re.DOTALL
    )
    assert recon_match, (
        "Reconciliation daemon must have min_instance_count = 1 for continuous operation"
    )


def test_reconciliation_daemon_cpu_idle_false():
    """Reconciliation daemon must have cpu_idle = false (CPU always allocated)."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    recon_match = re.search(
        r'resource "google_cloud_run_v2_service" "reconciliation_daemon" \{.*?cpu_idle = false',
        content,
        re.DOTALL
    )
    assert recon_match, (
        "Reconciliation daemon must have cpu_idle = false to prevent daemon freeze between requests"
    )


def test_reconciliation_daemon_continuous_mode():
    """Reconciliation daemon must set RECONCILIATION_SINGLE_SHOT = false."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    recon_match = re.search(
        r'resource "google_cloud_run_v2_service" "reconciliation_daemon" \{.*?RECONCILIATION_SINGLE_SHOT.*?value\s*=\s*"false"',
        content,
        re.DOTALL
    )
    assert recon_match, (
        'Reconciliation daemon must set RECONCILIATION_SINGLE_SHOT = "false" for continuous mode'
    )


# ─── Requirement 12: POAM-019 Precondition ────────────────────────────────────


def test_poam_019_precondition_exists():
    """POAM-019 telemetry isolation terraform_data precondition must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "terraform_data" "poam_019_langfuse_isolation"' in content, (
        "POAM-019 terraform_data precondition not found (AU-9 telemetry isolation)"
    )


def test_poam_019_key_distinctness_validation():
    """POAM-019 precondition must validate compliance keys ≠ application keys."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    poam_match = re.search(
        r'resource "terraform_data" "poam_019_langfuse_isolation" \{.*?(?=\n(?:resource|#|$))',
        content,
        re.DOTALL
    )
    assert poam_match, "POAM-019 terraform_data resource not found"
    poam_block = poam_match.group(0)
    
    # Verify precondition validates non-empty compliance keys
    assert 'langfuse_compliance_public_key != ""' in poam_block, (
        "POAM-019 must validate langfuse_compliance_public_key is non-empty"
    )
    assert 'langfuse_compliance_secret_key != ""' in poam_block, (
        "POAM-019 must validate langfuse_compliance_secret_key is non-empty"
    )
    
    # Verify precondition validates keys are distinct
    assert 'langfuse_compliance_public_key != var.langfuse_public_key' in poam_block, (
        "POAM-019 must validate compliance public key differs from application key"
    )
    assert 'langfuse_compliance_secret_key != var.langfuse_secret_key' in poam_block, (
        "POAM-019 must validate compliance secret key differs from application key"
    )


def test_poam_019_error_message():
    """POAM-019 precondition must have detailed error message with remediation steps."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    poam_match = re.search(
        r'resource "terraform_data" "poam_019_langfuse_isolation" \{.*?(?=\n(?:resource|#|$))',
        content,
        re.DOTALL
    )
    assert poam_match, "POAM-019 terraform_data resource not found"
    poam_block = poam_match.group(0)
    
    # Verify error message contains key elements
    assert 'error_message' in poam_block, "POAM-019 must have error_message"
    assert 'POAM-019' in poam_block, "Error message must reference POAM-019"
    assert 'AU-9' in poam_block, "Error message must reference NIST AU-9 control"
    assert 'Remediation' in poam_block or 'remediation' in poam_block.lower(), (
        "Error message must include remediation steps"
    )


def test_poam_019_conditional_count():
    """POAM-019 precondition must only activate when enable_nist_compliance=true."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    poam_match = re.search(
        r'resource "terraform_data" "poam_019_langfuse_isolation" \{.*?count = var\.enable_nist_compliance \? 1 : 0',
        content,
        re.DOTALL
    )
    assert poam_match, (
        "POAM-019 must use count = var.enable_nist_compliance ? 1 : 0"
    )


# ─── IAM Bindings for Reconciliation Daemon ───────────────────────────────────


def test_reconciliation_gcs_iam_binding():
    """Reconciliation daemon must have GCS objectViewer role for evidence enumeration."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    gcs_iam = re.search(
        r'resource "google_storage_bucket_iam_member" "reconciliation_compliance_artifacts_viewer"',
        content
    )
    assert gcs_iam, (
        "Reconciliation daemon must have GCS IAM binding for evidence bucket access"
    )
    
    # Verify objectViewer role
    iam_match = re.search(
        r'resource "google_storage_bucket_iam_member" "reconciliation_compliance_artifacts_viewer" \{.*?role\s*=\s*"roles/storage.objectViewer"',
        content,
        re.DOTALL
    )
    assert iam_match, (
        "Reconciliation daemon must have roles/storage.objectViewer"
    )


def test_reconciliation_kms_iam_binding():
    """Reconciliation daemon must have KMS signerVerifier role for signature verification."""
    content = _parse_terraform_hcl(MAIN_TF)
    
    kms_iam = re.search(
        r'resource "google_kms_crypto_key_iam_member" "reconciliation_kms_verifier"',
        content
    )
    assert kms_iam, (
        "Reconciliation daemon must have KMS IAM binding for signature verification"
    )
    
    # Verify signerVerifier role
    iam_match = re.search(
        r'resource "google_kms_crypto_key_iam_member" "reconciliation_kms_verifier" \{.*?role\s*=\s*"roles/cloudkms.signerVerifier"',
        content,
        re.DOTALL
    )
    assert iam_match, (
        "Reconciliation daemon must have roles/cloudkms.signerVerifier"
    )


# ─── Service Accounts ──────────────────────────────────────────────────────────


def test_nemo_service_account_exists():
    """NeMo Guardrails dedicated service account must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_service_account" "nemo_guardrails"' in content, (
        "NeMo Guardrails service account not found"
    )


def test_reconciliation_service_account_exists():
    """Reconciliation daemon dedicated service account must be defined."""
    content = _parse_terraform_hcl(MAIN_TF)
    assert 'resource "google_service_account" "reconciliation_daemon"' in content, (
        "Reconciliation daemon service account not found"
    )
