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

"""Structural tests for the Persistent Evidence Custody Domain (PR-10, §10a, R-10, F-66, F-94, F-97)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DOMAIN_DIR = REPO_ROOT / "infra" / "modules" / "evidence_domain"
WORM_BUCKET_DIR = REPO_ROOT / "infra" / "modules" / "worm_bucket"
GKE_TARGET_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
DEPLOYMENT_RULES_MD = REPO_ROOT / "docs" / "operations" / "DEPLOYMENT_RULES.md"
BREAKING_CHANGES_MD = REPO_ROOT / "docs" / "BREAKING_CHANGES.md"


def test_evidence_domain_module_files_exist() -> None:
    for fname in ("main.tf", "variables.tf", "outputs.tf"):
        assert (EVIDENCE_DOMAIN_DIR / fname).is_file(), (
            f"Missing {fname} in evidence_domain module"
        )


def test_kms_protection_level_declared_in_target_and_module() -> None:
    target_vars = (GKE_TARGET_DIR / "variables.tf").read_text(encoding="utf-8")
    mod_vars = (EVIDENCE_DOMAIN_DIR / "variables.tf").read_text(encoding="utf-8")
    assert 'variable "kms_protection_level"' in target_vars
    assert 'variable "kms_protection_level"' in mod_vars


def test_evidence_cmek_enforces_120_day_destroy_window_and_gcs_service_agent_iam() -> (
    None
):
    """F-97 & live GCP CMEK 403 fix: 120-day window + GCS service agent IAM + bucket depends_on."""
    main_tf = (EVIDENCE_DOMAIN_DIR / "main.tf").read_text(encoding="utf-8")
    m = re.search(
        r'resource\s+"google_kms_crypto_key"\s+"evidence_cmek"\s*\{(.*?)\n\}',
        main_tf,
        re.DOTALL,
    )
    assert m is not None, "google_kms_crypto_key.evidence_cmek not found"
    body = m.group(1)
    assert 'destroy_scheduled_duration = "10368000s"' in body
    assert "prevent_destroy = true" in body
    assert "var.evidence_project_id != var.workload_project_id" in body

    assert 'data "google_project" "evidence"' in main_tf
    assert (
        "service-${data.google_project.evidence[0].number}@gs-project-accounts.iam.gserviceaccount.com"
        in main_tf
    )

    binding = re.search(
        r'resource\s+"google_kms_crypto_key_iam_binding"\s+"evidence_cmek_crypto_operator"\s*\{(.*?)\n\}',
        main_tf,
        re.DOTALL,
    )
    assert binding is not None, "Authoritative CMEK IAM binding not found"
    assert (
        'role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"'
        in binding.group(1)
    )
    assert "deployer" not in binding.group(1)

    worm_main = (WORM_BUCKET_DIR / "main.tf").read_text(encoding="utf-8")
    assert "depends_on = [terraform_data.cmek_iam_ready]" in worm_main


def test_audit_logs_worm_bucket_and_versioned_pem_signing_key_manifest() -> None:
    """F-66, F-94, R-4, PF8-in-reverse: audit-logs-worm bucket + content-addressed real PEM kid manifest."""
    main_tf = (EVIDENCE_DOMAIN_DIR / "main.tf").read_text(encoding="utf-8")
    bucket_match = re.search(
        r'resource\s+"google_storage_bucket"\s+"audit_logs_worm"\s*\{(.*?)\n\}',
        main_tf,
        re.DOTALL,
    )
    assert bucket_match is not None, "google_storage_bucket.audit_logs_worm not found"
    bbody = bucket_match.group(1)
    assert "force_destroy = false" in bbody
    assert "prevent_destroy = true" in bbody
    assert "default_kms_key_name = google_kms_crypto_key.evidence_cmek[0].id" in bbody
    assert (
        "depends_on = [google_kms_crypto_key_iam_binding.evidence_cmek_crypto_operator]"
        in bbody
    )

    assert (
        'signing_key_manifest_object_name = "trust-anchors/signing-key-manifest-${substr(sha256(local.signing_key_manifest_json), 0, 16)}.json"'
        in main_tf
    )
    manifest_match = re.search(
        r'resource\s+"google_storage_bucket_object"\s+"signing_key_manifest"\s*\{(.*?)\n\}',
        main_tf,
        re.DOTALL,
    )
    assert manifest_match is not None, (
        "google_storage_bucket_object.signing_key_manifest not found"
    )
    assert "create_before_destroy = true" in manifest_match.group(1)
    assert "prevent_destroy = true" not in manifest_match.group(1)
    assert "-----BEGIN PUBLIC KEY-----" in manifest_match.group(1)

    kms_signing_tf = (GKE_TARGET_DIR / "kms_signing.tf").read_text(encoding="utf-8")
    for role_key, tf_name in (
        ("gateway-seal", "gateway_seal"),
        ("compliance-evidence", "compliance_evidence"),
        ("reconciler-snapshot", "reconciler_snapshot"),
    ):
        assert f'"{role_key}"' in kms_signing_tf
        assert f'data "google_kms_crypto_key_version" "{tf_name}"' in kms_signing_tf
        assert (
            f"data.google_kms_crypto_key_version.{tf_name}.public_key[0].pem"
            in kms_signing_tf
        )


def test_evidence_domain_cross_project_least_privilege_and_external_mode() -> None:
    """AU-9(4): least-privilege grants and external_evidence_domain_enabled read-only adoption."""
    main_tf = (EVIDENCE_DOMAIN_DIR / "main.tf").read_text(encoding="utf-8")
    assert 'role   = "roles/storage.objectCreator"' in main_tf
    assert 'role   = "roles/storage.objectViewer"' in main_tf
    assert "roles/storage.admin" not in main_tf
    assert "roles/storage.objectAdmin" not in main_tf
    assert 'data "google_storage_bucket" "external_audit_logs_worm"' in main_tf

    gke_main = (GKE_TARGET_DIR / "main.tf").read_text(encoding="utf-8")
    assert 'module "evidence_domain"' in gke_main
    assert 'resource "terraform_data" "evidence_domain_isolation_guard"' in gke_main
    assert (
        "evidence_project_id               = coalesce(var.evidence_project_id, var.project_id)"
        in gke_main
    )
    assert (
        "external_evidence_domain_enabled  = var.external_evidence_domain_enabled"
        in gke_main
    )


def test_deployment_rules_forbids_manual_worm_deletion_and_documents_ed1_in_breaking_changes() -> (
    None
):
    """F-66, F-94: Manual WORM deletion instruction removed; ED-1 recorded in docs/BREAKING_CHANGES.md."""
    rules_text = DEPLOYMENT_RULES_MD.read_text(encoding="utf-8")
    assert "gcloud storage rm --all-versions" not in rules_text
    assert "infra/modules/evidence_domain/" in rules_text
    assert "BOUND_CHAIN_ROTATION" in rules_text

    breaking_text = BREAKING_CHANGES_MD.read_text(encoding="utf-8")
    assert "| **ED-1** |" in breaking_text
