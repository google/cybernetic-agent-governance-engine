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
"""POAM-2026-165: Workload Identity Federation deployer / partner-harness isolation.

Verifies that ``infra/targets/gcp-gke/wif.tf`` codifies the two-identity WIF
partition:
1. The GitHub Actions OIDC provider maps ``attribute.ref`` and
   ``attribute.environment`` in addition to ``attribute.repository``.
2. ``sa-cage-deployer`` trusts only ``attribute.ref/${var.github_deployer_ref}``
   (default ``refs/heads/main``) and never the repository-wide principal set or
   the Compute Engine default service account.
3. ``cage-partner-harness`` is a dedicated low-privilege identity for CI partner
   runs with zero IAM bindings on ``cage-gateway`` (no impersonation path to
   ``gateway-seal``, CMEK, or secrets), optional ``roles/run.invoker`` on an
   explicit partner harness Cloud Run service, and ``roles/cloudkms.signer``
   (+ viewer/publicKeyViewer) exclusively on the partner test signing key.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
GCP_GKE_DIR = REPO_ROOT / "infra" / "targets" / "gcp-gke"
WIF_TF = GCP_GKE_DIR / "wif.tf"
VARIABLES_TF = GCP_GKE_DIR / "variables.tf"


def _extract_resource_block(text: str, resource_type: str, resource_name: str) -> str:
    pattern = re.compile(
        rf'^resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{',
        re.MULTILINE,
    )
    match = pattern.search(text)
    assert match is not None, (
        f'Missing resource "{resource_type}" "{resource_name}" in wif.tf'
    )
    lines = text[match.start() :].splitlines()
    block_lines: list[str] = []
    for line in lines:
        block_lines.append(line)
        if line == "}":
            break
    return "\n".join(block_lines)


def test_wif_provider_maps_ref_and_environment() -> None:
    text = WIF_TF.read_text(encoding="utf-8")
    provider_block = _extract_resource_block(
        text, "google_iam_workload_identity_pool_provider", "github"
    )
    assert '"attribute.ref"' in provider_block and '"assertion.ref"' in provider_block
    assert (
        '"attribute.environment"' in provider_block
        and '"assertion.environment"' in provider_block
    )
    assert "\"assertion.repository == '${var.github_repository}'\"" in provider_block


def test_deployer_bindings_restrict_to_deployer_ref_and_exclude_compute_default_sa() -> (
    None
):
    text = WIF_TF.read_text(encoding="utf-8")
    deployer_sa = _extract_resource_block(text, "google_service_account", "deployer")
    assert 'account_id   = "sa-cage-deployer"' in deployer_sa

    for binding_name in ("deployer_workload_identity", "deployer_token_creator"):
        block = _extract_resource_block(
            text, "google_service_account_iam_binding", binding_name
        )
        assert "attribute.ref/${var.github_deployer_ref}" in block
        assert "attribute.repository/" not in block
        assert "-compute@developer.gserviceaccount.com" not in block


def test_partner_harness_isolation_and_narrow_grants() -> None:
    text = WIF_TF.read_text(encoding="utf-8")
    partner_sa = _extract_resource_block(
        text, "google_service_account", "partner_harness"
    )
    assert 'account_id   = "cage-partner-harness"' in partner_sa

    for binding_name in (
        "partner_harness_workload_identity",
        "partner_harness_token_creator",
    ):
        block = _extract_resource_block(
            text, "google_service_account_iam_binding", binding_name
        )
        assert "attribute.repository/${var.github_repository}" in block
        assert "-compute@developer.gserviceaccount.com" not in block

    assert "gateway_partner_token_creator" not in text
    assert "google_service_account.gateway" not in text

    invoker_binding = _extract_resource_block(
        text, "google_cloud_run_v2_service_iam_member", "partner_harness_invoker"
    )
    assert 'role     = "roles/run.invoker"' in invoker_binding
    assert (
        'member   = "serviceAccount:${google_service_account.partner_harness.email}"'
        in invoker_binding
    )
    assert "sa-cage-deployer" not in invoker_binding
    assert "-compute@developer.gserviceaccount.com" not in invoker_binding

    kms_policy = _extract_resource_block(
        text, "google_kms_crypto_key_iam_policy", "partner_harness_kms_signer"
    )
    assert (
        "data.google_iam_policy.partner_harness_kms_signer[0].policy_data" in kms_policy
    )


def test_github_deployer_ref_variable_forbids_wildcards() -> None:
    variables_text = VARIABLES_TF.read_text(encoding="utf-8")
    assert 'variable "github_deployer_ref"' in variables_text
    assert 'default     = "refs/heads/main"' in variables_text
    assert 'startswith(var.github_deployer_ref, "refs/heads/")' in variables_text
    assert '!endswith(var.github_deployer_ref, "*")' in variables_text


def test_partner_harness_kms_key_defaults_empty_for_clean_projects() -> None:
    variables_text = VARIABLES_TF.read_text(encoding="utf-8")
    match = re.search(
        r'variable\s+"partner_harness_kms_key"\s*\{(.*?)\n\}',
        variables_text,
        re.DOTALL,
    )
    assert match is not None
    assert 'default     = ""' in match.group(1)
    wif_text = WIF_TF.read_text(encoding="utf-8")
    assert (
        'var.partner_harness_kms_keyring != "" && var.partner_harness_kms_key != ""'
        in wif_text
    )


def test_alert_verifier_isolation_and_least_privilege_grants() -> None:
    text = WIF_TF.read_text(encoding="utf-8")
    verifier_sa = _extract_resource_block(
        text, "google_service_account", "alert_verifier"
    )
    assert 'account_id   = "cage-alert-verifier"' in verifier_sa

    for binding_name in (
        "alert_verifier_workload_identity",
        "alert_verifier_token_creator",
    ):
        block = _extract_resource_block(
            text, "google_service_account_iam_binding", binding_name
        )
        assert "attribute.ref/${var.github_deployer_ref}" in block
        assert "attribute.repository/" not in block
        assert "-compute@developer.gserviceaccount.com" not in block

    mon_viewer = _extract_resource_block(
        text, "google_project_iam_member", "alert_verifier_monitoring_viewer"
    )
    assert 'role    = "roles/monitoring.viewer"' in mon_viewer
    mon_writer = _extract_resource_block(
        text, "google_project_iam_member", "alert_verifier_metric_writer"
    )
    assert 'role    = "roles/monitoring.metricWriter"' in mon_writer

    for sub_binding in ("alert_verifier_subscriber", "alert_verifier_viewer"):
        block = _extract_resource_block(
            text, "google_pubsub_subscription_iam_member", sub_binding
        )
        assert 'trimspace(var.alert_verify_pubsub_subscription) != ""' in block
        assert (
            'member       = "serviceAccount:${google_service_account.alert_verifier.email}"'
            in block
        )
