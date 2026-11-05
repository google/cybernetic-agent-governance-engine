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
   runs with only ``roles/iam.serviceAccountTokenCreator`` on ``cage-gateway``
   and ``roles/cloudkms.signer`` (+ viewer/publicKeyViewer) on the partner
   signing key.
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

    gateway_binding = _extract_resource_block(
        text, "google_service_account_iam_binding", "gateway_partner_token_creator"
    )
    assert "google_service_account.gateway.name" in gateway_binding
    assert (
        'role               = "roles/iam.serviceAccountTokenCreator"' in gateway_binding
    )
    assert (
        '"serviceAccount:${google_service_account.partner_harness.email}"'
        in gateway_binding
    )
    assert "sa-cage-deployer" not in gateway_binding
    assert "-compute@developer.gserviceaccount.com" not in gateway_binding

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
