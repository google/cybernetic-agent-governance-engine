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
Phase C: Cloud Run Binary Authorization Infrastructure Tests

Validates Binary Authorization policy configuration enforcing attestation-based
container admission control. Verifies production breakglass prohibition and
dev/staging rapid iteration allowances.
"""

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

CLOUDRUN_DIR = Path("infra/targets/gcp-cloudrun")


def read_terraform_file(filename: str) -> str:
    """Read a Terraform file from the gcp-cloudrun target."""
    filepath = CLOUDRUN_DIR / filename
    return filepath.read_text()


def test_binary_authorization_policy_created():
    """Verify Binary Authorization policy resource exists."""
    binauth_config = read_terraform_file("binary_authorization.tf")

    # Verify policy resource exists
    assert 'resource "google_binary_authorization_policy" "cloudrun_policy"' in binauth_config
    
    # Verify conditional creation with enable_binary_authorization
    assert "count   = var.enable_binary_authorization ? 1 : 0" in binauth_config
    
    # Verify default admission rule exists
    assert "default_admission_rule {" in binauth_config
    
    # Verify enforcement mode
    assert 'enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"' in binauth_config


def test_prod_requires_attestation():
    """Verify production environments require attestation."""
    binauth_config = read_terraform_file("binary_authorization.tf")

    # Verify evaluation_mode is REQUIRE_ATTESTATION for prod
    assert re.search(
        r'evaluation_mode\s*=\s*var\.environment\s*==\s*"prod"\s*\?\s*"REQUIRE_ATTESTATION"\s*:\s*"ALWAYS_ALLOW"',
        binauth_config
    ), "evaluation_mode must be REQUIRE_ATTESTATION for prod, ALWAYS_ALLOW otherwise"
    
    # Verify require_attestations_by references attestor for prod
    assert re.search(
        r'require_attestations_by\s*=\s*var\.environment\s*==\s*"prod"\s*\?\s*\[.*?google_binary_authorization_attestor\.cloudrun_attestor\[0\]\.name.*?\]\s*:\s*\[\]',
        binauth_config,
        re.DOTALL
    ), "require_attestations_by must reference attestor for prod only"


def test_prod_breakglass_prohibition():
    """Verify production environments disable breakglass escape hatches."""
    binauth_config = read_terraform_file("binary_authorization.tf")

    # CRITICAL: Verify global_policy_evaluation_mode is ENABLE for prod (no breakglass)
    assert re.search(
        r'global_policy_evaluation_mode\s*=\s*var\.environment\s*==\s*"prod"\s*\?\s*"ENABLE"\s*:\s*"DISABLE"',
        binauth_config
    ), "global_policy_evaluation_mode must be ENABLE for prod (breakglass disabled)"


def test_attestor_and_note_created():
    """Verify Container Analysis Note and Attestor resources are created."""
    binauth_config = read_terraform_file("binary_authorization.tf")

    # Verify Container Analysis Note exists
    assert 'resource "google_container_analysis_note" "cloudrun_attestation_note"' in binauth_config
    assert 'name    = "cage-cloudrun-attestation-${var.environment}"' in binauth_config
    assert "attestation_authority {" in binauth_config
    
    # Verify Attestor exists
    assert 'resource "google_binary_authorization_attestor" "cloudrun_attestor"' in binauth_config
    assert 'name    = "cage-cloudrun-attestor-${var.environment}"' in binauth_config
    assert "attestation_authority_note {" in binauth_config
    
    # Verify attestor references note
    assert "note_reference = google_container_analysis_note.cloudrun_attestation_note[0].id" in binauth_config


def test_cloudbuild_attestor_iam_binding():
    """Verify Cloud Build service account has containeranalysis.notes.attacher role."""
    binauth_config = read_terraform_file("binary_authorization.tf")

    # Verify IAM binding exists
    assert 'resource "google_project_iam_member" "cloudbuild_attestor"' in binauth_config
    
    # Verify role
    assert 'role    = "roles/containeranalysis.notes.attacher"' in binauth_config
    
    # Verify Cloud Build service account pattern
    assert "@cloudbuild.gserviceaccount.com" in binauth_config


def test_binary_auth_variables_defined():
    """Verify enable_binary_authorization variable is properly defined."""
    variables_config = read_terraform_file("variables.tf")

    # Verify enable_binary_authorization variable exists
    assert 'variable "enable_binary_authorization"' in variables_config
    
    # Verify description mentions Binary Authorization and production attestation
    assert re.search(
        r'variable\s+"enable_binary_authorization".*?description\s*=.*?Binary Authorization.*?REQUIRE_ATTESTATION',
        variables_config,
        re.DOTALL | re.IGNORECASE
    ), "enable_binary_authorization variable must describe Binary Authorization policy"
    
    # Verify default is false
    assert re.search(
        r'variable\s+"enable_binary_authorization".*?default\s*=\s*false',
        variables_config,
        re.DOTALL
    ), "enable_binary_authorization must default to false"


def test_binary_auth_outputs_defined():
    """Verify Binary Authorization outputs are properly defined."""
    outputs_config = read_terraform_file("outputs.tf")

    # Verify binary_authorization_policy_id output
    assert 'output "binary_authorization_policy_id"' in outputs_config
    assert "google_binary_authorization_policy.cloudrun_policy[0].id" in outputs_config
    
    # Verify attestor_name output
    assert 'output "attestor_name"' in outputs_config
    assert "google_binary_authorization_attestor.cloudrun_attestor[0].name" in outputs_config
    
    # Verify conditional outputs based on enable_binary_authorization
    assert outputs_config.count("var.enable_binary_authorization ?") >= 2
