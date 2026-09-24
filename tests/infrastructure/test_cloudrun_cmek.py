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
Phase C: Cloud Run CMEK Infrastructure Tests

Validates Customer-Managed Encryption Keys (CMEK) configuration across
Cloud SQL, Redis, GCS, and Cloud Run services. Ensures 90-day key rotation,
regional data residency lifecycle preconditions, and service agent IAM grants.
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


def test_kms_key_ring_created():
    """Verify KMS key ring resource exists with regional lifecycle preconditions."""
    kms_config = read_terraform_file("kms.tf")

    # Verify key ring resource exists
    assert 'resource "google_kms_key_ring" "cloudrun_keyring"' in kms_config
    
    # Verify conditional creation with enable_cmek
    assert "count    = var.enable_cmek ? 1 : 0" in kms_config
    
    # Verify name pattern
    assert 'name     = "cage-cloudrun-keyring-${var.environment}"' in kms_config
    
    # Verify region assignment
    assert "location = var.region" in kms_config
    
    # Verify lifecycle preconditions for data residency (DEP-08)
    assert "lifecycle {" in kms_config
    assert "precondition {" in kms_config
    assert 'error_message = "CMEK key ring requires explicit region' in kms_config


def test_crypto_key_rotation_period():
    """Verify crypto key has 90-day rotation period."""
    kms_config = read_terraform_file("kms.tf")

    # Verify crypto key resource exists
    assert 'resource "google_kms_crypto_key" "cloudrun_cmek"' in kms_config
    
    # Verify 90-day rotation period (7776000 seconds)
    assert 'rotation_period = "7776000s"' in kms_config
    
    # Verify purpose
    assert 'purpose = "ENCRYPT_DECRYPT"' in kms_config
    
    # Verify prevent_destroy lifecycle
    assert "prevent_destroy = true" in kms_config


def test_service_agent_iam_grants():
    """Verify all service agents receive cryptoKeyEncrypterDecrypter role."""
    kms_config = read_terraform_file("kms.tf")

    # Cloud Run Service Agent
    assert 'resource "google_kms_crypto_key_iam_member" "cloudrun_agent"' in kms_config
    assert "service-${data.google_project.current.number}@serverless-robot-prod.iam.gserviceaccount.com" in kms_config
    
    # Cloud SQL Service Agent
    assert 'resource "google_kms_crypto_key_iam_member" "cloudsql_agent"' in kms_config
    assert "service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com" in kms_config
    
    # GCS Service Agent
    assert 'resource "google_kms_crypto_key_iam_member" "gcs_agent"' in kms_config
    assert "service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com" in kms_config
    
    # Redis Service Agent
    assert 'resource "google_kms_crypto_key_iam_member" "redis_agent"' in kms_config
    assert "service-${data.google_project.current.number}@cloud-redis.iam.gserviceaccount.com" in kms_config
    
    # Verify role for all agents
    assert kms_config.count('role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"') == 4


def test_cloud_sql_cmek_integration():
    """Verify Cloud SQL instance references CMEK crypto key."""
    main_config = read_terraform_file("main.tf")

    # Verify encryption_key_name attribute exists in Cloud SQL resource
    assert re.search(
        r'resource\s+"google_sql_database_instance"\s+"postgres".*?encryption_key_name\s*=\s*var\.enable_cmek\s*\?\s*google_kms_crypto_key\.cloudrun_cmek\[0\]\.id\s*:\s*null',
        main_config,
        re.DOTALL
    ), "Cloud SQL instance must reference CMEK crypto key when enable_cmek=true"


def test_redis_cmek_integration():
    """Verify Redis instance references CMEK crypto key."""
    main_config = read_terraform_file("main.tf")

    # Verify customer_managed_key attribute exists in Redis resource
    assert re.search(
        r'resource\s+"google_redis_instance"\s+"redis".*?customer_managed_key\s*=\s*var\.enable_cmek\s*\?\s*google_kms_crypto_key\.cloudrun_cmek\[0\]\.id\s*:\s*null',
        main_config,
        re.DOTALL
    ), "Redis instance must reference CMEK crypto key when enable_cmek=true"


def test_gcs_bucket_cmek_integration():
    """Verify both GCS buckets use CMEK encryption."""
    main_config = read_terraform_file("main.tf")

    # Verify langfuse_traces bucket has dynamic encryption block
    assert re.search(
        r'resource\s+"google_storage_bucket"\s+"langfuse_traces".*?dynamic\s+"encryption"',
        main_config,
        re.DOTALL
    ), "langfuse_traces bucket must have dynamic encryption block"
    
    # Verify compliance_artifacts bucket has dynamic encryption block
    assert re.search(
        r'resource\s+"google_storage_bucket"\s+"compliance_artifacts".*?dynamic\s+"encryption"',
        main_config,
        re.DOTALL
    ), "compliance_artifacts bucket must have dynamic encryption block"
    
    # Verify encryption blocks reference CMEK key
    assert main_config.count("default_kms_key_name = google_kms_crypto_key.cloudrun_cmek[0].id") == 2


def test_cloud_run_services_cmek_integration():
    """Verify all Cloud Run services reference CMEK encryption key."""
    main_config = read_terraform_file("main.tf")

    # List of all Cloud Run services
    services = [
        "gateway",
        "governed_advisor",
        "agentsight_ui",
        "compliance_bridge",
        "langfuse_web",
        "langfuse_worker"
    ]
    
    # Verify each service has encryption_key in template block
    for service in services:
        assert re.search(
            rf'resource\s+"google_cloud_run_v2_service"\s+"{service}".*?template\s*{{.*?encryption_key\s*=\s*var\.enable_cmek\s*\?\s*google_kms_crypto_key\.cloudrun_cmek\[0\]\.id\s*:\s*null',
            main_config,
            re.DOTALL
        ), f"{service} service must reference CMEK encryption key in template block"


def test_cmek_variables_defined():
    """Verify enable_cmek variable is properly defined."""
    variables_config = read_terraform_file("variables.tf")

    # Verify enable_cmek variable exists
    assert 'variable "enable_cmek"' in variables_config
    
    # Verify description mentions CMEK and 90-day rotation
    assert re.search(
        r'variable\s+"enable_cmek".*?description\s*=.*?Customer-Managed Encryption Keys.*?90-day',
        variables_config,
        re.DOTALL | re.IGNORECASE
    ), "enable_cmek variable must describe CMEK with 90-day rotation"
    
    # Verify default is false
    assert re.search(
        r'variable\s+"enable_cmek".*?default\s*=\s*false',
        variables_config,
        re.DOTALL
    ), "enable_cmek must default to false"


def test_cmek_outputs_defined():
    """Verify CMEK outputs are properly defined."""
    outputs_config = read_terraform_file("outputs.tf")

    # Verify kms_key_ring_id output
    assert 'output "kms_key_ring_id"' in outputs_config
    assert "google_kms_key_ring.cloudrun_keyring[0].id" in outputs_config
    
    # Verify kms_crypto_key_id output
    assert 'output "kms_crypto_key_id"' in outputs_config
    assert "google_kms_crypto_key.cloudrun_cmek[0].id" in outputs_config
    
    # Verify conditional outputs based on enable_cmek
    assert outputs_config.count("var.enable_cmek ?") >= 2
