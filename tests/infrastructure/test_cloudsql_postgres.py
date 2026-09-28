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

"""Static architecture gate: Cloud SQL PostgreSQL and Langfuse IAM authn (Track 6c / §2.5).

Enforces:
1. In-cluster Helm PostgreSQL module is deleted from the GKE target (§2.5).
2. Cloud SQL PostgreSQL instance is provisioned via module "cloudsql_postgres" with:
   - PG15 (POSTGRES_15)
   - Private IP (authorized_network = var.network, ipv4_enabled = false)
   - ENCRYPTED_ONLY ssl_mode
   - Posture matrix tiers (§1.1): dev (db-f1-micro), staging (db-g1-small), prod (db-custom-2-7680, PITR, HA)
   - IAM authentication enabled (cloudsql.iam_authentication = on, CLOUD_IAM_SERVICE_ACCOUNT)
3. Langfuse connects through the Cloud SQL Auth Proxy sidecar with --auto-iam-authn (§2.5).
4. Zero static database passwords:
   - No static password generated or passed to Cloud SQL
   - <PG_PASSWORD> placeholder removed from manifests
   - DATABASE_URL uses localhost:5432 with encoded IAM service account user
5. Workload Identity and IAM role separation for Langfuse:
   - Dedicated GSA and KSA bound via roles/iam.workloadIdentityUser
   - Granted roles/cloudsql.client and roles/cloudsql.instanceUser
   - Zero KMS signing roles
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE_MAIN = _REPO / "infra/targets/gcp-gke/main.tf"
_GKE_IAM = _REPO / "infra/targets/gcp-gke/iam.tf"
_GKE_OUTPUTS = _REPO / "infra/targets/gcp-gke/outputs.tf"
_CLOUDSQL_MAIN = _REPO / "infra/modules/cloudsql_postgres/main.tf"
_CLOUDSQL_VARS = _REPO / "infra/modules/cloudsql_postgres/variables.tf"
_LANGFUSE_STACK_MAIN = _REPO / "infra/modules/langfuse_stack/main.tf"
_LANGFUSE_STACK_VARS = _REPO / "infra/modules/langfuse_stack/variables.tf"
_LANGFUSE_DB_SECRETS = _REPO / "deployment/k8s/langfuse-db-secrets.yaml"
_LANGFUSE_WEB_YAML = _REPO / "deployment/k8s/langfuse-web.yaml"
_LANGFUSE_WORKER_YAML = _REPO / "deployment/k8s/langfuse-worker.yaml"


def _extract_module_block(name: str, text: str) -> str:
    start_str = f'module "{name}" {{'
    start = text.find(start_str)
    assert start != -1, f"module '{name}' not found"
    pos = start + len(start_str)
    depth = 1
    while pos < len(text) and depth > 0:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


def test_in_cluster_helm_postgres_deleted() -> None:
    """§2.5: In-cluster Helm PostgreSQL module must be deleted from GKE target."""
    gke_main = _GKE_MAIN.read_text()
    assert 'source = "../../modules/postgres_db"' not in gke_main, (
        "In-cluster postgres_db module still referenced in gcp-gke/main.tf"
    )


def test_cloudsql_postgres_module_configured() -> None:
    """§2.5: Managed Cloud SQL PostgreSQL module must be declared in GKE target."""
    gke_main = _GKE_MAIN.read_text()
    assert 'module "cloudsql_postgres"' in gke_main
    block = _extract_module_block("cloudsql_postgres", gke_main)

    assert 'source = "../../modules/cloudsql_postgres"' in block
    assert 'database_version   = "POSTGRES_15"' in block
    assert "authorized_network = var.network" in block
    assert 'user_type       = "CLOUD_IAM_SERVICE_ACCOUNT"' in block
    assert "enable_iam_auth = true" in block


def test_cloudsql_posture_matrix_tiers() -> None:
    """§1.1: Posture matrix specifies machine tiers and HA/PITR per environment."""
    gke_main = _GKE_MAIN.read_text()
    block = _extract_module_block("cloudsql_postgres", gke_main)

    # dev: db-f1-micro, ZONAL
    # staging: db-g1-small, ZONAL
    # prod: db-custom-2-7680, REGIONAL, PITR
    assert 'var.environment == "prod" ? "db-custom-2-7680"' in block
    assert '"db-g1-small"' in block
    assert "var.postgres_tier" in block
    assert 'enable_high_availability      = var.environment == "prod"' in block
    assert 'enable_point_in_time_recovery = var.environment == "prod"' in block


def test_cloudsql_module_enforces_iam_auth_and_encrypted_only() -> None:
    """§2.5: Module enforces private IP, ENCRYPTED_ONLY, and IAM database authn flag."""
    cloudsql_main = _CLOUDSQL_MAIN.read_text()
    assert "ipv4_enabled    = false" in cloudsql_main
    assert 'ssl_mode        = "ENCRYPTED_ONLY"' in cloudsql_main
    assert 'name  = "cloudsql.iam_authentication"' in cloudsql_main
    assert 'value = "on"' in cloudsql_main

    # PostgreSQL IAM user name trims .gserviceaccount.com suffix
    assert 'trimsuffix(var.user_name, ".gserviceaccount.com")' in cloudsql_main


def test_langfuse_stack_uses_cloudsql_proxy_sidecar() -> None:
    """§2.5: Langfuse web and worker connect via Cloud SQL Auth Proxy sidecar with --auto-iam-authn."""
    langfuse_main = _LANGFUSE_STACK_MAIN.read_text()

    # Cloud SQL Auth Proxy container in web and worker
    assert 'name  = "cloud-sql-proxy"' in langfuse_main
    assert '"--auto-iam-authn"' in langfuse_main
    assert '"--port=5432"' in langfuse_main
    assert '"--structured-logs"' in langfuse_main

    # Localhost connection URL for IAM authentication
    assert "postgresql://${local.encoded_iam_user}:unused@127.0.0.1:5432/" in langfuse_main
    assert "sslmode=disable" in langfuse_main

    # GKE target passes Cloud SQL parameters to langfuse module
    gke_main = _GKE_MAIN.read_text()
    lf_block = _extract_module_block("langfuse", gke_main)
    assert "enable_cloudsql_proxy    = true" in lf_block
    assert "cloudsql_connection_name = module.cloudsql_postgres.connection_name" in lf_block
    assert "cloudsql_iam_user        = module.cloudsql_postgres.iam_user_name" in lf_block
    assert "cloudsql_database_name   = module.cloudsql_postgres.database_name" in lf_block
    assert 'service_account_name     = kubernetes_service_account.workload["langfuse"].metadata[0].name' in lf_block


def test_no_static_db_password_anywhere() -> None:
    """Exit criteria (§6c): Langfuse up with no static DB password."""
    # Manifests must not contain the static placeholder
    secrets_yaml = _LANGFUSE_DB_SECRETS.read_text()
    assert "<PG_PASSWORD>" not in secrets_yaml
    assert "127.0.0.1:5432" in secrets_yaml

    # GKE main does not generate or pass random password
    gke_main = _GKE_MAIN.read_text()
    cs_block = _extract_module_block("cloudsql_postgres", gke_main)
    assert "user_password" not in cs_block
    assert 'user_type       = "CLOUD_IAM_SERVICE_ACCOUNT"' in cs_block


def test_langfuse_workload_identity_and_iam_grants() -> None:
    """§5.1: Langfuse KSA is bound to its own GSA and granted Cloud SQL roles."""
    iam_text = _GKE_IAM.read_text()

    # GSA defined
    assert 'resource "google_service_account" "langfuse"' in iam_text
    assert 'account_id   = local.sa_langfuse' in iam_text

    # Roles granted: Cloud SQL Client and Instance User
    assert 'resource "google_project_iam_member" "langfuse_cloudsql_client"' in iam_text
    assert 'role    = "roles/cloudsql.client"' in iam_text
    assert 'resource "google_project_iam_member" "langfuse_cloudsql_instance_user"' in iam_text
    assert 'role    = "roles/cloudsql.instanceUser"' in iam_text

    # Authoritative Workload Identity binding
    assert 'resource "google_service_account_iam_binding" "langfuse_workload_identity"' in iam_text

    # No KMS signing role on Langfuse
    assert "google_service_account.langfuse" not in (_REPO / "infra/targets/gcp-gke/kms_signing.tf").read_text()


def test_k8s_manifests_include_cloudsql_proxy_sidecar() -> None:
    """K8s raw manifests for Langfuse web and worker include cloud-sql-proxy container."""
    web_yaml = _LANGFUSE_WEB_YAML.read_text()
    worker_yaml = _LANGFUSE_WORKER_YAML.read_text()

    assert "name: cloud-sql-proxy" in web_yaml
    assert "--auto-iam-authn" in web_yaml
    assert "name: cloud-sql-proxy" in worker_yaml
    assert "--auto-iam-authn" in worker_yaml
