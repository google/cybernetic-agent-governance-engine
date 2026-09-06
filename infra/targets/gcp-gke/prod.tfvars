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

# US_FED Production Environment Configuration (GCP-GKE Target)
#
# DEP-12: This file is explicitly scoped to CAGE_DEPLOYMENT_REGION=US_FED.
# For EU_ECB production deployments, use eu-prod.tfvars.
# For APAC_MAS production deployments, use apac-prod.tfvars.
#
# Jurisdiction: United States Federal
# Primary framework: NIST SP 800-53 Rev 5 HIGH + NIST AI 600-1 + FedRAMP
# Universal baseline: ISO 42001 (always active for all regions)
#
# Activate:
#   CAGE_DEPLOYMENT_REGION=US_FED ./deploy_all.sh --target gcp-gke --env prod \
#     --var-file=infra/targets/gcp-gke/prod.tfvars

# ─── GCP Project ──────────────────────────────────────────────────────────────
# REPLACE with your production project ID
project_id = "your-production-project"
region     = "us-central1"
zone       = "us-central1-a"

# ─── Cluster ──────────────────────────────────────────────────────────────────
cluster_name = "cage-prod"
environment  = "prod"
namespace    = "governance-stack"

# ─── Jurisdiction (DEP-12: explicit US_FED scope) ─────────────────────────────
# This must always be set explicitly — no default in variables.tf (DEP-09).
# Activates US_FED_BASELINE.json compliance posture and NIST SP 800-53 hardening.
# The Terraform precondition on the langfuse_events bucket (DEP-10) will validate
# that region = "us-central1" is consistent with cage_deployment_region = "US_FED".
cage_deployment_region = "US_FED"

# ─── Security Posture (US_FED Prod: NIST SP 800-53 + ISO 42001 baseline) ──────
# DEP-01: enable_nist_compliance is now only activated for US_FED deployments.
# EU_ECB and APAC_MAS use enable_eu_ecb_compliance / enable_apac_mas_compliance.
enable_nist_compliance     = true
enable_eu_ecb_compliance   = false
enable_apac_mas_compliance = false
# POAM-024: HA decoupled from compliance — set explicitly true for production
enable_high_availability       = true
enable_deletion_protection     = true
enable_binary_authorization    = true
enable_audit_logging           = true
enable_cmek                    = false # Enable when KMS key is configured
enable_private_master_endpoint = false # Enable when VPN is configured
enable_pod_security_standards  = true
pod_security_level             = "restricted"
enable_dataplane_v2            = true

# Prod: Lock down to corporate VPN only (REPLACE with your CIDR)
authorized_networks = [
  {
    cidr         = "10.0.0.0/8"
    display_name = "Corporate VPN"
  }
]

# CMEK: Uncomment when Cloud KMS key is created
# kms_key_id = "projects/your-project/locations/us-central1/keyRings/cage-prod/cryptoKeys/gke-disk"

# ─── High Availability (Prod: Multi-Zone, Larger Nodes) ──────────────────────

# Primary pool: Production-grade nodes
primary_node_pool_machine_type  = "e2-standard-8"
primary_node_pool_min_count     = 3 # HA requires 3+ nodes
primary_node_pool_max_count     = 10
primary_node_pool_initial_count = 3
primary_node_pool_disk_type     = "pd-ssd" # Faster

# GPU pool: Production L4 GPUs, always available, on-demand only
enable_gpu_node_pool        = true
gpu_type                    = "nvidia-l4" # Better than T4
gpu_count                   = 1
gpu_node_pool_machine_type  = "g2-standard-8"
gpu_node_pool_min_count     = 2 # Always-on for production
gpu_node_pool_max_count     = 5
gpu_node_pool_initial_count = 2
gpu_node_pool_spot          = false # on-demand — production workloads must not be preempted

# ─── Storage (Prod: Larger, Faster) ───────────────────────────────────────────
storage_class = "pd-ssd"

model_bucket_name = "" # Defaults to ${project_id}-models

# ─── Container Registry ───────────────────────────────────────────────────────
registry_url = "" # Defaults to gcr.io/${project_id}

# ─── GCP Features ─────────────────────────────────────────────────────────────
enable_gcs_fuse_csi = true

# ─── Deployment ───────────────────────────────────────────────────────────────
force_redeploy = false
