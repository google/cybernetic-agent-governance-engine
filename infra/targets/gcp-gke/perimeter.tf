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

# ─── Track 6f Perimeter & Network Boundary Protection (§5.4) ──────────────────
# Consolidates VPC network (with GKE pod/service secondary ranges and PSA peering),
# Binary Authorization cluster policy, VPC Service Controls perimeter, Cloud Armor
# WAF security policy (attached to the GKE Ingress backend via BackendConfig), and
# Cloud DNS into the sole GKE deployment target.

# ─── 1. VPC Network with GKE Secondary Ranges & PSA Peering (§5.4) ────────────

module "vpc_network" {
  count  = var.create_vpc_network ? 1 : 0
  source = "../../modules/vpc_network"

  project_id           = var.project_id
  environment          = var.environment
  region               = var.region
  network_name         = var.network != "" && var.network != "default" ? var.network : "cage-vpc-${var.environment}"
  subnetwork_name      = var.subnetwork != "" && var.subnetwork != "default" ? var.subnetwork : "cage-subnet-${var.environment}"
  subnet_cidr          = var.subnet_cidr
  pod_cidr             = var.pod_cidr
  service_cidr         = var.service_cidr
  enable_audit_logging = var.enable_audit_logging
  enable_psa           = true
  enable_default_deny  = true
}

# ─── 2. Binary Authorization Cluster Policy (CM-7, SI-7, §1.1, §5.4) ──────────

data "google_kms_crypto_key_version" "binauthz_attestor" {
  count      = var.enable_binary_authorization ? 1 : 0
  crypto_key = google_kms_crypto_key.binauthz_attestor.id
  version    = 1
}

resource "google_container_analysis_note" "build_attestor_note" {
  count   = var.enable_binary_authorization ? 1 : 0
  name    = "cage-build-attestor-note-${var.environment}"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "CAGE Cloud Build Attestor (${var.environment})"
    }
  }
}

resource "google_binary_authorization_attestor" "build_attestor" {
  count   = var.enable_binary_authorization ? 1 : 0
  name    = "cage-build-attestor-${var.environment}"
  project = var.project_id

  attestation_authority_note {
    note_reference = google_container_analysis_note.build_attestor_note[0].name

    public_keys {
      id = data.google_kms_crypto_key_version.binauthz_attestor[0].id
      pkix_public_key {
        public_key_pem      = data.google_kms_crypto_key_version.binauthz_attestor[0].public_key[0].pem
        signature_algorithm = data.google_kms_crypto_key_version.binauthz_attestor[0].public_key[0].algorithm
      }
    }
  }
}

resource "google_binary_authorization_attestor_iam_member" "cloudbuild_attestor_viewer" {
  count    = var.enable_binary_authorization ? 1 : 0
  project  = var.project_id
  attestor = google_binary_authorization_attestor.build_attestor[0].name
  role     = "roles/binaryauthorization.attestorsViewer"
  member   = local.cloudbuild_member
}

resource "google_container_analysis_note_iam_member" "cloudbuild_note_attacher" {
  count   = var.enable_binary_authorization ? 1 : 0
  project = var.project_id
  note    = google_container_analysis_note.build_attestor_note[0].name
  role    = "roles/containeranalysis.notes.attacher"
  member  = local.cloudbuild_member
}

resource "google_binary_authorization_policy" "cluster_policy" {
  count   = var.enable_binary_authorization ? 1 : 0
  project = var.project_id

  global_policy_evaluation_mode = "ENABLE"

  # Allow GKE system images
  admission_whitelist_patterns {
    name_pattern = "gcr.io/gke-release/*"
  }
  admission_whitelist_patterns {
    name_pattern = "gcr.io/config-management-release/*"
  }
  admission_whitelist_patterns {
    name_pattern = "k8s.gcr.io/*"
  }
  admission_whitelist_patterns {
    name_pattern = "gke.gcr.io/*"
  }
  # Service mesh infrastructure (cert-manager and Linkerd - POAM-2026-080)
  admission_whitelist_patterns {
    name_pattern = "quay.io/jetstack/*"
  }
  admission_whitelist_patterns {
    name_pattern = "cr.l5d.io/*"
  }
  admission_whitelist_patterns {
    name_pattern = "cr.l5d.io/linkerd/*"
  }
  admission_whitelist_patterns {
    name_pattern = "ghcr.io/linkerd/*"
  }

  default_admission_rule {
    evaluation_mode         = "REQUIRE_ATTESTATION"
    enforcement_mode        = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [google_binary_authorization_attestor.build_attestor[0].name]
  }

  cluster_admission_rules {
    cluster                 = "${module.gke.cluster_location}.${var.cluster_name}"
    evaluation_mode         = "REQUIRE_ATTESTATION"
    enforcement_mode        = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [google_binary_authorization_attestor.build_attestor[0].name]
  }
}

# ─── 3. VPC Service Controls Perimeter (SC-7, AC-4, §5.4) ─────────────────────

resource "google_access_context_manager_access_policy" "cage_policy" {
  count  = var.enable_vpc_sc && var.organization_id != "" && var.access_policy_id == "" ? 1 : 0
  parent = "organizations/${var.organization_id}"
  title  = "CAGE Sovereign Governance Access Policy (${var.environment})"
}

locals {
  effective_access_policy_id = var.access_policy_id != "" ? var.access_policy_id : (
    length(google_access_context_manager_access_policy.cage_policy) > 0
    ? google_access_context_manager_access_policy.cage_policy[0].name
    : ""
  )
}

resource "google_access_context_manager_service_perimeter" "cage_perimeter" {
  count  = var.enable_vpc_sc && local.effective_access_policy_id != "" ? 1 : 0
  parent = "accessPolicies/${local.effective_access_policy_id}"
  name   = "accessPolicies/${local.effective_access_policy_id}/servicePerimeters/cage_${var.environment}_perimeter"
  title  = "CAGE Sovereign Service Perimeter (${var.environment})"

  status {
    resources = [
      "projects/${data.google_project.current.number}",
    ]

    restricted_services = [
      "storage.googleapis.com",
      "bigquery.googleapis.com",
      "container.googleapis.com",
      "secretmanager.googleapis.com",
      "cloudkms.googleapis.com",
      "sqladmin.googleapis.com",
      "redis.googleapis.com",
      "artifactregistry.googleapis.com",
      "containerfilesystem.googleapis.com",
      "binaryauthorization.googleapis.com",
    ]

    vpc_accessible_services {
      enable_restriction = true
      allowed_services   = ["RESTRICTED-SERVICES"]
    }
  }
}

# ─── 4. Cloud Armor WAF Policy for GKE Ingress Backend (SC-5, SC-7, SI-10, §5.4) ──

resource "google_compute_security_policy" "gateway_armor" {
  count       = var.enable_cloud_armor ? 1 : 0
  name        = "cage-gateway-armor-${var.environment}"
  project     = var.project_id
  description = "SC-5 / SC-7 / SI-10: Cloud Armor WAF and rate-limiting policy attached to the CAGE GKE Ingress backend (§5.4)"

  # Rule 1000: Rate-based ban (DoS protection — SC-5)
  rule {
    action   = "rate_based_ban"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      ban_duration_sec = 300
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
    description = "SC-5: Rate-limit per client IP (100 req/min, 5-min ban)"
  }

  # Rule 2000: Block SQL Injection (SI-10)
  rule {
    action   = "deny(403)"
    priority = 2000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-stable')"
      }
    }
    description = "SI-10: OWASP CRS SQL injection protection"
  }

  # Rule 2001: Block Cross-Site Scripting (SI-10)
  rule {
    action   = "deny(403)"
    priority = 2001
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-stable')"
      }
    }
    description = "SI-10: OWASP CRS XSS protection"
  }

  # Rule 2002: Block Remote Code Execution / Command Injection (SI-10)
  rule {
    action   = "deny(403)"
    priority = 2002
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-stable')"
      }
    }
    description = "SI-10: OWASP CRS RCE protection"
  }

  # Rule 2003: Block Local File Inclusion / Path Traversal (SI-10)
  rule {
    action   = "deny(403)"
    priority = 2003
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-stable')"
      }
    }
    description = "SI-10: OWASP CRS LFI protection"
  }

  # Default Rule: Allow legitimate traffic that passes WAF filters
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule after WAF evaluation"
  }
}

locals {
  # §5.4: GKE BackendConfig manifest binding Cloud Armor securityPolicy to the
  # gateway Service (matched by cloud.google.com/backend-config annotation in
  # deployment/k8s/gateway.yaml and deployment/k8s/ingress.yaml).
  gateway_backend_config_manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = "gateway-backend-config"
      namespace = var.namespace
      labels = {
        "app.kubernetes.io/managed-by" = "terraform"
        "cage.io/component"            = "perimeter-security"
      }
    }
    spec = {
      securityPolicy = {
        name = var.enable_cloud_armor ? google_compute_security_policy.gateway_armor[0].name : "cage-gateway-armor-${var.environment}"
      }
    }
  }
}

# ─── 5. Cloud DNS Managed Zone & Ingress A-Record (SC-8, SC-20, §5.4) ─────────
# Foundational persistent managed zone is looked up via data source (never destroyed
# on ephemeral teardown to prevent orphaned zone takeover).

resource "google_compute_global_address" "gateway_ingress_ip" {
  count   = var.enable_cloud_dns ? 1 : 0
  name    = "cage-gateway-ingress-ip-${var.environment}"
  project = var.project_id
}

data "google_dns_managed_zone" "cage_zone" {
  count   = var.enable_cloud_dns && var.dns_managed_zone_name != "" ? 1 : 0
  name    = var.dns_managed_zone_name
  project = var.project_id
}

resource "google_dns_record_set" "gateway_a_record" {
  count        = var.enable_cloud_dns && var.dns_managed_zone_name != "" && var.dns_domain_name != "" ? 1 : 0
  name         = endswith(var.dns_domain_name, ".") ? var.dns_domain_name : "${var.dns_domain_name}."
  managed_zone = data.google_dns_managed_zone.cage_zone[0].name
  type         = "A"
  ttl          = 300
  project      = var.project_id

  rrdatas = [google_compute_global_address.gateway_ingress_ip[0].address]
}
