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

# ─── External HTTPS Load Balancer + Cloud Armor (B2 Boundary) ────────────────
#
# This file implements the B2 security boundary: external HTTPS load balancer
# with Cloud Armor WAF for OWASP CRS protection, rate limiting, and DDoS defense.
#
# Critical Ordering Constraint (B2 defect prevention):
# - The gateway service in main.tf MUST depend on the HTTPS forwarding rule
# - This ensures INTERNAL_AND_CLOUD_LOAD_BALANCING ingress is only applied AFTER
#   the load balancer exists, preventing production access severance

# ─── Static IP Address ────────────────────────────────────────────────────────

resource "google_compute_global_address" "gateway" {
  count   = var.enable_load_balancer ? 1 : 0
  name    = "cage-gateway-lb-ip-${var.environment}"
  project = var.project_id
}

# ─── Serverless Network Endpoint Group ────────────────────────────────────────

resource "google_compute_region_network_endpoint_group" "gateway_neg" {
  count                 = var.enable_load_balancer ? 1 : 0
  name                  = "cage-gateway-neg-${var.environment}"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  project               = var.project_id

  cloud_run {
    service = google_cloud_run_v2_service.gateway.name
  }
}

# ─── SSL Policy (Modern TLS) ──────────────────────────────────────────────────

resource "google_compute_ssl_policy" "modern_tls" {
  count           = var.enable_load_balancer ? 1 : 0
  name            = "cage-modern-tls-${var.environment}"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
  project         = var.project_id
}

# ─── Managed SSL Certificate ──────────────────────────────────────────────────

resource "google_compute_managed_ssl_certificate" "gateway" {
  count   = var.enable_load_balancer && var.gateway_domain != "" ? 1 : 0
  name    = "cage-gateway-cert-${var.environment}"
  project = var.project_id

  managed {
    domains = [var.gateway_domain]
  }
}

# ─── Backend Service ──────────────────────────────────────────────────────────

resource "google_compute_backend_service" "gateway" {
  count                 = var.enable_load_balancer ? 1 : 0
  name                  = "cage-gateway-backend-${var.environment}"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_name             = "http"
  timeout_sec           = 30
  project               = var.project_id

  backend {
    group = google_compute_region_network_endpoint_group.gateway_neg[0].id
  }

  # Cloud Armor security policy
  security_policy = google_compute_security_policy.gateway_armor[0].id

  # Identity-Aware Proxy (IAP) integration
  dynamic "iap" {
    for_each = var.enable_iap ? [1] : []
    content {
      oauth2_client_id     = var.iap_client_id
      oauth2_client_secret = var.iap_client_secret
    }
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

# ─── URL Map (HTTPS) ──────────────────────────────────────────────────────────

resource "google_compute_url_map" "gateway" {
  count           = var.enable_load_balancer ? 1 : 0
  name            = "cage-gateway-urlmap-${var.environment}"
  default_service = google_compute_backend_service.gateway[0].id
  project         = var.project_id
}

# ─── HTTPS Target Proxy ───────────────────────────────────────────────────────

resource "google_compute_target_https_proxy" "gateway" {
  count            = var.enable_load_balancer ? 1 : 0
  name             = "cage-gateway-https-proxy-${var.environment}"
  url_map          = google_compute_url_map.gateway[0].id
  ssl_certificates = var.gateway_domain != "" ? [google_compute_managed_ssl_certificate.gateway[0].id] : []
  ssl_policy       = google_compute_ssl_policy.modern_tls[0].id
  project          = var.project_id
}

# ─── Global Forwarding Rule (HTTPS) ───────────────────────────────────────────

resource "google_compute_global_forwarding_rule" "gateway_https" {
  count                 = var.enable_load_balancer ? 1 : 0
  name                  = "cage-gateway-https-${var.environment}"
  target                = google_compute_target_https_proxy.gateway[0].id
  port_range            = "443"
  ip_address            = google_compute_global_address.gateway[0].address
  load_balancing_scheme = "EXTERNAL_MANAGED"
  project               = var.project_id
}

# ─── HTTP→HTTPS Redirect ──────────────────────────────────────────────────────

resource "google_compute_url_map" "https_redirect" {
  count   = var.enable_load_balancer ? 1 : 0
  name    = "cage-gateway-https-redirect-${var.environment}"
  project = var.project_id

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "https_redirect" {
  count   = var.enable_load_balancer ? 1 : 0
  name    = "cage-gateway-http-proxy-${var.environment}"
  url_map = google_compute_url_map.https_redirect[0].id
  project = var.project_id
}

resource "google_compute_global_forwarding_rule" "gateway_http" {
  count                 = var.enable_load_balancer ? 1 : 0
  name                  = "cage-gateway-http-${var.environment}"
  target                = google_compute_target_http_proxy.https_redirect[0].id
  port_range            = "80"
  ip_address            = google_compute_global_address.gateway[0].address
  load_balancing_scheme = "EXTERNAL_MANAGED"
  project               = var.project_id
}
