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

# ─── Cloud Armor Security Policy (WAF + DDoS Defense) ─────────────────────────
#
# Implements OWASP CRS protection, rate limiting, and adaptive DDoS defense.
# Priority ordering:
# - 1000: Block known malicious IPs
# - 2000-2900: OWASP CRS rules (XSS, SQLi, LFI, RCE, RFI, etc.)
# - 3000: Rate limiting (prod only)
# - 2147483647: Default allow

resource "google_compute_security_policy" "gateway_armor" {
  count   = var.enable_load_balancer ? 1 : 0
  name    = "cage-gateway-armor-${var.environment}"
  project = var.project_id

  # Adaptive Protection (Layer 7 DDoS Defense)
  dynamic "adaptive_protection_config" {
    for_each = var.enable_nist_compliance ? [1] : []
    content {
      layer_7_ddos_defense_config {
        enable = true
      }
    }
  }

  # Default allow rule (lowest priority)
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }

  # Block known malicious IPs
  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sourceiplist-known-malicious')"
      }
    }
    description = "Block known malicious IP addresses"
  }

  # OWASP CRS: Cross-Site Scripting (XSS)
  rule {
    action   = "deny(403)"
    priority = 2000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-stable')"
      }
    }
    description = "OWASP CRS: Block XSS attacks"
  }

  # OWASP CRS: SQL Injection (SQLi)
  rule {
    action   = "deny(403)"
    priority = 2100
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-stable')"
      }
    }
    description = "OWASP CRS: Block SQL injection attacks"
  }

  # OWASP CRS: Local File Inclusion (LFI)
  rule {
    action   = "deny(403)"
    priority = 2200
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-stable')"
      }
    }
    description = "OWASP CRS: Block local file inclusion attacks"
  }

  # OWASP CRS: Remote Code Execution (RCE)
  rule {
    action   = "deny(403)"
    priority = 2300
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-stable')"
      }
    }
    description = "OWASP CRS: Block remote code execution attacks"
  }

  # OWASP CRS: Remote File Inclusion (RFI)
  rule {
    action   = "deny(403)"
    priority = 2400
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-stable')"
      }
    }
    description = "OWASP CRS: Block remote file inclusion attacks"
  }

  # OWASP CRS: Method Enforcement
  rule {
    action   = "deny(403)"
    priority = 2500
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('methodenforcement-stable')"
      }
    }
    description = "OWASP CRS: Enforce allowed HTTP methods"
  }

  # OWASP CRS: Scanner Detection
  rule {
    action   = "deny(403)"
    priority = 2600
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-stable')"
      }
    }
    description = "OWASP CRS: Block vulnerability scanners"
  }

  # OWASP CRS: Protocol Attack
  rule {
    action   = "deny(403)"
    priority = 2700
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-stable')"
      }
    }
    description = "OWASP CRS: Block protocol attacks"
  }

  # OWASP CRS: PHP Injection
  rule {
    action   = "deny(403)"
    priority = 2800
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('php-stable')"
      }
    }
    description = "OWASP CRS: Block PHP injection attacks"
  }

  # OWASP CRS: Session Fixation
  rule {
    action   = "deny(403)"
    priority = 2900
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sessionfixation-stable')"
      }
    }
    description = "OWASP CRS: Block session fixation attacks"
  }

  # Rate Limiting (prod only, 100 req/min per IP, 10-min ban)
  dynamic "rule" {
    for_each = var.environment == "prod" ? [1] : []
    content {
      action   = "rate_based_ban"
      priority = 3000
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
        rate_limit_threshold {
          count        = 100
          interval_sec = 60
        }
        ban_duration_sec = 600
      }
      description = "Rate limit: 100 req/min per IP, 10-min ban on exceed"
    }
  }
}
