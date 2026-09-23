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
Cloud Run Load Balancer Infrastructure Tests (B2 Boundary).

Validates:
- Serverless NEG targeting gateway service
- Backend service with Cloud Armor policy
- HTTPS proxy with TLS 1.2 minimum
- HTTP→HTTPS redirect
- Conditional gateway ingress tightening (only when LB exists)
- Internal-only ingress for all non-gateway services
- OWASP CRS rules in Cloud Armor
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


def test_serverless_neg_targets_gateway_service():
    """Serverless NEG must target gateway Cloud Run service."""
    lb_config = read_terraform_file("load_balancer.tf")

    # Verify serverless NEG exists
    assert 'resource "google_compute_region_network_endpoint_group" "gateway_neg"' in lb_config
    
    # Verify network_endpoint_type = "SERVERLESS"
    assert 'network_endpoint_type = "SERVERLESS"' in lb_config
    
    # Verify cloud_run block references gateway service
    assert re.search(
        r'cloud_run\s*{[^}]*service\s*=\s*google_cloud_run_v2_service\.gateway\.name',
        lb_config,
        re.DOTALL
    ), "Serverless NEG must reference gateway service"


def test_backend_service_has_cloud_armor_policy():
    """Backend service must attach Cloud Armor security policy."""
    lb_config = read_terraform_file("load_balancer.tf")

    # Verify backend service exists
    assert 'resource "google_compute_backend_service" "gateway"' in lb_config
    
    # Verify protocol = "HTTPS"
    assert 'protocol              = "HTTPS"' in lb_config or 'protocol = "HTTPS"' in lb_config
    
    # Verify load_balancing_scheme = "EXTERNAL_MANAGED"
    assert 'load_balancing_scheme = "EXTERNAL_MANAGED"' in lb_config
    
    # Verify backend references NEG
    assert 'google_compute_region_network_endpoint_group.gateway_neg[0].id' in lb_config
    
    # Verify Cloud Armor policy is attached
    assert re.search(
        r'security_policy\s*=\s*google_compute_security_policy\.gateway_armor\[0\]\.id',
        lb_config
    ), "Backend service must attach Cloud Armor security policy"


def test_https_proxy_uses_tls_1_2_minimum():
    """HTTPS proxy must enforce TLS 1.2 minimum via SSL policy."""
    lb_config = read_terraform_file("load_balancer.tf")

    # Verify SSL policy exists
    assert 'resource "google_compute_ssl_policy" "modern_tls"' in lb_config
    
    # Verify profile = "MODERN"
    assert 'profile         = "MODERN"' in lb_config or 'profile = "MODERN"' in lb_config
    
    # Verify min_tls_version = "TLS_1_2"
    assert 'min_tls_version = "TLS_1_2"' in lb_config
    
    # Verify HTTPS proxy references SSL policy
    assert 'resource "google_compute_target_https_proxy" "gateway"' in lb_config
    assert re.search(
        r'ssl_policy\s*=\s*google_compute_ssl_policy\.modern_tls\[0\]\.id',
        lb_config
    ), "HTTPS proxy must reference modern TLS policy"


def test_http_redirects_to_https():
    """HTTP traffic must redirect to HTTPS with 301."""
    lb_config = read_terraform_file("load_balancer.tf")

    # Verify HTTP→HTTPS redirect URL map
    assert 'resource "google_compute_url_map" "https_redirect"' in lb_config
    assert 'default_url_redirect {' in lb_config
    assert 'https_redirect         = true' in lb_config or 'https_redirect = true' in lb_config
    assert 'redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"' in lb_config
    
    # Verify HTTP target proxy
    assert 'resource "google_compute_target_http_proxy" "https_redirect"' in lb_config
    
    # Verify HTTP forwarding rule on port 80
    assert 'resource "google_compute_global_forwarding_rule" "gateway_http"' in lb_config
    assert re.search(
        r'port_range\s*=\s*"80"',
        lb_config
    ), "HTTP forwarding rule must listen on port 80"


def test_gateway_ingress_tightening_is_conditional():
    """Gateway ingress must only tighten when load balancer is enabled."""
    main_config = read_terraform_file("main.tf")

    # Verify gateway has conditional ingress setting
    assert 'resource "google_cloud_run_v2_service" "gateway"' in main_config
    
    # Verify ingress is conditional on enable_load_balancer
    assert re.search(
        r'ingress\s*=\s*var\.enable_load_balancer\s*\?\s*"INGRESS_TRAFFIC_INTERNAL_AND_CLOUD_LOAD_BALANCING"\s*:\s*"INGRESS_TRAFFIC_ALL"',
        main_config
    ), "Gateway ingress must be conditional: LB traffic when enabled, all traffic when disabled"
    
    # Verify B2 ordering comment explains how circular dependency is avoided
    # (conditional count-based resources prevent cycle, no explicit depends_on needed)
    assert re.search(
        r'B2:.*ordering|Critical.*ordering',
        main_config,
        re.IGNORECASE
    ), "Must document B2 ordering constraint to prevent production access severance"


def test_internal_services_use_internal_only_ingress():
    """All non-gateway services must use INTERNAL_ONLY ingress."""
    main_config = read_terraform_file("main.tf")

    # Define internal services
    internal_services = [
        "governed_advisor",
        "agentsight_ui",
        "compliance_bridge",
        "langfuse_web",
        "langfuse_worker"
    ]

    for service in internal_services:
        # Verify service exists
        assert f'resource "google_cloud_run_v2_service" "{service}"' in main_config, \
            f"Service {service} not found"
        
        # Extract service block
        service_pattern = rf'resource "google_cloud_run_v2_service" "{service}".*?(?=resource\s+"|$)'
        service_match = re.search(service_pattern, main_config, re.DOTALL)
        assert service_match, f"Could not extract service block for {service}"
        
        service_block = service_match.group(0)
        
        # Verify INTERNAL_ONLY ingress
        assert re.search(
            r'ingress\s*=\s*"INGRESS_TRAFFIC_INTERNAL_ONLY"',
            service_block
        ), f"Service {service} must use INGRESS_TRAFFIC_INTERNAL_ONLY"


def test_cloud_armor_has_owasp_rules():
    """Cloud Armor policy must include OWASP CRS rules."""
    armor_config = read_terraform_file("cloud_armor.tf")

    # Verify Cloud Armor policy exists
    assert 'resource "google_compute_security_policy" "gateway_armor"' in armor_config

    # Define required OWASP CRS rules
    required_rules = [
        "xss-stable",          # Cross-Site Scripting
        "sqli-stable",         # SQL Injection
        "lfi-stable",          # Local File Inclusion
        "rce-stable",          # Remote Code Execution
        "rfi-stable",          # Remote File Inclusion
        "methodenforcement-stable",  # Method Enforcement
        "scannerdetection-stable",   # Scanner Detection
        "protocolattack-stable",     # Protocol Attack
        "php-stable",          # PHP Injection
        "sessionfixation-stable"     # Session Fixation
    ]

    for rule in required_rules:
        # Verify each rule uses evaluatePreconfiguredExpr
        assert re.search(
            rf'evaluatePreconfiguredExpr\([\'\"]{rule}[\'\"]',
            armor_config
        ), f"Cloud Armor must include OWASP CRS rule: {rule}"
        
        # Verify rule has deny action (action comes before expression in HCL)
        # Pattern: rule { action = "deny(403)" ... expression = "evaluatePreconfiguredExpr('rule-name')" }
        rule_pattern = rf'rule\s*{{[^}}]*action\s*=\s*"deny\(403\)"[^}}]*evaluatePreconfiguredExpr\([\'\"]{rule}[\'\"]\)'
        assert re.search(
            rule_pattern,
            armor_config,
            re.DOTALL
        ), f"OWASP rule {rule} must have deny(403) action"

    # Verify default allow rule (action comes before priority in HCL)
    assert re.search(
        r'action\s*=\s*"allow"[^}]*priority\s*=\s*2147483647',
        armor_config,
        re.DOTALL
    ), "Cloud Armor must have default allow rule at priority 2147483647"

    # Verify rate limiting (prod only)
    assert 'rate_based_ban' in armor_config
    assert 'enforce_on_key = "IP"' in armor_config
    assert re.search(
        r'for_each\s*=\s*var\.environment\s*==\s*"prod"\s*\?\s*\[1\]\s*:\s*\[\]',
        armor_config
    ), "Rate limiting must only be enabled in prod environment"
