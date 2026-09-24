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

"""DNS Propagation and SSL Certificate Status Diagnostic Tool.

Validates that:
1. The domain FQDN resolves via DNS to the expected load balancer or ingress IP.
2. The Google Cloud Managed SSL Certificate (or GKE ManagedCertificate) has
   successfully validated and transitioned towards ACTIVE status.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


def check_dns_resolution(domain: str, expected_ip: Optional[str] = None) -> Tuple[bool, List[str], str]:
    """Check DNS resolution for the given domain and verify against expected IP."""
    clean_domain = domain.rstrip(".")
    try:
        addr_info = socket.getaddrinfo(clean_domain, 443, proto=socket.IPPROTO_TCP)
        resolved_ips = list(dict.fromkeys(info[4][0] for info in addr_info))
    except socket.gaierror as err:
        return False, [], f"DNS lookup failed for '{clean_domain}': {err}"

    if not resolved_ips:
        return False, [], f"No IP addresses resolved for '{clean_domain}'."

    if expected_ip:
        clean_expected = expected_ip.strip()
        if clean_expected not in resolved_ips:
            return False, resolved_ips, (
                f"Resolved IPs {resolved_ips} do not match expected IP '{clean_expected}'. "
                "DNS record may be pointing to the wrong target or still propagating."
            )
        return True, resolved_ips, f"Domain '{clean_domain}' correctly resolves to expected IP '{clean_expected}'."

    return True, resolved_ips, f"Domain '{clean_domain}' resolves to: {', '.join(resolved_ips)}"


def check_gcp_ssl_certificate(cert_name: str, project_id: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """Check GCP Compute Managed SSL Certificate status via gcloud CLI."""
    if not shutil.which("gcloud"):
        return False, "'gcloud' CLI is not installed or not in PATH.", {}

    cmd = ["gcloud", "compute", "ssl-certificates", "describe", cert_name, "--format=json"]
    if project_id:
        cmd.extend(["--project", project_id])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            return False, f"gcloud command failed (code {res.returncode}): {res.stderr.strip()}", {}
        data = json.loads(res.stdout)
    except Exception as err:
        return False, f"Failed to execute gcloud or parse output: {err}", {}

    managed = data.get("managed", {})
    status = managed.get("status", "UNKNOWN")
    domain_status = managed.get("domainStatus", {})

    msg = f"GCP SSL Certificate '{cert_name}' status: {status} (Domains: {domain_status})"
    is_active = (status == "ACTIVE")
    return is_active, msg, data


def check_gke_managed_certificate(cert_name: str, namespace: str = "governance-stack") -> Tuple[bool, str, Dict[str, Any]]:
    """Check GKE ManagedCertificate custom resource status via kubectl."""
    if not shutil.which("kubectl"):
        return False, "'kubectl' CLI is not installed or not in PATH.", {}

    cmd = ["kubectl", "get", "managedcertificate", cert_name, "-n", namespace, "-o", "json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            return False, f"kubectl command failed (code {res.returncode}): {res.stderr.strip()}", {}
        data = json.loads(res.stdout)
    except Exception as err:
        return False, f"Failed to execute kubectl or parse output: {err}", {}

    status_block = data.get("status", {})
    cert_status = status_block.get("certificateStatus", "Unknown")
    domain_status = status_block.get("domainStatus", [])

    msg = f"GKE ManagedCertificate '{cert_name}' status: {cert_status} (Domains: {domain_status})"
    is_active = (cert_status.lower() == "active")
    return is_active, msg, data


def main() -> int:
    """CLI entrypoint for DNS and SSL status diagnostics."""
    parser = argparse.ArgumentParser(
        description="Diagnose DNS propagation and managed SSL certificate status for CAGE targets."
    )
    parser.add_argument("--domain", required=True, help="Domain FQDN to check (e.g. gateway.example.com)")
    parser.add_argument("--expected-ip", help="Expected External Load Balancer or Ingress IP address")
    parser.add_argument("--cert-name", help="Name of GCP SSL certificate or GKE ManagedCertificate")
    parser.add_argument("--project", help="GCP project ID (for GCP compute certificate lookup)")
    parser.add_argument("--target", choices=["cloudrun", "gke", "dns-only"], default="dns-only",
                        help="Deployment target to check certificates for (cloudrun, gke, or dns-only)")
    parser.add_argument("--namespace", default="governance-stack", help="Kubernetes namespace for GKE target")
    parser.add_argument("--fail-on-warning", action="store_true", help="Exit with non-zero if certificate is still provisioning")

    args = parser.parse_args()

    print("=" * 60)
    print(f"CAGE DNS & SSL Certificate Status Diagnostic")
    print(f"Domain: {args.domain}")
    if args.expected_ip:
        print(f"Expected IP: {args.expected_ip}")
    print("=" * 60)

    # 1. Check DNS Resolution
    dns_ok, ips, dns_msg = check_dns_resolution(args.domain, args.expected_ip)
    if dns_ok:
        print(f"✅ DNS Resolution: SUCCESS")
        print(f"   {dns_msg}")
    else:
        print(f"❌ DNS Resolution: FAILED")
        print(f"   {dns_msg}")
        print("\nTroubleshooting Guidance:")
        print("  - Ensure your DNS A record has been created in Google Cloud DNS or your external provider.")
        print("  - If recently created, allow time for DNS TTL propagation (typically 5-300 seconds).")
        print("  - For maintainers using Argolis, confirm the 24h CAI sync and go/argolis delegation completed.")

    # 2. Check SSL Certificate (if requested)
    cert_ok = True
    if args.target != "dns-only" and args.cert_name:
        print("-" * 60)
        if args.target == "cloudrun":
            cert_active, cert_msg, _ = check_gcp_ssl_certificate(args.cert_name, args.project)
        else:
            cert_active, cert_msg, _ = check_gke_managed_certificate(args.cert_name, args.namespace)

        if cert_active:
            print(f"✅ SSL Certificate: ACTIVE")
            print(f"   {cert_msg}")
        else:
            print(f"⚠️ SSL Certificate: PENDING / PROVISIONING")
            print(f"   {cert_msg}")
            print("\nSSL Provisioning Guidance:")
            print("  - Managed certificates require DNS propagation to complete before Google's CA can issue the cert.")
            print("  - Provisioning typically takes 15-60 minutes after DNS resolution succeeds.")
            if args.fail_on_warning:
                cert_ok = False

    overall_success = dns_ok and cert_ok
    print("=" * 60)
    print(f"Diagnostic Result: {'PASSED' if overall_success else 'ATTENTION REQUIRED'}")
    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())

