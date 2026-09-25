#!/usr/bin/env python3
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
Live Cloud Run Service Smoke Test
=================================
Tests connectivity, health, and IAM invocation across all deployed CAGE services
in Google Cloud Run (infra/targets/gcp-cloudrun).

Usage:
    # 1. Automatic endpoint discovery via Terraform outputs:
    python scripts/test_live_cloudrun_services.py

    # 2. Or explicit environment overrides:
    GATEWAY_URL="https://cage-gateway-xxx.a.run.app" \\
    BACKEND_URL="https://cage-advisor-xxx.a.run.app" \\
    COMPLIANCE_BRIDGE_URL="https://cage-compliance-xxx.a.run.app" \\
    python scripts/test_live_cloudrun_services.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import httpx


def _get_tf_outputs() -> dict[str, Any]:
    """Retrieve outputs from infra/targets/gcp-cloudrun if Terraform state exists."""
    tf_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "infra",
        "targets",
        "gcp-cloudrun",
    )
    if not os.path.isdir(tf_dir):
        return {}
    try:
        res = subprocess.run(
            ["terraform", f"-chdir={tf_dir}", "output", "-json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0 and res.stdout.strip():
            raw = json.loads(res.stdout)
            return {k: v.get("value") for k, v in raw.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


_token_cache: dict[str, str] = {}
_warned_personal_creds = False


def _get_identity_token(audience: str | None = None) -> str | None:
    """Fetch IAM identity token for authenticating to Cloud Run services."""
    global _warned_personal_creds
    cache_key = audience or "default"
    if cache_key in _token_cache:
        return _token_cache[cache_key]

    token = os.environ.get("CLOUDRUN_IDENTITY_TOKEN") or os.environ.get("GCP_IDENTITY_TOKEN")
    if token:
        _token_cache[cache_key] = token.strip()
        return token.strip()

    test_sa = os.environ.get("CLOUDRUN_TEST_SERVICE_ACCOUNT")
    if test_sa:
        # Use iamcredentials API with active gcloud access token to mint ID token for test SA
        try:
            acc_cmd = ["gcloud", "auth", "print-access-token"]
            acc_res = subprocess.run(acc_cmd, capture_output=True, text=True, timeout=10)
            if acc_res.returncode == 0 and acc_res.stdout.strip():
                access_token = acc_res.stdout.strip().splitlines()[-1]
                aud = audience or "https://iam.googleapis.com/"
                payload = {"audience": aud, "includeEmail": True}
                url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{test_sa}:generateIdToken"
                resp = httpx.post(
                    url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    json=payload,
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    id_token = resp.json().get("token")
                    if id_token:
                        _token_cache[cache_key] = id_token
                        return id_token
        except Exception:
            pass

        # Fallback to gcloud CLI impersonation
        try:
            cmd = ["gcloud", "auth", "print-identity-token", f"--impersonate-service-account={test_sa}"]
            if audience:
                cmd.append(f"--audiences={audience}")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                token = res.stdout.strip().splitlines()[-1]
                _token_cache[cache_key] = token
                return token
        except Exception:
            pass
    else:
        if not _warned_personal_creds:
            print("  ⚠️  WARNING: Using personal gcloud credentials (set CLOUDRUN_TEST_SERVICE_ACCOUNT for production testing)")
            _warned_personal_creds = True
        try:
            cmd = ["gcloud", "auth", "print-identity-token"]
            if audience:
                cmd.extend([f"--audiences={audience}"])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                token = res.stdout.strip().splitlines()[-1]
                _token_cache[cache_key] = token
                return token
        except Exception:
            pass
    return None


def _headers_for(url: str) -> dict[str, str]:
    """Return Authorization header with identity token scoped to destination origin."""
    if not url:
        return {}
    parts = url.split("/")
    origin = f"{parts[0]}//{parts[2]}" if len(parts) >= 3 else url
    token = _get_identity_token(audience=origin)
    return {"Authorization": f"Bearer {token}"} if token else {}


def test_http_service(
    name: str,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    expected_status: tuple[int, ...] = (200,),
) -> bool:
    """Test HTTP connectivity and status code for a Cloud Run service."""
    print(f"\n=== {name} ({url}) ===")
    if not url:
        print("  ⚠️ URL not configured — skipping")
        return False

    req_headers = dict(headers if headers is not None else _headers_for(url))
    try:
        response = httpx.get(url, headers=req_headers, timeout=timeout, follow_redirects=True)
        print(f"✓ Status: {response.status_code}")
        try:
            data = response.json()
            print(f"✓ Response: {json.dumps(data, indent=2)[:200]}")
        except Exception:
            print(f"✓ Response (non-JSON): {response.text[:100]}")

        success = response.status_code in expected_status
        if not success:
            print(f"✗ Expected {expected_status}, got {response.status_code}")
        return success
    except httpx.ConnectError as e:
        print(f"✗ Connection error (service may be internal-only or VPC unreachable): {e}")
        return False
    except Exception as e:
        print(f"✗ Request failed: {e}")
        return False


def main() -> int:
    print("=" * 65)
    print("CAGE Live Cloud Run Service Smoke Test")
    print("=" * 65)

    tf_outputs = _get_tf_outputs()
    if tf_outputs:
        print(f"ℹ️  Discovered {len(tf_outputs)} Terraform outputs from gcp-cloudrun")
    else:
        print("ℹ️  No Terraform outputs found — falling back to environment variables")

    # Resolve endpoints (env vars win, followed by terraform outputs)
    gateway_url = os.environ.get("GATEWAY_URL") or tf_outputs.get("gateway_url") or ""
    advisor_url = (
        os.environ.get("BACKEND_URL")
        or os.environ.get("ADVISOR_URL")
        or tf_outputs.get("governed_advisor_url")
        or ""
    )
    compliance_url = (
        os.environ.get("COMPLIANCE_BRIDGE_URL") or tf_outputs.get("compliance_bridge_url") or ""
    )
    langfuse_url = (
        os.environ.get("LANGFUSE_HOST")
        or os.environ.get("LANGFUSE_WEB_URL")
        or tf_outputs.get("langfuse_web_url")
        or ""
    )
    agentsight_url = (
        os.environ.get("AGENTSIGHT_UI_URL") or tf_outputs.get("agentsight_ui_url") or ""
    )
    vllm_fast_url = (
        os.environ.get("VLLM_FAST_URL") or tf_outputs.get("vllm_fast_url") or ""
    )

    test_sa = os.environ.get("CLOUDRUN_TEST_SERVICE_ACCOUNT")
    if test_sa:
        print(f"✓ Authenticating via test service account: {test_sa}")
    else:
        print("ℹ️  CLOUDRUN_TEST_SERVICE_ACCOUNT not set — will fall back to gcloud credentials")

    results: dict[str, bool] = {}

    # 1. Gateway (Public / Cloud Load Balancer / Direct)
    if gateway_url:
        results["gateway_health"] = test_http_service(
            "Gateway Health",
            f"{gateway_url.rstrip('/')}/health",
            headers=_headers_for(gateway_url),
        )
    else:
        print("\n⚠️ Gateway URL not found (set GATEWAY_URL)")

    # 2. Governed Financial Advisor Backend
    if advisor_url:
        results["advisor_health"] = test_http_service(
            "Governed Financial Advisor",
            f"{advisor_url.rstrip('/')}/health",
            headers=_headers_for(advisor_url),
        )

    # 3. Compliance Bridge
    if compliance_url:
        results["compliance_bridge_health"] = test_http_service(
            "Compliance Bridge Health",
            f"{compliance_url.rstrip('/')}/health",
            headers=_headers_for(compliance_url),
        )
        results["compliance_bridge_controls"] = test_http_service(
            "Compliance Bridge Controls",
            f"{compliance_url.rstrip('/')}/v1/controls",
            headers=_headers_for(compliance_url),
        )

    # 4. Langfuse Web
    if langfuse_url:
        results["langfuse_health"] = test_http_service(
            "Langfuse Web Health",
            f"{langfuse_url.rstrip('/')}/api/public/health",
            headers=_headers_for(langfuse_url),
        )
        # Check Langfuse API key auth if provided
        pk = os.environ.get("LANGFUSE_PUBLIC_KEY")
        sk = os.environ.get("LANGFUSE_SECRET_KEY")
        if pk and sk:
            print("\n=== Langfuse API Key Authentication ===")
            try:
                lf_resp = httpx.get(
                    f"{langfuse_url.rstrip('/')}/api/public/projects",
                    auth=(pk, sk),
                    timeout=10,
                )
                print(f"✓ Langfuse Auth Status: {lf_resp.status_code}")
                results["langfuse_auth"] = lf_resp.status_code == 200
            except Exception as e:
                print(f"✗ Langfuse auth request failed: {e}")
                results["langfuse_auth"] = False

    # 5. AgentSight UI
    if agentsight_url:
        results["agentsight_ui"] = test_http_service(
            "AgentSight UI",
            agentsight_url,
            headers=_headers_for(agentsight_url),
            expected_status=(200, 301, 302, 401),
        )

    # 6. vLLM Fast (Optional GPU)
    if vllm_fast_url:
        results["vllm_fast"] = test_http_service(
            "vLLM Fast Model",
            f"{vllm_fast_url.rstrip('/')}/v1/models",
            headers=_headers_for(vllm_fast_url),
            expected_status=(200, 403),
            timeout=15.0,
        )

    # Summary
    print("\n" + "=" * 65)
    print("CLOUDRUN SMOKE TEST SUMMARY")
    print("=" * 65)

    if not results:
        print("✗ No services could be tested (missing endpoints).")
        return 1

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for service, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} {service}")

    print(f"\nTotal: {passed}/{total} checks passed")

    if passed == total:
        print("\n✓ All tested Cloud Run services are healthy and reachable!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} check(s) failed or were unreachable.")
        print("Note: Services with INGRESS_TRAFFIC_INTERNAL_ONLY require in-VPC reachability")
        print("      (e.g., Cloud Build, Cloud VPN, or an in-VPC bastion host).")
        return 1


if __name__ == "__main__":
    sys.exit(main())
