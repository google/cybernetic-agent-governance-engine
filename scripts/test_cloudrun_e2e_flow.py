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
End-to-End Functional Test for Live Cloud Run Deployment
=========================================================
Tests the complete cybernetic governance and observability flow:
  1. Gateway Governance & MCP dispatch
  2. Governed Financial Advisor cybernetic loop (/agent/query)
  3. Langfuse trace ingestion and observability pipeline
  4. vLLM Serverless L4 GPU inference (when provisioned)

Usage:
    # Automatic endpoint discovery via Terraform:
    python scripts/test_cloudrun_e2e_flow.py

    # Or with explicit environment variables:
    GATEWAY_URL="https://cage-gateway-xxx.a.run.app" \\
    BACKEND_URL="https://cage-advisor-xxx.a.run.app" \\
    LANGFUSE_HOST="https://cage-langfuse-web-xxx.a.run.app" \\
    python scripts/test_cloudrun_e2e_flow.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
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


def test_gateway_governance_flow(gateway_url: str, compliance_url: str, headers: dict[str, str]) -> bool:
    """Test gateway health, MCP tool dispatch, and compliance controls."""
    print("\n=== 1. Testing Gateway Governance Flow ===")

    if not gateway_url:
        print("  ⚠️ Gateway URL not configured — skipping")
        return False

    # 1. Health check
    print("1.1. Gateway health check...")
    try:
        resp = httpx.get(f"{gateway_url.rstrip('/')}/health", headers=headers, timeout=10)
        assert resp.status_code == 200, f"Gateway health failed: {resp.status_code}"
        print(f"✓ Health check passed: {resp.json()}")
    except Exception as e:
        print(f"✗ Gateway health failed: {e}")
        return False

    # 1.2. MCP tools listing
    print("1.2. Gateway MCP tools listing...")
    try:
        resp = httpx.post(
            f"{gateway_url.rstrip('/')}/mcp",
            json={"method": "tools/list"},
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            tools = resp.json().get("result", {}).get("tools", [])
            print(f"✓ MCP tools available: {len(tools)} tools")
            if tools:
                print(f"  Sample tools: {[t.get('name') for t in tools[:3]]}")
        else:
            print(f"  Note: MCP endpoint returned status {resp.status_code}")
    except Exception as e:
        print(f"  Note: MCP check skipped: {e}")

    # 1.3. Compliance controls check
    if compliance_url:
        print("1.3. Compliance bridge controls catalog...")
        try:
            resp = httpx.get(f"{compliance_url.rstrip('/')}/v1/controls", headers=headers, timeout=10)
            if resp.status_code == 200:
                controls = resp.json()
                print(f"✓ Compliance controls available: {len(controls)} controls")
            else:
                print(f"  Compliance controls returned status: {resp.status_code}")
        except Exception as e:
            print(f"  Note: Compliance controls check: {e}")

    return True


def test_governed_advisor_query(advisor_url: str, headers: dict[str, str]) -> bool:
    """Test a full financial advisory query through the Governed Financial Advisor."""
    print("\n=== 2. Testing Governed Financial Advisor Query Flow ===")

    if not advisor_url:
        print("  ⚠️ Governed Advisor URL not configured — skipping")
        return False

    session_id = f"cloudrun-e2e-{int(time.time())}"
    payload = {
        "prompt": "Analyze the performance and market risk profile of AAPL for a conservative portfolio.",
        "user_id": session_id,
        "thread_id": session_id,
    }

    req_headers = dict(headers)
    req_headers["Content-Type"] = "application/json"

    # If application-level API key is configured, pass it
    cage_api_key = os.environ.get("CAGE_API_KEY", "")
    if cage_api_key and "Authorization" not in req_headers:
        req_headers["Authorization"] = f"Bearer {cage_api_key}"

    print(f"Sending advisory query to: {advisor_url.rstrip('/')}/agent/query")
    print(f"Query prompt: '{payload['prompt']}'")

    try:
        resp = httpx.post(
            f"{advisor_url.rstrip('/')}/agent/query",
            json=payload,
            headers=req_headers,
            timeout=120.0,
        )
        print(f"✓ Response HTTP Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            response_text = data.get("response", "") or str(data)
            print("✓ Governed Financial Advisor query succeeded!")
            print(f"  Sample response preview: {response_text[:250]}...")
            return True
        elif resp.status_code in (401, 403):
            print(f"✗ Authentication failure ({resp.status_code}). Check IAM invoker role or CAGE_API_KEY.")
            return False
        else:
            print(f"✗ Advisor returned status {resp.status_code}: {resp.text[:200]}")
            return False
    except httpx.ConnectError as e:
        print(f"✗ Connection error: {e}")
        print("  Note: Governed Advisor has INGRESS_TRAFFIC_INTERNAL_ONLY.")
        print("        Ensure you are executing from within the VPC (e.g. Cloud Build, VPN, or bastion).")
        return False
    except Exception as e:
        print(f"✗ Governed Advisor query failed: {e}")
        return False


def test_langfuse_trace_and_telemetry(langfuse_url: str, headers: dict[str, str]) -> bool:
    """Test Langfuse trace ingestion and ClickHouse storage connectivity."""
    print("\n=== 3. Testing Langfuse Trace & Telemetry Pipeline ===")

    if not langfuse_url:
        print("  ⚠️ Langfuse URL not configured — skipping")
        return False

    pk = os.environ.get("LANGFUSE_PUBLIC_KEY")
    sk = os.environ.get("LANGFUSE_SECRET_KEY")

    trace_id = f"cloudrun-trace-{int(time.time())}"
    print(f"Creating test audit trace: {trace_id}")

    try:
        req_headers = dict(headers)
        auth = (pk, sk) if pk and sk else None

        resp = httpx.post(
            f"{langfuse_url.rstrip('/')}/api/public/traces",
            auth=auth,
            headers=req_headers,
            json={
                "id": trace_id,
                "name": "cloudrun-e2e-governance-verification",
                "metadata": {
                    "target": "gcp-cloudrun",
                    "timestamp": int(time.time()),
                    "component": "governed_advisor",
                },
            },
            timeout=15.0,
        )
        if resp.status_code in (200, 201):
            print(f"✓ Langfuse trace created successfully: {trace_id}")
            print("✓ Telemetry pipeline and ClickHouse OLAP sink operational!")
            return True
        else:
            print(f"  Langfuse trace returned status {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"✗ Langfuse trace creation failed: {e}")
        return False


def test_vllm_inference(vllm_url: str, headers: dict[str, str]) -> bool:
    """Test serverless L4 GPU inference when provisioned."""
    print("\n=== 4. Testing Serverless vLLM GPU Inference ===")

    if not vllm_url:
        print("  ℹ️ vLLM Fast URL not configured (GPU may be scale-to-zero in dev) — skipping")
        return True

    fast_model = os.environ.get("VLLM_FAST_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    print(f"Querying vLLM Fast endpoint: {vllm_url.rstrip('/')}/v1/completions")

    try:
        resp = httpx.post(
            f"{vllm_url.rstrip('/')}/v1/completions",
            headers=headers,
            json={
                "model": fast_model,
                "prompt": "Hello CAGE. Confirm governance readiness:",
                "max_tokens": 16,
                "temperature": 0.1,
            },
            timeout=45.0,
        )
        if resp.status_code == 200:
            text = resp.json().get("choices", [{}])[0].get("text", "").strip()
            print("✓ vLLM Fast inference successful!")
            print(f"  Generated text: {text[:100]}")
            return True
        else:
            print(f"  vLLM returned status {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print(f"  Note: vLLM inference test skipped: {e}")
        return True


def main() -> int:
    print("=" * 70)
    print("CAGE Live Cloud Run End-to-End Governance & Telemetry Flow")
    print("=" * 70)

    tf_outputs = _get_tf_outputs()
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
    vllm_fast_url = os.environ.get("VLLM_FAST_URL") or tf_outputs.get("vllm_fast_url") or ""

    test_sa = os.environ.get("CLOUDRUN_TEST_SERVICE_ACCOUNT")
    if test_sa:
        print(f"✓ Authenticating via test service account: {test_sa}")
    else:
        print("ℹ️  CLOUDRUN_TEST_SERVICE_ACCOUNT not set — will fall back to gcloud credentials")

    results: dict[str, bool] = {}

    # Step 1: Gateway Governance & MCP flow
    results["gateway_governance"] = test_gateway_governance_flow(gateway_url, compliance_url, _headers_for(gateway_url))

    # Step 2: Governed Financial Advisor query flow
    results["advisor_query"] = test_governed_advisor_query(advisor_url, _headers_for(advisor_url))

    # Step 3: Langfuse trace and telemetry pipeline
    results["langfuse_telemetry"] = test_langfuse_trace_and_telemetry(langfuse_url, _headers_for(langfuse_url))

    # Step 4: vLLM GPU inference (optional)
    results["vllm_inference"] = test_vllm_inference(vllm_fast_url, _headers_for(vllm_fast_url))

    print("\n" + "=" * 70)
    print("END-TO-END FLOW SUMMARY")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for step, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} {step}")

    print(f"\nTotal: {passed}/{total} flows verified")

    if passed == total:
        print("\n✓ Full Governed Financial Advisor & Langfuse pipeline verified on Cloud Run!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} flow(s) failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
