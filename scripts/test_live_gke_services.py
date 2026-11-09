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
Live GKE Service Smoke Test
Tests connectivity to all port-forwarded services from the staging cluster.
"""

import json
import os
import subprocess
import sys

import httpx
import redis

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _get_deployment_replicas(
    deployment_name: str, namespace: str = "governance-stack"
) -> int | None:
    try:
        res = subprocess.run(
            [
                "kubectl",
                "get",
                "deploy",
                deployment_name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.spec.replicas}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip().isdigit():
            return int(res.stdout.strip())
    except Exception:
        pass
    return None


def test_redis():
    """Test Redis / Memorystore for Valkey connectivity and configuration"""
    print("\n=== Redis / Memorystore for Valkey ===")
    try:
        r = redis.Redis(
            host="localhost",
            port=6379,
            password=os.getenv("REDIS_PASSWORD"),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        ping_result = r.ping()
        info = r.info("server")
        config_maxmemory = r.config_get("maxmemory")
        config_policy = r.config_get("maxmemory-policy")

        print(f"✓ PING (localhost:6379): {ping_result}")
        print(f"✓ Redis Version: {info.get('redis_version', 'unknown')}")
        print(f"✓ Uptime: {info.get('uptime_in_seconds', 0)} seconds")
        print(f"✓ Max Memory: {config_maxmemory}")
        print(f"✓ Eviction Policy: {config_policy}")
        return True
    except Exception as local_err:
        print(
            f"  Info: localhost:6379 not forwarded ({local_err}); checking managed Memorystore PSC via gateway pod..."
        )
        try:
            script_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "smoke_test_memorystore_wait.py",
            )
            with open(script_path, encoding="utf-8") as fh:
                script_src = fh.read()
            res = subprocess.run(
                [
                    "kubectl",
                    "exec",
                    "-i",
                    "-n",
                    "governance-stack",
                    "deploy/gateway",
                    "-c",
                    "gateway",
                    "--",
                    "python3",
                    "-",
                    "--replicas",
                    "1",
                    "--timeout-ms",
                    "100",
                    "--tls",
                    "--iam-auth",
                ],
                input=script_src,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if res.returncode == 0:
                print(f"✓ Managed Memorystore PSC: {res.stdout.strip()}")
                return True
            print(
                f"✗ Managed Memorystore PSC check failed: {res.stderr.strip() or res.stdout.strip()}"
            )
            return False
        except Exception as e:
            print(f"✗ Redis / Memorystore connection failed: {e}")
            return False


def _cluster_reachable(namespace: str = "governance-stack") -> bool:
    """Return True if core gateway deployment is readable in the target namespace."""
    return _get_deployment_replicas("gateway", namespace=namespace) is not None


def test_opa_uds_sidecar(namespace: str = "governance-stack") -> bool:
    """Verify the in-pod OPA UDS sidecar (/var/run/opa/opa.sock) and /governance/jwks."""
    print("\n=== OPA UDS Sidecar (/var/run/opa/opa.sock) & Gateway JWKS ===")
    uds_probe = (
        "import http.client, json, socket, sys\n"
        "class UDSConn(http.client.HTTPConnection):\n"
        "    def connect(self):\n"
        "        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "        self.sock.settimeout(5)\n"
        "        self.sock.connect('/var/run/opa/opa.sock')\n"
        "c = UDSConn('localhost')\n"
        "c.request('GET', '/health')\n"
        "r = c.getresponse()\n"
        "r.read()\n"
        "if r.status != 200:\n"
        "    sys.exit(f'OPA UDS /health HTTP {r.status}')\n"
        "c.request('GET', '/v1/policies')\n"
        "r2 = c.getresponse()\n"
        "doc = json.loads(r2.read().decode('utf-8'))\n"
        "policies = doc.get('result') or []\n"
        "if r2.status != 200 or len(policies) == 0:\n"
        "    sys.exit(f'OPA UDS /v1/policies empty or HTTP {r2.status}')\n"
        "print(json.dumps({'uds_health': r.status, 'loaded_policies': len(policies)}))\n"
    )
    try:
        res = subprocess.run(
            [
                "kubectl",
                "exec",
                "-n",
                namespace,
                "deploy/gateway",
                "-c",
                "gateway",
                "--",
                "python3",
                "-c",
                uds_probe,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if res.returncode != 0:
            print(
                f"✗ OPA UDS sidecar check failed: {res.stderr.strip() or res.stdout.strip()}"
            )
            return False
        print(f"✓ OPA UDS sidecar: {res.stdout.strip()}")

        jwks_resp = httpx.get("http://localhost:8080/governance/jwks", timeout=5)
        if jwks_resp.status_code != 200:
            print(f"✗ Gateway /governance/jwks HTTP {jwks_resp.status_code}")
            return False
        keys = jwks_resp.json().get("keys", [])
        print(f"✓ Gateway /governance/jwks: {len(keys)} key(s) published")
        return len(keys) >= 1
    except Exception as e:
        print(f"✗ OPA UDS / Gateway JWKS check failed: {e}")
        return False


def test_http_service(
    name,
    url,
    timeout=5,
    deployment_name=None,
    required_env="REQUIRE_VLLM_GPUS",
):
    """Test HTTP service connectivity"""
    print(f"\n=== {name} ({url}) ===")
    try:
        response = httpx.get(url, timeout=timeout)
        print(f"✓ Status: {response.status_code}")
        try:
            data = response.json()
            print(f"✓ Response: {json.dumps(data, indent=2)[:200]}")
        except Exception:
            print(f"✓ Response (non-JSON): {response.text[:100]}")
        return response.status_code < 400
    except Exception as e:
        if deployment_name and os.getenv(required_env, "0") != "1":
            replicas = _get_deployment_replicas(deployment_name)
            if replicas == 0 or (replicas is None and _cluster_reachable()):
                state_desc = (
                    "scaled to 0 replicas"
                    if replicas == 0
                    else "not deployed (inference_backend=none)"
                )
                print(
                    f"✓ {name} {state_desc} in governance-stack (opt-in via {required_env}=1)"
                )
                return True
        print(f"✗ {name} failed: {e}")
        return False


def test_langfuse_auth():
    """Test Langfuse API authentication"""
    print("\n=== Langfuse Authentication Test ===")
    try:
        # Test with valid credentials
        response = httpx.get(
            "http://localhost:3001/api/public/projects",
            auth=(
                os.getenv("LANGFUSE_PUBLIC_KEY", ""),
                os.getenv("LANGFUSE_SECRET_KEY", ""),
            ),
            timeout=10,
        )
        print(f"✓ Auth Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Projects: {len(data.get('data', []))} found")
            return True
        return False
    except Exception as e:
        print(f"✗ Langfuse auth failed: {e}")
        return False


def main():
    print("=" * 60)
    print("CAGE Live GKE Service Smoke Test")
    print("=" * 60)

    results = {}

    # Test Redis / Memorystore
    results["redis"] = test_redis()

    # Test OPA UDS sidecar + HTTP services
    results["opa_uds"] = test_opa_uds_sidecar()
    results["langfuse_health"] = test_http_service(
        "Langfuse Health", "http://localhost:3001/api/public/health"
    )
    results["gateway"] = test_http_service("Gateway", "http://localhost:8080/health")
    results["backend"] = test_http_service(
        "Backend/GFA",
        "http://localhost:8081/health",
        deployment_name="governed-financial-advisor",
        required_env="REQUIRE_E2E_ADVISOR",
    )
    results["compliance"] = test_http_service(
        "Compliance Bridge", "http://localhost:3002/health"
    )
    results["vllm_fast"] = test_http_service(
        "vLLM Fast",
        "http://localhost:8001/v1/models",
        timeout=10,
        deployment_name="vllm-inference",
    )
    results["vllm_reasoning"] = test_http_service(
        "vLLM Reasoning",
        "http://localhost:8000/v1/models",
        timeout=10,
        deployment_name="vllm-reasoning",
    )

    # Test Langfuse authentication
    results["langfuse_auth"] = test_langfuse_auth()

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for service, success in results.items():
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} {service}")

    print(f"\nTotal: {passed}/{total} services passed")

    if passed == total:
        print("\n✓ All services are healthy!")
        return 0
    else:
        print(f"\n✗ {total - passed} service(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
