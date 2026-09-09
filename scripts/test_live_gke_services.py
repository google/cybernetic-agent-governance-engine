#!/usr/bin/env python3
"""
Live GKE Service Smoke Test
Tests connectivity to all port-forwarded services from the staging cluster.
"""

import json
import os
import sys

import httpx
import redis


def test_redis():
    """Test Redis connectivity and configuration"""
    print("\n=== Redis (localhost:6379) ===")
    try:
        r = redis.Redis(
            host="localhost",
            port=6379,
            password=os.getenv("REDIS_PASSWORD"),
            decode_responses=True,
        )
        ping_result = r.ping()
        info = r.info("server")
        config_maxmemory = r.config_get("maxmemory")
        config_policy = r.config_get("maxmemory-policy")

        print(f"✓ PING: {ping_result}")
        print(f"✓ Redis Version: {info.get('redis_version', 'unknown')}")
        print(f"✓ Uptime: {info.get('uptime_in_seconds', 0)} seconds")
        print(f"✓ Max Memory: {config_maxmemory}")
        print(f"✓ Eviction Policy: {config_policy}")
        return True
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        return False


def test_http_service(name, url, timeout=5):
    """Test HTTP service connectivity"""
    print(f"\n=== {name} ({url}) ===")
    try:
        response = httpx.get(url, timeout=timeout)
        print(f"✓ Status: {response.status_code}")
        try:
            data = response.json()
            print(f"✓ Response: {json.dumps(data, indent=2)[:200]}")
        except:
            print(f"✓ Response (non-JSON): {response.text[:100]}")
        return response.status_code < 400
    except Exception as e:
        print(f"✗ {name} failed: {e}")
        return False


def test_langfuse_auth():
    """Test Langfuse API authentication"""
    print("\n=== Langfuse Authentication Test ===")
    try:
        # Test with valid credentials
        response = httpx.get(
            "http://localhost:3001/api/public/projects",
            auth=(os.getenv("LANGFUSE_PUBLIC_KEY"), os.getenv("LANGFUSE_SECRET_KEY")),
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

    # Test Redis
    results["redis"] = test_redis()

    # Test HTTP services
    results["opa"] = test_http_service("OPA", "http://localhost:8181/health")
    results["langfuse_health"] = test_http_service(
        "Langfuse Health", "http://localhost:3001/api/public/health"
    )
    results["gateway"] = test_http_service("Gateway", "http://localhost:8080/health")
    results["backend"] = test_http_service(
        "Backend/GFA", "http://localhost:8081/health"
    )
    results["compliance"] = test_http_service(
        "Compliance Bridge", "http://localhost:3002/health"
    )
    results["vllm_fast"] = test_http_service(
        "vLLM Fast", "http://localhost:8001/v1/models", timeout=10
    )
    results["vllm_reasoning"] = test_http_service(
        "vLLM Reasoning", "http://localhost:8000/v1/models", timeout=10
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
