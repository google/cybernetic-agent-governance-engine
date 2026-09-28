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

"""Remote deployment verification script for the CAGE gateway.

Checks performed:
  1. Health checks — GET /, /health, /v1/models on the Cloud Run URL
     (or CAGE_GATEWAY_URL if set) to confirm the service is reachable.
  2. Ingress identity enforcement (Track C, gates U-15 / U-16, POAM-2026-080):
       U-15: POST to /governance/check without a trusted mesh workload
             identity → must return HTTP 403 (deny by default)
       U-16: GET /health (open path) → must return HTTP 200
     The gateway authenticates callers by Linkerd mTLS workload identity, so
     this script — running outside the mesh — is by construction an
     unauthenticated caller. No secret is needed.
  3. Langfuse posture — runs scripts/verify_langfuse_posture.py as a subprocess
     and reports pass/fail based on exit code.

Exit codes:
  0 — all checks passed
  1 — one or more checks failed
"""

import json
import os
import subprocess
import sys

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# DEP-15: Remove hardcoded us-central1 fallback URL.
# The previous fallback silently verified the wrong (US) endpoint when
# CAGE_GATEWAY_URL was unset for EU_ECB or APAC_MAS deployments.
# R-7: deployment scripts must not embed region-specific hardcoded values.
_gateway_url = os.environ.get("CAGE_GATEWAY_URL", "")
if not _gateway_url:
    raise RuntimeError(
        "CAGE_GATEWAY_URL must be explicitly set before running verify_remote.py. "
        "There is no safe fallback URL — each deployment region has a different "
        "gateway endpoint. Set CAGE_GATEWAY_URL to the correct endpoint for your "
        "CAGE_DEPLOYMENT_REGION (US_FED, EU_ECB, or APAC_MAS)."
    )
BASE_URL = _gateway_url.rstrip("/")

_GOVERNANCE_CHECK_PATH = "/governance/check"
_GOVERNANCE_CHECK_BODY: bytes = json.dumps(
    {"tool_name": "verify_content_safety", "params": {}},
    separators=(",", ":"),
).encode()

_HEALTH_PATH = "/health"


# ---------------------------------------------------------------------------
# Health checks (existing — unchanged)
# ---------------------------------------------------------------------------


def verify_deployment() -> bool:
    """GET /, /health, /v1/models and confirm the service is reachable.

    Returns True if at least one endpoint responds with a non-5xx status.
    """
    print(f"\n🔍 Verifying deployment at {BASE_URL}...")
    endpoints = ["/", "/health", "/v1/models"]
    success = False

    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        try:
            print(f"  Testing {url}...")
            resp = requests.get(url, timeout=10)
            print(f"  Status: {resp.status_code}")
            if resp.status_code < 500:
                print("  ✅ Service is reachable.")
                success = True
            else:
                print("  ⚠️  Service returned server error.")
        except Exception as exc:
            print(f"  ❌ Failed to request {url}: {exc}")

    if success:
        print("🚀 Deployment verification PASSED (service is reachable).")
    else:
        print("❌ Deployment verification FAILED.")
    return success


# ---------------------------------------------------------------------------
# Ingress identity enforcement checks (Track C — U-15 / U-16)
# ---------------------------------------------------------------------------


def check_identity_enforcement(gateway_url: str) -> bool:
    """Verify the gateway refuses unauthenticated callers and keeps /health open.

    U-15: POST /governance/check with no trusted workload identity → expect 403.
    U-16: GET /health → expect 200 (open path, no identity required).

    Args:
        gateway_url: Base URL of the gateway (no trailing slash).

    Returns:
        True if both U-15 and U-16 pass, False otherwise.
    """
    all_pass = True
    print(f"\n🔒 Ingress identity checks against {gateway_url}")

    # ── U-15: unauthenticated call to a gated route must be refused ─────────
    url = f"{gateway_url}{_GOVERNANCE_CHECK_PATH}"
    print(f"  [U-15] POST {_GOVERNANCE_CHECK_PATH} (no workload identity) → expect 403 ...")
    try:
        resp = requests.post(
            url,
            data=_GOVERNANCE_CHECK_BODY,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        status = resp.status_code
        if status == 403:
            print(f"  [PASS] U-15: unauthenticated request returned {status} (refused)")
        else:
            print(
                f"  [FAIL] U-15: unauthenticated request returned {status} "
                "(expected 403 — check CAGE_TRUSTED_CLIENT_IDENTITIES and Linkerd "
                "mesh policy on the gateway)"
            )
            all_pass = False
    except Exception as exc:
        print(f"  [ERROR] U-15: connection error — {exc}")
        all_pass = False

    # ── U-16: the open health path must stay reachable ──────────────────────
    url = f"{gateway_url}{_HEALTH_PATH}"
    print(f"  [U-16] GET {_HEALTH_PATH} → expect 200 ...")
    try:
        resp = requests.get(url, timeout=10)
        status = resp.status_code
        if status == 200:
            print(f"  [PASS] U-16: {_HEALTH_PATH} returned {status}")
        else:
            print(
                f"  [FAIL] U-16: {_HEALTH_PATH} returned {status} "
                "(expected 200 — open-path list may be out of sync)"
            )
            all_pass = False
    except Exception as exc:
        print(f"  [ERROR] U-16: connection error — {exc}")
        all_pass = False

    if all_pass:
        print("🔒 Ingress identity checks PASSED.")
    else:
        print("❌ Ingress identity checks FAILED.")
    return all_pass


# ---------------------------------------------------------------------------
# Langfuse posture check
# ---------------------------------------------------------------------------


def check_langfuse_posture() -> bool:
    """Run scripts/verify_langfuse_posture.py and report pass/fail.

    Returns True if the subprocess exits with code 0, False otherwise.
    """
    print("\n📊 Langfuse posture check ...")
    script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "verify_langfuse_posture.py"
    )
    try:
        result = subprocess.run(
            [sys.executable, script, "--dry-run"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                print(f"  {line}")
        if result.stderr:
            for line in result.stderr.splitlines():
                print(f"  [stderr] {line}")
        if result.returncode == 0:
            print("📊 Langfuse posture check PASSED.")
            return True
        else:
            print(f"❌ Langfuse posture check FAILED (exit code {result.returncode}).")
            return False
    except FileNotFoundError:
        print(f"  [ERROR] Script not found: {script}")
        return False
    except subprocess.TimeoutExpired:
        print("  [ERROR] Langfuse posture check timed out after 60 s.")
        return False
    except Exception as exc:
        print(f"  [ERROR] Unexpected error running Langfuse posture check: {exc}")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Run all verification checks and return an exit code (0=pass, 1=fail)."""
    results: list[bool] = []

    # 1. Health checks
    results.append(verify_deployment())

    # 2. Ingress identity enforcement (U-15 / U-16)
    results.append(check_identity_enforcement(BASE_URL))

    # 3. Langfuse posture
    results.append(check_langfuse_posture())

    # Overall verdict
    print("\n" + "=" * 60)
    if all(results):
        print("✅ All verification checks PASSED — exit 0")
        return 0
    else:
        failed = results.count(False)
        print(f"❌ {failed} check(s) FAILED — exit 1")
        return 1


if __name__ == "__main__":
    sys.exit(main())
