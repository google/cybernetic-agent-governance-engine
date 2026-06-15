"""Remote deployment verification script for the CAGE gateway.

Checks performed:
  1. Health checks — GET /, /health, /v1/models on the Cloud Run URL
     (or CAGE_GATEWAY_URL if set) to confirm the service is reachable.
  2. Seal enforcement (Track C, gates U-15 / U-16):
       U-15: unsigned POST to /governance/check → must return HTTP 403
       U-16: HMAC-SHA256-signed POST to /governance/check → must NOT return 403
     Requires CAGE_ROUTING_SEAL_SECRET to be set; skipped with a warning if absent.
  3. Langfuse posture — runs scripts/verify_langfuse_posture.py as a subprocess
     and reports pass/fail based on exit code.

Exit codes:
  0 — all checks passed
  1 — one or more checks failed
"""

import hashlib
import hmac
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

_SEAL_HEADER = "X-CAGE-Routing-Seal"


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
# Seal enforcement checks (Track C — U-15 / U-16)
# ---------------------------------------------------------------------------

def _compute_seal(secret: str, body_bytes: bytes) -> str:
    """Return the HMAC-SHA256 hex digest of *body_bytes* keyed with *secret*."""
    return hmac.new(
        secret.encode(),
        body_bytes,
        hashlib.sha256,
    ).hexdigest()


def check_seal_enforcement(gateway_url: str, secret: str) -> bool:
    """Verify that the gateway enforces the X-CAGE-Routing-Seal header.

    U-15: POST without seal → expect HTTP 403.
    U-16: POST with valid HMAC-SHA256 seal → expect any status except 403.

    Args:
        gateway_url: Base URL of the gateway (no trailing slash).
        secret:      Value of CAGE_ROUTING_SEAL_SECRET.

    Returns:
        True if both U-15 and U-16 pass, False otherwise.
    """
    url = f"{gateway_url}{_GOVERNANCE_CHECK_PATH}"
    body = _GOVERNANCE_CHECK_BODY
    headers_base = {"Content-Type": "application/json"}
    all_pass = True

    print(f"\n🔒 Seal enforcement checks against {url}")

    # ── U-15: unsigned request must be rejected with 403 ────────────────────
    print(f"  [U-15] POST (no {_SEAL_HEADER}) → expect 403 ...")
    try:
        resp = requests.post(url, data=body, headers=headers_base, timeout=10)
        status = resp.status_code
        if status == 403:
            print(f"  [PASS] U-15: unsigned request returned {status} (403 as expected)")
        else:
            print(
                f"  [FAIL] U-15: unsigned request returned {status} "
                f"(expected 403 — seal enforcement may be disabled)"
            )
            all_pass = False
    except Exception as exc:
        print(f"  [ERROR] U-15: connection error — {exc}")
        all_pass = False

    # ── U-16: signed request must NOT be rejected with 403 ──────────────────
    seal = _compute_seal(secret, body)
    signed_headers = {**headers_base, _SEAL_HEADER: seal}
    print(f"  [U-16] POST (with valid {_SEAL_HEADER}) → expect non-403 ...")
    try:
        resp = requests.post(url, data=body, headers=signed_headers, timeout=10)
        status = resp.status_code
        if status != 403:
            print(
                f"  [PASS] U-16: signed request returned {status} "
                f"(seal accepted — non-403 as expected)"
            )
        else:
            print(
                f"  [FAIL] U-16: signed request returned 403 "
                f"(seal was rejected — check CAGE_ROUTING_SEAL_SECRET matches the gateway)"
            )
            all_pass = False
    except Exception as exc:
        print(f"  [ERROR] U-16: connection error — {exc}")
        all_pass = False

    if all_pass:
        print("🔒 Seal enforcement checks PASSED.")
    else:
        print("❌ Seal enforcement checks FAILED.")
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

    # 2. Seal enforcement (U-15 / U-16)
    seal_secret = os.environ.get("CAGE_ROUTING_SEAL_SECRET", "")
    if not seal_secret:
        print(
            "\n⚠️  CAGE_ROUTING_SEAL_SECRET is not set — "
            "skipping seal enforcement checks (U-15 / U-16)."
        )
    else:
        results.append(check_seal_enforcement(BASE_URL, seal_secret))

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
