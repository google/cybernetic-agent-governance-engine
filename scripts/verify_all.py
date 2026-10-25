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

import shlex
import subprocess
import sys


def run_command(command, description):
    print(f"\n--- Running: {description} ---")
    print(f"Command: {command}")
    try:
        result = subprocess.run(
            shlex.split(command) if isinstance(command, str) else command,
            check=True,
            text=True,
            capture_output=True,
        )
        print("✅ SUCCESS")
        print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print("❌ FAILED")
        print(f"Return Code: {e.returncode}")
        print(f"Stdout:\n{e.stdout.strip()}")
        print(f"Stderr:\n{e.stderr.strip()}")
        return False


def main():
    # DEP-23: Read CAGE_DEPLOYMENT_REGION and run jurisdiction-specific OPA suites.
    # This script covers universal ISO 42001 controls only. Jurisdiction-specific
    # OPA test suites (NIST SP 800-53, EU AI Act, MAS FEAT) are run conditionally
    # based on CAGE_DEPLOYMENT_REGION. R-7: scripts must be region-aware.
    import os

    cage_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "")
    print("🚀 Starting Final Verification Suite 🚀\n")
    if cage_region:
        print(
            f"[INFO] CAGE_DEPLOYMENT_REGION={cage_region} - jurisdiction-specific checks active"
        )
    else:
        print(
            "[INFO] CAGE_DEPLOYMENT_REGION not set - running universal ISO 42001 checks only"
        )
    print()
    success = True

    # 1. Unit Tests (Universal — ISO 42001 A.9.2 continuous monitoring)
    if not run_command(
        [
            "uv",
            "run",
            "pytest",
            "tests/",
            "-m",
            "unit and local",
            "--maxfail=1",
            "--disable-warnings",
            "-q",
        ],
        "Unit Tests (Pytest — Universal ISO 42001)",
    ):
        success = False

    # 2. OPA Policy Checks — Universal ISO 42001 trade governance policy
    if not run_command(
        ["opa", "test", "config/opa/", "-v"],
        "OPA Policy Checks (Universal ISO 42001)",
    ):
        print(
            "   Note: Adjust the opa test path if your policies are stored elsewhere."
        )
        success = False

    # 2a. US_FED-only OPA checks (NIST SP 800-53 / AI 600-1)
    if cage_region == "US_FED":
        print("\n--- US_FED jurisdiction-specific OPA checks (NIST SP 800-53) ---")
        if not run_command(
            ["opa", "test", "compliance/postures/us_fed/opa/", "-v"],
            "OPA Policy Checks (US_FED — NIST SP 800-53)",
        ):
            print(
                "   Note: Verify compliance/postures/us_fed/opa/ NIST-specific Rego tests."
            )
            # Non-fatal until US_FED OPA test suite is created
    # 2b. EU_ECB-only OPA checks (EU AI Act / GDPR / DORA)
    elif cage_region == "EU_ECB":
        print(
            "\n--- EU_ECB jurisdiction-specific OPA checks (EU AI Act / GDPR / DORA) ---"
        )
        if not run_command(
            ["opa", "test", "compliance/postures/eu_ecb/opa/", "-v"],
            "OPA Policy Checks (EU_ECB — EU AI Act)",
        ):
            print(
                "   Note: Create compliance/postures/eu_ecb/opa/ with EU AI Act Rego tests."
            )
            # Non-fatal until EU_ECB OPA test suite is created
    # 2c. APAC_MAS-only OPA checks (MAS FEAT / MAS Notice 655 / MAS TRM)
    elif cage_region == "APAC_MAS":
        print(
            "\n--- APAC_MAS jurisdiction-specific OPA checks (MAS FEAT / Notice 655) ---"
        )
        if not run_command(
            ["opa", "test", "compliance/postures/apac_mas/opa/", "-v"],
            "OPA Policy Checks (APAC_MAS — MAS FEAT)",
        ):
            print(
                "   Note: Create compliance/postures/apac_mas/opa/ with MAS FEAT Rego tests."
            )
            # Non-fatal until APAC_MAS OPA test suite is created

    # 3. NeMo Rail Tests (Colang syntax + action registry & gateway action tests)
    if not run_command(
        [
            "uv",
            "run",
            "pytest",
            "tests/test_nemo_action_registry.py",
            "tests/test_gateway_nemo_actions.py",
            "-q",
        ],
        "NeMo Guardrails Tests",
    ):
        print("   Note: Adjust the NeMo test paths if needed.")
        success = False

    # 4. Red Team Live Run (Dry Run to preserve quota while verifying logic)
    if not run_command(
        ["uv", "run", "python", "tests/red_team/adversarial_red_team.py", "--dry-run"],
        "Red Team Adversarial Tests (Dry Run)",
    ):
        success = False

    if success:
        print(
            "\n🎉 All Verification Checks Passed! Conflict Resolution and Vibe Logic are intact. 🎉"
        )
    else:
        print("\n⚠️ Verification Failed! Please review the errors above. ⚠️")
        sys.exit(1)


if __name__ == "__main__":
    main()
