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

import subprocess
import sys

def run_command(command, description):
    print(f"\n--- Running: {description} ---")
    print(f"Command: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
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
    print("🚀 Starting Final Verification Suite 🚀\n")
    success = True

    # 1. Unit Tests
    if not run_command("pytest tests/ --maxfail=1 --disable-warnings -q", "Unit Tests (Pytest)"):
        success = False

    # 2. OPA Policy Checks (if a script or command exists, adjusting appropriately, assuming check_opa.sh or similar, using conftest if available)
    # This is a placeholder for the actual OPA test command in your repo.
    if not run_command("opa test tests/opa/ -v", "OPA Policy Checks"):
        print("   Note: Adjust the opa test path if your policies are stored elsewhere.")
        success = False

    # 3. NeMo Rail Tests
    if not run_command("nemoguardrails test -c src/governed_financial_advisor/governance/nemo_config tests/nemo_tests", "NeMo Guardrails Tests"):
         print("   Note: Adjust the nemoguardrails paths if needed.")
         success = False

    # 4. Red Team Live Run (Dry Run to preserve quota while verifying logic)
    if not run_command("python tests/red_team/adversarial_red_team.py --dry-run", "Red Team Adversarial Tests (Dry Run)"):
         success = False

    if success:
        print("\n🎉 All Verification Checks Passed! Conflict Resolution and Vibe Logic are intact. 🎉")
    else:
        print("\n⚠️ Verification Failed! Please review the errors above. ⚠️")
        sys.exit(1)

if __name__ == "__main__":
    main()
