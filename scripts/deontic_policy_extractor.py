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

import os
import re
from pathlib import Path

# Configuration
INPUT_FILE = "docs/banking_regs.md"
OUTPUT_FILE = "config/opa/policies.rego"

TEMPLATE_HEADER = """package agent.governance

# Default to deny (Zero Trust Architecture)
default allow = false

# Stream A: Deontic Extraction (Compliance Rules)
"""

TEMPLATE_FOOTER = """
# Stream B: Systemic Derivation (Safety Constraints)
# Constraint: Agent SHALL NOT commit a transaction if the state is 'unstable'
deny[msg] {
    input.action == "commit"
    input.system_health < 0.9
    msg := "Systemic hazard detected: latency/health threshold exceeded."
}
"""

def extract_policies(text):
    policies = []

    # Simple heuristic extraction logic
    # 1. Identity Verification
    # Text: "The system **MUST** verify the identity of the user for any transaction amount greater than 1000 USD."
    if re.search(r"MUST\*\*? verify the identity.*greater than 1000", text, re.IGNORECASE | re.DOTALL):
        policies.append("""# Requirement: MUST verify identity for transactions > 1000
allow {
    input.action == "transfer_funds"
    input.amount <= 1000
    input.user_role == "verified"
}

allow {
    input.action == "transfer_funds"
    input.amount > 1000
    input.identity_verified == true
}""")

    # 2. Frozen Account
    # Text: "The agent **SHALL** deny any transaction if the account status is 'frozen'."
    if re.search(r"SHALL\*\*? deny.*account status.*frozen", text, re.IGNORECASE | re.DOTALL):
        policies.append("""# Requirement: SHALL deny if account is frozen
deny[msg] {
    input.account_status == "frozen"
    msg := "Account is frozen."
}""")

    # 3. OFAC Sanctions
    # Text: "For international transfers, the system **MUST** screen the beneficiary against the OFAC sanctions list."
    if re.search(r"MUST\*\*? screen.*OFAC", text, re.IGNORECASE | re.DOTALL):
        policies.append("""# Requirement: MUST screen against OFAC list
deny[msg] {
    input.is_international == true
    input.ofac_screened == false
    msg := "International transfer requires OFAC screening."
}""")

    # 4. Auth Token
    # Text: "Access to account details **MUST** require a valid session token signed by the auth provider."
    if re.search(r"MUST\*\*? require a valid session token", text, re.IGNORECASE | re.DOTALL):
        policies.append("""# Requirement: MUST require valid session token
allow {
    input.action == "view_account"
    input.valid_token == true
}""")

    # 5. Latency/Stability
    # Text: "The system **SHALL NOT** commit a transaction if the reported latency exceeds 200ms."
    if re.search(r"SHALL NOT\*\*? commit.*latency exceeds 200ms", text, re.IGNORECASE | re.DOTALL):
         policies.append("""# Requirement: SHALL NOT commit if latency > 200ms
deny[msg] {
    input.action == "commit"
    input.latency_ms > 200
    msg := "Latency violation."
}""")

    return policies

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Input file {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE) as f:
        content = f.read()

    policies = extract_policies(content)

    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        f.write(TEMPLATE_HEADER)
        f.write("\n\n".join(policies))
        f.write(TEMPLATE_FOOTER)

    print(f"✅ Generated OPA policies at {OUTPUT_FILE}")
    print(f"Extracted {len(policies)} policies.")

if __name__ == "__main__":
    main()
