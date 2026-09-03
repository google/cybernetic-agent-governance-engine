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

import re

with open("src/gateway/governance/symbolic_governor.py") as f:
    content = f.read()

content = re.sub(
    r"\s+enable_legacy_trade_dispatch:\s*bool\s*\|\s*None\s*=\s*None,", "", content
)

content = re.sub(
    r'\s+# D4 fix: env-driven legacy dispatch flag.*?self\.enable_legacy_trade_dispatch.*?_env_flag\("ENABLE_LEGACY_TRADE_DISPATCH", default=True\)\n\s*\)\n',
    "\n",
    content,
    flags=re.DOTALL,
)

# Replace _legacy_financial_checks
content = re.sub(
    r"\s+async def _legacy_financial_checks\(.*?\)\s*->\s*tuple\[list\[Violation\],\s*str\s*\|\s*None\]:.*?(?=\n\s+async def evaluate_action\()",
    "\n",
    content,
    flags=re.DOTALL,
)

# And remove its call inside evaluate_action:
content = re.sub(
    r"\s+# --- LEGACY DISPATCH PATH \(DEPRECATED\) ---.*?# --- END LEGACY DISPATCH PATH ---",
    "",
    content,
    flags=re.DOTALL,
)

# Remove enable_legacy_trade_dispatch and its comment from __init__ docstring if exists

with open("src/gateway/governance/symbolic_governor.py", "w") as f:
    f.write(content)
