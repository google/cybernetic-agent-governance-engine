import re

with open("src/gateway/governance/symbolic_governor.py") as f:
    content = f.read()

content = re.sub(
    r'\s+enable_legacy_trade_dispatch:\s*bool\s*\|\s*None\s*=\s*None,',
    '',
    content
)

content = re.sub(
    r'\s+# D4 fix: env-driven legacy dispatch flag.*?self\.enable_legacy_trade_dispatch.*?_env_flag\("ENABLE_LEGACY_TRADE_DISPATCH", default=True\)\n\s*\)\n',
    '\n',
    content,
    flags=re.DOTALL
)

# Replace _legacy_financial_checks
content = re.sub(
    r'\s+async def _legacy_financial_checks\(.*?\)\s*->\s*tuple\[list\[Violation\],\s*str\s*\|\s*None\]:.*?(?=\n\s+async def evaluate_action\()',
    '\n',
    content,
    flags=re.DOTALL
)

# And remove its call inside evaluate_action:
content = re.sub(
    r'\s+# --- LEGACY DISPATCH PATH \(DEPRECATED\) ---.*?# --- END LEGACY DISPATCH PATH ---',
    '',
    content,
    flags=re.DOTALL
)

# Remove enable_legacy_trade_dispatch and its comment from __init__ docstring if exists

with open("src/gateway/governance/symbolic_governor.py", "w") as f:
    f.write(content)
