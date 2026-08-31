import re
with open("tests/conftest.py") as f:
    content = f.read()

# Add env vars
new_env = """os.environ.setdefault("CAGE_ENV", "test")
os.environ.setdefault("CAGE_ACTIVE_PLUGINS", "finance")
os.environ.setdefault("CAGE_OPA_DEFAULT_PATH", "src/cage_finance/opa")
"""

content = content.replace('os.environ.setdefault("CAGE_ENV", "test")', new_env)

with open("tests/conftest.py", "w") as f:
    f.write(content)
