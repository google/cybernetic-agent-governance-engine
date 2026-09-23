import re

with open("tests/test_telemetry_provider.py", "r") as f:
    content = f.read()

content = content.replace('_selective_import_error("remote")', '_selective_import_error("langfuse")')

with open("tests/test_telemetry_provider.py", "w") as f:
    f.write(content)
