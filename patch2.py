import re

with open("tests/test_inference_proxy_extended.py", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "def test_nemo_block_returns_403(proxy_deps" in line:
        lines[i] = line.replace("(proxy_deps):", "(proxy_deps, monkeypatch):")
    elif "mod.verify_input = AsyncMock" in line:
        lines[i] = line.replace("mod.verify_input =", 'monkeypatch.setattr("src.integrations.nemo.manager.verify_input",') + ")"
    elif "def test_nemo_exception_triggers_quota_rollback(proxy_deps" in line:
        lines[i] = line.replace("(proxy_deps):", "(proxy_deps, monkeypatch):")
    elif "mod.verify_input = _bad_verify" in line:
        lines[i] = line.replace("mod.verify_input = _bad_verify", 'monkeypatch.setattr("src.integrations.nemo.manager.verify_input", _bad_verify)')
    elif "def test_output_content_passed_through_nemo_filter(proxy_deps" in line:
        lines[i] = line.replace("(proxy_deps):", "(proxy_deps, monkeypatch):")
    elif "mod.verify_and_mask_output = _capture_mask" in line:
        lines[i] = line.replace("mod.verify_and_mask_output = _capture_mask", 'monkeypatch.setattr("src.integrations.nemo.manager.verify_and_mask_output", _capture_mask)')
    elif "def test_masked_content_replaces_original(proxy_deps" in line:
        lines[i] = line.replace("(proxy_deps):", "(proxy_deps, monkeypatch):")
    elif "mod.verify_and_mask_output = _mask" in line:
        lines[i] = line.replace("mod.verify_and_mask_output = _mask", 'monkeypatch.setattr("src.integrations.nemo.manager.verify_and_mask_output", _mask)')
    elif "def test_tool_call_arguments_filtered_by_nemo(proxy_deps" in line:
        lines[i] = line.replace("(proxy_deps):", "(proxy_deps, monkeypatch):")
    elif "mod.verify_and_mask_output = _capture_tool_mask" in line:
        lines[i] = line.replace("mod.verify_and_mask_output = _capture_tool_mask", 'monkeypatch.setattr("src.integrations.nemo.manager.verify_and_mask_output", _capture_tool_mask)')

with open("tests/test_inference_proxy_extended.py", "w") as f:
    f.writelines(lines)
