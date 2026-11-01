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

"""Every server behind the workload-identity check runs with proxy headers off.

The check believes ``l5d-client-id`` only on a connection from inside the pod,
which it recognises by ``scope["client"]``
(``src/gateway/server/workload_identity.py``, POAM-2026-167). With uvicorn's
proxy-header handling on, a peer that uvicorn trusts could set that address
through ``X-Forwarded-For``, so every launch path must turn it off.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]
_LAUNCHERS = (
    "src/gateway/server/hybrid_server.py",
    "src/gateway/server/mcp_tool_server.py",
    "src/compliance_bridge/main.py",
)


def _uvicorn_run_calls(path: str) -> list[ast.Call]:
    tree = ast.parse((_REPO / path).read_text())
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "uvicorn"
    ]


def _command_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip().startswith("uvicorn ")]


@pytest.mark.parametrize("path", _LAUNCHERS)
def test_uvicorn_run_turns_proxy_headers_off(path: str) -> None:
    calls = _uvicorn_run_calls(path)
    assert calls, f"{path} no longer calls uvicorn.run"
    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        value = keywords.get("proxy_headers")
        assert isinstance(value, ast.Constant) and value.value is False, (
            f"{path}:{call.lineno} must pass proxy_headers=False to uvicorn.run"
        )


def test_the_gateway_container_launches_through_run_gateway_server() -> None:
    # run_gateway_server() is the uvicorn.run call checked above. A CMD that
    # started uvicorn directly would need the flag itself.
    cmd = [
        line
        for line in (_REPO / "src/gateway/Dockerfile").read_text().splitlines()
        if line.startswith("CMD ")
    ]
    assert len(cmd) == 1
    assert "src/gateway/server/hybrid_server.py" in cmd[0] or (
        "--no-proxy-headers" in cmd[0]
    )


def test_the_compliance_bridge_container_turns_proxy_headers_off() -> None:
    cmd = [
        line
        for line in (_REPO / "src/compliance_bridge/Dockerfile")
        .read_text()
        .splitlines()
        if line.startswith("CMD ")
    ]
    assert len(cmd) == 1
    assert "--no-proxy-headers" in cmd[0]


@pytest.mark.parametrize(
    "path",
    ("src/gateway/server/hybrid_server.py", "src/compliance_bridge/main.py"),
)
def test_documented_uvicorn_commands_turn_proxy_headers_off(path: str) -> None:
    lines = _command_lines((_REPO / path).read_text())
    assert lines, f"{path} no longer documents a uvicorn command"
    for line in lines:
        assert "--no-proxy-headers" in line, line.strip()


def _workflow_launches() -> list[tuple[str, str]]:
    # A shell command continued with a backslash counts as one line.
    launches: list[tuple[str, str]] = []
    for path in sorted((_REPO / ".github/workflows").glob("*.yml")):
        for line in path.read_text().replace("\\\n", " ").splitlines():
            if "uvicorn " in line and (
                "src.gateway." in line or "compliance_bridge." in line
            ):
                launches.append((path.name, " ".join(line.split())))
    return launches


def test_workflow_uvicorn_launches_turn_proxy_headers_off() -> None:
    launches = _workflow_launches()
    assert launches, "no workflow launches the gateway or the bridge with uvicorn"
    for name, line in launches:
        assert "--no-proxy-headers" in line, f"{name}: {line}"
