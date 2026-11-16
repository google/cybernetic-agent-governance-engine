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

"""Static gate: the workload modules never turn telemetry content capture on.

The telemetry backend writes every raw event it receives to an event bucket that
is retention-locked outside staging. Neither workload module may therefore enable
HTTP body or GenAI message-content capture
(``OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY``,
``OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY``,
``OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT``), or capture a request
header that asserts who the end user is.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_MODULES = {
    "governed_advisor": _REPO / "infra/modules/governed_advisor/main.tf",
    "gateway": _REPO / "infra/modules/gateway/main.tf",
}
_CAPTURE_VARIABLES = (
    "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY",
    "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY",
    "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
)
_CAPTURED_REQUEST_HEADERS = "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST"
_IDENTITY_HEADER_TOKENS = ("principal", "email", "user-id", "authenticated-user")

# One env entry: ``name = "X"`` with its ``value = ...`` on the next line, in both
# the ``env {}`` block form (governed_advisor) and the object-list form (gateway).
_ENV_ENTRY = re.compile(
    r'name\s*=\s*"(?P<name>[A-Z0-9_]+)"\s*\n\s*value\s*=\s*(?P<value>[^\n]+)'
)


def _env_values(module: Path) -> dict[str, list[str]]:
    """Map each env var name in *module* to every raw value expression it is given."""
    values: dict[str, list[str]] = {}
    for match in _ENV_ENTRY.finditer(module.read_text(encoding="utf-8")):
        values.setdefault(match["name"], []).append(match["value"].strip())
    return values


@pytest.mark.parametrize("variable", _CAPTURE_VARIABLES)
@pytest.mark.parametrize("module", sorted(_MODULES))
def test_content_capture_variable_is_false(module: str, variable: str) -> None:
    values = _env_values(_MODULES[module]).get(variable)

    assert values, f"{module}/main.tf no longer sets {variable} explicitly"
    assert values == ['"false"'] * len(values), (
        f"{module}/main.tf sets {variable} to {values}: raw content must not reach "
        "the retention-locked telemetry event bucket"
    )


@pytest.mark.parametrize("module", sorted(_MODULES))
def test_no_identity_header_is_captured(module: str) -> None:
    (value,) = _env_values(_MODULES[module])[_CAPTURED_REQUEST_HEADERS]
    headers = [header.strip().lower() for header in value.strip('"').split(",")]

    assert headers, f"{module}/main.tf captures no request headers at all"
    assert [
        header
        for header in headers
        if any(token in header for token in _IDENTITY_HEADER_TOKENS)
    ] == []


def test_env_parser_reports_a_value_that_turns_capture_on(tmp_path: Path) -> None:
    """The gate would fail on ``"true"``: the parser reports the raw value."""
    module = tmp_path / "main.tf"
    module.write_text(
        "env {\n"
        '  name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"\n'
        '  value = "true"\n'
        "}\n"
        "{\n"
        '  name      = "OTEL_EXPORTER_OTLP_HEADERS"\n'
        "  valueFrom = {}\n"
        "}\n",
        encoding="utf-8",
    )

    assert _env_values(module) == {
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": ['"true"']
    }
