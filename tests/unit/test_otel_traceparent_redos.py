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

"""Regression tests for CVE-2026-126360 / GHSA-mf5v-w3w3-f6cg (`opentelemetry-api` ReDoS)."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import tomllib
from opentelemetry import trace
from starlette.requests import Request

from src.gateway.observability.mcp_tracing import (
    MAX_TRACEPARENT_LENGTH,
    patch_mcp_tools,
    sanitize_trace_carrier,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]


def _parse_version_tuple(raw: str) -> tuple[int, ...]:
    return tuple(int(part) for part in raw.split(".")[:3])


def test_pyproject_and_uv_lock_enforce_opentelemetry_api_1_45_2_floor() -> None:
    """Both pyproject.toml and uv.lock must require opentelemetry-api >= 1.45.2."""
    pyproject = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    deps: list[str] = pyproject["project"]["dependencies"]
    overrides: list[str] = pyproject["tool"]["uv"]["override-dependencies"]
    assert "opentelemetry-api>=1.45.2" in deps
    assert "opentelemetry-api>=1.45.2" in overrides

    lock_data = tomllib.loads((_REPO / "uv.lock").read_text(encoding="utf-8"))
    otel_pkgs = [
        pkg for pkg in lock_data["package"] if pkg.get("name") == "opentelemetry-api"
    ]
    assert len(otel_pkgs) == 1
    assert _parse_version_tuple(otel_pkgs[0]["version"]) >= (1, 45, 2)


def test_sanitize_trace_carrier_rejects_redos_newlines_oversize_and_non_mapping() -> (
    None
):
    """CVE-2026-126360 crafted carriers must be stripped in O(1) while preserving valid headers."""
    valid_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    assert sanitize_trace_carrier(
        {"traceparent": valid_tp, "tracestate": "rojo=1"}
    ) == {
        "traceparent": valid_tp,
        "tracestate": "rojo=1",
    }

    crafted_redos = f"{valid_tp}{' ' * 50_000}\nx"
    t0 = time.perf_counter()
    cleaned = sanitize_trace_carrier({"traceparent": crafted_redos})
    elapsed = time.perf_counter() - t0
    assert cleaned == {}
    assert elapsed < 0.05

    assert sanitize_trace_carrier({"traceparent": f"{valid_tp}\r\ninjected: 1"}) == {}
    assert (
        sanitize_trace_carrier({"TRACEPARENT": "0" * (MAX_TRACEPARENT_LENGTH + 1)})
        == {}
    )
    assert sanitize_trace_carrier("not-a-mapping") == {}
    assert sanitize_trace_carrier(["traceparent", valid_tp]) == {}
    assert sanitize_trace_carrier({"traceparent": 12345}) == {}


@pytest.mark.asyncio
async def test_patch_mcp_tools_handles_hostile_otel_carrier_without_blocking_or_crashing() -> (
    None
):
    """MCP JSON `_otel_carrier` payloads with ReDoS strings or non-dict shapes must not stall or raise."""
    seen_args: list[dict[str, Any]] = []
    seen_trace_ids: list[int] = []

    async def fake_call_tool(
        name: str,
        arguments: dict[str, Any],
        context: Any = None,
        convert_result: bool = False,
    ) -> str:
        seen_args.append(dict(arguments))
        seen_trace_ids.append(trace.get_current_span().get_span_context().trace_id)
        return f"ok:{name}"

    tool_manager = SimpleNamespace(
        call_tool=fake_call_tool,
        list_tools=lambda: ["read_portfolio"],
    )
    mcp_server = SimpleNamespace(_tool_manager=tool_manager)
    patch_mcp_tools(mcp_server)

    valid_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    crafted_redos = f"{valid_tp}{' ' * 60_000}\nx"

    t0 = time.perf_counter()
    out1 = await tool_manager.call_tool(
        "read_portfolio",
        {"account": "a1", "_otel_carrier": {"traceparent": crafted_redos}},
    )
    elapsed = time.perf_counter() - t0
    assert out1 == "ok:read_portfolio"
    assert elapsed < 0.1
    assert seen_args[-1] == {"account": "a1"}

    # Non-mapping `_otel_carrier` (previously crashed with AttributeError in propagator.extract)
    out2 = await tool_manager.call_tool(
        "read_portfolio",
        {"account": "a2", "_otel_carrier": ["unexpected", "list"]},
    )
    assert out2 == "ok:read_portfolio"
    assert seen_args[-1] == {"account": "a2"}


@pytest.mark.asyncio
async def test_governance_middleware_sanitizes_hostile_traceparent_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inbound HTTP headers on governance endpoints must strip hostile traceparent before otel_extract."""
    from src.gateway.server import governance_middleware as gm

    extracted_carriers: list[dict[str, str]] = []
    real_extract = gm.otel_extract

    def spy_extract(carrier: Any, *args: Any, **kwargs: Any) -> Any:
        extracted_carriers.append(dict(carrier))
        return real_extract(carrier, *args, **kwargs)

    async def allow_rate_limit(_req: Any) -> bool:
        return True

    async def fake_bind_server_inputs(
        _action: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        return dict(params)

    async def fake_evaluate_policy(_payload: dict[str, Any]) -> dict[str, Any]:
        return {"allow": True}

    fake_governor = SimpleNamespace(
        bind_server_inputs=fake_bind_server_inputs,
        components=SimpleNamespace(
            opa=SimpleNamespace(evaluate_policy=fake_evaluate_policy)
        ),
    )

    monkeypatch.setattr(gm, "otel_extract", spy_extract)
    monkeypatch.setattr(gm, "_check_validate_action_rate_limit", allow_rate_limit)
    monkeypatch.setattr(gm, "governor_of", lambda _app: fake_governor)

    valid_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    crafted_redos = f"{valid_tp}{' ' * 60_000}\nx"
    real_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/governance/policy-precheck",
            "headers": [
                (b"traceparent", crafted_redos.encode("latin-1")),
                (b"x-request-id", b"req-1"),
            ],
            "app": SimpleNamespace(state=SimpleNamespace()),
        }
    )
    body = gm.PolicyPrecheckRequest(action="read_resource", params={"id": "1"})

    t0 = time.perf_counter()
    resp = await gm.policy_precheck_endpoint(real_request, body)
    elapsed = time.perf_counter() - t0

    assert resp.status_code == 200
    assert elapsed < 0.1
    assert extracted_carriers == [{"x-request-id": "req-1"}]
