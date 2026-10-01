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

"""The advisor is an untrusted client of the gateway (POAM-2026-079).

Fail-closed guards for the split between the neural plane (the governed
financial advisor) and the kernel (the gateway):

* the advisor never imports the governor, seal or signing modules, nor the
  trade actuator;
* the advisor refuses to boot with a signing-key variable;
* the advisor's graph routes on the evaluator verdict alone — it signs nothing;
* every governed tool call and post-HITL re-validation crosses the network to
  the gateway, and anything other than an explicit approval blocks;
* the gateway's REST tool dispatch reaches plugin-registered tools, so trades
  run through ``execute_trade_action`` and the ``ActuatorRegistry``;
* seal and envelope verification reject unknown key IDs instead of falling
  back to the local signer.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]
_ADVISOR = _REPO / "src" / "governed_financial_advisor"

# Modules the advisor must never import: the governor (and its bootstrap),
# seal issue/verify, signing, the app-state accessor for an in-process
# governor, and the trade actuator path.
_FORBIDDEN_PREFIXES = (
    "src.gateway.governance.governor",
    "src.gateway.governance.routing_seal",
    "src.gateway.governance.kms_signer",
    "src.gateway.governance.signer_factory",
    "src.gateway.governance.jwks",
    "src.gateway.governance.execution_actuator",
    "src.gateway.governance.defer_queue",
    "src.gateway.server.app_state",
    "src.integrations.nemo",
    "src.cage_finance.tools.trade_executor",
    "src.cage_finance.actuators",
)


def _imports(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.lineno, node.module))
            found += [(node.lineno, f"{node.module}.{a.name}") for a in node.names]
    return found


# ---------------------------------------------------------------------------
# Import boundary
# ---------------------------------------------------------------------------


def test_advisor_never_imports_kernel_signing_or_actuation_modules() -> None:
    offenders = [
        f"{path.relative_to(_REPO)}:{line}: {module}"
        for path in sorted(_ADVISOR.rglob("*.py"))
        for line, module in _imports(path)
        if module.startswith(_FORBIDDEN_PREFIXES)
    ]
    assert offenders == [], f"Advisor imports kernel/signing modules: {offenders}"


def test_boundary_scan_detects_a_forbidden_import(tmp_path: Path) -> None:
    """The scan itself must fail on a violation (guards against a vacuous pass)."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from src.gateway.governance.governor.bootstrap import bootstrap_governor\n"
        "import src.gateway.governance.routing_seal\n"
    )
    hits = [m for _, m in _imports(probe) if m.startswith(_FORBIDDEN_PREFIXES)]
    assert "src.gateway.governance.governor.bootstrap" in hits
    assert "src.gateway.governance.routing_seal" in hits


# ---------------------------------------------------------------------------
# Startup guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "var", ["KMS_GOVERNANCE_KEY", "RECONCILER_KMS_KEY", "AWS_KMS_KEY_ID", "AZURE_KMS_KEY_NAME"]
)
def test_identity_guard_refuses_any_signing_key_variable(var: str) -> None:
    from src.governed_financial_advisor.infrastructure.identity_guard import (
        assert_no_signing_identity,
    )

    with pytest.raises(RuntimeError, match=var):
        assert_no_signing_identity({var: "projects/p/locations/l/keyRings/r/cryptoKeys/k"})


def test_identity_guard_passes_without_signing_keys() -> None:
    from src.governed_financial_advisor.infrastructure.identity_guard import (
        assert_no_signing_identity,
    )

    assert_no_signing_identity({"CAGE_ENV": "production", "KMS_GOVERNANCE_KEY": "  "})


def test_advisor_lifespan_runs_identity_guard_and_no_governor() -> None:
    tree = ast.parse((_ADVISOR / "server.py").read_text())
    lifespan = next(
        n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"
    )
    calls = [
        n.func.id for n in ast.walk(lifespan)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    ]
    assert calls.index("assert_no_signing_identity") < calls.index("create_graph")
    assert "bootstrap_governor" not in calls


# ---------------------------------------------------------------------------
# Graph: verdict-only routing, no signing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"evaluation_result": {"verdict": "APPROVED"}}, "ftra_node"),
        ({"evaluation_result": {"verdict": "REJECTED"}, "loop_count": 1}, "execution_analyst"),
        ({"evaluation_result": {"verdict": "REJECTED"}, "loop_count": 3}, "explainer"),
        ({"evaluation_result": None}, "execution_analyst"),
    ],
)
def test_evaluator_edge_routes_on_verdict_alone(state: dict, expected: str) -> None:
    from src.governed_financial_advisor.graph.graph import route_after_evaluator

    assert route_after_evaluator(state) == expected


@pytest.mark.asyncio
async def test_evaluator_node_returns_no_signature() -> None:
    from src.governed_financial_advisor.graph.nodes import evaluator_node as mod

    plan = {"steps": [{"action": "execute_trade", "parameters": {"symbol": "AAPL"}}]}
    with patch.object(
        mod, "simulate_governance_check", AsyncMock(return_value={"verdict": "ALLOW"})
    ):
        result = await mod.evaluator_node({"execution_plan_output": plan})

    assert result["evaluation_result"]["verdict"] == "APPROVED"
    assert "governance_signature" not in result


# ---------------------------------------------------------------------------
# GatewayClient: network calls that fail closed
# ---------------------------------------------------------------------------


def _client_with(handler) -> object:
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )

    client = GatewayClient()
    client._http = httpx.AsyncClient(
        base_url="http://gateway", transport=httpx.MockTransport(handler)
    )
    return client


def test_gateway_client_has_no_post_hitl_path() -> None:
    from src.governed_financial_advisor.infrastructure.gateway_client import (
        GatewayClient,
    )

    assert not hasattr(GatewayClient, "revalidate_post_hitl")


@pytest.mark.asyncio
async def test_validate_action_returns_require_approval_with_deferred_id() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"verdict": "REQUIRE_APPROVAL", "deferred_id": "d-1", "violations": []}
        )

    result = await _client_with(handler).validate_action("execute_trade", {"amount": 1.0})

    assert result["verdict"] == "REQUIRE_APPROVAL"
    assert result["deferred_id"] == "d-1"
    assert "seal" not in result
    assert seen["path"] == "/governance/validate-action"
    assert seen["body"]["params"] == {"amount": 1.0}


@pytest.mark.asyncio
async def test_validate_action_unwraps_allow_envelope() -> None:
    envelope = {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "payload": {"verdict": "ALLOW", "violations": []},
    }
    client = _client_with(lambda request: httpx.Response(200, json=envelope))
    result = await client.validate_action("execute_trade", {})
    assert result["verdict"] == "ALLOW"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(403, json={"verdict": "DENIED", "violations": ["CBF Violation"]}),
        httpx.Response(200, json={"verdict": "DENIED"}),
        httpx.Response(200, json={"verdict": "APPROVED"}),
        httpx.Response(200, json={"verdict": "REQUIRE_APPROVAL"}),
        httpx.Response(200, json={}),
    ],
    ids=["denied_403", "denied_200", "legacy_approved", "approval_without_token", "no_verdict"],
)
async def test_validate_action_without_routable_verdict_raises(response: httpx.Response) -> None:
    client = _client_with(lambda request: response)
    with pytest.raises(PermissionError):
        await client.validate_action("execute_trade", {})


@pytest.mark.asyncio
async def test_validate_action_server_error_raises() -> None:
    client = _client_with(lambda request: httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        await client.validate_action("execute_trade", {})


# ---------------------------------------------------------------------------
# Advisor /tools/execute forwards governed tools to the gateway
# ---------------------------------------------------------------------------


def _tools_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.governed_financial_advisor.infrastructure.auth import require_api_key
    from src.governed_financial_advisor.tools.api import tools_router

    app = FastAPI()
    app.include_router(tools_router)
    app.dependency_overrides[require_api_key] = lambda: "test"
    return TestClient(app)


def test_execute_trade_forwards_to_gateway_execute_trade_action() -> None:
    from src.governed_financial_advisor.tools import api

    gateway = AsyncMock(return_value={"status": "SUCCESS", "output": "EXECUTED: AAPL x 5.0"})
    params = {"symbol": "AAPL", "amount": 5.0, "currency": "USD", "confidence": 0.99}
    with patch.object(api._gateway_client, "execute_tool", gateway):
        resp = _tools_client().post(
            "/tools/execute", json={"tool_name": "execute_trade", "params": params}
        )

    assert resp.json() == {"status": "SUCCESS", "output": "EXECUTED: AAPL x 5.0"}
    tool_name, forwarded = gateway.await_args.args
    assert tool_name == "execute_trade_action"
    assert {k: forwarded[k] for k in ("symbol", "amount", "currency", "confidence")} == params


@pytest.mark.parametrize(
    ("tool", "gateway_tool"),
    [
        ("execute_trade", "execute_trade_action"),
        ("evaluate_policy", "evaluate_policy"),
        ("simulate_governance_check", "simulate_governance_check"),
    ],
)
def test_gateway_tool_error_is_not_reported_as_success(tool: str, gateway_tool: str) -> None:
    from src.governed_financial_advisor.tools import api

    gateway = AsyncMock(return_value={"status": "ERROR", "error": "seal invalid"})
    params = {"symbol": "AAPL", "amount": 5.0, "currency": "USD", "confidence": 0.99,
              "action": "execute_trade"}
    with patch.object(api._gateway_client, "execute_tool", gateway):
        resp = _tools_client().post("/tools/execute", json={"tool_name": tool, "params": params})

    assert resp.json()["status"] == "ERROR"
    assert gateway.await_args.args[0] == gateway_tool


def test_gateway_unreachable_is_an_error() -> None:
    from src.governed_financial_advisor.tools import api

    gateway = AsyncMock(side_effect=httpx.ConnectError("gateway down"))
    with patch.object(api._gateway_client, "execute_tool", gateway):
        resp = _tools_client().post(
            "/tools/execute",
            json={"tool_name": "evaluate_policy", "params": {"action": "execute_trade"}},
        )

    assert resp.json()["status"] == "ERROR"


# ---------------------------------------------------------------------------
# Gateway: REST dispatch reaches plugin-registered tools
# ---------------------------------------------------------------------------


def test_gateway_tools_execute_reaches_plugin_registered_tool() -> None:
    from fastapi.testclient import TestClient

    import src.gateway.server.mcp_tool_server as mod

    async def plugin_probe(x: int) -> str:
        return f"probe:{x}"

    mod.mcp.tool(name="plugin_probe_poam079")(plugin_probe)
    with patch.object(mod, "_check_rate_limit", AsyncMock(return_value=True)):
        resp = TestClient(mod.app).post(
            "/tools/execute", json={"tool_name": "plugin_probe_poam079", "params": {"x": 3}}
        )

    assert resp.json() == {"status": "SUCCESS", "output": "probe:3"}


# ---------------------------------------------------------------------------
# Unknown key IDs fail closed
# ---------------------------------------------------------------------------


def test_verify_seal_rejects_unknown_kid_without_signer_fallback() -> None:
    import base64

    from src.gateway.governance import routing_seal

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "ES256", "typ": "JWT", "kid": "unknown-kid"}).encode()
    ).rstrip(b"=").decode()
    seal = f"{header}.e30.c2ln"
    signer = MagicMock()
    with (
        patch("src.gateway.governance.jwks.get_verification_key_for_jwt", return_value=None),
        patch.object(routing_seal, "get_governance_signer", return_value=signer),
        pytest.raises(routing_seal.SymbolicGovernorViolation, match="unknown kid"),
    ):
        routing_seal.verify_seal(seal, "execute_trade", {"amount": 1.0})

    signer.get_public_key_pem.assert_not_called()


def test_envelope_verify_rejects_unknown_kid_without_signer_fallback() -> None:
    from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder

    envelope = MagicMock()
    envelope.signature.kid = "unknown-kid"
    jwks = MagicMock()
    jwks.get_pem.return_value = None
    signer = MagicMock()
    with (
        patch("src.gateway.governance.jwks.get_jwks", return_value=jwks),
        patch("src.gateway.governance.kms_signer.get_governance_signer", return_value=signer),
    ):
        assert GovernanceEnvelopeBuilder().verify(envelope) is False

    signer.get_public_key_pem.assert_not_called()
