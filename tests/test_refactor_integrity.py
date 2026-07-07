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

"""
OPA Guardrail Refactor Integrity Tests (P2).

Dead-man's switch tests that permanently enforce the architectural invariant:

  OPA invocation in the mandatory safety_check LangGraph node MUST be native/direct
  (via symbolic_governor.govern()) and MUST NOT go through any MCP client.

If any of these tests fail, it means the MCP bypass has been reintroduced and
the security-critical guardrail is agent-bypassable.  CI must block the merge.
"""

import ast
import pathlib

import pytest

pytestmark = pytest.mark.unit


class TestOPAGuardrailIntegrity:
    """Structural (AST-level) tests that cannot be defeated by runtime mocking."""

    def test_safety_node_does_not_import_mcp_client(self):
        """
        Dead-man's switch: the safety check node MUST NOT import any MCP client.

        OPA invocation in the mandatory guardrail path must be native/direct only.
        If this test fails, the MCP bypass has been reintroduced.
        """
        safety_node_candidates = list(pathlib.Path("src").rglob("*safety*node*"))
        assert safety_node_candidates, "Could not find safety node file under src/"

        for candidate in safety_node_candidates:
            if not candidate.suffix == ".py":
                continue
            source = candidate.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name or ""
                        assert "mcp_client" not in name.lower(), (
                            f"{candidate}: imports '{name}' — "
                            "OPA guardrail bypass reintroduced via MCP client import"
                        )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    assert "mcp_client" not in module.lower(), (
                        f"{candidate}: imports from '{module}' — "
                        "OPA guardrail bypass reintroduced via MCP client import"
                    )
                    for alias in node.names:
                        name = alias.name or ""
                        assert "mcp_client" not in name.lower(), (
                            f"{candidate}: imports '{name}' from '{module}' — "
                            "OPA guardrail bypass reintroduced via MCP client import"
                        )

    def test_safety_node_does_not_call_call_tool(self):
        """
        Dead-man's switch: safety_check_node must not call `.call_tool(...)`.

        Any call to `call_tool` in the safety node would be an agent-visible
        MCP dispatch — a bypassable OPA path.  The only permitted OPA invocation
        pattern is ``symbolic_governor.govern()``.
        """
        safety_node_candidates = list(pathlib.Path("src").rglob("*safety*node*"))
        assert safety_node_candidates, "Could not find safety node file under src/"

        for candidate in safety_node_candidates:
            if not candidate.suffix == ".py":
                continue
            source = candidate.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "call_tool":
                    raise AssertionError(
                        f"{candidate}: found `.call_tool(...)` call — "
                        "OPA guardrail bypass reintroduced via MCP tool dispatch"
                    )

    def test_safety_node_imports_symbolic_governor(self):
        """
        The safety node MUST import from the singletons/symbolic_governor module.

        This ensures it is wired to the direct OPA path.
        """
        safety_node_candidates = list(pathlib.Path("src").rglob("*safety*node*"))
        assert safety_node_candidates, "Could not find safety node file under src/"

        found_governor_import = False
        for candidate in safety_node_candidates:
            if not candidate.suffix == ".py":
                continue
            source = candidate.read_text()
            if "symbolic_governor" in source:
                found_governor_import = True
                break

        assert found_governor_import, (
            "safety_check_node does not import symbolic_governor — "
            "the mandatory OPA guardrail path may be missing"
        )

    def test_evaluate_policy_not_exposed_as_mcp_tool(self):
        """
        OPA evaluation must not appear in the MCP tool manifest.

        The ``@mcp.tool()`` decorator must NOT be applied to ``evaluate_policy``
        (or ``_evaluate_policy_internal``).  Inspected at AST level to catch
        decorator-based registration without executing any server code.
        """
        mcp_server_path = pathlib.Path("src/gateway/server/mcp_tool_server.py")
        assert mcp_server_path.exists(), "mcp_tool_server.py not found"

        source = mcp_server_path.read_text()
        tree = ast.parse(source)

        # Find all async def / def functions that are decorated with @mcp.tool()
        mcp_tool_registered_functions: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                for decorator in node.decorator_list:
                    # Match @mcp.tool() — represented as ast.Call with func=ast.Attribute
                    if (
                        isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr == "tool"
                    ) or (
                        # Match @mcp.tool (no parentheses variant)
                        isinstance(decorator, ast.Attribute)
                        and decorator.attr == "tool"
                    ):
                        mcp_tool_registered_functions.append(node.name)

        assert "evaluate_policy" not in mcp_tool_registered_functions, (
            "evaluate_policy is registered as an @mcp.tool() — "
            "OPA must NOT be agent-reachable via the MCP tool surface. "
            f"Currently registered MCP tools: {mcp_tool_registered_functions}"
        )
        assert "_evaluate_policy_internal" not in mcp_tool_registered_functions, (
            "_evaluate_policy_internal must not be registered as an @mcp.tool()"
        )

    def test_simulate_governance_check_is_mcp_tool(self):
        """
        ``simulate_governance_check`` MUST be registered as an @mcp.tool().

        This is the legitimate dry-run simulation surface for the Evaluator Agent.
        If it disappears from the MCP manifest, the agent loses its simulation
        capability (expected).  If it is absent AND evaluate_policy is back,
        something has regressed.
        """
        mcp_server_path = pathlib.Path("src/gateway/server/mcp_tool_server.py")
        assert mcp_server_path.exists(), "mcp_tool_server.py not found"

        source = mcp_server_path.read_text()
        tree = ast.parse(source)

        mcp_tool_registered_functions: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                for decorator in node.decorator_list:
                    if (
                        isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr == "tool"
                    ) or (
                        isinstance(decorator, ast.Attribute)
                        and decorator.attr == "tool"
                    ):
                        mcp_tool_registered_functions.append(node.name)

        assert "simulate_governance_check" in mcp_tool_registered_functions, (
            "simulate_governance_check is NOT registered as an @mcp.tool() — "
            f"registered tools: {mcp_tool_registered_functions}"
        )
