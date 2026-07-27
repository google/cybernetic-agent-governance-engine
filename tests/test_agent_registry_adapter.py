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
tests/test_agent_registry_adapter.py
=====================================

Comprehensive tests for:
  - RegistryCatalog dataclass
  - AgentRegistryAdapter (no-op path + configured path)
  - AgentRegistryDaemon (lifecycle + fallback behaviour)
  - generate_registry_manifest() in stpa_compiler

All tests are offline — no real network calls are made.
httpx.AsyncClient is mocked throughout.

Run with:
    uv run --no-sync pytest tests/test_agent_registry_adapter.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure CAGE_AGENT_REGISTRY_PROJECT is unset by default for each test."""
    monkeypatch.delenv("CAGE_AGENT_REGISTRY_PROJECT", raising=False)
    monkeypatch.delenv("CAGE_AGENT_REGISTRY_LOCATION", raising=False)
    monkeypatch.delenv("CAGE_AGENT_REGISTRY_ID", raising=False)
    monkeypatch.delenv("CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES", raising=False)
    monkeypatch.delenv("CAGE_AGENT_REGISTRY_BOOT_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("OPA_URL", raising=False)


@pytest.fixture()
def configured_env(monkeypatch):
    """Set environment variables to activate the adapter."""
    monkeypatch.setenv("CAGE_AGENT_REGISTRY_PROJECT", "my-gcp-project")
    monkeypatch.setenv("CAGE_AGENT_REGISTRY_LOCATION", "us-central1")
    monkeypatch.setenv("CAGE_AGENT_REGISTRY_ID", "cage-agent-registry")
    monkeypatch.setenv("CAGE_AGENT_REGISTRY_POLL_INTERVAL_MINUTES", "15")
    monkeypatch.setenv("CAGE_AGENT_REGISTRY_BOOT_TIMEOUT_SECONDS", "10")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_catalog(agents: dict | None = None, error: str | None = None):
    """Build a RegistryCatalog for testing."""
    from src.gateway.governance.ingress.agent_registry_adapter import RegistryCatalog

    return RegistryCatalog(
        agents=agents or {},
        fetched_at=time.time(),
        registry_resource_name="projects/p/locations/l/agentRegistries/r",
        error=error,
    )


def _load_stpa_cs():
    """Load the real STPA control structure for compiler tests."""
    from src.gateway.governance.stpa_compiler import (
        ControlStructureModel,
        load_control_structure,
    )

    stpa_path = (
        Path(__file__).resolve().parents[1] / "config" / "stpa_control_structure.yaml"
    )
    if stpa_path.exists():
        return load_control_structure(stpa_path)

    # Minimal synthetic model for environments without the full YAML
    import yaml

    minimal_yaml = """
system:
  name: "Test System"
  version: "1.0.0"
  description: "Test"
  controller: "Test Controller"
  controlled_process: "Test Process"
hazards:
  - id: H-1
    description: "Unauthorized trade"
    severity: critical
  - id: H-2
    description: "Stale data"
    severity: high
control_actions:
  - name: execute_trade
    params: [amount, symbol]
unsafe_control_actions:
  - id: UCA-1
    action: execute_trade
    uca_type: unsafe_action
    hazard_refs: [H-1, H-2]
    description: "Trade without auth"
    condition:
      param: auth_token
      operator: is_null
    enforcement: [opa]
    opa_rule:
      decision: DENY
      message: "Trade requires auth_token"
    terminal_classification: IRREVERSIBLE_TERMINAL
  - id: UCA-2
    action: execute_trade
    uca_type: wrong_timing
    hazard_refs: [H-2]
    description: "Trade on stale data"
    condition:
      param: data_fresh
      operator: is_false
    enforcement: [opa]
    opa_rule:
      decision: DENY
      message: "Trade requires fresh data"
    terminal_classification: IRREVERSIBLE_TERMINAL
  - id: UCA-3
    action: get_portfolio
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Portfolio access without auth"
    condition:
      param: auth_token
      operator: is_null
    enforcement: [opa]
    opa_rule:
      decision: DENY
      message: "Portfolio requires auth_token"
    terminal_classification: READ_ONLY
safety_constraints:
  - id: SC-1
    description: "All trades require auth"
    logic: "auth_token must be present"
    scope: [execute_trade]
rbac_rules:
  roles:
    - name: trader
      allowed_actions: [execute_trade, get_portfolio]
      trade_limits:
        allow_below: 5000
        manual_review_below: 50000
    - name: senior
      allowed_actions: [execute_trade, get_portfolio]
      trade_limits:
        allow_below: 100000
        manual_review_below: 500000
    - name: junior
      allowed_actions: [get_portfolio]
"""
    raw = yaml.safe_load(minimal_yaml)
    return ControlStructureModel(**raw)


# ===========================================================================
# TestRegistryCatalog
# ===========================================================================


class TestRegistryCatalog:
    def test_is_valid_true_when_agents_present(self):
        catalog = _make_catalog(
            agents={"spiffe://cage/agent/foo": {"allowed_tools": ["tool_a"]}}
        )
        assert catalog.is_valid is True

    def test_is_valid_false_when_error_set(self):
        catalog = _make_catalog(
            agents={"spiffe://cage/agent/foo": {"allowed_tools": ["tool_a"]}},
            error="connection refused",
        )
        assert catalog.is_valid is False

    def test_is_valid_false_when_agents_empty(self):
        catalog = _make_catalog(agents={})
        assert catalog.is_valid is False

    def test_to_opa_data_document_shape(self):
        agents = {
            "spiffe://cage/agent/foo": {
                "allowed_tools": ["tool_a", "tool_b"],
                "roles": ["trader"],
            }
        }
        catalog = _make_catalog(agents=agents)
        doc = catalog.to_opa_data_document()
        assert "agents" in doc
        assert doc["agents"] == agents

    def test_to_opa_data_document_empty_agents(self):
        catalog = _make_catalog(agents={})
        doc = catalog.to_opa_data_document()
        assert doc == {"agents": {}}


# ===========================================================================
# TestAgentRegistryAdapter
# ===========================================================================


class TestAgentRegistryAdapter:
    def test_is_configured_false_when_no_env_var(self):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        assert adapter.is_configured is False

    def test_is_configured_true_when_env_var_set(self, configured_env):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        assert adapter.is_configured is True

    def test_registry_resource_name_format(self, configured_env):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        name = adapter.registry_resource_name
        assert (
            name
            == "projects/my-gcp-project/locations/us-central1/agentRegistries/cage-agent-registry"
        )

    def test_get_registry_audit_reference_empty_when_not_configured(self):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        assert adapter.get_registry_audit_reference() == ""

    def test_get_registry_audit_reference_returns_resource_name_when_configured(
        self, configured_env
    ):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        ref = adapter.get_registry_audit_reference()
        assert (
            ref
            == "projects/my-gcp-project/locations/us-central1/agentRegistries/cage-agent-registry"
        )

    def test_load_static_fallback_returns_agents_dict(self):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        result = adapter.load_static_fallback()
        assert "agents" in result
        assert isinstance(result["agents"], dict)

    def test_load_static_fallback_has_trade_executor_agent(self):
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        result = adapter.load_static_fallback()
        agents = result["agents"]
        # The static catalog must contain at least one agent with execute_trade
        trade_agents = [
            spiffe_id
            for spiffe_id, data in agents.items()
            if "execute_trade" in data.get("allowed_tools", [])
        ]
        assert len(trade_agents) >= 1, (
            "Static catalog must have at least one agent with execute_trade in allowed_tools"
        )

    def test_load_static_fallback_missing_file(self, tmp_path, monkeypatch):
        """When the static catalog file is missing, returns empty agents dict."""
        from src.gateway.governance.ingress import agent_registry_adapter as mod

        monkeypatch.setattr(mod, "_STATIC_CATALOG_PATH", tmp_path / "nonexistent.json")

        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        result = adapter.load_static_fallback()
        assert result == {"agents": {}}

    @pytest.mark.asyncio
    async def test_fetch_catalog_returns_fallback_when_not_configured(self):
        """No-op path: fetch_catalog returns error catalog when unconfigured."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        catalog = await adapter.fetch_catalog()
        assert catalog.is_valid is False
        assert catalog.error is not None
        assert "CAGE_AGENT_REGISTRY_PROJECT" in catalog.error

    @pytest.mark.asyncio
    async def test_fetch_catalog_returns_valid_catalog_when_configured(
        self, configured_env
    ):
        """Configured path: fetch_catalog calls the API and parses the response."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        mock_response_data = {
            "agents": [
                {
                    "name": "projects/my-gcp-project/locations/us-central1/agentRegistries/cage-agent-registry/agents/spiffe://cage/agent/foo",
                    "displayName": "Foo Agent",
                    "labels": {"role": "trader"},
                    "toolAuthorizations": [
                        {"toolName": "execute_trade"},
                        {"toolName": "get_portfolio"},
                    ],
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_response_data
        mock_resp.raise_for_status = MagicMock()

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter.AgentRegistryAdapter._get_auth_headers",
            new_callable=AsyncMock,
            return_value={},
        ):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                adapter = AgentRegistryAdapter()
                catalog = await adapter.fetch_catalog()

        assert catalog.is_valid is True
        assert len(catalog.agents) == 1
        # The adapter extracts the last path segment of the resource name as the key.
        # Resource name: ".../agents/spiffe://cage/agent/foo" → last segment = "foo"
        spiffe_id = list(catalog.agents.keys())[0]
        assert spiffe_id == "foo"
        assert "execute_trade" in catalog.agents[spiffe_id]["allowed_tools"]

    @pytest.mark.asyncio
    async def test_fetch_catalog_returns_error_on_http_failure(self, configured_env):
        """HTTP errors are caught and returned as error catalog."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter.AgentRegistryAdapter._get_auth_headers",
            new_callable=AsyncMock,
            return_value={},
        ):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
                mock_client_cls.return_value = mock_client

                adapter = AgentRegistryAdapter()
                catalog = await adapter.fetch_catalog()

        assert catalog.is_valid is False
        assert "connection refused" in catalog.error

    @pytest.mark.asyncio
    async def test_push_tool_authorizations_noop_when_not_configured(self):
        """push_tool_authorizations is a no-op when not configured."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        adapter = AgentRegistryAdapter()
        # Should not raise, should not make any HTTP calls
        with patch("httpx.AsyncClient") as mock_client_cls:
            await adapter.push_tool_authorizations(
                {"tool_authorizations": [{"tool_name": "execute_trade"}]}
            )
            mock_client_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_push_tool_authorizations_calls_api_when_configured(
        self, configured_env
    ):
        """push_tool_authorizations calls the registry API when configured."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
        )

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter.AgentRegistryAdapter._get_auth_headers",
            new_callable=AsyncMock,
            return_value={},
        ):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                adapter = AgentRegistryAdapter()
                await adapter.push_tool_authorizations(
                    {"tool_authorizations": [{"tool_name": "execute_trade"}]}
                )

                mock_client.post.assert_called_once()


# ===========================================================================
# TestAgentRegistryDaemon
# ===========================================================================


class TestAgentRegistryDaemon:
    @pytest.mark.asyncio
    async def test_start_noop_when_not_configured(self):
        """Daemon.start() is a no-op when CAGE_AGENT_REGISTRY_PROJECT is not set."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryDaemon,
        )

        daemon = AgentRegistryDaemon()
        # Should return immediately without creating a task
        await daemon.start()
        assert daemon._task is None

    @pytest.mark.asyncio
    async def test_stop_noop_when_not_started(self):
        """Daemon.stop() is safe to call when no task is running."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryDaemon,
        )

        daemon = AgentRegistryDaemon()
        # Should not raise
        await daemon.stop()
        assert daemon._task is None

    @pytest.mark.asyncio
    async def test_start_uses_static_fallback_when_registry_unreachable(
        self, configured_env
    ):
        """When fetch_catalog fails, daemon falls back to static catalog."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
            AgentRegistryDaemon,
        )

        mock_adapter = MagicMock(spec=AgentRegistryAdapter)
        mock_adapter.is_configured = True
        mock_adapter._poll_interval_s = 900.0
        mock_adapter._boot_timeout_s = 10.0
        mock_adapter.registry_resource_name = "projects/p/locations/l/agentRegistries/r"
        # fetch_catalog raises to simulate unreachable registry
        mock_adapter.fetch_catalog = AsyncMock(
            side_effect=Exception("registry unreachable")
        )
        mock_adapter.load_static_fallback = MagicMock(
            return_value={"agents": {"spiffe://cage/agent/foo": {"allowed_tools": []}}}
        )

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter._push_to_opa",
            new_callable=AsyncMock,
        ) as mock_push:
            daemon = AgentRegistryDaemon(adapter=mock_adapter)
            await daemon.start()

            # Static fallback should have been pushed to OPA
            mock_push.assert_called_once()
            pushed_data = mock_push.call_args[0][0]
            assert "agents" in pushed_data

        # Cancel the background task
        await daemon.stop()

    @pytest.mark.asyncio
    async def test_start_pushes_registry_catalog_when_reachable(self, configured_env):
        """When fetch_catalog succeeds, daemon pushes registry catalog to OPA."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
            AgentRegistryDaemon,
            RegistryCatalog,
        )

        valid_catalog = RegistryCatalog(
            agents={"spiffe://cage/agent/foo": {"allowed_tools": ["execute_trade"]}},
            fetched_at=time.time(),
            registry_resource_name="projects/p/locations/l/agentRegistries/r",
        )

        mock_adapter = MagicMock(spec=AgentRegistryAdapter)
        mock_adapter.is_configured = True
        mock_adapter._poll_interval_s = 900.0
        mock_adapter._boot_timeout_s = 10.0
        mock_adapter.registry_resource_name = "projects/p/locations/l/agentRegistries/r"
        mock_adapter.fetch_catalog = AsyncMock(return_value=valid_catalog)

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter._push_to_opa",
            new_callable=AsyncMock,
        ) as mock_push:
            daemon = AgentRegistryDaemon(adapter=mock_adapter)
            await daemon.start()

            mock_push.assert_called_once_with(
                {
                    "agents": {
                        "spiffe://cage/agent/foo": {"allowed_tools": ["execute_trade"]}
                    }
                }
            )

        await daemon.stop()

    @pytest.mark.asyncio
    async def test_poll_loop_cancelled_on_stop(self, configured_env):
        """Background poll task is cancelled cleanly when stop() is called."""
        from src.gateway.governance.ingress.agent_registry_adapter import (
            AgentRegistryAdapter,
            AgentRegistryDaemon,
            RegistryCatalog,
        )

        valid_catalog = RegistryCatalog(
            agents={"spiffe://cage/agent/foo": {"allowed_tools": []}},
            fetched_at=time.time(),
            registry_resource_name="projects/p/locations/l/agentRegistries/r",
        )

        mock_adapter = MagicMock(spec=AgentRegistryAdapter)
        mock_adapter.is_configured = True
        mock_adapter._poll_interval_s = 9999.0  # Very long — won't fire during test
        mock_adapter._boot_timeout_s = 10.0
        mock_adapter.registry_resource_name = "projects/p/locations/l/agentRegistries/r"
        mock_adapter.fetch_catalog = AsyncMock(return_value=valid_catalog)

        with patch(
            "src.gateway.governance.ingress.agent_registry_adapter._push_to_opa",
            new_callable=AsyncMock,
        ):
            daemon = AgentRegistryDaemon(adapter=mock_adapter)
            await daemon.start()

            assert daemon._task is not None
            assert not daemon._task.done()

            await daemon.stop()

            assert daemon._task is None


# ===========================================================================
# TestGenerateRegistryManifest
# ===========================================================================


class TestGenerateRegistryManifest:
    @pytest.fixture(autouse=True)
    def _cs(self):
        self.cs = _load_stpa_cs()

    def test_manifest_has_required_keys(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest_str = generate_registry_manifest(self.cs)
        manifest = json.loads(manifest_str)

        assert "_generated_by" in manifest
        assert "_source" in manifest
        assert "_generated_at" in manifest
        assert "_schema_version" in manifest
        assert "tool_authorizations" in manifest

    def test_manifest_tool_authorizations_is_list(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        assert isinstance(manifest["tool_authorizations"], list)
        assert len(manifest["tool_authorizations"]) > 0

    def test_manifest_contains_execute_trade(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        tool_names = [t["tool_name"] for t in manifest["tool_authorizations"]]
        assert "execute_trade" in tool_names

    def test_manifest_uca_refs_populated(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        execute_trade = next(
            t
            for t in manifest["tool_authorizations"]
            if t["tool_name"] == "execute_trade"
        )
        assert isinstance(execute_trade["uca_refs"], list)
        assert len(execute_trade["uca_refs"]) > 0

    def test_manifest_hazard_refs_populated(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        execute_trade = next(
            t
            for t in manifest["tool_authorizations"]
            if t["tool_name"] == "execute_trade"
        )
        assert isinstance(execute_trade["hazard_refs"], list)
        assert len(execute_trade["hazard_refs"]) > 0
        # H-1 must be referenced (execute_trade is constrained by H-1)
        assert "H-1" in execute_trade["hazard_refs"]

    def test_manifest_is_valid_json(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest_str = generate_registry_manifest(self.cs)
        # Should not raise
        parsed = json.loads(manifest_str)
        assert isinstance(parsed, dict)

    def test_manifest_schema_version_present(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        assert manifest["_schema_version"] == "1.0.0"

    def test_manifest_generated_by_correct(self):
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        assert manifest["_generated_by"] == "CAGE stpa_compiler"

    def test_manifest_allowed_roles_from_rbac(self):
        """allowed_roles must be populated from rbac_rules when present."""
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        execute_trade = next(
            (
                t
                for t in manifest["tool_authorizations"]
                if t["tool_name"] == "execute_trade"
            ),
            None,
        )
        if execute_trade is None:
            pytest.skip("execute_trade not in manifest")

        if self.cs.rbac_rules:
            # At least one role should be allowed or denied
            assert isinstance(execute_trade["allowed_roles"], list)
            assert isinstance(execute_trade["denied_roles"], list)

    def test_manifest_requires_approval_threshold_when_rbac_present(self):
        """requires_approval_above_usd is set when rbac trade_limits are defined."""
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        execute_trade = next(
            (
                t
                for t in manifest["tool_authorizations"]
                if t["tool_name"] == "execute_trade"
            ),
            None,
        )
        if execute_trade is None:
            pytest.skip("execute_trade not in manifest")

        if self.cs.rbac_rules:
            has_limits = any(
                r.trade_limits and r.trade_limits.get("manual_review_below")
                for r in self.cs.rbac_rules.roles
                if "execute_trade" in r.allowed_actions
            )
            if has_limits:
                assert "requires_approval_above_usd" in execute_trade
                assert isinstance(
                    execute_trade["requires_approval_above_usd"], (int, float)
                )

    def test_manifest_all_actions_present(self):
        """Every unique action in unsafe_control_actions appears in the manifest."""
        from src.gateway.governance.stpa_compiler import generate_registry_manifest

        manifest = json.loads(generate_registry_manifest(self.cs))
        tool_names = {t["tool_name"] for t in manifest["tool_authorizations"]}
        expected_actions = {uca.action for uca in self.cs.unsafe_control_actions}
        assert expected_actions == tool_names

    def test_manifest_output_dir_cli(self, tmp_path):
        """CLI --targets registry writes the manifest to the specified path."""
        from src.gateway.governance.stpa_compiler import main

        out_file = tmp_path / "generated_tool_authorizations.json"
        stpa_path = (
            Path(__file__).resolve().parents[1]
            / "config"
            / "stpa_control_structure.yaml"
        )
        if not stpa_path.exists():
            pytest.skip("stpa_control_structure.yaml not found")

        rc = main(
            [
                "compile",
                "--targets",
                "registry",
                "--input",
                str(stpa_path),
                "--registry-out",
                str(out_file),
            ]
        )
        assert rc == 0
        assert out_file.exists()
        manifest = json.loads(out_file.read_text())
        assert "tool_authorizations" in manifest
        assert "_schema_version" in manifest
