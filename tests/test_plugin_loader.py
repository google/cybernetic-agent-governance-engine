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

"""Tests for plugin loader and discovery mechanism.

D1 regression tests: verify the plugin activation filter semantics are correct.
The inverted condition bug would load all plugins when activation_list=[] (empty),
which is the opposite of the intended bare-kernel mode.
"""

import os
from unittest import mock

import pytest


class TestPluginActivationSemantics:
    """D1 regression test suite: plugin activation filter truth table.

    Per implementation plan §1.2.2 (lines 481-490), these six cases must be
    distinguished correctly. The D1 bug inverted the skip-guard, causing
    an empty activation list to load ALL plugins instead of NONE.
    """

    def test_unset_env_none_arg_loads_all(self, monkeypatch):
        """CAGE_ACTIVE_PLUGINS unset + activation_list=None → load all discovered."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.delenv("CAGE_ACTIVE_PLUGINS", raising=False)

        # Mock entry_points to return a known set
        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(["finance", "other"])
            plugins = discover_plugins(activation_list=None)

        assert len(plugins) == 2, "unset env + None arg should load all discovered"

    def test_empty_string_env_none_arg_loads_none(self, monkeypatch):
        """CAGE_ACTIVE_PLUGINS="" + activation_list=None → load NO plugins (bare kernel).

        D1 FIX VERIFICATION: This is the critical case. The inverted condition
        would have loaded ALL plugins here, defeating bare-kernel mode.
        """
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "")

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(["finance", "other"])
            plugins = discover_plugins(activation_list=None)

        assert len(plugins) == 0, (
            "D1 REGRESSION: empty string should load ZERO plugins (bare kernel). "
            f"Got {len(plugins)} plugins. This indicates the activation filter is inverted."
        )

    def test_single_plugin_env_loads_one(self, monkeypatch):
        """CAGE_ACTIVE_PLUGINS="finance" + activation_list=None → load only finance."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance")

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(["finance", "other"])
            plugins = discover_plugins(activation_list=None)

        assert len(plugins) == 1
        assert plugins[0].name == "finance"

    def test_multi_plugin_env_loads_multiple(self, monkeypatch):
        """CAGE_ACTIVE_PLUGINS="finance,other" + activation_list=None → load both."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance,other")

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(
                ["finance", "other", "third"]
            )
            plugins = discover_plugins(activation_list=None)

        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"finance", "other"}

    def test_explicit_empty_list_loads_none(self, monkeypatch):
        """activation_list=[] overrides env → load NO plugins."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance,other")  # Should be ignored

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(["finance", "other"])
            plugins = discover_plugins(activation_list=[])

        assert len(plugins) == 0, "explicit empty list should override env"

    def test_explicit_list_overrides_env(self, monkeypatch):
        """activation_list=["finance"] overrides env → load only finance."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "other")  # Should be ignored

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(["finance", "other"])
            plugins = discover_plugins(activation_list=["finance"])

        assert len(plugins) == 1
        assert plugins[0].name == "finance"

    def test_whitespace_handling_in_env(self, monkeypatch):
        """CAGE_ACTIVE_PLUGINS=" finance , other " → loads both (whitespace stripped)."""
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", " finance , other ")

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            mock_eps.return_value = self._mock_entry_points(
                ["finance", "other", "third"]
            )
            plugins = discover_plugins(activation_list=None)

        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert names == {"finance", "other"}

    @staticmethod
    def _mock_entry_points(plugin_names: list[str]):
        """Create mock entry points for testing."""
        eps = []
        for name in plugin_names:
            ep = mock.Mock()
            ep.name = name
            ep.load.return_value = type(
                f"Mock{name.capitalize()}Plugin",
                (),
                {
                    "name": name,
                    "api_version": "1.0",
                    "register": lambda self, governor, tool_server=None: None,
                },
            )
            eps.append(ep)
        return eps


class TestPluginValidation:
    """D7 regression tests: CagePlugin protocol validation."""

    def test_plugin_name_mismatch_rejected(self):
        """Plugin name must match entry-point name (fail-closed)."""
        from src.gateway.governance.contracts import validate_plugin

        class MismatchedPlugin:
            name = "wrong_name"
            api_version = "1.0"

            def register(self, governor, tool_server=None):
                pass

        with pytest.raises(
            ValueError, match="plugin name 'wrong_name' != entry point 'finance'"
        ):
            validate_plugin(MismatchedPlugin(), entry_point_name="finance")

    def test_incompatible_api_version_rejected(self):
        """Plugin api_version major mismatch must be rejected (fail-closed)."""
        from src.gateway.governance.contracts import validate_plugin

        class IncompatiblePlugin:
            name = "finance"
            api_version = "2.0"  # CAGE_PLUGIN_API_VERSION is "1.0"

            def register(self, governor, tool_server=None):
                pass

        with pytest.raises(ValueError, match="api_version 2.0 is incompatible"):
            validate_plugin(IncompatiblePlugin(), entry_point_name="finance")

    def test_non_conforming_object_rejected(self):
        """Object that doesn't satisfy CagePlugin protocol must be rejected."""
        from src.gateway.governance.contracts import validate_plugin

        class NonConformingPlugin:
            # Missing `name`, `api_version`, and `register`
            pass

        with pytest.raises(TypeError, match="does not satisfy the CagePlugin protocol"):
            validate_plugin(NonConformingPlugin(), entry_point_name="finance")

    def test_valid_plugin_accepted(self):
        """Well-formed plugin passes validation."""
        from src.gateway.governance.contracts import validate_plugin

        class ValidPlugin:
            name = "finance"
            api_version = "1.0"

            def register(self, governor, tool_server=None):
                pass

        # Should not raise
        result = validate_plugin(ValidPlugin(), entry_point_name="finance")
        assert result.name == "finance"


class TestPluginLoadFailure:
    """Fail-closed behavior when plugin loading fails."""

    def test_import_error_propagates(self, monkeypatch):
        """Plugin that cannot be imported must propagate the exception (fail-closed).

        Per plan §1.2.2: "Fail closed: a plugin that cannot be imported must not
        be silently downgraded to 'absent'."
        """
        from src.gateway.governance.plugin_loader import discover_plugins

        monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "broken")

        with mock.patch("importlib.metadata.entry_points") as mock_eps:
            ep = mock.Mock()
            ep.name = "broken"
            ep.load.side_effect = ImportError("module not found")
            mock_eps.return_value = [ep]

            with pytest.raises(ImportError, match="module not found"):
                discover_plugins(activation_list=None)


# Pytest markers
pytestmark = [
    pytest.mark.unit,
    pytest.mark.local,
]
