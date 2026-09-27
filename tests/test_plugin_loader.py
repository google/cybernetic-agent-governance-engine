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

"""Single-domain plugin loading: CAGE_DOMAIN selects exactly one plugin, fail-closed."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.contracts import DomainConfig
from src.gateway.governance.env_posture import resolve_domain
from src.gateway.governance.plugin_loader import (
    active_domain_config,
    domain_config_of,
    load_domain_plugin,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class FakePlugin:
    def __init__(self, name, api_version="1.0", domain_config=None):
        self.name = name
        self.api_version = api_version
        self.domain_config = domain_config

    def register(self, governor, tool_server=None):
        pass


def make_mock_entry_point(name, plugin_instance=None, raise_exc=None):
    ep = MagicMock()
    ep.name = name
    if raise_exc:
        ep.load.side_effect = raise_exc
    else:
        ep.load.return_value = MagicMock(return_value=plugin_instance)
    return ep


@pytest.fixture
def entry_points():
    eps = [make_mock_entry_point("finance", FakePlugin("finance")), make_mock_entry_point("other", FakePlugin("other"))]
    with patch("importlib.metadata.entry_points", return_value=eps):
        yield eps


# --- resolve_domain() -------------------------------------------------------


def test_resolve_domain_returns_the_single_named_domain(monkeypatch):
    monkeypatch.setenv("CAGE_DOMAIN", " Finance ")
    assert resolve_domain() == "finance"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_resolve_domain_unset_or_blank_fails_closed(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("CAGE_DOMAIN", raising=False)
    else:
        monkeypatch.setenv("CAGE_DOMAIN", value)
    with pytest.raises(RuntimeError, match="CAGE_DOMAIN is not set"):
        resolve_domain()


@pytest.mark.parametrize("value", ["finance,healthcare", "finance healthcare", "finance,"])
def test_resolve_domain_more_than_one_fails_closed(monkeypatch, value):
    monkeypatch.setenv("CAGE_DOMAIN", value)
    with pytest.raises(RuntimeError, match="more than one domain"):
        resolve_domain()


# --- load_domain_plugin() ---------------------------------------------------


def test_loads_only_the_named_plugin(monkeypatch, entry_points):
    monkeypatch.setenv("CAGE_DOMAIN", "finance")
    assert load_domain_plugin().name == "finance"
    entry_points[1].load.assert_not_called()  # other domains are never imported


def test_explicit_domain_argument_wins(monkeypatch, entry_points):
    monkeypatch.setenv("CAGE_DOMAIN", "finance")
    assert load_domain_plugin("other").name == "other"


def test_unset_domain_fails_closed(monkeypatch, entry_points):
    monkeypatch.delenv("CAGE_DOMAIN", raising=False)
    with pytest.raises(RuntimeError, match="CAGE_DOMAIN is not set"):
        load_domain_plugin()


def test_unknown_domain_fails_closed(entry_points):
    with pytest.raises(RuntimeError, match="matches no registered plugin"):
        load_domain_plugin("retail")


def test_ambiguous_entry_points_fail_closed():
    eps = [make_mock_entry_point("finance", FakePlugin("finance")) for _ in range(2)]
    with patch("importlib.metadata.entry_points", return_value=eps):
        with pytest.raises(RuntimeError, match="must be unique"):
            load_domain_plugin("finance")


def test_plugin_import_failure_propagates():
    ep = make_mock_entry_point("finance", raise_exc=ImportError("Failed to load module"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ImportError):
            load_domain_plugin("finance")


def test_plugin_name_mismatch_fails_closed():
    ep = make_mock_entry_point("finance", FakePlugin("not_finance"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ValueError, match="plugin name.*!=.*entry point"):
            load_domain_plugin("finance")


def test_incompatible_api_version_fails_closed():
    ep = make_mock_entry_point("finance", FakePlugin("finance", api_version="2.0"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ValueError, match="incompatible with kernel"):
            load_domain_plugin("finance")


# --- domain_config_of() -----------------------------------------------------


def test_complete_domain_config_is_returned(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text("{}")
    config = DomainConfig(ftra_registry_path=registry)
    assert domain_config_of(FakePlugin("x", domain_config=config)) is config


def test_missing_domain_config_fails_closed():
    with pytest.raises(RuntimeError, match="declares no DomainConfig"):
        domain_config_of(FakePlugin("healthcare"))


def test_relative_path_fails_closed():
    config = DomainConfig(ftra_registry_path=Path("config/ftra/terminal_registry.json"))
    with pytest.raises(RuntimeError, match="must be absolute"):
        domain_config_of(FakePlugin("x", domain_config=config))


def test_missing_registry_file_fails_closed(tmp_path):
    config = DomainConfig(ftra_registry_path=tmp_path / "absent.json")
    with pytest.raises(RuntimeError, match="ftra_registry_path does not exist"):
        domain_config_of(FakePlugin("x", domain_config=config))


def test_missing_causal_graph_file_fails_closed(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text("{}")
    config = DomainConfig(ftra_registry_path=registry, causal_graph_path=tmp_path / "absent.yaml")
    with pytest.raises(RuntimeError, match="causal_graph_path does not exist"):
        domain_config_of(FakePlugin("x", domain_config=config))


# --- real shipped plugins ---------------------------------------------------


def test_finance_is_runnable_and_declares_existing_config():
    config = domain_config_of(load_domain_plugin("finance"))
    assert config.ftra_registry_path.name == "terminal_registry.json"
    assert config.causal_graph_path is not None and config.causal_graph_path.is_file()


@pytest.mark.parametrize("domain", ["healthcare", "physical_ai"])
def test_domains_without_config_refuse_to_start(domain):
    with pytest.raises(RuntimeError, match="declares no DomainConfig"):
        domain_config_of(load_domain_plugin(domain))


def test_active_domain_config_follows_cage_domain(monkeypatch):
    active_domain_config.cache_clear()
    monkeypatch.setenv("CAGE_DOMAIN", "healthcare")
    try:
        with pytest.raises(RuntimeError, match="declares no DomainConfig"):
            active_domain_config()
    finally:
        active_domain_config.cache_clear()
