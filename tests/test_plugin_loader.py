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

from unittest.mock import MagicMock, patch

import pytest

from src.gateway.governance.plugin_loader import discover_plugins


class FakePlugin:
    def __init__(self, name, api_version="1.0"):
        self.name = name
        self.api_version = api_version

    def register(self, governor):
        pass


def make_mock_entry_point(name, plugin_instance=None, raise_exc=None):
    ep = MagicMock()
    ep.name = name
    if raise_exc:
        ep.load.side_effect = raise_exc
    else:
        # load returns the plugin CLASS, discover_plugins probably instantiates it
        mock_class = MagicMock()
        mock_class.return_value = plugin_instance
        ep.load.return_value = mock_class
    return ep


@pytest.fixture
def mock_entry_points():
    finance_ep = make_mock_entry_point("finance", FakePlugin("finance"))
    other_ep = make_mock_entry_point("other", FakePlugin("other"))

    with patch("importlib.metadata.entry_points") as mock_ep:
        mock_ep.return_value = [finance_ep, other_ep]
        yield mock_ep


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_unset_none(monkeypatch, mock_entry_points):
    monkeypatch.delenv("CAGE_ACTIVE_PLUGINS", raising=False)
    plugins = discover_plugins(activation_list=None)
    names = {p.name for p in plugins}
    assert names == {"finance", "other"}


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_empty_none(monkeypatch, mock_entry_points):
    monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "")
    plugins = discover_plugins(activation_list=None)
    assert len(plugins) == 0


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_finance_none(monkeypatch, mock_entry_points):
    monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance")
    plugins = discover_plugins(activation_list=None)
    names = {p.name for p in plugins}
    assert names == {"finance"}


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_finance_other_none(monkeypatch, mock_entry_points):
    monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance,other")
    plugins = discover_plugins(activation_list=None)
    names = {p.name for p in plugins}
    assert names == {"finance", "other"}


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_any_empty_list(monkeypatch, mock_entry_points):
    monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance,other")
    plugins = discover_plugins(activation_list=[])
    assert len(plugins) == 0


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_any_finance_list(monkeypatch, mock_entry_points):
    monkeypatch.setenv("CAGE_ACTIVE_PLUGINS", "finance,other")
    plugins = discover_plugins(activation_list=["finance"])
    names = {p.name for p in plugins}
    assert names == {"finance"}


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_fails_to_load(monkeypatch):
    monkeypatch.delenv("CAGE_ACTIVE_PLUGINS", raising=False)
    ep = make_mock_entry_point("bad", raise_exc=ImportError("Failed to load module"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ImportError):
            discover_plugins()


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_wrong_name():
    # entry point name doesn't match plugin name
    ep = make_mock_entry_point("finance", FakePlugin("not_finance"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ValueError, match="plugin name.*!=.*entry point"):
            discover_plugins()


@pytest.mark.local
@pytest.mark.unit
def test_discover_plugins_incompatible_api_version():
    ep = make_mock_entry_point("finance", FakePlugin("finance", api_version="2.0"))
    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with pytest.raises(ValueError, match="incompatible with kernel"):
            discover_plugins()
