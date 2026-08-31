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

import pytest

from src.gateway.governance.contracts import (
    CAGE_PLUGIN_API_VERSION,
    CagePlugin,
    validate_plugin,
)


class ValidPlugin:
    name = "test"
    api_version = "1.0"

    def register(self, governor, tool_server=None):
        pass


class WrongNamePlugin:
    name = "wrong"
    api_version = "1.0"

    def register(self, governor, tool_server=None):
        pass


class IncompatibleVersionPlugin:
    name = "test"
    api_version = "2.0"

    def register(self, governor, tool_server=None):
        pass


class MinorVersionOkPlugin:
    name = "test"
    api_version = "1.5"

    def register(self, governor, tool_server=None):
        pass


class NotAPlugin:
    pass


class MissingRegisterPlugin:
    name = "test"
    api_version = "1.0"


@pytest.mark.local
@pytest.mark.unit
def test_valid_plugin_passes():
    plugin = ValidPlugin()
    validated = validate_plugin(plugin, entry_point_name="test")
    # In python versions < 3.10 with Protocol, isinstance checking can sometimes be problematic
    # but runtime_checkable should make it work.
    assert isinstance(validated, CagePlugin)


@pytest.mark.local
@pytest.mark.unit
def test_wrong_name_raises_value_error():
    plugin = WrongNamePlugin()
    with pytest.raises(ValueError):
        validate_plugin(plugin, entry_point_name="test")


@pytest.mark.local
@pytest.mark.unit
def test_incompatible_major_version_raises():
    plugin = IncompatibleVersionPlugin()
    with pytest.raises(ValueError):
        validate_plugin(plugin, entry_point_name="test")


@pytest.mark.local
@pytest.mark.unit
def test_minor_version_compatible():
    plugin = MinorVersionOkPlugin()
    validated = validate_plugin(plugin, entry_point_name="test")
    assert isinstance(validated, CagePlugin)


@pytest.mark.local
@pytest.mark.unit
def test_not_a_plugin_raises_type_error():
    plugin = NotAPlugin()
    with pytest.raises(TypeError):
        validate_plugin(plugin, entry_point_name="test")


@pytest.mark.local
@pytest.mark.unit
def test_missing_register_raises_type_error():
    plugin = MissingRegisterPlugin()
    with pytest.raises(TypeError):
        validate_plugin(plugin, entry_point_name="test")


@pytest.mark.local
@pytest.mark.unit
def test_cage_plugin_api_version_constant():
    assert CAGE_PLUGIN_API_VERSION == "1.0"
