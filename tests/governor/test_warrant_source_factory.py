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

"""``CAGE_WARRANT_SOURCE`` resolution: unset is "no source", unknown raises."""

from __future__ import annotations

import pytest

from src.gateway.governance.seams.warrant import WarrantSource
from src.gateway.governance.warrant.source_factory import (
    WARRANT_SOURCE_ENV,
    UnknownWarrantSourceError,
    warrant_source_from_env,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.parametrize("value", ["", "   "])
def test_unset_or_blank_means_no_source(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(WARRANT_SOURCE_ENV, value)
    assert warrant_source_from_env() is None


def test_absent_env_means_no_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(WARRANT_SOURCE_ENV, raising=False)
    assert warrant_source_from_env() is None


@pytest.mark.parametrize("name", ["provider_05", "PROVIDER_05", "p05"])
def test_known_names_resolve_to_a_warrant_source(name: str) -> None:
    source = warrant_source_from_env(name)
    assert isinstance(source, WarrantSource)
    assert source.provider_name


def test_unknown_name_raises_instead_of_falling_back() -> None:
    with pytest.raises(UnknownWarrantSourceError, match="provider_99"):
        warrant_source_from_env("provider_99")
