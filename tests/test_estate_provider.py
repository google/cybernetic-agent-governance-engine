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

"""Fail-closed resolution tests for the EstateProvider factory."""

from __future__ import annotations

import builtins
import importlib.util

import pytest

from src.gateway.governance.estate_provider import (
    StubEstateProvider,
    UnavailableEstateProvider,
    get_estate_provider,
)
from src.gateway.governance.seams.estate import EstateQueryStatus

pytestmark = [pytest.mark.unit, pytest.mark.local]

_P09 = "src.integrations.provider_09"


def test_unset_env_resolves_to_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CAGE_ESTATE_PROVIDER", raising=False)
    assert isinstance(get_estate_provider(), UnavailableEstateProvider)


def test_unknown_provider_raises() -> None:
    with pytest.raises(ValueError, match="Unknown estate provider"):
        get_estate_provider("provider_99")


def test_stub_refused_outside_dev_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")
    with pytest.raises(RuntimeError):
        get_estate_provider("stub")


def test_stub_allowed_in_test_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    assert isinstance(get_estate_provider("stub"), StubEstateProvider)


@pytest.mark.skipif(
    importlib.util.find_spec(_P09) is not None,
    reason="provider_09 adapter is installed; slot is no longer empty",
)
@pytest.mark.parametrize("alias", ["provider_09", "opscanvas", "p09"])
async def test_uninstalled_provider_09_fails_closed(alias: str) -> None:
    provider = get_estate_provider(alias)
    assert isinstance(provider, UnavailableEstateProvider)

    predicate = await provider.get_resource_predicate("gcp:sql:us-central1:primary")
    assert predicate.status is EstateQueryStatus.UNAVAILABLE
    assert not predicate.is_trustworthy
    assert predicate.error == "provider_09 adapter not installed"

    blast = await provider.query_blast_radius("gcp:sql:us-central1:primary", "delete")
    assert blast.requires_approval and not blast.is_trustworthy

    snapshot = await provider.get_topology_snapshot("project:demo")
    assert snapshot.ttl_seconds == 0 and not snapshot.is_trustworthy


def test_inner_import_error_is_not_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing dependency *inside* an installed adapter must propagate."""
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == _P09:
            raise ModuleNotFoundError("No module named 'mcp'", name="mcp")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ModuleNotFoundError, match="mcp"):
        get_estate_provider("provider_09")
