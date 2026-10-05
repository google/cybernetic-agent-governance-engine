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

"""Kernel config comes from the single active domain, never a hard-coded domain."""

from pathlib import Path

import pandas as pd
import pytest

from src.gateway.governance.causal import gatekeeper
from src.gateway.governance.contracts import DomainConfig
from src.gateway.governance.ftra import classifier

pytestmark = [pytest.mark.unit, pytest.mark.local]

_PKG = "trade.governance"
_RULES = ("allow",)

_KERNEL = Path(__file__).resolve().parents[1] / "src" / "gateway"


def test_kernel_does_not_hard_code_a_domain_package_path():
    offenders = [
        str(p.relative_to(_KERNEL))
        for p in (
            _KERNEL / "governance" / "causal" / "gatekeeper.py",
            _KERNEL / "governance" / "ftra" / "classifier.py",
        )
        if '"cage_finance"' in p.read_text() or "cage_finance/config" in p.read_text()
    ]
    assert offenders == []


def test_ftra_registry_path_comes_from_active_domain(monkeypatch, tmp_path):
    registry = tmp_path / "registry.json"
    monkeypatch.setattr(
        "src.gateway.governance.plugin_loader.active_domain_config",
        lambda: DomainConfig(
            ftra_registry_path=registry, opa_package=_PKG, opa_required_rules=_RULES
        ),
    )
    assert classifier._active_registry_path() == registry


def test_ftra_classifier_fails_closed_without_a_runnable_domain(monkeypatch):
    def _refuse():
        raise RuntimeError("domain 'healthcare' declares no DomainConfig")

    monkeypatch.setattr(
        "src.gateway.governance.plugin_loader.active_domain_config", _refuse
    )
    monkeypatch.setattr(classifier, "_registry_cache", None)
    with pytest.raises(RuntimeError, match="declares no DomainConfig"):
        classifier._get_registry()


@pytest.fixture
def causal_ready(monkeypatch):
    """Reach the causal-config step: dowhy present, telemetry supplied."""
    monkeypatch.setattr(gatekeeper, "_DOWHY_AVAILABLE", True)
    gatekeeper._causal_config.cache_clear()
    yield pd.DataFrame()
    gatekeeper._causal_config.cache_clear()


def test_causal_check_fails_closed_when_domain_has_no_causal_graph(
    monkeypatch, causal_ready, tmp_path
):
    registry = tmp_path / "registry.json"
    monkeypatch.setattr(
        "src.gateway.governance.plugin_loader.active_domain_config",
        lambda: DomainConfig(
            ftra_registry_path=registry,
            opa_package=_PKG,
            opa_required_rules=_RULES,
            causal_graph_path=None,
        ),
    )
    assert (
        gatekeeper.causal_safety_check(
            {"amount": 100.0}, current_telemetry=causal_ready
        )
        is False
    )


def test_causal_check_fails_closed_when_domain_config_unavailable(
    monkeypatch, causal_ready
):
    def _refuse():
        raise RuntimeError("CAGE_DOMAIN is not set")

    monkeypatch.setattr(
        "src.gateway.governance.plugin_loader.active_domain_config", _refuse
    )
    assert (
        gatekeeper.causal_safety_check(
            {"amount": 100.0}, current_telemetry=causal_ready
        )
        is False
    )


def test_causal_config_loads_the_active_domains_graph(
    monkeypatch, causal_ready, tmp_path
):
    graph = tmp_path / "causal_graph.yaml"
    graph.write_text("treatment: t\noutcome: o\ngraph: 'digraph { t -> o; }'\n")
    monkeypatch.setattr(
        "src.gateway.governance.plugin_loader.active_domain_config",
        lambda: DomainConfig(
            ftra_registry_path=tmp_path / "r.json",
            opa_package=_PKG,
            opa_required_rules=_RULES,
            causal_graph_path=graph,
        ),
    )
    assert gatekeeper._causal_config()["treatment"] == "t"
