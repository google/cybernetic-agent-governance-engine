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

"""Contract tests for the test-session region harness.

Covers ``tests/fixtures/deployment_region.py`` and the region fixtures in
``tests/conftest.py``: hermetic sessions run under US_FED, region markers pin
a hermetic test to their region, and live sessions take the region from the
deployment's ``cage-deployment`` ConfigMap, failing closed on any conflict.
"""

from __future__ import annotations

import configparser
import os
import pathlib
import subprocess
from types import SimpleNamespace

import pytest

from src.gateway.governance.jurisdiction.registry import JURISDICTIONS, active_region
from tests.fixtures import deployment_region as dr

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _item(*markers: str) -> SimpleNamespace:
    """Minimal stand-in for ``pytest.Item`` (only ``keywords``/``nodeid`` used)."""
    return SimpleNamespace(keywords=set(markers), nodeid="tests/x.py::test_x")


# ── Region table ──────────────────────────────────────────────────────────────


def test_region_markers_cover_every_jurisdiction() -> None:
    assert set(dr.REGION_MARKERS.values()) == set(JURISDICTIONS)


def test_region_markers_are_declared_in_pytest_ini() -> None:
    parser = configparser.ConfigParser()
    parser.read(_REPO_ROOT / "pytest.ini")
    declared = {
        line.split(":", 1)[0].strip()
        for line in parser["pytest"]["markers"].splitlines()
        if ":" in line
    }
    assert set(dr.REGION_MARKERS) <= declared


# ── Session region ────────────────────────────────────────────────────────────


def test_hermetic_session_ignores_exported_region() -> None:
    region = dr.resolve_session_region(
        live=False, namespace="unused", env_region="EU_ECB"
    )
    assert region == dr.HERMETIC_DEFAULT_REGION == "US_FED"


@pytest.mark.parametrize("exported", [None, "", "eu_ecb", "EU_ECB"])
def test_live_session_uses_deployed_region(monkeypatch, exported) -> None:
    monkeypatch.setattr(dr, "discover_deployed_region", lambda ns: "EU_ECB")
    region = dr.resolve_session_region(
        live=True, namespace="governance-stack", env_region=exported
    )
    assert region == "EU_ECB"


def test_live_session_refuses_conflicting_export(monkeypatch) -> None:
    monkeypatch.setattr(dr, "discover_deployed_region", lambda ns: "EU_ECB")
    with pytest.raises(dr.DeploymentRegionError, match="configured for EU_ECB"):
        dr.resolve_session_region(
            live=True, namespace="governance-stack", env_region="US_FED"
        )


# ── ConfigMap discovery ───────────────────────────────────────────────────────


def _fake_kubectl(monkeypatch, *, stdout="", stderr="", returncode=0):
    calls: list[list[str]] = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/kubectl")
    monkeypatch.setattr(dr.subprocess, "run", run)
    return calls


def test_discovery_reads_the_cage_deployment_config_map(monkeypatch) -> None:
    calls = _fake_kubectl(monkeypatch, stdout="apac_mas\n")
    assert dr.discover_deployed_region("cage-ns") == "APAC_MAS"
    argv = calls[0]
    assert argv[1:4] == ["get", "configmap", dr.DEPLOYMENT_CONFIG_MAP]
    assert argv[argv.index("--namespace") + 1] == "cage-ns"
    assert argv[-1] == "jsonpath={.data.CAGE_DEPLOYMENT_REGION}"


def test_discovery_fails_closed_without_kubectl(monkeypatch) -> None:
    monkeypatch.setattr(dr.shutil, "which", lambda name: None)
    with pytest.raises(dr.DeploymentRegionError, match="kubectl not found"):
        dr.discover_deployed_region("governance-stack")


def test_discovery_fails_closed_on_kubectl_error(monkeypatch) -> None:
    _fake_kubectl(monkeypatch, returncode=1, stderr="NotFound")
    with pytest.raises(dr.DeploymentRegionError, match="NotFound"):
        dr.discover_deployed_region("governance-stack")


@pytest.mark.parametrize("value", ["", "LOCAL", "us-central1"])
def test_discovery_fails_closed_on_unknown_region(monkeypatch, value) -> None:
    _fake_kubectl(monkeypatch, stdout=value)
    with pytest.raises(dr.DeploymentRegionError, match="expected one of"):
        dr.discover_deployed_region("governance-stack")


def test_discovery_fails_closed_on_timeout(monkeypatch) -> None:
    def run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))

    monkeypatch.setattr(dr.shutil, "which", lambda name: "/usr/bin/kubectl")
    monkeypatch.setattr(dr.subprocess, "run", run)
    with pytest.raises(dr.DeploymentRegionError, match="timed out"):
        dr.discover_deployed_region("governance-stack")


# ── Per-test selection ────────────────────────────────────────────────────────


def test_several_region_markers_are_refused() -> None:
    with pytest.raises(pytest.UsageError, match="several region markers"):
        dr.marked_region(_item("unit", "us_fed", "eu_ecb"))


def test_hermetic_region_marker_pins_the_test() -> None:
    assert dr.region_pin(_item("local", "eu_ecb")) == "EU_ECB"
    assert dr.region_pin(_item("local")) is None
    assert dr.live_region_mismatch(_item("local", "eu_ecb"), "US_FED") is None


def test_live_region_marker_filters_against_the_deployment() -> None:
    live_eu = _item("integration", "eu_ecb")
    assert dr.region_pin(live_eu) is None
    assert dr.live_region_mismatch(live_eu, "EU_ECB") is None
    reason = dr.live_region_mismatch(live_eu, "US_FED")
    assert reason is not None and "configured for US_FED" in reason
    assert dr.live_region_mismatch(_item("e2e"), "APAC_MAS") is None


# ── conftest fixtures ─────────────────────────────────────────────────────────


def test_unmarked_hermetic_test_runs_under_us_fed() -> None:
    assert os.environ[dr.REGION_ENV_VAR] == "US_FED"
    assert active_region() == "US_FED"


@pytest.mark.eu_ecb
def test_eu_ecb_marker_pins_region() -> None:
    assert os.environ[dr.REGION_ENV_VAR] == "EU_ECB"
    assert active_region() == "EU_ECB"


@pytest.mark.apac_mas
def test_apac_mas_marker_pins_region() -> None:
    assert os.environ[dr.REGION_ENV_VAR] == "APAC_MAS"
    assert active_region() == "APAC_MAS"


def test_each_region_applies_the_region(each_region: str) -> None:
    assert each_region in JURISDICTIONS
    assert os.environ[dr.REGION_ENV_VAR] == each_region
    assert active_region() == each_region
