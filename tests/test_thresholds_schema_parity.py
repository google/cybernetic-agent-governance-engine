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

"""Parity between ``config/governance_thresholds.json`` and the Pydantic schema.

A key that exists in the JSON but not in ``GovernanceThresholds`` is silently
dropped by Pydantic (``extra='ignore'``), so a typo or an un-modelled block
would look configured while the code reads a default. This walks every leaf
of the JSON and requires ``THRESHOLDS.resolve()`` to succeed, and checks the
env-override map only names paths that resolve.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.gateway.governance.schemas.thresholds import (
    _ENV_CONFIG_PATH,
    _ENV_OVERRIDES,
    THRESHOLDS,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _leaf_paths(node: Any, prefix: str = "") -> list[str]:
    """Dot-paths of every non-comment leaf in the raw JSON."""
    paths: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("_"):
                continue  # _comment*, _schema_version, _env_override_comment
            child = f"{prefix}.{key}" if prefix else key
            paths.extend(_leaf_paths(value, child))
    else:
        paths.append(prefix)
    return paths


def _raw_config() -> dict[str, Any]:
    return json.loads(Path(_ENV_CONFIG_PATH).read_text())


def test_every_json_key_resolves() -> None:
    raw = _raw_config()
    leaves = _leaf_paths(raw)
    assert leaves, "governance_thresholds.json produced no leaves"
    unresolved = []
    for dot_path in leaves:
        try:
            THRESHOLDS.resolve(dot_path)
        except KeyError:
            unresolved.append(dot_path)
    assert unresolved == [], f"JSON keys the schema does not model: {unresolved}"


def test_every_env_override_path_resolves() -> None:
    bad = []
    for env_var, (dot_path, _type_fn) in _ENV_OVERRIDES.items():
        try:
            THRESHOLDS.resolve(dot_path)
        except KeyError:
            bad.append((env_var, dot_path))
    assert bad == [], f"_ENV_OVERRIDES entries pointing at unknown paths: {bad}"


def test_reconciliation_block_is_modelled_and_defaults_match_json() -> None:
    raw = _raw_config()["reconciliation"]
    recon = THRESHOLDS.reconciliation
    assert recon.discrepancy_ratio == pytest.approx(raw["discrepancy_ratio"])
    assert recon.discrepancy_abs_floor == pytest.approx(raw["discrepancy_abs_floor"])
    assert recon.settlement_lag_seconds == pytest.approx(raw["settlement_lag_seconds"])
    assert recon.settlement_clock_skew_seconds == pytest.approx(
        raw["settlement_clock_skew_seconds"]
    )
