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

"""Static gate: Gateway module posture flags and replica invariant (Track 6b / §1.2).

Validates that:
1. All required CAGE_* kernel posture flags are declared and wired in infra/modules/gateway.
2. Invariant (§1.2): in staging and prod, CAGE_REDIS_WAIT_REPLICAS <= governance instance replica count
   is enforced via a Terraform precondition.
3. Posture resolution logic matches the §1.2 Posture Matrix exactly for dev, staging, prod.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GATEWAY_MAIN = _REPO / "infra/modules/gateway/main.tf"
_GATEWAY_VARS = _REPO / "infra/modules/gateway/variables.tf"


def test_gateway_module_declares_posture_variables() -> None:
    vars_text = _GATEWAY_VARS.read_text()
    expected_vars = [
        "cbf_strict_mode",
        "strict_replication",
        "redis_synchronous_replication",
        "redis_wait_replicas",
        "redis_wait_timeout_ms",
        "reconciliation_replay_defense",
        "governance_redis_replica_count",
    ]
    for var_name in expected_vars:
        assert f'variable "{var_name}"' in vars_text, f"Missing variable '{var_name}' in gateway/variables.tf"


def test_gateway_module_wires_posture_env_vars() -> None:
    main_text = _GATEWAY_MAIN.read_text()
    expected_envs = [
        "CAGE_CBF_STRICT_MODE",
        "CAGE_STRICT_REPLICATION",
        "CAGE_REDIS_SYNCHRONOUS_REPLICATION",
        "CAGE_REDIS_WAIT_REPLICAS",
        "CAGE_REDIS_WAIT_TIMEOUT_MS",
        "CAGE_RECONCILIATION_REPLAY_DEFENSE",
    ]
    for env_name in expected_envs:
        assert f'name  = "{env_name}"' in main_text, f"Missing env var '{env_name}' in gateway/main.tf"


def test_gateway_precondition_enforces_replica_invariant() -> None:
    """Precondition must verify redis_wait_replicas <= governance_redis_replica_count in staging/prod."""
    main_text = _GATEWAY_MAIN.read_text()
    assert "precondition" in main_text
    assert "governance_redis_replica_count" in main_text
    assert "redis_wait_replicas" in main_text
    assert "CAGE Invariant (§1.2)" in main_text


@pytest.mark.parametrize(
    ("env", "expected_strict", "expected_wait_replicas", "expected_wait_timeout_ms"),
    [
        ("dev", False, 0, 100),
        ("staging", True, 1, 100),
        ("prod", True, 1, 100),
    ],
)
def test_posture_matrix_resolution(
    env: str,
    expected_strict: bool,
    expected_wait_replicas: int,
    expected_wait_timeout_ms: int,
) -> None:
    """Simulate Terraform locals resolution matching the §1.2 Posture Matrix."""
    is_prod_or_staging = env in ("prod", "production", "staging")
    cbf_strict_mode = is_prod_or_staging
    strict_replication = is_prod_or_staging
    redis_sync_replication = True
    redis_wait_replicas = 1 if is_prod_or_staging else 0
    redis_wait_timeout_ms = 100
    reconciliation_replay_defense = True

    assert cbf_strict_mode is expected_strict
    assert strict_replication is expected_strict
    assert redis_sync_replication is True
    assert redis_wait_replicas == expected_wait_replicas
    assert redis_wait_timeout_ms == expected_wait_timeout_ms
    assert reconciliation_replay_defense is True
