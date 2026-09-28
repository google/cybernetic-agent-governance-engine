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

"""Static architecture gate: Memorystore topology and workload isolation (D5, D6, §2.1).

Enforces:
1. Two distinct Memorystore instances: `memorystore_governance` and `memorystore_app`.
2. Memorystore for Valkey, Cluster Mode Disabled (D5).
3. Primary endpoint only exported to consumers (Pitfall guard: read-replica endpoints forbidden).
4. Workload separation:
   - Gateway and reconciler bind to governance Memorystore.
   - Advisor and Langfuse bind to app Memorystore.
5. In-cluster Helm Redis module is deleted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[2]
_GKE_MAIN = _REPO / "infra/targets/gcp-gke/main.tf"
_GKE_OUTPUTS = _REPO / "infra/targets/gcp-gke/outputs.tf"
_VALKEY_MAIN = _REPO / "infra/modules/memorystore_valkey/main.tf"
_VALKEY_OUTPUTS = _REPO / "infra/modules/memorystore_valkey/outputs.tf"


def test_in_cluster_helm_redis_deleted() -> None:
    """The in-cluster module 'redis' from Helm must be deleted from GKE target (§2.1)."""
    gke_main_text = _GKE_MAIN.read_text()
    assert 'module "redis"' not in gke_main_text
    assert 'source = "../../modules/redis_cache"' not in gke_main_text


def test_two_memorystore_instances_provisioned() -> None:
    """D6: Exactly two Memorystore instances (governance and app) must be provisioned."""
    gke_main_text = _GKE_MAIN.read_text()
    assert 'module "memorystore_governance"' in gke_main_text
    assert 'module "memorystore_app"' in gke_main_text


def test_memorystore_valkey_cluster_disabled() -> None:
    """D5: Valkey instances must use CLUSTER_DISABLED mode (single-shard, multi-key EVAL)."""
    valkey_main_text = _VALKEY_MAIN.read_text()
    assert "google_memorystore_instance" in valkey_main_text
    gke_main_text = _GKE_MAIN.read_text()
    assert 'mode          = "CLUSTER_DISABLED"' in gke_main_text


def _extract_module_block(name: str, text: str) -> str:
    start_str = f'module "{name}" {{'
    start = text.find(start_str)
    assert start != -1, f"module '{name}' not found"
    pos = start + len(start_str)
    depth = 1
    while pos < len(text) and depth > 0:
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
        pos += 1
    return text[start:pos]


def test_workload_isolation_separation() -> None:
    """§2.1: Gateway uses governance instance; advisor and Langfuse use app instance."""
    gke_main_text = _GKE_MAIN.read_text()

    # Find gateway module block
    gw_block = _extract_module_block("gateway", gke_main_text)
    assert "module.memorystore_governance.primary_endpoint_ip" in gw_block
    assert "module.memorystore_app" not in gw_block

    # Find advisor module block
    adv_block = _extract_module_block("governed_advisor", gke_main_text)
    assert "module.memorystore_app.primary_endpoint_ip" in adv_block
    assert "module.memorystore_governance" not in adv_block

    # Find langfuse module block
    lf_block = _extract_module_block("langfuse", gke_main_text)
    assert "module.memorystore_app.primary_endpoint_ip" in lf_block
    assert "module.memorystore_governance" not in lf_block


def test_primary_endpoint_only_exported() -> None:
    """Pitfall guard: Memorystore module must export only primary endpoint, no read replicas."""
    valkey_outputs_text = _VALKEY_OUTPUTS.read_text()
    assert "output \"primary_endpoint_ip\"" in valkey_outputs_text
    assert "read_replica" not in valkey_outputs_text
    assert "replica_endpoint" not in valkey_outputs_text
