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

from pathlib import Path

import pytest

from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    load_control_structure,
    load_control_structures,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_yaml(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


@pytest.mark.local
@pytest.mark.unit
def test_merge_determinism_independent_of_file_order():
    core_path = _REPO_ROOT / "config" / "stpa" / "core_system.yaml"
    trade_path = (
        _REPO_ROOT / "config" / "stpa" / "domains" / "finance" / "trade_hazards.yaml"
    )

    cs_forward = load_control_structures([core_path, trade_path])
    cs_reversed = load_control_structures([trade_path, core_path])

    assert [h.id for h in cs_forward.hazards] == [h.id for h in cs_reversed.hazards]
    assert [u.id for u in cs_forward.unsafe_control_actions] == [
        u.id for u in cs_reversed.unsafe_control_actions
    ]
    assert [c.id for c in cs_forward.safety_constraints] == [
        c.id for c in cs_reversed.safety_constraints
    ]

    # Check UCA IDs are exactly in the same order
    assert [u.id for u in cs_forward.unsafe_control_actions] == [
        u.id for u in cs_reversed.unsafe_control_actions
    ]


@pytest.mark.local
@pytest.mark.unit
def test_merge_union_of_single_file_matches_monolithic():
    stpa_dir = _REPO_ROOT / "config" / "stpa"
    split_files = sorted(stpa_dir.rglob("*.yaml"))

    cs_merged = load_control_structures(split_files)

    monolithic_path = _REPO_ROOT / "config" / "stpa_control_structure.yaml"
    cs_mono = load_control_structure(monolithic_path)

    # Same hazard IDs
    assert [h.id for h in cs_merged.hazards] == [h.id for h in cs_mono.hazards]

    # Same UCA IDs
    assert [u.id for u in cs_merged.unsafe_control_actions] == [
        u.id for u in cs_mono.unsafe_control_actions
    ]

    # Same hazard refs on each UCA
    merged_refs = {
        u.id: sorted(u.hazard_refs) for u in cs_merged.unsafe_control_actions
    }
    mono_refs = {u.id: sorted(u.hazard_refs) for u in cs_mono.unsafe_control_actions}
    assert merged_refs == mono_refs

    # Same control action names
    merged_ca_names = sorted([ca["name"] for ca in cs_merged.control_actions])
    mono_ca_names = sorted([ca["name"] for ca in cs_mono.control_actions])
    assert merged_ca_names == mono_ca_names


@pytest.mark.local
@pytest.mark.unit
def test_duplicate_hazard_id_across_files_raises(tmp_path):
    yaml1 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards:
  - id: H-1
    description: Test hazard
    severity: high
control_actions: []
unsafe_control_actions: []
safety_constraints: []
"""
    yaml2 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards:
  - id: H-1
    description: Test hazard 2
    severity: high
control_actions: []
unsafe_control_actions: []
safety_constraints: []
"""
    p1 = _write_yaml(tmp_path, "f1.yaml", yaml1)
    p2 = _write_yaml(tmp_path, "f2.yaml", yaml2)

    with pytest.raises(ValueError, match="Duplicate hazard ID"):
        load_control_structures([p1, p2])


@pytest.mark.local
@pytest.mark.unit
def test_duplicate_uca_id_across_files_raises(tmp_path):
    yaml1 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards:
  - id: H-1
    description: Test hazard
    severity: high
control_actions:
  - name: action1
    description: Test action
unsafe_control_actions:
  - id: UCA-TEST-1
    action: action1
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: Test
    condition:
      param: p
      operator: is_null
    enforcement: [python]
safety_constraints: []
"""
    yaml2 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards:
  - id: H-2
    description: Test hazard
    severity: high
control_actions:
  - name: action2
    description: Test action
unsafe_control_actions:
  - id: UCA-TEST-1
    action: action2
    uca_type: unsafe_action
    hazard_refs: [H-2]
    description: Test 2
    condition:
      param: p
      operator: is_null
    enforcement: [python]
safety_constraints: []
"""

    p1 = _write_yaml(tmp_path, "f1.yaml", yaml1)
    p2 = _write_yaml(tmp_path, "f2.yaml", yaml2)

    with pytest.raises(ValueError, match="Duplicate UCA ID"):
        load_control_structures([p1, p2])


@pytest.mark.local
@pytest.mark.unit
def test_dangling_hazard_ref_raises(tmp_path):
    yaml1 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards:
  - id: H-1
    description: Test
    severity: high
control_actions: []
unsafe_control_actions: []
safety_constraints: []
"""
    yaml2 = """
system:
  name: Test System
  version: "0.1"
  description: Test
  controller: TestController
  controlled_process: TestProcess
hazards: []
control_actions:
  - name: action1
    description: Test action
unsafe_control_actions:
  - id: UCA-TEST-1
    action: action1
    uca_type: unsafe_action
    hazard_refs: [H-NONEXISTENT]
    description: Test
    condition:
      param: p
      operator: is_null
    enforcement: [python]
safety_constraints: []
"""
    p1 = _write_yaml(tmp_path, "f1.yaml", yaml1)
    p2 = _write_yaml(tmp_path, "f2.yaml", yaml2)

    with pytest.raises(ValueError, match="references hazard"):
        load_control_structures([p1, p2])


@pytest.mark.local
@pytest.mark.unit
def test_load_control_structures_single_file_is_passthrough():
    single_path = _REPO_ROOT / "config" / "stpa_control_structure.yaml"

    cs_list = load_control_structures([single_path])
    cs_single = load_control_structure(single_path)

    assert [h.id for h in cs_list.hazards] == [h.id for h in cs_single.hazards]
    assert [u.id for u in cs_list.unsafe_control_actions] == [
        u.id for u in cs_single.unsafe_control_actions
    ]


@pytest.mark.local
@pytest.mark.unit
def test_load_control_structures_empty_list_raises():
    with pytest.raises(ValueError):
        load_control_structures([])
