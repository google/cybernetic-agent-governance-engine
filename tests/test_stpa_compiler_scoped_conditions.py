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

"""Scoped (``applies_when``) and fail-closed (``require_params``) STPA conditions.

Both are generic condition features: the compiler never names a domain
parameter; the values come from the control-structure YAML and are held to the
identifier grammar so they cannot break out of a generated literal.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    generate_agp,
    generate_opa,
    generate_python,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_YAML = """\
system:
  name: "Scoped Test System"
  version: "0.1"
  description: "Unit test system"
  controller: "Test Controller"
  controlled_process: "Test Process"

hazards:
  - id: H-1
    description: "Oversized request."
    severity: high

control_actions:
  - name: do_thing
    description: "Perform a controlled action."
    params: []

unsafe_control_actions:
  - id: UCA-1
    action: do_thing
    uca_type: unsafe_action
    hazard_refs: [H-1]
    description: "Request exceeds the allowed fraction of the pool."
    condition:
      composite: "qty > threshold_ref(stpa.max_fraction) * pool"
    enforcement: [opa, python]
    opa_rule:
      decision: DENY
      message: "UCA-1: request exceeds the allowed fraction."

safety_constraints: []
"""


def _cs(**condition: Any) -> ControlStructureModel:
    raw = yaml.safe_load(_YAML)
    raw["unsafe_control_actions"][0]["condition"].update(condition)
    return ControlStructureModel(**raw)


_SCOPE = {"param": "mode", "equals": "Release"}


class TestSchema:
    def test_require_params_needs_a_composite(self) -> None:
        raw = yaml.safe_load(_YAML)
        raw["unsafe_control_actions"][0]["condition"] = {
            "param": "qty",
            "operator": "is_null",
            "require_params": True,
        }
        with pytest.raises(ValueError, match="require_params applies only"):
            ControlStructureModel(**raw)

    @pytest.mark.parametrize(
        "scope",
        [
            {"param": "mode", "equals": 'x"; import os'},
            {"param": "mode", "equals": "a b"},
            {"param": "mo-de", "equals": "x"},
            {"param": "mode", "equals": ""},
        ],
    )
    def test_scope_values_are_held_to_the_identifier_grammar(self, scope: dict) -> None:
        with pytest.raises(ValueError, match="applies_when"):
            _cs(applies_when=scope)

    def test_defaults_leave_existing_composites_unchanged(self) -> None:
        cond = _cs().unsafe_control_actions[0].condition
        assert cond.require_params is False
        assert cond.applies_when is None


class TestPython:
    def test_scope_guard_is_case_insensitive_and_string_only(self) -> None:
        py = generate_python(_cs(applies_when=_SCOPE))
        assert 'scope_val = params.get("mode")' in py
        assert (
            'isinstance(scope_val, str) and scope_val.strip().lower() == "release"'
            in py
        )

    def test_require_params_fails_closed_on_any_missing_operand(self) -> None:
        py = generate_python(_cs(require_params=True))
        assert "if lhs_val is None or rhs_val is None:" in py
        assert "Missing required composite param `qty` / `pool`." in py
        assert "(lhs_val is None) != (rhs_val is None)" not in py

    def test_default_composite_keeps_partial_input_check(self) -> None:
        py = generate_python(_cs())
        assert "(lhs_val is None) != (rhs_val is None)" in py
        assert "scope_val" not in py

    def test_composite_rejects_bool_and_non_numeric_operands(self) -> None:
        py = generate_python(_cs())
        assert "isinstance(v, bool) or not isinstance(v, (int, float, str))" in py

    def test_generated_module_enforces_scope_and_required_params(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        namespace: dict[str, Any] = {}
        exec(  # noqa: S102 — compiling generated test fixture source
            compile(
                generate_python(_cs(applies_when=_SCOPE, require_params=True)),
                "<generated>",
                "exec",
            ),
            namespace,
        )
        monkeypatch.setitem(namespace, "_resolve_threshold", lambda _path: 0.5)
        check = namespace["GeneratedSTPAValidator"]()._check_uca_1

        assert check("do_thing", {"mode": "other", "qty": 99, "pool": 1}) is None
        assert check("do_thing", {"qty": 99}) is None
        assert check("do_thing", {"mode": "RELEASE", "qty": 5, "pool": 10}) is None
        assert check("do_thing", {"mode": "release", "qty": 6, "pool": 10}) is not None
        assert check("do_thing", {"mode": "release", "qty": 1}) is not None
        assert check("do_thing", {"mode": "release"}) is not None


class TestRego:
    def test_scope_guard_and_missing_operand_rules(self) -> None:
        rego = generate_opa(_cs(applies_when=_SCOPE, require_params=True))
        assert rego.count('lower(input.mode) == "release"') == 3
        assert "not is_number(input.qty)" in rego
        assert "not is_number(input.pool)" in rego
        assert rego.count("stpa_violation_uca_1 := msg if {") == 3

    def test_default_composite_emits_a_single_rule(self) -> None:
        rego = generate_opa(_cs())
        assert rego.count("stpa_violation_uca_1 := msg if {") == 1
        assert "is_number" not in rego


class TestAgp:
    def test_scope_and_required_params_are_stated(self) -> None:
        text = generate_agp(_cs(applies_when=_SCOPE, require_params=True))
        assert 'When "mode" is "Release": Do not execute "do_thing" when:' in text
        assert 'Also do not execute it if "qty" or "pool" is missing.' in text
