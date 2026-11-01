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

"""POAM-2026-155: the declared consequence-magnitude contract and its one rule.

Covers the declaration types in ``contracts.py`` (``MagnitudePath``,
``ConsequenceMagnitude``) and the kernel policy
(``consequence_magnitude.ConsequenceMagnitudes``): which payloads it refuses,
with which reason code, at a length-1 path and at a nested one. The three
places that enforce it are covered in
``tests/test_consequence_magnitude_enforcement.py``.
"""

from __future__ import annotations

import dataclasses
import math
from typing import Any

import pytest

from src.gateway.governance.consequence_magnitude import (
    MAX_SAFE_MINOR_UNITS,
    ConsequenceMagnitudes,
    MagnitudeReason,
    MagnitudeViolation,
    describe,
    magnitude_violations,
)
from src.gateway.governance.contracts import (
    MAX_MINOR_UNIT_DIGITS,
    ConsequenceMagnitude,
    MagnitudePath,
    PluginContribution,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_AMOUNT = MagnitudePath(("amount",), 2)
_NESTED = MagnitudePath(("payment", "amount"), 2)
POLICY = ConsequenceMagnitudes(
    (
        ConsequenceMagnitude("transfer", (_AMOUNT,)),
        ConsequenceMagnitude("payout", (_NESTED,)),
        ConsequenceMagnitude("lookup", ()),
        ConsequenceMagnitude(
            "split", (MagnitudePath(("a",), 2), MagnitudePath(("b",), 0))
        ),
        ConsequenceMagnitude("units", (MagnitudePath(("count",), 0),)),
    )
)
PATHS = {"flat": ("transfer", ("amount",)), "nested": ("payout", ("payment", "amount"))}


def _payload(shape: str, value: Any) -> dict[str, Any]:
    action, keys = PATHS[shape]
    params: dict[str, Any] = {keys[-1]: value}
    for key in reversed(keys[:-1]):
        params = {key: params}
    return {"action": action, "params": params}


def _reasons(payload: Any, policy: ConsequenceMagnitudes = POLICY) -> list[str]:
    return [v.reason.value for v in policy.violations(payload)]


# ── Declarations (contracts.py) ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "keys", [["amount"], "amount", (), ("",), ("payment", ""), (1,), None]
)
def test_magnitude_path_rejects_malformed_keys(keys: Any) -> None:
    with pytest.raises(ValueError, match="keys"):
        MagnitudePath(keys, 2)


@pytest.mark.parametrize(
    "digits", [-1, MAX_MINOR_UNIT_DIGITS + 1, True, 2.0, "2", None]
)
def test_magnitude_path_rejects_digits_outside_the_bounded_int_range(
    digits: Any,
) -> None:
    with pytest.raises(ValueError, match="minor_unit_digits"):
        MagnitudePath(("amount",), digits)


@pytest.mark.parametrize("digits", [0, 2, MAX_MINOR_UNIT_DIGITS])
def test_magnitude_path_accepts_the_bounds(digits: int) -> None:
    path = MagnitudePath(("payment", "amount"), digits)
    assert path.dotted == "params.payment.amount"


@pytest.mark.parametrize("action", ["", None, 7])
def test_declaration_needs_an_action(action: Any) -> None:
    with pytest.raises(ValueError, match="action"):
        ConsequenceMagnitude(action, ())


@pytest.mark.parametrize("paths", [[_AMOUNT], (("amount",),), _AMOUNT, None])
def test_declaration_paths_must_be_a_tuple_of_magnitude_paths(paths: Any) -> None:
    with pytest.raises(ValueError, match="paths"):
        ConsequenceMagnitude("transfer", paths)


def test_declaration_rejects_a_duplicate_path() -> None:
    with pytest.raises(ValueError, match="declared twice"):
        ConsequenceMagnitude("transfer", (_AMOUNT, MagnitudePath(("amount",), 0)))


def test_declaration_rejects_a_path_inside_another() -> None:
    with pytest.raises(ValueError, match="contains"):
        ConsequenceMagnitude("payout", (MagnitudePath(("payment",), 2), _NESTED))


def test_empty_paths_is_the_explicit_magnitude_free_declaration() -> None:
    declaration = ConsequenceMagnitude("lookup", ())
    assert declaration.paths == ()
    assert dataclasses.is_dataclass(declaration)
    with pytest.raises(dataclasses.FrozenInstanceError):
        declaration.paths = (_AMOUNT,)  # type: ignore[misc]


def test_plugin_contribution_declares_no_magnitudes_by_default() -> None:
    assert PluginContribution(domain="d").consequence_magnitudes == ()


# ── The policy object ─────────────────────────────────────────────────────────


def test_policy_rejects_an_action_declared_twice() -> None:
    with pytest.raises(ValueError, match="declared twice"):
        ConsequenceMagnitudes(
            (ConsequenceMagnitude("lookup", ()), ConsequenceMagnitude("lookup", ()))
        )


@pytest.mark.parametrize("declarations", ["lookup", (object(),), ({"action": "x"},), 5])
def test_policy_takes_only_declarations(declarations: Any) -> None:
    with pytest.raises(TypeError):
        ConsequenceMagnitudes(declarations)


def test_policy_is_read_only_and_order_insensitive() -> None:
    a = ConsequenceMagnitude("lookup", ())
    b = ConsequenceMagnitude("transfer", (_AMOUNT,))
    policy = ConsequenceMagnitudes((b, a))
    assert policy == ConsequenceMagnitudes((a, b))
    assert hash(policy) == hash(ConsequenceMagnitudes((a, b)))
    assert policy.actions == frozenset({"lookup", "transfer"})
    assert policy.declaration("transfer") is b
    assert policy.declaration("absent") is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.declarations = ()  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy._by_action["x"] = a  # type: ignore[index]


# ── MAGNITUDE_INVALID: value rules, at a flat and a nested path ──────────────

_INVALID: list[Any] = [
    pytest.param(0, id="zero"),
    pytest.param(0.0, id="zero-float"),
    pytest.param(-0.0, id="negative-zero"),
    pytest.param(-5.0, id="negative"),
    pytest.param(-1, id="negative-int"),
    pytest.param(True, id="boolean-true"),
    pytest.param(False, id="boolean-false"),
    pytest.param(10.005, id="dust"),
    pytest.param(0.001, id="dust-below-one-cent"),
    pytest.param(5e-324, id="dust-subnormal"),
    pytest.param("10.00", id="non-numeric-string"),
    pytest.param(None, id="null"),
    pytest.param([10], id="list"),
    pytest.param({"value": 10}, id="mapping"),
    pytest.param(2**53, id="unsafe-int"),
    pytest.param(2**53 - 1, id="safe-int-unsafe-in-minor-units"),
    pytest.param(2.0**53, id="unsafe-float"),
    pytest.param(1e300, id="huge-float"),
    pytest.param(math.nan, id="nan"),
    pytest.param(math.inf, id="inf"),
    pytest.param(-math.inf, id="negative-inf"),
]


@pytest.mark.parametrize("shape", sorted(PATHS))
@pytest.mark.parametrize("value", _INVALID)
def test_invalid_magnitudes_are_refused(shape: str, value: Any) -> None:
    assert _reasons(_payload(shape, value)) == ["MAGNITUDE_INVALID"]


@pytest.mark.parametrize("shape", sorted(PATHS))
@pytest.mark.parametrize(
    "value",
    [10.0, 10.01, 0.01, 1, 250000.0, 90071992547409.9],
    ids=["whole", "cents", "one-cent", "int", "large", "near-bound"],
)
def test_whole_positive_safe_minor_units_pass(shape: str, value: Any) -> None:
    assert _reasons(_payload(shape, value)) == []


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        (True, "boolean"),
        ("10.00", "not a number"),
        (math.nan, "not a finite number"),
        (math.inf, "not a finite number"),
        (10.005, "whole number of minor units"),
        (0, "not positive"),
        (-5.0, "not positive"),
        (2.0**53, "exceeds"),
    ],
)
def test_each_rule_names_itself_and_the_path(value: Any, rule: str) -> None:
    [violation] = POLICY.violations(_payload("nested", value))
    assert violation.path == ("payment", "amount")
    assert violation.detail.startswith("params.payment.amount ")
    assert rule in violation.detail


def test_the_bound_is_exactly_two_to_the_53_minus_one_minor_units() -> None:
    def units(value: Any) -> list[str]:
        return _reasons({"action": "units", "params": {"count": value}})

    assert units(MAX_SAFE_MINOR_UNITS) == []
    assert units(MAX_SAFE_MINOR_UNITS + 1) == ["MAGNITUDE_INVALID"]
    assert units(float(2**52)) == []
    assert units(2.0**53) == ["MAGNITUDE_INVALID"]


def test_floats_convert_from_their_shortest_repr_not_their_binary_expansion() -> None:
    """10.01 is 10.0099999999999997868... in binary; its repr is the decimal sent."""
    assert _reasons(_payload("flat", 10.01)) == []
    assert _reasons(_payload("flat", 0.1 + 0.2)) == [
        "MAGNITUDE_INVALID"
    ]  # 0.30000000000000004


def test_a_refused_value_is_never_echoed() -> None:
    [violation] = POLICY.violations(_payload("flat", "SECRET-VALUE-0042"))
    assert "SECRET-VALUE-0042" not in str(violation)


def test_every_path_is_checked() -> None:
    payload = {"action": "split", "params": {"a": 0, "b": 1.5}}
    violations = POLICY.violations(payload)
    assert [(v.reason.value, v.path) for v in violations] == [
        ("MAGNITUDE_INVALID", ("a",)),
        ("MAGNITUDE_INVALID", ("b",)),
    ]
    assert describe(violations) == "; ".join(str(v) for v in violations)


# ── MAGNITUDE_ABSENT: paths are relative to params ───────────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"action": "transfer", "params": {}}, id="missing"),
        pytest.param({"action": "transfer"}, id="no-params"),
        pytest.param({"action": "transfer", "params": [1]}, id="params-not-mapping"),
        pytest.param({"action": "transfer", "params": None}, id="params-null"),
        pytest.param(
            {"action": "transfer", "amount": 10.0, "params": {}}, id="top-level-only"
        ),
        pytest.param(
            {"action": "payout", "params": {"amount": 10.0}}, id="nested-at-wrong-depth"
        ),
        pytest.param(
            {"action": "payout", "params": {"payment": 10.0}},
            id="intermediate-not-mapping",
        ),
        pytest.param(
            {"action": "payout", "params": {"payment": {}}}, id="nested-missing"
        ),
    ],
)
def test_a_declared_magnitude_that_is_not_where_declared_is_absent(
    payload: dict[str, Any],
) -> None:
    assert _reasons(payload) == ["MAGNITUDE_ABSENT"]


def test_absent_names_the_first_non_mapping() -> None:
    [violation] = POLICY.violations({"action": "payout", "params": {"payment": 10.0}})
    assert violation.detail == (
        "params.payment.amount is absent: params.payment is not a mapping"
    )


# ── MAGNITUDE_UNDECLARED: fail closed on anything not declared ───────────────


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"action": "wire", "params": {"amount": 10.0}}, id="undeclared"),
        pytest.param({"params": {"amount": 10.0}}, id="no-action"),
        pytest.param({"action": 5, "params": {}}, id="action-not-str"),
        pytest.param({"action": "", "params": {}}, id="action-empty"),
        pytest.param(["transfer"], id="payload-not-mapping"),
        pytest.param(None, id="payload-null"),
    ],
)
def test_an_action_without_a_declaration_is_refused(payload: Any) -> None:
    assert _reasons(payload) == ["MAGNITUDE_UNDECLARED"]


def test_no_policy_refuses_every_action() -> None:
    [violation] = magnitude_violations(None, {"action": "lookup", "params": {}})
    assert violation.reason is MagnitudeReason.UNDECLARED
    assert magnitude_violations(POLICY, {"action": "lookup", "params": {}}) == ()


def test_a_long_action_name_is_truncated_in_the_detail() -> None:
    [violation] = POLICY.violations({"action": "x" * 500, "params": {}})
    assert len(violation.detail) < 200


def test_a_magnitude_free_action_passes_whatever_its_params() -> None:
    for params in ({}, {"amount": -5}, {"amount": "x"}, None, [1]):
        assert _reasons({"action": "lookup", "params": params}) == []


def test_violation_renders_reason_then_detail() -> None:
    violation = MagnitudeViolation(MagnitudeReason.ABSENT, ("amount",), "gone")
    assert str(violation) == "MAGNITUDE_ABSENT: gone"
