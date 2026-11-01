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

"""Declared consequence magnitudes: the one rule every consequence check applies.

A domain plugin declares, per action, where the magnitudes of the action's
consequence sit in its ``params`` and how many minor-unit digits each has
(:class:`~src.gateway.governance.contracts.ConsequenceMagnitude`).
:func:`~src.gateway.governance.governor.assembly.assemble_governor` validates
the declarations and builds one immutable :class:`ConsequenceMagnitudes`
policy, which is passed explicitly, never looked up, to every place a
consequence is checked:

* a jurisdiction tier's pre-flight, before an external authority is consulted;
* :func:`~src.gateway.governance.consequence_token_service.mint_consequence_token_finding`,
  before a ConsequenceToken is signed;
* :class:`~src.gateway.governance.consequence_gateway.ConsequenceGateway`,
  after the ``act`` digest matches and before the single-use marker is
  consumed.

Each refuses on its own; none relies on another having run. The rule names
no domain key: the paths are the domain's, and the kernel only walks them.

Reason codes (:class:`MagnitudeReason`):

* ``MAGNITUDE_UNDECLARED``: the payload names no action, or its action has no
  declaration (no policy at all declares nothing). Fail closed: an action the
  domain never described is refused rather than assumed magnitude-free.
* ``MAGNITUDE_ABSENT``: a declared path is missing, or ``params`` or an
  intermediate key along the path is not a mapping. Paths are relative to
  ``params``; a magnitude anywhere else, at the payload's top level for
  example, is not where the declaration says, so it does not count.
* ``MAGNITUDE_INVALID``: the value is a boolean, not a number, not finite, not
  a whole number of minor units, not positive, or more than 2**53-1 minor
  units.

Whole minor units: params carry magnitudes as numbers of major units, and the
finance domain's are floats (``12.34``). The kernel converts exactly, using
``Decimal(repr(v))`` for a float (the shortest repr, which round-trips to the
same double, so it is the decimal the sender wrote) and ``Decimal(v)`` for an
int, then scales by ``10**minor_unit_digits``. The result must be a whole
number in ``1..2**53-1``: ``12.345`` at two digits is a fraction of a cent
("dust") and is refused, and the bound keeps every magnitude exactly
representable for a consumer that compares in minor units.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Context, Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType

from src.gateway.governance.contracts import ConsequenceMagnitude, MagnitudePath

#: Most minor units a magnitude may carry: the I-JSON safe-integer bound.
MAX_SAFE_MINOR_UNITS = 2**53 - 1

# An explicit context, so the conversion never depends on the thread's
# decimal context. Scaling only shifts the exponent; a double's repr has at
# most 17 significant digits.
_DECIMAL = Context(prec=60, rounding=ROUND_HALF_EVEN, traps=[InvalidOperation])
_SHOWN_ACTION_CHARS = 64


class MagnitudeReason(StrEnum):
    """Why a consequence's magnitudes are refused."""

    UNDECLARED = "MAGNITUDE_UNDECLARED"
    ABSENT = "MAGNITUDE_ABSENT"
    INVALID = "MAGNITUDE_INVALID"


@dataclass(frozen=True)
class MagnitudeViolation:
    """One refused magnitude.

    ``path`` is the declared key path inside ``params`` (``()`` when the
    refusal concerns the action rather than one path). ``detail`` names the
    path and the rule, never the refused value.
    """

    reason: MagnitudeReason
    path: tuple[str, ...]
    detail: str

    def __str__(self) -> str:
        return f"{self.reason.value}: {self.detail}"


def describe(violations: Iterable[MagnitudeViolation]) -> str:
    """Every violation as ``REASON: detail``, ``; ``-separated."""
    return "; ".join(str(v) for v in violations)


@dataclass(frozen=True)
class ConsequenceMagnitudes:
    """The immutable per-action magnitude policy (read-only).

    Holds at most one declaration per action, kept sorted by action, so two
    policies with the same declarations compare equal.

    Raises:
        TypeError: ``declarations`` is not an iterable of
            :class:`~src.gateway.governance.contracts.ConsequenceMagnitude`.
        ValueError: An action is declared twice.
    """

    declarations: tuple[ConsequenceMagnitude, ...] = ()
    _by_action: Mapping[str, ConsequenceMagnitude] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        declared = self.declarations
        if isinstance(declared, (str, bytes)) or not isinstance(declared, Iterable):
            raise TypeError(
                "ConsequenceMagnitudes.declarations must be an iterable of "
                f"ConsequenceMagnitude, got {type(declared).__name__}"
            )
        by_action: dict[str, ConsequenceMagnitude] = {}
        for declaration in declared:
            if not isinstance(declaration, ConsequenceMagnitude):
                raise TypeError(
                    "ConsequenceMagnitudes takes ConsequenceMagnitude "
                    f"declarations, got {type(declaration).__name__}"
                )
            if declaration.action in by_action:
                raise ValueError(
                    f"consequence magnitude for {declaration.action!r} is declared twice"
                )
            by_action[declaration.action] = declaration
        object.__setattr__(
            self, "declarations", tuple(by_action[a] for a in sorted(by_action))
        )
        object.__setattr__(self, "_by_action", MappingProxyType(by_action))

    @property
    def actions(self) -> frozenset[str]:
        """Every action with a declaration, magnitude-free ones included."""
        return frozenset(self._by_action)

    def declaration(self, action: str) -> ConsequenceMagnitude | None:
        """``action``'s declaration, or ``None`` when it has none."""
        return self._by_action.get(action)

    def violations(self, action_payload: object) -> tuple[MagnitudeViolation, ...]:
        """Every way ``action_payload`` breaks this policy; ``()`` when none.

        ``action_payload`` is a consequence's payload: ``action`` names the
        action, and ``params`` holds the parameters every declared path is
        relative to. Pure and total: it never raises.
        """
        if not isinstance(action_payload, Mapping):
            return (_undeclared("the action payload is not a mapping"),)
        action = action_payload.get("action")
        if not isinstance(action, str) or not action:
            return (_undeclared("the action payload names no action"),)
        declaration = self._by_action.get(action)
        if declaration is None:
            return (
                _undeclared(
                    f"no consequence magnitude is declared for action {_shown(action)}"
                ),
            )
        params = action_payload.get("params")
        found = (_check(params, path) for path in declaration.paths)
        return tuple(v for v in found if v is not None)


def magnitude_violations(
    policy: ConsequenceMagnitudes | None, action_payload: object
) -> tuple[MagnitudeViolation, ...]:
    """``policy.violations(action_payload)``; no policy refuses every action.

    The checks take their policy explicitly and can be handed none (an adapter
    constructed without one). No policy declares nothing, so the payload is
    ``MAGNITUDE_UNDECLARED``.
    """
    if not isinstance(policy, ConsequenceMagnitudes):
        return (_undeclared("no consequence-magnitude policy is configured"),)
    return policy.violations(action_payload)


def _undeclared(detail: str) -> MagnitudeViolation:
    return MagnitudeViolation(MagnitudeReason.UNDECLARED, (), detail)


def _shown(action: str) -> str:
    if len(action) <= _SHOWN_ACTION_CHARS:
        return repr(action)
    return repr(action[:_SHOWN_ACTION_CHARS] + "...")


def _check(params: object, path: MagnitudePath) -> MagnitudeViolation | None:
    """The violation at ``path`` inside ``params``, or ``None``."""
    node: object = params
    walked: list[str] = []
    for key in path.keys:
        if not isinstance(node, Mapping):
            where = ".".join(("params", *walked))
            return MagnitudeViolation(
                MagnitudeReason.ABSENT,
                path.keys,
                f"{path.dotted} is absent: {where} is not a mapping",
            )
        if key not in node:
            return MagnitudeViolation(
                MagnitudeReason.ABSENT, path.keys, f"{path.dotted} is absent"
            )
        node = node[key]
        walked.append(key)
    problem = _invalid(node, path.minor_unit_digits)
    if problem is None:
        return None
    return MagnitudeViolation(
        MagnitudeReason.INVALID, path.keys, f"{path.dotted} {problem}"
    )


def _invalid(value: object, digits: int) -> str | None:
    """Why ``value`` is not a whole, positive, safe number of minor units."""
    if isinstance(value, bool):
        return "is a boolean, not a number"
    if isinstance(value, int):
        exact = Decimal(int(value))
    elif isinstance(value, float):
        if not math.isfinite(value):
            return "is not a finite number"
        # float.__repr__, not repr(): a float subclass may override repr.
        exact = Decimal(float.__repr__(value))
    else:
        return f"is a {type(value).__name__}, not a number"
    try:
        minor = exact.scaleb(digits, context=_DECIMAL)
        whole = minor == minor.to_integral_value(context=_DECIMAL)
    except ArithmeticError:  # decimal signals; unreachable for finite input
        return "is not a representable number"
    if not whole:
        return f"is not a whole number of minor units ({digits} minor-unit digits)"
    if minor <= 0:
        return "is not positive"
    if minor > MAX_SAFE_MINOR_UNITS:
        return f"exceeds {MAX_SAFE_MINOR_UNITS} minor units"
    return None


__all__ = [
    "MAX_SAFE_MINOR_UNITS",
    "ConsequenceMagnitudes",
    "MagnitudeReason",
    "MagnitudeViolation",
    "describe",
    "magnitude_violations",
]
