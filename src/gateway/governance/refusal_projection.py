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

"""Retention-tier parameter projection for 7-year WORM refusal evidence.

Splits the 7-year WORM retention tier from the short-lived / offline content
tier on governance refusals (``POAM-2026-225``, ``RP-1``):

* Every ``GOVERNANCE_REFUSAL`` / ``GOVERNANCE_REFUSAL_RECEIPT`` committed to
  ``cage:evidence:stream`` and ``module.worm_bucket`` carries:
    1. ``params_hash`` — deterministic 64-hex SHA-256 over canonical
       ``(action, params)`` (excluding call-envelope ``thread_id`` /
       ``transaction_id``), matching ``GOVERNANCE_DECISION`` and
       ``GOVERNANCE_DEFERRAL``; and
    2. ``evaluated_params`` — a **default-deny**, **value-shape-constrained**
       projection of only the bounded scalar, boolean, closed-enum, or short
       uppercase-alpha code parameters the domain policy actually evaluated.

* Raw ``attempted_params`` remains on the in-memory ``RefusalReceipt`` object
  only (for offline ``Profile.DRY_RUN`` evaluation / DPO harvesting into a
  separate store with its own bounded retention) and is **never** serialized
  onto the 2,555-day WORM chain.

* **Survivable by default-deny + closed value shapes:**
  - A domain plugin that declares no ``evaluated_param_specs`` emits
    ``evaluated_params == {}`` ("a domain which declares nothing leaks
    nothing").
  - Domain plugins cannot supply custom regular expressions: every spec must
    use one of the kernel's four closed shapes (``NUMBER``, ``BOOLEAN``,
    ``ENUM``, ``UPPER_ALPHA_CODE``), and parameter names carrying identity,
    credential, or free-text semantics (``*_id``, ``*_urn``, ``prompt``,
    ``rationale``, ``indication``, ``notes``, etc.) are rejected at
    declaration/assembly time.
  - Both runtime projection and ``RefusalReceipt.to_worm_dict()`` re-verify
    every emitted key and value shape so malformed or stuffed caller inputs
    (e.g. prose placed inside a code field) are omitted rather than archived.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

#: Internal kernel key reserved for server-input unavailability metadata; never
#: accepted from callers and never serialized into params_hash or WORM payloads.
SERVER_INPUT_INFRA_ERRORS_KEY = "__cage_server_input_unavailable__"

#: Envelope-level correlation keys excluded before computing ``params_hash``,
#: matching ``build_refusal_receipt``'s historical parameter scope.
REFUSAL_ENVELOPE_EXCLUDED_KEYS: frozenset[str] = frozenset(
    {"thread_id", "transaction_id", SERVER_INPUT_INFRA_ERRORS_KEY}
)

#: Valid Python/JSON parameter identifier shape.
_PARAM_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")

#: Domain-agnostic parameter-name segments forbidden in WORM ``evaluated_params``
#: (entity identifiers, credentials, and free-text / prose fields).
_FORBIDDEN_PARAM_SEGMENTS_RE = re.compile(
    r"(?i)(?:^|_)(?:"
    r"id|ids|urn|uuid|guid|subject|principal|email|phone|ssn|iban|"
    r"name|names|person|user|account|owner|beneficiary|"
    r"note|notes|memo|reason|rationale|indication|prompt|query|"
    r"message|messages|text|comment|comments|description|narrative|"
    r"body|content|transcript|summary|detail|details|"
    r"token|secret|key|password|credential|signature|seal"
    r")(?:$|_)"
)

#: Closed token alphabet for ``ENUM`` choices: 1..32 ASCII token chars, zero whitespace.
_ENUM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

#: Closed uppercase-alphabetic code alphabet (e.g. ISO currency or ticker):
#: 1..12 uppercase ASCII letters ONLY — zero digits, zero spaces, zero prose.
_UPPER_ALPHA_CODE_RE = re.compile(r"^[A-Z]{1,12}$")

_MAX_ENUM_CARDINALITY = 64
_MAX_UPPER_ALPHA_CODE_LENGTH = 12


class _OmitSentinel:
    """Internal sentinel marking a parameter value omitted from projection."""


_OMIT = _OmitSentinel()


class EvaluatedParamKind(StrEnum):
    """Closed kernel value shapes permitted in WORM ``evaluated_params``."""

    NUMBER = "number"
    BOOLEAN = "boolean"
    ENUM = "enum"
    UPPER_ALPHA_CODE = "upper_alpha_code"


def validate_evaluated_param_name(name: str) -> str:
    """Validate that ``name`` is a non-identifier, non-prose scalar/enum key."""
    if not isinstance(name, str) or not _PARAM_NAME_RE.fullmatch(name):
        raise ValueError(
            f"evaluated_param_specs parameter name {name!r} must match "
            f"{_PARAM_NAME_RE.pattern}"
        )
    if _FORBIDDEN_PARAM_SEGMENTS_RE.search(name):
        raise ValueError(
            f"evaluated_param_specs parameter name {name!r} is forbidden in "
            "7-year WORM refusal projections (identifier, credential, or "
            "free-text field)"
        )
    return name


@dataclass(frozen=True)
class EvaluatedParamSpec:
    """Closed kernel value-shape specification for one policy-evaluated parameter.

    Construct via :meth:`number`, :meth:`boolean`, :meth:`enum`, or
    :meth:`upper_alpha_code`. Custom regex patterns are intentionally
    unsupported so plugins cannot widen string shapes to admit free text.
    """

    kind: EvaluatedParamKind
    enum_values: frozenset[str] = frozenset()
    max_length: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvaluatedParamKind):
            raise TypeError(
                f"EvaluatedParamSpec.kind must be EvaluatedParamKind, got {self.kind!r}"
            )
        if self.kind == EvaluatedParamKind.NUMBER:
            if self.enum_values or self.max_length != 0:
                raise ValueError(
                    "NUMBER EvaluatedParamSpec takes no enum_values or max_length"
                )
        elif self.kind == EvaluatedParamKind.BOOLEAN:
            if self.enum_values or self.max_length != 0:
                raise ValueError(
                    "BOOLEAN EvaluatedParamSpec takes no enum_values or max_length"
                )
        elif self.kind == EvaluatedParamKind.ENUM:
            vals = frozenset(self.enum_values)
            if not vals or len(vals) > _MAX_ENUM_CARDINALITY:
                raise ValueError(
                    f"ENUM EvaluatedParamSpec requires 1..{_MAX_ENUM_CARDINALITY} "
                    f"values, got {len(vals)}"
                )
            for item in vals:
                if not isinstance(item, str) or not _ENUM_TOKEN_RE.fullmatch(item):
                    raise ValueError(
                        f"ENUM choice {item!r} must be a 1..32 char non-whitespace "
                        f"ASCII token ({_ENUM_TOKEN_RE.pattern})"
                    )
            object.__setattr__(self, "enum_values", vals)
            if self.max_length != 0:
                raise ValueError("ENUM EvaluatedParamSpec takes no max_length")
        elif self.kind == EvaluatedParamKind.UPPER_ALPHA_CODE:
            if self.enum_values:
                raise ValueError(
                    "UPPER_ALPHA_CODE EvaluatedParamSpec takes no enum_values"
                )
            if (
                isinstance(self.max_length, bool)
                or not isinstance(self.max_length, int)
                or not (1 <= self.max_length <= _MAX_UPPER_ALPHA_CODE_LENGTH)
            ):
                raise ValueError(
                    f"UPPER_ALPHA_CODE max_length must be an int in "
                    f"1..{_MAX_UPPER_ALPHA_CODE_LENGTH}, got {self.max_length!r}"
                )

    @classmethod
    def number(cls) -> EvaluatedParamSpec:
        """Finite ``int`` or ``float`` (booleans rejected)."""
        return cls(kind=EvaluatedParamKind.NUMBER)

    @classmethod
    def boolean(cls) -> EvaluatedParamSpec:
        """Strict ``bool``."""
        return cls(kind=EvaluatedParamKind.BOOLEAN)

    @classmethod
    def enum(cls, *values: str) -> EvaluatedParamSpec:
        """Closed set of 1..64 non-whitespace ASCII token strings."""
        return cls(kind=EvaluatedParamKind.ENUM, enum_values=frozenset(values))

    @classmethod
    def upper_alpha_code(cls, *, max_length: int = 8) -> EvaluatedParamSpec:
        """Short uppercase ASCII alphabetic code (``^[A-Z]{1,max_length}$``, max 12)."""
        return cls(kind=EvaluatedParamKind.UPPER_ALPHA_CODE, max_length=max_length)

    def project(self, raw: Any) -> int | float | bool | str | _OmitSentinel:
        """Return ``raw`` iff it satisfies this closed shape, else ``_OMIT``."""
        if self.kind == EvaluatedParamKind.BOOLEAN:
            return raw if isinstance(raw, bool) else _OMIT
        if self.kind == EvaluatedParamKind.NUMBER:
            if (
                isinstance(raw, (int, float))
                and not isinstance(raw, bool)
                and math.isfinite(raw)
            ):
                return raw
            return _OMIT
        if self.kind == EvaluatedParamKind.ENUM:
            if isinstance(raw, str) and raw in self.enum_values:
                return raw
            return _OMIT
        if self.kind == EvaluatedParamKind.UPPER_ALPHA_CODE:
            if (
                isinstance(raw, str)
                and 1 <= len(raw) <= self.max_length
                and _UPPER_ALPHA_CODE_RE.fullmatch(raw) is not None
            ):
                return raw
            return _OMIT
        return _OMIT


EvaluatedParamSpecMap = Mapping[str, Mapping[str, EvaluatedParamSpec]]


def validate_evaluated_param_specs(
    specs: Mapping[str, Mapping[str, EvaluatedParamSpec]] | None,
    *,
    allowed_actions: Iterable[str] | None = None,
    domain_label: str = "",
) -> Mapping[str, Mapping[str, EvaluatedParamSpec]]:
    """Validate and freeze an ``action -> param_name -> EvaluatedParamSpec`` mapping."""
    if not specs:
        return MappingProxyType({})
    if not isinstance(specs, Mapping):
        raise TypeError(
            f"evaluated_param_specs must be a Mapping, got {type(specs).__name__}"
        )
    allowed = frozenset(allowed_actions) if allowed_actions is not None else None
    prefix = f"domain {domain_label!r}: " if domain_label else ""
    frozen_outer: dict[str, Mapping[str, EvaluatedParamSpec]] = {}
    for action, param_map in specs.items():
        if not isinstance(action, str) or not action.strip():
            raise ValueError(
                f"{prefix}evaluated_param_specs action key must be a non-empty str"
            )
        if allowed is not None and action not in allowed:
            raise ValueError(
                f"{prefix}declares evaluated_param_specs for {action!r}, "
                "which it does not register"
            )
        if not isinstance(param_map, Mapping):
            raise TypeError(
                f"{prefix}evaluated_param_specs[{action!r}] must be a Mapping, "
                f"got {type(param_map).__name__}"
            )
        frozen_inner: dict[str, EvaluatedParamSpec] = {}
        for param_name, spec in param_map.items():
            validate_evaluated_param_name(param_name)
            if not isinstance(spec, EvaluatedParamSpec):
                raise TypeError(
                    f"{prefix}evaluated_param_specs[{action!r}][{param_name!r}] "
                    f"must be EvaluatedParamSpec, got {type(spec).__name__}"
                )
            frozen_inner[param_name] = spec
        frozen_outer[action] = MappingProxyType(frozen_inner)
    return MappingProxyType(frozen_outer)


def project_evaluated_params(
    specs: EvaluatedParamSpecMap | None,
    action: str,
    params: Mapping[str, Any] | None,
) -> dict[str, int | float | bool | str]:
    """Return the default-deny, value-shape-verified projection for ``(action, params)``."""
    if not specs or not params or not isinstance(params, Mapping):
        return {}
    action_specs = specs.get(action)
    if not action_specs:
        return {}
    projected: dict[str, int | float | bool | str] = {}
    for key, spec in action_specs.items():
        if key.startswith("_") or key in REFUSAL_ENVELOPE_EXCLUDED_KEYS:
            continue
        if key not in params:
            continue
        val = spec.project(params[key])
        if not isinstance(val, _OmitSentinel):
            projected[key] = val
    return projected


def assert_worm_safe_evaluated_params(
    evaluated_params: Mapping[str, Any] | None,
) -> dict[str, int | float | bool | str]:
    """Fail-closed belt-and-suspenders check before serializing ``evaluated_params`` to WORM.

    Rejects any key failing :func:`validate_evaluated_param_name` and any value
    that is not a ``bool``, finite ``int | float``, or non-whitespace ASCII
    token ``^[A-Za-z0-9_.-]{1,32}$``.
    """
    if not evaluated_params:
        return {}
    if not isinstance(evaluated_params, Mapping):
        raise TypeError(
            f"evaluated_params must be a Mapping, got {type(evaluated_params).__name__}"
        )
    out: dict[str, int | float | bool | str] = {}
    for key, val in evaluated_params.items():
        validate_evaluated_param_name(key)
        if isinstance(val, bool):
            out[key] = val
        elif isinstance(val, (int, float)):
            if not math.isfinite(val):
                raise ValueError(
                    f"evaluated_params[{key!r}] must be finite, got {val!r}"
                )
            out[key] = val
        elif isinstance(val, str):
            if not _ENUM_TOKEN_RE.fullmatch(val):
                raise ValueError(
                    f"evaluated_params[{key!r}] violates WORM token shape "
                    f"({_ENUM_TOKEN_RE.pattern}): free-form or overlong string refused"
                )
            out[key] = val
        else:
            raise TypeError(
                f"evaluated_params[{key!r}] has unsupported WORM type "
                f"{type(val).__name__}"
            )
    return out


def _jcs_safe_value(value: Any) -> Any:
    """Coerce arbitrary caller values into deterministic JCS-compatible JSON values for hashing."""
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"__non_finite__": "NaN"}
        if math.isinf(value):
            return {"__non_finite__": "Infinity" if value > 0 else "-Infinity"}
        return value
    if isinstance(value, Mapping):
        return {str(k): _jcs_safe_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jcs_safe_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        rendered = [_jcs_safe_value(item) for item in value]
        return sorted(rendered, key=lambda item: jcs_canonicalize_plan(item))
    return repr(value)


def compute_refusal_params_hash(action: str, params: Mapping[str, Any] | None) -> str:
    """Compute a deterministic 64-hex SHA-256 over ``(action, stripped_params)``.

    Uses :func:`routing_seal.compute_action_hash` when ``stripped_params`` is
    seal-canonicalizable so ``GOVERNANCE_REFUSAL.receipt.params_hash`` matches
    ``GOVERNANCE_DECISION.params_hash`` and ``GOVERNANCE_DEFERRAL.params_hash``
    for identical inputs, falling back to JCS SHA-256 over coerced JSON values
    when the refused call carried non-sealable types.
    """
    from src.gateway.governance import routing_seal

    stripped: dict[str, Any] = (
        {
            str(k): v
            for k, v in params.items()
            if k not in REFUSAL_ENVELOPE_EXCLUDED_KEYS
        }
        if isinstance(params, Mapping)
        else {}
    )
    try:
        return routing_seal.compute_action_hash(action, stripped)
    except Exception:
        canon = jcs_canonicalize_plan(
            {"action": str(action), "params": _jcs_safe_value(stripped)}
        )
        return hashlib.sha256(canon).hexdigest()
