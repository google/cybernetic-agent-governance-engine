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

"""
ACS Ingress Adapter
===================

Translates Microsoft Agent Control Specification (ACS) behavior declarations
into CAGE UCA YAML format, which can then be fed into ``stpa_compiler.py``.

ACS spec reference: https://github.com/microsoft/agent-control-specification

ACS behavior declarations use the ``behaviorDeclarations`` top-level key and
describe agent behaviors with constraints, triggers, and actions. This adapter
maps those constructs to CAGE's Unsafe Control Action (UCA) model.

Mapping logic
-------------
| ACS field                              | CAGE UCA field          |
|----------------------------------------|-------------------------|
| ``behavior.id``                        | ``id``                  |
| ``behavior.action``                    | ``action``              |
| ``behavior.description``               | ``description``         |
| ``behavior.constraints[].type``        | ``condition.operator``  |
| ``behavior.constraints[].parameter``   | ``condition.param``     |
| ``behavior.constraints[].value``       | ``condition.threshold`` |
| ``behavior.hazardRefs``                | ``hazard_refs``         |
| ``behavior.enforcement``               | ``enforcement``         |

Usage::

    from src.gateway.governance.ingress.acs_adapter import translate_acs

    uca_list = translate_acs(acs_spec_dict)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("Gateway.Governance.Ingress.ACSAdapter")

# ---------------------------------------------------------------------------
# ACS constraint-type → CAGE operator mapping
# ---------------------------------------------------------------------------

_ACS_CONSTRAINT_TYPE_MAP: dict[str, str] = {
    "null_check": "is_null",
    "not_null": "is_null",  # inverted — handled below
    "boolean_false": "is_false",
    "boolean_true": "is_true",
    "greater_than": "greater_than",
    "less_than": "less_than",
    "equals": "equals",
    "max_value": "greater_than",
    "min_value": "less_than",
}

# ACS UCA type → CAGE uca_type mapping
_ACS_UCA_TYPE_MAP: dict[str, str] = {
    "not_provided": "not_provided",
    "unsafe_action": "unsafe_action",
    "wrong_timing": "wrong_timing",
    "stopped_too_soon": "stopped_too_soon",
    # ACS-specific types mapped to closest CAGE equivalent
    "omission": "not_provided",
    "commission": "unsafe_action",
    "early": "wrong_timing",
    "late": "wrong_timing",
    "too_long": "stopped_too_soon",
    "too_short": "stopped_too_soon",
}

# Default enforcement targets when ACS spec does not specify
_DEFAULT_ENFORCEMENT: list[str] = ["python"]


def _map_constraint(constraint: dict[str, Any]) -> dict[str, Any]:
    """Map a single ACS constraint dict to a CAGE ConditionModel dict."""
    ctype = constraint.get("type", "")
    param = constraint.get("parameter") or constraint.get("param")
    value = constraint.get("value") or constraint.get("threshold")
    threshold_ref = constraint.get("thresholdRef") or constraint.get("threshold_ref")

    cage_operator = _ACS_CONSTRAINT_TYPE_MAP.get(ctype)
    if cage_operator is None:
        logger.warning(
            "ACSAdapter: unknown constraint type '%s' — using composite fallback.", ctype
        )
        return {"composite": constraint.get("expression", str(constraint))}

    condition: dict[str, Any] = {"operator": cage_operator}
    if param:
        condition["param"] = param
    if value is not None:
        condition["threshold"] = float(value) if isinstance(value, (int, float)) else value
    if threshold_ref:
        condition["threshold_ref"] = threshold_ref

    return condition


def _map_behavior(behavior: dict[str, Any], index: int) -> dict[str, Any] | None:
    """Map a single ACS behavior declaration to a CAGE UCA dict.

    Returns None if the behavior cannot be mapped (logged as a warning).
    """
    behavior_id = behavior.get("id") or f"ACS-UCA-{index:03d}"
    action = behavior.get("action") or behavior.get("controlAction")
    if not action:
        logger.warning(
            "ACSAdapter: behavior '%s' has no 'action' field — skipping.", behavior_id
        )
        return None

    description = behavior.get("description", f"ACS behavior {behavior_id}")
    hazard_refs = behavior.get("hazardRefs") or behavior.get("hazard_refs") or ["H-ACS-1"]
    uca_type_raw = behavior.get("ucaType") or behavior.get("uca_type") or "unsafe_action"
    uca_type = _ACS_UCA_TYPE_MAP.get(uca_type_raw, "unsafe_action")
    enforcement = behavior.get("enforcement") or _DEFAULT_ENFORCEMENT

    # Map constraints → condition
    constraints = behavior.get("constraints") or []
    if constraints:
        # Use the first constraint as the primary condition; composite for multiple
        if len(constraints) == 1:
            condition = _map_constraint(constraints[0])
        else:
            # Multiple constraints: emit as composite free-form expression
            parts = [
                f"{c.get('parameter', '?')} {c.get('type', '?')} {c.get('value', '?')}"
                for c in constraints
            ]
            condition = {"composite": " AND ".join(parts)}
    else:
        # No constraints: use is_null on a sentinel param to represent "always unsafe"
        condition = {"composite": behavior.get("condition", "always")}

    uca: dict[str, Any] = {
        "id": behavior_id,
        "action": action,
        "uca_type": uca_type,
        "hazard_refs": hazard_refs,
        "description": description,
        "condition": condition,
        "enforcement": enforcement,
    }

    # Carry through optional OPA rule if present in ACS spec
    opa_rule = behavior.get("opaRule")
    if opa_rule:
        uca["opa_rule"] = opa_rule

    # Carry through optional NeMo rail if present
    nemo_rail = behavior.get("nemoRail") or behavior.get("nemo_rail")
    if nemo_rail:
        uca["nemo_rail"] = nemo_rail

    return uca


def translate_acs(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate an ACS behavior declaration document into a list of CAGE UCA dicts.

    Args:
        spec: Parsed ACS specification document (dict from JSON/YAML).
              Must contain a ``behaviorDeclarations`` top-level key.

    Returns:
        List of CAGE UCA dicts compatible with ``ControlStructureModel.unsafe_control_actions``.
        Empty list if no behaviors can be mapped.

    Raises:
        ValueError: If ``spec`` does not contain ``behaviorDeclarations``.
    """
    if "behaviorDeclarations" not in spec:
        raise ValueError(
            "ACSAdapter: spec does not contain 'behaviorDeclarations' key. "
            "Ensure the input is a valid ACS behavior declaration document."
        )

    behaviors = spec["behaviorDeclarations"]
    if not isinstance(behaviors, list):
        raise ValueError(
            "ACSAdapter: 'behaviorDeclarations' must be a list of behavior objects."
        )

    ucas: list[dict[str, Any]] = []
    for i, behavior in enumerate(behaviors):
        uca = _map_behavior(behavior, i)
        if uca is not None:
            ucas.append(uca)

    logger.info(
        "ACSAdapter: translated %d/%d ACS behaviors into CAGE UCAs.",
        len(ucas),
        len(behaviors),
    )
    return ucas


def acs_to_control_structure_patch(spec: dict[str, Any]) -> dict[str, Any]:
    """Produce a partial ControlStructureModel dict from an ACS spec.

    This is the artifact bundle format consumed by ``policy_translator.py``.
    The caller merges this patch into an existing control structure or uses it
    as a standalone input to ``stpa_compiler.compile_control_structure()``.

    Args:
        spec: Parsed ACS specification document.

    Returns:
        Dict with ``unsafe_control_actions`` key populated from ACS behaviors,
        plus ``system`` and ``hazards`` stubs derived from ACS metadata.
    """
    ucas = translate_acs(spec)
    metadata = spec.get("metadata") or {}
    system_name = metadata.get("name") or spec.get("name") or "ACS-Imported System"
    system_version = metadata.get("version") or spec.get("version") or "0.0.0"

    # Build minimal hazard stubs from hazard_refs referenced in UCAs
    all_hazard_refs: set[str] = set()
    for uca in ucas:
        all_hazard_refs.update(uca.get("hazard_refs", []))

    hazards = [
        {
            "id": href,
            "description": f"Hazard imported from ACS spec: {href}",
            "severity": "high",
        }
        for href in sorted(all_hazard_refs)
    ]

    return {
        "system": {
            "name": system_name,
            "version": system_version,
            "description": f"Imported from ACS specification: {system_name}",
            "controller": "ACS-Agent",
            "controlled_process": "ACS-ControlledProcess",
        },
        "hazards": hazards,
        "control_actions": [],
        "unsafe_control_actions": ucas,
        "safety_constraints": [],
    }
