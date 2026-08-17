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
AAIF Ingress Adapter
====================

Translates Linux Foundation AAIF (Agentic AI Interoperability Framework)
governed run loop specifications into CAGE pipeline stage mappings and UCA
YAML format.

AAIF spec reference: Linux Foundation AAIF working group.

AAIF governed run loop specs use the ``governedRunLoop`` top-level key and
describe agent execution stages with governance hooks at each stage. This
adapter maps those constructs to CAGE's 8-tier governance pipeline stages (FTRA pre-gate + 7 in-pipeline tiers)
and UCA model.

AAIF stage → CAGE pipeline tier mapping
-----------------------------------------
| AAIF stage              | CAGE tier                              |
|-------------------------|----------------------------------------|
| ``input_validation``    | Tier 0 — Aho-Corasick / prompt inject  |
| ``content_filtering``   | Tier 1 — NeMo Guardrails               |
| ``policy_check``        | Tier 2 — STPA validator                |
| ``access_control``      | Tier 3 — OPA RBAC                      |
| ``rate_limiting``       | Tier 4 — CBF / token quota             |
| ``consensus``           | Tier 5 — Consensus / multi-agent       |
| ``causal_validation``   | Tier 6 — DoWhy causal gatekeeper       |
| ``output_validation``   | Tier 1 — NeMo output guardrail         |

Usage::

    from src.gateway.governance.ingress.aaif_adapter import translate_aaif

    stage_map, uca_list = translate_aaif(aaif_spec_dict)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("Gateway.Governance.Ingress.AAIFAdapter")

# ---------------------------------------------------------------------------
# AAIF stage → CAGE tier mapping
# ---------------------------------------------------------------------------

_AAIF_STAGE_TO_CAGE_TIER: dict[str, dict[str, Any]] = {
    "input_validation": {
        "tier": 0,
        "name": "Aho-Corasick / Prompt Injection Detection",
        "enforcement": ["python"],
        "module": "src.gateway.governance.prompt_injection_detector",
    },
    "content_filtering": {
        "tier": 1,
        "name": "NeMo Guardrails",
        "enforcement": ["nemo"],
        "module": "src.gateway.governance.nemo.manager",
    },
    "policy_check": {
        "tier": 2,
        "name": "STPA Validator",
        "enforcement": ["python", "opa"],
        "module": "src.gateway.governance.stpa_validator",
    },
    "access_control": {
        "tier": 3,
        "name": "OPA RBAC",
        "enforcement": ["opa"],
        "module": "src.gateway.governance.symbolic_governor",
    },
    "rate_limiting": {
        "tier": 4,
        "name": "CBF / Token Quota",
        "enforcement": ["python"],
        "module": "src.gateway.governance.cbf",
    },
    "consensus": {
        "tier": 5,
        "name": "Consensus / Multi-Agent",
        "enforcement": ["python"],
        "module": "src.gateway.governance.consensus",
    },
    "causal_validation": {
        "tier": 6,
        "name": "DoWhy Causal Gatekeeper",
        "enforcement": ["python"],
        "module": "src.gateway.governance.causal_gatekeeper",
    },
    "output_validation": {
        "tier": 1,
        "name": "NeMo Output Guardrail",
        "enforcement": ["nemo"],
        "module": "src.gateway.governance.nemo.manager",
    },
}

# Default enforcement when AAIF stage has no explicit enforcement spec
_DEFAULT_ENFORCEMENT: list[str] = ["python"]


def _map_stage_constraint(constraint: dict[str, Any]) -> dict[str, Any]:
    """Map an AAIF stage constraint to a CAGE ConditionModel dict."""
    ctype = constraint.get("type", "")
    param = constraint.get("parameter") or constraint.get("param")
    value = constraint.get("value") or constraint.get("threshold")

    operator_map = {
        "required": "is_null",
        "max": "greater_than",
        "min": "less_than",
        "equals": "equals",
        "forbidden": "is_false",
        "must_be_true": "is_true",
    }

    cage_operator = operator_map.get(ctype)
    if cage_operator is None:
        return {"composite": constraint.get("expression", str(constraint))}

    condition: dict[str, Any] = {"operator": cage_operator}
    if param:
        condition["param"] = param
    if value is not None:
        condition["threshold"] = (
            float(value) if isinstance(value, (int, float)) else value
        )

    return condition


def _map_hook_to_uca(
    hook: dict[str, Any],
    stage_name: str,
    stage_info: dict[str, Any],
    index: int,
) -> dict[str, Any] | None:
    """Map a single AAIF governance hook to a CAGE UCA dict."""
    hook_id = hook.get("id") or f"AAIF-{stage_name.upper()}-{index:03d}"
    action = hook.get("action") or hook.get("controlAction") or stage_name
    description = hook.get("description", f"AAIF governance hook: {hook_id}")
    hazard_refs = (
        hook.get("hazardRefs") or hook.get("hazard_refs") or [f"H-AAIF-{stage_name}"]
    )
    enforcement = (
        hook.get("enforcement") or stage_info.get("enforcement") or _DEFAULT_ENFORCEMENT
    )

    constraints = hook.get("constraints") or []
    if constraints:
        if len(constraints) == 1:
            condition = _map_stage_constraint(constraints[0])
        else:
            parts = [
                f"{c.get('parameter', '?')} {c.get('type', '?')} {c.get('value', '?')}"
                for c in constraints
            ]
            condition = {"composite": " AND ".join(parts)}
    else:
        condition = {"composite": hook.get("condition", f"aaif_{stage_name}_violation")}

    uca_type_raw = hook.get("ucaType") or hook.get("uca_type") or "unsafe_action"
    uca_type_map = {
        "omission": "not_provided",
        "commission": "unsafe_action",
        "early": "wrong_timing",
        "late": "wrong_timing",
        "too_long": "stopped_too_soon",
        "not_provided": "not_provided",
        "unsafe_action": "unsafe_action",
        "wrong_timing": "wrong_timing",
        "stopped_too_soon": "stopped_too_soon",
    }
    uca_type = uca_type_map.get(uca_type_raw, "unsafe_action")

    return {
        "id": hook_id,
        "action": action,
        "uca_type": uca_type,
        "hazard_refs": hazard_refs,
        "description": description,
        "condition": condition,
        "enforcement": enforcement,
        "_aaif_stage": stage_name,
        "_aaif_tier": stage_info.get("tier"),
    }


def translate_aaif(spec: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Translate an AAIF governed run loop spec into CAGE pipeline stage map and UCAs.

    Args:
        spec: Parsed AAIF specification document (dict from JSON/YAML).
              Must contain a ``governedRunLoop`` top-level key.

    Returns:
        Tuple of:
        - ``stage_map``: dict mapping AAIF stage names to CAGE tier info
        - ``uca_list``: list of CAGE UCA dicts from governance hooks

    Raises:
        ValueError: If ``spec`` does not contain ``governedRunLoop``.
    """
    if "governedRunLoop" not in spec:
        raise ValueError(
            "AAIFAdapter: spec does not contain 'governedRunLoop' key. "
            "Ensure the input is a valid AAIF governed run loop specification."
        )

    run_loop = spec["governedRunLoop"]
    stages = run_loop.get("stages") or []

    stage_map: dict[str, Any] = {}
    ucas: list[dict[str, Any]] = []

    for stage in stages:
        stage_name = stage.get("name") or stage.get("id") or "unknown"
        stage_info = _AAIF_STAGE_TO_CAGE_TIER.get(
            stage_name,
            {
                "tier": -1,
                "name": f"Unknown AAIF stage: {stage_name}",
                "enforcement": _DEFAULT_ENFORCEMENT,
            },
        )

        stage_map[stage_name] = {
            **stage_info,
            "aaif_stage": stage,
        }

        # Map governance hooks within this stage to UCAs
        hooks = stage.get("governanceHooks") or stage.get("hooks") or []
        for i, hook in enumerate(hooks):
            uca = _map_hook_to_uca(hook, stage_name, stage_info, i)
            if uca is not None:
                ucas.append(uca)

        # If no explicit hooks but stage has constraints, create a synthetic UCA
        if not hooks and stage.get("constraints"):
            synthetic_hook = {
                "id": f"AAIF-{stage_name.upper()}-SYNTHETIC",
                "action": stage_name,
                "description": f"Synthetic UCA from AAIF stage '{stage_name}' constraints",
                "constraints": stage.get("constraints", []),
            }
            uca = _map_hook_to_uca(synthetic_hook, stage_name, stage_info, 0)
            if uca is not None:
                ucas.append(uca)

    logger.info(
        "AAIFAdapter: mapped %d AAIF stages → %d CAGE UCAs.",
        len(stages),
        len(ucas),
    )
    return stage_map, ucas


def aaif_to_control_structure_patch(spec: dict[str, Any]) -> dict[str, Any]:
    """Produce a partial ControlStructureModel dict from an AAIF spec.

    This is the artifact bundle format consumed by ``policy_translator.py``.

    Args:
        spec: Parsed AAIF specification document.

    Returns:
        Dict with ``unsafe_control_actions`` key populated from AAIF hooks,
        plus ``system`` and ``hazards`` stubs derived from AAIF metadata.
    """
    stage_map, ucas = translate_aaif(spec)

    metadata = spec.get("metadata") or {}
    run_loop = spec.get("governedRunLoop") or {}
    system_name = (
        metadata.get("name")
        or run_loop.get("name")
        or spec.get("name")
        or "AAIF-Imported System"
    )
    system_version = metadata.get("version") or spec.get("version") or "0.0.0"

    # Build minimal hazard stubs from hazard_refs referenced in UCAs
    all_hazard_refs: set[str] = set()
    for uca in ucas:
        all_hazard_refs.update(uca.get("hazard_refs", []))

    hazards = [
        {
            "id": href,
            "description": f"Hazard imported from AAIF spec: {href}",
            "severity": "high",
        }
        for href in sorted(all_hazard_refs)
    ]

    # Build control_actions from stage_map
    control_actions = [
        {
            "name": stage_name,
            "description": info.get("name", stage_name),
            "cage_tier": info.get("tier", -1),
        }
        for stage_name, info in stage_map.items()
    ]

    return {
        "system": {
            "name": system_name,
            "version": system_version,
            "description": f"Imported from AAIF governed run loop specification: {system_name}",
            "controller": "AAIF-Agent",
            "controlled_process": "AAIF-GovernedRunLoop",
        },
        "hazards": hazards,
        "control_actions": control_actions,
        "unsafe_control_actions": ucas,
        "safety_constraints": [],
        "_aaif_stage_map": stage_map,
    }
