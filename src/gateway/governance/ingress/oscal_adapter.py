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
OSCAL Ingestion Adapter
=======================

Accepts an OSCAL 1.1.x component definition document and translates the
implemented controls into CAGE UCA YAML format, feeding ``stpa_compiler.py``.

OSCAL spec reference: https://pages.nist.gov/OSCAL/

Mapping logic
-------------
| OSCAL element                                                          | CAGE UCA field  |
|------------------------------------------------------------------------|-----------------|
| ``component.control-implementations[].implemented-requirements[].control-id`` | ``hazard_refs`` |
| ``implemented-requirement.description``                                | ``description`` |
| ``implemented-requirement.props[name=status].value``                   | ``uca_type``    |
| ``implemented-requirement.statements[].description``                   | ``condition.composite`` |
| ``implemented-requirement.props[name=enforcement-target].value``       | ``enforcement`` |

Format detection: presence of ``oscal-version`` key in the parsed document
(either at top level or under ``component-definition.metadata``).

Compliance note: This adapter touches NIST SP 800-53 control implementations.
An OSCAL component update in ``compliance/oscal/`` is required within 2
business days of PR merge per Code Mode compliance obligations.

Usage::

    from src.gateway.governance.ingress.oscal_adapter import translate_oscal

    uca_list = translate_oscal(oscal_doc)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("Gateway.Governance.Ingress.OSCALAdapter")

# ---------------------------------------------------------------------------
# OSCAL implementation-status → CAGE uca_type mapping
# ---------------------------------------------------------------------------

_OSCAL_STATUS_TO_UCA_TYPE: dict[str, str] = {
    "implemented": "unsafe_action",
    "planned": "not_provided",
    "partial": "wrong_timing",
    "not-applicable": "not_provided",
    "alternative": "unsafe_action",
    # Fallback for non-standard values
    "active": "unsafe_action",
    "inactive": "not_provided",
}

# Default enforcement when no enforcement-target prop is present
_DEFAULT_ENFORCEMENT: list[str] = ["python"]

# Known CAGE enforcement target values (validated against EnforcementTarget literal)
_VALID_ENFORCEMENT_TARGETS = frozenset({"opa", "nemo", "python", "langgraph", "all"})


def _extract_prop(props: list[dict[str, Any]], name: str) -> str | None:
    """Extract the value of a named prop from an OSCAL props list."""
    for prop in props:
        if prop.get("name") == name:
            return prop.get("value")
    return None


def _extract_enforcement(props: list[dict[str, Any]]) -> list[str]:
    """Extract enforcement targets from OSCAL props.

    Looks for ``enforcement-target`` prop. Value may be comma-separated
    (e.g. ``"opa,python"``) or a single target.

    Returns default ``["python"]`` if prop is absent.
    """
    raw = _extract_prop(props, "enforcement-target")
    if not raw:
        return _DEFAULT_ENFORCEMENT

    targets = [t.strip().lower() for t in raw.split(",") if t.strip()]
    valid = [t for t in targets if t in _VALID_ENFORCEMENT_TARGETS]
    invalid = [t for t in targets if t not in _VALID_ENFORCEMENT_TARGETS]

    if invalid:
        logger.warning(
            "OSCALAdapter: unknown enforcement targets %s — ignoring.", invalid
        )

    return valid if valid else _DEFAULT_ENFORCEMENT


def _map_implemented_requirement(
    req: dict[str, Any],
    component_title: str,
    req_index: int,
) -> dict[str, Any] | None:
    """Map a single OSCAL implemented-requirement to a CAGE UCA dict.

    Returns None if the requirement cannot be meaningfully mapped (logged).
    """
    control_id = req.get("control-id")
    if not control_id:
        logger.warning(
            "OSCALAdapter: implemented-requirement at index %d has no 'control-id' — skipping.",
            req_index,
        )
        return None

    req_uuid = req.get("uuid", f"oscal-req-{req_index:04d}")
    description = req.get("description") or f"OSCAL control {control_id} implementation"
    props = req.get("props") or []

    # Derive uca_type from implementation-status prop
    status = _extract_prop(props, "implementation-status") or _extract_prop(
        props, "status"
    )
    uca_type = _OSCAL_STATUS_TO_UCA_TYPE.get(status or "implemented", "unsafe_action")

    # Derive enforcement from enforcement-target prop
    enforcement = _extract_enforcement(props)

    # Build condition from statements (free-form composite)
    statements = req.get("statements") or []
    if statements:
        stmt_texts = [
            s.get("description", "") for s in statements if s.get("description")
        ]
        composite = " | ".join(stmt_texts) if stmt_texts else description
        condition: dict[str, Any] = {"composite": composite}
    else:
        # No statements: use description as composite condition
        condition = {"composite": description}

    # Map control-id to CAGE hazard_refs
    # OSCAL control IDs (e.g. "ac-3", "si-10") map to CAGE CTRL_* enum values
    # via ControlRegistry. We store the raw control-id as the hazard_ref and
    # let the compiler resolve it.
    hazard_refs = [control_id.upper().replace("-", "_")]

    # Build a stable UCA ID from component + control-id + uuid suffix
    uca_id = f"OSCAL-{control_id.upper().replace('-', '_')}-{req_uuid[:8].upper()}"

    # Derive action from control-id (e.g. "ac-3" → "access_enforcement")
    action = _control_id_to_action(control_id)

    return {
        "id": uca_id,
        "action": action,
        "uca_type": uca_type,
        "hazard_refs": hazard_refs,
        "description": description,
        "condition": condition,
        "enforcement": enforcement,
        "_oscal_control_id": control_id,
        "_oscal_component": component_title,
        "_oscal_req_uuid": req_uuid,
    }


def _control_id_to_action(control_id: str) -> str:
    """Map an OSCAL control ID to a CAGE action name.

    Uses a best-effort mapping for common NIST SP 800-53 controls.
    Unknown controls fall back to a sanitized version of the control ID.
    """
    _CONTROL_ACTION_MAP: dict[str, str] = {
        "ac-2": "account_management",
        "ac-3": "access_enforcement",
        "ac-4": "information_flow_enforcement",
        "ac-6": "least_privilege",
        "ac-17": "remote_access",
        "au-2": "audit_event_generation",
        "au-12": "audit_record_generation",
        "ca-2": "security_assessment",
        "cm-6": "configuration_settings",
        "ia-3": "device_identification",
        "ia-5": "authenticator_management",
        "ir-6": "incident_reporting",
        "ra-5": "vulnerability_monitoring",
        "sc-4": "information_in_shared_system_resources",
        "sc-8": "transmission_confidentiality",
        "sc-12": "cryptographic_key_establishment",
        "si-2": "flaw_remediation",
        "si-10": "information_input_validation",
    }
    normalized = control_id.lower().strip()
    return _CONTROL_ACTION_MAP.get(normalized, normalized.replace("-", "_"))


def _find_oscal_version(doc: dict[str, Any]) -> str | None:
    """Find the oscal-version field anywhere in the document structure."""
    # Top-level
    if "oscal-version" in doc:
        return doc["oscal-version"]
    # Under component-definition.metadata
    comp_def = doc.get("component-definition") or {}
    metadata = comp_def.get("metadata") or {}
    return metadata.get("oscal-version")


def translate_oscal(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate an OSCAL component definition document into CAGE UCA dicts.

    Args:
        doc: Parsed OSCAL document (dict from JSON/YAML). Must contain
             ``oscal-version`` at top level or under
             ``component-definition.metadata``.

    Returns:
        List of CAGE UCA dicts. Unknown control-ids are logged as warnings
        and omitted (not a hard failure).

    Raises:
        ValueError: If the document does not appear to be an OSCAL document
                    (no ``oscal-version`` key found).
    """
    oscal_version = _find_oscal_version(doc)
    if oscal_version is None:
        raise ValueError(
            "OSCALAdapter: document does not contain 'oscal-version' key. "
            "Ensure the input is a valid OSCAL component definition document."
        )

    logger.info("OSCALAdapter: processing OSCAL %s document.", oscal_version)

    # Navigate to components — support both wrapped and unwrapped formats
    comp_def = doc.get("component-definition") or doc
    components = comp_def.get("components") or []

    ucas: list[dict[str, Any]] = []
    total_reqs = 0

    for component in components:
        comp_title = (
            component.get("title") or component.get("name") or "Unknown Component"
        )
        control_impls = component.get("control-implementations") or []

        for impl in control_impls:
            impl_reqs = impl.get("implemented-requirements") or []
            for i, req in enumerate(impl_reqs):
                total_reqs += 1
                uca = _map_implemented_requirement(req, comp_title, i)
                if uca is not None:
                    ucas.append(uca)

    logger.info(
        "OSCALAdapter: translated %d/%d implemented-requirements into CAGE UCAs.",
        len(ucas),
        total_reqs,
    )
    return ucas


def oscal_to_control_structure_patch(doc: dict[str, Any]) -> dict[str, Any]:
    """Produce a partial ControlStructureModel dict from an OSCAL document.

    This is the artifact bundle format consumed by ``policy_translator.py``.

    Args:
        doc: Parsed OSCAL component definition document.

    Returns:
        Dict with ``unsafe_control_actions`` key populated from OSCAL
        implemented-requirements, plus ``system`` and ``hazards`` stubs.
    """
    ucas = translate_oscal(doc)

    comp_def = doc.get("component-definition") or doc
    metadata = comp_def.get("metadata") or {}
    system_name = metadata.get("title") or "OSCAL-Imported System"
    system_version = metadata.get("version") or "0.0.0"

    # Build hazard stubs from unique control IDs referenced in UCAs
    all_hazard_refs: set[str] = set()
    for uca in ucas:
        all_hazard_refs.update(uca.get("hazard_refs", []))

    hazards = [
        {
            "id": href,
            "description": f"NIST SP 800-53 control: {href.replace('_', '-').lower()}",
            "severity": "high",
        }
        for href in sorted(all_hazard_refs)
    ]

    return {
        "system": {
            "name": system_name,
            "version": system_version,
            "description": f"Imported from OSCAL component definition: {system_name}",
            "controller": "OSCAL-Component",
            "controlled_process": "OSCAL-ControlledSystem",
        },
        "hazards": hazards,
        "control_actions": [],
        "unsafe_control_actions": ucas,
        "safety_constraints": [],
        "_oscal_version": _find_oscal_version(doc),
    }
