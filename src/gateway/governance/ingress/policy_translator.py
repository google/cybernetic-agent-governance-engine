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
Policy Translator — Unified Ingress Pipeline
=============================================

Unified translation pipeline that:

1. Detects the spec format (ACS / AAIF / OSCAL / Lula / native CAGE YAML)
2. Routes to the appropriate adapter
3. Calls ``stpa_compiler.py`` to produce compiled enforcement artifacts
4. Returns a ``ControlRegistry``-compatible ``ArtifactBundle``

This module is the single entry point for the ``POST /governance/ingest-policy``
API endpoint.

Format detection (G4 — ``detect_format()``)
--------------------------------------------
| Key present in spec                | Detected format |
|------------------------------------|-----------------|
| ``oscal-version``                  | ``"oscal"``     |
| ``kind == "LulaValidation"``       | ``"lula"``      |
| ``component-definition`` (OSCAL)   | ``"oscal"``     |
| ``behaviorDeclarations``           | ``"acs"``       |
| ``governedRunLoop``                | ``"aaif"``      |
| (none of the above)                | ``"cage_yaml"`` |

Usage::

    from src.gateway.governance.ingress.policy_translator import translate_policy

    bundle = translate_policy(spec_dict)
    print(bundle.policy_version_id)
    print(bundle.format_detected)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger("Gateway.Governance.Ingress.PolicyTranslator")

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

PolicyFormat = Literal["acs", "aaif", "oscal", "lula", "cage_yaml"]


# ---------------------------------------------------------------------------
# ArtifactBundle — the output of the translation pipeline
# ---------------------------------------------------------------------------


@dataclass
class ArtifactBundle:
    """Output of the policy translation pipeline.

    Attributes:
        format_detected: The detected input format.
        policy_version_id: SHA-256 hash of the compiled OPA content (first 16 hex chars).
                           Matches the ``policy_version_id`` field in the
                           ``GET /governance/policy-version`` response.
        opa_content: Compiled OPA Rego policy text (empty string if not applicable).
        nemo_content: Compiled NeMo Colang rail text (empty string if not applicable).
        python_content: Compiled Python validator text (empty string if not applicable).
        langgraph_content: Compiled LangGraph Saga nodes text (empty string if not applicable).
        opa_bundle_modules: List of OPA module dicts from Lula adapter (format-specific).
        control_structure_patch: The intermediate ControlStructureModel-compatible dict.
        errors: List of error strings encountered during translation.
        warnings: List of warning strings (non-fatal).
    """

    format_detected: PolicyFormat = "cage_yaml"
    policy_version_id: str = ""
    opa_content: str = ""
    nemo_content: str = ""
    python_content: str = ""
    langgraph_content: str = ""
    opa_bundle_modules: list[dict[str, str]] = field(default_factory=list)
    control_structure_patch: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True if translation completed without fatal errors."""
        return len(self.errors) == 0


# ---------------------------------------------------------------------------
# G4 — Format detection
# ---------------------------------------------------------------------------


def detect_format(spec: dict[str, Any]) -> PolicyFormat:
    """Detect the policy specification format from the parsed document.

    Detection order (first match wins):
    1. ``oscal-version`` key → ``"oscal"``
    2. ``kind == "LulaValidation"`` → ``"lula"``
    3. ``component-definition`` key (OSCAL-wrapped Lula) → ``"oscal"``
    4. ``behaviorDeclarations`` key → ``"acs"``
    5. ``governedRunLoop`` key → ``"aaif"``
    6. Fallback → ``"cage_yaml"``

    Args:
        spec: Parsed policy specification document (dict from JSON/YAML).

    Returns:
        One of ``"acs"``, ``"aaif"``, ``"oscal"``, ``"lula"``, ``"cage_yaml"``.
    """
    if "oscal-version" in spec:
        return "oscal"
    if spec.get("kind") == "LulaValidation":
        return "lula"
    if "component-definition" in spec:
        # OSCAL-wrapped format (e.g. Lula manifests converted to OSCAL)
        comp_def = spec["component-definition"]
        metadata = comp_def.get("metadata") or {}
        if "oscal-version" in metadata:
            return "oscal"
        # Could be OSCAL-wrapped Lula — treat as OSCAL
        return "oscal"
    if "behaviorDeclarations" in spec:
        return "acs"
    if "governedRunLoop" in spec:
        return "aaif"
    return "cage_yaml"


# ---------------------------------------------------------------------------
# Translation pipeline
# ---------------------------------------------------------------------------


def _compute_version_id(content: str) -> str:
    """Compute a stable policy_version_id from compiled content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _translate_acs(spec: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Route ACS spec through the ACS adapter and STPA compiler."""
    from src.gateway.governance.ingress.acs_adapter import (
        acs_to_control_structure_patch,
    )
    from src.gateway.governance.stpa_compiler import (
        ControlStructureModel,
        compile_control_structure,
    )

    try:
        patch = acs_to_control_structure_patch(spec)
        bundle.control_structure_patch = patch
    except Exception as exc:
        bundle.errors.append(f"ACS adapter failed: {exc}")
        return

    _compile_patch(patch, bundle)


def _translate_aaif(spec: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Route AAIF spec through the AAIF adapter and STPA compiler."""
    from src.gateway.governance.ingress.aaif_adapter import (
        aaif_to_control_structure_patch,
    )

    try:
        patch = aaif_to_control_structure_patch(spec)
        bundle.control_structure_patch = patch
    except Exception as exc:
        bundle.errors.append(f"AAIF adapter failed: {exc}")
        return

    _compile_patch(patch, bundle)


def _translate_oscal(spec: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Route OSCAL document through the OSCAL adapter and STPA compiler."""
    from src.gateway.governance.ingress.oscal_adapter import (
        oscal_to_control_structure_patch,
    )

    try:
        patch = oscal_to_control_structure_patch(spec)
        bundle.control_structure_patch = patch
    except Exception as exc:
        bundle.errors.append(f"OSCAL adapter failed: {exc}")
        return

    _compile_patch(patch, bundle)


def _translate_lula(spec: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Route Lula manifest through the Lula adapter (OPA bundle path)."""
    from src.gateway.governance.ingress.lula_adapter import lula_to_opa_bundle_patch

    try:
        result = lula_to_opa_bundle_patch(spec)
        bundle.opa_bundle_modules = result["bundle_modules"]
        bundle.control_structure_patch = {
            "lula_policy_name": result["lula_policy_name"],
            "input_schema": result["input_schema"],
        }
        # For Lula, the OPA content is the concatenation of all modules
        if result["bundle_modules"]:
            bundle.opa_content = "\n\n".join(
                m["rego"] for m in result["bundle_modules"]
            )
    except Exception as exc:
        bundle.errors.append(f"Lula adapter failed: {exc}")
        return


def _translate_cage_yaml(spec: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Pass native CAGE YAML directly to the STPA compiler."""
    bundle.control_structure_patch = spec
    _compile_patch(spec, bundle)


def _compile_patch(patch: dict[str, Any], bundle: ArtifactBundle) -> None:
    """Attempt to compile a ControlStructureModel patch via stpa_compiler.

    Skips compilation gracefully if the patch does not have the minimum
    required fields for a valid ControlStructureModel (e.g. OSCAL patches
    with no UCAs that have opa_rule defined).
    """
    from src.gateway.governance.stpa_compiler import (
        ControlStructureModel,
        compile_control_structure,
    )

    # Ensure minimum required fields are present
    if "system" not in patch:
        bundle.warnings.append(
            "Patch has no 'system' key — skipping STPA compiler. "
            "OPA/NeMo/Python artifacts will not be generated."
        )
        return

    # Strip private keys (prefixed with _) before Pydantic validation
    clean_patch = {k: v for k, v in patch.items() if not k.startswith("_")}

    # Ensure required top-level keys exist with defaults
    clean_patch.setdefault("hazards", [])
    clean_patch.setdefault("control_actions", [])
    clean_patch.setdefault("unsafe_control_actions", [])
    clean_patch.setdefault("safety_constraints", [])

    # Strip private keys from UCAs too
    ucas = clean_patch.get("unsafe_control_actions") or []
    clean_ucas = []
    for uca in ucas:
        clean_uca = {k: v for k, v in uca.items() if not k.startswith("_")}
        clean_ucas.append(clean_uca)
    clean_patch["unsafe_control_actions"] = clean_ucas

    try:
        cs = ControlStructureModel(**clean_patch)
    except Exception as exc:
        bundle.warnings.append(
            f"ControlStructureModel validation failed (patch may be partial): {exc}. "
            "Skipping STPA compiler — raw patch preserved in control_structure_patch."
        )
        return

    # Determine which targets to compile based on what UCAs have enforcement for
    targets: set[str] = set()
    for uca in cs.unsafe_control_actions:
        for t in uca.enforcement:
            if t == "all":
                targets.update(["opa", "nemo", "python", "langgraph"])
            else:
                targets.add(t)

    if not targets:
        bundle.warnings.append(
            "No enforcement targets found in UCAs — skipping compilation."
        )
        return

    try:
        result = compile_control_structure(cs, list(targets))
        if result.errors:
            for err in result.errors:
                bundle.warnings.append(f"Compiler warning: {err}")
        bundle.opa_content = result.opa_content
        bundle.nemo_content = result.nemo_content
        bundle.python_content = result.python_content
        bundle.langgraph_content = result.langgraph_content
    except Exception as exc:
        bundle.errors.append(f"STPA compiler failed: {exc}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def translate_policy(spec: dict[str, Any]) -> ArtifactBundle:
    """Translate an external policy specification into CAGE enforcement artifacts.

    This is the main entry point for the ``POST /governance/ingest-policy``
    API endpoint.

    Steps:
    1. Detect format (ACS / AAIF / OSCAL / Lula / native CAGE YAML)
    2. Route to the appropriate adapter
    3. Compile via ``stpa_compiler.py`` where applicable
    4. Compute ``policy_version_id`` from compiled OPA content

    Args:
        spec: Parsed policy specification document (dict from JSON/YAML).

    Returns:
        ``ArtifactBundle`` with compiled artifacts and metadata.
        Check ``bundle.success`` and ``bundle.errors`` for failure details.
    """
    bundle = ArtifactBundle()
    fmt = detect_format(spec)
    bundle.format_detected = fmt

    logger.info("PolicyTranslator: detected format '%s'.", fmt)

    _ROUTERS = {
        "acs": _translate_acs,
        "aaif": _translate_aaif,
        "oscal": _translate_oscal,
        "lula": _translate_lula,
        "cage_yaml": _translate_cage_yaml,
    }

    router = _ROUTERS.get(fmt)
    if router is None:
        bundle.errors.append(f"No router registered for format '{fmt}'.")
        return bundle

    router(spec, bundle)

    # Compute policy_version_id from the primary compiled artifact
    primary_content = (
        bundle.opa_content
        or bundle.python_content
        or bundle.nemo_content
        or bundle.langgraph_content
        or json.dumps(bundle.control_structure_patch, sort_keys=True)
    )
    bundle.policy_version_id = _compute_version_id(primary_content)

    if bundle.success:
        logger.info(
            "PolicyTranslator: translation complete. format=%s version_id=%s",
            fmt,
            bundle.policy_version_id,
        )
    else:
        logger.error(
            "PolicyTranslator: translation failed. format=%s errors=%s",
            fmt,
            bundle.errors,
        )

    return bundle
