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
Lula Validation Manifest Adapter
=================================

Accepts a Lula validation manifest (``compliance/lula/*.yaml``) and extracts
the Kubernetes resource assertions as CAGE governance constraints, feeding the
OPA policy engine.

Lula spec reference: https://lula.dev

Mapping logic
-------------
| Lula manifest element                                    | CAGE target                        |
|----------------------------------------------------------|------------------------------------|
| ``metadata.name``                                        | OPA policy rule name (``lula_<name>``) |
| ``spec.domain.kubernetes-spec.resources[].name``         | OPA input field reference          |
| ``spec.domain.kubernetes-spec.resources[].resource-rule.version`` | OPA input validation constraint |
| ``spec.policy.opa.rego``                                 | Injected as named OPA module       |
| ``spec.policy.opa.modules[]``                            | Additional OPA modules appended    |

Format detection: presence of ``kind: LulaValidation`` in the parsed document.

Compliance note: Adding ``lula_adapter.py`` adds a new Kubernetes resource
reference. A Lula validation update in ``compliance/lula/`` must be included
in the same PR or flagged for a follow-on PR per Code Mode compliance
obligations.

Usage::

    from src.gateway.governance.ingress.lula_adapter import translate_lula

    opa_bundle = translate_lula(lula_manifest_dict)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("Gateway.Governance.Ingress.LulaAdapter")


def _extract_rego_from_back_matter(doc: dict[str, Any]) -> str | None:
    """Extract inline Rego from OSCAL-wrapped Lula back-matter format.

    Some Lula manifests embed the domain/provider spec as a YAML string
    inside ``component-definition.back-matter.resources[].description``.
    This helper parses that embedded YAML to extract the OPA Rego.
    """
    try:
        import yaml as _yaml

        comp_def = doc.get("component-definition") or {}
        back_matter = comp_def.get("back-matter") or {}
        resources = back_matter.get("resources") or []
        for resource in resources:
            desc = resource.get("description") or ""
            if not desc:
                continue
            try:
                embedded = _yaml.safe_load(desc)
                if isinstance(embedded, dict):
                    provider = embedded.get("provider") or {}
                    opa_spec = provider.get("opa-spec") or {}
                    rego = opa_spec.get("rego")
                    if rego:
                        return rego
            except Exception:
                pass
    except ImportError:
        pass
    return None


def _extract_kubernetes_resources(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract Kubernetes resource specs from a Lula manifest.

    Handles both direct ``spec.domain.kubernetes-spec`` format and
    OSCAL-wrapped back-matter format.
    """
    # Direct format
    spec = doc.get("spec") or {}
    domain = spec.get("domain") or {}
    k8s_spec = domain.get("kubernetes-spec") or {}
    resources = k8s_spec.get("resources") or []
    if resources:
        return resources

    # OSCAL-wrapped format: parse from back-matter description
    try:
        import yaml as _yaml

        comp_def = doc.get("component-definition") or {}
        back_matter = comp_def.get("back-matter") or {}
        bm_resources = back_matter.get("resources") or []
        for resource in bm_resources:
            desc = resource.get("description") or ""
            if not desc:
                continue
            try:
                embedded = _yaml.safe_load(desc)
                if isinstance(embedded, dict):
                    emb_domain = embedded.get("domain") or {}
                    emb_k8s = emb_domain.get("kubernetes-spec") or {}
                    emb_resources = emb_k8s.get("resources") or []
                    if emb_resources:
                        return emb_resources
            except Exception:
                pass
    except ImportError:
        pass

    return []


def translate_lula(doc: dict[str, Any]) -> dict[str, Any]:
    """Translate a Lula validation manifest into a CAGE OPA bundle descriptor.

    Args:
        doc: Parsed Lula manifest document (dict from YAML). Must contain
             ``kind: LulaValidation`` at top level, OR be an OSCAL-wrapped
             component definition containing embedded Lula validation data.

    Returns:
        Dict with:
        - ``policy_name``: OPA rule name (``lula_<metadata.name>``)
        - ``opa_modules``: list of OPA module dicts, each with ``name`` and ``rego``
        - ``k8s_resources``: list of Kubernetes resource specs referenced
        - ``raw_manifest``: the original manifest for audit purposes

    Raises:
        ValueError: If the document is not a Lula validation manifest.
    """
    # Support both direct LulaValidation kind and OSCAL-wrapped format
    kind = doc.get("kind")
    is_oscal_wrapped = "component-definition" in doc

    if kind != "LulaValidation" and not is_oscal_wrapped:
        raise ValueError(
            "LulaAdapter: document does not have 'kind: LulaValidation' and is not "
            "an OSCAL-wrapped Lula manifest. "
            "Ensure the input is a valid Lula validation manifest."
        )

    # Extract name
    if kind == "LulaValidation":
        metadata = doc.get("metadata") or {}
        name = metadata.get("name") or "unnamed"
    else:
        # OSCAL-wrapped: use component-definition.metadata.title
        comp_def = doc.get("component-definition") or {}
        metadata = comp_def.get("metadata") or {}
        title = metadata.get("title") or "unnamed"
        # Sanitize title to a valid OPA rule name
        name = title.lower().replace(" ", "_").replace("-", "_").replace("—", "_")
        # Strip common prefixes
        for prefix in ("cage_validation_", "lula_validation_", "cage_"):
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break

    policy_name = f"lula_{name.lower().replace('-', '_').replace(' ', '_')}"

    # Extract OPA modules
    opa_modules: list[dict[str, str]] = []

    if kind == "LulaValidation":
        spec = doc.get("spec") or {}
        policy = spec.get("policy") or {}
        opa_spec = policy.get("opa") or {}

        # Primary inline Rego
        inline_rego = opa_spec.get("rego")
        if inline_rego:
            opa_modules.append(
                {
                    "name": policy_name,
                    "rego": inline_rego,
                }
            )

        # Additional modules
        extra_modules = opa_spec.get("modules") or []
        for i, module in enumerate(extra_modules):
            if isinstance(module, str):
                opa_modules.append(
                    {
                        "name": f"{policy_name}_module_{i}",
                        "rego": module,
                    }
                )
            elif isinstance(module, dict):
                mod_name = module.get("name") or f"{policy_name}_module_{i}"
                mod_rego = module.get("rego") or module.get("content") or ""
                if mod_rego:
                    opa_modules.append({"name": mod_name, "rego": mod_rego})
    else:
        # OSCAL-wrapped: extract from back-matter
        inline_rego = _extract_rego_from_back_matter(doc)
        if inline_rego:
            opa_modules.append(
                {
                    "name": policy_name,
                    "rego": inline_rego,
                }
            )

    if not opa_modules:
        logger.warning(
            "LulaAdapter: manifest '%s' has no OPA Rego content — "
            "bundle will have no enforcement rules.",
            policy_name,
        )

    # Extract Kubernetes resource references
    k8s_resources = _extract_kubernetes_resources(doc)

    logger.info(
        "LulaAdapter: extracted %d OPA module(s) and %d k8s resource(s) from '%s'.",
        len(opa_modules),
        len(k8s_resources),
        policy_name,
    )

    return {
        "policy_name": policy_name,
        "opa_modules": opa_modules,
        "k8s_resources": k8s_resources,
        "raw_manifest": doc,
    }


def lula_to_opa_bundle_patch(doc: dict[str, Any]) -> dict[str, Any]:
    """Produce an OPA bundle patch dict from a Lula manifest.

    This is the artifact bundle format consumed by ``policy_translator.py``.
    The caller merges this patch into the active OPA bundle at startup or
    via the policy ingestion API.

    Args:
        doc: Parsed Lula manifest document.

    Returns:
        Dict with:
        - ``bundle_modules``: list of OPA module dicts ready for bundle injection
        - ``input_schema``: dict describing expected OPA input fields from k8s resources
        - ``lula_policy_name``: the generated policy name
    """
    result = translate_lula(doc)

    # Build input schema from k8s resource specs
    input_schema: dict[str, Any] = {}
    for resource in result["k8s_resources"]:
        res_name = resource.get("name") or resource.get("resource") or "unknown"
        resource_rule = resource.get("resource-rule") or {}
        input_schema[res_name] = {
            "type": "kubernetes_resource",
            "resource": resource.get("resource") or resource_rule.get("resource"),
            "version": resource_rule.get("version") or resource.get("version"),
            "namespace": resource.get("namespace") or resource_rule.get("namespaces"),
        }

    return {
        "bundle_modules": result["opa_modules"],
        "input_schema": input_schema,
        "lula_policy_name": result["policy_name"],
    }
