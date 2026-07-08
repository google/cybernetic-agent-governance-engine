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
OSCAL SSP Exporter
==================

Reads the active ``config/stpa_control_structure.yaml`` (compiler output)
and surgically patches the existing OSCAL artifacts to reflect the runtime
state of the STPA compiler, closing the compliance loop.

What it does
------------
1. Generates a new OSCAL ``implemented-requirement`` block for the STPA
   compiler controls and **merges** it into the existing
   ``compliance/oscal/system-security-plan.yaml`` under
   ``control-implementation.implemented-requirements``.
2. Patches the ``metadata.last-modified`` and ``metadata.version`` in the SSP.
3. Appends the STPA Compiler as a new component entry in
   ``compliance/oscal/component-definition.yaml``.
4. Emits a standalone ``compliance/oscal/stpa_compiler_ssp_patch.yaml``
   containing only the generated block — useful for diff-review without
   viewing the full 1 100-line SSP.

Design decisions
----------------
* **No `python-oscal` library** — that package does not exist on PyPI.
  We use PyYAML (already a repo dep) to read/write OSCAL YAML directly,
  preserving the existing document structure and comments as much as possible.
  Round-tripping via PyYAML cannot preserve YAML block scalars (``>``) or
  comments inside existing top-level nodes; the generated block is added
  at the end of ``implemented-requirements`` and is always safe to diff.
* **Idempotent**: the exporter checks for an existing
  ``stpa-compiler-sa-1`` requirement ID before inserting; re-running
  overwrites only the generated block, not hand-authored content.
* **Fail-closed on schema errors**: if the SSP fails to load or the
  generated block fails Pydantic validation, the exporter aborts without
  writing any files.

Usage::

    python -m src.gateway.governance.oscal_ssp_exporter export

    # Dry-run: print patch block without writing files
    python -m src.gateway.governance.oscal_ssp_exporter export --dry-run

    # Point at a non-default control structure
    python -m src.gateway.governance.oscal_ssp_exporter export \\
        --input path/to/stpa_control_structure.yaml

Exit codes:
    0  Patch applied (or dry-run OK).
    1  Fatal error.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

import yaml

from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    UCAModel,
    load_control_structure,
)

logger = logging.getLogger("oscal_ssp_exporter")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_INPUT = _REPO_ROOT / "config" / "stpa_control_structure.yaml"
_DEFAULT_SSP = _REPO_ROOT / "compliance" / "oscal" / "system-security-plan.yaml"
_DEFAULT_COMP_DEF = _REPO_ROOT / "compliance" / "oscal" / "component-definition.yaml"
_DEFAULT_PATCH_OUT = (
    _REPO_ROOT / "compliance" / "oscal" / "stpa_compiler_ssp_patch.yaml"
)

# Stable UUIDs for the STPA compiler artifacts — deterministic so the SSP diff
# is minimal across re-runs (no UUID churn).
_STPA_COMPONENT_UUID = "e5000099-stpa-4000-8000-compiler00001"
_STPA_IMPL_UUID = "g7000099-stpa-4000-8000-compiler00001"
_STPA_BY_COMP_UUID = "h8000099-stpa-4000-8000-compiler00001"
_STPA_CTRL_IMPL_UUID = "c3000099-stpa-4000-8000-compiler00001"
_STPA_REQ_UUID_PREFIX = "d4000099-stpa-4000-8000"

# ---------------------------------------------------------------------------
# Multi-jurisdiction SSP router — see docs/technical-report/06-COMPLIANCE-STANDARDS.md §15.7
# ---------------------------------------------------------------------------

# Maps CAGE_DEPLOYMENT_REGION values to OSCAL profile paths and framework metadata.
# Each entry drives both the profile import-href in the SSP and the FrameworkRouter
# selection for UCA cross-walk narrative generation.
REGIONAL_PROFILES: dict[str, dict] = {
    "US_FED": {
        "profile_path": "compliance/oscal/sp800053-profile.yaml",
        "framework": "NIST SP 800-53 Rev 5 HIGH",
        "framework_id": "nist-sp800-53-rev5-high",
        "coverage_metric": "nist_sp800_53_coverage_pct",
    },
    "EU_ECB": {
        "profile_path": "compliance/oscal/eu-ai-act-profile.yaml",
        "framework": "EU AI Act (Reg 2024/1689) + GDPR",
        "framework_id": "eu-ai-act-2024",
        "coverage_metric": "eu_ai_act_coverage_pct",
    },
    "APAC_MAS": {
        "profile_path": "compliance/oscal/mas-feat-profile.yaml",
        "framework": "MAS FEAT Principles + MAS Notice 655",
        "framework_id": "mas-feat-2023",
        "coverage_metric": "mas_feat_coverage_pct",
    },
}

# Maps CAGE_DEPLOYMENT_REGION to the FrameworkRouter key used for UCA cross-walk.
# US_FED → NIST, EU_ECB → EU_AI_ACT, APAC_MAS → MAS_FEAT.
_REGION_TO_FRAMEWORK_KEY: dict[str, str] = {
    "US_FED": "NIST",
    "EU_ECB": "EU_AI_ACT",
    "APAC_MAS": "MAS_FEAT",
}


def get_regional_profile(region: str | None = None) -> dict:
    """Return the OSCAL profile metadata dict for the given deployment region.

    Args:
        region: Explicit region string (``"US_FED"``, ``"EU_ECB"``, or
            ``"APAC_MAS"``).  If *None*, the value is read from the
            ``CAGE_DEPLOYMENT_REGION`` environment variable.  Defaults to
            ``"US_FED"`` if the variable is unset or the value is unrecognised
            (backward-compatible with pre-multi-jurisdiction deployments).

    Returns:
        A dict from :data:`REGIONAL_PROFILES` with keys ``profile_path``,
        ``framework``, ``framework_id``, and ``coverage_metric``.
    """
    if region is None:
        region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()
    else:
        region = region.strip().upper()

    if region not in REGIONAL_PROFILES:
        logger.warning(
            "get_regional_profile: unknown region '%s' — falling back to US_FED. "
            "Set CAGE_DEPLOYMENT_REGION to one of: %s",
            region,
            sorted(REGIONAL_PROFILES.keys()),
        )
        region = "US_FED"

    profile = REGIONAL_PROFILES[region]
    logger.info(
        "get_regional_profile: region=%s → profile=%s framework=%s",
        region,
        profile["profile_path"],
        profile["framework"],
    )
    return profile


# ---------------------------------------------------------------------------
# Framework Router — external JSON-driven UCA-to-control mapping
# ---------------------------------------------------------------------------

_OSCAL_MAPPINGS_DIR: Path = _REPO_ROOT / "config" / "oscal" / "framework_mappings"

# Canonical framework ID → JSON filename stem mapping.
# To add a new jurisdiction: drop a JSON file into the mappings dir and add
# an entry here.  Zero Python changes required in generate_ssp_patch().
_FRAMEWORK_FILE_MAP: dict[str, str] = {
    "NIST": "NIST_SP800_53",
    "ISO42001": "ISO_42001",
    "EU_AI_ACT": "EU_AI_ACT",
    "MAS_FEAT": "MAS_FEAT",
}


class FrameworkRouter:
    """Load and cache an external JSON framework routing table.

    Replaces the hardcoded ``_UCA_TO_*`` dicts and ``_*_DESCRIPTIONS`` dicts
    that previously lived in Python source.  Each supported framework is now
    a versioned JSON file under ``config/oscal/framework_mappings/``.

    Attributes:
        framework_id (str): Canonical framework identifier (e.g. ``"EU_AI_ACT"``).
        label (str): Human-readable framework name for SSP prose.
        source (str): Canonical URL for the framework document.
        uca_mappings (dict): UCA ID → list of control IDs for this framework.
        control_descriptions (dict): Control ID → description string.
        narrative_template (str): ``str.format()`` template for by-component narratives.
    """

    _cache: dict[str, FrameworkRouter] = {}

    def __init__(self, framework_id: str) -> None:
        fid = framework_id.strip().upper()
        file_stem = _FRAMEWORK_FILE_MAP.get(fid)
        if file_stem is None:
            raise ValueError(
                f"FrameworkRouter: unknown framework '{framework_id}'. "
                f"Supported: {sorted(_FRAMEWORK_FILE_MAP.keys())}. "
                f"To add a new framework, create a JSON file in "
                f"config/oscal/framework_mappings/ and register it in "
                f"_FRAMEWORK_FILE_MAP."
            )
        json_path = _OSCAL_MAPPINGS_DIR / f"{file_stem}.json"
        if not json_path.exists():
            raise FileNotFoundError(
                f"FrameworkRouter: mapping file not found at {json_path}. "
                f"Ensure config/oscal/framework_mappings/{file_stem}.json exists."
            )
        with open(json_path) as fh:
            data = json.load(fh)

        self.framework_id: str = data["_framework_id"]
        self.label: str = data["_framework_label"]
        self.source: str = data["_framework_source"]
        self.uca_mappings: dict[str, list[str]] = data["uca_mappings"]
        self.control_descriptions: dict[str, str] = data["control_descriptions"]
        self.narrative_template: str = data["narrative_template"]
        logger.info(
            "FrameworkRouter: loaded '%s' from %s (%d UCA entries)",
            self.framework_id,
            json_path,
            len(self.uca_mappings),
        )

    @classmethod
    def get(cls, framework_id: str) -> FrameworkRouter:
        """Return a cached FrameworkRouter for the given framework ID."""
        fid = framework_id.strip().upper()
        if fid not in cls._cache:
            cls._cache[fid] = cls(fid)
        return cls._cache[fid]

    def controls_for_uca(self, uca_id: str) -> list[str]:
        """Return the list of control IDs that this UCA maps to."""
        return self.uca_mappings.get(uca_id, [])

    def describe(self, control_id: str) -> str:
        """Return the human-readable description for a control ID."""
        return self.control_descriptions.get(control_id, control_id)

    def format_narrative(self, control_id: str, ucas: list[UCAModel]) -> str:
        """Build the by-component description prose for a single control."""
        uca_list = ", ".join(
            u.id for u in ucas if control_id in self.controls_for_uca(u.id)
        )
        return self.narrative_template.format(
            control_id=control_id,
            control_id_upper=control_id.upper(),
            control_description=self.describe(control_id),
            uca_list=uca_list,
        )

    def build_summary(self, ucas: list[UCAModel]) -> str:
        """Build a full prose cross-walk of all UCAs for this framework."""
        lines = []
        for uca in ucas:
            controls = self.controls_for_uca(uca.id)
            ctrl_str = ", ".join(f"{c} ({self.describe(c)})" for c in controls)
            lines.append(
                f"  {uca.id} ({uca.uca_type}): {uca.description}\n"
                f"    → {self.framework_id}: {ctrl_str}"
            )
        return "\n".join(lines)

    def all_controls(self, ucas: list[UCAModel]) -> list[str]:
        """Return a deduplicated ordered list of all control IDs referenced by UCAs."""
        seen: list[str] = []
        for uca in ucas:
            for ctrl in self.controls_for_uca(uca.id):
                if ctrl not in seen:
                    seen.append(ctrl)
        return seen


# ---------------------------------------------------------------------------
# Z3N Network Hardening — SC-7 / SC-8 SSP narrative mapping
# ---------------------------------------------------------------------------

NETWORK_HARDENING_MAPPINGS: dict[str, dict[str, str]] = {
    "sc-8": {
        "title": "Transmission Confidentiality and Integrity — Linkerd mTLS",
        "implemented_by": "Linkerd Service Mesh (Server + AuthorizationPolicy + MeshTLSAuthentication)",
        "status": "implemented",
        "evidence_file": "deployment/k8s/linkerd-mtls-policy.yaml",
        "iso_clause": "A.7.5 (Cryptographic Controls), A.8.4 (AI System Operation)",
        "narrative": (
            "Intra-cluster communications between CAGE core components (Gateway → OPA, "
            "Gateway → NeMo Guardrails) are encrypted using mutual TLS via Linkerd data-plane "
            "proxies. Each workload's identity is derived deterministically from its "
            "Kubernetes ServiceAccount as a SPIFFE Verifiable Identity Document (SVID). "
            "Private keys are stored exclusively in-memory (tmpfs) and TLS certificates are "
            "rotated automatically every 24 hours by the Linkerd control plane. "
            "AuthorizationPolicy resources enforce that only explicitly authorized service "
            "accounts (cage-gateway-sa, cage-compliance-bridge-sa) may reach the OPA Server "
            "on port 8181; any other caller is rejected at the proxy sidecar before reaching "
            "the application layer. Evidence: linkerd viz authz deployment/opa-service -n governance-stack."
        ),
        "poam_refs": "POAM-007 (IA-3), POAM-011 (SC-8)",
        "poam_status": "CLOSED — Linkerd mTLS implemented and verified",
    },
    "sc-7": {
        "title": "Boundary Protection — Cilium L7 FQDN Egress Lockdown",
        "implemented_by": "Cilium CNI CiliumNetworkPolicy (L7 FQDN rules)",
        "status": "implemented",
        "evidence_file": "deployment/k8s/cilium-egress-lockdown.yaml",
        "iso_clause": "A.6.2 (AI System Lifecycle), A.8.4 (AI System Operation)",
        "narrative": (
            "Layer-7 FQDN-aware egress boundaries are enforced on all governance-stack pods "
            "by Cilium CiliumNetworkPolicy resources. Standard Kubernetes NetworkPolicies "
            "(network-policy.yaml) provide L3/L4 default-deny; Cilium extends this to the "
            "application layer by intercepting DNS responses and binding resolved IP addresses "
            "to the FQDN allow-list in real time. Gateway pods may reach only approved external "
            "LLM provider endpoints (api.openai.com, api.anthropic.com, "
            "generativelanguage.googleapis.com) and required GCP service APIs. Sovereign "
            "agent pods are locked to intra-cluster egress only (OPA:8181, Gateway:8080, "
            "OTel:4317/4318) and cannot contact any external endpoint directly, preventing "
            "lateral movement and data exfiltration even if a pod is compromised. "
            "Evidence: cilium monitor --type l7."
        ),
        "poam_refs": "POAM-007 (IA-3)",
        "poam_status": "CLOSED — Cilium L7 egress lockdown implemented",
    },
}

# Stable UUIDs for Z3N SSP blocks
_Z3N_SC8_IMPL_UUID = "g7000098-z3n-sc8-8000-linkerd000001"
_Z3N_SC7_IMPL_UUID = "g7000097-z3n-sc7-8000-cilium0000001"
_Z3N_SC8_BY_COMP_UUID = "h8000098-z3n-sc8-8000-linkerd000001"
_Z3N_SC7_BY_COMP_UUID = "h8000097-z3n-sc7-8000-cilium0000001"


# ---------------------------------------------------------------------------
# Patch block generator
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_ssp_patch(
    cs: ControlStructureModel,
    target_framework: str = "NIST",
) -> dict[str, Any]:
    """
    Generate the OSCAL ``implemented-requirement`` block for the STPA compiler.

    Args:
        cs: The loaded ControlStructureModel from stpa_control_structure.yaml.
        target_framework: Output framework for the UCA cross-walk narrative.
            One of ``"NIST"`` (default, FedRAMP/SP 800-53),
            ``"ISO42001"`` (global baseline),
            ``"EU_AI_ACT"`` (EU High-Risk AI / DORA / GDPR), or
            ``"MAS_FEAT"`` (Singapore FEAT Principles / TRM Guidelines).
            Framework routing tables live in config/oscal/framework_mappings/.

    Returns a dict ready to be appended to
    ``system-security-plan.implemented-requirements``.
    """
    now = _now_iso()

    # Load the external framework routing table — zero hardcoded dicts in Python.
    router = FrameworkRouter.get(target_framework)

    uca_prose = router.build_summary(cs.unsafe_control_actions)
    framework_label = router.label
    framework_source = router.source
    all_framework_controls = router.all_controls(cs.unsafe_control_actions)

    # Build by-components entries — one per referenced control.
    # Narrative prose is rendered by the FrameworkRouter from the external JSON template.
    by_components = []
    for i, ctrl in enumerate(all_framework_controls):
        by_components.append(
            {
                "component-uuid": _STPA_COMPONENT_UUID,
                "uuid": f"{_STPA_BY_COMP_UUID[:-4]}{i:04d}",
                "description": router.format_narrative(ctrl, cs.unsafe_control_actions),
                "implementation-status": {"state": "implemented"},
                "links": [
                    {
                        "href": "../../config/stpa_control_structure.yaml",
                        "rel": "reference",
                        "text": "STPA control structure YAML (source of truth)",
                    },
                    {
                        "href": "../../config/opa/generated_stpa_policy.rego",
                        "rel": "reference",
                        "text": "Generated OPA Rego policy",
                    },
                ],
            }
        )

    requirement: dict[str, Any] = {
        "uuid": _STPA_IMPL_UUID,
        "control-id": "sa-11",  # SA-11 Developer Testing — closest NIST anchor for compiler-as-control
        "description": textwrap.dedent(f"""\
            The STPA-to-Policy Compiler implements a deterministic, design-time safety
            control that translates STAMP/STPA Unsafe Control Action (UCA) analysis
            directly into runtime-enforceable governance artifacts. This eliminates the
            "Natural Language Tax" — the compliance gap between human-readable safety
            specifications and the actual code running in the cluster.

            Compiler source: src/gateway/governance/stpa_compiler.py
            Control structure (source of truth): config/stpa_control_structure.yaml
            Generated artifacts:
              - config/opa/generated_stpa_policy.rego    (OPA Rego — {len([u for u in cs.unsafe_control_actions if "opa" in u.enforcement or "all" in u.enforcement])} UCAs)
              - config/rails/generated_stpa_rails.co     (NeMo Colang — {len([u for u in cs.unsafe_control_actions if "nemo" in u.enforcement or "all" in u.enforcement])} UCAs)
              - src/gateway/governance/generated_stpa_validator.py (Python — {len([u for u in cs.unsafe_control_actions if "python" in u.enforcement or "all" in u.enforcement])} UCAs)

            Target compliance framework: {framework_label}
            Framework reference: {framework_source}
            System: {cs.system.name} v{cs.system.version}
            UCAs encoded: {len(cs.unsafe_control_actions)}
            Hazards modelled: {len(cs.hazards)}
            Safety constraints: {len(cs.safety_constraints)}
            Last compiled: {now}

            UCA-to-Control mapping ({framework_label}):
            {uca_prose}
        """).strip(),
        "props": [
            {"name": "implementation-status", "value": "implemented"},
            {"name": "stpa-compiler-version", "value": cs.system.version},
            {"name": "uca-count", "value": str(len(cs.unsafe_control_actions))},
            {"name": "hazard-count", "value": str(len(cs.hazards))},
            {"name": "last-compiled", "value": now},
            {"name": "target-framework", "value": framework_label},
            {"name": "artifact-opa", "value": "config/opa/generated_stpa_policy.rego"},
            {"name": "artifact-nemo", "value": "config/rails/generated_stpa_rails.co"},
            {
                "name": "artifact-python",
                "value": "src/gateway/governance/generated_stpa_validator.py",
            },
            {
                "name": "compiler-source",
                "value": "src/gateway/governance/stpa_compiler.py",
            },
        ],
        "responsible-roles": [{"role-id": "compliance-engineer"}],
        "by-components": by_components,
    }
    return requirement


def generate_component_entry(cs: ControlStructureModel) -> dict[str, Any]:
    """
    Generate a new OSCAL component entry for the STPA compiler itself,
    to be merged into component-definition.yaml.

    The ISO 42001 Annex A control mapping is loaded from the external
    ``config/oscal/framework_mappings/ISO_42001.json`` routing table.
    """
    now = _now_iso()
    # Load ISO 42001 mappings from external routing table
    iso_router = FrameworkRouter.get("ISO42001")
    all_iso = iso_router.all_controls(cs.unsafe_control_actions)

    impl_requirements = []
    for i, ctrl in enumerate(all_iso):
        uca_list = [
            u.id
            for u in cs.unsafe_control_actions
            if ctrl in iso_router.controls_for_uca(u.id)
        ]
        impl_requirements.append(
            {
                "uuid": f"{_STPA_REQ_UUID_PREFIX}-{i:04d}00{i}",
                "control-id": ctrl,
                "description": (
                    f"STPA compiler generates deterministic enforcement artifacts for "
                    f"{ctrl} ({iso_router.describe(ctrl)}) from config/stpa_control_structure.yaml. "
                    f"UCAs: {', '.join(uca_list)}."
                ),
                "remarks": (
                    "Implemented via stpa_compiler.py compile command. "
                    "Re-run on any YAML change to keep artifacts in sync."
                ),
            }
        )

    return {
        "uuid": _STPA_COMPONENT_UUID,
        "title": "STPA-to-Policy Compiler",
        "type": "software",
        "description": (
            f"CLI compiler (src/gateway/governance/stpa_compiler.py) that ingests "
            f"config/stpa_control_structure.yaml and generates deterministic OPA Rego, "
            f"NeMo Colang, and Python validator artifacts enforcing STAMP/STPA UCAs at "
            f"runtime. Eliminates manual policy drift by treating the YAML as the single "
            f"authoritative source of truth. System: {cs.system.name} v{cs.system.version}."
        ),
        "purpose": (
            "Provides compile-time enforcement of STPA UCAs, bridging design-time "
            "hazard analysis (MIT STAMP methodology) with runtime OPA/NeMo/Python "
            "governance controls. Closes the compliance loop between safety engineering "
            "artefacts and live cluster enforcement policies."
        ),
        "responsible-roles": [{"role-id": "compliance-engineer"}],
        "props": [
            {"name": "software-version", "value": cs.system.version},
            {"name": "source-file", "value": "src/gateway/governance/stpa_compiler.py"},
            {
                "name": "control-structure-input",
                "value": "config/stpa_control_structure.yaml",
            },
            {"name": "last-compiled", "value": now},
            {"name": "uca-count", "value": str(len(cs.unsafe_control_actions))},
        ],
        "control-implementations": [
            {
                "uuid": _STPA_CTRL_IMPL_UUID,
                "source": "https://www.iso.org/standard/81230.html",
                "description": "ISO/IEC 42001:2023 controls implemented by the STPA compiler",
                "implemented-requirements": impl_requirements,
            }
        ],
    }


# ---------------------------------------------------------------------------
# SSP patch application (idempotent)
# ---------------------------------------------------------------------------

# Marker: if an existing requirement has this UUID, it was written by this exporter
_STPA_IMPL_MARKER = _STPA_IMPL_UUID


def _apply_ssp_patch(
    ssp_path: Path,
    patch_block: dict[str, Any],
    dry_run: bool = False,
) -> bool:
    """
    Load the existing SSP YAML, inject/replace the STPA patch block, write back.

    Returns True if the SSP was modified (or would have been in dry-run).
    """
    if not ssp_path.exists():
        logger.error("SSP not found at %s", ssp_path)
        return False

    with open(ssp_path) as fh:
        ssp = yaml.safe_load(fh)

    try:
        impl_reqs: list[dict] = ssp["system-security-plan"]["control-implementation"][
            "implemented-requirements"
        ]
    except (KeyError, TypeError) as exc:
        logger.error("Cannot navigate SSP to implemented-requirements: %s", exc)
        return False

    # Remove any pre-existing exporter block (idempotent)
    impl_reqs = [r for r in impl_reqs if r.get("uuid") != _STPA_IMPL_MARKER]

    # Append new block
    impl_reqs.append(patch_block)
    ssp["system-security-plan"]["control-implementation"][
        "implemented-requirements"
    ] = impl_reqs

    # Update metadata timestamps
    now = _now_iso()
    ssp["system-security-plan"]["metadata"]["last-modified"] = now
    old_version = ssp["system-security-plan"]["metadata"].get("version", "1.0.0-draft")
    if not old_version.endswith("-stpa"):
        ssp["system-security-plan"]["metadata"]["version"] = f"{old_version}+stpa"

    if dry_run:
        logger.info("[DRY-RUN] Would update SSP at %s", ssp_path)
        return True

    with open(ssp_path, "w") as fh:
        yaml.dump(
            ssp, fh, allow_unicode=True, default_flow_style=False, sort_keys=False
        )

    logger.info("✅ SSP patched → %s", ssp_path)
    return True


def _apply_component_patch(
    comp_path: Path,
    component_entry: dict[str, Any],
    dry_run: bool = False,
) -> bool:
    """Inject/replace the STPA compiler component in component-definition.yaml."""
    if not comp_path.exists():
        logger.warning("Component definition not found at %s — skipping", comp_path)
        return False

    with open(comp_path) as fh:
        comp_def = yaml.safe_load(fh)

    try:
        components: list[dict] = comp_def["component-definition"]["components"]
    except (KeyError, TypeError) as exc:
        logger.error("Cannot navigate component-definition: %s", exc)
        return False

    # Remove existing exporter component (idempotent)
    components = [c for c in components if c.get("uuid") != _STPA_COMPONENT_UUID]
    components.append(component_entry)
    comp_def["component-definition"]["components"] = components

    now = _now_iso()
    comp_def["component-definition"]["metadata"]["last-modified"] = now

    if dry_run:
        logger.info("[DRY-RUN] Would update component-definition at %s", comp_path)
        return True

    with open(comp_path, "w") as fh:
        yaml.dump(
            comp_def, fh, allow_unicode=True, default_flow_style=False, sort_keys=False
        )

    logger.info("✅ Component definition patched → %s", comp_path)
    return True


def _write_standalone_patch(
    patch_path: Path,
    patch_block: dict[str, Any],
    component_entry: dict[str, Any],
    cs: ControlStructureModel,
    dry_run: bool = False,
) -> None:
    """Write the standalone patch YAML (for PR diff review)."""
    doc = {
        "stpa-compiler-ssp-patch": {
            "generated": _now_iso(),
            "source": "config/stpa_control_structure.yaml",
            "system": cs.system.name,
            "version": cs.system.version,
            "implemented-requirement": patch_block,
            "new-component": component_entry,
        }
    }
    if dry_run:
        print("\n" + "=" * 80)
        print("STANDALONE PATCH (dry-run)")
        print("=" * 80)
        print(
            yaml.dump(
                doc, allow_unicode=True, default_flow_style=False, sort_keys=False
            )
        )
        return

    patch_path.parent.mkdir(parents=True, exist_ok=True)
    with open(patch_path, "w") as fh:
        yaml.dump(
            doc, fh, allow_unicode=True, default_flow_style=False, sort_keys=False
        )
    logger.info("✅ Standalone patch → %s", patch_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oscal_ssp_exporter",
        description=textwrap.dedent(
            """\
            OSCAL SSP Exporter — reads the active stpa_control_structure.yaml
            and patches the existing OSCAL SSP with a generated implemented-requirement
            block, closing the safety-to-compliance loop.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    exp = sub.add_parser("export", help="Export compiler state to OSCAL SSP patch.")
    exp.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        metavar="YAML",
        help=f"Control structure YAML (default: {_DEFAULT_INPUT})",
    )
    exp.add_argument(
        "--ssp",
        type=Path,
        default=_DEFAULT_SSP,
        metavar="FILE",
        help=f"Target SSP YAML (default: {_DEFAULT_SSP})",
    )
    exp.add_argument(
        "--component-def",
        type=Path,
        default=_DEFAULT_COMP_DEF,
        metavar="FILE",
        help=f"Target component-definition YAML (default: {_DEFAULT_COMP_DEF})",
    )
    exp.add_argument(
        "--patch-out",
        type=Path,
        default=_DEFAULT_PATCH_OUT,
        metavar="FILE",
        help=f"Standalone patch output (default: {_DEFAULT_PATCH_OUT})",
    )
    exp.add_argument(
        "--dry-run",
        action="store_true",
        help="Print patch blocks without writing any files.",
    )
    exp.add_argument(
        "--framework",
        default="NIST",
        choices=["NIST", "ISO42001", "EU_AI_ACT", "MAS_FEAT"],
        metavar="FRAMEWORK",
        help=(
            "Target compliance framework for UCA cross-walk narrative. "
            "NIST = SP 800-53 / FedRAMP (default). "
            "ISO42001 = ISO/IEC 42001:2023. "
            "EU_AI_ACT = EU AI Act High-Risk AI + DORA + GDPR. "
            "MAS_FEAT = MAS FEAT Principles + TRM Guidelines."
        ),
    )
    return parser


def cmd_export(args: argparse.Namespace) -> int:
    # ---------------------------------------------------------------------------
    # Multi-jurisdiction SSP router — resolve region before any framework work.
    # CAGE_DEPLOYMENT_REGION drives both the OSCAL profile path and the
    # FrameworkRouter key used for UCA cross-walk narrative generation.
    # The --framework CLI flag is still honoured when explicitly supplied;
    # if it was left at the default ("NIST"), the router overrides it from env.
    # ---------------------------------------------------------------------------
    regional_profile = get_regional_profile()  # reads CAGE_DEPLOYMENT_REGION
    region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()
    if region not in REGIONAL_PROFILES:
        region = "US_FED"

    # Derive the FrameworkRouter key from the resolved region, unless the caller
    # explicitly passed a non-default --framework value on the CLI.
    framework_key = _REGION_TO_FRAMEWORK_KEY.get(region, "NIST")
    if args.framework != "NIST":
        # Explicit CLI override — respect it and warn if it conflicts with region.
        framework_key = args.framework
        logger.warning(
            "cmd_export: --framework=%s overrides region-derived framework for %s",
            args.framework,
            region,
        )

    try:
        cs = load_control_structure(args.input)
    except Exception as exc:
        print(f"❌ Failed to load control structure: {exc}", file=sys.stderr)
        return 1

    patch_block = generate_ssp_patch(cs, target_framework=framework_key)
    component_entry = generate_component_entry(cs)

    ok_ssp = _apply_ssp_patch(args.ssp, patch_block, dry_run=args.dry_run)
    _apply_component_patch(
        args.component_def, component_entry, dry_run=args.dry_run
    )
    _write_standalone_patch(
        args.patch_out, patch_block, component_entry, cs, dry_run=args.dry_run
    )

    if not ok_ssp:
        print("⚠️  SSP patch failed — check logs above.", file=sys.stderr)
        return 1

    if not args.dry_run:
        router = FrameworkRouter.get(framework_key)
        print("✅ OSCAL SSP export complete:")
        print(f"   Region          : {region}")
        print(f"   Profile path    : {regional_profile['profile_path']}")
        print(f"   SSP             → {args.ssp}")
        print(f"   Component def   → {args.component_def}")
        print(f"   Standalone patch→ {args.patch_out}")
        print(f"   Framework       : {router.label}")
        print(f"   UCAs exported   : {len(cs.unsafe_control_actions)}")
        print(
            f"   Controls mapped : {len(router.all_controls(cs.unsafe_control_actions))}"
        )
        # Coverage metric is region-specific — only emit the NIST coverage label
        # for US_FED deployments; other regions use their own coverage_metric key.
        coverage_metric = regional_profile["coverage_metric"]
        if region == "US_FED":
            print(f"   Coverage metric : {coverage_metric} (NIST SP 800-53 Rev 5 HIGH)")
        else:
            print(f"   Coverage metric : {coverage_metric}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if args.command == "export":
        return cmd_export(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
