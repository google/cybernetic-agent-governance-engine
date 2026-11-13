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

Reads the active ``config/stpa/`` and domain STPA YAML sources
and surgically patches the existing OSCAL artifacts to reflect the runtime
state of the STPA compiler and live ``assemble_governor()`` server inputs,
closing the compliance loop.

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
5. Applies the output's narrative source (``config/oscal/narratives/<output
   stem>.json``): restated hand-authored blocks, matched by UUID, and the
   domain-specific statement prose of generated components. A block named
   there is owned by the exporter; edit the JSON, never the YAML (F-82).

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
  overwrites only the generated blocks and the blocks its narrative source
  names, never other hand-authored content.
* **Fail-closed on schema errors**: if the SSP fails to load or the
  generated block fails Pydantic validation, the exporter aborts without
  writing any files.

Usage::

    python -m src.gateway.governance.oscal_ssp_exporter export

    # Dry-run: print patch block without writing files
    python -m src.gateway.governance.oscal_ssp_exporter export --dry-run

    # Point at a non-default control structure
    python -m src.gateway.governance.oscal_ssp_exporter export \\
        --input config/stpa/core_system.yaml

Exit codes:
    0  Patch applied (or dry-run OK).
    1  Fatal error.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from src.gateway.governance.stpa_compiler import (
    ControlStructureModel,
    UCAModel,
    load_control_structure,
    load_control_structures,
)

logger = logging.getLogger("oscal_ssp_exporter")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_INPUT_DIR = _REPO_ROOT / "config" / "stpa"
_DEFAULT_SSP = _REPO_ROOT / "compliance" / "oscal" / "system-security-plan.yaml"
_DEFAULT_EU_SSP = (
    _REPO_ROOT / "compliance" / "oscal" / "system-security-plan-eu-ecb.yaml"
)
_DEFAULT_APAC_SSP = (
    _REPO_ROOT / "compliance" / "oscal" / "system-security-plan-apac-mas.yaml"
)
_DEFAULT_COMP_DEF = _REPO_ROOT / "compliance" / "oscal" / "component-definition.yaml"
_DEFAULT_PATCH_OUT = (
    _REPO_ROOT / "compliance" / "oscal" / "stpa_compiler_ssp_patch.yaml"
)

# Volatile generation timestamps masked when comparing OSCAL / STPA outputs
# across runs (`--check` and `scripts/check_stpa_freshness.py`, POAM-2026-176).
_VOLATILE_STAMP_RE = re.compile(
    r"(Generated:\s*"
    r'|"(?:generated_at|issued_at|expires_at)":\s*"'
    r"|(?:last-modified|generated):\s*\'?"
    r"|- name: last-compiled\n\s+value:\s*\'?"
    r"|Last(?:\\\n\s*\\)?\s+compiled:(?:\\\n\s*\\)?\s*)"
    r"\d{4}-\d{2}-\d{2}T[^\s\"\'\\]*"
)


def mask_volatile_stamps(text: str) -> str:
    """Replace volatile wall-clock generation timestamps in *text* with ``<ts>``."""
    return _VOLATILE_STAMP_RE.sub(r"\1<ts>", text)


# Stable UUIDs for the STPA compiler artifacts — deterministic so the SSP diff
# is minimal across re-runs (no UUID churn).
_STPA_COMPONENT_UUID = "e5000099-stpa-4000-8000-compiler00001"
_STPA_IMPL_UUID = "g7000099-stpa-4000-8000-compiler00001"
_STPA_BY_COMP_UUID = "h8000099-stpa-4000-8000-compiler00001"
_STPA_CTRL_IMPL_UUID = "c3000099-stpa-4000-8000-compiler00001"
_STPA_REQ_UUID_PREFIX = "d4000099-stpa-4000-8000"

# Stable UUIDs for the FTRA Irreversibility Classifier component — deterministic so the
# SSP diff is minimal across re-runs (no UUID churn).
_FTRA_COMPONENT_UUID = "ftra0001-4e47-bbc8-irreversibility01"
_FTRA_CTRL_IMPL_UUID = "ftra0001-ctrl-impl-8000-classifier01"
_FTRA_SI10_IMPL_UUID = "si100001-ftra-8000-classifier00001"

#: SI-10 statement for the FTRA component. FTRA validates no parameter values
#: (docs/governance/FTRA_SCOPE.md); it names where value validation lives.
#: This is seed text: the kernel may name no domain path (Gate G3), so it names
#: the domain's rules generically. The narrative source for
#: component-definition.yaml supplies the domain-specific statement
#: (_NARRATIVE_PROSE_SLOTS); the seed is used only when it supplies none.
_FTRA_SI10_DESCRIPTION = (
    "FTRA (Tier 0.5) classifies each tool call against the digest-covered terminal "
    "registry (src/gateway/governance/ftra/classifier.py) and routes irreversible or "
    "unregistered actions to human review; a registered terminal clears autonomously "
    "only inside its autonomous envelope with a known, finite, positive magnitude "
    "(src/gateway/governance/ftra/autonomy.py). Parameter value validation (SI-10) "
    "is delegated to the domain STPA UCA rules, whose security-critical inputs are "
    "bound server-side by domain ServerInputResolvers, and to the domain OPA policy "
    "running as a read-only Unix-domain-socket sidecar inside the gateway pod. UCA-7 "
    "is enforced on the Python STPA path (_check_core_uca_7 in "
    "src/gateway/governance/stpa_validator.py), which denies a prompt_injection_check "
    "whose semantic_score, bound server-side by deterministic prompt-injection "
    "inspection (src/gateway/governance/governor/server_inputs.py), exceeds the UCA's "
    "threshold. The deterministic Stage 1 keyword scan (ac_keyword_scan in "
    "src/gateway/governance/text_filter.py) screens requests routed through the "
    "gateway inference proxy (src/gateway/server/inference_proxy.py), which Terraform "
    "configures as the sole model endpoint reachable by in-cluster agent pods (live "
    "cluster verification pending, POAM-2026-191), and runs in the agent-side "
    "LangGraph input rail. The optional NeMo Colang rails add LLM-backed screening "
    "only when CAGE_NEMO_ENABLED=true on a semantic model backend. Before parking a "
    "REQUIRE_APPROVAL token for human review, run_pipeline() previews every claiming "
    "phase-2 barrier side-effect-free (Phase2Mode.PREVIEW in "
    "src/gateway/governance/governor/pipeline.py), denying outright on HARD barrier "
    "breaches and recording NARROWABLE barrier bounds (Violation.bound in "
    "src/gateway/governance/contracts.py) on the DeferToken snapshot. "
    "The registry's manifest_sha256 (registry_digest in "
    "src/gateway/governance/ftra/classifier.py) covers the autonomous_envelope together "
    "with the terminals, so an in-file edit to a ceiling fails the load-time integrity "
    "check; a re-hashed edit is refused only when the out-of-band "
    "FTRA_EXPECTED_MANIFEST_SHA256 pin is set."
)

# ---------------------------------------------------------------------------
# Multi-jurisdiction SSP router — see docs/compliance/cross-region/GOVERNANCE_CROSSWALK.md
# ---------------------------------------------------------------------------

# Maps CAGE_DEPLOYMENT_REGION values to OSCAL profile paths and framework metadata.
# Each entry drives both the profile import-href in the SSP and the FrameworkRouter
# selection for UCA cross-walk narrative generation.
REGIONAL_PROFILES: dict[str, dict] = {
    "US_FED": {
        "profile_path": "compliance/oscal/sp800053-profile.yaml",
        "ssp_path": "compliance/oscal/system-security-plan.yaml",
        "framework": "NIST SP 800-53 Rev 5 HIGH",
        "framework_id": "nist-sp800-53-rev5-high",
        "coverage_metric": "nist_sp800_53_coverage_pct",
    },
    "EU_ECB": {
        "profile_path": "compliance/oscal/eu-ai-act-profile.yaml",
        "ssp_path": "compliance/oscal/system-security-plan-eu-ecb.yaml",
        "framework": "EU AI Act (Reg 2024/1689) + GDPR",
        "framework_id": "eu-ai-act-2024",
        "coverage_metric": "eu_ai_act_coverage_pct",
    },
    "APAC_MAS": {
        "profile_path": "compliance/oscal/mas-feat-profile.yaml",
        "ssp_path": "compliance/oscal/system-security-plan-apac-mas.yaml",
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


def _detect_deployment_platform() -> str:
    """Detect the current deployment platform via environment variables.

    Returns:
        Platform identifier: one of ``gcp-gke``, ``aws-ecs``,
        ``azure-containerapp``, or ``agnostic`` (local/unknown).
    """
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        return "gcp-gke"
    if os.getenv("ECS_CONTAINER_METADATA_URI_V4"):
        return "aws-ecs"
    if os.getenv("IDENTITY_ENDPOINT") and os.getenv("IDENTITY_HEADER"):
        return "azure-containerapp"
    return "agnostic"


# ---------------------------------------------------------------------------
# Platform-aware OSCAL SSP Control Narratives (Phase E)
# ---------------------------------------------------------------------------

# Stable UUIDs for platform control narratives
_PLATFORM_SC7_IMPL_UUID = "p7000001-plat-sc7-8000-platform0001"
_PLATFORM_SC8_IMPL_UUID = "p8000001-plat-sc8-8000-platform0001"
_PLATFORM_SC39_IMPL_UUID = "p9000001-plat-sc39-8000-platform001"
_PLATFORM_SI3_IMPL_UUID = "s3000001-plat-si3-8000-platform0001"

TIER3_COMMERCIAL_LEDGER_CUSTOMER_RESPONSIBILITY = (
    "Customer Responsibility (Tier-3 Commercial Deployment Interface — Retail-Banking, "
    "Custody & Payment Ledger APIs): CAGE ships the Tier-2 posture-completing simulated "
    "ground-truth reconciliation provider (SimulatedEstateProvider) with deterministic "
    "seeding, fault injection, and real Cloud KMS asymmetric snapshot signing "
    "(RECONCILER_KMS_KEY). Commercial retail-banking, custody, and core-banking ledger "
    "APIs are classified as Tier-3 commercial-deployment-only interfaces and do not "
    "live in the reference repository; organizations deploying CAGE in commercial "
    "production are responsible for supplying and accrediting their own external "
    "retail-banking ledger integration behind the EstateProvider seam."
)

PLATFORM_CONTROL_NARRATIVES: dict[str, dict[str, dict[str, str]]] = {
    "gcp-gke": {
        "sc-7": {
            "uuid": _PLATFORM_SC7_IMPL_UUID,
            "control-id": "sc-7",
            "title": "Boundary Protection — GKE Dataplane V2 Per-Workload Segmentation & Default-Deny Ingress/Egress (FQDN L7 Filtering & Live Verification Pending)",
            "status": "partial",
            "narrative": (
                "Ingress and external egress in the governance-stack namespace are default-deny "
                "on GKE Dataplane V2 (Cilium/eBPF) through Kubernetes NetworkPolicy "
                "(networking.k8s.io/v1), GKE FQDNNetworkPolicy (networking.gke.io/v1alpha1) and "
                "Dataplane V2 NetworkLogging resources reconciled by Terraform in "
                "infra/targets/gcp-gke/network_policy.tf and "
                "infra/targets/gcp-gke/dataplane_v2_logging.tf. default_deny_ingress and "
                "default_deny_external_egress block unpermitted pod-to-pod and external flows, "
                "per-workload policies scope Cloud SQL and Memorystore for Valkey /32 PSC "
                "endpoints strictly to their declared consumers (excluding the governed advisor "
                "from Valkey, POAM-2026-190, POAM-2026-195), and model_backend_ingress admits "
                "TCP 8000 solely from app=gateway while routing in-cluster advisor completions "
                "through the gateway /v1/chat/completions proxy (POAM-2026-191). External HTTPS "
                "egress exists only where a workload FQDNNetworkPolicy allows it (the gateway, "
                "compliance-bridge, reconciliation-worker, vLLM, ClickHouse tiering and "
                "telemetry-stack allowlists); the governed financial advisor has none. Open gaps "
                "keep this control partial: FQDNNetworkPolicy enforces at L3/L4 on DNS-resolved "
                "IPs without L7 HTTP-method filtering and the gateway allowlist's "
                "*.googleapis.com entry also matches Google's model API (POAM-2026-152), and "
                "live deployed-cluster drop/allow corroboration for POAM-2026-190, POAM-2026-191 "
                "and POAM-2026-195 remains pending Gate W."
            ),
            "evidence": (
                "infra/targets/gcp-gke/network_policy.tf, "
                "infra/targets/gcp-gke/tests/namespace_segmentation.tftest.hcl, "
                "tests/infrastructure/test_gateway_egress_allowlist.py"
            ),
            "poam_refs": (
                "POAM-2026-152 (SC-7), POAM-2026-190 (SC-7), POAM-2026-191 (SC-7), "
                "POAM-2026-195 (SC-7/AC-4)"
            ),
        },
        "sc-8": {
            "uuid": _PLATFORM_SC8_IMPL_UUID,
            "control-id": "sc-8",
            "title": "Transmission Confidentiality and Integrity — Linkerd mTLS, OPA UDS Sidecar & Managed Data-Plane TLS (App Cache TLS, TLS 1.3 Floor & Live Verification Pending)",
            "status": "partial",
            "narrative": (
                "Pods in the governance-stack namespace are meshed by Linkerd "
                "(linkerd.io/inject=enabled) with defaultInboundPolicy=all-authenticated via "
                "infra/modules/service_mesh, and a ValidatingAdmissionPolicy "
                "(charts/mesh-proxy-required) refuses any pod created there without the "
                "Linkerd proxy, including while the fail-open proxy injector is down (live "
                "verification pending, POAM-2026-167). Pod-to-pod traffic is mutual TLS using "
                "24-hour in-memory workload certificates signed through a 48-hour Google "
                "Certificate Authority Service intermediate CSR flow, while OPA runs inside the "
                "gateway pod over a non-networked Unix domain socket "
                "(infra/modules/gateway/main.tf). Per-route Linkerd Server, HTTPRoute and "
                "AuthorizationPolicy resources in "
                "infra/modules/gateway/mesh-policy/templates/policy.yaml, "
                "infra/modules/compliance_bridge/mesh-policy/templates/policy.yaml and "
                "infra/targets/gcp-gke/charts/workload-mesh-policy/templates/servers-and-authz.yaml "
                "restrict L7 HTTP and ClickHouse TCP 9000 callers by ServiceAccount identity, "
                "backed by src/gateway/server/workload_identity.py on the gateway. Governance "
                "Memorystore for Valkey enforces transit_encryption_mode=SERVER_AUTHENTICATION "
                "over Private Service Connect with REDIS_CA_CERT_PATH "
                "(infra/modules/memorystore_valkey/main.tf, "
                "src/gateway/infrastructure/redis_client.py; POAM-2026-086), and Cloud SQL "
                "PostgreSQL enforces ssl_mode=ENCRYPTED_ONLY "
                "(infra/modules/cloudsql_postgres/main.tf). Open gaps keep this control "
                "partial: the application Memorystore instance (memorystore_app in "
                "infra/targets/gcp-gke/main.tf) runs with transit encryption and authentication "
                "disabled; live deployed-cluster verification of mesh mTLS and L7 authorization "
                "remains pending (POAM-2026-080, POAM-2026-195); and outbound Python HTTP "
                "clients use default SSL contexts with a TLS 1.2 floor because "
                "create_hardened_client_context in src/gateway/infrastructure/tls_context.py "
                "has no production call site (POAM-2026-011)."
            ),
            "evidence": (
                "infra/modules/service_mesh/main.tf, infra/modules/gateway/mesh-policy/templates/policy.yaml, "
                "infra/modules/compliance_bridge/mesh-policy/templates/policy.yaml, "
                "infra/targets/gcp-gke/charts/workload-mesh-policy/templates/servers-and-authz.yaml, "
                "infra/modules/memorystore_valkey/main.tf, infra/modules/cloudsql_postgres/main.tf, "
                "tests/integration/test_linkerd_mesh_conformance.py, "
                "tests/infrastructure/test_mesh_proxy_required_policy.py, "
                "tests/test_redis_async_builder.py"
            ),
            "poam_refs": (
                "POAM-011 (SC-8), POAM-2026-011 (SC-8), POAM-2026-080 (IA-9/SC-8), "
                "POAM-2026-086 (SC-8), POAM-2026-167 (IA-9/SC-8), POAM-2026-195 (SC-8)"
            ),
        },
        "sc-39": {
            "uuid": _PLATFORM_SC39_IMPL_UUID,
            "control-id": "sc-39",
            "title": "Process Isolation — Pod Security Standards, Hardened Container Contexts & Tainted Node Pools (GKE Sandbox Not Enabled)",
            "status": "partial",
            "narrative": (
                "Process isolation on the gcp-gke target rests on Kubernetes controls declared "
                "in Terraform. Pod Security Admission labels enforce the restricted profile on "
                "governance-stack when enable_pod_security_standards is true "
                "(infra/modules/k8s_namespace/main.tf; set in the staging, prod, eu-prod and "
                "apac-prod tfvars and off in the dev profiles), and every Terraform workload "
                "module sets run_as_non_root, allow_privilege_escalation = false, drops ALL "
                "capabilities and uses the RuntimeDefault seccomp profile (for example "
                "infra/modules/gateway/main.tf, infra/modules/compliance_bridge/main.tf and "
                "infra/modules/governed_advisor/main.tf, which runs the governed advisor "
                "in-cluster as a Kubernetes Deployment). Hardware-bound workloads are isolated "
                "on dedicated tainted node pools in infra/modules/gcp_gke_cluster/main.tf: vLLM "
                "on g2-standard-8 NVIDIA L4 nodes (nvidia.com/gpu=present:NoSchedule) and "
                "ClickHouse on local-SSD nodes (workload=clickhouse:NoSchedule). Open gap "
                "keeping this control partial: GKE Sandbox (gVisor) is not enabled. "
                "enable_gvisor_sandbox sets only the COS_CONTAINERD image type and a node "
                "label, the node_config.sandbox_config block that provides the gvisor "
                "RuntimeClass is not configured (it needs the google-beta provider), and no "
                "Terraform workload sets runtimeClassName, so containers share the node kernel."
            ),
            "evidence": (
                "infra/modules/k8s_namespace/main.tf, infra/modules/gateway/main.tf, "
                "infra/modules/compliance_bridge/main.tf, infra/modules/governed_advisor/main.tf, "
                "infra/modules/gcp_gke_cluster/main.tf, "
                "tests/infrastructure/test_gke_sole_target_6f.py"
            ),
            "poam_refs": "",
        },
        "si-3": {
            "uuid": _PLATFORM_SI3_IMPL_UUID,
            "control-id": "si-3",
            "title": "Malicious Code Protection — Digest Pinning & Binary Authorization Attestation (Read-Only Root Filesystem & CVE Admission Gate Pending)",
            "status": "partial",
            "narrative": (
                "Container supply-chain integrity on the gcp-gke target is enforced at plan and "
                "admission time. var.image_digests in infra/targets/gcp-gke/variables.tf "
                "rejects tag-only, :latest and empty-digest image references (exercised by "
                "infra/targets/gcp-gke/tests/image_digests.tftest.hcl). The Binary "
                "Authorization policy in infra/targets/gcp-gke/perimeter.tf requires an "
                "attestation from google_binary_authorization_attestor.build_attestor, whose "
                "signing key is the Cloud KMS asymmetric key "
                "google_kms_crypto_key.binauthz_attestor "
                "(infra/targets/gcp-gke/kms_signing.tf), with evaluation_mode "
                "REQUIRE_ATTESTATION and enforcement_mode ENFORCED_BLOCK_AND_AUDIT_LOG; images "
                "are attested by the build helpers (deployment/docker/cloudbuild.image.yaml, "
                "scripts/build_images.sh, scripts/mirror_and_attest_images.sh, "
                "scripts/attest_image.sh). CI runs pip-audit and a Trivy filesystem scan "
                "(CRITICAL,HIGH) over the repository (.github/workflows/security-scan.yml). "
                "Open gaps keep this control partial: attestation does not depend on a "
                "vulnerability-scan result, so admission does not block images with "
                "CRITICAL/HIGH CVEs; read_only_root_filesystem = true is set only by the "
                "gateway OPA sidecar, the non-production inference stub, the reconciliation "
                "worker and the Lula audit CronJob (infra/modules/gateway/main.tf, "
                "infra/modules/inference_stub/main.tf, "
                "infra/modules/reconciliation_worker/main.tf, infra/modules/lula_cron/main.tf), "
                "while the main gateway container, compliance-bridge, governed advisor and the "
                "remaining workload modules leave the root filesystem writable; and admission "
                "enforcement on a deployed cluster is unverified (POAM-2026-083)."
            ),
            "evidence": (
                "infra/targets/gcp-gke/perimeter.tf, infra/targets/gcp-gke/kms_signing.tf, "
                "infra/targets/gcp-gke/variables.tf, "
                "infra/targets/gcp-gke/tests/image_digests.tftest.hcl"
            ),
            "poam_refs": "POAM-2026-083 (SI-3/SI-7)",
        },
    },
}


def generate_platform_control_narratives(
    platform: str | None = None,
) -> list[dict[str, Any]]:
    """Generate OSCAL implemented-requirement blocks for platform-aware controls.

    Args:
        platform: Explicit platform identifier (``gcp-gke``, ``agnostic``, etc.).
            If ``None``, auto-detect via :func:`_detect_deployment_platform`.

    Returns:
        List of OSCAL implemented-requirement dicts for SC-7, SC-8, SC-39, SI-3.
        Returns empty list for ``agnostic`` or unknown platforms.
    """
    if platform is None:
        platform = _detect_deployment_platform()

    logger.info("generate_platform_control_narratives: platform=%s", platform)

    if platform not in PLATFORM_CONTROL_NARRATIVES:
        logger.warning(
            "generate_platform_control_narratives: no narratives defined for platform '%s' — "
            "skipping platform-aware controls",
            platform,
        )
        return []

    narratives = PLATFORM_CONTROL_NARRATIVES[platform]
    blocks = []

    for control_id in ["sc-7", "sc-8", "sc-39", "si-3"]:
        if control_id not in narratives:
            continue
        meta = narratives[control_id]
        blocks.append(
            {
                "uuid": meta["uuid"],
                "control-id": control_id,
                "description": meta["narrative"],
                "props": [
                    {"name": "implementation-status", "value": meta["status"]},
                    {"name": "deployment-platform", "value": platform},
                    {"name": "evidence-file", "value": meta["evidence"]},
                    *(
                        [{"name": "poam-refs", "value": meta["poam_refs"]}]
                        if meta["poam_refs"]
                        else []
                    ),
                ],
                "responsible-roles": [{"role-id": "system-administrator"}],
            }
        )

    logger.info(
        "generate_platform_control_narratives: generated %d control blocks for platform=%s",
        len(blocks),
        platform,
    )
    return blocks


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

#: Generators an ``all`` enforcement entry stands for. stpa_compiler.py emits
#: OPA, NeMo and Python output for ``all``; LangGraph and sandbox output need
#: an explicit target.
_ALL_EXPANDS_TO = frozenset({"opa", "nemo", "python"})


def _enforcement_targets(ucas: list[UCAModel]) -> set[str]:
    """Return the enforcement targets *ucas* declare, with ``all`` expanded.

    Every artifact list the exporter writes derives from this set, so a
    generator no UCA targets (NeMo Colang while no UCA declares ``nemo``) is
    never named as enforcing a control.
    """
    targets: set[str] = {t for u in ucas for t in u.enforcement}
    if "all" in targets:
        targets |= _ALL_EXPANDS_TO
    return targets


_COMPOSITE_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\s*>\s*threshold_ref\([A-Za-z0-9_.]+\)\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)$"
)


def _live_registered_server_inputs() -> dict[str, frozenset[str]]:
    """Inspect live ``assemble_governor()`` across installed production plugins.

    Returns a mapping from governed action name to the ``owned_keys`` registered
    by real ``ServerInputResolver`` instances in ``assemble_governor()`` (kernel
    core resolvers plus ``maturity == "production"`` domain plugins).
    """
    import importlib.metadata

    from src.gateway.governance.env_posture import DeploymentPosture
    from src.gateway.governance.governor.assembly import (
        DecisionFlags,
        assemble_governor,
    )
    from src.gateway.governance.jurisdiction import JurisdictionContribution
    from src.gateway.governance.plugin_loader import load_domain_plugin
    from src.gateway.governance.schemas import thresholds as _thresholds_mod

    class _InspectorPolicyClient:
        async def evaluate_policy(
            self, input_data: dict[str, Any], current_latency_ms: float = 0.0
        ) -> str:
            return "DENY"

        async def verify_domain_policy(
            self, package: str, required_rules: tuple[str, ...]
        ) -> None:
            return None

        async def close(self) -> None:
            return None

    class _InspectorWarrantSource:
        @property
        def provider_name(self) -> str:
            return "oscal_inspector"

        async def fetch(self, norm_id: str) -> Any:
            return None

    jurisdiction = JurisdictionContribution(region=_thresholds_mod.THRESHOLDS.region)
    flags = DecisionFlags(defer=True, narrow=True)
    opa = _InspectorPolicyClient()
    warrant_source = _InspectorWarrantSource()

    merged: dict[str, set[str]] = {}
    base_gov = assemble_governor(
        [],
        opa=opa,
        posture=DeploymentPosture.DEV,
        jurisdiction=jurisdiction,
        flags=flags,
        warrant_source=warrant_source,
    )
    for action, resolver in base_gov.components.server_inputs.items():
        merged.setdefault(action, set()).update(resolver.owned_keys)

    eps = sorted(
        importlib.metadata.entry_points(group="cage.plugins"),
        key=lambda ep: ep.name,
    )
    for ep in eps:
        plugin = load_domain_plugin(ep.name)
        if getattr(plugin, "maturity", "production") != "production":
            continue
        gov = assemble_governor(
            [plugin],
            opa=opa,
            posture=DeploymentPosture.DEV,
            jurisdiction=jurisdiction,
            flags=flags,
            warrant_source=warrant_source,
        )
        for action, resolver in gov.components.server_inputs.items():
            merged.setdefault(action, set()).update(resolver.owned_keys)

    return {action: frozenset(keys) for action, keys in merged.items()}


def _uca_implementation_state(
    uca: UCAModel,
    cs: ControlStructureModel,
    *,
    live_server_inputs: Mapping[str, frozenset[str]] | None = None,
) -> str:
    """Return ``'implemented'``, ``'partial'``, or ``'planned'`` for *uca*.

    * ``'partial'`` when ``uca.advisory`` is True or Python enforcement is absent.
    * ``'implemented'`` only when every ``server_bound: true`` parameter read by
      *uca* is backed by a live ``ServerInputResolver`` in ``assemble_governor()``.
    * ``'planned'`` when YAML claims non-advisory ``server_bound: true`` without
      a registered ``ServerInputResolver`` (never credited as ``implemented``).
    """
    if getattr(uca, "advisory", False):
        return "partial"
    if "python" not in _enforcement_targets([uca]):
        return "partial"
    action_spec = next(
        (a for a in cs.control_actions if a.get("name") == uca.action), None
    )
    if action_spec is None:
        return "planned"
    sb_params = {
        str(p.get("name"))
        for p in (action_spec.get("params") or [])
        if isinstance(p, dict) and p.get("server_bound") is True
    }
    if not sb_params:
        return "planned"
    decl_params = {
        str(p.get("name"))
        for p in (action_spec.get("params") or [])
        if isinstance(p, dict)
    }
    resolved_inputs = (
        _live_registered_server_inputs()
        if live_server_inputs is None
        else live_server_inputs
    )
    registered_keys = resolved_inputs.get(uca.action, frozenset())

    cond = uca.condition
    if cond.param is not None:
        if cond.param not in sb_params:
            return "planned"
        return "implemented" if cond.param in registered_keys else "planned"
    if cond.composite is not None:
        m = _COMPOSITE_RE.match(cond.composite.strip())
        if m:
            lhs, rhs = m.group(1), m.group(2)
            if rhs not in sb_params or lhs not in (sb_params | decl_params):
                return "planned"
            required_live = {rhs}
            if lhs in sb_params:
                required_live.add(lhs)
            return (
                "implemented" if required_live.issubset(registered_keys) else "planned"
            )
    return "planned"


def _verify_uca_enforced_and_server_bound(
    uca: UCAModel,
    cs: ControlStructureModel,
    *,
    live_server_inputs: Mapping[str, frozenset[str]] | None = None,
) -> bool:
    """Return True iff *uca* has ``'implemented'`` live server-bound enforcement."""
    return (
        _uca_implementation_state(uca, cs, live_server_inputs=live_server_inputs)
        == "implemented"
    )


def _rollup_state(states: list[str]) -> str:
    """Roll per-UCA states up to one OSCAL implementation state.

    ``implemented`` only when every UCA enforces; ``planned`` when none
    enforces or runs at all; ``partial`` otherwise (some UCA enforces, or an
    advisory rule runs on caller-asserted inputs).
    """
    unique = set(states)
    if unique and unique <= {"implemented"}:
        return "implemented"
    if unique & {"implemented", "partial"}:
        return "partial"
    return "planned"


def _enforcement_split_sentence(ucas: list[UCAModel], states: Mapping[str, str]) -> str:
    """Name which of *ucas* enforce server-side and which do not (by-component prose)."""
    enforcing = [u.id for u in ucas if states[u.id] == "implemented"]
    advisory = [u.id for u in ucas if states[u.id] == "partial"]
    unbound = [u.id for u in ucas if states[u.id] == "planned"]
    parts = [
        f"Server-bound enforcing UCAs: {', '.join(enforcing) or 'none'}",
        f"advisory UCAs (not server-bound): {', '.join(advisory) or 'none'}",
    ]
    if unbound:
        parts.append(
            f"server_bound inputs without a registered resolver: {', '.join(unbound)}"
        )
    return "; ".join(parts) + "."


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
        # Enforcement target (a UCA's ``enforcement`` entry) → the generated
        # artifact text a narrative cites for it. Kept in the mapping file so
        # the kernel holds no domain paths (Gate G3).
        self.enforcement_artifacts: dict[str, str] = data.get(
            "enforcement_artifacts", {}
        )
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

    def artifacts_for(self, ucas: list[UCAModel]) -> str:
        """Return the generated artifacts that enforce *ucas*, in mapping order.

        Only targets the UCAs declare are cited (:func:`_enforcement_targets`).
        """
        targets = _enforcement_targets(ucas)
        return ", ".join(
            text
            for target, text in self.enforcement_artifacts.items()
            if target in targets
        )

    def format_narrative(self, control_id: str, ucas: list[UCAModel]) -> str:
        """Build the by-component description prose for a single control."""
        mapped = [u for u in ucas if control_id in self.controls_for_uca(u.id)]
        return self.narrative_template.format(
            control_id=control_id,
            control_id_upper=control_id.upper(),
            control_description=self.describe(control_id),
            uca_list=", ".join(u.id for u in mapped),
            artifacts=self.artifacts_for(mapped) or "none",
        )

    def build_summary(
        self,
        ucas: list[UCAModel],
        cs: ControlStructureModel | None = None,
        *,
        live_server_inputs: Mapping[str, frozenset[str]] | None = None,
    ) -> str:
        """Build a full prose cross-walk of all UCAs for this framework."""
        resolved_inputs = (
            _live_registered_server_inputs()
            if (cs is not None and live_server_inputs is None)
            else live_server_inputs
        )
        lines = []
        for uca in ucas:
            controls = self.controls_for_uca(uca.id)
            ctrl_str = ", ".join(f"{c} ({self.describe(c)})" for c in controls)
            posture_tag = ""
            if cs is not None:
                state = _uca_implementation_state(
                    uca, cs, live_server_inputs=resolved_inputs
                )
                if state == "partial":
                    posture_tag = " [advisory — partial]"
                elif state == "planned":
                    posture_tag = " [unregistered server_bound — planned]"
            lines.append(
                f"  {uca.id} ({uca.uca_type}){posture_tag}: {uca.description}\n"
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
# Patch block generator
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_metadata(region: str = "US_FED") -> dict[str, Any]:
    """Build OSCAL SSP metadata with AssurancePosture injection (v3.1.5 Phase 1.2).

    Args:
        region: Deployment region (US_FED, EU_ECB, APAC_MAS, UK_DSIT).

    Returns:
        OSCAL metadata dict with assurance posture props and root assurance-posture block.
    """
    # Lazy import to avoid Layer 1 → Layer 3 boundary violation (Gate G3)
    from src.compliance_bridge.types import AssurancePosture

    posture = AssurancePosture()

    # Convert AssurancePosture to OSCAL props format
    props = [
        {
            "name": "assurance_status",
            "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
            "value": posture.status.value,
            "class": "assurance-lifecycle",
        },
        {
            "name": "attestation_boundary",
            "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
            "value": posture.attestation_boundary,
            "class": "assurance-lifecycle",
        },
        {
            "name": "disclaimer",
            "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
            "value": posture.disclaimer,
            "class": "legal-notice",
        },
        {
            "name": "customer_responsibility_tier3_ledger_apis",
            "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
            "value": TIER3_COMMERCIAL_LEDGER_CUSTOMER_RESPONSIBILITY,
            "class": "customer-responsibility",
        },
    ]

    if posture.third_party_certificate_url:
        props.append(
            {
                "name": "third_party_certificate_url",
                "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
                "value": posture.third_party_certificate_url,
                "class": "assurance-evidence",
            }
        )

    metadata = {
        "title": f"CAGE System Security Plan — {region}",
        "last-modified": _now_iso(),
        "version": "4.1.0",
        "oscal-version": "1.0.4",
        "props": props,
        "assurance-posture": posture.model_dump(mode="json"),
    }

    return metadata


def generate_ssp_patch(
    cs: ControlStructureModel,
    target_framework: str = "NIST",
    *,
    now: str | None = None,
    live_server_inputs: Mapping[str, frozenset[str]] | None = None,
) -> dict[str, Any]:
    """
    Generate the OSCAL ``implemented-requirement`` block for the STPA compiler.

    Args:
        cs: The loaded ControlStructureModel from ``config/stpa/`` and domain YAML.
        target_framework: Output framework for the UCA cross-walk narrative.
            One of ``"NIST"`` (default, FedRAMP/SP 800-53),
            ``"ISO42001"`` (global baseline),
            ``"EU_AI_ACT"`` (EU High-Risk AI / DORA / GDPR), or
            ``"MAS_FEAT"`` (Singapore FEAT Principles / TRM Guidelines).
            Framework routing tables live in config/oscal/framework_mappings/.

    Returns a dict ready to be appended to
    ``system-security-plan.implemented-requirements``.
    """
    now = now or _now_iso()

    resolved_inputs = (
        _live_registered_server_inputs()
        if live_server_inputs is None
        else live_server_inputs
    )

    # Load the external framework routing table — zero hardcoded dicts in Python.
    router = FrameworkRouter.get(target_framework)

    uca_prose = router.build_summary(
        cs.unsafe_control_actions, cs=cs, live_server_inputs=resolved_inputs
    )
    framework_label = router.label
    framework_source = router.source
    all_framework_controls = router.all_controls(cs.unsafe_control_actions)

    uca_states = {
        u.id: _uca_implementation_state(u, cs, live_server_inputs=resolved_inputs)
        for u in cs.unsafe_control_actions
    }
    enforcing_ucas = [
        u for u in cs.unsafe_control_actions if uca_states[u.id] == "implemented"
    ]
    advisory_ucas = [
        u for u in cs.unsafe_control_actions if uca_states[u.id] != "implemented"
    ]

    # Build by-components entries — one per referenced control. A control is
    # "implemented" only when every mapped UCA has live server-bound enforcement
    # (_rollup_state); each row names which of its UCAs enforce and which do not.
    by_components = []
    for i, ctrl in enumerate(all_framework_controls):
        mapped_ctrl = [
            u
            for u in cs.unsafe_control_actions
            if ctrl in router.controls_for_uca(u.id)
        ]
        ctrl_state = _rollup_state([uca_states[u.id] for u in mapped_ctrl])
        by_components.append(
            {
                "component-uuid": _STPA_COMPONENT_UUID,
                "uuid": f"{_STPA_BY_COMP_UUID[:-4]}{i:04d}",
                "description": (
                    router.format_narrative(ctrl, cs.unsafe_control_actions)
                    + " "
                    + _enforcement_split_sentence(mapped_ctrl, uca_states)
                ),
                "implementation-status": {"state": ctrl_state},
                "links": [
                    {
                        "href": "../../config/stpa/core_system.yaml",
                        "rel": "reference",
                        "text": "STPA control structure YAML (source of truth)",
                    },
                    {
                        "href": "../../src/gateway/governance/stpa_validator.py",
                        "rel": "reference",
                        "text": "STPA Python validator",
                    },
                ],
            }
        )

    def _targeting(target: str) -> int:
        return sum(
            1 for u in cs.unsafe_control_actions if target in _enforcement_targets([u])
        )

    # A generator no UCA targets is not listed as an enforcement artifact.
    nemo_ucas = _targeting("nemo")
    nemo_artifact_line = (
        "              - config/rails/generated_stpa_rails.co     "
        f"(NeMo Colang — {nemo_ucas} UCAs)\n"
        if nemo_ucas
        else ""
    )
    nemo_artifact_props = (
        [{"name": "artifact-nemo", "value": "config/rails/generated_stpa_rails.co"}]
        if nemo_ucas
        else []
    )
    overall_status = _rollup_state(list(uca_states.values()))
    sandbox_ucas = len(
        [u for u in cs.unsafe_control_actions if u.sandbox_rule is not None]
    )
    python_artifacts = router.enforcement_artifacts.get(
        "python", "src/gateway/governance/stpa_validator.py"
    )

    requirement: dict[str, Any] = {
        "uuid": _STPA_IMPL_UUID,
        "control-id": "sa-11",  # SA-11 Developer Testing — closest NIST anchor for compiler-as-control
        "description": textwrap.dedent(f"""\
            The STPA-to-Policy Compiler deterministically compiles the merged STAMP/STPA
            Unsafe Control Action (UCA) specifications into governance artifacts whose
            freshness CI checks (scripts/check_stpa_freshness.py). A UCA's Python rule
            enforces at runtime only when every input it reads is bound server-side by a
            ServerInputResolver registered in assemble_governor(); rules keyed on
            caller-asserted flags are advisory, so this control is implemented only
            when every UCA enforces.

            Compiler source: src/gateway/governance/stpa_compiler.py
            Control structure sources: config/stpa/ and each domain's src/cage_*/config/stpa/
            Generated artifacts:
{nemo_artifact_line}              - Python rules: {python_artifacts} ({_targeting("python")} UCAs: {len(enforcing_ucas)} enforcing, {len(advisory_ucas)} advisory)
              - config/sandbox/generated_sandbox_policy.yaml (sandbox metadata for {sandbox_ucas} UCAs; design-time reference, not read at runtime)

            Target compliance framework: {framework_label}
            Framework reference: {framework_source}
            System: {cs.system.name} v{cs.system.version}
            UCAs encoded: {len(cs.unsafe_control_actions)} ({len(enforcing_ucas)} enforcing server-bound, {len(advisory_ucas)} advisory)
            Hazards modelled: {len(cs.hazards)}
            Safety constraints: {len(cs.safety_constraints)}
            Last compiled: {now}

            UCA-to-Control mapping ({framework_label}):
            {uca_prose}
        """).strip(),
        "props": [
            {"name": "implementation-status", "value": overall_status},
            {"name": "stpa-compiler-version", "value": cs.system.version},
            {"name": "uca-count", "value": str(len(cs.unsafe_control_actions))},
            {"name": "enforcing-uca-count", "value": str(len(enforcing_ucas))},
            {"name": "advisory-uca-count", "value": str(len(advisory_ucas))},
            {"name": "hazard-count", "value": str(len(cs.hazards))},
            {"name": "last-compiled", "value": now},
            {"name": "target-framework", "value": framework_label},
            *nemo_artifact_props,
            {
                "name": "artifact-python",
                "value": "src/gateway/governance/stpa_validator.py",
            },
            {
                "name": "artifact-sandbox",
                "value": "config/sandbox/generated_sandbox_policy.yaml",
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


def generate_component_entry(
    cs: ControlStructureModel,
    *,
    now: str | None = None,
    live_server_inputs: Mapping[str, frozenset[str]] | None = None,
) -> dict[str, Any]:
    """
    Generate a new OSCAL component entry for the STPA compiler itself,
    to be merged into component-definition.yaml.

    The ISO 42001 Annex A control mapping is loaded from the external
    ``config/oscal/framework_mappings/ISO_42001.json`` routing table. Each
    requirement's implementation status rolls up the live per-UCA states
    (:func:`_uca_implementation_state`, :func:`_rollup_state`).
    """
    now = now or _now_iso()
    resolved_inputs = (
        _live_registered_server_inputs()
        if live_server_inputs is None
        else live_server_inputs
    )
    uca_states = {
        u.id: _uca_implementation_state(u, cs, live_server_inputs=resolved_inputs)
        for u in cs.unsafe_control_actions
    }
    # Load ISO 42001 mappings from external routing table
    iso_router = FrameworkRouter.get("ISO42001")
    all_iso = iso_router.all_controls(cs.unsafe_control_actions)

    impl_requirements = []
    for i, ctrl in enumerate(all_iso):
        mapped = [
            u
            for u in cs.unsafe_control_actions
            if ctrl in iso_router.controls_for_uca(u.id)
        ]
        impl_requirements.append(
            {
                "uuid": f"{_STPA_REQ_UUID_PREFIX}-{i:04d}00{i}",
                "control-id": ctrl,
                "description": (
                    f"STPA compiler maps {ctrl} ({iso_router.describe(ctrl)}) to "
                    f"UCAs {', '.join(u.id for u in mapped)}, compiled from config/stpa/ "
                    f"and the domain control structures. "
                    f"{_enforcement_split_sentence(mapped, uca_states)}"
                ),
                "props": [
                    {
                        "name": "implementation-status",
                        "value": _rollup_state([uca_states[u.id] for u in mapped]),
                    },
                ],
                "remarks": (
                    "Compiled by stpa_compiler.py; scripts/check_stpa_freshness.py fails "
                    "CI when a generated artifact drifts from its YAML source."
                ),
            }
        )

    # Name only the artifact kinds some UCA actually targets.
    targeted = _enforcement_targets(cs.unsafe_control_actions)
    kinds = [
        label
        for target, label in (
            ("nemo", "NeMo Colang"),
            ("python", "Python validator"),
        )
        if target in targeted
    ] or ["Python validator"]
    kinds_prose = (
        ", ".join(kinds[:-1]) + f", and {kinds[-1]}"
        if len(kinds) > 2
        else " and ".join(kinds)
    )
    runtime_prose = "/".join(k.split()[0] for k in kinds)

    return {
        "uuid": _STPA_COMPONENT_UUID,
        "title": "STPA-to-Policy Compiler",
        "type": "software",
        "description": (
            f"CLI compiler (src/gateway/governance/stpa_compiler.py) that compiles "
            f"config/stpa/ and the domain control structures into deterministic "
            f"{kinds_prose} artifacts mapped to STAMP/STPA UCAs. A UCA's Python rule "
            f"enforces at runtime only when every input it reads is bound server-side; "
            f"rules keyed on caller-asserted flags are advisory. "
            f"System: {cs.system.name} v{cs.system.version}."
        ),
        "purpose": (
            "Provides deterministic compile-time translation of STPA UCAs, bridging "
            "design-time hazard analysis (MIT STAMP methodology) with runtime "
            f"{runtime_prose} governance controls wherever a rule's inputs are bound "
            "server-side; CI checks the generated artifacts for drift from the YAML."
        ),
        "responsible-roles": [{"role-id": "compliance-engineer"}],
        "props": [
            {"name": "software-version", "value": cs.system.version},
            {"name": "source-file", "value": "src/gateway/governance/stpa_compiler.py"},
            {
                "name": "control-structure-input",
                "value": "config/stpa/",
            },
            {"name": "last-compiled", "value": now},
            {"name": "uca-count", "value": str(len(cs.unsafe_control_actions))},
        ],
        "control-implementations": [
            {
                "uuid": _STPA_CTRL_IMPL_UUID,
                "source": "https://www.iso.org/standard/81230.html",
                "description": "ISO/IEC 42001:2023 controls the STPA compiler maps UCAs to",
                "implemented-requirements": impl_requirements,
            }
        ],
    }


def generate_ftra_component_entry(
    *,
    now: str | None = None,
    si10_description: str | None = None,
) -> dict[str, Any]:
    """
    Generate the OSCAL component entry for the FTRA Irreversibility Classifier,
    to be merged into component-definition.yaml.

    Returns a component dict with its SI-10 control implementation. FTRA claims
    no AC-4: it never rejected undeclared parameters in production (the schema
    validator that could have was never registered and has been removed).
    *si10_description* is the domain-specific SI-10 statement from the narrative
    source (:data:`_NARRATIVE_PROSE_SLOTS`); without one the kernel seed is used.
    SI-10 is ``partial``: value validation is delegated to domain UCA rules that
    are advisory where their inputs are caller-asserted.
    """
    now = now or _now_iso()

    return {
        "uuid": _FTRA_COMPONENT_UUID,
        "title": "FTRA Irreversibility Classifier",
        "type": "software",
        "description": (
            "Forward-Looking Trajectory Reachability Analyzer (FTRA, Tier 0.5): "
            "classifies each tool call against the active domain's digest-covered "
            "terminal registry, records the registry provenance of the classification, "
            "and lets a registered terminal clear without a human only inside its "
            "digest-covered autonomous envelope. It validates no parameter values; value "
            "policy is owned by STPA UCA rules and the domain OPA policy "
            "(docs/governance/FTRA_SCOPE.md)."
        ),
        "purpose": (
            "Irreversibility classification and autonomous-envelope gating for tool execution"
        ),
        "responsible-roles": [{"role-id": "provider"}],
        "props": [
            {
                "name": "source-file",
                "value": "src/gateway/governance/governor/stages/ftra.py",
            },
            {"name": "last-compiled", "value": now},
        ],
        "control-implementations": [
            {
                "uuid": _FTRA_CTRL_IMPL_UUID,
                "source": "https://csrc.nist.gov/projects/cprt/api/cprt/framework/version/SP_800_53_5_1_1/home",
                "description": "NIST SP 800-53 Rev 5 HIGH-baseline controls implemented by FTRA Irreversibility Classifier",
                "implemented-requirements": [
                    {
                        "uuid": _FTRA_SI10_IMPL_UUID,
                        "control-id": "si-10",
                        "description": si10_description or _FTRA_SI10_DESCRIPTION,
                        "props": [
                            {"name": "implementation-status", "value": "partial"},
                            {"name": "control-origination", "value": "system-specific"},
                        ],
                        "links": [
                            {
                                "href": "https://csrc.nist.gov/projects/cprt/api/cprt/framework/version/SP_800_53_5_1_1/home?element=SI-10",
                                "rel": "reference",
                            }
                        ],
                    },
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Narrative sources — hand-authored blocks brought under the exporter (F-82)
# ---------------------------------------------------------------------------

#: One narrative source per canonical exporter output, named after the output's
#: stem: ``config/oscal/narratives/system-security-plan.json`` patches
#: ``compliance/oscal/system-security-plan.yaml``. Each holds data the kernel
#: may not (domain paths, Gate G3; vendor names, Gate G8).
_NARRATIVES_DIR: Path = _REPO_ROOT / "config" / "oscal" / "narratives"

_NARRATIVE_KEYS = frozenset({"_comment", "nodes", "set_parameters", "remove"})

#: Statements inside exporter-generated components whose prose comes from the
#: narrative source. Only ``description`` may be supplied for them; the
#: exporter keeps owning their structure, status and other props.
_NARRATIVE_PROSE_SLOTS = frozenset({_FTRA_SI10_IMPL_UUID})


def _canonical_outputs() -> frozenset[Path]:
    return frozenset(
        [(_REPO_ROOT / p["ssp_path"]).resolve() for p in REGIONAL_PROFILES.values()]
        + [_DEFAULT_COMP_DEF.resolve()]
    )


def narrative_source_for(target: Path) -> Path | None:
    """Return the narrative source of a canonical exporter output, if it has one.

    Non-canonical paths (``--ssp`` copies, test fixtures) never get one, so the
    UUIDs a source names are always resolved against the document they belong to.
    """
    resolved = target.resolve()
    if resolved not in _canonical_outputs():
        return None
    source = _NARRATIVES_DIR / f"{resolved.stem}.json"
    return source if source.is_file() else None


def load_narrative_source(source: Path) -> dict[str, Any]:
    """Load and validate a narrative source; raise ``ValueError`` on bad shape."""
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{source}: a narrative source must be a JSON object")
    unknown = sorted(set(data) - _NARRATIVE_KEYS)
    if unknown:
        raise ValueError(f"{source}: unknown top-level keys {unknown}")
    nodes = data.get("nodes", {})
    if not isinstance(nodes, dict) or not all(
        isinstance(fields, dict) and fields for fields in nodes.values()
    ):
        raise ValueError(f"{source}: 'nodes' must map uuid -> non-empty field object")
    for uid, fields in nodes.items():
        if "uuid" in fields:
            raise ValueError(f"{source}: node {uid} may not replace its uuid")
        if uid in _NARRATIVE_PROSE_SLOTS and (
            set(fields) != {"description"} or not isinstance(fields["description"], str)
        ):
            raise ValueError(
                f"{source}: generated statement {uid} accepts only 'description'"
            )
    params = data.get("set_parameters", {})
    if not isinstance(params, dict) or not all(
        isinstance(v, list) and all(isinstance(x, str) for x in v)
        for v in params.values()
    ):
        raise ValueError(f"{source}: 'set_parameters' must map param-id -> [str]")
    remove = data.get("remove", [])
    if not isinstance(remove, list) or not all(isinstance(u, str) for u in remove):
        raise ValueError(f"{source}: 'remove' must be a list of uuids")
    return data


def _index_uuid_nodes(node: Any, index: dict[str, list[dict[str, Any]]]) -> None:
    if isinstance(node, dict):
        uid = node.get("uuid")
        if isinstance(uid, str):
            index.setdefault(uid, []).append(node)
        for value in node.values():
            _index_uuid_nodes(value, index)
    elif isinstance(node, list):
        for item in node:
            _index_uuid_nodes(item, index)


def _collect_uuids(blocks: Any) -> frozenset[str]:
    index: dict[str, list[dict[str, Any]]] = {}
    _index_uuid_nodes(blocks, index)
    return frozenset(index)


def _drop_uuid_items(node: Any, doomed: set[str]) -> None:
    if isinstance(node, dict):
        for value in node.values():
            _drop_uuid_items(value, doomed)
    elif isinstance(node, list):
        node[:] = [
            item
            for item in node
            if not (isinstance(item, dict) and item.get("uuid") in doomed)
        ]
        for item in node:
            _drop_uuid_items(item, doomed)


def _set_parameter_nodes(node: Any, found: dict[str, list[dict[str, Any]]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "set-parameters" and isinstance(value, list):
                for param in value:
                    if isinstance(param, dict) and isinstance(
                        param.get("param-id"), str
                    ):
                        found.setdefault(param["param-id"], []).append(param)
            else:
                _set_parameter_nodes(value, found)
    elif isinstance(node, list):
        for item in node:
            _set_parameter_nodes(item, found)


def apply_narrative_source(
    doc: dict[str, Any],
    data: dict[str, Any],
    *,
    generated_uuids: frozenset[str],
    source: Path,
) -> None:
    """Apply a loaded narrative source to the OSCAL document *doc*, in place.

    Each ``nodes`` entry replaces the listed fields of the node with that UUID
    wholesale; a field set to ``null`` is deleted. ``remove`` drops list items
    by UUID and ``set_parameters`` replaces a set-parameter's ``values``.
    Fails closed (``ValueError``) when a named UUID or param-id does not match
    exactly one node, or when an entry targets an exporter-generated block
    other than a :data:`_NARRATIVE_PROSE_SLOTS` statement: every entry must
    resolve, and no block gets two sources.
    """
    nodes: dict[str, dict[str, Any]] = data.get("nodes", {})
    remove: list[str] = data.get("remove", [])
    clash = sorted(
        (set(nodes) | set(remove)) & (generated_uuids - _NARRATIVE_PROSE_SLOTS)
    )
    if clash:
        raise ValueError(f"{source}: names exporter-generated blocks {clash}")
    index: dict[str, list[dict[str, Any]]] = {}
    _index_uuid_nodes(doc, index)
    for uid in sorted(set(nodes) | set(remove)):
        hits = len(index.get(uid, []))
        if hits != 1:
            raise ValueError(f"{source}: uuid {uid} matches {hits} nodes, expected 1")
    for uid, fields in nodes.items():
        node = index[uid][0]
        for field, value in fields.items():
            if value is None:
                node.pop(field, None)
            else:
                node[field] = copy.deepcopy(value)
    if remove:
        _drop_uuid_items(doc, set(remove))
    params: dict[str, list[str]] = data.get("set_parameters", {})
    found: dict[str, list[dict[str, Any]]] = {}
    _set_parameter_nodes(doc, found)
    for param_id, values in params.items():
        hits = len(found.get(param_id, []))
        if hits != 1:
            raise ValueError(
                f"{source}: set-parameter {param_id} matches {hits} nodes, expected 1"
            )
        found[param_id][0]["values"] = list(values)


def _prose_slot(narratives: Path | None, uuid: str) -> str | None:
    """Return the narrative-source description for a generated statement, if any."""
    if narratives is None:
        return None
    entry = load_narrative_source(narratives).get("nodes", {}).get(uuid)
    return None if entry is None else str(entry["description"])


# ---------------------------------------------------------------------------
# SSP patch application (idempotent)
# ---------------------------------------------------------------------------

# Marker: if an existing requirement has this UUID, it was written by this exporter
_STPA_IMPL_MARKER = _STPA_IMPL_UUID


def _apply_ssp_patch(
    ssp_path: Path,
    patch_blocks: list[dict[str, Any]],
    dry_run: bool = False,
    *,
    now: str | None = None,
    narratives: Path | None = None,
) -> bool:
    """
    Load the existing SSP YAML, inject/replace patch blocks, write back.

    Args:
        ssp_path: Path to the SSP YAML file.
        patch_blocks: List of OSCAL implemented-requirement dicts to inject.
        dry_run: If True, do not write files.
        narratives: The SSP's narrative source (:func:`narrative_source_for`),
            applied after the generated blocks; a malformed or stale source
            aborts the patch without writing.

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

    # Remove any pre-existing platform control blocks (idempotent, by UUID)
    platform_uuids = {
        _PLATFORM_SC7_IMPL_UUID,
        _PLATFORM_SC8_IMPL_UUID,
        _PLATFORM_SC39_IMPL_UUID,
        _PLATFORM_SI3_IMPL_UUID,
    }
    impl_reqs = [r for r in impl_reqs if r.get("uuid") not in platform_uuids]

    # Append new blocks
    impl_reqs.extend(patch_blocks)
    ssp["system-security-plan"]["control-implementation"][
        "implemented-requirements"
    ] = impl_reqs

    # Apply the narrative source: it may name hand-authored blocks only.
    if narratives is not None:
        try:
            apply_narrative_source(
                ssp,
                load_narrative_source(narratives),
                generated_uuids=_collect_uuids(patch_blocks)
                | {_STPA_IMPL_MARKER, *platform_uuids},
                source=narratives,
            )
        except ValueError as exc:
            logger.error("Narrative source rejected: %s", exc)
            return False

    # Update metadata timestamps
    now = now or _now_iso()
    ssp["system-security-plan"]["metadata"]["last-modified"] = now
    old_version = ssp["system-security-plan"]["metadata"].get("version", "1.0.0-draft")
    if not old_version.endswith("+stpa"):
        ssp["system-security-plan"]["metadata"]["version"] = f"{old_version}+stpa"

    # Inject AssurancePosture (v3.1.5 Phase 1.2)
    # Lazy import to avoid Layer 1 → Layer 3 boundary violation (Gate G3)
    from src.compliance_bridge.types import AssurancePosture

    # Convert to dict with mode='json' to ensure enums serialize as strings
    posture_dict = AssurancePosture().model_dump(mode="json")
    ssp["system-security-plan"]["metadata"]["assurance-posture"] = posture_dict

    # Inject Tier-3 commercial retail-banking ledger API customer-responsibility statement (§6 Step 6f)
    meta_props: list[dict[str, Any]] = list(
        ssp["system-security-plan"]["metadata"].get("props") or []
    )
    meta_props = [
        p
        for p in meta_props
        if p.get("name") != "customer_responsibility_tier3_ledger_apis"
    ]
    meta_props.append(
        {
            "name": "customer_responsibility_tier3_ledger_apis",
            "ns": "https://cage.laah.cybernetics.dev/ns/oscal",
            "value": TIER3_COMMERCIAL_LEDGER_CUSTOMER_RESPONSIBILITY,
            "class": "customer-responsibility",
        }
    )
    ssp["system-security-plan"]["metadata"]["props"] = meta_props

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
    *,
    now: str | None = None,
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

    now = now or _now_iso()
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


def _apply_ftra_component_patch(
    comp_path: Path,
    ftra_component_entry: dict[str, Any],
    dry_run: bool = False,
    *,
    now: str | None = None,
    narratives: Path | None = None,
) -> bool:
    """Inject/replace the FTRA component in component-definition.yaml.

    The generated component replaces the committed one wholesale; its SI-10
    prose comes from the narrative source (``si10_description`` of
    :func:`generate_ftra_component_entry`), never from the committed YAML.
    This is the last component-definition step, so the narrative source
    (*narratives*) is applied here, after both generated components are in
    place; a malformed or stale source aborts the patch without writing.
    """
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

    # Remove existing FTRA component (idempotent)
    components = [c for c in components if c.get("uuid") != _FTRA_COMPONENT_UUID]
    components.append(copy.deepcopy(ftra_component_entry))
    comp_def["component-definition"]["components"] = components

    if narratives is not None:
        generated = [
            c
            for c in components
            if c.get("uuid") in {_STPA_COMPONENT_UUID, _FTRA_COMPONENT_UUID}
        ]
        try:
            apply_narrative_source(
                comp_def,
                load_narrative_source(narratives),
                generated_uuids=_collect_uuids(generated),
                source=narratives,
            )
        except ValueError as exc:
            logger.error("Narrative source rejected: %s", exc)
            return False

    now = now or _now_iso()
    comp_def["component-definition"]["metadata"]["last-modified"] = now

    if dry_run:
        logger.info("[DRY-RUN] Would update FTRA component in %s", comp_path)
        return True

    with open(comp_path, "w") as fh:
        yaml.dump(
            comp_def, fh, allow_unicode=True, default_flow_style=False, sort_keys=False
        )

    logger.info("✅ FTRA component definition patched → %s", comp_path)
    return True


def _write_standalone_patch(
    patch_path: Path,
    patch_block: dict[str, Any],
    component_entry: dict[str, Any],
    cs: ControlStructureModel,
    dry_run: bool = False,
    *,
    now: str | None = None,
) -> None:
    """Write the standalone patch YAML (for PR diff review)."""
    doc = {
        "stpa-compiler-ssp-patch": {
            "generated": now or _now_iso(),
            "source": "config/stpa/",
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


def _infer_region_from_ssp(ssp_path: Path) -> str | None:
    """Return the deployment region declared by *ssp_path*, or ``None``."""
    try:
        resolved = ssp_path.resolve()
        for r, prof in REGIONAL_PROFILES.items():
            if (_REPO_ROOT / prof["ssp_path"]).resolve() == resolved:
                return r
    except OSError:
        pass
    if not ssp_path.exists():
        return None
    try:
        with open(ssp_path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        props = (doc or {}).get("system-security-plan", {}).get("metadata", {}).get(
            "props"
        ) or []
        for prop in props:
            if isinstance(prop, dict) and prop.get("name") == "cage-deployment-region":
                val = str(prop.get("value", "")).strip().upper()
                if val in REGIONAL_PROFILES:
                    return val
    except Exception:  # noqa: BLE001
        return None
    return None


def _render_targets_in_memory(
    *,
    cs: ControlStructureModel,
    ssp_path: Path,
    comp_def_path: Path | None,
    patch_out_path: Path | None,
    framework_key: str,
    platform: str | None,
    now: str | None = None,
) -> tuple[bool, dict[Path, str]]:
    """Render target OSCAL YAML artifacts into memory without modifying files on disk.

    Narrative sources are resolved from the canonical target paths
    (:func:`narrative_source_for`), never from the temporary copies.
    """
    now = now or _now_iso()
    live_inputs = _live_registered_server_inputs()
    comp_narratives = (
        narrative_source_for(comp_def_path) if comp_def_path is not None else None
    )
    try:
        si10_description = _prose_slot(comp_narratives, _FTRA_SI10_IMPL_UUID)
    except ValueError as exc:
        logger.error("Narrative source rejected: %s", exc)
        return False, {}
    stpa_patch_block = generate_ssp_patch(
        cs, target_framework=framework_key, now=now, live_server_inputs=live_inputs
    )
    component_entry = generate_component_entry(
        cs, now=now, live_server_inputs=live_inputs
    )
    ftra_component_entry = generate_ftra_component_entry(
        now=now, si10_description=si10_description
    )
    platform_narratives = generate_platform_control_narratives(platform)
    all_patch_blocks = [stpa_patch_block, *platform_narratives]

    rendered: dict[Path, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        if not ssp_path.exists():
            logger.error("SSP not found at %s", ssp_path)
            return False, {}
        tmp_ssp = tmp_dir / "ssp.yaml"
        shutil.copyfile(ssp_path, tmp_ssp)
        if not _apply_ssp_patch(
            tmp_ssp,
            all_patch_blocks,
            dry_run=False,
            now=now,
            narratives=narrative_source_for(ssp_path),
        ):
            return False, {}
        rendered[ssp_path] = tmp_ssp.read_text(encoding="utf-8")

        if comp_def_path is not None:
            if comp_def_path.exists():
                tmp_comp = tmp_dir / "comp.yaml"
                shutil.copyfile(comp_def_path, tmp_comp)
                if not _apply_component_patch(
                    tmp_comp, component_entry, dry_run=False, now=now
                ) or not _apply_ftra_component_patch(
                    tmp_comp,
                    ftra_component_entry,
                    dry_run=False,
                    now=now,
                    narratives=comp_narratives,
                ):
                    return False, {}
                rendered[comp_def_path] = tmp_comp.read_text(encoding="utf-8")
            else:
                logger.warning(
                    "Component definition not found at %s — skipping", comp_def_path
                )

        if patch_out_path is not None:
            tmp_patch = tmp_dir / "patch.yaml"
            _write_standalone_patch(
                tmp_patch,
                stpa_patch_block,
                component_entry,
                cs,
                dry_run=False,
                now=now,
            )
            rendered[patch_out_path] = tmp_patch.read_text(encoding="utf-8")

    return True, rendered


def render_default_oscal_artifacts(
    cs: ControlStructureModel | None = None,
    *,
    ssp_path: Path = _DEFAULT_SSP,
    comp_def_path: Path = _DEFAULT_COMP_DEF,
    patch_out_path: Path = _DEFAULT_PATCH_OUT,
) -> dict[Path, str | None]:
    """Render the three default US_FED OSCAL artifacts in memory for freshness checking."""
    unavailable: dict[Path, str | None] = {
        ssp_path: None,
        comp_def_path: None,
        patch_out_path: None,
    }
    try:
        if cs is None:
            core_yamls = sorted(_DEFAULT_INPUT_DIR.rglob("*.yaml"))
            domain_yamls = sorted(
                (_REPO_ROOT / "src").glob("cage_*/config/stpa/*.yaml")
            )
            cs = load_control_structures([*core_yamls, *domain_yamls])
        ok, rendered = _render_targets_in_memory(
            cs=cs,
            ssp_path=ssp_path,
            comp_def_path=comp_def_path,
            patch_out_path=patch_out_path,
            framework_key="NIST",
            platform="gcp-gke",
        )
        if not ok:
            return unavailable
        return {k: rendered.get(k) for k in unavailable}
    except Exception:  # noqa: BLE001
        return unavailable


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oscal_ssp_exporter",
        description=textwrap.dedent(
            """\
            OSCAL SSP Exporter — reads the active config/stpa/ and domain STPA YAML sources
            and patches the existing OSCAL SSP with a generated implemented-requirement
            block verified against live assemble_governor() server inputs.
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
        default=None,
        metavar="YAML",
        help=(
            "Explicit single control structure YAML (default: merge "
            f"{_DEFAULT_INPUT_DIR}/*.yaml + src/cage_*/config/stpa/*.yaml)"
        ),
    )
    exp.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Directory of STPA YAML source files; all *.yaml files are merged "
            "deterministically (mutually exclusive with --input). "
            f"Default directory: {_DEFAULT_INPUT_DIR}"
        ),
    )
    exp.add_argument(
        "--ssp",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            f"Target SSP YAML (default: regional SSP from CAGE_DEPLOYMENT_REGION, "
            f"or {_DEFAULT_SSP})"
        ),
    )
    exp.add_argument(
        "--component-def",
        type=Path,
        default=None,
        metavar="FILE",
        help=f"Target component-definition YAML (default: {_DEFAULT_COMP_DEF})",
    )
    exp.add_argument(
        "--patch-out",
        type=Path,
        default=None,
        metavar="FILE",
        help=f"Standalone patch output (default: {_DEFAULT_PATCH_OUT})",
    )
    exp.add_argument(
        "--dry-run",
        action="store_true",
        help="Print patch blocks without writing any files.",
    )
    exp.add_argument(
        "--check",
        action="store_true",
        help=(
            "Verify that target OSCAL file(s) on disk match a fresh export "
            "(masking volatile timestamps); exit 1 on drift without writing files."
        ),
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
    exp.add_argument(
        "--platform",
        default=None,
        choices=["gcp-gke", "aws-ecs", "azure-containerapp", "agnostic"],
        metavar="PLATFORM",
        help=(
            "Deployment platform for platform-aware control narratives (SC-7, SC-8, SC-39, SI-3). "
            "Auto-detected if not specified. gcp-gke = GKE (default for K8s), "
            "aws-ecs = ECS, azure-containerapp = Azure Container Apps, agnostic = local/unknown."
        ),
    )
    return parser


def cmd_export(args: argparse.Namespace) -> int:
    # ---------------------------------------------------------------------------
    # Multi-jurisdiction SSP router — resolve region and target SSP path.
    # When --ssp is omitted, CAGE_DEPLOYMENT_REGION selects both the regional
    # profile and its canonical ssp_path (preventing an EU_ECB/APAC_MAS run from
    # overwriting the US_FED system-security-plan.yaml, POAM-2026-177).
    # When --ssp is explicitly supplied and declares cage-deployment-region in
    # metadata.props, that region's profile and framework are used automatically.
    # ---------------------------------------------------------------------------
    env_region = os.environ.get("CAGE_DEPLOYMENT_REGION", "US_FED").strip().upper()
    if env_region not in REGIONAL_PROFILES:
        env_region = "US_FED"

    if args.ssp is None:
        region = env_region
        regional_profile = get_regional_profile(region)
        ssp_path = _REPO_ROOT / regional_profile["ssp_path"]
    else:
        ssp_path = args.ssp
        inferred_region = _infer_region_from_ssp(ssp_path)
        region = inferred_region if inferred_region is not None else env_region
        regional_profile = get_regional_profile(region)

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

    is_default_us_ssp = (
        ssp_path.resolve() == _DEFAULT_SSP.resolve() and region == "US_FED"
    )
    comp_def_path = (
        args.component_def
        if args.component_def is not None
        else (_DEFAULT_COMP_DEF if is_default_us_ssp else None)
    )
    patch_out_path = (
        args.patch_out
        if args.patch_out is not None
        else (_DEFAULT_PATCH_OUT if is_default_us_ssp else None)
    )

    try:
        if args.input_dir is not None:
            yaml_files = sorted(args.input_dir.rglob("*.yaml"))
            if not yaml_files:
                print(
                    f"❌ No YAML files found under {args.input_dir}",
                    file=sys.stderr,
                )
                return 1
            logger.info(
                "Multi-source mode: merging %d files from %s",
                len(yaml_files),
                args.input_dir,
            )
            cs = load_control_structures(yaml_files)
        elif args.input is None:
            core_yamls = sorted(_DEFAULT_INPUT_DIR.rglob("*.yaml"))
            domain_yamls = sorted(
                (_REPO_ROOT / "src").glob("cage_*/config/stpa/*.yaml")
            )
            cs = load_control_structures([*core_yamls, *domain_yamls])
        else:
            cs = load_control_structure(args.input)
    except Exception as exc:
        print(f"❌ Failed to load control structure: {exc}", file=sys.stderr)
        return 1

    # Generate platform-aware control narratives (Phase E / Step 6f: GKE is sole cloud target
    # for the US_FED NIST SP 800-53 SSP; regional EU_ECB/APAC_MAS SSPs use their own profiles).
    platform = getattr(args, "platform", None)
    if platform is None:
        if is_default_us_ssp:
            platform = "gcp-gke"
        elif region != "US_FED":
            platform = "agnostic"

    now = _now_iso()

    ok_ssp, rendered = _render_targets_in_memory(
        cs=cs,
        ssp_path=ssp_path,
        comp_def_path=comp_def_path,
        patch_out_path=patch_out_path,
        framework_key=framework_key,
        platform=platform,
        now=now,
    )
    if not ok_ssp:
        print("⚠️  SSP patch failed — check logs above.", file=sys.stderr)
        return 1

    if args.dry_run:
        for target in rendered:
            logger.info("[DRY-RUN] Would update %s", target)
        if patch_out_path is not None and patch_out_path in rendered:
            print("\n" + "=" * 80)
            print("STANDALONE PATCH (dry-run)")
            print("=" * 80)
            print(rendered[patch_out_path])
        return 0

    if getattr(args, "check", False):
        expected_targets = [
            p for p in (ssp_path, comp_def_path, patch_out_path) if p is not None
        ]
        drifted: list[str] = []
        for target in expected_targets:
            if not target.exists() or target not in rendered:
                drifted.append(f"MISSING: {target}")
                continue
            on_disk = target.read_text(encoding="utf-8")
            if mask_volatile_stamps(on_disk) != mask_volatile_stamps(rendered[target]):
                drifted.append(f"DRIFTED: {target}")
        if drifted:
            for item in drifted:
                print(f"❌ {item}", file=sys.stderr)
            remediation = "python -m src.gateway.governance.oscal_ssp_exporter export"
            if not is_default_us_ssp:
                remediation += f" --ssp {ssp_path}"
            print(
                f"Fix: {remediation}",
                file=sys.stderr,
            )
            return 1
        print(
            f"✅ OSCAL SSP check passed ({len(expected_targets)} file(s) current: "
            f"{', '.join(str(p) for p in expected_targets)})"
        )
        return 0

    for target, fresh_text in rendered.items():
        if target.exists() and mask_volatile_stamps(
            target.read_text(encoding="utf-8")
        ) == mask_volatile_stamps(fresh_text):
            logger.info(
                "OSCAL artifact unchanged (skipping timestamp-only write) → %s",
                target,
            )
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fresh_text, encoding="utf-8")
        logger.info("✅ OSCAL artifact written → %s", target)

    router = FrameworkRouter.get(framework_key)
    print("✅ OSCAL SSP export complete:")
    print(f"   Region          : {region}")
    print(f"   Profile path    : {regional_profile['profile_path']}")
    print(f"   SSP             → {ssp_path}")
    if comp_def_path is not None:
        print(f"   Component def   → {comp_def_path}")
    if patch_out_path is not None:
        print(f"   Standalone patch→ {patch_out_path}")
    print(f"   Framework       : {router.label}")
    print(f"   UCAs exported   : {len(cs.unsafe_control_actions)}")
    print(f"   Controls mapped : {len(router.all_controls(cs.unsafe_control_actions))}")
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
