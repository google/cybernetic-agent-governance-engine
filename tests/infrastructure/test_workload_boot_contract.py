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
# Closure regression guard for: POAM-2026-231

"""Boot-contract guard: every enforcing CAGE workload injects CAGE_DEPLOYMENT_REGION.

PR #764 (3347b4b1) centralized ``CAGE_DEPLOYMENT_REGION`` resolution in
``resolve_deployment_region()`` and made an unset region fail closed with
``DeploymentRegionError`` in every enforcing posture (``staging``, ``prod``,
``local``, or unknown ``CAGE_ENV``). ``Deployment/gateway-canary`` in
``infra/targets/gcp-gke/gateway_canary.tf`` set ``CAGE_ENV`` and ``CAGE_DOMAIN``
without injecting ``CAGE_DEPLOYMENT_REGION`` from ``ConfigMap/cage-deployment``,
causing a startup crash loop on live staging (POAM-2026-231).

This guard prevents silent omissions across all Kubernetes workload templates in
``infra/``:

1. Dynamically discovers EVERY Kubernetes workload template across ``infra/``:
   - Terraform ``kubernetes_{deployment,stateful_set,daemon_set,job,cron_job,pod}[_v1]``
     and pod-bearing ``kubernetes_manifest`` resources (both static and
     ``dynamic`` container / init_container blocks);
   - Terraform ``helm_release`` local manifest charts (such as
     ``infra/modules/gateway/main.tf`` rendering ``local.gateway_deployment_manifest``
     through ``infra/modules/gateway/deployment/templates/deployment.yaml``);
   - Kubernetes / Helm YAML templates (``*.yaml``, ``*.yml``) declaring
     ``Deployment``, ``StatefulSet``, ``DaemonSet``, ``Job``, ``CronJob``, or ``Pod``.
2. Refuses silent skips: every discovered container NOT explicitly accounted for
   with documented rationale in ``EXEMPT_CONTAINERS`` is audited as an enforcing
   CAGE workload and MUST bind ``CAGE_DEPLOYMENT_REGION`` via ``configMapKeyRef``
   (``optional = false``) wired to ``module.deployment_config.config_map_name``.
3. Enforces non-vacuous discovery floors and verifies CAGE-adjacent exemptions
   mechanically (AST / Terraform / YAML checks) rather than trusting comments.
4. Proves via planted-drift negative tests that dropping ``CAGE_DEPLOYMENT_REGION``,
   relaxing ``optional = false``, breaking root module wiring, or adding a new
   unconfigured workload causes the audit to FAIL.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRA_DIR = REPO_ROOT / "infra"

ContainerKey = tuple[str, str, str]

_POD_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
)

_TF_WORKLOAD_RESOURCE_KINDS: dict[str, str] = {
    "kubernetes_deployment": "Deployment",
    "kubernetes_deployment_v1": "Deployment",
    "kubernetes_stateful_set": "StatefulSet",
    "kubernetes_stateful_set_v1": "StatefulSet",
    "kubernetes_daemon_set": "DaemonSet",
    "kubernetes_daemon_set_v1": "DaemonSet",
    "kubernetes_job": "Job",
    "kubernetes_job_v1": "Job",
    "kubernetes_cron_job": "CronJob",
    "kubernetes_cron_job_v1": "CronJob",
    "kubernetes_pod": "Pod",
    "kubernetes_pod_v1": "Pod",
}

# Non-vacuous discovery floors: fail immediately if parser regressions silently
# shrink coverage.
MIN_ENFORCING_CAGE_CONTAINERS = 5
MIN_TOTAL_DISCOVERED_CONTAINERS = 15
EXPECTED_DISCOVERED_KINDS = frozenset({"Deployment", "StatefulSet", "CronJob", "Job"})

# Every container in infra/ that does NOT run enforcing CAGE Python governance
# code MUST be explicitly registered here with its rationale. Any newly added
# workload container in infra/ that is absent from this mapping is treated as
# enforcing and fails until wired to ConfigMap/cage-deployment or explicitly
# justified here.
EXEMPT_CONTAINERS: dict[ContainerKey, str] = {
    (
        "infra/modules/gateway/main.tf",
        "helm_release.gateway",
        "opa",
    ): "Third-party Open Policy Agent Go native sidecar (var.opa_image); runs Rego only and no CAGE Python code.",
    (
        "infra/modules/agentsight_ui/main.tf",
        "kubernetes_deployment.agentsight_ui",
        "agentsight-ui",
    ): "Static React/Vite UI frontend served by nginx (src/agentsight-ui/Dockerfile); no Python runtime.",
    (
        "infra/modules/clickhouse_operator/main.tf",
        "kubernetes_stateful_set.clickhouse",
        "clickhouse",
    ): "Third-party ClickHouse OLAP database container; no CAGE Python code.",
    (
        "infra/modules/clickhouse_operator/main.tf",
        "kubernetes_stateful_set.clickhouse_keeper",
        "clickhouse-keeper",
    ): "Third-party ClickHouse Keeper coordination container; no CAGE Python code.",
    (
        "infra/modules/langfuse_stack/main.tf",
        "kubernetes_deployment.langfuse_web",
        "langfuse-web",
    ): "Third-party Node.js Langfuse v3 web server; no CAGE Python code.",
    (
        "infra/modules/langfuse_stack/main.tf",
        "kubernetes_deployment.langfuse_web",
        "cloud-sql-proxy",
    ): "Third-party Google Cloud SQL Auth Proxy Go sidecar; no CAGE Python code.",
    (
        "infra/modules/langfuse_stack/main.tf",
        "kubernetes_deployment.langfuse_worker",
        "langfuse-worker",
    ): "Third-party Node.js Langfuse v3 worker; no CAGE Python code.",
    (
        "infra/modules/langfuse_stack/main.tf",
        "kubernetes_deployment.langfuse_worker",
        "cloud-sql-proxy",
    ): "Third-party Google Cloud SQL Auth Proxy Go sidecar; no CAGE Python code.",
    (
        "infra/modules/vllm_inference/main.tf",
        "kubernetes_deployment.vllm",
        "vllm",
    ): "Third-party vLLM OpenAI-compatible inference engine; no CAGE Python code.",
    (
        "infra/modules/lula_cron/main.tf",
        "kubernetes_cron_job_v1.lula_audit",
        "lula-audit",
    ): "Shell/Go compliance audit CronJob (/bin/sh running run_lula_audit.sh + Go lula binary); no Python runtime.",
    (
        "infra/targets/gcp-gke/charts/dataplane-v2-logging/templates/reconcile-hook.yaml",
        "Job/cage-dpv2-logging-reconcile",
        "reconcile",
    ): "Helm hook Job in kube-system running a stdlib-only inline Python patch for GKE NetworkLogging/default; imports no CAGE modules.",
    (
        "infra/modules/inference_stub/main.tf",
        "kubernetes_deployment_v1.inference_stub",
        "inference-stub",
    ): "Opt-in non-production E2E deterministic OpenAI stub (forbidden in prod); AST-verified to import no src.gateway or region reader.",
    (
        "infra/modules/nemo_guardrails/main.tf",
        "kubernetes_deployment.nemo_guardrails",
        "nemo-guardrails",
    ): "Retired standalone NeMo Guardrails module not instantiated in infra/targets/gcp-gke/ (verified mechanically); NeMo runs in-process inside gateway.",
    (
        "infra/modules/nemo_guardrails/main.tf",
        "kubernetes_deployment.nemo_guardrails",
        "presidio-analyzer",
    ): "Third-party Microsoft Presidio Analyzer HTTP service inside retired standalone nemo_guardrails module.",
    (
        "infra/modules/nemo_guardrails/main.tf",
        "kubernetes_deployment.nemo_guardrails",
        "presidio-anonymizer",
    ): "Third-party Microsoft Presidio Anonymizer HTTP service inside retired standalone nemo_guardrails module.",
}

# Only these two mechanically verified exemptions may set CAGE_ENV without
# triggering a boot-contract violation.
_ALLOWED_CAGE_ENV_EXEMPTIONS: frozenset[ContainerKey] = frozenset(
    {
        (
            "infra/modules/inference_stub/main.tf",
            "kubernetes_deployment_v1.inference_stub",
            "inference-stub",
        ),
        (
            "infra/modules/nemo_guardrails/main.tf",
            "kubernetes_deployment.nemo_guardrails",
            "nemo-guardrails",
        ),
    }
)


@dataclass(frozen=True)
class RegionEnvBinding:
    """Parsed declaration of the ``CAGE_DEPLOYMENT_REGION`` env entry."""

    source_kind: str  # "config_map_key_ref" | "value" | "other"
    config_map_ref_expr: str | None
    key: str | None
    optional: bool | None


@dataclass(frozen=True)
class DiscoveredContainer:
    """One container discovered inside a Kubernetes workload template."""

    file_path: str
    resource_id: str
    workload_kind: str
    container_name: str
    is_init: bool
    env_names: frozenset[str]
    region_binding: RegionEnvBinding | None
    module_dir: str | None

    @property
    def key(self) -> ContainerKey:
        return (self.file_path, self.resource_id, self.container_name)


# ---------------------------------------------------------------------------
# HCL lexical scanning (comment-, string-, and heredoc-safe)
# ---------------------------------------------------------------------------


def _strip_hcl_comments(text: str) -> str:
    """Remove HCL ``#``, ``//``, and ``/* ... */`` comments outside strings/heredocs."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # Double-quoted string
        if ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                c = text[i]
                out.append(c)
                i += 1
                if c == "\\" and i < n:
                    out.append(text[i])
                    i += 1
                elif c == '"':
                    break
            continue
        # Heredoc (<<EOF or <<-EOF)
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            hm = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n", text[i:])
            if hm:
                indented = text[i + 2] == "-"
                marker = hm.group(1)
                end_header = i + hm.end()
                out.append(text[i:end_header])
                i = end_header
                while i < n:
                    nl = text.find("\n", i)
                    if nl == -1:
                        line = text[i:]
                        out.append(line)
                        i = n
                        break
                    line = text[i : nl + 1]
                    out.append(line)
                    i = nl + 1
                    candidate = line.rstrip("\r\n")
                    if indented:
                        candidate = candidate.lstrip(" \t")
                    if candidate == marker:
                        break
                continue
        # Block comment /* ... */
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                out.append("\n" * text[i:].count("\n"))
                break
            out.append("\n" * text[i : end + 2].count("\n"))
            i = end + 2
            continue
        # Line comment # or //
        if ch == "#" or (ch == "/" and i + 1 < n and text[i + 1] == "/"):
            nl = text.find("\n", i)
            if nl == -1:
                break
            out.append("\n")
            i = nl + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _balanced_span(
    text: str, start_idx: int, open_ch: str = "{", close_ch: str = "}"
) -> tuple[str, int]:
    """Return balanced ``open_ch ... close_ch`` body and index after ``close_ch``."""
    open_idx = text.index(open_ch, start_idx)
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            hm = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n", text[i:])
            if hm:
                indented = text[i + 2] == "-"
                marker = hm.group(1)
                i += hm.end()
                while i < n:
                    nl = text.find("\n", i)
                    if nl == -1:
                        i = n
                        break
                    line = text[i:nl]
                    i = nl + 1
                    cand = line.lstrip(" \t") if indented else line
                    if cand == marker:
                        break
                continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
        i += 1
    raise AssertionError(f"Unbalanced {open_ch}...{close_ch} starting at {start_idx}")


def _depth_zero_text(block_body: str) -> str:
    """Return only depth-0 lines/tokens of an HCL block (nested blocks/lists blanked)."""
    out: list[str] = []
    brace_depth = 0
    bracket_depth = 0
    i = 0
    n = len(block_body)
    while i < n:
        ch = block_body[i]
        if ch == '"':
            start = i
            i += 1
            while i < n:
                if block_body[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if block_body[i] == '"':
                    i += 1
                    break
                i += 1
            if brace_depth == 0 and bracket_depth == 0:
                out.append(block_body[start:i])
            continue
        if ch == "{":
            brace_depth += 1
            i += 1
            continue
        if ch == "}":
            brace_depth = max(0, brace_depth - 1)
            i += 1
            continue
        if ch == "[":
            bracket_depth += 1
            i += 1
            continue
        if ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            i += 1
            continue
        if brace_depth == 0 and bracket_depth == 0:
            out.append(ch)
        elif ch == "\n":
            out.append("\n")
        i += 1
    return "".join(out)


def _top_level_attr_raw(block_body: str, attr: str) -> str | None:
    """Read a depth-0 ``attr = <rhs>`` value from an HCL block or map body."""
    flat = _depth_zero_text(block_body)
    m = re.search(rf"^\s*{re.escape(attr)}\s*=\s*(.+?)\s*$", flat, re.MULTILINE)
    if not m:
        return None
    return m.group(1).rstrip(",").strip()


def _unquote(expr: str | None) -> str | None:
    if expr is None:
        return None
    stripped = expr.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _parse_bool(expr: str | None) -> bool | None:
    if expr is None:
        return None
    val = expr.strip().lower()
    if val == "true":
        return True
    if val == "false":
        return False
    return None


# ---------------------------------------------------------------------------
# Terraform HCL resource & Helm-release manifest discovery
# ---------------------------------------------------------------------------

_CONTAINER_BLOCK_RE = re.compile(
    r'\b(?:(?P<dyn>dynamic)\s+"(?P<dyn_kind>init_container|container)"'
    r"|(?P<plain>init_container|container))\s*\{"
)
_ENV_BLOCK_RE = re.compile(r'\b(?:(?P<dyn>dynamic)\s+"env"|(?P<plain>env))\s*\{')


def _parse_hcl_region_binding(env_body: str) -> RegionEnvBinding:
    vf = re.search(r"\bvalue_from\s*\{", env_body)
    if vf:
        vf_body, _ = _balanced_span(env_body, vf.start())
        cm = re.search(r"\bconfig_map_key_ref\s*\{", vf_body)
        if cm:
            cm_body, _ = _balanced_span(vf_body, cm.start())
            return RegionEnvBinding(
                source_kind="config_map_key_ref",
                config_map_ref_expr=_top_level_attr_raw(cm_body, "name"),
                key=_unquote(_top_level_attr_raw(cm_body, "key")),
                optional=_parse_bool(_top_level_attr_raw(cm_body, "optional")),
            )
        return RegionEnvBinding(
            source_kind="other",
            config_map_ref_expr=None,
            key=None,
            optional=None,
        )
    if _top_level_attr_raw(env_body, "value") is not None:
        return RegionEnvBinding(
            source_kind="value",
            config_map_ref_expr=None,
            key=None,
            optional=None,
        )
    return RegionEnvBinding(
        source_kind="other",
        config_map_ref_expr=None,
        key=None,
        optional=None,
    )


def _parse_hcl_container_envs(
    container_body: str,
) -> tuple[frozenset[str], RegionEnvBinding | None]:
    env_names: set[str] = set()
    region_binding: RegionEnvBinding | None = None
    pos = 0
    while True:
        m = _ENV_BLOCK_RE.search(container_body, pos)
        if not m:
            break
        block_body, pos = _balanced_span(container_body, m.start())
        if m.group("dyn"):
            cm = re.search(r"\bcontent\s*\{", block_body)
            if not cm:
                continue
            env_body, _ = _balanced_span(block_body, cm.start())
        else:
            env_body = block_body
        raw_name = _top_level_attr_raw(env_body, "name")
        if raw_name and raw_name.startswith('"') and raw_name.endswith('"'):
            name = raw_name[1:-1]
            env_names.add(name)
            if name == "CAGE_DEPLOYMENT_REGION":
                region_binding = _parse_hcl_region_binding(env_body)
    return frozenset(env_names), region_binding


def _extract_hcl_containers(
    resource_body: str,
) -> list[tuple[str, bool, frozenset[str], RegionEnvBinding | None]]:
    found: list[tuple[str, bool, frozenset[str], RegionEnvBinding | None]] = []
    pos = 0
    while True:
        m = _CONTAINER_BLOCK_RE.search(resource_body, pos)
        if not m:
            break
        block_body, pos = _balanced_span(resource_body, m.start())
        if m.group("dyn"):
            kind_tok = m.group("dyn_kind")
            cm = re.search(r"\bcontent\s*\{", block_body)
            if not cm:
                continue
            cbody, _ = _balanced_span(block_body, cm.start())
        else:
            kind_tok = m.group("plain")
            cbody = block_body
        is_init = kind_tok == "init_container"
        cname = _unquote(_top_level_attr_raw(cbody, "name")) or "<unnamed>"
        env_names, region_binding = _parse_hcl_container_envs(cbody)
        found.append((cname, is_init, env_names, region_binding))
    return found


def _skip_hcl_expr(text: str, start: int) -> int:
    """Advance past an HCL expression starting at ``start`` until end-of-line at depth 0."""
    i = start
    n = len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth = max(0, depth - 1)
        elif ch == "\n" and depth == 0:
            return i + 1
        i += 1
    return n


def _collect_module_locals(module_dir: Path) -> dict[str, str]:
    """Return ``local_name -> map body`` for every map-valued local in ``module_dir``."""
    locals_map: dict[str, str] = {}
    for tf_path in sorted(module_dir.glob("*.tf")):
        clean = _strip_hcl_comments(tf_path.read_text(encoding="utf-8"))
        pos = 0
        while True:
            lm = re.search(r"(?m)^\s*locals\s*\{", clean[pos:])
            if not lm:
                break
            lstart = pos + lm.start()
            lbody, pos = _balanced_span(clean, lstart)
            idx = 0
            n = len(lbody)
            while idx < n:
                am = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*", lbody[idx:])
                if not am:
                    nl = lbody.find("\n", idx)
                    idx = n if nl == -1 else nl + 1
                    continue
                lname = am.group(1)
                rhs_start = idx + am.end()
                if rhs_start < n and lbody[rhs_start] == "{":
                    val_body, idx = _balanced_span(lbody, rhs_start)
                    locals_map[lname] = val_body
                else:
                    idx = _skip_hcl_expr(lbody, rhs_start)
    return locals_map


def _parse_hcl_map_region_binding(env_map_body: str) -> RegionEnvBinding:
    vf = re.search(r"\bvalueFrom\s*=\s*\{", env_map_body)
    if vf:
        vf_body, _ = _balanced_span(env_map_body, vf.start())
        cm = re.search(r"\bconfigMapKeyRef\s*=\s*\{", vf_body)
        if cm:
            cm_body, _ = _balanced_span(vf_body, cm.start())
            return RegionEnvBinding(
                source_kind="config_map_key_ref",
                config_map_ref_expr=_top_level_attr_raw(cm_body, "name"),
                key=_unquote(_top_level_attr_raw(cm_body, "key")),
                optional=_parse_bool(_top_level_attr_raw(cm_body, "optional")),
            )
        return RegionEnvBinding(
            source_kind="other",
            config_map_ref_expr=None,
            key=None,
            optional=None,
        )
    if _top_level_attr_raw(env_map_body, "value") is not None:
        return RegionEnvBinding(
            source_kind="value",
            config_map_ref_expr=None,
            key=None,
            optional=None,
        )
    return RegionEnvBinding(
        source_kind="other",
        config_map_ref_expr=None,
        key=None,
        optional=None,
    )


def _extract_hcl_map_env_entries(
    container_map_body: str,
) -> tuple[frozenset[str], RegionEnvBinding | None]:
    em = re.search(r"(?m)^\s*env\s*=\s*", container_map_body)
    if not em:
        return frozenset(), None
    rhs_start = em.end()
    env_expr_end = _skip_hcl_expr(container_map_body, rhs_start)
    env_expr = container_map_body[rhs_start:env_expr_end]

    env_names: set[str] = set()
    region_binding: RegionEnvBinding | None = None
    pos = 0
    while pos < len(env_expr):
        ch = env_expr[pos]
        if ch == '"':
            pos += 1
            while pos < len(env_expr):
                if env_expr[pos] == "\\" and pos + 1 < len(env_expr):
                    pos += 2
                    continue
                if env_expr[pos] == '"':
                    pos += 1
                    break
                pos += 1
            continue
        if ch == "{":
            item_body, pos = _balanced_span(env_expr, pos)
            raw_name = _top_level_attr_raw(item_body, "name")
            if raw_name and raw_name.startswith('"') and raw_name.endswith('"'):
                name = raw_name[1:-1]
                env_names.add(name)
                if name == "CAGE_DEPLOYMENT_REGION":
                    region_binding = _parse_hcl_map_region_binding(item_body)
            continue
        pos += 1
    return frozenset(env_names), region_binding


def _extract_hcl_map_containers(
    manifest_body: str,
    module_locals: Mapping[str, str],
) -> list[tuple[str, bool, frozenset[str], RegionEnvBinding | None]]:
    """Extract ``containers`` and ``initContainers`` from an HCL K8s manifest map."""
    found: list[tuple[str, bool, frozenset[str], RegionEnvBinding | None]] = []
    for key_name, is_init in (("initContainers", True), ("containers", False)):
        km = re.search(rf"\b{key_name}\s*=\s*\[", manifest_body)
        if not km:
            continue
        list_body, _ = _balanced_span(manifest_body, km.start(), "[", "]")
        pos = 0
        while pos < len(list_body):
            ch = list_body[pos]
            if ch == "{":
                cbody, pos = _balanced_span(list_body, pos)
                cname = _unquote(_top_level_attr_raw(cbody, "name")) or "<unnamed>"
                env_names, region_binding = _extract_hcl_map_env_entries(cbody)
                found.append((cname, is_init, env_names, region_binding))
                continue
            lm = re.match(r"local\.([A-Za-z_][A-Za-z0-9_]*)", list_body[pos:])
            if lm:
                pos += lm.end()
                ref = lm.group(1)
                assert ref in module_locals, (
                    f"Manifest {key_name} references local.{ref}, which could not be resolved"
                )
                cbody = module_locals[ref]
                cname = _unquote(_top_level_attr_raw(cbody, "name")) or "<unnamed>"
                env_names, region_binding = _extract_hcl_map_env_entries(cbody)
                found.append((cname, is_init, env_names, region_binding))
                continue
            pos += 1
    return found


def _module_dir_name(infra_dir: Path, path: Path) -> str | None:
    rel = path.relative_to(infra_dir)
    if len(rel.parts) >= 2 and rel.parts[0] == "modules":
        return rel.parts[1]
    return None


# ---------------------------------------------------------------------------
# YAML / Helm template discovery
# ---------------------------------------------------------------------------

_HELM_CONTROL_LINE_RE = re.compile(
    r"^\s*\{\{-?\s*(?:if|else|else\s+if|end|range|with|define|template|block)\b.*\}\}\s*$"
)
_HELM_EXPR_RE = re.compile(r"\{\{-?.*?-?\}\}")


def _sanitize_helm_yaml(raw_text: str) -> str:
    """Neutralize Go/Helm template directives so ``yaml.safe_load_all`` can parse K8s specs."""
    cleaned_lines: list[str] = []
    for line in raw_text.splitlines():
        if _HELM_CONTROL_LINE_RE.match(line):
            continue
        cleaned_lines.append(_HELM_EXPR_RE.sub('"__HELM_EXPR__"', line))
    return "\n".join(cleaned_lines)


def _parse_yaml_region_binding(env_entry: Mapping[str, object]) -> RegionEnvBinding:
    vf = env_entry.get("valueFrom")
    if isinstance(vf, Mapping):
        cm = vf.get("configMapKeyRef")
        if isinstance(cm, Mapping):
            opt_raw = cm.get("optional")
            opt = opt_raw if isinstance(opt_raw, bool) else None
            name_raw = cm.get("name")
            key_raw = cm.get("key")
            return RegionEnvBinding(
                source_kind="config_map_key_ref",
                config_map_ref_expr=str(name_raw) if name_raw is not None else None,
                key=str(key_raw) if key_raw is not None else None,
                optional=opt,
            )
        return RegionEnvBinding("other", None, None, None)
    if "value" in env_entry:
        return RegionEnvBinding("value", None, None, None)
    return RegionEnvBinding("other", None, None, None)


def _extract_yaml_pod_spec(doc: Mapping[str, object]) -> Mapping[str, object] | None:
    kind = doc.get("kind")
    if kind not in _POD_KINDS:
        return None
    spec = doc.get("spec")
    if not isinstance(spec, Mapping):
        return None
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        jt = spec.get("jobTemplate")
        if not isinstance(jt, Mapping):
            return None
        spec = jt.get("spec")
        if not isinstance(spec, Mapping):
            return None
    tmpl = spec.get("template")
    if not isinstance(tmpl, Mapping):
        return None
    pod_spec = tmpl.get("spec")
    return pod_spec if isinstance(pod_spec, Mapping) else None


def _discover_yaml_workloads(
    infra_dir: Path, repo_root: Path
) -> tuple[list[DiscoveredContainer], set[Path]]:
    """Discover workload containers in ``*.yaml`` / ``*.yml`` under ``infra_dir``.

    Also returns the set of pass-through ``toYaml .Values.manifest`` chart
    directories so callers can verify each one is backed by a discovered
    ``helm_release`` resource.
    """
    containers: list[DiscoveredContainer] = []
    passthrough_charts: set[Path] = set()

    for yaml_path in sorted(
        p
        for p in infra_dir.rglob("*")
        if p.is_file() and p.suffix in {".yaml", ".yml"} and ".terraform" not in p.parts
    ):
        raw_text = yaml_path.read_text(encoding="utf-8")
        if (
            yaml_path.parent.name == "templates"
            and re.search(r"toYaml\s+\.Values\.manifest\b", raw_text) is not None
        ):
            passthrough_charts.add(yaml_path.parent.parent.resolve())
            continue

        if not re.search(
            r"(?m)^\s*kind:\s*(?:Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)\b",
            raw_text,
        ):
            continue

        sanitized = _sanitize_helm_yaml(raw_text)
        rel_path = yaml_path.relative_to(repo_root).as_posix()
        mod_name = _module_dir_name(infra_dir, yaml_path)
        for doc in yaml.safe_load_all(sanitized):
            if not isinstance(doc, Mapping):
                continue
            pod_spec = _extract_yaml_pod_spec(doc)
            if pod_spec is None:
                continue
            kind = str(doc["kind"])
            meta = doc.get("metadata")
            meta_name = (
                str(meta.get("name", "<unnamed>"))
                if isinstance(meta, Mapping)
                else "<unnamed>"
            )
            resource_id = f"{kind}/{meta_name}"
            for field_name, is_init in (
                ("initContainers", True),
                ("containers", False),
            ):
                raw_list = pod_spec.get(field_name)
                if not isinstance(raw_list, list):
                    continue
                for entry in raw_list:
                    if not isinstance(entry, Mapping):
                        continue
                    cname = str(entry.get("name", "<unnamed>"))
                    env_names: set[str] = set()
                    region_binding: RegionEnvBinding | None = None
                    raw_envs = entry.get("env")
                    if isinstance(raw_envs, list):
                        for env_item in raw_envs:
                            if not isinstance(env_item, Mapping):
                                continue
                            ename = env_item.get("name")
                            if isinstance(ename, str):
                                env_names.add(ename)
                                if ename == "CAGE_DEPLOYMENT_REGION":
                                    region_binding = _parse_yaml_region_binding(
                                        env_item
                                    )
                    containers.append(
                        DiscoveredContainer(
                            file_path=rel_path,
                            resource_id=resource_id,
                            workload_kind=kind,
                            container_name=cname,
                            is_init=is_init,
                            env_names=frozenset(env_names),
                            region_binding=region_binding,
                            module_dir=mod_name,
                        )
                    )
    return containers, passthrough_charts


def discover_infra_workloads(
    infra_dir: Path,
) -> tuple[list[DiscoveredContainer], set[Path], set[Path]]:
    """Enumerate every Kubernetes workload container across ``infra_dir``.

    Returns ``(containers, passthrough_chart_dirs, covered_helm_chart_dirs)``.
    """
    repo_root = infra_dir.parent
    discovered: list[DiscoveredContainer] = []
    covered_helm_charts: set[Path] = set()
    locals_cache: dict[Path, dict[str, str]] = {}

    for tf_path in sorted(
        p for p in infra_dir.rglob("*.tf") if ".terraform" not in p.parts
    ):
        clean = _strip_hcl_comments(tf_path.read_text(encoding="utf-8"))
        rel_path = tf_path.relative_to(repo_root).as_posix()
        mod_name = _module_dir_name(infra_dir, tf_path)

        # 1. Native Terraform Kubernetes workload resources
        for rm in re.finditer(
            r'(?m)^\s*resource\s+"(kubernetes_\w+)"\s+"(\w+)"\s*\{', clean
        ):
            rtype, rname = rm.group(1), rm.group(2)
            rbody, _ = _balanced_span(clean, rm.start())

            if rtype in _TF_WORKLOAD_RESOURCE_KINDS:
                wkind = _TF_WORKLOAD_RESOURCE_KINDS[rtype]
                for (
                    cname,
                    is_init,
                    env_names,
                    region_binding,
                ) in _extract_hcl_containers(rbody):
                    discovered.append(
                        DiscoveredContainer(
                            file_path=rel_path,
                            resource_id=f"{rtype}.{rname}",
                            workload_kind=wkind,
                            container_name=cname,
                            is_init=is_init,
                            env_names=env_names,
                            region_binding=region_binding,
                            module_dir=mod_name,
                        )
                    )
            elif rtype == "kubernetes_manifest":
                mm = re.search(r"\bmanifest\s*=\s*\{", rbody)
                if not mm:
                    continue
                mbody, _ = _balanced_span(rbody, mm.start())
                kind = _unquote(_top_level_attr_raw(mbody, "kind"))
                if kind not in _POD_KINDS:
                    continue
                mod_locals = locals_cache.setdefault(
                    tf_path.parent, _collect_module_locals(tf_path.parent)
                )
                for (
                    cname,
                    is_init,
                    env_names,
                    region_binding,
                ) in _extract_hcl_map_containers(mbody, mod_locals):
                    discovered.append(
                        DiscoveredContainer(
                            file_path=rel_path,
                            resource_id=f"{rtype}.{rname}",
                            workload_kind=kind,
                            container_name=cname,
                            is_init=is_init,
                            env_names=env_names,
                            region_binding=region_binding,
                            module_dir=mod_name,
                        )
                    )

        # 2. Terraform helm_release local manifest charts (e.g., gateway native sidecar)
        for hm in re.finditer(
            r'(?m)^\s*resource\s+"helm_release"\s+"(\w+)"\s*\{', clean
        ):
            hname = hm.group(1)
            hbody, _ = _balanced_span(clean, hm.start())
            lm = re.search(r"\bmanifest\s*=\s*local\.([A-Za-z_][A-Za-z0-9_]*)", hbody)
            if not lm:
                continue
            mod_locals = locals_cache.setdefault(
                tf_path.parent, _collect_module_locals(tf_path.parent)
            )
            local_name = lm.group(1)
            assert local_name in mod_locals, (
                f"{rel_path}: helm_release.{hname} references local.{local_name} "
                "which was not found in module locals"
            )
            manifest_body = mod_locals[local_name]
            kind = _unquote(_top_level_attr_raw(manifest_body, "kind"))
            if kind not in _POD_KINDS:
                continue

            chart_raw = _unquote(_top_level_attr_raw(hbody, "chart"))
            if chart_raw and "${path.module}/" in chart_raw:
                chart_rel = chart_raw.split("${path.module}/", 1)[1]
                covered_helm_charts.add((tf_path.parent / chart_rel).resolve())

            for (
                cname,
                is_init,
                env_names,
                region_binding,
            ) in _extract_hcl_map_containers(manifest_body, mod_locals):
                discovered.append(
                    DiscoveredContainer(
                        file_path=rel_path,
                        resource_id=f"helm_release.{hname}",
                        workload_kind=kind,
                        container_name=cname,
                        is_init=is_init,
                        env_names=env_names,
                        region_binding=region_binding,
                        module_dir=mod_name,
                    )
                )

    yaml_containers, passthrough_charts = _discover_yaml_workloads(infra_dir, repo_root)
    discovered.extend(yaml_containers)
    return discovered, passthrough_charts, covered_helm_charts


def _parse_gke_module_calls(
    infra_dir: Path,
) -> dict[str, list[tuple[str, dict[str, str]]]]:
    """Map ``module_dir_name -> [(instance_name, {arg: raw_rhs})]`` in ``infra/targets/gcp-gke``."""
    gke_dir = infra_dir / "targets" / "gcp-gke"
    calls: dict[str, list[tuple[str, dict[str, str]]]] = {}
    if not gke_dir.is_dir():
        return calls
    for tf_path in sorted(gke_dir.glob("*.tf")):
        clean = _strip_hcl_comments(tf_path.read_text(encoding="utf-8"))
        for mm in re.finditer(r'(?m)^\s*module\s+"(\w+)"\s*\{', clean):
            inst = mm.group(1)
            mbody, _ = _balanced_span(clean, mm.start())
            src = _unquote(_top_level_attr_raw(mbody, "source"))
            if not src or "/modules/" not in src:
                continue
            mod_name = src.rsplit("/modules/", 1)[1].strip("/")
            flat = _depth_zero_text(mbody)
            args: dict[str, str] = {}
            for am in re.finditer(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", flat, re.MULTILINE
            ):
                args[am.group(1)] = am.group(2).rstrip(",").strip()
            calls.setdefault(mod_name, []).append((inst, args))
    return calls


# ---------------------------------------------------------------------------
# Boot-contract auditor
# ---------------------------------------------------------------------------


def audit_workload_boot_contract(
    infra_dir: Path,
    exempt_containers: Mapping[ContainerKey, str] = EXEMPT_CONTAINERS,
) -> list[str]:
    """Audit every discovered Kubernetes workload container under ``infra_dir``.

    Returns a list of violation descriptions (empty list means every enforcing
    workload satisfies the ``CAGE_DEPLOYMENT_REGION`` ConfigMap boot contract).
    """
    violations: list[str] = []
    discovered, passthrough_charts, covered_helm_charts = discover_infra_workloads(
        infra_dir
    )
    gke_calls = _parse_gke_module_calls(infra_dir)

    uncovered_charts = sorted(passthrough_charts - covered_helm_charts)
    for chart in uncovered_charts:
        violations.append(
            f"Pass-through Helm manifest chart {chart} is not backed by a discovered helm_release."
        )

    discovered_by_key: dict[ContainerKey, DiscoveredContainer] = {}
    for item in discovered:
        if item.key in discovered_by_key:
            violations.append(f"Duplicate discovered container key: {item.key}")
        discovered_by_key[item.key] = item

    stale_exemptions = sorted(set(exempt_containers) - set(discovered_by_key))
    for key in stale_exemptions:
        violations.append(
            f"Stale entry in EXEMPT_CONTAINERS (no longer discovered): {key}"
        )

    for container in discovered:
        if container.key in exempt_containers:
            if (
                "CAGE_ENV" in container.env_names
                and container.key not in _ALLOWED_CAGE_ENV_EXEMPTIONS
            ):
                violations.append(
                    f"Exempt container {container.key} sets CAGE_ENV without being "
                    "registered in _ALLOWED_CAGE_ENV_EXEMPTIONS."
                )
            continue

        binding = container.region_binding
        if binding is None:
            violations.append(
                f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                "missing CAGE_DEPLOYMENT_REGION env entry (enforcing workloads crash-loop with "
                "DeploymentRegionError when omitted; POAM-2026-231)."
            )
            continue

        if binding.source_kind != "config_map_key_ref":
            violations.append(
                f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                f"CAGE_DEPLOYMENT_REGION must use config_map_key_ref/configMapKeyRef, got {binding.source_kind!r}."
            )
            continue

        if binding.key != "CAGE_DEPLOYMENT_REGION":
            violations.append(
                f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                f"CAGE_DEPLOYMENT_REGION configMapKeyRef.key must be 'CAGE_DEPLOYMENT_REGION', got {binding.key!r}."
            )

        if binding.optional is not False:
            violations.append(
                f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                f"CAGE_DEPLOYMENT_REGION configMapKeyRef must set optional = false (fail closed), got {binding.optional!r}."
            )

        ref_expr = binding.config_map_ref_expr or ""
        if container.module_dir is None:
            if ref_expr != "module.deployment_config.config_map_name":
                violations.append(
                    f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                    f"CAGE_DEPLOYMENT_REGION configMapKeyRef.name must reference "
                    f"module.deployment_config.config_map_name, got {ref_expr!r}."
                )
        else:
            vm = re.fullmatch(r"var\.([A-Za-z_][A-Za-z0-9_]*)", ref_expr)
            if not vm:
                violations.append(
                    f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                    f"module container must read ConfigMap name from an input variable (var.*), got {ref_expr!r}."
                )
                continue
            var_name = vm.group(1)
            instantiations = gke_calls.get(container.module_dir, [])
            if not instantiations:
                violations.append(
                    f"{container.file_path} ({container.resource_id}, container={container.container_name!r}): "
                    f"module {container.module_dir!r} is not instantiated in infra/targets/gcp-gke/."
                )
                continue
            for inst_name, args in instantiations:
                bound_rhs = args.get(var_name)
                if bound_rhs != "module.deployment_config.config_map_name":
                    violations.append(
                        f"infra/targets/gcp-gke module.{inst_name} ({container.module_dir}): "
                        f"argument {var_name!r} must equal module.deployment_config.config_map_name, "
                        f"got {bound_rhs!r}."
                    )

    return violations


# ---------------------------------------------------------------------------
# Repository contract tests
# ---------------------------------------------------------------------------


def test_deployment_config_module_publishes_cage_deployment_region() -> None:
    """Single source of truth: ConfigMap/cage-deployment exports CAGE_DEPLOYMENT_REGION."""
    cm_main = _strip_hcl_comments(
        (INFRA_DIR / "modules" / "deployment_config" / "main.tf").read_text(
            encoding="utf-8"
        )
    )
    cm_match = re.search(
        r'resource\s+"kubernetes_config_map(?:_v1)?"\s+"cage_deployment"\s*\{',
        cm_main,
    )
    assert cm_match is not None, "kubernetes_config_map.cage_deployment missing"
    cm_body, _ = _balanced_span(cm_main, cm_match.start())
    assert re.search(r'\bname\s*=\s*"cage-deployment"', cm_body)
    assert re.search(
        r'"CAGE_DEPLOYMENT_REGION"\s*=\s*var\.cage_deployment_region\b', cm_body
    )

    gke_calls = _parse_gke_module_calls(INFRA_DIR)
    dep_calls = gke_calls.get("deployment_config", [])
    assert len(dep_calls) == 1, (
        f"Expected 1 deployment_config module call, got {dep_calls}"
    )
    inst_name, args = dep_calls[0]
    assert inst_name == "deployment_config"
    assert args.get("cage_deployment_region") == "var.cage_deployment_region"


def test_workload_discovery_meets_non_vacuous_floors() -> None:
    """Scanner discovers every workload kind and exceeds non-vacuous container floors."""
    discovered, passthrough_charts, covered_helm_charts = discover_infra_workloads(
        INFRA_DIR
    )
    enforcing = [c for c in discovered if c.key not in EXEMPT_CONTAINERS]
    discovered_kinds = {c.workload_kind for c in discovered}

    assert len(enforcing) >= MIN_ENFORCING_CAGE_CONTAINERS, (
        f"Expected at least {MIN_ENFORCING_CAGE_CONTAINERS} enforcing CAGE containers, "
        f"discovered only {len(enforcing)}: {[c.key for c in enforcing]}"
    )
    assert len(discovered) >= MIN_TOTAL_DISCOVERED_CONTAINERS, (
        f"Expected at least {MIN_TOTAL_DISCOVERED_CONTAINERS} total containers across infra/, "
        f"discovered only {len(discovered)}: {[c.key for c in discovered]}"
    )
    assert EXPECTED_DISCOVERED_KINDS <= discovered_kinds, (
        f"Scanner missed workload kinds: expected {sorted(EXPECTED_DISCOVERED_KINDS)}, "
        f"got {sorted(discovered_kinds)}"
    )
    assert passthrough_charts <= covered_helm_charts, (
        f"Uncovered pass-through Helm chart(s): {sorted(passthrough_charts - covered_helm_charts)}"
    )
    enforcing_keys = {c.key for c in enforcing}
    assert (
        "infra/targets/gcp-gke/gateway_canary.tf",
        "kubernetes_deployment_v1.gateway_canary",
        "gateway-canary",
    ) in enforcing_keys


def test_every_enforcing_workload_injects_cage_deployment_region_from_configmap() -> (
    None
):
    """Every enforcing CAGE container in infra/ satisfies the region boot contract."""
    violations = audit_workload_boot_contract(INFRA_DIR, EXEMPT_CONTAINERS)
    assert not violations, "Workload boot-contract violations:\n- " + "\n- ".join(
        violations
    )


def test_exempt_inference_stub_imports_no_gateway_or_region_reader() -> None:
    """Mechanically verify why inference-stub is exempt from CAGE_DEPLOYMENT_REGION."""
    stub_dir = REPO_ROOT / "src" / "integrations" / "inference_stub"
    py_files = sorted(stub_dir.rglob("*.py"))
    assert py_files, f"No Python files found under {stub_dir}"

    forbidden_prefixes = ("src.gateway", "src.cage_", "src.compliance_bridge")
    for py_path in py_files:
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{py_path} imports {alias.name!r}; wire CAGE_DEPLOYMENT_REGION "
                        "into infra/modules/inference_stub/main.tf and drop its exemption."
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith(forbidden_prefixes), (
                    f"{py_path} imports from {mod!r}; wire CAGE_DEPLOYMENT_REGION "
                    "into infra/modules/inference_stub/main.tf and drop its exemption."
                )
        assert "resolve_deployment_region" not in source, py_path
        assert "CAGE_DEPLOYMENT_REGION" not in source, py_path


def test_exempt_nemo_guardrails_module_is_not_instantiated_in_gke_target() -> None:
    """If standalone nemo_guardrails is ever re-enabled in GKE, fail until region-wired."""
    gke_calls = _parse_gke_module_calls(INFRA_DIR)
    assert "nemo_guardrails" not in gke_calls, (
        "infra/modules/nemo_guardrails is instantiated in infra/targets/gcp-gke/; "
        "wire CAGE_DEPLOYMENT_REGION from module.deployment_config.config_map_name "
        "and remove its exemption from EXEMPT_CONTAINERS."
    )


def test_exempt_dpv2_reconcile_hook_imports_no_cage_modules() -> None:
    """Mechanically verify the Helm reconcile Job runs stdlib-only Python."""
    hook_path = (
        INFRA_DIR
        / "targets"
        / "gcp-gke"
        / "charts"
        / "dataplane-v2-logging"
        / "templates"
        / "reconcile-hook.yaml"
    )
    text = hook_path.read_text(encoding="utf-8")
    for forbidden in (
        "src.gateway",
        "src.cage_",
        "resolve_deployment_region",
        "CAGE_DEPLOYMENT_REGION",
        "CAGE_ENV",
    ):
        assert forbidden not in text, (
            f"{hook_path} references {forbidden!r}; wire CAGE_DEPLOYMENT_REGION "
            "and drop its exemption."
        )


# ---------------------------------------------------------------------------
# Planted-drift negative tests (proving the guard catches real regressions)
# ---------------------------------------------------------------------------


def _copy_infra(tmp_path: Path) -> Path:
    dst = tmp_path / "infra"
    shutil.copytree(
        INFRA_DIR,
        dst,
        ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"),
    )
    return dst


def test_planted_drift_dropping_region_from_gateway_canary_fails(
    tmp_path: Path,
) -> None:
    """Planted drift: omitting CAGE_DEPLOYMENT_REGION from gateway_canary.tf MUST fail."""
    infra_copy = _copy_infra(tmp_path)
    canary_tf = infra_copy / "targets" / "gcp-gke" / "gateway_canary.tf"
    original = canary_tf.read_text(encoding="utf-8")

    m = re.search(r'\s*env\s*\{\s*name\s*=\s*"CAGE_DEPLOYMENT_REGION"', original)
    assert m is not None, (
        "Expected CAGE_DEPLOYMENT_REGION env block in gateway_canary.tf"
    )
    _, end_idx = _balanced_span(original, m.start())
    drifted = original[: m.start()] + original[end_idx:]
    assert "CAGE_DEPLOYMENT_REGION" not in _strip_hcl_comments(drifted)
    canary_tf.write_text(drifted, encoding="utf-8")

    violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any(
        "gateway_canary" in v and "missing CAGE_DEPLOYMENT_REGION" in v
        for v in violations
    ), f"Expected gateway_canary missing-region violation, got: {violations}"


def test_planted_drift_optional_true_in_gateway_canary_fails(tmp_path: Path) -> None:
    """Planted drift: relaxing or omitting optional = false MUST fail."""
    infra_copy = _copy_infra(tmp_path)
    canary_tf = infra_copy / "targets" / "gcp-gke" / "gateway_canary.tf"
    original = canary_tf.read_text(encoding="utf-8")

    # 1. Relaxing optional = false -> optional = true (HCL attribute, not comment)
    drifted_true, count = re.subn(
        r"(?m)^([ \t]*optional[ \t]*=[ \t]*)false\b",
        r"\1true",
        original,
    )
    assert count == 1, f"Expected 1 HCL optional = false attribute, replaced {count}"
    canary_tf.write_text(drifted_true, encoding="utf-8")

    violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any("gateway_canary" in v and "optional = false" in v for v in violations), (
        f"Expected optional = false violation for optional=true, got: {violations}"
    )

    # 2. Removing optional altogether (omitted attribute -> optional is None)
    drifted_omitted, omitted_count = re.subn(
        r"(?m)^[ \t]*optional[ \t]*=[ \t]*false[ \t]*\n",
        "",
        original,
    )
    assert omitted_count == 1
    canary_tf.write_text(drifted_omitted, encoding="utf-8")

    omitted_violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any(
        "gateway_canary" in v and "optional = false" in v for v in omitted_violations
    ), f"Expected optional = false violation when omitted, got: {omitted_violations}"


def test_planted_drift_dropping_region_from_helm_gateway_fails(
    tmp_path: Path,
) -> None:
    """Planted drift: dropping CAGE_DEPLOYMENT_REGION from Helm-rendered gateway MUST fail."""
    infra_copy = _copy_infra(tmp_path)
    gateway_tf = infra_copy / "modules" / "gateway" / "main.tf"
    original = gateway_tf.read_text(encoding="utf-8")

    m = re.search(r'\{\s*name\s*=\s*"CAGE_DEPLOYMENT_REGION"', original)
    assert m is not None, "Expected CAGE_DEPLOYMENT_REGION map entry in gateway/main.tf"
    _, end_idx = _balanced_span(original, m.start())
    after = original[end_idx:]
    if after.startswith(","):
        after = after[1:]
    drifted = original[: m.start()] + after
    gateway_tf.write_text(drifted, encoding="utf-8")

    violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any(
        "helm_release.gateway" in v and "missing CAGE_DEPLOYMENT_REGION" in v
        for v in violations
    ), f"Expected helm_release.gateway missing-region violation, got: {violations}"


def test_planted_drift_new_unconfigured_workloads_are_dynamically_caught(
    tmp_path: Path,
) -> None:
    """Planted drift: brand-new TF Deployment, TF CronJob, and YAML Deployment MUST fail."""
    infra_copy = _copy_infra(tmp_path)

    (infra_copy / "targets" / "gcp-gke" / "planted_worker.tf").write_text(
        """resource "kubernetes_deployment_v1" "planted_worker" {
  metadata {
    name      = "planted-worker"
    namespace = module.namespace.name
  }
  spec {
    template {
      spec {
        container {
          name  = "planted-worker"
          image = var.image_digests["gateway"]
          env {
            name  = "CAGE_ENV"
            value = var.environment
          }
        }
      }
    }
  }
}
""",
        encoding="utf-8",
    )

    (infra_copy / "targets" / "gcp-gke" / "planted_cron.tf").write_text(
        """resource "kubernetes_cron_job_v1" "planted_cron" {
  metadata {
    name      = "planted-cron"
    namespace = module.namespace.name
  }
  spec {
    job_template {
      spec {
        template {
          spec {
            container {
              name  = "planted-cron"
              image = var.image_digests["gateway"]
            }
          }
        }
      }
    }
  }
}
""",
        encoding="utf-8",
    )

    helm_dir = (
        infra_copy / "targets" / "gcp-gke" / "charts" / "planted-chart" / "templates"
    )
    helm_dir.mkdir(parents=True, exist_ok=True)
    (helm_dir / "deployment.yaml").write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: planted-helm-worker
spec:
  template:
    spec:
      containers:
        - name: planted-helm-worker
          image: {{ .Values.image | quote }}
          env:
            - name: CAGE_ENV
              value: staging
""",
        encoding="utf-8",
    )

    violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any("planted_worker" in v for v in violations), violations
    assert any("planted_cron" in v for v in violations), violations
    assert any("planted-helm-worker" in v for v in violations), violations


def test_planted_drift_broken_root_module_configmap_wiring_fails(
    tmp_path: Path,
) -> None:
    """Planted drift: dropping deployment_config_map_name in gcp-gke/main.tf MUST fail."""
    infra_copy = _copy_infra(tmp_path)
    main_tf = infra_copy / "targets" / "gcp-gke" / "main.tf"
    original = main_tf.read_text(encoding="utf-8")

    mod_match = re.search(r'(?m)^\s*module\s+"reconciliation_worker"\s*\{', original)
    assert mod_match is not None
    mod_body, mod_end = _balanced_span(original, mod_match.start())
    new_mod_body = re.sub(
        r"(?m)^\s*deployment_config_map_name\s*=\s*module\.deployment_config\.config_map_name\s*\n",
        "",
        mod_body,
    )
    assert new_mod_body != mod_body
    open_brace = original.index("{", mod_match.start())
    drifted = original[: open_brace + 1] + new_mod_body + original[mod_end - 1 :]
    main_tf.write_text(drifted, encoding="utf-8")

    violations = audit_workload_boot_contract(infra_copy, EXEMPT_CONTAINERS)
    assert any(
        "module.reconciliation_worker" in v and "deployment_config_map_name" in v
        for v in violations
    ), f"Expected broken root module wiring violation, got: {violations}"


# ---------------------------------------------------------------------------
# Runtime cold-start smoke test for gateway-canary (POAM-2026-231)
# ---------------------------------------------------------------------------


def test_gateway_canary_runtime_boot_contract_in_enforcing_posture() -> None:
    """Reproduce the POAM-2026-231 staging boot failure and verify the fix cold-start."""
    probe_script = (
        "from src.gateway.canary import validate_gateway_base_url; "
        "from src.gateway.governance.plugin_loader import active_domain_config; "
        "probe = active_domain_config().canary_probe; "
        "assert probe is not None; "
        "print(probe.route, probe.action)"
    )
    base_env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(REPO_ROOT),
        "CAGE_ENV": "staging",
        "CAGE_DOMAIN": "finance",
    }

    missing = subprocess.run(
        [sys.executable, "-c", probe_script],
        cwd=REPO_ROOT,
        env=base_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert missing.returncode != 0, (
        f"Expected cold-start failure without CAGE_DEPLOYMENT_REGION, "
        f"stdout={missing.stdout!r} stderr={missing.stderr!r}"
    )
    assert "DeploymentRegionError" in missing.stderr, missing.stderr
    assert "CAGE_DEPLOYMENT_REGION" in missing.stderr, missing.stderr

    for region in ("US_FED", "EU_ECB", "APAC_MAS"):
        present = subprocess.run(
            [sys.executable, "-c", probe_script],
            cwd=REPO_ROOT,
            env={**base_env, "CAGE_DEPLOYMENT_REGION": region},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert present.returncode == 0, (
            f"Canary cold-start failed under CAGE_DEPLOYMENT_REGION={region}: "
            f"stdout={present.stdout!r} stderr={present.stderr!r}"
        )
        assert "/governance/validate-action" in present.stdout, present.stdout


def _parse_mi(quantity: str) -> int:
    q = quantity.strip()
    if q.endswith("Gi"):
        return int(q[:-2]) * 1024
    if q.endswith("Mi"):
        return int(q[:-2])
    raise AssertionError(f"Expected Mi/Gi Kubernetes memory quantity, got {quantity!r}")


def test_gateway_canary_memory_headroom_above_domain_plugin_rss() -> None:
    """gateway-canary loads active_domain_config() (~236Mi RSS); keep request >= 256Mi and limit >= 512Mi."""
    canary_tf = (INFRA_DIR / "targets" / "gcp-gke" / "gateway_canary.tf").read_text(
        encoding="utf-8"
    )
    cleaned = _strip_hcl_comments(canary_tf)
    req_match = re.search(
        r'requests\s*=\s*\{[^}]*memory\s*=\s*"([^"]+)"', cleaned, re.DOTALL
    )
    lim_match = re.search(
        r'limits\s*=\s*\{[^}]*memory\s*=\s*"([^"]+)"', cleaned, re.DOTALL
    )
    assert req_match is not None, "gateway_canary.tf missing requests.memory"
    assert lim_match is not None, "gateway_canary.tf missing limits.memory"
    req_mi = _parse_mi(req_match.group(1))
    lim_mi = _parse_mi(lim_match.group(1))
    assert req_mi >= 256, (
        f"gateway_canary requests.memory={req_mi}Mi is below its ~236Mi steady-state RSS"
    )
    assert lim_mi >= 512, (
        f"gateway_canary limits.memory={lim_mi}Mi leaves insufficient headroom above ~236Mi RSS"
    )
