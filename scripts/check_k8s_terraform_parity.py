#!/usr/bin/env python3
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
"""Kubernetes / Terraform Shadow-Manifest & Selector Parity Gate.

Enforces three structural invariants across the repository with zero waivers:

1. **No Unmanaged Shadow Manifest Directory**: ``deployment/k8s/`` must not
   exist on disk. All Kubernetes workloads, services, network policies, service
   accounts, and monitoring CRDs are provisioned exclusively from ``infra/``.
2. **Non-Orphan Selector Parity (Anti-Gaming Gate)**: Every non-empty pod
   selector declared in ``infra/`` — across ``kubernetes_network_policy_v1``
   (both ``spec.pod_selector`` and same-namespace ``ingress.from`` /
   ``egress.to`` ``pod_selector`` peers), ``FQDNNetworkPolicy`` manifests,
   ``kubernetes_service``, ``kubernetes_pod_disruption_budget_v1``, and Helm
   ``PodMonitoring`` / ``ServiceMonitor`` / Linkerd ``Server`` templates — must
   match at least one Terraform workload pod template (``Deployment``,
   ``StatefulSet``, ``DaemonSet``, ``CronJob``, or ``Job``) in ``infra/``.
   Any selector matching zero workload templates raises ``OrphanSelectorError``.
3. **Lula Name-Selector Parity (POAM-2026-219)**: Every object a Lula manifest
   rated Active in ``compliance/lula/README.md`` selects by name — through a
   ``resource-rule.name``, or a Rego test of ``metadata.name`` against a string,
   a set, or a variable iterating a set — must be an object of that kind that a
   Terraform resource, ``locals`` manifest or Helm template in ``infra/`` names,
   or a declared platform object (``PLATFORM_OBJECTS``) whose enabling Terraform
   setting resolves to its required value. A rule selecting an object nothing
   creates can never be satisfied by a cluster Terraform builds, so it raises
   ``OrphanSelectorError``, and so does any use of ``metadata.name`` this gate
   cannot read. Names resolve through variable defaults, as for the selectors
   above, and namespaces are compared for platform objects only.
"""

from __future__ import annotations

import argparse
import functools
import importlib.util
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]

# Non-vacuous corpus floors for repository-wide runs.
MIN_TF_FILES = 40
MIN_WORKLOAD_TEMPLATES = 10
MIN_NETWORK_POLICY_SELECTORS = 15
MIN_SERVICE_SELECTORS = 10
MIN_HELM_SELECTORS = 3
MIN_LULA_SELECTING_MANIFESTS = 8
MIN_LULA_NAME_SELECTORS = 20

WORKLOAD_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "kubernetes_deployment",
        "kubernetes_deployment_v1",
        "kubernetes_stateful_set",
        "kubernetes_stateful_set_v1",
        "kubernetes_daemon_set",
        "kubernetes_daemon_set_v1",
        "kubernetes_job",
        "kubernetes_job_v1",
        "kubernetes_cron_job",
        "kubernetes_cron_job_v1",
    }
)

CRONJOB_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "kubernetes_cron_job",
        "kubernetes_cron_job_v1",
    }
)

NETWORK_POLICY_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "kubernetes_network_policy",
        "kubernetes_network_policy_v1",
    }
)

SERVICE_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "kubernetes_service",
        "kubernetes_service_v1",
    }
)

PDB_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "kubernetes_pod_disruption_budget",
        "kubernetes_pod_disruption_budget_v1",
    }
)

HELM_SELECTOR_KINDS: frozenset[str] = frozenset(
    {
        "PodMonitoring",
        "ServiceMonitor",
        "Server",
        "NetworkPolicy",
        "FQDNNetworkPolicy",
    }
)

LULA_DIR_REL = Path("compliance") / "lula"

#: Terraform resource types that create one named Kubernetes object, keyed to
#: the Lula ``resource-rule.resource`` that fetches objects of that kind.
TF_RESOURCE_LULA_RESOURCES: dict[str, str] = {
    "kubernetes_config_map": "configmaps",
    "kubernetes_config_map_v1": "configmaps",
    "kubernetes_cron_job": "cronjobs",
    "kubernetes_cron_job_v1": "cronjobs",
    "kubernetes_daemon_set": "daemonsets",
    "kubernetes_daemon_set_v1": "daemonsets",
    "kubernetes_daemonset": "daemonsets",
    "kubernetes_deployment": "deployments",
    "kubernetes_deployment_v1": "deployments",
    "kubernetes_job": "jobs",
    "kubernetes_job_v1": "jobs",
    "kubernetes_network_policy": "networkpolicies",
    "kubernetes_network_policy_v1": "networkpolicies",
    "kubernetes_secret": "secrets",
    "kubernetes_secret_v1": "secrets",
    "kubernetes_service": "services",
    "kubernetes_service_v1": "services",
    "kubernetes_service_account": "serviceaccounts",
    "kubernetes_service_account_v1": "serviceaccounts",
    "kubernetes_stateful_set": "statefulsets",
    "kubernetes_stateful_set_v1": "statefulsets",
}

#: The ``kind`` of a manifest embedded in ``locals``, a ``kubernetes_manifest``
#: or a Helm template, keyed to the same Lula resource names.
MANIFEST_KIND_LULA_RESOURCES: dict[str, str] = {
    "ConfigMap": "configmaps",
    "CronJob": "cronjobs",
    "DaemonSet": "daemonsets",
    "Deployment": "deployments",
    "FQDNNetworkPolicy": "fqdnnetworkpolicies",
    "Job": "jobs",
    "NetworkPolicy": "networkpolicies",
    "PodMonitoring": "podmonitorings",
    "Secret": "secrets",
    "Service": "services",
    "ServiceAccount": "serviceaccounts",
    "ServiceMonitor": "servicemonitors",
    "StatefulSet": "statefulsets",
}


@dataclass(frozen=True)
class PlatformObject:
    """A Kubernetes object no module declares, created by the platform on a setting.

    It may be selected by an Active Lula manifest only while ``attribute`` of
    every ``resource_type`` resource in ``infra/modules/<module>`` resolves to
    ``value`` in every instantiation of that module.
    """

    resource: str
    namespace: str
    name: str
    created_by: str
    module: str
    resource_type: str
    attribute: str
    value: str


PLATFORM_OBJECTS: tuple[PlatformObject, ...] = (
    PlatformObject(
        resource="daemonsets",
        namespace="kube-system",
        name="anetd",
        created_by="GKE Dataplane V2",
        module="gcp_gke_cluster",
        resource_type="google_container_cluster",
        attribute="datapath_provider",
        value="ADVANCED_DATAPATH",
    ),
)

#: The Lula resources whose objects this gate can hold to ``infra/``.
NAMEABLE_LULA_RESOURCES: frozenset[str] = frozenset(
    {
        *TF_RESOURCE_LULA_RESOURCES.values(),
        *MANIFEST_KIND_LULA_RESOURCES.values(),
        *(obj.resource for obj in PLATFORM_OBJECTS),
    }
)


class ShadowManifestError(RuntimeError):
    """Raised when the retired ``deployment/k8s`` shadow directory exists."""


class OrphanSelectorError(RuntimeError):
    """Raised when a selector in ``infra/`` or an Active Lula manifest matches nothing."""


@dataclass(frozen=True)
class MatchExpression:
    """Kubernetes labelSelector ``matchExpressions`` predicate."""

    key: str
    operator: str
    values: tuple[str, ...] = ()

    def matches(self, labels: dict[str, str]) -> bool:
        if self.operator == "In":
            return labels.get(self.key) in self.values
        if self.operator == "NotIn":
            return labels.get(self.key) not in self.values
        if self.operator == "Exists":
            return self.key in labels
        if self.operator == "DoesNotExist":
            return self.key not in labels
        return False


@dataclass(frozen=True)
class WorkloadTemplate:
    """Resolved pod template label set for a Terraform Kubernetes workload."""

    resource_type: str
    resource_name: str
    instance_id: str
    source_file: Path
    line: int
    labels: dict[str, str]


@dataclass(frozen=True)
class SelectorRequirement:
    """A pod-targeting selector extracted from Terraform HCL or Helm YAML."""

    category: str  # "network_policy" | "service" | "pdb" | "helm"
    kind: str
    resource_id: str
    source_file: Path
    line: int
    match_labels: dict[str, str]
    match_expressions: tuple[MatchExpression, ...] = ()
    allow_match_all: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.match_labels and not self.match_expressions

    def matches(self, workload: WorkloadTemplate) -> bool:
        if self.is_empty:
            return self.allow_match_all
        for key, expected in self.match_labels.items():
            if workload.labels.get(key) != expected:
                return False
        return all(expr.matches(workload.labels) for expr in self.match_expressions)

    def format_selector(self) -> str:
        parts: list[str] = [f"{k}={v!r}" for k, v in sorted(self.match_labels.items())]
        for expr in self.match_expressions:
            parts.append(f"{expr.key} {expr.operator} {list(expr.values)}")
        return "{" + ", ".join(parts) + "}"


@dataclass(frozen=True)
class TerraformObject:
    """A named Kubernetes object that ``infra/`` creates.

    ``name`` is ``None`` when it does not resolve through variable defaults.
    """

    resource: str
    name: str | None
    origin: str


@dataclass(frozen=True)
class LulaNameSelector:
    """An object an Active Lula manifest selects by name."""

    manifest: str
    rule: str
    alias: str
    resource: str
    namespaces: tuple[str, ...]
    name: str


@dataclass(frozen=True)
class ParityReport:
    """Summary returned by ``verify_k8s_terraform_parity``."""

    tf_files_scanned: int
    helm_templates_scanned: int
    workloads: tuple[WorkloadTemplate, ...]
    selectors: tuple[SelectorRequirement, ...]
    terraform_objects: tuple[TerraformObject, ...] = ()
    lula_manifests: tuple[str, ...] = ()
    lula_selectors: tuple[LulaNameSelector, ...] = ()


@dataclass(frozen=True)
class _HclBlock:
    header: str
    body: str
    start_line: int


def _strip_hcl_comments(text: str) -> str:
    """Strip ``#`` and ``//`` comments and ``/* ... */`` blocks preserving newlines."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    escape = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, open_pos: int, source_file: Path) -> int:
    """Return index of matching ``}`` for ``{`` at *open_pos*, or fail closed."""
    depth = 0
    in_str = False
    escape = False
    for idx in range(open_pos, len(text)):
        ch = text[idx]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise OrphanSelectorError(
        f"Unbalanced HCL braces in {source_file} starting at byte {open_pos}"
    )


_TOP_BLOCK_RE = re.compile(
    r"^[ \t]*(?P<header>"
    r'(?:resource|data)\s+"[^"]+"\s+"[^"]+"'
    r'|(?:module|variable|output|check)\s+"[^"]+"'
    r'|locals|terraform|provider\s+"[^"]+"'
    r")[ \t]*\{",
    re.MULTILINE,
)

_NAMED_SUBBLOCK_RE = re.compile(
    r'^[ \t]*(?P<name>[A-Za-z0-9_-]+)(?:\s+"(?P<label>[^"]+)")?[ \t]*=[ \t]*\{'
    r'|^[ \t]*(?P<bname>[A-Za-z0-9_-]+)(?:\s+"(?P<blabel>[^"]+)")?[ \t]*\{',
    re.MULTILINE,
)


def _iter_blocks(text: str, source_file: Path, base_line: int = 1) -> list[_HclBlock]:
    """Extract immediate child HCL blocks (both ``foo {`` and ``foo = {``)."""
    blocks: list[_HclBlock] = []
    pos = 0
    while pos < len(text):
        match = _NAMED_SUBBLOCK_RE.search(text, pos)
        if not match:
            break
        brace_idx = match.end() - 1
        end_idx = _find_matching_brace(text, brace_idx, source_file)
        line_no = base_line + text.count("\n", 0, match.start())
        name = match.group("name") or match.group("bname") or ""
        label = match.group("label") or match.group("blabel")
        header = f'{name} "{label}"' if label else name
        blocks.append(
            _HclBlock(
                header=header,
                body=text[brace_idx + 1 : end_idx],
                start_line=line_no,
            )
        )
        pos = end_idx + 1
    return blocks


def _iter_top_blocks(cleaned_text: str, source_file: Path) -> list[_HclBlock]:
    blocks: list[_HclBlock] = []
    pos = 0
    while pos < len(cleaned_text):
        match = _TOP_BLOCK_RE.search(cleaned_text, pos)
        if not match:
            break
        brace_idx = match.end() - 1
        end_idx = _find_matching_brace(cleaned_text, brace_idx, source_file)
        line_no = 1 + cleaned_text.count("\n", 0, match.start())
        blocks.append(
            _HclBlock(
                header=match.group("header").strip(),
                body=cleaned_text[brace_idx + 1 : end_idx],
                start_line=line_no,
            )
        )
        pos = end_idx + 1
    return blocks


_KV_LINE_RE = re.compile(
    r'^[ \t]*(?:"(?P<qkey>[^"]+)"|(?P<ukey>[A-Za-z0-9_.-]+))[ \t]*=[ \t]*(?P<val>[^\n]+)$',
    re.MULTILINE,
)

_INTERP_VAR_RE = re.compile(r"\$\{var\.([A-Za-z0-9_]+)\}")
_DIRECT_VAR_RE = re.compile(r"^var\.([A-Za-z0-9_]+)$")


def _resolve_hcl_scalar(raw_val: str, var_env: dict[str, str]) -> str | None:
    """Resolve an HCL string or boolean literal or a ``var.<name>`` reference."""
    val = raw_val.strip().rstrip(",")
    direct = _DIRECT_VAR_RE.match(val)
    if direct:
        return var_env.get(direct.group(1), f"<unresolved:var.{direct.group(1)}>")
    if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        inner = val[1:-1]
        return _INTERP_VAR_RE.sub(
            lambda m: var_env.get(m.group(1), f"<unresolved:var.{m.group(1)}>"),
            inner,
        )
    if val in ("true", "false"):
        return val
    return None


def _mask_nested_blocks(body: str) -> str:
    """Blank nested ``{...}`` blocks so their keys do not bleed into the outer map."""
    masked: list[str] = []
    depth = 0
    in_str = False
    escape = False
    for ch in body:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            if depth == 0:
                masked.append(ch)
            continue
        if ch == '"':
            in_str = True
            if depth == 0:
                masked.append(ch)
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            masked.append(ch)
        elif ch == "\n":
            masked.append("\n")
    return "".join(masked)


def _parse_kv_map(body: str, var_env: dict[str, str]) -> dict[str, str]:
    """Parse top-level ``key = value`` scalar pairs inside an HCL map block."""
    result: dict[str, str] = {}
    for m in _KV_LINE_RE.finditer(_mask_nested_blocks(body)):
        key = m.group("qkey") or m.group("ukey")
        resolved = _resolve_hcl_scalar(m.group("val"), var_env)
        if key and resolved is not None:
            result[key] = resolved
    return result


def _raw_hcl_attribute(body: str, attribute: str) -> str | None:
    """Return the unresolved expression assigned to a top-level ``attribute``."""
    for m in _KV_LINE_RE.finditer(_mask_nested_blocks(body)):
        if (m.group("qkey") or m.group("ukey")) == attribute:
            return m.group("val").strip()
    return None


def _parse_string_list(raw_val: str, var_env: dict[str, str]) -> tuple[str, ...]:
    items = re.findall(r'"([^"]*)"', raw_val)
    return tuple(
        _INTERP_VAR_RE.sub(
            lambda m: var_env.get(m.group(1), f"<unresolved:var.{m.group(1)}>"),
            item,
        )
        for item in items
    )


def _find_child_blocks(
    body: str, name: str, source_file: Path, base_line: int
) -> list[_HclBlock]:
    return [
        b
        for b in _iter_blocks(body, source_file, base_line)
        if b.header == name or b.header.startswith(f'{name} "')
    ]


def _parse_label_selector_block(
    selector_block: _HclBlock,
    source_file: Path,
    var_env: dict[str, str],
) -> tuple[dict[str, str], tuple[MatchExpression, ...]]:
    """Parse ``match_labels``/``matchLabels`` and ``match_expressions``/``matchExpressions``."""
    match_labels: dict[str, str] = {}
    for ml_name in ("match_labels", "matchLabels"):
        for ml_block in _find_child_blocks(
            selector_block.body, ml_name, source_file, selector_block.start_line
        ):
            match_labels.update(_parse_kv_map(ml_block.body, var_env))

    expressions: list[MatchExpression] = []
    expr_bodies: list[str] = []
    for me_name in ("match_expressions", "matchExpressions"):
        for me_block in _find_child_blocks(
            selector_block.body, me_name, source_file, selector_block.start_line
        ):
            expr_bodies.append(me_block.body)
        for list_match in re.finditer(rf"\b{me_name}\s*=\s*\[", selector_block.body):
            pos = list_match.end()
            while pos < len(selector_block.body):
                brace_pos = selector_block.body.find("{", pos)
                close_bracket = selector_block.body.find("]", pos)
                if brace_pos == -1 or (
                    close_bracket != -1 and close_bracket < brace_pos
                ):
                    break
                end_brace = _find_matching_brace(
                    selector_block.body, brace_pos, source_file
                )
                expr_bodies.append(selector_block.body[brace_pos + 1 : end_brace])
                pos = end_brace + 1

    for me_body in expr_bodies:
        kv = _parse_kv_map(me_body, var_env)
        val_match = re.search(r"values\s*=\s*(\[[^\]]*\])", me_body)
        vals = _parse_string_list(val_match.group(1), var_env) if val_match else ()
        if "key" in kv and "operator" in kv:
            expressions.append(
                MatchExpression(
                    key=kv["key"],
                    operator=kv["operator"],
                    values=vals,
                )
            )
    return match_labels, tuple(expressions)


def _extract_module_variable_defaults(module_dir: Path) -> dict[str, str]:
    """Extract string ``default`` values from ``variable`` blocks in *module_dir*."""
    defaults: dict[str, str] = {}
    for tf_file in sorted(module_dir.glob("*.tf")):
        cleaned = _strip_hcl_comments(tf_file.read_text(encoding="utf-8"))
        for block in _iter_top_blocks(cleaned, tf_file):
            m = re.match(r'^variable\s+"([^"]+)"$', block.header)
            if not m:
                continue
            var_name = m.group(1)
            kv = _parse_kv_map(block.body, {})
            if "default" in kv:
                defaults[var_name] = kv["default"]
    return defaults


def _discover_module_instances(
    infra_dir: Path,
) -> dict[Path, list[tuple[str, dict[str, str]]]]:
    """Map each module directory in ``infra/modules/`` to ``(instance_name, var_env)``."""
    modules_root = infra_dir / "modules"
    targets_root = infra_dir / "targets"
    defaults_by_dir: dict[Path, dict[str, str]] = {}
    if modules_root.is_dir():
        for mod_dir in sorted(p for p in modules_root.iterdir() if p.is_dir()):
            defaults_by_dir[mod_dir.resolve()] = _extract_module_variable_defaults(
                mod_dir
            )

    instances: dict[Path, list[tuple[str, dict[str, str]]]] = {
        mod_dir: [] for mod_dir in defaults_by_dir
    }

    if targets_root.is_dir():
        target_tf_files = [
            p for p in sorted(targets_root.rglob("*.tf")) if ".terraform" not in p.parts
        ]
        for tf_file in target_tf_files:
            target_defaults = _extract_module_variable_defaults(tf_file.parent)
            cleaned = _strip_hcl_comments(tf_file.read_text(encoding="utf-8"))
            for block in _iter_top_blocks(cleaned, tf_file):
                m = re.match(r'^module\s+"([^"]+)"$', block.header)
                if not m:
                    continue
                call_name = m.group(1)
                kv = _parse_kv_map(block.body, target_defaults)
                src = kv.get("source")
                if not src or not src.startswith("."):
                    continue
                mod_dir = (tf_file.parent / src).resolve()
                base_env = dict(defaults_by_dir.get(mod_dir, {}))
                for k, v in kv.items():
                    if k != "source":
                        base_env[k] = v
                instances.setdefault(mod_dir, []).append(
                    (f"module.{call_name}", base_env)
                )

    # Any module not instantiated from infra/targets/ is still audited using its defaults.
    for mod_dir, call_list in instances.items():
        if not call_list:
            call_list.append((f"module.{mod_dir.name}", dict(defaults_by_dir[mod_dir])))

    return instances


def _extract_workload_labels(
    res_type: str,
    block: _HclBlock,
    source_file: Path,
    var_env: dict[str, str],
) -> dict[str, str] | None:
    spec_blocks = _find_child_blocks(block.body, "spec", source_file, block.start_line)
    if not spec_blocks:
        return None
    parent = spec_blocks[0]
    if res_type in CRONJOB_RESOURCE_TYPES:
        jt_blocks = _find_child_blocks(
            parent.body, "job_template", source_file, parent.start_line
        )
        if not jt_blocks:
            return None
        jt_spec = _find_child_blocks(
            jt_blocks[0].body, "spec", source_file, jt_blocks[0].start_line
        )
        if not jt_spec:
            return None
        parent = jt_spec[0]

    tmpl_blocks = _find_child_blocks(
        parent.body, "template", source_file, parent.start_line
    )
    if not tmpl_blocks:
        return None
    meta_blocks = _find_child_blocks(
        tmpl_blocks[0].body, "metadata", source_file, tmpl_blocks[0].start_line
    )
    if not meta_blocks:
        return None
    label_blocks = _find_child_blocks(
        meta_blocks[0].body, "labels", source_file, meta_blocks[0].start_line
    )
    if not label_blocks:
        return None
    return _parse_kv_map(label_blocks[0].body, var_env)


def _extract_tf_items_from_file(
    tf_file: Path,
    instance_prefix: str,
    var_env: dict[str, str],
) -> tuple[list[WorkloadTemplate], list[SelectorRequirement]]:
    workloads: list[WorkloadTemplate] = []
    selectors: list[SelectorRequirement] = []
    cleaned = _strip_hcl_comments(tf_file.read_text(encoding="utf-8"))

    for block in _iter_top_blocks(cleaned, tf_file):
        res_match = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"$', block.header)
        if res_match:
            res_type, res_name = res_match.group(1), res_match.group(2)
            fq_id = (
                f"{instance_prefix}.{res_type}.{res_name}"
                if instance_prefix
                else f"{res_type}.{res_name}"
            )

            if res_type in WORKLOAD_RESOURCE_TYPES:
                labels = _extract_workload_labels(res_type, block, tf_file, var_env)
                if not labels:
                    raise OrphanSelectorError(
                        f"Workload {fq_id} at {tf_file}:{block.start_line} declares no "
                        f"template.metadata.labels"
                    )
                workloads.append(
                    WorkloadTemplate(
                        resource_type=res_type,
                        resource_name=res_name,
                        instance_id=fq_id,
                        source_file=tf_file,
                        line=block.start_line,
                        labels=labels,
                    )
                )

            elif res_type in NETWORK_POLICY_RESOURCE_TYPES:
                spec_blocks = _find_child_blocks(
                    block.body, "spec", tf_file, block.start_line
                )
                if not spec_blocks:
                    raise OrphanSelectorError(
                        f"NetworkPolicy {fq_id} at {tf_file}:{block.start_line} has no spec block"
                    )
                spec = spec_blocks[0]
                ps_blocks = _find_child_blocks(
                    spec.body, "pod_selector", tf_file, spec.start_line
                )
                if not ps_blocks:
                    raise OrphanSelectorError(
                        f"NetworkPolicy {fq_id} at {tf_file}:{block.start_line} has no spec.pod_selector"
                    )
                ml, me = _parse_label_selector_block(ps_blocks[0], tf_file, var_env)
                selectors.append(
                    SelectorRequirement(
                        category="network_policy",
                        kind=res_type,
                        resource_id=f"{fq_id}.spec.pod_selector",
                        source_file=tf_file,
                        line=ps_blocks[0].start_line,
                        match_labels=ml,
                        match_expressions=me,
                        allow_match_all=True,
                    )
                )

                # Same-namespace ingress.from / egress.to pod_selector peers
                # (those without namespace_selector) must also match a real pod template.
                for rule_dir, peer_key in (("ingress", "from"), ("egress", "to")):
                    for rule_idx, rule_blk in enumerate(
                        _find_child_blocks(
                            spec.body, rule_dir, tf_file, spec.start_line
                        )
                    ):
                        for peer_idx, peer_blk in enumerate(
                            _find_child_blocks(
                                rule_blk.body, peer_key, tf_file, rule_blk.start_line
                            )
                        ):
                            ns_peers = _find_child_blocks(
                                peer_blk.body,
                                "namespace_selector",
                                tf_file,
                                peer_blk.start_line,
                            )
                            if ns_peers:
                                continue
                            peer_ps = _find_child_blocks(
                                peer_blk.body,
                                "pod_selector",
                                tf_file,
                                peer_blk.start_line,
                            )
                            for ps in peer_ps:
                                p_ml, p_me = _parse_label_selector_block(
                                    ps, tf_file, var_env
                                )
                                selectors.append(
                                    SelectorRequirement(
                                        category="network_policy",
                                        kind=f"{res_type}:peer",
                                        resource_id=(
                                            f"{fq_id}.spec.{rule_dir}[{rule_idx}]"
                                            f".{peer_key}[{peer_idx}].pod_selector"
                                        ),
                                        source_file=tf_file,
                                        line=ps.start_line,
                                        match_labels=p_ml,
                                        match_expressions=p_me,
                                        allow_match_all=True,
                                    )
                                )

            elif res_type in SERVICE_RESOURCE_TYPES:
                spec_blocks = _find_child_blocks(
                    block.body, "spec", tf_file, block.start_line
                )
                if spec_blocks:
                    sel_blocks = _find_child_blocks(
                        spec_blocks[0].body,
                        "selector",
                        tf_file,
                        spec_blocks[0].start_line,
                    )
                    if sel_blocks:
                        sel_labels = _parse_kv_map(sel_blocks[0].body, var_env)
                        selectors.append(
                            SelectorRequirement(
                                category="service",
                                kind=res_type,
                                resource_id=f"{fq_id}.spec.selector",
                                source_file=tf_file,
                                line=sel_blocks[0].start_line,
                                match_labels=sel_labels,
                                allow_match_all=False,
                            )
                        )

            elif res_type in PDB_RESOURCE_TYPES:
                spec_blocks = _find_child_blocks(
                    block.body, "spec", tf_file, block.start_line
                )
                if spec_blocks:
                    sel_blocks = _find_child_blocks(
                        spec_blocks[0].body,
                        "selector",
                        tf_file,
                        spec_blocks[0].start_line,
                    )
                    if sel_blocks:
                        ml, me = _parse_label_selector_block(
                            sel_blocks[0], tf_file, var_env
                        )
                        selectors.append(
                            SelectorRequirement(
                                category="pdb",
                                kind=res_type,
                                resource_id=f"{fq_id}.spec.selector",
                                source_file=tf_file,
                                line=sel_blocks[0].start_line,
                                match_labels=ml,
                                match_expressions=me,
                                allow_match_all=False,
                            )
                        )

        elif block.header == "locals":
            # Inspect embedded workload manifests (e.g., Deployment rendered via
            # local Helm chart for native sidecars) and FQDNNetworkPolicy maps.
            for outer in _iter_blocks(block.body, tf_file, block.start_line):
                outer_kv = _parse_kv_map(outer.body, var_env)
                outer_kind = outer_kv.get("kind")
                if outer_kind in {
                    "Deployment",
                    "StatefulSet",
                    "DaemonSet",
                    "Job",
                    "CronJob",
                }:
                    pseudo_type = (
                        "kubernetes_cron_job"
                        if outer_kind == "CronJob"
                        else "kubernetes_deployment"
                    )
                    labels = _extract_workload_labels(
                        pseudo_type, outer, tf_file, var_env
                    )
                    if not labels:
                        raise OrphanSelectorError(
                            f"Workload local.{outer.header} at {tf_file}:{outer.start_line} "
                            f"declares no template.metadata.labels"
                        )
                    workloads.append(
                        WorkloadTemplate(
                            resource_type=f"local:{outer_kind}",
                            resource_name=outer.header,
                            instance_id=(
                                f"{instance_prefix}.local.{outer.header}"
                                if instance_prefix
                                else f"local.{outer.header}"
                            ),
                            source_file=tf_file,
                            line=outer.start_line,
                            labels=labels,
                        )
                    )
                    continue
                for entry in _iter_blocks(outer.body, tf_file, outer.start_line):
                    entry_kv = _parse_kv_map(entry.body, var_env)
                    if entry_kv.get("kind") != "FQDNNetworkPolicy":
                        continue
                    spec_blocks = _find_child_blocks(
                        entry.body, "spec", tf_file, entry.start_line
                    )
                    if not spec_blocks:
                        continue
                    ps_blocks = _find_child_blocks(
                        spec_blocks[0].body,
                        "podSelector",
                        tf_file,
                        spec_blocks[0].start_line,
                    )
                    if not ps_blocks:
                        continue
                    ml, me = _parse_label_selector_block(ps_blocks[0], tf_file, var_env)
                    selectors.append(
                        SelectorRequirement(
                            category="network_policy",
                            kind="FQDNNetworkPolicy",
                            resource_id=f"local.{outer.header}.{entry.header}.spec.podSelector",
                            source_file=tf_file,
                            line=ps_blocks[0].start_line,
                            match_labels=ml,
                            match_expressions=me,
                            allow_match_all=False,
                        )
                    )

    return workloads, selectors


_HELM_CTRL_LINE_RE = re.compile(r"^\s*\{\{-?.*-?\}\}\s*$")
_HELM_INLINE_EXPR_RE = re.compile(r"\{\{-?.*?-?\}\}")


def _sanitize_helm_template(raw_yaml: str) -> str:
    """Replace Helm ``{{ ... }}`` directives with valid YAML placeholders."""
    lines: list[str] = []
    for line in raw_yaml.splitlines():
        if _HELM_CTRL_LINE_RE.match(line):
            lines.append("")
            continue
        lines.append(_HELM_INLINE_EXPR_RE.sub('"helm-placeholder"', line))
    return "\n".join(lines)


def _extract_helm_selectors(template_file: Path) -> list[SelectorRequirement]:
    """Extract pod selectors from Helm templates (PodMonitoring, ServiceMonitor, Server)."""
    sanitized = _sanitize_helm_template(template_file.read_text(encoding="utf-8"))
    try:
        docs = list(yaml.safe_load_all(sanitized))
    except yaml.YAMLError as exc:
        raise OrphanSelectorError(
            f"Failed to parse Helm template {template_file}: {exc}"
        ) from exc

    # Service-mesh charts under infra/modules/service_mesh/charts/ target
    # kube-system / linkerd CNI infrastructure rather than governance-stack pods;
    # inspect every governance workload chart and fail closed on any selector.
    out: list[SelectorRequirement] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind not in HELM_SELECTOR_KINDS:
            continue
        metadata = doc.get("metadata") or {}
        name = metadata.get("name", "<unnamed>")
        namespace = metadata.get("namespace", "")
        if namespace in ("linkerd", "linkerd-cni", "kube-system"):
            continue

        spec = doc.get("spec")
        if not isinstance(spec, dict):
            continue

        sel_obj: Any = None
        sel_field = ""
        for candidate in ("podSelector", "selector"):
            if candidate in spec and isinstance(spec[candidate], dict):
                sel_obj = spec[candidate]
                sel_field = candidate
                break
        if sel_obj is None:
            continue

        raw_ml = sel_obj.get("matchLabels")
        match_labels: dict[str, str] = {}
        if isinstance(raw_ml, dict):
            match_labels = {str(k): str(v) for k, v in raw_ml.items()}
        elif "matchExpressions" not in sel_obj:
            match_labels = {
                str(k): str(v)
                for k, v in sel_obj.items()
                if isinstance(v, (str, int, bool))
            }

        expressions: list[MatchExpression] = []
        raw_me = sel_obj.get("matchExpressions")
        if isinstance(raw_me, list):
            for item in raw_me:
                if isinstance(item, dict) and "key" in item and "operator" in item:
                    vals = tuple(str(v) for v in (item.get("values") or []))
                    expressions.append(
                        MatchExpression(
                            key=str(item["key"]),
                            operator=str(item["operator"]),
                            values=vals,
                        )
                    )

        # Skip cluster-admission policies whose selector checks mesh injection annotations/labels
        # via NotIn/DoesNotExist across arbitrary namespaces (e.g. linkerd.io/inject).
        if not match_labels and any(
            e.key.startswith("linkerd.io/") for e in expressions
        ):
            continue

        out.append(
            SelectorRequirement(
                category="helm",
                kind=str(kind),
                resource_id=f"{kind}/{name}.spec.{sel_field}",
                source_file=template_file,
                line=1,
                match_labels=match_labels,
                match_expressions=tuple(expressions),
                allow_match_all=(kind == "NetworkPolicy"),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Invariant 3: objects infra/ creates by name, and the names Lula selects
# ---------------------------------------------------------------------------


def _metadata_name(
    block: _HclBlock, source_file: Path, var_env: dict[str, str]
) -> str | None:
    """Return the resolved ``metadata.name`` of *block*, or ``None``."""
    metas = _find_child_blocks(block.body, "metadata", source_file, block.start_line)
    if not metas:
        return None
    name = _parse_kv_map(metas[0].body, var_env).get("name")
    if not name or "<unresolved:" in name:
        return None
    return name


def _manifest_object(
    block: _HclBlock, source_file: Path, var_env: dict[str, str], origin: str
) -> TerraformObject | None:
    """Return the object an embedded manifest map declares, if it declares one."""
    kv = _parse_kv_map(block.body, var_env)
    resource = MANIFEST_KIND_LULA_RESOURCES.get(kv.get("kind", ""))
    if resource is None or "apiVersion" not in kv:
        return None
    return TerraformObject(
        resource=resource,
        name=_metadata_name(block, source_file, var_env),
        origin=origin,
    )


def _extract_tf_objects_from_file(
    tf_file: Path, instance_prefix: str, var_env: dict[str, str]
) -> list[TerraformObject]:
    """Return the named Kubernetes objects one ``.tf`` file's resources and locals create."""
    objects: list[TerraformObject] = []
    prefix = f"{instance_prefix}." if instance_prefix else ""
    cleaned = _strip_hcl_comments(tf_file.read_text(encoding="utf-8"))
    for block in _iter_top_blocks(cleaned, tf_file):
        res_match = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"$', block.header)
        if res_match:
            res_type, res_name = res_match.groups()
            origin = f"{prefix}{res_type}.{res_name}"
            if res_type in TF_RESOURCE_LULA_RESOURCES:
                objects.append(
                    TerraformObject(
                        resource=TF_RESOURCE_LULA_RESOURCES[res_type],
                        name=_metadata_name(block, tf_file, var_env),
                        origin=origin,
                    )
                )
            elif res_type == "kubernetes_manifest":
                for manifest in _find_child_blocks(
                    block.body, "manifest", tf_file, block.start_line
                ):
                    obj = _manifest_object(manifest, tf_file, var_env, origin)
                    if obj is not None:
                        objects.append(obj)
        elif block.header == "locals":
            for outer in _iter_blocks(block.body, tf_file, block.start_line):
                origin = f"{prefix}local.{outer.header}"
                obj = _manifest_object(outer, tf_file, var_env, origin)
                if obj is not None:
                    objects.append(obj)
                    continue
                for entry in _iter_blocks(outer.body, tf_file, outer.start_line):
                    nested = _manifest_object(
                        entry, tf_file, var_env, f"{origin}.{entry.header}"
                    )
                    if nested is not None:
                        objects.append(nested)
    return objects


def _extract_helm_objects(template_file: Path) -> list[TerraformObject]:
    """Return the named objects a Helm template under ``infra/`` renders."""
    sanitized = _sanitize_helm_template(template_file.read_text(encoding="utf-8"))
    try:
        docs = list(yaml.safe_load_all(sanitized))
    except yaml.YAMLError as exc:
        raise OrphanSelectorError(
            f"Failed to parse Helm template {template_file}: {exc}"
        ) from exc
    objects: list[TerraformObject] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        resource = MANIFEST_KIND_LULA_RESOURCES.get(str(doc.get("kind")))
        if resource is None:
            continue
        metadata = doc.get("metadata")
        name = metadata.get("name") if isinstance(metadata, dict) else None
        literal = isinstance(name, str) and name and "helm-placeholder" not in name
        objects.append(
            TerraformObject(
                resource=resource,
                name=name if literal else None,
                origin=template_file.as_posix(),
            )
        )
    return objects


_TERNARY_ON_VAR_RE = re.compile(
    r'^var\.([A-Za-z0-9_]+)\s*\?\s*"([^"]*)"\s*:\s*"([^"]*)"$'
)


def _resolve_hcl_setting(raw: str, var_env: dict[str, str]) -> str | None:
    """Resolve a literal, a ``var.<name>``, or ``var.<flag> ? "a" : "b"``."""
    ternary = _TERNARY_ON_VAR_RE.match(raw.strip())
    if ternary is None:
        return _resolve_hcl_scalar(raw, var_env)
    flag = var_env.get(ternary.group(1))
    if flag == "true":
        return ternary.group(2)
    if flag == "false":
        return ternary.group(3)
    return None


def _platform_object_shortfall(
    infra_dir: Path,
    module_instances: Mapping[Path, list[tuple[str, dict[str, str]]]],
    obj: PlatformObject,
) -> str | None:
    """Return why Terraform does not enable *obj*, or ``None`` if it does everywhere."""
    mod_dir = (infra_dir / "modules" / obj.module).resolve()
    header_re = re.compile(rf'^resource\s+"{re.escape(obj.resource_type)}"\s+"[^"]+"$')
    expressions: list[str] = []
    for tf_file in sorted(mod_dir.glob("*.tf")):
        cleaned = _strip_hcl_comments(tf_file.read_text(encoding="utf-8"))
        for block in _iter_top_blocks(cleaned, tf_file):
            if header_re.match(block.header):
                raw = _raw_hcl_attribute(block.body, obj.attribute)
                if raw is not None:
                    expressions.append(raw)
    if not expressions:
        return (
            f"no {obj.resource_type} in infra/modules/{obj.module} sets {obj.attribute}"
        )
    for instance_id, var_env in module_instances.get(mod_dir, []):
        for raw in expressions:
            value = _resolve_hcl_setting(raw, var_env)
            if value != obj.value:
                return (
                    f"{instance_id} resolves {obj.attribute} = {raw} to {value!r}, "
                    f"not {obj.value!r}"
                )
    return None


@functools.cache
def _sibling_script(name: str) -> ModuleType:
    """Load ``scripts/<name>.py`` as ``check_poam_lula_divergence.py`` loads siblings."""
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_k8s_parity_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class LulaAlias:
    """What ``input["<alias>"]`` holds: the objects one ``resource-rule`` fetches."""

    resource: str
    namespaces: tuple[str, ...]


@dataclass(frozen=True)
class _RegoRule:
    name: str
    params: tuple[str, ...]
    text: str


_REGO_STRING = r'"(?:[^"\\]|\\.)*"'
_REGO_SET = r"\{[^{}]*\}"
_REGO_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_REGO_INPUT = r'input\[\s*"(?P<input_alias>[^"]+)"\s*\]'
_REGO_LITERAL_RE = re.compile(rf"{_REGO_STRING}|`[^`]*`")

# ``some d in input["a"]``, ``every _, d in input["a"]`` and ``d := input["a"][_]``.
_INPUT_BINDING_RES: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\b(?:some|every)\s+(?:{_REGO_IDENT}\s*,\s*)?(?P<var>{_REGO_IDENT})"
        rf"\s+in\s+{_REGO_INPUT}"
    ),
    re.compile(
        rf"(?<![.\w])(?P<var>{_REGO_IDENT})\s*:?=\s*{_REGO_INPUT}\s*\[\s*_\s*\]"
    ),
)
_SET_DEFINITION_RE = re.compile(
    rf"(?m)^(?P<name>{_REGO_IDENT})\s*:?=\s*(?P<set>{_REGO_SET})"
)
# ``every n in {"a", "b"}`` or ``some n in named_set`` (never ``in input[...]``).
_ITERATION_RE = re.compile(
    rf"\b(?:some|every)\s+(?P<var>{_REGO_IDENT})\s+in\s+"
    rf"(?P<src>{_REGO_SET}|{_REGO_IDENT}\b(?!\s*\[))"
)
_NAME_REF_RE = re.compile(
    rf"(?:(?<![.\w])(?P<var>{_REGO_IDENT})|{_REGO_INPUT}(?:\[\s*_\s*\])?)"
    r"\.metadata\.name\b"
)
# Every use, so one the reference pattern does not attribute fails closed.
_ANY_NAME_USE_RE = re.compile(r"\.metadata\.name\b")
_NAME_TEST_AFTER_RE = re.compile(
    rf"\s*(?P<op>==|!=|\bin\b)\s*(?P<rhs>{_REGO_STRING}|{_REGO_SET}|{_REGO_IDENT}\b)"
)
_NAME_TEST_BEFORE_RE = re.compile(rf"(?P<lit>{_REGO_STRING})\s*(?P<op>==|!=)\s*$")
_SET_LOOKUP_BEFORE_RE = re.compile(rf"(?<![.\w])(?P<set>{_REGO_IDENT})\[\s*$")
_RULE_HEAD_RE = re.compile(
    rf"^(?:default\s+)?(?P<name>{_REGO_IDENT})(?:\((?P<params>[^)]*)\))?"
)


def _strip_rego_comments(rego: str) -> str:
    """Drop ``#`` comments outside string literals, keeping line structure."""
    out: list[str] = []
    i, n = 0, len(rego)
    while i < n:
        ch = rego[i]
        if ch == '"':
            j = i + 1
            while j < n and rego[j] != '"':
                j += 2 if rego[j] == "\\" else 1
            out.append(rego[i : j + 1])
            i = j + 1
        elif ch == "`":
            j = rego.find("`", i + 1)
            j = n - 1 if j == -1 else j
            out.append(rego[i : j + 1])
            i = j + 1
        elif ch == "#":
            j = rego.find("\n", i)
            i = n if j == -1 else j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _rego_rules(code: str) -> list[_RegoRule]:
    """Split comment-free Rego into its top-level rules, in source order."""
    rules: list[_RegoRule] = []
    current: list[str] = []

    def flush() -> None:
        head = _RULE_HEAD_RE.match(current[0]) if current else None
        if head is not None:
            params = tuple(
                p.strip() for p in (head.group("params") or "").split(",") if p.strip()
            )
            rules.append(_RegoRule(head.group("name"), params, "\n".join(current)))
        current.clear()

    for line in code.splitlines():
        starts_rule = (
            bool(line)
            and not line[0].isspace()
            and not line.startswith(("}", "]", ")", "package ", "import "))
        )
        if starts_rule:
            flush()
        if starts_rule or current:
            current.append(line)
    flush()
    return rules


def _rego_string(literal: str) -> str | None:
    """Decode a double-quoted Rego string literal, or ``None`` if it is malformed."""
    try:
        value = json.loads(literal)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, str) else None


def _set_members(literal: str) -> tuple[str, ...] | None:
    """Return the members of a Rego set literal of strings, or ``None``."""
    inner = literal.strip()[1:-1]
    if re.sub(_REGO_STRING, "", inner).replace(",", "").strip():
        return None
    members = [_rego_string(s) for s in re.findall(_REGO_STRING, inner)]
    if any(member is None for member in members):
        return None
    return tuple(member for member in members if member is not None)


def _input_bindings(text: str) -> dict[str, set[str]]:
    bindings: dict[str, set[str]] = {}
    for pattern in _INPUT_BINDING_RES:
        for m in pattern.finditer(text):
            bindings.setdefault(m["var"], set()).add(m["input_alias"])
    return bindings


def _iterations(
    text: str, named_sets: Mapping[str, tuple[str, ...] | None]
) -> dict[str, tuple[str, ...] | None]:
    iterations: dict[str, tuple[str, ...] | None] = {}
    for m in _ITERATION_RE.finditer(text):
        src = m["src"]
        iterations[m["var"]] = (
            _set_members(src) if src.startswith("{") else named_sets.get(src)
        )
    return iterations


def _tested_names(
    text: str,
    ref: re.Match[str],
    named_sets: Mapping[str, tuple[str, ...] | None],
    iterations: Mapping[str, tuple[str, ...] | None],
) -> tuple[str, ...] | None:
    """Return the names one ``metadata.name`` reference is tested against.

    ``()`` for an exclusion (``!=``), which selects nothing, and ``None`` for a
    use this gate cannot read.
    """
    after = _NAME_TEST_AFTER_RE.match(text, ref.end())
    if after is not None:
        op, rhs = after["op"], after["rhs"]
        if op == "!=":
            return ()
        if rhs.startswith('"'):
            literal = _rego_string(rhs)
            return (literal,) if op == "==" and literal is not None else None
        if rhs.startswith("{"):
            return _set_members(rhs) if op == "in" else None
        return iterations.get(rhs) if op == "==" else named_sets.get(rhs)
    before = text[: ref.start()]
    reversed_test = _NAME_TEST_BEFORE_RE.search(before)
    if reversed_test is not None:
        if reversed_test["op"] == "!=":
            return ()
        literal = _rego_string(reversed_test["lit"])
        return (literal,) if literal is not None else None
    lookup = _SET_LOOKUP_BEFORE_RE.search(before)
    if lookup is not None and re.match(r"\s*\]", text[ref.end() :]):
        return named_sets.get(lookup["set"])
    return None


def _call_sites(
    rules: list[_RegoRule], function: _RegoRule
) -> tuple[list[tuple[_RegoRule, tuple[str, ...]]], list[str]]:
    """Return each call of *function* with its arguments, and each call it cannot read.

    A call whose argument list nests parentheses cannot be split into arguments,
    so it is reported rather than skipped: skipping it would leave that caller's
    argument unchecked while the readable calls passed.
    """
    name_re = re.compile(rf"(?<![.\w]){re.escape(function.name)}\s*\(")
    call_re = re.compile(
        rf"(?<![.\w]){re.escape(function.name)}\s*\(\s*(?P<args>[^()]*)\)"
    )
    calls: list[tuple[_RegoRule, tuple[str, ...]]] = []
    unreadable: list[str] = []
    for rule in rules:
        literals = [m.span() for m in _REGO_LITERAL_RE.finditer(rule.text)]
        for m in name_re.finditer(rule.text):
            if rule.name == function.name and m.start() == 0:
                continue  # a head of the function itself
            if any(start <= m.start() < end for start, end in literals):
                continue
            call = call_re.match(rule.text, m.start())
            if call is None:
                line_end = rule.text.find("\n", m.start())
                snippet = rule.text[m.start() : None if line_end == -1 else line_end]
                unreadable.append(
                    f"rule {rule.name} calls {function.name}() at {snippet.strip()!r}, "
                    "whose arguments this gate cannot read"
                )
                continue
            calls.append((rule, tuple(a.strip() for a in call["args"].split(","))))
    return calls, unreadable


def rego_name_selectors(
    rego: str, aliases: Mapping[str, LulaAlias], manifest: str
) -> list[LulaNameSelector]:
    """Return every object *rego* selects by ``metadata.name``.

    Recognised forms, where ``x`` is bound by ``some x in input["a"]``,
    ``every x in input["a"]`` or ``x := input["a"][_]`` (directly, or as the
    argument of a function whose parameter is tested): ``x.metadata.name ==``
    a string, a variable iterating a set literal or a named set of strings;
    ``x.metadata.name in`` a set literal or a named set; ``"lit" ==
    x.metadata.name``; ``named_set[x.metadata.name]``; and the same tests on
    ``input["a"].metadata.name``. ``!=`` excludes and selects nothing. Any other
    use raises ``OrphanSelectorError``, so a new form fails closed.
    """
    code = _strip_rego_comments(rego)
    named_sets = {
        m["name"]: _set_members(m["set"]) for m in _SET_DEFINITION_RE.finditer(code)
    }
    rules = _rego_rules(code)
    selected: list[LulaNameSelector] = []
    parameter_tests: list[tuple[_RegoRule, int, tuple[str, ...]]] = []
    problems: list[str] = []

    def select(rule_name: str, alias: str, names: tuple[str, ...]) -> None:
        target = aliases.get(alias)
        if target is None:
            problems.append(
                f"rule {rule_name} reads input[{alias!r}], which kubernetes-spec "
                "does not declare"
            )
            return
        selected.extend(
            LulaNameSelector(
                manifest, rule_name, alias, target.resource, target.namespaces, name
            )
            for name in names
        )

    for rule in rules:
        bindings = _input_bindings(rule.text)
        iterations = _iterations(rule.text, named_sets)
        literals = [m.span() for m in _REGO_LITERAL_RE.finditer(rule.text)]

        def in_literal(pos: int, spans: list[tuple[int, int]] = literals) -> bool:
            return any(start <= pos < end for start, end in spans)

        refs = [
            ref
            for ref in _NAME_REF_RE.finditer(rule.text)
            if not in_literal(ref.start())
        ]
        attributed = {ref.end() for ref in refs}
        for use in _ANY_NAME_USE_RE.finditer(rule.text):
            if not in_literal(use.start()) and use.end() not in attributed:
                line_start = rule.text.rfind("\n", 0, use.start()) + 1
                snippet = rule.text[line_start : use.end()].strip()
                problems.append(
                    f"rule {rule.name} reads metadata.name at {snippet!r}, which is "
                    "not a variable or input alias this gate can attribute"
                )
        for ref in refs:
            names = _tested_names(rule.text, ref, named_sets, iterations)
            if names is None:
                snippet = rule.text[ref.start() : ref.end() + 40].splitlines()[0]
                problems.append(f"rule {rule.name} cannot be read at {snippet!r}")
                continue
            if not names:
                continue
            if ref["input_alias"] is not None:
                select(rule.name, ref["input_alias"], names)
                continue
            var = ref["var"]
            bound = bindings.get(var, set())
            if len(bound) == 1:
                select(rule.name, next(iter(bound)), names)
            elif not bound and var in rule.params:
                parameter_tests.append((rule, rule.params.index(var), names))
            elif not bound:
                problems.append(
                    f"rule {rule.name} tests {var}.metadata.name, but {var} is not "
                    "bound to an input alias"
                )
            else:
                problems.append(
                    f"rule {rule.name} binds {var} to more than one input alias "
                    f"({', '.join(sorted(bound))})"
                )

    for function, index, names in parameter_tests:
        calls, unreadable = _call_sites(rules, function)
        problems.extend(unreadable)
        if not calls and not unreadable:
            problems.append(
                f"function {function.name}() tests metadata.name but nothing calls it"
            )
        for caller, args in calls:
            arg = args[index] if index < len(args) else ""
            bound = _input_bindings(caller.text).get(arg, set())
            if len(bound) != 1:
                problems.append(
                    f"rule {caller.name} calls {function.name}() with {arg!r}, not a "
                    "variable bound to one input alias"
                )
                continue
            select(caller.name, next(iter(bound)), names)

    if problems:
        raise OrphanSelectorError(f"{manifest}: " + "; ".join(dict.fromkeys(problems)))
    return list(dict.fromkeys(selected))


def _lula_aliases(
    domain: Mapping[str, Any], manifest: str
) -> tuple[dict[str, LulaAlias], list[LulaNameSelector]]:
    """Return a Kubernetes domain's aliases and the names its resource-rules fix."""
    spec = domain.get("kubernetes-spec")
    if not isinstance(spec, dict):
        raise OrphanSelectorError(
            f"{manifest}: kubernetes domain has no kubernetes-spec (Lula v0.16 schema)"
        )
    aliases: dict[str, LulaAlias] = {}
    named: list[LulaNameSelector] = []
    for entry in spec.get("resources") or []:
        rule = entry.get("resource-rule") if isinstance(entry, dict) else None
        if (
            not isinstance(rule, dict)
            or not entry.get("name")
            or not rule.get("resource")
        ):
            raise OrphanSelectorError(
                f"{manifest}: kubernetes-spec resource needs a name and a "
                f"resource-rule.resource: {entry!r}"
            )
        alias = LulaAlias(
            resource=str(rule["resource"]),
            namespaces=tuple(str(ns) for ns in rule.get("namespaces") or ()),
        )
        aliases[str(entry["name"])] = alias
        if rule.get("name"):
            named.append(
                LulaNameSelector(
                    manifest,
                    "resource-rule",
                    str(entry["name"]),
                    alias.resource,
                    alias.namespaces,
                    str(rule["name"]),
                )
            )
    return aliases, named


def lula_name_selectors(manifest: Path) -> list[LulaNameSelector]:
    """Return every object a Lula manifest's Kubernetes domains select by name."""
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payloads, errors = _sibling_script("check_lula_stub_count")._extract_lula_payloads(
        doc if isinstance(doc, dict) else {}
    )
    if errors:
        raise OrphanSelectorError(f"{manifest.name}: {'; '.join(errors)}")
    selected: list[LulaNameSelector] = []
    for payload in payloads:
        domain = payload.get("domain")
        if not isinstance(domain, dict) or domain.get("type") != "kubernetes":
            continue
        aliases, named = _lula_aliases(domain, manifest.name)
        provider = payload.get("provider")
        opa_spec = provider.get("opa-spec") if isinstance(provider, dict) else None
        rego = opa_spec.get("rego") if isinstance(opa_spec, dict) else None
        if not isinstance(rego, str):
            raise OrphanSelectorError(
                f"{manifest.name}: kubernetes domain without an opa-spec rego"
            )
        selected.extend(named)
        selected.extend(rego_name_selectors(rego, aliases, manifest.name))
    return list(dict.fromkeys(selected))


def _active_lula_manifests(repo_root: Path) -> tuple[Path, ...] | None:
    """Return the manifests ``compliance/lula/README.md`` rates Active.

    ``None`` when the README is absent, as in a synthetic ``infra/``-only tree.
    """
    readme = repo_root / LULA_DIR_REL / "README.md"
    if not readme.is_file():
        return None
    names = _sibling_script("lula_rating_breakdown").rated_active(
        readme.read_text(encoding="utf-8")
    )
    return tuple(repo_root / LULA_DIR_REL / name for name in sorted(names))


def _lula_orphans(
    selectors: tuple[LulaNameSelector, ...],
    objects: tuple[TerraformObject, ...],
    infra_dir: Path,
    module_instances: Mapping[Path, list[tuple[str, dict[str, str]]]],
) -> list[str]:
    """Describe each Lula name selector no object in ``infra/`` satisfies."""
    created: dict[str, set[str]] = {}
    for obj in objects:
        if obj.name is not None:
            created.setdefault(obj.resource, set()).add(obj.name)
    shortfalls = {
        obj: _platform_object_shortfall(infra_dir, module_instances, obj)
        for obj in PLATFORM_OBJECTS
    }
    orphans: list[str] = []
    for sel in selectors:
        where = f"{(LULA_DIR_REL / sel.manifest).as_posix()} rule {sel.rule} [{sel.resource}]"
        if sel.resource not in NAMEABLE_LULA_RESOURCES:
            orphans.append(
                f"  - {where} selects {sel.name!r} by name, and this gate cannot hold "
                f"{sel.resource} to infra/"
            )
            continue
        if sel.name in created.get(sel.resource, set()):
            continue
        platform = next(
            (
                obj
                for obj in PLATFORM_OBJECTS
                if (obj.resource, obj.name) == (sel.resource, sel.name)
                and obj.namespace in sel.namespaces
            ),
            None,
        )
        if platform is None:
            reason = "no Terraform resource, locals manifest or Helm template in infra/ creates it"
        elif shortfalls[platform] is None:
            continue
        else:
            reason = f"{platform.created_by} creates it, but {shortfalls[platform]}"
        orphans.append(f"  - {where} selects metadata.name {sel.name!r}: {reason}")
    return orphans


def verify_k8s_terraform_parity(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    enforce_floors: bool = True,
) -> ParityReport:
    """Verify shadow-manifest absence, selector parity, and Lula name parity.

    Raises:
        ShadowManifestError: If ``deployment/k8s`` exists at *repo_root*.
        OrphanSelectorError: If any selector matches zero workload templates, if
            an Active Lula manifest selects an object ``infra/`` does not create
            or uses ``metadata.name`` in a form this gate cannot read, or if
            corpus floors are not met.
    """
    shadow_dir = repo_root / "deployment" / "k8s"
    if shadow_dir.exists():
        remaining = sorted(
            str(p.relative_to(repo_root)) for p in shadow_dir.rglob("*") if p.is_file()
        )
        sample = ", ".join(remaining[:5]) if remaining else "<empty directory>"
        raise ShadowManifestError(
            f"Forbidden unmanaged shadow manifest directory exists at "
            f"{shadow_dir} ({len(remaining)} file(s): {sample}). "
            f"Provision all Kubernetes resources via infra/ Terraform modules."
        )

    infra_dir = repo_root / "infra"
    if not infra_dir.is_dir():
        raise OrphanSelectorError(f"Missing infra/ directory under {repo_root}")

    all_tf_files = [
        p for p in sorted(infra_dir.rglob("*.tf")) if ".terraform" not in p.parts
    ]
    module_instances = _discover_module_instances(infra_dir)

    workloads: list[WorkloadTemplate] = []
    selectors: list[SelectorRequirement] = []
    tf_objects: list[TerraformObject] = []

    # 1. Scan module .tf files once per concrete module instantiation.
    modules_root = (infra_dir / "modules").resolve()
    for mod_dir, inst_list in sorted(module_instances.items()):
        mod_tf_files = sorted(mod_dir.glob("*.tf"))
        for inst_prefix, var_env in inst_list:
            for tf_file in mod_tf_files:
                w, s = _extract_tf_items_from_file(tf_file, inst_prefix, var_env)
                workloads.extend(w)
                selectors.extend(s)
                tf_objects.extend(
                    _extract_tf_objects_from_file(tf_file, inst_prefix, var_env)
                )

    # 2. Scan non-module .tf files (e.g. infra/targets/gcp-gke/*.tf).
    for tf_file in all_tf_files:
        resolved = tf_file.resolve()
        if modules_root in resolved.parents:
            continue
        target_env = _extract_module_variable_defaults(tf_file.parent)
        w, s = _extract_tf_items_from_file(tf_file, "", target_env)
        workloads.extend(w)
        selectors.extend(s)
        tf_objects.extend(_extract_tf_objects_from_file(tf_file, "", target_env))

    # 3. Scan Helm templates under infra/**/templates/*.yaml.
    helm_templates = [
        p
        for p in sorted(infra_dir.rglob("templates/*.yaml"))
        if ".terraform" not in p.parts
    ] + [
        p
        for p in sorted(infra_dir.rglob("templates/*.yml"))
        if ".terraform" not in p.parts
    ]
    for tmpl in helm_templates:
        selectors.extend(_extract_helm_selectors(tmpl))
        tf_objects.extend(_extract_helm_objects(tmpl))

    # 4. Read what each Lula manifest rated Active selects by name.
    lula_manifests = _active_lula_manifests(repo_root)
    lula_selectors: list[LulaNameSelector] = []
    for manifest in lula_manifests or ():
        if not manifest.is_file():
            raise OrphanSelectorError(
                f"{(LULA_DIR_REL / 'README.md').as_posix()} rates {manifest.name} "
                "Active, but the manifest does not exist"
            )
        lula_selectors.extend(lula_name_selectors(manifest))

    if enforce_floors:
        np_count = sum(1 for s in selectors if s.category == "network_policy")
        svc_count = sum(1 for s in selectors if s.category == "service")
        helm_count = sum(1 for s in selectors if s.category == "helm")
        floor_errors: list[str] = []
        if len(all_tf_files) < MIN_TF_FILES:
            floor_errors.append(
                f"tf_files={len(all_tf_files)} < MIN_TF_FILES={MIN_TF_FILES}"
            )
        if len(workloads) < MIN_WORKLOAD_TEMPLATES:
            floor_errors.append(
                f"workloads={len(workloads)} < MIN_WORKLOAD_TEMPLATES={MIN_WORKLOAD_TEMPLATES}"
            )
        if np_count < MIN_NETWORK_POLICY_SELECTORS:
            floor_errors.append(
                f"network_policy_selectors={np_count} < "
                f"MIN_NETWORK_POLICY_SELECTORS={MIN_NETWORK_POLICY_SELECTORS}"
            )
        if svc_count < MIN_SERVICE_SELECTORS:
            floor_errors.append(
                f"service_selectors={svc_count} < MIN_SERVICE_SELECTORS={MIN_SERVICE_SELECTORS}"
            )
        if helm_count < MIN_HELM_SELECTORS:
            floor_errors.append(
                f"helm_selectors={helm_count} < MIN_HELM_SELECTORS={MIN_HELM_SELECTORS}"
            )
        if lula_manifests is None:
            floor_errors.append(f"{(LULA_DIR_REL / 'README.md').as_posix()} is missing")
        else:
            selecting = len({sel.manifest for sel in lula_selectors})
            if selecting < MIN_LULA_SELECTING_MANIFESTS:
                floor_errors.append(
                    f"lula_selecting_manifests={selecting} < "
                    f"MIN_LULA_SELECTING_MANIFESTS={MIN_LULA_SELECTING_MANIFESTS}"
                )
            if len(lula_selectors) < MIN_LULA_NAME_SELECTORS:
                floor_errors.append(
                    f"lula_name_selectors={len(lula_selectors)} < "
                    f"MIN_LULA_NAME_SELECTORS={MIN_LULA_NAME_SELECTORS}"
                )
        if floor_errors:
            raise OrphanSelectorError(
                "Corpus floor check failed (vacuous scan guard): "
                + "; ".join(floor_errors)
            )

    orphans: list[str] = []
    for req in selectors:
        matched = [w for w in workloads if req.matches(w)]
        if not matched:
            rel_src = (
                req.source_file.relative_to(repo_root)
                if req.source_file.is_relative_to(repo_root)
                else req.source_file
            )
            orphans.append(
                f"  - {rel_src}:{req.line} [{req.kind}] {req.resource_id} "
                f"selector {req.format_selector()} matched 0 Terraform workload pod templates"
            )

    if orphans:
        known_labels = sorted(
            {
                ", ".join(f"{k}={v}" for k, v in sorted(w.labels.items()))
                for w in workloads
            }
        )
        raise OrphanSelectorError(
            f"OrphanSelectorError: {len(orphans)} Kubernetes selector(s) in infra/ "
            f"matched zero workload pod templates:\n"
            + "\n".join(orphans)
            + "\nKnown workload label sets:\n  "
            + "\n  ".join(known_labels)
        )

    lula_orphans = _lula_orphans(
        tuple(lula_selectors), tuple(tf_objects), infra_dir, module_instances
    )
    if lula_orphans:
        kinds = sorted({sel.resource for sel in lula_selectors})
        known_objects = [
            f"  {kind}: "
            + ", ".join(
                [
                    *sorted(
                        {o.name for o in tf_objects if o.resource == kind and o.name}
                    ),
                    *(
                        f"{p.name} in {p.namespace} (platform object: {p.created_by})"
                        for p in PLATFORM_OBJECTS
                        if p.resource == kind
                    ),
                ]
            )
            for kind in kinds
        ]
        raise OrphanSelectorError(
            f"OrphanSelectorError: {len(lula_orphans)} name selector(s) in Active "
            "Lula manifests select objects infra/ does not create:\n"
            + "\n".join(lula_orphans)
            + "\nNamed objects infra/ creates, by the kinds those manifests select:\n"
            + "\n".join(known_objects)
        )

    return ParityReport(
        tf_files_scanned=len(all_tf_files),
        helm_templates_scanned=len(helm_templates),
        workloads=tuple(workloads),
        selectors=tuple(selectors),
        terraform_objects=tuple(tf_objects),
        lula_manifests=tuple(m.name for m in lula_manifests or ()),
        lula_selectors=tuple(lula_selectors),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify deployment/k8s absence, Terraform workload selector parity, "
            "and that Active Lula manifests select only objects infra/ creates."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root path (defaults to repo root).",
    )
    parser.add_argument(
        "--no-floors",
        action="store_true",
        help="Disable repository corpus-size floors (for synthetic unit-test fixtures).",
    )
    args = parser.parse_args(argv)

    try:
        report = verify_k8s_terraform_parity(
            args.repo_root.resolve(),
            enforce_floors=not args.no_floors,
        )
    except (ShadowManifestError, OrphanSelectorError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    selecting = len({sel.manifest for sel in report.lula_selectors})
    print(
        f"OK: deployment/k8s absent; verified {len(report.selectors)} Kubernetes "
        f"selectors against {len(report.workloads)} Terraform workload templates "
        f"across {report.tf_files_scanned} .tf files and "
        f"{report.helm_templates_scanned} Helm templates (0 orphans); "
        f"{len(report.lula_selectors)} name selectors in {selecting} of "
        f"{len(report.lula_manifests)} Active Lula manifests name objects infra/ "
        "creates."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
