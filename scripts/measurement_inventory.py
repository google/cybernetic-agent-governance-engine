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
"""Shared measurement-inventory discovery module (POAM-2026-222 & POAM-2026-234).

Discovers all four repository measurement surfaces directly from source code and
declarative configuration (never from hard-coded lists):

1. ``PrometheusMetric`` — ``Counter``, ``Gauge``, ``Histogram``, and ``Summary``
   registrations across ``src/**/*.py`` (including module-local wrapper helpers)
   and any Prometheus textfile exposition definitions under ``infra/``.
2. ``AlertPolicy`` — ``resource "google_monitoring_alert_policy" "<label>"``
   blocks across ``infra/**/*.tf``, resolving ``local.<name>`` PromQL/MQL/filter
   expressions to extract referenced ``cage_*`` series and notification-channel
   wiring.
3. ``LulaBridgeSpec`` — active/evaluated ``compliance/lula/lula-validation-*.yaml``
   manifests whose ``api`` domain queries compliance-bridge HTTP endpoints and
   whose OPA Rego asserts over compliance-bridge response fields.
4. ``BridgeScoreSurface`` — compliance-bridge response models/dataclasses,
   FastAPI HTTP payload surfaces, ``lula_audit`` stream record schemas, and
   effectiveness / freshness / SLA / dead-man evaluation functions under
   ``src/compliance_bridge/**/*.py``.

Designed for independent consumption by both:
- ``scripts/check_mechanism_references.py`` (``POAM-2026-222``)
- ``POAM-2026-234``'s bidirectional failure-direction gate
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]

PrometheusMetricType = Literal["counter", "gauge", "histogram", "summary"]
BridgeSurfaceKind = Literal["model", "endpoint", "stream_record", "evaluator"]

# Tight non-vacuous corpus floors calibrated against the live repository.
MIN_PROMETHEUS_METRICS = 42
MIN_ALERT_POLICIES = 8
MIN_LULA_BRIDGE_SPECS = 4
MIN_BRIDGE_SCORES = 51

_PROM_CLASS_TO_TYPE: dict[str, PrometheusMetricType] = {
    "Counter": "counter",
    "Gauge": "gauge",
    "Histogram": "histogram",
    "Summary": "summary",
}

_TEXTFILE_TYPE_RE = re.compile(
    r"^\s*#\s*TYPE\s+(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\s+"
    r"(?P<mtype>counter|gauge|histogram|summary)\b",
    re.MULTILINE,
)

_NON_ACTIVE_LULA_HEADER_RE = re.compile(
    r"(?m)^#[ \t]*cage-status:[ \t]*(?:planned|not-applicable)(?:[ \t]|$)"
)

_PROM_METRIC_TOKEN_RE = re.compile(
    r"(?:prometheus\.googleapis\.com[|/](?P<gmp>cage_[a-zA-Z0-9_]+))"
    r"|(?:\b(?P<bare>cage_[a-zA-Z0-9_]+)\b)"
)

_HCL_LOCAL_REF_RE = re.compile(r"\blocal\.([a-zA-Z_][a-zA-Z0-9_]*)\b")
_HCL_INTERP_RE = re.compile(r"\$\{[^}]*\}")
_PROMQL_LABEL_BLOCK_RE = re.compile(r"\{[^{}]*\}")


class CorpusFloorError(RuntimeError):
    """Raised when discovered measurement inventory falls below non-vacuous floors."""


@dataclass(frozen=True)
class PrometheusMetric:
    """A Prometheus collector registration discovered from source or config."""

    name: str
    metric_type: PrometheusMetricType
    labels: tuple[str, ...]
    rel_path: str
    line: int

    def base_family_name(self) -> str:
        """Return the ``prometheus_client`` metric family base name."""
        if self.metric_type == "counter":
            return self.name.removesuffix("_total")
        return self.name

    def exposed_series_names(self) -> tuple[str, ...]:
        """Return exact Prometheus exposition / PromQL series names for this collector.

        Matches ``prometheus_client`` exposition semantics:
        - ``Counter("foo")`` and ``Counter("foo_total")`` both expose
          ``foo_total`` and ``foo_created`` (never ``foo_total_total``).
        - ``Gauge("foo")`` exposes ``foo``.
        - ``Histogram("foo")`` exposes ``foo`` (family / GMP descriptor) plus
          ``foo_bucket``, ``foo_count``, ``foo_sum``, and ``foo_created``.
        - ``Summary("foo")`` exposes ``foo`` plus ``foo_count``, ``foo_sum``,
          and ``foo_created``.
        """
        if self.metric_type == "counter":
            base = self.name.removesuffix("_total")
            return tuple(sorted({f"{base}_total", f"{base}_created"}))
        if self.metric_type == "gauge":
            return (self.name,)
        if self.metric_type == "histogram":
            return tuple(
                sorted(
                    {
                        self.name,
                        f"{self.name}_bucket",
                        f"{self.name}_count",
                        f"{self.name}_created",
                        f"{self.name}_sum",
                    }
                )
            )
        return tuple(
            sorted(
                {
                    self.name,
                    f"{self.name}_count",
                    f"{self.name}_created",
                    f"{self.name}_sum",
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "metric_type": self.metric_type,
            "labels": list(self.labels),
            "exposed_series_names": list(self.exposed_series_names()),
            "rel_path": self.rel_path,
            "line": self.line,
        }


@dataclass(frozen=True)
class AlertPolicy:
    """A Terraform ``google_monitoring_alert_policy`` resource definition."""

    resource_label: str
    display_name: str
    referenced_metrics: tuple[str, ...]
    has_notification_channels_expr: bool
    rel_path: str
    line: int
    notification_channels_expr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_label": self.resource_label,
            "display_name": self.display_name,
            "referenced_metrics": list(self.referenced_metrics),
            "has_notification_channels_expr": self.has_notification_channels_expr,
            "notification_channels_expr": self.notification_channels_expr,
            "rel_path": self.rel_path,
            "line": self.line,
        }


@dataclass(frozen=True)
class LulaBridgeSpec:
    """An evaluated Lula validation manifest querying compliance-bridge HTTP endpoints."""

    rel_path: str
    validation_ids: tuple[str, ...]
    endpoints: tuple[str, ...]
    referenced_fields: tuple[str, ...]
    control_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "validation_ids": list(self.validation_ids),
            "control_ids": list(self.control_ids),
            "endpoints": list(self.endpoints),
            "referenced_fields": list(self.referenced_fields),
        }


@dataclass(frozen=True)
class BridgeScoreSurface:
    """A compliance-bridge score model, HTTP payload surface, stream schema, or evaluator."""

    name: str
    surface_kind: BridgeSurfaceKind
    fields: tuple[str, ...]
    rel_path: str
    line: int
    endpoint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "surface_kind": self.surface_kind,
            "fields": list(self.fields),
            "endpoint": self.endpoint,
            "rel_path": self.rel_path,
            "line": self.line,
        }


@dataclass(frozen=True)
class InventorySnapshot:
    """Complete discovered measurement inventory across all four classes."""

    prometheus_metrics: tuple[PrometheusMetric, ...]
    alert_policies: tuple[AlertPolicy, ...]
    lula_bridge_specs: tuple[LulaBridgeSpec, ...]
    bridge_scores: tuple[BridgeScoreSurface, ...]

    def all_exposed_prometheus_series(self) -> frozenset[str]:
        """Return all exposed PromQL series names across discovered collectors."""
        out: set[str] = set()
        for metric in self.prometheus_metrics:
            out.update(metric.exposed_series_names())
        return frozenset(out)

    def all_resolvable_prometheus_names(self) -> frozenset[str]:
        """Return all exposed series names plus registered base collector names."""
        out = set(self.all_exposed_prometheus_series())
        for metric in self.prometheus_metrics:
            out.add(metric.name)
        return frozenset(out)

    def alert_policy_labels(self) -> frozenset[str]:
        """Return all ``google_monitoring_alert_policy`` Terraform resource labels."""
        return frozenset(p.resource_label for p in self.alert_policies)

    def all_bridge_produced_fields(self) -> frozenset[str]:
        """Return union of all payload/model fields produced by ``src/compliance_bridge/``."""
        out: set[str] = set()
        for surface in self.bridge_scores:
            if surface.surface_kind in ("model", "endpoint", "stream_record"):
                out.update(surface.fields)
        return frozenset(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": {
                "prometheus_metrics": len(self.prometheus_metrics),
                "alert_policies": len(self.alert_policies),
                "lula_bridge_specs": len(self.lula_bridge_specs),
                "bridge_scores": len(self.bridge_scores),
            },
            "prometheus_metrics": [m.to_dict() for m in self.prometheus_metrics],
            "alert_policies": [a.to_dict() for a in self.alert_policies],
            "lula_bridge_specs": [s.to_dict() for s in self.lula_bridge_specs],
            "bridge_scores": [b.to_dict() for b in self.bridge_scores],
        }


# ---------------------------------------------------------------------------
# 1. Prometheus Metric Discovery
# ---------------------------------------------------------------------------


def _extract_str_seq(node: ast.AST | None) -> tuple[str, ...]:
    """Extract a tuple of literal strings from a list/tuple/set AST node."""
    if node is None:
        return ()
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        vals = [
            elt.value
            for elt in node.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
        return tuple(vals)
    return ()


def _get_kwarg(call: ast.Call, names: tuple[str, ...]) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg in names:
            return kw.value
    return None


@dataclass(frozen=True)
class _WrapperSpec:
    kind: Literal["fixed", "cls_arg"]
    fixed_type: PrometheusMetricType | None
    cls_param_idx: int | None
    name_param_idx: int
    labels_param_idx: int | None
    accepts_varargs: bool


def _collect_prom_imports(
    tree: ast.Module,
) -> tuple[dict[str, PrometheusMetricType], set[str]]:
    """Return ``(collector_symbol_to_type, module_aliases_for_prometheus_client)``."""
    collector_aliases: dict[str, PrometheusMetricType] = {}
    mod_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "prometheus_client":
                    mod_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "prometheus_client":
            for alias in node.names:
                if alias.name in _PROM_CLASS_TO_TYPE:
                    local = alias.asname or alias.name
                    collector_aliases[local] = _PROM_CLASS_TO_TYPE[alias.name]
    return collector_aliases, mod_aliases


def _resolve_prom_cls_node(
    node: ast.AST,
    collector_aliases: dict[str, PrometheusMetricType],
    mod_aliases: set[str],
) -> PrometheusMetricType | None:
    if isinstance(node, ast.Name) and node.id in collector_aliases:
        return collector_aliases[node.id]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in mod_aliases
        and node.attr in _PROM_CLASS_TO_TYPE
    ):
        return _PROM_CLASS_TO_TYPE[node.attr]
    return None


def _discover_prom_wrappers(
    tree: ast.Module,
    collector_aliases: dict[str, PrometheusMetricType],
    mod_aliases: set[str],
) -> dict[str, _WrapperSpec]:
    """Identify helper functions that wrap ``Counter``/``Gauge``/``Histogram``/``Summary``."""
    wrappers: dict[str, _WrapperSpec] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        param_names = [arg.arg for arg in node.args.args]
        if not param_names:
            continue
        has_varargs = node.args.vararg is not None
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            direct_type = _resolve_prom_cls_node(
                sub.func, collector_aliases, mod_aliases
            )
            if direct_type is not None and sub.args:
                first = sub.args[0]
                if isinstance(first, ast.Name) and first.id in param_names:
                    name_idx = param_names.index(first.id)
                    lbl_idx: int | None = None
                    for candidate_lbl in ("labelnames", "labels"):
                        if candidate_lbl in param_names:
                            lbl_idx = param_names.index(candidate_lbl)
                            break
                    wrappers[node.name] = _WrapperSpec(
                        kind="fixed",
                        fixed_type=direct_type,
                        cls_param_idx=None,
                        name_param_idx=name_idx,
                        labels_param_idx=lbl_idx,
                        accepts_varargs=has_varargs,
                    )
                    break
            elif (
                isinstance(sub.func, ast.Name)
                and sub.func.id in param_names
                and sub.args
            ):
                first = sub.args[0]
                if isinstance(first, ast.Name) and first.id in param_names:
                    cls_idx = param_names.index(sub.func.id)
                    name_idx = param_names.index(first.id)
                    lbl_idx = None
                    for candidate_lbl in ("labelnames", "labels"):
                        if candidate_lbl in param_names:
                            lbl_idx = param_names.index(candidate_lbl)
                            break
                    wrappers[node.name] = _WrapperSpec(
                        kind="cls_arg",
                        fixed_type=None,
                        cls_param_idx=cls_idx,
                        name_param_idx=name_idx,
                        labels_param_idx=lbl_idx,
                        accepts_varargs=has_varargs,
                    )
                    break
    return wrappers


def discover_prometheus_metrics(
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> tuple[PrometheusMetric, ...]:
    """Discover all Prometheus metric registrations across ``src/`` and ``infra/``."""
    root = repo_root.resolve()
    discovered: dict[tuple[str, str], PrometheusMetric] = {}

    src_root = root / "src"
    if src_root.is_dir():
        for py_path in sorted(src_root.rglob("*.py")):
            if "__pycache__" in py_path.parts:
                continue
            try:
                source = py_path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_path))
            except (OSError, SyntaxError):
                continue

            collector_aliases, mod_aliases = _collect_prom_imports(tree)
            if not collector_aliases and not mod_aliases:
                continue

            wrappers = _discover_prom_wrappers(tree, collector_aliases, mod_aliases)
            rel_path = py_path.relative_to(root).as_posix()

            wrapper_internal_calls: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in wrappers:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            wrapper_internal_calls.add(id(sub))

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or id(node) in wrapper_internal_calls:
                    continue

                mtype: PrometheusMetricType | None = None
                name_node: ast.AST | None = None
                labels_node: ast.AST | None = None

                direct_type = _resolve_prom_cls_node(
                    node.func, collector_aliases, mod_aliases
                )
                if direct_type is not None:
                    mtype = direct_type
                    name_node = (
                        node.args[0] if node.args else _get_kwarg(node, ("name",))
                    )
                    labels_node = (
                        node.args[2]
                        if len(node.args) >= 3
                        else _get_kwarg(node, ("labelnames",))
                    )
                elif isinstance(node.func, ast.Name) and node.func.id in wrappers:
                    wspec = wrappers[node.func.id]
                    if wspec.kind == "fixed":
                        mtype = wspec.fixed_type
                    elif (
                        wspec.cls_param_idx is not None
                        and len(node.args) > wspec.cls_param_idx
                    ):
                        mtype = _resolve_prom_cls_node(
                            node.args[wspec.cls_param_idx],
                            collector_aliases,
                            mod_aliases,
                        )
                    if len(node.args) > wspec.name_param_idx:
                        name_node = node.args[wspec.name_param_idx]
                    else:
                        name_node = _get_kwarg(node, ("name",))

                    if (
                        wspec.labels_param_idx is not None
                        and len(node.args) > wspec.labels_param_idx
                    ):
                        labels_node = node.args[wspec.labels_param_idx]
                    elif wspec.accepts_varargs and len(node.args) > (
                        wspec.name_param_idx + 2
                    ):
                        labels_node = node.args[wspec.name_param_idx + 2]
                    else:
                        labels_node = _get_kwarg(node, ("labelnames", "labels"))

                if (
                    mtype is not None
                    and isinstance(name_node, ast.Constant)
                    and isinstance(name_node.value, str)
                    and name_node.value.strip()
                ):
                    metric_name = name_node.value.strip()
                    labels = _extract_str_seq(labels_node)
                    key = (rel_path, metric_name)
                    if key not in discovered:
                        discovered[key] = PrometheusMetric(
                            name=metric_name,
                            metric_type=mtype,
                            labels=labels,
                            rel_path=rel_path,
                            line=node.lineno,
                        )

    infra_root = root / "infra"
    if infra_root.is_dir():
        for ext in ("*.sh", "*.prom"):
            for path in sorted(infra_root.rglob(ext)):
                if ".terraform" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except OSError:
                    continue
                rel_path = path.relative_to(root).as_posix()
                for match in _TEXTFILE_TYPE_RE.finditer(text):
                    mname = match.group("name")
                    raw_type = match.group("mtype")
                    if raw_type in ("counter", "gauge", "histogram", "summary"):
                        line_no = text.count("\n", 0, match.start()) + 1
                        key = (rel_path, mname)
                        if key not in discovered:
                            discovered[key] = PrometheusMetric(
                                name=mname,
                                metric_type=raw_type,  # type: ignore[arg-type]
                                labels=(),
                                rel_path=rel_path,
                                line=line_no,
                            )

    return tuple(
        sorted(discovered.values(), key=lambda m: (m.name, m.rel_path, m.line))
    )


# ---------------------------------------------------------------------------
# 2. Terraform Cloud Monitoring Alert Policy Discovery
# ---------------------------------------------------------------------------


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Find the closing ``}`` matching ``text[open_pos] == '{'``, respecting strings, comments, and heredocs."""
    n = len(text)
    depth = 0
    i = open_pos
    while i < n:
        ch = text[i]
        if ch == "#":
            nl = text.find("\n", i)
            if nl == -1:
                return n - 1
            i = nl + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            if nl == -1:
                return n - 1
            i = nl + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end_c = text.find("*/", i + 2)
            if end_c == -1:
                return n - 1
            i = end_c + 2
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            hm = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\s*\n", text[i:])
            if hm:
                marker = hm.group(1)
                body_start = i + hm.end()
                end_re = re.compile(rf"(?m)^[ \t]*{re.escape(marker)}[ \t]*$")
                em = end_re.search(text, body_start)
                if em:
                    i = em.end()
                    continue
        if ch == '"':
            i = _skip_hcl_string(text, i)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _skip_hcl_string(text: str, quote_pos: int) -> int:
    """Advance past a double-quoted HCL string starting at ``quote_pos``."""
    n = len(text)
    i = quote_pos + 1
    interp_depth = 0
    while i < n:
        ch = text[i]
        if ch == "\\" and interp_depth == 0:
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            interp_depth += 1
            i += 2
            continue
        if interp_depth > 0:
            if ch == '"':
                i = _skip_hcl_string(text, i)
                continue
            if ch == "{":
                interp_depth += 1
            elif ch == "}":
                interp_depth -= 1
            i += 1
            continue
        if ch == '"':
            return i + 1
        i += 1
    return n


def _skip_hcl_expr(text: str, start_pos: int) -> int:
    """Scan a single HCL attribute value expression starting at ``start_pos``."""
    n = len(text)
    i = start_pos
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    while i < n:
        ch = text[i]
        if ch == '"':
            i = _skip_hcl_string(text, i)
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            hm = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\s*\n", text[i:])
            if hm:
                marker = hm.group(1)
                em = re.search(
                    rf"(?m)^[ \t]*{re.escape(marker)}[ \t]*$", text[i + hm.end() :]
                )
                if em:
                    return i + hm.end() + em.end()
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif ch == "{":
            brace_depth += 1
        elif ch == "}":
            if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                return i
            brace_depth = max(0, brace_depth - 1)
        elif (
            ch == "\n" and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0
        ):
            next_line = text[i + 1 :].lstrip(" \t")
            if next_line.startswith(("?", ":", "&&", "||", "+")):
                i += 1
                continue
            return i
        i += 1
    return n


def _parse_top_level_hcl_attrs(block_body: str) -> dict[str, str]:
    """Extract top-level ``key = <expr>`` attributes inside an HCL block body."""
    attrs: dict[str, str] = {}
    n = len(block_body)
    i = 0
    while i < n:
        while i < n and block_body[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if block_body[i] == "#":
            nl = block_body.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if block_body.startswith("//", i):
            nl = block_body.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if block_body.startswith("/*", i):
            end_c = block_body.find("*/", i + 2)
            i = n if end_c == -1 else end_c + 2
            continue

        m_attr = re.match(
            r"([a-zA-Z_][a-zA-Z0-9_-]*)[ \t]*=(?!=)[ \t]*", block_body[i:]
        )
        if m_attr:
            key = m_attr.group(1)
            val_start = i + m_attr.end()
            val_end = _skip_hcl_expr(block_body, val_start)
            attrs[key] = block_body[val_start:val_end].strip()
            i = val_end
            continue

        brace_pos = block_body.find("{", i)
        nl_pos = block_body.find("\n", i)
        if brace_pos != -1 and (nl_pos == -1 or brace_pos < nl_pos):
            close_pos = _find_matching_brace(block_body, brace_pos)
            i = close_pos + 1
        else:
            i = n if nl_pos == -1 else nl_pos + 1
    return attrs


def _iter_named_subblocks(block_body: str, target_name: str) -> list[str]:
    """Return inner bodies of direct or nested HCL blocks named ``target_name``."""
    results: list[str] = []
    pattern = re.compile(rf"(?m)^[ \t]*{re.escape(target_name)}[ \t]*\{{")
    pos = 0
    while pos < len(block_body):
        m = pattern.search(block_body, pos)
        if not m:
            break
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(block_body, open_brace)
        inner = block_body[open_brace + 1 : close_brace]
        results.append(inner)
        pos = close_brace + 1
    return results


def _collect_dir_hcl_locals(tf_dir: Path) -> dict[str, str]:
    """Parse all ``locals { ... }`` blocks across ``*.tf`` files in ``tf_dir``."""
    locals_map: dict[str, str] = {}
    locals_re = re.compile(r"(?m)^[ \t]*locals[ \t]*\{")
    for tf_path in sorted(tf_dir.glob("*.tf")):
        try:
            text = tf_path.read_text(encoding="utf-8")
        except OSError:
            continue
        pos = 0
        while pos < len(text):
            m = locals_re.search(text, pos)
            if not m:
                break
            open_brace = m.end() - 1
            close_brace = _find_matching_brace(text, open_brace)
            inner = text[open_brace + 1 : close_brace]
            locals_map.update(_parse_top_level_hcl_attrs(inner))
            pos = close_brace + 1
    return locals_map


def _expand_hcl_locals(
    expr: str, locals_map: dict[str, str], seen: frozenset[str] = frozenset()
) -> str:
    """Transitively inline ``local.<name>`` references in an HCL expression."""

    def _repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in seen or name not in locals_map:
            return match.group(0)
        return _expand_hcl_locals(locals_map[name], locals_map, seen | {name})

    return _HCL_LOCAL_REF_RE.sub(_repl, expr)


def extract_cage_metrics_from_query_expr(expr: str) -> tuple[str, ...]:
    """Extract ``cage_*`` Prometheus series identifiers from a PromQL/MQL/filter HCL expression."""
    unescaped = expr.replace('\\"', '"')
    cleaned = _HCL_INTERP_RE.sub("", unescaped)
    found: set[str] = set()
    for gmp_match in re.finditer(
        r"prometheus\.googleapis\.com[|/](cage_[a-zA-Z0-9_]+)", cleaned
    ):
        found.add(gmp_match.group(1))
    prev = None
    stripped_labels = cleaned
    while prev != stripped_labels:
        prev = stripped_labels
        stripped_labels = _PROMQL_LABEL_BLOCK_RE.sub("", stripped_labels)
    for match in _PROM_METRIC_TOKEN_RE.finditer(stripped_labels):
        tok = match.group("gmp") or match.group("bare")
        if tok:
            found.add(tok)
    return tuple(sorted(found))


def _unquote_hcl_literal(raw: str) -> str:
    val = raw.strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    return val


def discover_alert_policies(
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> tuple[AlertPolicy, ...]:
    """Discover all ``google_monitoring_alert_policy`` resources across ``infra/**/*.tf``."""
    root = repo_root.resolve()
    infra_root = root / "infra"
    if not infra_root.is_dir():
        return ()

    resource_re = re.compile(
        r'(?m)^[ \t]*resource[ \t]+"google_monitoring_alert_policy"[ \t]+"([a-zA-Z0-9_-]+)"[ \t]*\{'
    )
    dir_locals_cache: dict[Path, dict[str, str]] = {}
    policies: list[AlertPolicy] = []

    for tf_path in sorted(infra_root.rglob("*.tf")):
        if ".terraform" in tf_path.parts:
            continue
        try:
            text = tf_path.read_text(encoding="utf-8")
        except OSError:
            continue

        tf_dir = tf_path.parent
        if tf_dir not in dir_locals_cache:
            dir_locals_cache[tf_dir] = _collect_dir_hcl_locals(tf_dir)
        locals_map = dir_locals_cache[tf_dir]
        rel_path = tf_path.relative_to(root).as_posix()

        pos = 0
        while pos < len(text):
            m = resource_re.search(text, pos)
            if not m:
                break
            label = m.group(1)
            line_no = text.count("\n", 0, m.start()) + 1
            open_brace = m.end() - 1
            close_brace = _find_matching_brace(text, open_brace)
            body = text[open_brace + 1 : close_brace]

            top_attrs = _parse_top_level_hcl_attrs(body)
            display_name = _unquote_hcl_literal(top_attrs.get("display_name", ""))
            notif_expr = top_attrs.get("notification_channels")
            if notif_expr is not None:
                compact = (
                    notif_expr.replace(" ", "").replace("\t", "").replace("\n", "")
                )
                has_notif = compact not in ("", "[]", "null")
            else:
                has_notif = False

            metrics_referenced: set[str] = set()
            for cond_body in _iter_named_subblocks(body, "conditions"):
                for sub_kind in (
                    "condition_prometheus_query_language",
                    "condition_monitoring_query_language",
                    "condition_threshold",
                    "condition_absent",
                ):
                    for q_body in _iter_named_subblocks(cond_body, sub_kind):
                        q_attrs = _parse_top_level_hcl_attrs(q_body)
                        for attr_key in ("query", "filter", "denominator_filter"):
                            raw_q = q_attrs.get(attr_key)
                            if raw_q:
                                expanded = _expand_hcl_locals(raw_q, locals_map)
                                metrics_referenced.update(
                                    extract_cage_metrics_from_query_expr(expanded)
                                )

            policies.append(
                AlertPolicy(
                    resource_label=label,
                    display_name=display_name,
                    referenced_metrics=tuple(sorted(metrics_referenced)),
                    has_notification_channels_expr=has_notif,
                    rel_path=rel_path,
                    line=line_no,
                    notification_channels_expr=notif_expr,
                )
            )
            pos = close_brace + 1

    return tuple(sorted(policies, key=lambda p: (p.resource_label, p.rel_path, p.line)))


# ---------------------------------------------------------------------------
# 3. Lula Compliance-Bridge Validation Discovery
# ---------------------------------------------------------------------------


def _collect_non_active_oscal_lula_hrefs(repo_root: Path) -> set[str]:
    """Return Lula manifest filenames marked ``planned`` or ``not-applicable`` in OSCAL SSPs."""
    non_active: set[str] = set()
    oscal_dir = repo_root / "compliance" / "oscal"
    if not oscal_dir.is_dir():
        return non_active
    for ssp_path in sorted(oscal_dir.glob("system-security-plan*.yaml")):
        try:
            doc = yaml.safe_load(ssp_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue
        ssp = doc.get("system-security-plan")
        if not isinstance(ssp, dict):
            continue
        ctrl_impl = ssp.get("control-implementation")
        if not isinstance(ctrl_impl, dict):
            continue
        reqs = ctrl_impl.get("implemented-requirements")
        if not isinstance(reqs, list):
            continue
        for req in reqs:
            if not isinstance(req, dict):
                continue
            props = req.get("props")
            status_vals: set[str] = set()
            if isinstance(props, list):
                for prop in props:
                    if (
                        isinstance(prop, dict)
                        and prop.get("name") == "implementation-status"
                        and isinstance(prop.get("value"), str)
                    ):
                        status_vals.add(prop["value"].strip().lower())
            if not (status_vals & {"planned", "not-applicable"}):
                continue
            links = req.get("links")
            if isinstance(links, list):
                for link in links:
                    if isinstance(link, dict) and isinstance(link.get("href"), str):
                        href_name = Path(link["href"].split("#")[0]).name
                        if href_name.startswith("lula-validation-"):
                            non_active.add(href_name)
    return non_active


def _extract_lula_embedded_specs(
    doc: dict[str, Any],
) -> list[tuple[str | None, dict[str, Any]]]:
    """Return ``(resource_uuid, lula_spec_dict)`` pairs from an OSCAL or standalone Lula YAML."""
    out: list[tuple[str | None, dict[str, Any]]] = []
    if "domain" in doc or "provider" in doc:
        meta = doc.get("metadata")
        uid = meta.get("uuid") if isinstance(meta, dict) else None
        out.append((uid if isinstance(uid, str) else None, doc))

    comp_def = doc.get("component-definition")
    if isinstance(comp_def, dict):
        back_matter = comp_def.get("back-matter")
        if isinstance(back_matter, dict):
            resources = back_matter.get("resources")
            if isinstance(resources, list):
                for res in resources:
                    if not isinstance(res, dict):
                        continue
                    uid = res.get("uuid") if isinstance(res.get("uuid"), str) else None
                    desc = res.get("description")
                    if not isinstance(desc, str) or not desc.strip():
                        continue
                    try:
                        embedded = yaml.safe_load(desc)
                    except yaml.YAMLError:
                        continue
                    if isinstance(embedded, dict) and (
                        "domain" in embedded or "provider" in embedded
                    ):
                        out.append((uid, embedded))
    return out


def _extract_rego_bridge_fields(
    rego_text: str, request_names: set[str]
) -> tuple[str, ...]:
    """Extract compliance-bridge response payload field names referenced in Rego."""
    clean_lines = [line.split("#", 1)[0] for line in rego_text.splitlines()]
    clean = "\n".join(clean_lines)

    root_exprs: set[str] = set()
    for rname in request_names:
        root_exprs.add(f"input.{rname}")
        root_exprs.add(f'input["{rname}"]')

    payload_vars: set[str] = set()
    fields: set[str] = set()

    changed = True
    while changed:
        changed = False
        for m in re.finditer(
            r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:=\s*(?:round\s*\(\s*)?object\.get\(\s*"
            r'([a-zA-Z0-9_."\[\]]+)\s*,\s*"([a-zA-Z0-9_]+)"',
            clean,
        ):
            lhs, src, key = m.group(1), m.group(2), m.group(3)
            if src in root_exprs:
                if key != "response":
                    fields.add(key)
                if lhs not in payload_vars:
                    payload_vars.add(lhs)
                    changed = True
            elif src in payload_vars:
                fields.add(key)
                if lhs not in payload_vars:
                    payload_vars.add(lhs)
                    changed = True

        for m in re.finditer(
            r"\b([a-zA-Z_][a-zA-Z0-9_]*)(?:\[[^\]]*\])?\s*:=\s*"
            r"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)",
            clean,
        ):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in root_exprs or rhs in payload_vars:
                if lhs not in payload_vars:
                    payload_vars.add(lhs)
                    changed = True
            elif "." in rhs:
                base, attr = rhs.split(".", 1)
                if f"{base}.{attr}" in root_exprs:
                    if lhs not in payload_vars:
                        payload_vars.add(lhs)
                        changed = True
                elif base in payload_vars:
                    if attr != "response":
                        fields.add(attr)
                    if lhs not in payload_vars:
                        payload_vars.add(lhs)
                        changed = True

        for m in re.finditer(
            r"\bsome\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)",
            clean,
        ):
            elem_var, base_var, attr = m.group(1), m.group(2), m.group(3)
            if base_var in payload_vars:
                fields.add(attr)
                if elem_var not in payload_vars:
                    payload_vars.add(elem_var)
                    changed = True

    for rname in request_names:
        for m in re.finditer(
            rf"\binput\.{re.escape(rname)}\.([a-zA-Z_][a-zA-Z0-9_]*)\b"
            rf'|\binput\.{re.escape(rname)}\["([a-zA-Z_][a-zA-Z0-9_]*)"\]'
            rf'|\binput\["{re.escape(rname)}"\]\.([a-zA-Z_][a-zA-Z0-9_]*)\b'
            rf'|\binput\["{re.escape(rname)}"\]\["([a-zA-Z_][a-zA-Z0-9_]*)"\]',
            clean,
        ):
            key = next(g for g in m.groups() if g is not None)
            if key != "response":
                fields.add(key)
        for m in re.finditer(
            rf'object\.get\(\s*input\.{re.escape(rname)}\s*,\s*"([a-zA-Z0-9_]+)"',
            clean,
        ):
            if m.group(1) != "response":
                fields.add(m.group(1))

    for pvar in payload_vars:
        for m in re.finditer(
            rf"\b{re.escape(pvar)}(?:\[[^\]]+\])?\.([a-zA-Z_][a-zA-Z0-9_]*)\b"
            rf'|\b{re.escape(pvar)}(?:\[[^\]]+\])?\["([a-zA-Z_][a-zA-Z0-9_]*)"\]'
            rf'|object\.get\(\s*{re.escape(pvar)}(?:\[[^\]]+\])?\s*,\s*"([a-zA-Z0-9_]+)"',
            clean,
        ):
            key = next(g for g in m.groups() if g is not None)
            if key != "response":
                fields.add(key)

    return tuple(sorted(fields))


def discover_lula_bridge_specs(
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> tuple[LulaBridgeSpec, ...]:
    """Discover active/evaluated Lula manifests querying compliance-bridge HTTP endpoints."""
    root = repo_root.resolve()
    lula_dir = root / "compliance" / "lula"
    if not lula_dir.is_dir():
        return ()

    ssp_non_active = _collect_non_active_oscal_lula_hrefs(root)
    specs: list[LulaBridgeSpec] = []

    for yaml_path in sorted(lula_dir.glob("lula-validation-*.yaml")):
        try:
            raw_text = yaml_path.read_text(encoding="utf-8")
            doc = yaml.safe_load(raw_text)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue

        if _NON_ACTIVE_LULA_HEADER_RE.search(raw_text):
            continue
        if yaml_path.name in ssp_non_active:
            continue

        control_ids: set[str] = set()
        comp_def = doc.get("component-definition")
        if isinstance(comp_def, dict):
            for comp in comp_def.get("components") or []:
                if not isinstance(comp, dict):
                    continue
                for ci in comp.get("control-implementations") or []:
                    if not isinstance(ci, dict):
                        continue
                    for req in ci.get("implemented-requirements") or []:
                        if isinstance(req, dict) and isinstance(
                            req.get("control-id"), str
                        ):
                            control_ids.add(req["control-id"])

        validation_ids: list[str] = []
        endpoints: set[str] = set()
        referenced_fields: set[str] = set()

        for uid, payload in _extract_lula_embedded_specs(doc):
            domain = payload.get("domain")
            if not isinstance(domain, dict) or domain.get("type") != "api":
                continue
            api_spec = domain.get("api-spec")
            if not isinstance(api_spec, dict):
                continue
            requests_list = api_spec.get("requests")
            if not isinstance(requests_list, list):
                continue

            bridge_req_names: set[str] = set()
            for req in requests_list:
                if not isinstance(req, dict):
                    continue
                url = str(req.get("url", "")).strip()
                rname = str(req.get("name", "")).strip()
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                path = parsed.path or ""
                if (
                    "compliance-bridge" in host
                    or "compliance_bridge" in host
                    or path.startswith("/v1/")
                ):
                    if path:
                        endpoints.add(path)
                    if rname:
                        bridge_req_names.add(rname)

            if not endpoints and not bridge_req_names:
                continue

            if uid and uid not in validation_ids:
                validation_ids.append(uid)

            provider = payload.get("provider")
            if isinstance(provider, dict):
                opa_spec = provider.get("opa-spec")
                if isinstance(opa_spec, dict) and isinstance(opa_spec.get("rego"), str):
                    referenced_fields.update(
                        _extract_rego_bridge_fields(opa_spec["rego"], bridge_req_names)
                    )

        if endpoints:
            if not validation_ids:
                validation_ids.append(yaml_path.stem)
            specs.append(
                LulaBridgeSpec(
                    rel_path=yaml_path.relative_to(root).as_posix(),
                    validation_ids=tuple(validation_ids),
                    endpoints=tuple(sorted(endpoints)),
                    referenced_fields=tuple(sorted(referenced_fields)),
                    control_ids=tuple(sorted(control_ids)),
                )
            )

    return tuple(sorted(specs, key=lambda s: s.rel_path))


# ---------------------------------------------------------------------------
# 4. Compliance-Bridge Score, Freshness, Endpoint & Evaluator Discovery
# ---------------------------------------------------------------------------

_REQUEST_MODEL_SUFFIXES = ("Request",)
_INPUT_PARSER_PREFIXES = ("Raw",)

_EVALUATOR_FUNC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^_is_.*(?:record|lula_audit)$"),
    re.compile(r"^_get_grace_status$"),
    re.compile(r"^_fetch_from_.*"),
    re.compile(r"^get_compliance_metrics$"),
    re.compile(r"^get_last_passing_.*"),
    re.compile(r"^_check_.*"),
    re.compile(r"^findings_from_.*"),
    re.compile(r"^_finding_to_state$"),
    re.compile(r"^build_aarm_conformance_report$"),
    re.compile(r"^build_oscal_assessment_results$"),
    re.compile(r"^verify_evidence_chain$"),
    re.compile(r"^_handle_lula_audit_post_custody$"),
)


def _is_model_or_dataclass(cls_node: ast.ClassDef) -> bool:
    for dec in cls_node.decorator_list:
        dec_name = ast.unparse(dec)
        if "dataclass" in dec_name:
            return True
    for base in cls_node.bases:
        base_name = ast.unparse(base)
        if any(tok in base_name for tok in ("BaseModel", "TypedDict", "NamedTuple")):
            return True
    return False


def _extract_class_fields(cls_node: ast.ClassDef) -> set[str]:
    fields: set[str] = set()
    for stmt in cls_node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            fname = stmt.target.id
            if not fname.startswith("_") and fname != "model_config":
                fields.add(fname)
        elif isinstance(stmt, ast.FunctionDef) and stmt.name == "to_dict":
            fields.update(_extract_returned_dict_keys(stmt))
    return fields


def _extract_referenced_type_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            for m in re.finditer(r"\b[A-Z][A-Za-z0-9_]+\b", sub.value):
                names.add(m.group(0))
    return names


def _extract_returned_dict_keys(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Extract literal string keys from returned dicts / ``JSONResponse(content=...)`` in ``fn_node``."""
    local_dicts: dict[str, set[str]] = {}
    for sub in ast.walk(fn_node):
        if isinstance(sub, (ast.Assign, ast.AnnAssign)):
            val = sub.value
            targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
            if isinstance(val, ast.Dict):
                dkeys = {
                    k.value
                    for k in val.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
                for t in targets:
                    if isinstance(t, ast.Name):
                        local_dicts.setdefault(t.id, set()).update(dkeys)

    returned: set[str] = set()
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Return) and sub.value is not None:
            val = sub.value
            if isinstance(val, ast.Dict):
                for k in val.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        returned.add(k.value)
            elif isinstance(val, ast.Name) and val.id in local_dicts:
                returned.update(local_dicts[val.id])
            elif isinstance(val, ast.Call):
                content_arg = _get_kwarg(val, ("content",))
                if isinstance(content_arg, ast.Dict):
                    for k in content_arg.keys:
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            returned.add(k.value)
                elif (
                    isinstance(content_arg, ast.Name) and content_arg.id in local_dicts
                ):
                    returned.update(local_dicts[content_arg.id])
    return returned


def _extract_route_decorator(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str, set[str]] | None:
    """If ``fn_node`` carries ``@app.<method>("/path", ...)``, return ``(METHOD, path, response_models)``."""
    for dec in fn_node.decorator_list:
        if (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in ("get", "post", "put", "delete", "patch")
            and dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            method = dec.func.attr.upper()
            route_path = dec.args[0].value
            resp_models = _extract_referenced_type_names(
                _get_kwarg(dec, ("response_model",))
            )
            return method, route_path, resp_models
    return None


def discover_bridge_scores(
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> tuple[BridgeScoreSurface, ...]:
    """Discover compliance-bridge models, HTTP endpoints, stream schemas, and score/SLA evaluators."""
    root = repo_root.resolve()
    bridge_dir = root / "src" / "compliance_bridge"
    if not bridge_dir.is_dir():
        return ()

    parsed_files: list[tuple[Path, str, ast.Module]] = []
    for py_path in sorted(bridge_dir.rglob("*.py")):
        if "__pycache__" in py_path.parts:
            continue
        try:
            src = py_path.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=str(py_path))
        except (OSError, SyntaxError):
            continue
        parsed_files.append((py_path, py_path.relative_to(root).as_posix(), tree))

    model_fields: dict[str, set[str]] = {}
    model_nested_refs: dict[str, set[str]] = {}
    model_locations: dict[str, tuple[str, int]] = {}
    func_return_models: dict[str, set[str]] = {}

    for _py_path, rel_path, tree in parsed_files:
        for stmt in tree.body:
            if isinstance(stmt, ast.ClassDef):
                cname = stmt.name
                if cname.startswith("_") or cname.startswith(_INPUT_PARSER_PREFIXES):
                    continue
                if cname.endswith(("Error", "Exception")):
                    continue
                if _is_model_or_dataclass(stmt):
                    fset = _extract_class_fields(stmt)
                    if not fset:
                        continue
                    if cname == "InfraEvent":
                        model_fields[cname] = fset
                        model_locations[cname] = (rel_path, stmt.lineno)
                        continue
                    if cname.endswith(_REQUEST_MODEL_SUFFIXES):
                        continue
                    model_fields[cname] = fset
                    model_locations[cname] = (rel_path, stmt.lineno)
                    nested: set[str] = set()
                    for cstmt in stmt.body:
                        if isinstance(cstmt, ast.AnnAssign):
                            nested.update(
                                _extract_referenced_type_names(cstmt.annotation)
                            )
                    model_nested_refs[cname] = nested
        for sub in ast.walk(tree):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.returns:
                ret_types = _extract_referenced_type_names(sub.returns)
                if ret_types:
                    func_return_models.setdefault(sub.name, set()).update(ret_types)

    def _transitive_model_fields(seed_models: set[str]) -> set[str]:
        out: set[str] = set()
        queue = [m for m in seed_models if m in model_fields]
        visited: set[str] = set()
        while queue:
            cur = queue.pop()
            if cur in visited:
                continue
            visited.add(cur)
            out.update(model_fields.get(cur, set()))
            for child in model_nested_refs.get(cur, set()):
                if child in model_fields and child not in visited:
                    queue.append(child)
        return out

    surfaces: list[BridgeScoreSurface] = []

    _NON_SCORE_MODULES = frozenset(
        {"auth.py", "kms_batch_signer.py", "governance_webhook.py"}
    )

    lula_record_read_keys: set[str] = set()
    for _py_path, _rel_path, tree in parsed_files:
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef) and "lula_audit" in stmt.name:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        if (
                            isinstance(sub.func, ast.Name)
                            and sub.func.id == "_get_record_field"
                            and len(sub.args) >= 2
                            and isinstance(sub.args[1], ast.Constant)
                            and isinstance(sub.args[1].value, str)
                        ):
                            lula_record_read_keys.add(sub.args[1].value)
                        elif (
                            isinstance(sub.func, ast.Attribute)
                            and sub.func.attr == "get"
                            and not (
                                isinstance(sub.func.value, ast.Attribute)
                                and sub.func.value.attr == "environ"
                            )
                            and sub.args
                            and isinstance(sub.args[0], ast.Constant)
                            and isinstance(sub.args[0].value, str)
                        ):
                            lula_record_read_keys.add(sub.args[0].value)

    for cname, fset in sorted(model_fields.items()):
        rel_path, lineno = model_locations[cname]
        if Path(rel_path).name in _NON_SCORE_MODULES:
            continue
        if cname == "InfraEvent":
            surfaces.append(
                BridgeScoreSurface(
                    name="lula_audit_infra_event",
                    surface_kind="stream_record",
                    fields=tuple(sorted(fset | lula_record_read_keys)),
                    rel_path=rel_path,
                    line=lineno,
                )
            )
        else:
            surfaces.append(
                BridgeScoreSurface(
                    name=cname,
                    surface_kind="model",
                    fields=tuple(sorted(fset)),
                    rel_path=rel_path,
                    line=lineno,
                )
            )

    score_model_names = {
        cname
        for cname in model_fields
        if cname != "InfraEvent"
        and Path(model_locations[cname][0]).name not in _NON_SCORE_MODULES
    }
    for _py_path, rel_path, tree in parsed_files:
        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route_info = _extract_route_decorator(stmt)
            if route_info is not None:
                method, route_path, dec_models = route_info
                direct_keys = _extract_returned_dict_keys(stmt)
                called_models: set[str] = set(dec_models)
                called_models.update(
                    _extract_referenced_type_names(stmt.returns) & score_model_names
                )
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        callee_name: str | None = None
                        if isinstance(sub.func, ast.Name):
                            callee_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            callee_name = sub.func.attr
                        if callee_name:
                            if callee_name in score_model_names:
                                called_models.add(callee_name)
                            called_models.update(
                                func_return_models.get(callee_name, set())
                                & score_model_names
                            )
                ep_fields = direct_keys | _transitive_model_fields(called_models)
                surfaces.append(
                    BridgeScoreSurface(
                        name=stmt.name,
                        surface_kind="endpoint",
                        fields=tuple(sorted(ep_fields)),
                        rel_path=rel_path,
                        line=stmt.lineno,
                        endpoint=f"{method} {route_path}",
                    )
                )
                continue

            is_eval = any(pat.match(stmt.name) for pat in _EVALUATOR_FUNC_PATTERNS)
            ret_models = (
                _extract_referenced_type_names(stmt.returns) & score_model_names
            )
            if is_eval or ret_models:
                eval_fields = _extract_returned_dict_keys(
                    stmt
                ) | _transitive_model_fields(ret_models)
                surfaces.append(
                    BridgeScoreSurface(
                        name=stmt.name,
                        surface_kind="evaluator",
                        fields=tuple(sorted(eval_fields)),
                        rel_path=rel_path,
                        line=stmt.lineno,
                    )
                )

    return tuple(
        sorted(surfaces, key=lambda s: (s.surface_kind, s.name, s.rel_path, s.line))
    )


# ---------------------------------------------------------------------------
# Snapshot & Corpus Floor Enforcement
# ---------------------------------------------------------------------------


def discover_inventory(repo_root: Path = DEFAULT_REPO_ROOT) -> InventorySnapshot:
    """Discover all four measurement classes from ``repo_root``."""
    return InventorySnapshot(
        prometheus_metrics=discover_prometheus_metrics(repo_root),
        alert_policies=discover_alert_policies(repo_root),
        lula_bridge_specs=discover_lula_bridge_specs(repo_root),
        bridge_scores=discover_bridge_scores(repo_root),
    )


def enforce_corpus_floors(
    snapshot: InventorySnapshot,
    *,
    min_prometheus_metrics: int = MIN_PROMETHEUS_METRICS,
    min_alert_policies: int = MIN_ALERT_POLICIES,
    min_lula_bridge_specs: int = MIN_LULA_BRIDGE_SPECS,
    min_bridge_scores: int = MIN_BRIDGE_SCORES,
) -> None:
    """Fail closed if any of the four measurement classes drops below its floor."""
    breaches: list[str] = []
    if len(snapshot.prometheus_metrics) < min_prometheus_metrics:
        breaches.append(
            f"prometheus_metrics={len(snapshot.prometheus_metrics)} < floor {min_prometheus_metrics}"
        )
    if len(snapshot.alert_policies) < min_alert_policies:
        breaches.append(
            f"alert_policies={len(snapshot.alert_policies)} < floor {min_alert_policies}"
        )
    if len(snapshot.lula_bridge_specs) < min_lula_bridge_specs:
        breaches.append(
            f"lula_bridge_specs={len(snapshot.lula_bridge_specs)} < floor {min_lula_bridge_specs}"
        )
    if len(snapshot.bridge_scores) < min_bridge_scores:
        breaches.append(
            f"bridge_scores={len(snapshot.bridge_scores)} < floor {min_bridge_scores}"
        )
    if breaches:
        raise CorpusFloorError(
            "Measurement inventory corpus floor breach: " + "; ".join(breaches)
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover CAGE measurement inventory across code and config."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory to scan.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit full inventory snapshot as JSON.",
    )
    parser.add_argument(
        "--no-floors",
        action="store_true",
        help="Skip non-vacuous corpus floor enforcement.",
    )
    args = parser.parse_args(argv)

    snapshot = discover_inventory(args.repo_root)
    if not args.no_floors:
        try:
            enforce_corpus_floors(snapshot)
        except CorpusFloorError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
        return 0

    print(
        "Measurement Inventory Summary:\n"
        f"  Prometheus metrics : {len(snapshot.prometheus_metrics)} (floor >= {MIN_PROMETHEUS_METRICS})\n"
        f"  Alert policies     : {len(snapshot.alert_policies)} (floor >= {MIN_ALERT_POLICIES})\n"
        f"  Lula bridge specs  : {len(snapshot.lula_bridge_specs)} (floor >= {MIN_LULA_BRIDGE_SPECS})\n"
        f"  Bridge scores      : {len(snapshot.bridge_scores)} (floor >= {MIN_BRIDGE_SCORES})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
