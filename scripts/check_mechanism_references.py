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
"""Mechanism-reference integrity gate (POAM-2026-222, zero waivers).

Consumes ``scripts/measurement_inventory.py`` to verify that monitoring,
alerting, Lula compliance-bridge validations, OSCAL narratives, core
documentation, and ``THRESHOLD_TRACEABILITY_MATRIX.md`` (``CAGE-TTM-001``) never
cite telemetry series, alert-policy resources, or compliance-bridge payload
fields that do not exist in code/configuration:

1. **Infra Alert Policies, PodMonitoring & Dashboards -> Prometheus Metrics**:
   Every ``cage_*`` series referenced in ``AlertPolicy.referenced_metrics``,
   ``infra/**/*.tf`` PromQL/MQL/GMP descriptors, and ``infra/**/*.{json,yaml,yml}``
   dashboards or relabeling manifests must resolve to a discovered
   ``PrometheusMetric`` (``exposed_series_names()`` or base ``name``).
2. **Lula Bridge Specs -> Compliance-Bridge Score Surfaces**:
   Every active ``LulaBridgeSpec`` must target a real FastAPI route (when routes
   are present in ``src/compliance_bridge/``) and every compliance-bridge JSON
   field read in its Rego policy must be produced by ``BridgeScoreSurface``.
3. **OSCAL & In-Scope Documentation Mechanism Citations**:
   Every ``google_monitoring_alert_policy.<label>`` and ``cage_<metric>``
   Prometheus series cited across ``compliance/oscal/**/*.yaml`` and living
   ``DOC_SCOPE`` documents must resolve in the discovered inventory.
4. **CAGE-TTM-001 & POAM-2026-222 Signing-Hold / Closure Binding**:
   - Always verifies ``lula-validation-*.yaml`` files and any ``cage_*``
     Prometheus metrics cited in §2.1.
   - While ``POAM-2026-222`` is ``Open`` in ``docs/POAM.md``, enforces presence
     of the ``Evidence Withdrawal and Signing Hold`` notice and verifies that
     ``RA-001``..``RA-004`` (§5) and the §6 Approval Block remain unsigned.
   - Once ``POAM-2026-222`` is not ``Open`` (e.g. ``Closed``), fails closed on
     any ``cage.<subsystem>.<metric>`` dot-separated name or unresolved
     ``cage_*`` metric in §2.1 or Appendix B.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    from scripts.check_doc_references import (
        DOC_SCOPE,
        RETRACTED_ARCHIVE,
        RETRACTION_NOTICE_PATTERN,
    )
    from scripts.measurement_inventory import (
        DEFAULT_REPO_ROOT,
        CorpusFloorError,
        InventorySnapshot,
        discover_inventory,
        enforce_corpus_floors,
        extract_cage_metrics_from_query_expr,
    )
except ImportError:
    from check_doc_references import (  # type: ignore[import-not-found, no-redef]
        DOC_SCOPE,
        RETRACTED_ARCHIVE,
        RETRACTION_NOTICE_PATTERN,
    )
    from measurement_inventory import (  # type: ignore[import-not-found, no-redef]
        DEFAULT_REPO_ROOT,
        CorpusFloorError,
        InventorySnapshot,
        discover_inventory,
        enforce_corpus_floors,
        extract_cage_metrics_from_query_expr,
    )


# Historical change and defect ledgers deliberately record retired or
# never-emitted metric names as part of finding/clean-break histories.
_HISTORICAL_LEDGER_PATHS: frozenset[str] = frozenset(
    {
        "docs/POAM.md",
        "docs/BREAKING_CHANGES.md",
    }
)

_PROMETHEUS_METRIC_SUFFIXES: tuple[str, ...] = (
    "_total",
    "_created",
    "_seconds",
    "_bytes",
    "_ratio",
    "_info",
    "_count",
    "_bucket",
    "_sum",
    "_batches",
    "_failures",
    "_gaps",
    "_controls",
    "_manifests",
    "_disabled",
    "_attempts",
    "_epoch",
)

_PROMETHEUS_SUBSYSTEM_PREFIXES: tuple[str, ...] = (
    "cage_gateway_",
    "cage_governance_",
    "cage_lula_audit_",
    "cage_cbf_",
    "cage_ftra_",
    "cage_kms_",
    "cage_rate_limit_",
    "cage_reconciliation_",
    "cage_consequence_",
    "cage_event_loop_",
    "cage_stpa_",
    "cage_phantom_",
)

_INLINE_BACKTICK_RE = re.compile(r"`([^`\n]+)`")
_ALERT_POLICY_REF_RE = re.compile(
    r"\bgoogle_monitoring_alert_policy\.([a-zA-Z0-9_-]+)\b"
)
_GMP_DESCRIPTOR_RE = re.compile(r"prometheus\.googleapis\.com[|/](cage_[a-zA-Z0-9_]+)")
_LABELED_METRIC_RE = re.compile(r"(?<![A-Za-z0-9_./-])(cage_[a-z0-9_]+)\{[^{}\n]*\}")
_WILDCARD_METRIC_RE = re.compile(
    r"^(?:prometheus\.googleapis\.com/)?(cage_[a-z0-9_]+)\*$"
)
_BARE_CAGE_IDENT_RE = re.compile(r"^cage_[a-z0-9]+_[a-z0-9_]+$")
_VERSIONED_SCHEMA_KEY_RE = re.compile(r"_v\d+$")
_DOT_METRIC_RE = re.compile(
    r"\bcage\.[a-z0-9_]+(?:\.(?:[a-z0-9_*]+|<[a-z0-9_]+>))+(?![A-Za-z0-9_*<>])"
)
_LULA_FILENAME_RE = re.compile(r"\blula-validation-[a-zA-Z0-9_-]+\.yaml\b")


@dataclass(frozen=True)
class MechanismViolation:
    """A single broken mechanism reference or signing-hold invariant breach."""

    file: str
    line: int
    kind: str
    detail: str

    def format(self) -> str:
        return f"{self.file}:{self.line}: [{self.kind}] {self.detail}"


class MechanismReferenceError(RuntimeError):
    """Raised when ``verify_mechanism_references`` detects one or more violations."""

    def __init__(self, violations: list[MechanismViolation]) -> None:
        self.violations = tuple(violations)
        summary = "\n  ".join(v.format() for v in self.violations)
        super().__init__(
            f"Found {len(self.violations)} mechanism-reference violation(s):\n  {summary}"
        )


# ---------------------------------------------------------------------------
# Helpers: Structural Non-Metric Symbol Discovery (Zero Hard-Coded Waivers)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RepoSymbolContext:
    python_modules: frozenset[str]
    tf_variables: frozenset[str]
    rego_rules: frozenset[str]


def _discover_non_metric_repo_symbols(repo_root: Path) -> _RepoSymbolContext:
    """Discover ``cage_*`` package/module names, Terraform variables, and Rego rules on disk."""
    py_mods: set[str] = set()
    for search_root in (
        repo_root / "src",
        repo_root / "packages",
        repo_root / "scripts",
    ):
        if not search_root.is_dir():
            continue
        for p in search_root.rglob("*"):
            if "__pycache__" in p.parts:
                continue
            stem = p.stem if p.is_file() and p.suffix == ".py" else p.name
            if stem.startswith("cage_"):
                py_mods.add(stem)

    tf_vars: set[str] = set()
    infra_dir = repo_root / "infra"
    tf_var_re = re.compile(r'(?m)^\s*variable\s+"(cage_[a-zA-Z0-9_]+)"\s*\{')
    if infra_dir.is_dir():
        for tf_path in infra_dir.rglob("*.tf"):
            if ".terraform" in tf_path.parts:
                continue
            try:
                txt = tf_path.read_text(encoding="utf-8")
            except OSError:
                continue
            tf_vars.update(tf_var_re.findall(txt))

    rego_rules: set[str] = set()
    rego_rule_re = re.compile(r"(?m)^\s*(cage_[a-zA-Z0-9_]+)\s*(?:if\b|:=|\{)")
    lula_dir = repo_root / "compliance" / "lula"
    if lula_dir.is_dir():
        for ypath in lula_dir.glob("lula-validation-*.yaml"):
            try:
                txt = ypath.read_text(encoding="utf-8")
            except OSError:
                continue
            rego_rules.update(rego_rule_re.findall(txt))

    return _RepoSymbolContext(
        python_modules=frozenset(py_mods),
        tf_variables=frozenset(tf_vars),
        rego_rules=frozenset(rego_rules),
    )


def _is_prometheus_metric_identifier(token: str, ctx: _RepoSymbolContext) -> bool:
    """Return True when bare ``cage_*`` identifier ``token`` is structurally a metric series name."""
    if not _BARE_CAGE_IDENT_RE.match(token):
        return False
    if _VERSIONED_SCHEMA_KEY_RE.search(token):
        return False
    if (
        token in ctx.python_modules
        or token in ctx.tf_variables
        or token in ctx.rego_rules
    ):
        return False
    if token.endswith(_PROMETHEUS_METRIC_SUFFIXES):
        return True
    if token.startswith(_PROMETHEUS_SUBSYSTEM_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------------------
# Check 1: Infra Alert Policies, PodMonitoring & Dashboards -> Prometheus
# ---------------------------------------------------------------------------


def _strip_tf_comments_and_doc_heredocs(text: str) -> str:
    """Blank out comments and ``documentation { ... }`` prose while preserving line numbers."""
    # First blank out `documentation { ... }` blocks by line-preserving spaces.
    chars = list(text)
    doc_re = re.compile(r"(?m)^[ \t]*documentation[ \t]*\{")
    pos = 0
    while pos < len(text):
        m = doc_re.search(text, pos)
        if not m:
            break
        # Find matching brace respecting heredocs
        open_b = m.end() - 1
        try:
            from scripts.measurement_inventory import _find_matching_brace
        except ImportError:
            from measurement_inventory import (  # type: ignore[import-not-found, no-redef]
                _find_matching_brace,
            )
        close_b = _find_matching_brace(text, open_b)
        for idx in range(m.start(), min(close_b + 1, len(chars))):
            if chars[idx] != "\n":
                chars[idx] = " "
        pos = close_b + 1

    without_docs = "".join(chars)
    out_lines: list[str] = []
    for line in without_docs.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")):
            out_lines.append("")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def _walk_dashboard_or_manifest_strings(
    obj: Any, parent_key: str = ""
) -> list[tuple[str, str]]:
    """Collect ``(context_key, string_value)`` pairs from parsed YAML/JSON infra files."""
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            next_key = f"{parent_key}.{key_str}" if parent_key else key_str
            found.extend(_walk_dashboard_or_manifest_strings(v, next_key))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_dashboard_or_manifest_strings(item, parent_key))
    elif isinstance(obj, str):
        found.append((parent_key, obj))
    return found


def _check_infra_prometheus_references(
    repo_root: Path, snapshot: InventorySnapshot
) -> list[MechanismViolation]:
    violations: list[MechanismViolation] = []
    valid_metrics = snapshot.all_resolvable_prometheus_names()

    # 1a. AlertPolicy.referenced_metrics
    for policy in snapshot.alert_policies:
        for mname in policy.referenced_metrics:
            if mname not in valid_metrics:
                violations.append(
                    MechanismViolation(
                        file=policy.rel_path,
                        line=policy.line,
                        kind="unresolved_alert_metric",
                        detail=(
                            f"google_monitoring_alert_policy.{policy.resource_label} "
                            f"references Prometheus metric {mname!r} which is not registered in src/ or infra/"
                        ),
                    )
                )

    infra_root = repo_root / "infra"
    if not infra_root.is_dir():
        return violations

    # 1b. Terraform GMP descriptors (`prometheus.googleapis.com|cage_...|...`) & *_promql/*_mql locals
    promql_attr_re = re.compile(
        r"(?m)^[ \t]*([a-zA-Z0-9_]*(?:promql|mql)[a-zA-Z0-9_]*|query|filter)[ \t]*=[ \t]*(.+)$"
    )
    for tf_path in sorted(infra_root.rglob("*.tf")):
        if ".terraform" in tf_path.parts:
            continue
        try:
            raw_text = tf_path.read_text(encoding="utf-8")
        except OSError:
            continue
        rel_path = tf_path.relative_to(repo_root).as_posix()
        executable_tf = _strip_tf_comments_and_doc_heredocs(raw_text)

        for gmp_m in _GMP_DESCRIPTOR_RE.finditer(executable_tf):
            mname = gmp_m.group(1)
            if mname not in valid_metrics:
                line_no = executable_tf.count("\n", 0, gmp_m.start()) + 1
                violations.append(
                    MechanismViolation(
                        file=rel_path,
                        line=line_no,
                        kind="unresolved_tf_gmp_metric",
                        detail=(
                            f"Terraform GMP descriptor references unregistered metric {mname!r}"
                        ),
                    )
                )

        for q_m in promql_attr_re.finditer(executable_tf):
            line_no = executable_tf.count("\n", 0, q_m.start()) + 1
            for mname in extract_cage_metrics_from_query_expr(q_m.group(2)):
                if mname not in valid_metrics:
                    violations.append(
                        MechanismViolation(
                            file=rel_path,
                            line=line_no,
                            kind="unresolved_tf_query_metric",
                            detail=(
                                f"Terraform query/filter attribute {q_m.group(1)!r} "
                                f"references unregistered metric {mname!r}"
                            ),
                        )
                    )

    # 1c. Infra YAML/JSON dashboards, PrometheusRules & PodMonitoring relabelings
    query_key_suffixes = (
        "expr",
        "query",
        "filter",
        "promql",
        "metric",
        "metricType",
        "regex",
    )
    helm_tag_re = re.compile(r"\{\{.*?\}\}")
    for ext in ("*.json", "*.yaml", "*.yml"):
        for mf_path in sorted(infra_root.rglob(ext)):
            if ".terraform" in mf_path.parts:
                continue
            try:
                raw_text = mf_path.read_text(encoding="utf-8")
            except OSError:
                continue
            rel_path = mf_path.relative_to(repo_root).as_posix()

            # Check explicit GMP descriptors anywhere in the manifest/dashboard.
            for gmp_m in _GMP_DESCRIPTOR_RE.finditer(raw_text):
                mname = gmp_m.group(1)
                if mname not in valid_metrics:
                    line_no = raw_text.count("\n", 0, gmp_m.start()) + 1
                    violations.append(
                        MechanismViolation(
                            file=rel_path,
                            line=line_no,
                            kind="unresolved_dashboard_metric",
                            detail=f"Manifest/dashboard references unregistered GMP metric {mname!r}",
                        )
                    )

            sanitized = "\n".join(
                ""
                if ln.lstrip().startswith(("{{-", "{{"))
                else helm_tag_re.sub('"helm_val"', ln)
                for ln in raw_text.splitlines()
            )
            try:
                docs = (
                    [json.loads(sanitized)]
                    if mf_path.suffix == ".json"
                    else list(yaml.safe_load_all(sanitized))
                )
            except (json.JSONDecodeError, yaml.YAMLError):
                continue

            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                for key_path, val_str in _walk_dashboard_or_manifest_strings(doc):
                    leaf_key = key_path.rsplit(".", 1)[-1]
                    if leaf_key in query_key_suffixes or any(
                        seg in key_path
                        for seg in (
                            "promqlQuery",
                            "timeSeriesFilter",
                            "metricRelabelings",
                            "groups.rules",
                        )
                    ):
                        for mname in extract_cage_metrics_from_query_expr(val_str):
                            if mname not in valid_metrics:
                                pos = raw_text.find(mname)
                                line_no = (
                                    raw_text.count("\n", 0, pos) + 1 if pos >= 0 else 1
                                )
                                violations.append(
                                    MechanismViolation(
                                        file=rel_path,
                                        line=line_no,
                                        kind="unresolved_dashboard_metric",
                                        detail=(
                                            f"Dashboard/manifest field {key_path!r} "
                                            f"references unregistered metric {mname!r}"
                                        ),
                                    )
                                )

    # Deduplicate preserving order
    return list(dict.fromkeys(violations))


# ---------------------------------------------------------------------------
# Check 2: Lula Bridge Specs -> Compliance-Bridge Score Surfaces
# ---------------------------------------------------------------------------


def _compile_fastapi_route_regex(route_spec: str) -> re.Pattern[str] | None:
    """Compile ``GET /v1/metrics/{control_id}`` into a URL-path regex."""
    parts = route_spec.strip().split(None, 1)
    if len(parts) != 2:
        return None
    method, path_template = parts
    if method.upper() != "GET":
        return None
    escaped = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", r"[^/]+", path_template)
    return re.compile(rf"^{escaped}$")


def _check_lula_bridge_references(
    snapshot: InventorySnapshot,
) -> list[MechanismViolation]:
    violations: list[MechanismViolation] = []
    endpoint_surfaces = [
        (s, pat)
        for s in snapshot.bridge_scores
        if s.surface_kind == "endpoint" and s.endpoint is not None
        for pat in (_compile_fastapi_route_regex(s.endpoint),)
        if pat is not None
    ]
    all_produced_fields = snapshot.all_bridge_produced_fields()

    for spec in snapshot.lula_bridge_specs:
        if endpoint_surfaces:
            matched_fields: set[str] = set()
            for ep in spec.endpoints:
                matching = [surf for surf, pat in endpoint_surfaces if pat.match(ep)]
                if not matching:
                    violations.append(
                        MechanismViolation(
                            file=spec.rel_path,
                            line=1,
                            kind="unresolved_lula_bridge_endpoint",
                            detail=(
                                f"Lula validation {spec.validation_ids} queries "
                                f"compliance-bridge endpoint {ep!r}, which matches no "
                                "GET route in src/compliance_bridge/"
                            ),
                        )
                    )
                else:
                    for surf in matching:
                        matched_fields.update(surf.fields)

            allowed_fields = (
                frozenset(matched_fields) if matched_fields else all_produced_fields
            )
        else:
            allowed_fields = all_produced_fields

        for field_name in spec.referenced_fields:
            if field_name not in allowed_fields:
                violations.append(
                    MechanismViolation(
                        file=spec.rel_path,
                        line=1,
                        kind="unresolved_lula_bridge_field",
                        detail=(
                            f"Lula validation {spec.validation_ids} (endpoints={list(spec.endpoints)}) "
                            f"asserts on compliance-bridge field {field_name!r}, which is not "
                            "produced by src/compliance_bridge/"
                        ),
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# Check 3: OSCAL & In-Scope Documentation Mechanism Citations
# ---------------------------------------------------------------------------


def _verify_retracted_file_notice(
    path: Path, rel_path: str, poam_text: str | None
) -> MechanismViolation | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    first_non_empty = next((ln.strip() for ln in lines if ln.strip()), "")
    m = RETRACTION_NOTICE_PATTERN.match(first_non_empty)
    if m is None:
        return MechanismViolation(
            file=rel_path,
            line=1,
            kind="invalid_retracted_notice",
            detail=(
                f"File under {RETRACTED_ARCHIVE}/ lacks first-line "
                "`> **RETRACTED YYYY-MM-DD** ... POAM-YYYY-NNN` notice"
            ),
        )
    poam_id = m.group("poam")
    if poam_text is not None and poam_id not in poam_text:
        return MechanismViolation(
            file=rel_path,
            line=1,
            kind="untracked_retracted_poam",
            detail=f"Retracted notice cites {poam_id}, which is absent from docs/POAM.md",
        )
    return None


def _iter_in_scope_doc_and_oscal_files(repo_root: Path) -> list[Path]:
    files: set[Path] = set()
    oscal_dir = repo_root / "compliance" / "oscal"
    if oscal_dir.is_dir():
        for ext in ("*.yaml", "*.yml"):
            files.update(oscal_dir.rglob(ext))

    for scope_entry in DOC_SCOPE:
        target = repo_root / scope_entry
        if target.is_file():
            files.add(target)
        elif target.is_dir():
            files.update(target.rglob("*.md"))
    return sorted(files)


def _extract_markdown_metric_table_cells(
    md_text: str, *, skip_langfuse_col: bool
) -> list[tuple[int, str]]:
    """Extract ``(line_no, cell_text)`` from Markdown table columns whose header names ``Metric``."""
    results: list[tuple[int, str]] = []
    lines = md_text.splitlines()
    metric_col_indices: list[int] = []
    in_table = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            in_table = False
            metric_col_indices = []
            continue

        cells = [c.strip() for c in stripped.strip("|").split("|")]
        # Separator row `|---|---|`
        if all(re.match(r"^:?-{2,}:?$", c) for c in cells if c):
            continue

        if not in_table:
            in_table = True
            metric_col_indices = []
            for c_idx, hdr in enumerate(cells):
                hdr_low = hdr.lower()
                if "metric" in hdr_low:
                    if skip_langfuse_col and "langfuse metric" in hdr_low:
                        continue
                    metric_col_indices.append(c_idx)
            continue

        for c_idx in metric_col_indices:
            if c_idx < len(cells):
                results.append((idx, cells[c_idx]))
    return results


def _check_backtick_snippet_mechanisms(
    snippet: str,
    rel_path: str,
    line_no: int,
    valid_metrics: frozenset[str],
    metric_names: frozenset[str],
    alert_labels: frozenset[str],
    sym_ctx: _RepoSymbolContext,
    *,
    force_metric_column: bool = False,
) -> list[MechanismViolation]:
    violations: list[MechanismViolation] = []
    code = snippet.strip()
    if not code:
        return violations

    # 1. Alert policy resource citations (`google_monitoring_alert_policy.<label>`)
    for am in _ALERT_POLICY_REF_RE.finditer(code):
        lbl = am.group(1)
        if lbl not in alert_labels:
            violations.append(
                MechanismViolation(
                    file=rel_path,
                    line=line_no,
                    kind="unresolved_alert_policy_citation",
                    detail=(
                        f"Cites `google_monitoring_alert_policy.{lbl}`, which does not "
                        "exist in infra/**/*.tf"
                    ),
                )
            )

    # 2. Explicit GMP descriptor (`prometheus.googleapis.com/cage_...`)
    w_match = _WILDCARD_METRIC_RE.match(code)
    if w_match is not None:
        prefix = w_match.group(1)
        if prefix != "cage_" and not any(m.startswith(prefix) for m in metric_names):
            violations.append(
                MechanismViolation(
                    file=rel_path,
                    line=line_no,
                    kind="unresolved_metric_prefix_citation",
                    detail=(
                        f"Cites metric family wildcard `{code}`, which matches zero "
                        "registered Prometheus metrics"
                    ),
                )
            )
        return violations

    for gmp_m in _GMP_DESCRIPTOR_RE.finditer(code):
        mname = gmp_m.group(1)
        if mname not in valid_metrics:
            violations.append(
                MechanismViolation(
                    file=rel_path,
                    line=line_no,
                    kind="unresolved_metric_citation",
                    detail=f"Cites GMP metric `{mname}`, which is not registered in src/ or infra/",
                )
            )

    # Skip file paths, URLs, HCL assignments, function/decorator syntax for bare token checks
    if (
        "/" in code
        or ("=" in code and "{" not in code)
        or code.startswith(("@", "var.", "local.", "module."))
        or code.endswith(")")
    ):
        return violations

    # 3. Labeled Prometheus series (`cage_foo_total{outcome="blocked"}`)
    labeled_matched: set[str] = set()
    for lm in _LABELED_METRIC_RE.finditer(code):
        mname = lm.group(1)
        labeled_matched.add(mname)
        if mname not in valid_metrics:
            violations.append(
                MechanismViolation(
                    file=rel_path,
                    line=line_no,
                    kind="unresolved_metric_citation",
                    detail=(
                        f"Cites labeled Prometheus series `{mname}{{...}}`, "
                        "which is not registered in src/ or infra/"
                    ),
                )
            )

    # 4. Metric-table column cells (catches non-`cage_` collector typos like `ftra_llm_parse_failures_total`)
    base_code = code.split("{", 1)[0].strip()
    if force_metric_column and re.match(r"^[a-z][a-z0-9_]+$", base_code):
        if base_code not in valid_metrics and base_code not in labeled_matched:
            violations.append(
                MechanismViolation(
                    file=rel_path,
                    line=line_no,
                    kind="unresolved_metric_citation",
                    detail=(
                        f"Metrics table cites `{base_code}`, which is not registered "
                        "in src/ or infra/"
                    ),
                )
            )
        return violations

    # 5. Bare `cage_<subsystem>_<metric>` snippet
    if (
        base_code == code
        and code not in labeled_matched
        and _is_prometheus_metric_identifier(code, sym_ctx)
        and code not in valid_metrics
    ):
        violations.append(
            MechanismViolation(
                file=rel_path,
                line=line_no,
                kind="unresolved_metric_citation",
                detail=f"Cites Prometheus metric `{code}`, which is not registered in src/ or infra/",
            )
        )

    return violations


def _check_oscal_and_doc_citations(
    repo_root: Path,
    snapshot: InventorySnapshot,
    *,
    poam_222_open: bool,
) -> list[MechanismViolation]:
    violations: list[MechanismViolation] = []
    valid_metrics = snapshot.all_resolvable_prometheus_names()
    metric_names = frozenset(m.name for m in snapshot.prometheus_metrics)
    alert_labels = snapshot.alert_policy_labels()
    sym_ctx = _discover_non_metric_repo_symbols(repo_root)

    poam_path = repo_root / "docs" / "POAM.md"
    poam_text = (
        poam_path.read_text(encoding="utf-8", errors="replace")
        if poam_path.is_file()
        else None
    )

    for path in _iter_in_scope_doc_and_oscal_files(repo_root):
        rel_path = path.relative_to(repo_root).as_posix()

        if rel_path.startswith(f"{RETRACTED_ARCHIVE}/"):
            retract_err = _verify_retracted_file_notice(path, rel_path, poam_text)
            if retract_err is not None:
                violations.append(retract_err)
                # Fall through and scan unmarked file in full!
            else:
                continue

        if rel_path in _HISTORICAL_LEDGER_PATHS:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.suffix == ".md":
            is_ttm = (
                rel_path
                == "compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md"
            )
            for m in _INLINE_BACKTICK_RE.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                violations.extend(
                    _check_backtick_snippet_mechanisms(
                        m.group(1),
                        rel_path,
                        line_no,
                        valid_metrics,
                        metric_names,
                        alert_labels,
                        sym_ctx,
                    )
                )

            for cell_line, cell_text in _extract_markdown_metric_table_cells(
                text, skip_langfuse_col=(is_ttm and poam_222_open)
            ):
                for m in _INLINE_BACKTICK_RE.finditer(cell_text):
                    violations.extend(
                        _check_backtick_snippet_mechanisms(
                            m.group(1),
                            rel_path,
                            cell_line,
                            valid_metrics,
                            metric_names,
                            alert_labels,
                            sym_ctx,
                            force_metric_column=True,
                        )
                    )
        else:
            # OSCAL YAML (`compliance/oscal/**/*.yaml`)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue
                for am in _ALERT_POLICY_REF_RE.finditer(line):
                    lbl = am.group(1)
                    if lbl not in alert_labels:
                        violations.append(
                            MechanismViolation(
                                file=rel_path,
                                line=line_no,
                                kind="unresolved_oscal_alert_policy",
                                detail=(
                                    f"OSCAL cites google_monitoring_alert_policy.{lbl}, "
                                    "which does not exist in infra/**/*.tf"
                                ),
                            )
                        )
                for lm in _LABELED_METRIC_RE.finditer(line):
                    mname = lm.group(1)
                    if mname not in valid_metrics:
                        violations.append(
                            MechanismViolation(
                                file=rel_path,
                                line=line_no,
                                kind="unresolved_oscal_metric",
                                detail=(
                                    f"OSCAL cites labeled Prometheus series {mname!r}, "
                                    "which is not registered in src/ or infra/"
                                ),
                            )
                        )
                for cm in re.finditer(
                    r"(?<![A-Za-z0-9_./@-])(cage_[a-z0-9]+_[a-z0-9_]+)(?![A-Za-z0-9_./-])",
                    line,
                ):
                    tok = cm.group(1)
                    if _is_prometheus_metric_identifier(tok, sym_ctx) and (
                        tok not in valid_metrics
                    ):
                        violations.append(
                            MechanismViolation(
                                file=rel_path,
                                line=line_no,
                                kind="unresolved_oscal_metric",
                                detail=(
                                    f"OSCAL cites Prometheus metric {tok!r}, "
                                    "which is not registered in src/ or infra/"
                                ),
                            )
                        )

    return list(dict.fromkeys(violations))


# ---------------------------------------------------------------------------
# Check 4: THRESHOLD_TRACEABILITY_MATRIX.md & POAM-2026-222 Binding
# ---------------------------------------------------------------------------


def _parse_poam_222_status(poam_path: Path) -> tuple[str | None, int]:
    """Return ``(normalized_status_lower, line_number)`` for ``POAM-2026-222`` in ``docs/POAM.md``."""
    if not poam_path.is_file():
        return None, 1
    text = poam_path.read_text(encoding="utf-8", errors="replace")

    # 1. Detail section `### POAM-2026-222: ...` -> `**Status:** <val>`
    detail_m = re.search(
        r"(?m)^###\s+POAM-2026-222\b[^\n]*$",
        text,
    )
    detail_status: str | None = None
    detail_line = 1
    if detail_m is not None:
        detail_line = text.count("\n", 0, detail_m.start()) + 1
        next_h = re.search(r"(?m)^###?\s+", text[detail_m.end() :])
        sec_end = detail_m.end() + next_h.start() if next_h is not None else len(text)
        sec_body = text[detail_m.end() : sec_end]
        st_m = re.search(
            r"(?mi)^\*\*Status:\*\*[ \t]*([A-Za-z_-]+)",
            sec_body,
        )
        if st_m is not None:
            detail_line = text.count("\n", 0, detail_m.end() + st_m.start()) + 1
            detail_status = st_m.group(1).strip().lower()

    # 2. Check summary sections (`## Open Items` vs `## Closed Items`) for consistency
    summary_status: str | None = None
    current_section: str | None = None
    for idx, line in enumerate(text.splitlines(), start=1):
        sec_hdr = re.match(
            r"^##\s+(Open|Closed)\s+Items\b", line.strip(), re.IGNORECASE
        )
        if sec_hdr:
            current_section = sec_hdr.group(1).strip().lower()
            continue
        if re.match(r"^\|\s*\*?\*?POAM-2026-222\*?\*?\s*\|", line):
            if current_section in ("open", "closed"):
                summary_status = current_section
                if detail_status is None:
                    detail_line = idx
            else:
                cells = [c.strip().lower() for c in line.strip().strip("|").split("|")]
                for cell in cells:
                    if cell in ("open", "closed"):
                        summary_status = cell
                        if detail_status is None:
                            detail_line = idx
                        break

    if detail_status and summary_status and detail_status != summary_status:
        # Contradictory status between summary table and detail section: treat as non-open
        # so closure checks fire AND report the mismatch.
        return f"contradictory({summary_status}!={detail_status})", detail_line

    return (detail_status or summary_status), detail_line


def _extract_markdown_section(text: str, heading_prefix: str) -> tuple[str, int] | None:
    """Extract section body and starting line for a Markdown heading starting with ``heading_prefix``."""
    level_match = re.match(r"^(#+)\s+", heading_prefix)
    hashes = level_match.group(1) if level_match else "##"
    pat = re.compile(rf"(?m)^{re.escape(heading_prefix)}[^\n]*$")
    m = pat.search(text)
    if m is None:
        return None
    start_line = text.count("\n", 0, m.start()) + 1
    next_pat = re.compile(rf"(?m)^#{{1,{len(hashes)}}}\s+")
    nm = next_pat.search(text, m.end())
    end_pos = nm.start() if nm is not None else len(text)
    return text[m.start() : end_pos], start_line


def _check_ttm_and_poam_222_binding(
    repo_root: Path, snapshot: InventorySnapshot
) -> tuple[list[MechanismViolation], bool]:
    """Validate ``THRESHOLD_TRACEABILITY_MATRIX.md`` against ``POAM-2026-222``.

    Returns ``(violations, poam_222_is_open)``.
    """
    violations: list[MechanismViolation] = []
    ttm_rel = "compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md"
    ttm_path = repo_root / ttm_rel
    poam_path = repo_root / "docs" / "POAM.md"

    status, status_line = _parse_poam_222_status(poam_path)
    poam_is_open = status == "open"

    if not ttm_path.is_file():
        return violations, poam_is_open

    if status is None:
        violations.append(
            MechanismViolation(
                file="docs/POAM.md",
                line=1,
                kind="missing_poam_2026_222_status",
                detail=(
                    "THRESHOLD_TRACEABILITY_MATRIX.md is present, but POAM-2026-222 "
                    "status could not be resolved from docs/POAM.md"
                ),
            )
        )
        return violations, False

    if status.startswith("contradictory("):
        violations.append(
            MechanismViolation(
                file="docs/POAM.md",
                line=status_line,
                kind="contradictory_poam_2026_222_status",
                detail=(
                    f"POAM-2026-222 has contradictory summary vs detail status ({status}) in docs/POAM.md"
                ),
            )
        )

    ttm_text = ttm_path.read_text(encoding="utf-8", errors="replace")
    valid_metrics = snapshot.all_resolvable_prometheus_names()
    sym_ctx = _discover_non_metric_repo_symbols(repo_root)

    # Parse §2.1 Threshold Registry Table
    sec21 = _extract_markdown_section(ttm_text, "### 2.1")
    if sec21 is None:
        violations.append(
            MechanismViolation(
                file=ttm_rel,
                line=1,
                kind="missing_ttm_section_2_1",
                detail="Missing `### 2.1` Threshold Registry Table in THRESHOLD_TRACEABILITY_MATRIX.md",
            )
        )
    else:
        sec21_body, sec21_start_line = sec21
        lula_col_idx: int | None = None
        metric_col_idx: int | None = None
        parsed_rows = 0

        for offset, line in enumerate(sec21_body.splitlines()):
            line_no = sec21_start_line + offset
            stripped = line.strip()
            if not stripped.startswith("|") or not stripped.endswith("|"):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(re.match(r"^:?-{2,}:?$", c) for c in cells if c):
                continue
            if lula_col_idx is None and metric_col_idx is None:
                for idx, hdr in enumerate(cells):
                    low = hdr.lower()
                    if "lula validation" in low:
                        lula_col_idx = idx
                    elif "metric" in low:
                        metric_col_idx = idx
                continue

            parsed_rows += 1
            if lula_col_idx is not None and lula_col_idx < len(cells):
                lula_cell = cells[lula_col_idx]
                for fname in _LULA_FILENAME_RE.findall(lula_cell):
                    if not (repo_root / "compliance" / "lula" / fname).is_file():
                        violations.append(
                            MechanismViolation(
                                file=ttm_rel,
                                line=line_no,
                                kind="missing_ttm_lula_manifest",
                                detail=(
                                    f"§2.1 Lula Validation column cites {fname!r}, "
                                    "which does not exist under compliance/lula/"
                                ),
                            )
                        )

            if metric_col_idx is not None and metric_col_idx < len(cells):
                metric_cell = cells[metric_col_idx]
                # Always check any `cage_*` Prometheus metric cited in §2.1.
                for bm in _INLINE_BACKTICK_RE.finditer(metric_cell):
                    code = bm.group(1).strip()
                    base = code.split("{", 1)[0].strip()
                    if base.startswith("cage_") and (
                        "{" in code or _is_prometheus_metric_identifier(base, sym_ctx)
                    ):
                        if base not in valid_metrics:
                            violations.append(
                                MechanismViolation(
                                    file=ttm_rel,
                                    line=line_no,
                                    kind="unresolved_ttm_prometheus_metric",
                                    detail=(
                                        f"§2.1 monitoring column cites Prometheus metric `{base}`, "
                                        "which is not registered in src/ or infra/"
                                    ),
                                )
                            )

                # When POAM-2026-222 is NOT Open, forbid all un-emitted `cage.<subsys>.<metric>` names!
                if not poam_is_open:
                    for dm in _DOT_METRIC_RE.finditer(metric_cell):
                        violations.append(
                            MechanismViolation(
                                file=ttm_rel,
                                line=line_no,
                                kind="unremediated_ttm_dot_metric",
                                detail=(
                                    f"POAM-2026-222 is {status!r}, but §2.1 still cites "
                                    f"un-emitted Langfuse metric {dm.group(0)!r}"
                                ),
                            )
                        )

        if parsed_rows == 0:
            violations.append(
                MechanismViolation(
                    file=ttm_rel,
                    line=sec21_start_line,
                    kind="empty_ttm_section_2_1",
                    detail="§2.1 Threshold Registry Table in THRESHOLD_TRACEABILITY_MATRIX.md has zero rows",
                )
            )

    if poam_is_open:
        # 1. Verify top-of-document Evidence Withdrawal and Signing Hold notice
        sec1_pos = ttm_text.find("## 1.")
        preamble = ttm_text[:sec1_pos] if sec1_pos != -1 else ttm_text[:2500]
        if (
            "Evidence Withdrawal and Signing Hold" not in preamble
            or "POAM-2026-222" not in preamble
            or "Signing hold:" not in preamble
        ):
            violations.append(
                MechanismViolation(
                    file=ttm_rel,
                    line=1,
                    kind="missing_ttm_signing_hold_notice",
                    detail=(
                        "POAM-2026-222 is Open, so THRESHOLD_TRACEABILITY_MATRIX.md "
                        "must carry the top-level `Evidence Withdrawal and Signing Hold` "
                        "notice naming POAM-2026-222"
                    ),
                )
            )

        # 2. Verify RA-001..RA-004 in §5 remain unsigned
        sec5 = _extract_markdown_section(ttm_text, "## 5.")
        if sec5 is None:
            violations.append(
                MechanismViolation(
                    file=ttm_rel,
                    line=1,
                    kind="missing_ttm_section_5",
                    detail="Missing `## 5.` Risk Acceptance Register in THRESHOLD_TRACEABILITY_MATRIX.md",
                )
            )
        else:
            sec5_body, sec5_line = sec5
            for ra_id in ("RA-001", "RA-002", "RA-003", "RA-004"):
                ra_pat = re.compile(rf"(?m)^###\s+5\.\d+\s+{re.escape(ra_id)}\b[^\n]*$")
                ra_m = ra_pat.search(sec5_body)
                if ra_m is None:
                    violations.append(
                        MechanismViolation(
                            file=ttm_rel,
                            line=sec5_line,
                            kind="missing_ttm_ra_block",
                            detail=f"Missing {ra_id} subsection in §5 while POAM-2026-222 is Open",
                        )
                    )
                    continue
                ra_line = sec5_line + sec5_body.count("\n", 0, ra_m.start())
                next_ra = re.search(r"(?m)^###\s+", sec5_body[ra_m.end() :])
                ra_end = (
                    ra_m.end() + next_ra.start()
                    if next_ra is not None
                    else len(sec5_body)
                )
                ra_block = sec5_body[ra_m.start() : ra_end]

                who_m = re.search(
                    r"(?m)^\|\s*\*\*Who Accepted\*\*\s*\|\s*([^|]+)\|",
                    ra_block,
                )
                date_m = re.search(
                    r"(?m)^\|\s*\*\*Acceptance Date\*\*\s*\|\s*([^|]+)\|",
                    ra_block,
                )
                if who_m is None:
                    violations.append(
                        MechanismViolation(
                            file=ttm_rel,
                            line=ra_line,
                            kind="signed_or_missing_ra_hold",
                            detail=f"{ra_id} is missing `Who Accepted` row while POAM-2026-222 is Open",
                        )
                    )
                    continue

                who_val = who_m.group(1).strip()
                who_line = ra_line + ra_block.count("\n", 0, who_m.start())
                date_val = date_m.group(1).strip() if date_m else ""

                if ra_id in ("RA-001", "RA-002", "RA-003"):
                    is_unsigned = (
                        "[SIGNATURE PENDING]" in who_val
                        and "pending" in date_val.lower()
                    )
                else:
                    # RA-004 is either `[SIGNATURE PENDING]` or interim ISSO review
                    # explicitly stating `AO review required` with no AO signature.
                    is_unsigned = "[SIGNATURE PENDING]" in who_val or (
                        "AO review required" in who_val
                        and "Authorizing Official" not in who_val
                        and "interim" in date_val.lower()
                    )

                if not is_unsigned:
                    violations.append(
                        MechanismViolation(
                            file=ttm_rel,
                            line=who_line,
                            kind="ttm_signing_hold_violated",
                            detail=(
                                f"{ra_id} appears signed or missing `[SIGNATURE PENDING]` "
                                f"(Who Accepted={who_val!r}, Acceptance Date={date_val!r}) "
                                "while POAM-2026-222 is Open"
                            ),
                        )
                    )

        # 3. Verify §6 Approval Block remains unsigned
        sec6 = _extract_markdown_section(ttm_text, "## 6.")
        if sec6 is None:
            violations.append(
                MechanismViolation(
                    file=ttm_rel,
                    line=1,
                    kind="missing_ttm_section_6",
                    detail="Missing `## 6. Approval Block` in THRESHOLD_TRACEABILITY_MATRIX.md",
                )
            )
        else:
            sec6_body, sec6_line = sec6
            if (
                "[SIGNATURE REQUIRED — PENDING AO APPROVAL]" not in sec6_body
                or "POAM-2026-222" not in sec6_body
            ):
                violations.append(
                    MechanismViolation(
                        file=ttm_rel,
                        line=sec6_line,
                        kind="ttm_approval_block_hold_violated",
                        detail=(
                            "§6 Approval Block is missing `[SIGNATURE REQUIRED — PENDING AO APPROVAL]` "
                            "or POAM-2026-222 signing-hold notice while POAM-2026-222 is Open"
                        ),
                    )
                )

            sig_fields_found = 0
            past_sig_banner = False
            for offset, line in enumerate(sec6_body.splitlines()):
                line_no = sec6_line + offset
                if "[SIGNATURE REQUIRED" in line:
                    past_sig_banner = True
                    continue
                if not past_sig_banner:
                    continue
                for field_m in re.finditer(
                    r"(?:Name|Date|Signature|This acceptance expires):\s*([^\s│]+)",
                    line,
                ):
                    sig_fields_found += 1
                    val = field_m.group(1).strip()
                    if not re.match(r"^_{5,}$", val):
                        violations.append(
                            MechanismViolation(
                                file=ttm_rel,
                                line=line_no,
                                kind="ttm_approval_block_signed",
                                detail=(
                                    f"§6 Approval Block field is populated ({val!r}) "
                                    "while POAM-2026-222 is Open"
                                ),
                            )
                        )
            if sig_fields_found == 0:
                violations.append(
                    MechanismViolation(
                        file=ttm_rel,
                        line=sec6_line,
                        kind="missing_ttm_signature_lines",
                        detail="§6 Approval Block contains no blank signature lines to verify",
                    )
                )
    else:
        # POAM-2026-222 is NOT Open: Appendix B must also contain zero `cage.<subsys>.*` dot metrics
        # or unresolved `cage_*` metrics.
        app_b = _extract_markdown_section(ttm_text, "## Appendix B")
        if app_b is not None:
            app_b_body, app_b_line = app_b
            for offset, line in enumerate(app_b_body.splitlines()):
                line_no = app_b_line + offset
                for dm in _DOT_METRIC_RE.finditer(line):
                    violations.append(
                        MechanismViolation(
                            file=ttm_rel,
                            line=line_no,
                            kind="unremediated_ttm_appendix_b_metric",
                            detail=(
                                f"POAM-2026-222 is {status!r}, but Appendix B still cites "
                                f"un-emitted Langfuse metric pattern {dm.group(0)!r}"
                            ),
                        )
                    )
                for bm in _INLINE_BACKTICK_RE.finditer(line):
                    code = bm.group(1).strip()
                    base = code.split("{", 1)[0].strip()
                    if (
                        base.startswith("cage_")
                        and not base.endswith("_*")
                        and (
                            "{" in code
                            or _is_prometheus_metric_identifier(base, sym_ctx)
                        )
                        and base not in valid_metrics
                    ):
                        violations.append(
                            MechanismViolation(
                                file=ttm_rel,
                                line=line_no,
                                kind="unresolved_ttm_appendix_b_metric",
                                detail=(
                                    f"Appendix B cites unresolved Prometheus metric `{base}`"
                                ),
                            )
                        )

    return violations, poam_is_open


# ---------------------------------------------------------------------------
# Public Entry Points & CLI
# ---------------------------------------------------------------------------


def check_mechanism_references(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    enforce_floors: bool = True,
) -> list[MechanismViolation]:
    """Run all four mechanism-reference checks and return any violations."""
    root = repo_root.resolve()
    snapshot = discover_inventory(root)
    if enforce_floors:
        enforce_corpus_floors(snapshot)

    violations: list[MechanismViolation] = []
    violations.extend(_check_infra_prometheus_references(root, snapshot))
    violations.extend(_check_lula_bridge_references(snapshot))
    ttm_violations, poam_222_open = _check_ttm_and_poam_222_binding(root, snapshot)
    violations.extend(ttm_violations)
    violations.extend(
        _check_oscal_and_doc_citations(root, snapshot, poam_222_open=poam_222_open)
    )
    return list(dict.fromkeys(violations))


def verify_mechanism_references(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    enforce_floors: bool = True,
) -> InventorySnapshot:
    """Verify all mechanism references and raise ``CorpusFloorError`` or ``MechanismReferenceError`` on failure."""
    root = repo_root.resolve()
    snapshot = discover_inventory(root)
    if enforce_floors:
        enforce_corpus_floors(snapshot)

    violations: list[MechanismViolation] = []
    violations.extend(_check_infra_prometheus_references(root, snapshot))
    violations.extend(_check_lula_bridge_references(snapshot))
    ttm_violations, poam_222_open = _check_ttm_and_poam_222_binding(root, snapshot)
    violations.extend(ttm_violations)
    violations.extend(
        _check_oscal_and_doc_citations(root, snapshot, poam_222_open=poam_222_open)
    )
    deduped = list(dict.fromkeys(violations))
    if deduped:
        raise MechanismReferenceError(deduped)
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify monitoring, Lula, OSCAL, and TTM mechanism references (zero waivers)."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory to check.",
    )
    parser.add_argument(
        "--no-floors",
        action="store_true",
        help="Skip non-vacuous corpus floor enforcement (for minimal synthetic fixtures).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print discovered inventory counts on success.",
    )
    args = parser.parse_args(argv)

    try:
        snapshot = verify_mechanism_references(
            args.repo_root, enforce_floors=not args.no_floors
        )
    except CorpusFloorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except MechanismReferenceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.verbose:
        print(
            "OK: Mechanism-reference check passed (zero waivers) — "
            f"{len(snapshot.prometheus_metrics)} Prometheus metrics, "
            f"{len(snapshot.alert_policies)} alert policies, "
            f"{len(snapshot.lula_bridge_specs)} Lula bridge specs, "
            f"{len(snapshot.bridge_scores)} compliance-bridge score surfaces."
        )
    else:
        print("OK: Mechanism-reference check passed (zero waivers).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
