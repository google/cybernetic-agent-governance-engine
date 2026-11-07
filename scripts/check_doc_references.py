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

"""scripts/check_doc_references.py

Validates that Markdown documentation files do not contain broken links,
dangling file paths, or outdated Python symbol references with respect to
the live repository tree.

Paths removed from HEAD are cited pinned to a commit where they existed, in
git's own revision syntax: `<sha>:<path>` or `<sha>^:<path>`. A pinned path is
verified against history: the commit must exist and be an ancestor of HEAD, and
the path must exist in that commit. Verification needs full history and fails
closed in a shallow clone (CI checks out with fetch-depth: 0). Pins break if
history is rewritten; whoever rewrites `main` owns re-pinning them.

The label of a Markdown link with a local target is display text: the target is
the reference, and it is what gets verified.

Usage:
    uv run --active python scripts/check_doc_references.py
    uv run --active python scripts/check_doc_references.py --output /tmp/doc_references_report.txt
    uv run --active python scripts/check_doc_references.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import functools
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import tomllib

REPO_ROOT = Path.cwd().resolve()

# The gate's scope, and the only copy of it: CI gate G9 and `make docs-check`
# run this script without --path. CHANGELOG.md and docs/partners/** are outside
# the scope by design (a changelog must be free to name removed paths; the
# partner tree carries a known backlog).
DOC_SCOPE = (
    "README.md",
    "AGENTS.md",
    "COMPLIANCE.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/POAM.md",
    "docs/BREAKING_CHANGES.md",
    "docs/architecture",
    "compliance",
    "infra",
)
DOC_ROOTS = [REPO_ROOT / entry for entry in DOC_SCOPE]

# Markdown link: [text](target)
MD_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# Inline code backticks: `code`
INLINE_CODE_PATTERN = re.compile(r"`([^`\n]+)`")
# Revision-pinned path: `<sha>:<path>` or `<sha>^:<path>`
PINNED_PATH_PATTERN = re.compile(
    r"^(?P<commit>[0-9a-f]{7,40})(?P<parent>\^?):(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*)$"
)
GIT_TIMEOUT_SECONDS = 30

# Concrete file extensions to check
CONCRETE_EXTENSIONS = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".sh",
    ".rego",
    ".co",
    ".sql",
    ".proto",
    ".tf",
    ".tfvars",
    ".hcl",
}

# Literal words or tokens to ignore

# Deliberately documented compliance gap artifacts (cited in NIST RMF as missing)
KNOWN_DOCUMENTED_GAPS = {
    "src.gateway.governance.ftra",
    "src.compliance_bridge.evidence_stream",
    "src.cage_finance.safety.cbf",
    ".roo/rules-code/01-code-standards.md",
    ".github/branch-protection-rules.json",
    "compliance/authorization/PACKAGE_INDEX.md",
    "compliance/governance/ROLES_MATRIX.md",
    "compliance/lula/eu_ecb/component-validations.yaml",
    "compliance/lula/apac_mas/component-validations.yaml",
    "compliance/lula/lula-validation-ai600-supply-chain.yaml",
    "compliance/lula/lula-validation-ai600-privacy.yaml",
    "compliance/lula/sp80053/",
    "compliance/lula/sp80053",
    "compliance/evidence/",
    "compliance/evidence",
    "compliance/eu_ai_act/technical_documentation/",
    "compliance/eu_ai_act/technical_documentation",
    "compliance_bridge/reconciliation_worker.py",
    "compliance_bridge/evidence_stream.py",
    "deployment/TERRAFORM_MIGRATION.md",
    "config/critics.yaml",
    "compliance/ssp/INHERITED_CONTROLS.md",
    "compliance/sar/SAR_TEMPLATE.md",
    "compliance/oscal/us_fed/system-security-plan.yaml",
    "compliance/oscal/us_fed/component-definition.yaml",
    "compliance/oscal/sp80053-profile.yaml",
    "compliance/oscal/sp80053-assessment-results.yaml",
    "compliance/oscal/profiles/cage-moderate-tailored.yaml",
    "compliance/oscal/profiles/",
    "compliance/oscal/profiles",
    "compliance/oscal/plan-of-action-milestones.yaml",
    "compliance/oscal/eu_ecb/system-security-plan.yaml",
    "compliance/oscal/eu_ecb/component-definition.yaml",
    "compliance/oscal/components/cage_iso42001.json",
    "compliance/oscal/components/",
    "compliance/oscal/components",
    "compliance/oscal/assessment-plan.yaml",
    "compliance/oscal/apac_mas/system-security-plan.yaml",
    "compliance/oscal/apac_mas/component-definition.yaml",
    "compliance/lula/us_fed/component-validations.yaml",
    "compliance/lula/sp80053/lula-au-12.yaml",
    "compliance/lula/sp80053/lula-ac-3.yaml",
    "deployment/cloudbuild.yaml",
    "deployment/k8s/generated/debug-downloader.yaml",
    "deployment/k8s/generated/debug-downloader-fix.yaml",
    "deployment/k8s/falco-rules.yaml",
    "deployment/k8s/falco-daemonset.yaml",
    "deployment/k8s/compliance-bridge-servicemonitor.yaml",
    "deployment/k8s/authz-policy-seal.yaml",
    "deployment/k8s/network-policy-seal.yaml",
    "deployment/k8s/mtls-policy.yaml",
    "deployment/k8s/istio-peer-auth.yaml",
    "deployment/k8s/trace-auditor-cron.yaml",
    "docs/RED_TEAM_DATASET_EXTENSION.md",
    "docs/QUICKSTART_AGW.md",
    "docs/QUICKSTART_ACS.md",
    "docs/ISO42001_MANAGEMENT_REVIEW.md",
    "docs/INFRASTRUCTURE_POLICY.md",
    "docs/GIT_HISTORY_SCRUBBING.md",
    "docs/DATA_GOVERNANCE.md",
    "docs/Configuration_Baseline.md",
    "docs/CONTINGENCY_PLAN.md",
    "docs/COMPLIANCE_POLICY.md",
    "docs/CHANGE_MANAGEMENT_PROCESS.md",
    "docs/Authentication_Architecture.md",
    "docs/cage-arxiv-revision-plan",
    "docs/cage-arxiv-reproducibility",
    "docs/cage-arxiv-critical-fixes",
    "docs/cage-arxiv-bibliography",
    "docs/ai600-agentic-scope-statement",
    "proof/compliance-trigger-evidence.yaml",
    "oscal-artifacts/index.json",
    "scripts/deploy_sw.py",
    "scripts/check_region_guards.py",
    "docs/paper/FPR_IMPROVEMENT_PLAN.md",
    "docs/templates/COMPLIANCE_STATUS_REPORT.md",
    "docs/TECHNICAL_DECOMMISSION_GUIDELINES.md",
    "docs/System_Interconnection_Agreements.md",
    "docs/SYSTEM_BOUNDARY_DIAGRAM.md",
    "docs/SECURITY_POLICY.md",
    "docs/SECRET_MANAGEMENT_OPTIONS.md",
    "docs/security/INCIDENT_RESPONSE_PLAN.md",
    "tests/infra/",
    "src/evaluator_agent/",
    "compliance/lula/sp800-53/",
    "compliance/lula/sp800-53",
    "plans/poam-framework-redesign.md",
    "plans/domain_extraction_implementation_plan.md",
    "plans/CAGE_RISK_MATRIX.md",
    "src/cage_sdk/",
    "src/cage_sdk",
    "src/cage_sdk_ts/",
    "src/cage_sdk_ts",
    "scripts/vulnerability_scan.sh",
    "scripts/generate_sbom.sh",
    "scripts/generate_sar.py",
    "scripts/replay_refusal_receipt.py",
    "src/compliance_bridge/oscal_ssp_exporter.py",
    "src/gateway/governance/agw_envelope.py",
    "src/gateway/governance/provider_plugin_loader.py",
    "src/gateway/governance/region_utils.py",
    "test_results/final_summary_20260603T104718.json",
    "src/protos/gateway.js",
    "tests/test_fiscal_limit_guard.py",
    "tests/test_agw_envelope.py",
    "tests/red_team/README.md",
    "tests/integration/test_defer_workflow.py",
    "src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py",
    "src/governed_financial_advisor/infrastructure/mcp_client.py",
    "src/governed_financial_advisor/infrastructure/llm_client.py",
    "src/governed_financial_advisor/infrastructure/llm_client.py:23",
    "src/governed_financial_advisor/governance/nemo_action_registry.py",
    "src/governance/transpiler.py",
    "/.well-known/nexart-node.json",
    ".well-known/nexart-node.json",
    "docs/DATA_RETENTION_POLICY.md",
    "docs/Continuous_Monitoring_Plan.md",
    "docs/AUTHORIZATION_BOUNDARY.md",
    "docs/AI_600_1_IMPLEMENTATION_PLAN.md",
    "docs/AGENT_OPS_ARCHITECTURE.md",
    "docs/AC2_Account_Management_Procedure.md",
    "compliance/risk_acceptance/RISK_ACCEPTANCE_STATEMENT.md",
    "compliance/authorization/AUTHORIZATION_MEMO.md",
    "compliance/poam/POA_AND_M.md",
    "compliance/poam/poam.yaml",
    "deployment/k8s/secret-rotation-cronjob.yaml",
    "src/gateway/server/agw_service_extension.py",
    "docs/Network_Architecture.md",
    "docs/MODEL_OUTPUT_HANDLING.md",
    "docs/MISSION_BUSINESS_PROCESS.md",
    "docs/Flaw_Remediation_Policy.md",
    "docs/EXTERNAL_DEPENDENCY_REGISTER.md",
    "docs/DECOMMISSION_CHECKLIST.md",
    "docs/INTERCONNECTION_AGREEMENTS",
    "docs/INTERCONNECTION_AGREEMENTS/",
    "docs/Supply_Chain_Risk_Assessment.md",
    "docs/SUPPLY_CHAIN_RISK_ASSESSMENT.md",
    "docs/SECURITY_AUDIT_REPORT.md",
    "docs/SECURITY_AUDIT_REPORT.md:758",
    "docs/security/IR_PLAN.md",
    "docs/Incident_Response_Plan.md",
    "docs/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md",
    "src/governed_financial_advisor/requirements.txt",
    "src/governed_financial_advisor/utils/privacy.py",
    "src/governed_financial_advisor/utils/langfuse_utils.py",
    "src/governed_financial_advisor/governance/policy/generated_rules.rego",
    "src/compliance_bridge/requirements.txt",
    "plans/layer_inversion_remediation_plan.md",
    "docs/stpa-control-diagram",
    "docs/SYSTEM_SECURITY_PLAN.md",
    "docs/proposals/004_risk_remediation_plan.md",
    "docs/compliance/us_fed/SECURITY_ASSESSMENT_PLAN.md",
    "docs/compliance/us_fed/SP800-60_INFORMATION_TYPES.md",
    "deployment/deploy_sw.py",
    "docs/governance/ROLES_AND_RESPONSIBILITIES.md",
    "docs/compliance/universal/AI_IP_POLICY.md",
    "docs/compliance/us_fed/CONTINUOUS_MONITORING_STRATEGY.md",
    "docs/MIGRATION_GUIDE_v3.md",
    "docs/whitepapers/CAGE_TECHNICAL_PREPRINT.md",
    str(Path(tempfile.gettempdir()) / "benign_dataset.json"),
    str(Path(tempfile.gettempdir()) / "adversarial_dataset.json"),
    "tests/governance/test_ir_drill.py",
}

IGNORED_TOKENS = {
    "true",
    "false",
    "null",
    "none",
    "main",
    "master",
    "head",
    "code",
    "default",
}


@dataclass
class Issue:
    source_file: Path
    line_number: int
    reference_type: str
    target: str
    reason: str


# Markdown link line anchor: #L<start> or #L<start>-L<end>
LINE_ANCHOR_PATTERN = re.compile(r"#L(\d+)(?:-L(\d+))?$")
# Inline colon line anchor: path/to/file.ext:<line_spec>
COLON_LINE_SPEC_PATTERN = re.compile(
    r"^(?P<path>[A-Za-z0-9_./-]+\.[a-z0-9]+):(?P<spec>\d+(?:[-\u2013]\d+)?(?:,\d+(?:[-\u2013]\d+)?)*)$"
)
# Prose line citation immediately following a file link or inline file path
PROSE_LINE_REF_PATTERN = re.compile(
    r"(?:\[(?P<label>[^\]]+)\]\((?P<link>[^)]+)\)|`(?P<codepath>[A-Za-z0-9_./-]+\.[a-z0-9]+)`)"
    r"(?:\s*,\s*|\s+|\s*\(\s*|\s+at\s+|\s*\(`)(?:`?lines?\s+(?P<spec>\d+(?:[-\u2013]\d+)?(?:\s*,\s*\d+(?:[-\u2013]\d+)?)*)`?)"
)
# Standalone line range on a line that also links a YAML file and a UUID
STANDALONE_LINE_RANGE_PATTERN = re.compile(r"`?lines\s+(?P<spec>\d+[-\u2013]\d+)`?")

# HCL / Terraform block header in .tf files
HCL_HEADER_PATTERN = re.compile(
    r'^\s*(?:(?P<kind>resource|data)\s+"(?P<type>[a-zA-Z0-9_-]+)"\s+"(?P<name>[a-zA-Z0-9_-]+)"'
    r'|(?P<kind2>module|variable|output|check)\s+"(?P<name2>[a-zA-Z0-9_-]+)"'
    r"|(?P<kind3>locals|removed|moved))\s*\{",
    re.MULTILINE,
)
# HCL citations in Markdown backticks
HCL_DECL_SNIPPET_PATTERN = re.compile(
    r'^(?:(?P<kind>resource|data)\s+"(?P<type>[a-z0-9_]+)"\s+"(?P<name>[a-z0-9_]+)"'
    r'|(?P<kind2>module|variable|output|check)\s+"(?P<name2>[a-z0-9_]+)")$'
)
HCL_RES_SNIPPET_PATTERN = re.compile(
    r"^(?P<type>(?:google|kubernetes|helm|random|tls|null|time|local|external|http|archive|terraform)_[a-z0-9_]+)"
    r"\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))*$"
)
HCL_DATA_SNIPPET_PATTERN = re.compile(
    r"^data\.(?P<type>[a-z0-9_]+)\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))*$"
)
HCL_MOD_SNIPPET_PATTERN = re.compile(
    r"^module\.(?P<name>[a-z0-9_]+)(?P<idx>\[[^\]]+\])?(?:\.(?P<attr>[a-z0-9_]+))?$"
)
HCL_NAMED_SNIPPET_PATTERN = re.compile(
    r"^(?P<prefix>var|variable|output|check|locals?)\.(?P<name>[a-z0-9_]+)$"
)
HCL_MOD_META_ARGS = {
    "source",
    "version",
    "count",
    "for_each",
    "providers",
    "depends_on",
}

# Contextual Python symbol patterns:
# 1) `<sym>` in [`file.py`](path.py) or `<sym>` in `path.py`
CTX_PY_IN_PATTERN = re.compile(
    r"(?<!no\s)`(?P<sym>[A-Za-z_][A-Za-z0-9_]*(?:\(\))?)`\s+in\s+"
    r"(?:\[`?(?P<label>[^`\]]+\.py)`?\]\((?P<link>[^)]+\.py(?:#L\d+(?:-L\d+)?)?)\)|`(?P<codepath>[^`]+\.py)`)"
)
# 2) [`file.py`](path.py) (`<sym>`, ...)
CTX_PY_PAREN_PATTERN = re.compile(
    r"\[[^\]]+\]\((?P<link>[^)]+\.py(?:#L\d+(?:-L\d+)?)?)\)\s*\((?P<parens>`[^)]+)\)"
)
PY_CHECKABLE_SYM_PATTERN = re.compile(
    r"^(?:test_[a-zA-Z0-9_]+|Test[A-Za-z0-9_]+|_?[A-Z][A-Z0-9_]{2,}|_[a-z][a-zA-Z0-9_]+|[a-z_][a-zA-Z0-9_]*\(\))$"
)
PY_PAREN_SYM_PATTERN = re.compile(
    r"^(?:test_[a-zA-Z0-9_]+|Test[A-Za-z0-9_]+|[a-z_][a-zA-Z0-9_]*\(\))$"
)
UUID_PATTERN = re.compile(
    r"`(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`"
)


@dataclass(frozen=True)
class TerraformBlock:
    address: str
    file_path: Path
    start_line: int
    end_line: int
    has_index: bool
    module_source: str = ""


def _parse_line_spec(spec: str) -> list[tuple[int, int]]:
    """Parse a line specification like '42', '10-20', or '12, 15-18' into (start, end) pairs."""
    spans: list[tuple[int, int]] = []
    for part in re.split(r"\s*,\s*", spec.strip()):
        match = re.match(r"^(\d+)(?:[-\u2013](\d+))?$", part.strip())
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) is not None else start
            spans.append((start, end))
    return spans


def find_markdown_files() -> list[Path]:
    """Collect all target Markdown files as resolved paths."""
    files: list[Path] = []
    for root in DOC_ROOTS:
        resolved = root.resolve()
        if resolved.is_file() and resolved.suffix == ".md":
            files.append(resolved)
        elif resolved.is_dir():
            files.extend(p.resolve() for p in resolved.rglob("*.md"))
    return sorted(set(files))


def resolve_scoped_markdown_files(path_args: list[str]) -> list[Path]:
    """Resolve explicit --path arguments, allowing .md files or directories outside DOC_ROOTS."""
    default_files = find_markdown_files()
    matched: list[Path] = []
    for raw_path in path_args:
        candidate = Path(raw_path)
        prefix = (
            candidate.resolve()
            if candidate.is_absolute()
            else (REPO_ROOT / candidate).resolve()
        )
        prefix_matches = [
            f for f in default_files if f == prefix or prefix in f.parents
        ]
        if prefix_matches:
            matched.extend(prefix_matches)
        elif prefix.is_file() and prefix.suffix == ".md":
            matched.append(prefix)
        elif prefix.is_dir():
            matched.extend(p.resolve() for p in prefix.rglob("*.md"))
    return sorted(set(matched))


def is_template_or_pattern(text: str) -> bool:
    """Return True if text contains template wildcards or URI markers."""
    # Ignore URI schemes (e.g. gs://, file://, http://)
    if "://" in text:
        return True
    # Ignore placeholders, shell globs, or brace interpolations
    if any(char in text for char in ("<", ">", "{", "}", "*")):
        return True
    return False


def _validate_line_anchor(
    resolved_path: Path, target_path_str: str, *, allow_colon: bool = False
) -> tuple[bool, str]:
    """Validate optional #L<start>[-L<end>] or :<line_spec> anchor against resolved file."""
    stripped = target_path_str.strip().strip("'\"`")
    match = LINE_ANCHOR_PATTERN.search(stripped)
    colon_match = (
        COLON_LINE_SPEC_PATTERN.match(stripped) if (allow_colon and not match) else None
    )
    if not match and not colon_match:
        return True, ""
    anchor_label = match.group(0) if match else f":{colon_match.group('spec')}"  # type: ignore[union-attr]
    if not resolved_path.is_file():
        return (
            False,
            f"Line anchor '{anchor_label}' targets directory '{resolved_path.name}', not a file",
        )
    try:
        file_lines = resolved_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        total_lines = len(file_lines)
    except Exception as err:
        return (
            False,
            f"Failed to read '{resolved_path.name}' for line anchor check: {err}",
        )

    if match:
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else None
        if start < 1:
            return False, f"Line anchor '{anchor_label}' has start line {start} < 1"
        if end is not None and end < start:
            return (
                False,
                f"Line anchor '{anchor_label}' has inverted range ({end} < {start})",
            )
        last_line = end if end is not None else start
        if last_line > total_lines:
            return (
                False,
                f"Line anchor '{anchor_label}' exceeds file length ({total_lines} lines)",
            )
        return True, ""

    for start, end in _parse_line_spec(colon_match.group("spec")):  # type: ignore[union-attr]
        if start < 1:
            return False, f"Line anchor '{anchor_label}' has start line {start} < 1"
        if end < start:
            return (
                False,
                f"Line anchor '{anchor_label}' has inverted range ({end} < {start})",
            )
        if end > total_lines:
            return (
                False,
                f"Line anchor '{anchor_label}' exceeds file length ({total_lines} lines)",
            )
    return True, ""


def _resolve_candidate_path(base_dir: Path, target_path_str: str) -> Path | None:
    """Resolve a relative or repo-root path string to an existing Path on disk, or None."""
    stripped_target = target_path_str.strip().strip("'\"`")
    clean_target = re.split(r"[:#]", stripped_target)[0].strip()
    if (
        not clean_target
        or clean_target.lower() in IGNORED_TOKENS
        or is_template_or_pattern(clean_target)
    ):
        return None
    norm = clean_target[2:] if clean_target.startswith("./") else clean_target
    if (
        clean_target in KNOWN_DOCUMENTED_GAPS
        or norm in KNOWN_DOCUMENTED_GAPS
        or stripped_target in KNOWN_DOCUMENTED_GAPS
    ):
        return None

    candidates = [
        # 1. Direct from repo root
        REPO_ROOT / norm,
        # 2. Relative to the document base directory
        base_dir / clean_target,
        # 3. Subtree aliases
        REPO_ROOT / "docs" / norm,
        REPO_ROOT / "compliance" / norm,
        REPO_ROOT / "docs" / "compliance" / norm,
        REPO_ROOT / "src" / norm,
        REPO_ROOT / "src" / "gateway" / norm,
        REPO_ROOT / "src" / "gateway" / "governance" / norm,
        REPO_ROOT / "src" / "gateway" / "governance" / "nemo" / norm,
        REPO_ROOT / "src" / "governed_financial_advisor" / norm,
        REPO_ROOT / "src" / "governed_financial_advisor" / norm.replace("src/", ""),
        REPO_ROOT
        / norm.replace("src/integrations/flowsignal", "src/integrations/provider_01"),
        REPO_ROOT / "src" / "governed_financial_advisor" / "tools" / norm,
        REPO_ROOT / "src" / "governed_financial_advisor" / "agents" / norm,
        REPO_ROOT / "src" / "integrations" / norm,
        REPO_ROOT / "docs" / "compliance" / "us_fed" / norm,
        REPO_ROOT / "docs" / "compliance" / "universal" / norm,
        REPO_ROOT / "docs" / "governance" / norm,
        REPO_ROOT / "docs" / "operations" / norm,
        REPO_ROOT / "docs" / "project" / norm,
        REPO_ROOT / "compliance" / "rar" / norm,
        REPO_ROOT / "compliance" / "categorization" / norm,
        REPO_ROOT / "compliance" / "boundary" / norm,
        REPO_ROOT / "compliance" / "lula" / norm,
        REPO_ROOT / "docs" / "architecture" / norm,
        REPO_ROOT / "docs" / "compliance" / "cross-region" / norm,
        REPO_ROOT / "src" / "gateway" / "governance" / "opa" / norm,
        REPO_ROOT / "src" / "gateway" / "governance" / "opa" / norm.replace("opa/", ""),
        REPO_ROOT / "src" / "cage_finance" / "opa" / norm.replace("opa/", ""),
        REPO_ROOT / "src" / "cage_healthcare" / "opa" / norm.replace("opa/", ""),
        REPO_ROOT
        / "src"
        / "compliance_bridge"
        / norm.replace("compliance_bridge/", ""),
        REPO_ROOT / "src" / "compliance_bridge" / norm,
        REPO_ROOT
        / "src"
        / "gateway"
        / "compliance_bridge"
        / norm.replace("compliance_bridge/", ""),
        REPO_ROOT / "src" / "cage_healthcare" / "policy" / norm.replace("opa/", ""),
        REPO_ROOT / "config" / norm,
        REPO_ROOT / "local" / "plans" / norm.replace("plans/", ""),
        REPO_ROOT / "local" / norm,
        REPO_ROOT / "compliance" / "continuous-monitoring" / norm,
        REPO_ROOT / "local" / "plans" / "remediation" / norm,
        REPO_ROOT / "scripts" / norm,
        REPO_ROOT / "infra" / "targets" / "gcp-gke" / norm,
    ]
    if norm.startswith("compliance/"):
        candidates.append(REPO_ROOT / "docs" / norm)

    has_line_anchor = bool(
        LINE_ANCHOR_PATTERN.search(stripped_target)
        or COLON_LINE_SPEC_PATTERN.match(stripped_target)
    )
    for cand in candidates:
        try:
            resolved = cand.resolve()
            if resolved.exists():
                if has_line_anchor and not resolved.is_file():
                    continue
                return resolved
        except Exception:
            continue
    return None


def verify_file_path(
    base_dir: Path, target_path_str: str, *, allow_colon_anchor: bool = False
) -> tuple[bool, str]:
    """Verify if a relative or repo-root path exists on disk and validate any #L or :line anchor."""
    stripped_target = target_path_str.strip().strip("'\"`")
    clean_target = re.split(r"[:#]", stripped_target)[0].strip()
    if not clean_target or clean_target.lower() in IGNORED_TOKENS:
        return True, ""

    if is_template_or_pattern(clean_target):
        return True, ""

    norm = clean_target[2:] if clean_target.startswith("./") else clean_target
    if (
        clean_target in KNOWN_DOCUMENTED_GAPS
        or norm in KNOWN_DOCUMENTED_GAPS
        or stripped_target in KNOWN_DOCUMENTED_GAPS
    ):
        return True, ""

    resolved = _resolve_candidate_path(base_dir, target_path_str)
    if resolved is not None:
        return _validate_line_anchor(
            resolved, target_path_str, allow_colon=allow_colon_anchor
        )

    return False, f"Target path '{clean_target}' does not exist on disk"


def _git(repo_root: Path, *args: str) -> tuple[bool, str]:
    """Run git with a fixed argument list (no shell) in *repo_root*."""
    git = shutil.which("git")
    if git is None:
        return False, "git is not installed"
    try:
        result = subprocess.run(
            [git, *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, str(err)
    return result.returncode == 0, result.stdout.strip()


@functools.lru_cache(maxsize=8)
def _history_unavailable(repo_root: Path) -> str:
    """Return why pinned paths cannot be verified in *repo_root*, or "" if they can."""
    if shutil.which("git") is None:
        return "git is not installed, so pinned paths cannot be verified"
    ok, out = _git(repo_root, "rev-parse", "--is-shallow-repository")
    if not ok:
        return "not a git repository, so pinned paths cannot be verified"
    if out == "true":
        return (
            "shallow clone: pinned paths need full history "
            "(git fetch --unshallow; in CI, actions/checkout fetch-depth: 0)"
        )
    return ""


def verify_pinned_path(commit: str, parent: str, path: str) -> tuple[bool, str]:
    """Verify `<commit>[^]:<path>`: an ancestor of HEAD whose tree holds *path*."""
    unavailable = _history_unavailable(REPO_ROOT)
    if unavailable:
        return False, unavailable
    if not _git(REPO_ROOT, "cat-file", "-e", f"{commit}^{{commit}}")[0]:
        return False, f"'{commit}' is not a commit in this repository"
    if not _git(REPO_ROOT, "merge-base", "--is-ancestor", commit, "HEAD")[0]:
        return False, f"commit '{commit}' is not an ancestor of HEAD"
    revision = f"{commit}{parent}"
    if not _git(REPO_ROOT, "cat-file", "-e", f"{revision}:{path}")[0]:
        return False, f"'{path}' does not exist at {revision}"
    return True, ""


def _parse_tf_blocks(text: str, tf_path: Path) -> list[TerraformBlock]:
    """Extract resource, data, module, variable, output, check, local, and removed/moved blocks."""
    lines = text.splitlines()
    blocks: list[TerraformBlock] = []
    resolved_tf = tf_path.resolve() if tf_path.is_absolute() else tf_path
    for match in HCL_HEADER_PATTERN.finditer(text):
        start_line = text.count("\n", 0, match.start()) + 1
        brace_pos = match.end() - 1
        depth = 0
        in_str = False
        esc = False
        end_pos = len(text)
        idx = brace_pos
        while idx < len(text):
            ch = text[idx]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == "#" or (
                    ch == "/" and idx + 1 < len(text) and text[idx + 1] == "/"
                ):
                    nl = text.find("\n", idx)
                    if nl == -1:
                        break
                    idx = nl
                elif ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_pos = idx + 1
                        break
            idx += 1
        end_line = text.count("\n", 0, end_pos) + 1
        block_body = text[match.start() : end_pos]
        has_index = bool(re.search(r"^\s*(?:count|for_each)\s*=", block_body, re.M))
        if match.group("kind"):
            kind = match.group("kind")
            res_type = match.group("type")
            res_name = match.group("name")
            addr = (
                f"{res_type}.{res_name}"
                if kind == "resource"
                else f"data.{res_type}.{res_name}"
            )
            blocks.append(
                TerraformBlock(addr, resolved_tf, start_line, end_line, has_index)
            )
        elif match.group("kind2"):
            kind2 = match.group("kind2")
            name2 = match.group("name2")
            if kind2 == "module":
                src_match = re.search(r'^\s*source\s*=\s*"([^"]+)"', block_body, re.M)
                mod_source = src_match.group(1) if src_match else ""
                blocks.append(
                    TerraformBlock(
                        f"module.{name2}",
                        resolved_tf,
                        start_line,
                        end_line,
                        has_index,
                        mod_source,
                    )
                )
            elif kind2 == "variable":
                blocks.append(
                    TerraformBlock(
                        f"var.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
                blocks.append(
                    TerraformBlock(
                        f"variable.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
            elif kind2 == "output":
                blocks.append(
                    TerraformBlock(
                        f"output.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
            elif kind2 == "check":
                blocks.append(
                    TerraformBlock(
                        f"check.{name2}", resolved_tf, start_line, end_line, False
                    )
                )
        elif match.group("kind3") == "locals":
            brace_depth = 0
            local_starts: list[tuple[str, int]] = []
            for l_idx in range(start_line, end_line + 1):
                line_s = lines[l_idx - 1]
                clean_l = re.sub(r"(#|//).*$", "", line_s)
                if brace_depth == 1:
                    key_m = re.match(r"^\s*([a-zA-Z0-9_]+)\s*=", clean_l)
                    if key_m:
                        local_starts.append((key_m.group(1), l_idx))
                brace_depth += clean_l.count("{") - clean_l.count("}")
            for idx_k, (key_name, l_start) in enumerate(local_starts):
                l_end = (
                    local_starts[idx_k + 1][1] - 1
                    if idx_k + 1 < len(local_starts)
                    else end_line - 1
                )
                l_end = max(l_start, l_end)
                blocks.append(
                    TerraformBlock(
                        f"local.{key_name}", resolved_tf, l_start, l_end, False
                    )
                )
                blocks.append(
                    TerraformBlock(
                        f"locals.{key_name}", resolved_tf, l_start, l_end, False
                    )
                )
        elif match.group("kind3") in {"removed", "moved"}:
            from_m = re.search(r"^\s*from\s*=\s*([a-zA-Z0-9_.-]+)", block_body, re.M)
            if from_m:
                blocks.append(
                    TerraformBlock(
                        from_m.group(1), resolved_tf, start_line, end_line, False
                    )
                )
    return blocks


@functools.lru_cache(maxsize=8)
def _get_terraform_index(
    repo_root: Path,
) -> tuple[
    dict[str, list[TerraformBlock]],
    dict[Path, dict[str, tuple[int, int]]],
    dict[Path, set[str]],
]:
    """Index all .tf files under repo_root/infra."""
    by_addr: dict[str, list[TerraformBlock]] = {}
    by_file: dict[Path, dict[str, tuple[int, int]]] = {}
    mod_attrs: dict[Path, set[str]] = {}
    infra_dir = repo_root / "infra"
    if not infra_dir.is_dir():
        return by_addr, by_file, mod_attrs
    for tf_path in sorted(infra_dir.rglob("*.tf")):
        try:
            text = tf_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for block in _parse_tf_blocks(text, tf_path):
            by_addr.setdefault(block.address, []).append(block)
            by_file.setdefault(block.file_path, {})[block.address] = (
                block.start_line,
                block.end_line,
            )
            if block.address.startswith(("output.", "var.")):
                mod_attrs.setdefault(block.file_path.parent.resolve(), set()).add(
                    block.address.split(".", 1)[1]
                )
    return by_addr, by_file, mod_attrs


def verify_terraform_snippet(
    code_snippet: str, pinned_tf_addrs: set[str] | None = None
) -> tuple[bool, str] | None:
    """If *code_snippet* is a Terraform/HCL symbol or declaration, verify it against infra/*.tf."""
    if any(code_snippet.endswith(ext) for ext in CONCRETE_EXTENSIONS):
        return None
    by_addr, _, mod_attrs = _get_terraform_index(REPO_ROOT)
    if not by_addr:
        return None
    pinned = pinned_tf_addrs or set()

    decl_m = HCL_DECL_SNIPPET_PATTERN.match(code_snippet)
    if decl_m:
        if decl_m.group("kind"):
            addr = (
                f"{decl_m.group('type')}.{decl_m.group('name')}"
                if decl_m.group("kind") == "resource"
                else f"data.{decl_m.group('type')}.{decl_m.group('name')}"
            )
        else:
            kind2 = decl_m.group("kind2")
            name2 = decl_m.group("name2")
            addr = f"var.{name2}" if kind2 == "variable" else f"{kind2}.{name2}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform declaration '{code_snippet}' ({addr}) does not exist in infra/*.tf",
            )
        return True, ""

    res_m = HCL_RES_SNIPPET_PATTERN.match(code_snippet)
    if res_m:
        addr = f"{res_m.group('type')}.{res_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform resource '{addr}' does not exist in infra/*.tf",
            )
        if res_m.group("idx") and addr in by_addr:
            if not any(b.has_index for b in by_addr[addr]):
                return (
                    False,
                    f"Terraform resource '{addr}' has no count/for_each but is cited with index '{res_m.group('idx')}'",
                )
        return True, ""

    data_m = HCL_DATA_SNIPPET_PATTERN.match(code_snippet)
    if data_m:
        addr = f"data.{data_m.group('type')}.{data_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform data source '{addr}' does not exist in infra/*.tf",
            )
        return True, ""

    mod_m = HCL_MOD_SNIPPET_PATTERN.match(code_snippet)
    if mod_m:
        addr = f"module.{mod_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform module '{addr}' does not exist in infra/*.tf",
            )
        attr = mod_m.group("attr")
        if attr and attr not in HCL_MOD_META_ARGS and addr in by_addr:
            found_attr = False
            for block in by_addr[addr]:
                if block.module_source:
                    mod_dir = (block.file_path.parent / block.module_source).resolve()
                    if attr in mod_attrs.get(mod_dir, set()):
                        found_attr = True
                        break
            if not found_attr:
                return (
                    False,
                    f"Attribute/output '{attr}' not found in Terraform module '{addr}'",
                )
        return True, ""

    named_m = HCL_NAMED_SNIPPET_PATTERN.match(code_snippet)
    if named_m:
        addr = f"{named_m.group('prefix')}.{named_m.group('name')}"
        if addr not in by_addr and addr not in pinned:
            return (
                False,
                f"Terraform symbol '{code_snippet}' does not exist in infra/*.tf",
            )
        return True, ""

    return None


@functools.lru_cache(maxsize=256)
def _get_python_file_symbols(py_path: Path, _depth: int = 0) -> set[str]:
    """Collect defined, imported, attribute, and identifier-constant symbols from a Python file."""
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    syms: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            syms.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    syms.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            syms.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                syms.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                syms.add(alias.asname or alias.name)
            if _depth == 0 and node.module and node.module.startswith("src."):
                mod_file = (REPO_ROOT / Path(*node.module.split("."))).with_suffix(
                    ".py"
                )
                if mod_file.is_file():
                    syms.update(_get_python_file_symbols(mod_file, _depth=1))
        elif isinstance(node, ast.arg):
            syms.add(node.arg)
        elif isinstance(node, ast.Attribute):
            syms.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", node.value):
                syms.add(node.value)
    return syms


@functools.lru_cache(maxsize=256)
def _get_python_symbol_spans(py_path: Path) -> list[tuple[str, int, int]]:
    """Return (name, start_line, end_line) for functions and classes in a Python file."""
    try:
        tree = ast.parse(py_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    spans: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end_l = getattr(node, "end_lineno", None) or node.lineno
            spans.append((node.name.lower(), node.lineno, end_l))
    return spans


@functools.lru_cache(maxsize=64)
def _get_yaml_uuid_span(yaml_path: Path, uuid_str: str) -> tuple[int, int] | None:
    """Return the (start_line, end_line) of a `- uuid: <uuid_str>` list item in a YAML file."""
    try:
        lines = yaml_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    item_re = re.compile(r"^(\s*)-\s+uuid:\s*" + re.escape(uuid_str) + r"\s*$")
    for idx, line in enumerate(lines):
        match = item_re.match(line)
        if match:
            indent = len(match.group(1))
            start_line = idx + 1
            end_line = len(lines)
            for j in range(idx + 1, len(lines)):
                lj = lines[j]
                if not lj.strip() or lj.lstrip().startswith("#"):
                    continue
                cur_indent = len(lj) - len(lj.lstrip())
                if cur_indent < indent or (
                    cur_indent == indent and lj.lstrip().startswith("- ")
                ):
                    end_line = j
                    break
            return start_line, end_line
    return None


def verify_python_symbol(symbol_str: str) -> tuple[bool, str]:
    """Verify qualified module.Symbol references (e.g. src.gateway.symbolic_governor.SymbolicGovernor)."""
    clean_sym = symbol_str.strip()
    if clean_sym in KNOWN_DOCUMENTED_GAPS or any(
        clean_sym == g or clean_sym.startswith(g) for g in KNOWN_DOCUMENTED_GAPS
    ):
        return True, ""

    if is_template_or_pattern(symbol_str):
        return True, ""

    parts = symbol_str.split(".")
    if len(parts) < 2 or parts[0] not in {"src", "tests"}:
        return True, ""

    for i in range(len(parts), 0, -1):
        candidate_path = REPO_ROOT.joinpath(*parts[:i])
        candidate_file = candidate_path.with_suffix(".py")
        candidate_init = candidate_path / "__init__.py"
        if (
            candidate_file.is_file()
            or candidate_init.is_file()
            or candidate_path.is_dir()
        ):
            if candidate_init.is_file():
                candidate_file = candidate_init
            elif candidate_path.is_dir() and not candidate_file.is_file():
                return True, ""
            symbol_name = ".".join(parts[i:])
            if not symbol_name:
                return True, ""

            try:
                tree = ast.parse(candidate_file.read_text(encoding="utf-8"))
                top_level_defs = {
                    node.name
                    for node in tree.body
                    if isinstance(
                        node,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    )
                }
                for node in tree.body:
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                top_level_defs.add(target.id)

                root_symbol = symbol_name.split(".")[0]
                if root_symbol not in top_level_defs:
                    return (
                        False,
                        f"Symbol '{root_symbol}' not found in {candidate_file.relative_to(REPO_ROOT)}",
                    )
                return True, ""
            except Exception as err:
                return (
                    False,
                    f"Failed to parse {candidate_file.relative_to(REPO_ROOT)}: {err}",
                )

    return False, f"Could not resolve module path for symbol '{symbol_str}'"


def _audit_line_references_and_contextual_symbols(
    path: Path, line_idx: int, line: str, local_link_labels: list[tuple[int, int]]
) -> list[Issue]:
    """Validate prose line citations, YAML UUID block spans, and contextual Python symbols on *line*."""
    issues: list[Issue] = []
    historical_line = bool(
        re.search(
            r"(`#?\d+`\s+introduced|commits?\s+`[0-9a-f]{7,40}`|at\s+`[0-9a-f]{7,40}`)",
            line,
        )
    )
    code_spans = [
        (cm.start(), cm.end(), cm.group(1).strip())
        for cm in INLINE_CODE_PATTERN.finditer(line)
        if not any(ls <= cm.start() and cm.end() <= le for ls, le in local_link_labels)
    ]
    line_uuids = [m.group("uuid") for m in UUID_PATTERN.finditer(line)]
    if (
        "_STPA_IMPL_UUID" in line
        and "g7000099-stpa-4000-8000-compiler00001" not in line_uuids
    ):
        line_uuids.append("g7000099-stpa-4000-8000-compiler00001")

    for pm in PROSE_LINE_REF_PATTERN.finditer(line):
        target = pm.group("link") or pm.group("codepath")
        spec = pm.group("spec")
        if not target or is_template_or_pattern(target):
            continue
        resolved = _resolve_candidate_path(path.parent, target)
        if resolved is None or not resolved.is_file():
            continue
        try:
            flines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        total_lines = len(flines)
        spans = _parse_line_spec(spec)
        if not spans:
            continue
        bounds_failed = False
        for start, end in spans:
            if start < 1 or end < start or end > total_lines:
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Line Reference",
                        f"{target} (lines {spec})",
                        f"Cited line range {start}-{end} exceeds file length ({total_lines} lines)",
                    )
                )
                bounds_failed = True
            elif not historical_line and start == end and not flines[start - 1].strip():
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Line Reference",
                        f"{target} (line {start})",
                        f"Cited line {start} in '{resolved.name}' is blank",
                    )
                )
                bounds_failed = True
        if bounds_failed or historical_line:
            continue

        # Check clause-local code identifiers against the cited lines (+/- 1 line)
        window_chunks: list[str] = []
        for start, end in spans:
            lo = max(0, start - 2)
            hi = min(total_lines, end + 1)
            window_chunks.append("\n".join(flines[lo:hi]))
        if resolved.suffix == ".py":
            for sym_name, sym_s, sym_e in _get_python_symbol_spans(resolved):
                if any(sym_s <= end and sym_e >= start for start, end in spans):
                    window_chunks.append(sym_name)
        window_text = "\n".join(window_chunks).lower()

        tokens: set[str] = set()
        label_str = pm.group("label") or ""
        if label_str and not any(
            label_str.strip("`").endswith(ext) for ext in CONCRETE_EXTENSIONS
        ):
            for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{1,}", label_str):
                if ident.lower() not in IGNORED_TOKENS:
                    tokens.add(ident.lower())

        for cs_start, cs_end, cs in code_spans:
            if cs_end < pm.start() - 90 or cs_start > pm.end() + 90:
                continue
            between = line[min(cs_end, pm.end()) : max(cs_start, pm.start())]
            if (
                ";" in between
                or ". " in between
                or " — " in between
                or " | " in between
            ):
                continue
            if (
                cs.startswith(("line ", "lines "))
                or cs == resolved.name
                or cs in target
            ):
                continue
            if re.match(
                r"^(?:POAM-|EF\d|PF\d|W\d|Step\s|#\d+|[0-9a-f]{7,40}|\d+|rc=\d+)",
                cs,
                re.IGNORECASE,
            ):
                continue
            for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{1,}", cs):
                low = ident.lower()
                if (
                    low
                    not in {
                        "line",
                        "lines",
                        "true",
                        "false",
                        "none",
                        "null",
                        "staging",
                        "prod",
                        "main",
                        "yaml",
                        "json",
                        "bash",
                        "in",
                        "on",
                        "to",
                        "of",
                        "or",
                        "if",
                    }
                    and low not in resolved.name.lower()
                ):
                    tokens.add(low)
        if tokens and not any(tok in window_text for tok in tokens):
            issues.append(
                Issue(
                    path,
                    line_idx,
                    "Line Reference",
                    f"{target} (lines {spec})",
                    f"Cited line(s) {spec} in '{resolved.name}' do not contain expected clause token(s) {sorted(tokens)[:4]}",
                )
            )

    # Check YAML UUID span when a YAML link, UUID, and `(lines A-B)` appear on the same line
    if line_uuids and not historical_line:
        yaml_links = [
            _resolve_candidate_path(path.parent, m.group(2).strip())
            for m in MD_LINK_PATTERN.finditer(line)
            if m.group(2).strip().endswith((".yaml", ".yml"))
        ]
        resolved_yamls = [y for y in yaml_links if y is not None and y.is_file()]
        if len(resolved_yamls) == 1:
            y_file = resolved_yamls[0]
            for rm in STANDALONE_LINE_RANGE_PATTERN.finditer(line):
                spans = _parse_line_spec(rm.group("spec"))
                if len(spans) == 1:
                    s_line, e_line = spans[0]
                    for u_str in line_uuids:
                        uuid_span = _get_yaml_uuid_span(y_file, u_str)
                        if uuid_span is not None and (s_line, e_line) != uuid_span:
                            issues.append(
                                Issue(
                                    path,
                                    line_idx,
                                    "Line Reference",
                                    f"{y_file.name} (lines {rm.group('spec')})",
                                    f"UUID '{u_str}' block in '{y_file.name}' spans lines {uuid_span[0]}-{uuid_span[1]}, not {s_line}-{e_line}",
                                )
                            )

    # Contextual Python symbol checks:
    for m_in in CTX_PY_IN_PATTERN.finditer(line):
        raw_sym = m_in.group("sym")
        if not PY_CHECKABLE_SYM_PATTERN.match(raw_sym):
            continue
        sym = raw_sym[:-2] if raw_sym.endswith("()") else raw_sym
        target = m_in.group("link") or m_in.group("codepath")
        py_file = _resolve_candidate_path(path.parent, target)
        if py_file and py_file.suffix == ".py":
            py_rel = (
                py_file.relative_to(REPO_ROOT)
                if py_file.is_relative_to(REPO_ROOT)
                else py_file.name
            )
            if sym not in _get_python_file_symbols(py_file):
                issues.append(
                    Issue(
                        path,
                        line_idx,
                        "Python Symbol",
                        f"{py_rel}::{sym}",
                        f"Symbol '{sym}' not found in {py_rel}",
                    )
                )

    for m_paren in CTX_PY_PAREN_PATTERN.finditer(line):
        target = m_paren.group("link")
        parens = m_paren.group("parens")
        py_file = _resolve_candidate_path(path.parent, target)
        if py_file and py_file.suffix == ".py":
            py_rel = (
                py_file.relative_to(REPO_ROOT)
                if py_file.is_relative_to(REPO_ROOT)
                else py_file.name
            )
            syms = _get_python_file_symbols(py_file)
            for cm in INLINE_CODE_PATTERN.finditer(parens):
                raw_s = cm.group(1).strip()
                if PY_PAREN_SYM_PATTERN.match(raw_s):
                    clean_s = raw_s[:-2] if raw_s.endswith("()") else raw_s
                    if clean_s not in syms:
                        issues.append(
                            Issue(
                                path,
                                line_idx,
                                "Python Symbol",
                                f"{py_rel}::{clean_s}",
                                f"Symbol '{clean_s}' not found in {py_rel}",
                            )
                        )

    return issues


def audit_markdown_file(path: Path) -> list[Issue]:
    """Scan a single markdown file for broken file paths, links, and code symbols."""
    issues: list[Issue] = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as err:
        return [Issue(path, 1, "File Read Error", str(path), str(err))]

    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # Collect any revision-pinned .tf addresses on this line for historical HCL lookups
        pinned_tf_addrs: set[str] = set()
        for cm in INLINE_CODE_PATTERN.finditer(line):
            pm = PINNED_PATH_PATTERN.match(cm.group(1).strip())
            if pm and pm["path"].endswith(".tf"):
                rev = f"{pm['commit']}{pm['parent']}"
                ok, out = _git(REPO_ROOT, "show", f"{rev}:{pm['path']}")
                if ok:
                    for blk in _parse_tf_blocks(out, Path(pm["path"])):
                        pinned_tf_addrs.add(blk.address)

        # 1. Standard Markdown links: [Text](target)
        local_link_labels: list[tuple[int, int]] = []
        for link in MD_LINK_PATTERN.finditer(line):
            link_target = link.group(2).strip()
            if (
                link_target.startswith(("http://", "https://", "mailto:"))
                or link_target.startswith("#")
                or is_template_or_pattern(link_target)
            ):
                continue

            # The target is the reference; the label is display text.
            local_link_labels.append(link.span(1))
            valid, reason = verify_file_path(path.parent, link_target)
            if not valid:
                issues.append(
                    Issue(path, line_idx, "Markdown Link", link_target, reason)
                )

        # 2. Inline code backticks: `target`
        is_mutation_row = bool(re.search(r"\|\s*(?:Re-declare|Restore)\s+`", line))
        for code_match in INLINE_CODE_PATTERN.finditer(line):
            if any(
                start <= code_match.start() and code_match.end() <= end
                for start, end in local_link_labels
            ):
                continue
            code_snippet = code_match.group(1).strip()

            if (
                not code_snippet
                or code_snippet.startswith(("-", "$", "@"))
                or is_template_or_pattern(code_snippet)
            ):
                continue

            if not is_mutation_row:
                tf_check = verify_terraform_snippet(code_snippet, pinned_tf_addrs)
                if tf_check is not None:
                    tf_valid, tf_reason = tf_check
                    if not tf_valid:
                        issues.append(
                            Issue(
                                path,
                                line_idx,
                                "Terraform Symbol",
                                code_snippet,
                                tf_reason,
                            )
                        )
                    continue

            if " " in code_snippet:
                continue

            pinned = PINNED_PATH_PATTERN.match(code_snippet)
            if pinned:
                valid, reason = verify_pinned_path(
                    pinned["commit"], pinned["parent"], pinned["path"]
                )
                if not valid:
                    issues.append(
                        Issue(path, line_idx, "Pinned Path", code_snippet, reason)
                    )
                continue

            clean_snippet = re.split(r"[:#]", code_snippet)[0].strip()
            has_ext = any(clean_snippet.endswith(ext) for ext in CONCRETE_EXTENSIONS)
            has_colon_spec = bool(COLON_LINE_SPEC_PATTERN.match(code_snippet))
            is_explicit_path = (
                "/" in clean_snippet
                and (
                    clean_snippet.startswith(
                        ("src/", "tests/", "docs/", "compliance/", "scripts/", "infra/")
                    )
                    or has_ext
                )
            ) or (has_ext and has_colon_spec)

            if is_explicit_path:
                valid, reason = verify_file_path(
                    path.parent, code_snippet, allow_colon_anchor=True
                )
                if not valid and not any(
                    code_snippet.startswith(p) for p in ("../..", "...")
                ):
                    issues.append(
                        Issue(path, line_idx, "File Path", code_snippet, reason)
                    )

            elif (
                code_snippet.startswith(("src.", "tests."))
                and "." in code_snippet
                and not code_snippet.endswith(".")
            ):
                valid, reason = verify_python_symbol(code_snippet)
                if not valid:
                    issues.append(
                        Issue(path, line_idx, "Python Symbol", code_snippet, reason)
                    )

        # 3. Prose line references, YAML UUID spans, and contextual Python symbols
        issues.extend(
            _audit_line_references_and_contextual_symbols(
                path, line_idx, line, local_link_labels
            )
        )

        # 4. Historical assertions require state-serial, audit-log, or git/run history evidence (POAM-2026-169)
        issues.extend(_audit_historical_assertions(path, line_idx, line))

    return issues


HISTORICAL_CLAIM_PATTERN = re.compile(
    r"\b("
    r"verified\s+unfired"
    r"|unfired\s+on"
    r"|therefore\s+unfired"
    r"|never\s+fired"
    r"|(?:has|have|had)\s+never\s+\w+"
    r"|(?:has|have|had)\s+always\s+\w+"
    r"|no\s+evidence\s+of\b"
    r"|was\s+applied\s+via\b"
    r"|always\s+applied\s+via\b"
    r")",
    re.IGNORECASE,
)

DEPLOYMENT_SUBJECT_PATTERN = re.compile(
    r"(<PROJECT_ID>|<WALK_PROJECT_ID>|\bcage-staging\b|\bwas\s+applied\s+via\b|\balways\s+applied\s+via\b|\btherefore\s+unfired\b)",
    re.IGNORECASE,
)

DEPLOYMENT_HISTORICAL_EVIDENCE_PATTERN = re.compile(
    r"("
    r"\bserial:\s*\d+"
    r"|\.tfstate\b"
    r"|\bstate\s+history\b"
    r"|\baudit[- ]log"
    r"|\bCloud Audit Log"
    r"|\bgcloud logging read\b"
    r"|\bprotoPayload\b"
    r"|\bUpdateCluster\b"
    r"|\bCreateCluster\b"
    r"|\boperation-\d+"
    r")",
    re.IGNORECASE,
)

REPO_HISTORICAL_EVIDENCE_PATTERN = re.compile(
    r"("
    r"\bgit\s+log\b"
    r"|\bgit\s+rev-list\b"
    r"|\bactivity_type="
    r"|\brulesets/\d+/history\b"
    r"|\btotal_count:\s*\d+"
    r"|\bcheck[- ]run\s+`?\d+"
    r"|\brun\s+`?\d{8,}"
    r"|\bjob\s+log\b"
    r")",
    re.IGNORECASE,
)


def _audit_historical_assertions(path: Path, line_idx: int, line: str) -> list[Issue]:
    """Flag historical assertions unaccompanied by audit-log, state-serial, or history evidence."""
    if line.lstrip().startswith("#"):
        return []
    match = HISTORICAL_CLAIM_PATTERN.search(line)
    if match is None:
        return []
    if DEPLOYMENT_HISTORICAL_EVIDENCE_PATTERN.search(line):
        return []
    if DEPLOYMENT_SUBJECT_PATTERN.search(line):
        return [
            Issue(
                path,
                line_idx,
                "Historical Claim",
                match.group(0),
                "Deployment/cluster historical assertion requires audit-log or Terraform state-serial (.tfstate / serial: N) evidence on the same line (POAM-2026-169)",
            )
        ]
    if REPO_HISTORICAL_EVIDENCE_PATTERN.search(line):
        return []
    return [
        Issue(
            path,
            line_idx,
            "Historical Claim",
            match.group(0),
            "Historical assertion requires audit-log, state-serial (.tfstate / serial: N), or git-log/run-history evidence on the same line (POAM-2026-169)",
        )
    ]


SEMVER_MAJOR_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
RELEASED_MAJOR_HEADING_PATTERN = re.compile(r"^#\s+v(\d+)\.x\s*$")
UNRELEASED_MAJOR_HEADING_PATTERN = re.compile(
    r"^#\s+Unreleased(?:\s*\(v(\d+)\.x\))?(?:\s*$|\b)",
    re.IGNORECASE,
)
VERSIONED_DOC_FILENAME_PATTERN = re.compile(
    r"(?:^|[_-])v\d+(?:[._-]|$)",
    re.IGNORECASE,
)
LULA_SCHEMA_FILENAME_PATTERN = re.compile(
    r"^lula_v(\d)(\d{2})(\d)_validation\.schema\.json$"
)


def _check_lula_schema_version(repo_root: Path, schema_path: Path) -> list[Issue]:
    """Verify compliance/lula/schemas/lula_v<NNN>_validation.schema.json matches pinned Lula CLI."""
    rel = schema_path.relative_to(repo_root).as_posix()
    match = LULA_SCHEMA_FILENAME_PATTERN.match(schema_path.name)
    if match is None:
        return [
            Issue(
                schema_path,
                1,
                "Version Hygiene",
                rel,
                "Unrecognized versioned Lula schema filename; expected lula_v<M><mm><p>_validation.schema.json",
            )
        ]

    expected_ver = f"v{int(match.group(1))}.{int(match.group(2))}.{int(match.group(3))}"
    issues: list[Issue] = []

    verifier_path = repo_root / "scripts" / "verify_lula_assessment_results.py"
    if verifier_path.is_file():
        verifier_text = verifier_path.read_text(encoding="utf-8")
        if f"Lula {expected_ver}" not in verifier_text:
            issues.append(
                Issue(
                    schema_path,
                    1,
                    "Version Hygiene",
                    rel,
                    f"Schema filename pins Lula {expected_ver}, which does not match scripts/verify_lula_assessment_results.py",
                )
            )

    matrix_workflow = repo_root / ".github" / "workflows" / "compliance-matrix.yml"
    if matrix_workflow.is_file():
        wf_text = matrix_workflow.read_text(encoding="utf-8")
        if expected_ver not in wf_text:
            issues.append(
                Issue(
                    schema_path,
                    1,
                    "Version Hygiene",
                    rel,
                    f"Schema filename pins Lula {expected_ver}, which does not match LULA_VERSION in .github/workflows/compliance-matrix.yml",
                )
            )

    return issues


def audit_version_hygiene(repo_root: Path | None = None) -> list[Issue]:
    """Verify BREAKING_CHANGES.md major-version parity and forbid version-suffixed living doc filenames."""
    root = REPO_ROOT if repo_root is None else repo_root
    issues: list[Issue] = []

    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "pyproject.toml",
                "pyproject.toml is missing",
            )
        )
        return issues

    try:
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "pyproject.toml",
                f"Invalid TOML in pyproject.toml: {exc}",
            )
        )
        return issues

    version_str = str(pyproject_data.get("project", {}).get("version", ""))
    ver_match = SEMVER_MAJOR_PATTERN.match(version_str)
    if ver_match is None:
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                version_str or "project.version",
                "pyproject.toml [project].version must start with major.minor.patch",
            )
        )
        return issues

    current_major = int(ver_match.group(1))
    breaking_doc = root / "docs" / "BREAKING_CHANGES.md"
    if not breaking_doc.is_file():
        issues.append(
            Issue(
                pyproject_path,
                1,
                "Version Hygiene",
                "docs/BREAKING_CHANGES.md",
                "Canonical breaking-changes ledger docs/BREAKING_CHANGES.md is missing",
            )
        )
    else:
        released_majors: dict[int, int] = {}
        unreleased_headings: list[tuple[int, str, int | None]] = []
        in_fence = False
        for line_idx, raw_line in enumerate(
            breaking_doc.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = raw_line.strip()
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            rel_match = RELEASED_MAJOR_HEADING_PATTERN.match(stripped)
            if rel_match is not None:
                released_majors.setdefault(int(rel_match.group(1)), line_idx)
                continue
            unrel_match = UNRELEASED_MAJOR_HEADING_PATTERN.match(stripped)
            if unrel_match is not None:
                parsed_major = (
                    int(unrel_match.group(1))
                    if unrel_match.group(1) is not None
                    else None
                )
                unreleased_headings.append((line_idx, stripped, parsed_major))

        if current_major not in released_majors:
            issues.append(
                Issue(
                    breaking_doc,
                    1,
                    "Version Hygiene",
                    f"# v{current_major}.x",
                    f"docs/BREAKING_CHANGES.md lacks '# v{current_major}.x' section matching pyproject.toml version {version_str}",
                )
            )
        for maj, line_no in sorted(released_majors.items()):
            if maj > current_major:
                issues.append(
                    Issue(
                        breaking_doc,
                        line_no,
                        "Version Hygiene",
                        f"# v{maj}.x",
                        f"Released major section '# v{maj}.x' exceeds pyproject.toml version {version_str} (use '# Unreleased (v{current_major + 1}.x)')",
                    )
                )
        for line_no, heading_text, unrel_major in unreleased_headings:
            if unrel_major != current_major + 1:
                issues.append(
                    Issue(
                        breaking_doc,
                        line_no,
                        "Version Hygiene",
                        heading_text,
                        f"Unreleased major section must be '# Unreleased (v{current_major + 1}.x)' for pyproject.toml version {version_str}",
                    )
                )

    candidates: list[Path] = sorted(root.glob("*.md"))
    docs_dir = root / "docs"
    partners_dir = docs_dir / "partners"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.rglob("*")):
            if not path.is_file():
                continue
            if partners_dir in path.parents:
                continue
            candidates.append(path)

    compliance_dir = root / "compliance"
    lula_schemas_dir = compliance_dir / "lula" / "schemas"
    if compliance_dir.is_dir():
        for path in sorted(compliance_dir.rglob("*")):
            if path.is_file():
                candidates.append(path)

    for candidate in candidates:
        if VERSIONED_DOC_FILENAME_PATTERN.search(candidate.name) is None:
            continue
        if candidate.parent == lula_schemas_dir:
            issues.extend(_check_lula_schema_version(root, candidate))
            continue
        rel_path = candidate.relative_to(root).as_posix()
        issues.append(
            Issue(
                candidate,
                1,
                "Version Hygiene",
                rel_path,
                "Living documentation/compliance filenames must be version-neutral (organize per-version sections inside the file instead of '_v<N>' / '-v<N>' suffixes)",
            )
        )

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify doc references against repo code."
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None, help="Output file path"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--path",
        action="append",
        default=None,
        metavar="PREFIX",
        help=(
            "Restrict the audit to documents under this repo-relative path prefix. "
            "Repeatable. Omit to audit every discovered document."
        ),
    )
    args = parser.parse_args(argv)

    if args.path:
        files = resolve_scoped_markdown_files(args.path)
        print("Scoped to: " + ", ".join(args.path))
    else:
        files = find_markdown_files()

    all_issues: list[Issue] = []

    print(f"Auditing {len(files)} documentation files...")
    if len(files) == 0:
        msg = "No documentation files matched the requested scope.\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(msg, encoding="utf-8")
        else:
            print(msg)
        return 1

    for f in files:
        file_issues = audit_markdown_file(f)
        all_issues.extend(file_issues)

    if not args.path:
        all_issues.extend(audit_version_hygiene(REPO_ROOT))

    out_lines: list[str] = []
    if not all_issues:
        out_lines.append(
            "All documentation references, file paths, and symbols are valid."
        )
        exit_code = 0
    else:
        out_lines.append(f"Found {len(all_issues)} broken documentation references:\n")
        for issue in all_issues:
            try:
                rel_file = issue.source_file.relative_to(REPO_ROOT)
            except ValueError:
                rel_file = issue.source_file
            out_lines.append(
                f"  {rel_file}:{issue.line_number} [{issue.reference_type}] -> {issue.target} ({issue.reason})"
            )
        exit_code = 1

    report_text = "\n".join(out_lines) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report_text, encoding="utf-8")
        print(f"Report written to: {args.output} (Found {len(all_issues)} issues)")
    else:
        print(report_text)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
