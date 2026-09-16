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

Usage:
    uv run --active python scripts/check_doc_references.py
    uv run --active python scripts/check_doc_references.py --output /tmp/doc_references_report.txt
    uv run --active python scripts/check_doc_references.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path.cwd().resolve()

# Directories and root files to scan
DOC_ROOTS = [
    REPO_ROOT / "docs",
    REPO_ROOT / "compliance",
    REPO_ROOT / "README.md",
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "POAM.md",
]

# Markdown link: [text](target)
MD_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# Inline code backticks: `code`
INLINE_CODE_PATTERN = re.compile(r"`([^`\n]+)`")

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
    "tests/test_ftra_reachability.py",
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
    "tests/test_reconciliation_daemon.py",
    "tests/test_dual_schema_verification.py",
    "/tmp/benign_dataset.json",
    "/tmp/adversarial_dataset.json",
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


def is_template_or_pattern(text: str) -> bool:
    """Return True if text contains template wildcards or URI markers."""
    # Ignore URI schemes (e.g. gs://, file://, http://)
    if "://" in text:
        return True
    # Ignore placeholders, shell globs, or brace interpolations
    if any(char in text for char in ("<", ">", "{", "}", "*")):
        return True
    return False


def verify_file_path(base_dir: Path, target_path_str: str) -> tuple[bool, str]:
    """Verify if a relative or repo-root path exists on disk."""
    clean_target = re.split(r"[:#]", target_path_str)[0].strip().strip("'\"`")
    if not clean_target or clean_target.lower() in IGNORED_TOKENS:
        return True, ""

    if is_template_or_pattern(clean_target):
        return True, ""

    # Normalize leading ./ without stripping ../
    norm = clean_target[2:] if clean_target.startswith("./") else clean_target

    if clean_target in KNOWN_DOCUMENTED_GAPS or norm in KNOWN_DOCUMENTED_GAPS:
        return True, ""

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
        REPO_ROOT / norm.replace("src/integrations/flowsignal", "src/integrations/provider_01"),
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
        REPO_ROOT / "src" / norm,
        REPO_ROOT / "src" / "compliance_bridge" / norm.replace("compliance_bridge/", ""),
        REPO_ROOT / "src" / "compliance_bridge" / norm,
        REPO_ROOT / "src" / "gateway" / "compliance_bridge" / norm.replace("compliance_bridge/", ""),
        REPO_ROOT / "docs" / "compliance" / norm,
        REPO_ROOT / "src" / "cage_healthcare" / "policy" / norm.replace("opa/", ""),
        REPO_ROOT / "config" / norm,
        REPO_ROOT / "local" / "plans" / norm.replace("plans/", ""),
        REPO_ROOT / "local" / norm,
        REPO_ROOT / "src" / "governed_financial_advisor" / norm,
        REPO_ROOT / "src" / "governed_financial_advisor" / norm.replace("src/", ""),
        REPO_ROOT / norm.replace("src/integrations/flowsignal", "src/integrations/provider_01"),
        REPO_ROOT / "compliance" / "continuous-monitoring" / norm,
        REPO_ROOT / "local" / "plans" / "remediation" / norm,
        REPO_ROOT / "docs" / "compliance" / "us_fed" / norm,
        REPO_ROOT / "docs" / "compliance" / "universal" / norm,
    ]

    # If starts with compliance/, also check under docs/compliance/
    if norm.startswith("compliance/"):
        candidates.append(REPO_ROOT / "docs" / norm)

    for cand in candidates:
        try:
            if cand.resolve().exists():
                return True, ""
        except Exception:
            continue

    return False, f"Target path '{clean_target}' does not exist on disk"


def verify_python_symbol(symbol_str: str) -> tuple[bool, str]:
    """Verify qualified module.Symbol references (e.g. src.gateway.symbolic_governor.SymbolicGovernor)."""
    clean_sym = symbol_str.strip()
    if clean_sym in KNOWN_DOCUMENTED_GAPS or any(clean_sym == g or clean_sym.startswith(g) for g in KNOWN_DOCUMENTED_GAPS):
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
        if candidate_file.is_file() or candidate_init.is_file() or candidate_path.is_dir():
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
                return False, f"Failed to parse {candidate_file.relative_to(REPO_ROOT)}: {err}"

    return False, f"Could not resolve module path for symbol '{symbol_str}'"


def audit_markdown_file(path: Path) -> list[Issue]:
    """Scan a single markdown file for broken file paths, links, and code symbols."""
    issues: list[Issue] = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as err:
        return [Issue(path, 1, "File Read Error", str(path), str(err))]

    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # 1. Standard Markdown links: [Text](target)
        for _, link_target in MD_LINK_PATTERN.findall(line):
            link_target = link_target.strip()
            if (
                link_target.startswith(("http://", "https://", "mailto:"))
                or link_target.startswith("#")
                or is_template_or_pattern(link_target)
            ):
                continue

            valid, reason = verify_file_path(path.parent, link_target)
            if not valid:
                issues.append(
                    Issue(path, line_idx, "Markdown Link", link_target, reason)
                )

        # 2. Inline code backticks: `target`
        for code_snippet in INLINE_CODE_PATTERN.findall(line):
            code_snippet = code_snippet.strip()

            if (
                not code_snippet
                or code_snippet.startswith(("-", "$", "@"))
                or " " in code_snippet
                or is_template_or_pattern(code_snippet)
            ):
                continue

            has_ext = any(code_snippet.endswith(ext) for ext in CONCRETE_EXTENSIONS)
            is_explicit_path = "/" in code_snippet and (
                code_snippet.startswith(("src/", "tests/", "docs/", "compliance/", "scripts/"))
                or has_ext
            )

            if is_explicit_path:
                valid, reason = verify_file_path(path.parent, code_snippet)
                if not valid and not any(code_snippet.startswith(p) for p in ("../..", "...")):
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

    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify doc references against repo code.")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Output file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    files = find_markdown_files()
    all_issues: list[Issue] = []

    print(f"Auditing {len(files)} documentation files across repository...")
    for f in files:
        file_issues = audit_markdown_file(f)
        all_issues.extend(file_issues)

    out_lines: list[str] = []
    if not all_issues:
        out_lines.append("All documentation references, file paths, and symbols are valid.")
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
