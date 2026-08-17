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
EU_ECB compliance posture checks.

Validates:
  1. EU AI Act Lula manifest YAML structure (component-definition key present)
  2. GDPR Art. 44 data residency (eu-prod.tfvars region starts with europe-)
  3. DORA Art. 10 audit logging (eu-dev.tfvars has enable_eu_ecb_compliance)
  4. SR 26-2 telemetry suppression sentinel in EU threshold files

Exit codes:
  0 — all checks pass (warnings are non-fatal)
  1 — any hard check fails
"""

import pathlib
import re
import sys

import yaml


def check_eu_ai_act_manifests() -> list[str]:
    """Check EU AI Act Lula manifest YAML structure."""
    errors = []
    manifests = sorted(
        pathlib.Path("compliance/lula").glob("lula-validation-eu-*.yaml")
    )
    if not manifests:
        print("WARNING: no EU AI Act Lula manifests found — CA-03 remediation pending")
        return errors
    for m in manifests:
        doc = yaml.safe_load(m.read_text())
        if "component-definition" not in doc:
            errors.append(f"{m.name}: missing component-definition key")
        else:
            print(f"  OK {m.name}")
    if not errors:
        print(
            f"All {len(manifests)} EU AI Act Lula manifests passed YAML structure check."
        )
    return errors


def check_gdpr_residency() -> list[str]:
    """Check GDPR Art. 44 data residency in eu-prod.tfvars."""
    errors = []
    tfvars_path = pathlib.Path("infra/targets/gcp-gke/eu-prod.tfvars")
    if not tfvars_path.exists():
        errors.append("infra/targets/gcp-gke/eu-prod.tfvars not found")
        return errors
    content = tfvars_path.read_text()
    m = re.search(r'region\s*=\s*"([^"]+)"', content)
    if not m:
        errors.append("region not found in eu-prod.tfvars")
        return errors
    region = m.group(1)
    if not region.startswith("europe-"):
        errors.append(
            f"GDPR Art. 44 violation — EU_ECB region must be europe-*, got: {region}"
        )
    else:
        print(f"GDPR Art. 44 data residency OK: region={region}")
    m2 = re.search(r'cage_deployment_region\s*=\s*"([^"]+)"', content)
    if not m2 or m2.group(1) != "EU_ECB":
        errors.append("cage_deployment_region must be EU_ECB in eu-prod.tfvars")
    else:
        print("cage_deployment_region=EU_ECB — OK")
    if not re.search(r"enable_eu_ecb_compliance\s*=\s*true", content):
        errors.append("enable_eu_ecb_compliance must be true in eu-prod.tfvars")
    else:
        print("enable_eu_ecb_compliance=true — OK")
    return errors


def check_dora_logging() -> None:
    """Check DORA Art. 10 audit logging in eu-dev.tfvars (warning only)."""
    tfvars_path = pathlib.Path("infra/targets/gcp-gke/eu-dev.tfvars")
    if not tfvars_path.exists():
        print(
            "WARNING: infra/targets/gcp-gke/eu-dev.tfvars not found — skipping DORA check"
        )
        return
    content = tfvars_path.read_text()
    if "enable_eu_ecb_compliance" not in content:
        print("WARNING: enable_eu_ecb_compliance not found in eu-dev.tfvars")
    else:
        print("DORA Art. 10 audit logging configuration present — OK")


def check_sr262_sentinel() -> None:
    """Check SR 26-2 telemetry suppression sentinel in EU threshold files (warning only)."""
    threshold_files = list(pathlib.Path("config/thresholds").glob("*.yaml")) + list(
        pathlib.Path("config/thresholds").glob("*.json")
    )
    eu_files = [f for f in threshold_files if "eu" in f.name.lower()]
    if not eu_files:
        print("WARNING: No EU threshold files found — SR 26-2 sentinel check skipped")
        return
    for f in eu_files:
        content = f.read_text()
        if "no legal force" in content or "SR 26-2" in content:
            print(f"SR 26-2 sentinel present in {f.name} — OK")
        else:
            print(f"WARNING: SR 26-2 sentinel not found in {f.name}")


def check_iso42001_universal_manifests(region_context: str = "EU_ECB") -> list[str]:
    """Check ISO 42001 universal Lula manifests have component-definition key."""
    # Explicit list of universal manifests (ISO 42001 + AARM).
    # Do NOT use a glob — lula-validation-a*.yaml also matches NIST SP 800-53
    # (ac2, ac3, au12) and NIST AI 600-1 (ai600-*) which are US_FED-only.
    universal_manifests = [
        "compliance/lula/lula-validation-a52.yaml",
        "compliance/lula/lula-validation-a53.yaml",
        "compliance/lula/lula-validation-a92.yaml",
        "compliance/lula/lula-validation-aarm-vectors.yaml",
    ]
    errors = []
    validated = []
    for path in universal_manifests:
        m = pathlib.Path(path)
        if not m.exists():
            errors.append(f"{m.name}: file not found")
            continue
        doc = yaml.safe_load(m.read_text())
        if "component-definition" not in doc:
            errors.append(f"{m.name}: missing component-definition key")
        else:
            validated.append(m.name)
            print(f"  OK {m.name}")
    if not errors:
        print(
            f"All {len(validated)} universal ISO 42001 / AARM Lula manifests valid"
            f" ({region_context} context)."
        )
    return errors


def main() -> int:
    all_errors = []

    print("=== EU AI Act Lula manifest structure ===")
    all_errors.extend(check_eu_ai_act_manifests())

    print()
    print("=== GDPR Art. 44 data residency ===")
    all_errors.extend(check_gdpr_residency())

    print()
    print("=== DORA Art. 10 audit logging ===")
    check_dora_logging()

    print()
    print("=== SR 26-2 telemetry suppression sentinel ===")
    check_sr262_sentinel()

    print()
    print("=== ISO 42001 universal Lula manifests (EU_ECB context) ===")
    all_errors.extend(check_iso42001_universal_manifests("EU_ECB"))

    if all_errors:
        print()
        print("FAILURES:")
        for e in all_errors:
            print(f"  ERROR: {e}")
        return 1

    print()
    print("All EU_ECB compliance posture checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
