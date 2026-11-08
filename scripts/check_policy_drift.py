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

"""Policy Drift Detection Gate (B2).

Verifies that:
1. Core STPA sources (`config/stpa/*.yaml`) compile cleanly without errors.
2. Every selected production domain plugin (`--domain all` by default, or a
   specific installed `cage.plugins` entry point) ships a valid OPA policy
   bundle declaring its `DomainConfig.opa_package` and `opa_required_rules`,
   and any domain STPA YAML sources match their compiled `stpa/` artifacts.
3. `ControlRegistry.active_hash` matches the JCS-canonicalized SHA-256 of the
   on-disk regional compliance baseline (`config/compliance/<REGION>_BASELINE.json`).

Exit codes:
    0  No drift detected.
    1  Drift or missing domain policy rule detected.
    2  Fatal configuration or compilation error.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import inspect
import json
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("check_policy_drift")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT_DIR = _REPO_ROOT / "config" / "stpa"


def _verify_domain_opa_bundle(
    plugin: object, opa_package: str, required_rules: tuple[str, ...]
) -> list[str]:
    """Verify the plugin's on-disk `opa/*.rego` bundle declares its package and required rules."""
    plugin_dir = Path(inspect.getfile(type(plugin))).resolve().parent
    opa_dir = plugin_dir / "opa"
    if not opa_dir.is_dir():
        return [
            f"Domain {getattr(plugin, 'name', '?')!r} missing OPA directory: {opa_dir}"
        ]
    rego_files = [
        p for p in sorted(opa_dir.glob("*.rego")) if not p.name.endswith("_test.rego")
    ]
    if not rego_files:
        return [
            f"Domain {getattr(plugin, 'name', '?')!r} has no non-test .rego files in {opa_dir}"
        ]

    pkg_re = re.compile(rf"^\s*package\s+{re.escape(opa_package)}\b", re.MULTILINE)
    matching_texts: list[str] = []
    for rf in rego_files:
        text = rf.read_text(encoding="utf-8")
        if pkg_re.search(text):
            matching_texts.append(text)
    if not matching_texts:
        return [
            f"Domain {getattr(plugin, 'name', '?')!r} has no .rego module declaring package {opa_package!r} in {opa_dir}"
        ]

    combined = "\n".join(matching_texts)
    errors: list[str] = []
    for rule in required_rules:
        rule_re = re.compile(rf"^\s*(?:default\s+)?{re.escape(rule)}\b", re.MULTILINE)
        if not rule_re.search(combined):
            errors.append(
                f"Domain {getattr(plugin, 'name', '?')!r} package {opa_package!r} missing required rule {rule!r}"
            )
    return errors


def check_policy_drift(
    *,
    domain: str = "all",
    input_dir: Path = _DEFAULT_INPUT_DIR,
) -> int:
    """Verify STPA compilation, domain OPA bundles, and ControlRegistry hash parity."""
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    # Step 1: Core STPA compilation check
    try:
        from src.gateway.governance.stpa_compiler import (
            compile_control_structure,
            load_control_structures,
        )

        yaml_files = sorted(input_dir.rglob("*.yaml")) if input_dir.is_dir() else []
        if not yaml_files:
            logger.error("No YAML files found under %s", input_dir)
            return 2
        cs = load_control_structures(yaml_files)
        core_res = compile_control_structure(cs, ["nemo", "ftra", "sandbox"])
        if core_res.errors:
            for err in core_res.errors:
                logger.error("Core STPA compiler error: %s", err)
            return 2
        logger.info("Core STPA sources (%d file(s)) compiled cleanly.", len(yaml_files))
    except Exception as exc:
        logger.error("Failed to compile core STPA sources: %s", exc)
        return 2

    # Step 2: Domain plugin OPA & STPA verification
    try:
        from src.gateway.governance.plugin_loader import domain_config_of

        eps = sorted(
            importlib.metadata.entry_points(group="cage.plugins"),
            key=lambda ep: ep.name,
        )
        selected_plugins: list[object] = []
        for ep in eps:
            if domain != "all" and ep.name != domain:
                continue
            cls = ep.load()
            plugin = cls()
            if (
                domain == "all"
                and getattr(plugin, "maturity", "production") != "production"
            ):
                continue
            selected_plugins.append(plugin)

        if not selected_plugins:
            logger.error(
                "No matching production domain plugin found for --domain=%r", domain
            )
            return 2

        for plugin in selected_plugins:
            if getattr(plugin, "maturity", "production") == "stub":
                logger.error(
                    "Domain %r has maturity='stub' and cannot pass enforcing policy drift check.",
                    getattr(plugin, "name", "?"),
                )
                return 1
            cfg = domain_config_of(plugin)  # type: ignore[arg-type]
            opa_errors = _verify_domain_opa_bundle(
                plugin, cfg.opa_package, cfg.opa_required_rules
            )
            if opa_errors:
                for err in opa_errors:
                    logger.error("❌ %s", err)
                return 1

            plugin_dir = Path(inspect.getfile(type(plugin))).resolve().parent
            domain_stpa_dir = plugin_dir / "config" / "stpa"
            domain_yamls = (
                sorted(domain_stpa_dir.glob("*.yaml"))
                if domain_stpa_dir.is_dir()
                else []
            )
            if domain_yamls:
                d_cs = load_control_structures(domain_yamls)
                d_res = compile_control_structure(d_cs, ["python", "langgraph", "ftra"])
                if d_res.errors:
                    for err in d_res.errors:
                        logger.error(
                            "Domain %r STPA compiler error: %s",
                            getattr(plugin, "name", "?"),
                            err,
                        )
                    return 2
            logger.info(
                "Domain %r OPA package %r verified.",
                getattr(plugin, "name", "?"),
                cfg.opa_package,
            )
    except Exception as exc:
        logger.error("Failed domain policy verification: %s", exc)
        return 2

    # Step 3: Verify ControlRegistry.active_hash against on-disk regional baseline
    try:
        from src.gateway.governance.constants import _OVERLAY_DIRS, ControlRegistry
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

        registry = ControlRegistry()
        registry_hash = registry.active_hash
        if not registry_hash or len(registry_hash) != 64:
            logger.error(
                "❌ ControlRegistry.active_hash is empty or invalid: %r",
                registry_hash,
            )
            return 1
        baseline_file = (
            _REPO_ROOT
            / "config"
            / "compliance"
            / f"{registry.active_region}_BASELINE.json"
        )
        if baseline_file.exists():
            raw_baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
            for overlay_dir in _OVERLAY_DIRS:
                overlay_path = overlay_dir / f"{registry.active_region}_OVERLAY.json"
                if overlay_path.exists():
                    raw_baseline.update(
                        json.loads(overlay_path.read_text(encoding="utf-8"))
                    )
            expected_baseline_hash = hashlib.sha256(
                jcs_canonicalize_plan(ControlRegistry._coerce_floats(raw_baseline))
            ).hexdigest()
            if registry_hash != expected_baseline_hash:
                logger.error(
                    "❌ CONTROL REGISTRY DRIFT DETECTED\n"
                    "   ControlRegistry.active_hash : %s\n"
                    "   On-disk %s_BASELINE.json   : %s",
                    registry_hash[:16],
                    registry.active_region,
                    expected_baseline_hash[:16],
                )
                return 1
        logger.info("ControlRegistry.active_hash verified: %s", registry_hash[:16])
    except Exception as exc:
        logger.error("Failed to verify ControlRegistry.active_hash: %s", exc)
        return 2

    logger.info("✅ No policy drift detected (domain=%s).", domain)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_policy_drift",
        description="Detect STPA, domain OPA, and ControlRegistry policy drift.",
    )
    parser.add_argument(
        "--domain",
        default="all",
        help="Installed domain plugin name to verify, or 'all' for every production domain (default: all).",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=_DEFAULT_INPUT_DIR,
        metavar="DIR",
        help=f"Core STPA YAML directory (default: {_DEFAULT_INPUT_DIR}).",
    )
    args = parser.parse_args(argv)
    return check_policy_drift(domain=args.domain, input_dir=args.input_dir)


if __name__ == "__main__":
    sys.exit(main())
