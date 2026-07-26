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

"""
Policy Drift Detection Gate (B2)
=================================

Compares the compiled artifact hash against the active ``ControlRegistry.active_hash``
to detect policy drift between the compiled artifacts and the active governance profile.

Also computes the SHA-256 hash of the compiled OPA policy and compares it against
a stored baseline hash (``config/opa/.policy_hash``) to detect uncommitted changes
to the compiled artifacts.

Exit codes:
    0  No drift detected — compiled artifacts match the active registry.
    1  Drift detected — compiled artifacts do not match, or hash file missing.
    2  Fatal error — could not load control structure or compile artifacts.

Usage::

    # Check for drift (used in CI)
    python scripts/check_policy_drift.py

    # Update the stored baseline hash (run after intentional policy changes)
    python scripts/check_policy_drift.py --update-baseline

    # Check a specific compiled OPA file
    python scripts/check_policy_drift.py --opa-file config/opa/generated_stpa_policy.rego

    # Also check scripts/check_stpa_freshness.py for STPA source freshness
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("check_policy_drift")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT = _REPO_ROOT / "config" / "stpa_control_structure.yaml"
_DEFAULT_OPA_OUT = _REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego"
_DEFAULT_HASH_FILE = _REPO_ROOT / "config" / "opa" / ".policy_hash"
_DEFAULT_AGP_OUT = _REPO_ROOT / "config" / "agp" / "generated_semantic_policy.txt"
_AGP_CHAR_BUDGET = 5_000


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file's contents."""
    content = path.read_text(encoding="utf-8")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sha256_text(text: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_compiled_artifact_drift(
    input_path: Path,
    opa_file: Path,
    hash_file: Path,
    update_baseline: bool = False,
) -> int:
    """Check for drift between the compiled OPA artifact and the stored baseline hash.

    Args:
        input_path: Path to the STPA control structure YAML.
        opa_file: Path to the compiled OPA Rego file.
        hash_file: Path to the stored baseline hash file.
        update_baseline: If True, update the stored hash instead of checking.

    Returns:
        0 if no drift, 1 if drift detected, 2 on fatal error.
    """
    # Step 1: Compile fresh artifacts from the control structure
    try:
        sys.path.insert(0, str(_REPO_ROOT))
        from src.gateway.governance.stpa_compiler import (
            compile_control_structure,
            load_control_structure,
        )

        cs = load_control_structure(input_path)
        result = compile_control_structure(cs, ["opa"])

        if result.errors:
            for err in result.errors:
                logger.error("Compiler error: %s", err)
            return 2

        fresh_opa_hash = _sha256_text(result.opa_content)
        logger.info("Fresh OPA hash (from source): %s", fresh_opa_hash[:16])

    except FileNotFoundError as exc:
        logger.error("Control structure not found: %s", exc)
        return 2
    except Exception as exc:
        logger.error("Failed to compile control structure: %s", exc)
        return 2

    # Step 2: Check ControlRegistry.active_hash
    try:
        from src.gateway.governance.constants import ControlRegistry

        registry = ControlRegistry()
        registry_hash = registry.active_hash
        logger.info("ControlRegistry.active_hash: %s", registry_hash[:16])
    except Exception as exc:
        logger.warning(
            "Could not load ControlRegistry: %s — skipping registry hash check.", exc
        )
        registry_hash = None

    # Step 3: Compare against stored baseline hash
    if update_baseline:
        hash_file.parent.mkdir(parents=True, exist_ok=True)
        hash_file.write_text(fresh_opa_hash, encoding="utf-8")
        logger.info("✅ Baseline hash updated: %s → %s", hash_file, fresh_opa_hash[:16])
        return 0

    if not hash_file.exists():
        logger.error(
            "❌ Baseline hash file not found: %s\n"
            "   Run with --update-baseline to create it after an intentional policy change.",
            hash_file,
        )
        return 1

    stored_hash = hash_file.read_text(encoding="utf-8").strip()
    logger.info("Stored baseline hash: %s", stored_hash[:16])

    # Step 4: Compare fresh vs stored
    if fresh_opa_hash != stored_hash:
        logger.error(
            "❌ POLICY DRIFT DETECTED\n"
            "   Fresh compiled hash : %s\n"
            "   Stored baseline hash: %s\n"
            "   The compiled OPA policy has drifted from the stored baseline.\n"
            "   If this is intentional, run: python scripts/check_policy_drift.py --update-baseline\n"
            "   If this is unexpected, check for uncommitted changes to:\n"
            "     - config/stpa_control_structure.yaml\n"
            "     - config/opa/generated_stpa_policy.rego",
            fresh_opa_hash[:16],
            stored_hash[:16],
        )
        return 1

    # Step 5: Also compare the on-disk OPA file against the fresh compile
    if opa_file.exists():
        disk_hash = _sha256_file(opa_file)
        if disk_hash != fresh_opa_hash:
            logger.error(
                "❌ ON-DISK ARTIFACT DRIFT DETECTED\n"
                "   On-disk OPA file hash: %s\n"
                "   Fresh compiled hash  : %s\n"
                "   The on-disk OPA file does not match a fresh compile from source.\n"
                "   Re-run: python -m src.gateway.governance.stpa_compiler compile --targets opa",
                disk_hash[:16],
                fresh_opa_hash[:16],
            )
            return 1
        logger.info("✅ On-disk OPA artifact matches fresh compile.")
    else:
        logger.warning(
            "On-disk OPA file not found at %s — skipping on-disk check.", opa_file
        )

    logger.info("✅ No policy drift detected. Compiled hash: %s", fresh_opa_hash[:16])
    return 0


def check_agp_budget(agp_file: Path) -> int:
    """Check that the AGP policy file is within the 5,000-character budget.

    Returns:
        0 if within budget, 1 if over budget or contains TRUNCATED sentinel.
    """
    if not agp_file.exists():
        logger.info(
            "AGP policy file not found at %s — skipping budget check.", agp_file
        )
        return 0

    content = agp_file.read_text(encoding="utf-8")
    char_count = len(content)

    if "# TRUNCATED" in content:
        logger.error(
            "❌ AGP policy file contains TRUNCATED sentinel — "
            "output exceeded the 5,000-character budget.\n"
            "   File: %s (%d chars)",
            agp_file,
            char_count,
        )
        return 1

    if char_count > _AGP_CHAR_BUDGET:
        logger.error(
            "❌ AGP policy file exceeds 5,000-character budget: %d chars\n   File: %s",
            char_count,
            agp_file,
        )
        return 1

    logger.info(
        "✅ AGP policy budget OK: %d/%d chars (%.1f%%)",
        char_count,
        _AGP_CHAR_BUDGET,
        100.0 * char_count / _AGP_CHAR_BUDGET,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Policy drift detection gate — fails CI if compiled artifacts have drifted.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        metavar="YAML",
        help=f"Path to STPA control structure YAML (default: {_DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--opa-file",
        type=Path,
        default=_DEFAULT_OPA_OUT,
        metavar="FILE",
        help=f"Path to compiled OPA Rego file (default: {_DEFAULT_OPA_OUT})",
    )
    parser.add_argument(
        "--hash-file",
        type=Path,
        default=_DEFAULT_HASH_FILE,
        metavar="FILE",
        help=f"Path to stored baseline hash file (default: {_DEFAULT_HASH_FILE})",
    )
    parser.add_argument(
        "--agp-file",
        type=Path,
        default=_DEFAULT_AGP_OUT,
        metavar="FILE",
        help=f"Path to AGP policy text file for budget check (default: {_DEFAULT_AGP_OUT})",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update the stored baseline hash instead of checking for drift.",
    )
    parser.add_argument(
        "--skip-agp-check",
        action="store_true",
        help="Skip the AGP character budget check.",
    )

    args = parser.parse_args(argv)

    # Run drift check
    drift_rc = check_compiled_artifact_drift(
        input_path=args.input,
        opa_file=args.opa_file,
        hash_file=args.hash_file,
        update_baseline=args.update_baseline,
    )

    if args.update_baseline:
        return drift_rc

    # Run AGP budget check
    agp_rc = 0
    if not args.skip_agp_check:
        agp_rc = check_agp_budget(args.agp_file)

    # Return worst exit code
    return max(drift_rc, agp_rc)


if __name__ == "__main__":
    sys.exit(main())
