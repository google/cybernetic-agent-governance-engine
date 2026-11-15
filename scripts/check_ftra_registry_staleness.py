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

"""FTRA registry staleness gate (Issue #107 — Mayur Agnihotri follow-up).

Checks that the terminal registry still describes the live action surface of a
domain plugin.  The manifest digest check (in IrreversibilityClassifier) proves
nobody edited the file; this script proves the file still describes the system.

These are two separate controls:
  - Integrity  (manifest digest)  → was the file tampered with?
  - Staleness  (this script)      → does the file still match the system?

Usage::

    # Default: check cage_finance REGISTERED_ACTIONS against the default registry
    uv run python scripts/check_ftra_registry_staleness.py

    # Specify a different domain plugin
    uv run python scripts/check_ftra_registry_staleness.py \\
        --domain src.cage_healthcare \\
        --registry config/ftra/healthcare_registry.json

    # Exit non-zero on any mismatch (for CI)
    uv run python scripts/check_ftra_registry_staleness.py --strict

The script is domain-agnostic: it loads ``REGISTERED_ACTIONS`` from any
module path supplied via ``--domain``.  The kernel function
``check_registry_staleness()`` never imports domain code itself.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path

os.environ.setdefault("CAGE_ENV", "ci")

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FTRA registry staleness gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--domain",
        default="src.cage_finance",
        help=(
            "Dotted module path of a domain plugin that exports "
            "REGISTERED_ACTIONS: frozenset[str].  "
            "Default: src.cage_finance"
        ),
    )
    parser.add_argument(
        "--registry",
        default=None,
        help=(
            "Path to the terminal registry JSON.  "
            "Defaults to the domain plugin's DomainConfig.ftra_registry_path "
            "or config/ftra/terminal_registry.json."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any mismatch or expiration is detected.",
    )
    return parser.parse_args()


def _resolve_default_registry_path(
    domain_module_name: str, domain_module: object
) -> Path:
    """Resolve the terminal registry JSON path for *domain_module* without requiring CAGE_DOMAIN."""
    try:
        plugin_mod = importlib.import_module(f"{domain_module_name}.plugin")
        for obj in vars(plugin_mod).values():
            cfg = getattr(obj, "domain_config", None)
            reg_path = getattr(cfg, "ftra_registry_path", None)
            if isinstance(reg_path, Path) and reg_path.is_file():
                return reg_path
    except Exception:  # noqa: BLE001
        pass
    module_file = getattr(domain_module, "__file__", None)
    if isinstance(module_file, str):
        candidate = (
            Path(module_file).resolve().parent / "stpa" / "terminal_registry.json"
        )
        if candidate.is_file():
            return candidate
    return _REPO_ROOT / "config" / "ftra" / "terminal_registry.json"


def main() -> int:
    args = _parse_args()

    # ── Import REGISTERED_ACTIONS from the domain plugin ──────────────────
    try:
        domain_module = importlib.import_module(args.domain)
    except ModuleNotFoundError as exc:
        print(
            f"[FTRA staleness] ERROR: cannot import domain module {args.domain!r}: {exc}"
        )
        return 1

    live_actions = getattr(domain_module, "REGISTERED_ACTIONS", None)
    if live_actions is None:
        print(
            f"[FTRA staleness] ERROR: {args.domain} has no REGISTERED_ACTIONS attribute. "
            "Add a frozenset[str] named REGISTERED_ACTIONS to the domain plugin's __init__.py."
        )
        return 1
    if not isinstance(live_actions, frozenset):
        print(
            f"[FTRA staleness] ERROR: {args.domain}.REGISTERED_ACTIONS must be a frozenset, "
            f"got {type(live_actions).__name__}."
        )
        return 1

    # ── Call the kernel staleness function — no domain code in kernel ──────
    from src.gateway.governance.ftra.classifier import check_registry_staleness

    registry_path = (
        Path(args.registry)
        if args.registry
        else _resolve_default_registry_path(args.domain, domain_module)
    )
    report = check_registry_staleness(live_actions, registry_path=registry_path)

    # ── Report ─────────────────────────────────────────────────────────────
    if report.is_clean:
        print(
            f"[FTRA staleness] ✅ PASS — {args.domain} REGISTERED_ACTIONS matches registry "
            f"({len(live_actions)} actions)."
        )
        return 0

    exit_code = 0

    if report.expired:
        print(
            f"[FTRA staleness] ❌ Registry at {registry_path} has EXPIRED "
            "(expires_at <= current UTC time)."
        )
        exit_code = 1

    if report.unclassified:
        print(
            f"[FTRA staleness] ⚠️  {len(report.unclassified)} action(s) in {args.domain} "
            f"but ABSENT from registry (will default to IRREVERSIBLE_TERMINAL at runtime):"
        )
        for action in sorted(report.unclassified):
            print(f"       + {action}")
        if args.strict:
            exit_code = 1

    if report.phantom:
        print(
            f"[FTRA staleness] ⚠️  {len(report.phantom)} action(s) in registry but ABSENT "
            f"from {args.domain} (phantom entries — registry is ahead of or behind the code):"
        )
        for action in sorted(report.phantom):
            print(f"       - {action}")
        if args.strict:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
