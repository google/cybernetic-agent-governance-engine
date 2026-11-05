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

"""Mounted-`.rego` Gate (R-15, G-34, Decision 9).

Every non-test `.rego` file tracked in `git ls-files "*.rego"` (outside
`compliance/lula/`, `compliance/postures/`, and `tests/`) must be mounted by:
  1. `deployment/k8s/` manifests,
  2. `infra/modules/opa_policy/` Terraform configuration,
  3. a Lula validation in `compliance/lula/`, or
  4. a registered `src/cage_{domain}/opa/` domain plugin (`opa_policy_path`).

Also verifies that the 6 retired unmounted `.rego` files remain absent.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.cage_finance.plugin import FinanceCagePlugin
from src.cage_healthcare.plugin import HealthcareCagePlugin

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]

_RETIRED_UNMOUNTED_REGO_FILES: tuple[str, ...] = (
    "config/opa/generated_stpa_policy.rego",
    "deployment/system_authz.rego",
    "config/opa/trade_policy.rego",
    "config/opa/agent_catalog.rego",
    "config/opa/bounding_contracts.rego",
    "config/opa/bounding_contracts_test.rego",
)

_EXEMPT_PREFIXES: tuple[str, ...] = (
    "compliance/lula/",
    "compliance/postures/",
    "tests/",
)


def _collect_mounted_rego_paths(repo_root: Path = _REPO_ROOT) -> set[str]:
    """Return repo-relative paths (or basenames referenced in mounts) of mounted `.rego` policies."""
    mounted: set[str] = set()

    # 1. Registered domain plugins in src/cage_{domain}/opa/*.rego whose
    #    `package` declaration matches `plugin_cls.domain_config.opa_package`.
    import inspect
    import re

    for plugin_cls in (FinanceCagePlugin, HealthcareCagePlugin):
        opa_pkg = getattr(plugin_cls.domain_config, "opa_package", "")
        if not opa_pkg:
            continue
        plugin_dir = Path(inspect.getfile(plugin_cls)).resolve().parent
        rel_plugin = plugin_dir.relative_to(Path(__file__).resolve().parents[1])
        opa_dir = (repo_root / rel_plugin / "opa").resolve()
        if not opa_dir.is_dir():
            continue
        pkg_re = re.compile(rf"^\s*package\s+{re.escape(opa_pkg)}\b", re.MULTILINE)
        for rego_file in sorted(opa_dir.glob("*.rego")):
            text = rego_file.read_text(encoding="utf-8", errors="ignore")
            if pkg_re.search(text):
                rel = rego_file.relative_to(repo_root.resolve())
                mounted.add(rel.as_posix())

    # 2. infra/modules/opa_policy/, infra/targets/gcp-gke/, compliance/lula/ references
    #    Strip `#` (and HCL `//`) comment lines so commented-out filenames in
    #    Lula YAML or Terraform files can never mask an unmounted `.rego` file.
    search_dirs = (
        repo_root / "infra" / "modules" / "opa_policy",
        repo_root / "infra" / "targets" / "gcp-gke",
        repo_root / "compliance" / "lula",
    )
    corpus = ""
    for d in search_dirs:
        if d.exists():
            for f in sorted(d.rglob("*")):
                if f.is_file() and f.suffix in {".yaml", ".yml", ".tf", ".json"}:
                    raw_text = f.read_text(encoding="utf-8", errors="ignore")
                    active_lines: list[str] = []
                    for raw_line in raw_text.splitlines():
                        stripped = raw_line.lstrip()
                        if f.suffix in {".yaml", ".yml"} and stripped.startswith("#"):
                            continue
                        if f.suffix == ".tf" and (
                            stripped.startswith("#") or stripped.startswith("//")
                        ):
                            continue
                        if f.suffix in {".yaml", ".yml", ".tf"} and "#" in raw_line:
                            raw_line = raw_line.split("#", 1)[0]
                        active_lines.append(raw_line)
                    corpus += "\n".join(active_lines) + "\n"

    for candidate in repo_root.rglob("*.rego"):
        try:
            rel_str = candidate.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            continue
        if rel_str in corpus or candidate.name in corpus:
            mounted.add(rel_str)

    return mounted


def is_rego_file_allowed(rel_path: str, mounted_paths: set[str]) -> bool:
    """Return True if `rel_path` is a test/compliance `.rego` or is mounted at runtime."""
    if rel_path.endswith("_test.rego"):
        return True
    if any(rel_path.startswith(prefix) for prefix in _EXEMPT_PREFIXES):
        return True
    return rel_path in mounted_paths


class TestMountedRegoGate:
    """Enforces that every tracked non-test `.rego` file is mounted at runtime."""

    def test_every_tracked_non_test_rego_file_is_mounted(self) -> None:
        proc = subprocess.run(
            ["git", "ls-files", "*.rego"],
            cwd=_REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        tracked = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        assert tracked, "Expected at least one tracked .rego file in the repository"

        mounted = _collect_mounted_rego_paths(_REPO_ROOT)
        unmounted = [rel for rel in tracked if not is_rego_file_allowed(rel, mounted)]
        assert unmounted == [], (
            f"Unmounted .rego files found in git ls-files: {unmounted}. "
            "Every non-test .rego file outside compliance/lula/, compliance/postures/, "
            "and tests/ must be mounted by deployment/k8s/, infra/modules/opa_policy/, "
            "compliance/lula/, or a registered src/cage_<domain>/opa/ plugin."
        )

    def test_gate_rejects_unmounted_rego_path(self) -> None:
        mounted = _collect_mounted_rego_paths(_REPO_ROOT)
        for retired in (
            "config/opa/generated_stpa_policy.rego",
            "deployment/system_authz.rego",
            "config/opa/trade_policy.rego",
            "config/opa/agent_catalog.rego",
            "config/opa/bounding_contracts.rego",
        ):
            assert not is_rego_file_allowed(retired, mounted), (
                f"Gate must reject unmounted policy {retired}"
            )

    @pytest.mark.parametrize("rel_path", _RETIRED_UNMOUNTED_REGO_FILES)
    def test_retired_unmounted_rego_files_absent_from_disk(self, rel_path: str) -> None:
        assert not (_REPO_ROOT / rel_path).exists(), (
            f"Retired unmounted .rego file {rel_path} must not exist on disk"
        )

    def test_commented_out_lula_reference_does_not_mask_unmounted_rego(
        self, tmp_path: Path
    ) -> None:
        """A `# rogue_policy.rego` comment in compliance/lula/*.yaml must not count as mounted."""
        lula_dir = tmp_path / "compliance" / "lula"
        lula_dir.mkdir(parents=True)
        (lula_dir / "lula-validation-test.yaml").write_text(
            "# Historical reference: rogue_policy.rego\nkind: LulaValidation # inline_rogue.rego\n",
            encoding="utf-8",
        )
        rogue_dir = tmp_path / "src" / "rogue"
        rogue_dir.mkdir(parents=True)
        (rogue_dir / "rogue_policy.rego").write_text(
            "package rogue\ndefault allow := false\n", encoding="utf-8"
        )
        (rogue_dir / "inline_rogue.rego").write_text(
            "package rogue2\ndefault allow := false\n", encoding="utf-8"
        )
        mounted = _collect_mounted_rego_paths(tmp_path)
        assert "src/rogue/rogue_policy.rego" not in mounted
        assert "src/rogue/inline_rogue.rego" not in mounted

    def test_canonical_domain_rego_policies_exist_and_are_mounted(self) -> None:
        mounted = _collect_mounted_rego_paths(_REPO_ROOT)
        for canonical in (
            "src/cage_finance/opa/trade_governance.rego",
            "src/cage_healthcare/opa/dosing_governance.rego",
        ):
            path = _REPO_ROOT / canonical
            assert path.exists(), (
                f"Expected canonical domain policy {canonical} to exist"
            )
            assert path.read_text(encoding="utf-8").strip(), (
                f"{canonical} must be non-empty"
            )
            assert is_rego_file_allowed(canonical, mounted)


class TestCheckPolicyDriftCli:
    """Exercises scripts/check_policy_drift.py --domain parameterization."""

    @pytest.mark.parametrize("domain", ["all", "finance", "healthcare"])
    def test_production_domains_pass_policy_drift(self, domain: str) -> None:
        from scripts.check_policy_drift import main as drift_main

        assert drift_main(["--domain", domain]) == 0

    def test_stub_domain_fails_policy_drift(self) -> None:
        from scripts.check_policy_drift import main as drift_main

        assert drift_main(["--domain", "physical_ai"]) == 1

    def test_unknown_domain_returns_config_error(self) -> None:
        from scripts.check_policy_drift import main as drift_main

        assert drift_main(["--domain", "nonexistent_domain"]) == 2
