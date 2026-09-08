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

"""Unit and integration tests for Gate G3 (scripts/check_import_boundaries.py)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_import_boundaries import (
    BoundaryViolation,
    check_file_boundaries,
    extract_imports,
    main,
)


@pytest.mark.unit
class TestImportBoundaryDetection:
    """Table-driven unit tests for boundary violation detection."""

    @pytest.mark.parametrize(
        ("code", "expected_rule", "expected_module"),
        [
            (
                "import src.cage_finance.ontology\n",
                "Layer 1 → Layer 2",
                "src.cage_finance.ontology",
            ),
            (
                "from cage_healthcare import rules\n",
                "Layer 1 → Layer 2",
                "cage_healthcare",
            ),
            (
                "import src.compliance_bridge.main\n",
                "Layer 1 → Layer 3",
                "src.compliance_bridge.main",
            ),
            (
                "from compliance_bridge.types import EvidenceRecord\n",
                "Layer 1 → Layer 3",
                "compliance_bridge.types",
            ),
            (
                "import src.governed_financial_advisor.server\n",
                "Layer 1 → Layer 4",
                "src.governed_financial_advisor.server",
            ),
            (
                "from governed_financial_advisor import agent\n",
                "Layer 1 → Layer 4",
                "governed_financial_advisor",
            ),
        ],
    )
    def test_gateway_layer_violations(
        self,
        tmp_path: Path,
        code: str,
        expected_rule: str,
        expected_module: str,
    ) -> None:
        """Verify Layer 1 files importing from forbidden layers are detected."""
        fake_gateway = tmp_path / "src" / "gateway" / "subpackage"
        fake_gateway.mkdir(parents=True)
        test_file = fake_gateway / "test_module.py"
        test_file.write_text(code, encoding="utf-8")

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert violations[0].imported_module == expected_module
        assert expected_rule in violations[0].rule_violated
        assert violations[0].line_number == 1

    @pytest.mark.parametrize(
        ("code", "expected_vendor"),
        [
            ("import google.cloud.storage\n", "google.cloud"),
            ("from google.cloud import kms\n", "google.cloud"),
            ("import boto3\n", "boto3"),
            ("from botocore.exceptions import ClientError\n", "botocore"),
            ("import azure.storage.blob\n", "azure"),
            ("import langfuse\n", "langfuse"),
        ],
    )
    def test_evidence_kernel_vendor_sdk_violations(
        self,
        tmp_path: Path,
        code: str,
        expected_vendor: str,
    ) -> None:
        """Verify files in evidence kernel importing vendor SDKs are detected."""
        fake_evidence = tmp_path / "src" / "gateway" / "governance" / "evidence"
        fake_evidence.mkdir(parents=True)
        test_file = fake_evidence / "custom_sink.py"
        test_file.write_text(f"# header\n{code}", encoding="utf-8")

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert "Evidence kernel vendor neutrality" in violations[0].rule_violated
        assert expected_vendor in violations[0].rule_violated
        assert violations[0].line_number == 2

    def test_clean_gateway_file_has_no_violations(self, tmp_path: Path) -> None:
        """Verify standard kernel imports raise no violations."""
        fake_gateway = tmp_path / "src" / "gateway"
        fake_gateway.mkdir(parents=True)
        test_file = fake_gateway / "clean.py"
        test_file.write_text(
            "import os\n"
            "import sys\n"
            "from src.gateway.governance.evidence import get_cold_store\n"
            "from src.gateway.governance.routing_seal import generate_seal\n",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert violations == []


@pytest.mark.unit
class TestLayer1IntegrationsRule:
    """Test Layer 1 → Layer 3 integrations boundary enforcement (scope-aware)."""

    def test_module_scope_integrations_import_forbidden_in_gateway(
        self, tmp_path: Path
    ) -> None:
        """Module-scope src.integrations import in gateway must fail."""
        fake_gateway = tmp_path / "src" / "gateway" / "governance"
        fake_gateway.mkdir(parents=True)
        test_file = fake_gateway / "some_kernel_file.py"
        test_file.write_text(
            "from src.integrations.provider_01 import Provider\n",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert (
            "module-scope src.integrations import forbidden"
            in violations[0].rule_violated
        )
        assert violations[0].line_number == 1

    def test_module_scope_import_forbidden_even_in_allowlisted_file(
        self, tmp_path: Path
    ) -> None:
        """Module-scope import is forbidden even in allowlisted factory files."""
        # Simulate allowlisted file by creating the exact path
        fake_factory = tmp_path / "src" / "gateway" / "governance"
        fake_factory.mkdir(parents=True)
        test_file = fake_factory / "normative_provider.py"
        test_file.write_text(
            "from src.integrations.provider_01 import Provider\n",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert (
            "module-scope src.integrations import forbidden"
            in violations[0].rule_violated
        )

    def test_function_scope_import_permitted_in_allowlisted_file(
        self, tmp_path: Path
    ) -> None:
        """Function-scope lazy import in allowlisted factory file is permitted."""
        fake_factory = tmp_path / "src" / "gateway" / "governance"
        fake_factory.mkdir(parents=True)
        test_file = fake_factory / "normative_provider.py"
        test_file.write_text(
            """
def get_provider(name: str):
    if name == "provider_01":
        from src.integrations.provider_01 import Provider
        return Provider()
    return None
""",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert violations == []

    def test_function_scope_import_forbidden_outside_allowlist(
        self, tmp_path: Path
    ) -> None:
        """Function-scope import in non-allowlisted file must fail."""
        fake_gateway = tmp_path / "src" / "gateway" / "core"
        fake_gateway.mkdir(parents=True)
        test_file = fake_gateway / "some_other_file.py"
        test_file.write_text(
            """
def load_something():
    from src.integrations.provider_01 import Provider
    return Provider()
""",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert "outside the factory allowlist" in violations[0].rule_violated
        assert violations[0].line_number == 3

    def test_class_body_import_forbidden_even_in_allowlist(
        self, tmp_path: Path
    ) -> None:
        """Class-body imports are module-scope and forbidden even in allowlist."""
        fake_factory = tmp_path / "src" / "gateway" / "governance" / "evidence"
        fake_factory.mkdir(parents=True)
        test_file = fake_factory / "factory.py"
        test_file.write_text(
            """
class ColdStoreFactory:
    from src.integrations.storage_gcs import GcsColdStore
    
    def create(self):
        return self.GcsColdStore()
""",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert len(violations) == 1
        assert (
            "module-scope src.integrations import forbidden"
            in violations[0].rule_violated
        )

    def test_integrations_import_outside_gateway_ignored(self, tmp_path: Path) -> None:
        """Integrations imports outside src/gateway/ are not checked."""
        fake_other = tmp_path / "src" / "cage_finance"
        fake_other.mkdir(parents=True)
        test_file = fake_other / "plugin.py"
        test_file.write_text(
            "from src.integrations.provider_01 import Provider\n",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert violations == []

    def test_evidence_factory_lazy_imports_permitted(self, tmp_path: Path) -> None:
        """Evidence factory can lazy-load storage_gcs and storage_s3."""
        fake_evidence = tmp_path / "src" / "gateway" / "governance" / "evidence"
        fake_evidence.mkdir(parents=True)
        test_file = fake_evidence / "factory.py"
        test_file.write_text(
            """
def create_cold_store(backend: str):
    if backend == "gcs":
        from src.integrations.storage_gcs.cold_store import GcsColdStore
        return GcsColdStore()
    elif backend == "s3":
        from src.integrations.storage_s3.cold_store import S3ColdStore
        return S3ColdStore()
    return None
""",
            encoding="utf-8",
        )

        violations = check_file_boundaries(test_file)
        assert violations == []


@pytest.mark.unit
class TestRepoImportBoundaries:
    """Integration test verifying actual repository passes Gate G3."""

    def test_check_import_boundaries_script_passes(self) -> None:
        """Run scripts/check_import_boundaries.py against repository and assert exit code 0.

        This is the regression guard: ensures the allowlist and live tree stay in sync.
        The six legitimate lazy imports in normative_provider.py and evidence/factory.py
        must be permitted.
        """
        result = subprocess.run(
            [sys.executable, "scripts/check_import_boundaries.py", "--verbose"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"Gate G3 failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "All import boundaries respected" in result.stdout

    def test_six_legitimate_lazy_imports_pass(self) -> None:
        """Verify the six real lazy imports in the live tree generate zero violations."""
        from pathlib import Path

        from scripts.check_import_boundaries import check_file_boundaries

        # Test normative_provider.py (4 lazy imports)
        normative_provider = Path("src/gateway/governance/normative_provider.py")
        if normative_provider.exists():
            violations = check_file_boundaries(normative_provider)
            integrations_violations = [
                v for v in violations if "integrations" in v.imported_module
            ]
            assert integrations_violations == [], (
                f"normative_provider.py lazy imports should be permitted but got: {integrations_violations}"
            )

        # Test evidence/factory.py (2 lazy imports)
        evidence_factory = Path("src/gateway/governance/evidence/factory.py")
        if evidence_factory.exists():
            violations = check_file_boundaries(evidence_factory)
            integrations_violations = [
                v for v in violations if "integrations" in v.imported_module
            ]
            assert integrations_violations == [], (
                f"evidence/factory.py lazy imports should be permitted but got: {integrations_violations}"
            )
