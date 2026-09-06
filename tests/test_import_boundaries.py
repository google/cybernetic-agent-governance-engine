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


class TestRepoImportBoundaries:
    """Integration test verifying actual repository passes Gate G3."""

    def test_check_import_boundaries_script_passes(self) -> None:
        """Run scripts/check_import_boundaries.py against repository and assert exit code 0."""
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
