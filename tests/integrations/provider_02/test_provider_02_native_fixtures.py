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
Automated verification test for Provider 02 native schema fixtures.

Validates all test fixtures in tests/fixtures/provider_02_native/ against
the attestation_bundle.schema.json schema.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, RefResolver, ValidationError

# Marker contract (fail-closed)
pytestmark = [pytest.mark.unit, pytest.mark.local]

# Base paths
REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "provider_02_native"
SCHEMAS_DIR = REPO_ROOT / "schemas" / "provider_02"


def load_schema(schema_path: Path) -> dict:
    """Load a JSON schema from disk."""
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)


def load_fixture(fixture_path: Path) -> dict:
    """Load a JSON fixture from disk."""
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def attestation_schema():
    """Load the attestation bundle schema with reference resolution."""
    schema_path = SCHEMAS_DIR / "attestation_bundle.schema.json"
    schema = load_schema(schema_path)

    # Load referenced schemas for resolution
    step_schema_path = SCHEMAS_DIR / "project_bundle_step.schema.json"
    step_schema = load_schema(step_schema_path)

    # Create a resolver that knows about the step schema
    store = {"urn:cage:governance:v1:step-entry": step_schema}
    resolver = RefResolver.from_schema(schema, store=store)

    return schema, resolver


@pytest.mark.parametrize(
    "fixture_name",
    [
        "01_single_path_happy.json",
        "02_cbf_block.json",
        "03_loop_breaker.json",
        "04_nemo_policy_block.json",
        "05_large_dag.json",
    ],
)
def test_fixture_validates_against_schema(fixture_name, attestation_schema):
    """Verify each fixture passes JSON schema validation."""
    schema, resolver = attestation_schema
    fixture_path = FIXTURES_DIR / fixture_name

    # Load the fixture
    fixture_data = load_fixture(fixture_path)

    # Create validator with resolver for $ref support and format checker for RFC 4122 UUID validation
    validator = Draft202012Validator(
        schema, resolver=resolver, format_checker=Draft202012Validator.FORMAT_CHECKER
    )

    # Validate and collect errors
    errors = list(validator.iter_errors(fixture_data))

    # Assert no validation errors
    if errors:
        error_messages = [
            f"  - {err.message} at {'.'.join(str(p) for p in err.path)}"
            for err in errors
        ]
        pytest.fail(
            f"Fixture {fixture_name} failed schema validation:\n"
            + "\n".join(error_messages)
        )


def test_all_expected_fixtures_exist():
    """Ensure all expected fixture files are present."""
    expected_fixtures = [
        "01_single_path_happy.json",
        "02_cbf_block.json",
        "03_loop_breaker.json",
        "04_nemo_policy_block.json",
        "05_large_dag.json",
    ]

    for fixture_name in expected_fixtures:
        fixture_path = FIXTURES_DIR / fixture_name
        assert fixture_path.exists(), f"Expected fixture not found: {fixture_name}"


def test_fixture_terminal_path_coverage():
    """Verify fixtures cover all terminal path types."""
    expected_terminal_paths = {
        "happy_path",
        "cbf_block",
        "loop_breaker",
        "nemo_block",
    }

    actual_terminal_paths = set()

    for fixture_file in FIXTURES_DIR.glob("*.json"):
        fixture_data = load_fixture(fixture_file)
        terminal_path = fixture_data.get("terminalPath")
        if terminal_path:
            actual_terminal_paths.add(terminal_path)

    # Verify we have test coverage for the main terminal paths
    assert expected_terminal_paths.issubset(actual_terminal_paths), (
        f"Missing terminal path coverage. Expected: {expected_terminal_paths}, Got: {actual_terminal_paths}"
    )


if __name__ == "__main__":
    """
    Standalone execution for quick verification without pytest.
    Run: uv run python tests/test_provider_02_native_fixtures.py
    """
    print("=" * 70)
    print("Provider 02 Native Schema Fixture Validation")
    print("=" * 70)

    # Load schemas
    schema_path = SCHEMAS_DIR / "attestation_bundle.schema.json"
    step_schema_path = SCHEMAS_DIR / "project_bundle_step.schema.json"

    attestation_schema = load_schema(schema_path)
    step_schema = load_schema(step_schema_path)

    # Create resolver and validator with format checking enabled
    store = {"urn:cage:governance:v1:step-entry": step_schema}
    resolver = RefResolver.from_schema(attestation_schema, store=store)
    validator = Draft202012Validator(
        attestation_schema,
        resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    # Validate each fixture
    fixtures = sorted(FIXTURES_DIR.glob("*.json"))
    total_fixtures = len(fixtures)
    passed = 0
    failed = 0

    for fixture_path in fixtures:
        fixture_name = fixture_path.name
        try:
            fixture_data = load_fixture(fixture_path)
            validator.validate(fixture_data)
            print(f"✓ {fixture_name:40s} PASSED")
            passed += 1
        except ValidationError as e:
            print(f"✗ {fixture_name:40s} FAILED")
            print(f"  Error: {e.message}")
            print(f"  Path: {'.'.join(str(p) for p in e.path)}")
            failed += 1
        except Exception as e:
            print(f"✗ {fixture_name:40s} ERROR")
            print(f"  {type(e).__name__}: {e}")
            failed += 1

    print("=" * 70)
    print(f"Total: {total_fixtures} | Passed: {passed} | Failed: {failed}")
    print("=" * 70)

    if failed > 0:
        exit(1)
    else:
        print("\n✓ All fixtures validated successfully!")
        exit(0)
