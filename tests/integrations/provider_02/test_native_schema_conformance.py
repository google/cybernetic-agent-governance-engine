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
test_native_schema_conformance.py — Provider 02 Native Schema Conformance Suite
================================================================================

Ensures CAGE's internal runtime adapter serializes governance bundles that
strictly comply with the native schemas defined in:
  - schemas/provider_02/attestation_bundle.schema.json
  - schemas/provider_02/project_bundle_step.schema.json

Validates:
  1. Runtime model serialization conformance against JSON Schema
  2. Terminal path coverage (all 5 valid outcomes)
  3. JCS canonicalization invariant compatibility
  4. Parity between static fixtures and dynamic model output
"""

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

import pytest
from jsonschema import Draft202012Validator, RefResolver, ValidationError

from src.integrations.provider_02.adapter import (
    AttestationBundle,
    ProjectBundleStepEntry,
)

# Marker contract (fail-closed)
pytestmark = [pytest.mark.unit, pytest.mark.local]

# ---------------------------------------------------------------------------
# Schema Loading with $ref Resolution
# ---------------------------------------------------------------------------

SCHEMA_DIR = pathlib.Path(__file__).parent.parent.parent.parent / "schemas" / "provider_02"
FIXTURE_DIR = pathlib.Path(__file__).parent.parent.parent / "fixtures" / "provider_02_native"


def load_schema_with_refs(schema_name: str) -> tuple[dict[str, Any], Draft202012Validator]:
    """Load a JSON Schema file and configure $ref resolution.
    
    Args:
        schema_name: Name of schema file (e.g., 'attestation_bundle.schema.json')
    
    Returns:
        Tuple of (schema_dict, validator) with $ref resolution enabled
    """
    schema_path = SCHEMA_DIR / schema_name
    with open(schema_path) as f:
        schema = json.load(f)
    
    # Configure resolver to handle urn:cage:governance:v1:* references
    store = {}
    for schema_file in SCHEMA_DIR.glob("*.schema.json"):
        with open(schema_file) as f:
            sub_schema = json.load(f)
            if "$id" in sub_schema:
                store[sub_schema["$id"]] = sub_schema
    
    resolver = RefResolver.from_schema(schema, store=store)
    validator = Draft202012Validator(schema, resolver=resolver)
    
    return schema, validator


# Load schemas once at module level
ATTESTATION_BUNDLE_SCHEMA, ATTESTATION_BUNDLE_VALIDATOR = load_schema_with_refs(
    "attestation_bundle.schema.json"
)
PROJECT_STEP_SCHEMA, PROJECT_STEP_VALIDATOR = load_schema_with_refs(
    "project_bundle_step.schema.json"
)


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


def create_realistic_step(
    node_name: str = "evaluator",
    parent_step_ids: list[str] | None = None,
    signals: dict[str, Any] | None = None,
) -> ProjectBundleStepEntry:
    """Create a realistic ProjectBundleStepEntry for testing.
    
    Args:
        node_name: Node name (e.g., 'safety_check', 'governed_trader')
        parent_step_ids: Parent step UUIDs (empty list for entry nodes)
        signals: Governance signals dict (defaults to evaluator signals)
    
    Returns:
        Configured ProjectBundleStepEntry instance
    """
    if parent_step_ids is None:
        parent_step_ids = []
    
    if signals is None:
        signals = {
            "evaluationVerdict": "ALLOW",
            "evaluationReasoning": "Risk within acceptable thresholds",
            "policyCheck": {"allowed": True, "violations": []},
        }
    
    return ProjectBundleStepEntry(
        node_name=node_name,
        parent_step_ids=parent_step_ids,
        timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
        duration_ms=123.45,
        signals=signals,
        metadata={
            "loopIteration": 0,
            "threadId": "test-thread-123",
            "modelName": "gemini-2.0-flash-thinking-exp-01-21",
        },
        state_hash="a" * 64,  # Valid SHA-256 hex format
    )


def create_realistic_bundle(
    terminal_path: str = "happy_path",
    step_count: int = 5,
) -> AttestationBundle:
    """Create a realistic AttestationBundle for testing.
    
    Args:
        terminal_path: One of happy_path, nemo_block, cbf_block, loop_breaker, unknown
        step_count: Number of steps to include
    
    Returns:
        Configured AttestationBundle instance
    """
    # Create a simple linear DAG of steps
    steps: list[ProjectBundleStepEntry] = []
    
    for i in range(step_count):
        parent_ids = [steps[-1].step_id] if steps else []
        node_name = f"node_{i}"
        
        # Add domain-specific signals for realistic terminal paths
        signals: dict[str, Any] = {}
        if terminal_path == "nemo_block" and i == 0:
            signals = {
                "guardrailBlocked": True,
                "guardrailReason": "Detected prompt injection attempt",
            }
        elif terminal_path == "cbf_block" and i == step_count - 1:
            signals = {
                "safetyStatus": "BLOCKED",
                "cbfVerdict": "UNSAFE",
            }
        elif terminal_path == "loop_breaker" and i == step_count - 1:
            signals = {
                "loopCount": 3,
                "evaluationVerdict": "PAUSE",
            }
        
        step = create_realistic_step(
            node_name=node_name,
            parent_step_ids=parent_ids,
            signals=signals,
        )
        steps.append(step)
    
    now = datetime.now(tz=timezone.utc)
    
    return AttestationBundle(
        thread_id="test-thread-abc123",
        steps=steps,
        started_at=now.isoformat(),
        completed_at=now.isoformat(),
        terminal_path=terminal_path,
    )


# ---------------------------------------------------------------------------
# Conformance Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.local
class TestProjectBundleStepConformance:
    """Validate ProjectBundleStepEntry serialization against native schema."""
    
    def test_basic_step_serialization_conforms_to_schema(self) -> None:
        """Runtime step model serializes to valid JSON Schema format."""
        step = create_realistic_step()
        serialized = step.to_dict()
        
        # Should not raise ValidationError
        PROJECT_STEP_VALIDATOR.validate(serialized)
    
    def test_entry_node_with_empty_parents_is_valid(self) -> None:
        """Entry nodes with empty parentStepIds conform to schema."""
        step = create_realistic_step(node_name="nemo_guardrail", parent_step_ids=[])
        serialized = step.to_dict()
        
        PROJECT_STEP_VALIDATOR.validate(serialized)
        assert serialized["parentStepIds"] == []
    
    def test_step_with_multiple_parents_is_valid(self) -> None:
        """Steps with multiple parent edges conform to schema."""
        parent_ids = [
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
        ]
        step = create_realistic_step(parent_step_ids=parent_ids)
        serialized = step.to_dict()
        
        PROJECT_STEP_VALIDATOR.validate(serialized)
        assert serialized["parentStepIds"] == parent_ids
    
    def test_signals_extension_point_accepts_arbitrary_structure(self) -> None:
        """Signals field supports open extension for domain-specific data."""
        signals = {
            "evaluationVerdict": "DENY",
            "cbfBarrier": {"h_value": 0.95, "violation": True},
            "opaDecision": {"allowed": False, "policy": "trade_policy"},
            "nestedMetrics": {"latency": {"p50": 120, "p99": 450}},
        }
        step = create_realistic_step(signals=signals)
        serialized = step.to_dict()
        
        PROJECT_STEP_VALIDATOR.validate(serialized)
        assert serialized["signals"] == signals
    
    def test_metadata_extension_point_accepts_arbitrary_structure(self) -> None:
        """Metadata field supports open extension for operational data."""
        step = create_realistic_step()
        step.metadata = {
            "modelProvider": "google",
            "tokenUsage": {"input": 1500, "output": 300},
            "regionCode": "us-central1",
        }
        serialized = step.to_dict()
        
        PROJECT_STEP_VALIDATOR.validate(serialized)
        assert serialized["metadata"]["modelProvider"] == "google"
    
    def test_state_hash_must_be_valid_sha256_hex(self) -> None:
        """State hash must match SHA-256 hex pattern (64 lowercase hex chars)."""
        step = create_realistic_step()
        step.state_hash = "abc123def456" * 5 + "abcd"  # 64 chars, valid hex
        serialized = step.to_dict()
        
        PROJECT_STEP_VALIDATOR.validate(serialized)
    
    def test_invalid_state_hash_format_rejected(self) -> None:
        """State hash validation rejects non-hex or wrong-length values."""
        step = create_realistic_step()
        step.state_hash = "not-a-valid-sha256"  # Too short, contains hyphens
        serialized = step.to_dict()
        
        with pytest.raises(ValidationError, match="pattern"):
            PROJECT_STEP_VALIDATOR.validate(serialized)


@pytest.mark.unit
@pytest.mark.local
class TestAttestationBundleConformance:
    """Validate AttestationBundle serialization against native schema."""
    
    def test_basic_bundle_serialization_conforms_to_schema(self) -> None:
        """Runtime bundle model serializes to valid JSON Schema format."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        
        # Should not raise ValidationError
        ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_bundle_with_nested_step_refs_resolves_correctly(self) -> None:
        """Bundle schema correctly resolves $ref to step schema."""
        bundle = create_realistic_bundle(step_count=3)
        serialized = bundle.to_dict()
        
        # Validate bundle (which internally validates each step via $ref)
        ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
        
        # Manually validate each step as well
        for step_dict in serialized["steps"]:
            PROJECT_STEP_VALIDATOR.validate(step_dict)
    
    def test_bundle_requires_at_least_one_step(self) -> None:
        """Bundle schema enforces minItems: 1 for steps array."""
        bundle = create_realistic_bundle()
        bundle.steps = []  # Invalid: empty steps
        serialized = bundle.to_dict()
        
        with pytest.raises(ValidationError, match="minItems"):
            ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_bundle_timestamps_must_be_iso8601_datetime(self) -> None:
        """startedAt and completedAt must be valid ISO 8601 date-time strings."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        
        # Valid ISO 8601 with timezone
        assert "T" in serialized["startedAt"]
        assert serialized["startedAt"].endswith(("Z", "+00:00"))
        
        ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_bundle_timestamps_have_required_iso8601_structure(self) -> None:
        """Runtime models produce timestamps with required ISO 8601 structure."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        
        # Verify both timestamps have ISO 8601 date-time structure
        for ts_field in ["startedAt", "completedAt"]:
            ts = serialized[ts_field]
            assert isinstance(ts, str)
            assert "T" in ts, f"{ts_field} missing 'T' separator"
            assert ts.count(":") >= 2, f"{ts_field} missing time components"


@pytest.mark.unit
@pytest.mark.local
@pytest.mark.parametrize(
    "terminal_path",
    [
        "happy_path",
        "nemo_block",
        "cbf_block",
        "loop_breaker",
        "unknown",
    ],
)
class TestTerminalPathCoverage:
    """Validate serialization for all valid terminalPath outcomes."""
    
    def test_terminal_path_serialization_conforms_to_schema(
        self, terminal_path: str
    ) -> None:
        """All terminalPath enum values produce valid bundles."""
        bundle = create_realistic_bundle(terminal_path=terminal_path)
        serialized = bundle.to_dict()
        
        ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
        assert serialized["terminalPath"] == terminal_path
    
    def test_terminal_path_appears_in_serialized_output(
        self, terminal_path: str
    ) -> None:
        """Terminal path classification is included in JSON output."""
        bundle = create_realistic_bundle(terminal_path=terminal_path)
        serialized = bundle.to_dict()
        
        assert "terminalPath" in serialized
        assert serialized["terminalPath"] in [
            "happy_path",
            "nemo_block",
            "cbf_block",
            "loop_breaker",
            "unknown",
        ]


@pytest.mark.unit
@pytest.mark.local
class TestJCSCanonicalizationInvariant:
    """Validate JCS (RFC 8785) canonicalization compatibility."""
    
    def test_signals_dict_ordering_is_jcs_compatible(self) -> None:
        """Signal fields maintain deterministic ordering for JCS serialization."""
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
        
        signals = {
            "zebra": "last",
            "apple": "first",
            "beta": "middle",
        }
        step = create_realistic_step(signals=signals)
        serialized = step.to_dict()
        
        # JCS canonicalization should not raise
        canonical_bytes = jcs_canonicalize_plan(serialized["signals"])
        assert isinstance(canonical_bytes, bytes)
        
        # Keys should be lexicographically sorted in canonical form
        canonical_str = canonical_bytes.decode("utf-8")
        assert canonical_str.index('"apple"') < canonical_str.index('"beta"')
        assert canonical_str.index('"beta"') < canonical_str.index('"zebra"')
    
    def test_metadata_dict_ordering_is_jcs_compatible(self) -> None:
        """Metadata fields maintain deterministic ordering for JCS serialization."""
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
        
        metadata = {
            "timestamp": "2026-09-14T17:45:00Z",
            "modelName": "gemini-2.0-flash",
            "regionCode": "us-central1",
        }
        step = create_realistic_step()
        step.metadata = metadata
        serialized = step.to_dict()
        
        # JCS canonicalization should produce deterministic output
        canonical_1 = jcs_canonicalize_plan(serialized["metadata"])
        canonical_2 = jcs_canonicalize_plan(serialized["metadata"])
        assert canonical_1 == canonical_2
    
    def test_full_bundle_is_jcs_serializable(self) -> None:
        """Complete bundle serialization is compatible with JCS."""
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
        
        bundle = create_realistic_bundle(terminal_path="happy_path", step_count=3)
        serialized = bundle.to_dict()
        
        # Full bundle should be JCS-canonicalizable
        canonical_bytes = jcs_canonicalize_plan(serialized)
        assert isinstance(canonical_bytes, bytes)
        assert len(canonical_bytes) > 0


@pytest.mark.unit
@pytest.mark.local
class TestStaticFixtureValidation:
    """Validate parity between static fixtures and dynamic model output."""
    
    @pytest.mark.parametrize(
        "fixture_file",
        [
            "01_single_path_happy.json",
            "02_cbf_block.json",
            "03_loop_breaker.json",
            "04_nemo_policy_block.json",
            "05_large_dag.json",
        ],
    )
    def test_static_fixture_conforms_to_schema(self, fixture_file: str) -> None:
        """All static fixtures in tests/fixtures/provider_02_native/ are valid."""
        fixture_path = FIXTURE_DIR / fixture_file
        
        with open(fixture_path) as f:
            fixture_data = json.load(f)
        
        # Should not raise ValidationError
        ATTESTATION_BUNDLE_VALIDATOR.validate(fixture_data)
    
    @pytest.mark.parametrize(
        "fixture_file,expected_terminal_path",
        [
            ("01_single_path_happy.json", "happy_path"),
            ("02_cbf_block.json", "cbf_block"),
            ("03_loop_breaker.json", "loop_breaker"),
            ("04_nemo_policy_block.json", "nemo_block"),
            ("05_large_dag.json", "happy_path"),
        ],
    )
    def test_fixture_terminal_path_matches_filename(
        self, fixture_file: str, expected_terminal_path: str
    ) -> None:
        """Fixture terminal paths match their documented classifications."""
        fixture_path = FIXTURE_DIR / fixture_file
        
        with open(fixture_path) as f:
            fixture_data = json.load(f)
        
        assert fixture_data["terminalPath"] == expected_terminal_path
    
    def test_fixture_step_schemas_match_runtime_models(self) -> None:
        """Static fixture steps have same structure as runtime-generated steps."""
        # Load a fixture
        fixture_path = FIXTURE_DIR / "01_single_path_happy.json"
        with open(fixture_path) as f:
            fixture_data = json.load(f)
        
        # Create a runtime bundle
        runtime_bundle = create_realistic_bundle(terminal_path="happy_path")
        runtime_data = runtime_bundle.to_dict()
        
        # Both should have same top-level keys
        fixture_keys = set(fixture_data.keys())
        runtime_keys = set(runtime_data.keys())
        assert fixture_keys == runtime_keys
        
        # Step structures should match (same keys)
        if fixture_data["steps"]:
            fixture_step_keys = set(fixture_data["steps"][0].keys())
            runtime_step_keys = set(runtime_data["steps"][0].keys())
            assert fixture_step_keys == runtime_step_keys


@pytest.mark.unit
@pytest.mark.local
class TestSchemaEnforcement:
    """Validate schema enforcement rules and constraints."""
    
    def test_bundle_rejects_additional_properties(self) -> None:
        """Bundle schema has additionalProperties: false enforcement."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        serialized["unexpectedField"] = "should fail"
        
        with pytest.raises(ValidationError, match="Additional properties"):
            ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_step_rejects_additional_properties(self) -> None:
        """Step schema has additionalProperties: false enforcement."""
        step = create_realistic_step()
        serialized = step.to_dict()
        serialized["unexpectedField"] = "should fail"
        
        with pytest.raises(ValidationError, match="Additional properties"):
            PROJECT_STEP_VALIDATOR.validate(serialized)
    
    def test_bundle_rejects_invalid_terminal_path_enum(self) -> None:
        """terminalPath must be one of the 5 allowed enum values."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        serialized["terminalPath"] = "invalid_path_name"
        
        with pytest.raises(ValidationError, match="enum"):
            ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_bundle_rejects_missing_required_fields(self) -> None:
        """Bundle schema enforces all required fields are present."""
        bundle = create_realistic_bundle()
        serialized = bundle.to_dict()
        del serialized["threadId"]
        
        with pytest.raises(ValidationError, match="required"):
            ATTESTATION_BUNDLE_VALIDATOR.validate(serialized)
    
    def test_step_rejects_missing_required_fields(self) -> None:
        """Step schema enforces all required fields are present."""
        step = create_realistic_step()
        serialized = step.to_dict()
        del serialized["nodeName"]
        
        with pytest.raises(ValidationError, match="required"):
            PROJECT_STEP_VALIDATOR.validate(serialized)
    
    def test_step_duration_must_be_non_negative(self) -> None:
        """durationMs must be >= 0."""
        step = create_realistic_step()
        step.duration_ms = -10.0
        serialized = step.to_dict()
        
        with pytest.raises(ValidationError, match="minimum"):
            PROJECT_STEP_VALIDATOR.validate(serialized)


# Add pytest marker for the entire module
pytestmark = [pytest.mark.unit, pytest.mark.local]
