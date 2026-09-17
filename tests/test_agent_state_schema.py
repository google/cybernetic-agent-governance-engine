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
CI drift detection: verify AgentState TypedDict fields are all present
in the stored AgentStateSchema JSON Schema.

This test does NOT generate the schema from the TypedDict (that would
require a full type-introspection library). Instead it performs a
structural consistency check: every key declared in AgentState.__annotations__
must appear in the schema's "properties" dict.

This catches the most common drift pattern: a developer adds a field to
AgentState but forgets to update the JSON Schema.

Run with: pytest tests/test_agent_state_schema.py -v
"""

import json
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

SCHEMA_PATH = (
    Path(__file__).parents[1] / "compliance" / "schemas" / "agent_state_schema.json"
)


def get_agent_state_annotations() -> set[str]:
    """Return the set of field names declared in AgentState.__annotations__."""
    from src.governed_financial_advisor.graph.state import AgentState

    # TypedDict stores annotations in __annotations__ (includes inherited)
    annotations: dict = {}
    for cls in reversed(AgentState.__mro__):
        annotations.update(getattr(cls, "__annotations__", {}))
    return set(annotations.keys())


def get_schema_properties() -> set[str]:
    """Return the set of property names declared in the JSON Schema."""
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    return set(schema.get("properties", {}).keys())


def test_schema_file_is_valid_json():
    """The schema file must exist at the expected path and be valid JSON.

    Failure means the file is missing or has been corrupted.
    """
    assert SCHEMA_PATH.exists(), (
        f"AgentStateSchema not found at {SCHEMA_PATH}. "
        "Run the schema generation step or restore the file from git."
    )
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    assert isinstance(schema, dict), "Schema root must be a JSON object."
    assert "$schema" in schema, "Schema must declare a $schema version."
    assert "properties" in schema, "Schema must declare a 'properties' object."


def test_all_32_agent_state_fields_present():
    """Assert all 32 AgentState fields are present under properties.
    
    Failure means the expected field count has changed. This is a regression guard
    to detect unintentional field additions or removals.
    """
    schema_props = get_schema_properties()
    assert len(schema_props) == 32, (
        f"Expected exactly 32 properties in AgentState schema, found {len(schema_props)}. "
        f"Properties: {sorted(schema_props)}"
    )


def test_all_agent_state_fields_in_schema():
    """Every AgentState field must appear in the JSON Schema properties.

    Failure means a field was added to AgentState without updating the schema.
    Update compliance/schemas/agent_state_schema.json to fix this.
    """
    state_fields = get_agent_state_annotations()
    schema_props = get_schema_properties()

    missing_from_schema = state_fields - schema_props
    assert not missing_from_schema, (
        f"The following AgentState fields are missing from the JSON Schema: "
        f"{sorted(missing_from_schema)}. "
        f"Add them to compliance/schemas/agent_state_schema.json."
    )


def test_no_phantom_fields_in_schema():
    """Assert zero phantom fields exist (schema_props - state_fields == set()).
    
    Failure means the schema declares properties that don't exist in AgentState.
    This can happen when a field is removed from AgentState but not from the schema.
    """
    state_fields = get_agent_state_annotations()
    schema_props = get_schema_properties()
    
    phantom_fields = schema_props - state_fields
    assert phantom_fields == set(), (
        f"Schema contains phantom fields not present in AgentState: {sorted(phantom_fields)}. "
        f"Remove these from compliance/schemas/agent_state_schema.json or add them to AgentState."
    )


def test_guardrail_reason_is_non_nullable_string():
    """Assert guardrail_reason is {"type": "string"} (not nullable).
    
    Failure means the guardrail_reason field allows null, which violates the
    contract that it must always be present (empty string when not blocked).
    """
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    
    guardrail_reason_schema = schema["properties"]["guardrail_reason"]
    assert guardrail_reason_schema["type"] == "string", (
        f"guardrail_reason must be non-nullable string type, got: {guardrail_reason_schema}"
    )
    # Ensure it's not a list like ["string", "null"]
    assert isinstance(guardrail_reason_schema["type"], str), (
        f"guardrail_reason type must be a string, not a list: {guardrail_reason_schema['type']}"
    )


def test_additional_properties_is_false():
    """Assert additionalProperties is False.
    
    Failure means the schema allows arbitrary additional properties, which
    violates the strict schema contract.
    """
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    
    assert schema.get("additionalProperties") is False, (
        f"Schema must have additionalProperties set to False, got: {schema.get('additionalProperties')}"
    )


def test_required_fields_exist_in_agent_state():
    """Every JSON Schema 'required' field must exist in AgentState.__annotations__.

    Failure means a field was removed from AgentState but left in the schema's
    required array, or the schema's required array references a non-existent field.
    """
    state_fields = get_agent_state_annotations()

    with SCHEMA_PATH.open() as f:
        schema = json.load(f)

    required_in_schema: list[str] = schema.get("required", [])

    missing_from_state = [f for f in required_in_schema if f not in state_fields]
    assert not missing_from_state, (
        f"The following JSON Schema 'required' fields have no corresponding "
        f"AgentState field: {sorted(missing_from_state)}. "
        f"Either remove them from the schema's required array or add them to AgentState."
    )


def test_hermetic_induced_drift_detection(monkeypatch, tmp_path):
    """Hermetic induced-drift test with monkeypatched output path.
    
    This test verifies that the --check flag correctly detects schema drift
    without modifying the committed schema file. It monkeypatches the output
    path to a temporary location and tests both drift and parity scenarios.
    """
    import scripts.generate_agent_state_schema as gen_module
    
    # Monkeypatch the schema output path to tmp_path
    tmp_schema_path = tmp_path / "schema.json"
    monkeypatch.setattr(gen_module, "SCHEMA_OUTPUT_PATH", tmp_schema_path)
    
    # Test 1: Intentional drift (missing property) should return exit code 1
    drift_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AgentState",
        "type": "object",
        "required": ["messages"],  # Intentionally incomplete
        "additionalProperties": False,
        "properties": {
            "messages": {"type": "array"}  # Only one property instead of 32
        },
        "$defs": {}
    }
    tmp_schema_path.write_text(json.dumps(drift_schema, indent=2) + "\n")
    
    exit_code = gen_module.main(["--check"])
    assert exit_code == 1, (
        "Expected exit code 1 when schema has intentional drift (missing properties)"
    )
    
    # Test 2: Exact synchronized JSON should return exit code 0
    # Generate the current schema and write it to the temp path
    current_schema = gen_module.generate_schema()
    gen_module.write_schema(current_schema, tmp_schema_path)
    
    exit_code = gen_module.main(["--check"])
    assert exit_code == 0, (
        "Expected exit code 0 when schema is synchronized with AgentState model"
    )
    
    # Test 3: Verify the committed schema at git root remains untouched
    committed_schema_path = Path(__file__).parents[1] / "compliance" / "schemas" / "agent_state_schema.json"
    original_content = committed_schema_path.read_text()
    
    # Run the check again to ensure no side effects
    gen_module.main(["--check"])
    
    assert committed_schema_path.read_text() == original_content, (
        "Committed schema file was modified by --check mode (must remain read-only)"
    )
