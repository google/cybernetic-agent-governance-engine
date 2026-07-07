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
