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

"""Generate compliance/schemas/agent_state_schema.json from AgentState runtime model.

Automates schema synchronization to eliminate triple-source schema drift.
Dynamically introspects AgentState TypedDict and generates a JSON Schema
draft-2020-12 document with strict additionalProperties enforcement.

Usage:
    # Generate schema (overwrites existing file):
    uv run python scripts/generate_agent_state_schema.py

    # CI check mode (fails with exit code 1 if drift detected):
    uv run python scripts/generate_agent_state_schema.py --check
"""

import argparse
import json
import sys
import types
import typing
from pathlib import Path
from typing import Any, get_args, get_origin

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.governed_financial_advisor.graph.state import AgentState, LedgerEntry

SCHEMA_OUTPUT_PATH = PROJECT_ROOT / "compliance" / "schemas" / "agent_state_schema.json"

# Canonical required fields for AgentState
REQUIRED_FIELDS = [
    "messages",
    "next_step",
    "risk_status",
    "safety_status",
    "user_id",
    "approval_required",
    "guardrail_blocked",
    "guardrail_reason",
    "output_rail_applied",
    "completed_transactions",
]


def extract_literal_values(type_hint: Any) -> list[str] | None:
    """Extract values from a Literal type annotation."""
    origin = get_origin(type_hint)
    if origin is typing.Literal:
        return list(get_args(type_hint))
    return None


def is_optional(type_hint: Any) -> bool:
    """Check if a type hint is Optional (Union with None)."""
    origin = get_origin(type_hint)
    # Handle both typing.Union and types.UnionType (Python 3.10+ | syntax)
    if origin is typing.Union or isinstance(type_hint, types.UnionType):
        args = get_args(type_hint)
        return type(None) in args
    return False


def strip_optional(type_hint: Any) -> Any:
    """Remove None from Union types."""
    origin = get_origin(type_hint)
    # Handle both typing.Union and types.UnionType (Python 3.10+ | syntax)
    if origin is typing.Union or isinstance(type_hint, types.UnionType):
        args = get_args(type_hint)
        non_none_args = [arg for arg in args if arg is not type(None)]
        if len(non_none_args) == 1:
            return non_none_args[0]
        # Return remaining union if multiple non-None types
        return type_hint
    return type_hint


def map_type_to_schema(field_name: str, type_hint: Any, field_is_optional: bool) -> dict[str, Any]:
    """Map a Python type hint to a JSON Schema property definition."""
    
    # Handle Annotated types (e.g., Annotated[list[BaseMessage], add_messages])
    origin = get_origin(type_hint)
    if origin is typing.Annotated:
        args = get_args(type_hint)
        inner_type = args[0]
        
        # Special handling for messages field
        if field_name == "messages":
            return {
                "type": "array",
                "description": "Shared conversation history (LangChain BaseMessage serialized at boundary)",
                "items": {"$ref": "#/$defs/OpaqueMessage"}
            }
        
        # For completed_transactions with LedgerEntry
        if field_name == "completed_transactions":
            return {
                "type": "array",
                "description": "Saga transaction ledger (Write-Ahead Log) — append-only via operator.add reducer",
                "items": {"$ref": "#/$defs/LedgerEntry"}
            }
        
        # Recurse on the inner type for other Annotated cases
        type_hint = inner_type
        origin = get_origin(type_hint)
    
    # Strip Optional wrapper
    base_type = strip_optional(type_hint) if field_is_optional else type_hint
    
    # Handle Literal types
    literal_values = extract_literal_values(base_type)
    if literal_values:
        schema = {
            "type": "string",
            "enum": literal_values
        }
        return {"type": ["string", "null"]} if field_is_optional else schema
    
    # Handle Union types (e.g., str | dict | None for execution_plan_output)
    union_origin = get_origin(base_type)
    if union_origin is typing.Union or isinstance(base_type, types.UnionType):
        args = get_args(base_type)
        non_none_args = [arg for arg in args if arg is not type(None)]
        
        if len(non_none_args) > 1:
            # Multiple non-None types: use oneOf
            schemas = []
            for arg in non_none_args:
                if arg is str:
                    schemas.append({"type": "string"})
                elif arg is dict or get_origin(arg) is dict:
                    schemas.append({"type": "object"})
                elif arg is int:
                    schemas.append({"type": "integer"})
            if field_is_optional:
                schemas.append({"type": "null"})
            return {"oneOf": schemas}
    
    # Get the origin for generic types
    origin = get_origin(base_type)
    
    # Handle basic types
    if base_type is str:
        if field_name == "guardrail_reason":
            schema = {
                "type": "string",
                "description": "NeMo guardrail block reason — empty string when not blocked"
            }
        elif field_name == "user_id":
            schema = {
                "type": "string",
                "description": "User identity — ISO 42001 A.7.2 accountability attribution",
                "minLength": 1
            }
        else:
            schema = {"type": "string"}
        return {"type": ["string", "null"]} if field_is_optional else schema
    
    if base_type is int:
        schema = {"type": "integer"}
        if field_name == "loop_count":
            schema["minimum"] = 0
        return {"type": ["integer", "null"]} if field_is_optional else schema
    
    if base_type is bool:
        return {"type": "boolean"}
    
    # Handle dict types
    if origin is dict or base_type is dict:
        schema = {"type": "object"}
        if field_name == "latency_stats":
            schema["additionalProperties"] = {"type": "number"}
        return {"type": ["object", "null"]} if field_is_optional else schema
    
    # Handle list types
    if origin is list:
        schema = {
            "type": "array",
            "items": {"type": "object"}
        }
        return {"type": ["array", "null"]} if field_is_optional else schema
    
    # Fallback for Any or unknown types
    return {"type": ["object", "null"]} if field_is_optional else {"type": "object"}


def generate_ledger_entry_schema() -> dict[str, Any]:
    """Generate the LedgerEntry schema definition."""
    return {
        "type": "object",
        "description": "A single record in the Saga transaction ledger",
        "required": ["sequence_id", "timestamp", "uca_ref", "action", "idempotency_key", "status", "context_data"],
        "properties": {
            "sequence_id": {
                "type": "integer",
                "description": "Monotonically increasing int — used for LIFO rollback ordering",
                "minimum": 0
            },
            "timestamp": {
                "type": "string",
                "description": "ISO-8601 UTC string — written at PENDING time"
            },
            "uca_ref": {
                "type": "string",
                "description": "The STPA UCA ID that governs this action (e.g. 'UCA-4')"
            },
            "action": {
                "type": "string",
                "description": "The forward action name (e.g. 'execute_trade')"
            },
            "idempotency_key": {
                "type": "string",
                "description": "Derived key (hash of tx_id + action) to prevent double-refunds"
            },
            "status": {
                "type": "string",
                "description": "WAL transition state",
                "enum": ["PENDING", "COMPLETED", "ROLLED_BACK", "PARTIAL_FAILURE"]
            },
            "context_data": {
                "type": "object",
                "description": "Payload the compensating node needs to issue the reversal"
            }
        },
        "additionalProperties": False
    }


def generate_schema() -> dict:
    """Generate JSON Schema from AgentState TypedDict via runtime introspection."""
    
    # Get type hints with full resolution
    hints = typing.get_type_hints(AgentState, include_extras=True)
    
    properties = {}
    for field_name, type_hint in hints.items():
        field_is_optional = is_optional(type_hint)
        properties[field_name] = map_type_to_schema(field_name, type_hint, field_is_optional)
    
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://cage.internal/schemas/agent_state_schema.json",
        "$comment": "Auto-generated by scripts/generate_agent_state_schema.py — do not edit directly",
        "title": "AgentState",
        "description": "Financial Advisor Agent State Schema — synchronized from src/governed_financial_advisor/graph/state.py",
        "type": "object",
        "required": REQUIRED_FIELDS,
        "additionalProperties": False,
        "properties": properties,
        "$defs": {
            "OpaqueMessage": {
                "type": "object",
                "description": "LangChain BaseMessage serialised at boundary"
            },
            "LedgerEntry": generate_ledger_entry_schema()
        }
    }
    
    return schema


def format_schema_json(schema: dict) -> str:
    """Format schema as canonical JSON with consistent ordering."""
    return json.dumps(schema, indent=2, sort_keys=False) + "\n"


def write_schema(schema: dict, output_path: Path) -> None:
    """Write schema to JSON file with formatted output."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        f.write(format_schema_json(schema))
    print(f"✓ Schema written to {output_path}")


def check_schema(current_schema: dict, output_path: Path) -> bool:
    """Check if committed schema matches current model.
    
    Returns:
        True if schemas match, False otherwise.
    """
    if not output_path.exists():
        print(f"✗ Schema file does not exist: {output_path}", file=sys.stderr)
        print("  Run 'uv run python scripts/generate_agent_state_schema.py' to generate it.", file=sys.stderr)
        return False
    
    with output_path.open("r") as f:
        committed_content = f.read()
    
    current_content = format_schema_json(current_schema)
    
    if current_content != committed_content:
        print("✗ Schema drift detected!", file=sys.stderr)
        print(f"  Committed schema in {output_path} does not match current AgentState model.", file=sys.stderr)
        
        # Show diff
        import difflib
        committed_lines = committed_content.splitlines(keepends=True)
        current_lines = current_content.splitlines(keepends=True)
        diff = difflib.unified_diff(
            committed_lines,
            current_lines,
            fromfile=f"{output_path} (committed)",
            tofile=f"{output_path} (generated)",
            lineterm=""
        )
        print("\nDiff:", file=sys.stderr)
        for line in diff:
            print(line, file=sys.stderr)
        
        print("\n  Run 'uv run python scripts/generate_agent_state_schema.py' to update the schema.", file=sys.stderr)
        return False
    
    print(f"✓ Schema is up-to-date: {output_path}")
    return True


def main(args: list[str] | None = None) -> int:
    """Main entry point.
    
    Args:
        args: Command-line arguments (for testing). If None, uses sys.argv.
    
    Returns:
        Exit code: 0 on success, 1 on failure.
    """
    parser = argparse.ArgumentParser(
        description="Generate agent_state_schema.json from AgentState runtime model"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check mode: fail with exit code 1 if schema is out of sync (for CI)",
    )
    parsed_args = parser.parse_args(args)
    
    # Generate current schema from runtime model
    current_schema = generate_schema()
    
    if parsed_args.check:
        # CI check mode: verify committed schema matches current model
        if check_schema(current_schema, SCHEMA_OUTPUT_PATH):
            return 0
        else:
            return 1
    else:
        # Write mode: generate and save schema
        write_schema(current_schema, SCHEMA_OUTPUT_PATH)
        return 0


if __name__ == "__main__":
    sys.exit(main())
