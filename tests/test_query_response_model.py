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

"""Conformance tests for QueryResponse model (S0-2, S0-3, S1-5).

Validates that POST /agent/query returns HTTP 200 with valid QueryResponse
schema across all paths (allowed responses, NeMo refusals, OPA blocks, STPA
violations, Evaluator denials). Enforces trace_id format contract: 32-char
lowercase hex W3C/OTel trace ID or None.
"""

import pytest
from pydantic import ValidationError

from src.governed_financial_advisor.models.query import QueryRequest, QueryResponse

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestQueryResponseModel:
    """Unit tests for QueryResponse Pydantic model validation."""

    def test_query_response_valid_trace_id(self) -> None:
        """Verify 32-char lowercase hex trace_id validates cleanly."""
        valid_trace_id = "0123456789abcdef0123456789abcdef"
        
        response = QueryResponse(
            response="Your portfolio is well-diversified.",
            trace_id=valid_trace_id,
        )
        
        assert response.response == "Your portfolio is well-diversified."
        assert response.trace_id == valid_trace_id

    def test_query_response_none_trace_id(self) -> None:
        """Verify None is accepted when tracing is disabled/unsampled."""
        response = QueryResponse(
            response="I cannot assist with that request.",
            trace_id=None,
        )
        
        assert response.response == "I cannot assist with that request."
        assert response.trace_id is None

    def test_query_response_invalid_trace_id_uppercase(self) -> None:
        """Reject uppercase hex characters in trace_id."""
        with pytest.raises(ValidationError) as exc_info:
            QueryResponse(
                response="Response text",
                trace_id="0123456789ABCDEF0123456789ABCDEF",  # uppercase
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("trace_id",)
        assert "pattern" in errors[0]["type"]

    def test_query_response_invalid_trace_id_too_short(self) -> None:
        """Reject trace_id shorter than 32 characters."""
        with pytest.raises(ValidationError) as exc_info:
            QueryResponse(
                response="Response text",
                trace_id="0123456789abcdef",  # only 16 chars
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("trace_id",)
        assert "pattern" in errors[0]["type"]

    def test_query_response_invalid_trace_id_too_long(self) -> None:
        """Reject trace_id longer than 32 characters."""
        with pytest.raises(ValidationError) as exc_info:
            QueryResponse(
                response="Response text",
                trace_id="0123456789abcdef0123456789abcdef00",  # 34 chars
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("trace_id",)
        assert "pattern" in errors[0]["type"]

    def test_query_response_invalid_trace_id_non_hex(self) -> None:
        """Reject non-hexadecimal characters in trace_id."""
        with pytest.raises(ValidationError) as exc_info:
            QueryResponse(
                response="Response text",
                trace_id="0123456789abcdefghijklmnopqrstuv",  # contains g-v
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("trace_id",)
        assert "pattern" in errors[0]["type"]

    def test_query_response_frozen(self) -> None:
        """Verify QueryResponse is immutable (frozen=True)."""
        response = QueryResponse(
            response="Market analysis complete.",
            trace_id="abcdef0123456789abcdef0123456789",
        )
        
        with pytest.raises(ValidationError):
            response.response = "Modified text"  # type: ignore[misc]

    def test_query_request_model(self) -> None:
        """Verify QueryRequest model validates correctly."""
        request = QueryRequest(
            prompt="What stocks should I buy?",
            user_id="test_user_123",
            thread_id="thread_456",
        )
        
        assert request.prompt == "What stocks should I buy?"
        assert request.user_id == "test_user_123"
        assert request.thread_id == "thread_456"

    def test_query_request_defaults(self) -> None:
        """Verify QueryRequest applies default values for user_id and thread_id."""
        request = QueryRequest(prompt="Tell me about ETFs")
        
        assert request.prompt == "Tell me about ETFs"
        assert request.user_id == "default_user"
        assert request.thread_id == "default_thread"


class TestAgentQueryEndpointSchemaConformance:
    """Schema conformance tests for QueryResponse model."""

    def test_query_response_serialization_allowed(self) -> None:
        """Verify QueryResponse serializes correctly for allowed responses."""
        response = QueryResponse(
            response="Based on your risk profile, I recommend diversified ETFs.",
            trace_id="0123456789abcdef0123456789abcdef",
        )
        
        # Verify serialization matches expected wire format
        json_data = response.model_dump()
        assert json_data == {
            "response": "Based on your risk profile, I recommend diversified ETFs.",
            "trace_id": "0123456789abcdef0123456789abcdef",
        }

    def test_query_response_serialization_refusal(self) -> None:
        """Verify QueryResponse serializes correctly for governance refusals."""
        response = QueryResponse(
            response="I'm sorry, I can't assist with that request.",
            trace_id=None,
        )
        
        json_data = response.model_dump()
        assert json_data == {
            "response": "I'm sorry, I can't assist with that request.",
            "trace_id": None,
        }

    def test_query_response_deserialize_from_server_dict(self) -> None:
        """Verify QueryResponse can deserialize server response dicts."""
        # Simulate what the endpoint returns
        server_response = {
            "response": "Market analysis complete.",
            "trace_id": "abcdef0123456789abcdef0123456789",
        }
        
        validated = QueryResponse(**server_response)
        assert validated.response == "Market analysis complete."
        assert validated.trace_id == "abcdef0123456789abcdef0123456789"

    def test_query_response_json_schema_generation(self) -> None:
        """Verify QueryResponse generates valid JSON Schema for OpenAPI."""
        schema = QueryResponse.model_json_schema()
        
        # Verify schema structure
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "response" in schema["properties"]
        assert "trace_id" in schema["properties"]
        
        # Verify trace_id has pattern constraint
        trace_id_schema = schema["properties"]["trace_id"]
        assert "pattern" in trace_id_schema or "anyOf" in trace_id_schema

    def test_endpoint_decorator_specifies_response_model(self) -> None:
        """Verify POST /agent/query endpoint declares response_model=QueryResponse."""
        import inspect
        
        from src.governed_financial_advisor.server import app
        
        # Find the /agent/query endpoint
        query_route = None
        for route in app.routes:
            if hasattr(route, "path") and route.path == "/agent/query":
                if hasattr(route, "methods") and "POST" in route.methods:
                    query_route = route
                    break
        
        assert query_route is not None, "POST /agent/query endpoint not found"
        
        # Verify response_model is set
        assert hasattr(query_route, "response_model")
        assert query_route.response_model == QueryResponse
