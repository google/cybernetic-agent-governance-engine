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

"""The advisor's end-user principal is asserted, not authenticated (issue #516).

Covers the wire contract in ``src/governed_financial_advisor/models/principal.py``:

* ``QueryRequest.user_id`` is required and limited to the gateway's principal
  charset and 64-character cap, and ``POST /agent/query`` answers 422 before the
  graph runs when it is missing or invalid.
* ``x-cage-principal`` and ``x-geap-user-id`` are sanitized and truncated by one
  helper that matches the gateway's ``sanitize_principal``.
* The request span records ``cage.principal.verified = False`` next to
  ``enduser.id``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from pydantic import ValidationError

from src.gateway.observability.attributes import (
    SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED,
    SPAN_ATTR_ENDUSER_ID,
)
from src.gateway.server.rate_limit import sanitize_principal as gateway_sanitize
from src.governed_financial_advisor.infrastructure.gateway_client import (
    GatewayClient,
)
from src.governed_financial_advisor.models.principal import (
    PRINCIPAL_MAX_LEN,
    PRINCIPAL_PATTERN,
    principal_header_value,
)
from src.governed_financial_advisor.models.query import QueryRequest
from src.governed_financial_advisor.utils.context import user_context

pytestmark = [pytest.mark.unit, pytest.mark.local]

_API_KEY = "test-advisor-api-key"
_AUTH = {"Authorization": f"Bearer {_API_KEY}"}

#: Values QueryRequest accepts that reach the gateway byte-for-byte.
_PASS_THROUGH_PRINCIPALS = (
    "investor-42",
    "user:alice@example.com",
    "spiffe://cluster.local/ns/default/sa/advisor",
    "A.b_c:d@e/f-g",
    "p" * PRINCIPAL_MAX_LEN,
)

#: (value, reason) pairs QueryRequest must reject.
_INVALID_PRINCIPALS = (
    ("", "empty"),
    ("alice smith", "space"),
    ("alice\n", "trailing newline"),
    ("alice\r\nx-injected: 1", "header injection"),
    ("alice;drop", "semicolon"),
    ("ユーザー", "non-ASCII"),
    ("p" * (PRINCIPAL_MAX_LEN + 1), "65 characters"),
)

#: Hostile or malformed inputs for the header sanitizer parity check.
_SANITIZER_CORPUS = (
    "investor-42",
    "user:alice@example.com",
    "  padded  ",
    "bad\nheader\x00value!",
    "alice\r\nx-injected: 1",
    "ユーザー-7",
    "a b c",
    "__edge__",
    "x" * 100,
    "a" * 63 + "!" + "b",
    "_" * 70 + "z",
    "!!!",
    "   ",
    "",
    "anonymous",
)


# ---------------------------------------------------------------------------
# QueryRequest model
# ---------------------------------------------------------------------------


class TestQueryRequestPrincipal:
    """QueryRequest.user_id is required and matches the gateway principal charset."""

    def test_missing_user_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            QueryRequest(prompt="Tell me about ETFs")
        errors = exc_info.value.errors()
        assert [e["loc"] for e in errors] == [("user_id",)]
        assert errors[0]["type"] == "missing"

    @pytest.mark.parametrize(
        ("user_id", "reason"),
        _INVALID_PRINCIPALS,
        ids=[r for _, r in _INVALID_PRINCIPALS],
    )
    def test_invalid_user_id_is_rejected(self, user_id: str, reason: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            QueryRequest(prompt="Tell me about ETFs", user_id=user_id)
        assert [e["loc"] for e in exc_info.value.errors()] == [("user_id",)], reason

    def test_non_string_user_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            QueryRequest(prompt="Tell me about ETFs", user_id=42)  # type: ignore[arg-type]

    @pytest.mark.parametrize("user_id", _PASS_THROUGH_PRINCIPALS)
    def test_accepted_user_id_reaches_gateway_unchanged(self, user_id: str) -> None:
        request = QueryRequest(prompt="Tell me about ETFs", user_id=user_id)
        assert request.user_id == user_id
        assert principal_header_value(user_id) == user_id
        assert gateway_sanitize(user_id) == user_id

    def test_edge_underscores_are_normalized_like_the_gateway(self) -> None:
        """The charset admits ``_``; the gateway strips it from the edges, and so does the header."""
        request = QueryRequest(prompt="Tell me about ETFs", user_id="_alice_")
        assert principal_header_value(request.user_id) == "alice"
        assert gateway_sanitize(request.user_id) == "alice"

    def test_pattern_matches_the_gateway_charset(self) -> None:
        charset = "".join(chr(c) for c in range(32, 127))
        allowed = {ch for ch in charset if re.fullmatch(PRINCIPAL_PATTERN, ch)}
        survives_gateway = {
            ch for ch in charset if gateway_sanitize(f"a{ch}a") == f"a{ch}a"
        }
        assert allowed == survives_gateway


# ---------------------------------------------------------------------------
# POST /agent/query validation (HTTP)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def advisor_server() -> Any:
    """Import the advisor app with its import-time telemetry hooks stubbed."""
    with (
        patch("src.integrations.nemo.manager.load_rails", return_value=MagicMock()),
        patch("src.gateway.infrastructure.telemetry_client.configure_telemetry"),
        patch(
            "opentelemetry.instrumentation.langchain.LangchainInstrumentor.instrument"
        ),
    ):
        import src.governed_financial_advisor.server as srv
    return srv


class _CapturingGraph:
    """Graph stand-in that records the principal the gateway client would send."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def ainvoke(
        self, inputs: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "inputs": inputs,
                "config": config,
                "user_context": user_context.get(),
                "headers": GatewayClient()._build_headers(),
            }
        )
        return {"messages": [SimpleNamespace(content="Diversify across index funds.")]}


@pytest.fixture
def stub_cache() -> Iterator[MagicMock]:
    cache = MagicMock()
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock(return_value=None)
    with patch(
        "src.governed_financial_advisor.infrastructure.query_cache.get_query_cache",
        AsyncMock(return_value=cache),
    ):
        yield cache


@pytest.fixture
def query_client(
    advisor_server: Any, stub_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> tuple[TestClient, _CapturingGraph]:
    monkeypatch.setenv("CAGE_API_KEY", _API_KEY)
    monkeypatch.delenv("CAGE_ADVISOR_RUNTIME", raising=False)
    graph = _CapturingGraph()
    monkeypatch.setattr(advisor_server.app.state, "graph", graph, raising=False)
    return TestClient(advisor_server.app, raise_server_exceptions=True), graph


class TestAgentQueryRejectsBadPrincipal:
    """POST /agent/query fails closed with 422 before any graph execution."""

    def test_missing_user_id_returns_422(
        self, query_client: tuple[TestClient, _CapturingGraph]
    ) -> None:
        client, graph = query_client
        resp = client.post("/agent/query", json={"prompt": "Hello"}, headers=_AUTH)
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert [d["loc"] for d in detail] == [["body", "user_id"]]
        assert detail[0]["type"] == "missing"
        assert graph.calls == []

    @pytest.mark.parametrize(
        ("user_id", "reason"),
        _INVALID_PRINCIPALS,
        ids=[r for _, r in _INVALID_PRINCIPALS],
    )
    def test_invalid_user_id_returns_422(
        self,
        query_client: tuple[TestClient, _CapturingGraph],
        user_id: str,
        reason: str,
    ) -> None:
        client, graph = query_client
        resp = client.post(
            "/agent/query", json={"prompt": "Hello", "user_id": user_id}, headers=_AUTH
        )
        assert resp.status_code == 422, reason
        assert [d["loc"] for d in resp.json()["detail"]] == [["body", "user_id"]]
        assert graph.calls == []

    def test_valid_user_id_reaches_graph_and_gateway_header(
        self, query_client: tuple[TestClient, _CapturingGraph]
    ) -> None:
        client, graph = query_client
        resp = client.post(
            "/agent/query",
            json={"prompt": "Hello", "user_id": "user:alice@example.com"},
            headers=_AUTH,
        )
        assert resp.status_code == 200
        assert resp.json()["response"] == "Diversify across index funds."
        assert len(graph.calls) == 1
        call = graph.calls[0]
        assert call["inputs"]["user_id"] == "user:alice@example.com"
        assert call["user_context"] == "user:alice@example.com"
        assert call["headers"]["x-cage-principal"] == "user:alice@example.com"


class TestQuerySpanMarksPrincipalUnverified:
    """The /agent/query span records that enduser.id is caller-asserted."""

    async def test_span_records_enduser_and_unverified_flag(
        self, advisor_server: Any, stub_cache: MagicMock
    ) -> None:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer(__name__)
        graph = _CapturingGraph()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(graph=graph))
        )

        with tracer.start_as_current_span("POST /agent/query"):
            result = await advisor_server.query_agent(
                QueryRequest(prompt="Hello", user_id="investor-42"),
                request,
                _auth="test",
            )

        assert result["response"] == "Diversify across index funds."
        (span,) = exporter.get_finished_spans()
        assert span.attributes[SPAN_ATTR_ENDUSER_ID] == "investor-42"
        assert span.attributes[SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED] is False
        assert SPAN_ATTR_CAGE_PRINCIPAL_VERIFIED == "cage.principal.verified"
        assert SPAN_ATTR_ENDUSER_ID == "enduser.id"


# ---------------------------------------------------------------------------
# Outbound gateway headers
# ---------------------------------------------------------------------------


def _headers_for(principal: str) -> dict[str, str]:
    token = user_context.set(principal)
    try:
        return GatewayClient()._build_headers()
    finally:
        user_context.reset(token)


class TestPrincipalHeaders:
    """x-cage-principal and x-geap-user-id share one sanitizer and cap."""

    def test_both_headers_are_sanitized_and_truncated_identically(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        hostile = "bad\nheader\x00value!" + "x" * 100
        headers = _headers_for(hostile)

        expected = gateway_sanitize(hostile)
        assert headers["x-cage-principal"] == expected
        assert headers["x-geap-user-id"] == expected
        assert len(expected) == PRINCIPAL_MAX_LEN
        assert re.fullmatch(PRINCIPAL_PATTERN, expected)
        assert expected.startswith("bad_header_value_x")

    def test_long_principal_is_capped_at_64_in_both_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        headers = _headers_for("u" * 100)
        assert headers["x-cage-principal"] == "u" * PRINCIPAL_MAX_LEN
        assert headers["x-geap-user-id"] == "u" * PRINCIPAL_MAX_LEN

    @pytest.mark.parametrize("unusable", ["!!!", "   ", "", "\n\x00"])
    def test_unusable_principal_sends_neither_header(
        self, monkeypatch: pytest.MonkeyPatch, unusable: str
    ) -> None:
        monkeypatch.setenv("CAGE_ADVISOR_RUNTIME", "geap")
        headers = _headers_for(unusable)
        assert "x-cage-principal" not in headers
        assert "x-geap-user-id" not in headers

    def test_geap_user_header_only_on_geap_runtime(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CAGE_ADVISOR_RUNTIME", raising=False)
        headers = _headers_for("investor-42")
        assert headers["x-cage-principal"] == "investor-42"
        assert "x-geap-user-id" not in headers

    @pytest.mark.parametrize("raw", _SANITIZER_CORPUS)
    def test_helper_matches_gateway_sanitizer(self, raw: str) -> None:
        advisor_value = principal_header_value(raw)
        gateway_value = gateway_sanitize(raw)
        if advisor_value is None:
            assert gateway_value == "anonymous"
        else:
            assert advisor_value == gateway_value
