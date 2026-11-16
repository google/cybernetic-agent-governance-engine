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

"""Telemetry never exports raw content or end-user identifiers.

Covers ``src/gateway/observability/content_filter.py`` and the code that feeds it:

* ``ContentFilterSpanExporter`` drops denied keys (exact keys, dotted-segment
  prefixes, namespace-agnostic suffixes, identity-bearing captured headers) from
  span, event and link attributes, keeps everything else, passes a clean span
  through unchanged, and drops a span it cannot sanitise instead of exporting it.
* Every exporter that ``configure_telemetry()``, ``setup_tracing()`` and the
  evaluator auditor build is wrapped in the filter, and content capture is forced
  off.
* ``genai_span(prompt=...)`` and ``record_completion()`` record lengths, never text.
* A LangGraph run traced by the installed LangChain instrumentation exports no
  prompt, response or end-user identifier.

The advisor request span and the inference proxy span have their own canary tests
next to their fixtures (``tests/test_asserted_principal.py`` and
``tests/test_inference_proxy_extended.py``).
"""

from __future__ import annotations

import importlib.util
import logging
import os
from collections.abc import Iterator
from typing import Annotated, Any, TypedDict
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, AnyMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import Link, SpanContext, TraceFlags

from src.gateway.infrastructure import telemetry_client
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_OUTPUT,
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
    SPAN_ATTR_ENDUSER_ID,
    metadata,
)
from src.gateway.observability.content_filter import (
    CONTENT_CAPTURE_ENV_VARS,
    ContentFilterSpanExporter,
    disable_content_capture,
    is_denied_attribute_key,
)
from tests.fixtures.telemetry_canary import CanaryCapture, leaks

pytestmark = [pytest.mark.unit, pytest.mark.local]

PROMPT_CANARY = "zebra-prompt-canary-5d1e9b"
RESPONSE_CANARY = "okapi-response-canary-7c42a0"
USER_CANARY = "canary-user-3f8b61"

_CONTEXT = SpanContext(
    trace_id=0x5D1E9B,
    span_id=0x7C42A0,
    is_remote=False,
    trace_flags=TraceFlags(TraceFlags.SAMPLED),
)
_LINKED = SpanContext(
    trace_id=0x3F8B61,
    span_id=0x1,
    is_remote=True,
    trace_flags=TraceFlags(TraceFlags.SAMPLED),
)

#: The brief's exact keys plus keys the installed instrumentation was observed to
#: fill with content or an end-user identifier.
DENIED_EXACT_KEYS = (
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.system_instructions",
    "langfuse.observation.input",
    "langfuse.observation.output",
    "langfuse.trace.input",
    "langfuse.trace.output",
    "input.value",
    "output.value",
    "input",
    "output",
    "enduser.id",
    "user.id",
    "langfuse.user.id",
    "http.request.body",
    "http.response.body",
    "gen_ai.task.input",
    "gen_ai.task.output",
    "gen_ai.user",
    "llm.user",
    "gen_ai.conversation.id",
    OBSERVATION_INPUT,
    OBSERVATION_OUTPUT,
)

DENIED_PREFIXED_KEYS = (
    "gen_ai.prompt",
    "gen_ai.prompt.0.content",
    "gen_ai.completion",
    "gen_ai.completion.0.tool_calls.0.arguments",
    "llm.input_messages.0.message.content",
    "llm.output_messages.0.message.content",
    "llm.prompts.0",
    "traceloop.entity.input",
    "traceloop.entity.output",
    "traceloop.association.properties.thread_id",
    "traceloop.association.properties.user_id",
)

DENIED_HEADER_KEYS = (
    "http.request.header.x_goog_authenticated_user_email",
    "http.request.header.x_goog_authenticated_user_id",
    "http.request.header.x_cage_principal",
    "http.request.header.x_forwarded_email",
    "http.response.header.x_user_id",
)

#: Non-content metadata that must survive, including look-alikes of denied keys.
KEPT_KEYS = (
    "gen_ai.operation.name",
    "gen_ai.system",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.request.streaming",
    "gen_ai.usage.input_tokens",
    "gen_ai.completion_start_time",
    "gen_ai.prompt_tokens",
    "cage.principal.verified",
    "cage.verdict",
    "cage.governance.violation_codes",
    "governance.reason",
    "thread.id",
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    "traceloop.entity.name",
    "observation.output",
    "langfuse.observation.metadata.iso_control",
    metadata("governance.decision"),
    "http.request.header.user_agent",
    "http.request.header.x_request_id",
    "http.response.header.content_type",
)


def _span(attributes: Any, *, name: str = "unit") -> ReadableSpan:
    return ReadableSpan(
        name=name, context=_CONTEXT, attributes=attributes, start_time=1, end_time=2
    )


def _export_one(
    attributes: dict[str, Any],
    *,
    event_attributes: dict[str, Any] | None = None,
    link_attributes: dict[str, Any] | None = None,
) -> tuple[ReadableSpan, ReadableSpan]:
    """Record one real span; return it as produced and as exported."""
    capture = CanaryCapture()
    links = [Link(_LINKED, link_attributes)] if link_attributes else None
    with capture.tracer.start_as_current_span(
        "unit", attributes=attributes, links=links
    ) as span:
        if event_attributes is not None:
            span.add_event("unit.event", event_attributes)
    (raw,) = capture.raw_spans()
    (exported,) = capture.exported_spans()
    return raw, exported


# ---------------------------------------------------------------------------
# ContentFilterSpanExporter: what is dropped and what is kept
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key", DENIED_EXACT_KEYS + DENIED_PREFIXED_KEYS + DENIED_HEADER_KEYS
)
def test_denied_key_is_dropped_and_metadata_kept(key: str) -> None:
    raw, exported = _export_one({key: PROMPT_CANARY, "gen_ai.request.model": "m"})

    assert raw.attributes[key] == PROMPT_CANARY
    assert key not in exported.attributes
    assert exported.attributes["gen_ai.request.model"] == "m"
    assert leaks([exported], PROMPT_CANARY) == []


@pytest.mark.parametrize("key", KEPT_KEYS)
def test_non_content_key_is_kept(key: str) -> None:
    assert is_denied_attribute_key(key) is False
    _, exported = _export_one({key: "kept-value", "input": PROMPT_CANARY})

    assert exported.attributes[key] == "kept-value"
    assert "input" not in exported.attributes


def test_event_and_link_attributes_are_filtered() -> None:
    raw, exported = _export_one(
        {"gen_ai.operation.name": "chat"},
        event_attributes={
            "gen_ai.prompt": PROMPT_CANARY,
            "gen_ai.completion": RESPONSE_CANARY,
            "compliance.control_id": "A.5.3",
        },
        link_attributes={SPAN_ATTR_ENDUSER_ID: USER_CANARY, "link.kind": "follows"},
    )

    assert leaks([raw], PROMPT_CANARY, RESPONSE_CANARY, USER_CANARY)
    assert leaks([exported], PROMPT_CANARY, RESPONSE_CANARY, USER_CANARY) == []
    (event,) = exported.events
    assert event.name == "unit.event"
    assert event.timestamp == raw.events[0].timestamp
    assert dict(event.attributes) == {"compliance.control_id": "A.5.3"}
    (link,) = exported.links
    assert link.context == _LINKED
    assert dict(link.attributes) == {"link.kind": "follows"}
    assert exported.context == raw.context
    assert (exported.start_time, exported.end_time) == (raw.start_time, raw.end_time)


def test_span_without_denied_keys_is_exported_unchanged() -> None:
    raw, exported = _export_one({"gen_ai.request.model": "m", "cage.verdict": "ALLOW"})

    assert exported is raw


def test_non_string_key_is_rejected() -> None:
    with pytest.raises(TypeError):
        is_denied_attribute_key(7)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ContentFilterSpanExporter: fail closed
# ---------------------------------------------------------------------------


class _UnreadableSpan(ReadableSpan):
    """A span whose attribute store raises when read."""

    @property
    def attributes(self) -> Any:
        raise RuntimeError(f"attribute store unavailable: {PROMPT_CANARY}")


def test_span_that_cannot_be_sanitised_is_dropped_not_exported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    delegate = InMemorySpanExporter()
    exporter = ContentFilterSpanExporter(delegate)
    good = _span(
        {"gen_ai.input.messages": PROMPT_CANARY, "gen_ai.request.model": "m"},
        name="good",
    )
    unreadable = _UnreadableSpan(name="unreadable", context=_CONTEXT)
    non_string_key = _span({7: PROMPT_CANARY}, name="non-string-key")
    not_a_mapping = _span([PROMPT_CANARY], name="not-a-mapping")

    with caplog.at_level(logging.WARNING, logger="src.gateway.observability"):
        result = exporter.export([good, unreadable, non_string_key, not_a_mapping])

    assert result is SpanExportResult.SUCCESS
    (exported,) = delegate.get_finished_spans()
    assert exported.name == "good"
    assert dict(exported.attributes) == {"gen_ai.request.model": "m"}
    assert exporter.dropped_spans == 3
    assert "dropped 3 of 4 span(s)" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "TypeError" in caplog.text
    assert PROMPT_CANARY not in caplog.text


def test_batch_of_unsanitisable_spans_never_reaches_the_delegate() -> None:
    delegate = MagicMock(spec=SpanExporter)
    exporter = ContentFilterSpanExporter(delegate)

    result = exporter.export([_UnreadableSpan(name="unreadable", context=_CONTEXT)])

    assert result is SpanExportResult.SUCCESS
    delegate.export.assert_not_called()
    assert exporter.dropped_spans == 1


def test_delegate_result_and_lifecycle_pass_through() -> None:
    delegate = MagicMock(spec=SpanExporter)
    delegate.export.return_value = SpanExportResult.FAILURE
    delegate.force_flush.return_value = True
    exporter = ContentFilterSpanExporter(delegate)

    assert exporter.export([_span({"cage.verdict": "ALLOW"})]) is (
        SpanExportResult.FAILURE
    )
    assert exporter.force_flush(1234) is True
    delegate.force_flush.assert_called_once_with(1234)
    exporter.shutdown()
    delegate.shutdown.assert_called_once_with()
    assert exporter.delegate is delegate


# ---------------------------------------------------------------------------
# Content capture switches
# ---------------------------------------------------------------------------


def test_disable_content_capture_forces_every_switch_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert set(CONTENT_CAPTURE_ENV_VARS) >= {
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
        "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY",
        "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY",
        "TRACELOOP_TRACE_CONTENT",
    }
    for name in CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.setenv(name, "true")

    disable_content_capture()

    assert {
        name: os.environ[name] for name in CONTENT_CAPTURE_ENV_VARS
    } == dict.fromkeys(CONTENT_CAPTURE_ENV_VARS, "false")


# ---------------------------------------------------------------------------
# Every exporter CAGE builds is wrapped
# ---------------------------------------------------------------------------


@pytest.fixture
def recorded_exporters(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[SpanExporter]]:
    """Replace BatchSpanProcessor with a recorder of the exporter it receives."""
    recorded: list[SpanExporter] = []

    class _RecordingProcessor(SpanProcessor):
        def __init__(self, span_exporter: SpanExporter, **_kwargs: Any) -> None:
            recorded.append(span_exporter)

    monkeypatch.setattr(
        "opentelemetry.sdk.trace.export.BatchSpanProcessor", _RecordingProcessor
    )
    monkeypatch.setattr("opentelemetry.trace.set_tracer_provider", lambda _p: None)
    yield recorded
    for exporter in recorded:
        exporter.shutdown()


def _assert_all_filtered(exporters: list[SpanExporter], expected: int) -> None:
    assert len(exporters) == expected
    for exporter in exporters:
        assert isinstance(exporter, ContentFilterSpanExporter), exporter


@pytest.mark.parametrize(
    "endpoint",
    ["http://collector.invalid:4318/v1/traces", "collector.invalid:4317"],
    ids=["otlp-http", "otlp-grpc"],
)
def test_configure_telemetry_wraps_every_exporter(
    endpoint: str,
    monkeypatch: pytest.MonkeyPatch,
    recorded_exporters: list[SpanExporter],
) -> None:
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")
    monkeypatch.setenv("ENABLE_LOGGING", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
    monkeypatch.setattr(telemetry_client, "_telemetry_configured", False)
    monkeypatch.setattr(
        "opentelemetry.instrumentation.requests.RequestsInstrumentor.instrument",
        lambda _self, **_kwargs: None,
    )
    if importlib.util.find_spec("opentelemetry.instrumentation.httpx") is not None:
        monkeypatch.setattr(
            "opentelemetry.instrumentation.httpx.HTTPXClientInstrumentor.instrument",
            lambda _self, **_kwargs: None,
        )
    sdk_logger = logging.getLogger("opentelemetry.sdk.trace")
    level = sdk_logger.level
    try:
        telemetry_client.configure_telemetry()
    finally:
        sdk_logger.setLevel(level)

    _assert_all_filtered(recorded_exporters, expected=2)  # OTLP + console fallback


def test_setup_tracing_wraps_every_exporter(
    monkeypatch: pytest.MonkeyPatch, recorded_exporters: list[SpanExporter]
) -> None:
    from src.gateway import tracing_setup

    monkeypatch.setattr(tracing_setup, "_TRACES_EXPORTER", "otlp")
    monkeypatch.setattr(tracing_setup, "_OPENLLMETRY_ENABLED", False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.invalid:4318")
    monkeypatch.setattr("opentelemetry.trace.get_tracer_provider", lambda: object())
    for name in CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.setenv(name, "true")

    tracing_setup.setup_tracing()

    _assert_all_filtered(recorded_exporters, expected=2)  # OTLP + console fallback
    assert all(os.environ[name] == "false" for name in CONTENT_CAPTURE_ENV_VARS)


def test_evaluator_auditor_wraps_its_compliance_exporter(
    monkeypatch: pytest.MonkeyPatch, recorded_exporters: list[SpanExporter]
) -> None:
    from src.governed_financial_advisor.agents.evaluator.auditor import (
        EvaluatorAuditor,
    )

    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "otlp")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_PUBLIC_KEY", "test-public-key")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("LANGFUSE_COMPLIANCE_HOST", "http://collector.invalid")

    EvaluatorAuditor()._init_compliance_telemetry()

    _assert_all_filtered(recorded_exporters, expected=1)


# ---------------------------------------------------------------------------
# genai_span / record_completion
# ---------------------------------------------------------------------------


def test_genai_span_records_lengths_never_text(monkeypatch: pytest.MonkeyPatch) -> None:
    capture = CanaryCapture()
    monkeypatch.setattr(telemetry_client, "get_tracer", lambda: capture.tracer)
    prompt = f"Should I buy {PROMPT_CANARY} shares?"
    completion = f"Weigh {RESPONSE_CANARY} against an index fund."

    with telemetry_client.genai_span(
        "llm.generate.fast", prompt=prompt, model="provider/gs://bucket/fast-model"
    ) as span:
        telemetry_client.record_completion(span, completion)
        telemetry_client.record_usage(
            span, {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12}
        )

    assert leaks(capture.raw_spans(), PROMPT_CANARY, RESPONSE_CANARY) == []
    assert leaks(capture.exported_spans(), PROMPT_CANARY, RESPONSE_CANARY) == []
    (exported,) = capture.exported_spans()
    assert exported.attributes[SPAN_ATTR_CONTENT_INPUT_LENGTH] == len(prompt)
    assert exported.attributes[SPAN_ATTR_CONTENT_OUTPUT_LENGTH] == len(completion)
    assert exported.attributes["gen_ai.request.model"] == "fast-model"
    assert exported.attributes["gen_ai.usage.input_tokens"] == 7


# ---------------------------------------------------------------------------
# Third-party instrumentation: LangChain / LangGraph
# ---------------------------------------------------------------------------


class _GraphState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    user_id: str


def _answer(_state: _GraphState) -> dict[str, Any]:
    return {
        "messages": [AIMessage(content=f"Prefer index funds to {RESPONSE_CANARY}.")]
    }


@pytest.fixture
def langchain_capture(monkeypatch: pytest.MonkeyPatch) -> Iterator[CanaryCapture]:
    """Instrument LangChain against a canary capture with content capture off."""
    from opentelemetry.instrumentation.langchain import LangchainInstrumentor

    for name in CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.setenv(name, "true")
    disable_content_capture()
    instrumentor = LangchainInstrumentor()
    was_instrumented = instrumentor.is_instrumented_by_opentelemetry
    if was_instrumented:
        instrumentor.uninstrument()
    capture = CanaryCapture()
    instrumentor.instrument(tracer_provider=capture.provider)
    try:
        yield capture
    finally:
        instrumentor.uninstrument()
        if was_instrumented:
            instrumentor.instrument()


async def test_langgraph_run_exports_no_prompt_response_or_user(
    langchain_capture: CanaryCapture,
) -> None:
    builder = StateGraph(_GraphState)
    builder.add_node("answer", _answer)
    builder.add_edge(START, "answer")
    builder.add_edge("answer", END)
    graph = builder.compile(checkpointer=MemorySaver())

    await graph.ainvoke(
        {"messages": [("user", f"Is {PROMPT_CANARY} a buy?")], "user_id": USER_CANARY},
        # The advisor's default thread id embeds the user id.
        {"configurable": {"thread_id": f"advisor_session_{USER_CANARY}"}},
    )

    raw = langchain_capture.raw_spans()
    assert raw, "the LangChain instrumentation recorded no spans"
    raw_keys = {key for span in raw for key in span.attributes or {}}
    # Content capture is off at the source: no entity or task payloads at all.
    assert not raw_keys & {
        "traceloop.entity.input",
        "traceloop.entity.output",
        "gen_ai.task.input",
        "gen_ai.task.output",
    }
    exported = langchain_capture.exported_spans()
    assert len(exported) == len(raw)
    assert leaks(exported, PROMPT_CANARY, RESPONSE_CANARY, USER_CANARY) == []
    assert any(
        span.attributes.get("traceloop.entity.name") == "answer" for span in exported
    )
