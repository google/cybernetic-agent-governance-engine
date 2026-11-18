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

"""Canary capture for telemetry content tests.

``CanaryCapture`` puts two in-memory exporters on one tracer provider. ``raw``
receives spans exactly as the code produced them; ``exported`` sits behind
``ContentFilterSpanExporter`` and receives what would leave the process.

``leaks`` reports every place a canary string appears in a span: its name, status
description, attribute keys and values, event and link attributes, and resource
attributes.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.util.types import AttributeValue

from src.gateway.observability.content_filter import ContentFilterSpanExporter


def _render(value: AttributeValue) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value)
    return str(value)


def _texts(span: ReadableSpan) -> Iterator[tuple[str, str]]:
    """Yield ``(location, text)`` for every string the span would export."""
    yield "name", span.name
    if span.status.description:
        yield "status description", span.status.description
    for key, value in (span.attributes or {}).items():
        yield f"attribute {key}", f"{key}={_render(value)}"
    for event in span.events:
        yield f"event {event.name}", event.name
        for key, value in (event.attributes or {}).items():
            yield f"event {event.name} attribute {key}", f"{key}={_render(value)}"
    for link in span.links:
        for key, value in (link.attributes or {}).items():
            yield f"link attribute {key}", f"{key}={_render(value)}"
    for key, value in span.resource.attributes.items():
        yield f"resource attribute {key}", f"{key}={_render(value)}"


def leaks(spans: Iterable[ReadableSpan], *canaries: str) -> list[str]:
    """Return one ``"<span>: <location> contains <canary>"`` line per occurrence."""
    found: list[str] = []
    for span in spans:
        for location, text in _texts(span):
            found.extend(
                f"{span.name}: {location} contains {canary!r}"
                for canary in canaries
                if canary in text
            )
    return found


class CanaryCapture:
    """A tracer whose spans land in a raw and a content-filtered exporter."""

    def __init__(self) -> None:
        self.raw = InMemorySpanExporter()
        self.exported = InMemorySpanExporter()
        self.filter = ContentFilterSpanExporter(self.exported)
        self.provider = TracerProvider(shutdown_on_exit=False)
        self.provider.add_span_processor(SimpleSpanProcessor(self.raw))
        self.provider.add_span_processor(SimpleSpanProcessor(self.filter))
        self.tracer = self.provider.get_tracer("telemetry-canary")

    def raw_spans(self) -> tuple[ReadableSpan, ...]:
        return self.raw.get_finished_spans()

    def exported_spans(self) -> tuple[ReadableSpan, ...]:
        return self.exported.get_finished_spans()
