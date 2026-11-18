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

"""content_filter.py — keep raw content and end-user identity out of exported spans.

The self-hosted telemetry backend writes every raw event it receives to an object
bucket that is retention-locked for years outside staging. Anything a span carries
therefore outlives the privacy schedule, so prompt and response text and end-user
identifiers must never leave the process in a span.

Call sites record a character length instead of content
(``SPAN_ATTR_CONTENT_INPUT_LENGTH`` / ``SPAN_ATTR_CONTENT_OUTPUT_LENGTH``) and no
end-user identifier. This module is the second line, for any call site or
third-party instrumentation that does not comply:

* :class:`ContentFilterSpanExporter` wraps every span exporter CAGE constructs
  (``tracing_setup.setup_tracing``, ``telemetry_client.configure_telemetry`` and
  the reference advisor's evaluator auditor).
  Before delegating, it drops content- and identity-bearing attribute keys from
  each span, its events and its links. A span it cannot sanitise is dropped, never
  exported unsanitised (fail closed), and the drop is counted in a log line that
  carries no attribute values.
* :func:`disable_content_capture` forces every known instrumentation content
  switch off for the process, whatever the deployment sets.

Denied keys (:func:`is_denied_attribute_key`):

* Exact keys: OpenTelemetry GenAI message content (``gen_ai.input.messages``,
  ``gen_ai.output.messages``, ``gen_ai.system_instructions``), OpenLLMetry task
  payloads (``gen_ai.task.input``, ``gen_ai.task.output``), OpenInference payloads
  (``input.value``, ``output.value``), the generic ``input`` and ``output``, the
  observation payloads in the configured namespace (``OBSERVATION_INPUT``,
  ``OBSERVATION_OUTPUT``), end-user identity (``enduser.id``, ``user.id``,
  ``gen_ai.user``, ``llm.user``), conversation identifiers (``gen_ai.conversation.id``), and HTTP
  bodies (``http.request.body``, ``http.response.body``).
* Dotted-segment prefixes: ``gen_ai.prompt``, ``gen_ai.completion``,
  ``llm.input_messages``, ``llm.output_messages``, ``llm.prompts``,
  ``traceloop.entity.input``, ``traceloop.entity.output`` and
  ``traceloop.association.properties``. A prefix matches the key itself or the key
  followed by ``.`` and further segments, so ``gen_ai.completion_start_time`` (a
  timestamp) is kept while ``gen_ai.completion.0.content`` is dropped.
* Namespace-agnostic suffixes: ``*.observation.input``, ``*.observation.output``,
  ``*.trace.input``, ``*.trace.output`` and ``*.user.id``. They cover the
  backend's vendor-native keys (for Langfuse: ``langfuse.observation.input``,
  ``langfuse.observation.output``, ``langfuse.trace.input``,
  ``langfuse.trace.output`` and ``langfuse.user.id``) and any
  ``CAGE_TELEMETRY_ATTR_NAMESPACE`` remap, without naming a vendor in code.
* Captured HTTP headers that assert who the end user is: ``http.request.header.*``
  and ``http.response.header.*`` keys whose header name contains ``principal``,
  ``email``, ``user_id`` or ``authenticated_user``.

Conversation identifiers and OpenLLMetry association properties are copied
verbatim from the caller's session key, which the reference advisor derives from
the end-user identifier for default sessions; the filter cannot tell a derived key
from an opaque one, so it drops both. CAGE records its own ``thread.id`` only for
a thread id the client supplied.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Mapping, Sequence
from typing import Final

from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import Link
from opentelemetry.util.types import Attributes, AttributeValue

from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_OUTPUT,
    SPAN_ATTR_ENDUSER_ID,
)

logger = logging.getLogger(__name__)

DENIED_ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
    {
        # OpenTelemetry GenAI semantic conventions: message content.
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        # OpenLLMetry task payloads, set alongside traceloop.entity.*.
        "gen_ai.task.input",
        "gen_ai.task.output",
        # Observation payloads in the configured telemetry namespace.
        OBSERVATION_INPUT,
        OBSERVATION_OUTPUT,
        # OpenInference payloads and the generic input/output keys.
        "input.value",
        "output.value",
        "input",
        "output",
        # End-user identity.
        SPAN_ATTR_ENDUSER_ID,
        "user.id",
        "gen_ai.user",
        "llm.user",
        # Conversation identifier copied from the caller's session key.
        "gen_ai.conversation.id",
        # HTTP bodies.
        "http.request.body",
        "http.response.body",
    }
)

DENIED_ATTRIBUTE_PREFIXES: Final[tuple[str, ...]] = (
    "gen_ai.prompt",
    "gen_ai.completion",
    "llm.input_messages",
    "llm.output_messages",
    "llm.prompts",
    "traceloop.entity.input",
    "traceloop.entity.output",
    "traceloop.association.properties",
)

DENIED_ATTRIBUTE_SUFFIXES: Final[tuple[str, ...]] = (
    ".observation.input",
    ".observation.output",
    ".trace.input",
    ".trace.output",
    ".user.id",
)

#: Header-name fragments that mark a captured header as an end-user identity
#: assertion (CAGE's principal header, identity-aware proxy user headers).
IDENTITY_HEADER_TOKENS: Final[tuple[str, ...]] = (
    "principal",
    "email",
    "user_id",
    "authenticated_user",
)

_CAPTURED_HEADER_PREFIXES: Final[tuple[str, ...]] = (
    "http.request.header.",
    "http.response.header.",
)
_DOTTED_PREFIXES: Final[tuple[str, ...]] = tuple(
    f"{prefix}." for prefix in DENIED_ATTRIBUTE_PREFIXES
)
_EXACT_PREFIXES: Final[frozenset[str]] = frozenset(DENIED_ATTRIBUTE_PREFIXES)

#: Instrumentation switches that make libraries record message content or HTTP
#: bodies on spans. :func:`disable_content_capture` forces each one off.
CONTENT_CAPTURE_ENV_VARS: Final[tuple[str, ...]] = (
    "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
    "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_REQUEST_BODY",
    "OTEL_PYTHON_INSTRUMENTATION_HTTPX_CAPTURE_RESPONSE_BODY",
    "TRACELOOP_TRACE_CONTENT",
)


def disable_content_capture() -> None:
    """Force every known instrumentation content switch off for this process.

    This deliberately overrides the deployment's value, so configuration cannot
    turn content capture back on.
    """
    for name in CONTENT_CAPTURE_ENV_VARS:
        os.environ[name] = "false"


def is_denied_attribute_key(key: str) -> bool:
    """Return True when attribute *key* carries content or an end-user identity.

    Raises:
        TypeError: If *key* is not a string; the exporter drops such a span.
    """
    if not isinstance(key, str):
        raise TypeError(f"attribute key must be str, not {type(key).__name__}")
    if key in DENIED_ATTRIBUTE_KEYS or key in _EXACT_PREFIXES:
        return True
    if key.startswith(_DOTTED_PREFIXES) or key.endswith(DENIED_ATTRIBUTE_SUFFIXES):
        return True
    for header_prefix in _CAPTURED_HEADER_PREFIXES:
        if key.startswith(header_prefix):
            header_name = key[len(header_prefix) :]
            return any(token in header_name for token in IDENTITY_HEADER_TOKENS)
    return False


def _filter_attributes(
    attributes: Attributes,
) -> tuple[Mapping[str, AttributeValue], bool]:
    """Return *attributes* without denied keys, and whether any key was dropped."""
    if attributes is None:
        return {}, False
    if not isinstance(attributes, Mapping):
        raise TypeError(
            f"span attributes must be a mapping, not {type(attributes).__name__}"
        )
    kept = {
        key: value
        for key, value in attributes.items()
        if not is_denied_attribute_key(key)
    }
    if len(kept) == len(attributes):
        return attributes, False
    return kept, True


def sanitize_span(span: ReadableSpan) -> ReadableSpan:
    """Return *span* without content- or identity-bearing attributes.

    A span with nothing to drop is returned unchanged. Otherwise the result is a
    copy whose span, event and link attributes omit every denied key; name,
    context, timing, status, resource and scope are carried over as they are.

    Raises:
        Exception: Whatever a malformed span raises while it is read. The exporter
            treats any exception as "cannot sanitise" and drops the span.
    """
    attributes, changed = _filter_attributes(span.attributes)

    events: list[Event] = []
    for event in span.events:
        event_attributes, event_changed = _filter_attributes(event.attributes)
        changed = changed or event_changed
        events.append(
            Event(
                name=event.name,
                attributes=event_attributes,
                timestamp=event.timestamp,
            )
            if event_changed
            else event
        )

    links: list[Link] = []
    for link in span.links:
        link_attributes, link_changed = _filter_attributes(link.attributes)
        changed = changed or link_changed
        links.append(
            Link(context=link.context, attributes=link_attributes)
            if link_changed
            else link
        )

    if not changed:
        return span
    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes=attributes,
        events=tuple(events),
        links=tuple(links),
        kind=span.kind,
        status=span.status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


class ContentFilterSpanExporter(SpanExporter):
    """Span exporter that strips content and end-user identity, then delegates.

    Fails closed: a span that raises while it is sanitised is dropped rather than
    exported unsanitised. Each batch with drops logs one WARNING line with counts
    and exception type names only.
    """

    def __init__(self, delegate: SpanExporter) -> None:
        self._delegate = delegate
        self._lock = threading.Lock()
        self._dropped_spans = 0

    @property
    def delegate(self) -> SpanExporter:
        """The wrapped exporter that receives sanitised spans."""
        return self._delegate

    @property
    def dropped_spans(self) -> int:
        """Spans dropped because they could not be sanitised, since construction."""
        with self._lock:
            return self._dropped_spans

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        sanitized: list[ReadableSpan] = []
        failures: set[str] = set()
        received = 0
        for span in spans:
            received += 1
            try:
                sanitized.append(sanitize_span(span))
            except Exception as exc:  # fail closed: never export it unsanitised
                failures.add(type(exc).__name__)

        dropped = received - len(sanitized)
        if dropped:
            with self._lock:
                self._dropped_spans += dropped
                total = self._dropped_spans
            logger.warning(
                "Telemetry content filter dropped %d of %d span(s) that could not "
                "be sanitised (%s); %d dropped since start.",
                dropped,
                received,
                ", ".join(sorted(failures)),
                total,
            )
        if not sanitized:
            return SpanExportResult.SUCCESS
        return self._delegate.export(sanitized)

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._delegate.force_flush(timeout_millis)
