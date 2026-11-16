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
Telemetry configuration for GCP Cloud Logging and Cloud Trace.
Centralized Observability via OTLP Collector.
"""

import contextlib
import json
import logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from src.gateway.governance.env_posture import env_flag, is_enforcing, resolve_posture
from src.gateway.infrastructure.privacy import scrub_pii as global_scrub
from src.gateway.observability.attributes import (
    OBSERVATION_MODEL_NAME,
    OBSERVATION_TYPE,
    SPAN_ATTR_CONTENT_INPUT_LENGTH,
    SPAN_ATTR_CONTENT_OUTPUT_LENGTH,
    SPAN_ATTR_GEN_AI_OPERATION_NAME,
    SPAN_ATTR_GEN_AI_REQUEST_MODEL,
)
from src.gateway.observability.content_filter import (
    ContentFilterSpanExporter,
    disable_content_capture,
)

# Raw prompts, responses and end-user identifiers must never reach the
# retention-locked telemetry backend: force every instrumentation content switch
# off before any library reads it. Spans that still carry content are dropped at
# export by ContentFilterSpanExporter.
disable_content_capture()

from pythonjsonlogger import json as jsonlogger


# Configure Structured JSON Logging immediately
class TraceIdFilter(logging.Filter):
    """Injects OpenTelemetry trace_id and span_id into log records."""

    def filter(self, record):  # type: ignore[no-untyped-def]
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span:
                ctx = span.get_span_context()
                if (
                    getattr(ctx, "is_valid", False) is True
                    and isinstance(getattr(ctx, "trace_id", None), int)
                    and isinstance(getattr(ctx, "span_id", None), int)
                ):
                    record.trace_id = format(ctx.trace_id, "032x")
                    record.span_id = format(ctx.span_id, "016x")
                    record.trace_sampled = getattr(ctx.trace_flags, "sampled", False)
        except Exception:
            pass
        return True


class ServiceContextFilter(logging.Filter):
    """Injects serviceContext for GCP Cloud Logging/Error Reporting."""

    def filter(self, record):  # type: ignore[no-untyped-def]
        record.serviceContext = {
            "service": os.getenv("SERVICE_NAME", "cage"),
            "version": os.getenv("DEPLOY_TIMESTAMP", "unknown"),
        }
        return True


def setup_canonical_logging():  # type: ignore[no-untyped-def]
    """Configures the root logger to output structured JSON with trace correlation."""
    root_logger = logging.getLogger()

    # Avoid duplicate handlers
    if root_logger.handlers:
        return

    logHandler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s %(span_id)s",
        rename_fields={"levelname": "severity", "asctime": "timestamp"},
    )
    logHandler.setFormatter(formatter)
    logHandler.addFilter(TraceIdFilter())
    logHandler.addFilter(ServiceContextFilter())
    root_logger.addHandler(logHandler)
    root_logger.setLevel(logging.INFO)

    # Force uvicorn loggers to use our handler
    for log_name in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
        log = logging.getLogger(log_name)
        log.handlers = []
        log.propagate = True


# Initialize logging early
HANDLER_ADDED = False

if os.getenv("ENABLE_LOGGING", "true").lower() == "true":
    setup_canonical_logging()
    logger = logging.getLogger("FinancialAdvisor")
else:
    logger = logging.getLogger("FinancialAdvisor")
    # If logging is disabled or OTEL not configured, ensure we have at least a console handler
    if not HANDLER_ADDED:
        # Default to Console Logging if no other handler is added
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)
        # Avoid duplicate handlers if called multiple times
        HANDLER_ADDED = True
        logger.info("⚠️ OTEL disabled. Falling back to standard Console Logging.")

_telemetry_configured = False


# ---------------------------------------------------------------------------
# RemoteTelemetry OTLP endpoint resolution
# ---------------------------------------------------------------------------


def _resolve_otlp_endpoint_and_headers() -> tuple[str, dict]:
    """Resolve the OTLP endpoint and auth headers in priority order.

    Priority:
    1. ``OTEL_EXPORTER_OTLP_ENDPOINT`` set explicitly → use it with
       ``OTEL_EXPORTER_OTLP_HEADERS`` (parsed as ``key=value,key2=value2``).
    2. ``TELEMETRY_HOST`` + ``TELEMETRY_PUBLIC_KEY`` + ``TELEMETRY_SECRET_KEY`` →
       derive ``{TELEMETRY_HOST}/api/public/otel`` with HTTP Basic Auth.
       RemoteTelemetry's integrated OTel collector archives all received spans automatically.
    3. No endpoint configured → return ``("", {})`` so the caller skips OTLP export.
       The standalone otel-collector sidecar (port 4318) is deprecated; falling back
       to localhost:4318 would cause retry-loop timeouts in test workers.
    """
    import base64

    explicit = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if explicit:
        # Parse OTEL_EXPORTER_OTLP_HEADERS (format: "key=value,key2=value2")
        headers: dict = {}
        raw_headers = os.getenv("OTEL_EXPORTER_OTLP_HEADERS", "").strip()
        if raw_headers:
            for part in raw_headers.split(","):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    headers[k.strip()] = v.strip()
        return explicit, headers

    host = os.getenv("TELEMETRY_HOST", "").strip().rstrip("/")
    pk = os.getenv("TELEMETRY_PUBLIC_KEY", "").strip()
    sk = os.getenv("TELEMETRY_SECRET_KEY", "").strip()
    if host and pk and sk:
        endpoint = f"{host}/api/public/otel"
        token = base64.b64encode(f"{pk}:{sk}".encode()).decode()
        logger.info(
            "✅ Telemetry: derived RemoteTelemetry OTLP endpoint from TELEMETRY_HOST → %s",
            endpoint,
        )
        return endpoint, {"Authorization": f"Basic {token}"}

    # No endpoint configured — otel-collector (port 4318) is deprecated and removed.
    # Return empty string so configure_telemetry() skips OTLP exporter initialisation.
    logger.debug(
        "Telemetry: no OTEL_EXPORTER_OTLP_ENDPOINT or TELEMETRY_HOST set — "
        "OTLP export disabled (standalone otel-collector is deprecated; "
        "telemetry is collected natively by RemoteTelemetry when TELEMETRY_HOST is set)"
    )
    return "", {}


# ---------------------------------------------------------------------------
# Resilience: downgrade noisy OTLP/S3 backend errors to WARNING level
# ---------------------------------------------------------------------------

# Phrases emitted by the RemoteTelemetry S3 worker and by the OTel OTLP HTTP exporter
# when the collector's S3 backend or OTLP endpoint is unavailable.  These are
# background-thread errors that should never surface as ERROR in application
# logs.  The list also covers urllib3 connection-pool retry messages that the
# BatchSpanProcessor emits when no local OTLP collector is running (e.g. in
# unit-test environments where OTEL_TRACES_EXPORTER=none is set but a
# secondary TracerProvider was already initialised before the guard fired).
_S3_ERROR_PHRASES = (
    "Failed to upload JSON to S3",
    "Failed to export",
    "Transient error StatusCode",
    "Transient error HTTPConnectionPool",
    "Retrying in",
    "Max retries exceeded",
    "Failed to establish a new connection",
    "Connection refused",
)

# OTLP exporter logger namespaces that may emit these errors.
# Note: the HTTP trace exporter logger name is the module's __name__:
#   opentelemetry.exporter.otlp.proto.http.trace_exporter
# (not ".http.exporter" — that was the old incorrect name).
_OTLP_LOGGER_NAMESPACES = (
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.exporter.otlp.proto.http.metric_exporter",
    "opentelemetry.exporter.otlp.proto.http._log_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.sdk.trace.export",
)

# Short export timeout (seconds) — exported as milliseconds to BatchSpanProcessor.
_OTLP_EXPORT_TIMEOUT_S = int(os.getenv("OTEL_EXPORTER_OTLP_TIMEOUT", "5"))
_OTLP_EXPORT_TIMEOUT_MS = _OTLP_EXPORT_TIMEOUT_S * 1_000


class _OTLPErrorFilter(logging.Filter):
    """Suppresses or downgrades known OTLP/S3 export errors.

    Behaviour depends on ``OTEL_TRACES_EXPORTER``:

    * ``none`` (test mode) — **suppress** all matching records entirely
      (return ``False``).  The ``BatchSpanProcessor`` background thread emits
      ``WARNING``-level "Transient error HTTPConnectionPool … retrying in Xs"
      messages after pytest teardown when no local OTLP collector is running.
      These are expected and should not appear in test output.

    * Any other value (production) — **downgrade** ERROR → WARNING so the
      records are still visible but do not trigger alerting rules.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        msg = record.getMessage()
        if any(phrase in msg for phrase in _S3_ERROR_PHRASES):
            if os.environ.get("OTEL_TRACES_EXPORTER") == "none":
                return False  # suppress entirely in test/disabled mode
            if record.levelno >= logging.ERROR:
                record.levelno = logging.WARNING
                record.levelname = "WARNING"
        return True  # allow the (possibly mutated) record through


def _install_otlp_error_filter() -> None:
    """Attach ``_OTLPErrorFilter`` to every OTLP SDK logger namespace."""
    _filter = _OTLPErrorFilter()
    for ns in _OTLP_LOGGER_NAMESPACES:
        logging.getLogger(ns).addFilter(_filter)
    logger.debug(
        "🔇 OTLP error-downgrade filter installed on %s", _OTLP_LOGGER_NAMESPACES
    )


# Install the filter eagerly at module-import time so that any
# BatchSpanProcessor background thread that was started before
# configure_telemetry() is called (e.g. during pytest teardown) still has
# its noisy retry messages suppressed.
_install_otlp_error_filter()

from opentelemetry.sdk.trace import SpanProcessor

_SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "authorization",
    "bearer",
    "routing_seal",
    "consequence_token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "private_key",
)
_BEARER_VALUE_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-~+/=]{6,}")


def is_sensitive_span_key(key: str) -> bool:
    """Return True when an attribute or payload key names credential/seal material."""
    norm = re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")
    if not norm:
        return False
    if any(sub in norm for sub in _SENSITIVE_KEY_SUBSTRINGS):
        return True
    segments = norm.split("_")
    # Match singular 'token' (e.g. 'token', 'auth_token', 'access_token') while
    # preserving numeric token-usage counters ('input_tokens', 'total_tokens').
    return "token" in segments


def _scrub_json_obj(obj: Any) -> tuple[Any, bool]:
    """Recursively scrub sensitive dict keys and PII/Bearer strings inside JSON payloads."""
    if isinstance(obj, Mapping):
        modified = False
        out_dict: dict[str, Any] = {}
        for raw_k, raw_v in obj.items():
            k_str = str(raw_k)
            if is_sensitive_span_key(k_str):
                out_dict[k_str] = "[REDACTED]"
                if raw_v != "[REDACTED]":
                    modified = True
            else:
                new_v, child_mod = _scrub_json_obj(raw_v)
                out_dict[k_str] = new_v
                modified = modified or child_mod
        return out_dict, modified
    if isinstance(obj, list):
        modified = False
        out_list: list[Any] = []
        for item in obj:
            new_item, item_mod = _scrub_json_obj(item)
            out_list.append(new_item)
            modified = modified or item_mod
        return out_list, modified
    if isinstance(obj, str):
        scrubbed = scrub_span_text(obj)
        return scrubbed, scrubbed != obj
    return obj, False


def scrub_span_text(text: str) -> str:
    """Scrub PII, Bearer credentials, and JSON-embedded sensitive keys from *text*."""
    if not text:
        return text
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, (Mapping, list)):
            sanitized, modified = _scrub_json_obj(parsed)
            if modified:
                return json.dumps(sanitized)
            return text
    no_bearer = _BEARER_VALUE_RE.sub("[REDACTED_BEARER_TOKEN]", text)
    return global_scrub(no_bearer)


def redact_span_payload(obj: Any) -> Any:
    """Return a redacted copy of *obj* safe for serialising into OTel span/log payloads."""
    sanitized, _ = _scrub_json_obj(obj)
    return sanitized


def _scrub_attr_value(key: str, value: Any) -> tuple[Any, bool]:
    """Scrub a single span/event attribute ``(key, value)`` pair."""
    key_sensitive = is_sensitive_span_key(key)
    if isinstance(value, str):
        if key_sensitive:
            return "[REDACTED]", value != "[REDACTED]"
        scrubbed = scrub_span_text(value)
        return scrubbed, scrubbed != value
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        changed = False
        out_seq: list[Any] = []
        for elem in value:
            if isinstance(elem, str):
                new_elem = "[REDACTED]" if key_sensitive else scrub_span_text(elem)
                if new_elem != elem:
                    changed = True
                out_seq.append(new_elem)
            else:
                out_seq.append(elem)
        if not changed:
            return value, False
        return (tuple(out_seq) if isinstance(value, tuple) else out_seq), True
    if key_sensitive and value is not None:
        return "[REDACTED]", True
    return value, False


def _scrub_mutable_attributes(attrs: Any) -> dict[str, Any] | None:
    """Scrub an OTel attribute container in place if possible, returning a scrubbed dict."""
    if attrs is None or not hasattr(attrs, "items"):
        return None
    target = getattr(attrs, "_dict", attrs)
    can_mutate = hasattr(target, "__setitem__")
    scrubbed_copy: dict[str, Any] = {}
    any_changed = False
    for raw_key, raw_val in list(attrs.items()):
        key_str = str(raw_key)
        new_val, changed = _scrub_attr_value(key_str, raw_val)
        scrubbed_copy[key_str] = new_val
        if changed:
            any_changed = True
            if can_mutate:
                try:
                    target[raw_key] = new_val
                except TypeError:
                    can_mutate = False
    if any_changed and not can_mutate:
        return scrubbed_copy
    return scrubbed_copy if any_changed else None


class RedactingSpanProcessor(SpanProcessor):
    """Intercepts all spans and redacts PII, credentials, sequences, and events before export."""

    def __init__(self, inner):  # type: ignore[no-untyped-def]
        self.inner = inner

    def on_start(self, span, parent_context=None):  # type: ignore[no-untyped-def]
        self.inner.on_start(span, parent_context)

    def on_end(self, span):  # type: ignore[no-untyped-def]
        # 1. Scrub span attributes (strings, JSON strings, Sequence[str], sensitive keys)
        attrs = getattr(span, "_attributes", None)
        if attrs is not None:
            replacement = _scrub_mutable_attributes(attrs)
            target = getattr(attrs, "_dict", attrs)
            if replacement is not None and not hasattr(target, "__setitem__"):
                with contextlib.suppress(Exception):
                    object.__setattr__(span, "_attributes", replacement)

        # 2. Scrub span events and their attributes
        events = getattr(span, "_events", None)
        if events:
            from opentelemetry.sdk.trace import Event as _OtelEvent

            updated_events: list[Any] = []
            events_replaced = False
            for ev in list(events):
                ev_name = getattr(ev, "name", "")
                new_ev_name = (
                    scrub_span_text(ev_name) if isinstance(ev_name, str) else ev_name
                )
                ev_attrs = getattr(ev, "_attributes", None)
                if ev_attrs is None:
                    ev_attrs = getattr(ev, "attributes", None)
                ev_replacement = _scrub_mutable_attributes(ev_attrs)
                ev_target = getattr(ev_attrs, "_dict", ev_attrs)
                need_rebuild = new_ev_name != ev_name or (
                    ev_replacement is not None and not hasattr(ev_target, "__setitem__")
                )
                if need_rebuild:
                    clean_attrs = (
                        ev_replacement
                        if ev_replacement is not None
                        else (dict(ev_attrs.items()) if ev_attrs is not None else {})
                    )
                    updated_events.append(
                        _OtelEvent(
                            name=new_ev_name,
                            attributes=clean_attrs,
                            timestamp=getattr(ev, "timestamp", None),
                        )
                    )
                    events_replaced = True
                else:
                    updated_events.append(ev)
            if events_replaced:
                new_container = (
                    tuple(updated_events)
                    if isinstance(events, tuple)
                    else updated_events
                )
                with contextlib.suppress(Exception):
                    object.__setattr__(span, "_events", new_container)

        self.inner.on_end(span)

    def shutdown(self):  # type: ignore[no-untyped-def]
        self.inner.shutdown()

    def force_flush(self, timeout_millis=5_000):  # type: ignore[no-untyped-def]
        # Honour the short timeout so shutdown does not block > 5 s
        return self.inner.force_flush(timeout_millis)


def configure_telemetry():  # type: ignore[no-untyped-def]
    """
    Configures OpenTelemetry tracing (Centralized Mode).
    Uses standard OTLP exporting to an OpenTelemetry Collector.

    Resilience features (all configurable via environment variables):
      - Short OTLP export timeout: ``OTEL_EXPORTER_OTLP_TIMEOUT`` (default 5 s)
      - ``LoggingSpanExporter`` fallback always registered so spans are never
        silently dropped when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is absent
      - ``_OTLPErrorFilter`` installed on OTLP logger namespaces to downgrade
        "Failed to upload JSON to S3" and similar errors from ERROR to WARNING

    Privacy: every exporter (OTLP HTTP, OTLP gRPC and the console fallback) is
    wrapped in ``ContentFilterSpanExporter``, which drops content- and
    identity-bearing attributes before export.
    """
    global HANDLER_ADDED
    global _telemetry_configured

    if _telemetry_configured:
        return

    if os.getenv("ENABLE_LOGGING", "true").lower() != "true":
        return

    try:
        if os.getenv("OTEL_TRACES_EXPORTER") == "none":
            logger.info(
                "🚫 OTEL Telemetry explicitly disabled via environment variable."
            )
            return

        # Install the S3 error-downgrade filter immediately so it intercepts
        # any errors that arise during the exporter construction below.
        _install_otlp_error_filter()

        # Import optional dependencies
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter as GRPCSpanExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )
        from opentelemetry.sdk.trace.sampling import Decision, Sampler, SamplingResult

        class HealthProbeSampler(Sampler):
            def should_sample(  # type: ignore[no-untyped-def]
                self,
                parent_context,
                trace_id,
                name,
                kind=None,
                attributes=None,
                links=None,
                trace_state=None,
            ):
                attributes = attributes or {}
                # Handle both http.url and http.target
                target_url = attributes.get("http.url", "")
                target_url = target_url if isinstance(target_url, str) else ""

                target_target = attributes.get("http.target", "")
                target_target = target_target if isinstance(target_target, str) else ""

                target_method = attributes.get("http.method", "")
                target_method = target_method if isinstance(target_method, str) else ""

                if any(
                    path in target_url or path in target_target
                    for path in ["/health", "/readiness", "resolve-cache"]
                ):
                    return SamplingResult(Decision.DROP)
                if target_method == "HEAD":
                    return SamplingResult(Decision.DROP)

                return SamplingResult(Decision.RECORD_AND_SAMPLE)

            def get_description(self):  # type: ignore[no-untyped-def]
                return "HealthProbeSampler"

        # Configure Resource
        resource = Resource.create(
            {
                "service.name": os.getenv("SERVICE_NAME", "cage"),
                "service.version": os.getenv("DEPLOY_TIMESTAMP", "unknown"),
            }
        )

        # Set up tracer provider
        provider = TracerProvider(resource=resource, sampler=HealthProbeSampler())
        trace.set_tracer_provider(provider)

        # 1. Hot Tier: Cloud Trace (or OTLP fallback)
        try:
            # Note: Explicitly disabling Cloud Trace to prevent 403 crashes
            # if the service account lacks roles/cloudtrace.agent.
            # We rely entirely on OTLP Exporter below.
            pass
        except Exception:
            pass

        # 2. Centralized Tier / RemoteTelemetry native OTLP ingestion
        # Endpoint resolution priority (see _resolve_otlp_endpoint_and_headers):
        #   1. OTEL_EXPORTER_OTLP_ENDPOINT (explicit)
        #   2. TELEMETRY_HOST + TELEMETRY_PUBLIC_KEY + TELEMETRY_SECRET_KEY
        #      → auto-derives {TELEMETRY_HOST}/api/public/otel with HTTP Basic Auth
        #   3. No fallback — OTLP export is disabled if neither is set.
        #      The standalone OTel Collector (port 4318) is deprecated and removed.
        otel_endpoint, otlp_headers = _resolve_otlp_endpoint_and_headers()
        otlp_configured = False

        if not otel_endpoint:
            # No endpoint configured — otel-collector (port 4318) is deprecated.
            # Skip OTLP exporter entirely to avoid retry-loop timeouts in tests.
            logger.info(
                "[INFO] OpenTelemetry: OTLP export skipped - no OTEL_EXPORTER_OTLP_ENDPOINT or "
                "TELEMETRY_HOST configured. Set TELEMETRY_HOST + keys to enable telemetry "
                "via RemoteTelemetry's integrated OTel collector."
            )
        else:
            try:
                if otel_endpoint.startswith("http://") or otel_endpoint.startswith(
                    "https://"
                ):
                    # Use HTTP Exporter — 5 s timeout so failures don't stall the BSP thread
                    otlp_exporter = ContentFilterSpanExporter(
                        OTLPSpanExporter(
                            endpoint=otel_endpoint,
                            headers=otlp_headers,
                            timeout=_OTLP_EXPORT_TIMEOUT_S,
                        )
                    )
                    provider.add_span_processor(
                        RedactingSpanProcessor(
                            BatchSpanProcessor(
                                otlp_exporter,
                                export_timeout_millis=_OTLP_EXPORT_TIMEOUT_MS,
                            )
                        )
                    )
                    logger.info(
                        "✅ OpenTelemetry: HTTP OTLP Exporter configured at %s "
                        "(timeout=%ds, with Final Redaction Tier)",
                        otel_endpoint,
                        _OTLP_EXPORT_TIMEOUT_S,
                    )
                    otlp_configured = True
                else:
                    # Use gRPC Exporter — TLS enforced by default; insecure allowed
                    # only via explicit opt-in under a non-enforcing dev/test posture.
                    enforcing_posture = is_enforcing(resolve_posture())
                    grpc_insecure = (not enforcing_posture) and env_flag(
                        "OTEL_EXPORTER_OTLP_INSECURE", False
                    )
                    grpc_headers = (
                        tuple((str(k).lower(), str(v)) for k, v in otlp_headers.items())
                        if otlp_headers
                        else None
                    )
                    otlp_exporter = ContentFilterSpanExporter(
                        GRPCSpanExporter(
                            endpoint=otel_endpoint,
                            insecure=grpc_insecure,
                            headers=grpc_headers,
                            timeout=_OTLP_EXPORT_TIMEOUT_S,
                        )
                    )
                    provider.add_span_processor(
                        RedactingSpanProcessor(
                            BatchSpanProcessor(
                                otlp_exporter,
                                export_timeout_millis=_OTLP_EXPORT_TIMEOUT_MS,
                            )
                        )
                    )
                    logger.info(
                        "✅ OpenTelemetry: gRPC OTLP Exporter configured at %s "
                        "(timeout=%ds, insecure=%s, with Final Redaction Tier)",
                        otel_endpoint,
                        _OTLP_EXPORT_TIMEOUT_S,
                        grpc_insecure,
                    )
                    otlp_configured = True
            except Exception as otlp_exc:
                logger.warning(
                    "⚠️ OpenTelemetry: OTLP exporter setup failed (%s).",
                    otlp_exc,
                )

        # 3. Dev-only ConsoleSpanExporter fallback: disabled whenever OTLP is
        #    configured OR an enforcing posture is active so spans never write
        #    to stdout in production/staging or alongside OTLP.
        if not otlp_configured and not is_enforcing(resolve_posture()):
            fallback_exporter = ContentFilterSpanExporter(ConsoleSpanExporter())
            logging.getLogger("opentelemetry.sdk.trace").setLevel(logging.WARNING)
            provider.add_span_processor(
                RedactingSpanProcessor(
                    BatchSpanProcessor(
                        fallback_exporter,
                        export_timeout_millis=_OTLP_EXPORT_TIMEOUT_MS,
                    )
                )
            )
            logger.warning(
                "⚠️ OpenTelemetry: OTLP endpoint unavailable in non-enforcing posture — "
                "filtered & redacted spans will be logged locally via ConsoleSpanExporter."
            )

        # Instrument HTTP libraries
        try:
            from opentelemetry.instrumentation.requests import RequestsInstrumentor

            RequestsInstrumentor().instrument()
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

            HTTPXClientInstrumentor().instrument()
            logger.info("✅ OpenTelemetry: HTTP instrumentation enabled.")
        except ImportError:
            pass

        _telemetry_configured = True
        logger.info("✅ Telemetry configuration complete (Centralized Mode).")

    except ImportError as e:
        logger.warning(f"⚠️ Telemetry dependencies not available: {e}")
    except Exception as e:
        logger.error(f"❌ Telemetry configuration failed: {e}")


# Tracer for creating custom spans
def get_tracer():  # type: ignore[no-untyped-def]
    """Returns a tracer for creating custom spans."""
    try:
        from opentelemetry import trace

        return trace.get_tracer("src.genai")
    except ImportError:
        return None


def clean_model_name(model_name: str) -> str:
    """
    Cleans up fragmented model names by stripping provider and storage prefixes.
    Example: 'openai/gs://bucket/meta-llama/Meta-Llama-3.1-8B' -> 'Meta-Llama-3.1-8B'
    """
    if not model_name:
        return model_name

    # Strip common prefixes
    cleaned = model_name
    if cleaned.startswith("provider/"):
        cleaned = cleaned[9:]

    if "/" in cleaned and not cleaned.startswith("provider/"):
        # Extract the final basename from the POSIX path
        cleaned = cleaned.split("/")[-1]

    return cleaned


@contextlib.contextmanager
def genai_span(name: str, prompt: str = None, model: str = None):  # type: ignore[assignment, no-untyped-def]
    """
    Context manager for GenAI Semantic Conventions (Centralized).

    The prompt text is never recorded. The span carries only its character
    length (``SPAN_ATTR_CONTENT_INPUT_LENGTH``): raw prompts must not reach the
    retention-locked telemetry backend.
    """
    tracer = get_tracer()
    if tracer is None:
        yield None
        return

    from opentelemetry import trace as otel_trace

    with tracer.start_as_current_span(name) as span:
        span.set_attribute(SPAN_ATTR_GEN_AI_OPERATION_NAME, "chat")
        span.set_attribute(OBSERVATION_TYPE, "generation")

        if prompt:
            span.set_attribute(SPAN_ATTR_CONTENT_INPUT_LENGTH, len(prompt))

        if model:
            cleaned_model = clean_model_name(model)
            span.set_attribute(SPAN_ATTR_GEN_AI_REQUEST_MODEL, cleaned_model)
            span.set_attribute(OBSERVATION_MODEL_NAME, cleaned_model)

        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR))
            raise


def record_completion(span, completion: str):  # type: ignore[no-untyped-def]
    """Record the completion's character length; its text is never recorded."""
    if span and completion:
        span.set_attribute(SPAN_ATTR_CONTENT_OUTPUT_LENGTH, len(completion))


def record_usage(span, usage):  # type: ignore[no-untyped-def]
    """
    Helper to add token usage stats to the current span.
    """
    if not span or not usage:
        return

    prompt_tokens = None
    completion_tokens = None
    total_tokens = None

    if hasattr(usage, "prompt_tokens"):
        prompt_tokens = getattr(usage, "prompt_tokens", 0)
        completion_tokens = getattr(usage, "completion_tokens", 0)
        total_tokens = getattr(usage, "total_tokens", 0)
    elif isinstance(usage, dict):
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")

    if prompt_tokens is not None:
        span.set_attribute("gen_ai.usage.input_tokens", int(prompt_tokens))
    if completion_tokens is not None:
        span.set_attribute("gen_ai.usage.output_tokens", int(completion_tokens))
    if total_tokens is not None:
        span.set_attribute("gen_ai.usage.total_tokens", int(total_tokens))
