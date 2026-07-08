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
Pure OpenTelemetry tracing bootstrap for the CAGE Python gateway.

Call ``setup_tracing()`` once at process startup — before binding to any port
— to ensure every governance span is exported via OTLP and that OpenLLMetry
automatically wraps all vLLM / OpenAI SDK calls.

Environment variables:
    OTEL_EXPORTER_OTLP_ENDPOINT  — OTLP HTTP endpoint; if unset and LANGFUSE_HOST is
                                   also unset, OTLP export is disabled (no localhost fallback)
    OTEL_SERVICE_NAME            — OTel service name (default "cage-gateway")
    OTEL_TRACES_EXPORTER         — set to "none" to disable in tests
    OPENLLMETRY_ENABLED          — set to "false" to skip Traceloop init
"""

from __future__ import annotations

import base64
import logging
import os

logger = logging.getLogger("Gateway.TracingSetup")

_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "cage-gateway")
_TRACES_EXPORTER = os.environ.get("OTEL_TRACES_EXPORTER", "otlp").lower()
_OPENLLMETRY_ENABLED = os.environ.get("OPENLLMETRY_ENABLED", "true").lower() != "false"

# Short OTLP export timeout — prevents background BSP thread from blocking
# for the SDK default (10 s) on every failed S3-backend export.
_OTLP_EXPORT_TIMEOUT_S = int(os.environ.get("OTEL_EXPORTER_OTLP_TIMEOUT", "5"))
_OTLP_EXPORT_TIMEOUT_MS = _OTLP_EXPORT_TIMEOUT_S * 1_000


# ---------------------------------------------------------------------------
# Langfuse OTLP endpoint resolution (duplicated from
# governed_financial_advisor.utils.telemetry to keep the gateway package
# dependency-free).
# ---------------------------------------------------------------------------


def _resolve_otlp_endpoint_and_headers() -> tuple[str, dict]:
    """Resolve the OTLP endpoint and auth headers in priority order.

    Priority:
    1. ``OTEL_EXPORTER_OTLP_ENDPOINT`` set explicitly → use as-is, no extra headers.
    2. ``LANGFUSE_HOST`` + ``LANGFUSE_PUBLIC_KEY`` + ``LANGFUSE_SECRET_KEY`` →
       derive ``{LANGFUSE_HOST}/api/public/otel`` with HTTP Basic Auth.
       Langfuse's integrated OTel collector archives all received spans automatically.
    3. No endpoint configured → return ``("", {})`` so the caller skips OTLP export.
       The standalone otel-collector sidecar (port 4318) is deprecated; falling back
       to localhost:4318 would cause retry-loop timeouts in test workers.
    """
    explicit = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if explicit:
        # Parse OTEL_EXPORTER_OTLP_HEADERS (format: "key=value,key2=value2")
        headers: dict = {}
        raw = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "").strip()
        if raw:
            for part in raw.split(","):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    headers[k.strip()] = v.strip()
        return explicit, headers

    host = os.environ.get("LANGFUSE_HOST", "").strip().rstrip("/")
    pk = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip()
    sk = os.environ.get("LANGFUSE_SECRET_KEY", "").strip()
    if host and pk and sk:
        endpoint = f"{host}/api/public/otel"
        token = base64.b64encode(f"{pk}:{sk}".encode()).decode()
        logger.info(
            "✅ Gateway tracing: derived Langfuse OTLP endpoint from LANGFUSE_HOST → %s",
            endpoint,
        )
        return endpoint, {"Authorization": f"Basic {token}"}

    # No endpoint configured — otel-collector (port 4318) is deprecated and removed.
    # Return empty string so setup_tracing() skips OTLP exporter initialisation entirely.
    logger.debug(
        "Gateway tracing: no OTEL_EXPORTER_OTLP_ENDPOINT or LANGFUSE_HOST set — "
        "OTLP export disabled (standalone otel-collector is deprecated; "
        "telemetry is collected natively by Langfuse when LANGFUSE_HOST is set)"
    )
    return "", {}


# Phrases emitted by the Langfuse S3 worker / OTel OTLP exporter when the
# collector's S3 backend is unavailable.
_S3_ERROR_PHRASES = (
    "Failed to upload JSON to S3",
    "Failed to export",
    "Transient error StatusCode",
    "Retrying in",
)

_OTLP_LOGGER_NAMESPACES = (
    "opentelemetry.exporter.otlp.proto.http.exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.sdk.trace.export",
    # Traceloop creates its own internal OTLP exporter; filter that namespace
    # too so its "Failed to export" / retry logs are also downgraded.
    "traceloop",
    "traceloop.sdk",
)


class _OTLPErrorFilter(logging.Filter):
    """Downgrades known OTLP/S3 export ERROR records to WARNING.

    The OTel SDK ``BatchSpanProcessor`` background thread logs a record at
    ``logging.ERROR`` every time the OTLP endpoint returns a non-2xx status
    (e.g. HTTP 500 "Failed to upload JSON to S3" from the Langfuse collector).
    This filter intercepts those records and reduces their severity to WARNING
    so they do not surface as uncaught exceptions or trigger alerting rules.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        msg = record.getMessage()
        if any(phrase in msg for phrase in _S3_ERROR_PHRASES):
            if record.levelno >= logging.ERROR:
                record.levelno = logging.WARNING
                record.levelname = "WARNING"
        return True


def _install_otlp_error_filter() -> None:
    """Attach ``_OTLPErrorFilter`` to every OTLP SDK logger namespace."""
    _filter = _OTLPErrorFilter()
    for ns in _OTLP_LOGGER_NAMESPACES:
        logging.getLogger(ns).addFilter(_filter)
    logger.debug(
        "🔇 OTLP error-downgrade filter installed on %s", _OTLP_LOGGER_NAMESPACES
    )


def setup_tracing() -> None:
    """Initialise OTel TracerProvider + OpenLLMetry.

    Idempotent — safe to call multiple times (subsequent calls are no-ops once
    the global TracerProvider has been set).

    Resilience:
      - OTLP export timeout capped at ``OTEL_EXPORTER_OTLP_TIMEOUT`` (default 5 s)
      - ``_OTLPErrorFilter`` installed on OTLP logger namespaces to downgrade
        "Failed to upload JSON to S3" from ERROR to WARNING
      - ``LoggingSpanExporter`` fallback registered so spans are visible in
        application logs even when the OTLP backend is unavailable
    """
    if _TRACES_EXPORTER == "none":
        logger.info("OTel tracing disabled via OTEL_TRACES_EXPORTER=none.")
        return

    # Install the S3 error-downgrade filter before any exporter is constructed.
    _install_otlp_error_filter()

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            ConsoleSpanExporter,
        )

        # If a real provider is already installed, do not replace it.
        existing = trace.get_tracer_provider()
        if hasattr(existing, "_active_span_processor"):
            logger.debug("TracerProvider already configured — skipping re-init.")
        else:
            resource = Resource(attributes={SERVICE_NAME: _SERVICE_NAME})
            provider = TracerProvider(resource=resource)
            otlp_configured = False

            # OTLP HTTP exporter — only when a real endpoint is configured.
            # The standalone otel-collector (port 4318) is deprecated; we never
            # fall back to localhost:4318 to avoid retry-loop timeouts in tests.
            _otlp_endpoint, _otlp_headers = _resolve_otlp_endpoint_and_headers()
            if not _otlp_endpoint:
                logger.info(
                    "[INFO] OTel OTLP export skipped - no OTEL_EXPORTER_OTLP_ENDPOINT or "
                    "LANGFUSE_HOST configured. Set LANGFUSE_HOST + keys to enable "
                    "telemetry via Langfuse's integrated OTel collector."
                )
            else:
                try:
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    # Append /v1/traces only when using a generic collector endpoint
                    # (Langfuse's endpoint already includes the full path).
                    otlp_url = (
                        _otlp_endpoint
                        if _otlp_endpoint.endswith("/otel")
                        or "/api/public/" in _otlp_endpoint
                        else f"{_otlp_endpoint}/v1/traces"
                    )
                    exporter = OTLPSpanExporter(
                        endpoint=otlp_url,
                        headers=_otlp_headers,
                        timeout=_OTLP_EXPORT_TIMEOUT_S,
                    )
                    provider.add_span_processor(
                        BatchSpanProcessor(
                            exporter,
                            export_timeout_millis=_OTLP_EXPORT_TIMEOUT_MS,
                        )
                    )
                    logger.info(
                        "✅ OTel OTLP exporter configured → %s (timeout=%ds)",
                        otlp_url,
                        _OTLP_EXPORT_TIMEOUT_S,
                    )
                    otlp_configured = True
                except ImportError:
                    logger.warning(
                        "⚠️ opentelemetry-exporter-otlp-proto-http not installed — "
                        "spans will not be exported via OTLP.  "
                        "Install with: pip install opentelemetry-exporter-otlp-proto-http"
                    )

            # Fallback: ConsoleSpanExporter — always registered so spans are
            # never silently dropped when the OTLP backend is unavailable.
            fallback_exporter = ConsoleSpanExporter()
            provider.add_span_processor(
                BatchSpanProcessor(
                    fallback_exporter,
                    export_timeout_millis=_OTLP_EXPORT_TIMEOUT_MS,
                )
            )
            if not otlp_configured:
                logger.warning(
                    "⚠️ OTel: OTLP exporter unavailable — "
                    "spans will be logged locally via ConsoleSpanExporter."
                )

            trace.set_tracer_provider(provider)

    except ImportError:
        logger.warning(
            "⚠️ opentelemetry-sdk not installed — tracing disabled.  "
            "Install with: pip install opentelemetry-sdk"
        )
        return

    # --- OpenLLMetry: auto-instrument vLLM / OpenAI SDK calls ---
    if _OPENLLMETRY_ENABLED:
        try:
            from traceloop.sdk import Traceloop  # type: ignore[import]

            Traceloop.init(
                app_name=_SERVICE_NAME,
                disable_batch=False,
            )
            logger.info(
                "✅ OpenLLMetry (Traceloop) initialised for service '%s'.",
                _SERVICE_NAME,
            )
        except ImportError:
            logger.warning(
                "⚠️ traceloop-sdk not installed — LLM auto-instrumentation disabled.  "
                "Install with: pip install traceloop-sdk"
            )
        except Exception as exc:
            logger.warning("⚠️ OpenLLMetry init failed: %s", exc)
    else:
        logger.info("OpenLLMetry disabled via OPENLLMETRY_ENABLED=false.")
