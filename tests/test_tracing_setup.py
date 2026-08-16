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
tests/test_tracing_setup.py — Unit tests for OpenTelemetry tracing setup in gateway.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.tracing_setup import (
    _OTLPErrorFilter,
    _install_otlp_error_filter,
    _resolve_otlp_endpoint_and_headers,
    setup_tracing,
)


@pytest.mark.local
@pytest.mark.unit
def test_resolve_otlp_endpoint_explicit():
    with patch.dict(
        os.environ,
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
            "OTEL_EXPORTER_OTLP_HEADERS": "key1=val1, key2=val2",
        },
        clear=True,
    ):
        endpoint, headers = _resolve_otlp_endpoint_and_headers()
        assert endpoint == "http://collector:4318"
        assert headers == {"key1": "val1", "key2": "val2"}


@pytest.mark.local
@pytest.mark.unit
def test_resolve_otlp_endpoint_langfuse():
    with patch.dict(
        os.environ,
        {
            "LANGFUSE_HOST": "https://langfuse.example.com",
            "LANGFUSE_PUBLIC_KEY": "pk-lf-12345",
            "LANGFUSE_SECRET_KEY": "sk-lf-67890",
        },
        clear=True,
    ):
        endpoint, headers = _resolve_otlp_endpoint_and_headers()
        assert endpoint == "https://langfuse.example.com/api/public/otel"
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")


@pytest.mark.local
@pytest.mark.unit
def test_resolve_otlp_endpoint_empty():
    with patch.dict(os.environ, {}, clear=True):
        endpoint, headers = _resolve_otlp_endpoint_and_headers()
        assert endpoint == ""
        assert headers == {}


@pytest.mark.local
@pytest.mark.unit
def test_otlp_error_filter():
    error_filter = _OTLPErrorFilter()

    # Test record with S3 error phrase
    record_s3 = logging.LogRecord(
        name="opentelemetry.exporter.otlp.proto.http.exporter",
        level=logging.ERROR,
        pathname=__file__,
        lineno=10,
        msg="Failed to upload JSON to S3: connection timeout",
        args=(),
        exc_info=None,
    )
    res = error_filter.filter(record_s3)
    assert res is True
    assert record_s3.levelno == logging.WARNING
    assert record_s3.levelname == "WARNING"

    # Test regular error record
    record_regular = logging.LogRecord(
        name="opentelemetry.exporter.otlp.proto.http.exporter",
        level=logging.ERROR,
        pathname=__file__,
        lineno=20,
        msg="Some unexpected database error",
        args=(),
        exc_info=None,
    )
    res = error_filter.filter(record_regular)
    assert res is True
    assert record_regular.levelno == logging.ERROR


@pytest.mark.local
@pytest.mark.unit
def test_install_otlp_error_filter():
    _install_otlp_error_filter()


@pytest.mark.local
@pytest.mark.unit
def test_setup_tracing_disabled():
    with patch("src.gateway.tracing_setup._TRACES_EXPORTER", "none"):
        setup_tracing()


@pytest.mark.local
@pytest.mark.unit
def test_setup_tracing_already_configured():
    mock_provider = MagicMock()
    mock_provider._active_span_processor = MagicMock()

    with patch("src.gateway.tracing_setup._TRACES_EXPORTER", "otlp"), \
         patch("opentelemetry.trace.get_tracer_provider", return_value=mock_provider), \
         patch("src.gateway.tracing_setup._OPENLLMETRY_ENABLED", False):
        setup_tracing()
