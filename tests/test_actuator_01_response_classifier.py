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
Tests for actuator_01 response classifier.

Validates classification of HTTP status codes, 403 disambiguation (load-shed
vs replay vs terminal), 200 receipt extraction, network errors, and
fail-closed semantics for unrecognised status codes.
"""

from unittest.mock import MagicMock, PropertyMock

import pytest

from src.integrations.actuator_01.response_classifier import (
    ClassifiedResponse,
    ResponseCategory,
    classify_network_error,
    classify_response,
)

# Hermetic: tests HTTP response classification logic in-memory.
pytestmark = [pytest.mark.unit, pytest.mark.local]

# ── Helpers ───────────────────────────────────────────────────────────────


def _make_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("No JSON body")
    return resp


# ── Test: 200 OK ──────────────────────────────────────────────────────────


class TestClassify200:
    """200 OK with valid receipt → ACCEPTED; malformed → REJECTED_TERMINAL."""

    def test_valid_receipt(self):
        resp = _make_response(
            200,
            {
                "receipt_id": "rcpt-001",
                "session_uuid": "sess-001",
                "status": "ACCEPTED",
            },
        )
        result = classify_response(resp)
        assert result.category == ResponseCategory.ACCEPTED
        assert result.receipt_id == "rcpt-001"
        assert result.session_uuid == "sess-001"
        assert result.retryable is False
        assert result.findings == []

    def test_missing_receipt_id(self):
        resp = _make_response(200, {"status": "ACCEPTED"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.error_code == "MISSING_RECEIPT_ID"
        assert result.retryable is False

    def test_unparseable_body(self):
        resp = _make_response(200, None)
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.error_code == "UNPARSEABLE_RECEIPT"

    def test_receipt_with_extra_fields(self):
        resp = _make_response(
            200,
            {
                "receipt_id": "rcpt-002",
                "session_uuid": "sess-002",
                "extra_field": "ignored",
            },
        )
        result = classify_response(resp)
        assert result.category == ResponseCategory.ACCEPTED
        assert result.receipt_id == "rcpt-002"


# ── Test: 403 Disambiguation ─────────────────────────────────────────────


class TestClassify403:
    """403 Forbidden requires body inspection to distinguish sub-types."""

    def test_load_shed_is_retryable(self):
        resp = _make_response(
            403,
            {
                "error": "LOAD_SHED",
                "message": "Too many concurrent requests",
            },
        )
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_RETRYABLE
        assert result.retryable is True
        assert result.error_code == "LOAD_SHED"

    def test_capacity_limit_is_retryable(self):
        resp = _make_response(403, {"error": "CAPACITY_LIMIT"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_RETRYABLE
        assert result.retryable is True

    def test_replay_detected_is_terminal(self):
        resp = _make_response(
            403,
            {
                "error": "REPLAY_DETECTED",
                "message": "Nonce reuse",
            },
        )
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False
        assert result.error_code == "REPLAY_DETECTED"

    def test_quorum_failure_is_terminal(self):
        resp = _make_response(403, {"error": "QUORUM_FAILURE"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False

    def test_unknown_403_error_is_terminal(self):
        """Fail-closed: unknown 403 sub-types → terminal."""
        resp = _make_response(403, {"error": "SOMETHING_NEW"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False

    def test_403_no_body_is_terminal(self):
        """Fail-closed: 403 with no parseable body → terminal."""
        resp = _make_response(403, None)
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False

    def test_403_case_insensitive_error_code(self):
        resp = _make_response(403, {"error": "load_shed"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_RETRYABLE


# ── Test: Retryable Status Codes ─────────────────────────────────────────


class TestRetryableStatusCodes:
    """Status codes that should be retried with backoff."""

    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
    def test_retryable_status_codes(self, status):
        resp = _make_response(status, {"error": f"ERROR_{status}"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_RETRYABLE
        assert result.retryable is True

    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
    def test_retryable_with_no_body(self, status):
        resp = _make_response(status, None)
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_RETRYABLE
        assert result.retryable is True


# ── Test: Terminal Status Codes ───────────────────────────────────────────


class TestTerminalStatusCodes:
    """Status codes that should NOT be retried."""

    @pytest.mark.parametrize("status", [400, 401, 409, 421, 422])
    def test_terminal_status_codes(self, status):
        resp = _make_response(status, {"error": "VALIDATION_FAILED"})
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False


# ── Test: Unrecognised Status Codes ───────────────────────────────────────


class TestUnrecognisedStatusCodes:
    """Fail-closed: unrecognised status codes → terminal."""

    @pytest.mark.parametrize("status", [201, 204, 301, 418, 451, 599])
    def test_unrecognised_status_is_terminal(self, status):
        resp = _make_response(status, None)
        result = classify_response(resp)
        assert result.category == ResponseCategory.REJECTED_TERMINAL
        assert result.retryable is False


# ── Test: Network Errors ─────────────────────────────────────────────────


class TestNetworkErrors:
    """Transport-level failures are retryable and classified as NETWORK_ERROR."""

    def test_generic_network_error(self):
        exc = ConnectionError("Connection refused")
        result = classify_network_error(exc)
        assert result.category == ResponseCategory.NETWORK_ERROR
        assert result.retryable is True
        assert result.status_code == 0
        assert result.error_code == "NETWORK_ERROR"

    def test_rst_detection(self):
        exc = ConnectionError("Connection reset by peer")
        result = classify_network_error(exc)
        assert result.error_code == "CONNECTION_RESET"
        assert result.retryable is True

    def test_dns_error(self):
        exc = OSError("Name or service not known")
        result = classify_network_error(exc)
        assert result.category == ResponseCategory.NETWORK_ERROR
        assert result.retryable is True


# ── Test: ClassifiedResponse Defaults ─────────────────────────────────────


class TestClassifiedResponseDefaults:
    """Verify ClassifiedResponse field defaults."""

    def test_findings_defaults_to_empty_list(self):
        cr = ClassifiedResponse(category=ResponseCategory.ACCEPTED, status_code=200)
        assert cr.findings == []
        assert cr.retryable is False
        assert cr.receipt_id is None
