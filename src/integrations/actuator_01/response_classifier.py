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
response_classifier.py — HTTP Response Classification (Phase 3, Stream C / C.6b)

Classifies actuator HTTP responses into actionable categories for the adapter.
Distinguishes retryable transient errors from terminal failures, and extracts
structured receipt data from successful responses.

Classification follows fail-closed semantics: any unrecognised status code or
malformed response body is treated as a terminal rejection.

Wire Contract Response Categories
──────────────────────────────────
  200  OK                → Accepted (parse receipt)
  400  Bad Request       → Terminal: envelope validation failure
  401  Unauthorized      → Terminal: mTLS / tenant identity failure
  403  Forbidden         → Ambiguous: must inspect body for sub-type
       ├─ REPLAY_DETECTED   → Terminal: nonce/correlation reuse
       ├─ LOAD_SHED         → Retryable: partner is capacity-limiting
       └─ other/missing     → Terminal (fail-closed)
  408  Request Timeout   → Retryable: partner-side timeout
  409  Conflict          → Terminal: state conflict (stale clearance)
  421  Misdirected Req   → Terminal: malformed envelope
  422  Unprocessable     → Terminal: semantic validation failure
  429  Too Many Requests → Retryable: rate limited
  500  Internal Error    → Retryable: partner-side transient failure
  502  Bad Gateway       → Retryable: upstream failure
  503  Service Unavail   → Retryable: partner-side transient failure
  504  Gateway Timeout   → Retryable: upstream timeout
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


class ResponseCategory(str, Enum):
    """Classification of an actuator response."""

    ACCEPTED = "ACCEPTED"
    """200 OK with a valid receipt body and explicit acceptance status."""

    REJECTED_TERMINAL = "REJECTED_TERMINAL"
    """Definitive pre-execution non-retryable rejection — do not retry."""

    REJECTED_RETRYABLE = "REJECTED_RETRYABLE"
    """Definitive pre-execution transient rejection — safe to retry with backoff."""

    INDETERMINATE = "INDETERMINATE"
    """Ambiguous status or unconfirmed 200 receipt — side effect cannot be ruled out."""

    NETWORK_ERROR = "NETWORK_ERROR"
    """Transport-level failure (connection refused, RST, DNS, TLS)."""


@dataclass
class ClassifiedResponse:
    """Result of response classification.

    Attributes:
        category: The classification category.
        status_code: HTTP status code (0 for network errors).
        receipt_id: Partner-issued receipt ID (only if ACCEPTED).
        session_uuid: Partner-issued session UUID (only if ACCEPTED).
        raw_body: Parsed JSON body (if parseable), else None.
        error_code: Partner error code from response body (if present).
        error_message: Human-readable error message.
        retryable: True if the caller should retry with backoff.
        findings: Structured list of findings for ActuationReceipt.
    """

    category: ResponseCategory
    status_code: int
    receipt_id: str | None = None
    session_uuid: str | None = None
    raw_body: dict | None = None
    error_code: str | None = None
    error_message: str = ""
    retryable: bool = False
    findings: list[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []


# ── Status code sets ──────────────────────────────────────────────────────

# Only 400/401/403 prove pre-execution refusal without ambiguity. Statuses such
# as 408/409/421/422/429/500/502/503/504 can originate from proxies or duplicate
# state conflicts after a prior attempt executed and therefore settle UNKNOWN.
_TERMINAL_STATUS_CODES: frozenset[int] = frozenset({400, 401})
_AMBIGUOUS_HTTP_STATUS_CODES: frozenset[int] = frozenset(
    {408, 409, 421, 422, 429, 500, 502, 503, 504}
)

# 403 is disambiguated via response body (LOAD_SHED vs terminal admission refusal).
_AMBIGUOUS_STATUS_CODE = 403


def _parse_body(response: httpx.Response) -> dict | None:
    """Best-effort JSON body parse.  Returns None on any failure."""
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None


def _extract_error(body: dict | None) -> tuple[str | None, str]:
    """Extract error_code and message from a response body."""
    if not isinstance(body, dict):
        return None, ""
    error_code = body.get("error") or body.get("error_code")
    message = body.get("message") or body.get("error_message") or ""
    return error_code, message


def _extract_identifiers(body: dict | None) -> tuple[str | None, str | None]:
    """Extract receipt_id and session_uuid when present on any response body."""
    if not isinstance(body, dict):
        return None, None
    receipt_id = body.get("receipt_id")
    session_uuid = body.get("session_uuid")
    return (
        receipt_id if isinstance(receipt_id, str) and receipt_id else None,
        session_uuid if isinstance(session_uuid, str) and session_uuid else None,
    )


def _classify_403(body: dict | None) -> ClassifiedResponse:
    """Disambiguate 403 Forbidden responses.

    Per wire contract:
    - ``LOAD_SHED`` / ``CAPACITY_LIMIT`` → retryable
    - ``REPLAY_DETECTED`` → terminal (nonce/correlation reuse)
    - Anything else → terminal (fail-closed)
    """
    error_code, message = _extract_error(body)
    receipt_id, session_uuid = _extract_identifiers(body)
    error_code_upper = (error_code or "").upper()

    if error_code_upper in ("LOAD_SHED", "CAPACITY_LIMIT"):
        return ClassifiedResponse(
            category=ResponseCategory.REJECTED_RETRYABLE,
            status_code=403,
            receipt_id=receipt_id,
            session_uuid=session_uuid,
            raw_body=body,
            error_code=error_code,
            error_message=message or "Partner capacity-limited (load shed)",
            retryable=True,
            findings=[
                {
                    "code": error_code,
                    "severity": "TRANSIENT",
                    "detail": "Partner is load-shedding; retry with backoff",
                }
            ],
        )

    # REPLAY_DETECTED, QUORUM_FAILURE, or any unrecognised → terminal.
    return ClassifiedResponse(
        category=ResponseCategory.REJECTED_TERMINAL,
        status_code=403,
        receipt_id=receipt_id,
        session_uuid=session_uuid,
        raw_body=body,
        error_code=error_code,
        error_message=message or f"403 Forbidden: {error_code or 'unknown'}",
        retryable=False,
        findings=[
            {
                "code": error_code or "FORBIDDEN_UNSPECIFIED",
                "severity": "TERMINAL",
                "detail": message or "Request rejected by partner (fail-closed on 403)",
            }
        ],
    )


_ACCEPTED_RECEIPT_STATUSES: frozenset[str] = frozenset({"ACCEPTED", "OK", "EXECUTED"})
_REJECTED_RECEIPT_STATUSES: frozenset[str] = frozenset({"REJECTED", "DENIED"})


def _classify_200(body: dict | None) -> ClassifiedResponse:
    """Parse a 200 OK response and verify explicit acceptance status and receipt_id.

    Expected body shape (per wire contract):
    ```json
    {
        "receipt_id": "...",
        "session_uuid": "...",
        "status": "ACCEPTED",
        ...
    }
    ```

    Any 200 OK whose body is unparseable, lacks ``receipt_id``, or carries a
    missing/non-accepted ``status`` (other than explicit ``REJECTED`` /
    ``DENIED``) is classified as ``INDETERMINATE`` so downstream callers keep
    reservations held rather than treating an unconfirmed 200 as accepted or
    safely rejected (POAM-2026-232).
    """
    if body is None or not isinstance(body, dict):
        return ClassifiedResponse(
            category=ResponseCategory.INDETERMINATE,
            status_code=200,
            error_code="UNPARSEABLE_RECEIPT",
            error_message="200 OK but response body is not valid JSON",
            retryable=False,
            findings=[
                {
                    "code": "UNPARSEABLE_RECEIPT",
                    "severity": "TERMINAL",
                    "detail": "200 OK with unparseable body — outcome indeterminate",
                }
            ],
        )

    receipt_id = body.get("receipt_id")
    session_uuid = body.get("session_uuid")
    raw_status = body.get("status")
    status_str = raw_status.strip().upper() if isinstance(raw_status, str) else ""

    if status_str in _REJECTED_RECEIPT_STATUSES:
        error_code, message = _extract_error(body)
        return ClassifiedResponse(
            category=ResponseCategory.REJECTED_TERMINAL,
            status_code=200,
            receipt_id=receipt_id
            if isinstance(receipt_id, str) and receipt_id
            else None,
            session_uuid=session_uuid,
            raw_body=body,
            error_code=error_code or f"PARTNER_STATUS_{status_str}",
            error_message=message
            or f"200 OK with explicit refusal status={status_str!r}",
            retryable=False,
            findings=[
                {
                    "code": error_code or f"PARTNER_STATUS_{status_str}",
                    "severity": "TERMINAL",
                    "detail": message
                    or f"Explicit partner refusal status={status_str!r}",
                }
            ],
        )

    if status_str not in _ACCEPTED_RECEIPT_STATUSES:
        return ClassifiedResponse(
            category=ResponseCategory.INDETERMINATE,
            status_code=200,
            receipt_id=receipt_id
            if isinstance(receipt_id, str) and receipt_id
            else None,
            session_uuid=session_uuid,
            raw_body=body,
            error_code="AMBIGUOUS_RECEIPT_STATUS",
            error_message=f"200 OK with unconfirmed receipt status={raw_status!r}",
            retryable=False,
            findings=[
                {
                    "code": "AMBIGUOUS_RECEIPT_STATUS",
                    "severity": "TERMINAL",
                    "detail": f"200 OK without explicit ACCEPTED/OK/EXECUTED status (got {raw_status!r}) — outcome indeterminate",
                }
            ],
        )

    if not isinstance(receipt_id, str) or not receipt_id.strip():
        return ClassifiedResponse(
            category=ResponseCategory.INDETERMINATE,
            status_code=200,
            session_uuid=session_uuid,
            raw_body=body,
            error_code="MISSING_RECEIPT_ID",
            error_message="200 OK but response body missing receipt_id",
            retryable=False,
            findings=[
                {
                    "code": "MISSING_RECEIPT_ID",
                    "severity": "TERMINAL",
                    "detail": "200 OK with no receipt_id — outcome indeterminate",
                }
            ],
        )

    return ClassifiedResponse(
        category=ResponseCategory.ACCEPTED,
        status_code=200,
        receipt_id=receipt_id,
        session_uuid=session_uuid,
        raw_body=body,
        error_message="",
        retryable=False,
    )


def classify_response(response: httpx.Response) -> ClassifiedResponse:
    """Classify an actuator HTTP response.

    This is the single entry point used by ``Actuator01Adapter.actuate()``.
    Follows fail-closed semantics: only explicit pre-execution refusals
    (``400``, ``401``, ``403``) reject; ambiguous or unrecognised statuses and
    unconfirmed ``200`` responses classify as ``INDETERMINATE``.

    Args:
        response: The ``httpx.Response`` from ``ActuatorHttpClient.submit_envelope``.

    Returns:
        ``ClassifiedResponse`` with category, receipt data (if accepted),
        error details, and retryability flag.
    """
    status = response.status_code
    body = _parse_body(response)
    error_code, message = _extract_error(body)
    receipt_id, session_uuid = _extract_identifiers(body)

    # ── 200 OK ────────────────────────────────────────────────────────────
    if status == 200:
        result = _classify_200(body)
        logger.info(
            "[actuator_01/response] 200 OK → %s receipt_id=%s",
            result.category.value,
            result.receipt_id,
        )
        return result

    # ── Ambiguous 403 ─────────────────────────────────────────────────────
    if status == _AMBIGUOUS_STATUS_CODE:
        result = _classify_403(body)
        logger.warning(
            "[actuator_01/response] 403 → %s error_code=%s",
            result.category.value,
            result.error_code,
        )
        return result

    # ── Definitive pre-execution terminal status codes (400, 401) ─────────
    if status in _TERMINAL_STATUS_CODES:
        result = ClassifiedResponse(
            category=ResponseCategory.REJECTED_TERMINAL,
            status_code=status,
            receipt_id=receipt_id,
            session_uuid=session_uuid,
            raw_body=body,
            error_code=error_code,
            error_message=message or f"Terminal HTTP {status}",
            retryable=False,
            findings=[
                {
                    "code": error_code or f"HTTP_{status}",
                    "severity": "TERMINAL",
                    "detail": message
                    or f"HTTP {status} — definitive pre-execution refusal",
                }
            ],
        )
        logger.warning(
            "[actuator_01/response] HTTP %d → TERMINAL error_code=%s",
            status,
            error_code,
        )
        return result

    # ── Ambiguous or unrecognised status codes → INDETERMINATE ────────────
    indeterminate_code = error_code or (
        f"HTTP_{status}"
        if status in _AMBIGUOUS_HTTP_STATUS_CODES
        else f"UNRECOGNISED_{status}"
    )
    result = ClassifiedResponse(
        category=ResponseCategory.INDETERMINATE,
        status_code=status,
        receipt_id=receipt_id,
        session_uuid=session_uuid,
        raw_body=body,
        error_code=indeterminate_code,
        error_message=message or f"Indeterminate HTTP {status} — outcome unknown",
        retryable=False,
        findings=[
            {
                "code": indeterminate_code,
                "severity": "TERMINAL",
                "detail": message or f"HTTP {status} — side effect cannot be ruled out",
            }
        ],
    )
    logger.warning(
        "[actuator_01/response] HTTP %d → INDETERMINATE error_code=%s",
        status,
        indeterminate_code,
    )
    return result


def classify_network_error(exc: Exception) -> ClassifiedResponse:
    """Classify a transport-level exception as a network error.

    Called when ``submit_envelope`` raises ``httpx.HTTPError`` or any
    transport exception (connection refused, RST, DNS, TLS handshake).

    Network errors are retryable (the partner may come back) but are
    classified distinctly from HTTP-level retryable errors for observability.

    Args:
        exc: The transport exception.

    Returns:
        ``ClassifiedResponse`` with ``NETWORK_ERROR`` category.
    """
    # Detect TCP RST specifically for observability.
    exc_str = str(exc)
    is_rst = "reset" in exc_str.lower() or "rst" in exc_str.lower()
    error_code = "CONNECTION_RESET" if is_rst else "NETWORK_ERROR"

    result = ClassifiedResponse(
        category=ResponseCategory.NETWORK_ERROR,
        status_code=0,
        error_code=error_code,
        error_message=f"Transport error: {exc_str}",
        retryable=True,
        findings=[
            {
                "code": error_code,
                "severity": "TRANSIENT",
                "detail": f"Transport-level failure: {exc_str}",
            }
        ],
    )
    logger.error(
        "[actuator_01/response] Network error → %s: %s",
        error_code,
        exc_str,
    )
    return result
