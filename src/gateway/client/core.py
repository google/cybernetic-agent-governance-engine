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
CAGE Gateway Client - Out-of-Process Policy Enforcement Point (PEP).

This module provides the `CageClient` HTTP client that communicates with the
CAGE Gateway Policy Decision Point (PDP) over TLS/mTLS (with optional HTTP/2).
It mediates governance HTTP responses and envelope verdicts into tri-state outcomes:
  - ALLOW → Return schema-validated GovernanceEnvelope (signature and expires_at unverified client-side)
  - DENY / NARROW → Raise PolicyViolationException with structured diagnostics
  - DEFER / REQUIRE_APPROVAL → Raise DeferralPending with ticket details for HITL approval

Security & Verification Scope:
    1. `CageClient` performs Pydantic schema validation and fail-closed HTTP
       status and payload verdict mediation (`200`/`403`/`422`/`202`/`409`/`5xx`)
       only — **it does NOT verify `GovernanceEnvelope.signature` against a
       gateway trust anchor and does NOT check `GovernanceEnvelope.expires_at`
       freshness client-side** (`signature` and `expires_at` are parsed as
       untrusted fields unless verified separately).
    2. **TLS/mTLS in `transport.py` protects only the point-to-point transport
       channel and does NOT substitute for end-to-end envelope signature
       verification** (the envelope carries a signature specifically so trust
       does not rest solely on transport or proxy configuration).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any

import httpx

from . import transport
from .crypto import generate_w3c_traceparent
from .envelope import GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
)

# Check for optional HTTP/2 support (h2 package)
_HTTP2_AVAILABLE = importlib.util.find_spec("h2") is not None

_BRACKETED_CODE_RE = re.compile(r"^\[([A-Za-z0-9_.:-]+)\]\s+")

logger = logging.getLogger("CageClient")


def _first_violation_code(violations: Any) -> str | None:
    """Return the first non-empty code from structured violation dicts or ``[CODE] msg`` strings."""
    if not isinstance(violations, list):
        return None
    for item in violations:
        if isinstance(item, dict):
            code = item.get("code")
            if isinstance(code, str) and code.strip():
                return code.strip()
        elif isinstance(item, str):
            match = _BRACKETED_CODE_RE.match(item.strip())
            if match:
                return match.group(1)
    return None


class CageClient:
    """
    Out-of-process Policy Enforcement Point for CAGE governance.

    Submits proposed actions to the CAGE Gateway for governance evaluation over
    a persistent connection pool with optional mTLS transport authentication.
    """

    def __init__(
        self,
        gateway_url: str,
        mtls_certs: tuple[str, str, str] | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        """
        Initialize the CAGE Gateway client.

        Args:
            gateway_url: Base URL of the CAGE Gateway API (no trailing slash)
            mtls_certs: Optional tuple of (cert_path, key_path, ca_path) for mutual TLS
            timeout_s: Request timeout in seconds (default: 5.0)

        Raises:
            ValueError: If half-configured mTLS cert/key paths are supplied
            FileNotFoundError: If mTLS certificate paths are invalid (fail-closed)
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout_s = timeout_s

        if mtls_certs:
            cert_path, key_path, ca_path = mtls_certs
            http_transport = transport.create_mtls_transport(
                cert_path=cert_path, key_path=key_path, ca_path=ca_path
            )
        else:
            http_transport = transport.create_mtls_transport()

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            http2=_HTTP2_AVAILABLE,
            follow_redirects=False,
            transport=http_transport,
        )

        logger.info(
            "CageClient initialized: gateway=%s, mtls_enabled=%s",
            self.gateway_url,
            mtls_certs is not None,
        )

    async def validate_action(
        self,
        action: str,
        parameters: dict[str, Any],
        agent_id: str,
        context: dict[str, Any] | None = None,
    ) -> GovernanceEnvelope:
        """
        Submit an action to the CAGE Gateway for HTTP PEP governance mediation.

        This method sends a POST request to `/governance/validate-action` and
        mediates the HTTP status and envelope verdict fail-closed:
          - 200 OK (`ALLOW`) → Parse and return schema-validated GovernanceEnvelope
          - 200 OK (`NARROW` / `DENY` / `DENIED`) or 403/422 → Raise PolicyViolationException
          - 200 OK (`DEFER` / `REQUIRE_APPROVAL`) or 202/409 → Raise DeferralPending

        Security & Verification Scope:
            1. `CageClient` currently performs Pydantic schema validation and
               fail-closed HTTP status and verdict mediation
               (`200`/`403`/`422`/`202`/`409`/`5xx`) only — **it does NOT verify
               `GovernanceEnvelope.signature` against a gateway trust anchor and
               does NOT check `GovernanceEnvelope.expires_at` freshness
               client-side** (`signature` and `expires_at` are parsed as
               untrusted fields unless verified separately).
            2. **TLS/mTLS in `transport.py` protects only the point-to-point
               transport channel and does NOT substitute for end-to-end envelope
               signature verification** (the envelope carries a signature
               specifically so trust does not rest solely on transport or proxy
               configuration).
        """
        canonical_params = self._canonicalize_params(parameters)
        param_hash = hashlib.sha256(canonical_params.encode("utf-8")).hexdigest()

        traceparent = generate_w3c_traceparent()
        correlation_id = secrets.token_hex(16)

        payload: dict[str, Any] = {
            "action": action,
            "params": parameters,
            "parameters": parameters,
            "parameter_hash": param_hash,
            "agent_id": agent_id,
            "context": context or {},
            "correlation_id": correlation_id,
        }

        headers = {
            "Content-Type": "application/json",
            "traceparent": traceparent,
            "X-Correlation-ID": correlation_id,
            "User-Agent": "CageClient/3.0",
        }

        endpoint = f"{self.gateway_url}/governance/validate-action"

        logger.debug(
            "Submitting action for validation: action=%s, agent_id=%s, correlation_id=%s",
            action,
            agent_id,
            correlation_id,
        )

        try:
            response = await self._client.post(endpoint, json=payload, headers=headers)
        except httpx.RequestError as exc:
            logger.error(
                "Network error communicating with gateway: %s", exc, exc_info=True
            )
            raise CageGatewayError(
                f"Failed to reach CAGE Gateway at {endpoint}: {exc}"
            ) from exc

        if response.status_code == 200:
            return await self._handle_allow_response(response)

        if response.status_code in (403, 422):
            self._handle_deny_response(response)
            raise AssertionError("_handle_deny_response must raise")

        if response.status_code in (202, 409):
            self._handle_defer_response(response)
            raise AssertionError("_handle_defer_response must raise")

        if response.status_code >= 500:
            logger.error(
                "Gateway server error: status=%s, body=%s",
                response.status_code,
                response.text[:500],
            )
            raise CageGatewayError(
                f"Gateway server error (status {response.status_code}): {response.text[:200]}"
            )

        logger.error(
            "Unexpected gateway response: status=%s, body=%s",
            response.status_code,
            response.text[:500],
        )
        raise CageGatewayError(
            f"Unexpected gateway response (status {response.status_code}): {response.text[:200]}"
        )

    @staticmethod
    def _extract_envelope_dict(response_data: Any) -> dict[str, Any]:
        """Extract canonical envelope dict from wrapped or top-level wire format."""
        if not isinstance(response_data, dict):
            raise CageGatewayError("ALLOW response must be a JSON object")
        envelope_data = response_data.get("envelope")
        if isinstance(envelope_data, dict) and envelope_data:
            return envelope_data
        if (
            not envelope_data
            and "envelope_version" in response_data
            and "payload" in response_data
            and "subject" in response_data
        ):
            return response_data
        raise CageGatewayError("ALLOW response missing required 'envelope' field")

    @staticmethod
    def _mediate_narrow_verdict(envelope: GovernanceEnvelope) -> None:
        narrowed_params = envelope.payload.get("narrowed_params")
        if not isinstance(narrowed_params, dict):
            raise CageGatewayError(
                "NARROW envelope missing required 'narrowed_params' object"
            )
        audit_id = (
            envelope.payload.get("audit_id")
            or envelope.subject.get("record_hash")
            or envelope.envelope_id
        )
        if not audit_id:
            raise CageGatewayError(
                "NARROW envelope missing required 'record_hash' or 'envelope_id'"
            )
        raise PolicyViolationException(
            reason_code="NARROWED",
            violation_details={
                "narrowed_params": narrowed_params,
                "violations": envelope.payload.get("violations") or [],
            },
            audit_id=str(audit_id),
            recoverable=True,
        )

    @staticmethod
    def _mediate_deny_verdict(envelope: GovernanceEnvelope) -> None:
        audit_id = (
            envelope.payload.get("audit_id")
            or envelope.subject.get("record_hash")
            or envelope.envelope_id
        )
        if not audit_id:
            raise CageGatewayError(
                "DENY envelope missing required 'audit_id' or 'record_hash'"
            )
        violations = envelope.payload.get("violations", [])
        reason_code = (
            envelope.payload.get("reason_code")
            or _first_violation_code(violations)
            or "POLICY_DENIED"
        )
        raw_details = envelope.payload.get("details")
        details = (
            raw_details if isinstance(raw_details, dict) else {"violations": violations}
        )
        recoverable = bool(envelope.payload.get("recoverable", True))
        raise PolicyViolationException(
            reason_code=str(reason_code),
            violation_details=details,
            audit_id=str(audit_id),
            recoverable=recoverable,
        )

    @staticmethod
    def _mediate_defer_verdict(envelope: GovernanceEnvelope) -> None:
        # Never fall back to envelope.envelope_id: when DeferQueue persistence
        # fails on REQUIRE_APPROVAL, the gateway sets deferred_id=None so the
        # client treats the unpersisted hold as a fail-closed error rather than
        # polling an unapprovable envelope UUID.
        ticket_id = (
            envelope.payload.get("deferred_id")
            or envelope.payload.get("defer_token")
            or envelope.payload.get("defer_id")
            or envelope.payload.get("ticket_id")
        )
        if not ticket_id:
            raise CageGatewayError(
                "DEFER envelope missing required 'deferred_id', 'defer_token', 'defer_id', or 'ticket_id'"
            )
        defer_reason = str(
            envelope.payload.get("defer_reason")
            or envelope.payload.get("classification_reason")
            or envelope.payload.get("reason")
            or "Human approval required"
        )
        ttl_seconds = int(
            envelope.payload.get("ttl_seconds")
            or envelope.payload.get("retry_after_seconds")
            or 14400
        )
        raise DeferralPending(
            ticket_id=str(ticket_id),
            defer_reason=defer_reason,
            expires_at=envelope.expires_at,
            ttl_seconds=ttl_seconds,
        )

    async def _handle_allow_response(
        self, response: httpx.Response
    ) -> GovernanceEnvelope:
        """
        Parse, schema-validate, and mediate an HTTP 200 response from the gateway.

        Supports both top-level canonical ``GovernanceEnvelope`` responses returned
        by ``POST /governance/validate-action`` and wrapped ``{"envelope": {...}}``
        payloads, mediating ``ALLOW``, ``NARROW``, ``DENY``/``DENIED``, and
        ``DEFER``/``REQUIRE_APPROVAL`` verdicts fail-closed.

        Security & Verification Scope:
            1. This method performs JSON parsing, Pydantic schema validation, and
               verdict dispatch only — **it does NOT verify
               `GovernanceEnvelope.signature` against a gateway trust anchor and
               does NOT check `GovernanceEnvelope.expires_at` freshness
               client-side** (`signature` and `expires_at` are parsed as
               untrusted fields unless verified separately).
            2. **TLS/mTLS in `transport.py` protects only the point-to-point
               transport channel and does NOT substitute for end-to-end envelope
               signature verification.**
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in ALLOW response: {exc}") from exc

        envelope_data = self._extract_envelope_dict(response_data)
        try:
            envelope = GovernanceEnvelope(**envelope_data)
        except Exception as exc:
            raise CageGatewayError(
                f"Failed to parse governance envelope: {exc}"
            ) from exc

        verdict = str(
            envelope.payload.get("verdict") or envelope.payload.get("decision") or ""
        ).upper()

        if verdict == "NARROW":
            self._mediate_narrow_verdict(envelope)
        if verdict in ("DENY", "DENIED"):
            self._mediate_deny_verdict(envelope)
        if verdict in ("DEFER", "REQUIRE_APPROVAL"):
            self._mediate_defer_verdict(envelope)
        if verdict != "ALLOW":
            raise CageGatewayError(
                f"Gateway envelope carries unrecognised verdict {verdict or None!r}"
            )

        logger.info(
            "Action ALLOWED: action=%s, agent_id=%s",
            envelope.subject.get("action"),
            envelope.subject.get("agent_id"),
        )
        return envelope

    def _handle_deny_response(self, response: httpx.Response) -> None:
        """
        Parse a 403/422 (DENY) response and raise PolicyViolationException.

        Supports both the canonical gateway v2.0.0 refusal wire format
        (``proof_hash``, ``violations``, ``refusal_receipt``) and legacy
        ``audit_id`` / ``reason_code`` / ``details`` payloads.
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in DENY response: {exc}") from exc

        if not isinstance(response_data, dict):
            raise CageGatewayError("DENY response must be a JSON object")

        raw_receipt = response_data.get("refusal_receipt")
        receipt_dict = raw_receipt if isinstance(raw_receipt, dict) else {}

        audit_id = (
            response_data.get("audit_id")
            or response_data.get("proof_hash")
            or receipt_dict.get("proof_hash")
        )
        if not audit_id:
            raise CageGatewayError(
                "DENY response missing required 'audit_id' field (or 'proof_hash')"
            )

        violations = response_data.get("violations", [])
        reason_code = (
            response_data.get("reason_code")
            or _first_violation_code(violations)
            or receipt_dict.get("violated_rule")
            or "UNKNOWN_VIOLATION"
        )

        if "details" in response_data and isinstance(response_data["details"], dict):
            violation_details = response_data["details"]
        else:
            violation_details = {"violations": violations}
            if "refusal_receipt" in response_data:
                violation_details["refusal_receipt"] = response_data["refusal_receipt"]

        recoverable = bool(response_data.get("recoverable", True))

        logger.warning(
            "Action DENIED: reason_code=%s, audit_id=%s, recoverable=%s",
            reason_code,
            audit_id,
            recoverable,
        )

        raise PolicyViolationException(
            reason_code=str(reason_code),
            violation_details=violation_details,
            audit_id=str(audit_id),
            recoverable=recoverable,
        )

    def _handle_defer_response(self, response: httpx.Response) -> None:
        """
        Parse a 202/409 (DEFER) response and raise DeferralPending.

        Supports both the canonical gateway v1.0.0 EXTERNAL_HOLD receipt format
        (``defer_id``, ``defer_reason``, ``poll_url``, ``ttl_seconds``) and
        legacy ``ticket_id`` / ``reason`` payloads.
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as exc:
            raise CageGatewayError(f"Invalid JSON in DEFER response: {exc}") from exc

        if not isinstance(response_data, dict):
            raise CageGatewayError("DEFER response must be a JSON object")

        ticket_id = (
            response_data.get("ticket_id")
            or response_data.get("defer_id")
            or response_data.get("deferred_id")
            or response_data.get("defer_token")
        )
        if not ticket_id:
            raise CageGatewayError(
                "DEFER response missing required 'ticket_id' field (or 'defer_id')"
            )

        defer_reason = str(
            response_data.get("defer_reason")
            or response_data.get("reason")
            or "Human approval required"
        )
        expires_at_str = response_data.get("expires_at")
        ttl_seconds = int(response_data.get("ttl_seconds", 14400))

        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    str(expires_at_str).replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise CageGatewayError(
                    f"Invalid expires_at timestamp: {expires_at_str}"
                ) from exc
        else:
            expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
                seconds=ttl_seconds
            )

        logger.info(
            "Action DEFERRED: ticket_id=%s, expires_at=%s",
            ticket_id,
            expires_at.isoformat(),
        )

        raise DeferralPending(
            ticket_id=str(ticket_id),
            defer_reason=defer_reason,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )

    @staticmethod
    def _canonicalize_params(params: dict[str, Any]) -> str:
        """Canonicalize parameters dictionary into deterministic sorted-key JSON."""
        return json.dumps(params, sort_keys=True, separators=(",", ":"))

    async def aclose(self) -> None:
        """Cleanly shut down the HTTP/2 client and release connection pool resources."""
        await self._client.aclose()
        logger.info("CageClient closed")

    async def __aenter__(self) -> CageClient:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Async context manager exit."""
        await self.aclose()
        return False
