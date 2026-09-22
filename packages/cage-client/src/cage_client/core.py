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

This module provides the `CageClient` singleton that communicates with the
CAGE Gateway Policy Decision Point (PDP) over HTTP/2. It maps governance
responses into tri-state actions:
  - ALLOW → Return GovernanceEnvelope with verified routing seal
  - DENY → Raise PolicyViolationException with structured diagnostics
  - DEFER → Raise DeferralPending with ticket details for HITL approval

Architecture:
    ┌──────────────┐         HTTP/2         ┌──────────────┐
    │ CageClient   │ ──────────────────────> │ CAGE Gateway │
    │ (PEP)        │ <────────────────────── │ (PDP)        │
    └──────────────┘    TLS/mTLS + Seal     └──────────────┘
         │
         ├─ ALLOW  → GovernanceEnvelope
         ├─ DENY   → PolicyViolationException
         └─ DEFER  → DeferralPending

Fail-Closed Semantics:
    - Network errors → Raise CageGatewayError (deny action)
    - 5xx server errors → Raise CageGatewayError (deny action)
    - Invalid seal → Raise RoutingSealVerificationError (deny action)
    - Missing audit_id → Raise CageGatewayError (deny action)

Usage:
    from src.gateway.client.core import CageClient

    async with CageClient(
        gateway_url="https://cage-gateway.example.com",
        routing_seal_secret="shared-secret",
        timeout_s=5.0
    ) as client:
        try:
            envelope = await client.validate_action(
                action="execute_trade",
                parameters={"symbol": "AAPL", "amount": 1000},
                agent_id="advisor-prod-v3",
                context={"session_id": "abc123"}
            )
            # Action allowed, envelope contains execution grant
            print(f"Action allowed: {envelope.payload}")

        except PolicyViolationException as e:
            # Action denied by governance policy
            print(f"Denied: {e.reason_code} - {e.violation_details}")
            if e.recoverable:
                # Attempt reformulation
                pass
            else:
                # Fundamental prohibition, abort
                raise

        except DeferralPending as e:
            # Action requires human approval
            print(f"Deferred: {e.ticket_id}, expires at {e.expires_at}")
            # Park checkpoint, wait for HITL resolution
            pass
"""

import hashlib
import importlib.util
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any

import httpx

# Check for optional HTTP/2 support (h2 package)
_HTTP2_AVAILABLE = importlib.util.find_spec("h2") is not None

from .crypto import (
    RoutingSealVerificationError,
    generate_w3c_traceparent,
    verify_routing_seal,
)
from .envelope import GovernanceEnvelope
from .exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
)
from .transport import create_mtls_transport

logger = logging.getLogger("CageClient")


class CageClient:
    """
    Out-of-process Policy Enforcement Point for CAGE governance.

    This client acts as a reusable HTTP/2 singleton that submits proposed
    actions to the CAGE Gateway for governance evaluation. It maintains a
    persistent connection pool to minimize latency overhead and supports
    optional mTLS authentication and routing seal verification.

    Attributes:
        gateway_url: Base URL of the CAGE Gateway API (e.g., "https://cage.example.com")
        routing_seal_secret: Optional shared secret for HMAC seal verification
        timeout_s: Request timeout in seconds (default: 5.0)
        _client: Internal httpx.AsyncClient instance (HTTP/2 enabled)
    """

    def __init__(
        self,
        gateway_url: str,
        routing_seal_secret: str | None = None,
        mtls_certs: tuple[str, str, str] | None = None,
        timeout_s: float = 5.0,
    ):
        """
        Initialize the CAGE Gateway client.

        Args:
            gateway_url: Base URL of the CAGE Gateway API (no trailing slash)
            routing_seal_secret: Optional shared secret for X-CAGE-Routing-Seal verification
            mtls_certs: Optional tuple of (cert_path, key_path, ca_path) for mutual TLS
            timeout_s: Request timeout in seconds (default: 5.0)

        Raises:
            FileNotFoundError: If mTLS certificate paths are invalid (fail-closed)
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.routing_seal_secret = routing_seal_secret
        self.timeout_s = timeout_s

        # Configure HTTP/2 transport with optional mTLS
        transport_kwargs: dict[str, Any] = {}
        if mtls_certs:
            cert_path, key_path, ca_path = mtls_certs
            transport = create_mtls_transport(
                cert_path=cert_path, key_path=key_path, ca_path=ca_path
            )
            transport_kwargs["transport"] = transport
        else:
            # Standard HTTP/2 transport with system CA bundle
            transport_kwargs["transport"] = create_mtls_transport()

        # Create reusable HTTP/2 client (singleton pattern)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            http2=_HTTP2_AVAILABLE,
            follow_redirects=False,
            **transport_kwargs,
        )

        logger.info(
            f"CageClient initialized: gateway={self.gateway_url}, "
            f"seal_enabled={routing_seal_secret is not None}, "
            f"mtls_enabled={mtls_certs is not None}"
        )

    async def validate_action(
        self,
        action: str,
        parameters: dict[str, Any],
        agent_id: str,
        context: dict[str, Any] | None = None,
    ) -> GovernanceEnvelope:
        """
        Submit an action to the CAGE Gateway for governance validation.

        This method sends a POST request to the gateway's `/v1/governance/validate`
        endpoint with the proposed action details. It handles the tri-state response:
          - 200 OK (ALLOW) → Verify seal, return GovernanceEnvelope
          - 403/422 (DENY) → Parse diagnostics, raise PolicyViolationException
          - 202/409 (DEFER) → Parse ticket, raise DeferralPending

        Args:
            action: Action name (e.g., "execute_trade", "access_pii")
            parameters: Action parameters dictionary (will be canonicalized)
            agent_id: Identifier of the agent requesting the action
            context: Optional additional context (session metadata, etc.)

        Returns:
            GovernanceEnvelope: Cryptographically signed governance decision

        Raises:
            PolicyViolationException: Action denied by governance policy
            DeferralPending: Action requires human-in-the-loop approval
            CageGatewayError: Network error, server error, or invalid response
            RoutingSealVerificationError: Routing seal verification failed
        """
        # Canonicalize parameters using sorted JSON (deterministic hash)
        canonical_params = self._canonicalize_params(parameters)
        param_hash = hashlib.sha256(canonical_params.encode("utf-8")).hexdigest()

        # Generate W3C traceparent for distributed tracing
        traceparent = generate_w3c_traceparent()
        correlation_id = secrets.token_hex(16)

        # Build request payload
        payload: dict[str, Any] = {
            "action": action,
            "parameters": parameters,
            "parameter_hash": param_hash,
            "agent_id": agent_id,
            "context": context or {},
            "correlation_id": correlation_id,
        }

        # Attach tracing headers
        headers = {
            "Content-Type": "application/json",
            "traceparent": traceparent,
            "X-Correlation-ID": correlation_id,
            "User-Agent": "CageClient/3.0",
        }

        endpoint = f"{self.gateway_url}/v1/governance/validate"

        logger.debug(
            f"Submitting action for validation: action={action}, "
            f"agent_id={agent_id}, correlation_id={correlation_id}"
        )

        try:
            response = await self._client.post(endpoint, json=payload, headers=headers)
        except httpx.RequestError as e:
            # Network failure, timeout, connection refused (fail-closed)
            logger.error(
                f"Network error communicating with gateway: {e}", exc_info=True
            )
            raise CageGatewayError(
                f"Failed to reach CAGE Gateway at {endpoint}: {e}"
            ) from e

        # Handle tri-state response
        if response.status_code == 200:
            # ALLOW: Parse envelope and verify routing seal
            return await self._handle_allow_response(response)

        if response.status_code in (403, 422):
            # DENY: Parse structured diagnostics and raise exception
            self._handle_deny_response(response)
            # This line is unreachable but satisfies type checker
            raise AssertionError("_handle_deny_response must raise")

        if response.status_code in (202, 409):
            # DEFER: Parse ticket details and raise exception
            self._handle_defer_response(response)
            # This line is unreachable but satisfies type checker
            raise AssertionError("_handle_defer_response must raise")

        if response.status_code >= 500:
            # Server error (fail-closed)
            logger.error(
                f"Gateway server error: status={response.status_code}, "
                f"body={response.text[:500]}"
            )
            raise CageGatewayError(
                f"Gateway server error (status {response.status_code}): {response.text[:200]}"
            )

        # Unexpected status code (fail-closed)
        logger.error(
            f"Unexpected gateway response: status={response.status_code}, "
            f"body={response.text[:500]}"
        )
        raise CageGatewayError(
            f"Unexpected gateway response (status {response.status_code}): {response.text[:200]}"
        )

    async def _handle_allow_response(
        self, response: httpx.Response
    ) -> GovernanceEnvelope:
        """
        Parse and verify a 200 OK (ALLOW) response from the gateway.

        Args:
            response: httpx.Response object from the gateway

        Returns:
            GovernanceEnvelope: Validated governance decision envelope

        Raises:
            CageGatewayError: Invalid response structure or missing envelope
            RoutingSealVerificationError: Routing seal verification failed
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise CageGatewayError(f"Invalid JSON in ALLOW response: {e}") from e

        # Extract governance envelope from response
        envelope_data = response_data.get("envelope")
        if not envelope_data:
            raise CageGatewayError("ALLOW response missing required 'envelope' field")

        # Verify routing seal if secret is configured
        if self.routing_seal_secret:
            seal_header = response.headers.get("X-CAGE-Routing-Seal")
            if not seal_header:
                raise RoutingSealVerificationError(
                    "ALLOW response missing required X-CAGE-Routing-Seal header"
                )

            # Verify seal against response body
            body_bytes = response.content
            try:
                verify_routing_seal(
                    seal_header=seal_header,
                    body_bytes=body_bytes,
                    secret=self.routing_seal_secret,
                    ttl_seconds=30,
                )
                logger.debug("Routing seal verification successful")
            except RoutingSealVerificationError as e:
                logger.error(f"Routing seal verification failed: {e}")
                raise

        # Parse envelope into validated Pydantic model
        try:
            envelope = GovernanceEnvelope(**envelope_data)
        except Exception as e:
            raise CageGatewayError(f"Failed to parse governance envelope: {e}") from e

        logger.info(
            f"Action ALLOWED: action={envelope.subject.get('action')}, "
            f"agent_id={envelope.subject.get('agent_id')}"
        )

        return envelope

    def _handle_deny_response(self, response: httpx.Response) -> None:
        """
        Parse a 403/422 (DENY) response and raise PolicyViolationException.

        Args:
            response: httpx.Response object from the gateway

        Raises:
            PolicyViolationException: Always raised with structured diagnostics
            CageGatewayError: If response cannot be parsed
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise CageGatewayError(f"Invalid JSON in DENY response: {e}") from e

        # Extract structured violation details
        reason_code = response_data.get("reason_code", "UNKNOWN_VIOLATION")
        violation_details = response_data.get("details", {})
        audit_id = response_data.get("audit_id")
        recoverable = response_data.get("recoverable", True)

        if not audit_id:
            raise CageGatewayError("DENY response missing required 'audit_id' field")

        logger.warning(
            f"Action DENIED: reason_code={reason_code}, audit_id={audit_id}, "
            f"recoverable={recoverable}"
        )

        raise PolicyViolationException(
            reason_code=reason_code,
            violation_details=violation_details,
            audit_id=audit_id,
            recoverable=recoverable,
        )

    def _handle_defer_response(self, response: httpx.Response) -> None:
        """
        Parse a 202/409 (DEFER) response and raise DeferralPending.

        Args:
            response: httpx.Response object from the gateway

        Raises:
            DeferralPending: Always raised with ticket details
            CageGatewayError: If response cannot be parsed
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise CageGatewayError(f"Invalid JSON in DEFER response: {e}") from e

        # Extract deferral ticket details
        ticket_id = response_data.get("ticket_id")
        defer_reason = response_data.get("reason", "Human approval required")
        expires_at_str = response_data.get("expires_at")
        ttl_seconds = response_data.get("ttl_seconds", 14400)

        if not ticket_id:
            raise CageGatewayError("DEFER response missing required 'ticket_id' field")

        # Parse expiration timestamp
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    expires_at_str.replace("Z", "+00:00")
                )
            except ValueError as e:
                raise CageGatewayError(
                    f"Invalid expires_at timestamp: {expires_at_str}"
                ) from e
        else:
            # Fallback: calculate expiration from TTL
            expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
                seconds=ttl_seconds
            )

        logger.info(
            f"Action DEFERRED: ticket_id={ticket_id}, "
            f"expires_at={expires_at.isoformat()}"
        )

        raise DeferralPending(
            ticket_id=ticket_id,
            defer_reason=defer_reason,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
        )

    @staticmethod
    def _canonicalize_params(params: dict[str, Any]) -> str:
        """
        Canonicalize parameters dictionary into deterministic JSON string.

        Uses sorted keys (not full JCS RFC 8785) for lightweight canonicalization
        suitable for hash computation. Gateway will perform full JCS if needed.

        Args:
            params: Parameters dictionary to canonicalize

        Returns:
            JSON string with sorted keys, no whitespace
        """
        return json.dumps(params, sort_keys=True, separators=(",", ":"))

    async def aclose(self) -> None:
        """
        Cleanly shut down the HTTP/2 client and release resources.

        This method should be called when the client is no longer needed to
        ensure proper cleanup of connection pools and background tasks.

        Usage:
            client = CageClient(gateway_url="...")
            try:
                await client.validate_action(...)
            finally:
                await client.aclose()

        Or use as async context manager:
            async with CageClient(gateway_url="...") as client:
                await client.validate_action(...)
        """
        await self._client.aclose()
        logger.info("CageClient closed")

    async def __aenter__(self) -> "CageClient":
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
