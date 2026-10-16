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
  - ALLOW → Return KMS-signed GovernanceEnvelope
  - DENY → Raise PolicyViolationException with structured diagnostics
  - DEFER → Raise DeferralPending with ticket details for HITL approval

Architecture:
    ┌──────────────┐         HTTP/2         ┌──────────────┐
    │ CageClient   │ ──────────────────────> │ CAGE Gateway │
    │ (PEP)        │ <────────────────────── │ (PDP)        │
    └──────────────┘        TLS/mTLS        └──────────────┘
         │
         ├─ ALLOW  → GovernanceEnvelope
         ├─ DENY   → PolicyViolationException
         └─ DEFER  → DeferralPending

Fail-Closed Semantics:
    - Network errors → Raise CageGatewayError (deny action)
    - 5xx server errors → Raise CageGatewayError (deny action)
    - Missing audit_id → Raise CageGatewayError (deny action)

Usage:
    from src.gateway.client.core import CageClient

    async with CageClient(
        gateway_url="https://cage-gateway.example.com",
        timeout_s=5.0
    ) as client:
        try:
            envelope = await client.validate_action(
                action="execute_action",
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
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any

import httpx

try:
    import h2  # noqa: F401

    _HTTP2_AVAILABLE = True
except ImportError:
    _HTTP2_AVAILABLE = False

from src.gateway.client.crypto import generate_w3c_traceparent
from src.gateway.client.envelope import GovernanceEnvelope
from src.gateway.client.exceptions import (
    CageGatewayError,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
)
from src.gateway.client.transport import create_mtls_transport
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

logger = logging.getLogger("CageClient")


class CageClient:
    """
    Out-of-process Policy Enforcement Point for CAGE governance.

    This client acts as a reusable HTTP/2 singleton that submits proposed
    actions to the CAGE Gateway for governance evaluation. It maintains a
    persistent connection pool to minimize latency overhead and supports
    optional mTLS authentication.

    Attributes:
        gateway_url: Base URL of the CAGE Gateway API (e.g., "https://cage.example.com")
        timeout_s: Request timeout in seconds (default: 5.0)
        _client: Internal httpx.AsyncClient instance (HTTP/2 enabled)
    """

    def __init__(
        self,
        gateway_url: str,
        mtls_certs: tuple[str, str, str] | None = None,
        timeout_s: float = 5.0,
        *,
        public_keys: dict[str, str | bytes] | None = None,
        verify_expiration: bool = False,
    ):
        """
        Initialize the CAGE Gateway client.

        Args:
            gateway_url: Base URL of the CAGE Gateway API (no trailing slash)
            mtls_certs: Optional tuple of (cert_path, key_path, ca_path) for mutual TLS
            timeout_s: Request timeout in seconds (default: 5.0)
            public_keys: Optional out-of-band map of kid -> PEM public key for
                cryptographic verification of returned GovernanceEnvelopes
            verify_expiration: If True (or when public_keys is provided), enforce
                wall-clock expiration check against envelope.expires_at

        Raises:
            FileNotFoundError: If mTLS certificate paths are invalid (fail-closed)
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout_s = timeout_s
        self._public_keys = dict(public_keys) if public_keys is not None else None
        self._verify_expiration = verify_expiration or (public_keys is not None)

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

        This method sends a POST request to the gateway's `/governance/validate-action`
        endpoint with the proposed action details. It handles the tri-state response:
          - 200 OK (ALLOW) → Return GovernanceEnvelope
          - 403/422 (DENY) → Parse diagnostics, raise PolicyViolationException
          - 202/409 (DEFER) → Parse ticket, raise DeferralPending

        Args:
            action: Action name (e.g., "execute_action", "access_pii")
            parameters: Action parameters dictionary (will be canonicalized)
            agent_id: Identifier of the agent requesting the action
            context: Optional additional context (session metadata, etc.)

        Returns:
            GovernanceEnvelope: Cryptographically signed governance decision

        Raises:
            PolicyViolationException: Action denied by governance policy
            DeferralPending: Action requires human-in-the-loop approval
            CageGatewayError: Network error, server error, or invalid response
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
            "params": parameters,
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

        endpoint = f"{self.gateway_url}/governance/validate-action"

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
            # ALLOW: Parse governance envelope
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

    def _verify_envelope_integrity(
        self,
        raw_envelope_data: dict[str, Any],
        envelope: GovernanceEnvelope,
    ) -> None:
        """Verify envelope expiration and cryptographic signature.

        Raises:
            RoutingSealVerificationError: If the envelope is expired, lacks a
                valid signature block, references an unknown kid, or fails
                cryptographic signature verification.
        """
        if envelope.expires_at <= envelope.issued_at:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope expires_at must be strictly after issued_at"
            )

        if self._verify_expiration and envelope.expires_at <= datetime.now(
            timezone.utc
        ):
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope has expired (expires_at={envelope.expires_at.isoformat()})"
            )

        sig = envelope.signature
        if not isinstance(sig, dict):
            raise RoutingSealVerificationError(
                "GovernanceEnvelope is missing required 'signature' block"
            )

        kid = sig.get("kid", "")
        alg = sig.get("algorithm", "")
        sig_val = sig.get("value", "")
        if not kid or not alg or not sig_val:
            raise RoutingSealVerificationError(
                "GovernanceEnvelope signature block is incomplete (requires algorithm, kid, value)"
            )

        if self._public_keys is None:
            return

        pem_raw = self._public_keys.get(kid)
        if pem_raw is None:
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope signed by unknown kid={kid!r}"
            )

        try:
            import base64

            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import (
                ec,
                ed25519,
                rsa,
                utils,
            )
            from cryptography.hazmat.primitives.asymmetric import (
                padding as rsa_padding,
            )

            pem_bytes = pem_raw.encode("utf-8") if isinstance(pem_raw, str) else pem_raw
            public_key = serialization.load_pem_public_key(pem_bytes)

            unsigned_dict = {
                k: v for k, v in raw_envelope_data.items() if k != "signature"
            }
            canonical_bytes = jcs_canonicalize_plan(unsigned_dict)
            digest = hashlib.sha256(canonical_bytes).digest()

            pad_len = (4 - len(sig_val) % 4) % 4
            signature_bytes = base64.urlsafe_b64decode(sig_val + ("=" * pad_len))

            if isinstance(public_key, ec.EllipticCurvePublicKey):
                key_size = (public_key.curve.key_size + 7) // 8
                if len(signature_bytes) == key_size * 2:
                    r = int.from_bytes(signature_bytes[:key_size], "big")
                    s = int.from_bytes(signature_bytes[key_size:], "big")
                    signature_bytes = utils.encode_dss_signature(r, s)
                public_key.verify(
                    signature_bytes,
                    digest,
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())),
                )
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature_bytes, canonical_bytes)
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_bytes,
                    digest,
                    rsa_padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
            else:
                raise ValueError(f"Unsupported public key type: {type(public_key)}")
        except RoutingSealVerificationError:
            raise
        except Exception as exc:
            raise RoutingSealVerificationError(
                f"GovernanceEnvelope signature verification failed: {exc}"
            ) from exc

    async def _handle_allow_response(
        self, response: httpx.Response
    ) -> GovernanceEnvelope:
        """
        Parse and verify a 200 OK response from the gateway.

        Supports both wrapped ``{"envelope": {...}}`` responses and top-level
        canonical envelopes returned by ``POST /governance/validate-action``.

        Args:
            response: httpx.Response object from the gateway

        Returns:
            GovernanceEnvelope: Validated governance decision envelope

        Raises:
            RoutingSealVerificationError: Signature or expiration check failed
            PolicyViolationException: Envelope carries a DENY/DENIED verdict, or
                a NARROW verdict (``reason_code="NARROWED"``; the clamped params
                are in ``violation_details["narrowed_params"]``)
            DeferralPending: Envelope carries a DEFER/REQUIRE_APPROVAL verdict
            CageGatewayError: Invalid response structure, missing envelope, or
                a missing or unrecognised verdict
        """
        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise CageGatewayError(f"Invalid JSON in ALLOW response: {e}") from e

        if not isinstance(response_data, dict):
            raise CageGatewayError("ALLOW response must be a JSON object")

        # Extract governance envelope from either wrapped or top-level wire format
        envelope_data = response_data.get("envelope")
        if not envelope_data:
            if (
                "envelope_version" in response_data
                and "payload" in response_data
                and "subject" in response_data
            ):
                envelope_data = response_data
            else:
                raise CageGatewayError(
                    "ALLOW response missing required 'envelope' field"
                )

        # Parse envelope into validated Pydantic model
        try:
            envelope = GovernanceEnvelope(**envelope_data)
        except Exception as e:
            raise CageGatewayError(f"Failed to parse governance envelope: {e}") from e

        # Verify envelope expiration and signature before trusting payload
        self._verify_envelope_integrity(envelope_data, envelope)

        # Inspect verdict inside payload (server may return HTTP 200 envelopes
        # for NARROW, REQUIRE_APPROVAL, DEFER, or DENIED verdicts)
        verdict = str(
            envelope.payload.get("verdict") or envelope.payload.get("decision") or ""
        ).upper()

        if verdict == "NARROW":
            # A NARROW verdict authorises only the gateway's clamped params,
            # never the params that were submitted.
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

        if verdict in ("DENY", "DENIED"):
            audit_id = (
                envelope.payload.get("audit_id")
                or envelope.subject.get("record_hash")
                or envelope.envelope_id
            )
            if not audit_id:
                raise CageGatewayError(
                    "DENY envelope missing required 'audit_id' or 'record_hash'"
                )
            reason_code = envelope.payload.get("reason_code", "POLICY_DENIED")
            details = envelope.payload.get(
                "details",
                {"violations": envelope.payload.get("violations", [])},
            )
            recoverable = bool(envelope.payload.get("recoverable", True))
            raise PolicyViolationException(
                reason_code=reason_code,
                violation_details=details,
                audit_id=str(audit_id),
                recoverable=recoverable,
            )

        if verdict in ("DEFER", "REQUIRE_APPROVAL"):
            ticket_id = (
                envelope.payload.get("defer_id")
                or envelope.payload.get("ticket_id")
                or envelope.envelope_id
            )
            if not ticket_id:
                raise CageGatewayError(
                    "DEFER envelope missing required 'ticket_id' or 'defer_id'"
                )
            defer_reason = str(
                envelope.payload.get("defer_reason")
                or envelope.payload.get("reason")
                or "Human approval required"
            )
            ttl_seconds = int(envelope.payload.get("ttl_seconds", 14400))
            raise DeferralPending(
                ticket_id=str(ticket_id),
                defer_reason=defer_reason,
                expires_at=envelope.expires_at,
                ttl_seconds=ttl_seconds,
            )

        if verdict != "ALLOW":
            # Fail closed: an absent or unrecognised verdict is never ALLOW.
            raise CageGatewayError(
                f"Gateway envelope carries unrecognised verdict {verdict or None!r}"
            )

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
