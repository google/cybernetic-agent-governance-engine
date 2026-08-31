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
client.py — mTLS HTTP Client for Actuator 01 (Phase 2, Stream C)

Implements the transport layer with explicit TLS 1.3, session resumption
disabled, and proper timeout configuration per execution actuator protocol.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ActuatorHttpClient:
    """mTLS HTTPS client for actuator_01 with TLS 1.3 enforcement.

    Key properties:
    - Explicit TLS 1.3 only (no fallback to TLS 1.2)
    - Session resumption disabled (session=None)
    - Client certificate authentication
    - Timeouts well within 30s TTL window (connect=2s, read=5s, total=8s)
    - Content sent as raw bytes (never json=) to preserve signatures

    Args:
        base_url: Actuator endpoint base URL (https://...).
        cert_path: Path to client certificate PEM file.
        key_path: Path to client private key PEM file.
        ca_path: Path to CA bundle PEM file for server verification.
        tenant_id: Secure tenant identifier (X-Secure-Tenant-ID header).
    """

    def __init__(
        self,
        base_url: str,
        cert_path: str,
        key_path: str,
        ca_path: str,
        tenant_id: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id

        # Create SSL context with TLS 1.3 only
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path
        )
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        
        # Enforce TLS 1.3 only (no downgrade to TLS 1.2)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Disable session resumption via tickets (per wire contract requirements)
        ssl_context.options |= ssl.OP_NO_TICKET

        # Create httpx client with custom SSL context
        # Timeouts: connect=2s, read=5s, total=8s (well within 30s TTL window)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=ssl_context,
            cert=(cert_path, key_path),
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=8.0),
        )

        logger.info(
            "[actuator_01/client] Initialized mTLS client: base_url=%s tls_version=1.3",
            self.base_url,
        )

    async def submit_envelope(
        self,
        canonical_bytes: bytes,
        operator_urns: list[str],
        signatures: list[str],
        assertion: str,
        issued_at: int,
    ) -> httpx.Response:
        """Submit a canonical execution envelope with quorum signatures.

        The canonical_bytes are sent as-is in the request body (NOT re-serialized)
        to preserve cryptographic signatures.

        Headers constructed per wire contract:
        - X-Secure-Tenant-ID: tenant identifier (exactly one occurrence)
        - X-Operator-URNs: comma-separated operator URNs (positionally aligned)
        - X-Quorum-Signatures: comma-separated hex signatures (positionally aligned)
        - X-Execution-Assertion: base64-encoded 120-byte assertion
        - X-Timestamp: unix seconds (equals issued_at)
        - Content-Type: application/json

        Args:
            canonical_bytes: The exact canonical envelope bytes from JCS.
            operator_urns: List of operator URNs (≥2 distinct).
            signatures: List of hex signatures (positionally aligned with URNs).
            assertion: Base64-encoded 120-byte execution assertion.
            issued_at: Unix timestamp in seconds.

        Returns:
            httpx.Response object (caller classifies status code).

        Raises:
            httpx.HTTPError: Network/transport errors.
            RuntimeError: Invalid input (mismatched URN/signature counts, etc.).
        """
        if len(operator_urns) != len(signatures):
            raise RuntimeError(
                f"[actuator_01/client] URN/signature count mismatch: "
                f"{len(operator_urns)} URNs vs {len(signatures)} signatures"
            )

        if len(operator_urns) < 2:
            raise RuntimeError(
                f"[actuator_01/client] Insufficient quorum: {len(operator_urns)} URNs "
                "(minimum 2 required)"
            )

        # Build headers (positional alignment enforced by constructing from same lists)
        headers = {
            "Content-Type": "application/json",
            "X-Secure-Tenant-ID": self.tenant_id,
            "X-Operator-URNs": ",".join(operator_urns),
            "X-Quorum-Signatures": ",".join(signatures),
            "X-Execution-Assertion": assertion,
            "X-Timestamp": str(issued_at),
        }

        logger.info(
            "[actuator_01/client] Submitting envelope: operators=%d assertion_len=%d body_len=%d",
            len(operator_urns),
            len(assertion),
            len(canonical_bytes),
        )

        # Submit with content= (NOT json=) to preserve exact bytes
        response = await self._client.post(
            "/submit",
            content=canonical_bytes,
            headers=headers,
        )

        logger.info(
            "[actuator_01/client] Response received: status=%d",
            response.status_code,
        )

        return response

    async def health_check(self) -> bool:
        """Check actuator endpoint health (if available).

        Returns:
            True if endpoint is reachable and healthy, False otherwise.
        """
        try:
            response = await self._client.get("/health", timeout=5.0)
            return response.status_code == 200
        except Exception as exc:
            logger.warning("[actuator_01/client] Health check failed: %s", exc)
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> ActuatorHttpClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
