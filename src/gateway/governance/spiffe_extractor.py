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
SPIFFE Identity Extraction from TLS Certificates.

This module provides utilities to extract and validate SPIFFE Verifiable Identity
Documents (SVIDs) from client TLS certificates presented during mTLS handshakes.

Security Invariants:
    - Fail-closed: Requests without verified SPIFFE URIs are rejected (401/403).
    - SAN URI extraction: Only URI SANs matching ^spiffe://.+ are accepted.
    - No fallback: Missing or invalid certificates result in immediate rejection.

Compliance Citations:
    - SC-8 (Transmission Confidentiality): mTLS-based identity assertion.
    - AC-3 (Access Enforcement): SPIFFE ID used for OPA principal lookup.
    - IA-3 (Device Identification): Certificate-based agent authentication.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger("Gateway.SpiffeExtractor")

# SPIFFE URI pattern: spiffe://trust-domain/path
_SPIFFE_URI_PATTERN = re.compile(r"^spiffe://[a-zA-Z0-9._-]+(/[a-zA-Z0-9._/-]*)?$")


class SpiffeExtractionError(Exception):
    """Raised when SPIFFE identity extraction fails."""

    pass


def extract_spiffe_uri_from_asgi_scope(scope: Mapping[str, Any]) -> str:
    """Extract SPIFFE URI from ASGI connection scope (FastAPI/Uvicorn).

    Args:
        scope: ASGI connection scope dictionary containing TLS state.

    Returns:
        The verified SPIFFE URI string (e.g., "spiffe://cluster.local/ns/default/sa/advisor").

    Raises:
        SpiffeExtractionError: If no valid SPIFFE URI is found or certificate is missing.

    Example:
        >>> scope = {"client_cert": {"san": {"uri": ["spiffe://example.org/agent"]}}}
        >>> extract_spiffe_uri_from_asgi_scope(scope)
        'spiffe://example.org/agent'
    """
    # Extract client certificate from ASGI scope
    # FastAPI/Uvicorn exposes peer certificates via scope["client_cert"]
    # when TLS is configured with verify_mode=ssl.CERT_REQUIRED
    client_cert = scope.get("client_cert")

    if not client_cert:
        raise SpiffeExtractionError(
            "No client certificate found in ASGI scope — mTLS handshake required"
        )

    # Extract SAN (Subject Alternative Name) URIs
    # The structure depends on the SSL library, but typically:
    # client_cert = {"san": {"uri": ["spiffe://..."]}}
    # or decoded from DER/PEM via cryptography.x509
    san_data = client_cert.get("san") or client_cert.get("subjectAltName")

    if not san_data:
        raise SpiffeExtractionError(
            "Client certificate contains no Subject Alternative Names (SAN)"
        )

    # Extract URI-type SANs
    uri_sans: list[str] = []

    # Handle dict structure: {"uri": [...]}
    if isinstance(san_data, dict):
        uri_sans = san_data.get("uri", [])
    # Handle tuple structure from cryptography.x509: [("URI", "spiffe://...")]
    elif isinstance(san_data, (list, tuple)):
        uri_sans = [
            value
            for san_type, value in san_data
            if san_type.upper() in ("URI", "UNIFORMRESOURCEIDENTIFIER")
        ]

    if not uri_sans:
        raise SpiffeExtractionError("Client certificate SAN contains no URI entries")

    # Find the first SPIFFE URI
    for uri in uri_sans:
        if _SPIFFE_URI_PATTERN.match(uri):
            logger.debug("✅ Extracted SPIFFE URI: %s", uri)
            return uri

    raise SpiffeExtractionError(
        f"No valid SPIFFE URI found in certificate SANs: {uri_sans}"
    )


def extract_spiffe_uri_from_grpc_context(context: Any) -> str:
    """Extract SPIFFE URI from gRPC peer context (Envoy ext_authz).

    Args:
        context: gRPC service context containing peer authentication metadata.

    Returns:
        The verified SPIFFE URI string.

    Raises:
        SpiffeExtractionError: If no valid SPIFFE URI is found.

    Note:
        This function is used by agent_gateway_adapter.py when deployed behind
        Envoy/Istio. The SPIFFE ID is extracted from the `source.principal`
        attribute set by the service mesh.
    """
    # For Envoy ext_authz, the SPIFFE ID is typically in request.attributes.source.principal
    # The mesh already validated the certificate and extracted the SPIFFE ID
    principal = getattr(context, "principal", None) or getattr(
        getattr(context, "attributes", None), "source", {}
    ).get("principal", "")

    if not principal:
        raise SpiffeExtractionError(
            "No principal found in gRPC context — mTLS handshake required"
        )

    if _SPIFFE_URI_PATTERN.match(principal):
        logger.debug("✅ Extracted SPIFFE URI from gRPC context: %s", principal)
        return principal

    raise SpiffeExtractionError(f"Principal '{principal}' is not a valid SPIFFE URI")


def validate_spiffe_uri(uri: str) -> None:
    """Validate that a string is a well-formed SPIFFE URI.

    Args:
        uri: The SPIFFE URI string to validate.

    Raises:
        SpiffeExtractionError: If the URI is malformed.

    Example:
        >>> validate_spiffe_uri("spiffe://cluster.local/ns/default/sa/advisor")
        >>> validate_spiffe_uri("http://not-a-spiffe-uri")  # raises
    """
    if not _SPIFFE_URI_PATTERN.match(uri):
        raise SpiffeExtractionError(
            f"Invalid SPIFFE URI format: '{uri}' (expected spiffe://trust-domain/path)"
        )
