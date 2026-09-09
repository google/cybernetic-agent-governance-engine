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

"""Provider 02 Content-Addressed Evidence Resolution (CER Resolver).

This module provides the read path for Provider 02 content-addressed receipts,
resolving `sha256:<hex>` addresses to the full CER JSON structure via the
vendor's `/v1/resolve/cer/<hash>` endpoint.

The resolver:
- Accepts ContentAddress or string inputs, parsing before network calls
- Rejects COMMITMENT-kind addresses (hmac-sha256) at the boundary
- Implements ETag-based caching with no TTL (content is immutable)
- Unconditionally re-verifies digest integrity of returned payloads
- Returns structured CERResolution with fail-closed error semantics

Architecture precedent: follows the returning-convention pattern established
by Provider02AttestationProvider (not the raising-convention of Provider02Client).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from src.gateway.governance.content_address import ContentAddress, ContentAddressKind
from src.gateway.governance.seams.attestation import AttestationStatus

logger = logging.getLogger("cage.provider_02_resolver")

# URL path template - single source of truth for CER resolution endpoint construction
_CER_RESOLUTION_PATH_TEMPLATE = "/v1/resolve/cer/{hash}"


@dataclass(frozen=True)
class CERResolution:
    """Result of resolving a content-addressed receipt.

    Attributes:
        address: The content address that was resolved
        status: AttestationStatus value (UNVERIFIED, STALE, ERROR)
        resolved: True if the CER was successfully retrieved
        signature_checked: Set to True only by Phase 3 (signature verification)
        etag: HTTP ETag header value for cache revalidation
        from_cache: True if this result came from the in-process cache
        evidence: The raw CER payload body
        links: Extracted links (self, keyManifest, verify, humanVerifier)
        anchors: Transparency log anchors (captured verbatim, unvalidated)
        timestamps: RFC 3161 timestamps (captured verbatim, unvalidated)
        findings: Structured error/diagnostic findings
    """

    address: ContentAddress
    status: str  # AttestationStatus value
    resolved: bool
    signature_checked: bool = False  # Only Phase 3 may set this to True
    etag: str = ""
    from_cache: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    links: dict[str, str] = field(default_factory=dict)
    anchors: list[dict[str, Any]] = field(default_factory=list)
    timestamps: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _CacheEntry:
    """Internal cache entry for resolved CERs."""

    etag: str
    body: dict[str, Any]
    links: dict[str, str]
    anchors: list[dict[str, Any]]
    timestamps: list[dict[str, Any]]


class Provider02CERResolver:
    """Resolver for Provider 02 content-addressed receipts.

    Resolves sha256-addressed CERs via the vendor's public resolution endpoint,
    with ETag-based caching and unconditional digest integrity verification.

    Args:
        base_url: Base URL for the CER resolution API (PROVIDER_02_RESOLVER_URL)
        timeout: HTTP request timeout in seconds (PROVIDER_02_RESOLVER_TIMEOUT)
        verify: TLS verification - path to CA bundle or boolean (PROVIDER_02_CA_BUNDLE)
    """

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 5.0,
        verify: str | bool = True,
    ) -> None:
        """Initialize the CER resolver.

        Args:
            base_url: Base URL for the resolver endpoint
            timeout: Request timeout in seconds
            verify: TLS verification setting (CA bundle path or boolean)
        """
        self._base_url = base_url.rstrip("/") if base_url else ""
        self._timeout = timeout
        self._verify = verify
        self._cache: dict[str, _CacheEntry] = {}
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Lazily initialize the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                verify=self._verify,
                follow_redirects=True,
            )
        return self._client

    async def resolve(self, address: ContentAddress | str) -> CERResolution:
        """Resolve a content address to its CER payload.

        Accepts either a ContentAddress or a string. If a string is provided,
        it is parsed to ContentAddress before any network call, ensuring
        malformed input fails fast without hitting the network.

        COMMITMENT-kind addresses (hmac-sha256) are rejected immediately with
        zero network requests, as they are not dereferenceable public endpoints.

        Args:
            address: Content address to resolve (ContentAddress or string)

        Returns:
            CERResolution with structured status and findings
        """
        # Parse to ContentAddress immediately if string provided
        if isinstance(address, str):
            try:
                address = ContentAddress.parse(address)
            except Exception as e:
                logger.warning(f"Failed to parse content address: {e}")
                return CERResolution(
                    address=ContentAddress(
                        algorithm="sha256", hex_digest="", kind=ContentAddressKind.DIGEST
                    ),
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "CER_MALFORMED_REF",
                            "message": f"Malformed content address: {e}",
                            "retryable": False,
                        }
                    ],
                )

        # Reject COMMITMENT-kind addresses before any network call
        if address.kind == ContentAddressKind.COMMITMENT:
            logger.warning(
                f"Rejected COMMITMENT-kind address {address.canonical} - not dereferenceable"
            )
            return CERResolution(
                address=address,
                status=AttestationStatus.ERROR.value,
                resolved=False,
                findings=[
                    {
                        "code": "CER_MALFORMED_REF",
                        "message": "COMMITMENT-kind addresses are not dereferenceable",
                        "retryable": False,
                    }
                ],
            )

        # Check cache
        cached = self._cache.get(address.canonical)
        headers: dict[str, str] = {}
        if cached:
            headers["If-None-Match"] = cached.etag

        # Construct URL using url_encoded form (sha256%3A...)
        url = f"{self._base_url}{_CER_RESOLUTION_PATH_TEMPLATE.format(hash=address.url_encoded)}"

        try:
            client = await self._ensure_client()
            response = await client.get(url, headers=headers)

            # Handle 304 Not Modified - return from cache
            if response.status_code == 304 and cached:
                logger.debug(f"Cache hit for {address.canonical}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.UNVERIFIED.value,
                    resolved=True,
                    etag=cached.etag,
                    from_cache=True,
                    evidence=cached.body,
                    links=cached.links,
                    anchors=cached.anchors,
                    timestamps=cached.timestamps,
                )

            # Handle 404 - unresolvable (not "absent" or "invalid")
            if response.status_code == 404:
                logger.info(f"CER unresolvable for {address.canonical}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.STALE.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "CER_UNRESOLVABLE",
                            "message": "Content address is unresolvable (may be private or unknown)",
                            "retryable": False,
                        }
                    ],
                )

            # Handle 400 INVALID_HASH_FORMAT
            if response.status_code == 400:
                error_detail = response.text
                logger.warning(f"Invalid hash format for {address.canonical}: {error_detail}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "CER_MALFORMED_REF",
                            "message": f"Invalid hash format rejected by endpoint: {error_detail}",
                            "retryable": False,
                        }
                    ],
                )

            # Handle 5xx and other errors
            if response.status_code >= 500:
                logger.error(f"Server error resolving {address.canonical}: {response.status_code}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "ENDPOINT_ERROR",
                            "message": f"Server error: HTTP {response.status_code}",
                            "retryable": True,
                        }
                    ],
                )

            # Handle unexpected status codes
            if response.status_code != 200:
                logger.error(f"Unexpected status {response.status_code} for {address.canonical}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "ENDPOINT_ERROR",
                            "message": f"Unexpected HTTP status: {response.status_code}",
                            "retryable": True,
                        }
                    ],
                )

            # Parse JSON response
            try:
                body = response.json()
            except Exception as e:
                logger.error(f"Failed to parse JSON response for {address.canonical}: {e}")
                return CERResolution(
                    address=address,
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "CER_MALFORMED_REF",
                            "message": f"Malformed JSON response: {e}",
                            "retryable": False,
                        }
                    ],
                )

            # Unconditional digest re-verification
            # Hash the raw response bytes, not the re-serialized parse
            raw_bytes = response.content
            computed_digest = hashlib.sha256(raw_bytes).hexdigest()

            if computed_digest != address.hex_digest:
                logger.error(
                    f"Digest mismatch for {address.canonical}: "
                    f"expected {address.hex_digest}, got {computed_digest}"
                )
                return CERResolution(
                    address=address,
                    status=AttestationStatus.ERROR.value,
                    resolved=False,
                    findings=[
                        {
                            "code": "CER_DIGEST_MISMATCH",
                            "message": (
                                f"Content digest mismatch: expected {address.hex_digest}, "
                                f"computed {computed_digest}"
                            ),
                            "retryable": False,
                        }
                    ],
                )

            # Extract structured fields
            links = body.get("links", {})
            anchors = body.get("anchors", [])
            timestamps = body.get("timestamps", [])

            # Get ETag for caching
            etag = response.headers.get("ETag", "")

            # Update cache
            if etag:
                self._cache[address.canonical] = _CacheEntry(
                    etag=etag,
                    body=body,
                    links=links,
                    anchors=anchors,
                    timestamps=timestamps,
                )

            # Return UNVERIFIED status (signature not yet checked)
            return CERResolution(
                address=address,
                status=AttestationStatus.UNVERIFIED.value,
                resolved=True,
                etag=etag,
                evidence=body,
                links=links,
                anchors=anchors,
                timestamps=timestamps,
            )

        except httpx.TimeoutException as e:
            logger.error(f"Timeout resolving {address.canonical}: {e}")
            return CERResolution(
                address=address,
                status=AttestationStatus.ERROR.value,
                resolved=False,
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "message": f"Request timeout: {e}",
                        "retryable": True,
                    }
                ],
            )
        except httpx.TransportError as e:
            logger.error(f"Transport error resolving {address.canonical}: {e}")
            return CERResolution(
                address=address,
                status=AttestationStatus.ERROR.value,
                resolved=False,
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "message": f"Transport error: {e}",
                        "retryable": True,
                    }
                ],
            )
        except Exception as e:
            logger.error(f"Unexpected error resolving {address.canonical}: {e}")
            return CERResolution(
                address=address,
                status=AttestationStatus.ERROR.value,
                resolved=False,
                findings=[
                    {
                        "code": "ENDPOINT_ERROR",
                        "message": f"Unexpected error: {e}",
                        "retryable": True,
                    }
                ],
            )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
