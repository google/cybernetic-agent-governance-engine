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

"""Cryptographic seal verification and W3C traceparent generation.

Zero vendor SDKs. Fail-closed security posture.
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional

from .exceptions import RoutingSealVerificationError


def verify_routing_seal(
    seal_header: str, body_bytes: bytes, secret: str, ttl_seconds: int = 30
) -> bool:
    """Verify HMAC-SHA256 routing seal with micro-TTL enforcement.

    Args:
        seal_header: X-CAGE-Routing-Seal header value in format "timestamp.signature"
        body_bytes: Raw response body bytes to verify
        secret: Shared secret for HMAC verification
        ttl_seconds: Maximum age of seal in seconds (default 30s)

    Returns:
        True if seal is valid and within TTL window

    Raises:
        RoutingSealVerificationError: On tampering, expiration, or malformed seal
    """
    if not seal_header or not secret:
        raise RoutingSealVerificationError("Seal header and secret are required")

    # Parse seal format: "timestamp.signature"
    # Use rsplit(".", 1) to support both float (e.g. 1712345.678.sig) and integer timestamps
    parts = seal_header.rsplit(".", 1)
    if len(parts) != 2:
        raise RoutingSealVerificationError(
            f"Malformed seal header: expected 'timestamp.signature', got {len(parts)} parts"
        )

    timestamp_str, provided_signature = parts

    # Validate timestamp format and parse
    try:
        seal_timestamp = float(timestamp_str)
    except ValueError as e:
        raise RoutingSealVerificationError(
            f"Invalid timestamp in seal: {timestamp_str}"
        ) from e

    # Enforce micro-TTL (fail-closed on expiration)
    current_time = time.time()
    age_seconds = current_time - seal_timestamp

    if age_seconds < 0:
        raise RoutingSealVerificationError(
            f"Seal timestamp is in the future: {seal_timestamp} > {current_time}"
        )

    if age_seconds > ttl_seconds:
        raise RoutingSealVerificationError(
            f"Seal expired: age {age_seconds:.2f}s exceeds TTL {ttl_seconds}s"
        )

    # Compute expected HMAC-SHA256 signature
    message = f"{timestamp_str}.{body_bytes.hex()}".encode()
    expected_signature = hmac.new(
        secret.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(provided_signature, expected_signature):
        raise RoutingSealVerificationError(
            "Seal signature mismatch: tampering detected"
        )

    return True


def generate_w3c_traceparent() -> str:
    """Generate W3C Trace Context traceparent header.

    Returns compliant `00-{trace_id}-{span_id}-01` header using OpenTelemetry
    if available, or cryptographically secure hex fallback.

    Format: version-trace_id-span_id-trace_flags
    - version: 00 (fixed)
    - trace_id: 32 hex chars (16 bytes)
    - span_id: 16 hex chars (8 bytes)
    - trace_flags: 01 (sampled)

    Returns:
        W3C traceparent header string
    """
    trace_id: str | None = None
    span_id: str | None = None

    # Attempt to use OpenTelemetry if available (zero-dependency fallback)
    try:
        from opentelemetry import trace

        current_span = trace.get_current_span()
        span_context = current_span.get_span_context()

        if span_context.is_valid:
            # Format trace_id and span_id as hex strings
            trace_id = f"{span_context.trace_id:032x}"
            span_id = f"{span_context.span_id:016x}"
    except (ImportError, AttributeError):
        # OpenTelemetry not available or no active span context
        pass

    # Cryptographically secure fallback
    if trace_id is None:
        trace_id = secrets.token_hex(16)  # 16 bytes = 32 hex chars
    if span_id is None:
        span_id = secrets.token_hex(8)  # 8 bytes = 16 hex chars

    # W3C Trace Context format: version-trace_id-parent_id-trace_flags
    # trace_flags=01 means sampled
    return f"00-{trace_id}-{span_id}-01"
