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

"""W3C traceparent generation for distributed tracing.

Zero vendor SDKs. Fail-closed security posture.
"""

import secrets


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
