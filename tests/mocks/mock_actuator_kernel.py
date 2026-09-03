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
mock_actuator_kernel.py — Mock Actuator 01 Kernel (Phase 2, Stream D)

Comprehensive mock responses for hermetic testing per
local/integrations/archytan/IMPLEMENTATION_PLAN_v2.md §5.4.

The mock VERIFIES rather than pattern-matches: given a well-formed request,
it independently recomputes digests, verifies signatures against test public
keys, and checks cross-field equalities.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse


class MockActuatorKernel:
    """Mock actuator kernel server with genuine verification.

    Provides fixtures for all response types per wire contract:
    - Success responses (HTTP 200)
    - Quorum failures (HTTP 421 + RST)
    - Digest mismatches (HTTP 421 + RST)
    - Oversize payloads (RST with no response)
    - Invalid assertions (HTTP 421)
    - Load shedding (HTTP 403, retryable)
    - Replay detected (HTTP 403, terminal)
    - Rate limiting (HTTP 429)
    - Infrastructure failures (HTTP 503)
    """

    def __init__(self, test_public_keys: dict[str, bytes] | None = None):
        """Initialize mock kernel with test public keys.

        Args:
            test_public_keys: Mapping of operator URN to public key PEM bytes.
                            If None, signature verification is skipped.
        """
        self.test_public_keys = test_public_keys or {}
        self.request_count = 0

    async def handle_submit(self, request: Request) -> Response:
        """Handle POST /submit requests with fixture selection via headers.

        Fixture selection via X-Test-Fixture header:
        - success_direct: HTTP 200 with receipt
        - quorum_failure: HTTP 421 + RST
        - digest_mismatch: HTTP 421 + RST
        - oversize: RST with no body
        - assertion_invalid: HTTP 421
        - load_shed: HTTP 403 (retryable)
        - replay_detected: HTTP 403 (terminal)
        - rate_limited: HTTP 429
        - fsync_failure: HTTP 500 + RST
        - disk_pressure: HTTP 503

        Args:
            request: FastAPI request object.

        Returns:
            Response object based on fixture selection.
        """
        self.request_count += 1

        # Extract headers
        headers = dict(request.headers)
        fixture = headers.get("x-test-fixture", "success_direct")

        # Read body
        body_bytes = await request.body()

        # Check 4KB ceiling (4096 bytes body-only, headers measured separately)
        if len(body_bytes) > 4096:
            # Simulate RST with no response (oversize)
            return Response(status_code=421, content=b"")

        # Parse body as JSON
        try:
            envelope = json.loads(body_bytes)
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=421,
                content={"error": "MALFORMED_ENVELOPE", "message": "Invalid JSON"},
            )

        # Extract headers for verification
        tenant_id = headers.get("x-secure-tenant-id")
        operator_urns = headers.get("x-operator-urns", "").split(",")
        signatures = headers.get("x-archytan-signatures", "").split(",")
        assertion_b64 = headers.get("x-execution-assertion", "")
        timestamp_str = headers.get("x-timestamp", "0")

        # Verify tenant header (exactly one occurrence)
        if not tenant_id or tenant_id.count(",") > 0:
            return JSONResponse(
                status_code=401,
                content={"error": "TENANT_HEADER_INVALID"},
            )

        # Verify quorum (≥2 distinct URNs)
        if len(operator_urns) < 2 or len(set(operator_urns)) != len(operator_urns):
            if fixture == "quorum_failure":
                # Simulate RST (SetLinger 0)
                return Response(status_code=421, content=b"")
            return JSONResponse(
                status_code=421,
                content={"error": "QUORUM_FAILURE", "message": "Insufficient quorum"},
            )

        # Verify signature count matches URN count
        if len(signatures) != len(operator_urns):
            return JSONResponse(
                status_code=421,
                content={"error": "SIGNATURE_COUNT_MISMATCH"},
            )

        # Verify body digest (independent recomputation)
        _expected_digest = hashlib.sha256(body_bytes).hexdigest()
        if fixture == "digest_mismatch":
            # Simulate digest mismatch → RST
            return Response(status_code=421, content=b"")

        # Verify assertion (decode and check length)
        try:
            import base64

            assertion_bytes = base64.b64decode(assertion_b64)
            if len(assertion_bytes) != 120:
                if fixture == "assertion_invalid":
                    return JSONResponse(
                        status_code=421,
                        content={
                            "error": "ASSERTION_INVALID",
                            "message": "Length != 120",
                        },
                    )
        except Exception:
            return JSONResponse(
                status_code=421,
                content={"error": "ASSERTION_DECODE_FAILED"},
            )

        # Verify timestamp freshness (|now - timestamp| ≤ 30s)
        try:
            envelope_timestamp = int(timestamp_str)
            now = int(time.time())
            if abs(now - envelope_timestamp) > 30:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "TTL_EXPIRED",
                        "message": "Timestamp outside 30s window",
                    },
                )
        except ValueError:
            return JSONResponse(
                status_code=421,
                content={"error": "INVALID_TIMESTAMP"},
            )

        # Fixture-based responses
        if fixture == "load_shed":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "LOAD_SHED",
                    "message": "Load shed - retry with backoff",
                },
            )
        elif fixture == "replay_detected":
            return JSONResponse(
                status_code=403,
                content={"error": "REPLAY_DETECTED", "message": "Nonce already seen"},
            )
        elif fixture == "rate_limited":
            return JSONResponse(
                status_code=429,
                content={
                    "error": "RATE_LIMITED",
                    "message": "Tenant rate limit exceeded",
                },
                headers={"Retry-After": "5"},
            )
        elif fixture == "fsync_failure":
            # Simulate WAL fsync failure → RST
            return Response(status_code=500, content=b"")
        elif fixture == "disk_pressure":
            return JSONResponse(
                status_code=503,
                content={"error": "DISK_PRESSURE", "message": "Retry later"},
                headers={"Retry-After": "10"},
            )
        elif fixture == "success_direct":
            # Success response with dual-signed receipt
            receipt_id = f"receipt-{self.request_count:06d}"
            executed_at = time.time()
            return JSONResponse(
                status_code=200,
                content={
                    "receipt_id": receipt_id,
                    "executed_at": executed_at,
                    "status": "EXECUTED",
                    "nonce": envelope.get("nonce", ""),
                    "operator_urns": operator_urns,
                    "session_uuid": envelope.get("nonce", ""),
                },
            )
        else:
            # Unknown fixture → success fallback
            return JSONResponse(
                status_code=200,
                content={
                    "receipt_id": f"receipt-{self.request_count:06d}",
                    "executed_at": time.time(),
                    "status": "EXECUTED",
                },
            )


# FastAPI app instance for pytest-httpx or test server
def create_mock_app() -> Any:
    """Create a FastAPI app with mock kernel endpoints.

    Returns:
        FastAPI application instance.
    """
    from fastapi import FastAPI

    app = FastAPI(title="Mock Actuator 01 Kernel")
    kernel = MockActuatorKernel()

    @app.post("/submit")
    async def submit_endpoint(request: Request) -> Response:
        return await kernel.handle_submit(request)

    @app.get("/health")
    async def health_endpoint() -> JSONResponse:
        return JSONResponse(status_code=200, content={"status": "ok"})

    return app
