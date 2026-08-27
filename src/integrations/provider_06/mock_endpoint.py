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
mock_endpoint.py — Agent Integrity Mock Endpoint for Spike Testing
===================================================================

A lightweight mock HTTP server that simulates Agent Integrity's verification
endpoint. Returns pre-canned responses based on conformance fixtures from
the Agent Integrity repository.

Usage
-----
Run standalone:
    uv run python -m src.integrations.provider_06.mock_endpoint

Or programmatically in tests:
    from src.integrations.provider_06.mock_endpoint import app
    # Use with httpx.AsyncClient(app=app)

Fixture Mode
------------
Set the X-Fixture-Name header to control which conformance fixture is returned:
  - "pass"    → Returns PASS verdict (response may be released)
  - "review"  → Returns REVIEW verdict (requires human approval)
  - "blocked" → Returns BLOCKED verdict (response must not be released)

Default behavior (no header): Returns PASS.

Status
------
**SPIKE** — For local testing only. Not for production use.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

import jsonschema

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger("cage.integrations.provider_06.mock")

SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "local"
    / "integrations"
    / "singh"
    / "integrity-envelope.schema.json"
)
try:
    with open(SCHEMA_PATH) as f:
        ENVELOPE_SCHEMA = json.load(f)
except Exception as e:
    ENVELOPE_SCHEMA = None
    logger.warning(f"Could not load schema: {e}")

# Protocol version from Agent Integrity (packages/protocol/src/types.ts)
PROTOCOL_VERSION = "1-alpha"
RECEIPT_VERSION = "2-alpha"
ENGINE_VERSION = "0.1.0-mock"


# ---------------------------------------------------------------------------
# Conformance Fixtures (from third_party/agent-integrity/tests/conformance/)
# ---------------------------------------------------------------------------

FIXTURES: dict[str, dict[str, Any]] = {
    "pass": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "PASS",
        "findings": [],
    },
    "review": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "REVIEW",
        "findings": [
            {
                "code": "claim.support_ambiguous",
                "severity": "review",
                "message": "Evidence support is ambiguous and requires human review",
            }
        ],
    },
    "blocked": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "BLOCKED",
        "findings": [
            {
                "code": "decision.superseded",
                "severity": "blocked",
                "message": "Claim references a superseded decision",
            }
        ],
    },
    # Additional test fixtures for edge cases
    "checker_failure": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "BLOCKED",
        "findings": [
            {
                "code": "checker.failure",
                "severity": "blocked",
                "message": "Integrity checker failed closed: simulated failure",
            }
        ],
    },
    "contradictory_evidence": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "REVIEW",
        "findings": [
            {
                "code": "claim.contradictory_evidence",
                "severity": "review",
                "message": "Contradictory evidence detected for claim",
            }
        ],
    },
    "missing_evidence": {
        "protocolVersion": PROTOCOL_VERSION,
        "status": "BLOCKED",
        "findings": [
            {
                "code": "claim.missing_evidence",
                "severity": "blocked",
                "message": "Required evidence not provided for factual claim",
            }
        ],
    },
}


def _sha256(data: bytes | str) -> str:
    """Compute SHA-256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _create_mock_receipt(
    verification_result: dict[str, Any],
    envelope_digest: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Create a mock AlphaIntegrityReceipt.

    This simulates the receipt structure from Agent Integrity without
    actual cryptographic signing (Ed25519 signatures require a real key).
    """
    now = datetime.now(timezone.utc)
    receipt_run_id = run_id or str(uuid4())

    # Build the receipt payload (before signature)
    payload = {
        "protocolVersion": PROTOCOL_VERSION,
        "receiptVersion": RECEIPT_VERSION,
        "engineVersion": ENGINE_VERSION,
        "issuer": "cage-mock-endpoint",
        "audience": "cage-governance",
        "purpose": "verification",
        "nonce": str(uuid4()),
        "runId": receipt_run_id,
        "createdAt": now.isoformat(),
        "expiresAt": (now.replace(year=now.year + 1)).isoformat(),
        "policyDigest": _sha256("mock-policy"),
        "envelopeDigest": envelope_digest,
        "verification": verification_result,
    }

    # Mock signature (not cryptographically valid)
    payload_json = json.dumps(payload, sort_keys=True)
    mock_signature = _sha256(f"mock-sign:{payload_json}")

    return {
        **payload,
        "signature": {
            "algorithm": "Ed25519",
            "keyId": "mock-key-001",
            "value": mock_signature,
        },
        "receiptDigest": _sha256(payload_json + mock_signature),
    }


# ---------------------------------------------------------------------------
# FastAPI Mock Endpoint
# ---------------------------------------------------------------------------

try:
    from fastapi import FastAPI, Header, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="Agent Integrity Mock Endpoint",
        description="Mock endpoint for CAGE provider_06 spike testing",
        version=ENGINE_VERSION,
    )

    @app.get("/health")  # type: ignore[union-attr]
    async def health() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy", "version": ENGINE_VERSION}

    @app.post("/verify")  # type: ignore[union-attr]
    async def verify(
        request: Request,
        x_fixture_name: str | None = Header(None, alias="X-Fixture-Name"),
        x_protocol_version: str | None = Header(None, alias="X-Protocol-Version"),
    ) -> JSONResponse:
        """Verify a governance payload and return an IntegrityResult.

        Set X-Fixture-Name header to control the response:
          - pass: Return PASS verdict
          - review: Return REVIEW verdict
          - blocked: Return BLOCKED verdict

        Default: "pass"
        """
        fixture_name = (x_fixture_name or "pass").lower()

        if fixture_name not in FIXTURES:
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Unknown fixture: {fixture_name}",
                    "available": list(FIXTURES.keys()),
                },
            )

        try:
            body = await request.json()
            logger.debug("[MockEndpoint] verify request: %s", body)
            if ENVELOPE_SCHEMA:
                jsonschema.validate(instance=body, schema=ENVELOPE_SCHEMA)
        except jsonschema.ValidationError as exc:
            logger.error("Schema validation failed: %s", exc.message)
            return JSONResponse(
                status_code=400,
                content={"error": f"Schema validation failed: {exc.message}"},
            )
        except Exception:
            pass

        result = FIXTURES[fixture_name]
        logger.info(
            "[MockEndpoint] Returning %s verdict (fixture=%s)",
            result["status"],
            fixture_name,
        )

        return JSONResponse(content=result)

    @app.post("/receipt")  # type: ignore[union-attr]
    async def create_receipt(
        request: Request,
        x_fixture_name: str | None = Header(None, alias="X-Fixture-Name"),
    ) -> JSONResponse:
        """Create a mock receipt for evidence submission.

        The receipt includes the verification result and a mock Ed25519 signature.
        """
        fixture_name = (x_fixture_name or "pass").lower()

        if fixture_name not in FIXTURES:
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Unknown fixture: {fixture_name}",
                    "available": list(FIXTURES.keys()),
                },
            )

        try:
            body = await request.json()
            thread_id = body.get("thread_id", "unknown")
            evidence_hash = body.get("evidence_hash", "")
        except Exception:
            thread_id = "unknown"
            evidence_hash = ""

        # Create envelope digest from evidence
        envelope_digest = _sha256(f"{thread_id}:{evidence_hash}")

        receipt = _create_mock_receipt(
            verification_result=FIXTURES[fixture_name],
            envelope_digest=envelope_digest,
            run_id=thread_id,
        )

        logger.info(
            "[MockEndpoint] Created receipt for thread=%s fixture=%s",
            thread_id,
            fixture_name,
        )

        return JSONResponse(content=receipt)

    @app.get("/fixtures")  # type: ignore[union-attr]
    async def list_fixtures() -> dict[str, list[str]]:
        """List available test fixtures."""
        return {"fixtures": list(FIXTURES.keys())}


except ImportError:
    # FastAPI not available — provide a fallback for testing
    app = None  # type: ignore[assignment]
    logger.warning(
        "[MockEndpoint] FastAPI not available. Install with: uv add fastapi uvicorn"
    )


# ---------------------------------------------------------------------------
# Standalone Runner
# ---------------------------------------------------------------------------


def run_server(host: str = "127.0.0.1", port: int = 8090) -> None:
    """Run the mock endpoint server.

    Args:
        host: Bind address (default: 127.0.0.1)
        port: Bind port (default: 8090)
    """
    try:
        import uvicorn
    except ImportError:
        logger.error("uvicorn not available. Install with: uv add uvicorn")
        return

    if app is None:
        logger.error("FastAPI not available. Install with: uv add fastapi")
        return

    logger.info(
        "[MockEndpoint] Starting server on %s:%d (fixtures: %s)",
        host,
        port,
        list(FIXTURES.keys()),
    )

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    host = os.environ.get("MOCK_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_PORT", "8090"))

    print(f"Starting Agent Integrity mock endpoint on http://{host}:{port}")
    print(f"Available fixtures: {list(FIXTURES.keys())}")
    print("Set X-Fixture-Name header to control responses")
    print("Press Ctrl+C to stop")

    run_server(host=host, port=port)
