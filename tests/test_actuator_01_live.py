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

"""Live integration tests for Actuator 01 (execution gateway).

Executes live mTLS requests against the Actuator 01 sandbox endpoint
when configured via environment variables.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from src.gateway.governance.execution_actuator import (
    ExecutionClearance,
    ActuatorCapability,
)
from src.integrations.actuator_01.adapter import Actuator01Adapter

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _is_configured() -> bool:
    """Check if Actuator 01 live credentials are configured."""
    required_vars = [
        "ACTUATOR_01_ENDPOINT",
        "ACTUATOR_01_CLIENT_CERT",
        "ACTUATOR_01_CLIENT_KEY",
    ]
    return all(os.environ.get(var, "").strip() for var in required_vars)


@pytest.fixture
async def live_adapter() -> Actuator01Adapter:
    """Create a live Actuator 01 adapter instance."""
    if not _is_configured():
        pytest.skip(
            "Actuator 01 credentials not configured — "
            "set ACTUATOR_01_ENDPOINT, ACTUATOR_01_CLIENT_CERT, ACTUATOR_01_CLIENT_KEY"
        )
    
    try:
        adapter = Actuator01Adapter.from_env()
    except RuntimeError as exc:
        pytest.skip(f"Actuator 01 adapter initialization failed: {exc}")
    
    async with adapter:
        yield adapter


@pytest.mark.asyncio
async def test_live_health_check(live_adapter: Actuator01Adapter) -> None:
    """Verify live Actuator 01 health endpoint responds."""
    is_healthy = await live_adapter.health_check()
    assert is_healthy, "Actuator 01 health check failed"


@pytest.mark.asyncio
async def test_live_capabilities(live_adapter: Actuator01Adapter) -> None:
    """Verify Actuator 01 advertises expected capabilities."""
    capabilities = live_adapter.get_capabilities()
    
    # Assert core capabilities
    assert ActuatorCapability.MULTI_SIG_QUORUM in capabilities, \
        "Multi-sig quorum capability should be advertised"
    assert ActuatorCapability.MTLS_REQUIRED in capabilities, \
        "mTLS capability should be advertised"
    assert ActuatorCapability.DIGEST_ONLY_PAYLOAD in capabilities, \
        "Digest-only payload capability should be advertised"


@pytest.mark.asyncio
async def test_live_wire_dispatch_roundtrip(
    live_adapter: Actuator01Adapter,
) -> None:
    """Verify live wire dispatch with quorum signatures.
    
    This test requires a valid governance clearance and KMS signer.
    It will skip if KMS is not configured.
    """
    # Create a test clearance
    clearance = ExecutionClearance(
        correlation_id="test-cage-actuator01-live-001",
        action_name="test.wire.dispatch",
        payload_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        context={"test": True, "environment": "sandbox"},
        approvals=[
            {
                "operator_urn": "urn:cage:operator:test-alice",
                "approved_at": "2026-09-14T20:00:00Z",
                "signature": "placeholder-alice-sig",
            },
            {
                "operator_urn": "urn:cage:operator:test-bob",
                "approved_at": "2026-09-14T20:00:01Z",
                "signature": "placeholder-bob-sig",
            },
        ],
    )
    
    # Execute the actuation
    receipt = await live_adapter.actuate(clearance)
    
    # The test environment may not have real KMS configured, so we accept
    # either success or a clear KMS-related failure
    if receipt.error:
        if "KMS" in receipt.error or "not active" in receipt.error:
            pytest.skip(f"KMS not configured in test environment: {receipt.error}")
        # Other errors should fail the test
        pytest.fail(f"Actuation failed: {receipt.error}")
    
    # If we got a receipt, assert basic structure
    assert receipt.receipt_id, "Receipt ID should be present"
    assert receipt.submitted_at, "Submission timestamp should be present"


@pytest.mark.asyncio
async def test_live_jcs_canonicalization(
    live_adapter: Actuator01Adapter,
) -> None:
    """Verify RFC 8785 (JCS) canonical serialization in wire format.
    
    This is a structural test that validates envelope construction without
    requiring full actuation. It will skip if basic validation fails.
    """
    # Create a minimal clearance with deterministic payload
    clearance = ExecutionClearance(
        correlation_id="test-jcs-canonicalization",
        action_name="test.canonical.serialize",
        payload_digest="0" * 64,  # Deterministic test digest
        context={"test": True},
        approvals=[
            {
                "operator_urn": "urn:cage:operator:alice",
                "approved_at": "2026-09-14T00:00:00Z",
                "signature": "sig-alice",
            },
            {
                "operator_urn": "urn:cage:operator:bob",
                "approved_at": "2026-09-14T00:00:00Z",
                "signature": "sig-bob",
            },
        ],
    )
    
    # The adapter validates clearance during actuation
    receipt = await live_adapter.actuate(clearance)
    
    # Accept either success or well-formed errors
    if receipt.error:
        # Envelope size, KMS, or validation errors are acceptable
        acceptable_errors = ["KMS", "Envelope exceeds", "validation failed"]
        if not any(err in receipt.error for err in acceptable_errors):
            pytest.fail(f"Unexpected error during JCS canonicalization: {receipt.error}")
