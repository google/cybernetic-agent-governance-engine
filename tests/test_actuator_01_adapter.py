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
test_actuator_01_adapter.py — Actuator01Adapter Orchestration Tests

Comprehensive tests for the actuator adapter orchestration layer, covering:
- Per-operator quorum signing with distinct signatures
- All six fail-closed branches in actuate()
- Receipt field mapping on success and failure paths
- Health check fail-closed semantics
- Environment variable validation
- Capability isolation
- Async context manager lifecycle
"""

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from src.gateway.governance.execution_actuator import (
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
)
from src.gateway.governance.kms_signer import KMSGovernanceSigner
from src.integrations.actuator_01.adapter import Actuator01Adapter
from src.integrations.actuator_01.client import ActuatorHttpClient
from src.integrations.actuator_01.envelope_builder import (
    EnvelopeTooLargeError,
    InvalidClearanceError,
)
from src.integrations.actuator_01.response_classifier import (
    ClassifiedResponse,
    ResponseCategory,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


# ── Mock Helpers ──────────────────────────────────────────────────────────


class MockPerOperatorSigner:
    """Mock signer that produces distinct signatures keyed by operator URN.

    This is the critical test infrastructure piece: signatures are keyed off
    operator identity, so duplicate URNs produce duplicate signatures, and
    reordering URNs reorders signatures. A constant mock (b"a" * 64) cannot
    detect misalignment.
    """

    is_kms_active = True

    def __init__(self, urn: str) -> None:
        self._urn = urn

    def sign_raw(self, message: bytes) -> bytes:
        """Return a deterministic but URN-specific 64-byte signature."""
        return hashlib.sha512(self._urn.encode() + message).digest()[:64]


def make_valid_clearance(
    operator_urns: list[str] | None = None,
) -> ExecutionClearance:
    """Factory for valid ExecutionClearance."""
    if operator_urns is None:
        operator_urns = ["urn:actuator_01:op:alice", "urn:actuator_01:op:bob"]

    return ExecutionClearance(
        thread_id="test-thread-123",
        decision="ALLOW",
        decision_path="DIRECT",
        action="execute_trade",
        target="account:1234567890",
        operator_urn=operator_urns[0],
        issued_at=1785012000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        approvals=[
            {
                "approver_urn": urn,
                "approved_at_utc": f"2026-08-01T12:00:0{i}Z",
                "approval_signature": f"sig-{i}",
            }
            for i, urn in enumerate(operator_urns)
        ],
        required_quorum=2,
        ttl_seconds=30,
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestPerOperatorSigning:
    """Test per-operator signing with the signer_resolver seam."""

    async def test_distinct_signatures_with_resolver(self, monkeypatch):
        """With a per-URN resolver, each operator gets a distinct signature."""
        urns = ["urn:actuator_01:op:alice", "urn:actuator_01:op:bob"]
        clearance = make_valid_clearance(urns)

        # Mock client that captures the submitted signatures
        captured_signatures = []

        async def mock_submit(
            canonical_bytes, operator_urns, signatures, assertion, issued_at
        ):
            nonlocal captured_signatures
            captured_signatures = signatures
            # Create a real Response object
            return httpx.Response(
                200,
                json={
                    "receipt_id": "r-123",
                    "session_uuid": "s-456",
                    "status": "ACCEPTED",
                },
            )

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = AsyncMock(side_effect=mock_submit)

        # Resolver returns a distinct signer per URN
        def resolver(urn: str) -> KMSGovernanceSigner:
            return MockPerOperatorSigner(urn)  # type: ignore[return-value]

        # Use a dummy base signer (never called due to resolver)
        base_signer = MockPerOperatorSigner("urn:actuator_01:op:base")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=base_signer,  # type: ignore[arg-type]
            signer_resolver=resolver,
        )

        receipt = await adapter.actuate(clearance)

        assert receipt.accepted
        assert len(captured_signatures) == 2
        # Signatures must be pairwise distinct
        assert captured_signatures[0] != captured_signatures[1]

    async def test_default_resolver_uses_base_signer(self, monkeypatch):
        """Without a resolver, all operators use the same base signer."""
        urns = ["urn:actuator_01:op:alice", "urn:actuator_01:op:bob"]
        clearance = make_valid_clearance(urns)

        captured_signatures = []

        async def mock_submit(
            canonical_bytes, operator_urns, signatures, assertion, issued_at
        ):
            nonlocal captured_signatures
            captured_signatures = signatures
            return httpx.Response(
                200,
                json={
                    "receipt_id": "r-123",
                    "session_uuid": "s-456",
                    "status": "ACCEPTED",
                },
            )

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = AsyncMock(side_effect=mock_submit)

        base_signer = MockPerOperatorSigner("urn:actuator_01:op:shared")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=base_signer,  # type: ignore[arg-type]
            signer_resolver=None,  # No resolver — use default
        )

        receipt = await adapter.actuate(clearance)

        assert receipt.accepted
        assert len(captured_signatures) == 2
        # Without a resolver, signatures are identical (reference implementation mode)
        assert captured_signatures[0] == captured_signatures[1]

    async def test_signature_urn_positional_alignment(self, monkeypatch):
        """Reordering approvals reorders both URNs and signatures in lockstep."""
        # To test positional alignment, we use a deterministic mock signer that keys
        # off URN only (not message content), so signatures are URN-specific but
        # stable across different canonical bytes.

        urns_forward = ["urn:actuator_01:op:alice", "urn:actuator_01:op:bob"]
        clearance_forward = make_valid_clearance(urns_forward)

        urns_reversed = ["urn:actuator_01:op:bob", "urn:actuator_01:op:alice"]
        clearance_reversed = make_valid_clearance(urns_reversed)

        captured_forward = {}
        captured_reversed = {}

        async def mock_submit_forward(
            canonical_bytes, operator_urns, signatures, assertion, issued_at
        ):
            nonlocal captured_forward
            captured_forward = {"urns": operator_urns, "sigs": signatures}
            return httpx.Response(
                200,
                json={
                    "receipt_id": "r-123",
                    "session_uuid": "s-456",
                    "status": "ACCEPTED",
                },
            )

        async def mock_submit_reversed(
            canonical_bytes, operator_urns, signatures, assertion, issued_at
        ):
            nonlocal captured_reversed
            captured_reversed = {"urns": operator_urns, "sigs": signatures}
            return httpx.Response(
                200,
                json={
                    "receipt_id": "r-123",
                    "session_uuid": "s-456",
                    "status": "ACCEPTED",
                },
            )

        # Deterministic signer that returns URN-keyed signature (ignores message)
        class SimpleMockSigner:
            is_kms_active = True

            def __init__(self, urn: str) -> None:
                self._urn = urn

            def sign_raw(self, message: bytes) -> bytes:
                # Signature is deterministic based on URN alone
                return hashlib.sha256(self._urn.encode()).digest() + b"\x00" * 32

        def resolver(urn: str) -> KMSGovernanceSigner:
            return SimpleMockSigner(urn)  # type: ignore[return-value]

        base_signer = SimpleMockSigner("urn:actuator_01:op:base")

        # Forward run
        mock_client_forward = MagicMock(spec=ActuatorHttpClient)
        mock_client_forward.submit_envelope = AsyncMock(side_effect=mock_submit_forward)
        adapter_forward = Actuator01Adapter(
            client=mock_client_forward,
            signer=base_signer,  # type: ignore[arg-type]
            signer_resolver=resolver,
        )
        await adapter_forward.actuate(clearance_forward)

        # Reversed run
        mock_client_reversed = MagicMock(spec=ActuatorHttpClient)
        mock_client_reversed.submit_envelope = AsyncMock(
            side_effect=mock_submit_reversed
        )
        adapter_reversed = Actuator01Adapter(
            client=mock_client_reversed,
            signer=base_signer,  # type: ignore[arg-type]
            signer_resolver=resolver,
        )
        await adapter_reversed.actuate(clearance_reversed)

        # URNs and signatures must reverse together
        assert captured_forward["urns"] == urns_forward
        assert captured_reversed["urns"] == urns_reversed
        # Signatures reverse when URNs reverse (positional alignment)
        assert captured_forward["sigs"][0] == captured_reversed["sigs"][1]
        assert captured_forward["sigs"][1] == captured_reversed["sigs"][0]


class TestFailClosedBranches:
    """Test all six fail-closed error branches in actuate()."""

    async def test_invalid_clearance_fails_closed(self, monkeypatch):
        """INVALID_CLEARANCE: decision != ALLOW fails before envelope construction."""
        clearance = make_valid_clearance()
        clearance.decision = "DENY"  # Invalid for actuation

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] == "INVALID_CLEARANCE"
        assert receipt.findings[0]["severity"] == "TERMINAL"
        assert not receipt.retryable
        assert receipt.envelope_digest is None
        assert receipt.timestamp_utc is not None

    async def test_envelope_too_large_fails_closed(self, monkeypatch):
        """ENVELOPE_TOO_LARGE: 4KB ceiling enforcement."""
        clearance = make_valid_clearance()

        # Patch at the module level where it's imported in adapter
        def mock_build_and_canonicalize(clearance):
            raise EnvelopeTooLargeError(5000)

        monkeypatch.setattr(
            "src.integrations.actuator_01.adapter.build_and_canonicalize",
            mock_build_and_canonicalize,
        )

        # Client won't be called
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] == "ENVELOPE_TOO_LARGE"
        assert receipt.findings[0]["severity"] == "TERMINAL"
        assert not receipt.retryable
        assert receipt.envelope_digest is None

    async def test_assertion_build_failed_fails_closed(self, monkeypatch):
        """ASSERTION_BUILD_FAILED: KMS signing failure in assertion construction."""
        clearance = make_valid_clearance()

        def mock_build_assertion(envelope_digest_hex, nonce_hex, issued_at, signer):
            raise RuntimeError("KMS unavailable")

        monkeypatch.setattr(
            "src.integrations.actuator_01.adapter.build_assertion", mock_build_assertion
        )

        # Client won't be called
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] == "ASSERTION_BUILD_FAILED"
        assert receipt.findings[0]["severity"] == "TERMINAL"
        assert not receipt.retryable
        # Envelope digest IS populated (failure occurred after envelope step)
        assert receipt.envelope_digest is not None

    async def test_quorum_signing_failed_missing_approver_urn(self, monkeypatch):
        """QUORUM_SIGNING_FAILED: missing approver_urn in approval record."""
        clearance = make_valid_clearance()
        clearance.approvals[0]["approver_urn"] = ""  # Missing URN

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] == "QUORUM_SIGNING_FAILED"
        assert receipt.findings[0]["severity"] == "TERMINAL"
        assert "missing approver_urn" in receipt.findings[0]["detail"]
        assert not receipt.retryable

    async def test_network_error_fails_closed(self, monkeypatch):
        """Network error during submission classified as retryable."""
        clearance = make_valid_clearance()

        async def mock_submit(*args, **kwargs):
            raise httpx.ConnectError("Connection refused")

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = mock_submit
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] in ("NETWORK_ERROR", "CONNECTION_RESET")
        assert receipt.findings[0]["severity"] == "TRANSIENT"
        assert receipt.retryable  # Network errors are retryable

    async def test_unexpected_error_fails_closed(self, monkeypatch):
        """UNEXPECTED_ERROR: catch-all for non-HTTPError exceptions."""
        clearance = make_valid_clearance()

        async def mock_submit(*args, **kwargs):
            raise ValueError("Unexpected internal error")

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = mock_submit
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.findings[0]["code"] == "UNEXPECTED_ERROR"
        assert receipt.findings[0]["severity"] == "TERMINAL"
        assert not receipt.retryable


class TestReceiptFieldMapping:
    """Test ActuationReceipt field population on success and failure."""

    async def test_success_receipt_fields(self, monkeypatch):
        """Successful actuation populates all receipt fields."""
        clearance = make_valid_clearance()

        async def mock_submit(*args, **kwargs):
            return httpx.Response(
                200,
                json={
                    "receipt_id": "receipt-abc123",
                    "session_uuid": "session-def456",
                    "status": "ACCEPTED",
                },
            )

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = mock_submit
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert receipt.accepted
        assert receipt.receipt_id == "receipt-abc123"
        assert receipt.session_uuid == "session-def456"
        assert receipt.raw_receipt is not None
        assert receipt.envelope_digest is not None
        assert len(receipt.envelope_digest) == 64  # SHA-256 hex
        assert receipt.timestamp_utc is not None
        assert receipt.retryable is False

    async def test_failure_receipt_fields(self, monkeypatch):
        """Failed actuation still populates envelope_digest and timestamp_utc."""
        clearance = make_valid_clearance()

        async def mock_submit(*args, **kwargs):
            return httpx.Response(400, json={"error": "BAD_REQUEST"})

        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.submit_envelope = mock_submit
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        receipt = await adapter.actuate(clearance)

        assert not receipt.accepted
        assert receipt.receipt_id is None
        assert receipt.session_uuid is None
        # Envelope digest and timestamp are STILL populated
        assert receipt.envelope_digest is not None
        assert receipt.timestamp_utc is not None
        assert len(receipt.findings) > 0


class TestHealthCheckAndCapabilities:
    """Test health_check and get_capabilities."""

    async def test_health_check_fails_when_kms_inactive(self):
        """health_check returns False when KMS is not active."""

        class InactiveSigner:
            is_kms_active = False

        mock_client = MagicMock(spec=ActuatorHttpClient)
        adapter = Actuator01Adapter(
            client=mock_client,
            signer=InactiveSigner(),  # type: ignore[arg-type]
        )

        result = await adapter.health_check()
        assert result is False

    async def test_health_check_delegates_to_client(self):
        """health_check delegates to client when KMS is active."""
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.health_check = AsyncMock(return_value=True)

        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")
        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        result = await adapter.health_check()
        assert result is True
        mock_client.health_check.assert_called_once()

    def test_get_capabilities_returns_copy(self):
        """get_capabilities returns a copy to prevent mutation."""
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        caps1 = adapter.get_capabilities()
        caps2 = adapter.get_capabilities()

        # Mutating one should not affect the other
        caps1.add("fake_capability")  # type: ignore[arg-type]
        assert "fake_capability" not in caps2


class TestFromEnv:
    """Test from_env() environment variable validation."""

    def test_from_env_missing_endpoint(self, monkeypatch):
        """from_env raises RuntimeError when ACTUATOR_01_ENDPOINT is missing."""
        monkeypatch.delenv("ACTUATOR_01_ENDPOINT", raising=False)
        monkeypatch.setenv("ACTUATOR_01_CERT_PATH", "/fake/cert.pem")
        monkeypatch.setenv("ACTUATOR_01_KEY_PATH", "/fake/key.pem")
        monkeypatch.setenv("ACTUATOR_01_CA_PATH", "/fake/ca.pem")
        monkeypatch.setenv("ACTUATOR_01_TENANT_ID", "tenant-123")

        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        with pytest.raises(RuntimeError, match="ACTUATOR_01_ENDPOINT"):
            Actuator01Adapter.from_env(signer=mock_signer)  # type: ignore[arg-type]

    def test_from_env_missing_multiple(self, monkeypatch):
        """from_env lists all missing variables."""
        monkeypatch.delenv("ACTUATOR_01_ENDPOINT", raising=False)
        monkeypatch.delenv("ACTUATOR_01_CERT_PATH", raising=False)
        monkeypatch.setenv("ACTUATOR_01_KEY_PATH", "/fake/key.pem")
        monkeypatch.setenv("ACTUATOR_01_CA_PATH", "/fake/ca.pem")
        monkeypatch.setenv("ACTUATOR_01_TENANT_ID", "tenant-123")

        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        with pytest.raises(RuntimeError) as exc_info:
            Actuator01Adapter.from_env(signer=mock_signer)  # type: ignore[arg-type]

        error_msg = str(exc_info.value)
        assert "ACTUATOR_01_ENDPOINT" in error_msg
        assert "ACTUATOR_01_CERT_PATH" in error_msg


class TestAsyncContextManager:
    """Test async context manager lifecycle."""

    async def test_context_manager_closes_client(self):
        """Async context manager calls close() on exit."""
        mock_client = MagicMock(spec=ActuatorHttpClient)
        mock_client.close = AsyncMock()
        mock_signer = MockPerOperatorSigner("urn:actuator_01:op:test")

        adapter = Actuator01Adapter(
            client=mock_client,
            signer=mock_signer,  # type: ignore[arg-type]
        )

        async with adapter as ctx_adapter:
            assert ctx_adapter is adapter

        mock_client.close.assert_called_once()
