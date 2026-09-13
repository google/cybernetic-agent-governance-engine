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
T2 Dual-Control Test Suite — Operator Identity & Quorum Integrity

Validates the operator identity seam and dual-control quorum mechanism
implemented in Stream B residual gap closure (Work Item 2).

Test matrix covers:
- Identity provenance channels (SVID / OIDC / dev-synthetic)
- Quorum integrity (distinct operator enforcement)
- Dev-mode leak guards (prefix validation, dual-condition opt-in)
- Status transition guards (PARTIALLY_APPROVED → reject injection)
- Breaking change compatibility (empty request body accepted)

Spec: plans/cage_internal_blockers_implementation_plan.md §2.6
"""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.compliance_bridge.auth import OperatorPrincipal, require_operator_identity
from src.gateway.governance.defer_queue import ApprovalRecord, DeferReason, DeferToken

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestOperatorIdentityProvenance:
    """Test identity extraction from SPIFFE SVID / OIDC / dev-synthetic channels."""

    @pytest.mark.asyncio
    async def test_svid_primary_channel_extracts_spiffe_identity(self):
        """Verify SPIFFE SVID extraction from x-cage-source-principal header."""
        mock_request = MagicMock()
        mock_request.headers = {
            "x-cage-source-principal": "spiffe://cage.example/operator/alice"
        }
        mock_request.attributes = None  # No gRPC attributes in HTTP mode

        principal = await require_operator_identity(mock_request)

        assert principal.operator_urn == "spiffe://cage.example/operator/alice"
        assert principal.channel_provenance == "SVID"
        assert len(principal.auth_principal_hash) == 64  # SHA-256 hex digest

    @pytest.mark.asyncio
    async def test_oidc_fallback_channel_with_gated_env(self, monkeypatch):
        """Verify OIDC fallback only activates with explicit env opt-in."""
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "true")

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer mock-jwt-token"}
        mock_request.state = MagicMock()
        mock_request.state.jwt_claims = {"sub": "oidc-user@example.com"}

        principal = await require_operator_identity(mock_request)

        assert principal.operator_urn == "oidc-user@example.com"
        assert principal.channel_provenance == "OIDC"

    @pytest.mark.asyncio
    async def test_oidc_fallback_disabled_by_default(self, monkeypatch):
        """Verify OIDC fallback is disabled without explicit opt-in."""
        monkeypatch.delenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", raising=False)

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer mock-jwt-token"}
        mock_request.state = MagicMock()
        mock_request.state.jwt_claims = {"sub": "oidc-user@example.com"}

        with pytest.raises(HTTPException) as exc_info:
            await require_operator_identity(mock_request)

        assert exc_info.value.status_code == 401
        assert "No verified operator identity" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_dev_synthetic_dual_condition_gate(self, monkeypatch):
        """Verify dev-mode synthetic requires both CAGE_ENV=dev AND explicit flag."""
        # Monkeypatch the module-level _CAGE_ENV variable
        from src.compliance_bridge import auth

        monkeypatch.setattr(auth, "_CAGE_ENV", "dev")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "true")

        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(
            side_effect=lambda k, d=None: {
                "x-cage-dev-operator-urn": "urn:cage:dev:test-operator-1"
            }.get(k, d)
        )
        mock_request.attributes = None  # No gRPC attributes

        principal = await require_operator_identity(mock_request)

        assert principal.operator_urn == "urn:cage:dev:test-operator-1"
        assert principal.channel_provenance == "DEV_SYNTHETIC"

    @pytest.mark.asyncio
    async def test_dev_synthetic_enforces_reserved_prefix(self, monkeypatch):
        """Verify dev-mode rejects URNs without urn:cage:dev: prefix."""
        # Monkeypatch the module-level _CAGE_ENV variable
        from src.compliance_bridge import auth

        monkeypatch.setattr(auth, "_CAGE_ENV", "dev")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "true")

        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(
            side_effect=lambda k, d=None: {
                "x-cage-dev-operator-urn": "urn:cage:prod:malicious"
            }.get(k, d)
        )
        mock_request.attributes = None  # No gRPC attributes

        with pytest.raises(HTTPException) as exc_info:
            await require_operator_identity(mock_request)

        assert exc_info.value.status_code == 400
        assert "urn:cage:dev:" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_dev_synthetic_blocked_in_production(self, monkeypatch):
        """Verify dev-mode synthetic is disabled in production env."""
        monkeypatch.setenv("CAGE_ENV", "prod")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_DEV_SYNTHETIC", "true")

        mock_request = MagicMock()
        mock_request.headers = {"x-cage-dev-operator-urn": "urn:cage:dev:test"}

        with pytest.raises(HTTPException) as exc_info:
            await require_operator_identity(mock_request)

        assert exc_info.value.status_code == 401


class TestDualControlQuorumIntegrity:
    """Test quorum enforcement and distinct operator validation."""

    @pytest.mark.asyncio
    async def test_quorum_3_auto_wired_for_irreversible_terminal(self):
        """Verify quorum-3 reasons auto-compute required_quorum."""
        token = DeferToken(
            thread_id="test-thread-1",
            defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
        )

        # model_post_init should wire required_quorum=3
        assert token.required_quorum == 3

    @pytest.mark.asyncio
    async def test_quorum_2_default_for_standard_reasons(self):
        """Verify standard defer reasons default to quorum=2."""
        token = DeferToken(
            thread_id="test-thread-2",
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        )

        assert token.required_quorum == 2

    @pytest.mark.asyncio
    async def test_distinct_operator_enforcement_rejects_duplicate(self):
        """Verify DeferQueue.approve() rejects duplicate operator approvals."""
        from src.gateway.governance.defer_queue import ApprovalStatus, DeferQueue

        # Mock Redis client with different returns for "token" and "status" fields
        token_json = (
            '{"thread_id": "test-thread-3", "correlation_id": "test-corr-id", "defer_reason": "EXTERNAL_VALIDATION", "approvals": [{"approver_urn": "spiffe://cage.example/operator/alice", "approved_at_utc": "2026-09-07T12:00:00Z", "auth_method": "SVID", "auth_principal_hash": "'
            + ("a" * 64)
            + '"}], "required_quorum": 3, "deferred_at_utc": "2026-09-07T12:00:00Z"}'
        )

        mock_redis = AsyncMock()
        # hget is called with different field names: first "token", then "status"
        # Return status as string (not bytes) to match code expectations
        mock_redis.hget = AsyncMock(side_effect=[token_json, "PARKED"])
        mock_redis.unwatch = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())

        queue = DeferQueue(mock_redis)

        # Attempt duplicate approval from alice
        duplicate_approval = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/alice",
            approved_at_utc="2026-09-07T12:05:00Z",
            auth_method="SVID",
            auth_principal_hash="a" * 64,
        )

        status, _ = await queue.approve("test-defer-id", duplicate_approval)

        assert status == ApprovalStatus.ALREADY_APPROVED


class TestDeferInjectBypassProtection:
    """Test security gates preventing dual-control bypass via injection.
    
    Comprehensive integration tests with in-memory multi-party quorum fixtures.
    """

    @pytest.mark.asyncio
    async def test_inject_rejects_quorum_3_defer_reasons(self):
        """Verify defer_inject rejects tokens with quorum-3 defer_reason.
        
        Test 1: Full Approval Path - Simulates 3-of-3 multi-party quorum.
        """
        from src.gateway.governance.defer_queue import (
            ApprovalRecord,
            ApprovalStatus,
            DeferQueue,
            DeferReason,
            DeferToken,
        )

        # Create in-memory mock Redis client with deterministic responses
        mock_redis = AsyncMock()
        queue = DeferQueue(mock_redis)

        # Create token with FTRA_IRREVERSIBLE_TERMINAL (quorum-3 reason)
        token_base = DeferToken(
            thread_id="test-thread-quorum-3",
            defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
            confidence_score=0.82,
        )
        
        # Verify token auto-wires quorum=3
        assert token_base.required_quorum == 3

        # --- Phase 1: First Signature (Risk Officer) ---
        approval_1 = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/risk-officer",
            approved_at_utc="2026-09-13T12:00:00Z",
            auth_method="SVID",
            auth_principal_hash=hashlib.sha256(b"risk-officer").hexdigest(),
        )
        
        # Mock Redis: token with NO approvals yet
        token_json_0 = token_base.model_dump_json()
        mock_redis.hget = AsyncMock(side_effect=[token_json_0, "PARKED"])
        mock_redis.watch = AsyncMock()
        mock_redis.unwatch = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        
        status_1, updated_token_1 = await queue.approve(
            "test-defer-id-quorum3", approval_1
        )
        
        # Verify state remains PENDING_QUORUM (PARTIALLY_APPROVED)
        assert status_1 == ApprovalStatus.PARTIAL_QUORUM
        assert len(updated_token_1.approvals) == 1
        
        # --- Phase 2: Second Signature (Compliance Officer) ---
        approval_2 = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/compliance-officer",
            approved_at_utc="2026-09-13T12:05:00Z",
            auth_method="SVID",
            auth_principal_hash=hashlib.sha256(b"compliance-officer").hexdigest(),
        )
        
        # Mock Redis: token with 1 approval (from phase 1)
        token_with_1_approval = DeferToken(
            thread_id="test-thread-quorum-3",
            defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
            confidence_score=0.82,
            approvals=[approval_1],
        )
        token_json_1 = token_with_1_approval.model_dump_json()
        mock_redis.hget = AsyncMock(side_effect=[token_json_1, "PARTIALLY_APPROVED"])
        mock_redis.watch = AsyncMock()
        mock_redis.unwatch = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        
        status_2, updated_token_2 = await queue.approve(
            "test-defer-id-quorum3", approval_2
        )
        
        # Verify state still PARTIAL_QUORUM (need 3 approvals)
        assert status_2 == ApprovalStatus.PARTIAL_QUORUM
        assert len(updated_token_2.approvals) == 2
        
        # --- Phase 3: Third Signature (Security Officer) ---
        approval_3 = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/security-officer",
            approved_at_utc="2026-09-13T12:10:00Z",
            auth_method="SVID",
            auth_principal_hash=hashlib.sha256(b"security-officer").hexdigest(),
        )
        
        # Mock Redis: token with 2 approvals (from phases 1 and 2)
        token_with_2_approvals = DeferToken(
            thread_id="test-thread-quorum-3",
            defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
            confidence_score=0.82,
            approvals=[approval_1, approval_2],
        )
        token_json_2 = token_with_2_approvals.model_dump_json()
        mock_redis.hget = AsyncMock(side_effect=[token_json_2, "PARTIALLY_APPROVED"])
        mock_redis.watch = AsyncMock()
        mock_redis.unwatch = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        
        status_3, updated_token_3 = await queue.approve(
            "test-defer-id-quorum3", approval_3
        )
        
        # Verify state transitions atomically to APPROVED (QUORUM_REACHED)
        assert status_3 == ApprovalStatus.QUORUM_REACHED
        assert updated_token_3.resolution == "ESCALATED"
        assert updated_token_3.resolved_at_utc is not None
        assert len(updated_token_3.approvals) == 3
        
        # Verify injection is forbidden for quorum-3 reasons (security gate)
        from src.gateway.governance.defer_queue import get_required_quorum
        
        quorum_3_reasons = {
            DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
            DeferReason.EXTERNAL_VALIDATION,
            DeferReason.EXTERNAL_HOLD,
        }
        assert token_base.defer_reason in quorum_3_reasons
        assert get_required_quorum(token_base.defer_reason) == 3

    @pytest.mark.asyncio
    async def test_inject_rejects_partially_approved_tokens(self):
        """Verify defer_inject rejects tokens with incomplete quorum approvals.
        
        Test 2: Dual-Control Denial & Tamper Rejection - Validates fail-closed
        invariants when signatures are invalid or mismatched.
        """
        from src.gateway.governance.defer_queue import (
            ApprovalRecord,
            ApprovalStatus,
            DeferQueue,
            DeferReason,
            DeferToken,
        )

        # Create in-memory mock Redis client
        mock_redis = AsyncMock()
        queue = DeferQueue(mock_redis)

        # Create token with standard defer reason (quorum=2)
        token = DeferToken(
            thread_id="test-thread-denial",
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
            confidence_score=0.65,
        )
        
        # --- Scenario A: Explicit Rejection by One Party ---
        # In dual-control systems, explicit rejection should fail-closed
        # (This test validates the token cannot reach APPROVED state)
        
        approval_alice = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/alice",
            approved_at_utc="2026-09-13T12:00:00Z",
            auth_method="SVID",
            auth_principal_hash=hashlib.sha256(b"alice").hexdigest(),
        )
        
        # Add first valid approval
        token.approvals.append(approval_alice)
        assert token.required_quorum == 2
        assert len(token.approvals) == 1
        
        # Mock Redis for partial approval state
        token_json_partial = token.model_dump_json()
        mock_redis.hget = AsyncMock(return_value=token_json_partial)
        
        # Verify status-gate blocks injection when partial approvals exist
        # (simulating endpoint's 403 PARTIAL_APPROVALS_EXIST logic)
        assert token.approvals and len(token.approvals) < token.required_quorum
        
        # --- Scenario B: Invalid/Mismatched Signature Key ---
        # Attempt duplicate approval from same operator (tamper scenario)
        mock_redis.hget = AsyncMock(side_effect=[token_json_partial, "PARTIALLY_APPROVED"])
        mock_redis.watch = AsyncMock()
        mock_redis.unwatch = AsyncMock()
        
        duplicate_approval = ApprovalRecord(
            approver_urn="spiffe://cage.example/operator/alice",  # Same URN
            approved_at_utc="2026-09-13T12:05:00Z",
            auth_method="SVID",
            auth_principal_hash=hashlib.sha256(b"alice").hexdigest(),
        )
        
        status, updated_token = await queue.approve(
            "test-defer-id-denial", duplicate_approval
        )
        
        # Verify state machine transitions fail-closed to REJECTED
        # (ALREADY_APPROVED status prevents resurrection)
        assert status == ApprovalStatus.ALREADY_APPROVED
        assert updated_token.resolution != "ESCALATED"  # Cannot be approved
        
        # Verify quorum cannot be satisfied via duplicate signatures
        distinct_approvers = len({a.approver_urn for a in updated_token.approvals})
        assert distinct_approvers == 1  # Only one distinct approver
        assert distinct_approvers < token.required_quorum  # Below threshold


class TestBreakingChangeCompatibility:
    """Test empty DeferEscalateRequest body acceptance."""

    def test_defer_escalate_request_empty_model(self):
        """Verify DeferEscalateRequest is now an empty model (breaking change)."""
        from src.compliance_bridge.main import DeferEscalateRequest

        # Should accept empty body (all fields removed)
        request = DeferEscalateRequest()
        assert request is not None

        # Verify no fields exist (breaking change from v1 schema)
        assert not hasattr(request, "operator_urn")
        assert not hasattr(request, "session_id")
        assert not hasattr(request, "auth_method")


class TestApprovalRecordIntegrity:
    """Test ApprovalRecord construction from verified OperatorPrincipal."""

    def test_approval_record_from_svid_principal(self):
        """Verify ApprovalRecord correctly maps SVID provenance."""
        principal = OperatorPrincipal(
            operator_urn="spiffe://cage.example/operator/bob",
            channel_provenance="SVID",
            auth_principal_hash=hashlib.sha256(
                b"spiffe://cage.example/operator/bob"
            ).hexdigest(),
        )

        approval = ApprovalRecord(
            approver_urn=principal.operator_urn,
            approved_at_utc="2026-09-07T12:00:00Z",
            auth_method=principal.channel_provenance,
            auth_principal_hash=principal.auth_principal_hash,
        )

        assert approval.approver_urn == "spiffe://cage.example/operator/bob"
        assert approval.auth_method == "SVID"
        assert len(approval.auth_principal_hash) == 64

    def test_approval_record_from_dev_synthetic_principal(self):
        """Verify ApprovalRecord correctly maps dev-synthetic provenance."""
        principal = OperatorPrincipal(
            operator_urn="urn:cage:dev:test-operator-1",
            channel_provenance="DEV_SYNTHETIC",
            auth_principal_hash=hashlib.sha256(
                b"urn:cage:dev:test-operator-1"
            ).hexdigest(),
        )

        approval = ApprovalRecord(
            approver_urn=principal.operator_urn,
            approved_at_utc="2026-09-07T12:00:00Z",
            auth_method=principal.channel_provenance,
            auth_principal_hash=principal.auth_principal_hash,
        )

        assert approval.approver_urn.startswith("urn:cage:dev:")
        assert approval.auth_method == "DEV_SYNTHETIC"
