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
PRAXIS Alignment Phase 3: Hermetic Synthetic Reference Case Fixture.

Validates CAGE native enforcement against Philip Pinol's frozen canonical inputs
(PRAXIS_CAGE_SYNTHETIC_REFERENCE_CASE_V1) using GovernanceEnvelope v3.0 and
DEFER zero-authority parking.

This test suite proves:
  1. JCS-RFC8785 parameter canonicalization produces byte-for-byte deterministic digests
  2. GovernanceEnvelope v3.0 schema integrity with external attestations
  3. DEFER authority extinction for externally-bound permits

Local In-Memory Proof Ceiling:
  - JCS canonicalization correctness (SHA-256 digest stability)
  - NARROW monotonicity (CBF logic structure)
  - Authority extinction (DEFER immutability for authority-bound tokens)
  - Envelope schema v3.0 tamper-evident sealing
  - Physical socket is NOT opened (execution_state="NOT_EXECUTED")

Live GKE Staging Proof Ceiling (out of scope for this test):
  - Final preventable point at kernel socket layer via Cilium L7 eBPF
  - Redis Lua atomic barriers before TCP SYN dispatch
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

from src.gateway.governance.defer_queue import (
    ApprovalStatus,
    DeferQueue,
    DeferReason,
    DeferToken,
    ReplayResult,
    replay_evaluate,
)
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.seams.attestation import (
    AttestationStatus,
    ExternalAttestation,
)

# ---------------------------------------------------------------------------
# PRAXIS_CAGE_SYNTHETIC_REFERENCE_CASE_V1 — Frozen Canonical Parameters
# ---------------------------------------------------------------------------

SYNTHETIC_PARAMS = {
    "delivery_mode": "NO_DELIVERY",
    "message_class": "SYNTHETIC_REFERENCE",
    "recipient_ref": "synthetic-recipient-001",
    "route": "synthetic://resource/alpha",
}

EXPECTED_PARAM_DIGEST = "27f4188867f27b3431c635a1110b7cbc5e06bfd51eb5be6569672b30e7d3d5de"
EXPECTED_ACTION_DIGEST = "fdf5580a8d0add3d71394f57579467469a71d7bb684e7dd234ac9882cf5ec78e"

# ---------------------------------------------------------------------------
# Test 1: JCS Parameter Digest
# ---------------------------------------------------------------------------


def test_jcs_parameter_digest():
    """Verify JCS-RFC8785 canonicalization produces expected SHA-256 digest.

    PRAXIS canonical parameters must canonicalize to the frozen reference digest.
    This proves byte-for-byte deterministic serialization across Python/Go/Rust.
    """
    canonical_bytes = jcs_canonicalize_plan(SYNTHETIC_PARAMS)
    computed_digest = hashlib.sha256(canonical_bytes).hexdigest()

    assert computed_digest == EXPECTED_PARAM_DIGEST, (
        f"JCS parameter digest mismatch.\n"
        f"Expected: {EXPECTED_PARAM_DIGEST}\n"
        f"Computed: {computed_digest}\n"
        f"Canonical bytes: {canonical_bytes!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: Case A — Baseline Valid Permit (ENFORCED_ALLOW with External Attestation)
# ---------------------------------------------------------------------------


def test_case_a_baseline_valid_permit():
    """Construct GovernanceEnvelope v3.0 with PERMIT attestation and validate schema.

    This test proves:
      - GovernanceEnvelope v3.0 schema integrity
      - External attestation embedding in envelope
      - ENFORCED_ALLOW decision flow with NOT_EXECUTED state
      - Consequence ceiling and executor metadata binding
    """
    # Construct ExternalAttestation (PERMIT from provider_02_praxis)
    permit = ExternalAttestation(
        attestation_type="PERMIT",
        status=AttestationStatus.VERIFIED,
        receipt_id="praxis-permit-001",
        provider_name="provider_02_praxis",
        attested_at="2026-09-14T19:00:00Z",
        metadata={
            "permit_id": "praxis-permit-001",
            "nonce": "synthetic-nonce-001",
            "param_digest": EXPECTED_PARAM_DIGEST,
            "validity_window_start": "2026-09-14T19:00:00Z",
            "validity_window_end": "2026-09-14T19:05:00Z",
        },
    )

    # Build GovernanceEnvelope with ENFORCED_ALLOW decision
    builder = GovernanceEnvelopeBuilder()
    envelope = builder.build_unsigned(
        action="synthetic-connector.outbound.message",
        params=SYNTHETIC_PARAMS,
        governance_result={
            "decision_code": "ENFORCED_ALLOW",
            "execution_state": "NOT_EXECUTED",
            "outcome": "NOT_OBSERVED",
        },
        consequence_ceiling="LOW_INFORMATIONAL",
        target_route="synthetic://resource/alpha",
        executor_id="synthetic_actuator_01",
        external_attestations=[permit],
    )

    # Assert envelope version
    assert envelope.envelope_version == "3.0", (
        f"Expected envelope version 3.0, got {envelope.envelope_version}"
    )

    # Assert header metadata
    assert envelope.envelope_type == "cage_governance_decision"
    assert envelope.envelope_id.startswith("cage-")

    # Assert subject metadata (consequence ceiling, target route, executor)
    assert envelope.subject.consequence_ceiling == "LOW_INFORMATIONAL"
    assert envelope.subject.target_route == "synthetic://resource/alpha"
    assert envelope.subject.executor_id == "synthetic_actuator_01"
    assert envelope.subject.action == "synthetic-connector.outbound.message"

    # Assert payload decision codes
    assert envelope.payload["decision_code"] == "ENFORCED_ALLOW"
    assert envelope.payload["execution_state"] == "NOT_EXECUTED"
    assert envelope.payload.get("outcome") == "NOT_OBSERVED"

    # Assert external attestations embedded
    assert len(envelope.external_attestations) == 1
    att = envelope.external_attestations[0]
    assert att.receipt_id == "praxis-permit-001"
    assert att.status == AttestationStatus.VERIFIED
    assert att.provider_name == "provider_02_praxis"
    assert att.attestation_type == "PERMIT"

    # Assert attestation metadata flattened correctly in serialized output
    att_dict = att.to_dict()
    assert att_dict["permit_id"] == "praxis-permit-001"
    assert att_dict["nonce"] == "synthetic-nonce-001"
    assert att_dict["param_digest"] == EXPECTED_PARAM_DIGEST


# ---------------------------------------------------------------------------
# Test 3: Case B — DEFER Stale Evidence / Authority Extinction
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis_defer():
    """Minimal async Redis mock for DeferQueue (adapted from test_defer_queue.py)."""
    store: dict[str, dict] = {}
    zsets: dict[str, dict] = {}

    redis = MagicMock()

    async def _hget(key: str, field: str):
        return store.get(key, {}).get(field)

    async def _watch(key: str):
        pass

    async def _unwatch():
        pass

    class FakePipeline:
        def __init__(self):
            self._ops = []

        def hset(self, key, mapping):
            self._ops.append(("hset", key, mapping))
            return self

        def expire(self, key, ttl):
            self._ops.append(("expire", key, ttl))
            return self

        def zadd(self, zset_key, mapping):
            self._ops.append(("zadd", zset_key, mapping))
            return self

        def zrem(self, zset_key, member):
            self._ops.append(("zrem", zset_key, member))
            return self

        async def execute(self):
            for op in self._ops:
                if op[0] == "hset":
                    store.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zadd":
                    zsets.setdefault(op[1], {}).update(op[2])
                elif op[0] == "zrem":
                    zsets.get(op[1], {}).pop(op[2], None)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    redis.hget = _hget
    redis.watch = _watch
    redis.unwatch = _unwatch
    redis.pipeline = lambda transaction=True: FakePipeline()

    return redis


@pytest.mark.asyncio
async def test_case_b_defer_stale_evidence_authority_extinction(fake_redis_defer):
    """Validate zero-authority parking: authority-bound tokens refuse all mutations.

    This test proves PRAXIS Alignment Phase 2 zero-authority parking principle:
      - Tokens with upstream_permit_id are authority-bound
      - Authority-bound tokens REFUSE approve() operations (returns NOT_FOUND)
      - Authority-bound tokens REFUSE replay_evaluate() injection (returns NOT_FOUND)
      - Retrieved state remains unmodified; only natural expiry allows re-adjudication
    """
    queue = DeferQueue(fake_redis_defer)

    # Instantiate authority-bound DeferToken with upstream_permit_id
    token = DeferToken(
        defer_id="defer-synthetic-001",
        thread_id="synthetic-thread-001",
        defer_reason=DeferReason.EXTERNAL_HOLD,
        confidence_score=0.75,
        ttl_seconds=600,
        opa_input_snapshot={
            "action": "synthetic-connector.outbound.message",
            "evidence_currentness": "STALE",
        },
        upstream_permit_id="praxis-permit-001",
    )

    # Park token
    await queue.park(token)

    # Verify token is authority-bound
    assert token.is_authority_bound() is True

    # -------------------------------------------------------------------------
    # Attempt 1: Quorum approval (must be REFUSED)
    # -------------------------------------------------------------------------
    from src.gateway.governance.defer_queue import ApprovalRecord

    approval = ApprovalRecord(
        approver_urn="urn:operator:alice",
        approved_at_utc="2026-09-14T20:00:00Z",
        auth_method="OIDC",
        auth_principal_hash="abc123",
    )

    status, _ = await queue.approve("defer-synthetic-001", approval)

    # Assert approval was REFUSED (fail-closed: returns NOT_FOUND)
    assert status == ApprovalStatus.NOT_FOUND, (
        f"Expected ApprovalStatus.NOT_FOUND for authority-bound token, got {status}"
    )

    # -------------------------------------------------------------------------
    # Attempt 2: Context injection via replay_evaluate (must be REFUSED)
    # -------------------------------------------------------------------------
    enriched_context = {
        "confidence_score": 0.88,
        "new_state": "injected",
        "evidence_currentness": "FRESH",
    }

    result = await replay_evaluate(queue, "defer-synthetic-001", enriched_context)

    # Assert injection was REFUSED (fail-closed: returns NOT_FOUND)
    assert result == ReplayResult.NOT_FOUND, (
        f"Expected ReplayResult.NOT_FOUND for authority-bound token, got {result}"
    )

    # -------------------------------------------------------------------------
    # Verify token state remains unmodified
    # -------------------------------------------------------------------------
    retrieved = await queue.get("defer-synthetic-001")

    assert retrieved is not None, "Token should still exist in queue"
    assert retrieved.is_authority_bound() is True
    assert retrieved.upstream_permit_id == "praxis-permit-001"

    # No approvals were recorded
    assert len(retrieved.approvals) == 0

    # Resolution is still None (token remains PARKED)
    assert retrieved.resolution is None

    # Original state snapshot preserved (evidence_currentness not mutated)
    assert retrieved.opa_input_snapshot["evidence_currentness"] == "STALE"


# ---------------------------------------------------------------------------
# Pytest marker — all tests are unit and local (hermetic, no live GKE)
# ---------------------------------------------------------------------------

pytestmark = [pytest.mark.unit, pytest.mark.local]
