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
FlowSignal Step 1 Provenance & Step 2 Qualification Test Suite.

Verifies:
  1. Complete Phase 3 & Phase 4 provenance anchors in
     ``docs/partners/provider_01/CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json``.
  2. SCB-001 compatibility observation: ``REFUSE`` carrying a non-null
     ``authority_record_id`` never mints a ``ConsequenceToken``.
  3. Financial magnitude validation: zero, negative, and non-finite payment
     magnitudes fail closed on ``ALLOW`` (no ``ConsequenceToken`` minted).
  4. TC-01..TC-06 ConsequenceGateway & Step 2 ``authority_receipt.id`` (``rec``)
     vs ``mandate_id`` (``mnd``) qualification vectors.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from src.gateway.governance.consequence_authority_store import ConsequenceAuthorityStore
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.kms_signer import (
    GCPKMSProvider,
    KMSGovernanceSigner,
    reset_governance_signer,
)
from src.integrations.provider_01.provider import FlowSignalNormativeProvider

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_STEP1_RECORD_PATH = (
    _REPO_ROOT
    / "docs"
    / "partners"
    / "provider_01"
    / "CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json"
)


class _InMemoryAsyncRedis:
    """Deterministic async Redis stub supporting SET NX EX and GET."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool | None:
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def get(self, key: str) -> str | None:
        return self.data.get(key)


def _make_mock_signer() -> KMSGovernanceSigner:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    mock_client = MagicMock()
    key_name = (
        "projects/test/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
    )
    mock_version = MagicMock()
    mock_version.algorithm.name = "EC_SIGN_P256_SHA256"
    mock_client.get_crypto_key_version.return_value = mock_version

    provider = GCPKMSProvider(key_version_name=key_name, kms_client=mock_client)
    signer = KMSGovernanceSigner(
        kms_client=mock_client,
        key_version_name=key_name,
        public_key_pem=public_pem,
        provider=provider,
    )

    def mock_sign_raw(message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    provider.sign_digest = MagicMock(side_effect=lambda d: mock_sign_raw(b"dummy"))
    signer.sign_raw = MagicMock(side_effect=mock_sign_raw)
    return signer


def test_step1_record_contains_complete_phase3_and_phase4_provenance() -> None:
    """Verify CAGE_FLOWSIGNAL_PHASE3_STEP1_RECORD.json pins both Phase 3 and Phase 4 digests."""
    record = json.loads(_STEP1_RECORD_PATH.read_text(encoding="utf-8"))
    p3 = record["flowsignal_baseline"]["phase3_staging_reference"]
    assert p3["service"] == "flowsignal-cage-phase3-staging"
    assert p3["cloud_run_revision"] == "flowsignal-cage-phase3-staging-00005-8mp"
    assert (
        p3["container_image_digest"]
        == "sha256:ec26099cf1ee11aa1491ef14f716acd84d87dccc0ba3c59fca0a6e0f9fc80929"
    )
    assert (
        p3["preflight_evidence_sha256"]
        == "f1b81dd094a9fad8107d61996cb489b62e93302e427792bdf3c14d20277aea9d"
    )

    p4 = record["flowsignal_baseline"]["step1_exercised_deployment"]
    assert p4["service"] == "flowsignal-cage-phase4-staging"
    assert p4["cloud_run_revision"] == "flowsignal-cage-phase4-staging-00001-8nr"
    assert (
        p4["container_image_digest"]
        == "sha256:d681fd2df24f4585ac40c43a76c1eb73ffb7bdb7611f67d4ba2a717cd43d951d"
    )


@pytest.mark.asyncio
@respx.mock
async def test_scb_001_refuse_with_authority_record_id_never_mints_token() -> None:
    """Verify REFUSE responses carrying authority_record_id never mint a ConsequenceToken."""
    provider = FlowSignalNormativeProvider(
        endpoint="https://flowsignal.example.com",
        api_key="test-key",
    )
    respx.post("https://flowsignal.example.com/cage/validate").mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": "REFUSE",
                "authority_record_id": "MANDATE-TREASURY-001",
                "authority_state_version": "1",
                "message": "Refused by policy despite mandate reference",
            },
        )
    )
    result = await provider.validate_fria(
        {
            "action": "payment.release",
            "actor_id": "agent-treasury-01",
            "thread_id": "thread-scb-001",
            "params": {"amount": 500000.0, "currency": "GBP"},
        }
    )
    assert result.admitted is False
    assert len(result.findings) == 1
    assert result.findings[0]["code"] == "FLOWSIGNAL_REFUSE"
    assert "token" not in result.findings[0]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("bad_amount", [0.0, -500.0, float("nan"), float("inf")])
async def test_zero_negative_or_nonfinite_magnitude_fails_closed_on_allow(
    bad_amount: float,
) -> None:
    """Verify zero, negative, or non-finite payment magnitudes fail closed even on ALLOW."""
    provider = FlowSignalNormativeProvider(
        endpoint="https://flowsignal.example.com",
        api_key="test-key",
    )
    respx.post("https://flowsignal.example.com/cage/validate").mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": "ALLOW",
                "authority_record_id": "MANDATE-TREASURY-001",
                "authority_state_version": "1",
            },
        )
    )
    result = await provider.validate_fria(
        {
            "action": "payment.release",
            "actor_id": "agent-treasury-01",
            "thread_id": "thread-bad-mag",
            "params": {"amount": bad_amount, "currency": "GBP"},
        }
    )
    assert result.admitted is False
    assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"


@pytest.mark.asyncio
@respx.mock
async def test_tc01_to_tc06_step2_consequence_qualification_vectors() -> None:
    """Execute TC-01..TC-06 consequence token and receipt-vs-mandate separation vectors."""
    provider = FlowSignalNormativeProvider(
        endpoint="https://flowsignal.example.com",
        api_key="test-key",
    )
    signer = _make_mock_signer()
    redis_stub = _InMemoryAsyncRedis()
    store = ConsequenceAuthorityStore(redis_stub, ttl_seconds=90)
    gateway = ConsequenceGateway(store=store, signer=signer)

    base_payload: dict[str, Any] = {
        "action": "payment.release",
        "actor_id": "agent-treasury-01",
        "thread_id": "thread-step2-tc01",
        "prefer_receipt_id_for_rec": True,
        "params": {
            "amount": 250000.0,
            "currency": "GBP",
            "mandate_id": "MANDATE-TREASURY-001",
            "beneficiary": "SUPPLIER-ALPHA",
        },
    }

    try:
        with patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=signer,
        ):
            # TC-01: Nominal ALLOW with authority_receipt.id -> EXECUTE
            respx.post("https://flowsignal.example.com/cage/validate").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "ALLOW",
                        "authority_record_id": "MANDATE-TREASURY-001",
                        "authority_receipt": {"id": "rcpt-step2-0001"},
                        "authority_state_version": "2",
                    },
                )
            )
            val_res = await provider.validate_fria(base_payload)
            assert val_res.admitted is True
            finding = val_res.findings[0]
            assert finding["code"] == "CONSEQUENCE_TOKEN"
            assert finding["authority_record_id"] == "rcpt-step2-0001"
            assert finding["authority_receipt_id"] == "rcpt-step2-0001"
            assert finding["mandate_id"] == "MANDATE-TREASURY-001"
            token_1 = finding["token"]

            # TC-02: Post-ALLOW payload mutation -> BLOCK (ACTION_BINDING_MISMATCH)
            # without consuming the receipt in Redis
            mutated_payload = {
                **base_payload,
                "params": {**base_payload["params"], "amount": 950000.0},
            }
            eval_mutated = await gateway.evaluate(token_1, mutated_payload)
            assert eval_mutated.decision == ConsequenceDecision.BLOCK
            assert eval_mutated.reason_code == "ACTION_BINDING_MISMATCH"
            assert "flowsignal:token:rcpt-step2-0001" not in redis_stub.data

            # TC-01 (cont.): Unmutated payload consumes token_1 -> EXECUTE
            eval_ok = await gateway.evaluate(token_1, base_payload)
            assert eval_ok.decision == ConsequenceDecision.EXECUTE
            assert eval_ok.reason_code == "OK"

            # TC-03: Replay of consumed receipt -> BLOCK (ALREADY_CONSUMED)
            eval_replay = await gateway.evaluate(token_1, base_payload)
            assert eval_replay.decision == ConsequenceDecision.BLOCK
            assert eval_replay.reason_code == "ALREADY_CONSUMED"

            # TC-04: Expired ConsequenceToken -> BLOCK (TOKEN_INVALID)
            expired_token = await ConsequenceToken.mint(
                sub="agent-treasury-01",
                tid="thread-step2-tc04",
                rec="rcpt-step2-expired",
                act="a" * 64,
                ver="2",
                ttl_seconds=-10,
                signer=signer,
            )
            eval_expired = await gateway.evaluate(expired_token, base_payload)
            assert eval_expired.decision == ConsequenceDecision.BLOCK
            assert eval_expired.reason_code == "TOKEN_INVALID"

            # TC-05: ESCALATE -> EXTERNAL_HOLD with needs_human_review=True
            respx.post("https://flowsignal.example.com/cage/validate").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "ESCALATE",
                        "message": "Screening evidence older than 60s threshold",
                    },
                )
            )
            esc_res = await provider.validate_fria(base_payload)
            assert esc_res.admitted is False
            assert esc_res.findings[0]["code"] == "EXTERNAL_HOLD"
            assert esc_res.findings[0]["needs_human_review"] is True

            # TC-06: Second distinct transaction under the SAME mandate_id
            # with a fresh authority_receipt.id succeeds without false collision
            second_payload: dict[str, Any] = {
                **base_payload,
                "thread_id": "thread-step2-tc06",
                "params": {**base_payload["params"], "amount": 125000.0},
            }
            respx.post("https://flowsignal.example.com/cage/validate").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "ALLOW",
                        "authority_record_id": "MANDATE-TREASURY-001",
                        "authority_receipt": {"id": "rcpt-step2-0002"},
                        "authority_state_version": "3",
                    },
                )
            )
            val_res_2 = await provider.validate_fria(second_payload)
            assert val_res_2.admitted is True
            token_2 = val_res_2.findings[0]["token"]
            eval_ok_2 = await gateway.evaluate(token_2, second_payload)
            assert eval_ok_2.decision == ConsequenceDecision.EXECUTE
            assert eval_ok_2.reason_code == "OK"
    finally:
        reset_governance_signer()
