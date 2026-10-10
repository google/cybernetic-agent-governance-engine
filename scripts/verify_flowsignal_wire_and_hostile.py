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
verify_flowsignal_wire_and_hostile.py
======================================
Executes the Phase 4 Step 1 Live-Seeded Cross-Boundary Validation Suite across
FlowSignal Cloud Run staging and CAGE's Path 1 & Path 2 governance/consequence
harnesses:

1. Case 1 — ConsequenceToken Issuance & Suppression (Live Wire + Hostile LIVE-P3-004):
   - Live ALLOW (`payment.release`) -> `admitted=True`, `ConsequenceToken` minted.
   - Live REFUSE (`DELETE_ACCOUNT` & expired mandate) -> `admitted=False`, no token.
   - Live ESCALATE (stale screening) -> `admitted=False`, `EXTERNAL_HOLD`, no token.
   - Live Malformed & Field-Injection Ingress (`HTTP 422`).
   - Hostile Malformed FlowSignal Responses (Vectors A, B, C) -> `admitted=False`, no token.
2. Case 2 — Action-Binding Mutation & Substitution (Path 1, Live-Seeded Token):
   - Single-field (`amount`) and composed (`amount` + `beneficiary`) post-ALLOW
     payload mutations -> `ConsequenceGateway` returns `BLOCK` (`ACTION_BINDING_MISMATCH`).
3. Case 3 — Single-Use Token Consumption, Replay & Substitution Refusal (Path 1):
   - First consumption of live-minted `ConsequenceToken` -> `EXECUTE` (`OK`).
   - Replay of identical token + payload -> `BLOCK` (`ALREADY_CONSUMED`).
   - Reuse of `authority_record_id` (`rec`) under mutated `(tid, act)` binding ->
     `BLOCK` (`AUTHORITY_RECORD_BINDING_MISMATCH`).
   - Expired `ConsequenceToken` -> `BLOCK` (`TOKEN_INVALID`).
4. Case 4 — Route & Executor Drift at Actuator Boundary (`dispatch_actuation`):
   - Unclaimed action (`DELETE_ACCOUNT`) refused by `ActuatorRegistry`.
   - Drifted `executor_id` -> `REJECTED` (`EXECUTOR_ID_MISMATCH`).
   - Drifted `target_route` -> `REJECTED` (`TARGET_ROUTE_MISMATCH`).
5. Case 5 — Changed Authority Conditions & Post-Approval Revalidation (Path 2):
   - `FriaTier` over live `FlowSignalNormativeProvider` (stale local FRIA ->
     `FRIA_ASSESSMENT_STALE`; live ALLOW -> `[]`; live REFUSE -> `FRIA_REJECTED`;
     live ESCALATE -> `FRIA_EXTERNAL_HOLD`).
   - Post-`govern()` parameter tampering rejected by `verify_seal()`.
   - `SymbolicGovernor.revalidate_post_hitl()` blocks on barrier drift
     (`APPROVAL_CONTEXT_DRIFT`) and spent-approval replay (`APPROVAL_NOT_REDEEMABLE`).
6. Case 6 — Consequence Refusal & Evidence Recording:
   - Verifies `CONSEQUENCE_GATEWAY_DECISION`, `CONSEQUENCE_GATEWAY_REFUSAL`, and
     `ACTUATION_REFUSAL_RECEIPT` records in the evidence stream, plus fail-closed
     `EVIDENCE_CHAIN_UNAVAILABLE` downgrade when the evidence sink is unreachable.

Configuration
-------------
This script talks to a live partner staging environment, so all
deployment-specific identifiers are supplied by the operator. There are
deliberately no hardcoded fallbacks (AGENTS.md secret hygiene); a missing
value exits with actionable guidance rather than silently targeting someone
else's project.

Required:
    FLOWSIGNAL_STAGING_ENDPOINT — Cloud Run base URL of the staging service.
    CAGE_GCP_PROJECT            — GCP project ID or number holding the secret.
    CAGE_GCP_IMPERSONATE_SA     — service account to impersonate.

Optional:
    FLOWSIGNAL_BEARER_SECRET    — Secret Manager secret name
                                  (default: "flowsignal-cage-phase3-bearer").
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.gateway.governance.consequence_authority_store import (
    ConsequenceAuthorityStore,
)
from src.gateway.governance.consequence_gateway import (
    ConsequenceDecision,
    ConsequenceGateway,
)
from src.gateway.governance.consequence_token import ConsequenceToken
from src.gateway.governance.contracts import (
    CommitReceipt,
    MutatingTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
from src.gateway.governance.execution_actuator import (
    ActuationOutcome,
    ActuatorRegistry,
    ExecutionClearance,
    dispatch_actuation,
)
from src.gateway.governance.governor.approval import PostHitlApproval
from src.gateway.governance.governor.assembly import (
    GovernorComponents,
    assemble_governor,
    kernel_stages,
)
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.jurisdiction.eu_ai_act.fria_tier import (
    CODE_HOLD,
    CODE_REJECTED,
    CODE_STALE,
    FriaTier,
)
from src.gateway.governance.kms_signer import GCPKMSProvider, KMSGovernanceSigner
from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    generate_seal,
    verify_seal,
)
from src.gateway.governance.seams.normative import ValidationResult
from src.integrations.provider_01.provider import (
    FlowSignalNormativeProvider,
    _build_cage_authority_request,
)


def _require_env(name: str, description: str) -> str:
    """Return a required environment variable, or exit with actionable guidance."""
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(
            f"ERROR: {name} is not set.\n"
            f"  {name} must contain {description}.\n"
            f"  This script targets a live partner staging environment and has\n"
            f"  no default — export the variable for your own GCP project:\n"
            f"    export {name}=...\n"
        )
    return value


def get_gcp_credentials() -> tuple[str, str, str]:
    """Resolve the staging endpoint and credentials from the environment."""
    endpoint = _require_env(
        "FLOWSIGNAL_STAGING_ENDPOINT",
        "the Cloud Run base URL of the FlowSignal staging service",
    )
    project = _require_env(
        "CAGE_GCP_PROJECT",
        "the GCP project ID or number holding the FlowSignal bearer secret",
    )
    impersonate_sa = _require_env(
        "CAGE_GCP_IMPERSONATE_SA",
        "the service account to impersonate (e.g. cage-gateway@<project>.iam.gserviceaccount.com)",
    )
    secret_name = os.environ.get(
        "FLOWSIGNAL_BEARER_SECRET", "flowsignal-cage-phase3-bearer"
    )

    gcloud_env = {**os.environ, "CLOUDSDK_PYTHON": sys.executable}

    bearer = subprocess.check_output(
        [
            "gcloud",
            "secrets",
            "versions",
            "access",
            "latest",
            f"--secret={secret_name}",
            f"--project={project}",
            f"--impersonate-service-account={impersonate_sa}",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
        env=gcloud_env,
    ).strip()

    id_token = subprocess.check_output(
        [
            "gcloud",
            "auth",
            "print-identity-token",
            f"--audiences={endpoint}",
            f"--impersonate-service-account={impersonate_sa}",
        ],
        text=True,
        stderr=subprocess.DEVNULL,
        env=gcloud_env,
    ).strip()

    return endpoint.rstrip("/"), bearer, id_token


def _build_ephemeral_kms_signer() -> KMSGovernanceSigner:
    """Create a real ECDSA P-256 KMSGovernanceSigner for authentic JWS mint & verify."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    mock_client = MagicMock()
    key_name = "projects/test-proj/locations/us/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
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

    def _sign_raw(message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        return private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    signer.sign_raw = _sign_raw  # type: ignore[method-assign]
    return signer


class _RecordingBarrier(MutatingTier):
    """Phase-2 barrier tier for testing post-HITL context drift and reservation rollback."""

    tier_name = "recording_barrier"
    order = 9

    def __init__(self, *, refuse: bool = False) -> None:
        self.refuse = refuse
        self.commits: list[str] = []
        self.rollbacks: list[str] = []

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action == "payment.release"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        if self.refuse:
            return [
                Violation(
                    tier=self.tier_name,
                    code="BARRIER_VIOLATED",
                    message="liquidity reservation breached post-approval cap",
                    kind=ViolationKind.HARD,
                )
            ], None
        self.commits.append(action)
        return [], CommitReceipt(tier=self.tier_name, magnitude=1.0, token="debit-1")

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        self.rollbacks.append(action)

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        return None


def _base_allow_payload() -> dict[str, Any]:
    """Return the canonical AP-001 ALLOW envelope payload for FlowSignal staging."""
    return {
        "thread_id": "thread-live-wire-allow-001",
        "correlation_id": "exec-live-wire-allow-001",
        "approval_id": "APPROVAL-TREASURY-001",
        "action": "payment.release",
        "target": "TREASURY_GATEWAY",
        "operator_urn": "agent-treasury-01",
        "actor_id": "agent-treasury-01",
        "params": {
            "purpose": "Invoice 78431",
            "actor_role": "treasury_agent",
            "principal_id": "institution-001",
            "principal_name": "Example Financial Institution",
            "mandate_id": "MANDATE-TREASURY-001",
            "mandate_max_amount": 1000000.0,
            "currency": "GBP",
            "permitted_source_accounts": ["TREASURY-001"],
            "permitted_counterparty_class": "APPROVED_SUPPLIERS",
            "mandate_valid_until": "2026-12-31T23:59:59Z",
            "amount": 500000.0,
            "source_account": "TREASURY-001",
            "beneficiary": "SUPPLIER-X",
            "counterparty_status": "APPROVED",
            "account_status": "ACTIVE",
            "risk_state": "NORMAL",
            "approval_required": False,
            "screening_status": "CLEAR",
            "screening_max_age_seconds": 3600,
            "screening_source": "SCREENING-SERVICE-01",
        },
    }


async def main() -> None:
    print("=" * 88)
    print("FLOWSIGNAL PHASE 4 STEP 1 — LIVE WIRE & CROSS-BOUNDARY VALIDATION SUITE")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 88)

    endpoint, bearer, id_token = get_gcp_credentials()
    masked_bearer = f"{bearer[:6]}...{bearer[-4:]}"
    masked_id = f"{id_token[:10]}...{id_token[-6:]}"
    print(f"\n[0] Live Cloud Run Target: {endpoint}")
    print(f"    Secret Manager Bearer: {masked_bearer} (length {len(bearer)})")
    print(f"    Google IAM OIDC Token: {masked_id} (length {len(id_token)})")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer}",
        "X-Serverless-Authorization": f"Bearer {id_token}",
    }

    signer = _build_ephemeral_kms_signer()
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    authority_store = ConsequenceAuthorityStore(fake_redis, ttl_seconds=90)
    consequence_gateway = ConsequenceGateway(store=authority_store, signer=signer)

    recorded_evidence_events: list[dict[str, Any]] = []
    mock_evidence_sink = MagicMock()

    async def _ingest_evidence(event: dict[str, Any]) -> str:
        recorded_evidence_events.append(copy.deepcopy(event))
        return f"ev-{len(recorded_evidence_events)}"

    mock_evidence_sink.ingest = AsyncMock(side_effect=_ingest_evidence)

    allow_payload = _base_allow_payload()

    with (
        patch(
            "src.gateway.governance.consequence_token_service.get_governance_signer",
            return_value=signer,
        ),
        patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=mock_evidence_sink,
        ),
    ):
        provider = FlowSignalNormativeProvider(
            endpoint=endpoint,
            api_key=bearer,
            gcp_id_token=id_token,
            timeout=15.0,
        )

        # =====================================================================
        # CASE 1: ConsequenceToken Issuance & Suppression (Live Wire + Hostile)
        # =====================================================================
        print("\n" + "=" * 88)
        print("CASE 1: CONSEQUENCE TOKEN ISSUANCE & SUPPRESSION (LIVE WIRE + HOSTILE)")
        print("=" * 88)

        # 1A. Raw wire inspection on ALLOW to capture Cloud Run headers + receipt metadata
        wire_request_body = _build_cage_authority_request(allow_payload)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp_allow = await client.post(
                f"{endpoint}/cage/validate",
                json=wire_request_body,
                headers=headers,
            )
            resp_allow_data = resp_allow.json()
            print(
                f"  [1A] Raw Wire ALLOW Status: {resp_allow.status_code} "
                f"(trace={resp_allow.headers.get('x-cloud-trace-context')})"
            )
            print(
                f"       decision={resp_allow_data.get('decision')}, "
                f"authority_record_id={resp_allow_data.get('authority_record_id')}, "
                f"receipt_id={resp_allow_data.get('authority_receipt', {}).get('id')}"
            )
            assert resp_allow.status_code == 200
            assert resp_allow_data.get("decision") == "ALLOW"

        # 1B. Provider-level live ALLOW -> ConsequenceToken JWS minted
        res_allow = await provider.validate_fria(allow_payload)
        token_finding = next(
            (
                f
                for f in res_allow.findings
                if f.get("code") == "CONSEQUENCE_TOKEN" and "token" in f
            ),
            None,
        )
        assert res_allow.admitted is True, f"Expected ALLOW admission, got {res_allow}"
        assert token_finding is not None, "Expected CONSEQUENCE_TOKEN finding on ALLOW"
        live_consequence_token: str = token_finding["token"]
        live_authority_record_id: str = token_finding["authority_record_id"]
        verified_claims = ConsequenceToken.verify(live_consequence_token, signer=signer)
        print(
            f"  [1B] Provider Live ALLOW -> admitted={res_allow.admitted}, "
            f"token_minted=True, rec={verified_claims.rec}, act={verified_claims.act[:16]}..."
        )

        # 1C. Provider-level live REFUSE (unsupported action DELETE_ACCOUNT) -> no token
        refuse_action_payload = copy.deepcopy(allow_payload)
        refuse_action_payload["action"] = "DELETE_ACCOUNT"
        refuse_action_payload["correlation_id"] = "exec-live-wire-refuse-action-001"
        res_refuse_action = await provider.validate_fria(refuse_action_payload)
        refuse_token_minted = any(
            f.get("code") == "CONSEQUENCE_TOKEN" for f in res_refuse_action.findings
        )
        print(
            f"  [1C] Provider Live REFUSE (Unsupported Action 'DELETE_ACCOUNT') -> "
            f"admitted={res_refuse_action.admitted}, findings={[f.get('code') for f in res_refuse_action.findings]}, "
            f"token_minted={refuse_token_minted}"
        )
        assert res_refuse_action.admitted is False
        assert not refuse_token_minted
        assert any(
            f.get("code") == "FLOWSIGNAL_REFUSE" for f in res_refuse_action.findings
        )

        # 1D. Provider-level live REFUSE (expired mandate) -> no token
        refuse_mandate_payload = copy.deepcopy(allow_payload)
        refuse_mandate_payload["correlation_id"] = "exec-live-wire-refuse-mandate-001"
        refuse_mandate_payload["params"]["mandate_valid_until"] = "2020-01-01T00:00:00Z"
        res_refuse_mandate = await provider.validate_fria(refuse_mandate_payload)
        print(
            f"  [1D] Provider Live REFUSE (Expired Mandate) -> "
            f"admitted={res_refuse_mandate.admitted}, findings={[f.get('code') for f in res_refuse_mandate.findings]}"
        )
        assert res_refuse_mandate.admitted is False
        assert not any(
            f.get("code") == "CONSEQUENCE_TOKEN" for f in res_refuse_mandate.findings
        )

        # 1E. Provider-level live ESCALATE (stale screening capture) -> EXTERNAL_HOLD, no token
        escalate_payload = copy.deepcopy(allow_payload)
        escalate_payload["correlation_id"] = "exec-live-wire-escalate-stale-001"
        stale_ts = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        escalate_payload["params"]["screening_captured_at"] = stale_ts
        escalate_payload["params"]["screening_max_age_seconds"] = 60
        res_escalate = await provider.validate_fria(escalate_payload)
        escalate_token_minted = any(
            f.get("code") == "CONSEQUENCE_TOKEN" for f in res_escalate.findings
        )
        hold_finding = next(
            (f for f in res_escalate.findings if f.get("code") == "EXTERNAL_HOLD"),
            None,
        )
        print(
            f"  [1E] Provider Live ESCALATE (Stale Screening 72h > 60s) -> "
            f"admitted={res_escalate.admitted}, hold_finding={hold_finding}, "
            f"token_minted={escalate_token_minted}"
        )
        assert res_escalate.admitted is False
        assert not escalate_token_minted
        assert (
            hold_finding is not None and hold_finding.get("needs_human_review") is True
        )

        # 1F. Live Wire Hostile Ingress: Malformed Body & Injected Decision Field
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp_malformed = await client.post(
                f"{endpoint}/cage/validate",
                json={"malformed_attack_vector": True},
                headers=headers,
            )
            injected_body = copy.deepcopy(wire_request_body)
            injected_body["decision"] = "ALLOW"
            injected_body["authority_record_id"] = "FORGED-RECORD-999"
            resp_injected = await client.post(
                f"{endpoint}/cage/validate",
                json=injected_body,
                headers=headers,
            )
            print(
                f"  [1F] Live Wire Hostile Ingress -> malformed_status={resp_malformed.status_code}, "
                f"injected_decision_status={resp_injected.status_code}"
            )
            assert resp_malformed.status_code == 422
            assert resp_injected.status_code == 422

        # 1G. LIVE-P3-004 Hostile Response Interception Vectors (A, B, C)
        vectors = [
            (
                "A. Missing decision field",
                {
                    "authority_record_id": "MANDATE-TREASURY-001",
                    "message": "Authority evaluation complete",
                },
            ),
            (
                "B. Unknown decision value ('MAYBE')",
                {
                    "decision": "MAYBE",
                    "authority_record_id": "MANDATE-TREASURY-001",
                    "message": "Undetermined",
                },
            ),
            (
                "C. ALLOW with missing/empty authority_record_id",
                {
                    "decision": "ALLOW",
                    "authority_record_id": "",
                    "message": "Authorized without record reference",
                },
            ),
        ]
        for vec_name, injected_response in vectors:
            mock_response = httpx.Response(
                status_code=200,
                json=injected_response,
                request=httpx.Request("POST", f"{endpoint}/cage/validate"),
            )
            with patch("httpx.AsyncClient.post", return_value=mock_response):
                val_result: ValidationResult = await provider.validate_fria(
                    allow_payload
                )
            vec_token_minted = any(
                f.get("code") == "CONSEQUENCE_TOKEN" and "token" in f
                for f in val_result.findings
            )
            assert val_result.admitted is False and not vec_token_minted
            print(
                f"  [1G] LIVE-P3-004 {vec_name} -> admitted={val_result.admitted}, "
                f"findings={[f.get('code') for f in val_result.findings]}, token_minted={vec_token_minted}"
            )

        # =====================================================================
        # CASE 2: Action-Binding Mutation (Path 1, Live-Seeded ConsequenceToken)
        # =====================================================================
        print("\n" + "=" * 88)
        print("CASE 2: ACTION-BINDING MUTATION (LIVE-SEEDED CONSEQUENCE TOKEN)")
        print("=" * 88)

        # 2A. Single-field parameter mutation (amount: 500,000 -> 950,000)
        mutated_amount_payload = copy.deepcopy(allow_payload)
        mutated_amount_payload["params"]["amount"] = 950000.0
        eval_mut_amount = await consequence_gateway.evaluate(
            live_consequence_token, mutated_amount_payload
        )
        print(
            f"  [2A] Single-Field Mutation (amount 500k -> 950k) -> "
            f"decision={eval_mut_amount.decision.value}, reason_code={eval_mut_amount.reason_code}"
        )
        assert eval_mut_amount.decision == ConsequenceDecision.BLOCK
        assert eval_mut_amount.reason_code == "ACTION_BINDING_MISMATCH"

        # 2B. Composed consequence mutation (amount + beneficiary + target)
        mutated_composed_payload = copy.deepcopy(allow_payload)
        mutated_composed_payload["params"]["amount"] = 750000.0
        mutated_composed_payload["params"]["beneficiary"] = "UNAPPROVED-COUNTERPARTY-99"
        mutated_composed_payload["target"] = "SHADOW_SETTLEMENT_GATEWAY"
        eval_mut_composed = await consequence_gateway.evaluate(
            live_consequence_token, mutated_composed_payload
        )
        print(
            f"  [2B] Composed Consequence Mutation (amount + beneficiary + target) -> "
            f"decision={eval_mut_composed.decision.value}, reason_code={eval_mut_composed.reason_code}"
        )
        assert eval_mut_composed.decision == ConsequenceDecision.BLOCK
        assert eval_mut_composed.reason_code == "ACTION_BINDING_MISMATCH"

        # Confirm the live token was NOT consumed by the failed mutation attempts
        assert await authority_store.get_binding(live_authority_record_id) is None

        # =====================================================================
        # CASE 3: Single-Use Consumption, Replay & Substitution Refusal (Path 1)
        # =====================================================================
        print("\n" + "=" * 88)
        print("CASE 3: SINGLE-USE CONSUMPTION, REPLAY & SUBSTITUTION REFUSAL")
        print("=" * 88)

        # 3A. First valid consumption of live-minted ConsequenceToken -> EXECUTE (OK)
        eval_first = await consequence_gateway.evaluate(
            live_consequence_token, allow_payload
        )
        print(
            f"  [3A] First Consumption (Live Token + Unmutated Payload) -> "
            f"decision={eval_first.decision.value}, reason_code={eval_first.reason_code}"
        )
        assert eval_first.decision == ConsequenceDecision.EXECUTE
        assert eval_first.reason_code == "OK"

        # 3B. Immediate Replay of identical live token + payload -> BLOCK (ALREADY_CONSUMED)
        eval_replay = await consequence_gateway.evaluate(
            live_consequence_token, allow_payload
        )
        print(
            f"  [3B] Immediate Replay (Same Live Token + Same Payload) -> "
            f"decision={eval_replay.decision.value}, reason_code={eval_replay.reason_code}"
        )
        assert eval_replay.decision == ConsequenceDecision.BLOCK
        assert eval_replay.reason_code == "ALREADY_CONSUMED"

        # 3C. Live Wire Replay + Substitution (Second live ALLOW returning same rec
        #     under different thread_id / payload) -> BLOCK (AUTHORITY_RECORD_BINDING_MISMATCH)
        substituted_payload = copy.deepcopy(allow_payload)
        substituted_payload["thread_id"] = "thread-live-wire-allow-002"
        substituted_payload["correlation_id"] = "exec-live-wire-allow-002"
        substituted_payload["params"]["amount"] = 250000.0
        res_allow_second = await provider.validate_fria(substituted_payload)
        second_token = next(
            f["token"]
            for f in res_allow_second.findings
            if f.get("code") == "CONSEQUENCE_TOKEN"
        )
        eval_substitution = await consequence_gateway.evaluate(
            second_token, substituted_payload
        )
        print(
            f"  [3C] Authority-Record Substitution (Second Live Token with same rec={live_authority_record_id!r} "
            f"under distinct thread/amount) -> decision={eval_substitution.decision.value}, "
            f"reason_code={eval_substitution.reason_code}"
        )
        assert eval_substitution.decision == ConsequenceDecision.BLOCK
        assert eval_substitution.reason_code == "AUTHORITY_RECORD_BINDING_MISMATCH"

        # 3D. Expired ConsequenceToken -> BLOCK (TOKEN_INVALID)
        expired_digest = hashlib.sha256(
            jcs_canonicalize_plan(allow_payload)
        ).hexdigest()
        expired_token = ConsequenceToken.mint(
            sub=allow_payload["actor_id"],
            tid=allow_payload["thread_id"],
            rec="rec-expired-test-001",
            act=expired_digest,
            ver="1",
            ttl_seconds=-10,
            signer=signer,
        )
        eval_expired = await consequence_gateway.evaluate(expired_token, allow_payload)
        print(
            f"  [3D] Expired ConsequenceToken (ttl=-10s) -> "
            f"decision={eval_expired.decision.value}, reason_code={eval_expired.reason_code}"
        )
        assert eval_expired.decision == ConsequenceDecision.BLOCK
        assert eval_expired.reason_code == "TOKEN_INVALID"

        # =====================================================================
        # CASE 4: Route & Executor Drift at Actuator Boundary (`dispatch_actuation`)
        # =====================================================================
        print("\n" + "=" * 88)
        print("CASE 4: ROUTE & EXECUTOR DRIFT AT ACTUATOR BOUNDARY")
        print("=" * 88)

        broker_actuator = BrokerActuator()
        registry = ActuatorRegistry()
        registry.register(broker_actuator, claims={"payment.release", "execute_trade"})

        # 4A. Unclaimed action lookup refuses pre-dispatch
        unclaimed = registry.get_actuator("DELETE_ACCOUNT")
        print(f"  [4A] ActuatorRegistry.get_actuator('DELETE_ACCOUNT') -> {unclaimed}")
        assert unclaimed is None

        # 4B. Executor ID drift -> EXECUTOR_ID_MISMATCH
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        clearance_executor_drift = ExecutionClearance(
            thread_id=allow_payload["thread_id"],
            decision="ALLOW",
            decision_path="DIRECT",
            action="payment.release",
            target=allow_payload["target"],
            operator_urn=allow_payload["operator_urn"],
            issued_at=now_epoch,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=allow_payload["correlation_id"],
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest=verified_claims.act,
            opa_input_digest="b" * 64,
            nonce="0123456789abcdef0123456789abcdef",
            params=allow_payload["params"],
            approvals=[{"reviewer": "flowsignal-live-allow"}],
            required_quorum=1,
            executor_id="rogue_external_actuator",
            target_route="local://default",
        )
        receipt_exec_drift = await dispatch_actuation(
            broker_actuator, clearance_executor_drift
        )
        exec_drift_codes = [f.get("code") for f in receipt_exec_drift.findings]
        print(
            f"  [4B] Executor Drift (executor_id='rogue_external_actuator') -> "
            f"accepted={receipt_exec_drift.accepted}, outcome={receipt_exec_drift.outcome.value}, "
            f"findings={exec_drift_codes}"
        )
        assert receipt_exec_drift.accepted is False
        assert receipt_exec_drift.outcome == ActuationOutcome.REJECTED
        assert "EXECUTOR_ID_MISMATCH" in exec_drift_codes

        # 4C. Target route drift -> TARGET_ROUTE_MISMATCH
        clearance_route_drift = ExecutionClearance(
            thread_id=allow_payload["thread_id"],
            decision="ALLOW",
            decision_path="DIRECT",
            action="payment.release",
            target=allow_payload["target"],
            operator_urn=allow_payload["operator_urn"],
            issued_at=now_epoch,
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=allow_payload["correlation_id"],
            correlation_id_source="INGRESS_MINTED",
            governance_decision_digest=verified_claims.act,
            opa_input_digest="b" * 64,
            nonce="fedcba9876543210fedcba9876543210",
            params=allow_payload["params"],
            approvals=[{"reviewer": "flowsignal-live-allow"}],
            required_quorum=1,
            executor_id=broker_actuator.actuator_id,
            target_route="https://untrusted-egress.example.com/settle",
        )
        receipt_route_drift = await dispatch_actuation(
            broker_actuator, clearance_route_drift
        )
        route_drift_codes = [f.get("code") for f in receipt_route_drift.findings]
        print(
            f"  [4C] Target Route Drift (target_route='https://untrusted-egress...') -> "
            f"accepted={receipt_route_drift.accepted}, outcome={receipt_route_drift.outcome.value}, "
            f"findings={route_drift_codes}"
        )
        assert receipt_route_drift.accepted is False
        assert receipt_route_drift.outcome == ActuationOutcome.REJECTED
        assert "TARGET_ROUTE_MISMATCH" in route_drift_codes

        # =====================================================================
        # CASE 5: Path 2 (FriaTier + routing_seal + Post-HITL Revalidation)
        # =====================================================================
        print("\n" + "=" * 88)
        print(
            "CASE 5: PATH 2 — FRIA TIER (LIVE WIRE), ROUTING SEAL & POST-HITL REVALIDATION"
        )
        print("=" * 88)

        now_utc = datetime.now(timezone.utc)
        fresh_artefact = {"assessed_at": (now_utc - timedelta(days=10)).isoformat()}
        stale_artefact = {"assessed_at": (now_utc - timedelta(days=400)).isoformat()}

        # 5A. FriaTier with stale local FRIA artefact -> FRIA_ASSESSMENT_STALE (pre-wire)
        fria_stale = FriaTier(
            provider,
            region="EU_ECB",
            assessment_lookup=lambda _act: stale_artefact,
            reassessment_interval_days=365,
            gate_timeout_seconds=15.0,
            clock=lambda: now_utc,
        )
        v_stale = await fria_stale.evaluate("payment.release", allow_payload["params"])
        print(
            f"  [5A] FriaTier Stale Local Artefact (400d > 365d) -> "
            f"violations={[(v.code, v.kind.value) for v in v_stale]}"
        )
        assert len(v_stale) == 1 and v_stale[0].code == CODE_STALE
        assert v_stale[0].kind == ViolationKind.HARD

        # 5B. FriaTier with fresh local artefact + Live Wire ALLOW / REFUSE / ESCALATE
        fria_live = FriaTier(
            provider,
            region="EU_ECB",
            assessment_lookup=lambda _act: fresh_artefact,
            reassessment_interval_days=365,
            gate_timeout_seconds=15.0,
            clock=lambda: now_utc,
        )
        fria_allow_params = {
            **allow_payload["params"],
            "thread_id": allow_payload["thread_id"],
        }
        # Patch _payload on fria_live so the full envelope identifiers reach _build_cage_authority_request
        with patch.object(
            fria_live,
            "_payload",
            side_effect=lambda act, prms: {
                **allow_payload,
                "action": act,
                "params": dict(prms),
            },
        ):
            v_live_allow = await fria_live.evaluate(
                "payment.release", fria_allow_params
            )
            v_live_refuse = await fria_live.evaluate(
                "DELETE_ACCOUNT", fria_allow_params
            )
            v_live_escalate = await fria_live.evaluate(
                "payment.release", escalate_payload["params"]
            )

        print(f"  [5B.1] FriaTier Live ALLOW -> violations={v_live_allow}")
        print(
            f"  [5B.2] FriaTier Live REFUSE ('DELETE_ACCOUNT') -> "
            f"violations={[(v.code, v.kind.value) for v in v_live_refuse]}"
        )
        print(
            f"  [5B.3] FriaTier Live ESCALATE (Stale Screening) -> "
            f"violations={[(v.code, v.kind.value) for v in v_live_escalate]}"
        )
        assert v_live_allow == []
        assert len(v_live_refuse) == 1 and v_live_refuse[0].code == CODE_REJECTED
        assert v_live_refuse[0].kind == ViolationKind.HARD
        assert len(v_live_escalate) == 1 and v_live_escalate[0].code == CODE_HOLD
        assert v_live_escalate[0].kind == ViolationKind.HITL

        # 5C. Routing Seal (`cage-action/1`) post-issuance parameter mutation
        from src.gateway.governance.classification_engine import ClassificationEngine
        from src.gateway.governance.jwks import JWKSet
        from src.gateway.governance.narrower import NarrowerRegistry

        jwk_set = JWKSet()
        jwk_set.add_key(signer._public_key_pem)

        with (
            patch(
                "src.gateway.governance.routing_seal.get_governance_signer",
                return_value=signer,
            ),
            patch(
                "src.gateway.governance.jwks.get_jwks",
                return_value=jwk_set,
            ),
        ):
            seal = generate_seal(
                "payment.release",
                allow_payload["params"],
                record_hash="a" * 64,
            )
            # First confirm the unmutated params pass seal verification
            verify_seal(seal, "payment.release", allow_payload["params"])
            # Now mutate amount post-issuance and verify cage-action/1 digest rejection
            mutated_seal_params = {**allow_payload["params"], "amount": 999999.0}
            seal_tamper_blocked = False
            try:
                verify_seal(seal, "payment.release", mutated_seal_params)
            except SymbolicGovernorViolation as exc:
                seal_tamper_blocked = True
                print(
                    f"  [5C] Routing Seal Parameter Mutation Blocked -> {type(exc).__name__}: {exc}"
                )
            assert seal_tamper_blocked

        # 5D. SymbolicGovernor.revalidate_post_hitl() — Context Drift & Replay Refusal
        mock_opa = MagicMock()
        mock_opa.evaluate_policy = AsyncMock(return_value="ALLOW")
        mock_stpa = MagicMock()
        mock_stpa.validate_action = MagicMock(return_value=[])
        classifier = ClassificationEngine(narrower_registry=NarrowerRegistry())

        drift_barrier = _RecordingBarrier(refuse=True)
        gov_drift = SymbolicGovernor(
            GovernorComponents(
                opa=mock_opa,
                core_stages=kernel_stages(mock_opa, mock_stpa),
                classifier=classifier,
                domain_tiers=(drift_barrier,),
            )
        )
        spent_flags: list[bool] = []

        async def _spend_once() -> bool:
            if spent_flags:
                return False
            spent_flags.append(True)
            return True

        approval_for_drift = PostHitlApproval(
            approval_id="appr-step1-drift-001",
            barrier_preview="PASS",
            spend=_spend_once,
            thread_id=allow_payload["thread_id"],
        )
        drift_blocked = False
        with patch("src.gateway.governance.governor.verdicts.publish_refusal"):
            try:
                await gov_drift.revalidate_post_hitl(
                    "payment.release",
                    copy.deepcopy(allow_payload["params"]),
                    approval=approval_for_drift,
                )
            except GovernanceError as exc:
                drift_blocked = "APPROVAL_CONTEXT_DRIFT" in str(exc)
                print(
                    f"  [5D.1] Post-HITL Barrier Drift -> GovernanceError: {exc} "
                    f"(approval_spent={len(spent_flags) == 1})"
                )
        assert drift_blocked and len(spent_flags) == 1

        # Replay the now-spent approval against a clean barrier -> APPROVAL_NOT_REDEEMABLE
        clean_barrier = _RecordingBarrier(refuse=False)
        gov_clean = SymbolicGovernor(
            GovernorComponents(
                opa=mock_opa,
                core_stages=kernel_stages(mock_opa, mock_stpa),
                classifier=classifier,
                domain_tiers=(clean_barrier,),
            )
        )
        replay_approval_blocked = False
        with patch("src.gateway.governance.governor.verdicts.publish_refusal"):
            try:
                await gov_clean.revalidate_post_hitl(
                    "payment.release",
                    copy.deepcopy(allow_payload["params"]),
                    approval=approval_for_drift,
                )
            except GovernanceError as exc:
                replay_approval_blocked = "APPROVAL_NOT_REDEEMABLE" in str(exc)
                print(
                    f"  [5D.2] Post-HITL Spent Approval Replay -> GovernanceError: {exc} "
                    f"(barrier_commits={clean_barrier.commits}, rollbacks={clean_barrier.rollbacks})"
                )
        assert replay_approval_blocked
        assert clean_barrier.commits == ["payment.release"]
        assert clean_barrier.rollbacks == ["payment.release"]

        # =====================================================================
        # CASE 6: Consequence Refusal & Evidence Recording
        # =====================================================================
        print("\n" + "=" * 88)
        print("CASE 6: CONSEQUENCE REFUSAL & EVIDENCE STREAM RECORDING")
        print("=" * 88)

        event_Summary = [
            (
                e.get("type"),
                e.get("decision") or e.get("outcome"),
                e.get("reason_code") or e.get("finding_codes"),
            )
            for e in recorded_evidence_events
        ]
        for idx, (ev_type, ev_dec, ev_reason) in enumerate(event_Summary, 1):
            print(
                f"  [6A.{idx}] Evidence Event: type={ev_type}, outcome={ev_dec}, reason={ev_reason}"
            )

        recorded_types = {e.get("type") for e in recorded_evidence_events}
        assert "CONSEQUENCE_GATEWAY_DECISION" in recorded_types
        assert "CONSEQUENCE_GATEWAY_REFUSAL" in recorded_types
        assert "ACTUATION_REFUSAL_RECEIPT" in recorded_types

        # 6B. Fail-closed downgrade to BLOCK (EVIDENCE_CHAIN_UNAVAILABLE) when sink fails on EXECUTE
        fresh_token = ConsequenceToken.mint(
            sub=allow_payload["actor_id"],
            tid=allow_payload["thread_id"],
            rec="rec-evidence-outage-001",
            act=verified_claims.act,
            ver="1",
            ttl_seconds=60,
            signer=signer,
        )
        broken_sink = MagicMock()
        broken_sink.ingest = AsyncMock(
            side_effect=EvidenceChainUnavailableError(
                "ClickHouse/Redis stream unreachable"
            )
        )
        with patch(
            "src.gateway.governance.evidence.stream.get_evidence_sink",
            return_value=broken_sink,
        ):
            eval_sink_down = await consequence_gateway.evaluate(
                fresh_token, allow_payload
            )
        print(
            f"  [6B] Evidence Sink Outage on EXECUTE -> downgraded decision={eval_sink_down.decision.value}, "
            f"reason_code={eval_sink_down.reason_code}"
        )
        assert eval_sink_down.decision == ConsequenceDecision.BLOCK
        assert eval_sink_down.reason_code == "EVIDENCE_CHAIN_UNAVAILABLE"

    print("\n" + "=" * 88)
    print("ALL 6 PHASE 4 STEP 1 LIVE WIRE & CROSS-BOUNDARY CASES VERIFIED: 100% PASS")
    print("=" * 88)


if __name__ == "__main__":
    asyncio.run(main())
