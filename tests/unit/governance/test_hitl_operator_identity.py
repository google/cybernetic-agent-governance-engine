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

"""Unit and structural tests for POAM-2026-196 HITL human operator binding and R-2 telemetry secret split."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from pydantic import ValidationError

from scripts import cage_hitl_review
from src.compliance_bridge import main as bridge_main
from src.compliance_bridge.auth import (
    OperatorPrincipal,
    _load_operator_jwks_by_kid,
    ensure_human_operator_principal,
    is_workload_identity,
    require_human_operator_identity,
    require_operator_identity,
    validate_operator_identity_posture,
    validate_operator_oidc_token,
)
from src.compliance_bridge.main import DeferEscalateRequest, defer_escalate
from src.gateway.governance.defer_queue import (
    ApprovalRecord,
    ApprovalStatus,
    DeferQueue,
    DeferReason,
    DeferToken,
)
from src.gateway.governance.evidence.stream import EvidenceChainUnavailableError
from src.gateway.governance.governor.verdicts import _park_defer_context

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[3]


def _make_mock_pipe() -> MagicMock:
    pipe = MagicMock()
    pipe.execute = AsyncMock(return_value=[])
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=None)
    return pipe


def _make_valid_webauthn_binding(
    seed: bytes = b"cage-hitl-challenge-01",
    *,
    ceremony_type: str = "webauthn.get",
) -> tuple[str, str]:
    """Return ``(client_data_json_b64, challenge_binding_hex)`` for W3C WebAuthn tests."""
    challenge_bytes = hashlib.sha256(seed).digest()
    challenge_binding = challenge_bytes.hex()
    challenge_b64 = (
        base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode("ascii")
    )
    client_data_bytes = json.dumps(
        {
            "type": ceremony_type,
            "challenge": challenge_b64,
            "origin": "https://console.cage.example",
        }
    ).encode("utf-8")
    client_data_json = (
        base64.urlsafe_b64encode(client_data_bytes).rstrip(b"=").decode("ascii")
    )
    return client_data_json, challenge_binding


def _generate_es256_jwk_and_key(kid: str = "hitl-kid-1") -> tuple[Any, dict[str, Any]]:
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_jwk = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(priv_key.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "ES256"
    return priv_key, pub_jwk


def _mint_oidc_jwt(
    priv_key: Any,
    *,
    sub: str,
    kid: str = "hitl-kid-1",
    issuer: str = "https://idp.cage.example",
    audience: str = "cage-compliance-bridge",
    exp_offset_s: int = 300,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    headers: dict[str, Any] = {"kid": kid}
    if extra_headers:
        headers.update(extra_headers)
    return pyjwt.encode(
        {
            "sub": sub,
            "iss": issuer,
            "aud": audience,
            "iat": now - 5,
            "nbf": now - 5,
            "exp": now + exp_offset_s,
        },
        priv_key,
        algorithm="ES256",
        headers=headers,
    )


class TestHitlWorkloadRefusalAndPosture:
    """POAM-2026-196 (F-40, F-41, D-196-1): HITL approvals are human acts."""

    @pytest.mark.parametrize(
        "urn",
        [
            "spiffe://cluster.local/ns/governance-stack/sa/risk-officer-alice",
            "principal://agents.global.org-123.system.id.goog/resources/agents/a1",
            "governed-financial-advisor.governance-stack.serviceaccount.identity.linkerd.cluster.local",
            "compliance-bridge.governance-stack.svc.cluster.local",
        ],
    )
    def test_is_workload_identity_detects_machine_principals(self, urn: str) -> None:
        assert is_workload_identity(urn) is True

    def test_is_workload_identity_allows_human_principals(self) -> None:
        assert is_workload_identity("risk-officer-alice@example.com") is False
        assert is_workload_identity("oidc:https://idp.cage.example#alice") is False

    def test_defer_escalate_request_forbids_self_asserted_identity_fields(self) -> None:
        with pytest.raises(ValidationError):
            DeferEscalateRequest(operator_urn="alice@example.com")  # type: ignore[call-arg]

    @pytest.mark.asyncio
    async def test_svid_principal_refused_by_ensure_human_and_defer_escalate(
        self,
    ) -> None:
        svid_principal = OperatorPrincipal(
            operator_urn="spiffe://cluster.local/ns/governance-stack/sa/governed-financial-advisor",
            channel_provenance="SVID",
            auth_principal_hash="a" * 64,
        )
        with pytest.raises(HTTPException) as exc_info:
            ensure_human_operator_principal(svid_principal)
        assert exc_info.value.status_code == 403
        assert "Workload identities (SVID) cannot approve HITL escalations" in str(
            exc_info.value.detail
        )

        with pytest.raises(HTTPException) as route_exc:
            await defer_escalate(
                defer_id="defer-test-123",
                body=DeferEscalateRequest(),
                operator=svid_principal,
            )
        assert route_exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_human_oidc_defer_escalate_succeeds_without_internal_token_and_enforces_webauthn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.governance import defer_queue as dq_mod

        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.setenv("CAGE_TRUSTED_OPERATOR_IDENTITIES", "alice@example.com")
        monkeypatch.delenv("CAGE_INTERNAL_TOKEN", raising=False)
        monkeypatch.delenv("COMPLIANCE_BRIDGE_INTERNAL_TOKEN", raising=False)

        human_principal = OperatorPrincipal(
            operator_urn="alice@example.com",
            channel_provenance="OIDC",
            auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
        )

        # 1. Enforcing posture rejects missing WebAuthn binding with HTTP 400
        with pytest.raises(HTTPException) as missing_exc:
            await defer_escalate(
                defer_id="defer-enforcing-1",
                body=DeferEscalateRequest(),
                operator=human_principal,
            )
        assert missing_exc.value.status_code == 400
        assert isinstance(missing_exc.value.detail, dict)
        assert missing_exc.value.detail["error"] == "WEBAUTHN_BINDING_REQUIRED"

        # 2. Enforcing posture rejects mismatched WebAuthn challenge binding with HTTP 400
        client_data_json, _ = _make_valid_webauthn_binding(b"seed-a")
        _, wrong_binding = _make_valid_webauthn_binding(b"seed-b")
        monkeypatch.setattr(
            bridge_main, "_resolve_defer_redis_url", lambda: "redis://localhost:6379/1"
        )
        monkeypatch.setattr(bridge_main, "_get_defer_queue_cls", lambda: DeferQueue)

        with pytest.raises(HTTPException) as mismatch_exc:
            await defer_escalate(
                defer_id="defer-enforcing-1",
                body=DeferEscalateRequest(
                    client_data_json=client_data_json,
                    challenge_binding=wrong_binding,
                ),
                operator=human_principal,
            )
        assert mismatch_exc.value.status_code == 400
        assert isinstance(mismatch_exc.value.detail, dict)
        assert mismatch_exc.value.detail["error"] == "APPROVAL_VALIDATION_FAILED"

        # 3. Valid WebAuthn binding + human OIDC principal succeeds without CAGE_INTERNAL_TOKEN
        valid_cdj, valid_binding = _make_valid_webauthn_binding(b"seed-valid")
        parked_tok = DeferToken(
            defer_id="defer-enforcing-1",
            thread_id="thr-enforcing-1",
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
            initiator_urn="spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
        )
        mock_queue = AsyncMock()
        mock_queue.approve = AsyncMock(
            return_value=(ApprovalStatus.PARTIAL_QUORUM, parked_tok)
        )
        monkeypatch.setattr(
            dq_mod, "get_shared_defer_queue", lambda *_a, **_kw: mock_queue
        )

        resp = await defer_escalate(
            defer_id="defer-enforcing-1",
            body=DeferEscalateRequest(
                client_data_json=valid_cdj,
                challenge_binding=valid_binding,
            ),
            operator=human_principal,
        )
        assert resp.status_code == 200
        payload = json.loads(bytes(resp.body).decode("utf-8"))
        assert payload["status"] == "partially_approved"
        assert payload["defer_id"] == "defer-enforcing-1"

    @pytest.mark.asyncio
    async def test_require_human_operator_identity_refuses_linkerd_svid_request(
        self,
    ) -> None:
        from starlette.datastructures import Headers

        request = MagicMock()
        request.headers = Headers(
            raw=[
                (
                    b"l5d-client-id",
                    b"risk-officer-alice.governance-stack.serviceaccount.identity.linkerd.cluster.local",
                )
            ]
        )
        request.attributes = None
        # Non-loopback pod IP so Linkerd proxy check passes and SVID channel is reached
        request.scope = {
            "client": ("10.24.1.7", 50000),
            "server": ("10.24.1.7", 3001),
        }

        with pytest.raises(HTTPException) as exc_info:
            await require_human_operator_identity(request)
        assert exc_info.value.status_code == 403

    def test_validate_operator_identity_posture_fails_closed_when_empty_in_enforcing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "staging")
        monkeypatch.delenv("CAGE_TRUSTED_OPERATOR_IDENTITIES", raising=False)

        with pytest.raises(
            RuntimeError, match="CAGE_TRUSTED_OPERATOR_IDENTITIES is empty"
        ):
            validate_operator_identity_posture()

    def test_validate_operator_identity_posture_rejects_workload_entry_in_any_posture(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "dev")
        monkeypatch.setenv(
            "CAGE_TRUSTED_OPERATOR_IDENTITIES",
            "alice@example.com,spiffe://cluster.local/ns/governance-stack/sa/gateway",
        )

        with pytest.raises(
            RuntimeError,
            match="Workload identity .* is not permitted in CAGE_TRUSTED_OPERATOR_IDENTITIES",
        ):
            validate_operator_identity_posture()

    def test_validate_operator_identity_posture_validates_jwks_uri_and_accepts_human_allowlist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_ENV", "production")
        monkeypatch.setenv(
            "CAGE_TRUSTED_OPERATOR_IDENTITIES",
            "alice@example.com,bob@example.com",
        )
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_URI", "file:///etc/passwd")
        with pytest.raises(RuntimeError, match="Invalid CAGE_OPERATOR_JWKS_URI"):
            validate_operator_identity_posture()

        monkeypatch.setenv(
            "CAGE_OPERATOR_JWKS_URI",
            "https://idp.cage.example/.well-known/jwks.json",
        )
        validate_operator_identity_posture()


class TestEnforcingWebAuthnChallengeBinding:
    """POAM-2026-196: Mandatory W3C WebAuthn challenge binding in enforcing postures."""

    @pytest.mark.asyncio
    async def test_approval_record_and_defer_queue_enforce_webauthn_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Construct un-bound record in test posture first to test DeferQueue.approve defense-in-depth
        monkeypatch.setenv("CAGE_ENV", "test")
        unbound_record = ApprovalRecord(
            approver_urn="alice@example.com",
            approved_at_utc="2026-11-08T12:00:00Z",
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
        )

        # Switch to enforcing production posture
        monkeypatch.setenv("CAGE_ENV", "production")

        with pytest.raises(
            ValueError,
            match="WebAuthn client_data_json and challenge_binding are mandatory",
        ):
            ApprovalRecord(
                approver_urn="alice@example.com",
                approved_at_utc="2026-11-08T12:00:00Z",
                auth_method="OIDC",
                auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
            )

        # Wrong WebAuthn ceremony type (webauthn.create instead of webauthn.get) rejected
        bad_type_cdj, bad_type_binding = _make_valid_webauthn_binding(
            b"ceremony-check", ceremony_type="webauthn.create"
        )
        with pytest.raises(
            ValueError, match="WebAuthn challenge binding verification failed"
        ):
            ApprovalRecord(
                approver_urn="alice@example.com",
                approved_at_utc="2026-11-08T12:00:00Z",
                auth_method="OIDC",
                auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
                client_data_json=bad_type_cdj,
                challenge_binding=bad_type_binding,
            )

        # DeferQueue.approve also rejects pre-constructed unbound ApprovalRecord in production
        mock_redis = AsyncMock()
        queue = DeferQueue(mock_redis)
        with pytest.raises(
            ValueError,
            match="WebAuthn client_data_json and challenge_binding are mandatory",
        ):
            await queue.approve("defer-prod-1", unbound_record)
        mock_redis.hmget.assert_not_awaited()

        # Valid webauthn.get challenge binding succeeds and populates client_data_hash
        valid_cdj, valid_binding = _make_valid_webauthn_binding(b"prod-challenge-ok")
        valid_record = ApprovalRecord(
            approver_urn="alice@example.com",
            approved_at_utc="2026-11-08T12:00:00Z",
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
            client_data_json=valid_cdj,
            challenge_binding=valid_binding,
        )
        assert valid_record.verify_webauthn_challenge() is True
        assert valid_record.client_data_hash is not None
        assert len(valid_record.client_data_hash) == 64


class TestOidcKidVerificationAndAllowlist:
    """POAM-2026-196 (F-40, F-41, D-196-1): Out-of-band kid-resolved OIDC verification."""

    @pytest.mark.asyncio
    async def test_unverified_request_state_jwt_claims_shortcut_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "true")
        monkeypatch.setenv("CAGE_TRUSTED_OPERATOR_IDENTITIES", "alice@example.com")

        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer not-a-signed-jwt"}
        mock_request.attributes = None
        mock_request.state = MagicMock()
        mock_request.state.jwt_claims = {"sub": "alice@example.com"}

        with pytest.raises(HTTPException) as exc_info:
            await require_operator_identity(mock_request)
        assert exc_info.value.status_code == 401
        assert "OIDC JWT validation failed" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_kid_verified_oidc_token_succeeds_and_empty_allowlist_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        priv_key, pub_jwk = _generate_es256_jwk_and_key("kid-2026-11")
        monkeypatch.setenv("CAGE_OPERATOR_IDENTITY_ALLOW_OIDC", "true")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_ISSUER", "https://idp.cage.example")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_AUDIENCE", "cage-compliance-bridge")
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_JSON", json.dumps({"keys": [pub_jwk]}))
        token = _mint_oidc_jwt(priv_key, sub="alice@example.com", kid="kid-2026-11")

        # Empty allowlist must fail closed with 403 even when signature is valid
        monkeypatch.setenv("CAGE_TRUSTED_OPERATOR_IDENTITIES", "")
        mock_request = MagicMock()
        mock_request.headers = {"x-cage-operator-token": token}
        mock_request.attributes = None

        with pytest.raises(HTTPException) as empty_exc:
            await require_human_operator_identity(mock_request)
        assert empty_exc.value.status_code == 403
        assert "CAGE_TRUSTED_OPERATOR_IDENTITIES is empty" in str(
            empty_exc.value.detail
        )

        # Populating the human allowlist admits the verified operator
        monkeypatch.setenv(
            "CAGE_TRUSTED_OPERATOR_IDENTITIES", "alice@example.com,bob@example.com"
        )
        principal = await require_human_operator_identity(mock_request)
        assert principal.operator_urn == "alice@example.com"
        assert principal.channel_provenance == "OIDC"

    @pytest.mark.asyncio
    async def test_embedded_jwk_header_and_unknown_kid_and_wrong_claims_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        priv_key, pub_jwk = _generate_es256_jwk_and_key("kid-trusted")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_ISSUER", "https://idp.cage.example")
        monkeypatch.setenv("CAGE_OPERATOR_OIDC_AUDIENCE", "cage-compliance-bridge")
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_JSON", json.dumps({"keys": [pub_jwk]}))

        # 1. Embedded jwk header rejected
        tok_embedded = _mint_oidc_jwt(
            priv_key,
            sub="alice@example.com",
            kid="kid-trusted",
            extra_headers={"jwk": pub_jwk},
        )
        ok, _, reason = await validate_operator_oidc_token(tok_embedded)
        assert not ok
        assert "embedded key header" in reason

        # 2. Unknown kid rejected
        tok_unknown_kid = _mint_oidc_jwt(
            priv_key, sub="alice@example.com", kid="kid-unknown"
        )
        ok, _, reason = await validate_operator_oidc_token(tok_unknown_kid)
        assert not ok
        assert "unknown kid" in reason

        # 3. Wrong issuer rejected
        tok_bad_iss = _mint_oidc_jwt(
            priv_key,
            sub="alice@example.com",
            kid="kid-trusted",
            issuer="https://evil.example",
        )
        ok, _, reason = await validate_operator_oidc_token(tok_bad_iss)
        assert not ok
        assert "JWT verification failed" in reason

        # 4. Wrong audience rejected
        tok_bad_aud = _mint_oidc_jwt(
            priv_key,
            sub="alice@example.com",
            kid="kid-trusted",
            audience="wrong-audience",
        )
        ok, _, reason = await validate_operator_oidc_token(tok_bad_aud)
        assert not ok
        assert "JWT verification failed" in reason

    def test_private_jwk_material_rejected_by_jwks_loader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        priv_jwk = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(priv_key))
        priv_jwk["kid"] = "leaked-priv-kid"
        monkeypatch.setenv("CAGE_OPERATOR_JWKS_JSON", json.dumps({"keys": [priv_jwk]}))
        assert "leaked-priv-kid" not in _load_operator_jwks_by_kid()


class TestInitiatorSeparationOfDutiesAndQuorum:
    """POAM-2026-196 (F-42, F-44, D-196-2): verified caller precedence, SoD, and #685 rollback."""

    @pytest.mark.asyncio
    async def test_park_defer_context_prefers_verified_caller_over_params_and_preserves_rollback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.gateway.governance import defer_queue as dq_mod
        from src.gateway.governance.governor import verdicts as verdicts_mod

        mock_redis = AsyncMock()
        mock_queue = AsyncMock()
        mock_queue._redis = mock_redis
        mock_queue.park = AsyncMock(
            side_effect=["defer-bound-1", "defer-bound-2", "defer-rollback-3"]
        )

        @asynccontextmanager
        async def fake_open_defer_queue() -> AsyncIterator[Any]:
            yield mock_queue

        monkeypatch.setattr(dq_mod, "open_defer_queue", fake_open_defer_queue)
        monkeypatch.setattr(verdicts_mod, "publish_deferral", AsyncMock())

        # 1. Verified transport caller identity wins FIRST over caller-supplied params/metadata (F-44)
        from src.gateway.server import workload_identity as wi_mod

        monkeypatch.setattr(
            wi_mod,
            "current_client_identity",
            lambda: "spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa",
        )
        defer_id_1, persisted_1 = await _park_defer_context(
            action="execute_trade",
            params={
                "symbol": "AAPL",
                "amount": 50000,
                "user_id": "spoofed@example.com",
                "initiator_urn": "spoofed@example.com",
            },
            metadata={
                "trace_id": "trace-sod-1",
                "initiator_urn": "spoofed@example.com",
            },
            thread_id="thread-sod-1",
            confidence=0.62,
            classification_meta={"classification_reason": "CONFIDENCE_BELOW_THRESHOLD"},
            violations=[],
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        )
        assert defer_id_1 == "defer-bound-1"
        assert persisted_1 is True
        parked_token_1: DeferToken = mock_queue.park.await_args_list[0].args[0]
        assert (
            parked_token_1.initiator_urn
            == "spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa"
        )
        assert (
            parked_token_1.opa_input_snapshot["initiator_urn"]
            == "spiffe://cluster.local/ns/governance-stack/sa/cage-advisor-sa"
        )

        # 2. In-process evaluation (no transport caller context) falls back to params["user_id"]
        monkeypatch.setattr(wi_mod, "current_client_identity", lambda: None)
        defer_id_2, persisted_2 = await _park_defer_context(
            action="execute_trade",
            params={"symbol": "AAPL", "amount": 50000, "user_id": "alice@example.com"},
            metadata={"trace_id": "trace-sod-2"},
            thread_id="thread-sod-2",
            confidence=0.62,
            classification_meta={"classification_reason": "CONFIDENCE_BELOW_THRESHOLD"},
            violations=[],
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
        )
        assert defer_id_2 == "defer-bound-2"
        assert persisted_2 is True
        parked_token_2: DeferToken = mock_queue.park.await_args_list[1].args[0]
        assert parked_token_2.initiator_urn == "alice@example.com"
        assert parked_token_2.opa_input_snapshot["initiator_urn"] == "alice@example.com"

        # 3. Blocking evidence-chain failure unparks newly parked DeferToken (#685 invariant)
        monkeypatch.setattr(
            verdicts_mod,
            "publish_deferral",
            AsyncMock(side_effect=EvidenceChainUnavailableError("stream down")),
        )
        with pytest.raises(EvidenceChainUnavailableError, match="stream down"):
            await _park_defer_context(
                action="execute_trade",
                params={
                    "symbol": "AAPL",
                    "amount": 50000,
                    "user_id": "alice@example.com",
                },
                metadata={"trace_id": "trace-sod-3"},
                thread_id="thread-sod-3",
                confidence=0.62,
                classification_meta={
                    "classification_reason": "CONFIDENCE_BELOW_THRESHOLD"
                },
                violations=[],
                defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
            )
        mock_redis.delete.assert_awaited_once_with("DEFER:defer-rollback-3")
        mock_redis.zrem.assert_awaited_once_with(
            "DEFER:expiry_index", "defer-rollback-3"
        )

    @pytest.mark.asyncio
    async def test_self_approval_refused_and_distinct_human_quorum_succeeds(
        self,
    ) -> None:
        token = DeferToken(
            thread_id="thread-sod-2",
            defer_reason=DeferReason.CONFIDENCE_BELOW_THRESHOLD,
            initiator_urn="alice@example.com",
            opa_input_snapshot={"initiator_urn": "alice@example.com"},
        )
        mock_redis = AsyncMock()
        mock_redis.hmget = AsyncMock(
            return_value=(token.model_dump_json(), "PARKED", "0")
        )
        mock_redis.script_load = AsyncMock(return_value="cas-sha-1")
        mock_redis.evalsha = AsyncMock(side_effect=[[1, 1], [1, 2]])
        mock_redis.zrem = AsyncMock(return_value=1)
        mock_redis.pipeline = MagicMock(return_value=_make_mock_pipe())

        queue = DeferQueue(mock_redis)

        # Initiator alice cannot approve her own deferred action
        alice_approval = ApprovalRecord(
            approver_urn="alice@example.com",
            approved_at_utc="2026-11-05T12:00:00Z",
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"alice@example.com").hexdigest(),
        )
        with pytest.raises(ValueError, match="Separation-of-duties violation"):
            await queue.approve("defer-sod-2", alice_approval)

        # First distinct human reviewer (bob) reaches PARTIAL_QUORUM (1 of 2)
        bob_approval = ApprovalRecord(
            approver_urn="bob@example.com",
            approved_at_utc="2026-11-05T12:01:00Z",
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"bob@example.com").hexdigest(),
        )
        status_1, tok_1 = await queue.approve("defer-sod-2", bob_approval)
        assert status_1 == ApprovalStatus.PARTIAL_QUORUM
        assert tok_1 is not None
        assert len(tok_1.approvals) == 1

        # Second distinct human reviewer (carol) reaches QUORUM_REACHED (2 of 2)
        mock_redis.hmget = AsyncMock(
            return_value=(tok_1.model_dump_json(), "PARTIALLY_APPROVED", "1")
        )
        carol_approval = ApprovalRecord(
            approver_urn="carol@example.com",
            approved_at_utc="2026-11-05T12:02:00Z",
            auth_method="OIDC",
            auth_principal_hash=hashlib.sha256(b"carol@example.com").hexdigest(),
        )
        status_2, tok_2 = await queue.approve("defer-sod-2", carol_approval)
        assert status_2 == ApprovalStatus.QUORUM_REACHED
        assert tok_2 is not None
        assert tok_2.resolution == "ESCALATED"


class TestTerraformTelemetrySecretSplit:
    """R-2 (F-43, F-84) & POAM-2026-196: Gateway/advisor secret split and bridge OIDC wiring."""

    def test_app_secrets_removes_internal_token_from_advisor_and_isolates_gateway_secrets(
        self,
    ) -> None:
        app_secrets_tf = (
            REPO_ROOT / "infra" / "modules" / "app_secrets" / "main.tf"
        ).read_text(encoding="utf-8")
        advisor_block = app_secrets_tf.split(
            'resource "kubernetes_secret" "advisor_secrets"', 1
        )[1].split("\nresource ", 1)[0]
        assert "CAGE_INTERNAL_TOKEN" not in advisor_block
        assert "gateway_telemetry_secrets" not in app_secrets_tf

        gw_secrets_block = app_secrets_tf.split(
            'resource "kubernetes_secret" "gateway_secrets"', 1
        )[1].split("\nresource ", 1)[0]
        assert 'name      = "gateway-secrets"' in gw_secrets_block
        for expected_key in (
            "TELEMETRY_PUBLIC_KEY",
            "TELEMETRY_SECRET_KEY",
            "OTEL_EXPORTER_OTLP_HEADERS",
            "REDIS_PASSWORD",
        ):
            assert expected_key in gw_secrets_block
        assert "precondition" in gw_secrets_block
        assert (
            "var.gateway_langfuse_public_key != var.langfuse_public_key"
            in gw_secrets_block
        )

    def test_gateway_and_compliance_bridge_modules_enforce_partition_and_oidc_wiring(
        self,
    ) -> None:
        gateway_tf = (
            REPO_ROOT / "infra" / "modules" / "gateway" / "main.tf"
        ).read_text(encoding="utf-8")
        assert not re.search(r'name\s*=\s*"advisor-secrets"', gateway_tf)
        assert not re.search(r'name\s*=\s*"gateway-telemetry-secrets"', gateway_tf)
        secret_refs = re.findall(
            r'name\s*=\s*(?:"gateway-secrets"|var\.gateway_secret_name|local\.telemetry_secret_name)',
            gateway_tf,
        )
        assert len(secret_refs) == 5

        bridge_tf = (
            REPO_ROOT / "infra" / "modules" / "compliance_bridge" / "main.tf"
        ).read_text(encoding="utf-8")
        for expected_env in (
            "CAGE_OPERATOR_IDENTITY_ALLOW_OIDC",
            "CAGE_TRUSTED_OPERATOR_IDENTITIES",
            "CAGE_OPERATOR_OIDC_ISSUER",
            "CAGE_OPERATOR_OIDC_AUDIENCE",
            "CAGE_OPERATOR_JWKS_URI",
        ):
            assert expected_env in bridge_tf
        assert "precondition" in bridge_tf


class TestCageHitlReviewCli:
    """POAM-2026-196 (F-44, D-196-3): Operator HITL review CLI contract."""

    def test_validate_http_url_enforces_scheme(self) -> None:
        assert (
            cage_hitl_review.validate_http_url("https://bridge.internal:3001/")
            == "https://bridge.internal:3001"
        )
        with pytest.raises(ValueError, match="scheme must be http"):
            cage_hitl_review.validate_http_url("file:///etc/passwd")
        with pytest.raises(ValueError, match="scheme must be http"):
            cage_hitl_review.validate_http_url("ftp://bridge.internal/v1")

    def test_cli_rejects_missing_or_svid_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CAGE_OPERATOR_OIDC_TOKEN", raising=False)
        with pytest.raises(ValueError, match="Human OIDC JWT is required"):
            cage_hitl_review.cmd_approve(
                "https://bridge.internal:3001", "def-001", oidc_token=None
            )

        with pytest.raises(ValueError, match="Workload SVIDs cannot be used"):
            cage_hitl_review._build_headers(
                oidc_token="spiffe://cluster.local/ns/governance-stack/sa/gateway"
            )

    def test_cli_list_inspect_and_approve_roundtrip(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("CAGE_INTERNAL_TOKEN", "internal-read-only-token")
        captured_calls: list[
            tuple[str, str, dict[str, str], dict[str, Any] | None]
        ] = []

        def fake_request_json(
            method: str,
            url: str,
            *,
            headers: dict[str, str],
            payload: dict[str, Any] | None = None,
            timeout: float = 15.0,
        ) -> tuple[int, dict[str, Any]]:
            assert "Bearer " in headers.get("Authorization", "")
            captured_calls.append((method, url, dict(headers), payload))
            if "/v1/defer/pending" in url:
                return 200, {
                    "count": 1,
                    "pending": [
                        {
                            "defer_id": "def-001",
                            "thread_id": "thr-1",
                            "reason": "CONFIDENCE_BELOW_THRESHOLD",
                            "initiator_urn": "trader-1@example.com",
                        }
                    ],
                }
            return 200, {
                "status": "partially_approved",
                "defer_id": "def-001",
                "approvals_recorded": 1,
                "required_quorum": 2,
            }

        monkeypatch.setattr(cage_hitl_review, "_request_json", fake_request_json)
        valid_cdj, valid_binding = _make_valid_webauthn_binding(b"cli-webauthn")

        rc_list = cage_hitl_review.main(
            [
                "--bridge-url",
                "https://bridge.internal:3001",
                "--oidc-token",
                "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC0xIn0.payload.sig",
                "list",
            ]
        )
        assert rc_list == 0

        rc_inspect = cage_hitl_review.main(
            [
                "--bridge-url",
                "https://bridge.internal:3001",
                "--oidc-token",
                "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC0xIn0.payload.sig",
                "inspect",
                "def-001",
            ]
        )
        assert rc_inspect == 0

        rc_approve = cage_hitl_review.main(
            [
                "--bridge-url",
                "https://bridge.internal:3001",
                "--oidc-token",
                "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZC0xIn0.payload.sig",
                "approve",
                "def-001",
                "--client-data-json",
                valid_cdj,
                "--challenge-binding",
                valid_binding,
            ]
        )
        assert rc_approve == 0
        assert len(captured_calls) == 3
        approve_method, approve_url, approve_headers, approve_payload = captured_calls[
            2
        ]
        assert approve_method == "POST"
        assert approve_url.endswith("/v1/defer/def-001/escalate")
        assert "X-Cage-Internal-Token" not in approve_headers
        assert approve_payload == {
            "client_data_json": valid_cdj,
            "challenge_binding": valid_binding,
        }
        out = capsys.readouterr().out
        assert "partially_approved" in out
