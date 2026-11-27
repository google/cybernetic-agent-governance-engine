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

"""Unit tests for request-bound, KMS-signed CommitOutcome verification (POAM-2026-249)."""

from __future__ import annotations
import __future__

import importlib
import inspect
import json
import os
import textwrap
from collections.abc import Awaitable, Callable
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from mcp.types import CallToolResult, TextContent
from starlette.requests import Request

import src.gateway.governance.commit_outcome as co_mod
from src.gateway.governance.commit_outcome import (
    COMMIT_OUTCOME_SCHEMA,
    ApprovalRedemptionRefusal,
    CommitOutcome,
    CommitOutcomeDecodeError,
    CommitStatus,
    extract_request_idempotency_key,
    sign_commit_outcome_wire,
    signed_commit_tool_result,
    verify_commit_outcome_wire,
)
from src.gateway.governance.execution_idempotency import UnsettledDuplicate
from src.gateway.governance.governor.verdicts import GovernanceDeferred
from src.gateway.governance.jwks import pem_to_jwk
from src.gateway.governance.seams.actuation import (
    ActuationIndeterminateError,
    ActuationRejectedError,
)
from src.gateway.infrastructure.mcp_client import (
    GatewayMCPClient,
    MCPCommitOutcomeUnrecognizedError,
)
from src.gateway.observability.mcp_tracing import _sign_mcp_commit_result
from src.gateway.server import governance_middleware as gm
from src.gateway.server import mcp_tool_server as mts
from src.gateway.server import workload_identity as wid
from src.gateway.server.governance_middleware import ActionDeferred

pytestmark = [pytest.mark.unit, pytest.mark.local]

_CALLER = (
    "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
)
_KEY_1 = "11111111-2222-4333-8444-555555555555"
_KEY_2 = "66666666-7777-4888-9999-aaaaaaaaaaaa"


class _EphemeralAsymmetricSigner:
    """Test signer implementing the active KMSGovernanceSigner interface."""

    def __init__(self, alg: str, kid_override: str | None = None) -> None:
        self.is_kms_active = True
        self.kms_active = True
        self._alg = alg
        if alg == "ES256":
            self._priv = ec.generate_private_key(ec.SECP256R1())
        elif alg == "EdDSA":
            self._priv = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported test alg {alg}")
        pub_pem = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk = pem_to_jwk(pub_pem)
        jwk["alg"] = alg
        if kid_override is not None:
            jwk["kid"] = kid_override
        self._jwk = jwk

    @property
    def public_jwk(self) -> dict[str, Any]:
        return dict(self._jwk)

    async def sign_raw_async(self, message: bytes) -> bytes:
        assert isinstance(self._priv, ed25519.Ed25519PrivateKey)
        return self._priv.sign(message)

    async def sign_precomputed_digest_async(self, digest: bytes) -> str:
        from cryptography.hazmat.primitives.asymmetric import utils

        assert isinstance(self._priv, ec.EllipticCurvePrivateKey)
        sig_der = self._priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return sig_der.hex()


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
async def test_sign_and_verify_round_trip_with_request_binding(alg: str) -> None:
    signer = _EphemeralAsymmetricSigner(alg)
    jwk = signer.public_jwk
    outcome = CommitOutcome(
        CommitStatus.EXECUTED,
        "FILLED order-123",
    )

    signed = await sign_commit_outcome_wire(
        outcome,
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        issued_at="2020-01-01T00:00:00.000Z",  # Informational only; not TTL-rejected
        signer=signer,
    )
    assert signed["schema"] == COMMIT_OUTCOME_SCHEMA
    assert signed["tool_name"] == "execute_trade_action"
    assert signed["idempotency_key"] == _KEY_1
    assert signed["issued_at"] == "2020-01-01T00:00:00.000Z"
    assert signed["signature"]["algorithm"] == alg
    assert signed["signature"]["kid"] == jwk["kid"]

    decoded = await verify_commit_outcome_wire(
        signed,
        public_keys={jwk["kid"]: jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_1,
    )
    assert decoded.status is CommitStatus.EXECUTED
    assert decoded.tool_name == "execute_trade_action"
    assert decoded.idempotency_key == _KEY_1
    assert decoded.issued_at == "2020-01-01T00:00:00.000Z"


async def test_verify_rejects_tampered_fields_and_request_replay() -> None:
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    keys = {jwk["kid"]: jwk}
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )

    # 1. Cross-tool substitution fails closed.
    with pytest.raises(CommitOutcomeDecodeError, match="tool_name mismatch"):
        await verify_commit_outcome_wire(
            signed,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="administer_dose",
            expected_idempotency_key=_KEY_1,
        )

    # 2. Cross-request idempotency_key replay fails closed.
    with pytest.raises(CommitOutcomeDecodeError, match="idempotency_key"):
        await verify_commit_outcome_wire(
            signed,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_2,
        )

    # 3. Stripping bound fields after signing fails signature / missing-binding check.
    stripped = {k: v for k, v in signed.items() if k != "idempotency_key"}
    with pytest.raises(CommitOutcomeDecodeError):
        await verify_commit_outcome_wire(
            stripped,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    # 4. Payload tampering breaks JCS signature verification.
    tampered = dict(signed, status="REFUSED")
    with pytest.raises(CommitOutcomeDecodeError, match="signature invalid"):
        await verify_commit_outcome_wire(
            tampered,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )


async def test_unknown_kid_and_embedded_keys_fail_closed_in_all_postures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    signed = await sign_commit_outcome_wire(
        CommitOutcome(
            CommitStatus.REFUSED, "blocked", ApprovalRedemptionRefusal.PENDING
        ),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )

    # Unknown kid in dev/test posture MUST STILL FAIL CLOSED (empty public_keys map).
    with pytest.raises(CommitOutcomeDecodeError, match="unknown kid"):
        await verify_commit_outcome_wire(
            signed,
            public_keys={},
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    # Embedded public key material must always be rejected.
    with_jwk = dict(signed, jwk=jwk)
    with pytest.raises(CommitOutcomeDecodeError, match="embedded key material"):
        await verify_commit_outcome_wire(with_jwk, public_keys={jwk["kid"]: jwk})

    sig_with_jwk = dict(signed)
    sig_with_jwk["signature"] = {**signed["signature"], "jwk": jwk}
    with pytest.raises(CommitOutcomeDecodeError, match="unexpected fields"):
        await verify_commit_outcome_wire(sig_with_jwk, public_keys={jwk["kid"]: jwk})

    # Unsupported algorithm in signature fails closed.
    bad_alg = dict(signed)
    bad_alg["signature"] = {**signed["signature"], "algorithm": "HS256"}
    with pytest.raises(CommitOutcomeDecodeError, match="unsupported"):
        await verify_commit_outcome_wire(bad_alg, public_keys={jwk["kid"]: jwk})


async def test_enforcing_posture_rejects_unsigned_outcomes_and_opt_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.gateway.governance.kms_signer as ks

    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setattr(ks, "_signer", ks.KMSGovernanceSigner(provider=None))

    with pytest.raises(RuntimeError, match="enforcing posture"):
        await sign_commit_outcome_wire(
            CommitOutcome(CommitStatus.EXECUTED, "ok"),
            tool_name="execute_trade_action",
            idempotency_key=_KEY_1,
        )

    unsigned = CommitOutcome(
        CommitStatus.EXECUTED,
        "ok",
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
    ).to_wire()

    with pytest.raises(
        CommitOutcomeDecodeError, match="missing required KMS signature"
    ):
        await verify_commit_outcome_wire(
            unsigned,
            public_keys={},
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    with pytest.raises(ValueError, match="prohibited in enforcing posture"):
        await verify_commit_outcome_wire(
            unsigned,
            public_keys={},
            require_signature=False,
        )

    with pytest.raises(ValueError, match="prohibited in enforcing posture"):
        GatewayMCPClient("https://gateway.local/mcp/", verify_signature=False)


async def test_signed_commit_tool_result_and_mcp_client_jwks_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.gateway.governance.kms_signer as ks

    signer = _EphemeralAsymmetricSigner("ES256")
    monkeypatch.setattr(ks, "_signer", signer)

    # Mock JWKS endpoint served out-of-band by gateway.
    def _jwks_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [signer.public_jwk]})
        return httpx.Response(404)

    transport = httpx.MockTransport(_jwks_handler)

    result = await signed_commit_tool_result(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
    )
    assert isinstance(result, CallToolResult)
    assert result.structuredContent["signature"]["kid"] == signer.public_jwk["kid"]

    # Check both CallToolResult and 2-tuple MCP signing wrapper.
    tuple_res = await _sign_mcp_commit_result(
        (
            [TextContent(type="text", text="FILLED")],
            CommitOutcome(CommitStatus.EXECUTED, "FILLED").to_wire(),
        ),
        tool_name="administer_dose",
        idempotency_key=_KEY_2,
    )
    assert isinstance(tuple_res, tuple)
    assert tuple_res[1]["tool_name"] == "administer_dose"
    assert tuple_res[1]["idempotency_key"] == _KEY_2
    assert tuple_res[1]["signature"]["kid"] == signer.public_jwk["kid"]

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=transport,
        verify_signature=True,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=result)):
        verified = await client.call_commit_tool(
            "execute_trade_action",
            {"idempotency_key": _KEY_1},
        )
    assert verified.status is CommitStatus.EXECUTED
    assert verified.tool_name == "execute_trade_action"
    assert verified.idempotency_key == _KEY_1

    # Replaying that signed MCP result against a second key must fail closed.
    with patch.object(client, "_traced_call", AsyncMock(return_value=result)):
        with pytest.raises(MCPCommitOutcomeUnrecognizedError, match="idempotency_key"):
            await client.call_commit_tool(
                "execute_trade_action",
                {"idempotency_key": _KEY_2},
            )


@pytest.mark.parametrize(
    ("exc_factory", "expected_http", "expected_status", "extra_check"),
    [
        (
            lambda: ActionDeferred(
                GovernanceDeferred(
                    "need approval",
                    deferred_id="def-42",
                    defer_reason="amount_threshold",
                ),
                approval_retained=True,
            ),
            202,
            CommitStatus.DEFERRED,
            lambda out: out.deferred_id == "def-42" and out.approval_retained is True,
        ),
        (
            lambda: PermissionError("BLOCKED [CBF]: limit exceeded"),
            403,
            CommitStatus.REFUSED,
            lambda out: out.status is CommitStatus.REFUSED,
        ),
        (
            lambda: ActuationIndeterminateError("timeout"),
            200,
            CommitStatus.INDETERMINATE,
            lambda out: out.status is CommitStatus.INDETERMINATE,
        ),
        (
            lambda: UnsettledDuplicate("prior attempt in flight"),
            200,
            CommitStatus.UNSETTLED_DUPLICATE,
            lambda out: out.status is CommitStatus.UNSETTLED_DUPLICATE,
        ),
        (
            lambda: ActuationRejectedError("insufficient buying power"),
            200,
            CommitStatus.REFUSED,
            lambda out: out.status is CommitStatus.REFUSED,
        ),
    ],
)
async def test_tools_execute_signs_200_202_and_403_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    exc_factory: Any,
    expected_http: int,
    expected_status: CommitStatus,
    extra_check: Any,
) -> None:
    import src.gateway.governance.kms_signer as ks

    signer = _EphemeralAsymmetricSigner("EdDSA")
    monkeypatch.setattr(ks, "_signer", signer)

    async def _failing_tool(**kwargs: Any) -> CallToolResult:
        raise exc_factory()

    listed = [SimpleNamespace(name="execute_trade_action", fn=_failing_tool)]
    req = Request(
        {"type": "http", "method": "POST", "path": "/tools/execute", "headers": []}
    )
    body = mts.ToolExecutionRequest(
        tool_name="execute_trade_action",
        params={"idempotency_key": _KEY_1, "amount": 100.0},
    )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(wid, "extract_client_identity", return_value=_CALLER)
        )
        stack.enter_context(
            patch.object(
                wid,
                "load_identity_policy",
                return_value=SimpleNamespace(trusted=frozenset({_CALLER})),
            )
        )
        stack.enter_context(
            patch.object(mts, "refuse_if_quarantined", AsyncMock(return_value=None))
        )
        stack.enter_context(
            patch.object(mts, "_check_rate_limit", AsyncMock(return_value=True))
        )
        stack.enter_context(
            patch.object(gm, "sanitize_mcp_tool_response", AsyncMock(return_value=None))
        )
        stack.enter_context(
            patch.object(mts.mcp._tool_manager, "list_tools", return_value=listed)
        )
        stack.enter_context(patch.object(mts, "mark_request_refused"))
        res = await mts.execute_tool_endpoint(body, req)

    assert res.status_code == expected_http
    payload = json.loads(bytes(res.body).decode("utf-8"))
    assert "outcome" in payload
    verified = await verify_commit_outcome_wire(
        payload["outcome"],
        public_keys={signer.public_jwk["kid"]: signer.public_jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_1,
    )
    assert verified.status is expected_status
    assert extra_check(verified)


async def test_tools_execute_signs_403_quarantine_and_sanitizer_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from starlette.responses import JSONResponse

    import src.gateway.governance.kms_signer as ks

    signer = _EphemeralAsymmetricSigner("EdDSA")
    monkeypatch.setattr(ks, "_signer", signer)

    req = Request(
        {"type": "http", "method": "POST", "path": "/tools/execute", "headers": []}
    )
    body = mts.ToolExecutionRequest(
        tool_name="execute_trade_action",
        params={"idempotency_key": _KEY_2},
    )

    q_mock = AsyncMock(
        return_value=JSONResponse(
            status_code=403,
            content={"error": "workload_quarantined", "message": "quarantined"},
        )
    )
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(wid, "extract_client_identity", return_value=_CALLER)
        )
        stack.enter_context(
            patch.object(
                wid,
                "load_identity_policy",
                return_value=SimpleNamespace(trusted=frozenset({_CALLER})),
            )
        )
        stack.enter_context(patch.object(mts, "refuse_if_quarantined", q_mock))
        res = await mts.execute_tool_endpoint(body, req)

    assert res.status_code == 403
    payload = json.loads(bytes(res.body).decode("utf-8"))
    verified = await verify_commit_outcome_wire(
        payload["outcome"],
        public_keys={signer.public_jwk["kid"]: signer.public_jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_2,
    )
    assert verified.status is CommitStatus.REFUSED

    # Also verify sanitizer-blocked 403 carries a signed REFUSED outcome.
    async def _clean_tool(**kwargs: Any) -> CallToolResult:
        return CallToolResult(
            content=[TextContent(type="text", text="bad")],
            structuredContent=CommitOutcome(CommitStatus.EXECUTED, "bad").to_wire(),
            isError=False,
        )

    import src.gateway.governance.post_execution_sanitizer as pes

    listed = [SimpleNamespace(name="execute_trade_action", fn=_clean_tool)]
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(wid, "extract_client_identity", return_value=_CALLER)
        )
        stack.enter_context(
            patch.object(
                wid,
                "load_identity_policy",
                return_value=SimpleNamespace(trusted=frozenset({_CALLER})),
            )
        )
        stack.enter_context(
            patch.object(mts, "refuse_if_quarantined", AsyncMock(return_value=None))
        )
        stack.enter_context(
            patch.object(mts, "_check_rate_limit", AsyncMock(return_value=True))
        )
        stack.enter_context(
            patch.object(
                pes,
                "evaluate_post_execution_output",
                AsyncMock(
                    return_value=SimpleNamespace(
                        blocked=True,
                        redacted=False,
                        redacted_outcome=None,
                        violation="prompt_injection",
                    )
                ),
            )
        )
        stack.enter_context(
            patch.object(mts.mcp._tool_manager, "list_tools", return_value=listed)
        )
        stack.enter_context(patch.object(mts, "mark_request_refused"))
        res2 = await mts.execute_tool_endpoint(body, req)

    assert res2.status_code == 403
    payload2 = json.loads(bytes(res2.body).decode("utf-8"))
    verified2 = await verify_commit_outcome_wire(
        payload2["outcome"],
        public_keys={signer.public_jwk["kid"]: signer.public_jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_2,
    )
    assert verified2.status is CommitStatus.REFUSED


def test_extract_request_idempotency_key_preference_order() -> None:
    assert (
        extract_request_idempotency_key(
            {"idempotency_key": "k1", "transaction_id": "t1"}
        )
        == "k1"
    )
    assert extract_request_idempotency_key({"transaction_id": "t1"}) is None
    assert (
        extract_request_idempotency_key(
            {"transaction_id": "t1"},
            attempt=SimpleNamespace(_claimed_idempotency_key="claimed-1"),
        )
        == "claimed-1"
    )
    assert extract_request_idempotency_key(None) is None


# ---------------------------------------------------------------------------
# SIG-M1..SIG-M5: Dedicated standalone kill tests + live mutant harness
# ---------------------------------------------------------------------------


def _jwks_transport(keys: list[dict[str, Any]]) -> httpx.MockTransport:
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": keys})
        return httpx.Response(404)

    return httpx.MockTransport(_handler)


async def test_sig_m1_idempotency_key_comparison_enforced() -> None:
    """SIG-M1: dropping idempotency_key comparison allows cross-request replay."""
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    keys = {jwk["kid"]: jwk}
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )

    with pytest.raises(CommitOutcomeDecodeError, match="idempotency_key mismatch"):
        await verify_commit_outcome_wire(
            signed,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_2,
        )

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=_jwks_transport([jwk]),
        verify_signature=True,
    )
    call_result = CallToolResult(
        content=[TextContent(type="text", text="FILLED")],
        structuredContent=signed,
        isError=False,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=call_result)):
        with pytest.raises(MCPCommitOutcomeUnrecognizedError, match="idempotency_key"):
            await client.call_commit_tool(
                "execute_trade_action",
                {"idempotency_key": _KEY_2},
            )


async def test_sig_m2_tool_name_comparison_enforced() -> None:
    """SIG-M2: dropping tool_name comparison allows cross-tool substitution."""
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    keys = {jwk["kid"]: jwk}
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )

    with pytest.raises(CommitOutcomeDecodeError, match="tool_name mismatch"):
        await verify_commit_outcome_wire(
            signed,
            public_keys=keys,
            require_signature=True,
            expected_tool_name="administer_dose",
            expected_idempotency_key=_KEY_1,
        )

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=_jwks_transport([jwk]),
        verify_signature=True,
    )
    call_result = CallToolResult(
        content=[TextContent(type="text", text="FILLED")],
        structuredContent=signed,
        isError=False,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=call_result)):
        with pytest.raises(MCPCommitOutcomeUnrecognizedError, match="tool_name"):
            await client.call_commit_tool(
                "administer_dose",
                {"idempotency_key": _KEY_1},
            )


async def test_sig_m3_unknown_kid_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """SIG-M3: accepting an unknown kid in any posture defeats out-of-band key resolution."""
    monkeypatch.setenv("CAGE_ENV", "test")
    trusted_signer = _EphemeralAsymmetricSigner("ES256", kid_override="trusted-kid")
    unknown_signer = _EphemeralAsymmetricSigner("ES256", kid_override="rogue-kid")
    signed_by_unknown = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=unknown_signer,
    )

    with pytest.raises(CommitOutcomeDecodeError, match="unknown kid"):
        await verify_commit_outcome_wire(
            signed_by_unknown,
            public_keys={trusted_signer.public_jwk["kid"]: trusted_signer.public_jwk},
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=_jwks_transport([trusted_signer.public_jwk]),
        verify_signature=True,
    )
    call_result = CallToolResult(
        content=[TextContent(type="text", text="FILLED")],
        structuredContent=signed_by_unknown,
        isError=False,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=call_result)):
        with pytest.raises(MCPCommitOutcomeUnrecognizedError, match="unknown kid"):
            await client.call_commit_tool(
                "execute_trade_action",
                {"idempotency_key": _KEY_1},
            )


async def test_sig_m4_signature_verified_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIG-M4: skipping verification when signature is present accepts forged bodies."""
    monkeypatch.setenv("CAGE_ENV", "test")
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    keys = {jwk["kid"]: jwk}
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.REFUSED, "blocked"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )

    forged_status = dict(signed, status=CommitStatus.EXECUTED.value, message="FILLED")
    with pytest.raises(CommitOutcomeDecodeError, match="signature invalid"):
        await verify_commit_outcome_wire(
            forged_status,
            public_keys=keys,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    corrupted_sig = dict(signed)
    corrupted_sig["signature"] = {**signed["signature"], "value": "AAAA"}
    with pytest.raises(CommitOutcomeDecodeError):
        await verify_commit_outcome_wire(
            corrupted_sig,
            public_keys=keys,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=_jwks_transport([jwk]),
        verify_signature=True,
    )
    forged_result = CallToolResult(
        content=[TextContent(type="text", text="FILLED")],
        structuredContent=forged_status,
        isError=False,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=forged_result)):
        with pytest.raises(
            MCPCommitOutcomeUnrecognizedError, match="signature invalid"
        ):
            await client.call_commit_tool(
                "execute_trade_action",
                {"idempotency_key": _KEY_1},
            )


async def test_sig_m5_unsigned_outcome_rejected_in_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIG-M5: accepting an unsigned outcome in enforcing posture breaks fail-closed guarantees."""
    monkeypatch.setenv("CAGE_ENV", "production")
    signer = _EphemeralAsymmetricSigner("ES256")
    jwk = signer.public_jwk
    unsigned = CommitOutcome(
        CommitStatus.EXECUTED,
        "FILLED",
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
    ).to_wire()

    with pytest.raises(
        CommitOutcomeDecodeError, match="missing required KMS signature"
    ):
        await verify_commit_outcome_wire(
            unsigned,
            public_keys={jwk["kid"]: jwk},
            require_signature=None,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )

    client = GatewayMCPClient(
        "https://gateway.local/mcp/",
        http_transport=_jwks_transport([jwk]),
        verify_signature=True,
    )
    unsigned_result = CallToolResult(
        content=[TextContent(type="text", text="FILLED")],
        structuredContent=unsigned,
        isError=False,
    )
    with patch.object(client, "_traced_call", AsyncMock(return_value=unsigned_result)):
        with pytest.raises(
            MCPCommitOutcomeUnrecognizedError, match="missing required KMS signature"
        ):
            await client.call_commit_tool(
                "execute_trade_action",
                {"idempotency_key": _KEY_1},
            )


_SigEdit = tuple[str, str]
_SigProbe = Callable[[], Awaitable[bool]]


def _compile_sig_mutant(
    module: ModuleType, name: str, edits: tuple[_SigEdit, ...]
) -> Any:
    func = getattr(module, name)
    lines, first_line = inspect.getsourcelines(func)
    start = next(
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith(("def ", "async def "))
    )
    source = textwrap.dedent("".join(lines[start:]))
    for old, new in edits:
        found = source.count(old)
        assert found == 1, f"{name}: anchor found {found} times, expected 1: {old!r}"
        source = source.replace(old, new)
    code = compile(
        "\n" * (first_line + start - 1) + source,
        inspect.getsourcefile(func) or f"<mutant {name}>",
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    namespace: dict[str, Any] = {}
    exec(code, module.__dict__, namespace)  # noqa: S102
    return namespace[name]


async def _probe_sig_m1_idempotency_key_checked() -> bool:
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )
    ok = await co_mod.verify_commit_outcome_wire(
        signed,
        public_keys={jwk["kid"]: jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_1,
    )
    if ok.status is not CommitStatus.EXECUTED:
        return False
    try:
        await co_mod.verify_commit_outcome_wire(
            signed,
            public_keys={jwk["kid"]: jwk},
            require_signature=True,
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_2,
        )
    except CommitOutcomeDecodeError:
        return True
    return False


async def _probe_sig_m2_tool_name_checked() -> bool:
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )
    ok = await co_mod.verify_commit_outcome_wire(
        signed,
        public_keys={jwk["kid"]: jwk},
        require_signature=True,
        expected_tool_name="execute_trade_action",
        expected_idempotency_key=_KEY_1,
    )
    if ok.status is not CommitStatus.EXECUTED:
        return False
    try:
        await co_mod.verify_commit_outcome_wire(
            signed,
            public_keys={jwk["kid"]: jwk},
            require_signature=True,
            expected_tool_name="administer_dose",
            expected_idempotency_key=_KEY_1,
        )
    except CommitOutcomeDecodeError:
        return True
    return False


async def _probe_sig_m3_unknown_kid_rejected() -> bool:
    signer = _EphemeralAsymmetricSigner("ES256", kid_override="unknown-kid")
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.EXECUTED, "FILLED"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )
    try:
        await co_mod.verify_commit_outcome_wire(
            signed,
            public_keys={},
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )
    except CommitOutcomeDecodeError:
        return True
    return False


async def _probe_sig_m4_signature_verified_when_present() -> bool:
    signer = _EphemeralAsymmetricSigner("EdDSA")
    jwk = signer.public_jwk
    signed = await sign_commit_outcome_wire(
        CommitOutcome(CommitStatus.REFUSED, "blocked"),
        tool_name="execute_trade_action",
        idempotency_key=_KEY_1,
        signer=signer,
    )
    forged = dict(signed, status=CommitStatus.EXECUTED.value, message="FILLED")
    try:
        await co_mod.verify_commit_outcome_wire(
            forged,
            public_keys={jwk["kid"]: jwk},
            expected_tool_name="execute_trade_action",
            expected_idempotency_key=_KEY_1,
        )
    except CommitOutcomeDecodeError:
        return True
    return False


async def _probe_sig_m5_unsigned_rejected_in_enforcing() -> bool:
    prev = os.environ.get("CAGE_ENV")
    os.environ["CAGE_ENV"] = "production"
    try:
        signer = _EphemeralAsymmetricSigner("ES256")
        jwk = signer.public_jwk
        unsigned = CommitOutcome(
            CommitStatus.EXECUTED,
            "FILLED",
            tool_name="execute_trade_action",
            idempotency_key=_KEY_1,
        ).to_wire()
        try:
            await co_mod.verify_commit_outcome_wire(
                unsigned,
                public_keys={jwk["kid"]: jwk},
                require_signature=None,
                expected_tool_name="execute_trade_action",
                expected_idempotency_key=_KEY_1,
            )
        except CommitOutcomeDecodeError:
            return True
        return False
    finally:
        if prev is None:
            os.environ.pop("CAGE_ENV", None)
        else:
            os.environ["CAGE_ENV"] = prev


_SIG_MUTANTS: list[tuple[str, str, str, tuple[_SigEdit, ...], _SigProbe]] = [
    (
        "SIG-M1: drop idempotency_key comparison in _check_expected_binding",
        "src.gateway.governance.commit_outcome",
        "_check_expected_binding",
        (
            (
                "    if expected_idempotency_key is not None and idempotency_key is not None:\n",
                "    if False:\n",
            ),
        ),
        _probe_sig_m1_idempotency_key_checked,
    ),
    (
        "SIG-M2: drop tool_name comparison in _check_expected_binding",
        "src.gateway.governance.commit_outcome",
        "_check_expected_binding",
        (
            (
                "    if expected_tool_name is not None and tool_name is not None:\n",
                "    if False:\n",
            ),
        ),
        _probe_sig_m2_tool_name_checked,
    ),
    (
        "SIG-M3: accept unknown kid in verify_commit_outcome_wire",
        "src.gateway.governance.commit_outcome",
        "verify_commit_outcome_wire",
        (
            (
                "    if raw_key is None:\n"
                '        raise CommitOutcomeDecodeError(f"commit outcome signed by unknown kid={kid!r}")\n',
                "    if raw_key is None:\n        return outcome\n",
            ),
        ),
        _probe_sig_m3_unknown_kid_rejected,
    ),
    (
        "SIG-M4: skip verification when signature is present",
        "src.gateway.governance.commit_outcome",
        "verify_commit_outcome_wire",
        (
            (
                "    assert isinstance(payload, Mapping)\n",
                "    return outcome\n",
            ),
        ),
        _probe_sig_m4_signature_verified_when_present,
    ),
    (
        "SIG-M5: accept unsigned outcome in enforcing posture",
        "src.gateway.governance.commit_outcome",
        "verify_commit_outcome_wire",
        (
            (
                "    must_sign = bool(enforcing or require_signature is True)\n",
                "    must_sign = False\n",
            ),
        ),
        _probe_sig_m5_unsigned_rejected_in_enforcing,
    ),
]


@pytest.mark.parametrize(
    ("mid", "module_name", "func_name", "edits", "probe"),
    _SIG_MUTANTS,
    ids=[m[0].split(":")[0] for m in _SIG_MUTANTS],
)
async def test_sig_mutation_killed_with_inverted_verification(
    monkeypatch: pytest.MonkeyPatch,
    mid: str,
    module_name: str,
    func_name: str,
    edits: tuple[_SigEdit, ...],
    probe: _SigProbe,
) -> None:
    """Inverted pass/fail verification: original MUST pass probe (True); mutant MUST fail (False)."""
    module = importlib.import_module(module_name)
    assert await probe() is True, f"{mid}: invariant probe failed on unmutated code"
    monkeypatch.setattr(
        module, func_name, _compile_sig_mutant(module, func_name, edits)
    )
    assert await probe() is False, f"{mid} survived!"


def test_sig_mutation_set_covers_sig_m1_to_sig_m5() -> None:
    assert [m[0].split(":")[0] for m in _SIG_MUTANTS] == [
        f"SIG-M{i}" for i in range(1, 6)
    ]
