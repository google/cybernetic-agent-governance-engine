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

"""Standalone tests for CageClient preview/execute_tool, CommitOutcome signing, idempotency, and LangGraph node factories (POAM-2026-251)."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import logging
import operator
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, TypedDict

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

pytestmark = [pytest.mark.unit, pytest.mark.local]

subpackage_root = Path(__file__).parent.parent
subpackage_src = subpackage_root / "src"
if (
    importlib.util.find_spec("cage_client") is None
    and str(subpackage_src) not in sys.path
):
    sys.path.append(str(subpackage_src))

from cage_client import (  # noqa: E402
    COMMIT_OUTCOME_SCHEMA,
    ApprovalRedemptionRefusal,
    CageClient,
    CageGatewayError,
    CommitOutcome,
    CommitOutcomeDecodeError,
    CommitStatus,
    GatewayUnavailableError,
    GovernanceDecision,
    IndeterminateProvenance,
    RoutingSealVerificationError,
    compute_expected_action_hash,
    derive_idempotency_key,
    derive_plan_step_key,
    enforce_verification_posture,
    is_retryable_refusal,
)
from cage_client._jcs import canonicalize  # noqa: E402
from cage_client.langgraph import (  # noqa: E402
    approval_park_node,
    governed_node,
    governed_tool_node,
)

_KEY_1 = "11111111-2222-4333-8444-555555555555"
_KEY_2 = "66666666-7777-4888-9999-aaaaaaaaaaaa"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519_keypair(
    kid: str = "ed-key-exec-01",
) -> tuple[ed25519.Ed25519PrivateKey, dict[str, Any]]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": _b64u(raw),
    }
    return priv, jwk


def _make_ec_keypair(
    kid: str = "ec-key-exec-01",
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, Any]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }
    return priv, jwk


def _sign_jcs(
    payload: dict[str, Any], *, priv: Any, kid: str, alg: str
) -> dict[str, Any]:
    unsigned = {k: v for k, v in payload.items() if k != "signature"}
    canonical = canonicalize(unsigned)
    if alg == "EdDSA":
        sig_bytes = priv.sign(canonical)
    elif alg == "ES256":
        sig_bytes = priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(alg)
    return {
        **unsigned,
        "signature": {"algorithm": alg, "kid": kid, "value": _b64u(sig_bytes)},
    }


def _signed_outcome(
    *,
    status: CommitStatus,
    message: str,
    tool_name: str,
    idempotency_key: str,
    priv: Any,
    kid: str,
    alg: str = "EdDSA",
    redemption_refusal: ApprovalRedemptionRefusal | None = None,
    deferred_id: str | None = None,
    approval_retained: bool = False,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": COMMIT_OUTCOME_SCHEMA,
        "status": status.value,
        "message": message,
        "tool_name": tool_name,
        "idempotency_key": idempotency_key,
        "issued_at": "2026-11-26T12:00:00.000Z",
    }
    if status is CommitStatus.REFUSED and redemption_refusal is not None:
        body["redemption_refusal"] = redemption_refusal.value
    if status is CommitStatus.DEFERRED:
        body["deferred_id"] = deferred_id
        body["approval_retained"] = approval_retained
    return _sign_jcs(body, priv=priv, kid=kid, alg=alg)


def _signed_preview_envelope(
    *,
    action: str,
    parameters: dict[str, Any],
    payload: dict[str, Any],
    priv: Any,
    kid: str,
    alg: str = "EdDSA",
    correlation_id: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    final_payload = dict(payload)
    if correlation_id is not None:
        final_payload["correlation_id"] = correlation_id
    env = {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-preview-1",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-1",
            "region": "US_FED",
        },
        "subject": {
            "action": action,
            "action_hash": compute_expected_action_hash(action, parameters),
            "agent_id": "trader-01",
        },
        "governance_context": {"policy_version": "sha256:abc", "tiers_passed": ["opa"]},
        "payload": final_payload,
    }
    return _sign_jcs(env, priv=priv, kid=kid, alg=alg)


@pytest.fixture(autouse=True)
def _test_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_ENV", "test")
    monkeypatch.delenv("ENVIRONMENT", raising=False)


# ---------------------------------------------------------------------------
# 1. CageClient.preview() — all 5 GovernanceDecision outcomes
# ---------------------------------------------------------------------------


def test_preview_covers_all_five_governance_decisions() -> None:
    priv, jwk = _make_ed25519_keypair()
    params = {"symbol": "AAPL", "amount": 500}
    mode = ["ALLOW"]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        import json as _json

        corr = _json.loads(req.content).get("correlation_id")
        cur = mode[0]
        if cur == "ALLOW":
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action="execute_trade",
                    parameters=params,
                    payload={"verdict": "ALLOW"},
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=corr,
                ),
            )
        if cur == "NARROW":
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action="execute_trade",
                    parameters=params,
                    payload={
                        "verdict": "NARROW",
                        "narrowed_params": {"amount": 250},
                        "audit_id": "aud-narrow-1",
                    },
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=corr,
                ),
            )
        if cur == "DENY":
            return httpx.Response(
                403,
                json=_signed_preview_envelope(
                    action="execute_trade",
                    parameters=params,
                    payload={
                        "verdict": "DENY",
                        "reason_code": "CBF_HARD_BARRIER",
                        "proof_hash": "proof-deny-1",
                        "violations": ["[CBF_HARD_BARRIER] exceeded"],
                    },
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=corr,
                ),
            )
        if cur == "REQUIRE_APPROVAL":
            defer_exp = (
                (datetime.now(timezone.utc) + timedelta(hours=4))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action="execute_trade",
                    parameters=params,
                    payload={
                        "verdict": "REQUIRE_APPROVAL",
                        "deferred_id": "def-req-1",
                        "defer_reason": "amount_threshold",
                        "ttl_seconds": 14400,
                        "defer_expires_at": defer_exp,
                    },
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=corr,
                ),
            )
        if cur == "DEFER":
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action="execute_trade",
                    parameters=params,
                    payload={
                        "verdict": "DEFER",
                        "defer_token": "def-hold-1",
                        "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                        "retry_after_seconds": 300,
                    },
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=corr,
                ),
            )
        return httpx.Response(503, json={"error": "redis_unavailable"})

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(ValueError, match="agent_id"):
                await client.preview("execute_trade", params, "")
            with pytest.raises(ValueError, match="action"):
                await client.preview("", params, "trader-01")

            r_allow = await client.preview("execute_trade", params, "trader-01")
            assert r_allow.decision is GovernanceDecision.ALLOWED
            assert r_allow.is_executable is True
            assert r_allow.envelope is not None

            mode[0] = "NARROW"
            r_narrow = await client.preview("execute_trade", params, "trader-01")
            assert r_narrow.decision is GovernanceDecision.NARROWED
            assert r_narrow.is_executable is True
            assert r_narrow.narrowed_params == {"amount": 250}

            mode[0] = "DENY"
            r_deny = await client.preview("execute_trade", params, "trader-01")
            assert r_deny.decision is GovernanceDecision.DENIED
            assert r_deny.is_executable is False
            assert r_deny.reason_code == "CBF_HARD_BARRIER"
            assert r_deny.audit_id == "proof-deny-1"

            mode[0] = "REQUIRE_APPROVAL"
            r_req = await client.preview("execute_trade", params, "trader-01")
            assert r_req.decision is GovernanceDecision.DEFERRED
            assert r_req.requires_approval is True
            assert r_req.deferred_id == "def-req-1"
            assert r_req.defer_expires_at is not None
            assert r_req.defer_expires_at > datetime.now(timezone.utc) + timedelta(
                hours=3
            )

            mode[0] = "DEFER"
            r_def = await client.preview("execute_trade", params, "trader-01")
            assert r_def.decision is GovernanceDecision.DEFERRED
            assert r_def.requires_approval is False
            assert r_def.deferred_id == "def-hold-1"
            assert r_def.defer_expires_at is not None

            mode[0] = "503"
            r_unavail = await client.preview("execute_trade", params, "trader-01")
            assert r_unavail.decision is GovernanceDecision.UNAVAILABLE
            assert r_unavail.reason_code == "GATEWAY_UNAVAILABLE"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. CageClient.execute_tool() + signed CommitOutcome + provenance + posture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_execute_tool_verifies_signed_outcomes_across_200_202_403(alg: str) -> None:
    priv, jwk = _make_ec_keypair() if alg == "ES256" else _make_ed25519_keypair()
    scenario = ["200_executed"]
    seen_bodies: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        import json as _json

        payload = _json.loads(req.content)
        seen_bodies.append(payload)
        p = payload["params"]
        cur = scenario[0]
        if cur == "200_executed":
            return httpx.Response(
                200,
                json={
                    "status": "SUCCESS",
                    "output": "FILLED order-9",
                    "may_have_executed": True,
                    "outcome": _signed_outcome(
                        status=CommitStatus.EXECUTED,
                        message="FILLED order-9",
                        tool_name="execute_trade_action",
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                        alg=alg,
                    ),
                },
            )
        if cur == "202_deferred":
            return httpx.Response(
                202,
                json={
                    "status": "DEFERRED",
                    "deferred_id": "def-99",
                    "approval_retained": True,
                    "outcome": _signed_outcome(
                        status=CommitStatus.DEFERRED,
                        message="parked for review",
                        tool_name="execute_trade_action",
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                        alg=alg,
                        deferred_id="def-99",
                        approval_retained=True,
                    ),
                },
            )
        if cur == "403_refused":
            return httpx.Response(
                403,
                json={
                    "status": "ERROR",
                    "proof_hash": "proof-403",
                    "outcome": _signed_outcome(
                        status=CommitStatus.REFUSED,
                        message="blocked by CBF",
                        tool_name="execute_trade_action",
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                        alg=alg,
                        redemption_refusal=ApprovalRedemptionRefusal.CONSUMED,
                    ),
                },
            )
        return httpx.Response(
            200,
            json={
                "status": "ERROR",
                "actuation_outcome": "UNKNOWN",
                "may_have_executed": True,
                "outcome": _signed_outcome(
                    status=CommitStatus.INDETERMINATE,
                    message="broker timeout",
                    tool_name="execute_trade_action",
                    idempotency_key=p["idempotency_key"],
                    priv=priv,
                    kid=jwk["kid"],
                    alg=alg,
                ),
            },
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            # Untrusted model-supplied deferred_id is stripped unless approval_token passed.
            out_ok = await client.execute_tool(
                "execute_trade_action",
                {"symbol": "AAPL", "deferred_id": "forged-model-token"},
                idempotency_key=_KEY_1,
            )
            assert "deferred_id" not in seen_bodies[0]["params"]
            assert out_ok.status is CommitStatus.EXECUTED
            assert out_ok.verified is True
            assert out_ok.http_status == 200
            assert out_ok.output == "FILLED order-9"

            scenario[0] = "202_deferred"
            out_def = await client.execute_tool(
                "execute_trade_action",
                {"symbol": "AAPL"},
                idempotency_key=_KEY_1,
                approval_token="def-99",
            )
            assert seen_bodies[1]["params"]["deferred_id"] == "def-99"
            assert out_def.status is CommitStatus.DEFERRED
            assert out_def.deferred_id == "def-99"
            assert out_def.approval_retained is True
            assert out_def.awaits_same_ticket is True
            assert out_def.verified is True

            scenario[0] = "403_refused"
            out_ref = await client.execute_tool(
                "execute_trade_action",
                {"symbol": "AAPL"},
                idempotency_key=_KEY_1,
            )
            assert out_ref.status is CommitStatus.REFUSED
            assert out_ref.redemption_refusal is ApprovalRedemptionRefusal.CONSUMED
            assert out_ref.awaits_same_ticket is False
            assert out_ref.proof_hash == "proof-403"
            assert out_ref.http_status == 403

            scenario[0] = "200_indeterminate"
            out_ind = await client.execute_tool(
                "execute_trade_action",
                {"symbol": "AAPL"},
                idempotency_key=_KEY_1,
            )
            assert out_ind.status is CommitStatus.INDETERMINATE
            assert out_ind.provenance is IndeterminateProvenance.GATEWAY_ASSERTED
            assert out_ind.may_have_executed is True
            assert out_ind.verified is True

    asyncio.run(_run())


def test_execute_tool_transport_and_503_provenance_distinction() -> None:
    mode = ["503"]

    def handler(req: httpx.Request) -> httpx.Response:
        cur = mode[0]
        if cur == "503":
            return httpx.Response(
                503,
                json={
                    "error": "evidence_chain_unavailable",
                    "dependency": "evidence_stream",
                    "failure_code": "REDIS_DOWN",
                    "detail": "stream write failed",
                },
            )
        if cur == "429":
            return httpx.Response(
                429,
                headers={"Retry-After": "12"},
                json={"error": "rate_limit_exceeded"},
            )
        if cur == "connect_err":
            raise httpx.ConnectError("connection refused", request=req)
        if cur == "read_timeout":
            raise httpx.ReadTimeout("timed out reading body", request=req)
        if cur == "500":
            return httpx.Response(500, text="internal server error")
        return httpx.Response(200, content=b"{corrupted")

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(GatewayUnavailableError) as exc503:
                await client.execute_tool(
                    "execute_trade_action", {"symbol": "AAPL"}, idempotency_key=_KEY_1
                )
            assert exc503.value.status_code == 503
            assert exc503.value.dependency == "evidence_stream"

            mode[0] = "429"
            with pytest.raises(GatewayUnavailableError) as exc429:
                await client.execute_tool(
                    "execute_trade_action", {"symbol": "AAPL"}, idempotency_key=_KEY_1
                )
            assert exc429.value.retry_after_seconds == 12

            mode[0] = "connect_err"
            with pytest.raises(GatewayUnavailableError):
                await client.execute_tool(
                    "execute_trade_action", {"symbol": "AAPL"}, idempotency_key=_KEY_1
                )

            for ambiguous_mode in ("read_timeout", "500", "bad_json"):
                mode[0] = ambiguous_mode
                out = await client.execute_tool(
                    "execute_trade_action", {"symbol": "AAPL"}, idempotency_key=_KEY_1
                )
                assert out.status is CommitStatus.INDETERMINATE
                assert out.provenance is IndeterminateProvenance.CLIENT_INFERRED
                assert out.may_have_executed is True
                assert out.verified is False

    asyncio.run(_run())


def test_execute_tool_rejects_binding_mismatches_unknown_kid_and_tampering() -> None:
    priv, jwk = _make_ed25519_keypair(kid="trusted-kid")
    rogue_priv, rogue_jwk = _make_ed25519_keypair(kid="rogue-kid")
    payload_box: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(
            200, json={"status": "SUCCESS", "outcome": payload_box[0]}
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            # 1. Wrong idempotency_key binding
            payload_box[:] = [
                _signed_outcome(
                    status=CommitStatus.EXECUTED,
                    message="FILLED",
                    tool_name="execute_trade_action",
                    idempotency_key=_KEY_1,
                    priv=priv,
                    kid=jwk["kid"],
                )
            ]
            with pytest.raises(
                CommitOutcomeDecodeError, match="idempotency_key mismatch"
            ):
                await client.execute_tool(
                    "execute_trade_action", {"symbol": "AAPL"}, idempotency_key=_KEY_2
                )

            # 2. Wrong tool_name binding
            with pytest.raises(CommitOutcomeDecodeError, match="tool_name mismatch"):
                await client.execute_tool(
                    "administer_dose", {"symbol": "AAPL"}, idempotency_key=_KEY_1
                )

            # 3. Unknown kid fails closed even in dev/test
            payload_box[:] = [
                _signed_outcome(
                    status=CommitStatus.EXECUTED,
                    message="FILLED",
                    tool_name="execute_trade_action",
                    idempotency_key=_KEY_1,
                    priv=rogue_priv,
                    kid=rogue_jwk["kid"],
                )
            ]
            with pytest.raises(RoutingSealVerificationError, match="unknown"):
                await client.execute_tool(
                    "execute_trade_action",
                    {"symbol": "AAPL"},
                    idempotency_key=_KEY_1,
                    verify_signature=False,
                )

            # 4. Tampered body with known kid fails even when verify_signature=False in dev/test
            valid = _signed_outcome(
                status=CommitStatus.REFUSED,
                message="blocked",
                tool_name="execute_trade_action",
                idempotency_key=_KEY_1,
                priv=priv,
                kid=jwk["kid"],
            )
            payload_box[:] = [dict(valid, status=CommitStatus.EXECUTED.value)]
            with pytest.raises(RoutingSealVerificationError):
                await client.execute_tool(
                    "execute_trade_action",
                    {"symbol": "AAPL"},
                    idempotency_key=_KEY_1,
                    verify_signature=False,
                )

    asyncio.run(_run())


def test_execute_tool_posture_enforces_signed_outcomes_and_warns_on_dev_opt_out(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    unsigned_wire = {
        "schema": COMMIT_OUTCOME_SCHEMA,
        "status": CommitStatus.EXECUTED.value,
        "message": "FILLED",
        "tool_name": "execute_trade_action",
        "idempotency_key": _KEY_1,
    }

    async def _call_unsigned(*, verify_sig: bool | None) -> CommitOutcome:
        transport = httpx.MockTransport(
            lambda req: httpx.Response(
                200, json={"status": "SUCCESS", "outcome": unsigned_wire}
            )
        )
        async with CageClient(
            "https://gateway.example.test", http_transport=transport
        ) as client:
            return await client.execute_tool(
                "execute_trade_action",
                {"symbol": "AAPL"},
                idempotency_key=_KEY_1,
                verify_signature=verify_sig,
            )

    # Enforcing postures reject both verify_signature=False and unsigned outcomes.
    for env_val in (None, "", "local", "ci", "production"):
        if env_val is None:
            monkeypatch.delenv("CAGE_ENV", raising=False)
        else:
            monkeypatch.setenv("CAGE_ENV", env_val)

        with pytest.raises(ValueError, match="forbidden in enforcing posture"):
            enforce_verification_posture(
                verify_signature=False, subject_label="CommitOutcome"
            )

        with pytest.raises(ValueError, match="forbidden in enforcing posture"):
            asyncio.run(_call_unsigned(verify_sig=False))

        with pytest.raises(
            CommitOutcomeDecodeError, match="missing required KMS signature"
        ):
            asyncio.run(_call_unsigned(verify_sig=None))

    # Dev/test opt-out MUST emit a warning (never silent).
    monkeypatch.setenv("CAGE_ENV", "test")
    with caplog.at_level(logging.WARNING, logger="CageClient"):
        res = asyncio.run(_call_unsigned(verify_sig=False))
    assert res.status is CommitStatus.EXECUTED
    assert res.verified is False
    assert any(
        "Disabling CommitOutcome verification" in rec.getMessage()
        for rec in caplog.records
    )


# ---------------------------------------------------------------------------
# 3. Deterministic idempotency helpers + Node negative extractor tests
# ---------------------------------------------------------------------------


def test_derive_plan_step_key_and_idempotency_determinism() -> None:
    plan_steps = [{"symbol": "AAPL", "currency": "USD", "side": "buy", "amount": 500}]
    k1 = derive_plan_step_key(
        {"symbol": "aapl", "amount": 500, "side": "BUY", "currency": "usd"},
        plan_digest="abc123",
        plan_steps=plan_steps,
    )
    k2 = derive_plan_step_key(
        {"amount": 500.0, "side": "buy", "symbol": "AAPL"},
        plan_digest="abc123",
        plan_steps=plan_steps,
    )
    assert k1 == k2 == "plan:abc123|step:0|AAPL|USD|buy|500.00000000"
    assert derive_idempotency_key(
        k1, thread_id="t-1", message_id="m-1"
    ) == derive_idempotency_key(k2, thread_id="t-1", message_id="m-2")

    # Generic non-trade args ignore volatile token fields cleanly.
    g1 = derive_plan_step_key({"patient_id": "p1", "dose_mg": 5, "deferred_id": "d1"})
    g2 = derive_plan_step_key(
        {"dose_mg": 5, "patient_id": "p1", "idempotency_key": "k2"}
    )
    assert g1 == g2


def test_langgraph_nodes_fail_closed_without_fabricating_defaults() -> None:
    http_calls = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal http_calls
        http_calls += 1
        return httpx.Response(500)

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            node = governed_node(
                client=client,
                principal_extractor=lambda s: s.get("principal"),  # type: ignore[return-value]
                action_extractor=lambda s: (s.get("action"), s.get("params")),  # type: ignore[return-value]
                on_allow="exec",
                on_deny="deny",
            )
            cmd_missing_principal = await node(
                {"action": "trade", "params": {"symbol": "AAPL"}}
            )
            assert cmd_missing_principal.goto == "deny"
            assert cmd_missing_principal.update["governance_status"] == "DENIED"

            cmd_blank_principal = await node(
                {"principal": "   ", "action": "trade", "params": {"symbol": "AAPL"}}
            )
            assert cmd_blank_principal.goto == "deny"

            cmd_missing_params = await node(
                {"principal": "advisor-1", "action": "trade"}
            )
            assert cmd_missing_params.goto == "deny"

            tool_node = governed_tool_node(
                client=client,
                action="execute_trade",
                principal_extractor=lambda s: s.get("principal"),  # type: ignore[return-value]
                on_complete="agent",
                on_deny="deny",
            )
            msg = AIMessage(
                id="ai-1",
                content="",
                tool_calls=[
                    {
                        "id": "tc-1",
                        "name": "execute_trade_action",
                        "args": {"symbol": "AAPL"},
                    }
                ],
            )
            cmd_batch = await tool_node({"messages": [msg]})
            assert cmd_batch.goto == "deny"
            assert len(cmd_batch.update["messages"]) == 1
            assert cmd_batch.update["messages"][0].tool_call_id == "tc-1"

            park = approval_park_node(approved_target="exec", rejected_target="reject")
            cmd_park = park({})
            assert cmd_park.goto == "reject"
            assert cmd_park.update["governance_status"] == "DENIED"

    asyncio.run(_run())
    assert http_calls == 0


# ---------------------------------------------------------------------------
# 4. Batch 1..N ToolMessage pairing + full Checkpointer DEFER -> interrupt -> resume -> CONSUMED E2E
# ---------------------------------------------------------------------------


def test_governed_tool_node_pairs_all_tool_messages_on_batch_halt() -> None:
    priv, jwk = _make_ed25519_keypair()
    calls_made: list[tuple[str, str]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        import json as _json

        data = _json.loads(req.content)
        if req.url.path == "/governance/validate-action":
            calls_made.append(("preview", data["action"]))
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action=data["action"],
                    parameters=data["parameters"],
                    payload={"verdict": "ALLOW"},
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=data.get("correlation_id"),
                ),
            )
        p = data["params"]
        calls_made.append(("execute", p["symbol"]))
        if p["symbol"] == "AAPL":
            return httpx.Response(
                200,
                json={
                    "status": "SUCCESS",
                    "output": "FILLED AAPL",
                    "outcome": _signed_outcome(
                        status=CommitStatus.EXECUTED,
                        message="FILLED AAPL",
                        tool_name=data["tool_name"],
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                    ),
                },
            )
        return httpx.Response(
            200,
            json={
                "status": "ERROR",
                "actuation_outcome": "UNKNOWN",
                "may_have_executed": True,
                "outcome": _signed_outcome(
                    status=CommitStatus.INDETERMINATE,
                    message="wire timeout on MSFT",
                    tool_name=data["tool_name"],
                    idempotency_key=p["idempotency_key"],
                    priv=priv,
                    kid=jwk["kid"],
                ),
            },
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            node = governed_tool_node(
                client=client,
                action="execute_trade",
                principal_extractor=lambda s: s["principal"],
                committing_tools={"execute_trade_action"},
                on_complete="agent",
                on_approval_required="park",
                on_deny="deny",
                on_indeterminate="halt",
            )
            ai_msg = AIMessage(
                id="ai-batch-1",
                content="",
                tool_calls=[
                    {
                        "id": "c1",
                        "name": "execute_trade_action",
                        "args": {"symbol": "AAPL", "amount": 10},
                    },
                    {
                        "id": "c2",
                        "name": "execute_trade_action",
                        "args": {"symbol": "MSFT", "amount": 20},
                    },
                    {
                        "id": "c3",
                        "name": "execute_trade_action",
                        "args": {"symbol": "NVDA", "amount": 30},
                    },
                ],
            )
            cmd = await node({"principal": "advisor-sa", "messages": [ai_msg]})
            assert cmd.goto == "halt"
            assert cmd.update["governance_status"] == "INDETERMINATE"
            tmsgs: list[ToolMessage] = cmd.update["messages"]
            assert [m.tool_call_id for m in tmsgs] == ["c1", "c2", "c3"]
            assert "FILLED AAPL" in tmsgs[0].content
            assert "reconciled" in tmsgs[1].content
            assert "skipped" in tmsgs[2].content
            # c3 MUST NOT be executed once c2 halted indeterminate.
            assert [c for c in calls_made if c[0] == "execute"] == [
                ("execute", "AAPL"),
                ("execute", "MSFT"),
            ]

    asyncio.run(_run())


def test_governed_tool_node_routes_unavailable_decode_error_and_gateway_error() -> None:
    priv, jwk = _make_ed25519_keypair()
    mode = ["503"]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        import json as _json

        data = _json.loads(req.content)
        if req.url.path == "/governance/validate-action":
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action=data["action"],
                    parameters=data["parameters"],
                    payload={"verdict": "ALLOW"},
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=data.get("correlation_id"),
                ),
            )
        if mode[0] == "503":
            return httpx.Response(
                503,
                json={"error": "redis_unavailable", "dependency": "redis"},
            )
        if mode[0] == "tampered":
            p = data["params"]
            bad = _signed_outcome(
                status=CommitStatus.REFUSED,
                message="blocked",
                tool_name=data["tool_name"],
                idempotency_key=p["idempotency_key"],
                priv=priv,
                kid=jwk["kid"],
            )
            return httpx.Response(
                200,
                json={"status": "SUCCESS", "outcome": dict(bad, status="executed")},
            )
        return httpx.Response(400, json={"detail": "bad request"})

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            node = governed_tool_node(
                client=client,
                action="execute_trade",
                principal_extractor=lambda s: s["principal"],
                committing_tools={"execute_trade_action"},
                on_complete="done",
                on_approval_required="park",
                on_deny="deny",
                on_unavailable="retry_later",
                on_indeterminate="halt",
            )
            ai_msg = AIMessage(
                id="ai-err-1",
                content="",
                tool_calls=[
                    {
                        "id": "call-err-1",
                        "name": "execute_trade_action",
                        "args": {"symbol": "AAPL", "amount": 5},
                    }
                ],
            )
            state = {"principal": "advisor-sa", "messages": [ai_msg]}

            mode[0] = "503"
            cmd_503 = await node(state)
            assert cmd_503.goto == "retry_later"
            assert cmd_503.update["governance_status"] == "UNAVAILABLE"

            mode[0] = "tampered"
            cmd_tampered = await node(state)
            assert cmd_tampered.goto == "halt"
            assert cmd_tampered.update["governance_status"] == "INDETERMINATE"
            assert cmd_tampered.update["may_have_executed"] is True
            assert (
                cmd_tampered.update["commit_outcomes"]["call-err-1"]["provenance"]
                == "client_inferred"
            )

            mode[0] = "400"
            cmd_400 = await node(state)
            assert cmd_400.goto == "deny"
            assert cmd_400.update["governance_status"] == "DENIED"

    asyncio.run(_run())


class _GraphState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    principal: str
    execution_plan: str
    deferred_id: str | None
    approval_required: bool
    approval_decision: dict[str, Any] | None
    governance_status: str | None
    redemption_refusal: str | None
    commit_outcomes: dict[str, Any]


def test_real_checkpointer_defer_interrupt_resume_redeem_and_second_replay_refusal() -> (
    None
):
    priv, jwk = _make_ed25519_keypair()
    ticket_state = ["PENDING"]  # PENDING -> APPROVED -> CONSUMED
    exec_calls: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        import json as _json

        data = _json.loads(req.content)
        if req.url.path == "/governance/validate-action":
            return httpx.Response(
                200,
                json=_signed_preview_envelope(
                    action=data["action"],
                    parameters=data["parameters"],
                    payload={
                        "verdict": "REQUIRE_APPROVAL",
                        "deferred_id": "def-e2e-1",
                        "defer_reason": "amount_threshold",
                    },
                    priv=priv,
                    kid=jwk["kid"],
                    correlation_id=data.get("correlation_id"),
                ),
            )
        p = data["params"]
        exec_calls.append(p)
        state_now = ticket_state[0]
        if state_now == "PENDING":
            return httpx.Response(
                403,
                json={
                    "status": "ERROR",
                    "outcome": _signed_outcome(
                        status=CommitStatus.REFUSED,
                        message="pending approval",
                        tool_name=data["tool_name"],
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                        redemption_refusal=ApprovalRedemptionRefusal.PENDING,
                    ),
                },
            )
        if state_now == "APPROVED":
            ticket_state[0] = "CONSUMED"
            return httpx.Response(
                200,
                json={
                    "status": "SUCCESS",
                    "output": "FILLED e2e-trade",
                    "outcome": _signed_outcome(
                        status=CommitStatus.EXECUTED,
                        message="FILLED e2e-trade",
                        tool_name=data["tool_name"],
                        idempotency_key=p["idempotency_key"],
                        priv=priv,
                        kid=jwk["kid"],
                    ),
                },
            )
        return httpx.Response(
            403,
            json={
                "status": "ERROR",
                "outcome": _signed_outcome(
                    status=CommitStatus.REFUSED,
                    message="ticket already consumed",
                    tool_name=data["tool_name"],
                    idempotency_key=p["idempotency_key"],
                    priv=priv,
                    kid=jwk["kid"],
                    redemption_refusal=ApprovalRedemptionRefusal.CONSUMED,
                ),
            },
        )

    async def _run() -> None:
        assert is_retryable_refusal(ApprovalRedemptionRefusal.PENDING) is True
        assert is_retryable_refusal(ApprovalRedemptionRefusal.CONSUMED) is False

        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            tools_node = governed_tool_node(
                client=client,
                action="execute_trade",
                principal_extractor=lambda s: s["principal"],
                committing_tools={"execute_trade_action"},
                plan_extractor=lambda s: s.get("execution_plan"),
                on_complete=END,
                on_approval_required="park",
                on_deny=END,
            )
            park_node = approval_park_node(
                approved_target="tools",
                rejected_target=END,
            )

            builder = StateGraph(_GraphState)
            builder.add_node("tools", tools_node)
            builder.add_node("park", park_node)
            builder.add_edge(START, "tools")
            graph = builder.compile(checkpointer=MemorySaver())

            cfg = {"configurable": {"thread_id": "thread-e2e-1"}}
            ai_msg = AIMessage(
                id="ai-e2e-1",
                content="",
                tool_calls=[
                    {
                        "id": "call-e2e-1",
                        "name": "execute_trade_action",
                        "args": {
                            "symbol": "AAPL",
                            "amount": 5000,
                            "deferred_id": "forged-by-model",
                        },
                    }
                ],
            )

            # 1. DEFER -> deferred_id checkpoints BEFORE interrupt().
            r1 = await graph.ainvoke(
                {
                    "messages": [ai_msg],
                    "principal": "advisor-sa",
                    "execution_plan": '{"steps": [{"symbol": "AAPL", "amount": 5000}]}',
                    "deferred_id": None,
                    "approval_required": False,
                    "approval_decision": None,
                    "governance_status": None,
                    "redemption_refusal": None,
                    "commit_outcomes": {},
                },
                config=cfg,
            )
            assert "__interrupt__" in r1
            assert r1["deferred_id"] == "def-e2e-1"
            assert "def-e2e-1" not in str(r1["messages"][-1].content)
            assert len(exec_calls) == 0

            # 2. Premature resume (gateway PENDING) -> retryable refusal re-interrupts on SAME ticket.
            r2 = await graph.ainvoke(
                Command(
                    resume={
                        "approved": True,
                        "reviewer": "alice",
                        "rationale": "premature click",
                    }
                ),
                config=cfg,
            )
            assert "__interrupt__" in r2
            assert r2["deferred_id"] == "def-e2e-1"
            assert r2["approval_decision"] is None
            assert r2["redemption_refusal"] == "pending"
            assert exec_calls[0]["deferred_id"] == "def-e2e-1"

            # 3. Approved resume -> redeems def-e2e-1 once and completes.
            ticket_state[0] = "APPROVED"
            r3 = await graph.ainvoke(
                Command(
                    resume={
                        "approved": True,
                        "reviewer": "alice",
                        "rationale": "approved after review",
                    }
                ),
                config=cfg,
            )
            assert "__interrupt__" not in r3
            assert r3["governance_status"] == "ALLOWED"
            assert r3["deferred_id"] is None
            assert exec_calls[1]["idempotency_key"] == exec_calls[0]["idempotency_key"]
            assert isinstance(r3["messages"][-1], ToolMessage)
            assert "FILLED e2e-trade" in r3["messages"][-1].content

            # 4. Second replay with same ticket on a fresh thread -> CONSUMED terminal refusal.
            replay_cfg = {"configurable": {"thread_id": "thread-e2e-replay"}}
            r4 = await graph.ainvoke(
                {
                    "messages": [ai_msg],
                    "principal": "advisor-sa",
                    "execution_plan": '{"steps": [{"symbol": "AAPL", "amount": 5000}]}',
                    "deferred_id": "def-e2e-1",
                    "approval_required": False,
                    "approval_decision": {
                        "approved": True,
                        "reviewer": "alice",
                        "rationale": "replay",
                    },
                    "governance_status": None,
                    "redemption_refusal": None,
                    "commit_outcomes": {},
                },
                config=replay_cfg,
            )
            assert r4["governance_status"] == "DENIED"
            assert r4["redemption_refusal"] == "consumed"
            assert "already been used" in str(r4["messages"][-1].content)

    asyncio.run(_run())
