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

"""Standalone SC-23 tests for correlation_id preimage binding and defer_expires_at separation (POAM-2026-241)."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

pytestmark = [pytest.mark.unit, pytest.mark.local]

subpackage_root = Path(__file__).parent.parent
subpackage_src = subpackage_root / "src"
if (
    importlib.util.find_spec("cage_client") is None
    and str(subpackage_src) not in sys.path
):
    sys.path.insert(0, str(subpackage_src))

from cage_client import (  # noqa: E402
    CageClient,
    CageGatewayError,
    DeferralPending,
    GovernanceDecision,
    PolicyViolationException,
    RoutingSealVerificationError,
    compute_expected_action_hash,
)
from cage_client._jcs import canonicalize  # noqa: E402
from cage_client.langgraph import governed_node  # noqa: E402


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519(
    kid: str = "ed-sc23-01",
) -> tuple[ed25519.Ed25519PrivateKey, dict[str, Any]]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "x": _b64u(pub_raw),
    }
    return priv, jwk


def _build_signed_env(
    *,
    action: str,
    parameters: dict[str, Any],
    payload: dict[str, Any],
    priv: ed25519.Ed25519PrivateKey,
    kid: str,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    iat = issued_at or (datetime.now(timezone.utc) - timedelta(seconds=5))
    exp = expires_at or (iat + timedelta(minutes=5))
    env: dict[str, Any] = {
        "envelope_version": "3.0",
        "envelope_type": "cage_governance_decision",
        "envelope_id": "env-sc23-001",
        "issued_at": iat.isoformat(),
        "expires_at": exp.isoformat(),
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-1",
            "region": "US_FED",
        },
        "subject": {
            "action": action,
            "action_hash": compute_expected_action_hash(action, parameters),
            "agent_id": "agent-sc23",
        },
        "governance_context": {"policy_version": "sha256:abc", "tiers_passed": ["opa"]},
        "payload": payload,
    }
    sig = _b64u(priv.sign(canonicalize(env)))
    return {**env, "signature": {"algorithm": "EdDSA", "kid": kid, "value": sig}}


@pytest.mark.parametrize(
    "bad_correlation_id",
    [
        pytest.param("__OMIT__", id="missing"),
        pytest.param(None, id="none"),
        pytest.param("", id="empty-str"),
        pytest.param("   \t\n ", id="blank-str"),
        pytest.param(12345, id="int-type"),
        pytest.param(["abc"], id="list-type"),
        pytest.param({"id": "abc"}, id="dict-type"),
        pytest.param(True, id="bool-type"),
    ],
)
def test_sc23_m1_missing_blank_or_non_string_correlation_id_rejected(
    bad_correlation_id: Any,
) -> None:
    """SC23-M1: HTTP 200 envelope missing, blank, or non-string correlation_id fails closed."""
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL", "amount": 100}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        payload: dict[str, Any] = {"verdict": "ALLOW"}
        if bad_correlation_id != "__OMIT__":
            payload["correlation_id"] = bad_correlation_id
        return httpx.Response(
            200,
            json=_build_signed_env(
                action="query_portfolio",
                parameters=params,
                payload=payload,
                priv=priv,
                kid=jwk["kid"],
            ),
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(RoutingSealVerificationError, match="correlation_id"):
                await client.validate_action("query_portfolio", params, "agent-sc23")

    asyncio.run(_run())


def test_sc23_m2_cross_call_replay_with_different_correlation_id_rejected() -> None:
    """SC23-M2: Freshly signed ALLOW envelope captured from call A cannot replay into call B."""
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL", "amount": 100}
    captured_env: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        if captured_env:
            return httpx.Response(200, json=captured_env[0])
        corr = json.loads(req.content)["correlation_id"]
        env = _build_signed_env(
            action="query_portfolio",
            parameters=params,
            payload={"verdict": "ALLOW", "correlation_id": corr},
            priv=priv,
            kid=jwk["kid"],
        )
        captured_env.append(env)
        return httpx.Response(200, json=env)

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            first = await client.validate_action(
                "query_portfolio", params, "agent-sc23"
            )
            assert first.payload["verdict"] == "ALLOW"

            with pytest.raises(
                RoutingSealVerificationError,
                match="does not match request correlation_id",
            ):
                await client.validate_action("query_portfolio", params, "agent-sc23")

    asyncio.run(_run())


@pytest.mark.parametrize(
    "bad_corr",
    [None, "", 999, ["x"], "other-call-correlation-id"],
)
def test_sc23_m3_http_403_refusal_enforces_correlation_id_binding(
    bad_corr: Any,
) -> None:
    """SC23-M3: HTTP 403 refusal envelopes must also match the call's correlation_id."""
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL", "amount": 100}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        payload: dict[str, Any] = {
            "verdict": "DENIED",
            "proof_hash": "b" * 64,
            "violations": ["POLICY_DENIED"],
            "correlation_id": bad_corr,
        }
        return httpx.Response(
            403,
            json=_build_signed_env(
                action="query_portfolio",
                parameters=params,
                payload=payload,
                priv=priv,
                kid=jwk["kid"],
            ),
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(RoutingSealVerificationError) as exc_info:
                await client.validate_action("query_portfolio", params, "agent-sc23")
            assert not isinstance(exc_info.value, PolicyViolationException)

    asyncio.run(_run())


def test_sc23_m4_defer_expires_at_separated_from_envelope_expires_at_and_warns_on_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SC23-M4: DeferralPending and PreviewResult use defer_expires_at, never 5m envelope.expires_at."""
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL", "amount": 50000}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    envelope_exp = now + timedelta(minutes=5)
    explicit_defer_exp = now + timedelta(hours=4)

    mode = ["explicit"]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        corr = json.loads(req.content)["correlation_id"]
        cur = mode[0]
        payload: dict[str, Any] = {
            "verdict": "REQUIRE_APPROVAL",
            "deferred_id": f"def-{cur}",
            "defer_reason": "amount_threshold",
            "correlation_id": corr,
        }
        if cur == "explicit":
            payload["defer_expires_at"] = explicit_defer_exp.isoformat().replace(
                "+00:00", "Z"
            )
            payload["ttl_seconds"] = 14400
        elif cur == "retry_only":
            payload["retry_after_seconds"] = 900
        elif cur == "invalid_defer_exp":
            payload["defer_expires_at"] = "2026-11-26 12:00:00"
        elif cur == "invalid_ttl":
            payload["ttl_seconds"] = True
        return httpx.Response(
            200,
            json=_build_signed_env(
                action="execute_trade",
                parameters=params,
                payload=payload,
                priv=priv,
                kid=jwk["kid"],
                issued_at=now,
                expires_at=envelope_exp,
            ),
        )

    async def _run() -> None:
        async with CageClient(
            "https://gateway.example.test",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            # 1. Explicit defer_expires_at (4h) preserved independently of 5m envelope_expires_at
            mode[0] = "explicit"
            with pytest.raises(DeferralPending) as exc_exp:
                await client.validate_action("execute_trade", params, "agent-sc23")
            assert exc_exp.value.defer_expires_at == explicit_defer_exp
            assert exc_exp.value.expires_at == explicit_defer_exp
            assert exc_exp.value.envelope_expires_at == envelope_exp
            assert exc_exp.value.defer_expires_at != exc_exp.value.envelope_expires_at
            assert exc_exp.value.ttl_seconds == 14400

            # PreviewResult and governed_node also surface 4h defer_expires_at
            prev = await client.preview("execute_trade", params, "agent-sc23")
            assert prev.decision is GovernanceDecision.DEFERRED
            assert prev.defer_expires_at == explicit_defer_exp

            node = governed_node(
                client=client,
                principal_extractor=lambda s: s["principal"],
                action_extractor=lambda s: ("execute_trade", params),
                on_allow="done",
                on_approval_required="park",
                on_deny="deny",
            )
            cmd = await node({"principal": "agent-sc23"})
            assert cmd.goto == "park"
            assert cmd.update["defer_expires_at"] == explicit_defer_exp.isoformat()

            # 2. retry_after_seconds only -> issued_at + 900s (never 5m envelope.expires_at)
            mode[0] = "retry_only"
            with pytest.raises(DeferralPending) as exc_retry:
                await client.validate_action("execute_trade", params, "agent-sc23")
            assert exc_retry.value.defer_expires_at == now + timedelta(seconds=900)
            assert exc_retry.value.ttl_seconds == 900
            assert exc_retry.value.envelope_expires_at == envelope_exp

            # 3. Legacy envelope missing both defer_expires_at and ttl_seconds -> 14400s + WARNING log
            mode[0] = "fallback_default"
            with caplog.at_level(logging.WARNING, logger="CageClient"):
                with pytest.raises(DeferralPending) as exc_fb:
                    await client.validate_action("execute_trade", params, "agent-sc23")
            assert exc_fb.value.ttl_seconds == 14400
            assert exc_fb.value.defer_expires_at == now + timedelta(seconds=14400)
            assert exc_fb.value.envelope_expires_at == envelope_exp
            assert any(
                "defaulting deferral TTL to 14400s" in rec.getMessage()
                for rec in caplog.records
            )

            # 4. Malformed defer_expires_at or boolean ttl_seconds fails closed
            mode[0] = "invalid_defer_exp"
            with pytest.raises(CageGatewayError, match="defer_expires_at"):
                await client.validate_action("execute_trade", params, "agent-sc23")

            mode[0] = "invalid_ttl"
            with pytest.raises(CageGatewayError, match="ttl_seconds"):
                await client.validate_action("execute_trade", params, "agent-sc23")

    asyncio.run(_run())
