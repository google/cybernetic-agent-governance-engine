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

"""Live trade-governance flow against a deployed gateway (Phase 0, §0.6).

Runs scenarios S0, S1a, S1b, S1, S2, S3 and S4 from
``tests/test_trade_governance_e2e.py`` over the wire, from inside the mesh
(``deployment/k8s/verify-trade-e2e-job.yaml`` runs it as ``cage-advisor-sa`` with a
Linkerd proxy, so the gateway sees a real peer-verified ``l5d-client-id``).
It also checks what the hermetic suite cannot: the gateway's JWKS holds only
asymmetric keys with a ``kid``, and a signed ALLOW envelope verifies against a
key resolved by ``kid`` from that independently fetched JWKS.

Opt-in: ``--run-e2e`` (``make test-gke-e2e``). Once opted in, missing
configuration FAILS the run rather than skipping it.

Environment
-----------
``CAGE_E2E_GATEWAY_URL``
    Gateway base URL reached through the mesh (e.g. ``http://cage-gateway.governance-stack:8080``).
``CAGE_E2E_UNMESHED_GATEWAY_URL``
    The same gateway reached *without* a mesh identity (e.g. a ``kubectl
    port-forward``) — S0 asserts it is refused.
``CAGE_E2E_BRIDGE_URL``
    Compliance bridge base URL; approvals are recorded only through its
    ``POST /v1/defer/{defer_id}/escalate``.
``CAGE_E2E_INTERNAL_TOKEN``
    The bridge's internal service token (from a Secret, never a literal).
``CAGE_E2E_OPERATOR_PRINCIPALS``
    Two distinct operator SPIFFE IDs, comma-separated (HITL quorum is 2).

Known gap
---------
The bridge's ``require_operator_identity`` currently reads the operator SVID
from the self-asserted ``x-cage-source-principal`` header rather than binding it
to the mTLS peer identity (``l5d-client-id``). This suite sends that header per
operator, so a passing run proves the quorum mechanics, NOT that two distinct
humans approved: any holder of the internal token can assert both principals.
"""

from __future__ import annotations

import asyncio
import base64
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import httpx
import pytest

pytestmark = [pytest.mark.e2e]

_ENV = (
    "CAGE_E2E_GATEWAY_URL",
    "CAGE_E2E_UNMESHED_GATEWAY_URL",
    "CAGE_E2E_BRIDGE_URL",
    "CAGE_E2E_INTERNAL_TOKEN",
    "CAGE_E2E_OPERATOR_PRINCIPALS",
)
_TIMEOUT = httpx.Timeout(60.0)


@dataclass
class Live:
    gateway: httpx.AsyncClient
    unmeshed: httpx.AsyncClient
    bridge: httpx.AsyncClient
    internal_token: str
    operators: tuple[str, str]

    async def validate(self, action: str, params: dict[str, Any]) -> httpx.Response:
        return await self.gateway.post(
            "/governance/validate-action", json={"action": action, "params": params}
        )

    async def execute(
        self, params: dict[str, Any], deferred_id: str | None = None
    ) -> str:
        """Run ``execute_trade_action`` in the gateway; return its output string."""
        body = {**params, **({"deferred_id": deferred_id} if deferred_id else {})}
        resp = await self.gateway.post(
            "/tools/execute", json={"tool_name": "execute_trade_action", "params": body}
        )
        resp.raise_for_status()
        result = resp.json()
        return str(
            result.get("output") if result.get("status") == "SUCCESS" else result
        )

    async def approve(self, deferred_id: str) -> None:
        """Record the two-operator quorum through the compliance bridge."""
        statuses = []
        for principal in self.operators:
            resp = await self.bridge.post(
                f"/v1/defer/{deferred_id}/escalate",
                json={},
                headers={
                    "X-Cage-Internal-Token": self.internal_token,
                    "x-cage-source-principal": principal,
                },
            )
            assert resp.status_code == 200, resp.text
            statuses.append(resp.json().get("status"))
        assert statuses == ["partially_approved", "escalated"], statuses


@pytest.fixture
async def live() -> AsyncIterator[Live]:
    missing = [name for name in _ENV if not os.environ.get(name)]
    if missing:
        pytest.fail(f"--run-e2e requires {', '.join(missing)}")
    operators = tuple(
        p.strip() for p in os.environ["CAGE_E2E_OPERATOR_PRINCIPALS"].split(",")
    )
    if len(operators) != 2 or len(set(operators)) != 2:
        pytest.fail("CAGE_E2E_OPERATOR_PRINCIPALS must name two distinct operators")
    async with (
        httpx.AsyncClient(
            base_url=os.environ["CAGE_E2E_GATEWAY_URL"], timeout=_TIMEOUT
        ) as gw,
        httpx.AsyncClient(
            base_url=os.environ["CAGE_E2E_UNMESHED_GATEWAY_URL"], timeout=_TIMEOUT
        ) as unmeshed,
        httpx.AsyncClient(
            base_url=os.environ["CAGE_E2E_BRIDGE_URL"], timeout=_TIMEOUT
        ) as bridge,
    ):
        yield Live(
            gw, unmeshed, bridge, os.environ["CAGE_E2E_INTERNAL_TOKEN"], operators
        )  # type: ignore[arg-type]


def _trade(amount: float, role: str = "junior", **extra: Any) -> dict[str, Any]:
    """A trade with a run-unique trader so fiscal state never leaks between tests."""
    return {
        "symbol": "AAPL",
        "amount": amount,
        "currency": "USD",
        "confidence": 0.98,
        "trader_id": f"e2e-{uuid.uuid4().hex[:12]}",
        "trader_role": role,
        "latency_ms": 10.0,  # STPA UCA-2 input
        "drawdown": 0.0,  # STPA UCA-5 input
        **extra,
    }


def _body(resp: httpx.Response) -> dict[str, Any]:
    from src.gateway.governance.governance_envelope import unwrap_governance_envelope

    return unwrap_governance_envelope(resp.json())


async def _require_approval(live: Live, params: dict[str, Any]) -> str:
    resp = await live.validate("execute_trade", params)
    assert resp.status_code == 200, resp.text
    body = _body(resp)
    assert body["verdict"] == "REQUIRE_APPROVAL", body
    assert "seal" not in body
    assert body.get("deferred_id"), body
    return str(body["deferred_id"])


# ── Trust anchors ────────────────────────────────────────────────────────────


def _jwk_to_pem(jwk: dict[str, Any]) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    def _int(field: str) -> int:
        raw = jwk[field] + "=" * (-len(jwk[field]) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(raw), "big")

    if jwk["kty"] == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
        key: Any = ec.EllipticCurvePublicNumbers(
            _int("x"), _int("y"), curve
        ).public_key()
    elif jwk["kty"] == "RSA":
        key = rsa.RSAPublicNumbers(_int("e"), _int("n")).public_key()
    else:
        raise AssertionError(f"unsupported kty {jwk['kty']!r}")
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


async def test_jwks_holds_only_asymmetric_keys_with_kid(live: Live) -> None:
    resp = await live.gateway.get("/governance/jwks")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys, "the gateway publishes no verification keys"
    for jwk in keys:
        assert jwk.get("kid"), jwk
        assert jwk["kty"] in {"EC", "RSA"}, jwk  # never "oct" (HMAC)
        assert "d" not in jwk and "k" not in jwk, (
            "private or symmetric material published"
        )


async def test_allow_envelope_verifies_by_kid_against_fetched_jwks(live: Live) -> None:
    """Resolve the key by ``kid`` from the independently fetched JWKS — never from the envelope."""
    from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
    from src.gateway.governance.jwks import JWKSet

    trusted = JWKSet()
    for jwk in (await live.gateway.get("/governance/jwks")).json()["keys"]:
        trusted.add_key(_jwk_to_pem(jwk), kid=jwk["kid"])

    resp = await live.validate(
        "check_balance", {"account_id": "e2e", "confidence": 0.99}
    )
    assert resp.status_code == 200, resp.text
    envelope = resp.json()
    assert envelope["payload"]["verdict"] == "ALLOW"
    assert "seal" not in envelope["payload"]
    assert envelope["signature"]["kid"], "ALLOW envelope is unsigned"

    with patch("src.gateway.governance.jwks.get_jwks", return_value=trusted):
        builder = GovernanceEnvelopeBuilder()
        assert builder.verify(envelope) is True
        tampered = {**envelope, "payload": {**envelope["payload"], "verdict": "DENY"}}
        assert builder.verify(tampered) is False


# ── S0: no mesh identity ─────────────────────────────────────────────────────


async def test_s0_unidentified_caller_is_refused(live: Live) -> None:
    resp = await live.unmeshed.post(
        "/governance/validate-action",
        json={"action": "execute_trade", "params": _trade(500.0)},
    )
    assert resp.status_code == 403
    resp = await live.unmeshed.post(
        "/tools/execute",
        json={"tool_name": "execute_trade_action", "params": _trade(500.0)},
    )
    assert resp.status_code == 403


# ── S1a / S1b: autonomous paths (Phase 1) ────────────────────────────────────


async def test_s1a_small_junior_trade_allows_and_executes_once(live: Live) -> None:
    params = _trade(500.0)
    resp = await live.validate("execute_trade", params)
    assert resp.status_code == 200, resp.text
    assert _body(resp)["verdict"] == "ALLOW"
    assert (await live.execute(params)).startswith("EXECUTED")


async def test_s1b_mid_junior_trade_requires_approval_for_opa_review(
    live: Live,
) -> None:
    resp = await live.validate("execute_trade", _trade(7_500.0))
    body = _body(resp)
    assert body["verdict"] == "REQUIRE_APPROVAL"
    assert body["classification_reason"] == "opa_manual_review"
    assert [v for v in body["violations"] if "FTRA" in str(v)] == []


# ── S1 / S2 / S3: the approval path ──────────────────────────────────────────


async def test_s1_large_senior_trade_parks_an_approval_token(live: Live) -> None:
    await _require_approval(live, _trade(20_000.0, "senior"))


async def test_s1_unapproved_token_never_executes(live: Live) -> None:
    params = _trade(20_000.0, "senior")
    deferred_id = await _require_approval(live, params)
    assert (await live.execute(params, deferred_id)).startswith("BLOCKED")


async def test_s2_approved_token_executes_exactly_once(live: Live) -> None:
    params = _trade(20_000.0, "senior")
    deferred_id = await _require_approval(live, params)
    await live.approve(deferred_id)

    first = await live.execute(params, deferred_id)
    second = await live.execute(params, deferred_id)

    assert first.startswith("EXECUTED"), first
    assert second.startswith("BLOCKED"), second


async def test_s2_approval_does_not_cover_a_larger_trade(live: Live) -> None:
    params = _trade(20_000.0, "senior")
    deferred_id = await _require_approval(live, params)
    await live.approve(deferred_id)

    grown = await live.execute({**params, "amount": 40_000.0}, deferred_id)
    assert grown.startswith("BLOCKED"), grown
    # The mismatch did not burn the approval.
    assert (await live.execute(params, deferred_id)).startswith("EXECUTED")


async def test_s3_concurrent_replay_executes_exactly_once(live: Live) -> None:
    params = _trade(20_000.0, "senior")
    deferred_id = await _require_approval(live, params)
    await live.approve(deferred_id)

    outputs = await asyncio.gather(
        live.execute(params, deferred_id), live.execute(params, deferred_id)
    )

    assert sorted(out.split(":", 1)[0] for out in outputs) == ["BLOCKED", "EXECUTED"], (
        outputs
    )


# ── S4: refusal ──────────────────────────────────────────────────────────────


async def test_s4_oversized_junior_trade_is_denied_without_a_token(live: Live) -> None:
    resp = await live.validate("execute_trade", _trade(50_000.0))
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["verdict"] == "DENIED"
    assert any("CTRL_OPA_005" in str(v) for v in body["violations"]), body
    assert "deferred_id" not in body
