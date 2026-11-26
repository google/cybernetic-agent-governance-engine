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

"""Gateway + end-to-end SC-23 correlation_id binding, defer_expires_at separation, and mutation tests (POAM-2026-241)."""

from __future__ import annotations
import __future__

import base64
import importlib
import inspect
import json
import textwrap
from collections.abc import Awaitable, Callable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cage_client import (
    CageClient,
    DeferralPending,
    PolicyViolationException,
    RoutingSealVerificationError,
    compute_expected_action_hash,
)
from cage_client._jcs import canonicalize
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI

from src.gateway.governance import jwks as gov_jwks
from src.gateway.governance.classification_engine import (
    REASON_CONFIDENCE_BELOW_THRESHOLD,
)
from src.gateway.governance.contracts import (
    GovernanceTierFailure,
    Violation,
    ViolationKind,
)
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor.errors import GovernanceError
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.verdicts import (
    build_refusal_receipt,
    handle_defer,
    handle_require_approval,
)
from src.gateway.governance.kms_signer import (
    KMSGovernanceSigner,
    SoftwareEd25519Provider,
)
from src.gateway.server.governance_middleware import governance_app

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_ed25519(
    kid: str = "ed-gw-sc23-01",
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


@pytest.fixture
def live_sc23_asgi(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[FastAPI, MagicMock]]:
    """Mount real governance_app at /governance with EdDSA signer & JWKS."""
    monkeypatch.setenv("CAGE_ENV", "development")
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._check_validate_action_rate_limit",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "src.gateway.server.governance_middleware._emit_refusal_receipt",
        AsyncMock(return_value=None),
    )

    jwks = gov_jwks.JWKSet(max_keys=8)
    ed_provider = SoftwareEd25519Provider(key_id="cage-kms-sc23-ed25519")
    ed_signer = KMSGovernanceSigner(provider=ed_provider)
    monkeypatch.setattr(
        "src.gateway.governance.kms_signer.get_governance_signer",
        lambda: ed_signer,
    )
    gov_jwks._initialize_jwks_from_kms(jwks)
    monkeypatch.setattr(gov_jwks, "_global_jwks", jwks)

    mock_governor = MagicMock(spec=SymbolicGovernor)
    mock_governor.validate_action = AsyncMock()
    had_governor = hasattr(governance_app.state, "governor")
    prev_governor = getattr(governance_app.state, "governor", None)
    governance_app.state.governor = mock_governor

    root_app = FastAPI()
    root_app.mount("/governance", governance_app)
    try:
        yield root_app, mock_governor
    finally:
        if had_governor:
            governance_app.state.governor = prev_governor
        elif hasattr(governance_app.state, "governor"):
            delattr(governance_app.state, "governor")


async def _make_asgi_client(root_app: FastAPI) -> CageClient:
    client = CageClient(gateway_url="https://cage-sc23-asgi.example.test")
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root_app),
        base_url="https://cage-sc23-asgi.example.test",
    )
    return client


# ---------------------------------------------------------------------------
# 1. Gateway builder, verdict helpers, and live ASGI correlation / TTL binding
# ---------------------------------------------------------------------------


def test_envelope_builder_binds_correlation_id_without_mutating_caller_dict() -> None:
    builder = GovernanceEnvelopeBuilder()
    caller_result = {"verdict": "ALLOW", "tiers_passed": ["opa"]}
    env = builder.build_unsigned(
        action="query_portfolio",
        params={"symbol": "AAPL"},
        governance_result=caller_result,
        correlation_id="  corr-req-123  ",
    )
    assert env.payload["correlation_id"] == "corr-req-123"
    assert "correlation_id" not in caller_result

    with pytest.raises(ValueError, match="non-empty"):
        builder.build_unsigned(
            action="query_portfolio",
            params={"symbol": "AAPL"},
            governance_result={"verdict": "ALLOW"},
            correlation_id="   ",
        )
    with pytest.raises(ValueError, match="conflicting correlation_id"):
        builder.build_unsigned(
            action="query_portfolio",
            params={"symbol": "AAPL"},
            governance_result={"verdict": "ALLOW", "correlation_id": "other"},
            correlation_id="corr-req-123",
        )


async def test_gateway_defer_and_require_approval_emit_defer_expires_at_and_ttl() -> (
    None
):
    before = datetime.now(timezone.utc)
    with patch(
        "src.gateway.governance.governor.verdicts._park_defer_context",
        new_callable=AsyncMock,
        return_value=("tok-sc23-001", True),
    ):
        req_res = await handle_require_approval(
            action="execute_trade",
            params={"symbol": "AAPL", "amount": 50000},
            violations=[],
            tier_failures=[],
            classification_meta={"classification_reason": "hitl_threshold"},
        )
        defer_res = await handle_defer(
            action="execute_trade",
            params={"symbol": "AAPL", "amount": 500},
            violations=[],
            tier_failures=[],
            classification_meta={
                "classification_reason": REASON_CONFIDENCE_BELOW_THRESHOLD
            },
        )
    after = datetime.now(timezone.utc)

    for res in (req_res, defer_res):
        assert res["ttl_seconds"] == 14400
        raw_exp = res["defer_expires_at"]
        assert isinstance(raw_exp, str) and raw_exp.endswith("Z")
        parsed_exp = datetime.fromisoformat(raw_exp.replace("Z", "+00:00"))
        assert (
            before + timedelta(seconds=14399)
            <= parsed_exp
            <= after + timedelta(seconds=14401)
        )


async def test_live_asgi_binds_correlation_id_on_200_403_and_rejects_mismatch(
    live_sc23_asgi: tuple[FastAPI, MagicMock],
) -> None:
    root_app, mock_governor = live_sc23_asgi
    params = {"symbol": "AAPL", "amount": 50000}

    # 1. HTTP 200 ALLOW binds CageClient's per-call correlation_id inside signed payload
    mock_governor.validate_action.return_value = {
        "verdict": GovernanceDecision.ALLOW,
        "tiers_passed": ["opa", "cbf"],
    }
    client = await _make_asgi_client(root_app)
    try:
        env = await client.validate_action("query_portfolio", params, "agent-sc23")
        assert isinstance(env.payload.get("correlation_id"), str)
        assert len(env.payload["correlation_id"]) == 32

        # 2. HTTP 200 REQUIRE_APPROVAL with 4h defer_expires_at separates ticket TTL from 5m envelope TTL
        now = datetime.now(timezone.utc).replace(microsecond=0)
        defer_exp = (
            (now + timedelta(hours=4))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        mock_governor.validate_action.return_value = {
            "verdict": GovernanceDecision.REQUIRE_APPROVAL,
            "deferred_id": "def-asgi-sc23",
            "classification_reason": "hitl_threshold",
            "ttl_seconds": 14400,
            "defer_expires_at": defer_exp,
        }
        with pytest.raises(DeferralPending) as def_exc:
            await client.validate_action("execute_trade", params, "agent-sc23")
        assert def_exc.value.ttl_seconds == 14400
        assert def_exc.value.defer_expires_at is not None
        assert def_exc.value.envelope_expires_at is not None
        assert (
            def_exc.value.defer_expires_at
            > def_exc.value.envelope_expires_at + timedelta(hours=3)
        )
        assert def_exc.value.expires_at == def_exc.value.defer_expires_at

        # 3. HTTP 403 DENIED binds CageClient's correlation_id inside signed refusal envelope
        hard_violation = Violation(
            tier="cbf",
            code="CBF_HARD_BARRIER",
            message="cbf limit exceeded",
            kind=ViolationKind.HARD,
        )
        tier_failure = GovernanceTierFailure(
            tier="CBF",
            control_id="CAGE-CTRL-001",
            rule_description="cbf limit exceeded",
            governing_state={"headroom": -10.0},
            protected_consequence="Prevent limit breach",
        )
        real_receipt = build_refusal_receipt(
            action="execute_trade",
            params=params,
            violations=[hard_violation],
            tier_failures=[tier_failure],
        )
        mock_governor.validate_action.side_effect = GovernanceError(
            "[CBF_HARD_BARRIER] cbf limit exceeded",
            receipt=real_receipt,
            violations=["[CBF_HARD_BARRIER] cbf limit exceeded"],
        )
        with pytest.raises(PolicyViolationException) as deny_exc:
            await client.validate_action("execute_trade", params, "agent-sc23")
        assert deny_exc.value.audit_id == real_receipt.proof_hash
    finally:
        await client.aclose()

    # 4. Direct POST with blank correlation_id or header-vs-body mismatch fails closed HTTP 400
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=root_app),
        base_url="https://cage-sc23-asgi.example.test",
    ) as raw_http:
        r_mismatch = await raw_http.post(
            "/governance/validate-action",
            json={
                "action": "query_portfolio",
                "params": params,
                "correlation_id": "body-corr-1",
            },
            headers={"X-Correlation-ID": "header-corr-2"},
        )
        assert r_mismatch.status_code == 400
        assert r_mismatch.json()["error"] == "mismatched_correlation_id"

        r_blank = await raw_http.post(
            "/governance/validate-action",
            json={
                "action": "query_portfolio",
                "params": params,
                "correlation_id": "   ",
            },
        )
        assert r_blank.status_code == 400
        assert r_blank.json()["error"] == "invalid_correlation_id"


# ---------------------------------------------------------------------------
# 2. SC23-M1..SC23-M5 Dual-Column Inverted-Verification Mutation Suite
# ---------------------------------------------------------------------------

_Edit = tuple[str, str]
_Probe = Callable[[], Awaitable[bool]]


def _compile_mutant(target: Any, edits: tuple[_Edit, ...]) -> Any:
    unwrap = target.__func__ if isinstance(target, staticmethod) else target
    lines, first_line = inspect.getsourcelines(unwrap)
    start = next(
        i
        for i, line in enumerate(lines)
        if line.lstrip().startswith(("def ", "async def "))
    )
    source = textwrap.dedent("".join(lines[start:]))
    for old, new in edits:
        found = source.count(old)
        assert found == 1, f"{unwrap.__name__}: anchor found {found} times: {old!r}"
        source = source.replace(old, new)
    mod = importlib.import_module(unwrap.__module__)
    code = compile(
        "\n" * (first_line + start - 1) + source,
        inspect.getsourcefile(unwrap) or f"<mutant {unwrap.__name__}>",
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    namespace: dict[str, Any] = {}
    exec(code, mod.__dict__, namespace)  # noqa: S102
    compiled = namespace[unwrap.__name__]
    return staticmethod(compiled) if isinstance(target, staticmethod) else compiled


def _signed_env(
    *,
    action: str,
    params: dict[str, Any],
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
        "envelope_id": "env-sc23-mut",
        "issued_at": iat.isoformat(),
        "expires_at": exp.isoformat(),
        "issuer": {
            "service": "cage-gateway",
            "instance_id": "gw-1",
            "region": "US_FED",
        },
        "subject": {
            "action": action,
            "action_hash": compute_expected_action_hash(action, params),
            "agent_id": "agent-mut",
        },
        "governance_context": {"policy_version": "sha256:abc", "tiers_passed": ["opa"]},
        "payload": payload,
    }
    sig = _b64u(priv.sign(canonicalize(env)))
    return {
        "envelope_version": env["envelope_version"],
        "envelope_type": env["envelope_type"],
        "envelope_id": env["envelope_id"],
        "issued_at": env["issued_at"],
        "expires_at": env["expires_at"],
        "issuer": env["issuer"],
        "subject": env["subject"],
        "governance_context": env["governance_context"],
        "payload": payload,
        "signature": {"algorithm": "EdDSA", "kid": kid, "value": sig},
    }


async def _probe_sc23_m1_presence_checked() -> bool:
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL"}
    send_corr: list[Any] = [True]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        corr = json.loads(req.content)["correlation_id"]
        payload: dict[str, Any] = {"verdict": "ALLOW"}
        if send_corr[0]:
            payload["correlation_id"] = corr
        return httpx.Response(
            200,
            json=_signed_env(
                action="query_portfolio",
                params=params,
                payload=payload,
                priv=priv,
                kid=jwk["kid"],
            ),
        )

    async with CageClient(
        "https://gateway.example.test", http_transport=httpx.MockTransport(handler)
    ) as client:
        ok = await client.validate_action("query_portfolio", params, "agent-mut")
        if ok.payload["verdict"] != "ALLOW":
            return False
        send_corr[0] = False
        try:
            await client.validate_action("query_portfolio", params, "agent-mut")
        except RoutingSealVerificationError:
            return True
        return False


async def _probe_sc23_m1b_type_checked() -> bool:
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL"}
    mode: list[Any] = ["valid"]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        corr = json.loads(req.content)["correlation_id"]
        val = corr if mode[0] == "valid" else mode[0]
        return httpx.Response(
            200,
            json=_signed_env(
                action="query_portfolio",
                params=params,
                payload={"verdict": "ALLOW", "correlation_id": val},
                priv=priv,
                kid=jwk["kid"],
            ),
        )

    async with CageClient(
        "https://gateway.example.test", http_transport=httpx.MockTransport(handler)
    ) as client:
        ok = await client.validate_action("query_portfolio", params, "agent-mut")
        if ok.payload["verdict"] != "ALLOW":
            return False
        for non_str in (12345, ["abc"]):
            mode[0] = non_str
            try:
                with patch(
                    "cage_client.core.secrets.token_hex", return_value=str(non_str)
                ):
                    await client.validate_action("query_portfolio", params, "agent-mut")
                return False
            except RoutingSealVerificationError:
                pass
        return True


async def _probe_sc23_m2_parity_checked() -> bool:
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL"}
    captured: list[dict[str, Any]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        if captured:
            return httpx.Response(200, json=captured[0])
        corr = json.loads(req.content)["correlation_id"]
        env = _signed_env(
            action="query_portfolio",
            params=params,
            payload={"verdict": "ALLOW", "correlation_id": corr},
            priv=priv,
            kid=jwk["kid"],
        )
        captured.append(env)
        return httpx.Response(200, json=env)

    async with CageClient(
        "https://gateway.example.test", http_transport=httpx.MockTransport(handler)
    ) as client:
        await client.validate_action("query_portfolio", params, "agent-mut")
        try:
            await client.validate_action("query_portfolio", params, "agent-mut")
        except RoutingSealVerificationError:
            return True
        return False


async def _probe_sc23_m3_403_refusal_checked() -> bool:
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL"}
    mismatch = [False]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        corr = (
            "wrong-corr" if mismatch[0] else json.loads(req.content)["correlation_id"]
        )
        return httpx.Response(
            403,
            json=_signed_env(
                action="query_portfolio",
                params=params,
                payload={
                    "verdict": "DENIED",
                    "proof_hash": "c" * 64,
                    "violations": ["POLICY_DENIED"],
                    "correlation_id": corr,
                },
                priv=priv,
                kid=jwk["kid"],
            ),
        )

    async with CageClient(
        "https://gateway.example.test", http_transport=httpx.MockTransport(handler)
    ) as client:
        try:
            await client.validate_action("query_portfolio", params, "agent-mut")
            return False
        except PolicyViolationException:
            pass
        mismatch[0] = True
        try:
            await client.validate_action("query_portfolio", params, "agent-mut")
            return False
        except RoutingSealVerificationError:
            return True
        except PolicyViolationException:
            return False


async def _probe_sc23_m4_defer_ttl_separated() -> bool:
    priv, jwk = _make_ed25519()
    params = {"symbol": "AAPL"}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    envelope_exp = now + timedelta(minutes=5)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/governance/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [jwk]})
        corr = json.loads(req.content)["correlation_id"]
        return httpx.Response(
            200,
            json=_signed_env(
                action="execute_trade",
                params=params,
                payload={
                    "verdict": "REQUIRE_APPROVAL",
                    "deferred_id": "def-mut-1",
                    "defer_reason": "hitl_threshold",
                    "ttl_seconds": 14400,
                    "correlation_id": corr,
                },
                priv=priv,
                kid=jwk["kid"],
                issued_at=now,
                expires_at=envelope_exp,
            ),
        )

    async with CageClient(
        "https://gateway.example.test", http_transport=httpx.MockTransport(handler)
    ) as client:
        try:
            await client.validate_action("execute_trade", params, "agent-mut")
        except DeferralPending as exc:
            return exc.defer_expires_at == now + timedelta(seconds=14400)
        return False


async def _probe_sc23_m5_gateway_binds_correlation_id() -> bool:
    env = GovernanceEnvelopeBuilder().build_unsigned(
        action="query_portfolio",
        params={"symbol": "AAPL"},
        governance_result={"verdict": "ALLOW"},
        correlation_id="corr-mut-5",
    )
    return env.payload.get("correlation_id") == "corr-mut-5"


_SC23_MUTANTS: list[tuple[str, Any, str, tuple[_Edit, ...], _Probe]] = [
    (
        "SC23-M1: drop missing/blank correlation_id guard in _verify_subject_binding",
        CageClient,
        "_verify_subject_binding",
        (
            (
                '        if not isinstance(envelope_corr, str) or not envelope_corr.strip():\n            raise RoutingSealVerificationError(\n                "GovernanceEnvelope payload is missing required non-empty \'correlation_id\' binding"\n            )\n        if not hmac.compare_digest(\n            envelope_corr.encode("utf-8"),\n            correlation_id.encode("utf-8"),\n        ):\n            raise RoutingSealVerificationError(\n                "GovernanceEnvelope payload.correlation_id does not match request correlation_id"\n            )',
                '        if isinstance(envelope_corr, str) and envelope_corr.strip():\n            if not hmac.compare_digest(\n                envelope_corr.encode("utf-8"),\n                correlation_id.encode("utf-8"),\n            ):\n                raise RoutingSealVerificationError(\n                    "GovernanceEnvelope payload.correlation_id does not match request correlation_id"\n                )',
            ),
        ),
        _probe_sc23_m1_presence_checked,
    ),
    (
        "SC23-M1b: drop str isinstance type check in _verify_subject_binding",
        CageClient,
        "_verify_subject_binding",
        (
            (
                "if not isinstance(envelope_corr, str) or not envelope_corr.strip():",
                "if not envelope_corr or (isinstance(envelope_corr, str) and not envelope_corr.strip()):",
            ),
            (
                'envelope_corr.encode("utf-8")',
                'str(envelope_corr).encode("utf-8")',
            ),
        ),
        _probe_sc23_m1b_type_checked,
    ),
    (
        "SC23-M2: drop hmac.compare_digest correlation_id comparison in _verify_subject_binding",
        CageClient,
        "_verify_subject_binding",
        (
            (
                '        if not hmac.compare_digest(\n            envelope_corr.encode("utf-8"),\n            correlation_id.encode("utf-8"),\n        ):',
                "        if False:",
            ),
        ),
        _probe_sc23_m2_parity_checked,
    ),
    (
        "SC23-M3: drop correlation_id forwarding on HTTP 403 refusals in _handle_deny_response",
        CageClient,
        "_handle_deny_response",
        (
            (
                '        correlation_id=correlation_id,\n        response_label="DENY",',
                '        correlation_id=None,\n        response_label="DENY",',
            ),
        ),
        _probe_sc23_m3_403_refusal_checked,
    ),
    (
        "SC23-M4: fall back to envelope.expires_at instead of issued_at + ttl_seconds in _mediate_defer_verdict",
        CageClient,
        "_mediate_defer_verdict",
        (
            (
                "defer_expires_at = envelope.issued_at + timedelta(seconds=ttl_seconds)",
                "defer_expires_at = envelope.expires_at",
            ),
        ),
        _probe_sc23_m4_defer_ttl_separated,
    ),
    (
        "SC23-M5: drop correlation_id assignment inside GovernanceEnvelopeBuilder.build_unsigned",
        GovernanceEnvelopeBuilder,
        "build_unsigned",
        (
            (
                'payload_data["correlation_id"] = cleaned_corr',
                "pass",
            ),
        ),
        _probe_sc23_m5_gateway_binds_correlation_id,
    ),
]


@pytest.mark.parametrize(
    ("mid", "target_cls", "attr_name", "edits", "probe"),
    _SC23_MUTANTS,
    ids=[m[0].split(":")[0] for m in _SC23_MUTANTS],
)
async def test_sc23_mutation_killed_with_inverted_verification(
    monkeypatch: pytest.MonkeyPatch,
    mid: str,
    target_cls: Any,
    attr_name: str,
    edits: tuple[_Edit, ...],
    probe: _Probe,
) -> None:
    """Inverted verification: probe passes on intact code (True) and fails on mutant (False)."""
    assert await probe() is True, f"{mid}: probe failed on unmutated code"
    orig_descriptor = inspect.getattr_static(target_cls, attr_name)
    monkeypatch.setattr(target_cls, attr_name, _compile_mutant(orig_descriptor, edits))
    assert await probe() is False, f"{mid} survived!"


def test_sc23_mutation_set_complete() -> None:
    assert [m[0].split(":")[0] for m in _SC23_MUTANTS] == [
        "SC23-M1",
        "SC23-M1b",
        "SC23-M2",
        "SC23-M3",
        "SC23-M4",
        "SC23-M5",
    ]
